use super::*;
impl Windows<'_> {
    pub(super) fn handles(&self, p: &Process, r: &mut Results, job: &Job) -> Result<()> {
        let table = self.number(p.address, "_EPROCESS", "ObjectTable")?;
        if table == 0 {
            return Ok(());
        }
        let code = self.number(table, "_HANDLE_TABLE", "TableCode")?;
        let levels = code & 7;
        ensure!(levels <= 2, "不支持的句柄表层级");
        let root = code & !7;
        let max = self.number(table, "_HANDLE_TABLE", "NextHandleNeedingPool")?;
        ensure!(max / 4 <= MAX_OBJECTS as u64, "句柄表超限");
        let size = self.vm.isf.data["user_types"]["_HANDLE_TABLE_ENTRY"]["size"]
            .as_u64()
            .context("缺少句柄条目大小")?;
        ensure!(size > 0 && 4096 % size == 0, "无效句柄条目大小");
        let per = 4096 / size;
        for first in (0..max / 4).step_by(per as usize) {
            job.check()?;
            let mut page = root;
            let slot = first / per;
            for level in (0..levels).rev() {
                let n = (slot >> (level * 9)) & 511;
                page = self.vm.uint(add(page, n * 8)?, 8)?;
                if page == 0 {
                    break;
                }
            }
            if page == 0 {
                continue;
            }
            let mut entries = [0; 4096];
            if let Err(e) = self.vm.read(page, &mut entries) {
                Self::issue(r, format!("PID {} handle table page {page:#x}", p.pid), e);
                continue;
            }
            for index in first..(first + per).min(max / 4) {
                job.check()?;
                let entry = &entries[((index % per) * size) as usize..][..size as usize];
                let read = (|| -> Result<Option<Vec<String>>> {
                    let bits = physical_number(
                        self.vm.isf,
                        entry,
                        "_HANDLE_TABLE_ENTRY",
                        "ObjectPointerBits",
                    )?;
                    if bits == 0 {
                        return Ok(None);
                    }
                    let header = 0xffff_0000_0000_0000 | (bits << 4);
                    ensure!(self.vm.kernel(header), "无效对象头地址");
                    let body = self.field(header, "_OBJECT_HEADER", "Body")?;
                    let access = physical_number(
                        self.vm.isf,
                        entry,
                        "_HANDLE_TABLE_ENTRY",
                        "GrantedAccessBits",
                    )?;
                    let kind = self.object_type(header)?;
                    let name = match kind.as_str() {
                        "File" => {
                            self.vm
                                .unicode(self.field(body, "_FILE_OBJECT", "FileName")?)?
                        }
                        "Process" => self.process(body)?.name,
                        "Thread" => {
                            format!("TID {}", self.number(body, "_ETHREAD", "Cid.UniqueThread")?)
                        }
                        _ => self.object_name(header)?,
                    };
                    Ok(Some(vec![
                        p.pid.to_string(),
                        p.name.clone(),
                        hex(index * 4),
                        kind,
                        hex(body),
                        format!("{access:#x}"),
                        name,
                    ]))
                })();
                match read {
                    Ok(Some(row)) => r.rows.push(row),
                    Ok(None) => {}
                    Err(e) => Self::issue(
                        r,
                        format!("PID {} handle {:#x}", p.pid, index * 4),
                        format!("{e:#}"),
                    ),
                }
            }
        }
        Ok(())
    }
    fn object_type(&self, header: u64) -> Result<String> {
        let encoded = self.number(header, "_OBJECT_HEADER", "TypeIndex")?;
        let cookie = self.vm.uint(self.symbol("ObHeaderCookie")?, 1)?;
        let index = encoded ^ cookie ^ ((header >> 8) & 255);
        let ty = self
            .vm
            .uint(add(self.symbol("ObTypeIndexTable")?, index * 8)?, 8)?;
        ensure!(self.vm.kernel(ty), "无效对象类型");
        self.vm.unicode(self.field(ty, "_OBJECT_TYPE", "Name")?)
    }
    fn object_name(&self, header: u64) -> Result<String> {
        let mask = self.number(header, "_OBJECT_HEADER", "InfoMask")?;
        if mask & 2 == 0 {
            return Ok(String::new());
        }
        let offset = self
            .vm
            .uint(add(self.symbol("ObpInfoMaskToOffset")?, mask & 3)?, 1)?;
        let info = header.checked_sub(offset).context("对象名称地址下溢")?;
        self.vm
            .unicode(self.field(info, "_OBJECT_HEADER_NAME_INFO", "Name")?)
    }
    pub(super) fn scan_processes(
        &self,
        plugin: Plugin,
        options: &Options,
        job: &Job,
    ) -> Result<Results> {
        let mut r = self.result(plugin);
        let scanned = self.pool_processes(job)?;
        if plugin == Plugin::WinPsscan {
            for p in scanned
                .into_iter()
                .filter(|p| options.pid.is_none_or(|pid| p.pid == u64::from(pid)))
            {
                r.rows.push(p.row());
            }
            return Ok(r);
        }
        let (listed, diagnostics) = self.processes_partial(job)?;
        r.complete = diagnostics.is_empty();
        r.diagnostics = diagnostics;
        let mut seen = HashSet::new();
        for p in &listed {
            let pa = self.vm.translate(p.address)?;
            seen.insert(pa);
            if options.pid.is_none_or(|pid| p.pid == u64::from(pid)) {
                r.rows.push(vec![
                    p.pid.to_string(),
                    p.name.clone(),
                    hex(p.address),
                    "true".into(),
                    scanned.iter().any(|s| s.address == pa).to_string(),
                    filetime(p.exited),
                ]);
            }
        }
        for p in scanned {
            if !seen.contains(&p.address) && options.pid.is_none_or(|pid| p.pid == u64::from(pid)) {
                r.rows.push(vec![
                    p.pid.to_string(),
                    p.name,
                    format!("physical:{:#x}", p.address),
                    "false".into(),
                    "true".into(),
                    filetime(p.exited),
                ]);
            }
        }
        Ok(r)
    }
    fn pool_processes(&self, job: &Job) -> Result<Vec<Process>> {
        let isf = self.vm.isf;
        let header_size = isf.data["user_types"]["_POOL_HEADER"]["size"]
            .as_u64()
            .context("缺少 _POOL_HEADER")?;
        let size = isf.data["user_types"]["_EPROCESS"]["size"]
            .as_u64()
            .context("缺少 _EPROCESS")?;
        ensure!(size <= 65536 && header_size <= 64, "无效进程池结构大小");
        let tag_offset = isf.offset("_POOL_HEADER", "PoolTag")?;
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for tag in [b"Proc".as_slice(), b"Pro\xe3".as_slice()] {
            for hit in self.vm.image.scan(tag, job)? {
                job.check()?;
                let Some(header) = hit.checked_sub(tag_offset) else {
                    continue;
                };
                if header & 15 != 0 {
                    continue;
                }
                let mut bytes = vec![0; header_size as usize];
                if self.vm.image.read(header, &mut bytes).is_err() {
                    continue;
                }
                let block = physical_number(isf, &bytes, "_POOL_HEADER", "BlockSize")? * 16;
                if block < header_size + size || block > 4096 {
                    continue;
                }
                // Object optional headers vary: locate and validate the object body inside the allocation.
                for delta in (header_size..=block - size).step_by(16) {
                    let address = header + delta;
                    if !seen.insert(address) {
                        continue;
                    }
                    let mut b = vec![0; size as usize];
                    if self.vm.image.read(address, &mut b).is_err() {
                        continue;
                    }
                    let parsed = (|| -> Result<Process> {
                        let pid = physical_number(isf, &b, "_EPROCESS", "UniqueProcessId")?;
                        ensure!(pid <= u32::MAX as u64 && pid % 4 == 0, "无效 PID");
                        let offset = isf.offset("_EPROCESS", "ImageFileName")? as usize;
                        let len = isf.size("_EPROCESS", "ImageFileName")?;
                        let raw = b.get(offset..offset + len).context("进程名称越界")?;
                        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
                        ensure!(
                            end > 0
                                && raw[..end]
                                    .iter()
                                    .all(|b| b.is_ascii_graphic() || *b == b' '),
                            "无效名称"
                        );
                        let dtb = physical_number(isf, &b, "_EPROCESS", "Pcb.DirectoryTableBase")?
                            & PHYSICAL_MASK;
                        ensure!(dtb != 0, "缺少 DTB");
                        let mut page = [0; 4096];
                        self.vm.image.read(dtb, &mut page)?;
                        let links =
                            physical_number(isf, &b, "_EPROCESS", "ActiveProcessLinks.Flink")?;
                        ensure!(self.vm.kernel(links), "无效进程链表指针");
                        let threads = physical_number(isf, &b, "_EPROCESS", "ActiveThreads")?;
                        ensure!(threads <= 65536, "无效线程数");
                        let created = physical_number(isf, &b, "_EPROCESS", "CreateTime")?;
                        ensure!(
                            pid <= 4 || created >= 116_444_736_000_000_000,
                            "无效创建时间"
                        );
                        Ok(Process {
                            address,
                            physical: true,
                            pid,
                            ppid: physical_number(
                                isf,
                                &b,
                                "_EPROCESS",
                                "InheritedFromUniqueProcessId",
                            )?,
                            name: String::from_utf8_lossy(&raw[..end]).into_owned(),
                            dtb,
                            threads,
                            handles: None,
                            created,
                            exited: physical_number(isf, &b, "_EPROCESS", "ExitTime")?,
                        })
                    })();
                    if let Ok(p) = parsed {
                        out.push(p);
                        break;
                    }
                }
            }
        }
        out.sort_by_key(|p| p.address);
        Ok(out)
    }
}
pub(super) fn physical_number(isf: &Isf, bytes: &[u8], ty: &str, field: &str) -> Result<u64> {
    let offset = isf.offset(ty, field)? as usize;
    let size = isf.size(ty, field)?;
    ensure!(matches!(size, 1 | 2 | 4 | 8), "无效物理字段宽度");
    let mut b = [0; 8];
    b[..size].copy_from_slice(bytes.get(offset..offset + size).context("物理字段越界")?);
    json_number(isf, u64::from_le_bytes(b), ty, field)
}
