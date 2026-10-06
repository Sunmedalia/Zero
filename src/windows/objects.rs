use super::*;
// Windows 8 encodes 41 address bits; later kernels may encode 44.
// Sign-extend the exact symbol-declared width after the four alignment bits.
fn decode_object_pointer(bits: u64, width: u64) -> Result<u64> {
    ensure!((1..=60).contains(&width), "句柄编码指针位宽无效");
    ensure!(bits <= (u64::MAX >> (64 - width)), "句柄编码指针溢出");
    let shift = 64 - width - 4;
    Ok((((bits << 4) << shift) as i64 >> shift) as u64)
}

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
        let pointer_size = self.vm.pointer_size() as u64;
        let pointers_per_page = 4096 / pointer_size;
        let index_shift = pointers_per_page.trailing_zeros();
        for first in (0..max / 4).step_by(per as usize) {
            job.check()?;
            let mut page = root;
            let slot = first / per;
            for level in (0..levels).rev() {
                let n = (slot >> (level as u32 * index_shift)) & (pointers_per_page - 1);
                page = self.vm.pointer(add(page, n * pointer_size)?)?;
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
                    let header = if self
                        .vm
                        .isf
                        .field("_HANDLE_TABLE_ENTRY", "ObjectPointerBits")
                        .is_ok()
                    {
                        let bits = physical_number(
                            self.vm.isf,
                            entry,
                            "_HANDLE_TABLE_ENTRY",
                            "ObjectPointerBits",
                        )?;
                        if bits == 0 {
                            return Ok(None);
                        }
                        if pointer_size == 4 {
                            ensure!(bits <= (u32::MAX as u64 >> 4), "32 位句柄编码指针溢出");
                            bits.checked_shl(4).context("句柄对象指针溢出")? & u32::MAX as u64
                        } else {
                            let field = self
                                .vm
                                .isf
                                .field("_HANDLE_TABLE_ENTRY", "ObjectPointerBits")?;
                            let width = field["type"]["bit_length"]
                                .as_u64()
                                .context("句柄编码指针缺少位宽")?;
                            decode_object_pointer(bits, width)?
                        }
                    } else {
                        physical_number(self.vm.isf, entry, "_HANDLE_TABLE_ENTRY", "Object")? & !7
                    };
                    if header == 0 {
                        return Ok(None);
                    }
                    ensure!(self.vm.kernel(header), "无效对象头地址");
                    let body = self.field(header, "_OBJECT_HEADER", "Body")?;
                    let access = physical_number(
                        self.vm.isf,
                        entry,
                        "_HANDLE_TABLE_ENTRY",
                        if self
                            .vm
                            .isf
                            .field("_HANDLE_TABLE_ENTRY", "GrantedAccessBits")
                            .is_ok()
                        {
                            "GrantedAccessBits"
                        } else {
                            "GrantedAccess"
                        },
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
    pub(super) fn object_type(&self, header: u64) -> Result<String> {
        if self.vm.isf.field("_OBJECT_HEADER", "TypeIndex").is_err() {
            let ty = self.number(header, "_OBJECT_HEADER", "Type")?;
            ensure!(self.vm.kernel(ty), "旧版对象类型指针无效");
            return self.vm.unicode(self.field(ty, "_OBJECT_TYPE", "Name")?);
        }
        let encoded = self.number(header, "_OBJECT_HEADER", "TypeIndex")?;
        let index = if self.vm.isf.raw_address("ObHeaderCookie").is_ok() {
            let cookie = self.vm.uint(self.symbol("ObHeaderCookie")?, 1)?;
            encoded ^ cookie ^ ((header >> 8) & 255)
        } else {
            encoded
        };
        ensure!(index < 256, "对象类型索引越界");
        let ty = self.vm.pointer(add(
            self.symbol("ObTypeIndexTable")?,
            index * self.vm.pointer_size() as u64,
        )?)?;
        ensure!(self.vm.kernel(ty), "无效对象类型");
        self.vm.unicode(self.field(ty, "_OBJECT_TYPE", "Name")?)
    }
    pub(super) fn object_name(&self, header: u64) -> Result<String> {
        if self.vm.isf.field("_OBJECT_HEADER", "InfoMask").is_err() {
            let offset = self.number(header, "_OBJECT_HEADER", "NameInfoOffset")?;
            if offset == 0 {
                return Ok(String::new());
            }
            let info = header.checked_sub(offset).context("旧版对象名称地址下溢")?;
            return self
                .vm
                .unicode(self.field(info, "_OBJECT_HEADER_NAME_INFO", "Name")?);
        }
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
        let alignment = if self.vm.pointer_size() == 4 { 8 } else { 16 };
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for tag in [b"Proc".as_slice(), b"Pro\xe3".as_slice()] {
            for hit in self.vm.image.scan(tag, job)? {
                job.check()?;
                let Some(header) = hit.checked_sub(tag_offset) else {
                    continue;
                };
                if header % alignment != 0 {
                    continue;
                }
                let mut bytes = vec![0; header_size as usize];
                if self.vm.image.read(header, &mut bytes).is_err() {
                    continue;
                }
                let block = physical_number(isf, &bytes, "_POOL_HEADER", "BlockSize")? * alignment;
                if block < header_size + size || block > 4096 {
                    continue;
                }
                // Object optional headers vary: locate and validate the object body inside the allocation.
                for delta in (header_size..=block - size).step_by(alignment as usize) {
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
                            & self.vm.root_mask();
                        ensure!(dtb != 0, "缺少 DTB");
                        let mut page = vec![0; if self.vm.paging()?.pae { 32 } else { 4096 }];
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
    b[..size].copy_from_slice(
        bytes
            .get(offset..offset.checked_add(size).context("物理字段偏移溢出")?)
            .context("物理字段越界")?,
    );
    json_number(isf, u64::from_le_bytes(b), ty, field)
}

#[cfg(test)]
mod tests {
    #[test]
    fn encoded_object_addresses_sign_extend_the_declared_width() {
        for (address, width) in [(0xfffffa8000c12340, 41), (0xffffc10000a12340, 44)] {
            let bits = (address >> 4) & ((1u64 << width) - 1);
            assert_eq!(super::decode_object_pointer(bits, width).unwrap(), address);
        }
        assert!(super::decode_object_pointer(1 << 41, 41).is_err());
        assert!(super::decode_object_pointer(1, 0).is_err());
        assert!(super::decode_object_pointer(1, 61).is_err());
    }

    use super::super::tests::{fixture, image};
    use super::*;
    use serde_json::json;
    #[test]
    fn win7_x86_raw_handles_use_1024_pointer_fanout_without_cookie() {
        let (mut b, mut isf) = fixture();
        let k = 0x80000000u64;
        isf.data["base_types"]["pointer"]["size"] = json!(4);
        isf.data["base_types"]["u32"] = json!({"size":4});
        isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
        let field = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u32"}});
        for (name, size, fields) in [
            (
                "_HANDLE_TABLE",
                8,
                json!({"TableCode":field(0),"NextHandleNeedingPool":field(4)}),
            ),
            (
                "_HANDLE_TABLE_ENTRY",
                8,
                json!({"Object":field(0),"GrantedAccess":field(4)}),
            ),
            (
                "_OBJECT_HEADER",
                40,
                json!({"TypeIndex":field(0),"InfoMask":field(4),"Body":field(32)}),
            ),
            (
                "_OBJECT_TYPE",
                16,
                json!({"Name":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}),
            ),
        ] {
            isf.data["user_types"][name] = json!({"size":size,"fields":fields});
        }
        isf.data["symbols"]["ObTypeIndexTable"] = json!({"address":0x9000});
        let put32 = |b: &mut [u8], at: usize, n: u64| {
            b[at..at + 4].copy_from_slice(&(n as u32).to_le_bytes())
        };
        b[0x1000..0x2000].fill(0);
        b[0x3000..0x4000].fill(0);
        put32(&mut b, 0x1000 + 512 * 4, 0x3003);
        for i in 0..32 {
            put32(&mut b, 0x3000 + i * 4, 0x8003 + i as u64 * 4096);
        }
        put32(&mut b, 0x9050, k + 0x4000);
        put32(&mut b, 0xc000, k + 0x5002);
        // The first 1024 leaf slots are empty. Slot 1024 follows root[1], then row[0].
        put32(&mut b, 0xc004, (512 * 1024 + 1) * 4);
        put32(&mut b, 0xd004, k + 0x6000);
        put32(&mut b, 0xe000, k + 0x7000);
        put32(&mut b, 0xf000, k + 0x8003);
        put32(&mut b, 0xf004, 0x123);
        put32(&mut b, 0x10000, 7);
        put32(&mut b, 0x11000 + 7 * 4, k + 0xa000);
        b[0x12000..0x12004].copy_from_slice(&[10, 0, 10, 0]);
        put32(&mut b, 0x12008, k + 0xb000);
        for (i, c) in "Event".encode_utf16().enumerate() {
            b[0x13000 + i * 2..0x13002 + i * 2].copy_from_slice(&c.to_le_bytes());
        }
        let img = image(&b);
        let engine = Windows {
            vm: Memory {
                image: &img,
                root: 0x1000,
                isf: &isf,
                sources: None,
            },
            base: k,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let p = engine.process(k + 0x1000).unwrap();
        let mut result = engine.result(Plugin::WinHandles);
        engine.handles(&p, &mut result, &Job::default()).unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][2], hex(512 * 1024 * 4));
        assert_eq!(result.rows[0][3], "Event");
        assert_eq!(result.rows[0][5], "0x123");
    }
}
