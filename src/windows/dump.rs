use super::memory::protection;
use super::*;
use sha2::{Digest, Sha256};
use std::io::Write;
impl Windows<'_> {
    pub(super) fn run_dump(&self, p: Plugin, options: &DumpOptions, job: &Job) -> Result<Results> {
        options.validate(p)?;
        if p == Plugin::WinModdump {
            return self.run_moddump(options, job);
        }
        let (processes, diagnostics) = self.processes_partial(job)?;
        let process = processes
            .into_iter()
            .find(|p| p.pid == u64::from(options.pid))
            .context("目标 PID 不存在")?;
        let vm = self.process_memory(&process)?;
        let mut r = self.result(p);
        r.complete = diagnostics.is_empty();
        r.diagnostics = diagnostics;
        match p {
            Plugin::WinVaddump => return self.run_vaddump(&process, &vm, options, r, job),
            Plugin::WinDlldump => return self.run_dlldump(&process, &vm, options, r, job),
            _ => {}
        }
        let mut regions = if p == Plugin::WinMemdump {
            vec![(
                options.start.context("range 需要 start")?,
                options.end.context("range 需要 end")?,
            )]
        } else {
            self.vads(&process, job)?
                .into_iter()
                .filter(|v| v.protection & 7 != 0)
                .map(|v| (v.start, v.end))
                .collect()
        };
        if p == Plugin::WinProcdump
            && let (Some(start), Some(end)) = (options.start, options.end)
        {
            regions = regions
                .into_iter()
                .filter_map(|(a, b)| {
                    let a = a.max(start);
                    let b = b.min(end);
                    (a < b).then_some((a, b))
                })
                .collect();
        }
        if p == Plugin::WinPedump {
            let mut candidates: BTreeMap<u64, u64> = regions.into_iter().collect();
            match self.dlls(&process, job, &mut r) {
                Ok(dlls) => {
                    for (base, size, _, _) in dlls {
                        candidates.insert(base, add(base, size)?);
                    }
                }
                Err(e) => Self::issue(&mut r, "DLL 转储候选", e),
            }
            regions = candidates.into_iter().collect();
        }
        crate::dump::directory(&options.directory)?;
        let mut total = 0u64;
        for (start, end) in regions {
            job.check()?;
            if p == Plugin::WinPedump {
                let mut magic = [0; 2];
                if vm.read(start, &mut magic).is_err() || magic != *b"MZ" {
                    continue;
                }
            }
            let read = (|| -> Result<Vec<String>> {
                let mut tmp = tempfile::NamedTempFile::new_in(&options.directory)?;
                let mut hash = Sha256::new();
                let size = if p == Plugin::WinPedump {
                    self.write_pe(&vm, start, &mut tmp, &mut hash, job)?
                } else {
                    let size = end.checked_sub(start).context("转储地址倒置")?;
                    ensure!(
                        total
                            .checked_add(size)
                            .is_some_and(|n| n <= crate::dump::MAX_DUMP_BYTES),
                        "转储超过 256 MiB 限制"
                    );
                    write_region(&vm, start, size, &mut tmp, &mut hash, job)?;
                    size
                };
                ensure!(
                    total
                        .checked_add(size)
                        .is_some_and(|n| n <= crate::dump::MAX_DUMP_BYTES),
                    "转储超过 256 MiB 限制"
                );
                job.check()?;
                tmp.as_file().sync_all()?;
                let digest = format!("{:x}", hash.finalize());
                let target = options.directory.join(format!(
                    "windows-pid{}-{start:016x}-{}.{}",
                    process.pid,
                    &digest[..16],
                    if p == Plugin::WinPedump { "pe" } else { "bin" }
                ));
                if target.exists() {
                    ensure!(
                        std::fs::read(&target)? == std::fs::read(tmp.path())?,
                        "已有同名转储内容不同"
                    );
                } else {
                    tmp.persist(&target).map_err(|e| e.error)?;
                }
                total += size;
                Ok(vec![
                    process.pid.to_string(),
                    process.name.clone(),
                    hex(start),
                    hex(end),
                    size.to_string(),
                    digest,
                    target.display().to_string(),
                ])
            })();
            match read {
                Ok(row) => r.rows.push(row),
                Err(e) => {
                    job.check()?;
                    Self::issue(
                        &mut r,
                        format!("PID {} range {start:#x}..{end:#x}", process.pid),
                        format!("{e:#}"),
                    );
                }
            }
        }
        Ok(r)
    }
    /// 落盘已写入并哈希的临时文件；同名已存在时要求内容一致。
    fn persist_dump(
        tmp: tempfile::NamedTempFile,
        directory: &std::path::Path,
        name: &str,
    ) -> Result<String> {
        let target = directory.join(name);
        if target.exists() {
            ensure!(
                std::fs::read(&target)? == std::fs::read(tmp.path())?,
                "已有同名转储内容不同"
            );
        } else {
            tmp.persist(&target).map_err(|e| e.error)?;
        }
        Ok(target.display().to_string())
    }
    fn account(total: &mut u64, size: u64) -> Result<()> {
        ensure!(
            total
                .checked_add(size)
                .is_some_and(|n| n <= crate::dump::MAX_DUMP_BYTES),
            "转储超过 256 MiB 限制"
        );
        *total += size;
        Ok(())
    }
    /// windows.vaddump：进程全部 VAD 的逐段原始转储（可选用 start/end 相交过滤）。
    fn run_vaddump(
        &self,
        process: &Process,
        vm: &Memory<'_>,
        options: &DumpOptions,
        mut r: Results,
        job: &Job,
    ) -> Result<Results> {
        crate::dump::directory(&options.directory)?;
        let mut total = 0u64;
        let vads = match self.vads(process, job) {
            Ok(vads) => vads,
            Err(e) => {
                Self::issue(&mut r, format!("PID {} VAD 树", process.pid), e);
                return Ok(r);
            }
        };
        for v in vads {
            job.check()?;
            let (start, end) = match (options.start, options.end) {
                (Some(lo), Some(hi)) => (v.start.max(lo), v.end.min(hi)),
                _ => (v.start, v.end),
            };
            if start >= end {
                continue;
            }
            let write = (|| -> Result<Vec<String>> {
                let mut tmp = tempfile::NamedTempFile::new_in(&options.directory)?;
                let mut hash = Sha256::new();
                let size = end - start;
                Self::account(&mut total, size)?;
                write_region(vm, start, size, &mut tmp, &mut hash, job)?;
                job.check()?;
                tmp.as_file().sync_all()?;
                let digest = format!("{:x}", hash.finalize());
                let file = Self::persist_dump(
                    tmp,
                    &options.directory,
                    &format!(
                        "windows-vad-pid{}-{start:016x}-{end:016x}-{}.bin",
                        process.pid,
                        &digest[..16]
                    ),
                )?;
                Ok(vec![
                    process.pid.to_string(),
                    process.name.clone(),
                    hex(start),
                    hex(end),
                    size.to_string(),
                    protection(v.protection),
                    v.private.to_string(),
                    v.path.clone(),
                    digest,
                    file,
                ])
            })();
            match write {
                Ok(row) => r.rows.push(row),
                Err(e) => {
                    job.check()?;
                    Self::issue(
                        &mut r,
                        format!("PID {} VAD {:#x}", process.pid, v.address),
                        e,
                    );
                }
            }
        }
        Ok(r)
    }
    /// windows.dlldump：按模块列表重建导出进程 DLL（start 为可选精确基址）。
    fn run_dlldump(
        &self,
        process: &Process,
        vm: &Memory<'_>,
        options: &DumpOptions,
        mut r: Results,
        job: &Job,
    ) -> Result<Results> {
        let mut dlls = self.dlls(process, job, &mut r)?;
        if let Some(base) = options.start {
            dlls.retain(|(candidate, ..)| *candidate == base);
            ensure!(!dlls.is_empty(), "DLL 基址 {base:#x} 不在进程模块列表中");
        }
        crate::dump::directory(&options.directory)?;
        let mut total = 0u64;
        for (base, size, path, view) in dlls {
            job.check()?;
            let mut magic = [0; 2];
            if vm.read(base, &mut magic).is_err() || magic != *b"MZ" {
                Self::issue(
                    &mut r,
                    format!("DLL {base:#x}"),
                    anyhow::anyhow!("基址处无 MZ 头"),
                );
                continue;
            }
            let write = (|| -> Result<Vec<String>> {
                let mut tmp = tempfile::NamedTempFile::new_in(&options.directory)?;
                let mut hash = Sha256::new();
                let written = self.write_pe(vm, base, &mut tmp, &mut hash, job)?;
                Self::account(&mut total, written)?;
                job.check()?;
                tmp.as_file().sync_all()?;
                let digest = format!("{:x}", hash.finalize());
                let file = Self::persist_dump(
                    tmp,
                    &options.directory,
                    &format!(
                        "windows-dll-pid{}-{}-{base:016x}-{}.pe",
                        process.pid,
                        sanitized_component(&path),
                        &digest[..16]
                    ),
                )?;
                Ok(vec![
                    process.pid.to_string(),
                    process.name.clone(),
                    sanitized_component(&path),
                    hex(base),
                    size.to_string(),
                    view,
                    digest,
                    file,
                ])
            })();
            match write {
                Ok(row) => r.rows.push(row),
                Err(e) => {
                    job.check()?;
                    Self::issue(&mut r, format!("PID {} DLL {base:#x}", process.pid), e);
                }
            }
        }
        Ok(r)
    }
    /// windows.moddump：重建导出内核模块（内核地址空间，start 为可选精确基址）。
    fn run_moddump(&self, options: &DumpOptions, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinModdump);
        let mut modules = self.modules_partial(job, &mut r)?;
        if let Some(base) = options.start {
            modules.retain(|module| module.base == base);
            ensure!(
                !modules.is_empty(),
                "模块基址 {base:#x} 不在 PsLoadedModuleList 中"
            );
        }
        crate::dump::directory(&options.directory)?;
        let mut total = 0u64;
        for module in modules {
            job.check()?;
            let write = (|| -> Result<Vec<String>> {
                let mut magic = [0; 2];
                self.vm.read(module.base, &mut magic)?;
                ensure!(magic == *b"MZ", "模块基址处无 MZ 头");
                let mut tmp = tempfile::NamedTempFile::new_in(&options.directory)?;
                let mut hash = Sha256::new();
                let size = reconstruct_pe(
                    &mut |address, bytes| self.vm.read(address, bytes),
                    module.base,
                    &mut tmp,
                    &mut hash,
                    job,
                )?;
                Self::account(&mut total, size)?;
                job.check()?;
                tmp.as_file().sync_all()?;
                let digest = format!("{:x}", hash.finalize());
                let file = Self::persist_dump(
                    tmp,
                    &options.directory,
                    &format!(
                        "windows-mod-{}-{:#x}-{}.pe",
                        sanitized_component(&module.name),
                        module.base,
                        &digest[..16]
                    ),
                )?;
                Ok(vec![
                    module.name.clone(),
                    hex(module.base),
                    size.to_string(),
                    module.path.clone(),
                    digest,
                    file,
                ])
            })();
            match write {
                Ok(row) => r.rows.push(row),
                Err(e) => {
                    job.check()?;
                    Self::issue(&mut r, format!("模块 {:#x}", module.base), e);
                }
            }
        }
        Ok(r)
    }
    fn write_pe(
        &self,
        vm: &Memory<'_>,
        base: u64,
        file: &mut impl Write,
        hash: &mut Sha256,
        job: &Job,
    ) -> Result<u64> {
        reconstruct_pe(
            &mut |address, bytes| vm.read(address, bytes),
            base,
            file,
            hash,
            job,
        )
    }
}
pub(super) fn reconstruct_pe(
    read: &mut dyn FnMut(u64, &mut [u8]) -> Result<()>,
    base: u64,
    file: &mut impl Write,
    hash: &mut Sha256,
    job: &Job,
) -> Result<u64> {
    let mut b = [0; 4096];
    read(base, &mut b)?;
    let (image_size, _) = pe_header(&b)?;
    let pe = u32::from_le_bytes(b[60..64].try_into()?) as usize;
    let sections = u16::from_le_bytes(b[pe + 6..pe + 8].try_into()?) as usize;
    let optional = u16::from_le_bytes(b[pe + 20..pe + 22].try_into()?) as usize;
    ensure!(
        sections <= 96 && pe + 24 + optional + sections * 40 <= 4096,
        "PE 节表越界"
    );
    let headers = u32::from_le_bytes(b[pe + 84..pe + 88].try_into()?) as u64;
    ensure!(
        headers <= 4096 && headers >= ((pe + 24 + optional + sections * 40) as u64),
        "PE SizeOfHeaders 无效"
    );
    let mut ranges = vec![(0, headers, 0)];
    let mut size = headers;
    for i in 0..sections {
        let section = pe + 24 + optional + i * 40;
        let rva = u32::from_le_bytes(b[section + 12..section + 16].try_into()?) as u64;
        let len = u32::from_le_bytes(b[section + 16..section + 20].try_into()?) as u64;
        let raw = u32::from_le_bytes(b[section + 20..section + 24].try_into()?) as u64;
        if len == 0 {
            continue;
        }
        ensure!(
            rva.checked_add(len)
                .is_some_and(|end| end <= u64::from(image_size)),
            "PE section VA 越界"
        );
        ensure!(raw >= headers, "PE section 与头重叠");
        size = size.max(raw.checked_add(len).context("PE 大小溢出")?);
        ranges.push((raw, len, rva));
    }
    ensure!(size <= crate::dump::MAX_DUMP_BYTES, "PE 转储超过限制");
    ranges.sort_unstable();
    ensure!(
        ranges.windows(2).all(|r| r[0].0 + r[0].1 <= r[1].0),
        "PE raw sections 重叠"
    );
    let mut position = 0;
    let zeros = [0; 4096];
    for (raw, len, rva) in ranges {
        while position < raw {
            job.check()?;
            let n = ((raw - position) as usize).min(zeros.len());
            file.write_all(&zeros[..n])?;
            hash.update(&zeros[..n]);
            position += n as u64;
        }
        write_reader(read, add(base, rva)?, len, file, hash, job)?;
        position += len;
    }
    Ok(size)
}
fn write_region(
    vm: &Memory<'_>,
    address: u64,
    size: u64,
    file: &mut impl Write,
    hash: &mut Sha256,
    job: &Job,
) -> Result<()> {
    write_reader(
        &mut |address, bytes| vm.read(address, bytes),
        address,
        size,
        file,
        hash,
        job,
    )
}
/// 路径 basename 净化为文件名组件（保留 ASCII 字母数字与 . _ -，截 64 字符）。
fn sanitized_component(path: &str) -> String {
    let base = path.rsplit(['\\', '/']).next().unwrap_or(path);
    let mut out: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    out.truncate(64);
    if out.is_empty() {
        out.push('_');
    }
    out
}
pub(super) fn write_reader(
    read: &mut dyn FnMut(u64, &mut [u8]) -> Result<()>,
    mut address: u64,
    mut size: u64,
    file: &mut impl Write,
    hash: &mut Sha256,
    job: &Job,
) -> Result<()> {
    let mut b = vec![0; 1024 * 1024];
    while size > 0 {
        job.check()?;
        let n = (size as usize).min(b.len());
        read(address, &mut b[..n])?;
        file.write_all(&b[..n])?;
        hash.update(&b[..n]);
        address += n as u64;
        size -= n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    #[test]
    fn pe_reconstruction_preserves_headers_sections_and_hash() {
        let (mut b, isf) = fixture();
        b[0x8086..0x8088].copy_from_slice(&1u16.to_le_bytes());
        b[0x8094..0x8096].copy_from_slice(&240u16.to_le_bytes());
        b[0x80d4..0x80d8].copy_from_slice(&512u32.to_le_bytes());
        let section = 0x8188;
        b[section + 12..section + 16].copy_from_slice(&0x3000u32.to_le_bytes());
        b[section + 16..section + 20].copy_from_slice(&512u32.to_le_bytes());
        b[section + 20..section + 24].copy_from_slice(&512u32.to_le_bytes());
        b[0xb000..0xb200].fill(0x5a);
        let image = image(&b);
        let engine = Windows {
            vm: Memory::new(&image, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let mut out = Vec::new();
        let mut hash = Sha256::new();
        assert_eq!(
            engine
                .write_pe(&engine.vm, K, &mut out, &mut hash, &Job::default())
                .unwrap(),
            1024
        );
        assert_eq!(&out[..512], &b[0x8000..0x8200]);
        assert_eq!(&out[512..], &b[0xb000..0xb200]);
        assert_eq!(hash.finalize().as_slice(), Sha256::digest(&out).as_slice());
    }

    #[test]
    fn sanitized_component_keeps_only_file_name_characters() {
        assert_eq!(
            sanitized_component(r"C:\Windows\System32\nt dll.dll"),
            "nt_dll.dll"
        );
        assert_eq!(sanitized_component("中文.dll"), "__.dll");
        assert_eq!(sanitized_component("/bare"), "bare");
        assert_eq!(sanitized_component(""), "_");
        assert_eq!(sanitized_component("==="), "___");
        assert_eq!(sanitized_component(&"x".repeat(80)).len(), 64);
    }

    #[test]
    fn moddump_reconstructs_the_listed_kernel_module() {
        let (mut b, mut isf) = fixture();
        // 让 fixture 内置 PE 可重建：一节、头 512 字节（同 pe_reconstruction 测试）。
        b[0x8086..0x8088].copy_from_slice(&1u16.to_le_bytes());
        b[0x8094..0x8096].copy_from_slice(&240u16.to_le_bytes());
        b[0x80d4..0x80d8].copy_from_slice(&512u32.to_le_bytes());
        let section = 0x8188;
        b[section + 12..section + 16].copy_from_slice(&0x3000u32.to_le_bytes());
        b[section + 16..section + 20].copy_from_slice(&512u32.to_le_bytes());
        b[section + 20..section + 24].copy_from_slice(&512u32.to_le_bytes());
        b[0xb000..0xb200].fill(0x5a);
        isf.data["user_types"]["_KLDR_DATA_TABLE_ENTRY"] = serde_json::json!({
            "size": 64,
            "fields": {
                "InLoadOrderLinks": {"offset": 0, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
                "DllBase": {"offset": 16, "type": {"kind": "pointer"}},
                "SizeOfImage": {"offset": 24, "type": {"kind": "base", "name": "u64"}},
                "BaseDllName": {"offset": 32, "type": {"kind": "struct", "name": "_UNICODE_STRING"}},
                "FullDllName": {"offset": 48, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
            }
        });
        isf.invalidate_layouts();
        // 空模块表头（物理 0x8700）改指一条目 @K+0x1d000（物理 0x25000）。
        let entry = 0x25000;
        put(&mut b, 0x8700, K + 0x1d000);
        put(&mut b, 0x8708, K + 0x1d000);
        put(&mut b, entry, K + 0x700);
        put(&mut b, entry + 8, K + 0x700);
        put(&mut b, entry + 16, K);
        put(&mut b, entry + 24, 0x8000);
        let utf16 =
            |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let name = utf16("ntoskrnl.exe");
        let path = utf16(r"\SystemRoot\system32\ntoskrnl.exe");
        b[0x25200..0x25200 + name.len()].copy_from_slice(&name);
        b[0x25240..0x25240 + path.len()].copy_from_slice(&path);
        b[entry + 32..entry + 34].copy_from_slice(&(name.len() as u16).to_le_bytes());
        b[entry + 34..entry + 36].copy_from_slice(&((name.len() + 2) as u16).to_le_bytes());
        put(&mut b, entry + 40, K + 0x1d200);
        b[entry + 48..entry + 50].copy_from_slice(&(path.len() as u16).to_le_bytes());
        b[entry + 50..entry + 52].copy_from_slice(&((path.len() + 2) as u16).to_le_bytes());
        put(&mut b, entry + 56, K + 0x1d240);
        let image = image(&b);
        let engine = Windows {
            vm: Memory::new(&image, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let dir = tempfile::tempdir().unwrap();
        let options = DumpOptions {
            pid: 0,
            directory: dir.path().into(),
            start: None,
            end: None,
        };
        let r = engine
            .run_dump(Plugin::WinModdump, &options, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 1);
        let row = &r.rows[0];
        assert_eq!(row[0], "ntoskrnl.exe");
        assert_eq!(row[1], hex(K));
        assert_eq!(row[2], "1024");
        assert_eq!(row[3], r"\SystemRoot\system32\ntoskrnl.exe");
        let mut expected = b[0x8000..0x8200].to_vec();
        expected.extend_from_slice(&b[0xb000..0xb200]);
        assert_eq!(row[4], format!("{:x}", Sha256::digest(&expected)));
        assert_eq!(std::fs::read(&row[5]).unwrap(), expected);
        assert!(
            row[5]
                .rsplit('/')
                .next()
                .unwrap()
                .starts_with("windows-mod-ntoskrnl.exe-0xffff800000000000-")
        );
    }

    #[test]
    fn vaddump_writes_each_vad_region_to_its_own_file() {
        let (mut b, mut isf) = fixture();
        isf.data["user_types"]["_EPROCESS"]["fields"]["VadRoot"] =
            serde_json::json!({"offset": 120, "type": {"kind": "pointer"}});
        isf.data["user_types"]["_RTL_BALANCED_NODE"] = serde_json::json!({
            "size": 24,
            "fields": {
                "LeftChild": {"offset": 0, "type": {"kind": "pointer"}},
                "RightChild": {"offset": 8, "type": {"kind": "pointer"}},
                "ParentValue": {"offset": 16, "type": {"kind": "pointer"}}
            }
        });
        isf.data["user_types"]["_MMVAD_SHORT"] = serde_json::json!({
            "size": 56,
            "fields": {
                "VadNode": {"offset": 0, "type": {"kind": "struct", "name": "_RTL_BALANCED_NODE"}},
                "StartingVpn": {"offset": 24, "type": {"kind": "base", "name": "u64"}},
                "EndingVpn": {"offset": 32, "type": {"kind": "base", "name": "u64"}},
                "u": {"offset": 40, "type": {"kind": "struct", "name": "_MMVAD_FLAGS"}}
            }
        });
        isf.data["user_types"]["_MMVAD_FLAGS"] = serde_json::json!({
            "size": 16,
            "fields": {
                "Protection": {"offset": 0, "type": {"kind": "base", "name": "u64"}},
                "PrivateMemory": {"offset": 8, "type": {"kind": "base", "name": "u64"}}
            }
        });
        isf.invalidate_layouts();
        // 用户 VA 0x9000 经 PML4[0] 复用内核 PT@0x4000 映射到物理 0x11000。
        put(&mut b, 0x1000, 0x2003);
        for (i, slot) in b[0x11000..0x12000].iter_mut().enumerate() {
            *slot = (i % 251) as u8;
        }
        // 单节点 VAD 树 @K+0x1e000（物理 0x26000），child 进程 VadRoot 指向它。
        let node = 0x26000;
        put(&mut b, node + 16, K + 0x1e000);
        put(&mut b, node + 24, 9);
        put(&mut b, node + 32, 9);
        put(&mut b, node + 40, 4);
        put(&mut b, node + 48, 1);
        put(&mut b, 0xa000 + 120, K + 0x1e000);
        let image = image(&b);
        let engine = Windows {
            vm: Memory::new(&image, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let dir = tempfile::tempdir().unwrap();
        let options = DumpOptions {
            pid: 8,
            directory: dir.path().into(),
            start: None,
            end: None,
        };
        let r = engine
            .run_dump(Plugin::WinVaddump, &options, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 1);
        let row = &r.rows[0];
        assert_eq!(&row[..2], &["8", "child"]);
        assert_eq!(row[2], hex(0x9000));
        assert_eq!(row[3], hex(0xa000));
        assert_eq!(row[4], "4096");
        assert_eq!(row[5], "PAGE_READWRITE");
        assert_eq!(row[6], "true");
        assert_eq!(row[7], "");
        assert_eq!(
            row[8],
            format!("{:x}", Sha256::digest(&b[0x11000..0x12000]))
        );
        assert_eq!(std::fs::read(&row[9]).unwrap(), b[0x11000..0x12000]);
    }
}
