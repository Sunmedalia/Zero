//! Volatility-compatible Linux ELF mapping & shared library listings
//! (`linux.elfs.Elfs` and `linux.library_list.LibraryList`).
use super::*;
use crate::analysis::Options;
use crate::dump::DumpOptions;
use std::collections::BTreeSet;
use std::io::{Seek, SeekFrom, Write};

const PT_LOAD: u64 = 1;
const PT_DYNAMIC: u64 = 2;
const DT_PLTGOT: u64 = 3;
const DT_DEBUG: u64 = 21;

#[derive(Clone, Copy)]
struct ElfFormat {
    width: usize,
    little_endian: bool,
}

impl ElfFormat {
    fn word(self, bytes: &[u8], offset: usize, width: usize) -> Result<u64> {
        let mut raw = [0; 8];
        let field = bytes.at(offset..offset + width)?;
        if self.little_endian {
            raw.at_mut(..width)?.copy_from_slice(field);
            Ok(u64::from_le_bytes(raw))
        } else {
            raw.at_mut(8 - width..)?.copy_from_slice(field);
            Ok(u64::from_be_bytes(raw))
        }
    }

    fn pointer(self, vm: &VirtualMemory<'_>, address: u64) -> Result<u64> {
        let mut raw = [0; 8];
        vm.read(address, raw.at_mut(..self.width)?)?;
        self.word(&raw, 0, self.width)
    }
}

struct ProgramHeader {
    kind: u64,
    file_offset: u64,
    address: u64,
    file_size: u64,
    memory_size: u64,
}

struct MappedElf {
    format: ElfFormat,
    start: u64,
    headers: Vec<ProgramHeader>,
    base: Option<u64>,
    headers_end: u64,
}

impl MappedElf {
    fn read(vm: &VirtualMemory<'_>, start: u64, job: &Job) -> Result<Option<Self>> {
        let mut ident = [0; 16];
        if vm.read(start, &mut ident).is_err() || ident.at(..4)? != b"\x7fELF" {
            return Ok(None);
        }
        let width = match ident.at(4)? {
            1 => 4,
            2 => 8,
            _ => bail!("ELF class 无效"),
        };
        let little_endian = match ident.at(5)? {
            1 => true,
            2 => false,
            _ => bail!("ELF 字节序无效"),
        };
        ensure!(*ident.at(6)? == 1, "ELF 版本无效");
        let format = ElfFormat {
            width,
            little_endian,
        };
        let (header_size, phoff, phentsize, phnum, expected) = if width == 4 {
            (52, 28, 42, 44, 32)
        } else {
            (64, 32, 54, 56, 56)
        };
        let mut raw = [0; 64];
        vm.read(start, raw.at_mut(..header_size)?)?;
        let offset = format.word(&raw, phoff, width)?;
        let entry_size = format.word(&raw, phentsize, 2)?;
        let count = format.word(&raw, phnum, 2)?;
        ensure!(count <= 4096, "ELF 程序头数量超过上限");
        ensure!(
            count == 0 || (entry_size == expected as u64 && offset >= header_size as u64),
            "ELF 程序头布局无效"
        );
        let mut headers = Vec::new();
        for index in 0..count {
            job.check()?;
            vm.read(
                add(add(start, offset)?, index * entry_size)?,
                raw.at_mut(..expected)?,
            )?;
            let (file_offset, address, file_size, memory_size) = if width == 4 {
                (4, 8, 16, 20)
            } else {
                (8, 16, 32, 40)
            };
            headers.push(ProgramHeader {
                kind: format.word(&raw, 0, 4)?,
                file_offset: format.word(&raw, file_offset, width)?,
                address: format.word(&raw, address, width)?,
                file_size: format.word(&raw, file_size, width)?,
                memory_size: format.word(&raw, memory_size, width)?,
            });
        }
        let base = headers
            .iter()
            .filter(|header| header.kind == PT_LOAD && header.file_offset == 0)
            .map(|header| header.address & !4095)
            .min();
        Ok(Some(Self {
            format,
            start,
            headers,
            base,
            headers_end: add(offset, count * entry_size)?.max(header_size as u64),
        }))
    }

    fn mapped_address(&self, address: u64) -> Result<u64> {
        let base = self.base.context("ELF 缺少映射文件头的 PT_LOAD")?;
        // ET_EXEC has absolute p_vaddr values, while PIE typically starts at 0.
        add(
            self.start,
            address
                .checked_sub(base)
                .context("ELF 段位于映射基址之前")?,
        )
    }

    fn load_ranges(&self) -> Result<Vec<(u64, u64)>> {
        let mut raw = Vec::new();
        for header in &self.headers {
            if header.kind != PT_LOAD || header.memory_size == 0 {
                continue;
            }
            ensure!(
                header.file_size <= header.memory_size,
                "ELF PT_LOAD 文件大小超过内存大小"
            );
            let address = self.mapped_address(header.address)?;
            let start = address & !4095;
            let end = add(add(address, header.memory_size)?, 4095)? & !4095;
            raw.push((start, end));
        }
        ensure!(!raw.is_empty(), "ELF 缺少可导出的 PT_LOAD");
        raw.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(raw.len());
        for (start, end) in raw {
            if let Some((_, prev_end)) = merged.last_mut()
                && start <= *prev_end
            {
                *prev_end = (*prev_end).max(end);
            } else {
                merged.push((start, end));
            }
        }
        Ok(merged)
    }

    fn link_map_heads(&self, vm: &VirtualMemory<'_>, job: &Job) -> Result<Vec<u64>> {
        let width = self.format.width as u64;
        let mut heads = Vec::new();
        for header in &self.headers {
            if header.kind != PT_DYNAMIC || header.file_size == 0 {
                continue;
            }
            let start = self.mapped_address(header.address)?;
            let count = header.file_size / (2 * width);
            ensure!(count <= 4096, "ELF 动态表超过上限");
            for index in 0..count {
                job.check()?;
                let at = add(start, index * 2 * width)?;
                let tag = self.format.pointer(vm, at)?;
                if tag == 0 {
                    break;
                }
                if matches!(tag, DT_DEBUG | DT_PLTGOT) {
                    let pointer = self.format.pointer(vm, add(at, width)?)?;
                    if pointer != 0
                        && let Ok(head) =
                            add(pointer, width).and_then(|at| self.format.pointer(vm, at))
                        && head != 0
                    {
                        // r_debug.r_map and the second GOT entry both sit one word in.
                        heads.push(head);
                    }
                }
            }
        }
        Ok(heads)
    }
}

fn link_map_name(vm: &VirtualMemory<'_>, mut address: u64) -> Result<String> {
    let mut name = Vec::new();
    let mut buf = [0; 256];
    while name.len() < 4096 {
        let count = (4096 - usize::try_from(address & 4095)?)
            .min(buf.len())
            .min(4096 - name.len());
        let bytes = buf.at_mut(..count)?;
        vm.read(address, bytes)?;
        if let Some(end) = bytes.iter().position(|byte| *byte == 0) {
            name.extend_from_slice(bytes.at(..end)?);
            return Ok(String::from_utf8_lossy(&name).into_owned());
        }
        name.extend_from_slice(bytes);
        address = add(address, count as u64)?;
    }
    bail!("ELF link_map 路径超过上限")
}

impl Linux<'_> {
    fn resolve_vma_file_path(
        &self,
        task: &Task,
        root: Option<(u64, u64)>,
        file: u64,
        node: u64,
        result: &mut Results,
        job: &Job,
    ) -> String {
        if file == 0 {
            return "Anonymous Mapping".into();
        }
        let mut resolved = match root.map_or_else(
            || self.file_path(task.address, file, job),
            |root| self.file_path_from(root, file, job),
        ) {
            Ok(p) => p,
            Err(error) if error.to_string().starts_with("路径不在进程根目录内") => {
                match self
                    .number(file, "file", "f_path.dentry")
                    .and_then(|d| Ok((d, self.number(file, "file", "f_path.mnt")?)))
                    .and_then(|(d, m)| self.resolve_path(d, m, None, job))
                {
                    Ok(p) => p,
                    Err(e) => {
                        partial(
                            result,
                            format!("PID {} VMA {} 路径", task.pid, hex(node)),
                            e,
                        );
                        "[unresolved]".into()
                    }
                }
            }
            Err(error) => {
                partial(
                    result,
                    format!("PID {} VMA {} 路径", task.pid, hex(node)),
                    error,
                );
                "[unresolved]".into()
            }
        };
        if resolved != "[unresolved]"
            && self
                .inode(file)
                .ok()
                .and_then(|ino| self.number(ino, "inode", "i_nlink").ok())
                .is_some_and(|n| n == 0)
        {
            resolved.push_str(" (deleted)");
        }
        resolved
    }

    pub(super) fn write_main_executable(
        vm: &VirtualMemory<'_>,
        mappings: &[(u64, u64, u64)], // (start, end, file offset), sorted by start
        target: &std::path::Path,
        budget: u64,
        job: &Job,
    ) -> Result<(u64, u64)> {
        let start = mappings
            .iter()
            .find(|&&(_, _, offset)| offset == 0)
            .map(|&(start, _, _)| start)
            .context("主程序没有文件偏移为零的映射")?;
        let elf = MappedElf::read(vm, start, job)?.context("主程序 ELF 文件头不可读")?;
        let mut size = 0;
        let mut bytes_to_read = 0;
        let mut segments = Vec::new();
        for header in &elf.headers {
            if header.kind != PT_LOAD || header.file_size == 0 {
                continue;
            }
            ensure!(
                header.file_size <= header.memory_size,
                "ELF PT_LOAD 文件大小超过内存大小"
            );
            size = size.max(add(header.file_offset, header.file_size)?);
            bytes_to_read = add(bytes_to_read, header.file_size)?;
            let address = elf.mapped_address(header.address)?;
            add(address, header.file_size)?;
            segments.push((header.file_offset, address, header.file_size));
        }
        ensure!(
            size != 0 && size <= budget && bytes_to_read <= budget,
            "主程序 ELF 转储为空或超过累计上限"
        );
        ensure!(
            segments.iter().any(|&(offset, address, len)| offset == 0
                && address == start
                && len >= elf.headers_end),
            "主程序 ELF 文件头不在加载段内"
        );
        let parent = target.parent().context("导出路径缺少父目录")?;
        crate::dump::directory(parent)?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        let mut missing = 0;
        for (offset, address, length) in segments {
            tmp.seek(SeekFrom::Start(offset))?;
            let mut done = 0;
            let mut buffer = [0; 4096];
            while done < length {
                job.check()?;
                let at = address + done;
                let count = usize::try_from((length - done).min(4096 - (at & 4095)))?;
                let chunk = buffer.at_mut(..count)?;
                let matches_file = mappings
                    .partition_point(|&(first, _, _)| first <= at)
                    .checked_sub(1)
                    .and_then(|index| mappings.get(index))
                    .is_some_and(|&(first, end, file_offset)| {
                        at + count as u64 <= end
                            && file_offset.checked_add(at - first) == Some(offset + done)
                    });
                if !matches_file || vm.read(at, chunk).is_err() {
                    ensure!(offset + done >= elf.headers_end, "主程序 ELF 文件头不可读");
                    chunk.fill(0);
                    missing += 1;
                }
                tmp.write_all(chunk)?;
                done += count as u64;
            }
        }
        job.check()?;
        tmp.as_file().sync_all()?;
        job.check()?;
        tmp.persist_noclobber(target).map_err(|e| e.error)?;
        Ok((size, missing))
    }

    pub(super) fn linux_elfs(
        &self,
        options: &Options,
        dump: Option<&DumpOptions>,
        job: &Job,
    ) -> Result<Results> {
        let pids: BTreeSet<u32> = options.pids.iter().copied().chain(options.pid).collect();
        let (mut result, tasks) = self.task_identities(Plugin::LinuxElfs, job)?;

        for task in tasks {
            job.check()?;
            if !pids.is_empty() && !task.pid.parse::<u32>().is_ok_and(|pid| pids.contains(&pid)) {
                continue;
            }
            let addr = task.address;
            let read = (|| -> Result<()> {
                let mm = self.number(addr, "task_struct", "mm")?;
                if mm == 0 {
                    return Ok(());
                }
                let Some(vm) = self.process_vm(addr)? else {
                    return Ok(());
                };
                let nodes = self.vma_nodes(mm, job, &mut result)?;
                let root = self.process_root(addr).ok();

                for node in nodes {
                    job.check()?;
                    let scan = (|| -> Result<()> {
                        let start = self.number(node, "vm_area_struct", "vm_start")?;
                        let end = self.number(node, "vm_area_struct", "vm_end")?;
                        ensure!(start < end, "VMA 地址倒置");
                        let mut magic = [0; 4];
                        if vm.read(start, &mut magic).is_err() || &magic != b"\x7fELF" {
                            return Ok(());
                        }
                        let file = self.number(node, "vm_area_struct", "vm_file")?;
                        let path =
                            self.resolve_vma_file_path(&task, root, file, node, &mut result, job);
                        let file_output = if let Some(dump) = dump {
                            let exported = MappedElf::read(&vm, start, job)
                                .and_then(|elf| elf.context("ELF 文件头不可读"))
                                .and_then(|elf| {
                                    Self::dump_elf(&vm, &elf, &task.pid, dump, &mut result, job)
                                });
                            match exported {
                                Ok(name) => name,
                                Err(error) => {
                                    job.check()?;
                                    partial(
                                        &mut result,
                                        format!("PID {} ELF {} 导出", task.pid, hex(start)),
                                        error,
                                    );
                                    "Error outputting file".into()
                                }
                            }
                        } else {
                            "Disabled".into()
                        };
                        result.rows.push(vec![
                            task.pid.clone(),
                            task.name.clone(),
                            hex(start),
                            hex(end),
                            path,
                            file_output,
                        ]);
                        Ok(())
                    })();
                    if let Err(error) = scan {
                        job.check()?;
                        partial(
                            &mut result,
                            format!("PID {} VMA {}", task.pid, hex(node)),
                            error,
                        );
                    }
                }
                Ok(())
            })();
            if let Err(error) = read {
                job.check()?;
                partial(
                    &mut result,
                    format!("PID {} @ {}", task.pid, hex(addr)),
                    error,
                );
            }
            job.report(format!("linux.elfs.Elfs: {} 条", result.rows.len()));
        }
        Ok(result)
    }

    fn dump_elf(
        vm: &VirtualMemory<'_>,
        elf: &MappedElf,
        pid: &str,
        dump: &DumpOptions,
        result: &mut Results,
        job: &Job,
    ) -> Result<String> {
        let ranges = elf.load_ranges()?;
        let size = ranges
            .iter()
            .try_fold(0, |size, &(start, end)| add(size, end - start))?;
        ensure!(
            size <= crate::dump::MAX_DUMP_BYTES,
            "ELF 导出超过 256 MiB 上限"
        );
        let filename = format!("pid.{pid}.elf.{:#x}.dmp", elf.start);
        let mut missing = 0;
        crate::dump::write_stream_artifact(&dump.directory.join(&filename), job, |out| {
            let mut bytes = [0; 4096];
            for (start, end) in ranges {
                for at in (start..end).step_by(bytes.len()) {
                    job.check()?;
                    missing += super::maps::read_padded(vm, at, &mut bytes)?;
                    out.write_all(&bytes)?;
                }
            }
            Ok(())
        })?;
        if missing != 0 {
            partial(
                result,
                format!("PID {pid} ELF {}", hex(elf.start)),
                anyhow::anyhow!("{missing} 个缺页以零填充"),
            );
        }
        Ok(filename)
    }

    pub(super) fn linux_library_list(&self, options: &Options, job: &Job) -> Result<Results> {
        let pids: BTreeSet<u32> = options.pids.iter().copied().chain(options.pid).collect();
        let (mut result, tasks) = self.task_identities(Plugin::LinuxLibraryList, job)?;

        for task in tasks {
            job.check()?;
            if !pids.is_empty() && !task.pid.parse::<u32>().is_ok_and(|pid| pids.contains(&pid)) {
                continue;
            }
            let addr = task.address;
            let read = (|| -> Result<()> {
                let mm = self.number(addr, "task_struct", "mm")?;
                if mm == 0 {
                    return Ok(());
                }
                let Some(vm) = self.process_vm(addr)? else {
                    return Ok(());
                };
                let nodes = self.vma_nodes(mm, job, &mut result)?;
                let mut seen_maps = HashSet::new();
                let mut seen_addresses = HashSet::new();
                let mut dynamic_errors = Vec::new();
                for node in nodes {
                    job.check()?;
                    let scan = (|| -> Result<()> {
                        let start = self.number(node, "vm_area_struct", "vm_start")?;
                        let Some(elf) = MappedElf::read(&vm, start, job)? else {
                            return Ok(());
                        };
                        let mut pending = match elf.link_map_heads(&vm, job) {
                            Ok(heads) => heads,
                            Err(error) => {
                                job.check()?;
                                dynamic_errors.push((node, error));
                                return Ok(());
                            }
                        };
                        let width = elf.format.width as u64;
                        while let Some(map) = pending.pop() {
                            job.check()?;
                            if map == 0 || !seen_maps.insert(map) {
                                continue;
                            }
                            ensure!(seen_maps.len() <= LIMIT, "ELF link_map 数量超过上限");
                            let read = (|| -> Result<()> {
                                let address = elf.format.pointer(&vm, map)?;
                                let name_ptr = elf.format.pointer(&vm, add(map, width)?)?;
                                let next = elf.format.pointer(&vm, add(map, 3 * width)?)?;
                                let prev = elf.format.pointer(&vm, add(map, 4 * width)?)?;
                                pending.extend([prev, next]);
                                if address != 0
                                    && name_ptr != 0
                                    && !seen_addresses.contains(&address)
                                {
                                    let path = link_map_name(&vm, name_ptr)?;
                                    if !path.is_empty() {
                                        seen_addresses.insert(address);
                                        result.rows.push(vec![
                                            task.name.clone(),
                                            task.pid.clone(),
                                            hex(address),
                                            path,
                                        ]);
                                    }
                                }
                                Ok(())
                            })();
                            if let Err(error) = read {
                                partial(
                                    &mut result,
                                    format!("PID {} ELF link_map {}", task.pid, hex(map)),
                                    error,
                                );
                            }
                        }
                        Ok(())
                    })();
                    if let Err(error) = scan {
                        job.check()?;
                        partial(
                            &mut result,
                            format!("PID {} VMA {}", task.pid, hex(node)),
                            error,
                        );
                    }
                }
                if seen_maps.is_empty() {
                    for (node, error) in dynamic_errors {
                        partial(
                            &mut result,
                            format!("PID {} VMA {} PT_DYNAMIC", task.pid, hex(node)),
                            error,
                        );
                    }
                }
                Ok(())
            })();
            if let Err(error) = read {
                job.check()?;
                partial(
                    &mut result,
                    format!("PID {} @ {}", task.pid, hex(addr)),
                    error,
                );
            }
            job.report(format!(
                "linux.library_list.LibraryList: {} 条",
                result.rows.len()
            ));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};

    fn put(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn linux_elfs_and_library_list_match_vol3_columns_and_support_elf32_and_elf64() {
        let (mut b, mut isf) = fixture();
        put(&mut b, 0x9000, 0xa000);
        put(&mut b, 0x9008, 0xa000);
        put(&mut b, 0xa000, 0x9000);
        put(&mut b, 0xa008, 0x9000);
        put(&mut b, 0xa010, 5);
        put(&mut b, 0xa018, 5);
        put(&mut b, 0xa020, 0x9000);
        b[0xa028..0xa030].copy_from_slice(b"demo\0\0\0\0");
        put(&mut b, 0xa030, 0xb000); // mm
        put(&mut b, 0xa040, 0xd000); // fs

        put(&mut b, 0xb000, 0x4000); // pgd
        put(&mut b, 0xb028, 0xc000); // mmap

        // VMA 1 [0x200000, 0x201000) ET_DYN ELF64 file=/libc.so
        put(&mut b, 0xc000, 0xc100);
        put(&mut b, 0xc008, 0x200000);
        put(&mut b, 0xc010, 0x201000);
        put(&mut b, 0xc018, 5);
        put(&mut b, 0xc028, 0xe000);

        // VMA 2 [0x201000, 0x202000) ET_EXEC ELF32 anonymous
        put(&mut b, 0xc100, 0);
        put(&mut b, 0xc108, 0x201000);
        put(&mut b, 0xc110, 0x202000);
        put(&mut b, 0xc118, 5);
        put(&mut b, 0xc128, 0);

        // fs / vfsmount / dentry / file -> "/libc.so"
        put(&mut b, 0xd000, 0xd100);
        put(&mut b, 0xd008, 0xd200);
        put(&mut b, 0xd100, 0xd200);
        put(&mut b, 0xd108, 0xd100);
        put(&mut b, 0xd110, 0xd200);
        put(&mut b, 0xd200, 0xd200);
        put(&mut b, 0xe000, 0xd100);
        put(&mut b, 0xe008, 0xe100);
        put(&mut b, 0xe100, 0xd200);
        put(&mut b, 0xe108, 7);
        put(&mut b, 0xe110, 0xe200);
        put(&mut b, 0xe118, 0xe300);
        b[0xe200..0xe208].copy_from_slice(b"libc.so\0");
        put(&mut b, 0xe300, 0o100755);

        // ELF64 ET_DYN at phys 0x20000 (VA 0x200000)
        b[0x20000..0x20007].copy_from_slice(b"\x7fELF\x02\x01\x01");
        b[0x20010..0x20012].copy_from_slice(&3u16.to_le_bytes());

        // ELF32 ET_EXEC at phys 0x25000 (VA 0x201000)
        b[0x25000..0x25007].copy_from_slice(b"\x7fELF\x01\x01\x01");
        b[0x25010..0x25012].copy_from_slice(&2u16.to_le_bytes());

        // ELF64 PIE header with two load segments in separate (noncontiguous
        // physical) pages plus a dynamic table containing the loader's r_debug.
        put(&mut b, 0x20020, 64);
        b[0x20036..0x2003a].copy_from_slice(&[56, 0, 3, 0]);
        for (at, kind, offset, address, size) in [
            (0x20040, PT_LOAD, 0, 0, 4096),
            (0x20078, PT_LOAD, 4096, 4096, 4096),
            (0x200b0, PT_DYNAMIC, 0x200, 0x200, 32),
        ] {
            put(&mut b, at, kind);
            put(&mut b, at + 8, offset);
            put(&mut b, at + 16, address);
            put(&mut b, at + 32, size);
            put(&mut b, at + 40, size);
        }
        put(&mut b, 0x20200, DT_DEBUG);
        put(&mut b, 0x20208, 0x200300);
        put(&mut b, 0x20308, 0x200400);

        // Both loader entries have the same path, at different load addresses.
        // The mapped ELF "/libc.so" is absent from the loader list.
        put(&mut b, 0x20400, 0x700000);
        put(&mut b, 0x20408, 0x200500);
        put(&mut b, 0x20418, 0x200440);
        put(&mut b, 0x20440, 0x710000);
        put(&mut b, 0x20448, 0x200500);
        put(&mut b, 0x20460, 0x200400);
        b[0x20500..0x2050c].copy_from_slice(b"/libdemo.so\0");

        // ELF32 ET_EXEC uses an absolute p_vaddr and has only one PT_LOAD.
        b[0x2501c..0x25020].copy_from_slice(&52u32.to_le_bytes());
        b[0x2502a..0x2502e].copy_from_slice(&[32, 0, 1, 0]);
        b[0x25034..0x25038].copy_from_slice(&1u32.to_le_bytes());
        b[0x2503c..0x25040].copy_from_slice(&0x201000u32.to_le_bytes());
        b[0x25044..0x25048].copy_from_slice(&4096u32.to_le_bytes());
        b[0x25048..0x2504c].copy_from_slice(&4096u32.to_le_bytes());
        b[0x25800] = 0xa5;

        let img = image(&b);
        let linux = engine(&img, &isf);

        let elfs = linux
            .linux_elfs(&Options::default(), None, &Job::default())
            .unwrap();
        assert!(elfs.complete, "{:?}", elfs.diagnostics);
        assert_eq!(elfs.rows.len(), 2);
        assert_eq!(
            elfs.rows[0],
            vec![
                "5",
                "demo",
                "0x0000000000200000",
                "0x0000000000201000",
                "/libc.so",
                "Disabled",
            ]
        );
        assert_eq!(elfs.rows[1][4], "Anonymous Mapping");

        let libs = linux
            .linux_library_list(&Options::default(), &Job::default())
            .unwrap();
        assert!(libs.complete, "{:?}", libs.diagnostics);
        assert_eq!(
            libs.rows,
            [
                ["demo", "5", "0x0000000000700000", "/libdemo.so"],
                ["demo", "5", "0x0000000000710000", "/libdemo.so"],
            ]
        );

        let directory = tempfile::tempdir().unwrap();
        let dumped = linux
            .linux_elfs(
                &Options::default(),
                Some(&DumpOptions {
                    pid: 0,
                    directory: directory.path().into(),
                    start: None,
                    end: None,
                }),
                &Job::default(),
            )
            .unwrap();
        assert!(dumped.complete, "{:?}", dumped.diagnostics);
        let elf64 = std::fs::read(directory.path().join(&dumped.rows[0][5])).unwrap();
        let elf32 = std::fs::read(directory.path().join(&dumped.rows[1][5])).unwrap();
        assert_eq!(elf64.len(), 8192);
        assert_eq!(elf32.len(), 4096);
        assert_eq!(&elf64[4096..], elf32);
        assert_eq!(elf64[0x1800], 0xa5);

        isf.data["user_types"]["mm_struct"]["fields"]["exe_file"] =
            serde_json::json!({"offset":56,"type":{"kind":"pointer"}});
        put(&mut b, 0xb038, 0xe000);
        put(&mut b, 0xc128, 0xe000);
        put(&mut b, 0xc120, 3);
        put(&mut b, 0x20080, 0x3000); // Second PT_LOAD's file offset.
        let export = |bytes: &[u8], directory: &std::path::Path| {
            let img = image(bytes);
            engine(&img, &isf)
                .process_details_with_options(
                    &Options {
                        pid: Some(5),
                        ..Options::default()
                    },
                    Some(&DumpOptions {
                        pid: 0,
                        directory: directory.to_path_buf(),
                        start: None,
                        end: None,
                    }),
                    &Job::default(),
                )
                .unwrap()
        };
        let primary = tempfile::tempdir().unwrap();
        let result = export(&b, primary.path());
        let artifact = std::fs::read(primary.path().join(&result.rows[0][10])).unwrap();
        assert_eq!(artifact.len(), 0x4000);
        assert_eq!(&artifact[..4], b"\x7fELF");
        assert!(artifact[0x1000..0x3000].iter().all(|&byte| byte == 0));
        assert_eq!(&artifact[0x3000..], elf32);

        // A different file has a readable ELF at offset zero. The selected
        // executable has no readable header and must produce no artifact.
        put(&mut b, 0xc028, 0xe100);
        put(&mut b, 0xc120, 0);
        b[0x25000] = 0;
        let missing = tempfile::tempdir().unwrap();
        let result = export(&b, missing.path());
        assert_eq!(result.rows[0][10], "Error outputting file");
        assert!(missing.path().read_dir().unwrap().next().is_none());
    }

    #[test]
    fn load_ranges_merges_overlapping_pt_load_segments_with_different_starts() {
        let elf = MappedElf {
            format: ElfFormat {
                width: 8,
                little_endian: true,
            },
            start: 0x200000,
            headers_end: 0,
            headers: vec![
                ProgramHeader {
                    kind: PT_LOAD,
                    file_offset: 0,
                    address: 0,
                    file_size: 0x1800,
                    memory_size: 0x1800,
                },
                ProgramHeader {
                    kind: PT_LOAD,
                    file_offset: 0x1800,
                    address: 0x1800,
                    file_size: 0x1200,
                    memory_size: 0x1200,
                },
            ],
            base: Some(0),
        };
        assert_eq!(elf.load_ranges().unwrap(), vec![(0x200000, 0x203000)]);
    }
}
