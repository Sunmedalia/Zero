//! Volatility-compatible Linux ELF mapping & shared library listings
//! (`linux.elfs.Elfs` and `linux.library_list.LibraryList`).
use super::*;
use crate::analysis::Options;
use crate::dump::DumpOptions;
use std::collections::BTreeSet;

/// Check whether `bytes` starts with an ELF32 or ELF64 header and return its `e_type`.
fn elf_type(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 20 || bytes.get(..4)? != b"\x7fELF" {
        return None;
    }
    let class = *bytes.get(4)?;
    let endian = *bytes.get(5)?;
    let version = *bytes.get(6)?;
    if !matches!(class, 1 | 2) || !matches!(endian, 1 | 2) || version != 1 {
        return None;
    }
    let raw: [u8; 2] = bytes.get(16..18)?.try_into().ok()?;
    let kind = if endian == 1 {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    };
    Some(kind)
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
                let mut hdr = [0u8; 64];

                for node in nodes {
                    job.check()?;
                    let scan = (|| -> Result<()> {
                        let start = self.number(node, "vm_area_struct", "vm_start")?;
                        let end = self.number(node, "vm_area_struct", "vm_end")?;
                        ensure!(start < end, "VMA 地址倒置");
                        let flags = self.number(node, "vm_area_struct", "vm_flags")?;
                        if flags & 1 == 0 {
                            return Ok(());
                        }
                        if vm.read(start, &mut hdr).is_err() {
                            return Ok(());
                        }
                        if elf_type(&hdr).is_none() {
                            return Ok(());
                        }
                        let file = self.number(node, "vm_area_struct", "vm_file")?;
                        let path =
                            self.resolve_vma_file_path(&task, root, file, node, &mut result, job);
                        let file_output = if let Some(dump) = dump {
                            let size = end - start;
                            if size > crate::dump::MAX_DUMP_BYTES {
                                "Error outputting file".into()
                            } else {
                                match self.dump_vma_region(
                                    &vm,
                                    &task.pid,
                                    start,
                                    end,
                                    dump,
                                    &mut result,
                                    job,
                                ) {
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
                let root = self.process_root(addr).ok();
                let exe = self
                    .number(mm, "mm_struct", "exe_file")
                    .ok()
                    .filter(|&f| f != 0)
                    .and_then(|f| {
                        root.map_or_else(
                            || self.file_path(addr, f, job),
                            |root| self.file_path_from(root, f, job),
                        )
                        .ok()
                    });
                let mut seen_libs = HashSet::new();
                let mut hdr = [0u8; 64];

                for node in nodes {
                    job.check()?;
                    let scan = (|| -> Result<()> {
                        let start = self.number(node, "vm_area_struct", "vm_start")?;
                        let end = self.number(node, "vm_area_struct", "vm_end")?;
                        ensure!(start < end, "VMA 地址倒置");
                        let flags = self.number(node, "vm_area_struct", "vm_flags")?;
                        let file = self.number(node, "vm_area_struct", "vm_file")?;
                        if flags & 1 == 0 || file == 0 {
                            return Ok(());
                        }
                        if vm.read(start, &mut hdr).is_err() {
                            return Ok(());
                        }
                        // Shared libraries are ET_DYN (3).
                        if elf_type(&hdr) != Some(3) {
                            return Ok(());
                        }
                        let path =
                            self.resolve_vma_file_path(&task, root, file, node, &mut result, job);
                        if exe.as_ref() == Some(&path) {
                            return Ok(());
                        }
                        if path == "[unresolved]" || seen_libs.insert(path.clone()) {
                            result.rows.push(vec![
                                task.name.clone(),
                                task.pid.clone(),
                                hex(start),
                                path,
                            ]);
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
        let (mut b, isf) = fixture();
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
        assert_eq!(libs.rows.len(), 1);
        assert_eq!(
            libs.rows[0],
            vec!["demo", "5", "0x0000000000200000", "/libc.so"]
        );
    }
}
