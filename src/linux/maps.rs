//! Volatility-compatible Linux process VMA listing (`linux.proc.Maps`).
use super::*;
use crate::analysis::Options;
use crate::dump::DumpOptions;
use std::collections::BTreeSet;

pub(super) const MAPS_MAXSIZE_DEFAULT: u64 = 0x400_0000; // 64 MiB, matching Volatility 3 Maps.MAXSIZE_DEFAULT

/// Decode Linux kernel `dev_t` (`MINORBITS = 20`, `MINORMASK = 0xfffff`).
pub(super) fn decode_dev(dev: u64) -> (u64, u64) {
    (dev >> 20, dev & 0x000f_ffff)
}

/// Read a virtual range, padding absent pages and returning their count.
pub(super) fn read_padded(vm: &VirtualMemory<'_>, mut at: u64, mut out: &mut [u8]) -> Result<u64> {
    let mut missing = 0;
    while !out.is_empty() {
        let size = (4096 - usize::try_from(at & 4095)?).min(out.len());
        let (page, rest) = out.split_at_mut(size);
        if vm.read(at, page).is_err() {
            page.fill(0);
            missing += 1;
        }
        at = add(at, size as u64)?;
        out = rest;
    }
    Ok(missing)
}

impl Linux<'_> {
    pub(super) fn linux_maps(
        &self,
        options: &Options,
        dump: Option<&DumpOptions>,
        job: &Job,
    ) -> Result<Results> {
        self.require(&[
            ("task_struct", "mm"),
            (
                "mm_struct",
                if self.isf.field("mm_struct", "mmap").is_ok() {
                    "mmap"
                } else {
                    "mm_mt"
                },
            ),
            ("vm_area_struct", "vm_start"),
            ("vm_area_struct", "vm_end"),
            ("vm_area_struct", "vm_flags"),
            ("vm_area_struct", "vm_pgoff"),
            ("vm_area_struct", "vm_file"),
        ])?;

        let pids: BTreeSet<u32> = options.pids.iter().copied().chain(options.pid).collect();
        let (mut result, tasks) = self.task_identities(Plugin::LinuxMaps, job)?;
        let maxsize = match options.maxsize {
            Some(v) if v <= 0 => 0,
            Some(v) => u64::try_from(v)?,
            None => MAPS_MAXSIZE_DEFAULT,
        };

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
                let nodes = self.vma_nodes(mm, job, &mut result)?;
                let root = self.process_root(addr).ok();
                let start_brk = self.number(mm, "mm_struct", "start_brk").ok();
                let brk = self.number(mm, "mm_struct", "brk").ok();
                let start_stack = self.number(mm, "mm_struct", "start_stack").ok();
                let vdso = self.number(mm, "mm_struct", "context.vdso").ok();
                let user_vm = if dump.is_some() {
                    self.process_vm(addr)?
                } else {
                    None
                };

                for node in nodes {
                    job.check()?;
                    let row = (|| -> Result<Option<Vec<String>>> {
                        let start = self.number(node, "vm_area_struct", "vm_start")?;
                        let end = self.number(node, "vm_area_struct", "vm_end")?;
                        ensure!(start < end, "VMA 地址倒置");
                        if !options.vma_addresses.is_empty()
                            && !options
                                .vma_addresses
                                .iter()
                                .any(|&target| start <= target && target < end)
                        {
                            return Ok(None);
                        }
                        let flags = self.number(node, "vm_area_struct", "vm_flags")?;
                        let pgoff = self
                            .number(node, "vm_area_struct", "vm_pgoff")?
                            .checked_mul(4096)
                            .context("VMA 文件偏移溢出")?;
                        let file = self.number(node, "vm_area_struct", "vm_file")?;

                        let (major, minor, ino, path) = if file == 0 {
                            let label = if let (Some(sb), Some(b)) = (start_brk, brk)
                                && sb != 0
                                && b != 0
                                && start <= b
                                && end >= sb
                            {
                                "[heap]".into()
                            } else if let Some(ss) = start_stack
                                && ss != 0
                                && start <= ss
                                && end >= ss
                            {
                                "[stack]".into()
                            } else if let Some(v) = vdso
                                && v != 0
                                && start == v
                            {
                                "[vdso]".into()
                            } else {
                                "Anonymous Mapping".into()
                            };
                            (0u64, 0u64, 0u64, label)
                        } else {
                            let (major, minor, ino, deleted) = match self.inode(file) {
                                Ok(inode) => {
                                    let ino = self.number(inode, "inode", "i_ino").unwrap_or(0);
                                    let (maj, min) = self
                                        .number(inode, "inode", "i_sb")
                                        .ok()
                                        .filter(|&sb| sb != 0)
                                        .and_then(|sb| self.number(sb, "super_block", "s_dev").ok())
                                        .map(decode_dev)
                                        .unwrap_or((0, 0));
                                    let deleted = self
                                        .number(inode, "inode", "i_nlink")
                                        .ok()
                                        .is_some_and(|nlink| nlink == 0);
                                    (maj, min, ino, deleted)
                                }
                                Err(error) => {
                                    partial(
                                        &mut result,
                                        format!("PID {} VMA {} inode", task.pid, hex(node)),
                                        error,
                                    );
                                    (0, 0, 0, false)
                                }
                            };
                            let mut resolved = match root.map_or_else(
                                || self.file_path(addr, file, job),
                                |root| self.file_path_from(root, file, job),
                            ) {
                                Ok(p) => p,
                                Err(error)
                                    if error.to_string().starts_with("路径不在进程根目录内") =>
                                {
                                    let d = self.number(file, "file", "f_path.dentry")?;
                                    let m = self.number(file, "file", "f_path.mnt")?;
                                    self.resolve_path(d, m, None, job).unwrap_or_else(|e| {
                                        partial(
                                            &mut result,
                                            format!("PID {} VMA {} 路径", task.pid, hex(node)),
                                            e,
                                        );
                                        "[unresolved]".into()
                                    })
                                }
                                Err(error) => {
                                    job.check()?;
                                    partial(
                                        &mut result,
                                        format!("PID {} VMA {} 路径", task.pid, hex(node)),
                                        error,
                                    );
                                    "[unresolved]".into()
                                }
                            };
                            if deleted && resolved != "[unresolved]" {
                                resolved.push_str(" (deleted)");
                            }
                            (major, minor, ino, resolved)
                        };

                        let file_output = if let Some(dump) = dump {
                            let size = end - start;
                            if size > maxsize || size > crate::dump::MAX_DUMP_BYTES {
                                "Error outputting file".into()
                            } else if let Some(vm) = &user_vm {
                                match self.dump_vma_region(
                                    vm,
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
                                            format!("PID {} VMA {} 导出", task.pid, hex(start)),
                                            error,
                                        );
                                        "Error outputting file".into()
                                    }
                                }
                            } else {
                                "Error outputting file".into()
                            }
                        } else {
                            "Disabled".into()
                        };

                        Ok(Some(vec![
                            task.pid.clone(),
                            task.name.clone(),
                            hex(start),
                            hex(end),
                            permissions(flags),
                            hex(pgoff),
                            major.to_string(),
                            minor.to_string(),
                            ino.to_string(),
                            path,
                            file_output,
                        ]))
                    })();
                    match row {
                        Ok(Some(row)) => result.rows.push(row),
                        Ok(None) => {}
                        Err(error) => {
                            job.check()?;
                            partial(
                                &mut result,
                                format!("PID {} VMA {}", task.pid, hex(node)),
                                error,
                            );
                        }
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
            job.report(format!("linux.proc.Maps: {} 条", result.rows.len()));
        }
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn dump_vma_region(
        &self,
        vm: &VirtualMemory<'_>,
        pid: &str,
        start: u64,
        end: u64,
        dump: &DumpOptions,
        result: &mut Results,
        job: &Job,
    ) -> Result<String> {
        let filename = format!("pid.{pid}.vma.{start:#x}-{end:#x}.dmp");
        let target = dump.directory.join(&filename);
        let mut missing_pages = 0u64;
        crate::dump::write_stream_artifact(&target, job, |out| {
            let mut cursor = start;
            let mut page_buf = [0u8; 4096];
            while cursor < end {
                job.check()?;
                let page_rem = 4096 - (cursor & 4095);
                let take = usize::try_from((end - cursor).min(page_rem))?;
                let slice = page_buf.at_mut(..take)?;
                missing_pages += read_padded(vm, cursor, slice)?;
                out.write_all(slice)?;
                cursor = cursor
                    .checked_add(take as u64)
                    .context("VMA 导出偏移溢出")?;
            }
            Ok(())
        })?;
        if missing_pages > 0 {
            result.complete = false;
            result.diagnostics.push(format!(
                "PID {pid} VMA {start:#x}-{end:#x}: {missing_pages} 个未驻留页以零填充"
            ));
        }
        Ok(filename)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};
    use serde_json::json;

    fn put(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn maps_fixture() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        // Extend mm_struct with start_brk, brk, start_stack, context.vdso
        for (name, offset) in [
            ("start_brk", 48),
            ("brk", 56),
            ("start_stack", 64),
            ("context", 72),
        ] {
            isf.data["user_types"]["mm_struct"]["fields"][name] = if name == "context" {
                json!({"offset":offset,"type":{"kind":"struct","name":"mm_context_t"}})
            } else {
                json!({"offset":offset,"type":{"kind":"base","name":"u64"}})
            };
        }
        isf.data["user_types"]["mm_context_t"] = json!({
            "size": 16,
            "fields": {"vdso": {"offset": 0, "type": {"kind": "base", "name": "u64"}}}
        });
        // Extend inode with i_sb, i_nlink; add super_block.s_dev
        isf.data["user_types"]["inode"]["fields"]["i_sb"] =
            json!({"offset":16,"type":{"kind":"pointer"}});
        isf.data["user_types"]["inode"]["fields"]["i_nlink"] =
            json!({"offset":24,"type":{"kind":"base","name":"u32"}});
        isf.data["user_types"]["super_block"] = json!({
            "size": 16,
            "fields": {"s_dev": {"offset": 0, "type": {"kind": "base", "name": "u32"}}}
        });

        // init_task 0x9000 -> task 0xa000 (pid=1, tgid=1, "app")
        put(&mut b, 0x9000, 0xa000);
        put(&mut b, 0x9008, 0xa000);
        put(&mut b, 0xa000, 0x9000);
        put(&mut b, 0xa008, 0x9000);
        put(&mut b, 0xa010, 1);
        put(&mut b, 0xa018, 1);
        put(&mut b, 0xa020, 0x9000);
        b[0xa028..0xa030].copy_from_slice(b"app\0\0\0\0\0");
        put(&mut b, 0xa030, 0xb000); // mm
        put(&mut b, 0xa040, 0xd000); // fs

        // mm at 0xb000: pgd=0x4000, mmap=0xc000, start_brk=0x600000, brk=0x620000, start_stack=0x7ffe0000, vdso=0x7fff0000
        put(&mut b, 0xb000, 0x4000);
        put(&mut b, 0xb028, 0xc000);
        put(&mut b, 0xb030, 0x600000);
        put(&mut b, 0xb038, 0x620000);
        put(&mut b, 0xb040, 0x7ffe0000);
        put(&mut b, 0xb048, 0x7fff0000);

        // VMA 1 at 0xc000: file-backed [0x200000, 0x201000) r-xp pgoff=2 -> 0x2000, file=0xe000
        // (0x200000 is mapped to physical 0x20000 in fixture()'s user page table)
        put(&mut b, 0xc000, 0xc100);
        put(&mut b, 0xc008, 0x200000);
        put(&mut b, 0xc010, 0x201000);
        put(&mut b, 0xc018, 5); // r-xp
        put(&mut b, 0xc020, 2); // pgoff
        put(&mut b, 0xc028, 0xe000);

        // VMA 2 at 0xc100: [heap] [0x600000, 0x620000) rw-p anonymous
        put(&mut b, 0xc100, 0xc200);
        put(&mut b, 0xc108, 0x600000);
        put(&mut b, 0xc110, 0x620000);
        put(&mut b, 0xc118, 3);
        put(&mut b, 0xc120, 0);
        put(&mut b, 0xc128, 0);

        // VMA 3 at 0xc200: [vdso] [0x7fff0000, 0x7fff2000) r-xp anonymous
        put(&mut b, 0xc200, 0);
        put(&mut b, 0xc208, 0x7fff0000);
        put(&mut b, 0xc210, 0x7fff2000);
        put(&mut b, 0xc218, 5);
        put(&mut b, 0xc220, 0);
        put(&mut b, 0xc228, 0);

        // fs_struct at 0xd000 -> root (mnt=0xd100, dentry=0xd200)
        put(&mut b, 0xd000, 0xd100);
        put(&mut b, 0xd008, 0xd200);
        // vfsmount at 0xd100: mnt_root=0xd200, mnt_parent=0xd100, mnt_mountpoint=0xd200
        put(&mut b, 0xd100, 0xd200);
        put(&mut b, 0xd108, 0xd100);
        put(&mut b, 0xd110, 0xd200);
        // root dentry at 0xd200
        put(&mut b, 0xd200, 0xd200);
        // file at 0xe000: f_path=(mnt=0xd100, dentry=0xe100)
        put(&mut b, 0xe000, 0xd100);
        put(&mut b, 0xe008, 0xe100);
        // file dentry at 0xe100: d_parent=0xd200, d_name=(len=3, name=0xe200 "app"), d_inode(+0x18)=0xe300
        put(&mut b, 0xe100, 0xd200);
        put(&mut b, 0xe108, 3);
        put(&mut b, 0xe110, 0xe200);
        put(&mut b, 0xe118, 0xe300);
        b[0xe200..0xe204].copy_from_slice(b"app\0");
        // inode at 0xe300: i_mode=0100755, i_ino=12345, i_sb=0xe400, i_nlink=0 (deleted!)
        put(&mut b, 0xe300, 0o100755);
        put(&mut b, 0xe308, 12345);
        put(&mut b, 0xe310, 0xe400);
        put(&mut b, 0xe318, 0);
        // super_block at 0xe400: s_dev = (8 << 20) | 1  => major=8, minor=1
        put(&mut b, 0xe400, (8u64 << 20) | 1);

        // Put bytes at user VA 0x400000 (mapped to physical 0x20000 by fixture page table!)
        b[0x20000..0x20004].copy_from_slice(b"\x7fELF");
        (b, isf)
    }

    #[test]
    fn linux_maps_decodes_full_columns_special_vmas_and_filters_by_address() {
        let (bytes, isf) = maps_fixture();
        let img = image(&bytes);
        let linux = engine(&img, &isf);

        let result = linux
            .linux_maps(&Options::default(), None, &Job::default())
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 3);
        assert_eq!(
            result.rows[0],
            vec![
                "1",
                "app",
                "0x0000000000200000",
                "0x0000000000201000",
                "r-xp",
                "0x0000000000002000",
                "8",
                "1",
                "12345",
                "/app (deleted)",
                "Disabled",
            ]
        );
        assert_eq!(result.rows[1][9], "[heap]");
        assert_eq!(result.rows[2][9], "[vdso]");

        // Address filter selects only the VMA containing 0x600123
        let filtered = linux
            .linux_maps(
                &Options {
                    vma_addresses: vec![0x600123],
                    ..Default::default()
                },
                None,
                &Job::default(),
            )
            .unwrap();
        assert_eq!(filtered.rows.len(), 1);
        assert_eq!(filtered.rows[0][9], "[heap]");
    }

    #[test]
    fn linux_maps_dumps_selected_vma_respecting_maxsize() {
        let (bytes, isf) = maps_fixture();
        let img = image(&bytes);
        let linux = engine(&img, &isf);
        let dir = std::env::temp_dir().join(format!("zero-maps-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dump = DumpOptions {
            pid: 0,
            directory: dir.clone(),
            start: None,
            end: None,
        };
        let result = linux
            .linux_maps(
                &Options {
                    vma_addresses: vec![0x200000],
                    maxsize: Some(4096),
                    ..Default::default()
                },
                Some(&dump),
                &Job::default(),
            )
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][10], "pid.1.vma.0x200000-0x201000.dmp");
        let dumped = std::fs::read(dir.join(&result.rows[0][10])).unwrap();
        assert_eq!(dumped.len(), 4096);
        assert_eq!(&dumped[..4], b"\x7fELF");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
