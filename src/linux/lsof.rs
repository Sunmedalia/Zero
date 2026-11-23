//! Volatility-compatible Linux open files listing (`linux.lsof.Lsof`).
use super::*;
use crate::analysis::Options;
use crate::bytes::JsonKey as _;
use std::collections::BTreeSet;

pub(super) fn vol3_inode_type(mode: u64) -> &'static str {
    match mode & 0xf000 {
        0x1000 => "FIFO",
        0x2000 => "CHR",
        0x4000 => "DIR",
        0x6000 => "BLK",
        0x8000 => "REG",
        0xa000 => "LNK",
        0xc000 => "SOCK",
        _ => "UNK",
    }
}

/// Format POSIX mode bits as a 10-char string (matching Python `stat.filemode`).
pub(super) fn format_file_mode(mode: u64) -> String {
    let kind = match mode & 0xf000 {
        0x1000 => 'p',
        0x2000 => 'c',
        0x4000 => 'd',
        0x6000 => 'b',
        0x8000 => '-',
        0xa000 => 'l',
        0xc000 => 's',
        _ => '?',
    };
    let bit = |mask: u64, ch: char| if mode & mask != 0 { ch } else { '-' };
    let exec = |x_mask: u64, s_mask: u64, lower: char, upper: char| match (
        mode & x_mask != 0,
        mode & s_mask != 0,
    ) {
        (true, true) => lower,
        (false, true) => upper,
        (true, false) => 'x',
        (false, false) => '-',
    };
    [
        kind,
        bit(0o400, 'r'),
        bit(0o200, 'w'),
        exec(0o100, 0o4000, 's', 'S'),
        bit(0o040, 'r'),
        bit(0o020, 'w'),
        exec(0o010, 0o2000, 's', 'S'),
        bit(0o004, 'r'),
        bit(0o002, 'w'),
        exec(0o001, 0o1000, 't', 'T'),
    ]
    .iter()
    .collect()
}

fn format_timespec_utc(sec: i64, nsec: i64) -> Result<String> {
    ensure!(
        (0..1_000_000_000).contains(&nsec),
        "inode 时间戳纳秒无效: {nsec}"
    );
    ensure!(
        (-62_135_596_800..=253_402_300_799).contains(&sec),
        "inode 时间戳超出年份 1-9999 范围"
    );
    let date = crate::report::utc(sec).replace(' ', "T");
    let date = date.strip_suffix("TUTC").context("UTC 时间格式无效")?;
    Ok(format!("{date}.{:06}+00:00", nsec / 1000))
}

impl Linux<'_> {
    /// Read `i_ctime` / `i_mtime` / `i_atime` across Linux < 6.6 (`i_*`),
    /// 6.6–6.10 (`__i_*`), and >= 6.11 (`i_*_sec` + `i_*_nsec`).
    pub(super) fn inode_timestamp(&self, inode: u64, stem: &str) -> Result<String> {
        let sec_field = format!("i_{stem}_sec");
        let nsec_field = format!("i_{stem}_nsec");
        if self.isf.field("inode", &sec_field).is_ok()
            && self.isf.field("inode", &nsec_field).is_ok()
        {
            let sec = self.signed_field(inode, "inode", &sec_field)?;
            let nsec = self.signed_field(inode, "inode", &nsec_field)?;
            return format_timespec_utc(sec, nsec);
        }
        for name in [format!("i_{stem}"), format!("__i_{stem}")] {
            if let Ok(layout) = self.isf.field("inode", &name) {
                let ty = layout["type"]
                    .key("name")
                    .as_str()
                    .context("inode 时间字段缺少类型名")?;
                let at = self.field_address(inode, "inode", &name)?;
                let sec = self.signed_field(at, ty, "tv_sec")?;
                let nsec = self.signed_field(at, ty, "tv_nsec")?;
                return format_timespec_utc(sec, nsec);
            }
        }
        bail!("ISF 缺少 inode.{stem} 时间字段")
    }

    pub(super) fn signed_field(&self, address: u64, structure: &str, field: &str) -> Result<i64> {
        let size = self.isf.size(structure, field)?;
        ensure!(
            matches!(size, 1 | 2 | 4 | 8),
            "{structure}.{field} 宽度无效"
        );
        let raw = self.number(address, structure, field)?;
        let shift = 64 - size * 8;
        Ok(((raw << shift) as i64) >> shift)
    }

    pub(super) fn linux_lsof(&self, options: &Options, job: &Job) -> Result<Results> {
        self.require(&[
            ("task_struct", "files"),
            ("files_struct", "fdt"),
            ("fdtable", "max_fds"),
            ("fdtable", "fd"),
            ("file", "f_path"),
            ("path", "dentry"),
            ("dentry", "d_inode"),
            ("inode", "i_mode"),
            ("inode", "i_ino"),
        ])?;

        let width = usize::try_from(
            self.isf.data.key("base_types")["pointer"]
                .key("size")
                .as_u64()
                .context("ISF pointer size 缺失")?,
        )?;
        ensure!(matches!(width, 4 | 8), "ISF pointer size 无效");

        let pids: BTreeSet<u32> = options.pids.iter().copied().chain(options.pid).collect();
        let (mut result, tasks) = self.fd_tasks(Plugin::LinuxLsof, &pids, job)?;

        for task in tasks {
            job.check()?;
            let addr = task.address;
            let read = (|| -> Result<()> {
                let files = self.number(addr, "task_struct", "files")?;
                if files == 0 {
                    return Ok(());
                }
                let table = self.number(files, "files_struct", "fdt")?;
                ensure!(table != 0, "fdtable 为空");
                let count = self.number(table, "fdtable", "max_fds")?;
                let array = self.number(table, "fdtable", "fd")?;
                ensure!(count == 0 || array != 0, "FD 数组为空");

                let tgid = self.number(addr, "task_struct", "tgid")?.to_string();
                let process_root = self.process_root(addr).ok();
                let mut fd_cursor = self.vm.cursor();

                for fd in 0..count.min(OBJECT_LIMIT) {
                    job.check()?;
                    let row = (|| -> Result<Option<Vec<String>>> {
                        let slot = array
                            .checked_add(fd.checked_mul(width as u64).context("FD 偏移溢出")?)
                            .context("FD 地址溢出")?;
                        let file = fd_cursor.uint(slot, width)?;
                        if file == 0 {
                            return Ok(None);
                        }
                        let inode = self.inode(file)?;
                        let mode = self.number(inode, "inode", "i_mode")?;
                        if options.files_only && (mode & 0xf000) != 0x8000 {
                            return Ok(None);
                        }
                        let ino = self.number(inode, "inode", "i_ino")?;
                        let path = match mode & 0xf000 {
                            0xc000 => format!("socket:[{ino}]"),
                            0x1000 => {
                                let d = self.number(file, "file", "f_path.dentry")?;
                                if self.number(d, "dentry", "d_parent")? == d {
                                    format!("pipe:[{ino}]")
                                } else {
                                    self.lsof_file_path(
                                        addr,
                                        process_root,
                                        file,
                                        inode,
                                        &task.pid,
                                        fd,
                                        &mut result,
                                        job,
                                    )
                                }
                            }
                            _ => self.lsof_file_path(
                                addr,
                                process_root,
                                file,
                                inode,
                                &task.pid,
                                fd,
                                &mut result,
                                job,
                            ),
                        };
                        let device = self
                            .number(inode, "inode", "i_sb")
                            .ok()
                            .filter(|&sb| sb != 0)
                            .and_then(|sb| self.number(sb, "super_block", "s_dev").ok())
                            .map(|dev| {
                                let (maj, min) = super::maps::decode_dev(dev);
                                format!("{maj}:{min}")
                            })
                            .unwrap_or_else(|| "N/A".into());
                        let size = self
                            .signed_field(inode, "inode", "i_size")
                            .map(|v| v.to_string())
                            .unwrap_or_else(|_| "N/A".into());
                        let changed = self
                            .inode_timestamp(inode, "ctime")
                            .unwrap_or_else(|_| "N/A".into());
                        let modified = self
                            .inode_timestamp(inode, "mtime")
                            .unwrap_or_else(|_| "N/A".into());
                        let accessed = self
                            .inode_timestamp(inode, "atime")
                            .unwrap_or_else(|_| "N/A".into());

                        Ok(Some(vec![
                            tgid.clone(),
                            task.pid.clone(),
                            task.name.clone(),
                            fd.to_string(),
                            path,
                            device,
                            ino.to_string(),
                            vol3_inode_type(mode).into(),
                            format_file_mode(mode),
                            changed,
                            modified,
                            accessed,
                            size,
                        ]))
                    })();
                    match row {
                        Ok(Some(row)) => result.rows.push(row),
                        Ok(None) => {}
                        Err(error) => {
                            job.check()?;
                            partial(&mut result, format!("PID {} FD {fd}", task.pid), error);
                        }
                    }
                }
                ensure!(count <= OBJECT_LIMIT, "FD 超过 100 万项上限 ({count})");
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
            job.report(format!("linux.lsof.Lsof: {} 条", result.rows.len()));
        }
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn lsof_file_path(
        &self,
        task: u64,
        root: Option<(u64, u64)>,
        file: u64,
        inode: u64,
        pid: &str,
        fd: u64,
        result: &mut Results,
        job: &Job,
    ) -> String {
        let mut resolved = match root.map_or_else(
            || self.file_path(task, file, job),
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
                        partial(result, format!("PID {pid} FD {fd} 路径"), e);
                        "[unresolved]".into()
                    }
                }
            }
            Err(error) => {
                partial(result, format!("PID {pid} FD {fd} 路径"), error);
                "[unresolved]".into()
            }
        };
        if resolved != "[unresolved]"
            && self
                .number(inode, "inode", "i_nlink")
                .ok()
                .is_some_and(|n| n == 0)
        {
            resolved.push_str(" (deleted)");
        }
        resolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fd_thread_group, fixture, image};
    use serde_json::json;

    fn put(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn lsof_fixture(modern_split_times: bool) -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        isf.data["user_types"]["super_block"] = json!({
            "size": 16,
            "fields": {"s_dev": {"offset": 0, "type": {"kind": "base", "name": "u32"}}}
        });
        isf.data["user_types"]["inode"]["fields"]["i_sb"] =
            json!({"offset":16,"type":{"kind":"pointer"}});
        isf.data["user_types"]["inode"]["fields"]["i_size"] =
            json!({"offset":24,"type":{"kind":"base","name":"u64"}});
        isf.data["user_types"]["inode"]["fields"]["i_nlink"] =
            json!({"offset":32,"type":{"kind":"base","name":"u32"}});
        if modern_split_times {
            for (name, offset) in [
                ("i_ctime_sec", 40),
                ("i_ctime_nsec", 48),
                ("i_mtime_sec", 56),
                ("i_mtime_nsec", 64),
                ("i_atime_sec", 72),
                ("i_atime_nsec", 80),
            ] {
                isf.data["user_types"]["inode"]["fields"][name] =
                    json!({"offset":offset,"type":{"kind":"base","name":"u64"}});
            }
        } else {
            isf.data["user_types"]["timespec64"] = json!({
                "size": 16,
                "fields": {
                    "tv_sec": {"offset": 0, "type": {"kind": "base", "name": "u64"}},
                    "tv_nsec": {"offset": 8, "type": {"kind": "base", "name": "u64"}}
                }
            });
            for (name, offset) in [("i_ctime", 40), ("i_mtime", 56), ("i_atime", 72)] {
                isf.data["user_types"]["inode"]["fields"][name] =
                    json!({"offset":offset,"type":{"kind":"struct","name":"timespec64"}});
            }
        }

        // init_task 0x9000 -> task 0xa000 (pid=42, tgid=40, "srv")
        put(&mut b, 0x9000, 0xa000);
        put(&mut b, 0x9008, 0xa000);
        put(&mut b, 0xa000, 0x9000);
        put(&mut b, 0xa008, 0x9000);
        put(&mut b, 0xa010, 42);
        put(&mut b, 0xa018, 40);
        put(&mut b, 0xa020, 0x9000);
        b[0xa028..0xa030].copy_from_slice(b"srv\0\0\0\0\0");
        put(&mut b, 0xa038, 0xb000); // files
        put(&mut b, 0xa040, 0xd000); // fs

        // files_struct -> fdtable -> [file0 (REG), file1 (SOCK)]
        put(&mut b, 0xb000, 0xb100);
        put(&mut b, 0xb100, 2);
        put(&mut b, 0xb108, 0xb200);
        put(&mut b, 0xb200, 0xe000);
        put(&mut b, 0xb208, 0xe500);

        // fs_struct / vfsmount / root dentry
        put(&mut b, 0xd000, 0xd100);
        put(&mut b, 0xd008, 0xd200);
        put(&mut b, 0xd100, 0xd200);
        put(&mut b, 0xd108, 0xd100);
        put(&mut b, 0xd110, 0xd200);
        put(&mut b, 0xd200, 0xd200);

        // Regular file 0xe000 -> dentry 0xe100 ("log.txt") -> inode(+0x18) 0xe300
        put(&mut b, 0xe000, 0xd100);
        put(&mut b, 0xe008, 0xe100);
        put(&mut b, 0xe100, 0xd200);
        put(&mut b, 0xe108, 7);
        put(&mut b, 0xe110, 0xe200);
        put(&mut b, 0xe118, 0xe300);
        b[0xe200..0xe208].copy_from_slice(b"log.txt\0");
        put(&mut b, 0xe300, 0o104755); // S_IFREG + setuid rwsr-xr-x
        put(&mut b, 0xe308, 999);
        put(&mut b, 0xe310, 0xe400); // i_sb
        put(&mut b, 0xe318, 4096); // i_size
        put(&mut b, 0xe320, 1); // i_nlink
        put(&mut b, 0xe328, 1_700_000_000); // ctime sec
        put(&mut b, 0xe330, 123_000); // ctime nsec
        put(&mut b, 0xe338, 1_700_000_001); // mtime sec
        put(&mut b, 0xe340, 0);
        put(&mut b, 0xe348, 1_700_000_002); // atime sec
        put(&mut b, 0xe350, 500_000);
        put(&mut b, 0xe400, (253u64 << 20) | 2);

        // Socket file 0xe500 -> dentry 0xe600 -> inode(+0x18) 0xe700
        put(&mut b, 0xe500, 0xd100);
        put(&mut b, 0xe508, 0xe600);
        put(&mut b, 0xe618, 0xe700);
        put(&mut b, 0xe700, 0o140777); // S_IFSOCK
        put(&mut b, 0xe708, 7777);
        put(&mut b, 0xe710, 0xe400);
        put(&mut b, 0xe718, 0);
        put(&mut b, 0xe720, 1);

        fd_thread_group(&mut b, &mut isf, None);
        (b, isf)
    }

    #[test]
    fn linux_lsof_reads_13_columns_for_both_legacy_and_modern_inode_timestamps() {
        for modern in [false, true] {
            let (bytes, isf) = lsof_fixture(modern);
            let img = image(&bytes);
            let linux = engine(&img, &isf);
            let result = linux
                .linux_lsof(&Options::default(), &Job::default())
                .unwrap();
            assert!(result.complete, "{:?}", result.diagnostics);
            assert_eq!(result.rows.len(), 2);
            assert_eq!(
                result.rows[0],
                vec![
                    "40",
                    "42",
                    "srv",
                    "0",
                    "/log.txt",
                    "253:2",
                    "999",
                    "REG",
                    "-rwsr-xr-x",
                    "2023-11-14T22:13:20.000123+00:00",
                    "2023-11-14T22:13:21.000000+00:00",
                    "2023-11-14T22:13:22.000500+00:00",
                    "4096",
                ]
            );
            assert_eq!(result.rows[1][4], "socket:[7777]");
            assert_eq!(result.rows[1][7], "SOCK");
            assert_eq!(result.rows[1][8], "srwxrwxrwx");

            // files_only filters out sockets and keeps only regular files
            let reg_only = linux
                .linux_lsof(
                    &Options {
                        files_only: true,
                        ..Default::default()
                    },
                    &Job::default(),
                )
                .unwrap();
            assert_eq!(reg_only.rows.len(), 1);
            assert_eq!(reg_only.rows[0][7], "REG");
        }
    }
    #[test]
    fn linux_lsof_finds_a_worker_threads_private_file_table() {
        let (mut bytes, mut isf) = lsof_fixture(true);
        put(&mut bytes, 0xa038, 0);
        fd_thread_group(&mut bytes, &mut isf, Some((43, 40, 0xb000)));
        let image = image(&bytes);
        let linux = engine(&image, &isf);
        let result = linux
            .linux_lsof(
                &Options {
                    pids: vec![42],
                    files_only: true,
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(
            &result.rows[0][..5],
            ["40", "43", "worker", "0", "/log.txt"]
        );
    }
}
