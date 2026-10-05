//! Additional native Linux analyses. Unsupported layouts fail before traversal.
use crate::{
    Job,
    linux::{Linux, Plugin},
    store::Results,
};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, HashSet};
fn hex(n: u64) -> String {
    format!("{n:#018x}")
}
fn partial(r: &mut Results, context: impl AsRef<str>, e: anyhow::Error) {
    r.complete = false;
    r.diagnostics.push(format!("{}: {e:#}", context.as_ref()));
}
impl Linux<'_> {
    fn more_require(&self, fields: &[(&str, &str)]) -> Result<()> {
        for (s, f) in fields {
            if *s == "vfsmount" && self.modern_mount() && self.isf.field(s, f).is_err() {
                self.isf
                    .size("mount", f)
                    .with_context(|| format!("不支持: 缺少 mount.{f}"))?;
                continue;
            }
            self.isf
                .size(s, f)
                .with_context(|| format!("不支持: 缺少或无效字段 {s}.{f}"))?;
        }
        Ok(())
    }
    pub(crate) fn run_more(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        let required = match plugin {
            Plugin::Pwd => vec![
                ("task_struct", "fs"),
                ("task_struct", "mm"),
                ("fs_struct", "root"),
                ("fs_struct", "pwd"),
                ("path", "dentry"),
                ("path", "mnt"),
                ("vfsmount", "mnt_root"),
                ("vfsmount", "mnt_parent"),
                ("vfsmount", "mnt_mountpoint"),
                ("dentry", "d_parent"),
                ("dentry", "d_name"),
                ("qstr", "name"),
                ("qstr", "len"),
            ],
            Plugin::Pscred | Plugin::CheckCreds => vec![
                ("task_struct", "cred"),
                ("cred", "uid"),
                ("cred", "gid"),
                ("cred", "euid"),
                ("cred", "egid"),
                ("cred", "suid"),
                ("cred", "sgid"),
                ("cred", "fsuid"),
                ("cred", "fsgid"),
            ],
            Plugin::Threads => vec![
                ("task_struct", "group_leader"),
                (
                    "task_struct",
                    if self.isf.field("task_struct", "thread_group").is_ok() {
                        "thread_group"
                    } else {
                        "thread_node"
                    },
                ),
            ],
            Plugin::Mountinfo if self.modern_mount() => vec![
                ("mnt_namespace", "root"),
                ("mount", "mnt_mounts"),
                ("mount", "mnt_child"),
                ("mount", "mnt"),
            ],
            Plugin::Mountinfo => vec![
                ("task_struct", "nsproxy"),
                ("nsproxy", "mnt_ns"),
                ("mnt_namespace", "list"),
                ("vfsmount", "mnt_list"),
                ("vfsmount", "mnt_id"),
                ("vfsmount", "mnt_parent"),
                ("vfsmount", "mnt_root"),
                ("vfsmount", "mnt_sb"),
                ("vfsmount", "mnt_devname"),
                ("vfsmount", "mnt_flags"),
                ("super_block", "s_type"),
                ("file_system_type", "name"),
            ],
            Plugin::Dmesg => {
                for s in if self.isf.address("prb").is_ok() {
                    vec!["prb"]
                } else {
                    vec!["log_buf", "log_buf_len", "logged_chars", "log_end"]
                } {
                    self.isf.address(s).with_context(|| {
                        format!("不支持: 缺少 {s}（目前支持旧式 printk 环形缓冲区）")
                    })?;
                }
                vec![]
            }
            _ => unreachable!(),
        };
        self.more_require(&required)?;
        if plugin != Plugin::Dmesg {
            self.more_require(&[
                ("task_struct", "pid"),
                ("task_struct", "tgid"),
                ("task_struct", "comm"),
                ("task_struct", "real_parent"),
                ("task_struct", "tasks"),
                ("list_head", "next"),
                ("list_head", "prev"),
            ])?;
        }
        if plugin == Plugin::Mountinfo {
            self.more_require(&[
                ("vfsmount", "mnt_mountpoint"),
                ("dentry", "d_parent"),
                ("dentry", "d_name"),
                ("dentry", "d_sb"),
                ("qstr", "len"),
                ("qstr", "name"),
            ])?;
        }
        if matches!(plugin, Plugin::Pscred | Plugin::CheckCreds) {
            for f in [
                "uid", "gid", "euid", "egid", "suid", "sgid", "fsuid", "fsgid",
            ] {
                if self.isf.field("cred", f)?["type"]["kind"] == "struct" {
                    self.more_require(&[("cred", &format!("{f}.val"))])?;
                }
            }
        }

        if plugin == Plugin::Dmesg {
            let mut result = Results {
                plugin: plugin.name().into(),
                columns: plugin
                    .descriptor()
                    .columns
                    .iter()
                    .map(|s| (*s).into())
                    .collect(),
                rows: vec![],
                complete: true,
                diagnostics: vec![],
                banner: String::from_utf8_lossy(&self.isf.banner[..self.isf.banner.len() - 1])
                    .trim_end()
                    .into(),
                symbol: self.isf.label.clone(),
                page_table: self.vm.root,
                historical: false,
            };
            self.logs(&mut result, job)?;
            job.check()?;
            return Ok(result);
        }
        let mut result = self.run(Plugin::Pslist, job)?;
        let tasks = std::mem::take(&mut result.rows);
        result.plugin = plugin.name().into();
        result.columns = plugin
            .descriptor()
            .columns
            .iter()
            .map(|s| (*s).into())
            .collect();
        let mut credentials: BTreeMap<u64, Vec<(String, String)>> = BTreeMap::new();
        let mut leaders = HashSet::new();
        for task in tasks {
            job.check()?;
            let addr = u64::from_str_radix(&task[4][2..], 16)?;
            let prefix = vec![task[0].clone(), task[3].clone()];
            let read = (|| -> Result<()> {
                match plugin {
                    Plugin::Pwd => {
                        let fs = self.number(addr, "task_struct", "fs")?;
                        let (root, cwd) = if fs == 0 {
                            ("[none]".into(), "[none]".into())
                        } else {
                            let root = self.field_address(fs, "fs_struct", "root")?;
                            let pwd = self.field_address(fs, "fs_struct", "pwd")?;
                            let rd = self.number(root, "path", "dentry")?;
                            let rm = self.number(root, "path", "mnt")?;
                            if (rd == 0 || rm == 0) && self.number(addr, "task_struct", "mm")? == 0
                            {
                                ("[none]".into(), "[none]".into())
                            } else {
                                ensure!(rd != 0 && rm != 0, "进程根目录为空");
                                let pd = self.number(pwd, "path", "dentry")?;
                                let pm = self.number(pwd, "path", "mnt")?;
                                (
                                    self.resolve_path(rd, rm, None, job)?,
                                    self.resolve_path(pd, pm, Some((rd, rm)), job)?,
                                )
                            }
                        };
                        result.rows.push([prefix, vec![root, cwd]].concat());
                    }
                    Plugin::Pscred | Plugin::CheckCreds => {
                        let cred = self.number(addr, "task_struct", "cred")?;
                        ensure!(cred != 0, "cred 为空");
                        if plugin == Plugin::CheckCreds {
                            credentials
                                .entry(cred)
                                .or_default()
                                .push((task[0].clone(), task[3].clone()));
                        } else {
                            let mut row = prefix;
                            for f in [
                                "uid", "gid", "euid", "egid", "suid", "sgid", "fsuid", "fsgid",
                            ] {
                                row.push(self.credential(cred, f)?.to_string());
                            }
                            row.push(hex(cred));
                            result.rows.push(row);
                        }
                    }
                    Plugin::Threads => {
                        let leader = self.number(addr, "task_struct", "group_leader")?;
                        ensure!(leader != 0, "group_leader 为空");
                        if leaders.insert(leader) {
                            self.threads(leader, prefix, &mut result, job)?;
                        }
                    }
                    Plugin::Mountinfo => self.mounts(addr, prefix, &mut result, job)?,
                    _ => unreachable!(),
                }
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                partial(&mut result, format!("PID {} @ {}", task[0], task[4]), e);
            }
            job.report(format!("{}: {} 条", plugin.name(), result.rows.len()));
        }
        if plugin == Plugin::CheckCreds {
            for (cred, owners) in credentials.into_iter().filter(|(_, v)| v.len() > 1) {
                let read = (|| -> Result<Vec<String>> {
                    Ok(vec![
                        hex(cred),
                        owners
                            .iter()
                            .map(|(p, _)| p.as_str())
                            .collect::<Vec<_>>()
                            .join(","),
                        owners
                            .iter()
                            .map(|(_, n)| n.as_str())
                            .collect::<Vec<_>>()
                            .join(","),
                        self.credential(cred, "uid")?.to_string(),
                        self.credential(cred, "euid")?.to_string(),
                    ])
                })();
                match read {
                    Ok(row) => result.rows.push(row),
                    Err(e) => partial(&mut result, hex(cred), e),
                }
            }
        }
        job.check()?;
        Ok(result)
    }
    fn credential(&self, cred: u64, field: &str) -> Result<u64> {
        let ty = &self.isf.field("cred", field)?["type"];
        if ty["kind"] == "struct" {
            self.number(cred, "cred", &format!("{field}.val"))
        } else {
            self.number(cred, "cred", field)
        }
    }
    fn threads(
        &self,
        leader: u64,
        prefix: Vec<String>,
        result: &mut Results,
        job: &Job,
    ) -> Result<()> {
        if self.isf.field("task_struct", "thread_group").is_err() {
            for current in self.thread_nodes(leader, job)? {
                result.rows.push(
                    [
                        prefix.clone(),
                        vec![
                            self.number(current, "task_struct", "pid")?.to_string(),
                            self.vm
                                .string(self.field_address(current, "task_struct", "comm")?, 16)?,
                            hex(current),
                        ],
                    ]
                    .concat(),
                );
            }
            return Ok(());
        }
        let offset = self.isf.offset("task_struct", "thread_group")?;
        let head = leader.checked_add(offset).context("线程地址溢出")?;
        let mut current = leader;
        let mut visited = HashSet::new();
        loop {
            job.check()?;
            ensure!(visited.insert(current), "线程链表循环 @ {}", hex(current));
            ensure!(visited.len() <= 1_000_000, "线程超过 100 万项");
            let read = (|| -> Result<Vec<String>> {
                Ok([
                    prefix.clone(),
                    vec![
                        self.number(current, "task_struct", "pid")?.to_string(),
                        self.vm.string(
                            self.field_address(current, "task_struct", "comm")?,
                            self.isf.size("task_struct", "comm")?,
                        )?,
                        hex(current),
                    ],
                ]
                .concat())
            })();
            match read {
                Ok(row) => result.rows.push(row),
                Err(e) => partial(
                    result,
                    format!("PID {} thread {}", prefix[0], hex(current)),
                    e,
                ),
            }
            let entry = current.checked_add(offset).context("线程地址溢出")?;
            let next = self.number(entry, "list_head", "next")?;
            ensure!(
                self.number(next, "list_head", "prev")? == entry,
                "线程 next/prev 不一致"
            );
            if next == head {
                break;
            }
            current = next.checked_sub(offset).context("线程地址下溢")?;
        }
        Ok(())
    }
    fn mounts(
        &self,
        task: u64,
        prefix: Vec<String>,
        result: &mut Results,
        job: &Job,
    ) -> Result<()> {
        if self.modern_mount() {
            return self.modern_mounts(task, prefix, result, job);
        }
        let ns = self.number(task, "task_struct", "nsproxy")?;
        if ns == 0 {
            return Ok(());
        }
        let ns = self.number(ns, "nsproxy", "mnt_ns")?;
        ensure!(ns != 0, "mnt_ns 为空");
        let head = self.field_address(ns, "mnt_namespace", "list")?;
        let offset = self.isf.offset("vfsmount", "mnt_list")?;
        let mut node = self.number(head, "list_head", "next")?;
        let mut visited = HashSet::new();
        while node != head {
            job.check()?;
            ensure!(visited.insert(node), "挂载链表循环 @ {}", hex(node));
            ensure!(visited.len() <= 1_000_000, "挂载超过 100 万项");
            let next = self.number(node, "list_head", "next")?;
            ensure!(
                self.number(next, "list_head", "prev")? == node,
                "挂载 next/prev 不一致"
            );
            let m = node.checked_sub(offset).context("挂载地址下溢")?;
            let read = (|| -> Result<Vec<String>> {
                let id = self.number(m, "vfsmount", "mnt_id")?;
                let parent = self.number(m, "vfsmount", "mnt_parent")?;
                let parent_id = self.number(parent, "vfsmount", "mnt_id")?;
                let dev = self.number(m, "vfsmount", "mnt_devname")?;
                let device = if dev == 0 {
                    "[none]".into()
                } else {
                    self.kernel_text(dev, 4096)?
                };
                let sb = self.number(m, "vfsmount", "mnt_sb")?;
                let ty = self.number(sb, "super_block", "s_type")?;
                let name = self.kernel_text(self.number(ty, "file_system_type", "name")?, 128)?;
                let d = self.number(m, "vfsmount", "mnt_root")?;
                let path = self.resolve_path(d, m, None, job)?;
                Ok([
                    prefix.clone(),
                    vec![
                        id.to_string(),
                        parent_id.to_string(),
                        device,
                        path,
                        name,
                        hex(self.number(m, "vfsmount", "mnt_flags")?),
                        hex(m),
                    ],
                ]
                .concat())
            })();
            match read {
                Ok(row) => result.rows.push(row),
                Err(e) => partial(result, format!("PID {} mount {}", prefix[0], hex(m)), e),
            }
            node = next;
        }
        Ok(())
    }
    pub(crate) fn kernel_text(&self, ptr: u64, limit: usize) -> Result<String> {
        ensure!(ptr != 0, "字符串指针为空");
        let mut bytes = Vec::new();
        for i in 0..limit {
            let b = self
                .vm
                .uint(ptr.checked_add(i as u64).context("字符串地址溢出")?, 1)?
                as u8;
            if b == 0 {
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
            bytes.push(b);
        }
        anyhow::bail!("内核字符串超过 {limit} 字节")
    }
    fn logs(&self, result: &mut Results, job: &Job) -> Result<()> {
        let read = (|| -> Result<()> {
            if self.isf.address("prb").is_ok() {
                return self.modern_logs(result, job);
            }
            let ptr = self.vm.uint(self.isf.address("log_buf")?, 8)?;
            let size = self.vm.uint(self.isf.address("log_buf_len")?, 4)?;
            ensure!(
                size > 0 && size <= 16 * 1024 * 1024 && size.is_power_of_two(),
                "printk 缓冲区长度无效/超过 16 MiB"
            );
            // Linux 3.2 SYSLOG_ACTION_READ_ALL / kdb_syslog_data semantics.
            // log_start tracks the consuming syslog reader, not retained history.
            let end = self.vm.uint(self.isf.address("log_end")?, 4)? as u32;
            let length = self
                .vm
                .uint(self.isf.address("logged_chars")?, 4)?
                .min(size);
            let start = end.wrapping_sub(length as u32);
            let mut bytes = Vec::with_capacity(length as usize);
            let mut pos = start as u64;
            while bytes.len() < (length as usize) {
                job.check()?;
                let index = pos & (size - 1);
                let n = (size - index).min(length - bytes.len() as u64).min(4096) as usize;
                let old = bytes.len();
                bytes.resize(old + n, 0);
                self.vm.read(
                    ptr.checked_add(index).context("日志地址溢出")?,
                    &mut bytes[old..],
                )?;
                pos += n as u64;
            }
            for (i, line) in String::from_utf8_lossy(&bytes)
                .split_terminator('\n')
                .enumerate()
            {
                result.rows.push(vec![i.to_string(), line.into()]);
            }
            Ok(())
        })();
        if let Err(e) = read {
            job.check()?;
            partial(result, "dmesg", e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        extended::tests::{engine, fixture, image, path_fixture},
        symbols::Isf,
    };
    use serde_json::json;
    fn put(b: &mut [u8], at: usize, n: u64) {
        b[at..at + 8].copy_from_slice(&n.to_le_bytes());
    }
    fn setup() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        path_fixture(&mut b);
        for (s, f, o) in [
            ("task_struct", "cred", 72),
            ("task_struct", "thread_group", 80),
            ("task_struct", "nsproxy", 104),
            ("task_struct", "group_leader", 112),
            ("fs_struct", "pwd", 16),
            ("vfsmount", "mnt_id", 24),
            ("vfsmount", "mnt_list", 32),
            ("vfsmount", "mnt_devname", 48),
            ("vfsmount", "mnt_flags", 56),
            ("vfsmount", "mnt_sb", 64),
            ("dentry", "d_sb", 32),
        ] {
            isf.data["user_types"][s]["fields"][f] =
                json!({"offset":o,"type":{"kind":"base","name":"u64"}});
        }
        for (name, fields) in [
            (
                "cred",
                vec![
                    "uid", "gid", "euid", "egid", "suid", "sgid", "fsuid", "fsgid",
                ],
            ),
            ("nsproxy", vec!["mnt_ns"]),
            ("mnt_namespace", vec!["list"]),
            ("super_block", vec!["s_type"]),
            ("file_system_type", vec!["name"]),
        ] {
            let fields: serde_json::Map<String, serde_json::Value> = fields
                .into_iter()
                .enumerate()
                .map(|(i, f)| {
                    (
                        f.into(),
                        json!({"offset":i*8,"type":{"kind":"base","name":"u64"}}),
                    )
                })
                .collect();
            isf.data["user_types"][name] = json!({"size":128,"fields":fields});
        }
        isf.data["user_types"]["nsproxy"]["size"] = json!(8);
        isf.data["user_types"]["mnt_namespace"]["fields"]["list"]["type"] =
            json!({"kind":"struct","name":"list_head"});
        for (at, pid) in [(0xa000, 1), (0xa100, 2)] {
            put(&mut b, at + 72, 0xd000);
            put(&mut b, at + 112, at as u64);
            put(&mut b, at + 80, at as u64 + 80);
            put(&mut b, at + 88, at as u64 + 80);
            put(&mut b, at + 16, pid);
        }
        for i in 0..8 {
            put(&mut b, 0xd000 + i * 8, 1000 + i as u64);
        }
        put(&mut b, 0xa050, 0xa250);
        put(&mut b, 0xa058, 0xa250);
        put(&mut b, 0xa250, 0xa050);
        put(&mut b, 0xa258, 0xa050);
        put(&mut b, 0xa210, 17);
        b[0xa228..0xa22e].copy_from_slice(b"worker");
        put(&mut b, 0xc010, 0xc300);
        put(&mut b, 0xc018, 0xc700);
        put(&mut b, 0xa068, 0xe100);
        put(&mut b, 0xe100, 0xe000);
        put(&mut b, 0xe000, 0xc120);
        put(&mut b, 0xe008, 0xc320);
        put(&mut b, 0xc120, 0xc320);
        put(&mut b, 0xc128, 0xe000);
        put(&mut b, 0xc320, 0xe000);
        put(&mut b, 0xc328, 0xc120);
        for m in [0xc100, 0xc300] {
            put(&mut b, m + 24, if m == 0xc100 { 1 } else { 2 });
            put(&mut b, m + 48, 0xe500);
            put(&mut b, m + 64, 0xe200);
        }
        put(&mut b, 0xe200, 0xe300);
        put(&mut b, 0xe300, 0xe400);
        b[0xe400..0xe405].copy_from_slice(b"ext4\0");
        b[0xe500..0xe510].copy_from_slice(b"/dev/vda1\0\0\0\0\0\0\0");
        put(&mut b, 0xc220, 0xe200);
        put(&mut b, 0xc420, 0xe200);
        for (s, addr) in [
            ("log_buf", 0xf000),
            ("log_buf_len", 0xf008),
            ("logged_chars", 0xf010),
            ("log_end", 0xf018),
        ] {
            isf.data["symbols"][s] = json!({"address":addr});
        }
        put(&mut b, 0xf000, 0xf100);
        put(&mut b, 0xf008, 16);
        put(&mut b, 0xf010, 6);
        put(&mut b, 0xf018, 4);
        b[0xf10e..0xf110].copy_from_slice(b"A\n");
        b[0xf100..0xf104].copy_from_slice(b"B\nC\n");
        (b, isf)
    }
    #[test]
    fn credentials_shared_groups_and_wrapped_ids() {
        let (mut b, mut isf) = setup();
        let job = Job::default();
        let i = image(&b);
        let l = engine(&i, &isf);
        let r = l.run(Plugin::Pscred, &job).unwrap();
        assert!(r.complete);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(
            &r.rows[0][2..10],
            &[
                "1000", "1001", "1002", "1003", "1004", "1005", "1006", "1007"
            ]
        );
        let r = l.run(Plugin::CheckCreds, &job).unwrap();
        assert_eq!(r.rows[0][1], "1,2");
        isf.data["user_types"]["cred"]["fields"]["uid"]["type"] =
            json!({"kind":"struct","name":"kuid_t"});
        isf.data["user_types"]["kuid_t"] =
            json!({"size":8,"fields":{"val":{"offset":0,"type":{"kind":"base","name":"u64"}}}});
        let r = engine(&i, &isf).run(Plugin::Pscred, &job).unwrap();
        assert_eq!(r.rows[0][2], "1000");
        put(&mut b, 0xa048, 0x50000);
        let i = image(&b);
        let r = engine(&i, &isf).run(Plugin::Pscred, &job).unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
    }
    #[test]
    fn working_directory_threads_and_mounts() {
        let (mut b, isf) = setup();
        let job = Job::default();
        let i = image(&b);
        let l = engine(&i, &isf);
        let r = l.run(Plugin::Pwd, &job).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(&r.rows[0][2..], &["/", "/mnt/file"]);
        assert_eq!(r.rows[1][2], "[none]");
        let r = l.run(Plugin::Threads, &job).unwrap();
        assert!(r.complete);
        assert_eq!(r.rows.len(), 3);
        assert_eq!(r.rows[1][2], "17");
        let r = l.run(Plugin::Mountinfo, &job).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.rows[1][5], "/mnt");
        assert_eq!(r.rows[1][6], "ext4");
        put(&mut b, 0xa250, 0xa250);
        let i = image(&b);
        assert!(
            !engine(&i, &isf)
                .run(Plugin::Threads, &job)
                .unwrap()
                .complete
        );
        put(&mut b, 0xc320, 0xc320);
        let i = image(&b);
        assert!(
            !engine(&i, &isf)
                .run(Plugin::Mountinfo, &job)
                .unwrap()
                .complete
        );
    }
    #[test]
    fn log_ring_wrap_clear_corruption_and_missing_layout() {
        let (mut b, mut isf) = setup();
        let job = Job::default();
        let i = image(&b);
        let r = engine(&i, &isf).run(Plugin::Dmesg, &job).unwrap();
        assert!(r.complete);
        assert_eq!(r.rows, vec![vec!["0", "A"], vec!["1", "B"], vec!["2", "C"]]);
        put(&mut b, 0xf010, 0);
        let i = image(&b);
        assert!(
            engine(&i, &isf)
                .run(Plugin::Dmesg, &job)
                .unwrap()
                .rows
                .is_empty()
        );
        put(&mut b, 0xf008, 19);
        let i = image(&b);
        assert!(!engine(&i, &isf).run(Plugin::Dmesg, &job).unwrap().complete);
        isf.data["symbols"]
            .as_object_mut()
            .unwrap()
            .remove("logged_chars");
        assert!(
            engine(&i, &isf)
                .run(Plugin::Dmesg, &job)
                .unwrap_err()
                .to_string()
                .contains("不支持")
        );
    }
}
