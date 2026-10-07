//! Per-task plugins: arguments, environment, credentials, threads, state and ptrace.
use super::*;
impl Linux<'_> {
    pub(super) fn preflight(&self, plugin: Plugin) -> Result<()> {
        self.require(&[
            ("task_struct", "pid"),
            ("task_struct", "tgid"),
            ("task_struct", "comm"),
            ("task_struct", "real_parent"),
            ("task_struct", "tasks"),
            ("list_head", "next"),
            ("list_head", "prev"),
        ])?;
        self.isf
            .address("init_task")
            .context("不支持: 缺少 init_task 符号")?;
        if matches!(plugin, Plugin::Psaux | Plugin::Envars | Plugin::Maps) {
            self.require(&[("task_struct", "mm")])?;
        }
        match plugin {
            Plugin::Psaux | Plugin::Envars => {
                self.require(&[("mm_struct", "pgd")])?;
                let fields = if plugin == Plugin::Psaux {
                    ["arg_start", "arg_end"]
                } else {
                    ["env_start", "env_end"]
                };
                for f in fields {
                    self.require(&[("mm_struct", f)])?;
                }
            }
            Plugin::Maps => self.require(&[
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
            ])?,
            Plugin::Lsof | Plugin::Sockstat => self.require(&[
                ("task_struct", "files"),
                ("files_struct", "fdt"),
                ("fdtable", "max_fds"),
                ("fdtable", "fd"),
                ("file", "f_path"),
                ("path", "dentry"),
                ("dentry", "d_inode"),
                ("inode", "i_mode"),
                ("inode", "i_ino"),
            ])?,
            _ => {}
        }
        if matches!(plugin, Plugin::Maps | Plugin::Lsof) {
            self.require(&[
                ("task_struct", "fs"),
                ("fs_struct", "root"),
                ("file", "f_path"),
                ("path", "mnt"),
                ("path", "dentry"),
                ("dentry", "d_parent"),
                ("dentry", "d_name"),
                ("qstr", "len"),
                ("qstr", "name"),
                ("vfsmount", "mnt_root"),
                ("vfsmount", "mnt_parent"),
                ("vfsmount", "mnt_mountpoint"),
            ])?;
        }
        if plugin == Plugin::Sockstat {
            self.require(&[
                ("socket_alloc", "vfs_inode"),
                ("socket_alloc", "socket"),
                ("socket", "sk"),
                ("sock", "__sk_common"),
                ("sock", "sk_type"),
                ("sock", "sk_protocol"),
                ("sock", "sk_socket"),
                ("sock_common", "skc_family"),
                ("sock_common", "skc_state"),
                ("sock_common", "skc_rcv_saddr"),
                ("sock_common", "skc_daddr"),
                ("inet_sock", "inet_sport"),
                (
                    if self.isf.field("inet_sock", "inet_dport").is_ok() {
                        "inet_sock"
                    } else {
                        "sock_common"
                    },
                    if self.isf.field("inet_sock", "inet_dport").is_ok() {
                        "inet_dport"
                    } else {
                        "skc_dport"
                    },
                ),
                ("unix_sock", "addr"),
                ("unix_sock", "peer"),
                ("unix_address", "len"),
                ("unix_address", "name"),
                ("sockaddr_un", "sun_path"),
            ])?;
        }
        Ok(())
    }
    /// psaux / envars / maps / lsof / sockstat: user memory and open files of every task.
    pub(super) fn task_objects(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        self.preflight(plugin)?;
        // Reuse the validated tasks list and identity reader of pslist.
        let (mut result, processes) = self.tasks(plugin, job)?;
        for process in processes {
            job.check()?;
            let task = process.address;
            let context = format!("PID {} @ {}", process.pid, hex(task));
            let read = (|| -> Result<()> {
                let prefix = vec![process.pid.clone(), process.name.clone()];
                match plugin {
                    Plugin::Psaux | Plugin::Envars => {
                        let mm = self.number(task, "task_struct", "mm")?;
                        if mm == 0 {
                            if plugin == Plugin::Psaux {
                                result.rows.push(
                                    [
                                        prefix,
                                        vec![format!("[{}]", process.name), "KernelThread".into()],
                                    ]
                                    .concat(),
                                );
                            }
                            return Ok(());
                        }
                        let bytes = self.user_region(
                            mm,
                            if plugin == Plugin::Psaux {
                                "arg"
                            } else {
                                "env"
                            },
                            job,
                        )?;
                        if plugin == Plugin::Psaux {
                            result
                                .rows
                                .push([prefix, vec![command_line(&bytes), "OK".into()]].concat());
                        } else {
                            for entry in nul_strings(&bytes) {
                                let (key, value) = entry.split_once('=').unwrap_or((&entry, ""));
                                result.rows.push(
                                    [prefix.clone(), vec![key.into(), value.into()]].concat(),
                                );
                            }
                        }
                    }
                    Plugin::Maps => self.maps(task, prefix, &mut result, job)?,
                    Plugin::Lsof | Plugin::Sockstat => {
                        self.files(task, prefix, plugin, &mut result, job)?
                    }
                    _ => return Err(unrouted(plugin)),
                }
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                partial(&mut result, context, e);
            }
            job.report(format!("{}: {} 条", plugin.name(), result.rows.len()));
        }
        job.check()?;
        Ok(result)
    }
    /// pwd / pscred / check_creds / threads / mountinfo: per-task context objects.
    pub(super) fn task_context(&self, plugin: Plugin, job: &Job) -> Result<Results> {
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
            _ => return Err(unrouted(plugin)),
        };
        self.require(&required)?;
        self.require(&[
            ("task_struct", "pid"),
            ("task_struct", "tgid"),
            ("task_struct", "comm"),
            ("task_struct", "real_parent"),
            ("task_struct", "tasks"),
            ("list_head", "next"),
            ("list_head", "prev"),
        ])?;
        if plugin == Plugin::Mountinfo {
            self.require(&[
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
                    self.require(&[("cred", &format!("{f}.val"))])?;
                }
            }
        }

        let (mut result, tasks) = self.tasks(plugin, job)?;
        let mut credentials: BTreeMap<u64, Vec<(String, String)>> = BTreeMap::new();
        let mut leaders = HashSet::new();
        for task in tasks {
            job.check()?;
            let addr = task.address;
            let prefix = vec![task.pid.clone(), task.name.clone()];
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
                                .push((task.pid.clone(), task.name.clone()));
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
                    _ => return Err(unrouted(plugin)),
                }
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                partial(&mut result, format!("PID {} @ {}", task.pid, hex(addr)), e);
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
    pub(super) fn credential(&self, cred: u64, field: &str) -> Result<u64> {
        let ty = &self.isf.field("cred", field)?["type"];
        if ty["kind"] == "struct" {
            self.number(cred, "cred", &format!("{field}.val"))
        } else {
            self.number(cred, "cred", field)
        }
    }
    pub(super) fn threads(
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
    /// psstate / capabilities / fdsummary: one row of task state per task.
    pub(super) fn task_state(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        let state = if self.isf.field("task_struct", "__state").is_ok() {
            "__state"
        } else {
            "state"
        };
        let fields = match plugin {
            Plugin::Psstate => vec![
                ("task_struct", state),
                ("task_struct", "exit_state"),
                ("task_struct", "flags"),
            ],
            Plugin::Capabilities => vec![
                ("task_struct", "cred"),
                ("cred", "cap_inheritable"),
                ("cred", "cap_permitted"),
                ("cred", "cap_effective"),
                ("cred", "cap_bset"),
            ],
            _ => vec![],
        };
        for (structure, field) in fields {
            let size = self
                .isf
                .size(structure, field)
                .with_context(|| format!("不支持: 缺少 {structure}.{field}"))?;
            ensure!(
                (1..=8).contains(&size),
                "不支持: {structure}.{field} 超过 64 位"
            );
        }
        let (mut result, tasks) = self.tasks(plugin, job)?;
        let mut counts: BTreeMap<String, [u64; 4]> = BTreeMap::new();
        if plugin == Plugin::Fdsummary {
            let files = self.run(Plugin::Lsof, job)?;
            result.complete &= files.complete;
            result.diagnostics.extend(files.diagnostics);
            for row in files.rows {
                job.check()?;
                let n = counts.entry(row[0].clone()).or_default();
                n[0] += 1;
                match row[3].as_str() {
                    "Regular" => n[1] += 1,
                    "Socket" => n[2] += 1,
                    "FIFO" => n[3] += 1,
                    _ => {}
                }
            }
        }
        for task in tasks {
            job.check()?;
            let address = task.address;
            let read = (|| -> Result<Vec<String>> {
                let mut row = vec![task.pid.clone(), task.name.clone()];
                match plugin {
                    Plugin::Psstate => {
                        for field in [state, "exit_state", "flags"] {
                            row.push(format!(
                                "{:#018x}",
                                self.number(address, "task_struct", field)?
                            ));
                        }
                    }
                    Plugin::Capabilities => {
                        let cred = self.number(address, "task_struct", "cred")?;
                        ensure!(cred != 0, "空 cred 指针");
                        for field in [
                            "cap_inheritable",
                            "cap_permitted",
                            "cap_effective",
                            "cap_bset",
                        ] {
                            row.push(format!("{:#018x}", self.number(cred, "cred", field)?));
                        }
                        row.push(format!("{cred:#018x}"));
                    }
                    Plugin::Fdsummary => {
                        let n = counts.get(&task.pid).copied().unwrap_or_default();
                        row.extend(n.iter().map(u64::to_string));
                    }
                    _ => return Err(unrouted(plugin)),
                }
                Ok(row)
            })();
            match read {
                Ok(row) => result.rows.push(row),
                Err(e) => {
                    result.complete = false;
                    result
                        .diagnostics
                        .push(format!("PID {} @ {address:#x}: {e:#}", task.pid));
                }
            }
        }
        Ok(result)
    }
    pub(super) fn ptrace(&self, result: &mut Results, job: &Job) -> Result<()> {
        self.require(&[
            ("task_struct", "ptrace"),
            ("task_struct", "parent"),
            ("task_struct", "ptraced"),
            ("task_struct", "ptrace_entry"),
            ("task_struct", "pid"),
            ("task_struct", "tgid"),
            ("list_head", "next"),
            ("list_head", "prev"),
        ])?;
        let threads = self.run(Plugin::Threads, job)?;
        result.complete &= threads.complete;
        result.diagnostics.extend(threads.diagnostics);
        let mut tasks = BTreeMap::new();
        for row in threads.rows {
            let address = u64::from_str_radix(&row[4][2..], 16)?;
            tasks.insert(address, row);
        }
        for (address, task) in tasks {
            job.check()?;
            let context = format!("TID {} @ {}", task[2], hex(address));
            let read = (|| -> Result<()> {
                let flags = self.number(address, "task_struct", "ptrace")?;
                let tracer = if flags == 0 {
                    "[none]".into()
                } else {
                    let parent = self.number(address, "task_struct", "parent")?;
                    ensure!(parent != 0, "ptrace parent 为空");
                    self.number(parent, "task_struct", "pid")?.to_string()
                };
                let head = self.field_address(address, "task_struct", "ptraced")?;
                let offset = self.isf.offset("task_struct", "ptrace_entry")?;
                let mut tracees = Vec::new();
                let walk = (|| -> Result<()> {
                    let mut entry = self.number(head, "list_head", "next")?;
                    let mut previous = head;
                    let mut seen = HashSet::new();
                    while entry != head {
                        job.check()?;
                        ensure!(entry != 0 && seen.insert(entry), "ptraced 链表空指针或循环");
                        ensure!(seen.len() <= LIMIT, "ptraced 链表超过 {LIMIT} 项");
                        ensure!(
                            self.number(entry, "list_head", "prev")? == previous,
                            "ptraced next/prev 不一致"
                        );
                        let tracee = entry.checked_sub(offset).context("ptrace_entry 地址下溢")?;
                        tracees.push(self.number(tracee, "task_struct", "pid")?.to_string());
                        previous = entry;
                        entry = self.number(entry, "list_head", "next")?;
                    }
                    ensure!(
                        self.number(head, "list_head", "prev")? == previous,
                        "ptraced 尾指针不一致"
                    );
                    Ok(())
                })();
                if let Err(e) = walk {
                    job.check()?;
                    partial(result, &context, e);
                }
                if flags != 0 && tracees.is_empty() {
                    tracees.push("[none]".into());
                }
                for tracee in tracees {
                    result.rows.push(vec![
                        task[3].clone(),
                        self.number(address, "task_struct", "tgid")?.to_string(),
                        task[2].clone(),
                        tracer.clone(),
                        tracee,
                        hex(flags),
                    ]);
                }
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                partial(result, context, e);
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        linux::tests::{engine, fixture, image, path_fixture},
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
