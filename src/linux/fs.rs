//! Open files, path reconstruction and mount tables.
use super::*;
impl Linux<'_> {
    pub(super) fn inode(&self, file: u64) -> Result<u64> {
        let path = self.field_address(file, "file", "f_path")?;
        let dentry = self.number(path, "path", "dentry")?;
        let inode = self.number(dentry, "dentry", "d_inode")?;
        ensure!(inode != 0, "文件 inode 为空");
        Ok(inode)
    }
    pub(super) fn files(
        &self,
        task: u64,
        prefix: Vec<String>,
        plugin: Plugin,
        result: &mut Results,
        job: &Job,
    ) -> Result<()> {
        self.files_bounded(task, prefix, plugin, result, job, OBJECT_LIMIT)
    }
    pub(super) fn files_bounded(
        &self,
        task: u64,
        prefix: Vec<String>,
        plugin: Plugin,
        result: &mut Results,
        job: &Job,
        limit: u64,
    ) -> Result<()> {
        let files = self.number(task, "task_struct", "files")?;
        if files == 0 {
            return Ok(());
        }
        let table = self.number(files, "files_struct", "fdt")?;
        ensure!(table != 0, "fdtable 为空");
        let count = self.number(table, "fdtable", "max_fds")?;
        let array = self.number(table, "fdtable", "fd")?;
        ensure!(count == 0 || array != 0, "FD 数组为空");
        let mut seen_sockets = HashSet::new();
        for fd in 0..count.min(limit) {
            job.check()?;
            let row = (|| -> Result<Option<Vec<String>>> {
                let slot = array.checked_add(fd * 8).context("FD 地址溢出")?;
                let file = self.vm.uint(slot, 8)?;
                if file == 0 {
                    return Ok(None);
                }
                let inode = self.inode(file)?;
                let mode = self.number(inode, "inode", "i_mode")?;
                let mut row = prefix.clone();
                if plugin != Plugin::Netscan {
                    row.push(fd.to_string());
                }
                if plugin == Plugin::Lsof {
                    let ino = self.number(inode, "inode", "i_ino")?;
                    let path = match mode & 0xf000 {
                        0xc000 => format!("socket:[{ino}]"),
                        0x1000 => {
                            // Named FIFOs still have a normal path; anonymous pipes live on pipefs.
                            let p = self.field_address(file, "file", "f_path")?;
                            let d = self.number(p, "path", "dentry")?;
                            if self.number(d, "dentry", "d_parent")? == d {
                                format!("pipe:[{ino}]")
                            } else {
                                self.file_path(task, file, job)?
                            }
                        }
                        _ => match self.file_path(task, file, job) {
                            Ok(path) => path,
                            Err(e) => {
                                job.check()?;
                                partial(result, format!("PID {} FD {fd} 路径", prefix[0]), e);
                                "[unresolved]".into()
                            }
                        },
                    };
                    row.extend([inode_type(mode).into(), ino.to_string(), path, hex(file)]);
                } else {
                    if mode & 0xf000 != 0xc000 {
                        return Ok(None);
                    }
                    if plugin == Plugin::Netscan {
                        let Some(socket) = self.internet_socket(inode)? else {
                            return Ok(None);
                        };
                        if !seen_sockets.insert(socket[6].clone()) {
                            return Ok(None);
                        }
                        row.push(format!(
                            "{}v{}",
                            socket[2],
                            if socket[0] == "IPv4" { 4 } else { 6 }
                        ));
                        row.extend(socket[3..].iter().cloned());
                    } else {
                        row.extend(self.socket(inode)?);
                    }
                }
                Ok(Some(row))
            })();
            match row {
                Ok(Some(row)) => result.rows.push(row),
                Ok(None) => {}
                Err(e) => partial(result, format!("PID {} FD {fd}", prefix[0]), e),
            }
        }
        ensure!(count <= limit, "FD 超过 100 万项上限 ({count})");
        Ok(())
    }
    pub(crate) fn file_path(&self, task: u64, file: u64, job: &Job) -> Result<String> {
        let fs = self.number(task, "task_struct", "fs")?;
        ensure!(fs != 0, "进程 fs 为空");
        let root = self.field_address(fs, "fs_struct", "root")?;
        let root_d = self.number(root, "path", "dentry")?;
        let root_m = self.number(root, "path", "mnt")?;
        ensure!(root_d != 0 && root_m != 0, "进程根目录为空");
        let path = self.field_address(file, "file", "f_path")?;
        let d = self.number(path, "path", "dentry")?;
        let m = self.number(path, "path", "mnt")?;
        self.resolve_path(d, m, Some((root_d, root_m)), job)
    }
    pub(crate) fn resolve_path(
        &self,
        mut d: u64,
        mut m: u64,
        root: Option<(u64, u64)>,
        job: &Job,
    ) -> Result<String> {
        let mut parts = Vec::new();
        let mut visited = HashSet::new();
        for _ in 0..1024 {
            job.check()?;
            if root == Some((d, m)) {
                parts.reverse();
                return Ok(format!("/{}", parts.join("/")));
            }
            ensure!(
                d != 0 && m != 0 && visited.insert((d, m)),
                "路径为空或循环 @ {}",
                hex(d)
            );
            if d == self.number(m, "vfsmount", "mnt_root")? {
                let parent = self.number(m, "vfsmount", "mnt_parent")?;
                if parent == m && self.filesystem(d)? == "tmpfs" {
                    parts.reverse();
                    return Ok(format!("[tmpfs]/{}", parts.join("/")));
                }
                if parent == m && root.is_none() {
                    parts.reverse();
                    return Ok(format!("/{}", parts.join("/")));
                }
                ensure!(parent != m, "路径不在进程根目录内 @ {}", hex(d));
                d = self.number(m, "vfsmount", "mnt_mountpoint")?;
                m = parent;
                continue;
            }
            let qstr = self.field_address(d, "dentry", "d_name")?;
            let len = self.number(qstr, "qstr", "len")?;
            ensure!((1..=255).contains(&len), "路径名称长度无效: {len}");
            let ptr = self.number(qstr, "qstr", "name")?;
            let mut bytes = vec![0; len as usize + 1];
            self.vm.read(ptr, &mut bytes)?;
            ensure!(
                bytes[len as usize] == 0 && !bytes[..len as usize].contains(&0),
                "路径名称无效"
            );
            parts.push(String::from_utf8_lossy(&bytes[..len as usize]).into_owned());
            let parent = self.number(d, "dentry", "d_parent")?;
            if parent == d && self.filesystem(d)? == "anon_inodefs" {
                return Ok(format!("anon_inode:[{}]", parts[0]));
            }
            ensure!(parent != d, "路径未到根目录");
            d = parent;
        }
        bail!("路径超过 1024 层上限")
    }
    pub(super) fn filesystem(&self, dentry: u64) -> Result<String> {
        let sb = self.number(dentry, "dentry", "d_sb")?;
        let ty = self.number(sb, "super_block", "s_type")?;
        let ptr = self.number(ty, "file_system_type", "name")?;
        self.vm.string(ptr, 32)
    }
    pub(super) fn mounts(
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
    pub(crate) fn modern_mounts(
        &self,
        task: u64,
        prefix: Vec<String>,
        result: &mut Results,
        job: &Job,
    ) -> Result<()> {
        let proxy = self.number(task, "task_struct", "nsproxy")?;
        if proxy == 0 {
            return Ok(());
        }
        let ns = self.number(proxy, "nsproxy", "mnt_ns")?;
        let mut stack = vec![self.number(ns, "mnt_namespace", "root")?];
        let mut seen = HashSet::new();
        let offset = self.isf.offset("mount", "mnt")?;
        while let Some(m) = stack.pop() {
            job.check()?;
            ensure!(
                m != 0 && seen.insert(m) && seen.len() <= 1_000_000,
                "挂载树循环或上限"
            );
            let next = self.list_objects(
                self.field_address(m, "mount", "mnt_mounts")?,
                self.isf.offset("mount", "mnt_child")?,
                job,
            )?;
            stack.extend(next.into_iter().rev());
            let read = (|| -> Result<Vec<String>> {
                let parent = self.number(m, "mount", "mnt_parent")?;
                let dev = self.number(m, "mount", "mnt_devname")?;
                let sb = self.number(m + offset, "vfsmount", "mnt_sb")?;
                let ty = self.number(sb, "super_block", "s_type")?;
                let path = self.resolve_path(
                    self.number(m + offset, "vfsmount", "mnt_root")?,
                    m + offset,
                    None,
                    job,
                )?;
                Ok([
                    prefix.clone(),
                    vec![
                        self.number(m, "mount", "mnt_id")?.to_string(),
                        self.number(parent, "mount", "mnt_id")?.to_string(),
                        if dev == 0 {
                            "[none]".into()
                        } else {
                            self.kernel_text(dev, 4096)?
                        },
                        path,
                        self.kernel_text(self.number(ty, "file_system_type", "name")?, 128)?,
                        format!(
                            "{:#018x}",
                            self.number(m + offset, "vfsmount", "mnt_flags")?
                        ),
                        format!("{:#018x}", m + offset),
                    ],
                ]
                .concat())
            })();
            match read {
                Ok(row) => result.rows.push(row),
                Err(e) => {
                    result.complete = false;
                    result
                        .diagnostics
                        .push(format!("PID {} mount {m:#x}: {e:#}", prefix[0]));
                }
            }
        }
        ensure!(
            seen.len() as u64 == self.number(ns, "mnt_namespace", "nr_mounts")?,
            "挂载树数量与 namespace.mounts 不一致"
        );
        Ok(())
    }
}
