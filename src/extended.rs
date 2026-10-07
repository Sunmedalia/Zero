//! Process-associated Linux 3.2 objects, using only ISF supplied offsets.
use crate::{
    Job,
    image::VirtualMemory,
    linux::{Linux, Plugin},
    report::{hex, partial},
    store::Results,
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
};
const REGION_LIMIT: u64 = 1024 * 1024;
const OBJECT_LIMIT: u64 = 1_000_000;
fn nul_strings(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .collect()
}
fn command_line(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    bytes
        .split(|b| *b == 0)
        .map(|b| String::from_utf8_lossy(b))
        .collect::<Vec<_>>()
        .join(" ")
}
fn permissions(flags: u64) -> String {
    [
        if flags & 1 != 0 { 'r' } else { '-' },
        if flags & 2 != 0 { 'w' } else { '-' },
        if flags & 4 != 0 { 'x' } else { '-' },
        if flags & 8 != 0 { 's' } else { 'p' },
    ]
    .iter()
    .collect()
}
fn inode_type(mode: u64) -> &'static str {
    match mode & 0xf000 {
        0x1000 => "FIFO",
        0x2000 => "Character",
        0x4000 => "Directory",
        0x6000 => "Block",
        0x8000 => "Regular",
        0xa000 => "Symlink",
        0xc000 => "Socket",
        _ => "Unknown",
    }
}
impl Linux<'_> {
    fn preflight(&self, plugin: Plugin) -> Result<()> {
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
    pub(crate) fn run_extended(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        self.preflight(plugin)?;
        // Reuse the validated tasks list and identity reader of pslist.
        let mut result = self.run(Plugin::Pslist, job)?;
        let processes = std::mem::take(&mut result.rows);
        result.plugin = plugin.name().into();
        result.columns = plugin
            .descriptor()
            .columns
            .iter()
            .map(|s| (*s).into())
            .collect();
        for process in processes {
            job.check()?;
            let task = u64::from_str_radix(&process[4][2..], 16)?;
            let context = format!("PID {} @ {}", process[0], process[4]);
            let read = (|| -> Result<()> {
                let prefix = vec![process[0].clone(), process[3].clone()];
                match plugin {
                    Plugin::Psaux | Plugin::Envars => {
                        let mm = self.number(task, "task_struct", "mm")?;
                        if mm == 0 {
                            if plugin == Plugin::Psaux {
                                result.rows.push(
                                    [
                                        prefix,
                                        vec![format!("[{}]", process[3]), "KernelThread".into()],
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
                    _ => unreachable!(),
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
    fn user_region(&self, mm: u64, kind: &str, job: &Job) -> Result<Vec<u8>> {
        let start = self.number(mm, "mm_struct", &format!("{kind}_start"))?;
        let end = self.number(mm, "mm_struct", &format!("{kind}_end"))?;
        let length = end.checked_sub(start).context("用户区域地址倒置")?;
        ensure!(
            length <= REGION_LIMIT,
            "用户区域超过 1 MiB 上限 ({length} bytes)"
        );
        if length == 0 {
            return Ok(Vec::new());
        }
        let bits = self
            .vm
            .image
            .arm64_va_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        let ceiling = if bits == 0 { 1u64 << 47 } else { 1u64 << bits };
        ensure!(
            start < ceiling && end <= ceiling,
            "用户区域超出用户地址空间"
        );
        let pgd = self.number(mm, "mm_struct", "pgd")?;
        let root = self.vm.translate(pgd).context("mm.pgd 内核地址转换失败")?;
        ensure!(root & 4095 == 0, "进程页表未对齐");
        let vm = VirtualMemory {
            image: self.vm.image,
            root,
        };
        let mut out = vec![0; length as usize];
        for (i, chunk) in out.chunks_mut(4096).enumerate() {
            job.check()?;
            vm.read(start + i as u64 * 4096, chunk)?;
        }
        Ok(out)
    }
    fn maps(&self, task: u64, prefix: Vec<String>, result: &mut Results, job: &Job) -> Result<()> {
        self.maps_bounded(task, prefix, result, job, OBJECT_LIMIT)
    }
    fn maps_bounded(
        &self,
        task: u64,
        prefix: Vec<String>,
        result: &mut Results,
        job: &Job,
        limit: u64,
    ) -> Result<()> {
        let mm = self.number(task, "task_struct", "mm")?;
        if mm == 0 {
            return Ok(());
        }
        let modern = self.isf.field("mm_struct", "mmap").is_err();
        let mut nodes = if modern {
            self.maple_vmas(mm, job, limit)?.into_iter()
        } else {
            Vec::new().into_iter()
        };
        let mut node = if modern {
            nodes.next().unwrap_or(0)
        } else {
            self.number(mm, "mm_struct", "mmap")?
        };
        let mut visited = HashSet::new();
        while node != 0 {
            job.check()?;
            ensure!(visited.insert(node), "VMA 循环 @ {}", hex(node));
            ensure!(visited.len() as u64 <= limit, "VMA 超过 100 万项上限");
            let next = if modern {
                nodes.next().unwrap_or(0)
            } else {
                self.number(node, "vm_area_struct", "vm_next")?
            };
            let row = (|| -> Result<Vec<String>> {
                let start = self.number(node, "vm_area_struct", "vm_start")?;
                let end = self.number(node, "vm_area_struct", "vm_end")?;
                ensure!(start < end, "VMA 地址倒置");
                let flags = self.number(node, "vm_area_struct", "vm_flags")?;
                let offset = self
                    .number(node, "vm_area_struct", "vm_pgoff")?
                    .checked_mul(4096)
                    .context("VMA 文件偏移溢出")?;
                let file = self.number(node, "vm_area_struct", "vm_file")?;
                let path = if file == 0 {
                    "[anonymous]".into()
                } else {
                    match self.file_path(task, file, job) {
                        Ok(path) => path,
                        Err(e) => {
                            job.check()?;
                            partial(
                                result,
                                format!("PID {} VMA {} 路径", prefix[0], hex(node)),
                                e,
                            );
                            "[unresolved]".into()
                        }
                    }
                };
                Ok([
                    prefix.clone(),
                    vec![
                        hex(start),
                        hex(end),
                        permissions(flags),
                        offset.to_string(),
                        path,
                    ],
                ]
                .concat())
            })();
            match row {
                Ok(row) => result.rows.push(row),
                Err(e) => partial(result, format!("PID {} VMA {}", prefix[0], hex(node)), e),
            }
            node = next;
        }
        Ok(())
    }
    fn inode(&self, file: u64) -> Result<u64> {
        let path = self.field_address(file, "file", "f_path")?;
        let dentry = self.number(path, "path", "dentry")?;
        let inode = self.number(dentry, "dentry", "d_inode")?;
        ensure!(inode != 0, "文件 inode 为空");
        Ok(inode)
    }
    fn files(
        &self,
        task: u64,
        prefix: Vec<String>,
        plugin: Plugin,
        result: &mut Results,
        job: &Job,
    ) -> Result<()> {
        self.files_bounded(task, prefix, plugin, result, job, OBJECT_LIMIT)
    }
    fn files_bounded(
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
                let ino = self.number(inode, "inode", "i_ino")?;
                let mut row = prefix.clone();
                row.push(fd.to_string());
                if plugin == Plugin::Lsof {
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
                    row.extend(self.socket(inode)?);
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
    fn filesystem(&self, dentry: u64) -> Result<String> {
        let sb = self.number(dentry, "dentry", "d_sb")?;
        let ty = self.number(sb, "super_block", "s_type")?;
        let ptr = self.number(ty, "file_system_type", "name")?;
        self.vm.string(ptr, 32)
    }
    fn socket(&self, inode: u64) -> Result<Vec<String>> {
        let allocation = inode
            .checked_sub(self.isf.offset("socket_alloc", "vfs_inode")?)
            .context("socket 地址下溢")?;
        let socket = self.field_address(allocation, "socket_alloc", "socket")?;
        let sk = self.number(socket, "socket", "sk")?;
        ensure!(sk != 0, "socket.sk 为空 @ {}", hex(socket));
        let common = self.field_address(sk, "sock", "__sk_common")?;
        let family = self.number(common, "sock_common", "skc_family")?;
        let ty = self.number(sk, "sock", "sk_type")?;
        let protocol = self.number(sk, "sock", "sk_protocol")?;
        let type_name = match ty {
            1 => "STREAM".into(),
            2 => "DGRAM".into(),
            3 => "RAW".into(),
            5 => "SEQPACKET".into(),
            _ => ty.to_string(),
        };
        let protocol_name = match protocol {
            6 => "TCP".into(),
            17 => "UDP".into(),
            _ => protocol.to_string(),
        };
        let (family_name, local, remote, state) = match family {
            2 | 10 if matches!(protocol, 6 | 17) => {
                let sport = (self.number(sk, "inet_sock", "inet_sport")? as u16).to_be();
                let dport = (if self.isf.field("inet_sock", "inet_dport").is_ok() {
                    self.number(sk, "inet_sock", "inet_dport")?
                } else {
                    self.number(common, "sock_common", "skc_dport")?
                } as u16)
                    .to_be();
                let (local, remote) = if family == 2 {
                    let local = Ipv4Addr::from(
                        (self.number(common, "sock_common", "skc_rcv_saddr")? as u32).to_le_bytes(),
                    );
                    let remote = Ipv4Addr::from(
                        (self.number(common, "sock_common", "skc_daddr")? as u32).to_le_bytes(),
                    );
                    (format!("{local}:{sport}"), format!("{remote}:{dport}"))
                } else {
                    let modern = self.isf.field("sock_common", "skc_v6_rcv_saddr").is_ok();
                    let info = if modern {
                        common
                    } else {
                        self.number(sk, "inet_sock", "pinet6")?
                    };
                    ensure!(info != 0, "IPv6 info 为空");
                    let mut local = [0; 16];
                    let mut remote = [0; 16];
                    self.vm.read(
                        self.field_address(
                            info,
                            if modern { "sock_common" } else { "ipv6_pinfo" },
                            if modern {
                                "skc_v6_rcv_saddr"
                            } else {
                                "rcv_saddr"
                            },
                        )?,
                        &mut local,
                    )?;
                    self.vm.read(
                        self.field_address(
                            info,
                            if modern { "sock_common" } else { "ipv6_pinfo" },
                            if modern { "skc_v6_daddr" } else { "daddr" },
                        )?,
                        &mut remote,
                    )?;
                    (
                        format!("[{}]:{sport}", Ipv6Addr::from(local)),
                        format!("[{}]:{dport}", Ipv6Addr::from(remote)),
                    )
                };
                let state = if protocol == 6 {
                    tcp_state(self.number(common, "sock_common", "skc_state")?).into()
                } else {
                    "UDP".into()
                };
                (
                    if family == 2 {
                        "IPv4".into()
                    } else {
                        "IPv6".into()
                    },
                    local,
                    remote,
                    state,
                )
            }
            1 => {
                let addr = self.number(sk, "unix_sock", "addr")?;
                let local = if addr == 0 {
                    "[unnamed]".into()
                } else {
                    let len = self.number(addr, "unix_address", "len")?;
                    let offset = self.isf.offset("sockaddr_un", "sun_path")?;
                    ensure!(
                        len >= offset
                            && len
                                <= self.isf.data["user_types"]["sockaddr_un"]["size"]
                                    .as_u64()
                                    .context("sockaddr_un size 缺失")?,
                        "Unix 名称长度无效: {len}"
                    );
                    let name = self
                        .field_address(addr, "unix_address", "name")?
                        .checked_add(offset)
                        .context("Unix 名称地址溢出")?;
                    let mut bytes = vec![0; (len - offset) as usize];
                    self.vm.read(name, &mut bytes)?;
                    unix_name(&bytes)
                };
                let peer = self.number(sk, "unix_sock", "peer")?;
                (
                    "Unix".into(),
                    local,
                    if peer == 0 {
                        "[none]".into()
                    } else {
                        hex(self.number(peer, "sock", "sk_socket")?)
                    },
                    tcp_state(self.number(common, "sock_common", "skc_state")?).into(),
                )
            }
            _ => (
                family.to_string(),
                String::new(),
                String::new(),
                "UnsupportedFamily".into(),
            ),
        };
        Ok(vec![
            family_name,
            type_name,
            protocol_name,
            local,
            remote,
            state,
            hex(socket),
        ])
    }
}
fn unix_name(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "[unnamed]".into()
    } else if bytes[0] == 0 {
        format!("@{}", String::from_utf8_lossy(&bytes[1..]))
    } else {
        String::from_utf8_lossy(bytes.split(|b| *b == 0).next().unwrap()).into_owned()
    }
}
fn tcp_state(state: u64) -> &'static str {
    match state {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        12 => "NEW_SYN_RECV",
        _ => "Unknown",
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{image::Image, symbols::Isf};
    use serde_json::{Value, json};
    use std::io::Write;
    fn put(b: &mut [u8], at: usize, n: u64) {
        b[at..at + 8].copy_from_slice(&n.to_le_bytes());
    }
    pub(crate) fn fixture() -> (Vec<u8>, Isf) {
        let mut b = vec![0; 0x40000];
        // Identity kernel mapping, independent user page table with two noncontiguous pages.
        put(&mut b, 0x1000, 0x2003);
        put(&mut b, 0x2000, 0x3003);
        put(&mut b, 0x3000, 0x83);
        put(&mut b, 0x4000, 0x5003);
        put(&mut b, 0x5000, 0x6003);
        put(&mut b, 0x6008, 0x7003);
        put(&mut b, 0x7000, 0x20003);
        put(&mut b, 0x7008, 0x25003);
        let mut types = serde_json::Map::new();
        for (name, fields) in [
            ("list_head", vec!["next", "prev"]),
            (
                "task_struct",
                vec![
                    "tasks",
                    "pid",
                    "tgid",
                    "real_parent",
                    "comm",
                    "mm",
                    "files",
                    "fs",
                ],
            ),
            (
                "mm_struct",
                vec![
                    "pgd",
                    "arg_start",
                    "arg_end",
                    "env_start",
                    "env_end",
                    "mmap",
                ],
            ),
            (
                "vm_area_struct",
                vec![
                    "vm_next", "vm_start", "vm_end", "vm_flags", "vm_pgoff", "vm_file",
                ],
            ),
            ("files_struct", vec!["fdt"]),
            ("fdtable", vec!["max_fds", "fd"]),
            ("file", vec!["f_path", "unused"]),
            ("path", vec!["mnt", "dentry"]),
            ("fs_struct", vec!["root", "unused"]),
            ("vfsmount", vec!["mnt_root", "mnt_parent", "mnt_mountpoint"]),
            ("dentry", vec!["d_parent", "d_name", "unused", "d_inode"]),
            ("qstr", vec!["len", "name"]),
            ("inode", vec!["i_mode", "i_ino"]),
            (
                "socket_alloc",
                vec!["socket", "unused", "vfs_inode", "unused2"],
            ),
            ("socket", vec!["sk", "state"]),
            ("sock", vec!["__sk_common", "sk_type", "sk_protocol"]),
            (
                "sock_common",
                vec!["skc_family", "skc_state", "skc_rcv_saddr", "skc_daddr"],
            ),
            (
                "inet_sock",
                vec![
                    "unused",
                    "unused2",
                    "unused3",
                    "unused4",
                    "inet_sport",
                    "inet_dport",
                    "pinet6",
                ],
            ),
            (
                "ipv6_pinfo",
                vec!["rcv_saddr", "unused", "daddr", "unused2"],
            ),
            (
                "unix_sock",
                vec!["unused", "unused2", "unused3", "unused4", "addr", "peer"],
            ),
            ("unix_address", vec!["len", "name"]),
            ("sockaddr_un", vec!["sun_family", "sun_path"]),
        ] {
            let fields: serde_json::Map<String, Value> = fields
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    (
                        f.to_string(),
                        json!({"offset": i*8,"type":{"kind":"base","name":"u64"}}),
                    )
                })
                .collect();
            types.insert(name.into(), json!({"size":128,"fields":fields}));
        }
        let mut data = json!({"user_types":types,"base_types":{"pointer":{"size":8},"u64":{"size":8},"u32":{"size":4},"char":{"size":1}},"symbols":{"init_task":{"address":0x9000}},"enums":{"state":{"size":4}}});
        for (s, f, ty) in [
            (
                "task_struct",
                "tasks",
                json!({"kind":"struct","name":"list_head"}),
            ),
            (
                "task_struct",
                "comm",
                json!({"kind":"array","count":8,"subtype":{"kind":"base","name":"char"}}),
            ),
            ("file", "f_path", json!({"kind":"struct","name":"path"})),
            ("fs_struct", "root", json!({"kind":"struct","name":"path"})),
            ("dentry", "d_name", json!({"kind":"struct","name":"qstr"})),
            (
                "sock",
                "__sk_common",
                json!({"kind":"struct","name":"sock_common"}),
            ),
            (
                "sock",
                "sk_type",
                json!({"kind":"bitfield","bit_position":3,"bit_length":16,"type":{"kind":"base","name":"u32"}}),
            ),
            (
                "sock",
                "sk_protocol",
                json!({"kind":"bitfield","bit_position":0,"bit_length":8,"type":{"kind":"base","name":"u32"}}),
            ),
            ("socket", "state", json!({"kind":"enum","name":"state"})),
            (
                "unix_address",
                "name",
                json!({"kind":"array","count":0,"subtype":{"kind":"struct","name":"sockaddr_un"}}),
            ),
        ] {
            data["user_types"][s]["fields"][f]["type"] = ty;
        }
        data["user_types"]["sock"]["fields"]["sk_type"]["offset"] = json!(32);
        data["user_types"]["sock"]["fields"]["sk_protocol"]["offset"] = json!(40);
        data["user_types"]["unix_sock"]["fields"]["addr"]["offset"] = json!(48);
        data["user_types"]["unix_sock"]["fields"]["peer"]["offset"] = json!(56);
        data["user_types"]["inet_sock"]["fields"]["inet_sport"]["offset"] = json!(48);
        data["user_types"]["inet_sock"]["fields"]["inet_dport"]["offset"] = json!(56);
        data["user_types"]["inet_sock"]["fields"]["pinet6"]["offset"] = json!(64);
        for name in ["list_head", "path", "qstr"] {
            data["user_types"][name]["size"] = json!(16);
        }
        data["user_types"]["sock"]["fields"]["sk_socket"] =
            json!({"offset":72,"type":{"kind":"pointer"}});
        // Closed task list: PID 1 followed by a kernel thread.
        put(&mut b, 0x9000, 0xa000);
        put(&mut b, 0x9008, 0xa100);
        put(&mut b, 0xa000, 0xa100);
        put(&mut b, 0xa008, 0x9000);
        put(&mut b, 0xa100, 0x9000);
        put(&mut b, 0xa108, 0xa000);
        for (at, pid) in [(0xa000, 1), (0xa100, 2)] {
            put(&mut b, at + 8 * 2, pid);
            put(&mut b, at + 8 * 3, pid);
            put(&mut b, at + 8 * 4, 0x9000);
        }
        // tasks takes 16 bytes; shift the remaining members beyond it.
        for f in ["pid", "tgid", "real_parent", "comm", "mm", "files", "fs"] {
            let offset = data["user_types"]["task_struct"]["fields"][f]["offset"]
                .as_u64()
                .unwrap();
            data["user_types"]["task_struct"]["fields"][f]["offset"] = json!(offset + 8);
        }
        b[0xa028..0xa02c].copy_from_slice(b"init");
        b[0xa128..0xa12b].copy_from_slice(b"kth");
        put(&mut b, 0xa030, 0xb000);
        put(&mut b, 0xa040, 0xc000);
        put(&mut b, 0xb000, 0x4000);
        put(&mut b, 0xb008, 0x200ffe);
        put(&mut b, 0xb010, 0x201008);
        b[0x20ffe..0x21000].copy_from_slice(b"a\0");
        b[0x25000..0x25008].copy_from_slice(b"b=c\0d\0\0\0");
        let isf = Isf {
            slide: std::sync::atomic::AtomicU64::new(0),
            data,
            label: "fixture".into(),
            digest: "fixture".into(),
            banner: b"Linux version fixture\0".to_vec(),
            locations: vec![],
            layouts: Default::default(),
        };
        (b, isf)
    }
    pub(crate) fn image(b: &[u8]) -> Image {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(b).unwrap();
        Image::from_file(f, "test".into()).unwrap()
    }
    pub(crate) fn engine<'a>(image: &'a Image, isf: &'a Isf) -> Linux<'a> {
        Linux {
            vm: VirtualMemory {
                image,
                root: 0x1000,
            },
            isf,
        }
    }
    #[test]
    fn process_regions_and_failures() {
        let (mut b, mut isf) = fixture();
        let job = Job::default();
        let i = image(&b);
        let linux = engine(&i, &isf);
        assert_eq!(
            linux.user_region(0xb000, "arg", &job).unwrap(),
            b"a\0b=c\0d\0\0\0"
        );
        let r = linux.run(Plugin::Psaux, &job).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows[0][2], "a b=c d  ");
        assert_eq!(r.rows[1][3], "KernelThread");
        put(&mut b, 0xb018, 0x200ffe);
        put(&mut b, 0xb020, 0x201008);
        let i = image(&b);
        let r = engine(&i, &isf).run(Plugin::Envars, &job).unwrap();
        assert_eq!(r.rows[1], vec!["1", "init", "b", "c"]);
        put(&mut b, 0xb018, 0x201000);
        put(&mut b, 0xb020, 0x201008);
        b[0x25000..0x25008].copy_from_slice(b"K=a=b\0\0\0");
        let i = image(&b);
        let r = engine(&i, &isf).run(Plugin::Envars, &job).unwrap();
        assert_eq!(r.rows[0][3], "a=b");
        put(&mut b, 0xb018, 0);
        put(&mut b, 0xb020, 0);
        let i = image(&b);
        assert!(
            engine(&i, &isf)
                .run(Plugin::Envars, &job)
                .unwrap()
                .rows
                .is_empty()
        );
        put(&mut b, 0xb010, 0x400000);
        let i = image(&b);
        let r = engine(&i, &isf).run(Plugin::Psaux, &job).unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
        assert!(r.diagnostics[0].contains("1 MiB"));
        put(&mut b, 0xb010, 0x201008);
        put(&mut b, 0x7008, 0);
        let i = image(&b);
        let r = engine(&i, &isf).run(Plugin::Psaux, &job).unwrap();
        assert!(!r.complete);
        assert!(r.diagnostics[0].contains("缺页"));
        isf.data["user_types"]["mm_struct"]["fields"]
            .as_object_mut()
            .unwrap()
            .remove("pgd");
        isf.invalidate_layouts();
        assert!(
            engine(&i, &isf)
                .run(Plugin::Psaux, &job)
                .unwrap_err()
                .to_string()
                .contains("不支持")
        );
    }
    #[test]
    fn nested_enum_bitfield_flexible_array() {
        let (mut b, mut isf) = fixture();
        put(&mut b, 0xd008, 10);
        put(&mut b, 0xd120, 5 << 3);
        let i = image(&b);
        let linux = engine(&i, &isf);
        assert_eq!(linux.number(0xd000, "socket", "state").unwrap(), 10);
        assert_eq!(linux.number(0xd100, "sock", "sk_type").unwrap(), 5);
        assert_eq!(isf.offset("file", "f_path.dentry").unwrap(), 8);
        assert_eq!(isf.size("unix_address", "name").unwrap(), 0);
        isf.data["user_types"]["unix_address"]["fields"]["name"]["offset"] = json!(128);
        isf.invalidate_layouts();
        assert_eq!(isf.offset("unix_address", "name").unwrap(), 128);
        isf.data["user_types"]["unix_address"]["fields"]["name"]["type"]["count"] = json!(1);
        isf.invalidate_layouts();
        assert!(isf.offset("unix_address", "name").is_err());
    }
    #[test]
    fn vma_permissions_cycle_and_limits() {
        let (mut b, isf) = fixture();
        let job = Job::default();
        put(&mut b, 0xb028, 0xd000);
        put(&mut b, 0xd000, 0xd000);
        put(&mut b, 0xd008, 0x200000);
        put(&mut b, 0xd010, 0x201000);
        put(&mut b, 0xd018, 15);
        put(&mut b, 0xd020, 3);
        let i = image(&b);
        let r = engine(&i, &isf).run(Plugin::Maps, &job).unwrap();
        assert!(!r.complete);
        assert!(r.diagnostics[0].contains("循环"));
        assert_eq!(&r.rows[0][4..], &["rwxs", "12288", "[anonymous]"]);
        put(&mut b, 0xd000, 0);
        let i = image(&b);
        assert!(engine(&i, &isf).run(Plugin::Maps, &job).unwrap().complete);
        assert_eq!(permissions(0), "---p");
    }
    pub(crate) fn path_fixture(b: &mut [u8]) {
        // Process root /root. File resides inside a child mount at /root/mnt/file.
        put(b, 0xc000, 0xc100);
        put(b, 0xc008, 0xc200);
        put(b, 0xc100, 0xc200);
        put(b, 0xc108, 0xc100);
        put(b, 0xc300, 0xc400);
        put(b, 0xc308, 0xc100);
        put(b, 0xc310, 0xc500);
        put(b, 0xc600, 0xc300);
        put(b, 0xc608, 0xc700);
        put(b, 0xc700, 0xc400);
        put(b, 0xc708, 4);
        put(b, 0xc710, 0xc800);
        b[0xc800..0xc805].copy_from_slice(b"file\0");
        put(b, 0xc500, 0xc200);
        put(b, 0xc508, 3);
        put(b, 0xc510, 0xc900);
        b[0xc900..0xc904].copy_from_slice(b"mnt\0");
        put(b, 0xc718, 0xca00);
        put(b, 0xca00, 0x8000);
        put(b, 0xca08, 42);
    }
    #[test]
    fn mount_root_fd_holes_and_duplicate_references() {
        let (mut b, isf) = fixture();
        path_fixture(&mut b);
        let job = Job::default();
        put(&mut b, 0xa038, 0xcb00);
        put(&mut b, 0xcb00, 0xcc00);
        put(&mut b, 0xcc00, 3);
        put(&mut b, 0xcc08, 0xcd00);
        put(&mut b, 0xcd00, 0xc600);
        put(&mut b, 0xcd10, 0xc600);
        let i = image(&b);
        let linux = engine(&i, &isf);
        assert_eq!(linux.file_path(0xa000, 0xc600, &job).unwrap(), "/mnt/file");
        let r = linux.run(Plugin::Lsof, &job).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.rows[1][2], "2");
        assert_eq!(r.rows[0][5], "/mnt/file");
        put(&mut b, 0xc500, 0xc500);
        let i = image(&b);
        let r = engine(&i, &isf).run(Plugin::Lsof, &job).unwrap();
        assert!(!r.complete);
        assert_eq!(r.diagnostics.len(), 2);
        assert_eq!(r.rows.len(), 2);
    }
    #[test]
    fn ipv4_ipv6_tcp_udp_unix_and_unsupported() {
        let (mut b, isf) = fixture();
        let sk = 0xd100;
        put(&mut b, 0xd000, sk); // socket begins 16 bytes before inode
        put(&mut b, 0xd100, 2);
        put(&mut b, 0xd108, 10);
        b[0xd110..0xd114].copy_from_slice(&[127, 0, 0, 1]);
        b[0xd118..0xd11c].copy_from_slice(&[192, 0, 2, 1]);
        put(&mut b, 0xd120, 1 << 3);
        put(&mut b, 0xd128, 6);
        b[0xd130..0xd132].copy_from_slice(&8080u16.to_be_bytes());
        b[0xd138..0xd13a].copy_from_slice(&443u16.to_be_bytes());
        let i = image(&b);
        let row = engine(&i, &isf).socket(0xd010).unwrap();
        assert_eq!(
            &row[..6],
            &[
                "IPv4",
                "STREAM",
                "TCP",
                "127.0.0.1:8080",
                "192.0.2.1:443",
                "LISTEN"
            ]
        );
        put(&mut b, 0xd128, 17);
        let i = image(&b);
        assert_eq!(engine(&i, &isf).socket(0xd010).unwrap()[5], "UDP");
        put(&mut b, 0xd100, 10);
        put(&mut b, 0xd140, 0xe000);
        b[0xe000..0xe010].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        b[0xe010..0xe020].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        let i = image(&b);
        let row = engine(&i, &isf).socket(0xd010).unwrap();
        assert_eq!(row[3], "[::1]:8080");
        assert_eq!(row[4], "[::1]:443");
        put(&mut b, 0xd100, 1);
        put(&mut b, 0xd130, 0xe100);
        put(&mut b, 0xe100, 12); // sun_path offset 8, len 12
        b[0xe110..0xe114].copy_from_slice(b"abc\0");
        let i = image(&b);
        assert_eq!(engine(&i, &isf).socket(0xd010).unwrap()[3], "abc");
        b[0xe110..0xe114].copy_from_slice(b"\0ab\0");
        let i = image(&b);
        assert_eq!(engine(&i, &isf).socket(0xd010).unwrap()[3], "@ab\0");
        put(&mut b, 0xd138, 0xe200);
        put(&mut b, 0xe248, 0xe300);
        let i = image(&b);
        assert_eq!(
            engine(&i, &isf).socket(0xd010).unwrap()[4],
            "0x000000000000e300"
        );
        put(&mut b, 0xd130, 0);
        let i = image(&b);
        assert_eq!(engine(&i, &isf).socket(0xd010).unwrap()[3], "[unnamed]");
        put(&mut b, 0xd100, 16);
        let i = image(&b);
        assert_eq!(
            engine(&i, &isf).socket(0xd010).unwrap()[5],
            "UnsupportedFamily"
        );
    }
    #[test]
    fn traversal_limits_cancel_and_identity_failure() {
        let (mut b, isf) = fixture();
        let job = Job::default();
        put(&mut b, 0xa038, 0xcb00);
        put(&mut b, 0xcb00, 0xcc00);
        put(&mut b, 0xcc00, 4);
        put(&mut b, 0xcc08, 0xcd00);
        put(&mut b, 0xb028, 0xd000);
        for node in [0xd000, 0xd100, 0xd200, 0xd300] {
            put(&mut b, node, node as u64 + 0x100);
            put(&mut b, node + 8, 0x200000);
            put(&mut b, node + 16, 0x201000);
        }
        let i = image(&b);
        let linux = engine(&i, &isf);
        let mut result = linux.run(Plugin::Pslist, &job).unwrap();
        result.rows.clear();
        let prefix = vec!["1".into(), "init".into()];
        assert!(
            linux
                .files_bounded(0xa000, prefix.clone(), Plugin::Lsof, &mut result, &job, 3)
                .unwrap_err()
                .to_string()
                .contains("上限")
        );
        assert!(
            linux
                .maps_bounded(0xa000, prefix, &mut result, &job, 3)
                .unwrap_err()
                .to_string()
                .contains("上限")
        );
        assert_eq!(result.rows.len(), 3);
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(linux.run(Plugin::Psaux, &job).is_err());
        put(&mut b, 0xa010, u64::MAX);
        let i = image(&b);
        let r = engine(&i, &isf)
            .run(Plugin::Psaux, &Job::default())
            .unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows[0][0], "2");
    }
    #[test]
    fn path_depth_limit_and_name_bounds() {
        let (mut b, isf) = fixture();
        path_fixture(&mut b);
        let job = Job::default();
        put(&mut b, 0xc608, 0x10000);
        b[0x3f000..0x3f002].copy_from_slice(b"x\0");
        for n in 0..1024 {
            let d = 0x10000 + n * 64;
            put(&mut b, d, (d + 64) as u64);
            put(&mut b, d + 8, 1);
            put(&mut b, d + 16, 0x3f000);
        }
        let i = image(&b);
        assert!(
            engine(&i, &isf)
                .file_path(0xa000, 0xc600, &job)
                .unwrap_err()
                .to_string()
                .contains("1024")
        );
        put(&mut b, 0x10008, 256);
        let i = image(&b);
        assert!(
            engine(&i, &isf)
                .file_path(0xa000, 0xc600, &job)
                .unwrap_err()
                .to_string()
                .contains("长度")
        );
    }
}
