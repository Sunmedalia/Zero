//! Volatility-compatible Linux process socket listing (`linux.sockstat.Sockstat`).
use super::*;
use crate::analysis::Options;
use crate::bytes::JsonKey as _;
use std::collections::{BTreeSet, HashMap};

impl Linux<'_> {
    fn task_netns(&self, task: u64) -> Result<Option<(u64, Option<u64>)>> {
        if self.isf.field("task_struct", "nsproxy").is_err()
            || self.isf.field("nsproxy", "net_ns").is_err()
        {
            return Ok(None);
        }
        let proxy = self.number(task, "task_struct", "nsproxy")?;
        if proxy == 0 {
            return Ok(None);
        }
        let net = self.number(proxy, "nsproxy", "net_ns")?;
        if net == 0 {
            return Ok(None);
        }
        let inum =
            if self.isf.field("net", "ns").is_ok() && self.isf.field("ns_common", "inum").is_ok() {
                Some(self.number(net, "net", "ns.inum")?)
            } else if self.isf.field("net", "proc_inum").is_ok() {
                Some(self.number(net, "net", "proc_inum")?)
            } else {
                None
            };
        Ok(Some((net, inum)))
    }

    fn netns_devices(&self, net: u64, job: &Job) -> Result<BTreeMap<u64, String>> {
        if net == 0
            || self.isf.field("net", "dev_base_head").is_err()
            || self.isf.field("net_device", "dev_list").is_err()
        {
            return Ok(BTreeMap::new());
        }
        let mut out = BTreeMap::new();
        for device in self.list_objects(
            self.field_address(net, "net", "dev_base_head")?,
            self.isf.offset("net_device", "dev_list")?,
            job,
        )? {
            job.check()?;
            ensure!(out.len() < 65536, "网络设备数量超过上限");
            let name = self.string(device, "net_device", "name")?;
            ensure!(name.len() <= 256, "网络设备名称过长");
            out.insert(self.number(device, "net_device", "ifindex")?, name);
        }
        Ok(out)
    }

    pub(super) fn linux_sockstat(&self, options: &Options, job: &Job) -> Result<Results> {
        self.require(&[
            ("task_struct", "files"),
            ("files_struct", "fdt"),
            ("fdtable", "max_fds"),
            ("fdtable", "fd"),
            ("file", "f_path"),
            ("path", "dentry"),
            ("dentry", "d_inode"),
            ("inode", "i_mode"),
            ("socket_alloc", "vfs_inode"),
            ("socket_alloc", "socket"),
            ("socket", "sk"),
            ("sock", "__sk_common.skc_family"),
            ("sock", "sk_type"),
        ])?;

        let width = usize::try_from(
            self.isf.data.key("base_types")["pointer"]
                .key("size")
                .as_u64()
                .context("ISF pointer size 缺失")?,
        )?;
        ensure!(matches!(width, 4 | 8), "ISF pointer size 无效");
        let vfs_inode_offset = self.isf.offset("socket_alloc", "vfs_inode")?;
        let socket_offset = self.isf.offset("socket_alloc", "socket")?;

        let pids: BTreeSet<u32> = options.pids.iter().copied().chain(options.pid).collect();
        let (mut result, tasks) = self.fd_tasks(Plugin::LinuxSockstat, &pids, job)?;
        let mut device_cache: HashMap<u64, BTreeMap<u64, String>> = HashMap::new();
        let empty_devices = BTreeMap::new();

        for task in tasks {
            job.check()?;
            let addr = task.address;
            let read = (|| -> Result<()> {
                let netns = self.task_netns(addr)?;
                let (net_ptr, netns_inum) = match netns {
                    Some((net, inum)) => (net, inum),
                    None => (0, None),
                };
                if let Some(want) = options.netns
                    && netns_inum != Some(want)
                {
                    return Ok(());
                }
                let netns_label = netns_inum
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".into());

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
                        if (mode & 0xf000) != 0xc000 {
                            return Ok(None);
                        }
                        let alloc = inode
                            .checked_sub(vfs_inode_offset)
                            .context("socket_alloc 地址下溢")?;
                        let socket = add(alloc, socket_offset)?;
                        let sk = self.number(socket, "socket", "sk")?;
                        if sk == 0 {
                            return Ok(None);
                        }
                        let devices = if net_ptr != 0 {
                            if let std::collections::hash_map::Entry::Vacant(slot) =
                                device_cache.entry(net_ptr)
                            {
                                let devs = match self.netns_devices(net_ptr, job) {
                                    Ok(d) => d,
                                    Err(error) => {
                                        job.check()?;
                                        partial(
                                            &mut result,
                                            format!("netns {netns_label} 设备列表"),
                                            error,
                                        );
                                        BTreeMap::new()
                                    }
                                };
                                slot.insert(devs);
                            }
                            device_cache.get(&net_ptr).unwrap_or(&empty_devices)
                        } else {
                            &empty_devices
                        };
                        let Some(decoded) = self.socket_fields(sk, false, false, devices)? else {
                            return Ok(None);
                        };
                        for warning in decoded.warnings {
                            result.complete = false;
                            result
                                .diagnostics
                                .push(format!("PID {} FD {fd}: {warning}", task.pid));
                        }
                        // decoded.row has 10 columns: [Offset, Family, Type, Proto, Src, SPort, Dst, DPort, State, Filter]
                        let mut full = Vec::with_capacity(15);
                        full.push(netns_label.clone());
                        full.push(task.name.clone());
                        full.push(tgid.clone());
                        full.push(task.pid.clone());
                        full.push(fd.to_string());
                        full.extend(decoded.row);
                        Ok(Some(full))
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
            job.report(format!("linux.sockstat.Sockstat: {} 条", result.rows.len()));
        }
        Ok(result)
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

    fn sockstat_fixture() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        // Add nsproxy + net + ns_common (task_validity validates nsproxy subtype)
        isf.data["user_types"]["task_struct"]["fields"]["nsproxy"] = json!({
            "offset": 72,
            "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "nsproxy"}}
        });
        isf.data["user_types"]["nsproxy"] = json!({
            "size": 16,
            "fields": {"net_ns": {"offset": 0, "type": {"kind": "pointer"}}}
        });
        isf.data["user_types"]["ns_common"] = json!({
            "size": 16,
            "fields": {"inum": {"offset": 0, "type": {"kind": "base", "name": "u32"}}}
        });
        isf.data["user_types"]["net"] = json!({
            "size": 32,
            "fields": {
                "ns": {"offset": 0, "type": {"kind": "struct", "name": "ns_common"}}
            }
        });

        // init_task 0x9000 -> task 0xa000 (pid=77, tgid=70, "nginx")
        put(&mut b, 0x9000, 0xa000);
        put(&mut b, 0x9008, 0xa000);
        put(&mut b, 0xa000, 0x9000);
        put(&mut b, 0xa008, 0x9000);
        put(&mut b, 0xa010, 77);
        put(&mut b, 0xa018, 70);
        put(&mut b, 0xa020, 0x9000);
        b[0xa028..0xa030].copy_from_slice(b"nginx\0\0\0");
        put(&mut b, 0xa038, 0xb000); // files
        put(&mut b, 0xa040, 0); // fs
        put(&mut b, 0xa048, 0xc000); // nsproxy (+72)

        // nsproxy -> net (inum = 4026531992)
        put(&mut b, 0xc000, 0xc100);
        put(&mut b, 0xc100, 4_026_531_992);

        // files -> fdtable -> [fd 3 = 0xe000]
        put(&mut b, 0xb000, 0xb100);
        put(&mut b, 0xb100, 4);
        put(&mut b, 0xb108, 0xb200);
        put(&mut b, 0xb218, 0xe000);

        // file 0xe000 -> dentry 0xe100 -> inode(+0x18) at 0xf010 (inside socket_alloc 0xf000)
        put(&mut b, 0xe008, 0xe100);
        put(&mut b, 0xe118, 0xf010);
        // socket_alloc at 0xf000: socket at 0xf000 (sk=0x10000, state=3), vfs_inode at 0xf010 (i_mode=S_IFSOCK, i_ino=5555)
        put(&mut b, 0xf000, 0x10000);
        put(&mut b, 0xf008, 3);
        put(&mut b, 0xf010, 0o140777);
        put(&mut b, 0xf018, 5555);

        // inet_sock / sock at 0x10000: AF_INET (2), TCP_LISTEN (10), src=127.0.0.1:80, dst=0.0.0.0:0
        put(&mut b, 0x10000, 2); // skc_family
        put(&mut b, 0x10008, 10); // skc_state = LISTEN
        put(&mut b, 0x10010, 0x0100_007f); // 127.0.0.1
        put(&mut b, 0x10018, 0); // 0.0.0.0
        put(&mut b, 0x10020, 1 << 3); // sk_type = STREAM (bitpos 3)
        put(&mut b, 0x10028, 6); // sk_protocol = TCP
        put(&mut b, 0x10030, u64::from(80u16.to_be())); // inet_sport
        put(&mut b, 0x10038, 0); // inet_dport
        put(&mut b, 0x10048, 0xf000); // sk_socket (+72 in fixture())

        fd_thread_group(&mut b, &mut isf, None);
        (b, isf)
    }

    #[test]
    fn linux_sockstat_emits_15_columns_and_filters_by_netns() {
        let (bytes, isf) = sockstat_fixture();
        let img = image(&bytes);
        let linux = engine(&img, &isf);

        let result = linux
            .linux_sockstat(&Options::default(), &Job::default())
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(
            result.rows[0],
            vec![
                "4026531992",
                "nginx",
                "70",
                "77",
                "3",
                "0x0000000000010000",
                "AF_INET",
                "STREAM",
                "TCP",
                "127.0.0.1",
                "80",
                "0.0.0.0",
                "0",
                "LISTEN",
                "N/A",
            ]
        );

        let matching = linux
            .linux_sockstat(
                &Options {
                    netns: Some(4_026_531_992),
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert_eq!(matching.rows.len(), 1);

        let other = linux
            .linux_sockstat(
                &Options {
                    netns: Some(12345),
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(other.complete);
        assert!(other.rows.is_empty());
    }
    #[test]
    fn linux_sockstat_finds_a_worker_threads_private_socket_table() {
        let (mut bytes, mut isf) = sockstat_fixture();
        put(&mut bytes, 0xa038, 0);
        fd_thread_group(&mut bytes, &mut isf, Some((78, 70, 0xb000)));
        let image = image(&bytes);
        let linux = engine(&image, &isf);
        let result = linux
            .linux_sockstat(
                &Options {
                    pids: vec![77],
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(
            &result.rows[0][..5],
            ["4026531992", "worker", "70", "78", "3"]
        );
    }
}
