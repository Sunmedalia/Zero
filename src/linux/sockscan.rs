//! Independent physical socket discovery through file operations and destructors.
use super::*;
use crate::physical::{self, Decision, Object};
use serde::Serialize;
use std::collections::BTreeSet;
#[derive(Default, Serialize)]
struct Source {
    member: &'static str,
    needles: BTreeSet<u64>,
    offset: Option<u64>,
    hits: u64,
    resolved: u64,
    accepted: u64,
    read_failures: u64,
    field_warnings: u64,
    first_field_warning: Option<String>,
    first_read_failure: Option<String>,
}
impl Linux<'_> {
    pub(super) fn sockscan(&self, job: &Job) -> Result<Results> {
        ensure!(
            self.isf.data["base_types"]["pointer"]["size"]
                .as_u64()
                .unwrap_or(8)
                == 8,
            "Sockscan 当前仅支持 64 位内核"
        );
        let mut result = self.result(Plugin::LinuxSockscan);
        self.require(&[
            ("sock", "__sk_common.skc_family"),
            ("sock", "sk_type"),
            ("sock", "sk_socket"),
        ])?;
        let mut sources = Vec::new();
        for (ty, field, names) in [
            (
                "file",
                "f_op",
                &["socket_file_ops", "sockfs_dentry_operations"][..],
            ),
            (
                "sock",
                "sk_destruct",
                &[
                    "sock_def_destruct",
                    "packet_sock_destruct",
                    "unix_sock_destructor",
                    "netlink_sock_destruct",
                    "inet_sock_destruct",
                ][..],
            ),
        ] {
            let mut source = Source {
                member: if ty == "file" {
                    "file.f_op"
                } else {
                    "sock.sk_destruct"
                },
                ..Default::default()
            };
            source.offset = self.isf.offset(ty, field).ok();
            for name in names {
                if self.isf.raw_address(name).is_ok() {
                    source.needles.insert(self.scan_symbol_address(name)?);
                }
            }
            if source.needles.is_empty() || source.offset.is_none() {
                partial(
                    &mut result,
                    source.member,
                    anyhow::anyhow!("缺少扫描符号或字段；该来源未扫描"),
                );
                source.needles.clear();
            }
            sources.push(source);
        }
        let needles: Vec<_> = sources
            .iter()
            .flat_map(|s| s.needles.iter().copied())
            .collect();
        ensure!(
            !needles.is_empty(),
            "Sockscan 无可用的 file-ops/destructor 扫描来源"
        );
        let mut seen = HashSet::new();
        let mut devices = None;
        let mut output_bytes = 0usize;
        let coverage = physical::pointers(self.vm.image, &needles, 8, job, |hit, value| {
            let mut accepted = false;
            for (method, source) in sources.iter_mut().enumerate() {
                if !source.needles.contains(&value) {
                    continue;
                }
                source.hits += 1;
                let read = (|| -> Result<Option<super::socket_fields::SocketFields>> {
                    let Some(base) = hit.checked_sub(source.offset.unwrap()) else {
                        return Ok(None);
                    };
                    let address = if method == 0 {
                        match self.socket_from_physical_file(base)? {
                            Some(p) => p,
                            None => return Ok(None),
                        }
                    } else {
                        base
                    };
                    source.resolved += 1;
                    if !seen.insert(address) {
                        return Ok(None);
                    }
                    let object = Object {
                        image: self.vm.image,
                        isf: self.isf,
                        address,
                    };
                    if object.number("sock", "__sk_common.skc_family")? == 17 && devices.is_none() {
                        devices = Some(match self.socket_scan_devices(job) {
                            Ok(map) => map,
                            Err(e) => {
                                job.check()?;
                                partial(&mut result, "扫描套接字网络设备", e);
                                BTreeMap::new()
                            }
                        });
                    }
                    self.socket_scan_fields(address, devices.as_ref().unwrap_or(&BTreeMap::new()))
                })();
                match read {
                    Ok(Some(decoded)) => {
                        for warning in decoded.warnings {
                            source.field_warnings += 1;
                            source
                                .first_field_warning
                                .get_or_insert_with(|| format!("{hit:#x}: {warning}"));
                        }
                        let row = decoded.row;
                        let bytes = row.iter().map(String::len).sum::<usize>();
                        if output_bytes + bytes > 128 * 1024 * 1024 {
                            return Ok(Decision::Stop);
                        }
                        output_bytes += bytes;
                        result.rows.push(row);
                        source.accepted += 1;
                        accepted = true;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        job.check()?;
                        source.read_failures += 1;
                        if source.first_read_failure.is_none() {
                            source.first_read_failure = Some(format!("{hit:#x}: {e:#}"));
                        }
                    }
                }
            }
            Ok(if accepted {
                Decision::Accept
            } else {
                Decision::Reject
            })
        })?;
        if !coverage.complete() {
            partial(
                &mut result,
                "物理套接字扫描覆盖",
                anyhow::anyhow!(
                    "读取 {} / {} 字节；读取失败 {}；候选/输出上限 {}",
                    coverage.scanned_bytes,
                    coverage.captured_bytes,
                    coverage.read_failures,
                    coverage.limit_reached
                ),
            );
        }
        for source in &sources {
            if source.read_failures > 0 || source.field_warnings > 0 {
                partial(
                    &mut result,
                    source.member,
                    anyhow::anyhow!(
                        "{} 个候选无法完成读取；{} 处字段不可读；首处 {}",
                        source.read_failures,
                        source.field_warnings,
                        source
                            .first_read_failure
                            .as_deref()
                            .or(source.first_field_warning.as_deref())
                            .unwrap_or_default()
                    ),
                );
            }
        }
        result
            .rows
            .sort_unstable_by_key(|r| u64::from_str_radix(&r[0][2..], 16).unwrap_or(0));
        if !result.kernel_identity.is_object() {
            result.kernel_identity = serde_json::json!({});
        }
        result.kernel_identity["physical_socket_scan"] = serde_json::json!({"coverage":coverage,"sources":sources,"unique_socket_candidates":seen.len(),"deduplication":"resolved physical sock address","pointer_targets":"kernel virtual address space","source":"physical bytes; independent of task fd lists"});
        Ok(result)
    }
    fn socket_from_physical_file(&self, base: u64) -> Result<Option<u64>> {
        let object = Object {
            image: self.vm.image,
            isf: self.isf,
            address: base,
        };
        let dentry = object.number("file", "f_path.dentry")?;
        if dentry == 0 {
            return Ok(None);
        }
        let inode = self.number(dentry, "dentry", "d_inode")?;
        if inode == 0 {
            return Ok(None);
        }
        let alloc = inode
            .checked_sub(self.isf.offset("socket_alloc", "vfs_inode")?)
            .context("socket_alloc 地址下溢")?;
        let socket = self.field_address(alloc, "socket_alloc", "socket")?;
        let sk = self.number(socket, "socket", "sk")?;
        if sk == 0 {
            return Ok(None);
        }
        Ok(Some(self.vm.translate(sk)?))
    }
    /// Reference SockHandlers resolves AF_PACKET interfaces in init_task's netns.
    fn socket_scan_devices(&self, job: &Job) -> Result<BTreeMap<u64, String>> {
        if self.isf.field("net", "proc_inum").is_err() && self.isf.field("net", "ns.inum").is_err()
        {
            return Ok(BTreeMap::new());
        }
        let init = self.isf.address("init_task")?;
        let proxy = self.number(init, "task_struct", "nsproxy")?;
        let namespace = self.number(proxy, "nsproxy", "net_ns")?;
        let mut out = BTreeMap::new();
        for device in self.list_objects(
            self.field_address(namespace, "net", "dev_base_head")?,
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
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::{engine, fixture, image};
    use super::*;
    use serde_json::json;
    pub(super) fn put(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    pub(super) fn field(isf: &mut Isf, ty: &str, name: &str, offset: u64, kind: serde_json::Value) {
        isf.data["user_types"][ty]["fields"][name] = json!({"offset":offset,"type":kind});
    }
    pub(super) fn base_fixture() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        for (symbol, address) in [("socket_file_ops", 0x18000), ("sock_def_destruct", 0x18100)] {
            isf.data["symbols"][symbol] = json!({"address":address});
        }
        field(
            &mut isf,
            "sock",
            "sk_destruct",
            80,
            json!({"kind":"pointer"}),
        );
        field(&mut isf, "file", "f_op", 40, json!({"kind":"pointer"}));
        // High virtual alias is deliberately not a physical address.
        put(&mut b, 0x1800, 0x2003);
        (b, isf)
    }
    pub(super) fn inet(b: &mut [u8], at: usize, family: u64) {
        put(b, at, family);
        put(b, at + 8, 10);
        put(b, at + 16, 0x0100007f);
        put(b, at + 24, 0x0200007f);
        put(b, at + 32, 1 << 3);
        put(b, at + 40, 6);
        put(b, at + 48, (8080u16.to_be()) as u64);
        put(b, at + 56, (4040u16.to_be()) as u64);
        put(b, at + 80, 0x18100);
    }
    fn file(b: &mut [u8], at: usize, sk: u64) {
        put(b, at + 8, 0xffff80000001c000);
        put(b, at + 40, 0x18000);
        put(b, 0x1c018, 0xffff80000001d010); // dentry.d_inode -> socket_alloc.vfs_inode
        put(b, 0x1d000, sk); // socket_alloc.socket.sk
    }
    #[test]
    fn both_sources_find_independent_objects_and_deduplicate_resolved_physical_addresses() {
        let (mut b, isf) = base_fixture();
        inet(&mut b, 0x19000, 2);
        inet(&mut b, 0x19100, 2);
        // The second object is found solely through a physically carved file.
        put(&mut b, 0x19150, 0);
        file(&mut b, 0x1b000, 0xffff800000019100);
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(
            r.rows[0],
            vec![
                hex(0x19000),
                "AF_INET".into(),
                "STREAM".into(),
                "TCP".into(),
                "127.0.0.1".into(),
                "8080".into(),
                "127.0.0.2".into(),
                "4040".into(),
                "LISTEN".into(),
                "N/A".into()
            ]
        );
        assert_eq!(
            r.kernel_identity["physical_socket_scan"]["sources"][0]["accepted"],
            1
        );
        assert_eq!(
            r.kernel_identity["physical_socket_scan"]["sources"][1]["accepted"],
            1
        );
        file(&mut b, 0x1b100, 0xffff800000019000);
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert_eq!(r.rows.len(), 1); // both files now point to the destructor object
        assert_eq!(r.rows[0][0], hex(0x19000));
    }
    #[test]
    fn absent_source_and_unreadable_file_targets_preserve_other_source_with_diagnostics() {
        let (mut b, mut isf) = base_fixture();
        inet(&mut b, 0x19000, 2);
        isf.data["symbols"]
            .as_object_mut()
            .unwrap()
            .remove("socket_file_ops");
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert_eq!(r.rows.len(), 1);
        assert!(!r.complete);
        assert!(r.diagnostics.iter().any(|d| d.contains("来源未扫描")));
        isf.data["symbols"]["socket_file_ops"] = json!({"address":0x18000});
        file(&mut b, 0x1b000, 0xffff900000019000);
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert_eq!(r.rows.len(), 1);
        assert!(!r.complete);
        assert_eq!(
            r.kernel_identity["physical_socket_scan"]["sources"][0]["read_failures"],
            1
        );
    }
    #[test]
    fn ipv6_pointer_targets_use_virtual_memory_and_cancel_is_propagated() {
        let (mut b, mut isf) = base_fixture();
        field(
            &mut isf,
            "ipv6_pinfo",
            "saddr",
            0,
            json!({"kind":"array","count":16,"subtype":{"kind":"base","name":"char"}}),
        );
        field(
            &mut isf,
            "ipv6_pinfo",
            "daddr",
            16,
            json!({"kind":"array","count":16,"subtype":{"kind":"base","name":"char"}}),
        );
        inet(&mut b, 0x19000, 10);
        put(&mut b, 0x19040, 0xffff80000001e000);
        b[0x1e000..0x1e010].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        b[0x1e010..0x1e020].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(&r.rows[0][4], "::1");
        assert_eq!(&r.rows[0][6], "2001:db8::1");
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(engine(&i, &isf).sockscan(&job).is_err());
    }
    #[test]
    fn legacy_cbpf_and_modern_ebpf_filters_preserve_reuseport_order() {
        let (mut b, mut isf) = base_fixture();
        inet(&mut b, 0x19000, 2);
        field(&mut isf, "sock", "sk_filter", 88, json!({"kind":"pointer"}));
        isf.data["user_types"]["sk_filter"] = json!({"size":8,"fields":{}});
        put(&mut b, 0x19058, 0xffff80000001e000);
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert_eq!(
            &r.rows[0][9],
            "filter_type=socket_filter,bpf_filter_type=cBPF"
        );
        isf.data["user_types"]["sk_filter"] =
            json!({"size":8,"fields":{"prog":{"offset":0,"type":{"kind":"pointer"}}}});
        isf.data["user_types"]["sock_reuseport"] = isf.data["user_types"]["sk_filter"].clone();
        isf.data["user_types"]["bpf_prog"] = json!({"size":16,"fields":{"type":{"offset":0,"type":{"kind":"base","name":"u32"}},"aux":{"offset":8,"type":{"kind":"pointer"}}}});
        isf.data["user_types"]["bpf_prog_aux"] = json!({"size":24,"fields":{"id":{"offset":0,"type":{"kind":"base","name":"u32"}},"name":{"offset":8,"type":{"kind":"array","count":16,"subtype":{"kind":"base","name":"char"}}}}});
        isf.data["enums"]["bpf_prog_type"] = json!({"size":4,"constants":{"BPF_PROG_TYPE_UNSPEC":0,"BPF_PROG_TYPE_SOCKET_FILTER":1}});
        field(
            &mut isf,
            "sock",
            "sk_reuseport_cb",
            96,
            json!({"kind":"pointer"}),
        );
        put(&mut b, 0x19060, 0xffff80000001e000);
        put(&mut b, 0x1e000, 0xffff80000001e100);
        put(&mut b, 0x1e100, 1);
        put(&mut b, 0x1e108, 0xffff80000001e200);
        put(&mut b, 0x1e200, 77);
        b[0x1e208..0x1e20c].copy_from_slice(b"test");
        isf.invalidate_layouts();
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert_eq!(
            &r.rows[0][9],
            "filter_type=reuseport_filter,bpf_filter_type=eBPF,bpf_filter_id=77,bpf_filter_name=test"
        );
    }
}

#[cfg(test)]
mod family_tests {
    use super::super::tests::{engine, image};
    use super::tests::{base_fixture, field, inet, put};
    use super::*;
    use serde_json::json;
    fn structure(isf: &mut Isf, name: &str) {
        isf.data["user_types"][name] = json!({"size":128,"fields":{}});
    }
    fn integer(isf: &mut Isf, ty: &str, name: &str, at: u64) {
        field(isf, ty, name, at, json!({"kind":"base","name":"u64"}));
    }
    fn text(isf: &mut Isf, ty: &str, name: &str, at: u64, count: usize) {
        field(
            isf,
            ty,
            name,
            at,
            json!({"kind":"array","count":count,"subtype":{"kind":"base","name":"char"}}),
        );
    }
    #[test]
    fn netlink_groups_and_module_are_virtual_targets_with_legacy_ports() {
        let (mut b, mut isf) = base_fixture();
        inet(&mut b, 0x19000, 16);
        structure(&mut isf, "netlink_sock");
        structure(&mut isf, "module");
        for (name, at) in [
            ("groups", 48),
            ("pid", 56),
            ("dst_pid", 64),
            ("dst_group", 88),
            ("module", 96),
        ] {
            integer(&mut isf, "netlink_sock", name, at);
        }
        text(&mut isf, "module", "name", 0, 16);
        put(&mut b, 0x19028, 0);
        put(&mut b, 0x19030, 0xffff80000001e000);
        put(&mut b, 0x1e000, 0x123);
        put(&mut b, 0x19038, 100);
        put(&mut b, 0x19040, 200);
        put(&mut b, 0x19048, 0xffff80000001d000);
        put(&mut b, 0x1d008, 3);
        put(&mut b, 0x19058, 9);
        put(&mut b, 0x19060, 0xffff80000001f000);
        b[0x1f000..0x1f004].copy_from_slice(b"test");
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(
            &r.rows[0][3..9],
            &[
                "NETLINK_ROUTE",
                "groups:0x00000123",
                "100",
                "group:0x00000009,lkm:test",
                "200",
                "CONNECTED"
            ]
        );
    }
    #[test]
    fn vsock_nested_addresses_and_packet_protocols_have_distinct_semantics() {
        let (mut b, mut isf) = base_fixture();
        inet(&mut b, 0x19000, 40);
        structure(&mut isf, "vsock_sock");
        isf.data["user_types"]["sockaddr_vm"] = json!({"size":16,"fields":{"svm_cid":{"offset":0,"type":{"kind":"base","name":"u64"}},"svm_port":{"offset":8,"type":{"kind":"base","name":"u64"}}}});
        field(
            &mut isf,
            "vsock_sock",
            "local_addr",
            48,
            json!({"kind":"struct","name":"sockaddr_vm"}),
        );
        field(
            &mut isf,
            "vsock_sock",
            "remote_addr",
            96,
            json!({"kind":"struct","name":"sockaddr_vm"}),
        );
        put(&mut b, 0x19030, 2);
        put(&mut b, 0x19038, 1234);
        put(&mut b, 0x19060, 3);
        put(&mut b, 0x19068, 5678);
        put(&mut b, 0x19048, 0xffff80000001d000);
        put(&mut b, 0x1d008, 3);
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            &r.rows[0][3..9],
            &["N/A", "2", "1234", "3", "5678", "CONNECTED"]
        );
        structure(&mut isf, "packet_sock");
        integer(&mut isf, "packet_sock", "ifindex", 48);
        integer(&mut isf, "packet_sock", "num", 56);
        put(&mut b, 0x19000, 17);
        put(&mut b, 0x19030, 0);
        put(&mut b, 0x19038, u16::to_be(0x8100) as u64);
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            &r.rows[0][3..9],
            &["ETH_P_8021Q", "ANY", "N/A", "N/A", "N/A", "CONNECTED"]
        );
    }
    #[test]
    fn bluetooth_addresses_reverse_octets_and_xdp_uses_symbol_enum_and_aux() {
        let (mut b, mut isf) = base_fixture();
        inet(&mut b, 0x19000, 31);
        put(&mut b, 0x19028, 3);
        put(&mut b, 0x19008, 1);
        structure(&mut isf, "bt_sock");
        structure(&mut isf, "rfcomm_pinfo");
        text(&mut isf, "rfcomm_pinfo", "src", 48, 6);
        text(&mut isf, "rfcomm_pinfo", "dst", 56, 6);
        integer(&mut isf, "rfcomm_pinfo", "channel", 64);
        b[0x19030..0x19036].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        b[0x19038..0x1903e].copy_from_slice(&[11, 12, 13, 14, 15, 16]);
        put(&mut b, 0x19040, 9);
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            &r.rows[0][3..9],
            &[
                "RFCOMM",
                "06:05:04:03:02:01",
                "9",
                "10:0f:0e:0d:0c:0b",
                "N/A",
                "CONNECTED"
            ]
        );
        put(&mut b, 0x19000, 44);
        structure(&mut isf, "xdp_sock");
        structure(&mut isf, "net_device");
        structure(&mut isf, "bpf_prog");
        structure(&mut isf, "bpf_prog_aux");
        integer(&mut isf, "xdp_sock", "dev", 48);
        field(
            &mut isf,
            "xdp_sock",
            "state",
            56,
            json!({"kind":"enum","name":"custom_xsk_state"}),
        );
        isf.data["enums"]["custom_xsk_state"] = json!({"size":4,"constants":{"XSK_BOUND":2}});
        integer(&mut isf, "net_device", "xdp_prog", 80);
        text(&mut isf, "net_device", "name", 0, 16);
        integer(&mut isf, "bpf_prog", "aux", 0);
        integer(&mut isf, "bpf_prog_aux", "id", 0);
        text(&mut isf, "bpf_prog_aux", "name", 8, 16);
        put(&mut b, 0x19030, 0xffff80000001d000);
        put(&mut b, 0x19038, 2);
        b[0x1d000..0x1d004].copy_from_slice(b"eth0");
        put(&mut b, 0x1d050, 0xffff80000001e000);
        put(&mut b, 0x1e000, 0xffff80000001f000);
        put(&mut b, 0x1f000, 42);
        b[0x1f008..0x1f00c].copy_from_slice(b"test");
        isf.invalidate_layouts();
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            &r.rows[0][3..9],
            &[
                "N/A",
                "eth0",
                "N/A",
                "ebpf_prog_name:test",
                "ebpf_prog_id:42",
                "BOUND"
            ]
        );
    }
    #[test]
    fn readable_primary_port_does_not_require_an_unreadable_fallback_field() {
        let (mut b, mut isf) = base_fixture();
        inet(&mut b, 0x19000, 2);
        field(
            &mut isf,
            "sock_common",
            "skc_dport",
            126,
            json!({"kind":"base","name":"u16"}),
        );
        isf.data["base_types"]["u16"] = json!({"size":2});
        b.truncate(0x19058); // destructor is captured, fallback port is not
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0][7], "4040");
    }
    #[test]
    fn unreadable_ipv6_endpoints_preserve_ports_and_explicit_field_warnings() {
        let (mut b, mut isf) = base_fixture();
        inet(&mut b, 0x19000, 10);
        text(&mut isf, "ipv6_pinfo", "saddr", 0, 16);
        put(&mut b, 0x19040, 0xffff90000001e000);
        let i = image(&b);
        let r = engine(&i, &isf).sockscan(&Job::default()).unwrap();
        assert_eq!(r.rows.len(), 1);
        assert!(!r.complete);
        assert_eq!(&r.rows[0][4..8], &["N/A", "8080", "N/A", "4040"]);
        assert_eq!(
            r.kernel_identity["physical_socket_scan"]["sources"][1]["field_warnings"],
            2
        );
    }
}
