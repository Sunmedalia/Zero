//! Network interfaces and their addresses across every network namespace.
use super::*;

/// MAC and hardware address lengths are at most MAX_ADDR_LEN.
const ADDRESS_LIMIT: u64 = 32;
const ADDRESS_COUNT_LIMIT: usize = 4096;
/// Interface flag bits from include/uapi/linux/if.h.
const FLAGS: &[(u64, &str)] = &[
    (0x1, "UP"),
    (0x2, "BROADCAST"),
    (0x8, "LOOPBACK"),
    (0x10, "POINTOPOINT"),
    (0x40, "RUNNING"),
    (0x80, "NOARP"),
    (0x100, "PROMISC"),
    (0x200, "ALLMULTI"),
    (0x1000, "MULTICAST"),
];

pub(super) fn operstate(state: u64) -> &'static str {
    match state {
        0 => "UNKNOWN",
        1 => "NOTPRESENT",
        2 => "DOWN",
        3 => "LOWERLAYERDOWN",
        4 => "TESTING",
        5 => "DORMANT",
        6 => "UP",
        _ => "INVALID",
    }
}
pub(super) fn flag_names(flags: u64) -> String {
    FLAGS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(",")
}
pub(super) fn ipv4_scope(scope: u64) -> &'static str {
    match scope {
        0 => "global",
        200 => "site",
        253 => "link",
        254 => "host",
        255 => "nowhere",
        _ => "other",
    }
}
pub(super) fn ipv6_scope(scope: u64) -> &'static str {
    match scope & 0xf0 {
        0x00 => "global",
        0x10 => "host",
        0x20 => "link",
        0x40 => "site",
        _ => "other",
    }
}

/// One interface as both plugins report it.
struct Interface {
    namespace: u64,
    ns_id: String,
    index: Option<u64>,
    device: u64,
    name: String,
    mac: String,
    flags: u64,
    state: &'static str,
    mtu: u64,
    qdisc: String,
    qlen: String,
}

impl Linux<'_> {
    fn net_ns_label(&self, namespace: u64) -> String {
        if self.isf.field("net", "ns").is_ok() && self.isf.field("ns_common", "inum").is_ok() {
            if let Ok(inum) = self.number(namespace, "net", "ns.inum") {
                return inum.to_string();
            }
        } else if self.isf.field("net", "proc_inum").is_ok()
            && let Ok(inum) = self.number(namespace, "net", "proc_inum")
        {
            return inum.to_string();
        }
        hex(namespace)
    }

    fn device_qdisc(&self, device: u64) -> String {
        let Ok(qdisc) = self.number(device, "net_device", "qdisc") else {
            return "N/A".into();
        };
        if qdisc == 0 {
            return "N/A".into();
        }
        let Ok(ops) = self.number(qdisc, "Qdisc", "ops") else {
            return "N/A".into();
        };
        if ops == 0 {
            return "N/A".into();
        }
        self.string(ops, "Qdisc_ops", "id")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "N/A".into())
    }
    /// Every `struct net`, or only init_net on kernels without the namespace list.
    fn namespaces(&self, job: &Job) -> Result<Vec<u64>> {
        match self.isf.address("net_namespace_list") {
            Ok(head) => self.list_objects(head, self.isf.offset("net", "list")?, job),
            Err(_) => Ok(vec![
                self.isf
                    .address("init_net")
                    .context("不支持: 缺少 net_namespace_list 与 init_net")?,
            ]),
        }
    }
    fn interfaces(&self, r: &mut Results, job: &Job) -> Result<Vec<Interface>> {
        self.require(&[
            ("net", "dev_base_head"),
            ("net_device", "dev_list"),
            ("net_device", "name"),
            ("net_device", "flags"),
            ("net_device", "mtu"),
            ("net_device", "operstate"),
            ("net_device", "dev_addr"),
            ("net_device", "addr_len"),
        ])?;
        let mut out = Vec::new();
        for namespace in self.namespaces(job)? {
            job.check()?;
            let devices = match self.list_objects(
                self.field_address(namespace, "net", "dev_base_head")?,
                self.isf.offset("net_device", "dev_list")?,
                job,
            ) {
                Ok(devices) => devices,
                Err(e) => {
                    job.check()?;
                    partial(r, format!("netns {namespace:#x} 设备链表"), e);
                    continue;
                }
            };
            for device in devices {
                let read = (|| -> Result<Interface> {
                    let length = self.number(device, "net_device", "addr_len")?;
                    ensure!(length <= ADDRESS_LIMIT, "硬件地址长度无效");
                    let pointer = self.number(device, "net_device", "dev_addr")?;
                    let mut mac = vec![0; usize::try_from(length)?];
                    if pointer != 0 && length > 0 {
                        self.vm.read(pointer, &mut mac)?;
                    }
                    Ok(Interface {
                        namespace,
                        ns_id: self.net_ns_label(namespace),
                        index: self.number(device, "net_device", "ifindex").ok(),
                        device,
                        name: self.string(device, "net_device", "name")?,
                        mac: mac
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(":"),
                        flags: self.number(device, "net_device", "flags")?,
                        state: operstate(self.number(device, "net_device", "operstate")?),
                        mtu: self.number(device, "net_device", "mtu")?,
                        qdisc: self.device_qdisc(device),
                        qlen: self
                            .number(device, "net_device", "tx_queue_len")
                            .map(|v| v.to_string())
                            .unwrap_or_else(|_| "N/A".into()),
                    })
                })();
                match read {
                    Ok(interface) => out.push(interface),
                    Err(e) => {
                        job.check()?;
                        partial(r, format!("net_device {device:#x}"), e);
                    }
                }
            }
        }
        Ok(out)
    }
    /// ip_link: one row per interface.
    pub(super) fn ip_link(&self, r: &mut Results, job: &Job) -> Result<()> {
        for i in self.interfaces(r, job)? {
            r.rows.push(vec![
                hex(i.namespace),
                i.name,
                i.mac,
                i.state.into(),
                i.mtu.to_string(),
                flag_names(i.flags),
            ]);
        }
        Ok(())
    }
    /// Volatility-compatible `linux.ip.Link` (8 columns including Qdisc & Qlen).
    pub(super) fn linux_ip_link(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::LinuxIpLink);
        for i in self.interfaces(&mut r, job)? {
            r.rows.push(vec![
                i.ns_id,
                i.name,
                i.mac,
                i.state.into(),
                i.mtu.to_string(),
                i.qdisc,
                i.qlen,
                flag_names(i.flags),
            ]);
        }
        Ok(r)
    }
    /// ip_addr: IPv4 and IPv6 addresses of each interface.
    pub(super) fn ip_addr(&self, r: &mut Results, job: &Job) -> Result<()> {
        for i in self.interfaces(r, job)? {
            job.check()?;
            let prefix = vec![
                hex(i.namespace),
                i.name.clone(),
                i.mac.clone(),
                (i.flags & 0x100 != 0).to_string(),
            ];
            let state = i.state.to_string();
            if let Err(e) = self.ipv4_addresses(&i, &prefix, &state, r, job) {
                job.check()?;
                partial(r, format!("{} IPv4", i.name), e);
            }
            if let Err(e) = self.ipv6_addresses(&i, &prefix, &state, r, job) {
                job.check()?;
                partial(r, format!("{} IPv6", i.name), e);
            }
        }
        Ok(())
    }
    /// Volatility-compatible `linux.ip.Addr` (9 columns including NetNS inode & Index).
    pub(super) fn linux_ip_addr(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::LinuxIpAddr);
        for i in self.interfaces(&mut r, job)? {
            job.check()?;
            let prefix = vec![
                i.ns_id.clone(),
                i.index
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".into()),
                i.name.clone(),
                i.mac.clone(),
                (i.flags & 0x100 != 0).to_string(),
            ];
            let state = i.state.to_string();
            if let Err(e) = self.ipv4_addresses(&i, &prefix, &state, &mut r, job) {
                job.check()?;
                partial(&mut r, format!("{} IPv4", i.name), e);
            }
            if let Err(e) = self.ipv6_addresses(&i, &prefix, &state, &mut r, job) {
                job.check()?;
                partial(&mut r, format!("{} IPv6", i.name), e);
            }
        }
        Ok(r)
    }
    fn ipv4_addresses(
        &self,
        i: &Interface,
        prefix: &[String],
        state: &str,
        r: &mut Results,
        job: &Job,
    ) -> Result<()> {
        let device = self.number(i.device, "net_device", "ip_ptr")?;
        if device == 0 {
            return Ok(());
        }
        let mut address = self.number(device, "in_device", "ifa_list")?;
        let mut seen = HashSet::new();
        while address != 0 {
            job.check()?;
            ensure!(
                seen.insert(address) && seen.len() <= ADDRESS_COUNT_LIMIT,
                "IPv4 地址链表循环或超限"
            );
            let ip = u32::try_from(self.number(address, "in_ifaddr", "ifa_address")?)?;
            let mut row = prefix.to_vec();
            row.extend([
                Ipv4Addr::from(ip.to_le_bytes()).to_string(),
                self.number(address, "in_ifaddr", "ifa_prefixlen")?
                    .to_string(),
                ipv4_scope(self.number(address, "in_ifaddr", "ifa_scope")?).into(),
                state.into(),
            ]);
            r.rows.push(row);
            address = self.number(address, "in_ifaddr", "ifa_next")?;
        }
        Ok(())
    }
    fn ipv6_addresses(
        &self,
        i: &Interface,
        prefix: &[String],
        state: &str,
        r: &mut Results,
        job: &Job,
    ) -> Result<()> {
        if self.isf.field("net_device", "ip6_ptr").is_err() {
            return Ok(());
        }
        let device = self.number(i.device, "net_device", "ip6_ptr")?;
        if device == 0 {
            return Ok(());
        }
        let addresses = self.list_objects(
            self.field_address(device, "inet6_dev", "addr_list")?,
            self.isf.offset("inet6_ifaddr", "if_list")?,
            job,
        )?;
        for address in addresses {
            let mut ip = [0u8; 16];
            self.vm.read(
                self.field_address(address, "inet6_ifaddr", "addr")?,
                &mut ip,
            )?;
            let mut row = prefix.to_vec();
            row.extend([
                Ipv6Addr::from(ip).to_string(),
                self.number(address, "inet6_ifaddr", "prefix_len")?
                    .to_string(),
                ipv6_scope(self.number(address, "inet6_ifaddr", "scope")?).into(),
                state.into(),
            ]);
            r.rows.push(row);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};
    use serde_json::json;
    fn put(bytes: &mut [u8], address: usize, value: u64) {
        bytes[address..address + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn field(offset: u64, ty: serde_json::Value) -> serde_json::Value {
        json!({"offset":offset,"type":ty})
    }
    fn base(name: &str) -> serde_json::Value {
        json!({"kind":"base","name":name})
    }
    /// init_net only (no namespace list) with one interface "eth0" carrying
    /// 10.0.0.5/24 and fe80::1/64.
    fn interfaces() -> (Vec<u8>, crate::symbols::Isf) {
        let (mut b, mut isf) = fixture();
        isf.data["base_types"]["u8"] = json!({"size":1});
        isf.data["base_types"]["u32"] = json!({"size":4});
        isf.data["symbols"]["init_net"] = json!({"address":0x30000});
        let list = json!({"kind":"struct","name":"list_head"});
        isf.data["user_types"]["net"] =
            json!({"size":32,"fields":{"dev_base_head":field(16,list.clone())}});
        isf.data["user_types"]["net_device"] = json!({"size":128,"fields":{
            "name":field(0,json!({"kind":"array","count":16,"subtype":{"kind":"base","name":"char"}})),
            "dev_list":field(16,list.clone()),
            "flags":field(32,base("u32")),
            "mtu":field(36,base("u32")),
            "operstate":field(40,base("u8")),
            "addr_len":field(41,base("u8")),
            "dev_addr":field(48,base("u64")),
            "ip_ptr":field(56,base("u64")),
            "ip6_ptr":field(64,base("u64")),
        }});
        isf.data["user_types"]["in_device"] =
            json!({"size":8,"fields":{"ifa_list":field(0,base("u64"))}});
        isf.data["user_types"]["in_ifaddr"] = json!({"size":24,"fields":{
            "ifa_next":field(0,base("u64")),"ifa_address":field(8,base("u32")),
            "ifa_prefixlen":field(12,base("u8")),"ifa_scope":field(13,base("u8")),
        }});
        isf.data["user_types"]["inet6_dev"] =
            json!({"size":16,"fields":{"addr_list":field(0,list.clone())}});
        isf.data["user_types"]["inet6_ifaddr"] = json!({"size":48,"fields":{
            "addr":field(0,json!({"kind":"array","count":16,"subtype":{"kind":"base","name":"u8"}})),
            "prefix_len":field(16,base("u32")),"scope":field(20,base("u32")),
            "if_list":field(24,list),
        }});
        // init_net.dev_base_head <-> eth0.dev_list
        for (at, value) in [
            (0x30010, 0x30110),
            (0x30018, 0x30110),
            (0x30110, 0x30010),
            (0x30118, 0x30010),
        ] {
            put(&mut b, at, value);
        }
        b[0x30100..0x30104].copy_from_slice(b"eth0");
        b[0x30120..0x30124].copy_from_slice(&0x1043u32.to_le_bytes());
        b[0x30124..0x30128].copy_from_slice(&1500u32.to_le_bytes());
        b[0x30128] = 6;
        b[0x30129] = 6;
        put(&mut b, 0x30130, 0x30200);
        b[0x30200..0x30206].copy_from_slice(&[0, 0x0c, 0x29, 0x8f, 0xed, 0xca]);
        put(&mut b, 0x30138, 0x30300);
        put(&mut b, 0x30300, 0x30400);
        b[0x30408..0x3040c].copy_from_slice(&[10, 0, 0, 5]);
        b[0x3040c] = 24;
        put(&mut b, 0x30140, 0x30500);
        for (at, value) in [
            (0x30500, 0x30618),
            (0x30508, 0x30618),
            (0x30618, 0x30500),
            (0x30620, 0x30500),
        ] {
            put(&mut b, at, value);
        }
        b[0x30600] = 0xfe;
        b[0x30601] = 0x80;
        b[0x3060f] = 1;
        b[0x30610] = 64;
        b[0x30614] = 0x20;
        (b, isf)
    }
    #[test]
    fn ip_link_and_ip_addr_decode_init_net_interfaces() {
        let (mut b, isf) = interfaces();
        let im = image(&b);
        let linux = engine(&im, &isf);
        let r = linux.run(Plugin::IpLink, &Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows,
            [[
                hex(0x30000),
                "eth0".into(),
                "00:0c:29:8f:ed:ca".into(),
                "UP".into(),
                "1500".into(),
                "UP,BROADCAST,RUNNING,MULTICAST".into()
            ]
            .to_vec()]
        );
        let r = linux.run(Plugin::IpAddr, &Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        let addresses: Vec<_> = r
            .rows
            .iter()
            .map(|row| (row[4].as_str(), row[5].as_str(), row[6].as_str()))
            .collect();
        assert_eq!(
            addresses,
            [("10.0.0.5", "24", "global"), ("fe80::1", "64", "link")]
        );
        // A looping IPv4 chain keeps the rest of the interface and is partial.
        put(&mut b, 0x30400, 0x30400);
        let im = image(&b);
        let r = engine(&im, &isf)
            .run(Plugin::IpAddr, &Job::default())
            .unwrap();
        assert!(!r.complete);
        assert!(r.rows.iter().any(|row| row[4] == "fe80::1"));
    }
    #[test]
    fn vmcoreinfo_reads_static_and_pointer_buffers() {
        let (mut b, mut isf) = fixture();
        let note = b"OSRELEASE=6.8.11\nPAGESIZE=4096\nignored\n";
        b[0x31000..0x31000 + note.len()].copy_from_slice(note);
        put(&mut b, 0x31800, note.len() as u64);
        isf.data["symbols"]["vmcoreinfo_data"] =
            json!({"address":0x31000,"type":{"kind":"array","count":4096}});
        isf.data["symbols"]["vmcoreinfo_size"] = json!({"address":0x31800});
        let im = image(&b);
        let r = engine(&im, &isf)
            .run(Plugin::Vmcoreinfo, &Job::default())
            .unwrap();
        assert_eq!(
            r.rows,
            [["OSRELEASE", "6.8.11"], ["PAGESIZE", "4096"]]
                .map(|row| row.map(String::from).to_vec())
        );
        put(&mut b, 0x31900, 0x31000);
        isf.data["symbols"]["vmcoreinfo_data"] =
            json!({"address":0x31900,"type":{"kind":"pointer"}});
        let im = image(&b);
        assert_eq!(
            engine(&im, &isf)
                .run(Plugin::Vmcoreinfo, &Job::default())
                .unwrap()
                .rows
                .len(),
            2
        );
        isf.data["symbols"]
            .as_object_mut()
            .unwrap()
            .remove("vmcoreinfo_data");
        let e = engine(&im, &isf)
            .run(Plugin::Vmcoreinfo, &Job::default())
            .unwrap_err();
        assert!(format!("{e:#}").contains("不支持"));
    }

    #[test]
    fn flag_state_and_scope_names_follow_the_kernel_constants() {
        assert_eq!(flag_names(0x1043), "UP,BROADCAST,RUNNING,MULTICAST");
        assert_eq!(flag_names(0x109), "UP,LOOPBACK,PROMISC");
        assert_eq!(operstate(6), "UP");
        assert_eq!(operstate(99), "INVALID");
        assert_eq!(ipv4_scope(254), "host");
        assert_eq!(ipv6_scope(0x20), "link");
        assert_eq!(ipv6_scope(0x10), "host");
    }

    #[test]
    fn linux_ip_addr_and_link_emit_vol3_columns_with_ns_index_qdisc_and_qlen() {
        let (mut b, mut isf) = interfaces();
        isf.data["user_types"]["ns_common"] =
            json!({"size":16,"fields":{"inum":field(0,base("u32"))}});
        isf.data["user_types"]["net"]["fields"]["ns"] =
            field(0, json!({"kind":"struct","name":"ns_common"}));
        isf.data["user_types"]["net_device"]["fields"]["ifindex"] = field(72, base("u32"));
        isf.data["user_types"]["net_device"]["fields"]["tx_queue_len"] = field(76, base("u32"));
        isf.data["user_types"]["net_device"]["fields"]["qdisc"] = field(80, base("u64"));
        isf.data["user_types"]["Qdisc"] = json!({"size":16,"fields":{"ops":field(0,base("u64"))}});
        isf.data["user_types"]["Qdisc_ops"] = json!({"size":32,"fields":{
            "id":field(0,json!({"kind":"array","count":16,"subtype":{"kind":"base","name":"char"}}))
        }});

        // init_net.ns.inum = 4026531992
        put(&mut b, 0x30000, 4_026_531_992);
        // eth0 at 0x30100: ifindex=2, tx_queue_len=1000, qdisc=0x32000
        b[0x30148..0x3014c].copy_from_slice(&2u32.to_le_bytes());
        b[0x3014c..0x30150].copy_from_slice(&1000u32.to_le_bytes());
        put(&mut b, 0x30150, 0x32000);
        // Qdisc 0x32000 -> ops 0x32020 -> id "fq_codel"
        put(&mut b, 0x32000, 0x32020);
        b[0x32020..0x32029].copy_from_slice(b"fq_codel\0");

        let im = image(&b);
        let linux = engine(&im, &isf);
        let link = linux.linux_ip_link(&Job::default()).unwrap();
        assert!(link.complete, "{:?}", link.diagnostics);
        assert_eq!(link.rows.len(), 1);
        assert_eq!(link.rows[0].len(), 8);
        assert_eq!(link.rows[0][0], "4026531992");
        assert_eq!(link.rows[0][1], "eth0");
        assert_eq!(link.rows[0][5], "fq_codel");
        assert_eq!(link.rows[0][6], "1000");

        let addr = linux.linux_ip_addr(&Job::default()).unwrap();
        assert!(addr.complete, "{:?}", addr.diagnostics);
        assert_eq!(addr.rows.len(), 2);
        assert_eq!(addr.rows[0].len(), 9);
        assert_eq!(addr.rows[0][0], "4026531992");
        assert_eq!(addr.rows[0][1], "2");
        assert_eq!(addr.rows[0][2], "eth0");
        assert_eq!(addr.rows[0][5], "10.0.0.5");
        assert_eq!(addr.rows[1][5], "fe80::1");
    }
}
