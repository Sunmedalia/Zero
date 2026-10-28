//! Socket field decoding for independent scans. Embedded fields use their owning
//! address space; pointer targets always use the kernel virtual address space.
use super::*;
use crate::physical::Object;
const NA: &str = "N/A";
const FAMILIES: &[&str] = &[
    "AF_UNSPEC",
    "AF_UNIX",
    "AF_INET",
    "AF_AX25",
    "AF_IPX",
    "AF_APPLETALK",
    "AF_NETROM",
    "AF_BRIDGE",
    "AF_ATMPVC",
    "AF_X25",
    "AF_INET6",
    "AF_ROSE",
    "AF_DECnet",
    "AF_NETBEUI",
    "AF_SECURITY",
    "AF_KEY",
    "AF_NETLINK",
    "AF_PACKET",
    "AF_ASH",
    "AF_ECONET",
    "AF_ATMSVC",
    "AF_RDS",
    "AF_SNA",
    "AF_IRDA",
    "AF_PPPOX",
    "AF_WANPIPE",
    "AF_LLC",
    "AF_IB",
    "AF_MPLS",
    "AF_CAN",
    "AF_TIPC",
    "AF_BLUETOOTH",
    "AF_IUCV",
    "AF_RXRPC",
    "AF_ISDN",
    "AF_PHONET",
    "AF_IEEE802154",
    "AF_CAIF",
    "AF_ALG",
    "AF_NFC",
    "AF_VSOCK",
    "AF_KCM",
    "AF_QIPCRTR",
    "AF_SMC",
    "AF_XDP",
];
const SOCKET_STATES: &[&str] = &[
    "FREE",
    "UNCONNECTED",
    "CONNECTING",
    "CONNECTED",
    "DISCONNECTING",
];
const NETLINK: &[&str] = &[
    "NETLINK_ROUTE",
    "NETLINK_UNUSED",
    "NETLINK_USERSOCK",
    "NETLINK_FIREWALL",
    "NETLINK_SOCK_DIAG",
    "NETLINK_NFLOG",
    "NETLINK_XFRM",
    "NETLINK_SELINUX",
    "NETLINK_ISCSI",
    "NETLINK_AUDIT",
    "NETLINK_FIB_LOOKUP",
    "NETLINK_CONNECTOR",
    "NETLINK_NETFILTER",
    "NETLINK_IP6_FW",
    "NETLINK_DNRTMSG",
    "NETLINK_KOBJECT_UEVENT",
    "NETLINK_GENERIC",
    "NETLINK_DM",
    "NETLINK_SCSITRANSPORT",
    "NETLINK_ECRYPTFS",
    "NETLINK_RDMA",
    "NETLINK_CRYPTO",
    "NETLINK_SMC",
];
const BT: &[&str] = &[
    "L2CAP", "HCI", "SCO", "RFCOMM", "BNEP", "CMTP", "HIDP", "AVDTP",
];
const BT_STATES: &[&str] = &[
    "",
    "CONNECTED",
    "OPEN",
    "BOUND",
    "LISTEN",
    "CONNECT",
    "CONNECT2",
    "CONFIG",
    "DISCONN",
    "CLOSED",
];
fn socket_type(value: u64) -> &'static str {
    match value {
        1 => "STREAM",
        2 => "DGRAM",
        3 => "RAW",
        4 => "RDM",
        5 => "SEQPACKET",
        6 => "DCCP",
        10 => "PACKET",
        _ => "",
    }
}
fn ip_protocol(value: u64, ipv6: bool) -> Option<&'static str> {
    if ipv6 {
        match value {
            0 => return Some("HOPBYHOP_OPTS"),
            43 => return Some("ROUTING"),
            44 => return Some("FRAGMENT"),
            58 => return Some("ICMPv6"),
            59 => return Some("NO_NEXT"),
            60 => return Some("DESTINATION_OPTS"),
            135 => return Some("MOBILITY"),
            _ => {}
        }
    }
    Some(match value {
        0 => "IP",
        1 => "ICMP",
        2 => "IGMP",
        4 => "IPIP",
        6 => "TCP",
        8 => "EGP",
        12 => "PUP",
        17 => "UDP",
        22 => "IDP",
        29 => "TP",
        33 => "DCCP",
        41 => "IPV6",
        46 => "RSVP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        92 => "MTP",
        94 => "BEETPH",
        98 => "ENCAP",
        103 => "PIM",
        108 => "COMP",
        132 => "SCTP",
        136 => "UDPLITE",
        137 => "MPLS",
        143 => "ETHERNET",
        255 => "RAW",
        262 => "MPTCP",
        _ => return None,
    })
}
fn ethernet_protocol(value: u16) -> String {
    let name = match value {
        0 => return NA.into(),
        1 => "ETH_P_802_3",
        2 => "ETH_P_AX25",
        3 => "ETH_P_ALL",
        4 => "ETH_P_802_2",
        5 => "ETH_P_SNAP",
        6 => "ETH_P_DDCMP",
        7 => "ETH_P_WAN_PPP",
        8 => "ETH_P_PPP_MP",
        9 => "ETH_P_LOCALTALK",
        12 => "ETH_P_CAN",
        15 => "ETH_P_CANFD",
        16 => "ETH_P_PPPTALK",
        17 => "ETH_P_TR_802_2",
        22 => "ETH_P_CONTROL",
        23 => "ETH_P_IRDA",
        24 => "ETH_P_ECONET",
        25 => "ETH_P_HDLC",
        26 => "ETH_P_ARCNET",
        27 => "ETH_P_DSA",
        28 => "ETH_P_TRAILER",
        0x60 => "ETH_P_LOOP",
        0xf6 => "ETH_P_IEEE802154",
        0xf7 => "ETH_P_CAIF",
        0xf8 => "ETH_P_XDSA",
        0xf9 => "ETH_P_MAP",
        0x800 => "ETH_P_IP",
        0x805 => "ETH_P_X25",
        0x806 => "ETH_P_ARP",
        0x8035 => "ETH_P_RARP",
        0x809b => "ETH_P_ATALK",
        0x80f3 => "ETH_P_AARP",
        0x8100 => "ETH_P_8021Q",
        _ => return format!("0x{value:x}"),
    };
    name.into()
}
/// Read a struct cast without accidentally translating its physical base as VA.
#[derive(Clone, Copy)]
struct View<'a, 'b> {
    linux: &'a Linux<'b>,
    base: u64,
    physical: bool,
}
impl View<'_, '_> {
    fn number(&self, ty: &str, field: &str) -> Result<u64> {
        if self.physical {
            Object {
                image: self.linux.vm.image,
                isf: self.linux.isf,
                address: self.base,
            }
            .number(ty, field)
        } else {
            self.linux.number(self.base, ty, field)
        }
    }
    fn bytes(&self, ty: &str, field: &str, length: usize) -> Result<Vec<u8>> {
        ensure!(length <= 4096, "socket 字段读取超过上限");
        let layout = self.linux.isf.layout(ty, field)?;
        ensure!(length as u64 <= layout.size, "socket 字段读取超出 ISF 宽度");
        let at = add(self.base, layout.offset)?;
        let mut bytes = vec![0; length];
        if self.physical {
            self.linux.vm.image.read(at, &mut bytes)?;
        } else {
            self.linux.vm.read(at, &mut bytes)?;
        }
        Ok(bytes)
    }
    fn string(&self, ty: &str, field: &str) -> Result<String> {
        let bytes = self.bytes(ty, field, self.linux.isf.size(ty, field)?)?;
        Ok(
            String::from_utf8_lossy(bytes.split(|b| *b == 0).next().unwrap_or_default())
                .into_owned(),
        )
    }
    fn virtual_at(&self, base: u64) -> Self {
        Self {
            base,
            physical: false,
            ..*self
        }
    }
    fn has(&self, ty: &str, field: &str) -> bool {
        self.linux.isf.field(ty, field).is_ok()
    }
    fn optional(&self, ty: &str, fields: &[&str]) -> Result<Option<u64>> {
        fields
            .iter()
            .find(|f| self.has(ty, f))
            .map(|f| self.number(ty, f))
            .transpose()
    }
    fn generic_state(&self) -> Result<String> {
        let socket = self.number("sock", "sk_socket")?;
        // The reference reads address zero too; do not silently invent FREE.
        let state = self.virtual_at(socket).number("socket", "state")?;
        Ok(SOCKET_STATES
            .get(state as usize)
            .unwrap_or(&"Unknown socket state")
            .to_string())
    }
    fn inet_state(&self, unix: bool) -> Result<String> {
        if self.number("sock", "sk_type")? == 1 {
            let state = self.number("sock", "__sk_common.skc_state")?;
            Ok(match state {
                0 => "",
                12 => "TCP_NEW_SYN_RECV",
                1..=11 => super::net::tcp_state(state),
                _ if unix => "Unknown unix_sock stream state",
                _ => "Unknown inet_sock stream state",
            }
            .into())
        } else {
            self.generic_state()
        }
    }
    fn inode(&self) -> Result<String> {
        let socket = self.number("sock", "sk_socket")?;
        if socket == 0 {
            return Ok("0".into());
        }
        let alloc = socket
            .checked_sub(self.linux.isf.offset("socket_alloc", "socket")?)
            .context("socket_alloc 地址下溢")?;
        Ok(self
            .virtual_at(alloc)
            .number("socket_alloc", "vfs_inode.i_ino")?
            .to_string())
    }
    fn unix_name(&self) -> Result<String> {
        let addr = self.number("unix_sock", "addr")?;
        if addr == 0 {
            return Ok(NA.into());
        }
        self.virtual_at(add(addr, self.linux.isf.offset("unix_address", "name")?)?)
            .string("sockaddr_un", "sun_path")
    }
    fn inet_addr(&self, src: bool, family: u64) -> Result<String> {
        if family == 2 {
            let field = if src {
                self.optional("inet_sock", &["rcv_saddr", "inet_rcv_saddr"])?
            } else {
                self.optional("inet_sock", &["daddr", "inet_daddr"])?
                    .filter(|v| *v != 0)
            };
            let value = match field {
                Some(v) => v,
                None => self.number(
                    "sock",
                    if src {
                        "__sk_common.skc_rcv_saddr"
                    } else {
                        "__sk_common.skc_daddr"
                    },
                )?,
            };
            Ok(Ipv4Addr::from((value as u32).to_le_bytes()).to_string())
        } else {
            // pinet6 is a virtual pointer even when this sock was carved physically.
            // New kernels can store the addresses directly in sock_common.
            let bytes = if self.has("inet_sock", "pinet6") {
                let info = self.number("inet_sock", "pinet6")?;
                ensure!(info != 0, "IPv6 pinet6 为空");
                let info = self.virtual_at(info);
                if src {
                    info.bytes("ipv6_pinfo", "saddr", 16)?
                } else if info.has("ipv6_pinfo", "daddr") {
                    info.bytes("ipv6_pinfo", "daddr", 16)?
                } else {
                    self.bytes("sock", "__sk_common.skc_v6_daddr", 16)?
                }
            } else {
                self.bytes(
                    "sock",
                    if src {
                        "__sk_common.skc_v6_rcv_saddr"
                    } else {
                        "__sk_common.skc_v6_daddr"
                    },
                    16,
                )?
            };
            Ok(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()).to_string())
        }
    }
    fn filters(&self) -> Result<String> {
        let mut values: Vec<(String, String)> = Vec::new();
        for (field, ty, kind) in [
            ("sk_filter", "sk_filter", "socket_filter"),
            ("sk_reuseport_cb", "sock_reuseport", "reuseport_filter"),
        ] {
            if !self.has("sock", field) {
                continue;
            }
            let ptr = self.number("sock", field)?;
            if ptr == 0 {
                continue;
            }
            set(&mut values, "filter_type", kind.into());
            set(&mut values, "bpf_filter_type", "cBPF".into());
            let filter = self.virtual_at(ptr);
            if !filter.has(ty, "prog") {
                continue;
            }
            let prog = filter.number(ty, "prog")?;
            if prog == 0 {
                continue;
            }
            let prog = filter.virtual_at(prog);
            if !prog.has("bpf_prog", "type") {
                continue;
            }
            let num = prog.number("bpf_prog", "type")?;
            let name = self.linux.enum_socket_value("bpf_prog_type", num);
            let Some(name) = name else {
                continue;
            };
            if name == "BPF_PROG_TYPE_UNSPEC" {
                continue;
            }
            if name != "BPF_PROG_TYPE_SOCKET_FILTER" {
                set(&mut values, "bpf_filter_type", format!("UNK({name})"));
                continue;
            }
            set(&mut values, "bpf_filter_type", "eBPF".into());
            if !prog.has("bpf_prog", "aux") {
                continue;
            }
            let aux = prog.number("bpf_prog", "aux")?;
            if aux != 0 {
                self.virtual_at(aux).bpf_aux(
                    &mut values,
                    "bpf_filter_id",
                    "bpf_filter_name",
                    false,
                )?;
            }
        }
        Ok(if values.is_empty() {
            NA.into()
        } else {
            values
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(",")
        })
    }
    fn bpf_aux(
        &self,
        values: &mut Vec<(String, String)>,
        id: &str,
        name: &str,
        prefix: bool,
    ) -> Result<()> {
        if self.has("bpf_prog_aux", "id") {
            let v = self.number("bpf_prog_aux", "id")?;
            set(
                values,
                id,
                if prefix {
                    format!("ebpf_prog_id:{v}")
                } else {
                    v.to_string()
                },
            );
        }
        if self.has("bpf_prog_aux", "name") {
            let v = self.string("bpf_prog_aux", "name")?;
            if !v.is_empty() {
                set(
                    values,
                    name,
                    if prefix {
                        format!("ebpf_prog_name:{v}")
                    } else {
                        v
                    },
                );
            }
        }
        Ok(())
    }
}
fn set(values: &mut Vec<(String, String)>, key: &str, value: String) {
    if let Some(v) = values.iter_mut().find(|(k, _)| k == key) {
        v.1 = value;
    } else {
        values.push((key.into(), value));
    }
}
pub(super) struct SocketFields {
    pub row: Vec<String>,
    pub warnings: Vec<String>,
}
impl Linux<'_> {
    fn enum_socket_value(&self, ty: &str, value: u64) -> Option<String> {
        self.isf.data["enums"][ty]["constants"]
            .as_object()?
            .iter()
            .find(|(_, v)| v.as_u64() == Some(value))
            .map(|(k, _)| k.clone())
    }
    pub(super) fn socket_scan_fields(
        &self,
        address: u64,
        devices: &BTreeMap<u64, String>,
    ) -> Result<Option<SocketFields>> {
        let sock = View {
            linux: self,
            base: address,
            physical: true,
        };
        let family = sock.number("sock", "__sk_common.skc_family")?;
        let ty = sock.number("sock", "sk_type")?;
        let mut warnings = Vec::new();
        let mut proto = NA.to_string();
        let mut src = NA.to_string();
        let mut sport = NA.to_string();
        let mut dst = NA.to_string();
        let mut dport = NA.to_string();
        let mut state = None;
        let child = match family {
            1 => Some("unix_sock"),
            2 | 10 => Some("inet_sock"),
            16 => Some("netlink_sock"),
            17 => Some("packet_sock"),
            31 => Some("bt_sock"),
            40 => Some("vsock_sock"),
            44 => Some("xdp_sock"),
            _ => None,
        };
        // An absent family type is the reference's generic fallback, not a
        // successful read of zero endpoints. Reads of present types must succeed.
        let supported = child.is_some_and(|ty| self.isf.data["user_types"][ty].is_object());
        if supported {
            match family {
                1 => {
                    src = sock.unix_name()?;
                    sport = sock.inode()?;
                    let peer = sock.number("unix_sock", "peer")?;
                    if peer != 0 {
                        let peer = sock.virtual_at(peer);
                        dst = peer.unix_name()?;
                        dport = peer.inode()?;
                    }
                    state = Some(sock.inet_state(true)?);
                }
                2 | 10 => {
                    proto = ip_protocol(sock.number("sock", "sk_protocol")?, family == 10)
                        .unwrap_or(NA)
                        .into();
                    for (source, value) in [(true, &mut src), (false, &mut dst)] {
                        match sock.inet_addr(source, family) {
                            Ok(address) => *value = address,
                            Err(error) => warnings.push(format!(
                                "{} address: {error:#}",
                                if source { "source" } else { "destination" }
                            )),
                        }
                    }
                    sport = sock
                        .optional("inet_sock", &["sport", "inet_sport"])?
                        .map(|p| (p as u16).to_be().to_string())
                        .unwrap_or_else(|| NA.into());
                    let port = if sock.has("sock", "__sk_common.skc_portpair") {
                        Some(sock.number("sock", "__sk_common.skc_portpair")? & 0xffff)
                    } else if let Some(port) =
                        sock.optional("inet_sock", &["dport", "inet_dport"])?
                    {
                        Some(port)
                    } else {
                        sock.optional("sock", &["__sk_common.skc_dport"])?
                    };
                    dport = port
                        .map(|p| (p as u16).to_be().to_string())
                        .unwrap_or_else(|| NA.into());
                    state = Some(sock.inet_state(false)?);
                }
                16 => {
                    proto = NETLINK
                        .get(sock.number("sock", "sk_protocol")? as usize)
                        .unwrap_or(&"Unknown netlink_sock protocol")
                        .to_string();
                    let groups = sock.number("netlink_sock", "groups")?;
                    if groups != 0 {
                        let width = self.isf.data["base_types"]["unsigned long int"]["size"]
                            .as_u64()
                            .unwrap_or(8) as usize;
                        src = format!("groups:0x{:08x}", self.vm.uint(groups, width)?);
                    }
                    sport = sock
                        .optional("netlink_sock", &["pid", "portid"])?
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| NA.into());
                    dport = sock
                        .optional("netlink_sock", &["dst_pid", "dst_portid"])?
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| NA.into());
                    dst = format!("group:0x{:08x}", sock.number("netlink_sock", "dst_group")?);
                    let module = sock.number("netlink_sock", "module")?;
                    if module != 0 {
                        let name = sock.virtual_at(module).string("module", "name")?;
                        if !name.is_empty() {
                            dst.push_str(&format!(",lkm:{name}"));
                        }
                    }
                }
                40 => {
                    src = sock.number("vsock_sock", "local_addr.svm_cid")?.to_string();
                    sport = sock
                        .number("vsock_sock", "local_addr.svm_port")?
                        .to_string();
                    dst = sock
                        .number("vsock_sock", "remote_addr.svm_cid")?
                        .to_string();
                    dport = sock
                        .number("vsock_sock", "remote_addr.svm_port")?
                        .to_string();
                }
                17 => {
                    let index = sock.number("packet_sock", "ifindex")? as u32 as i32;
                    src = if index <= 0 {
                        "ANY".into()
                    } else {
                        devices
                            .get(&(index as u64))
                            .cloned()
                            .unwrap_or_else(|| NA.into())
                    };
                    let protocol = (sock.number("packet_sock", "num")? as u16).to_be();
                    proto = ethernet_protocol(protocol);
                }
                44 => {
                    let dev = sock.number("xdp_sock", "dev")?;
                    if dev == 0 {
                        return Ok(None);
                    }
                    let dev = sock.virtual_at(dev);
                    src = dev.string("net_device", "name")?;
                    let prog = dev.number("net_device", "xdp_prog")?;
                    if prog == 0 {
                        return Ok(None);
                    }
                    let prog = sock.virtual_at(prog);
                    if !prog.has("bpf_prog", "aux") {
                        return Ok(None);
                    }
                    let aux = prog.number("bpf_prog", "aux")?;
                    if aux == 0 {
                        return Ok(None);
                    }
                    let mut extra = Vec::new();
                    sock.virtual_at(aux)
                        .bpf_aux(&mut extra, "id", "name", true)?;
                    for (k, v) in extra {
                        if k == "id" {
                            dport = v;
                        } else {
                            dst = v;
                        }
                    }
                    state = Some(
                        self.enum_socket_value(
                            self.isf.field("xdp_sock", "state")?["type"]["name"]
                                .as_str()
                                .context("XDP state enum 类型缺失")?,
                            sock.number("xdp_sock", "state")?,
                        )
                        .context("未知 XDP socket state")?
                        .replace("XSK_", ""),
                    );
                }
                31 => {
                    let protocol = sock.number("sock", "sk_protocol")?;
                    proto = BT.get(protocol as usize).unwrap_or(&NA).to_string();
                    state = Some(
                        BT_STATES
                            .get(sock.number("sock", "__sk_common.skc_state")? as usize)
                            .unwrap_or(&NA)
                            .to_string(),
                    );
                    self.bluetooth_scan_fields(
                        &sock, &proto, &mut src, &mut sport, &mut dst, &mut dport,
                    )?;
                }
                _ => {}
            }
        }
        let state = match state {
            Some(v) => v,
            None => sock.generic_state()?,
        };
        let filter = if supported {
            sock.filters()?
        } else {
            NA.into()
        };
        // Match the reference's empty-object rule (including its source-absence
        // test), without using missing objects as proof of no connections.
        if (src == NA || src == "0.0.0.0" && dst == "0.0.0.0")
            && (state == "UNCONNECTED" || sport == "0" && dport == "0")
        {
            return Ok(None);
        }
        Ok(Some(SocketFields {
            row: vec![
                hex(address),
                FAMILIES
                    .get(family as usize)
                    .unwrap_or(&"Unknown socket family")
                    .to_string(),
                socket_type(ty).into(),
                proto,
                src,
                sport,
                dst,
                dport,
                state,
                filter,
            ],
            warnings,
        }))
    }
    fn bluetooth_scan_fields(
        &self,
        sock: &View<'_, '_>,
        proto: &str,
        src: &mut String,
        sport: &mut String,
        dst: &mut String,
        dport: &mut String,
    ) -> Result<()> {
        let kind = match proto {
            "HCI" => "hci_pinfo",
            "L2CAP" => "l2cap_pinfo",
            "RFCOMM" => "rfcomm_pinfo",
            "SCO" => "sco_pinfo",
            _ => return Ok(()),
        };
        if !self.isf.data["user_types"][kind].is_object() {
            return Ok(());
        }
        let addr = |view: &View<'_, '_>, ty: &str, field: &str| -> Result<String> {
            Ok(view
                .bytes(ty, field, 6)?
                .iter()
                .rev()
                .map(|v| format!("{v:02x}"))
                .collect::<Vec<_>>()
                .join(":"))
        };
        match proto {
            "HCI" if sock.has(kind, "hdev") => {
                let dev = sock.number(kind, "hdev")?;
                if dev != 0 && sock.has("hci_dev", "dev_name") {
                    *src = sock.virtual_at(dev).string("hci_dev", "dev_name")?;
                }
            }
            "L2CAP" => {
                let chan = if self.isf.field(kind, "chan")?["type"]["kind"] == "pointer" {
                    let chan = sock.number(kind, "chan")?;
                    ensure!(chan != 0, "L2CAP chan 为空");
                    sock.virtual_at(chan)
                } else {
                    View {
                        base: add(sock.base, self.isf.offset(kind, "chan")?)?,
                        ..*sock
                    }
                };
                *src = addr(&chan, "l2cap_chan", "src")?;
                *dst = addr(&chan, "l2cap_chan", "dst")?;
                *sport = chan.number("l2cap_chan", "sport")?.to_string();
                *dport = chan.number("l2cap_chan", "psm")?.to_string();
            }
            "RFCOMM" | "SCO" => {
                *src = addr(sock, kind, "src")?;
                *dst = addr(sock, kind, "dst")?;
                if proto == "RFCOMM" {
                    *sport = sock.number(kind, "channel")?.to_string();
                }
            }
            _ => {}
        }
        Ok(())
    }
}
