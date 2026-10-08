//! Socket decoding shared by sockstat and the Internet-only netscan view.
use super::*;
pub(super) fn unix_name(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "[unnamed]".into()
    } else if bytes[0] == 0 {
        format!("@{}", String::from_utf8_lossy(&bytes[1..]))
    } else {
        String::from_utf8_lossy(bytes.split(|b| *b == 0).next().unwrap()).into_owned()
    }
}
pub(super) fn tcp_state(state: u64) -> &'static str {
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
impl Linux<'_> {
    pub(super) fn socket(&self, inode: u64) -> Result<Vec<String>> {
        self.decode_socket(inode, false)?.context("socket 未解码")
    }
    pub(super) fn internet_socket(&self, inode: u64) -> Result<Option<Vec<String>>> {
        self.decode_socket(inode, true)
    }
    fn decode_socket(&self, inode: u64, internet_only: bool) -> Result<Option<Vec<String>>> {
        let allocation = inode
            .checked_sub(self.isf.offset("socket_alloc", "vfs_inode")?)
            .context("socket 地址下溢")?;
        let socket = self.field_address(allocation, "socket_alloc", "socket")?;
        let sk = self.number(socket, "socket", "sk")?;
        ensure!(sk != 0, "socket.sk 为空 @ {}", hex(socket));
        let common = self.field_address(sk, "sock", "__sk_common")?;
        let family = self.number(common, "sock_common", "skc_family")?;
        let protocol = self.number(sk, "sock", "sk_protocol")?;
        if internet_only && !(matches!(family, 2 | 10) && matches!(protocol, 6 | 17)) {
            return Ok(None);
        }
        let ty = self.number(sk, "sock", "sk_type")?;
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
        Ok(Some(vec![
            family_name,
            type_name,
            protocol_name,
            local,
            remote,
            state,
            hex(socket),
        ]))
    }
}
