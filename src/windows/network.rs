//! TCP/IP object layouts are allowlisted by exact driver PDB identity, not OS version.
use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};
pub(super) const LAYOUTS: &str = include_str!("network_layouts.json");
use super::network_layout::{self, Layout};
impl Windows<'_> {
    pub(super) fn netscan(
        &self,
        job: &Job,
        resources: Option<(&std::path::Path, bool)>,
    ) -> Result<Results> {
        let mut driver = None;
        let module_type = self.module_type()?;
        let (modules, diagnostics) = self.list_partial(
            self.symbol("PsLoadedModuleList")?,
            self.vm.isf.offset(module_type, "InLoadOrderLinks")?,
            job,
        )?;
        for module in modules {
            let name = self
                .vm
                .unicode(self.field(module, module_type, "BaseDllName")?)?;
            if name.eq_ignore_ascii_case("tcpip.sys") {
                driver = Some(self.number(module, module_type, "DllBase")?);
                break;
            }
        }
        let base = driver.context("tcpip.sys 未加载")?;
        let identity = pe_identity(&self.vm, base)?;
        let arch = Architecture::from_isf(self.vm.isf)?;
        let version = network_layout::file_version(&self.vm, base).ok();
        let exact = resources.and_then(|(cache, network)| {
            let result = windows_symbols::acquire(&identity, cache, network, job).and_then(|isf| {
                ensure!(Architecture::from_isf(&isf)? == arch, "TCP/IP PDB 架构冲突");
                Layout::from_isf(&isf)
            });
            match result {
                Ok(layout) => Some(layout),
                Err(e) => {
                    job.report(format!("TCP/IP 精确符号布局不可用: {e:#}"));
                    None
                }
            }
        });
        job.check()?;
        let layout = if let Some(layout) = exact {
            layout
        } else {
            match network_layout::manifest(&identity, arch, version) {
                Ok(layout) => layout,
                Err(e) if version.is_none() => {
                    let kernel_version = self.declared_kernel_version()?;
                    let mut layout =
                        network_layout::manifest(&identity, arch, Some(kernel_version))
                            .with_context(|| {
                                format!("驱动 PE 不可读且内核系列没有声明 TCP/IP 布局: {e:#}")
                            })?;
                    layout.validation = "synthetic-kernel-version-fallback".into();
                    layout
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("无法解码 TCP/IP {} version {version:?}", identity.key())
                    });
                }
            }
        };
        let mut r = self.result(Plugin::WinNetscan);
        r.complete = diagnostics.is_empty();
        r.diagnostics = diagnostics;
        r.kernel_identity["tcpip_pdb"] = serde_json::to_value(&identity)?;
        r.kernel_identity["tcpip_file_version"] = serde_json::json!(version);
        if layout.validation == "synthetic-kernel-version-fallback" {
            Self::issue(
                &mut r,
                "TCP/IP identity",
                "驱动 PE 版本不可读；仅采用显式声明的内核系列布局，未验证驱动布局兼容性",
            );
            r.kernel_identity["network_kernel_fallback"] =
                serde_json::json!(self.declared_kernel_version()?);
        }
        r.kernel_identity["network_layout"] = serde_json::json!({"source":layout.source,"validation":layout.validation,"pointer_size":layout.pointer_size});
        if !matches!(
            layout.validation.as_str(),
            "exact-driver-symbols" | "public-raw-reference" | "public-crash-reference"
        ) {
            Self::issue(
                &mut r,
                "TCP/IP 布局",
                "该驱动版本系列仅有合成布局验证，尚未验证此精确驱动身份",
            );
        }
        let isf = self.vm.isf;
        let alignment = if layout.pointer_size == 4 { 8 } else { 16 };
        let header_size = isf.data["user_types"]["_POOL_HEADER"]["size"]
            .as_u64()
            .context("缺少 pool header")?;
        let tag_offset = isf.offset("_POOL_HEADER", "PoolTag")?;
        let mut tags: Vec<(&[u8], usize)> = layout
            .endpoint_tags
            .iter()
            .map(|tag| (tag.as_bytes(), 0))
            .collect();
        tags.extend([(b"TcpL".as_slice(), 1), (b"UdpA".as_slice(), 2)]);
        self.prefetch_pool_tags(job)?;
        for (tag, kind) in tags {
            for hit in self.vm.image.scan(tag, job)? {
                job.check()?;
                let Some(header) = hit.checked_sub(tag_offset) else {
                    continue;
                };
                if header % alignment != 0 {
                    continue;
                }
                let mut bytes = vec![0; usize::try_from(header_size)?];
                if self.vm.image.read(header, &mut bytes).is_err() {
                    continue;
                }
                let block =
                    objects::physical_number(isf, &bytes, "_POOL_HEADER", "BlockSize")? * alignment;
                let size = layout.size(kind)?;
                if block < header_size + size as u64 || block > 4096 {
                    continue;
                }
                let address = header + header_size;
                let mut b = vec![0; size];
                if self.vm.image.read(address, &mut b).is_err() {
                    continue;
                }
                let mut recognized = false;
                let parsed = (|| -> Result<Vec<Vec<String>>> {
                    let fields = layout.fields(kind);
                    let field = |name: &str, width: usize| -> Result<u64> {
                        read(&b, *fields.get(name).context("缺少 TCP/IP 字段")?, width)
                    };
                    let af = field("InetAF", layout.pointer_size)?;
                    ensure!(self.vm.kernel(af), "无效 InetAF");
                    let family = self.vm.uint(add(af, layout.family)?, 2)?;
                    ensure!(matches!(family, 2 | 23), "无效地址族");
                    let owner = field("Owner", layout.pointer_size)?;
                    let process = self.process(owner)?;
                    let time = field("CreateTime", 8)?;
                    let time = if time == 0
                        || (110_000_000_000_000_000..190_000_000_000_000_000).contains(&time)
                    {
                        filetime(time)
                    } else {
                        String::new()
                    };
                    let port =
                        u16::try_from(field(if kind == 0 { "LocalPort" } else { "Port" }, 2)?)?;
                    let port = port.swap_bytes();
                    let (local, remote, state, remote_port) = if kind == 0 {
                        let state = field("State", 4)?;
                        let label = match state {
                            0 => "CLOSED",
                            1 => "LISTENING",
                            2 => "SYN_SENT",
                            3 => "SYN_RCVD",
                            4 => "ESTABLISHED",
                            5 => "FIN_WAIT1",
                            6 => "FIN_WAIT2",
                            7 => "CLOSE_WAIT",
                            8 => "CLOSING",
                            9 => "LAST_ACK",
                            12 => "TIME_WAIT",
                            13 => "DELETE_TCB",
                            _ => bail!("无效 TCP 状态"),
                        };
                        recognized = true;
                        let info = field("AddrInfo", layout.pointer_size)?;
                        let local = self.vm.pointer(add(info, layout.info_local)?)?;
                        let local = self.local_address(local, false, &layout)?;
                        let remote = self.vm.pointer(add(info, layout.info_remote)?)?;
                        let remote_port = u16::try_from(field("RemotePort", 2)?)?.swap_bytes();
                        (local, remote, label, remote_port)
                    } else {
                        recognized = true;
                        let local = field("LocalAddr", layout.pointer_size)?;
                        (
                            if local == 0 {
                                0
                            } else {
                                self.local_address(local, kind == 2, &layout)?
                            },
                            0,
                            if kind == 1 { "LISTENING" } else { "" },
                            0,
                        )
                    };
                    let families = if local == 0 && kind != 0 && family == 23 {
                        vec![2, 23]
                    } else {
                        vec![family]
                    };
                    let mut rows = Vec::new();
                    for family in families {
                        let protocol = format!(
                            "{}v{}",
                            if kind == 2 { "UDP" } else { "TCP" },
                            if family == 2 { 4 } else { 6 }
                        );
                        rows.push(vec![
                            format!("physical:{address:#x}"),
                            protocol,
                            endpoint(&self.vm, local, family, port)?,
                            endpoint(&self.vm, remote, family, remote_port)?,
                            state.into(),
                            process.pid.to_string(),
                            process.name.clone(),
                            time.clone(),
                        ]);
                    }
                    Ok(rows)
                })();
                match parsed {
                    Ok(rows) => r.rows.extend(rows),
                    Err(e) if recognized => Self::issue(
                        &mut r,
                        format!("network pool physical {address:#x}"),
                        format!("{e:#}"),
                    ),
                    Err(_) => {}
                }
            }
        }
        // Rejected pool candidates are not evidence; missing required driver/layout was fatal above.
        r.rows.sort();
        r.rows.dedup();
        Ok(r)
    }
    fn local_address(&self, address: u64, udp: bool, layout: &Layout) -> Result<u64> {
        let pointer = self.vm.pointer(add(
            address,
            if udp {
                layout.udp_data
            } else {
                layout.local_data
            },
        )?)?;
        if pointer == 0 {
            return Ok(0);
        }
        if udp && layout.udp_direct {
            Ok(pointer)
        } else {
            self.vm.pointer(pointer)
        }
    }
    /// Volatility windows.netstat.NetStat: partition tables and port pools, not pool tags.
    pub(super) fn netstat(
        &self,
        job: &Job,
        resources: Option<(&std::path::Path, bool)>,
    ) -> Result<Results> {
        let (base, size, identity) = self.tcpip_module(job)?;
        ensure!(
            (0x1000..=64 * 1024 * 1024).contains(&size),
            "tcpip.sys 映像大小无效"
        );
        let resources = resources.context("netstat 需要 tcpip.sys 的精确 PDB 符号")?;
        let isf = windows_symbols::acquire(&identity, resources.0, resources.1, job)?;
        let arch = Architecture::from_isf(self.vm.isf)?;
        ensure!(Architecture::from_isf(&isf)? == arch, "TCP/IP PDB 架构冲突");
        let version = network_layout::file_version(&self.vm, base).ok();
        let layout = network_layout::manifest(&identity, arch, version)
            .with_context(|| format!("没有 tcpip.sys {} 的 netstat 对象布局", identity.key()))?;
        let net = layout
            .netstat
            .clone()
            .filter(|item| item.available)
            .context("该 TCP/IP 布局没有端口池和分区表字段")?;
        let mut r = self.result(Plugin::WinNetstat);
        r.kernel_identity["tcpip_pdb"] = serde_json::to_value(&identity)?;
        r.kernel_identity["network_layout"] = serde_json::json!({
            "source": layout.source,
            "validation": layout.validation,
            "pointer_size": layout.pointer_size
        });
        let symbols = &isf.data["symbols"];
        let symbol = |name: &str| -> Result<u64> {
            symbols[name]["address"]
                .as_u64()
                .with_context(|| format!("tcpip.sys 缺少符号 {name}"))
        };
        let mut seen = HashSet::new();
        if let (Ok(table), Ok(count_rva)) = (symbol("PartitionTable"), symbol("PartitionCount")) {
            match self.netstat_partitions(&layout, &net, base, (table, count_rva), job, &mut seen) {
                Ok(rows) => r.rows.extend(rows),
                Err(error) => Self::issue(&mut r, "PartitionTable", format!("{error:#}")),
            }
        } else {
            Self::issue(&mut r, "PartitionTable", "tcpip 符号没有分区表");
        }
        match self.netstat_pool_addresses(&isf, &net, base) {
            Ok((udp_pool, tcp_pool)) => {
                match self.netstat_pool(&layout, &net, tcp_pool, true, job, &mut seen) {
                    Ok(rows) => r.rows.extend(rows),
                    Err(error) => Self::issue(&mut r, "TcpPortPool", format!("{error:#}")),
                }
                match self.netstat_pool(&layout, &net, udp_pool, false, job, &mut seen) {
                    Ok(rows) => r.rows.extend(rows),
                    Err(error) => Self::issue(&mut r, "UdpPortPool", format!("{error:#}")),
                }
            }
            Err(error) => Self::issue(&mut r, "PortPool", format!("{error:#}")),
        }
        r.rows.sort();
        r.rows.dedup();
        Ok(r)
    }

    fn tcpip_module(&self, job: &Job) -> Result<(u64, u64, PdbIdentity)> {
        let module_type = self.module_type()?;
        let (modules, _diagnostics) = self.list_partial(
            self.symbol("PsLoadedModuleList")?,
            self.vm.isf.offset(module_type, "InLoadOrderLinks")?,
            job,
        )?;
        for module in modules {
            let name = self
                .vm
                .unicode(self.field(module, module_type, "BaseDllName")?)?;
            if name.eq_ignore_ascii_case("tcpip.sys") {
                let base = self.number(module, module_type, "DllBase")?;
                let size = self.number(module, module_type, "SizeOfImage")?;
                return Ok((base, size, pe_identity(&self.vm, base)?));
            }
        }
        bail!("tcpip.sys 未加载")
    }

    fn netstat_partitions(
        &self,
        layout: &Layout,
        net: &network_layout::NetstatLayout,
        base: u64,
        table: (u64, u64),
        job: &Job,
        seen: &mut HashSet<u64>,
    ) -> Result<Vec<Vec<String>>> {
        let (table_rva, count_rva) = table;
        let table = self.vm.pointer(add(base, table_rva)?)?;
        ensure!(self.vm.kernel(table), "PartitionTable 不是内核地址");
        let count = self.vm.uint(add(base, count_rva)?, 1)?;
        ensure!((1..=256).contains(&count), "PartitionCount 无效: {count}");
        let part_size = net.partition_size.context("缺少分区大小")?;
        let endpoints = net.endpoints.context("缺少分区端点偏移")?;
        let entry = net.list_entry.context("缺少 TCP 链表偏移")?;
        let mut rows = Vec::new();
        for index in 0..count {
            job.check()?;
            let partition = add(table, index * part_size)?;
            let hash = match self.vm.pointer(add(partition, endpoints)?) {
                Ok(address) if self.vm.kernel(address) => address,
                _ => continue,
            };
            let directory = match self.vm.pointer(add(hash, net.hash_directory)?) {
                Ok(address) if self.vm.kernel(address) => address,
                _ => continue,
            };
            let table_size = self
                .vm
                .uint(add(hash, net.hash_table_size)?, 4)
                .unwrap_or(0);
            if table_size == 0 || table_size > 4096 {
                continue;
            }
            for slot in 0..table_size {
                job.check()?;
                let slot_addr = add(directory, slot * net.hash_alignment)?;
                let link = match self.vm.pointer(slot_addr) {
                    Ok(address) if address != slot_addr && self.vm.kernel(address) => address,
                    _ => continue,
                };
                let object = link.wrapping_sub(entry);
                // A live hash entry is a real LIST_ENTRY. Stale pointers still look
                // like endpoints but do not point both ways inside kernel space.
                let Ok(list) = add(object, entry) else {
                    continue;
                };
                let Ok(flink) = self.vm.pointer(list) else {
                    continue;
                };
                let Ok(blink) = self.vm.pointer(add(list, layout.pointer_size as u64)?) else {
                    continue;
                };
                if !self.vm.kernel(flink) || !self.vm.kernel(blink) {
                    continue;
                }
                if seen.insert(object) {
                    rows.extend(self.netstat_endpoint(layout, object));
                }
            }
        }
        Ok(rows)
    }

    fn netstat_pool_addresses(
        &self,
        isf: &Isf,
        net: &network_layout::NetstatLayout,
        base: u64,
    ) -> Result<(u64, u64)> {
        let symbols = &isf.data["symbols"];
        let address = |name: &str| {
            symbols[name]["address"]
                .as_u64()
                .with_context(|| format!("tcpip.sys 缺少符号 {name}"))
        };
        let pointer = |rva: u64| self.vm.pointer(add(base, rva)?);
        if symbols.get("UdpPortPool").is_some() && symbols.get("TcpPortPool").is_some() {
            return Ok((
                pointer(address("UdpPortPool")?)?,
                pointer(address("TcpPortPool")?)?,
            ));
        }
        let compartment = net.compartment.context("缺少 compartment 偏移")?;
        let protocol = net.protocol.context("缺少 protocol compartment 偏移")?;
        let pool = |name: &str| -> Result<u64> {
            let set = pointer(address(name)?)?;
            ensure!(self.vm.kernel(set), "{name} 不是内核地址");
            let compartment = self.vm.pointer(add(set, compartment)?)?;
            ensure!(self.vm.kernel(compartment), "{name} 的 compartment 不可读");
            let protocol = self.vm.pointer(add(compartment, protocol)?)?;
            ensure!(
                self.vm.kernel(protocol),
                "{name} 的 protocol compartment 不可读"
            );
            let pool = self.vm.pointer(add(protocol, net.port_pool)?)?;
            ensure!(self.vm.kernel(pool), "{name} 的端口池不可读");
            Ok(pool)
        };
        Ok((pool("UdpCompartmentSet")?, pool("TcpCompartmentSet")?))
    }

    fn netstat_pool(
        &self,
        layout: &Layout,
        net: &network_layout::NetstatLayout,
        pool: u64,
        tcp: bool,
        job: &Job,
        seen: &mut HashSet<u64>,
    ) -> Result<Vec<Vec<String>>> {
        let bitmap_off = net.bitmap.context("缺少端口位图偏移")?;
        let assignments = net.assignments.context("缺少端口分配表偏移")?;
        let list_off = net.assignment_list.context("缺少端口分配链表偏移")?;
        let entry_off = net.entry.context("缺少端口项偏移")?;
        let stride = net.entry_stride.context("缺少端口项大小")?;
        let next = if tcp {
            net.listener_next.context("缺少 TCP listener Next")?
        } else {
            net.udp_next.context("缺少 UDP Next")?
        };
        let bitmap = self
            .vm
            .pointer(add(pool, bitmap_off + layout.pointer_size as u64)?)?;
        let bits = self.vm.uint(add(pool, bitmap_off)?, 4)?;
        let bytes = bits / 8;
        ensure!(
            (1..=8192 * 10).contains(&bytes) && self.vm.kernel(bitmap),
            "端口位图不可读或超过上限"
        );
        let kind = if tcp { 1 } else { 2 };
        let pointer = layout.pointer_size as u64;
        let mut rows = Vec::new();
        for index in 0..bytes {
            job.check()?;
            let byte = match self.vm.uint(add(bitmap, index)?, 1) {
                Ok(value) => value,
                Err(_) => continue,
            };
            for bit in 0..8 {
                if byte & (1 << bit) == 0 {
                    continue;
                }
                let port = index * 8 + bit;
                if port == 0 {
                    continue;
                }
                let assignment = match self
                    .vm
                    .pointer(add(pool, assignments + (port >> 8) * pointer)?)
                {
                    Ok(address) if self.vm.kernel(address) => address,
                    _ => continue,
                };
                let list = match self.vm.pointer(add(assignment, list_off)?) {
                    Ok(address) if self.vm.kernel(address) => address,
                    _ => continue,
                };
                let entry = match self
                    .vm
                    .pointer(add(list, (port & 0xff) * stride + entry_off)?)
                {
                    Ok(value) if value != 0 => value & 0xffff_ffff_ffff_fffc,
                    _ => continue,
                };
                let mut inside = entry;
                for _ in 0..64 {
                    if inside == 0 {
                        break;
                    }
                    let object = inside.wrapping_sub(next);
                    if self.vm.kernel(object) && seen.insert(object) {
                        rows.extend(self.netstat_bound(layout, object, kind));
                    }
                    inside = match self.vm.pointer(add(object, next)?) {
                        Ok(value) if value != 0 => value & 0xffff_ffff_ffff_fffc,
                        _ => 0,
                    };
                }
            }
        }
        Ok(rows)
    }

    fn netstat_endpoint(&self, layout: &Layout, address: u64) -> Vec<Vec<String>> {
        let parsed = (|| -> Result<Option<Vec<String>>> {
            let state = self.netstat_field(address, layout, 0, "State", 4)?;
            let label = match state {
                0 => "CLOSED",
                1 => "LISTENING",
                2 => "SYN_SENT",
                3 => "SYN_RCVD",
                4 => "ESTABLISHED",
                5 => "FIN_WAIT1",
                6 => "FIN_WAIT2",
                7 => "CLOSE_WAIT",
                8 => "CLOSING",
                9 => "LAST_ACK",
                12 => "TIME_WAIT",
                13 => "DELETE_TCB",
                _ => return Ok(None),
            };
            let family = self.netstat_family(address, layout, 0)?;
            if !matches!(family, 2 | 23) {
                return Ok(None);
            }
            let local_port =
                u16::try_from(self.netstat_field(address, layout, 0, "LocalPort", 2)?)?
                    .swap_bytes();
            let remote_port =
                u16::try_from(self.netstat_field(address, layout, 0, "RemotePort", 2)?)?
                    .swap_bytes();
            let info = self.netstat_field(address, layout, 0, "AddrInfo", layout.pointer_size)?;
            if !self.vm.kernel(info) {
                return Ok(None);
            }
            let local = self.vm.pointer(add(info, layout.info_local)?)?;
            let local = if local == 0 {
                0
            } else {
                self.local_address(local, false, layout).unwrap_or(0)
            };
            let remote = self.vm.pointer(add(info, layout.info_remote)?)?;
            let (pid, owner) = self.netstat_owner(address, layout, 0);
            if local == 0
                && (pid == "-"
                    || pid
                        .parse::<u64>()
                        .is_ok_and(|value| value == 0 || value > 65535))
            {
                return Ok(None);
            }
            Ok(Some(vec![
                format!("{:#x}", address & 0x0000_ffff_ffff_ffff),
                if family == 2 {
                    "TCPv4".into()
                } else {
                    "TCPv6".into()
                },
                address_text(&self.vm, local, family)?,
                local_port.to_string(),
                address_text(&self.vm, remote, family)?,
                remote_port.to_string(),
                label.into(),
                pid,
                owner,
                self.netstat_time(address, layout, 0)?,
            ]))
        })();
        match parsed {
            Ok(Some(row)) => vec![row],
            Ok(None) | Err(_) => Vec::new(),
        }
    }

    fn netstat_bound(&self, layout: &Layout, address: u64, kind: usize) -> Vec<Vec<String>> {
        let parsed = (|| -> Result<Vec<Vec<String>>> {
            let family = self.netstat_family(address, layout, kind)?;
            if !matches!(family, 2 | 23) {
                return Ok(Vec::new());
            }
            let port =
                u16::try_from(self.netstat_field(address, layout, kind, "Port", 2)?)?.swap_bytes();
            let local =
                self.netstat_field(address, layout, kind, "LocalAddr", layout.pointer_size)?;
            let local = if local == 0 || !self.vm.kernel(local) {
                0
            } else {
                self.local_address(local, kind == 2, layout).unwrap_or(0)
            };
            let families = if local == 0 && family == 23 {
                vec![2, 23]
            } else {
                vec![family]
            };
            let (pid, owner) = self.netstat_owner(address, layout, kind);
            let time = self.netstat_time(address, layout, kind)?;
            let mut rows = Vec::new();
            for family in families {
                rows.push(vec![
                    format!("{:#x}", address & 0x0000_ffff_ffff_ffff),
                    format!(
                        "{}v{}",
                        if kind == 2 { "UDP" } else { "TCP" },
                        if family == 2 { 4 } else { 6 }
                    ),
                    address_text(&self.vm, local, family)?,
                    port.to_string(),
                    if kind == 2 {
                        "*".into()
                    } else if family == 2 {
                        "0.0.0.0".into()
                    } else {
                        "::".into()
                    },
                    "0".into(),
                    if kind == 1 {
                        "LISTENING".into()
                    } else {
                        String::new()
                    },
                    pid.clone(),
                    owner.clone(),
                    time.clone(),
                ]);
            }
            Ok(rows)
        })();
        parsed.unwrap_or_default()
    }

    fn netstat_field(
        &self,
        address: u64,
        layout: &Layout,
        kind: usize,
        name: &str,
        width: usize,
    ) -> Result<u64> {
        let offset = *layout
            .fields(kind)
            .get(name)
            .context("netstat 布局缺少字段")? as u64;
        self.vm.uint(add(address, offset)?, width)
    }

    fn netstat_family(&self, address: u64, layout: &Layout, kind: usize) -> Result<u64> {
        let inet = self.netstat_field(address, layout, kind, "InetAF", layout.pointer_size)?;
        if !self.vm.kernel(inet) {
            bail!("InetAF 无效");
        }
        self.vm.uint(add(inet, layout.family)?, 2)
    }

    fn netstat_owner(&self, address: u64, layout: &Layout, kind: usize) -> (String, String) {
        let Ok(owner) = self.netstat_field(address, layout, kind, "Owner", layout.pointer_size)
        else {
            return ("-".into(), "-".into());
        };
        match self.process(owner) {
            Ok(process) => (process.pid.to_string(), process.name),
            Err(_) => ("-".into(), "-".into()),
        }
    }

    fn netstat_time(&self, address: u64, layout: &Layout, kind: usize) -> Result<String> {
        let time = self.netstat_field(address, layout, kind, "CreateTime", 8)?;
        Ok(
            if (110_000_000_000_000_000..190_000_000_000_000_000).contains(&time) {
                crate::windows::timeline::filetime_utc(time)
            } else {
                String::new()
            },
        )
    }
}

pub(super) fn read(b: &[u8], offset: usize, size: usize) -> Result<u64> {
    ensure!(size <= 8, "网络字段宽度无效");
    let end = offset.checked_add(size).context("网络字段偏移溢出")?;
    let mut value = [0; 8];
    value[..size].copy_from_slice(b.get(offset..end).context("网络字段越界")?);
    Ok(u64::from_le_bytes(value))
}
fn address_text(vm: &Memory<'_>, address: u64, family: u64) -> Result<String> {
    let mut bytes = [0; 16];
    if address != 0 {
        vm.read(address, &mut bytes[..if family == 2 { 4 } else { 16 }])?;
    }
    if family == 2 {
        Ok(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
    } else if address == 0 {
        Ok("::".into())
    } else {
        Ok(Ipv6Addr::from(bytes).to_string())
    }
}
fn endpoint(vm: &Memory<'_>, address: u64, family: u64, port: u16) -> Result<String> {
    let mut b = [0; 16];
    if address != 0 {
        vm.read(address, &mut b[..if family == 2 { 4 } else { 16 }])?;
    }
    if family == 2 {
        Ok(format!("{}:{port}", Ipv4Addr::new(b[0], b[1], b[2], b[3])))
    } else {
        Ok(format!("[{}]:{port}", Ipv6Addr::from(b)))
    }
}
pub(super) fn pe_identity(vm: &Memory<'_>, base: u64) -> Result<PdbIdentity> {
    pe_identity_for_machine(vm, base, Architecture::from_isf(vm.isf)?.machine())
}
/// User modules can be WOW64: validate against their PE machine, not kernel width.
pub(super) fn pe_identity_for_machine(
    vm: &Memory<'_>,
    base: u64,
    machine: u16,
) -> Result<PdbIdentity> {
    let mut header = [0; 4096];
    vm.read(base, &mut header)?;
    let (size, debug) = pe_header(&header)?;
    let pe = u32::from_le_bytes(header[60..64].try_into()?) as usize;
    let directories = if u16::from_le_bytes(header[pe + 24..pe + 26].try_into()?) == 0x10b {
        96
    } else {
        112
    };
    ensure!(
        u16::from_le_bytes(header[pe + 4..pe + 6].try_into()?) == machine,
        "PE/符号机器类型冲突"
    );
    let len = u32::from_le_bytes(
        header[pe + 24 + directories + 52..pe + 24 + directories + 56].try_into()?,
    ) as u64;
    let in_image = |rva: u64, length: u64| {
        rva != 0
            && length != 0
            && rva
                .checked_add(length)
                .is_some_and(|end| end <= u64::from(size))
    };
    ensure!(
        len <= 4096 && len.is_multiple_of(28) && in_image(u64::from(debug), len),
        "PE debug directory 无效或越界"
    );
    let mut identity = None;
    for offset in (0..len).step_by(28) {
        let mut record = [0; 28];
        vm.read(add(base, u64::from(debug) + offset)?, &mut record)?;
        if u32::from_le_bytes(record[12..16].try_into()?) == 2 {
            let length = u32::from_le_bytes(record[16..20].try_into()?) as u64;
            let rva = u32::from_le_bytes(record[20..24].try_into()?) as u64;
            ensure!(
                (25..=4096).contains(&length) && in_image(rva, length),
                "PE CodeView 长度无效或越界"
            );
            let mut cv = vec![0; usize::try_from(length)?];
            vm.read(add(base, rva)?, &mut cv)?;
            // Older NB10 records cannot establish an exact RSDS identity.
            if !cv.starts_with(b"RSDS") {
                continue;
            }
            let found = PdbIdentity::from_rsds(&cv)?;
            ensure!(
                identity.as_ref().is_none_or(|old| *old == found),
                "PE 存在冲突的 RSDS 身份"
            );
            identity = Some(found);
        }
    }
    identity.context("PE 缺少 RSDS CodeView")
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image};
    use super::*;
    fn set_u32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn identity(bytes: &[u8], isf: &Isf) -> Result<PdbIdentity> {
        let image = image(bytes);
        pe_identity(&Memory::new(&image, 0x1000, isf, None), K)
    }
    #[test]
    fn codeview_uses_declared_size_at_a_page_boundary() {
        let (mut bytes, isf) = fixture();
        let cv = bytes[0x8600..0x8625].to_vec();
        bytes[0x8fdb..0x9000].copy_from_slice(&cv);
        set_u32(&mut bytes, 0x8514, 0xfdb);
        // Remove the next page: a fixed 512-byte read used to fail here.
        bytes[0x4008..0x4010].fill(0);
        assert_eq!(
            identity(&bytes, &isf).unwrap(),
            PdbIdentity::from_isf(&isf).unwrap()
        );
        set_u32(&mut bytes, 0x8510, 36);
        assert!(
            identity(&bytes, &isf).is_err(),
            "NUL outside SizeOfData must not terminate the name"
        );
    }
    #[test]
    fn codeview_rejects_out_of_module_ranges_and_unterminated_names() {
        let (bytes, isf) = fixture();
        for (at, value) in [
            (0x8138, 0x8000),
            (0x813c, 29),
            (0x8514, 0x7ff0),
            (0x8510, 4097),
            (0x8510, 0),
        ] {
            let mut bad = bytes.clone();
            set_u32(&mut bad, at, value);
            assert!(identity(&bad, &isf).is_err(), "{at:#x}={value}");
        }
        let mut bad = bytes;
        bad[0x8624] = b'x';
        assert!(identity(&bad, &isf).is_err());
    }
    #[test]
    fn codeview_accepts_repeated_identity_but_rejects_conflicts() {
        let (mut bytes, isf) = fixture();
        set_u32(&mut bytes, 0x813c, 56);
        let record = bytes[0x8500..0x851c].to_vec();
        bytes[0x851c..0x8538].copy_from_slice(&record);
        assert!(identity(&bytes, &isf).is_ok());
        let cv = bytes[0x8600..0x8625].to_vec();
        bytes[0x8680..0x86a5].copy_from_slice(&cv);
        bytes[0x8694] = 2; // same GUID, different PDB age
        set_u32(&mut bytes, 0x8530, 0x680);
        assert!(format!("{:#}", identity(&bytes, &isf).unwrap_err()).contains("冲突"));
    }
    #[test]
    fn endpoints_use_network_bytes_and_exact_identity_layouts() {
        let (mut b, isf) = fixture();
        b[0xb000..0xb004].copy_from_slice(&[192, 0, 2, 1]);
        let image = image(&b);
        let vm = Memory::new(&image, 0x1000, &isf, None);
        assert_eq!(endpoint(&vm, K + 0x3000, 2, 443).unwrap(), "192.0.2.1:443");
        assert_eq!(endpoint(&vm, 0, 23, 80).unwrap(), "[::]:80");
        let layouts: serde_json::Value = serde_json::from_str(LAYOUTS).unwrap();
        assert!(layouts["identities"]["tcpip.pdb/UNKNOWN1"].is_null());
        assert_eq!(
            layouts["identities"]["tcpip.pdb/ABB23D00EE7E4165B6AFF66F2DF02EB22"],
            "netscan-win7-x64"
        );
        assert!(read(&[1], 0, 2).is_err());
    }
}
