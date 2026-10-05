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
        let (modules, diagnostics) = self.list_partial(
            self.symbol("PsLoadedModuleList")?,
            self.vm
                .isf
                .offset("_KLDR_DATA_TABLE_ENTRY", "InLoadOrderLinks")?,
            job,
        )?;
        for module in modules {
            let name =
                self.vm
                    .unicode(self.field(module, "_KLDR_DATA_TABLE_ENTRY", "BaseDllName")?)?;
            if name.eq_ignore_ascii_case("tcpip.sys") {
                driver = Some(self.number(module, "_KLDR_DATA_TABLE_ENTRY", "DllBase")?);
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
            network_layout::manifest(&identity, arch, version).with_context(|| {
                format!("无法解码 TCP/IP {} version {version:?}", identity.key())
            })?
        };
        let mut r = self.result(Plugin::WinNetscan);
        r.complete = diagnostics.is_empty();
        r.diagnostics = diagnostics;
        r.kernel_identity["tcpip_pdb"] = serde_json::to_value(&identity)?;
        r.kernel_identity["tcpip_file_version"] = serde_json::json!(version);
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
        for (tag, kind) in tags {
            for hit in self.vm.image.scan(tag, job)? {
                job.check()?;
                let Some(header) = hit.checked_sub(tag_offset) else {
                    continue;
                };
                if header % alignment != 0 {
                    continue;
                }
                let mut bytes = vec![0; header_size as usize];
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
                    let port = field(if kind == 0 { "LocalPort" } else { "Port" }, 2)? as u16;
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
                        let remote_port = (field("RemotePort", 2)? as u16).swap_bytes();
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
}
pub(super) fn read(b: &[u8], offset: usize, size: usize) -> Result<u64> {
    ensure!(size <= 8, "网络字段宽度无效");
    let end = offset.checked_add(size).context("网络字段偏移溢出")?;
    let mut value = [0; 8];
    value[..size].copy_from_slice(b.get(offset..end).context("网络字段越界")?);
    Ok(u64::from_le_bytes(value))
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
    let mut header = [0; 4096];
    vm.read(base, &mut header)?;
    let (_, debug) = pe_header(&header)?;
    let pe = u32::from_le_bytes(header[60..64].try_into()?) as usize;
    let directories = if u16::from_le_bytes(header[pe + 24..pe + 26].try_into()?) == 0x10b {
        96
    } else {
        112
    };
    ensure!(
        u16::from_le_bytes(header[pe + 4..pe + 6].try_into()?)
            == Architecture::from_isf(vm.isf)?.machine(),
        "PE/符号机器类型冲突"
    );
    let len = u32::from_le_bytes(
        header[pe + 24 + directories + 52..pe + 24 + directories + 56].try_into()?,
    ) as u64;
    ensure!(
        len <= 4096 && len.is_multiple_of(28),
        "PE debug directory 无效"
    );
    for offset in (0..len).step_by(28) {
        let mut record = [0; 28];
        vm.read(add(base, u64::from(debug) + offset)?, &mut record)?;
        if u32::from_le_bytes(record[12..16].try_into()?) == 2 {
            let mut cv = [0; 512];
            let rva = u32::from_le_bytes(record[20..24].try_into()?) as u64;
            vm.read(add(base, rva)?, &mut cv)?;
            return PdbIdentity::from_rsds(&cv);
        }
    }
    bail!("PE 缺少 CodeView")
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image};
    use super::*;
    #[test]
    fn endpoints_use_network_bytes_and_exact_identity_layouts() {
        let (mut b, isf) = fixture();
        b[0xb000..0xb004].copy_from_slice(&[192, 0, 2, 1]);
        let image = image(&b);
        let vm = Memory {
            image: &image,
            root: 0x1000,
            isf: &isf,
            sources: None,
        };
        assert_eq!(endpoint(&vm, K + 0x3000, 2, 443).unwrap(), "192.0.2.1:443");
        assert_eq!(endpoint(&vm, 0, 23, 80).unwrap(), "[::]:80");
        let layouts: serde_json::Value = serde_json::from_str(LAYOUTS).unwrap();
        assert!(layouts["identities"]["tcpip.pdb/UNKNOWN1"].is_null());
        assert_eq!(layouts["identities"].as_object().unwrap().len(), 3);
        assert!(read(&[1], 0, 2).is_err());
    }
}
