//! TCP/IP object layouts are allowlisted by exact driver PDB identity, not OS version.
use super::*;
use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};
pub(super) const LAYOUTS: &str = include_str!("network_layouts.json");
#[derive(Deserialize)]
struct Layout {
    endpoint_tag: String,
    endpoint_owner: usize,
    endpoint_time: usize,
    udp_local: usize,
    udp_port: usize,
}
impl Windows<'_> {
    pub(super) fn netscan(&self, job: &Job) -> Result<Results> {
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
        let identity = pe_identity(&self.vm, driver.context("tcpip.sys 未加载")?)?;
        let data: serde_json::Value = serde_json::from_str(LAYOUTS)?;
        let layout: Layout = serde_json::from_value(data["identities"][identity.key()].clone())
            .with_context(|| format!("没有经验证的 TCP/IP 结构布局: {}", identity.key()))?;
        let mut r = self.result(Plugin::WinNetscan);
        r.complete = diagnostics.is_empty();
        r.diagnostics = diagnostics;
        r.kernel_identity["tcpip_pdb"] = serde_json::to_value(&identity)?;
        let isf = self.vm.isf;
        let header_size = isf.data["user_types"]["_POOL_HEADER"]["size"]
            .as_u64()
            .context("缺少 pool header")?;
        let tag_offset = isf.offset("_POOL_HEADER", "PoolTag")?;
        ensure!(layout.endpoint_tag.len() == 4, "无效 endpoint pool tag");
        for (tag, kind) in [
            (layout.endpoint_tag.as_bytes(), 0),
            (b"TcpL".as_slice(), 1),
            (b"UdpA".as_slice(), 2),
        ] {
            for hit in self.vm.image.scan(tag, job)? {
                job.check()?;
                let Some(header) = hit.checked_sub(tag_offset) else {
                    continue;
                };
                if header & 15 != 0 {
                    continue;
                }
                let mut bytes = vec![0; header_size as usize];
                if self.vm.image.read(header, &mut bytes).is_err() {
                    continue;
                }
                let block =
                    objects::physical_number(isf, &bytes, "_POOL_HEADER", "BlockSize")? * 16;
                let size = match kind {
                    0 => layout.endpoint_time.max(layout.endpoint_owner) + 8,
                    1 => 128,
                    _ => layout.udp_local + 8,
                };
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
                    let af = read(
                        &b,
                        if kind == 0 {
                            16
                        } else if kind == 1 {
                            40
                        } else {
                            32
                        },
                        8,
                    )?;
                    ensure!(self.vm.kernel(af), "无效 InetAF");
                    let family = self.vm.uint(add(af, 24)?, 2)?;
                    ensure!(matches!(family, 2 | 23), "无效地址族");
                    let owner = read(
                        &b,
                        if kind == 0 {
                            layout.endpoint_owner
                        } else if kind == 1 {
                            48
                        } else {
                            40
                        },
                        8,
                    )?;
                    let process = self.process(owner)?;
                    let time = read(
                        &b,
                        if kind == 0 {
                            layout.endpoint_time
                        } else if kind == 1 {
                            64
                        } else {
                            88
                        },
                        8,
                    )?;
                    let time = if time == 0
                        || (110_000_000_000_000_000..190_000_000_000_000_000).contains(&time)
                    {
                        filetime(time)
                    } else {
                        String::new()
                    };
                    let port = read(
                        &b,
                        if kind == 0 {
                            112
                        } else if kind == 1 {
                            114
                        } else {
                            layout.udp_port
                        },
                        2,
                    )? as u16;
                    let port = port.swap_bytes();
                    let (local, remote, state, remote_port) = if kind == 0 {
                        let state = read(&b, 108, 4)?;
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
                        let info = read(&b, 24, 8)?;
                        let local = self.vm.uint(info, 8)?;
                        let local = self.local_address(local, false)?;
                        let remote = self.vm.uint(add(info, 16)?, 8)?;
                        let remote_port = (read(&b, 114, 2)? as u16).swap_bytes();
                        (local, remote, label, remote_port)
                    } else {
                        recognized = true;
                        let local = read(&b, if kind == 1 { 96 } else { layout.udp_local }, 8)?;
                        (
                            if local == 0 {
                                0
                            } else {
                                self.local_address(local, kind == 2)?
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
    fn local_address(&self, address: u64, udp: bool) -> Result<u64> {
        let pointer = self.vm.uint(add(address, if udp { 0 } else { 16 })?, 8)?;
        if pointer == 0 {
            return Ok(0);
        }
        if udp {
            Ok(pointer)
        } else {
            self.vm.uint(pointer, 8)
        }
    }
}
fn read(b: &[u8], offset: usize, size: usize) -> Result<u64> {
    let mut value = [0; 8];
    value[..size].copy_from_slice(b.get(offset..offset + size).context("网络字段越界")?);
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
        };
        assert_eq!(endpoint(&vm, K + 0x3000, 2, 443).unwrap(), "192.0.2.1:443");
        assert_eq!(endpoint(&vm, 0, 23, 80).unwrap(), "[::]:80");
        let layouts: serde_json::Value = serde_json::from_str(LAYOUTS).unwrap();
        assert!(layouts["identities"]["tcpip.pdb/UNKNOWN1"].is_null());
        assert_eq!(layouts["identities"].as_object().unwrap().len(), 2);
        assert!(read(&[1], 0, 2).is_err());
    }
}
