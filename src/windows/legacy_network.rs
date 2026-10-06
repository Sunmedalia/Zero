//! NT5 TCP/IP layouts are separate from Vista+ endpoint objects.
use super::*;
use serde::Deserialize;
use std::net::Ipv4Addr;
#[derive(Deserialize)]
struct Manifest {
    source: String,
    layouts: BTreeMap<String, LegacyLayout>,
}
#[derive(Deserialize)]
struct LegacyLayout {
    pointer_size: usize,
    connection: BTreeMap<String, usize>,
    socket: BTreeMap<String, usize>,
}
fn fields_size(fields: &BTreeMap<String, usize>) -> Result<usize> {
    fields
        .iter()
        .map(|(name, offset)| {
            offset
                .checked_add(match name.as_str() {
                    "time" => 8,
                    "local_port" | "remote_port" | "protocol" => 2,
                    _ => 4,
                })
                .context("NT5 TCP/IP 字段溢出")
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .context("空 NT5 TCP/IP 布局")
}
fn parse_row(
    bytes: &[u8],
    fields: &BTreeMap<String, usize>,
    physical: u64,
    socket: bool,
) -> Result<Vec<String>> {
    let read = |name: &str, width: usize| -> Result<&[u8]> {
        let offset = *fields.get(name).context("NT5 TCP/IP 缺少字段")?;
        bytes
            .get(offset..offset + width)
            .context("NT5 TCP/IP 字段越界")
    };
    let pid = u32::from_le_bytes(read("pid", 4)?.try_into()?);
    ensure!(
        pid <= 0x400000 && pid.is_multiple_of(4),
        "NT5 网络 PID 无效"
    );
    let ip = |name| -> Result<String> {
        Ok(Ipv4Addr::from(<[u8; 4]>::try_from(read(name, 4)?)?).to_string())
    };
    let port = |name| -> Result<u16> { Ok(u16::from_be_bytes(read(name, 2)?.try_into()?)) };
    let mut row = vec![
        format!("physical:{physical:#x}"),
        pid.to_string(),
        ip("local_ip")?,
        port("local_port")?.to_string(),
    ];
    if socket {
        let protocol = u16::from_le_bytes(read("protocol", 2)?.try_into()?);
        ensure!((1..=255).contains(&protocol), "NT5 socket 协议无效");
        let time = u64::from_le_bytes(read("time", 8)?.try_into()?);
        ensure!(
            time > 0 && time <= 2650467743999999999,
            "NT5 socket 创建时间无效"
        );
        row.extend([protocol.to_string(), filetime(time)]);
    } else {
        ensure!(
            port("local_port")? != 0 || port("remote_port")? != 0,
            "空 NT5 TCP 端点不构成有效候选"
        );
        row.extend([ip("remote_ip")?, port("remote_port")?.to_string()]);
    }
    Ok(row)
}
impl Windows<'_> {
    pub(super) fn legacy_network(&self, p: Plugin, job: &Job) -> Result<Results> {
        let mut r = self.result(p);
        let read = self.legacy_rows(p, &mut r, job);
        if let Err(e) = read {
            job.check()?;
            Self::issue(&mut r, p.name(), format!("{e:#}"));
        }
        Ok(r)
    }
    fn legacy_rows(&self, p: Plugin, r: &mut Results, job: &Job) -> Result<()> {
        ensure!(
            self.build_number()? == 3790,
            "connscan/sockscan 仅提供 NT5 Server 2003 声明布局；现代系统使用 netscan"
        );
        let arch = Architecture::from_isf(self.vm.isf)?;
        ensure!(
            matches!(arch, Architecture::X86 | Architecture::X64),
            "NT5 TCP/IP 架构不支持"
        );
        let ty = self.module_type()?;
        let (nodes, diagnostics) = self.list_partial(
            self.symbol("PsLoadedModuleList")?,
            self.vm.isf.offset(ty, "InLoadOrderLinks")?,
            job,
        )?;
        if !diagnostics.is_empty() {
            r.complete = false;
            r.diagnostics.extend(diagnostics);
        }
        let mut driver = None;
        for node in nodes {
            job.check()?;
            let name = self.vm.unicode(self.field(node, ty, "BaseDllName")?)?;
            if name.eq_ignore_ascii_case("tcpip.sys") {
                driver = Some(self.number(node, ty, "DllBase")?);
                break;
            }
        }
        let base = driver.context("tcpip.sys 未加载或不可读")?;
        let identity = network::pe_identity(&self.vm, base).ok();
        let version = match network_layout::file_version(&self.vm, base) {
            Ok(v) => {
                ensure!(v[..3] == [5, 2, 3790], "未知 NT5 tcpip.sys 版本 {v:?}");
                Some(v)
            }
            Err(e) => {
                ensure!(
                    self.declared_kernel_version()?[..3] == [5, 2, 3790],
                    "未知 NT5 内核系列"
                );
                Self::issue(
                    r,
                    "NT5 tcpip identity",
                    format!("驱动 PE 不可读；使用显式 NT5 内核构建和 service pack 布局: {e:#}"),
                );
                None
            }
        };
        let socket = p == Plugin::WinSockscan;
        let key = if arch == Architecture::X64 {
            "x64"
        } else if !socket {
            "x86-sp0"
        } else {
            let sp = self.vm.uint(self.symbol("CmNtCSDVersion")?, 4)? >> 8;
            match sp {
                0 => "x86-sp0",
                1 | 2 => "x86-sp12",
                _ => bail!("未知 Server 2003 service pack"),
            }
        };
        let manifest: Manifest = serde_json::from_str(include_str!("legacy_network_layouts.json"))?;
        let layout = manifest.layouts.get(key).context("缺少 NT5 布局")?;
        ensure!(
            layout.pointer_size == arch.pointer_size(),
            "NT5 TCP/IP 布局架构冲突"
        );
        let fields = if socket {
            &layout.socket
        } else {
            &layout.connection
        };
        let size = fields_size(fields)?;
        ensure!(size <= 4096, "NT5 网络对象过大");
        r.kernel_identity["network_layout"] = serde_json::json!({"key":key,"source":manifest.source,"tcpip_pdb":identity,"file_version":version,"validation":"synthetic-layout; pool candidates"});
        Self::issue(
            r,
            "NT5 TCP/IP",
            "声明布局的扫描候选，尚未完成此精确 tcpip.sys 身份验收",
        );
        let tag: &[u8] = if socket { b"TCPA" } else { b"TCPT" };
        let mut seen = HashSet::new();
        for (start, length) in self.pool_blocks(&[tag], size as u64, job)? {
            job.check()?;
            ensure!(length >= size as u64, "NT5 网络分配过小");
            let mut bytes = vec![0; size];
            if self.vm.image.read(start, &mut bytes).is_err() {
                continue;
            }
            let mut pointer = [0; 8];
            pointer[..arch.pointer_size()].copy_from_slice(&bytes[..arch.pointer_size()]);
            let next = u64::from_le_bytes(pointer);
            if next != 0 && !arch.kernel(next) {
                continue;
            }
            if let Ok(row) = parse_row(&bytes, fields, start, socket)
                && seen.insert(start)
            {
                r.rows.push(row);
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nt5_field_boundaries_and_network_byte_order() {
        let m: Manifest =
            serde_json::from_str(include_str!("legacy_network_layouts.json")).unwrap();
        for l in m.layouts.values() {
            for socket in [false, true] {
                let f = if socket { &l.socket } else { &l.connection };
                let size = fields_size(f).unwrap();
                let mut b = vec![0; size];
                b[f["pid"]..f["pid"] + 4].copy_from_slice(&100u32.to_le_bytes());
                b[f["local_ip"]..f["local_ip"] + 4].copy_from_slice(&[127, 0, 0, 1]);
                b[f["local_port"]..f["local_port"] + 2].copy_from_slice(&3389u16.to_be_bytes());
                if socket {
                    b[f["protocol"]..f["protocol"] + 2].copy_from_slice(&6u16.to_le_bytes());
                    b[f["time"]..f["time"] + 8]
                        .copy_from_slice(&130000000000000000u64.to_le_bytes());
                }
                let row = parse_row(&b, f, 0x1000, socket).unwrap();
                assert_eq!(row[2], "127.0.0.1");
                assert_eq!(row[3], "3389");
                assert!(parse_row(&b[..size - 1], f, 0, socket).is_err());
            }
        }
    }
}
