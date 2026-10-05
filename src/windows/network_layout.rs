//! Declarative TCP/IP field facts; no nearest-version or cross-architecture fallback.
use super::*;
use serde::Deserialize;
use std::collections::BTreeMap;
#[derive(Clone, Deserialize)]
pub(super) struct Layout {
    pub pointer_size: usize,
    pub endpoint_tags: Vec<String>,
    pub endpoint: BTreeMap<String, usize>,
    pub listener: BTreeMap<String, usize>,
    pub udp: BTreeMap<String, usize>,
    pub family: u64,
    pub local_data: u64,
    pub udp_data: u64,
    pub info_local: u64,
    pub info_remote: u64,
    pub udp_direct: bool,
    pub source: String,
    pub validation: String,
}
impl Layout {
    pub fn fields(&self, kind: usize) -> &BTreeMap<String, usize> {
        match kind {
            0 => &self.endpoint,
            1 => &self.listener,
            _ => &self.udp,
        }
    }
    pub fn size(&self, kind: usize) -> Result<usize> {
        self.fields(kind)
            .iter()
            .map(|(name, offset)| {
                let width = match name.as_str() {
                    "CreateTime" => 8,
                    "State" => 4,
                    "LocalPort" | "RemotePort" | "Port" => 2,
                    _ => self.pointer_size,
                };
                offset.checked_add(width).context("TCP/IP 字段溢出")
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .context("空 TCP/IP 布局")
    }
    pub fn validate(&self, arch: Architecture) -> Result<()> {
        ensure!(
            self.pointer_size == arch.pointer_size(),
            "TCP/IP 布局架构不一致"
        );
        ensure!(
            !self.endpoint_tags.is_empty() && self.endpoint_tags.iter().all(|t| t.len() == 4),
            "TCP/IP pool tag 无效"
        );
        for kind in 0..3 {
            let fields = self.fields(kind);
            let required: &[&str] = if kind == 0 {
                &[
                    "Owner",
                    "CreateTime",
                    "InetAF",
                    "AddrInfo",
                    "LocalPort",
                    "RemotePort",
                    "State",
                ]
            } else {
                &["Owner", "CreateTime", "InetAF", "LocalAddr", "Port"]
            };
            ensure!(
                required.iter().all(|k| fields.contains_key(*k)),
                "TCP/IP 缺少字段"
            );
            ensure!(self.size(kind)? <= 4096, "TCP/IP 布局过大");
        }
        ensure!(
            [
                self.family,
                self.local_data,
                self.udp_data,
                self.info_local,
                self.info_remote
            ]
            .iter()
            .all(|o| *o < 4096),
            "TCP/IP 间接字段越界"
        );
        Ok(())
    }
    pub fn from_isf(isf: &Isf) -> Result<Self> {
        let arch = Architecture::from_isf(isf)?;
        let fields = |ty: &str, names: &[&str]| -> Result<BTreeMap<String, usize>> {
            names
                .iter()
                .map(|n| Ok((n.to_string(), usize::try_from(isf.offset(ty, n)?)?)))
                .collect()
        };
        let udp_direct = isf.data["user_types"]["_LOCAL_ADDRESS_WIN10_UDP"].is_object();
        let result = Self {
            pointer_size: arch.pointer_size(),
            endpoint_tags: vec!["TcpE".into(), "TTcb".into()],
            endpoint: fields(
                "_TCP_ENDPOINT",
                &[
                    "Owner",
                    "CreateTime",
                    "InetAF",
                    "AddrInfo",
                    "LocalPort",
                    "RemotePort",
                    "State",
                ],
            )?,
            listener: fields(
                "_TCP_LISTENER",
                &["Owner", "CreateTime", "InetAF", "LocalAddr", "Port"],
            )?,
            udp: fields(
                "_UDP_ENDPOINT",
                &["Owner", "CreateTime", "InetAF", "LocalAddr", "Port"],
            )?,
            family: isf.offset("_INETAF", "AddressFamily")?,
            local_data: isf.offset("_LOCAL_ADDRESS", "pData")?,
            udp_data: isf.offset(
                if udp_direct {
                    "_LOCAL_ADDRESS_WIN10_UDP"
                } else {
                    "_LOCAL_ADDRESS"
                },
                "pData",
            )?,
            info_local: isf.offset("_ADDRINFO", "Local")?,
            info_remote: isf.offset("_ADDRINFO", "Remote")?,
            udp_direct,
            source: PdbIdentity::from_isf(isf)?.key(),
            validation: "exact-driver-symbols".into(),
        };
        result.validate(arch)?;
        Ok(result)
    }
}
/// Parse the bounded VS_VERSION_INFO payload, including the required key and alignment.
fn fixed_version(bytes: &[u8]) -> Result<[u16; 4]> {
    ensure!(bytes.len() >= 6, "VERSIONINFO 截断");
    let len = u16::from_le_bytes(bytes[..2].try_into()?) as usize;
    let value_len = u16::from_le_bytes(bytes[2..4].try_into()?) as usize;
    ensure!(
        len <= bytes.len() && value_len >= 52,
        "VERSIONINFO 长度无效"
    );
    let key: Vec<u8> = "VS_VERSION_INFO\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    ensure!(
        bytes.get(6..6 + key.len()) == Some(key.as_slice()),
        "VERSIONINFO key 无效"
    );
    let start = (6 + key.len() + 3) & !3;
    let value = bytes
        .get(start..start + value_len)
        .filter(|_| start + value_len <= len)
        .context("固定版本截断")?;
    ensure!(
        value[..4] == 0xfeef04bdu32.to_le_bytes(),
        "固定版本签名无效"
    );
    Ok([
        u16::from_le_bytes(value[10..12].try_into()?),
        u16::from_le_bytes(value[8..10].try_into()?),
        u16::from_le_bytes(value[14..16].try_into()?),
        u16::from_le_bytes(value[12..14].try_into()?),
    ])
}
pub(super) fn file_version(vm: &Memory<'_>, base: u64) -> Result<[u16; 4]> {
    let mut header = [0; 4096];
    vm.read(base, &mut header)?;
    let (size, _) = pe_header(&header)?;
    let pe = u32::from_le_bytes(header[60..64].try_into()?) as usize;
    let directories = if header[pe + 24..pe + 26] == 0x10bu16.to_le_bytes() {
        96
    } else {
        112
    };
    let at = pe + 24 + directories + 16;
    let rva = u32::from_le_bytes(header[at..at + 4].try_into()?) as u64;
    let len = u32::from_le_bytes(header[at + 4..at + 8].try_into()?) as u64;
    ensure!(
        rva != 0 && (16..=1024 * 1024).contains(&len) && rva + len <= size as u64,
        "PE resource 越界"
    );
    let mut resources = vec![0; len as usize];
    vm.read(add(base, rva)?, &mut resources)?;
    let mut offset = 0usize;
    for depth in 0..3 {
        let dir = resources
            .get(offset..offset + 16)
            .context("resource directory 截断")?;
        let count = u16::from_le_bytes(dir[12..14].try_into()?) as usize
            + u16::from_le_bytes(dir[14..16].try_into()?) as usize;
        ensure!((1..=4096).contains(&count), "resource entry 数量无效");
        let entries = resources
            .get(offset + 16..offset + 16 + count * 8)
            .context("resource entries 截断")?;
        let entry = entries
            .chunks_exact(8)
            .find(|e| depth != 0 || e[..4] == 16u32.to_le_bytes())
            .context("PE 缺少 RT_VERSION")?;
        let child = u32::from_le_bytes(entry[4..8].try_into()?);
        if depth < 2 {
            ensure!(child & 0x80000000 != 0, "resource directory 层级无效");
            offset = (child & 0x7fffffff) as usize;
        } else {
            ensure!(child & 0x80000000 == 0, "resource data 层级无效");
            let data = resources
                .get(child as usize..child as usize + 16)
                .context("resource data entry 截断")?;
            let start = u32::from_le_bytes(data[..4].try_into()?) as u64;
            let length = u32::from_le_bytes(data[4..8].try_into()?) as u64;
            ensure!(
                (52..=1024 * 1024).contains(&length) && start + length <= size as u64,
                "版本资源越界"
            );
            let mut value = vec![0; length as usize];
            vm.read(add(base, start)?, &mut value)?;
            return fixed_version(&value);
        }
    }
    bail!("PE 缺少版本")
}
pub(super) fn manifest(
    identity: &PdbIdentity,
    arch: Architecture,
    version: Option<[u16; 4]>,
) -> Result<Layout> {
    let data: serde_json::Value = serde_json::from_str(super::network::LAYOUTS)?;
    let profile = data["identities"][identity.key()]
        .as_str()
        .or_else(|| {
            let v = version?;
            let a = match arch {
                Architecture::X86 => "x86",
                Architecture::X64 => "x64",
                Architecture::Arm64 => "arm64",
                _ => return None,
            };
            data["versions"][format!("{a}:{}.{}.{}", v[0], v[1], v[2])].as_str()
        })
        .context("没有匹配架构和 TCP/IP 驱动版本的布局")?;
    let suffix = match arch {
        Architecture::X86 => "-x86",
        Architecture::X64 => "-x64",
        Architecture::Arm64 => "-arm64",
        _ => bail!("TCP/IP 架构未确定"),
    };
    ensure!(profile.ends_with(suffix), "TCP/IP manifest 架构不一致");
    let mut layout: Layout = serde_json::from_value(data["profiles"][profile].clone())?;
    // A version family is synthetic coverage until this exact driver identity is validated.
    if data["identities"][identity.key()].is_null() {
        layout.validation = "synthetic-version-family".into();
    }
    layout.validate(arch)?;
    Ok(layout)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_layouts_are_bounded_and_architecture_specific() {
        let data: serde_json::Value = serde_json::from_str(super::super::network::LAYOUTS).unwrap();
        for (_, value) in data["profiles"].as_object().unwrap() {
            let l: Layout = serde_json::from_value(value.clone()).unwrap();
            let arch = if l.pointer_size == 4 {
                Architecture::X86
            } else {
                Architecture::X64
            };
            l.validate(arch).unwrap();
            assert!(l.validate(Architecture::Arm64).is_ok() == (l.pointer_size == 8));
            for kind in 0..3 {
                let b = vec![0u8; l.size(kind).unwrap()];
                for (name, offset) in l.fields(kind) {
                    let width = match name.as_str() {
                        "CreateTime" => 8,
                        "State" => 4,
                        "Port" | "LocalPort" | "RemotePort" => 2,
                        _ => l.pointer_size,
                    };
                    super::super::network::read(&b, *offset, width).unwrap();
                }
            }
        }
        let id = PdbIdentity {
            name: "tcpip.pdb".into(),
            guid: "0".repeat(32),
            age: 1,
        };
        assert!(manifest(&id, Architecture::Arm64, Some([10, 0, 19041, 1])).is_err());
        assert!(manifest(&id, Architecture::X64, Some([10, 0, 65535, 1])).is_err());
        assert!(manifest(&id, Architecture::X86, Some([6, 1, 7601, 1])).is_ok());
    }
    #[test]
    fn version_payload_requires_key_signature_and_lengths() {
        let mut b = vec![0; 92];
        b[..2].copy_from_slice(&92u16.to_le_bytes());
        b[2..4].copy_from_slice(&52u16.to_le_bytes());
        let key: Vec<u8> = "VS_VERSION_INFO\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        b[6..6 + key.len()].copy_from_slice(&key);
        b[40..44].copy_from_slice(&0xfeef04bdu32.to_le_bytes());
        b[48..52].copy_from_slice(&0x000a0000u32.to_le_bytes());
        b[52..56].copy_from_slice(&0x4a610001u32.to_le_bytes());
        assert_eq!(fixed_version(&b).unwrap(), [10, 0, 19041, 1]);
        assert!(fixed_version(&b[..90]).is_err());
        b[6] = 0;
        assert!(fixed_version(&b).is_err());
    }
}
