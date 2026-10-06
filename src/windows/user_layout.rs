//! Auditable field facts selected by explicit architecture and file versions.
use super::*;
use serde::Deserialize;
use std::sync::OnceLock;
#[derive(Clone, Deserialize)]
pub(super) struct ServiceLayout {
    pub pointer_size: usize,
    pub source: String,
    pub fields: BTreeMap<String, u64>,
    pub previous: Option<u64>,
    pub binary: u64,
    pub pid: u64,
    pub header_record: u64,
}
#[derive(Clone, Deserialize)]
pub(super) struct ConsoleLayout {
    pub source: String,
    #[serde(rename = "CommandHistorySize")]
    pub maximum: u64,
    #[serde(rename = "HistoryBufferMax")]
    pub buffers: u64,
    #[serde(rename = "Title")]
    pub title: u64,
    #[serde(rename = "HistoryList")]
    pub history: i64,
    #[serde(rename = "HistoryBufferCount")]
    pub count: i64,
}
#[derive(Deserialize)]
struct Manifest {
    services: BTreeMap<String, ServiceLayout>,
    service_versions: BTreeMap<String, String>,
    consoles: BTreeMap<String, ConsoleLayout>,
}
fn manifest() -> &'static Manifest {
    static M: OnceLock<Manifest> = OnceLock::new();
    M.get_or_init(|| {
        serde_json::from_str(include_str!("user_layouts.json")).expect("checked user layouts")
    })
}
pub(super) fn service(arch: Architecture, version: [u16; 4]) -> Result<ServiceLayout> {
    let a = match arch {
        Architecture::X86 => "x86",
        Architecture::X64 => "x64",
        _ => bail!("服务声明布局仅提供 x86/x64"),
    };
    let key = format!("{a}:{}.{}.{}", version[0], version[1], version[2]);
    let name = manifest()
        .service_versions
        .get(&key)
        .context("未声明该 services.exe 版本布局")?;
    let layout = manifest()
        .services
        .get(name)
        .context("服务声明布局缺失")?
        .clone();
    ensure!(
        layout.pointer_size == arch.pointer_size(),
        "服务布局架构冲突"
    );
    for field in [
        "ServiceName",
        "DisplayName",
        "Start",
        "Type",
        "State",
        "ServiceProcess",
        "DriverName",
    ] {
        ensure!(
            layout.fields.get(field).is_some_and(|n| *n < 4096),
            "服务字段缺失或越界"
        );
    }
    ensure!(
        layout.previous.is_none_or(|n| n < 4096)
            && layout.binary < 4096
            && layout.pid < 4096
            && layout.header_record < 4096,
        "服务间接字段越界"
    );
    Ok(layout)
}
pub(super) fn console(arch: Architecture, version: [u16; 4]) -> Result<ConsoleLayout> {
    ensure!(
        arch == Architecture::X64 && version[..2] == [10, 0],
        "控制台声明布局仅提供 NT10 x64"
    );
    let (build, revision) = (version[2], version[3]);
    let name = match (build, revision) {
        (18362, _) => "consoles-win10-18362-x64",
        (19041, _) => "consoles-win10-19041-x64",
        (22000, _) => "consoles-win10-22000-x64",
        (17763, 1) => "consoles-win10-17763-x64",
        (17763, 3232) => "consoles-win10-17763-3232-x64",
        (20348, 1) => "consoles-win10-20348-x64",
        (20348, 1970) => "consoles-win10-20348-1970-x64",
        (20348, 2461 | 2520) => "consoles-win10-20348-2461-x64",
        (22621, 1) => "consoles-win10-22621-x64",
        (22621, 3527) => "consoles-win10-22621-3527-x64",
        // No nearest revision fallback when an update changed the layout.
        _ => bail!("未声明该精确 conhost.exe 构建/修订布局 {version:?}"),
    };
    let l = manifest()
        .consoles
        .get(name)
        .context("缺少控制台声明布局")?
        .clone();
    ensure!(
        l.maximum < 65536
            && l.buffers == l.maximum + 4
            && l.title < 65536
            && l.history.abs() < 65536
            && l.count == l.history + 8,
        "控制台布局越界"
    );
    Ok(l)
}
pub(super) fn signed_add(base: u64, offset: i64) -> Result<u64> {
    base.checked_add_signed(offset)
        .context("控制台字段地址溢出/下溢")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn declared_versions_do_not_choose_nearest_or_cross_arch_layout() {
        for (key, name) in &manifest().service_versions {
            let (a, v) = key.split_once(':').unwrap();
            let n: Vec<u16> = v.split('.').map(|s| s.parse().unwrap()).collect();
            let arch = if a == "x86" {
                Architecture::X86
            } else {
                Architecture::X64
            };
            let l = service(arch, [n[0], n[1], n[2], 0]).unwrap();
            assert_eq!(l.source, manifest().services[name].source);
        }
        assert!(service(Architecture::X64, [10, 0, 26101, 0]).is_err());
        assert!(service(Architecture::Arm64, [10, 0, 26100, 0]).is_err());
        assert_ne!(
            console(Architecture::X64, [10, 0, 20348, 1])
                .unwrap()
                .history,
            console(Architecture::X64, [10, 0, 20348, 1970])
                .unwrap()
                .history
        );
        assert!(console(Architecture::X64, [10, 0, 20348, 1971]).is_err());
        assert!(console(Architecture::X64, [10, 0, 26100, 1]).is_err());
        assert_eq!(signed_add(1000, -352).unwrap(), 648);
        assert!(signed_add(10, -352).is_err());
    }
}
