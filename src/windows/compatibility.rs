//! Product identity is evidence, never a substitute for exact structure symbols.
use super::*;
const TARGETS: &str = include_str!("compatibility.json");
fn targets() -> &'static serde_json::Value {
    static M: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    M.get_or_init(|| serde_json::from_str(TARGETS).expect("checked compatibility manifest"))
}
impl Windows<'_> {
    pub(super) fn build_number(&self) -> Result<u32> {
        Ok((self.vm.uint(self.symbol("NtBuildNumber")?, 4)? & 0xffff) as u32)
    }
    pub(super) fn version_identity(&self) -> serde_json::Value {
        let shared = match Architecture::from_isf(self.vm.isf) {
            Ok(Architecture::X86) => 0xffdf0000,
            Ok(Architecture::X64) => 0xfffff78000000000,
            _ => 0,
        };
        let read = |field| self.number(shared, "_KUSER_SHARED_DATA", field).ok();
        let product_type = if read("ProductTypeIsValid") == Some(1) {
            read("NtProductType").filter(|v| (1..=3).contains(v))
        } else {
            None
        };
        let version = network_layout::file_version(&self.vm, self.base).ok();
        let build = self
            .build_number()
            .ok()
            .or(version.map(|v| u32::from(v[2])));
        let major = version
            .map(|v| u64::from(v[0]))
            .or_else(|| read("NtMajorVersion"));
        let minor = version
            .map(|v| u64::from(v[1]))
            .or_else(|| read("NtMinorVersion"));
        let manifest = targets();
        let target = manifest["targets"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| {
                let server = product_type.is_some_and(|p| p != 1);
                product_type.is_some()
                    && t["server"].as_bool() == Some(server)
                    && t["builds"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|b| b.as_u64() == build.map(u64::from))
                    && major.is_none_or(|m| t["major"].as_u64() == Some(m))
                    && minor.is_none_or(|m| t["minor"].as_u64() == Some(m))
            })
            .map(|t| t["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        serde_json::json!({"major":major,"minor":minor,"build":build,"pe_version":version,
            "product_type":product_type,"product":if target.is_empty(){None}else{Some(target.join(" / "))},
            "evidence":{"build":if self.build_number().is_ok(){"NtBuildNumber"}else{"kernel PE version or unavailable"},
                "product_type":if product_type.is_some(){"validated KUSER_SHARED_DATA"}else{"unavailable"}},
            "validation":"exact PDB required; product identity does not certify plugin coverage"})
    }
    pub(super) fn declared_kernel_version(&self) -> Result<[u16; 4]> {
        let build = self.build_number()?;
        let target = targets()["targets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| {
                t["builds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|n| n.as_u64() == Some(u64::from(build)))
            })
            .context("未声明该内核构建版本")?;
        Ok([
            target["major"].as_u64().unwrap() as u16,
            target["minor"].as_u64().unwrap() as u16,
            build as u16,
            0,
        ])
    }
    pub(super) fn declared_build(&self) -> bool {
        let Ok(build) = self.build_number() else {
            return false;
        };
        let manifest = targets();
        manifest["targets"].as_array().unwrap().iter().any(|t| {
            t["builds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|b| b.as_u64() == Some(u64::from(build)))
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matrix_has_every_target_and_explicit_evidence() {
        let m: serde_json::Value = serde_json::from_str(TARGETS).unwrap();
        assert_eq!(m["targets"].as_array().unwrap().len(), 15);
        let plugins: Vec<_> = crate::linux::PLUGINS
            .iter()
            .filter(|p| p.plugin.is_windows())
            .map(|p| p.name)
            .collect();
        for target in m["targets"].as_array().unwrap() {
            assert!(!target["builds"].as_array().unwrap().is_empty());
            for arch in target["architectures"].as_array().unwrap() {
                for plugin in &plugins {
                    let cell = &target["plugins"][arch.as_str().unwrap()][*plugin];
                    assert!(
                        matches!(
                            cell.as_str(),
                            Some("real")
                                | Some("synthetic")
                                | Some("pending")
                                | Some("unsupported")
                        ),
                        "{plugin}: {cell}"
                    );
                    if cell == "real" {
                        assert!(
                            target["evidence"].as_array().unwrap().iter().any(|e| {
                                e["architecture"] == *arch
                                    && e["rows"][*plugin].as_u64().is_some_and(|n| n > 0)
                                    && e["sha256"].as_str().is_some_and(|s| s.len() == 64)
                                    && (e["pdb"]["guid"].as_str().is_some_and(|s| s.len() == 32)
                                        || (e["container"] == "kernel-triage"
                                            && matches!(
                                                *plugin,
                                                "windows.crashinfo" | "windows.modules"
                                            )
                                            && e["identity_validation"].as_str().is_some()))
                                    && target["builds"].as_array().unwrap().contains(&e["build"])
                            }),
                            "real cell lacks matching exact evidence: {plugin}"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod identity_tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    #[test]
    fn shared_product_type_distinguishes_server_and_keeps_2003_r2_ambiguous() {
        for (build, major, minor, product, expected) in [
            (26100, 10, 0, 3, "Windows Server 2025"),
            (26100, 10, 0, 1, "Windows 11"),
            (
                3790,
                5,
                2,
                3,
                "Windows Server 2003 / Windows Server 2003 R2",
            ),
        ] {
            let (mut b, mut isf) = fixture();
            let shared = 0xfffff78000000000u64;
            let index = ((shared >> 39) & 511) as usize;
            put(&mut b, 0x1000 + index * 8, 0x2003);
            // Shared address uses zero lower-level indices.
            put(&mut b, 0x8200, build);
            put(&mut b, 0x8000, 1);
            put(&mut b, 0x8008, product);
            put(&mut b, 0x8010, major);
            put(&mut b, 0x8018, minor);
            let f = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u64"}});
            isf.data["user_types"]["_KUSER_SHARED_DATA"] = json!({"size":32,"fields":{"ProductTypeIsValid":f(0),"NtProductType":f(8),"NtMajorVersion":f(16),"NtMinorVersion":f(24)}});
            let img = image(&b);
            let w = Windows {
                vm: Memory {
                    image: &img,
                    root: 0x1000,
                    isf: &isf,
                    sources: None,
                },
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            assert_eq!(w.version_identity()["product"], expected);
            b[0x8000..0x8008].fill(0);
            let img = image(&b);
            let w = Windows {
                vm: Memory {
                    image: &img,
                    root: 0x1000,
                    isf: &isf,
                    sources: None,
                },
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            assert!(w.version_identity()["product"].is_null());
        }
    }
}
