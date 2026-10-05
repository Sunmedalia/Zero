//! Windows machine types and paging geometry. Linux translation stays independent.
use super::*;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    #[default]
    Auto,
    X86,
    X64,
    Arm64,
}
impl Architecture {
    pub fn from_isf(isf: &Isf) -> Result<Self> {
        let width = isf.data["base_types"]["pointer"]["size"]
            .as_u64()
            .context("缺少指针宽度")?;
        let pdb = isf.data["metadata"]["windows"]["pdb"]["machine_type"].as_u64();
        let pe = isf.data["metadata"]["windows"]["pe"]["machine_type"].as_u64();
        ensure!(
            pdb.is_none() || pe.is_none() || pdb == pe,
            "PDB/PE 架构冲突"
        );
        let arch = match pe.or(pdb) {
            Some(0x14c) => Self::X86,
            Some(0x8664) => Self::X64,
            Some(0xaa64) => Self::Arm64,
            None if width == 4 => Self::X86,
            None if width == 8 => Self::X64,
            _ => bail!("未知 Windows 机器类型"),
        };
        ensure!(
            width == arch.pointer_size() as u64,
            "Windows 架构/指针宽度冲突"
        );
        Ok(arch)
    }
    pub fn pointer_size(self) -> usize {
        if self == Self::X86 { 4 } else { 8 }
    }
    pub fn machine(self) -> u16 {
        match self {
            Self::X86 => 0x14c,
            Self::Arm64 => 0xaa64,
            _ => 0x8664,
        }
    }
    pub(super) fn kernel(self, va: u64) -> bool {
        match self {
            Self::X86 => (0x80000000..u32::MAX as u64).contains(&va),
            Self::Arm64 => va >= 0xffff000000000000 && va != u64::MAX,
            _ => kernel(va),
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Paging {
    pub arch: Architecture,
    pub pae: bool,
}
impl Paging {
    pub fn new(isf: &Isf) -> Result<Self> {
        let arch = Architecture::from_isf(isf)?;
        let pae = arch == Architecture::X86
            && (isf.data["metadata"]["windows"]["paging"] == "pae"
                || isf.data["user_types"]["_MMPTE_HARDWARE"]["size"] == 8);
        Ok(Self { arch, pae })
    }
    pub fn shifts(self) -> &'static [u32] {
        match (self.arch, self.pae) {
            (Architecture::X86, false) => &[22, 12],
            (Architecture::X86, true) => &[30, 21, 12],
            _ => &[39, 30, 21, 12],
        }
    }
    pub fn width(self) -> usize {
        if self.arch == Architecture::X86 && !self.pae {
            4
        } else {
            8
        }
    }
    pub fn mask(self) -> u64 {
        if self.width() == 4 {
            0xfffff000
        } else {
            PHYSICAL_MASK
        }
    }
    pub fn root_mask(self) -> u64 {
        if self.pae {
            PHYSICAL_MASK | 0xfe0
        } else {
            self.mask()
        }
    }
    pub fn entries(self, level: usize) -> usize {
        if self.pae && level == 0 {
            4
        } else {
            4096 / self.width()
        }
    }
    pub fn block(self, entry: u64, shift: u32) -> bool {
        shift != 12
            && if self.arch == Architecture::Arm64 {
                entry & 3 == 1
            } else {
                entry & 128 != 0
            }
    }
    pub fn canonical(self, va: u64) -> bool {
        match self.arch {
            Architecture::X86 => va <= u32::MAX as u64,
            Architecture::Arm64 => va >> 48 == 0 || va >> 48 == 0xffff,
            _ => va >> 47 == 0 || va >> 47 == 0x1ffff,
        }
    }
    pub fn extend(self, va: u64) -> u64 {
        if self.arch == Architecture::X86 {
            va
        } else {
            va | 0xffff000000000000
        }
    }
    pub fn entry(self, image: &Image, table: u64, index: usize) -> Result<u64> {
        let mut b = [0; 8];
        image.read(
            table + index as u64 * self.width() as u64,
            &mut b[..self.width()],
        )?;
        Ok(u64::from_le_bytes(b))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    fn set_arch(isf: &mut Isf, arch: Architecture) {
        isf.data["metadata"]["windows"]["pdb"]["machine_type"] = serde_json::json!(arch.machine());
        isf.data["metadata"]["windows"]["pe"]["machine_type"] = serde_json::json!(arch.machine());
        isf.data["base_types"]["pointer"]["size"] = serde_json::json!(arch.pointer_size());
    }
    #[test]
    fn arm64_pages_blocks_and_machine_conflicts() {
        let (mut b, mut isf) = fixture();
        set_arch(&mut isf, Architecture::Arm64);
        b[0x8084..0x8086].copy_from_slice(&0xaa64u16.to_le_bytes());
        let img = image(&b);
        let vm = Memory {
            image: &img,
            root: 0x1000,
            isf: &isf,
        };
        assert_eq!(vm.translate(K + 0x1234).unwrap(), 0x9234);
        assert_eq!(discover(&img, &isf, &Job::default()).unwrap(), (0x1000, K));
        put(&mut b, 0x3000, 0x200001);
        let img = image(&b);
        assert_eq!(
            Memory {
                image: &img,
                root: 0x1000,
                isf: &isf
            }
            .translate(K + 0x1234)
            .unwrap(),
            0x201234
        );
        isf.data["metadata"]["windows"]["pe"]["machine_type"] = serde_json::json!(0x8664);
        assert!(Architecture::from_isf(&isf).is_err());
    }
    #[test]
    fn x86_pages_pae_and_large_pages() {
        let (mut b, mut isf) = fixture();
        set_arch(&mut isf, Architecture::X86);
        b[0x1000..0x5000].fill(0);
        b[0x1800..0x1804].copy_from_slice(&0x2003u32.to_le_bytes());
        b[0x2000..0x2004].copy_from_slice(&0x8003u32.to_le_bytes());
        let img = image(&b);
        let vm = Memory {
            image: &img,
            root: 0x1000,
            isf: &isf,
        };
        assert_eq!(vm.translate(0x80000123).unwrap(), 0x8123);
        assert!(vm.translate(0x1_80000123).is_err());
        b[0x1800..0x1804].copy_from_slice(&0x400083u32.to_le_bytes());
        let img = image(&b);
        assert_eq!(
            Memory {
                image: &img,
                root: 0x1000,
                isf: &isf
            }
            .translate(0x80001234)
            .unwrap(),
            0x401234
        );
        isf.data["metadata"]["windows"]["paging"] = serde_json::json!("pae");
        b[0x1000..0x5000].fill(0);
        put(&mut b, 0x1030, 0x2003); // PDPT aligned to 32 bytes, kernel entry 2.
        put(&mut b, 0x2000, 0x3003);
        put(&mut b, 0x3000, 0x8003);
        let img = image(&b);
        assert_eq!(
            Memory {
                image: &img,
                root: 0x1020,
                isf: &isf
            }
            .translate(0x80000123)
            .unwrap(),
            0x8123
        );
    }
    #[test]
    fn windows_32bit_isf_does_not_relax_linux_constraint() {
        let (_, mut isf) = fixture();
        set_arch(&mut isf, Architecture::X86);
        assert!(Isf::parse(&serde_json::to_vec(&isf.data).unwrap(), "x86".into()).is_ok());
        isf.data["metadata"]["windows"] = serde_json::Value::Null;
        assert!(Isf::parse(&serde_json::to_vec(&isf.data).unwrap(), "linux".into()).is_err());
    }
}
