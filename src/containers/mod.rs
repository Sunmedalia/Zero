//! Virtualization and cloud-native memory container parsers.
//!
//! Covers:
//! - QEMU/KVM ELF Core dumps (`virsh dump --memory-only` / `dump-guest-memory`)
//! - VMware `.vmsn` / `.vmss` / `.vmsst` + `.vmem` snapshots
//! - AVML Snappy-compressed LiME v2 images (`avml --compress`)
//! - Pure-Rust Snappy block/framed decompression for AVML
pub mod avml;
pub mod elf;
pub mod snappy;
#[cfg(test)]
mod tests;
pub mod vmware;

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

/// Register snapshot for a single guest virtual CPU, when provided by the
/// container metadata (QEMU `PT_NOTE` or VMware checkpoint `cpu` group).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VcpuState {
    pub id: u32,
    pub rip: Option<u64>,
    pub rsp: Option<u64>,
    pub cr0: Option<u64>,
    pub cr2: Option<u64>,
    pub cr3: Option<u64>,
    pub cr4: Option<u64>,
    pub registers: BTreeMap<String, u64>,
}

/// Hypervisor / snapshot metadata extracted alongside physical memory segments.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VmMetadata {
    pub container: String,
    pub architecture: Option<String>,
    pub vcpus: Vec<VcpuState>,
    pub companion_path: Option<PathBuf>,
    pub vmcoreinfo: Option<String>,
    pub notes: Vec<String>,
}

impl VmMetadata {
    /// Non-zero page-aligned CR3 values reported by guest vCPUs, deduplicated
    /// in vCPU order. Useful as page-table root hints for discovery.
    pub fn cr3_hints(&self) -> Vec<u64> {
        let mut roots = Vec::new();
        for vcpu in &self.vcpus {
            if let Some(cr3) = vcpu.cr3 {
                let root = cr3 & 0x000f_ffff_ffff_f000;
                if root != 0 && !roots.contains(&root) {
                    roots.push(root);
                }
            }
        }
        roots
    }
}
