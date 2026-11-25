//! QEMU/KVM ELF Core Dump parser (`virsh dump --memory-only` / `dump-guest-memory`).
//!
//! Extracts physical memory `PT_LOAD` segments and optional `PT_NOTE` metadata
//! (`QEMU` x86_64 vCPU register state, `VMCOREINFO`).
use super::{VcpuState, VmMetadata};
use crate::{
    Job,
    bytes::{Checked as _, c_str_lossy, le_u16, le_u32, le_u64},
    file_io::ReadAt as _,
    image::Segment,
};
use anyhow::{Context, Result, bail, ensure};
use std::{collections::BTreeMap, fs::File};

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const EI_CLASS_32: u8 = 1;
const EI_CLASS_64: u8 = 2;
const EI_DATA_LSB: u8 = 1;
const ET_CORE: u16 = 4;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const PN_XNUM: u16 = 0xffff;
const MAX_PHDRS: usize = 65_536;
const MAX_NOTE_BYTES: usize = 16 * 1024 * 1024;

pub struct Parsed {
    pub format: &'static str,
    pub segments: Vec<Segment>,
    pub metadata: VmMetadata,
}

/// Returns true only for little-endian ELF `ET_CORE` files.
pub fn recognized(file: &File, magic: &[u8; 4]) -> bool {
    if magic != ELF_MAGIC {
        return false;
    }
    let mut header = [0u8; 20];
    if file.read_exact_at(&mut header, 0).is_err() {
        return false;
    }
    let class = header[4];
    let data = header[5];
    let e_type = u16::from_le_bytes([header[16], header[17]]);
    matches!(class, EI_CLASS_32 | EI_CLASS_64) && data == EI_DATA_LSB && e_type == ET_CORE
}

pub fn parse(file: &File, job: &Job) -> Result<Parsed> {
    job.check()?;
    let len = file.metadata()?.len();
    ensure!(len >= 52, "ELF Core 头部截断");
    let mut ident = [0u8; 16];
    file.read_exact_at(&mut ident, 0)?;
    ensure!(&ident[0..4] == ELF_MAGIC, "ELF magic 无效");
    let is_64 = match ident[4] {
        EI_CLASS_64 => true,
        EI_CLASS_32 => false,
        other => bail!("不支持的 ELF 位宽 {other}"),
    };
    ensure!(ident[5] == EI_DATA_LSB, "不支持大端序 ELF Core");

    let header_len = if is_64 { 64usize } else { 52usize };
    ensure!(len >= header_len as u64, "ELF Core 头部截断");
    let mut ehdr = vec![0u8; header_len];
    file.read_exact_at(&mut ehdr, 0)?;

    let e_type = le_u16(&ehdr, 16).context("ELF e_type 截断")?;
    ensure!(e_type == ET_CORE, "不是 ELF Core 转储 (e_type={e_type})");
    let e_machine = le_u16(&ehdr, 18).context("ELF e_machine 截断")?;

    let (e_phoff, e_shoff, e_phentsize, raw_phnum, e_shentsize) = if is_64 {
        (
            le_u64(&ehdr, 32).context("ELF64 e_phoff 截断")?,
            le_u64(&ehdr, 40).context("ELF64 e_shoff 截断")?,
            usize::from(le_u16(&ehdr, 54).context("ELF64 e_phentsize 截断")?),
            le_u16(&ehdr, 56).context("ELF64 e_phnum 截断")?,
            usize::from(le_u16(&ehdr, 58).context("ELF64 e_shentsize 截断")?),
        )
    } else {
        (
            u64::from(le_u32(&ehdr, 28).context("ELF32 e_phoff 截断")?),
            u64::from(le_u32(&ehdr, 32).context("ELF32 e_shoff 截断")?),
            usize::from(le_u16(&ehdr, 42).context("ELF32 e_phentsize 截断")?),
            le_u16(&ehdr, 44).context("ELF32 e_phnum 截断")?,
            usize::from(le_u16(&ehdr, 46).context("ELF32 e_shentsize 截断")?),
        )
    };

    let min_phent = if is_64 { 56 } else { 32 };
    ensure!(
        e_phentsize >= min_phent && e_phentsize <= 256,
        "ELF e_phentsize 无效 ({e_phentsize})"
    );

    let phnum: usize = if raw_phnum == PN_XNUM {
        // Extended program header count lives in section header 0's sh_info.
        let min_shent = if is_64 { 64 } else { 40 };
        ensure!(
            e_shoff != 0
                && e_shentsize >= min_shent
                && e_shoff
                    .checked_add(e_shentsize as u64)
                    .is_some_and(|e| e <= len),
            "ELF PN_XNUM 节头 0 越界"
        );
        let mut sh0 = vec![0u8; min_shent];
        file.read_exact_at(&mut sh0, e_shoff)?;
        let sh_info_off = if is_64 { 44 } else { 28 };
        usize::try_from(le_u32(&sh0, sh_info_off).context("ELF sh_info 截断")?)?
    } else {
        usize::from(raw_phnum)
    };

    ensure!(
        phnum > 0 && phnum <= MAX_PHDRS,
        "ELF 程序头数量无效 ({phnum})"
    );
    let ph_bytes = phnum
        .checked_mul(e_phentsize)
        .context("ELF 程序头表长度溢出")?;
    ensure!(
        e_phoff
            .checked_add(ph_bytes as u64)
            .is_some_and(|e| e <= len),
        "ELF 程序头表越界"
    );

    let mut table = vec![0u8; ph_bytes];
    file.read_exact_at(&mut table, e_phoff)?;

    let mut segments = Vec::new();
    let mut note_ranges = Vec::new();

    for i in 0..phnum {
        if i.is_multiple_of(1024) {
            job.check()?;
        }
        let ph = table.at(i * e_phentsize..(i + 1) * e_phentsize)?;
        let p_type = le_u32(ph, 0).context("ELF p_type 截断")?;
        let (p_offset, p_paddr, p_filesz, p_memsz) = if is_64 {
            (
                le_u64(ph, 8).context("ELF64 p_offset 截断")?,
                le_u64(ph, 24).context("ELF64 p_paddr 截断")?,
                le_u64(ph, 32).context("ELF64 p_filesz 截断")?,
                le_u64(ph, 40).context("ELF64 p_memsz 截断")?,
            )
        } else {
            (
                u64::from(le_u32(ph, 4).context("ELF32 p_offset 截断")?),
                u64::from(le_u32(ph, 12).context("ELF32 p_paddr 截断")?),
                u64::from(le_u32(ph, 16).context("ELF32 p_filesz 截断")?),
                u64::from(le_u32(ph, 20).context("ELF32 p_memsz 截断")?),
            )
        };

        match p_type {
            PT_LOAD => {
                if p_filesz == 0 {
                    continue;
                }
                ensure!(
                    p_filesz <= p_memsz,
                    "ELF PT_LOAD p_filesz ({p_filesz:#x}) 大于 p_memsz ({p_memsz:#x}) @ {p_offset:#x}"
                );
                ensure!(
                    p_offset.checked_add(p_filesz).is_some_and(|e| e <= len),
                    "ELF PT_LOAD 文件范围越界 @ {p_offset:#x}"
                );
                let end = p_paddr
                    .checked_add(p_filesz)
                    .context("ELF PT_LOAD 物理地址溢出")?;
                segments.push(Segment {
                    start: p_paddr,
                    end,
                    file_offset: p_offset,
                });
            }
            PT_NOTE
                if p_filesz > 0
                    && p_filesz <= MAX_NOTE_BYTES as u64
                    && p_offset.checked_add(p_filesz).is_some_and(|e| e <= len) =>
            {
                note_ranges.push((p_offset, usize::try_from(p_filesz)?));
            }
            _ => {}
        }
    }

    ensure!(
        !segments.is_empty(),
        "ELF Core 不包含任何可读 PT_LOAD 物理内存段"
    );
    segments.sort_by_key(|s| s.start);
    ensure!(
        segments
            .windows(2)
            .all(|s| matches!(s, [a, b] if a.end <= b.start)),
        "ELF Core PT_LOAD 物理内存段重叠"
    );

    let mut metadata = VmMetadata {
        container: "ELF Core".into(),
        architecture: machine_name(e_machine).map(str::to_owned),
        ..Default::default()
    };

    let mut has_qemu_note = false;
    for (offset, size) in note_ranges {
        job.check()?;
        let mut buf = vec![0u8; size];
        if file.read_exact_at(&mut buf, offset).is_ok() {
            parse_notes(&buf, e_machine, &mut metadata, &mut has_qemu_note);
        }
    }

    let format = if has_qemu_note {
        metadata.container = "ELF Core (QEMU/KVM)".into();
        "ELF Core (QEMU/KVM)"
    } else {
        "ELF Core"
    };

    Ok(Parsed {
        format,
        segments,
        metadata,
    })
}

fn machine_name(e_machine: u16) -> Option<&'static str> {
    match e_machine {
        3 => Some("x86"),
        40 => Some("arm"),
        62 => Some("x86_64"),
        183 => Some("aarch64"),
        _ => None,
    }
}

fn align4(n: usize) -> Option<usize> {
    n.checked_add(3).map(|v| v & !3)
}

fn parse_notes(bytes: &[u8], e_machine: u16, metadata: &mut VmMetadata, has_qemu_note: &mut bool) {
    let mut pos = 0usize;
    while pos + 12 <= bytes.len() {
        let Some(namesz) = le_u32(bytes, pos).and_then(|v| usize::try_from(v).ok()) else {
            break;
        };
        let Some(descsz) = le_u32(bytes, pos + 4).and_then(|v| usize::try_from(v).ok()) else {
            break;
        };
        let Some(n_type) = le_u32(bytes, pos + 8) else {
            break;
        };
        let Some(name_aligned) = align4(namesz) else {
            break;
        };
        let Some(desc_aligned) = align4(descsz) else {
            break;
        };
        let Some(name_start) = pos.checked_add(12) else {
            break;
        };
        let Some(desc_start) = name_start.checked_add(name_aligned) else {
            break;
        };
        let Some(next) = desc_start.checked_add(desc_aligned) else {
            break;
        };
        if next > bytes.len() {
            break;
        }
        let name = bytes
            .get(name_start..name_start + namesz)
            .map(c_str_lossy)
            .unwrap_or_default();
        let desc = bytes.get(desc_start..desc_start + descsz).unwrap_or(&[]);

        if name == "QEMU" {
            *has_qemu_note = true;
            if e_machine == 62
                && let Some(vcpu) = parse_qemu_x86_64_cpu_state(
                    desc,
                    u32::try_from(metadata.vcpus.len()).unwrap_or(0),
                )
            {
                metadata.vcpus.push(vcpu);
            }
        } else if name == "VMCOREINFO" {
            let text = String::from_utf8_lossy(desc)
                .trim_end_matches('\0')
                .to_owned();
            if !text.is_empty() && metadata.vmcoreinfo.is_none() {
                metadata.vmcoreinfo = Some(text);
            }
        } else if !name.is_empty() && metadata.notes.len() < 32 {
            let label = format!("{name} (type={n_type})");
            if !metadata.notes.contains(&label) {
                metadata.notes.push(label);
            }
        }
        pos = next;
    }
}

/// Parse QEMU `QEMUCPUState` for x86_64 (`target/i386/arch_dump.c`).
///
/// Layout:
/// - `size: u32` (@0), `version: u32` (@4)
/// - `rax..r15`: 16 × `u64` (@8..136)
/// - `rip: u64` (@136), `rflags: u64` (@144)
/// - 10 × `QEMUCPUSegment` (24 bytes each = 240 bytes, @152..392)
/// - `cr[0..5]`: 5 × `u64` (@392..432): `cr0`, `cr1`, `cr2`, `cr3`, `cr4`
fn parse_qemu_x86_64_cpu_state(desc: &[u8], id: u32) -> Option<VcpuState> {
    if desc.len() < 432 {
        return None;
    }
    let size = usize::try_from(le_u32(desc, 0)?).ok()?;
    let version = le_u32(desc, 4)?;
    if version == 0 || size < 432 || size > desc.len() {
        return None;
    }
    let names = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    let mut registers = BTreeMap::new();
    for (i, name) in names.iter().enumerate() {
        registers.insert((*name).to_owned(), le_u64(desc, 8 + i * 8)?);
    }
    let rip = le_u64(desc, 136)?;
    let rflags = le_u64(desc, 144)?;
    let rsp = registers.get("rsp").copied();
    let cr0 = le_u64(desc, 392)?;
    let cr2 = le_u64(desc, 408)?;
    let cr3 = le_u64(desc, 416)?;
    let cr4 = le_u64(desc, 424)?;
    registers.insert("rip".into(), rip);
    registers.insert("rflags".into(), rflags);
    registers.insert("cr0".into(), cr0);
    registers.insert("cr2".into(), cr2);
    registers.insert("cr3".into(), cr3);
    registers.insert("cr4".into(), cr4);
    Some(VcpuState {
        id,
        rip: Some(rip),
        rsp,
        cr0: Some(cr0),
        cr2: Some(cr2),
        cr3: Some(cr3),
        cr4: Some(cr4),
        registers,
    })
}
