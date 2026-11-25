//! VMware `.vmsn` / `.vmss` / `.vmsst` + `.vmem` snapshot container parser.
//!
//! Parses VMware checkpoint headers (`0xbed2bed0`, `0xbed2bed2`, `0xbed3bed3`,
//! `0xbad1bad1`), extracts physical memory region descriptors (`regionsCount`,
//! `regionPPN`, `regionPageNum`, `regionSize`) and vCPU register states (`cpu`
//! group), and pairs `.vmem` files with sibling `.vmsn`/`.vmss`/`.vmsst`
//! metadata when present.
use super::{VcpuState, VmMetadata};
use crate::{
    Job,
    bytes::{Checked as _, c_str_lossy, le_u16, le_u32, le_u64, le_uint},
    file_io::ReadAt as _,
    image::Segment,
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeMap,
    fs::File,
    path::{Path, PathBuf},
};

const MAGIC_V0: u32 = 0xbed2_bed0;
const MAGIC_V2: u32 = 0xbed2_bed2;
const MAGIC_V3: u32 = 0xbed3_bed3;
const MAGIC_BAD: u32 = 0xbad1_bad1;
const GROUP_ENTRY_SIZE: usize = 80;
const MAX_GROUPS: usize = 4096;
const MAX_TAGS_PER_GROUP: usize = 131_072;
const MAX_REGIONS: usize = 65_536;
const PAGE_SIZE: u64 = 4096;

pub struct Parsed {
    pub format: &'static str,
    pub segments: Vec<Segment>,
    pub metadata: VmMetadata,
}

/// Raw parsed checkpoint metadata before binding to embedded memory or `.vmem`.
pub struct Checkpoint {
    pub embedded_memory: Option<(u64, u64)>,
    pub regions: Vec<Region>,
    pub vcpus: Vec<VcpuState>,
    pub version: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub ppn: u64,
    pub page_num: u64,
    pub size_pages: u64,
}

pub fn recognized_magic(magic: &[u8; 4]) -> bool {
    matches!(
        u32::from_le_bytes(*magic),
        MAGIC_V0 | MAGIC_V2 | MAGIC_V3 | MAGIC_BAD
    )
}

/// Find a sibling `.vmsn`, `.vmss`, or `.vmsst` checkpoint file for a `.vmem` image.
pub fn companion_checkpoint(path: &Path) -> Option<PathBuf> {
    let ext = path.extension()?.to_string_lossy().to_lowercase();
    if ext != "vmem" {
        return None;
    }
    for candidate_ext in ["vmsn", "vmss", "vmsst"] {
        let candidate = path.with_extension(candidate_ext);
        if candidate.is_file()
            && let Ok(file) = File::open(&candidate)
        {
            let mut magic = [0u8; 4];
            if file.read_exact_at(&mut magic, 0).is_ok() && recognized_magic(&magic) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Find a sibling `.vmem` backing memory file for a `.vmsn`/`.vmss`/`.vmsst` checkpoint.
pub fn companion_vmem(path: &Path) -> Option<PathBuf> {
    let ext = path.extension()?.to_string_lossy().to_lowercase();
    if !matches!(ext.as_str(), "vmsn" | "vmss" | "vmsst") {
        return None;
    }
    let candidate = path.with_extension("vmem");
    candidate.is_file().then_some(candidate)
}

/// Parse a VMware checkpoint file (`.vmsn` / `.vmss` / `.vmsst`).
pub fn parse_checkpoint(file: &File, job: &Job) -> Result<Checkpoint> {
    job.check()?;
    let len = file.metadata()?.len();
    ensure!(len >= 12, "VMware 快照头部截断");
    let mut hdr = [0u8; 12];
    file.read_exact_at(&mut hdr, 0)?;
    let magic = u32::from_le_bytes(hdr[0..4].try_into()?);
    ensure!(
        matches!(magic, MAGIC_V0 | MAGIC_V2 | MAGIC_V3 | MAGIC_BAD),
        "未知 VMware 快照 magic {magic:#x}"
    );
    let version = u32::from_le_bytes(hdr[4..8].try_into()?);
    let group_count = usize::try_from(u32::from_le_bytes(hdr[8..12].try_into()?))?;
    ensure!(
        group_count > 0 && group_count <= MAX_GROUPS,
        "VMware 快照组数量无效 ({group_count})"
    );
    let dir_size = group_count
        .checked_mul(GROUP_ENTRY_SIZE)
        .context("VMware 组目录大小溢出")?;
    ensure!(
        12u64.checked_add(dir_size as u64).is_some_and(|e| e <= len),
        "VMware 组目录截断"
    );
    let mut dir = vec![0u8; dir_size];
    file.read_exact_at(&mut dir, 12)?;

    let mut embedded_memory: Option<(u64, u64)> = None;
    let mut regions_count: Option<usize> = None;
    let mut region_ppn: BTreeMap<u32, u64> = BTreeMap::new();
    let mut region_page_num: BTreeMap<u32, u64> = BTreeMap::new();
    let mut region_size: BTreeMap<u32, u64> = BTreeMap::new();
    let mut vcpu_map: BTreeMap<u32, VcpuState> = BTreeMap::new();

    for i in 0..group_count {
        job.check()?;
        let entry = dir.at(i * GROUP_ENTRY_SIZE..(i + 1) * GROUP_ENTRY_SIZE)?;
        let name = c_str_lossy(entry.at(..64)?);
        let tags_offset = le_u64(entry, 64).context("VMware tags_offset 截断")?;
        let tags_size = le_u64(entry, 72).context("VMware tags_size 截断")?;
        if tags_size == 0 {
            continue;
        }
        ensure!(
            tags_offset.checked_add(tags_size).is_some_and(|e| e <= len),
            "VMware 组 {name} 越界"
        );
        if name.eq_ignore_ascii_case("memory") {
            parse_memory_group(
                file,
                tags_offset,
                tags_offset + tags_size,
                &mut embedded_memory,
                &mut regions_count,
                &mut region_ppn,
                &mut region_page_num,
                &mut region_size,
                job,
            )?;
        } else if name.eq_ignore_ascii_case("cpu") {
            parse_cpu_group(
                file,
                tags_offset,
                tags_offset + tags_size,
                &mut vcpu_map,
                job,
            )?;
        }
    }

    let count = regions_count.unwrap_or_else(|| {
        region_ppn
            .keys()
            .copied()
            .max()
            .map_or(0, |m| usize::try_from(m).unwrap_or(0) + 1)
    });
    ensure!(count <= MAX_REGIONS, "VMware 内存区域数量超限 ({count})");

    let mut regions = Vec::with_capacity(count);
    for idx in 0..count {
        let key = u32::try_from(idx)?;
        let Some(&ppn) = region_ppn.get(&key) else {
            continue;
        };
        let page_num = region_page_num.get(&key).copied().unwrap_or(0);
        let size_pages = region_size.get(&key).copied().unwrap_or(0);
        if size_pages > 0 {
            regions.push(Region {
                ppn,
                page_num,
                size_pages,
            });
        }
    }

    Ok(Checkpoint {
        embedded_memory,
        regions,
        vcpus: vcpu_map.into_values().collect(),
        version,
    })
}

/// Build physical `Segment`s and `VmMetadata` from a parsed checkpoint and a
/// backing memory file length + base offset inside that file.
pub fn build_segments(
    checkpoint: Checkpoint,
    backing_len: u64,
    memory_base_offset: u64,
    memory_window_len: u64,
    companion_path: Option<PathBuf>,
) -> Result<Parsed> {
    let mut segments = Vec::new();
    if checkpoint.regions.is_empty() {
        ensure!(memory_window_len > 0, "VMware 快照不包含内存数据");
        ensure!(
            memory_base_offset
                .checked_add(memory_window_len)
                .is_some_and(|e| e <= backing_len),
            "VMware 内存区域超出文件长度"
        );
        segments.push(Segment {
            start: 0,
            end: memory_window_len,
            file_offset: memory_base_offset,
        });
    } else {
        for r in &checkpoint.regions {
            let start = r
                .ppn
                .checked_mul(PAGE_SIZE)
                .context("VMware regionPPN 地址溢出")?;
            let length = r
                .size_pages
                .checked_mul(PAGE_SIZE)
                .context("VMware regionSize 长度溢出")?;
            let end = start
                .checked_add(length)
                .context("VMware 内存区域结束地址溢出")?;
            let rel_off = r
                .page_num
                .checked_mul(PAGE_SIZE)
                .context("VMware regionPageNum 偏移溢出")?;
            let file_offset = memory_base_offset
                .checked_add(rel_off)
                .context("VMware 文件偏移溢出")?;
            ensure!(
                file_offset
                    .checked_add(length)
                    .is_some_and(|e| e <= backing_len),
                "VMware 内存区域超出后备文件长度 (offset={file_offset:#x}, len={length:#x})"
            );
            segments.push(Segment {
                start,
                end,
                file_offset,
            });
        }
    }

    segments.sort_by_key(|s| s.start);
    ensure!(
        segments
            .windows(2)
            .all(|s| matches!(s, [a, b] if a.end <= b.start)),
        "VMware 物理内存区域重叠"
    );

    let format = if companion_path.is_some() {
        "VMware (.vmem+.vmsn)"
    } else {
        "VMware Snapshot"
    };
    let metadata = VmMetadata {
        container: format.into(),
        architecture: None,
        vcpus: checkpoint.vcpus,
        companion_path,
        vmcoreinfo: None,
        notes: vec![format!("VMware checkpoint v{}", checkpoint.version)],
    };

    Ok(Parsed {
        format,
        segments,
        metadata,
    })
}

/// Parse a standalone VMware `.vmsn` / `.vmss` / `.vmsst` file that embeds guest RAM.
pub fn parse_embedded(file: &File, job: &Job) -> Result<Parsed> {
    let checkpoint = parse_checkpoint(file, job)?;
    let (mem_offset, mem_len) = checkpoint
        .embedded_memory
        .context("VMware 快照未内嵌内存数据，且未找到同名 .vmem 文件")?;
    let backing_len = file.metadata()?.len();
    build_segments(checkpoint, backing_len, mem_offset, mem_len, None)
}

/// Parse a `.vmem` file paired with its sibling `.vmsn` / `.vmss` / `.vmsst` metadata.
pub fn parse_with_companion(vmem_file: &File, checkpoint_path: &Path, job: &Job) -> Result<Parsed> {
    let cp_file = File::open(checkpoint_path)
        .with_context(|| format!("无法打开 VMware 快照元数据 {}", checkpoint_path.display()))?;
    let checkpoint = parse_checkpoint(&cp_file, job)?;
    let vmem_len = vmem_file.metadata()?.len();
    build_segments(
        checkpoint,
        vmem_len,
        0,
        vmem_len,
        Some(checkpoint_path.to_path_buf()),
    )
}

struct TagHeader {
    name: String,
    indices: Vec<u32>,
    data_offset: u64,
    data_size: u64,
    next_offset: u64,
    is_block: bool,
}

fn read_tag(file: &File, pos: u64, group_end: u64) -> Result<Option<TagHeader>> {
    if pos >= group_end {
        return Ok(None);
    }
    let mut head = [0u8; 2];
    ensure!(group_end - pos >= 2, "VMware tag 头部截断 @ {pos:#x}");
    file.read_exact_at(&mut head, pos)?;
    let flags = head[0];
    let name_len = usize::from(head[1]);
    if flags == 0 && name_len == 0 {
        return Ok(None);
    }
    let data_len = flags & 0x3f;
    let n_indices = usize::from((flags >> 6) & 0x03);
    let mut cursor = pos + 2;

    ensure!(
        group_end - cursor >= name_len as u64,
        "VMware tag 名称截断 @ {cursor:#x}"
    );
    let mut name_buf = vec![0u8; name_len];
    file.read_exact_at(&mut name_buf, cursor)?;
    let name = c_str_lossy(&name_buf);
    cursor += name_len as u64;

    let idx_bytes = n_indices * 4;
    ensure!(
        group_end - cursor >= idx_bytes as u64,
        "VMware tag 索引截断 @ {cursor:#x}"
    );
    let mut indices = Vec::with_capacity(n_indices);
    if idx_bytes > 0 {
        let mut idx_buf = vec![0u8; idx_bytes];
        file.read_exact_at(&mut idx_buf, cursor)?;
        for i in 0..n_indices {
            indices.push(le_u32(&idx_buf, i * 4).context("VMware tag 索引读取失败")?);
        }
        cursor += idx_bytes as u64;
    }

    let (data_offset, data_size, is_block) = match data_len {
        0x3e => {
            ensure!(
                group_end - cursor >= 10,
                "VMware 32位块头截断 @ {cursor:#x}"
            );
            let mut b = [0u8; 10];
            file.read_exact_at(&mut b, cursor)?;
            let disk_size = u64::from(le_u32(&b, 0).context("VMware 块大小截断")?);
            let pad_size = u64::from(le_u16(&b, 8).context("VMware 块填充长度截断")?);
            let data_off = cursor
                .checked_add(10)
                .and_then(|v| v.checked_add(pad_size))
                .context("VMware 块偏移溢出")?;
            (data_off, disk_size, true)
        }
        0x3f => {
            ensure!(
                group_end - cursor >= 18,
                "VMware 64位块头截断 @ {cursor:#x}"
            );
            let mut b = [0u8; 18];
            file.read_exact_at(&mut b, cursor)?;
            let disk_size = le_u64(&b, 0).context("VMware 64位块大小截断")?;
            let pad_size = u64::from(le_u16(&b, 16).context("VMware 64位块填充长度截断")?);
            let data_off = cursor
                .checked_add(18)
                .and_then(|v| v.checked_add(pad_size))
                .context("VMware 64位块偏移溢出")?;
            (data_off, disk_size, true)
        }
        inline => (cursor, u64::from(inline), false),
    };

    let next_offset = data_offset
        .checked_add(data_size)
        .context("VMware tag 数据结束偏移溢出")?;
    ensure!(next_offset <= group_end, "VMware tag {name} 超出组边界");

    Ok(Some(TagHeader {
        name,
        indices,
        data_offset,
        data_size,
        next_offset,
        is_block,
    }))
}

fn read_tag_uint(file: &File, tag: &TagHeader) -> Result<Option<u64>> {
    if tag.is_block || tag.data_size == 0 || tag.data_size > 8 {
        return Ok(None);
    }
    let mut buf = vec![0u8; usize::try_from(tag.data_size)?];
    file.read_exact_at(&mut buf, tag.data_offset)?;
    Ok(le_uint(&buf))
}

#[allow(clippy::too_many_arguments)]
fn parse_memory_group(
    file: &File,
    start: u64,
    end: u64,
    embedded_memory: &mut Option<(u64, u64)>,
    regions_count: &mut Option<usize>,
    region_ppn: &mut BTreeMap<u32, u64>,
    region_page_num: &mut BTreeMap<u32, u64>,
    region_size: &mut BTreeMap<u32, u64>,
    job: &Job,
) -> Result<()> {
    let mut pos = start;
    let mut count = 0usize;
    while let Some(tag) = read_tag(file, pos, end)? {
        count += 1;
        ensure!(count <= MAX_TAGS_PER_GROUP, "VMware memory 组 tag 数量超限");
        if count.is_multiple_of(1024) {
            job.check()?;
        }
        match tag.name.as_str() {
            "Memory" if tag.is_block && tag.data_size > 0 && embedded_memory.is_none() => {
                *embedded_memory = Some((tag.data_offset, tag.data_size));
            }
            "regionsCount" => {
                if let Some(v) = read_tag_uint(file, &tag)? {
                    *regions_count = Some(usize::try_from(v)?);
                }
            }
            "regionPPN" => {
                if let (Some(&idx), Some(v)) = (tag.indices.first(), read_tag_uint(file, &tag)?) {
                    region_ppn.insert(idx, v);
                }
            }
            "regionPageNum" => {
                if let (Some(&idx), Some(v)) = (tag.indices.first(), read_tag_uint(file, &tag)?) {
                    region_page_num.insert(idx, v);
                }
            }
            "regionSize" => {
                if let (Some(&idx), Some(v)) = (tag.indices.first(), read_tag_uint(file, &tag)?) {
                    region_size.insert(idx, v);
                }
            }
            _ => {}
        }
        pos = tag.next_offset;
    }
    Ok(())
}

fn parse_cpu_group(
    file: &File,
    start: u64,
    end: u64,
    vcpus: &mut BTreeMap<u32, VcpuState>,
    job: &Job,
) -> Result<()> {
    let mut pos = start;
    let mut count = 0usize;
    while let Some(tag) = read_tag(file, pos, end)? {
        count += 1;
        ensure!(count <= MAX_TAGS_PER_GROUP, "VMware cpu 组 tag 数量超限");
        if count.is_multiple_of(1024) {
            job.check()?;
        }
        let vcpu_id = tag.indices.first().copied().unwrap_or(0);
        if let Some(val) = read_tag_uint(file, &tag)? {
            let lower = tag.name.to_ascii_lowercase();
            match lower.as_str() {
                "cr" => {
                    if let Some(&cr_idx) = tag.indices.get(1) {
                        let entry = vcpus.entry(vcpu_id).or_insert_with(|| VcpuState {
                            id: vcpu_id,
                            ..Default::default()
                        });
                        match cr_idx {
                            0 => {
                                entry.cr0 = Some(val);
                                entry.registers.insert("cr0".into(), val);
                            }
                            2 => {
                                entry.cr2 = Some(val);
                                entry.registers.insert("cr2".into(), val);
                            }
                            3 => {
                                entry.cr3 = Some(val);
                                entry.registers.insert("cr3".into(), val);
                            }
                            4 => {
                                entry.cr4 = Some(val);
                                entry.registers.insert("cr4".into(), val);
                            }
                            _ => {}
                        }
                    }
                }
                "cr0" | "cr2" | "cr3" | "cr4" | "rip" | "eip" | "rsp" | "esp" | "rax" | "rbx"
                | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rflags" | "eflags" => {
                    let entry = vcpus.entry(vcpu_id).or_insert_with(|| VcpuState {
                        id: vcpu_id,
                        ..Default::default()
                    });
                    match lower.as_str() {
                        "cr0" => entry.cr0 = Some(val),
                        "cr2" => entry.cr2 = Some(val),
                        "cr3" => entry.cr3 = Some(val),
                        "cr4" => entry.cr4 = Some(val),
                        "rip" | "eip" => entry.rip = Some(val),
                        "rsp" | "esp" => entry.rsp = Some(val),
                        _ => {}
                    }
                    entry.registers.insert(lower, val);
                }
                _ => {}
            }
        }
        pos = tag.next_offset;
    }
    Ok(())
}

/// Ensure a standalone checkpoint file without embedded memory resolves cleanly
/// when a companion `.vmem` is present, or fails with a clear diagnostic.
pub fn resolve_source_for_open(path: &Path, job: &Job) -> Result<(PathBuf, Option<PathBuf>)> {
    job.check()?;
    let file = File::open(path).with_context(|| format!("无法打开镜像 {}", path.display()))?;
    let mut magic = [0u8; 4];
    if file.read_exact_at(&mut magic, 0).is_ok() && recognized_magic(&magic) {
        let cp = parse_checkpoint(&file, job)?;
        if cp.embedded_memory.is_some() {
            return Ok((path.to_path_buf(), None));
        }
        if let Some(vmem) = companion_vmem(path) {
            return Ok((vmem, Some(path.to_path_buf())));
        }
        bail!(
            "VMware 快照 {} 未内嵌内存数据，且同目录缺少对应的 .vmem 文件",
            path.display()
        );
    }
    if let Some(cp_path) = companion_checkpoint(path) {
        return Ok((path.to_path_buf(), Some(cp_path)));
    }
    Ok((path.to_path_buf(), None))
}
