//! Indexed random-access reader for AVML Snappy-compressed (version 2) images.
//!
//! AVML (`microsoft/avml --compress`) writes 32-byte LiME-like range headers
//! with magic `0x4c4d5641` (`"AVML"` in little-endian) and `version == 2`,
//! followed by a Snappy framed stream for each range (and may also contain
//! uncompressed LiME v1 `0x4c694d45` blocks in the same file).
use super::snappy;
use crate::{Job, bytes::Checked as _, file_io::ReadAt as _, image::Segment};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::File,
    sync::{Arc, Mutex},
};

pub const AVML_MAGIC: u32 = 0x4c4d_5641; // "AVML" in LE bytes
pub const LIME_MAGIC: u32 = 0x4c69_4d45; // "EMiL" in LE bytes
const MAX_CHUNKS: usize = 8 * 1024 * 1024;
const CACHE_CAPACITY: usize = 256;

#[derive(Clone, Copy)]
enum ChunkKind {
    Raw,
    SnappyUncompressed { masked_crc: u32 },
    SnappyCompressed { masked_crc: u32 },
}

#[derive(Clone, Copy)]
struct Chunk {
    start: u64,
    end: u64,
    file_offset: u64,
    file_len: usize,
    kind: ChunkKind,
}

#[derive(Default)]
struct Cache {
    entries: BTreeMap<usize, Arc<Vec<u8>>>,
    order: VecDeque<usize>,
}

pub struct Avml {
    chunks: Vec<Chunk>,
    segments: Vec<Segment>,
    cache: Mutex<Cache>,
}

pub fn recognized(magic: &[u8; 4]) -> bool {
    u32::from_le_bytes(*magic) == AVML_MAGIC
}

impl Avml {
    pub fn parse(file: &File, job: &Job) -> Result<Self> {
        let len = file.metadata()?.len();
        let mut chunks = Vec::new();
        let mut segments = Vec::new();
        let mut pos = 0u64;

        while pos < len {
            job.check()?;
            ensure!(len - pos >= 32, "AVML 头部截断 @ {pos:#x}");
            let mut h = [0u8; 32];
            file.read_exact_at(&mut h, pos)?;
            let magic = u32::from_le_bytes(h[0..4].try_into()?);
            let version = u32::from_le_bytes(h[4..8].try_into()?);
            let start = u64::from_le_bytes(h[8..16].try_into()?);
            let last = u64::from_le_bytes(h[16..24].try_into()?);
            let end = last.checked_add(1).context("AVML 地址溢出")?;
            ensure!(start < end, "AVML 范围无效 @ {pos:#x}");
            let range_len = end - start;
            pos += 32;

            match (magic, version) {
                (LIME_MAGIC, 1) => {
                    let next = pos.checked_add(range_len).context("LiME 长度溢出")?;
                    ensure!(next <= len, "LiME 数据截断 @ {pos:#x}");
                    // Split raw runs into 64 KiB index chunks only when needed, or
                    // read directly as raw chunks without caching.
                    let mut phys = start;
                    let mut off = pos;
                    while phys < end {
                        let step = (end - phys).min(snappy::MAX_FRAMED_CHUNK_UNCOMPRESSED as u64);
                        ensure!(chunks.len() < MAX_CHUNKS, "AVML 块数量超限");
                        chunks.push(Chunk {
                            start: phys,
                            end: phys + step,
                            file_offset: off,
                            file_len: usize::try_from(step)?,
                            kind: ChunkKind::Raw,
                        });
                        phys += step;
                        off += step;
                    }
                    segments.push(Segment {
                        start,
                        end,
                        file_offset: pos,
                    });
                    pos = next;
                }
                (AVML_MAGIC, 2) => {
                    let seg_file_offset = pos;
                    let mut produced = 0u64;
                    let mut saw_stream_id = false;
                    while produced < range_len {
                        job.check()?;
                        ensure!(len - pos >= 4, "AVML Snappy 帧头截断 @ {pos:#x}");
                        let mut hdr = [0u8; 4];
                        file.read_exact_at(&mut hdr, pos)?;
                        let chunk_type = hdr[0];
                        let chunk_len = u64::from(u32::from_le_bytes([hdr[1], hdr[2], hdr[3], 0]));
                        let payload_off = pos + 4;
                        let next_pos = payload_off
                            .checked_add(chunk_len)
                            .context("AVML Snappy 块偏移溢出")?;
                        ensure!(next_pos <= len, "AVML Snappy 块截断 @ {pos:#x}");

                        match chunk_type {
                            0xff => {
                                ensure!(chunk_len == 6, "AVML Snappy 流标识长度无效");
                                let mut id = [0u8; 6];
                                file.read_exact_at(&mut id, payload_off)?;
                                ensure!(&id == snappy::STREAM_IDENTIFIER, "AVML Snappy 流标识错误");
                                saw_stream_id = true;
                            }
                            0x00 => {
                                ensure!(saw_stream_id, "AVML Snappy 数据块缺少流标识");
                                ensure!(chunk_len >= 5, "AVML Snappy 压缩块过短 @ {pos:#x}");
                                let mut prefix = [0u8; 9];
                                let read_n = usize::try_from(chunk_len.min(9))?;
                                file.read_exact_at(prefix.at_mut(..read_n)?, payload_off)?;
                                let masked_crc = u32::from_le_bytes(prefix[0..4].try_into()?);
                                let (uncompressed_len, _) =
                                    snappy::read_uncompressed_len(prefix.at(4..read_n)?)?;
                                ensure!(
                                    uncompressed_len > 0
                                        && uncompressed_len
                                            <= snappy::MAX_FRAMED_CHUNK_UNCOMPRESSED,
                                    "AVML Snappy 压缩块解压长度 {uncompressed_len} 无效"
                                );
                                let chunk_start = start + produced;
                                let chunk_end = chunk_start
                                    .checked_add(uncompressed_len as u64)
                                    .context("AVML 物理地址溢出")?;
                                ensure!(chunk_end <= end, "AVML Snappy 解压数据超出头部声明范围");
                                ensure!(chunks.len() < MAX_CHUNKS, "AVML 块数量超限");
                                chunks.push(Chunk {
                                    start: chunk_start,
                                    end: chunk_end,
                                    file_offset: payload_off + 4,
                                    file_len: usize::try_from(chunk_len - 4)?,
                                    kind: ChunkKind::SnappyCompressed { masked_crc },
                                });
                                produced += uncompressed_len as u64;
                            }
                            0x01 => {
                                ensure!(saw_stream_id, "AVML Snappy 数据块缺少流标识");
                                ensure!(chunk_len >= 4, "AVML Snappy 未压缩块过短 @ {pos:#x}");
                                let mut crc_bytes = [0u8; 4];
                                file.read_exact_at(&mut crc_bytes, payload_off)?;
                                let masked_crc = u32::from_le_bytes(crc_bytes);
                                let data_len = chunk_len - 4;
                                ensure!(
                                    data_len > 0
                                        && data_len <= snappy::MAX_FRAMED_CHUNK_UNCOMPRESSED as u64,
                                    "AVML Snappy 未压缩块长度 {data_len} 无效"
                                );
                                let chunk_start = start + produced;
                                let chunk_end = chunk_start
                                    .checked_add(data_len)
                                    .context("AVML 物理地址溢出")?;
                                ensure!(chunk_end <= end, "AVML Snappy 未压缩数据超出头部声明范围");
                                ensure!(chunks.len() < MAX_CHUNKS, "AVML 块数量超限");
                                chunks.push(Chunk {
                                    start: chunk_start,
                                    end: chunk_end,
                                    file_offset: payload_off + 4,
                                    file_len: usize::try_from(data_len)?,
                                    kind: ChunkKind::SnappyUncompressed { masked_crc },
                                });
                                produced += data_len;
                            }
                            0x80..=0xfe => {
                                // Padding or reserved skippable chunk per Snappy framing spec.
                            }
                            other => {
                                bail!(
                                    "AVML Snappy 遇到不支持的不可跳过块类型 {other:#x} @ {pos:#x}"
                                );
                            }
                        }
                        pos = next_pos;
                    }
                    ensure!(produced == range_len, "AVML 压缩范围长度不一致");
                    segments.push(Segment {
                        start,
                        end,
                        file_offset: seg_file_offset,
                    });
                }
                _ => {
                    bail!("AVML/LiME 头部 magic={magic:#x} version={version} 无效 @ {pos:#x}");
                }
            }
        }

        ensure!(!segments.is_empty(), "AVML 镜像不包含任何内存段");
        segments.sort_by_key(|s| s.start);
        ensure!(
            segments
                .windows(2)
                .all(|s| matches!(s, [a, b] if a.end <= b.start)),
            "AVML 物理内存范围重叠"
        );
        chunks.sort_by_key(|c| c.start);
        ensure!(
            chunks
                .windows(2)
                .all(|c| matches!(c, [a, b] if a.end <= b.start)),
            "AVML 块范围重叠"
        );

        Ok(Self {
            chunks,
            segments,
            cache: Mutex::new(Cache::default()),
        })
    }

    pub fn segments(&self) -> Vec<Segment> {
        self.segments.clone()
    }

    fn decode_chunk(&self, file: &File, index: usize) -> Result<Arc<Vec<u8>>> {
        if let Some(bytes) = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("AVML 解压缓存锁失败"))?
            .entries
            .get(&index)
        {
            return Ok(bytes.clone());
        }
        let chunk = self.chunks.at(index)?;
        let expected_len = usize::try_from(chunk.end - chunk.start)?;
        let mut raw = vec![0u8; chunk.file_len];
        file.read_exact_at(&mut raw, chunk.file_offset)?;
        let decoded = match chunk.kind {
            ChunkKind::Raw => {
                ensure!(raw.len() == expected_len, "AVML 原始块长度不一致");
                raw
            }
            ChunkKind::SnappyUncompressed { masked_crc } => {
                ensure!(raw.len() == expected_len, "AVML Snappy 未压缩块长度不一致");
                let actual = snappy::mask_crc32c(snappy::crc32c(&raw));
                ensure!(
                    actual == masked_crc,
                    "AVML Snappy 校验和错误 @ {:#x}",
                    chunk.start
                );
                raw
            }
            ChunkKind::SnappyCompressed { masked_crc } => {
                let bytes = snappy::decompress_raw(&raw, snappy::MAX_FRAMED_CHUNK_UNCOMPRESSED)?;
                ensure!(
                    bytes.len() == expected_len,
                    "AVML Snappy 压缩块解压长度不一致 @ {:#x}",
                    chunk.start
                );
                let actual = snappy::mask_crc32c(snappy::crc32c(&bytes));
                ensure!(
                    actual == masked_crc,
                    "AVML Snappy 校验和错误 @ {:#x}",
                    chunk.start
                );
                bytes
            }
        };
        let bytes = Arc::new(decoded);
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("AVML 解压缓存锁失败"))?;
        if !cache.entries.contains_key(&index) {
            if cache.order.len() >= CACHE_CAPACITY
                && let Some(old) = cache.order.pop_front()
            {
                cache.entries.remove(&old);
            }
            cache.order.push_back(index);
            cache.entries.insert(index, bytes.clone());
        }
        Ok(bytes)
    }

    pub fn read(&self, file: &File, mut address: u64, mut out: &mut [u8]) -> Result<()> {
        address
            .checked_add(out.len() as u64)
            .context("AVML 物理地址溢出")?;
        while !out.is_empty() {
            let idx = self
                .chunks
                .partition_point(|c| c.start <= address)
                .wrapping_sub(1);
            let chunk = self
                .chunks
                .get(idx)
                .filter(|c| address < c.end)
                .with_context(|| format!("物理地址越界或 AVML 空洞 @ {address:#x}"))?;
            let n = out.len().min(usize::try_from(chunk.end - address)?);
            let in_chunk = usize::try_from(address - chunk.start)?;
            if matches!(chunk.kind, ChunkKind::Raw) {
                file.read_exact_at(out.at_mut(..n)?, chunk.file_offset + in_chunk as u64)?;
            } else {
                let decoded = self.decode_chunk(file, idx)?;
                out.at_mut(..n)?
                    .copy_from_slice(decoded.at(in_chunk..in_chunk + n)?);
            }
            address += n as u64;
            out = out.at_mut(n..)?;
        }
        Ok(())
    }
}
