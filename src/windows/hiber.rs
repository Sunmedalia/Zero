//! Hibernation page maps: Win7 range arrays and NT6.2+ restoration sets.
//! Format facts: libyal/libhibr, MagnetForensics/Hibr2Bin and Khalil (TalTech, 2020).
use super::*;
use crate::image::Segment;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fs::File,
    os::unix::fs::FileExt,
    sync::{Arc, Mutex},
};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Info {
    pub layout: String,
    pub pointer_size: usize,
    pub image_type: u32,
    pub hiberboot: Option<bool>,
    pub saved_pages: u64,
    pub validation: String,
    pub diagnostics: Vec<String>,
}
#[derive(Clone)]
struct Block {
    offset: u64,
    length: usize,
    size: usize,
    format: u16,
    raw: bool,
}
struct Mapping {
    end: u64,
    block: usize,
    offset: usize,
}
#[derive(Default)]
struct Cache {
    bytes: BTreeMap<usize, Arc<Vec<u8>>>,
    order: VecDeque<usize>,
}
pub struct Hibernation {
    stamp: String,
    blocks: Vec<Block>,
    maps: BTreeMap<u64, Mapping>,
    cache: Mutex<Cache>,
    pub info: Info,
}
struct Reader<'a> {
    file: &'a File,
    len: u64,
}
impl Reader<'_> {
    fn bytes(&self, at: u64, size: usize) -> Result<Vec<u8>> {
        ensure!(
            size <= 65536 && at.checked_add(size as u64).is_some_and(|e| e <= self.len),
            "休眠文件范围越界/截断 @ {at:#x}"
        );
        let mut b = vec![0; size];
        self.file.read_exact_at(&mut b, at)?;
        Ok(b)
    }
}
fn uint(b: &[u8], at: usize, width: usize) -> Result<u64> {
    let mut v = [0; 8];
    v[..width].copy_from_slice(b.get(at..at + width).context("休眠字段截断")?);
    Ok(u64::from_le_bytes(v))
}
pub fn recognized(magic: &[u8]) -> bool {
    matches!(
        magic,
        b"hibr" | b"HIBR" | b"wake" | b"WAKE" | b"RSTR" | b"HORM" | b"BRKP"
    )
}
impl Hibernation {
    fn decode(&self, r: &Reader<'_>, index: usize) -> Result<Arc<Vec<u8>>> {
        if let Some(bytes) = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("hiber cache 锁失败"))?
            .bytes
            .get(&index)
        {
            return Ok(bytes.clone());
        }
        let block = &self.blocks[index];
        let input = r.bytes(block.offset, block.length)?;
        let bytes = Arc::new(if block.raw {
            ensure!(input.len() == block.size, "休眠原始块长度错误");
            input
        } else {
            codec::decompress(block.format, &input, block.size)?
        });
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("hiber cache 锁失败"))?;
        if !cache.bytes.contains_key(&index) {
            if cache.order.len() >= 128
                && let Some(old) = cache.order.pop_front()
            {
                cache.bytes.remove(&old);
            }
            cache.order.push_back(index);
            cache.bytes.insert(index, bytes.clone());
        }
        Ok(bytes)
    }
    fn block(
        &mut self,
        r: &Reader<'_>,
        block: Block,
        ranges: &[(u64, u64)],
        job: &Job,
    ) -> Result<()> {
        job.check()?;
        ensure!(self.blocks.len() < MAX_OBJECTS, "休眠块数量超限");
        let index = self.blocks.len();
        self.blocks.push(block);
        if let Err(e) = self.decode(r, index) {
            ensure!(self.info.diagnostics.len() < 4096, "休眠损坏块过多");
            self.info.diagnostics.push(format!(
                "block file {:#x}: {e:#}",
                self.blocks[index].offset
            ));
            return Ok(());
        }
        let mut offset = 0usize;
        for &(page, count) in ranges {
            job.check()?;
            let start = page.checked_mul(4096).context("休眠物理页地址溢出")?;
            let length = count.checked_mul(4096).context("休眠页长度溢出")?;
            let end = start.checked_add(length).context("休眠物理范围溢出")?;
            ensure!(
                self.maps.len() < MAX_OBJECTS
                    && start < end
                    && offset
                        .checked_add(length as usize)
                        .is_some_and(|n| n <= self.blocks[index].size),
                "休眠映射范围无效"
            );
            if let Some((_, previous)) = self.maps.range(..=start).next_back() {
                ensure!(previous.end <= start, "休眠物理范围重叠");
            }
            if let Some((&next, _)) = self.maps.range(start..).next() {
                ensure!(end <= next, "休眠物理范围重叠");
            }
            self.maps.insert(
                start,
                Mapping {
                    end,
                    block: index,
                    offset,
                },
            );
            offset += length as usize;
            self.info.saved_pages += count;
        }
        ensure!(offset == self.blocks[index].size, "休眠块页面计数不一致");
        Ok(())
    }
    pub fn read(&self, file: &File, mut address: u64, mut out: &mut [u8]) -> Result<()> {
        address
            .checked_add(out.len() as u64)
            .context("休眠物理读取溢出")?;
        ensure!(
            crate::image::metadata_stamp(&file.metadata()?)? == self.stamp,
            "休眠文件在分析期间被修改"
        );
        let r = Reader {
            file,
            len: file.metadata()?.len(),
        };
        while !out.is_empty() {
            let (&start, map) = self
                .maps
                .range(..=address)
                .next_back()
                .filter(|(_, m)| address < m.end)
                .with_context(|| format!("休眠文件缺少物理页 {address:#x}"))?;
            let n = out.len().min((map.end - address) as usize);
            let bytes = self.decode(&r, map.block)?;
            let at = map.offset + (address - start) as usize;
            out[..n].copy_from_slice(bytes.get(at..at + n).context("休眠解压块范围无效")?);
            address += n as u64;
            out = &mut out[n..];
        }
        Ok(())
    }
    pub fn segments(&self) -> Vec<Segment> {
        let mut segments: Vec<Segment> = Vec::new();
        for (&start, map) in &self.maps {
            if let Some(previous) = segments.last_mut()
                && previous.end == start
            {
                previous.end = map.end;
            } else {
                segments.push(Segment {
                    start,
                    end: map.end,
                    file_offset: 0,
                });
            }
        }
        segments
    }
}
pub fn parse(file: &File, job: &Job) -> Result<(Hibernation, container::Metadata)> {
    let r = Reader {
        file,
        len: file.metadata()?.len(),
    };
    let header = r.bytes(0, 4096)?;
    ensure!(recognized(&header[..4]), "不是 Windows 休眠文件");
    let length = uint(&header, 12, 4)?;
    ensure!((80..=4096).contains(&length), "未知休眠头部尺寸");
    let width = if uint(&header, 20, 4)? == 4096 {
        4
    } else {
        ensure!(uint(&header, 24, 4)? == 4096, "仅支持 4 KiB 休眠页");
        8
    };
    let legacy = (width == 4 && length == 224) || (width == 8 && length == 296);
    let mut h = Hibernation {
        stamp: crate::image::metadata_stamp(&file.metadata()?)?,
        blocks: Vec::new(),
        maps: BTreeMap::new(),
        cache: Mutex::new(Cache::default()),
        info: Info {
            layout: if legacy {
                "win7-range-array"
            } else {
                "nt62-restoration-set"
            }
            .into(),
            pointer_size: width,
            image_type: uint(&header, 4, 4)? as u32,
            hiberboot: if width == 8 && length == 0x3e0 {
                Some(header[0x364] != 0)
            } else {
                None
            },
            saved_pages: 0,
            validation: "synthetic".into(),
            diagnostics: vec![],
        },
    };
    if matches!(&header[..4], b"wake" | b"WAKE" | b"BRKP") {
        h.info
            .diagnostics
            .push("恢复后的休眠文件可能已清除保存页".into());
    }
    if legacy {
        let first = uint(&header, if width == 4 { 80 } else { 104 }, width)?;
        legacy_ranges(&r, &mut h, first, width, job)?;
    } else {
        ensure!(
            length >= if width == 4 { 0x58 } else { 0x78 },
            "未知现代休眠头部布局"
        );
        let (boot_at, kernel_at) = if width == 4 {
            (0x50, 0x54)
        } else if length < 0x280 {
            (0x60, 0x68)
        } else {
            (0x68, 0x70)
        };
        let boot = uint(&header, boot_at, width)?
            .checked_mul(4096)
            .context("restore offset 溢出")?;
        let kernel = uint(&header, kernel_at, width)?
            .checked_mul(4096)
            .context("restore offset 溢出")?;
        ensure!(
            boot == 0 || kernel == 0 || boot < kernel,
            "休眠 restoration sets 顺序无效"
        );
        let counted = width == 8 && length >= 0x280;
        for (start, end, count) in [
            (
                boot,
                if kernel > boot { kernel } else { r.len },
                if counted {
                    Some(uint(&header, 0x228, 8)?)
                } else {
                    None
                },
            ),
            (
                kernel,
                r.len,
                if counted {
                    Some(uint(&header, 0x230, 8)?)
                } else {
                    None
                },
            ),
        ] {
            if start == 0 {
                ensure!(
                    count.is_none_or(|n| n == 0),
                    "休眠保存页存在但缺少 restoration set"
                );
                continue;
            }
            modern_ranges(&r, &mut h, start, end, width, count, job)?;
        }
    }
    ensure!(
        crate::image::metadata_stamp(&file.metadata()?)? == h.stamp,
        "休眠文件在解析期间被修改"
    );
    let metadata = container::Metadata {
        architecture: if width == 4 {
            Architecture::X86
        } else {
            Architecture::Auto
        },
        hibernation: Some(h.info.clone()),
        ..container::Metadata::default()
    };
    Ok((h, metadata))
}
fn modern_ranges(
    r: &Reader<'_>,
    h: &mut Hibernation,
    mut at: u64,
    end: u64,
    width: usize,
    expected: Option<u64>,
    job: &Job,
) -> Result<()> {
    ensure!(
        at >= 4096 && at <= end && end <= r.len,
        "restoration set 文件范围无效"
    );
    let mut pages = 0u64;
    let mut blocks = 0;
    while at < end && expected.is_none_or(|n| pages < n) {
        job.check()?;
        ensure!(blocks < MAX_OBJECTS, "restoration set 块数量超限");
        blocks += 1;
        let word = uint(&r.bytes(at, 4)?, 0, 4)?;
        let count = (word & 255) as usize;
        let length = ((word >> 8) & 0x3fffff) as usize;
        let format = if word >> 30 >= 2 { 4 } else { 3 };
        if word == 0 && expected.is_none() {
            break;
        }
        ensure!(
            count > 0 && count <= 16 && (1..=65536).contains(&length),
            "restoration set 头部无效 @ {at:#x}"
        );
        let descriptors = r.bytes(add(at, 4)?, count * width)?;
        let mut ranges = Vec::new();
        let mut total = 0;
        for descriptor in descriptors.chunks_exact(width) {
            let value = uint(descriptor, 0, width)?;
            let count = (value & 15) + 1;
            total += count;
            ranges.push((value >> 4, count));
        }
        ensure!((1..=16).contains(&total), "restoration set 解压页数无效");
        pages = pages
            .checked_add(total)
            .context("restoration set 页数溢出")?;
        ensure!(
            expected.is_none_or(|n| pages <= n),
            "restoration set 超出头部页面计数"
        );
        let data = add(at, 4 + (count * width) as u64)?;
        at = add(data, length as u64)?;
        ensure!(at <= end, "restoration set 数据截断");
        h.block(
            r,
            Block {
                offset: data,
                length,
                size: total as usize * 4096,
                format,
                raw: false,
            },
            &ranges,
            job,
        )?;
    }
    ensure!(
        expected.is_none_or(|n| pages == n),
        "restoration set 页面计数不足"
    );
    Ok(())
}
fn legacy_ranges(
    r: &Reader<'_>,
    h: &mut Hibernation,
    mut page: u64,
    width: usize,
    job: &Job,
) -> Result<()> {
    let mut tables = HashSet::new();
    while page != 0 {
        job.check()?;
        ensure!(
            tables.len() < MAX_OBJECTS && tables.insert(page),
            "休眠 range table 循环或超限"
        );
        let at = page.checked_mul(4096).context("range table offset 溢出")?;
        let bytes = r.bytes(at, 4096)?;
        let next = uint(&bytes, 0, width)?;
        let count = uint(&bytes, width, 4)? as usize;
        let header = width * 2;
        ensure!(
            count > 0 && count <= (4096 - header) / (width * 2),
            "休眠 range table 计数无效"
        );
        let mut ranges = VecDeque::new();
        let mut total = 0u64;
        for i in 0..count {
            let start = uint(&bytes, header + i * width * 2, width)?;
            let end = uint(&bytes, header + i * width * 2 + width, width)?;
            ensure!(start < end, "休眠页范围无效");
            total = total.checked_add(end - start).context("休眠页数溢出")?;
            ranges.push_back((start, end - start));
        }
        let mut data = add(at, 4096)?;
        let limit = if next != 0 {
            next.checked_mul(4096).context("next range table 溢出")?
        } else {
            r.len
        };
        ensure!(data <= limit && limit <= r.len, "休眠 range table 顺序无效");
        while total > 0 {
            job.check()?;
            let header = r.bytes(data, 32)?;
            ensure!(&header[..8] == b"\x81\x81xpress", "休眠 XPRESS 块签名无效");
            let info = uint(&header, 8, 4)?;
            let pages = (info & 1023) + 1;
            let length = (info >> 10) + 1;
            ensure!(
                pages <= 16 && pages <= total && length <= 65536,
                "休眠 XPRESS 块尺寸无效"
            );
            let start = add(data, 32)?;
            data = add(start, (length + 7) & !7)?;
            ensure!(data <= limit, "休眠 XPRESS 数据截断");
            let mut block_ranges = Vec::new();
            let mut remaining = pages;
            while remaining > 0 {
                let (page, count) = ranges.pop_front().context("休眠 range table 页数不足")?;
                let take = count.min(remaining);
                block_ranges.push((page, take));
                if count > take {
                    ranges.push_front((page + take, count - take));
                }
                remaining -= take;
            }
            h.block(
                r,
                Block {
                    offset: start,
                    length: length as usize,
                    size: pages as usize * 4096,
                    format: 3,
                    raw: length == pages * 4096,
                },
                &block_ranges,
                job,
            )?;
            total -= pages;
        }
        page = next;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image};
    use super::*;
    fn literals(bytes: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        for group in bytes.chunks(32) {
            data.extend_from_slice(&[0; 4]);
            data.extend_from_slice(group);
        }
        data
    }
    fn modern(bytes: &[u8], hiberboot: bool) -> Vec<u8> {
        let mut file = vec![0; 4096];
        file[..4].copy_from_slice(b"HIBR");
        file[12..16].copy_from_slice(&0x3e0u32.to_le_bytes());
        file[24..28].copy_from_slice(&4096u32.to_le_bytes());
        file[0x68..0x70].copy_from_slice(&1u64.to_le_bytes());
        file[0x228..0x230].copy_from_slice(&(bytes.len() as u64 / 4096).to_le_bytes());
        file[0x364] = u8::from(hiberboot);
        for (page, bytes) in bytes.chunks_exact(4096).enumerate() {
            let compressed = literals(bytes);
            let word = ((compressed.len() as u32) << 8) | 1;
            file.extend_from_slice(&word.to_le_bytes());
            file.extend_from_slice(&((page as u64) << 4).to_le_bytes());
            file.extend_from_slice(&compressed);
        }
        file
    }
    #[test]
    fn modern_full_and_fast_startup_maps_bootstrap_and_bound_cache() {
        let (bytes, isf) = fixture();
        for fast in [false, true] {
            let file = modern(&bytes, fast);
            let img = image(&file);
            assert_eq!(img.format, "Windows hibernation");
            let mut all = vec![0; bytes.len()];
            img.read(0, &mut all).unwrap();
            assert_eq!(all, bytes);
            assert_eq!(discover(&img, &isf, &Job::default()).unwrap(), (0x1000, K));
            assert_eq!(img.hibernation.as_ref().unwrap().info.hiberboot, Some(fast));
            assert!(img.read(bytes.len() as u64, &mut [0; 1]).is_err());
            assert_eq!(img.scan(b"RSDS", &Job::default()).unwrap(), vec![0x8600]);
        }
        let file = modern(&bytes, true);
        assert!(
            Image::from_file(
                {
                    use std::io::Write;
                    let mut f = tempfile::tempfile().unwrap();
                    f.write_all(&file[..file.len() - 1]).unwrap();
                    f
                },
                "truncated".into()
            )
            .is_err()
        );
    }
    #[test]
    fn legacy_win7_ranges_and_xpress_headers_preserve_physical_holes() {
        let (bytes, isf) = fixture();
        let mut file = vec![0; 0x7000];
        file[..4].copy_from_slice(b"hibr");
        file[12..16].copy_from_slice(&296u32.to_le_bytes());
        file[24..28].copy_from_slice(&4096u32.to_le_bytes());
        file[104..112].copy_from_slice(&6u64.to_le_bytes());
        file[0x6008..0x600c].copy_from_slice(&1u32.to_le_bytes());
        file[0x6018..0x6020].copy_from_slice(&64u64.to_le_bytes());
        for page in bytes.chunks_exact(4096) {
            let compressed = literals(page);
            let mut header = [0; 32];
            header[..8].copy_from_slice(b"\x81\x81xpress");
            header[8..12].copy_from_slice(&((compressed.len() as u32 - 1) << 10).to_le_bytes());
            file.extend_from_slice(&header);
            file.extend_from_slice(&compressed);
            while !file.len().is_multiple_of(8) {
                file.push(0);
            }
        }
        let img = image(&file);
        assert_eq!(discover(&img, &isf, &Job::default()).unwrap(), (0x1000, K));
        let mut all = vec![0; bytes.len()];
        img.read(0, &mut all).unwrap();
        assert_eq!(all, bytes);
        file[0x6000..0x6008].copy_from_slice(&6u64.to_le_bytes());
        assert!(
            Image::from_file(
                {
                    use std::io::Write;
                    let mut f = tempfile::tempfile().unwrap();
                    f.write_all(&file).unwrap();
                    f
                },
                "cycle".into()
            )
            .is_err()
        );
    }
    #[test]
    fn corrupt_compression_creates_a_reported_hole_instead_of_zeroes() {
        let bytes = vec![b'a'; 4096];
        let mut file = modern(&bytes, false);
        file[4108..4112].fill(255);
        let img = image(&file);
        assert!(img.segments.is_empty());
        assert_eq!(img.hibernation.as_ref().unwrap().info.diagnostics.len(), 1);
        assert!(img.read(0, &mut [0; 1]).is_err());
    }
    #[test]
    fn huffman_stream_is_decoded_with_exact_output_size() {
        let mut payload = vec![0x88; 128];
        payload.resize(256, 0);
        payload.extend_from_slice(&[b'b'; 4096]);
        payload.extend_from_slice(&[0; 8]);
        let mut file = vec![0; 4096];
        file[..4].copy_from_slice(b"HIBR");
        file[12..16].copy_from_slice(&0x3e0u32.to_le_bytes());
        file[24..28].copy_from_slice(&4096u32.to_le_bytes());
        file[0x68..0x70].copy_from_slice(&1u64.to_le_bytes());
        file[0x228..0x230].copy_from_slice(&1u64.to_le_bytes());
        file.extend_from_slice(&(0x80000001u32 | ((payload.len() as u32) << 8)).to_le_bytes());
        file.extend_from_slice(&0u64.to_le_bytes());
        file.extend_from_slice(&payload);
        let img = image(&file);
        let mut out = [0; 4096];
        img.read(0, &mut out).unwrap();
        assert_eq!(out, [b'b'; 4096]);
    }
    #[test]
    fn cache_is_bounded_and_modified_sources_are_rejected() {
        use std::io::Write;
        let file = modern(&vec![0; 4096 * 140], false);
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(&file).unwrap();
        let img = Image::from_file(source.reopen().unwrap(), "cache-test".into()).unwrap();
        let mut page = [0; 4096];
        for i in 0..140 {
            img.read(i * 4096, &mut page).unwrap();
        }
        assert_eq!(
            img.hibernation
                .as_ref()
                .unwrap()
                .cache
                .lock()
                .unwrap()
                .bytes
                .len(),
            128
        );
        source.write_all(&[0]).unwrap();
        assert!(img.read(0, &mut page).is_err());
    }
    #[test]
    fn x86_legacy_and_modern_descriptors_use_four_byte_fields() {
        let bytes = vec![0x5a; 4096];
        let compressed = literals(&bytes);
        for legacy in [false, true] {
            let mut file = vec![0; if legacy { 0x7000 } else { 4096 }];
            file[..4].copy_from_slice(b"HIBR");
            file[12..16].copy_from_slice(&(if legacy { 224u32 } else { 0x200u32 }).to_le_bytes());
            file[20..24].copy_from_slice(&4096u32.to_le_bytes());
            if legacy {
                file[80..84].copy_from_slice(&6u32.to_le_bytes());
                file[0x6004..0x6008].copy_from_slice(&1u32.to_le_bytes());
                file[0x6008..0x600c].copy_from_slice(&2u32.to_le_bytes());
                file[0x600c..0x6010].copy_from_slice(&3u32.to_le_bytes());
                let mut header = [0; 32];
                header[..8].copy_from_slice(b"\x81\x81xpress");
                header[8..12].copy_from_slice(&((compressed.len() as u32 - 1) << 10).to_le_bytes());
                file.extend_from_slice(&header);
            } else {
                file[0x50..0x54].copy_from_slice(&1u32.to_le_bytes());
                file.extend_from_slice(&(((compressed.len() as u32) << 8) | 1).to_le_bytes());
                file.extend_from_slice(&32u32.to_le_bytes());
            }
            file.extend_from_slice(&compressed);
            let img = image(&file);
            let mut page = [0; 4096];
            img.read(8192, &mut page).unwrap();
            assert_eq!(page, [0x5a; 4096]);
            assert!(img.read(0, &mut page).is_err());
            assert_eq!(
                img.windows_container.as_ref().unwrap().architecture,
                Architecture::X86
            );
        }
    }
}
