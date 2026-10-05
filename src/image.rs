//! Read-only physical address space. LiME holes are errors, never zero filled.
use crate::Job;
use anyhow::{Context, Result, bail, ensure};
use flate2::read::MultiGzDecoder;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::FileExt,
    path::Path,
};

#[derive(Clone, Debug)]
pub struct Segment {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
}
pub struct Image {
    file: File,
    _cache_guard: Option<File>,
    pub(crate) arm64_va_bits: std::sync::atomic::AtomicU8,
    windows: std::sync::OnceLock<Vec<crate::windows_symbols::Candidate>>,
    pub(crate) windows_roots: std::sync::Mutex<std::collections::HashMap<String, (u64, u64)>>,
    banners: std::sync::OnceLock<Vec<(u64, Vec<u8>)>>,
    pub segments: Vec<Segment>,
    pub digest: String,
    pub format: &'static str,
}
pub fn digest_reader(mut reader: impl Read, job: &Job) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buf = vec![0; 4 * 1024 * 1024];
    let mut total = 0;
    loop {
        job.check()?;
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        total += n;
        job.report(format!("镜像摘要: {} MiB", total / 1048576));
    }
    Ok(format!("{:x}", hash.finalize()))
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Identification {
    source_stamp: String,
    prepared: std::path::PathBuf,
    prepared_stamp: String,
    banners: Vec<(u64, Vec<u8>)>,
}
#[derive(Default)]
struct Fingerprint {
    hash: Sha256,
    tail: Vec<u8>,
    offset: u64,
    found: Vec<u64>,
}
impl Fingerprint {
    fn push(&mut self, bytes: &[u8], job: &Job) {
        self.hash.update(bytes);
        let needle = b"Linux version ";
        let overlap = self.tail.len();
        let mut boundary = self.tail.clone();
        boundary.extend_from_slice(&bytes[..bytes.len().min(needle.len() - 1)]);
        let crossed = memchr::memmem::find_iter(&boundary, needle)
            .filter(|i| *i < overlap && *i + needle.len() > overlap)
            .map(|i| self.offset - overlap as u64 + i as u64);
        let within = memchr::memmem::find_iter(bytes, needle).map(|i| self.offset + i as u64);
        for position in crossed.chain(within) {
            self.found.push(position);
            job.report(format!(
                "发现 banner 候选 @ 文件偏移 {position:#x}（尚未验证）"
            ));
        }
        if bytes.len() >= needle.len() - 1 {
            self.tail.clear();
            self.tail
                .extend_from_slice(&bytes[bytes.len() - (needle.len() - 1)..]);
        } else {
            self.tail.extend_from_slice(bytes);
            let keep = self.tail.len().min(needle.len() - 1);
            let start = self.tail.len() - keep;
            self.tail.copy_within(start.., 0);
            self.tail.truncate(keep);
        }
        self.offset += bytes.len() as u64;
        job.report(format!("摘要与候选扫描: {} MiB", self.offset / 1048576));
    }
    fn finish(self) -> (String, Vec<u64>) {
        (format!("{:x}", self.hash.finalize()), self.found)
    }
}
fn fingerprint(mut reader: impl Read, total: u64, job: &Job) -> Result<(String, Vec<u64>)> {
    let mut scan = Fingerprint::default();
    let mut buf = vec![0; 4 * 1024 * 1024];
    loop {
        job.check()?;
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        scan.push(&buf[..n], job);
        job.report(format!(
            "摘要与候选扫描: {} / {} MiB · {}%",
            scan.offset / 1048576,
            total / 1048576,
            scan.offset.saturating_mul(100) / total.max(1)
        ));
    }
    Ok(scan.finish())
}
impl Image {
    pub fn open(path: &Path, cache: &Path, job: &Job) -> Result<Self> {
        let started = std::time::Instant::now();
        let source_stamp = metadata_stamp(&fs::metadata(path)?)?;
        let identity = format!(
            "{:x}",
            Sha256::digest(path.canonicalize()?.to_string_lossy().as_bytes())
        );
        let identification = cache
            .join("identification")
            .join(format!("{identity}.json"));
        let guard = crate::cache::lock(cache, false)?;
        if let Ok(metadata) = fs::metadata(&identification)
            && metadata.len() <= 1024 * 1024
            && let Ok(bytes) = fs::read(&identification)
            && let Ok(value) = serde_json::from_slice::<Identification>(&bytes)
            && value.source_stamp == source_stamp
            && let Ok(file) = File::open(&value.prepared)
            && metadata_stamp(&file.metadata()?)? == value.prepared_stamp
            && let Ok(preview) = Self::from_file(file, String::new())
        {
            for (address, banner) in value.banners.into_iter().take(1024) {
                if banner.len() > 65536 {
                    continue;
                }
                let mut current = vec![0; banner.len()];
                if preview.read(address, &mut current).is_ok() && current == banner {
                    job.report(format!(
                        "缓存内核候选 {address:#x}: {}（内容摘要／页表尚待验证）",
                        String::from_utf8_lossy(&banner).trim_end_matches('\0')
                    ));
                }
            }
        }
        job.report("计算镜像摘要与识别候选");
        let mut magic = [0; 2];
        File::open(path)
            .with_context(|| format!("无法打开镜像 {}", path.display()))?
            .read_exact(&mut magic)?;
        let (prepared, digest, candidates) = if magic == [0x1f, 0x8b] {
            let source = digest_reader(File::open(path)?, job)?;
            let target = cache.join(format!("{source}.image"));
            let marker = cache.join(format!("{source}.sha256"));
            let existing = if target.exists() && marker.exists() {
                let (hash, found) =
                    fingerprint(File::open(&target)?, fs::metadata(&target)?.len(), job)?;
                (hash == fs::read_to_string(&marker)?.trim()).then_some((hash, found))
            } else {
                None
            };
            let (digest, found) = if let Some(value) = existing {
                value
            } else {
                let mut temporary = tempfile::NamedTempFile::new_in(cache)?;
                let mut decoder = MultiGzDecoder::new(File::open(path)?);
                let mut scan = Fingerprint::default();
                let mut buf = vec![0; 4 * 1024 * 1024];
                loop {
                    job.check()?;
                    let n = decoder
                        .read(&mut buf)
                        .context("gzip 解压失败（文件损坏或截断）")?;
                    if n == 0 {
                        break;
                    }
                    temporary.write_all(&buf[..n])?;
                    scan.push(&buf[..n], job);
                    job.report(format!("解压: {} MiB", scan.offset / 1048576));
                }
                job.check()?;
                temporary.as_file().sync_all()?;
                temporary.persist(&target).map_err(|e| e.error)?;
                let value = scan.finish();
                crate::store::atomic_write(&marker, value.0.as_bytes())?;
                value
            };
            (target, digest, found)
        } else {
            let (digest, found) = fingerprint(File::open(path)?, fs::metadata(path)?.len(), job)?;
            (path.to_path_buf(), digest, found)
        };
        let mut image = Self::from_file(File::open(&prepared)?, digest)?;
        image._cache_guard = Some(guard);
        let mut physical = Vec::new();
        for offset in candidates {
            if let Some(s) = image
                .segments
                .iter()
                .find(|s| offset >= s.file_offset && offset < s.file_offset + s.end - s.start)
            {
                physical.push(s.start + offset - s.file_offset);
            }
        }
        // File headers interrupt otherwise contiguous physical memory in LiME.
        for pair in image.segments.windows(2) {
            if pair[0].end == pair[1].start {
                let start = pair[0].end.saturating_sub(12).max(pair[0].start);
                let mut bytes = vec![0; (pair[1].end.min(pair[1].start + 12) - start) as usize];
                image.read(start, &mut bytes)?;
                physical.extend(
                    memchr::memmem::find_iter(&bytes, b"Linux version ").map(|n| start + n as u64),
                );
            }
        }
        physical.sort_unstable();
        physical.dedup();
        let found = image.read_banners(physical, job)?;
        let count = found.len();
        ensure!(
            source_stamp == metadata_stamp(&fs::metadata(path)?)?,
            "镜像在读取过程中发生变化，请重新打开"
        );
        job.check()?;
        crate::store::atomic_write(
            &identification,
            &serde_json::to_vec(&Identification {
                source_stamp,
                prepared: prepared.canonicalize()?,
                prepared_stamp: image.stamp()?,
                banners: found.clone(),
            })?,
        )?;
        let _ = image.banners.set(found);
        job.report(format!(
            "镜像摘要与候选扫描完成: {count} 个候选 · {:.3}s（待符号／页表验证）",
            started.elapsed().as_secs_f64()
        ));
        Ok(image)
    }
    pub fn from_file(file: File, digest: String) -> Result<Self> {
        let len = file.metadata()?.len();
        ensure!(len >= 4, "镜像过短");
        let mut magic = [0; 4];
        file.read_exact_at(&mut magic, 0)?;
        ensure!(
            &magic != b"PAGE" && &magic != b"MDMP" && &magic != b"hibr" && &magic != b"wake",
            "不支持 Windows 崩溃转储/休眠容器；请提供 RAW 物理内存镜像"
        );
        let mut segments = Vec::new();
        let format = if u32::from_le_bytes(magic) == 0x4c694d45 {
            let mut pos = 0;
            while pos < len {
                ensure!(len - pos >= 32, "LiME 头部截断 @ {pos:#x}");
                let mut h = [0; 32];
                file.read_exact_at(&mut h, pos)?;
                ensure!(
                    u32::from_le_bytes(h[0..4].try_into()?) == 0x4c694d45,
                    "LiME magic 错误 @ {pos:#x}"
                );
                ensure!(
                    u32::from_le_bytes(h[4..8].try_into()?) == 1,
                    "不支持的 LiME 版本"
                );
                let start = u64::from_le_bytes(h[8..16].try_into()?);
                let last = u64::from_le_bytes(h[16..24].try_into()?);
                let end = last.checked_add(1).context("LiME 地址溢出")?;
                ensure!(start < end, "LiME 范围无效");
                let offset = pos + 32;
                pos = offset.checked_add(end - start).context("LiME 长度溢出")?;
                ensure!(pos <= len, "LiME 数据截断");
                segments.push(Segment {
                    start,
                    end,
                    file_offset: offset,
                });
            }
            segments.sort_by_key(|s| s.start);
            ensure!(
                segments.windows(2).all(|s| s[0].end <= s[1].start),
                "LiME 范围重叠"
            );
            "LiME"
        } else {
            segments.push(Segment {
                start: 0,
                end: len,
                file_offset: 0,
            });
            "RAW"
        };
        Ok(Self {
            file,
            _cache_guard: None,
            arm64_va_bits: std::sync::atomic::AtomicU8::new(0),
            windows: std::sync::OnceLock::new(),
            windows_roots: std::sync::Mutex::new(std::collections::HashMap::new()),
            banners: std::sync::OnceLock::new(),
            segments,
            digest,
            format,
        })
    }
    pub fn read(&self, mut address: u64, mut out: &mut [u8]) -> Result<()> {
        address
            .checked_add(out.len() as u64)
            .context("物理地址溢出")?;
        while !out.is_empty() {
            let s = self
                .segments
                .iter()
                .find(|s| address >= s.start && address < s.end)
                .with_context(|| format!("物理地址越界或 LiME 空洞 @ {address:#x}"))?;
            let n = out.len().min((s.end - address) as usize);
            self.file
                .read_exact_at(&mut out[..n], s.file_offset + address - s.start)?;
            address += n as u64;
            out = &mut out[n..];
        }
        Ok(())
    }
    pub fn u64(&self, address: u64) -> Result<u64> {
        let mut b = [0; 8];
        self.read(address, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    /// Single prefix scan shared by local and remote symbol matching.
    pub fn windows_candidates(&self, job: &Job) -> Result<&[crate::windows_symbols::Candidate]> {
        if self.windows.get().is_none() {
            let found = crate::windows_symbols::identify(self, job)?;
            let _ = self.windows.set(found);
        }
        Ok(self.windows.get().context("Windows 识别未完成")?)
    }
    pub fn banners(&self, job: &Job) -> Result<Vec<(u64, Vec<u8>)>> {
        job.check()?;
        if let Some(banners) = self.banners.get() {
            return Ok(banners.clone());
        }
        let found = self.read_banners(self.scan(b"Linux version ", job)?, job)?;
        let _ = self.banners.set(found.clone());
        Ok(found)
    }
    fn read_banners(&self, candidates: Vec<u64>, job: &Job) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut found = Vec::new();
        for address in candidates {
            job.check()?;
            let mut end = self
                .segments
                .iter()
                .find(|s| address >= s.start && address < s.end)
                .context("banner 物理地址无效")?
                .end;
            while let Some(next) = self.segments.iter().find(|s| s.start == end) {
                end = next.end;
            }
            let mut bytes = vec![0; (end - address).min(65536) as usize];
            self.read(address, &mut bytes)?;
            if !bytes.starts_with(b"Linux version ") {
                continue;
            }
            if let Some(end) = bytes.iter().position(|b| *b == 0) {
                bytes.truncate(end + 1);
                if bytes[..end]
                    .iter()
                    .all(|b| !matches!(b,0..=8|11|12|14..=31|127))
                {
                    found.push((address, bytes));
                }
            }
        }
        Ok(found)
    }
    pub fn stamp(&self) -> Result<String> {
        metadata_stamp(&self.file.metadata()?)
    }
    pub fn scan(&self, needle: &[u8], job: &Job) -> Result<Vec<u64>> {
        ensure!(
            !needle.is_empty() && needle.len() <= 65536,
            "扫描模式长度无效"
        );
        let mut found = Vec::new();
        let mut tail = Vec::new();
        let mut previous_end = None;
        for s in &self.segments {
            if previous_end != Some(s.start) {
                tail.clear();
            }
            let mut position = s.start;
            while position < s.end {
                job.check()?;
                let n = (s.end - position).min(4 * 1024 * 1024) as usize;
                let overlap = tail.len();
                tail.resize(overlap + n, 0);
                self.read(position, &mut tail[overlap..])?;
                for index in memchr::memmem::find_iter(&tail, needle) {
                    found.push(position - overlap as u64 + index as u64);
                }
                let keep = (needle.len() - 1).min(tail.len());
                tail = tail[tail.len() - keep..].to_vec();
                position += n as u64;
                job.report(format!("扫描候选: {position:#x}"));
            }
            previous_end = Some(s.end);
        }
        found.sort_unstable();
        found.dedup();
        Ok(found)
    }
}
pub struct VirtualMemory<'a> {
    pub image: &'a Image,
    pub root: u64,
}
impl VirtualMemory<'_> {
    pub fn translate(&self, va: u64) -> Result<u64> {
        let bits = self
            .image
            .arm64_va_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        if bits != 0 {
            ensure!(matches!(bits, 39 | 48), "不支持的 ARM64 VA_BITS {bits}");
            let mask = (1u64 << bits) - 1;
            // Tagged userspace pointers are not silently normalized.
            ensure!(
                va & !mask == 0 || va & !mask == !mask,
                "ARM64 非 canonical 地址 {va:#x}"
            );
            let mut table = self.root & 0x0000_ffff_ffff_f000;
            let levels: &[u32] = if bits == 48 {
                &[39, 30, 21, 12]
            } else {
                &[30, 21, 12]
            };
            for &shift in levels {
                let entry = self.image.u64(table + ((va >> shift) & 511) * 8)?;
                ensure!(entry & 1 != 0, "ARM64 缺页 VA {va:#x} level {shift}");
                let base = entry & 0x0000_ffff_ffff_f000;
                if entry & 2 == 0 {
                    ensure!(shift == 30 || shift == 21, "ARM64 非法块描述符");
                    let offset = (1u64 << shift) - 1;
                    ensure!(base & offset == 0, "ARM64 块地址未对齐");
                    return Ok(base | (va & offset));
                }
                table = base;
            }
            return Ok(table | (va & 4095));
        }
        ensure!(
            va >> 47 == 0 || va >> 47 == 0x1ffff,
            "非四级页表 canonical 地址 {va:#x}"
        );
        let mut table = self.root & 0x000f_ffff_ffff_f000;
        for shift in [39, 30, 21, 12] {
            let entry = self
                .image
                .u64(table + ((va >> shift) & 511) * 8)
                .with_context(|| format!("页表读取失败 VA {va:#x}, level {shift}"))?;
            ensure!(entry & 1 != 0, "缺页 VA {va:#x}, level {shift}");
            if entry & 128 != 0 && shift != 12 {
                ensure!(shift == 30 || shift == 21, "非法大页 level {shift}");
                let mask = (1u64 << shift) - 1;
                return Ok((entry & 0x000f_ffff_ffff_f000 & !mask) | (va & mask));
            }
            table = entry & 0x000f_ffff_ffff_f000;
        }
        Ok(table | (va & 4095))
    }
    pub fn read(&self, mut va: u64, mut out: &mut [u8]) -> Result<()> {
        va.checked_add(out.len() as u64).context("虚拟地址溢出")?;
        while !out.is_empty() {
            let n = out.len().min(4096 - (va & 4095) as usize);
            self.image.read(self.translate(va)?, &mut out[..n])?;
            va += n as u64;
            out = &mut out[n..];
        }
        Ok(())
    }
    pub fn uint(&self, va: u64, size: usize) -> Result<u64> {
        ensure!(matches!(size, 1 | 2 | 4 | 8), "不支持的整数字段大小 {size}");
        let mut b = [0; 8];
        self.read(va, &mut b[..size])?;
        Ok(u64::from_le_bytes(b))
    }
    pub fn string(&self, va: u64, len: usize) -> Result<String> {
        ensure!((1..=4096).contains(&len), "字符串长度无效");
        let mut b = vec![0; len];
        self.read(va, &mut b)?;
        let end = b.iter().position(|b| *b == 0).unwrap_or(len);
        if b[..end].iter().any(|b| *b < 32 || *b == 127) {
            bail!("对象字符串含控制字符 @ {va:#x}");
        }
        Ok(String::from_utf8_lossy(&b[..end]).into_owned())
    }
}

pub fn metadata_stamp(metadata: &std::fs::Metadata) -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    Ok(format!(
        "{}:{}:{}:{}:{}:{}:{}",
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec()
    ))
}
#[cfg(test)]
mod arm_tests {
    use super::*;
    use crate::extended::tests::{fixture, image};
    fn put(b: &mut [u8], p: usize, v: u64) {
        b[p..p + 8].copy_from_slice(&v.to_le_bytes());
    }
    #[test]
    fn arm64_page_block_canonical_and_missing() {
        let (mut b, _) = fixture();
        put(&mut b, 0x3000, 1);
        let img = image(&b);
        img.arm64_va_bits
            .store(48, std::sync::atomic::Ordering::Relaxed);
        let vm = VirtualMemory {
            image: &img,
            root: 0x1000,
        };
        assert_eq!(vm.translate(0x12345).unwrap(), 0x12345);
        let user = VirtualMemory {
            image: &img,
            root: 0x4000,
        };
        assert_eq!(user.translate(0x200ffe).unwrap(), 0x20ffe);
        let mut bytes = [0; 4];
        user.read(0x200ffe, &mut bytes).unwrap();
        assert_eq!(bytes, [b'a', 0, b'b', b'=']);
        assert!(user.translate(0x202000).is_err());
        assert!(user.translate(0xab00000000200000).is_err());
        img.arm64_va_bits
            .store(39, std::sync::atomic::Ordering::Relaxed);
        let vm = VirtualMemory {
            image: &img,
            root: 0x2000,
        };
        assert_eq!(vm.translate(0x12345).unwrap(), 0x12345);
        assert!(vm.translate(1 << 39).is_err());
        put(&mut b, 0x3000, 0x1001);
        let img = image(&b);
        img.arm64_va_bits
            .store(48, std::sync::atomic::Ordering::Relaxed);
        assert!(
            VirtualMemory {
                image: &img,
                root: 0x1000
            }
            .translate(0)
            .is_err()
        );
    }
}
