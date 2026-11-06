//! Read-only physical address space. LiME holes are errors, never zero filled.
use crate::Job;
use crate::bytes::Checked as _;
use anyhow::{Context, Result, bail, ensure};
use flate2::read::MultiGzDecoder;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::FileExt,
    path::Path,
    thread,
};

#[derive(Clone, Debug)]
pub struct Segment {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
}
pub struct Image {
    pub limits: crate::resources::Limits,
    file: File,
    _cache_guard: Option<File>,
    pub(crate) arm64_va_bits: std::sync::atomic::AtomicU8,
    windows: std::sync::OnceLock<Vec<crate::windows_symbols::Candidate>>,
    pub(crate) windows_roots: std::sync::Mutex<std::collections::HashMap<String, (u64, u64)>>,
    /// Kernel roots validated in an earlier session, keyed by ISF digest.
    /// Discovery must validate a hint again before trusting it.
    pub(crate) persisted_roots: std::collections::HashMap<String, (u64, u64)>,
    /// Identification manifest this image was opened against and the content
    /// digest that manifest describes; Windows preparation is remembered there.
    identification: Option<(std::path::PathBuf, String)>,
    banners: std::sync::OnceLock<Vec<(u64, Vec<u8>)>>,
    /// Physical RSDS offsets collected by the digest pass, equal to `scan(b"RSDS")`.
    rsds: std::sync::OnceLock<Vec<u64>>,
    /// Completed physical scans keyed by needle; the image is read-only.
    scans: std::sync::Mutex<crate::resources::Lru<Vec<u8>, std::sync::Arc<[u64]>>>,
    /// Whole 4 KiB pages behind small physical reads (fields, page-table entries).
    physical: std::sync::Mutex<PhysicalPages>,
    pub segments: Vec<Segment>,
    pub digest: String,
    pub format: &'static str,
    pub windows_container: Option<crate::windows::container::Metadata>,
    pub hibernation: Option<crate::windows::hiber::Hibernation>,
}
/// Slots of the direct-mapped physical page cache (4 MiB when full).
const PHYSICAL_SLOTS: u64 = 1024;
/// Direct-mapped: one slot per page frame number modulo the slot count, so a
/// lookup is a single compare and eviction needs no bookkeeping. Only pages
/// lying wholly inside one segment are cached; the image never changes.
#[derive(Default)]
struct PhysicalPages {
    slots: Vec<Option<(u64, Box<[u8; 4096]>)>>,
}
/// Read-ahead chunk for image digesting.
const DIGEST_CHUNK: usize = 4 * 1024 * 1024;
pub fn digest_reader(mut reader: impl Read, job: &Job) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buf = vec![0; DIGEST_CHUNK];
    let mut total = 0u64;
    let mut reported = 0u64;
    loop {
        job.check()?;
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(buf.at(..n)?);
        total += n as u64;
        // Progress is per 64 MiB: a multi-gigabyte image would otherwise emit
        // hundreds of formatted strings for a bar that cannot show them.
        if total - reported >= 64 * 1024 * 1024 {
            reported = total;
            job.report(format!("镜像摘要: {} MiB", total / 1048576));
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}
/// Digest a file with the read and the hash overlapping.
///
/// SHA256 runs at roughly half the throughput of the disk read on a warm page
/// cache, and the two are serial in `digest_reader`. A small pool of buffers
/// lets one thread read ahead while this one hashes, which measured 26% faster
/// on a 3.7 GB image. The chunk order, and therefore the digest, is unchanged.
pub fn digest_file(file: File, job: &Job) -> Result<String> {
    use std::sync::mpsc;
    let (free_tx, free_rx) = mpsc::channel::<Vec<u8>>();
    let (full_tx, full_rx) = mpsc::channel::<(Vec<u8>, usize)>();
    // Two buffers bound the extra memory at 8 MiB while keeping the reader one
    // chunk ahead; deeper queues measured no faster.
    for _ in 0..2 {
        free_tx.send(vec![0; DIGEST_CHUNK])?;
    }
    let reader = thread::spawn(move || -> Result<()> {
        let mut file = file;
        while let Ok(mut buf) = free_rx.recv() {
            let n = file.read(&mut buf)?;
            if n == 0 || full_tx.send((buf, n)).is_err() {
                break;
            }
        }
        Ok(())
    });
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut reported = 0u64;
    while let Ok((buf, n)) = full_rx.recv() {
        job.check()?;
        hash.update(buf.at(..n)?);
        total += n as u64;
        if total - reported >= 64 * 1024 * 1024 {
            reported = total;
            job.report(format!("镜像摘要: {} MiB", total / 1048576));
        }
        let _ = free_tx.send(buf);
    }
    drop(free_tx);
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("摘要读取线程异常"))??;
    Ok(format!("{:x}", hash.finalize()))
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Identification {
    source_stamp: String,
    prepared: std::path::PathBuf,
    prepared_stamp: String,
    banners: Vec<(u64, Vec<u8>)>,
    /// Content SHA256 the Windows fields below were derived from. They are
    /// only reused after `open` recomputes the same digest.
    #[serde(default)]
    digest: String,
    /// Kernel RSDS records (physical offset, PDB identity).
    #[serde(default)]
    windows: Option<Vec<(u64, crate::windows_symbols::PdbIdentity)>>,
    /// Validated kernel roots: (ISF digest, DTB, kernel base). Hints only;
    /// discovery re-runs the full kernel validation before using one.
    #[serde(default)]
    windows_roots: Vec<(String, u64, u64)>,
    /// Whether `digest` may stand in for a new full pass: the source had not
    /// been modified for `SETTLED` when it was recorded, so any later write
    /// lands on a later timestamp tick and changes `source_stamp`.
    #[serde(default)]
    digest_reusable: bool,
    /// `content_sample` of the prepared file, checked before reusing `digest`.
    #[serde(default)]
    sample: String,
}
/// How long a source must have been unmodified before its digest may be reused.
/// Filesystem timestamps come from a coarse clock (ext4: a few ms), so two
/// writes inside one tick look identical; a settled file cannot hit that.
const SETTLED: std::time::Duration = std::time::Duration::from_secs(2);
/// Whether `path` has gone unmodified for `SETTLED`, so a later write must show
/// up as a different metadata stamp.
pub fn settled(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age >= SETTLED)
}
/// SHA256 over the size and 16 evenly spaced 64 KiB blocks: about 1 MiB of
/// reads that must match before a recorded digest is reused.
fn content_sample(file: &File) -> Result<String> {
    use std::os::unix::fs::FileExt;
    const BLOCK: u64 = 64 * 1024;
    let len = file.metadata()?.len();
    let mut hash = Sha256::new();
    hash.update(len.to_le_bytes());
    let mut buf = vec![0; usize::try_from(BLOCK)?];
    for index in 0..16u64 {
        let offset = len.saturating_sub(BLOCK) * index / 15;
        let n = usize::try_from(BLOCK.min(len - offset))?;
        file.read_exact_at(buf.at_mut(..n)?, offset)?;
        hash.update(offset.to_le_bytes());
        hash.update(buf.at(..n)?);
    }
    Ok(format!("{:x}", hash.finalize()))
}
/// What an identification manifest offers beyond banners and signatures.
struct Reuse {
    /// Remembered Windows kernel roots (ISF digest, DTB, base); hints only.
    roots: Vec<(String, u64, u64)>,
    /// The recorded content digest, when it may replace a full pass.
    digest: Option<String>,
}
/// Needles collected by the digest pass: Linux banners and Windows RSDS
/// debug records, so identification needs no second pass over the file.
const FINGERPRINT_NEEDLES: [&[u8]; 2] = [b"Linux version ", b"RSDS"];
const FINGERPRINT_TAIL: usize = 13;
/// Pool tags read by the Windows scanning plugins. The digest pass records
/// them too, so pool scans need no second read of the whole image; anything
/// it could not record is still found by one `prefetch_scans` pass.
pub(crate) const POOL_TAGS: &[&[u8]] = &[
    b"File", b"Fil\xe5", b"Muta", b"Mut\xe1", b"Driv", b"Dri\xf6", b"Proc", b"Pro\xe3", b"TcpL",
    b"UdpA", b"TcpE", b"TTcb", b"MmLd", b"Symb", b"Sym\xe2", b"CM10",
];
/// Hits kept per pool tag in the digest pass. A tag past this is dropped and
/// left to `prefetch_scans`, so an unusual image cannot grow memory unbounded.
const POOL_HIT_LIMIT: usize = 1 << 22;
/// Distinct three-byte prefixes of `POOL_TAGS`. None overlaps itself, so a
/// non-overlapping search finds every occurrence; the fourth byte then picks
/// the tags. Ten prefix passes measured faster than one automaton or sixteen
/// whole-tag passes over memory images.
fn pool_prefixes() -> Vec<&'static [u8]> {
    let mut prefixes: Vec<&[u8]> = POOL_TAGS.iter().filter_map(|tag| tag.get(..3)).collect();
    prefixes.sort_unstable();
    prefixes.dedup();
    prefixes
}
/// (tag index, file offset) of every pool tag that starts in `boundary` before
/// `overlap` (the retained tail) or anywhere in `bytes`, which starts at
/// `offset`. No tag's suffix is a prefix of any tag (checked by a test), so
/// occurrences never overlap and none is hidden behind another.
fn pool_hits(boundary: &[u8], overlap: usize, bytes: &[u8], offset: u64) -> Vec<(usize, u64)> {
    let mut hits = Vec::new();
    let base = offset - overlap as u64;
    for (index, tag) in POOL_TAGS.iter().enumerate() {
        hits.extend(
            memchr::memmem::find_iter(boundary, tag)
                .filter(|at| *at < overlap)
                .map(|at| (index, base + at as u64)),
        );
    }
    for prefix in pool_prefixes() {
        for at in memchr::memmem::find_iter(bytes, prefix) {
            let Some(&last) = bytes.get(at + 3) else {
                // Completed by the next chunk's boundary search.
                continue;
            };
            for (index, tag) in POOL_TAGS.iter().enumerate() {
                if tag.get(..3) == Some(prefix) && tag.get(3) == Some(&last) {
                    hits.push((index, offset + at as u64));
                }
            }
        }
    }
    hits.sort_unstable_by_key(|(index, at)| (*at, *index));
    hits
}
#[derive(Default)]
struct Fingerprint {
    hash: Sha256,
    tail: Vec<u8>,
    offset: u64,
    /// File offsets of each needle in `FINGERPRINT_NEEDLES`.
    found: [Vec<u64>; 2],
    /// File offsets of each pool tag; `None` once a tag passed the limit.
    pool: Vec<Option<Vec<u64>>>,
}
/// File offsets found by the digest pass.
struct Found {
    banners: Vec<u64>,
    rsds: Vec<u64>,
    /// Per `POOL_TAGS` entry; empty when no matcher could be built.
    pool: Vec<Option<Vec<u64>>>,
}
impl Fingerprint {
    /// Hash `bytes` and record the pool tags in it. The tag search runs on a
    /// scoped thread beside the hash, so the pass costs the slower of the two
    /// rather than their sum; if no thread can be started it runs inline.
    fn hash_and_pool(&mut self, bytes: &[u8]) {
        let overlap = self.tail.len().min(3);
        let mut boundary = [0u8; 6];
        let tail = self.tail.get(self.tail.len() - overlap..).unwrap_or(&[]);
        let head = bytes.get(..bytes.len().min(3)).unwrap_or(&[]);
        if let Some(start) = boundary.get_mut(..overlap) {
            start.copy_from_slice(tail);
        }
        if let Some(end) = boundary.get_mut(overlap..overlap + head.len()) {
            end.copy_from_slice(head);
        }
        let boundary = boundary.get(..overlap + head.len()).unwrap_or(&[]);
        let offset = self.offset;
        let hash = &mut self.hash;
        let hits = thread::scope(|scope| {
            let worker = thread::Builder::new()
                .spawn_scoped(scope, || pool_hits(boundary, overlap, bytes, offset));
            hash.update(bytes);
            match worker {
                Ok(worker) => worker.join().ok(),
                Err(_) => Some(pool_hits(boundary, overlap, bytes, offset)),
            }
        });
        if self.pool.is_empty() {
            self.pool = vec![Some(Vec::new()); POOL_TAGS.len()];
        }
        let Some(hits) = hits else {
            // A failed search cannot vouch for absence: leave every tag to
            // `prefetch_scans`.
            self.pool.iter_mut().for_each(|slot| *slot = None);
            return;
        };
        for (pattern, position) in hits {
            if let Some(slot) = self.pool.get_mut(pattern) {
                if slot
                    .as_ref()
                    .is_some_and(|found| found.len() >= POOL_HIT_LIMIT)
                {
                    *slot = None;
                }
                if let Some(found) = slot {
                    found.push(position);
                }
            }
        }
    }
    fn push(&mut self, bytes: &[u8], job: &Job) {
        self.hash_and_pool(bytes);
        for (index, needle) in FINGERPRINT_NEEDLES.iter().enumerate() {
            // Match the boundary first without allocating: a hit straddling two
            // chunks is only possible when the retained tail plus this chunk's
            // head contains the needle.
            let overlap = self.tail.len().min(needle.len() - 1);
            let tail = self.tail.get(self.tail.len() - overlap..).unwrap_or(&[]);
            if overlap > 0 && bytes.len() >= needle.len() {
                let head = bytes.get(..needle.len() - 1).unwrap_or(&[]);
                let mut boundary = [0u8; 32];
                if let Some(start) = boundary.get_mut(..overlap) {
                    start.copy_from_slice(tail);
                }
                if let Some(end) = boundary.get_mut(overlap..overlap + head.len()) {
                    end.copy_from_slice(head);
                }
                let boundary = boundary.get(..overlap + head.len()).unwrap_or(&[]);
                for i in memchr::memmem::find_iter(boundary, needle)
                    .filter(|i| *i < overlap && *i + needle.len() > overlap)
                {
                    let position = self.offset - overlap as u64 + i as u64;
                    if let Some(found) = self.found.get_mut(index) {
                        found.push(position);
                    }
                    if index == 0 {
                        job.report(format!(
                            "发现 banner 候选 @ 文件偏移 {position:#x}（尚未验证）"
                        ));
                    }
                }
            }
            for i in memchr::memmem::find_iter(bytes, needle) {
                let position = self.offset + i as u64;
                if let Some(found) = self.found.get_mut(index) {
                    found.push(position);
                }
                if index == 0 {
                    job.report(format!(
                        "发现 banner 候选 @ 文件偏移 {position:#x}（尚未验证）"
                    ));
                }
            }
        }
        let width = FINGERPRINT_TAIL;
        if bytes.len() >= width {
            self.tail.clear();
            self.tail
                .extend_from_slice(bytes.get(bytes.len() - width..).unwrap_or(&[]));
        } else {
            self.tail.extend_from_slice(bytes);
            let keep = self.tail.len().min(width);
            let start = self.tail.len() - keep;
            self.tail.copy_within(start.., 0);
            self.tail.truncate(keep);
        }
        self.offset += bytes.len() as u64;
    }
    fn finish(self) -> (String, Found) {
        let [banners, rsds] = self.found;
        (
            format!("{:x}", self.hash.finalize()),
            Found {
                banners,
                rsds,
                pool: self.pool,
            },
        )
    }
}
/// The digest pass. One thread reads ahead while this one hashes and matches,
/// as in `digest_file`; chunks are consumed in file order, so the digest and
/// every recorded offset are unchanged.
fn fingerprint(file: File, total: u64, job: &Job) -> Result<(String, Found)> {
    use std::sync::mpsc;
    let (free_tx, free_rx) = mpsc::channel::<Vec<u8>>();
    let (full_tx, full_rx) = mpsc::channel::<std::io::Result<(Vec<u8>, usize)>>();
    for _ in 0..2 {
        free_tx.send(vec![0; DIGEST_CHUNK])?;
    }
    let reader = thread::spawn(move || {
        let mut file = file;
        while let Ok(mut buf) = free_rx.recv() {
            let read = file.read(&mut buf).map(|n| (buf, n));
            let stop = !matches!(read, Ok((_, n)) if n > 0);
            if full_tx.send(read).is_err() || stop {
                break;
            }
        }
    });
    let outcome = (|| -> Result<(String, Found)> {
        let mut scan = Fingerprint::default();
        let mut reported = 0u64;
        while let Ok(read) = full_rx.recv() {
            job.check()?;
            let (buf, n) = read?;
            if n == 0 {
                break;
            }
            scan.push(buf.at(..n)?, job);
            let _ = free_tx.send(buf);
            // One update per 64 MiB: formatting a string per chunk is not free.
            if scan.offset - reported >= 64 * 1024 * 1024 {
                reported = scan.offset;
                job.report(format!(
                    "校验镜像 SHA256: {} / {} MiB · {}%",
                    scan.offset / 1048576,
                    total / 1048576,
                    scan.offset.saturating_mul(100) / total.max(1)
                ));
            }
        }
        Ok(scan.finish())
    })();
    // Closing both channels ends the reader whether it is waiting for a free
    // buffer or blocked handing over a full one.
    drop(free_tx);
    drop(full_rx);
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("摘要读取线程异常"))?;
    outcome
}
/// What an earlier identification bound to an image file: the system and its
/// kernel banners or PDB identities. Display only — it is returned while the
/// file's metadata stamp is unchanged, and analysis still verifies content.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BoundIdentity {
    pub system: &'static str,
    pub kernels: Vec<String>,
}
/// The identification manifest of an image while its metadata is unchanged.
fn current_manifest(path: &Path, cache: &Path) -> Option<Identification> {
    let source = path.canonicalize().ok()?;
    let identity = format!("{:x}", Sha256::digest(source.to_string_lossy().as_bytes()));
    let manifest = cache
        .join("identification")
        .join(format!("{identity}.json"));
    if fs::metadata(&manifest).ok()?.len() > 1024 * 1024 {
        return None;
    }
    let value: Identification = serde_json::from_slice(&fs::read(manifest).ok()?).ok()?;
    (value.source_stamp == metadata_stamp(&fs::metadata(&source).ok()?).ok()?).then_some(value)
}
/// The SHA256 the last full verification recorded for an image, while the
/// file's metadata is unchanged. Display only: it is not a fresh check.
pub fn recorded_digest(path: &Path, cache: &Path) -> Option<String> {
    current_manifest(path, cache).and_then(manifest_digest)
}
pub fn bound_identity(path: &Path, cache: &Path) -> Option<BoundIdentity> {
    manifest_identity(&current_manifest(path, cache)?)
}
/// `bound_identity` and `recorded_digest` from a single manifest read.
pub fn recorded_summary(path: &Path, cache: &Path) -> (Option<BoundIdentity>, Option<String>) {
    match current_manifest(path, cache) {
        Some(value) => (manifest_identity(&value), manifest_digest(value)),
        None => (None, None),
    }
}
fn manifest_digest(value: Identification) -> Option<String> {
    Some(value.digest).filter(|digest| digest.len() == 64)
}
fn manifest_identity(value: &Identification) -> Option<BoundIdentity> {
    let linux: Vec<String> = value
        .banners
        .iter()
        .map(|(_, banner)| {
            String::from_utf8_lossy(banner)
                .trim_end_matches(['\0', '\n'])
                .to_owned()
        })
        .collect();
    if !linux.is_empty() {
        return Some(BoundIdentity {
            system: "linux",
            kernels: linux,
        });
    }
    let mut windows: Vec<String> = value
        .windows
        .as_ref()?
        .iter()
        .map(|(_, pdb)| format!("Windows PDB {}", pdb.key()))
        .collect();
    windows.sort();
    windows.dedup();
    (!windows.is_empty()).then_some(BoundIdentity {
        system: "windows",
        kernels: windows,
    })
}
/// Physical offsets of `needle` from file offsets found by the digest pass,
/// exactly as `Image::scan` reports them: a hit counts only when it lies inside
/// one segment, and hits spanning physically contiguous segments are read back.
fn physical_hits(image: &Image, file_hits: &[u64], needle: &[u8]) -> Result<Vec<u64>> {
    let length = needle.len() as u64;
    let mut by_file: Vec<&Segment> = image.segments.iter().collect();
    by_file.sort_unstable_by_key(|s| s.file_offset);
    let mut physical = Vec::new();
    for &offset in file_hits {
        if let Some(s) = by_file.get(
            by_file
                .partition_point(|s| s.file_offset <= offset)
                .wrapping_sub(1),
        ) && offset + length <= s.file_offset + (s.end - s.start)
        {
            physical.push(s.start + offset - s.file_offset);
        }
    }
    for pair in image.segments.windows(2) {
        if pair.at(0)?.end == pair.at(1)?.start {
            let start = pair
                .at(0)?
                .end
                .saturating_sub(length - 1)
                .max(pair.at(0)?.start);
            let mut bytes =
                vec![
                    0;
                    usize::try_from(pair.at(1)?.end.min(pair.at(1)?.start + length - 1) - start)?
                ];
            image.read(start, &mut bytes)?;
            physical.extend(
                memchr::memmem::find_iter(&bytes, needle)
                    .map(|n| start + n as u64)
                    .filter(|hit| {
                        pair.first()
                            .is_some_and(|p| *hit < p.end && hit + length > p.end)
                    }),
            );
        }
    }
    physical.sort_unstable();
    physical.dedup();
    Ok(physical)
}
impl Image {
    /// Reopen an image from its identification manifest without reading the
    /// whole file: the file's metadata stamp (device, inode, size, mtime and
    /// ctime) must be unchanged and every remembered banner and RSDS record is
    /// read back. The digest stays empty; `identification` carries the digest
    /// the manifest recorded. Returns the remembered Windows kernel roots.
    fn from_manifest(path: &Path, cache: &Path, job: &Job) -> Result<(Self, Reuse)> {
        job.check()?;
        let source = path.canonicalize()?;
        let source_stamp = metadata_stamp(&fs::metadata(&source)?)?;
        let identity = format!("{:x}", Sha256::digest(source.to_string_lossy().as_bytes()));
        let manifest = cache
            .join("identification")
            .join(format!("{identity}.json"));
        ensure!(
            fs::metadata(&manifest)?.len() <= 1024 * 1024,
            "识别缓存过大"
        );
        let value: Identification = serde_json::from_slice(&fs::read(&manifest)?)?;
        ensure!(value.source_stamp == source_stamp, "镜像识别缓存已过期");
        let mut magic = [0; 2];
        File::open(&source)?.read_exact(&mut magic)?;
        if magic == [0x1f, 0x8b] {
            ensure!(
                value.prepared.parent() == Some(cache.canonicalize()?.as_path())
                    && value.prepared.extension().is_some_and(|s| s == "image")
                    && value.prepared.file_stem().is_some_and(|s| {
                        let name = s.to_string_lossy();
                        name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
                    }),
                "识别缓存解压路径无效"
            );
        } else {
            ensure!(value.prepared == source, "识别缓存镜像路径不匹配");
        }
        let file = File::open(&value.prepared)?;
        ensure!(
            metadata_stamp(&file.metadata()?)? == value.prepared_stamp,
            "识别缓存已过期"
        );
        let mut image = Self::from_file_with_job(file, String::new(), job)?;
        ensure!(value.banners.len() <= 1024, "识别缓存候选过多");
        let addresses = value.banners.iter().map(|(address, _)| *address).collect();
        ensure!(
            image.read_banners(addresses, job)? == value.banners,
            "缓存 banner 与镜像不一致"
        );
        ensure!(
            image.stamp()? == value.prepared_stamp
                && metadata_stamp(&fs::metadata(&source)?)? == source_stamp,
            "镜像在识别过程中发生变化"
        );
        job.check()?;
        let count = value.banners.len();
        let _ = image.banners.set(value.banners);
        job.report(format!(
            "复用持久化 banner 识别：{count} 个候选（banner 已重新读取）"
        ));
        // Windows kernel signatures follow the same rule as banners: the
        // file metadata must be unchanged and every record must re-read to
        // the same PDB identity. Analysis still verifies the digest.
        if let Some(records) = value.windows.filter(|records| image.verify_rsds(records)) {
            job.report(format!(
                "复用持久化 Windows 内核签名：{} 个（签名已重新读取）",
                records.len()
            ));
            let _ = image.windows.set(
                records
                    .into_iter()
                    .map(|(offset, pdb)| crate::windows_symbols::Candidate { offset, pdb })
                    .collect(),
            );
        }
        let digest = (value.digest_reusable
            && value.digest.len() == 64
            && content_sample(&image.file)? == value.sample)
            .then(|| value.digest.clone());
        image.identification = Some((manifest, value.digest));
        Ok((
            image,
            Reuse {
                roots: value.windows_roots,
                digest,
            },
        ))
    }
    /// Reuse persisted banners for identification and symbol matching. A cache
    /// hit has no verified digest of its own.
    pub fn open_identified(path: &Path, cache: &Path, job: &Job) -> Result<Self> {
        job.check()?;
        let guard = crate::cache::lock(cache, false)?;
        match Self::from_manifest(path, cache, job) {
            Ok((mut image, _)) => {
                image._cache_guard = Some(guard);
                Ok(image)
            }
            Err(_) => {
                job.check()?;
                drop(guard);
                Self::open(path, cache, job)
            }
        }
    }
    /// Open an image for analysis with a content digest. Only when settings opt
    /// in is the digest an earlier session computed reused, and then only while
    /// the file's metadata stamp and content sample are unchanged.
    pub fn open(path: &Path, cache: &Path, job: &Job) -> Result<Self> {
        let started = std::time::Instant::now();
        if crate::store::read_settings(cache).reuse_recorded_digest {
            let guard = crate::cache::lock(cache, false)?;
            if let Ok((mut image, reuse)) = Self::from_manifest(path, cache, job)
                && let Some(digest) = reuse.digest
            {
                image.digest = digest;
                image.persisted_roots = reuse
                    .roots
                    .into_iter()
                    .map(|(isf, root, base)| (isf, (root, base)))
                    .collect();
                image._cache_guard = Some(guard);
                job.report(format!(
                    "复用已记录的内容摘要 {}…（文件元数据与内容抽样一致）· {:.3}s",
                    &image.digest[..12],
                    started.elapsed().as_secs_f64()
                ));
                return Ok(image);
            }
            drop(guard);
        }
        let source_stamp = metadata_stamp(&fs::metadata(path)?)?;
        let identity = format!(
            "{:x}",
            Sha256::digest(path.canonicalize()?.to_string_lossy().as_bytes())
        );
        let identification = cache
            .join("identification")
            .join(format!("{identity}.json"));
        let guard = crate::cache::lock(cache, false)?;
        let mut previous = None;
        if let Ok(metadata) = fs::metadata(&identification)
            && metadata.len() <= 1024 * 1024
            && let Ok(bytes) = fs::read(&identification)
            && let Ok(value) = serde_json::from_slice::<Identification>(&bytes)
            && value.source_stamp == source_stamp
            && let Ok(file) = File::open(&value.prepared)
            && metadata_stamp(&file.metadata()?)? == value.prepared_stamp
            && let Ok(preview) = Self::from_file_with_job(file, String::new(), job)
        {
            for (address, banner) in value.banners.iter().take(1024) {
                let (address, banner) = (*address, banner.clone());
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
            previous = Some(value);
        }
        job.report("校验镜像 SHA256（同一遍读取识别内核签名）");
        job.mark_prepared();
        let mut magic = [0; 2];
        File::open(path)
            .with_context(|| format!("无法打开镜像 {}", path.display()))?
            .read_exact(&mut magic)?;
        let (prepared, digest, candidates) = if magic == [0x1f, 0x8b] {
            let source = digest_file(File::open(path)?, job)?;
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
                    temporary.write_all(buf.at(..n)?)?;
                    scan.push(buf.at(..n)?, job);
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
        let mut image = Self::from_file_with_job(File::open(&prepared)?, digest, job)?;
        image._cache_guard = Some(guard);
        let mut physical = Vec::new();
        if image.hibernation.is_some() {
            physical = image.scan(b"Linux version ", job)?;
        } else {
            let _ = image
                .rsds
                .set(physical_hits(&image, &candidates.rsds, b"RSDS")?);
            for (tag, hits) in POOL_TAGS.iter().zip(&candidates.pool) {
                if let Some(hits) = hits {
                    image.remember_scan(tag, &physical_hits(&image, hits, tag)?);
                }
            }
            for offset in candidates.banners {
                if let Some(s) = image
                    .segments
                    .iter()
                    .find(|s| offset >= s.file_offset && offset < s.file_offset + s.end - s.start)
                {
                    physical.push(s.start + offset - s.file_offset);
                }
            }
        }
        // File headers interrupt otherwise contiguous physical memory in LiME.
        for pair in image.segments.windows(2) {
            if pair.at(0)?.end == pair.at(1)?.start {
                let start = pair.at(0)?.end.saturating_sub(12).max(pair.at(0)?.start);
                let mut bytes =
                    vec![0; usize::try_from(pair.at(1)?.end.min(pair.at(1)?.start + 12) - start)?];
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
        // Windows preparation from an earlier session is reused only for the
        // same verified content, and only after its RSDS records still parse.
        let (windows, windows_roots) = match previous {
            Some(value) if !value.digest.is_empty() && value.digest == image.digest => {
                let windows = value.windows.filter(|records| image.verify_rsds(records));
                (windows, value.windows_roots)
            }
            _ => (None, Vec::new()),
        };
        if let Some(records) = &windows {
            let _ = image.windows.set(
                records
                    .iter()
                    .map(|(offset, pdb)| crate::windows_symbols::Candidate {
                        offset: *offset,
                        pdb: pdb.clone(),
                    })
                    .collect(),
            );
            job.report(format!(
                "复用持久化 Windows 内核签名：{} 个（内容摘要一致，签名已重新读取）",
                records.len()
            ));
        }
        image.persisted_roots = windows_roots
            .iter()
            .map(|(isf, root, base)| (isf.clone(), (*root, *base)))
            .collect();
        crate::store::atomic_write(
            &identification,
            &serde_json::to_vec(&Identification {
                source_stamp,
                prepared: prepared.canonicalize()?,
                prepared_stamp: image.stamp()?,
                banners: found.clone(),
                digest: image.digest.clone(),
                windows,
                windows_roots,
                digest_reusable: settled(path),
                sample: content_sample(&image.file)?,
            })?,
        )?;
        image.identification = Some((identification, image.digest.clone()));
        let _ = image.banners.set(found);
        job.report(format!(
            "镜像校验完成：SHA256 {}… · {count} 个内核候选 · {:.3}s（待符号／页表验证）",
            &image.digest[..12.min(image.digest.len())],
            started.elapsed().as_secs_f64()
        ));
        Ok(image)
    }
    pub fn from_file(file: File, digest: String) -> Result<Self> {
        Self::from_file_with_job(file, digest, &Job::default())
    }
    fn from_file_with_job(file: File, digest: String, job: &Job) -> Result<Self> {
        let len = file.metadata()?.len();
        ensure!(len >= 4, "镜像过短");
        let mut magic = [0; 4];
        file.read_exact_at(&mut magic, 0)?;
        let mut segments = Vec::new();
        let mut windows_container = None;
        let mut hibernation = None;
        let format = if &magic == b"PAGE" || &magic == b"MDMP" {
            let parsed = crate::windows::container::parse(&file, job)?;
            segments = parsed.segments;
            windows_container = Some(parsed.metadata);
            parsed.format
        } else if crate::windows::hiber::recognized(&magic) {
            let (parsed, metadata) = crate::windows::hiber::parse(&file, job)?;
            segments = parsed.segments();
            windows_container = Some(metadata);
            hibernation = Some(parsed);
            "Windows hibernation"
        } else if u32::from_le_bytes(magic) == 0x4c694d45 {
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
                segments
                    .windows(2)
                    .all(|s| matches!(s, [a, b] if a.end <= b.start)),
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
            persisted_roots: std::collections::HashMap::new(),
            identification: None,
            banners: std::sync::OnceLock::new(),
            rsds: std::sync::OnceLock::new(),
            limits: Default::default(),
            scans: std::sync::Mutex::new(crate::resources::Lru::new(
                crate::resources::Limits::default().scan_cache_bytes,
            )),
            physical: std::sync::Mutex::new(PhysicalPages::default()),
            segments,
            digest,
            format,
            windows_container,
            hibernation,
        })
    }
    pub fn read(&self, mut address: u64, mut out: &mut [u8]) -> Result<()> {
        if let Some(hiber) = &self.hibernation {
            return hiber.read(&self.file, address, out);
        }
        address
            .checked_add(out.len() as u64)
            .context("物理地址溢出")?;
        while !out.is_empty() {
            let s = self
                .segments
                .get(
                    self.segments
                        .partition_point(|s| s.start <= address)
                        .wrapping_sub(1),
                )
                .filter(|s| address < s.end)
                .with_context(|| {
                    if self.windows_container.is_some() {
                        format!("地址越界或镜像空洞 @ {address:#x}")
                    } else {
                        format!("物理地址越界或 LiME 空洞 @ {address:#x}")
                    }
                })?;
            let mut n = out.len().min(usize::try_from(s.end - address)?);
            let page = address & !4095;
            let in_page = usize::try_from(address - page)?;
            // Small reads go through whole cached pages; bulk reads (scans,
            // dumps) bypass the cache so they neither pay a copy nor evict.
            if out.len() < 4096
                && page >= s.start
                && page.checked_add(4096).is_some_and(|end| end <= s.end)
            {
                n = n.min(4096 - in_page);
                self.cached_page_read(
                    page,
                    s.file_offset + page - s.start,
                    in_page,
                    out.at_mut(..n)?,
                )?;
            } else {
                self.file
                    .read_exact_at(out.at_mut(..n)?, s.file_offset + address - s.start)?;
            }
            address += n as u64;
            out = out.at_mut(n..)?;
        }
        Ok(())
    }
    fn cached_page_read(
        &self,
        page: u64,
        file_offset: u64,
        in_page: usize,
        out: &mut [u8],
    ) -> Result<()> {
        let slot = usize::try_from((page >> 12) % PHYSICAL_SLOTS)?;
        let lock = || {
            self.physical
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        };
        let range = in_page..in_page + out.len();
        if let Some(Some((tag, data))) = lock().slots.get(slot)
            && *tag == page
        {
            out.copy_from_slice(data.at(range)?);
            return Ok(());
        }
        // Read outside the lock so concurrent analyses are not serialized.
        let mut data = Box::new([0u8; 4096]);
        if self.file.read_exact_at(&mut data[..], file_offset).is_err() {
            // A short file behind a declared segment: read exactly what was asked.
            return Ok(self.file.read_exact_at(out, file_offset + in_page as u64)?);
        }
        out.copy_from_slice(data.at(range)?);
        let mut cache = lock();
        if cache.slots.is_empty() {
            cache
                .slots
                .resize_with(usize::try_from(PHYSICAL_SLOTS)?, || None);
        }
        if let Some(entry) = cache.slots.get_mut(slot) {
            *entry = Some((page, data));
        }
        Ok(())
    }
    pub fn u64(&self, address: u64) -> Result<u64> {
        let mut b = [0; 8];
        self.read(address, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    /// Physical offsets of RSDS records: from the digest pass when it ran in
    /// this session, otherwise one scan of the image.
    pub fn rsds_offsets(&self, job: &Job) -> Result<Vec<u64>> {
        match self.rsds.get() {
            Some(hits) => Ok(hits.clone()),
            None => self.scan(b"RSDS", job),
        }
    }
    /// Single prefix scan shared by local and remote symbol matching.
    pub fn windows_candidates(&self, job: &Job) -> Result<&[crate::windows_symbols::Candidate]> {
        if self.windows.get().is_none() {
            let found = crate::windows_symbols::identify(self, job)?;
            let records = found.iter().map(|c| (c.offset, c.pdb.clone())).collect();
            let _ = self.windows.set(found);
            self.remember(|value| value.windows = Some(records));
        }
        Ok(self.windows.get().context("Windows 识别未完成")?)
    }
    /// Every remembered RSDS record still parses to the same PDB identity.
    fn verify_rsds(&self, records: &[(u64, crate::windows_symbols::PdbIdentity)]) -> bool {
        records.len() <= 1024
            && records.iter().all(|(offset, pdb)| {
                let mut bytes = [0; 512];
                self.read(*offset, &mut bytes).is_ok()
                    && crate::windows_symbols::PdbIdentity::from_rsds(&bytes)
                        .ok()
                        .as_ref()
                        == Some(pdb)
            })
    }
    /// Record a kernel root that passed full validation for `isf_digest`.
    pub(crate) fn remember_windows_root(&self, isf_digest: &str, root: u64, base: u64) {
        let isf_digest = isf_digest.to_owned();
        self.remember(move |value| {
            value.windows_roots.retain(|(isf, ..)| *isf != isf_digest);
            value.windows_roots.push((isf_digest, root, base));
            value.windows_roots.truncate(64);
        });
    }
    /// Best-effort update of this image's identification manifest. It only
    /// applies while the manifest still describes the same verified content.
    fn remember(&self, update: impl FnOnce(&mut Identification)) {
        let Some((path, digest)) = &self.identification else {
            return;
        };
        let _ = (|| -> Result<()> {
            ensure!(fs::metadata(path)?.len() <= 1024 * 1024, "识别缓存过大");
            let mut value: Identification = serde_json::from_slice(&fs::read(path)?)?;
            ensure!(value.digest == *digest, "识别缓存已对应其他内容");
            update(&mut value);
            crate::store::atomic_write(path, &serde_json::to_vec(&value)?)
        })();
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
                if bytes
                    .at(..end)?
                    .iter()
                    .all(|b| !matches!(b,0..=8|11|12|14..=31|127))
                {
                    found.push((address, bytes));
                }
            }
        }
        Ok(found)
    }
    /// Apply resource limits. Scans recorded so far, such as the pool tags the
    /// digest pass found, stay cached while they fit the new budget.
    pub fn set_limits(&mut self, limits: crate::resources::Limits) {
        match self.scans.get_mut() {
            Ok(scans) => scans.set_budget(limits.scan_cache_bytes),
            Err(_) => {
                self.scans =
                    std::sync::Mutex::new(crate::resources::Lru::new(limits.scan_cache_bytes));
            }
        }
        self.limits = limits;
    }
    pub fn stamp(&self) -> Result<String> {
        metadata_stamp(&self.file.metadata()?)
    }
    /// Sorted, unique physical offsets of `needle`. Results are memoized per image.
    pub fn scan(&self, needle: &[u8], job: &Job) -> Result<Vec<u64>> {
        ensure!(
            !needle.is_empty() && needle.len() <= 65536,
            "扫描模式长度无效"
        );
        if let Some(hits) = self.cached_scan(needle) {
            return Ok(hits.to_vec());
        }
        let mut found = self.scan_pass(&[needle], job)?;
        let hits = found.pop().unwrap_or_default();
        self.remember_scan(needle, &hits);
        Ok(hits)
    }
    /// Scan for every not-yet-scanned needle in one pass over the image, so later
    /// `scan` calls for them are served from memory. Needles that overlap
    /// themselves are left to `scan`, whose single-needle matching they rely on.
    pub fn prefetch_scans(&self, needles: &[&[u8]], job: &Job) -> Result<()> {
        let pending: Vec<&[u8]> = needles
            .iter()
            .copied()
            .filter(|n| !n.is_empty() && n.len() <= 65536 && !self_overlapping(n))
            .filter(|n| self.cached_scan(n).is_none())
            .collect();
        if pending.len() < 2 {
            return Ok(());
        }
        for (needle, hits) in pending.iter().zip(self.scan_pass(&pending, job)?) {
            self.remember_scan(needle, &hits);
        }
        Ok(())
    }
    fn cached_scan(&self, needle: &[u8]) -> Option<std::sync::Arc<[u64]>> {
        self.scans.lock().ok()?.get(&needle.to_vec()).cloned()
    }
    fn remember_scan(&self, needle: &[u8], hits: &[u64]) {
        let weight = hits.len().saturating_mul(8).saturating_add(needle.len());
        if weight > self.limits.scan_cache_bytes {
            return;
        }
        if let Ok(mut scans) = self.scans.lock() {
            scans.insert(needle.to_vec(), hits.into(), weight);
        }
    }
    fn scan_pass(&self, needles: &[&[u8]], job: &Job) -> Result<Vec<Vec<u64>>> {
        let finders: Vec<_> = needles.iter().map(memchr::memmem::Finder::new).collect();
        let longest = needles.iter().map(|n| n.len()).max().unwrap_or(1);
        let mut found = vec![Vec::new(); needles.len()];
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
                self.read(position, tail.at_mut(overlap..)?)?;
                for (finder, hits) in finders.iter().zip(&mut found) {
                    for index in finder.find_iter(&tail) {
                        hits.push(position - overlap as u64 + index as u64);
                    }
                }
                let keep = (longest - 1).min(tail.len());
                tail.drain(..tail.len() - keep);
                position += n as u64;
                job.report(format!("扫描候选: {position:#x}"));
            }
            previous_end = Some(s.end);
        }
        for hits in &mut found {
            hits.sort_unstable();
            hits.dedup();
        }
        Ok(found)
    }
}
/// A needle with a proper border (e.g. `aa`) can match at overlapping offsets,
/// where non-overlapping iteration depends on where a chunk starts.
fn self_overlapping(needle: &[u8]) -> bool {
    (1..needle.len()).any(|k| needle.get(..k) == needle.get(needle.len() - k..))
}
struct PageCache {
    /// `arm64_va_bits` this map was filled for. `u8::MAX` means empty.
    bits: u8,
    /// Virtual 4 KiB page → physical 4 KiB page. The image is read-only.
    pages: crate::resources::Lru<u64, u64>,
    /// Most recent translation: consecutive field reads usually share a page,
    /// and this hit skips the LRU's reordering.
    last: Option<(u64, u64)>,
}
pub struct VirtualMemory<'a> {
    pub image: &'a Image,
    pub root: u64,
    pages: std::sync::Mutex<PageCache>,
    linux32: Option<crate::intel_scan::Kind>,
    /// One Linux32/PAE mapper per address space, so its table cache survives
    /// between reads; the image is read-only, so cached tables stay exact.
    mapper_tables: std::sync::Mutex<Option<crate::intel_scan::Tables>>,
}
impl<'a> VirtualMemory<'a> {
    pub fn new(image: &'a Image, root: u64) -> Self {
        Self {
            image,
            root,
            pages: std::sync::Mutex::new(PageCache {
                bits: u8::MAX,
                pages: crate::resources::Lru::new(image.limits.page_cache_entries),
                last: None,
            }),
            linux32: None,
            mapper_tables: std::sync::Mutex::new(None),
        }
    }
    pub(crate) fn new_linux32(image: &'a Image, root: u64, pae: bool) -> Self {
        let mut vm = Self::new(image, root);
        let kind = if pae {
            crate::intel_scan::Kind::LinuxPae
        } else {
            crate::intel_scan::Kind::Linux32
        };
        vm.set_linux32(Some(kind));
        vm
    }
    fn set_linux32(&mut self, kind: Option<crate::intel_scan::Kind>) {
        self.linux32 = kind;
    }
    /// Run `f` on a Linux32/PAE mapper that reuses this address space's table
    /// cache; concurrent callers simply start from an empty cache.
    fn with_mapper<T>(
        &self,
        kind: crate::intel_scan::Kind,
        f: impl FnOnce(&mut crate::intel_scan::Mapper<'_>) -> T,
    ) -> T {
        let lock = || {
            self.mapper_tables
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        };
        let tables = lock().take();
        let mut mapper =
            crate::intel_scan::Mapper::with_tables(self.image, self.root, kind, tables);
        let value = f(&mut mapper);
        *lock() = Some(mapper.into_tables());
        value
    }
    pub(crate) fn linux_intel_kind(&self) -> crate::intel_scan::Kind {
        self.linux32.unwrap_or(crate::intel_scan::Kind::Linux64)
    }
    pub(crate) fn with_root(&self, root: u64) -> VirtualMemory<'a> {
        let mut vm = Self::new(self.image, root);
        vm.set_linux32(self.linux32);
        vm
    }
    fn cached_page(&self, va: u64, bits: u8) -> Option<u64> {
        let mut cache = self.pages.lock().unwrap_or_else(|e| e.into_inner());
        if cache.bits != bits {
            return None;
        }
        let page = va & !4095;
        if let Some((virtual_page, physical)) = cache.last
            && virtual_page == page
        {
            return Some(physical);
        }
        let physical = cache.pages.get(&page).copied()?;
        cache.last = Some((page, physical));
        Some(physical)
    }
    fn store_page(&self, va: u64, pa: u64, bits: u8) {
        let mut cache = self.pages.lock().unwrap_or_else(|e| e.into_inner());
        if cache.bits != bits {
            cache.pages.clear();
            cache.bits = bits;
        }
        cache.last = Some((va & !4095, pa & !4095));
        cache.pages.insert(va & !4095, pa & !4095, 1);
    }
    pub fn translate(&self, va: u64) -> Result<u64> {
        if let Some(kind) = self.linux32 {
            ensure!(va <= u64::from(u32::MAX), "Linux32 虚拟地址越界 {va:#x}");
            if let Some(base) = self.cached_page(va, 32) {
                return Ok(base | (va & 4095));
            }
            let pa = self.with_mapper(kind, |mapper| mapper.translate_address(va))?;
            self.store_page(va, pa, 32);
            return Ok(pa);
        }
        let bits = self
            .image
            .arm64_va_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        if let Some(base) = self.cached_page(va, bits) {
            return Ok(base | (va & 4095));
        }
        let pa = self.translate_walk(va, bits)?;
        self.store_page(va, pa, bits);
        Ok(pa)
    }
    fn translate_walk(&self, va: u64, bits: u8) -> Result<u64> {
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
        if let Some(kind) = self.linux32 {
            let end = va.checked_add(out.len() as u64).context("虚拟地址溢出")?;
            ensure!(
                va <= u64::from(u32::MAX) && end <= 1u64 << 32,
                "Linux32 读取地址越界"
            );
            return self.with_mapper(kind, |mapper| {
                mapper.read(va, out, |_, _, _| {
                    anyhow::bail!("Linux32 不支持 Windows 交换页")
                })
            });
        }
        va.checked_add(out.len() as u64).context("虚拟地址溢出")?;
        while !out.is_empty() {
            let n = out.len().min(4096 - (va & 4095) as usize);
            self.image.read(self.translate(va)?, out.at_mut(..n)?)?;
            va += n as u64;
            out = out.at_mut(n..)?;
        }
        Ok(())
    }
    /// Cursor for many small reads that walk one table: each page is read once.
    pub(crate) fn cursor(&self) -> PageCursor<'_, 'a> {
        PageCursor {
            vm: self,
            page: None,
            valid: false,
            data: Box::new([0; 4096]),
        }
    }
    pub fn uint(&self, va: u64, size: usize) -> Result<u64> {
        ensure!(matches!(size, 1 | 2 | 4 | 8), "不支持的整数字段大小 {size}");
        let mut b = [0; 8];
        self.read(va, b.at_mut(..size)?)?;
        Ok(u64::from_le_bytes(b))
    }
    pub fn string(&self, va: u64, len: usize) -> Result<String> {
        ensure!((1..=4096).contains(&len), "字符串长度无效");
        let mut b = vec![0; len];
        self.read(va, &mut b)?;
        let end = b.iter().position(|b| *b == 0).unwrap_or(len);
        if b.at(..end)?.iter().any(|b| *b < 32 || *b == 127) {
            bail!("对象字符串含控制字符 @ {va:#x}");
        }
        Ok(String::from_utf8_lossy(b.at(..end)?).into_owned())
    }
}

/// Serves small integer reads from the last whole virtual page it read.
/// Reads crossing a page, and pages that cannot be read whole, go straight to
/// `VirtualMemory::uint`, so values and errors equal direct reads exactly.
pub(crate) struct PageCursor<'v, 'a> {
    vm: &'v VirtualMemory<'a>,
    page: Option<u64>,
    valid: bool,
    data: Box<[u8; 4096]>,
}
impl PageCursor<'_, '_> {
    pub(crate) fn uint(&mut self, va: u64, size: usize) -> Result<u64> {
        let offset = usize::try_from(va & 4095)?;
        if matches!(size, 1 | 2 | 4 | 8) && offset + size <= 4096 {
            let page = va & !4095;
            if self.page != Some(page) {
                self.page = Some(page);
                self.valid = self.vm.read(page, &mut self.data[..]).is_ok();
            }
            if self.valid {
                let mut b = [0; 8];
                b.at_mut(..size)?
                    .copy_from_slice(self.data.at(offset..offset + size)?);
                return Ok(u64::from_le_bytes(b));
            }
        }
        self.vm.uint(va, size)
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
    use crate::linux::tests::{fixture, image};
    fn put(b: &mut [u8], p: usize, v: u64) {
        b[p..p + 8].copy_from_slice(&v.to_le_bytes());
    }
    #[test]
    fn fragmented_physical_reads_preserve_boundaries_and_holes() {
        let mut img = image(b"abcdefgh");
        img.segments = vec![
            Segment {
                start: 100,
                end: 102,
                file_offset: 0,
            },
            Segment {
                start: 102,
                end: 104,
                file_offset: 4,
            },
            Segment {
                start: 200,
                end: 204,
                file_offset: 0,
            },
        ];
        let mut bytes = [0; 4];
        img.read(100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"abef");
        img.read(200, &mut bytes).unwrap();
        assert_eq!(&bytes, b"abcd");
        for address in [0, 99, 104, 199, 204] {
            assert!(img.read(address, &mut [0]).is_err());
        }
        assert!(img.read(103, &mut [0; 2]).is_err());
    }
    #[test]
    fn digest_pass_rsds_hits_equal_a_physical_scan() {
        // file  0..16 → phys 0x1000   file 32..48 → phys 0x1010 (contiguous)
        // file 16..32 → phys 0x3000   file 48..64 → phys 0x5000
        let mut bytes = vec![b'.'; 64];
        bytes[4..8].copy_from_slice(b"RSDS"); // inside the first segment
        bytes[14..16].copy_from_slice(b"RS"); // completed physically by...
        bytes[32..34].copy_from_slice(b"DS"); // ...the contiguous segment
        bytes[46..50].copy_from_slice(b"RSDS"); // adjacent in the file only
        bytes[52..56].copy_from_slice(b"RSDS"); // inside the last segment
        let mut img = image(&bytes);
        img.segments = vec![
            Segment {
                start: 0x1000,
                end: 0x1010,
                file_offset: 0,
            },
            Segment {
                start: 0x1010,
                end: 0x1020,
                file_offset: 32,
            },
            Segment {
                start: 0x3000,
                end: 0x3010,
                file_offset: 16,
            },
            Segment {
                start: 0x5000,
                end: 0x5010,
                file_offset: 48,
            },
        ];
        let job = Job::default();
        // Uneven pushes so records straddle the digest pass's chunks.
        let mut scan = Fingerprint::default();
        for chunk in bytes.chunks(5) {
            scan.push(chunk, &job);
        }
        let (_, found) = scan.finish();
        assert_eq!(found.rsds, vec![4, 46, 52]);
        let scanned = img.scan(b"RSDS", &job).unwrap();
        assert_eq!(scanned, vec![0x1004, 0x100e, 0x5004]);
        assert_eq!(physical_hits(&img, &found.rsds, b"RSDS").unwrap(), scanned);
    }
    #[test]
    fn arm64_page_block_canonical_and_missing() {
        let (mut b, _) = fixture();
        put(&mut b, 0x3000, 1);
        let img = image(&b);
        img.arm64_va_bits
            .store(48, std::sync::atomic::Ordering::Relaxed);
        let vm = VirtualMemory::new(&img, 0x1000);
        assert_eq!(vm.translate(0x12345).unwrap(), 0x12345);
        let user = VirtualMemory::new(&img, 0x4000);
        assert_eq!(user.translate(0x200ffe).unwrap(), 0x20ffe);
        // Same 4 KiB page must come back from the translation cache.
        assert_eq!(user.translate(0x200fff).unwrap(), 0x20fff);
        let mut bytes = [0; 4];
        user.read(0x200ffe, &mut bytes).unwrap();
        assert_eq!(bytes, [b'a', 0, b'b', b'=']);
        assert!(user.translate(0x202000).is_err());
        assert!(user.translate(0xab00000000200000).is_err());
        img.arm64_va_bits
            .store(39, std::sync::atomic::Ordering::Relaxed);
        let vm = VirtualMemory::new(&img, 0x2000);
        assert_eq!(vm.translate(0x12345).unwrap(), 0x12345);
        assert!(vm.translate(1 << 39).is_err());
        put(&mut b, 0x3000, 0x1001);
        let img = image(&b);
        img.arm64_va_bits
            .store(48, std::sync::atomic::Ordering::Relaxed);
        assert!(VirtualMemory::new(&img, 0x1000).translate(0).is_err());
    }
}
#[cfg(test)]
mod scan_tests {
    use super::*;
    use crate::linux::tests::image;

    #[test]
    fn batched_prefetch_matches_independent_scans_across_chunks() {
        let chunk = 4 * 1024 * 1024;
        let mut bytes = vec![0u8; chunk * 2 + 4096];
        // Straddle the first chunk boundary, sit at both ends, and repeat.
        for (at, needle) in [
            (chunk - 2, b"File".as_slice()),
            (0, b"Muta"),
            (bytes.len() - 7, b"System\0"),
            (100, b"File"),
            (chunk + 3, b"Proc"),
        ] {
            bytes[at..at + needle.len()].copy_from_slice(needle);
        }
        let needles: &[&[u8]] = &[b"File", b"Muta", b"Proc", b"System\0", b"none"];
        let job = Job::default();
        let batched = image(&bytes);
        batched.prefetch_scans(needles, &job).unwrap();
        for needle in needles {
            assert!(batched.cached_scan(needle).is_some());
            let fresh = image(&bytes);
            assert_eq!(
                batched.scan(needle, &job).unwrap(),
                fresh.scan(needle, &job).unwrap(),
                "{needle:?}"
            );
        }
        assert_eq!(
            batched.scan(b"File", &job).unwrap(),
            vec![100, chunk as u64 - 2]
        );
        // Self-overlapping needles keep the single-needle path.
        assert!(self_overlapping(b"aa") && !self_overlapping(b"File"));
        batched.prefetch_scans(&[b"aa", b"zz"], &job).unwrap();
        assert!(batched.cached_scan(b"aa").is_none());
    }
}

#[test]
fn pipelined_digest_matches_serial_digest() -> Result<()> {
    // The read-ahead thread changes how the bytes are delivered, so the chunk
    // order and therefore the digest must be proven identical to the serial
    // path for sizes that straddle a chunk boundary.
    let dir = tempfile::tempdir()?;
    for size in [
        0usize,
        1,
        4095,
        4096,
        DIGEST_CHUNK - 1,
        DIGEST_CHUNK,
        DIGEST_CHUNK + 7,
    ] {
        let path = dir.path().join(format!("image-{size}.raw"));
        let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        fs::write(&path, &bytes)?;
        let job = Job::default();
        let serial = digest_reader(File::open(&path)?, &job)?;
        let pipelined = digest_file(File::open(&path)?, &job)?;
        assert_eq!(serial, pipelined, "size {size}");
    }
    Ok(())
}
#[test]
fn pool_tag_occurrences_can_never_overlap() {
    for a in POOL_TAGS {
        for b in POOL_TAGS {
            for k in 1..a.len().min(b.len()) {
                assert_ne!(
                    a.get(a.len() - k..),
                    b.get(..k),
                    "{a:?} overlaps {b:?} by {k}"
                );
            }
        }
    }
}
#[test]
fn digest_pass_records_pool_tags_exactly_as_scan_finds_them() -> Result<()> {
    // Tags straddling, starting at and ending at chunk boundaries, adjacent
    // repeats and every tag at least once: the recorded offsets must equal a
    // whole-buffer search, and their physical form must equal `scan`.
    let size = 2 * DIGEST_CHUNK + 4096;
    let mut bytes: Vec<u8> = (0..size).map(|i| (i % 7) as u8).collect();
    let mut place = |at: usize, tag: &[u8]| {
        if let Some(slot) = bytes.get_mut(at..at + tag.len()) {
            slot.copy_from_slice(tag);
        }
    };
    for (i, tag) in POOL_TAGS.iter().enumerate() {
        place(100 + i * 9, tag);
    }
    place(DIGEST_CHUNK - 2, b"File");
    place(DIGEST_CHUNK - 4, b"TcpE");
    place(DIGEST_CHUNK, b"Fil\xe5");
    place(2 * DIGEST_CHUNK - 1, b"CM10");
    place(2 * DIGEST_CHUNK + 50, b"FileFileMuta");
    place(size - 4, b"Symb");
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("pool.raw");
    fs::write(&path, &bytes)?;
    let job = Job::default();
    let (digest, found) = fingerprint(File::open(&path)?, size as u64, &job)?;
    assert_eq!(digest, digest_reader(File::open(&path)?, &job)?);
    assert_eq!(found.pool.len(), POOL_TAGS.len());
    let image = crate::linux::tests::image(&bytes);
    for (tag, hits) in POOL_TAGS.iter().zip(&found.pool) {
        let hits = hits.as_ref().context("pool tag dropped")?;
        let expected: Vec<u64> = memchr::memmem::find_iter(&bytes, tag)
            .map(|i| i as u64)
            .collect();
        assert_eq!(hits, &expected, "{tag:?}");
        assert!(!expected.is_empty(), "{tag:?}");
        assert_eq!(
            physical_hits(&image, hits, tag)?,
            image.scan(tag, &job)?,
            "{tag:?}"
        );
    }
    Ok(())
}
#[cfg(test)]
mod budget_tests {
    use super::*;
    use crate::linux::tests::{fixture, image};
    #[test]
    fn uncached_scan_preserves_all_hits_and_evicted_pages_translate_again() {
        let mut input = image(b"abcdabcdabcd");
        input.set_limits(crate::resources::Limits {
            scan_cache_bytes: 8,
            ..Default::default()
        });
        let expected = vec![0, 4, 8];
        assert_eq!(input.scan(b"abcd", &Job::default()).unwrap(), expected);
        assert!(input.cached_scan(b"abcd").is_none());
        assert_eq!(input.scan(b"abcd", &Job::default()).unwrap(), expected);
        let (bytes, _) = fixture();
        let mut input = image(&bytes);
        input.set_limits(crate::resources::Limits {
            page_cache_entries: 1,
            ..Default::default()
        });
        let vm = VirtualMemory::new(&input, 0x1000);
        let first = vm.translate(0x1000).unwrap();
        vm.translate(0x2000).unwrap();
        assert!(vm.cached_page(0x1000, 0).is_none());
        assert_eq!(vm.translate(0x1000).unwrap(), first);
    }
}

#[cfg(test)]
mod physical_cache_tests {
    use super::*;
    #[test]
    fn cached_small_reads_equal_the_file_bytes_everywhere() {
        // Not a page multiple: the tail page is never cached and must still read.
        let bytes: Vec<u8> = (0..(PHYSICAL_SLOTS as usize + 3) * 4096 + 1234)
            .map(|i| (i * 31 % 251) as u8)
            .collect();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        let image = Image::from_file(file, "cache-fixture".into()).unwrap();
        let len = bytes.len() as u64;
        let mut offsets = vec![0, 1, 4095, 4096, 8190, len - 1234, len - 9, len - 1];
        // Revisit pages that collide in the direct-mapped cache.
        offsets.extend((0..6).map(|i| i * PHYSICAL_SLOTS * 4096 / 2 + 77));
        offsets.retain(|offset| *offset < len);
        for round in 0..2 {
            for &offset in &offsets {
                for size in [1usize, 2, 8, 100, 4095, 4096, 9000] {
                    let end = (offset + size as u64).min(len);
                    let mut out = vec![0u8; usize::try_from(end - offset).unwrap()];
                    image.read(offset, &mut out).unwrap();
                    assert_eq!(
                        out,
                        bytes[offset as usize..end as usize],
                        "round {round} offset {offset} size {size}"
                    );
                }
            }
        }
        let mut past = [0u8; 2];
        assert!(image.read(len - 1, &mut past).is_err());
    }
}
