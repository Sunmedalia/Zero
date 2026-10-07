//! Explicit, read-only paging attachments. No adjacent-file discovery or implicit index guessing.
use super::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, Metadata},
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
    sync::Mutex,
};
thread_local! { static ACTIVE_READS: std::cell::RefCell<HashSet<(usize,u64,u64)>> = std::cell::RefCell::new(HashSet::new()); }
pub(super) struct ReadDepth((usize, u64, u64));
impl ReadDepth {
    pub(super) fn enter(image: &Image, root: u64, va: u64) -> Result<Self> {
        let key = (image as *const Image as usize, root, va & !4095);
        ACTIVE_READS.with(|reads| {
            let mut reads = reads.borrow_mut();
            ensure!(reads.len() < 32, "Windows 页面恢复递归超过上限");
            ensure!(reads.insert(key), "Windows 页面恢复循环");
            Ok(Self(key))
        })
    }
}
impl Drop for ReadDepth {
    fn drop(&mut self) {
        ACTIVE_READS.with(|reads| {
            reads.borrow_mut().remove(&self.0);
        });
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attachment {
    pub index: u8,
    pub path: PathBuf,
}
pub fn parse_attachment(value: &str) -> Result<Attachment, String> {
    let (index, path) = value
        .split_once('=')
        .ok_or("使用 INDEX=PATH 指定同次采集的分页文件")?;
    let index = index.parse::<u8>().map_err(|_| "分页文件索引无效")?;
    if index > 15 || path.is_empty() {
        return Err("分页文件索引必须为 0..15，路径不能为空".into());
    }
    Ok(Attachment {
        index,
        path: path.into(),
    })
}
#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    length: u64,
    dev: u64,
    inode: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl Stamp {
    fn from(m: &Metadata) -> Self {
        Self {
            length: m.len(),
            dev: m.dev(),
            inode: m.ino(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
}
struct BackingFile {
    file: File,
    path: PathBuf,
    stamp: Stamp,
    digest: String,
    kind: &'static str,
}
impl BackingFile {
    fn open(path: &Path, kind: &'static str, job: &Job) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("打开 {kind} {}", path.display()))?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.len() != 0 && metadata.len().is_multiple_of(4096),
            "分页附件必须是完整页组成的普通文件"
        );
        let stamp = Stamp::from(&metadata);
        let digest = crate::image::digest_reader(file.try_clone()?, job)?;
        let result = Self {
            file,
            path: path.canonicalize()?,
            stamp,
            digest,
            kind,
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            Stamp::from(&self.file.metadata()?) == self.stamp
                && Stamp::from(&std::fs::metadata(&self.path)?) == self.stamp,
            "分页附件在分析期间被修改或替换: {}",
            self.path.display()
        );
        Ok(())
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<()> {
        self.validate()?;
        ensure!(
            offset
                .checked_add(out.len() as u64)
                .is_some_and(|end| end <= self.stamp.length),
            "{} 越界: {offset:#x}",
            self.kind
        );
        self.file.read_exact_at(out, offset)?;
        self.validate()
    }
}
pub struct Sources {
    pub(super) job: Job,
    pub(super) kernel_context: Option<(u64, u64)>,
    pub(super) virtual_indexes: HashSet<u8>,
    pub(super) compressed: Mutex<compressed::State>,
    files: BTreeMap<u8, BackingFile>,
    swap: Option<BackingFile>,
    reads: Mutex<BTreeMap<(u8, u64), u64>>,
}
impl Sources {
    pub(super) fn open(options: &Options, job: &Job) -> Result<Self> {
        let mut files = BTreeMap::new();
        for a in &options.pagefiles {
            job.check()?;
            ensure!(
                a.index < 16 && !files.contains_key(&a.index),
                "分页文件索引重复或无效"
            );
            files.insert(a.index, BackingFile::open(&a.path, "pagefile", job)?);
        }
        let swap = options
            .swapfile
            .as_deref()
            .map(|p| BackingFile::open(p, "swapfile", job))
            .transpose()?;
        Ok(Self {
            job: job.clone(),
            kernel_context: None,
            virtual_indexes: HashSet::new(),
            compressed: Mutex::new(compressed::State::default()),
            files,
            swap,
            reads: Mutex::new(BTreeMap::new()),
        })
    }
    pub(super) fn configure_kernel(&mut self, engine: &Windows<'_>) -> Result<()> {
        self.kernel_context = Some((engine.vm.root, engine.base));
        if let (Ok(count), Ok(array)) = (
            engine.symbol("MmNumberOfPagingFiles"),
            engine.symbol("MmPagingFile"),
        ) {
            let count = engine.vm.uint(count, 4)?;
            ensure!(count <= 16, "分页文件数量无效");
            let field = if engine
                .vm
                .isf
                .field("_MMPAGING_FILE", "VirtualStorePagefile")
                .is_ok()
            {
                Some("VirtualStorePagefile")
            } else if engine
                .vm
                .isf
                .field("_MMPAGING_FILE", "u.VirtualStorePagefile")
                .is_ok()
            {
                Some("u.VirtualStorePagefile")
            } else {
                None
            };
            if let Some(field) = field {
                for index in 0..count {
                    self.job.check()?;
                    let object = engine
                        .vm
                        .pointer(add(array, index * engine.vm.pointer_size() as u64)?)?;
                    if object != 0 && engine.vm.number(object, "_MMPAGING_FILE", field)? != 0 {
                        self.virtual_indexes.insert(index as u8);
                    }
                }
            }
        }
        ensure!(
            !self
                .files
                .keys()
                .any(|index| self.virtual_indexes.contains(index)),
            "虚拟压缩 store 索引不能绑定普通 pagefile"
        );
        self.bind_swap(engine)
    }
    pub(super) fn bind_swap(&mut self, engine: &Windows<'_>) -> Result<()> {
        if self.swap.is_none() {
            return Ok(());
        }
        let count = engine.vm.uint(
            engine
                .symbol("MmNumberOfPagingFiles")
                .context("swapfile 需要精确 MmNumberOfPagingFiles 符号以验证索引")?,
            4,
        )?;
        ensure!(count <= 16, "分页文件数量无效");
        let array = engine.symbol("MmPagingFile")?;
        let mut matches = Vec::new();
        for index in 0..count {
            let object = engine
                .vm
                .pointer(add(array, index * engine.vm.pointer_size() as u64)?)?;
            if object == 0 {
                continue;
            }
            let name =
                engine
                    .vm
                    .unicode(engine.field(object, "_MMPAGING_FILE", "PageFileName")?)?;
            if name
                .rsplit(['\\', '/'])
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("swapfile.sys"))
            {
                matches.push(index as u8);
            }
        }
        ensure!(matches.len() == 1, "无法唯一验证 swapfile 的内核分页索引");
        ensure!(
            !self.files.contains_key(&matches[0]),
            "swapfile 与 pagefile 索引冲突"
        );
        self.files
            .insert(matches[0], self.swap.take().context("swapfile 未打开")?);
        Ok(())
    }
    pub(super) fn read(&self, index: u8, offset: u64, out: &mut [u8]) -> Result<()> {
        self.job.check()?;
        let file = self
            .files
            .get(&index)
            .with_context(|| format!("缺少显式分页附件 index {index}"))?;
        file.read(offset, out)?;
        let mut reads = self
            .reads
            .lock()
            .map_err(|_| anyhow::anyhow!("分页来源记录锁失败"))?;
        ensure!(
            reads.len() < 1_000_000 || reads.contains_key(&(index, offset & !4095)),
            "分页来源记录超过上限"
        );
        *reads.entry((index, offset & !4095)).or_default() += out.len() as u64;
        Ok(())
    }
    pub(super) fn validate(&self) -> Result<()> {
        for f in self.files.values().chain(self.swap.iter()) {
            f.validate()?;
        }
        Ok(())
    }
    pub(super) fn manifest(&self) -> Result<serde_json::Value> {
        let files:Vec<_>=self.files.iter().map(|(index,f)|serde_json::json!({"index":index,"kind":f.kind,"path":f.path,"size":f.stamp.length,"sha256":f.digest,"capture_match":"user-supplied"})).collect();
        let reads = self
            .reads
            .lock()
            .map_err(|_| anyhow::anyhow!("分页来源记录锁失败"))?;
        let pages:Vec<_>=reads.iter().map(|((index,offset),bytes)|serde_json::json!({"index":index,"file_offset":offset,"bytes_read":bytes})).collect();
        Ok(serde_json::json!({"files":files,"pages_read":pages}))
    }
    pub(super) fn cache_identity(&self) -> String {
        serde_json::json!(
            self.files
                .iter()
                .map(|(i, f)| (*i, &f.digest, &f.path, f.kind))
                .collect::<Vec<_>>()
        )
        .to_string()
    }
    fn has_file(&self, index: u8) -> bool {
        self.files.contains_key(&index)
    }
}
impl Memory<'_> {
    pub(super) fn pagefile_high(&self, entry: u64) -> Result<u64> {
        let mut high = json_number(self.isf, entry, "_MMPTE_SOFTWARE", "PageFileHigh")?;
        // Old layouts have no swizzle flag. Modern nonswizzled PTEs include
        // the kernel's invalid-PTE marker in PageFileHigh, not in the file offset.
        if self.isf.field("_MMPTE_SOFTWARE", "SwizzleBit").is_ok()
            && json_number(self.isf, entry, "_MMPTE_SOFTWARE", "SwizzleBit")? == 0
        {
            let (root, base) = self
                .sources
                .context("缺少分页上下文")?
                .kernel_context
                .context("缺少分页内核上下文")?;
            let kernel = Windows {
                vm: Memory::new(self.image, root, self.isf, self.sources),
                base,
                pdb: PdbIdentity::from_isf(self.isf)?,
            };
            let state = kernel.symbol("MiState")?;
            high &=
                !(kernel
                    .vm
                    .number(state, "_MI_SYSTEM_INFORMATION", "Hardware.InvalidPteMask")?
                    >> 32);
        }
        Ok(high)
    }
    pub(super) fn pagefile_read(&self, va: u64, out: &mut [u8]) -> Result<()> {
        let geometry = self.paging()?;
        ensure!(geometry.canonical(va), "Windows 非 canonical 地址");
        let mut table = self.root & geometry.root_mask();
        let mut backing = None;
        for (level, &shift) in geometry.shifts().iter().enumerate() {
            let index = ((va >> shift) & (geometry.entries(level) as u64 - 1)) as usize;
            let entry = if let Some((file, offset)) = backing {
                let mut b = [0; 8];
                self.sources.context("未附加分页文件")?.read(
                    file,
                    add(offset, (index * geometry.width()) as u64)?,
                    &mut b[..geometry.width()],
                )?;
                u64::from_le_bytes(b)
            } else {
                geometry.entry(self.image, table, index)?
            };
            if entry & 1 != 0 || (entry & (1 << 11) != 0 && entry & (1 << 10) == 0) {
                ensure!(
                    entry & 1 == 0 || !geometry.block(entry, shift),
                    "大型驻留页应使用物理翻译"
                );
                if geometry.arch == Architecture::Arm64 && entry & 1 != 0 {
                    ensure!(entry & 3 == 3, "无效 ARM64 table/page descriptor");
                }
                table = if entry & 1 == 0 {
                    self.transition_frame(entry, geometry)?
                } else {
                    entry & geometry.mask()
                };
                backing = None;
                if shift == 12 {
                    self.image.read(table | (va & 4095), out)?;
                    return Ok(());
                }
                continue;
            }
            if shift == 12 && entry & (1 << 10) != 0 {
                return self.prototype_read(entry, va, out);
            }
            ensure!(
                json_number(self.isf, entry, "_MMPTE_SOFTWARE", "Prototype")? == 0
                    && json_number(self.isf, entry, "_MMPTE_SOFTWARE", "Transition")? == 0,
                "非普通分页 PTE"
            );
            let file = u8::try_from(json_number(
                self.isf,
                entry,
                "_MMPTE_SOFTWARE",
                "PageFileLow",
            )?)?;
            let page = self.pagefile_high(entry)?;
            ensure!(
                page != 0 && file < 16,
                "无分页内容的 PTE（未提交或 demand-zero）"
            );
            let offset = page.checked_mul(4096).context("分页偏移溢出")?;
            if shift == 12 {
                return self.software_page_read(va, entry, out);
            }
            backing = Some((file, offset));
        }
        bail!("无法解析分页 PTE")
    }
    fn software_page_read(&self, va: u64, entry: u64, out: &mut [u8]) -> Result<()> {
        ensure!(
            json_number(self.isf, entry, "_MMPTE_SOFTWARE", "Prototype")? == 0
                && json_number(self.isf, entry, "_MMPTE_SOFTWARE", "Transition")? == 0,
            "非普通分页 PTE"
        );
        let file = u8::try_from(json_number(
            self.isf,
            entry,
            "_MMPTE_SOFTWARE",
            "PageFileLow",
        )?)?;
        let high = self.pagefile_high(entry)?;
        ensure!(
            high != 0 && file < 16,
            "无分页内容的 PTE（未提交或 demand-zero）"
        );
        let offset = high.checked_mul(4096).context("分页偏移溢出")?;
        let sources = self.sources.context("未附加分页文件")?;
        if sources.has_file(file) {
            return sources.read(file, add(offset, va & 4095)?, out);
        }
        ensure!(
            sources.virtual_indexes.contains(&file),
            "缺少显式分页附件 index {file}；该索引也未验证为虚拟压缩 store"
        );
        let page = sources.compressed_page(self, va, entry, file)?;
        let start = (va & 4095) as usize;
        out.copy_from_slice(
            page.get(start..start + out.len())
                .context("压缩页范围越界")?,
        );
        Ok(())
    }
    fn prototype_read(&self, mut entry: u64, va: u64, out: &mut [u8]) -> Result<()> {
        let geometry = self.paging()?;
        let mut seen = HashSet::new();
        for _ in 0..32 {
            if let Some(sources) = self.sources {
                sources.job.check()?;
            }
            let address = self.prototype_address(entry)?;
            ensure!(seen.insert(address), "prototype PTE 链循环");
            entry = self.uint(address, geometry.width())?;
            if entry & 1 != 0 {
                if geometry.arch == Architecture::Arm64 && entry & 1 != 0 {
                    ensure!(entry & 3 == 3, "无效 ARM64 prototype descriptor");
                }
                return self
                    .image
                    .read((entry & geometry.mask()) | (va & 4095), out);
            }
            if entry & (1 << 10) != 0 {
                continue;
            }
            if entry & (1 << 11) != 0 {
                return self
                    .image
                    .read(self.transition_frame(entry, geometry)? | (va & 4095), out);
            }
            return self.software_page_read(va, entry, out);
        }
        bail!("prototype PTE 链超过 32 层")
    }
}
#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image};
    use super::*;
    #[test]
    fn nonswizzled_offsets_remove_exact_invalid_pte_mask() {
        use super::super::tests::put;
        let (mut b, mut isf) = fixture();
        let bit = |pos, len| serde_json::json!({"offset":0,"type":{"kind":"bitfield","bit_position":pos,"bit_length":len,"type":{"kind":"base","name":"u64"}}});
        isf.data["user_types"]["_MMPTE_SOFTWARE"] = serde_json::json!({"size":8,"fields":{"PageFileHigh":bit(32,32),"SwizzleBit":bit(4,1)}});
        isf.data["symbols"]["MiState"] = serde_json::json!({"address":0x4000});
        isf.data["user_types"]["_MI_SYSTEM_INFORMATION"] = serde_json::json!({"size":8,"fields":{"Hardware":{"offset":0,"type":{"kind":"struct","name":"_MI_HARDWARE_STATE"}}}});
        isf.data["user_types"]["_MI_HARDWARE_STATE"] = serde_json::json!({"size":8,"fields":{"InvalidPteMask":{"offset":0,"type":{"kind":"base","name":"u64"}}}});
        put(&mut b, 0xc000, 1 << 63);
        let img = image(&b);
        let mut sources = Sources::open(&Options::default(), &Job::default()).unwrap();
        sources.kernel_context = Some((0x1000, K));
        let vm = Memory::new(&img, 0x1000, &isf, Some(&sources));
        assert_eq!(vm.pagefile_high((1 << 63) | (9 << 32)).unwrap(), 9);
        assert_eq!(
            vm.pagefile_high((1 << 63) | (9 << 32) | 16).unwrap(),
            0x80000009
        );
        let mut missing = Isf::parse(
            &serde_json::to_vec(&isf.data).unwrap(),
            "missing.json".into(),
        )
        .unwrap();
        missing.data["symbols"]
            .as_object_mut()
            .unwrap()
            .remove("MiState");
        let vm = Memory::new(vm.image, vm.root, &missing, vm.sources);
        assert!(vm.pagefile_high((1 << 63) | (9 << 32)).is_err());
    }
    #[test]
    fn explicit_pagefiles_read_software_pages_and_detect_mutation() {
        use std::io::Write;
        let (mut b, mut isf) = fixture();
        isf.data["user_types"]["_MMPTE_SOFTWARE"] = serde_json::json!({"kind":"struct","size":8,"fields":{"Prototype":{"offset":0,"type":{"kind":"bitfield","bit_position":10,"bit_length":1,"type":{"kind":"base","name":"u64"}}},"Transition":{"offset":0,"type":{"kind":"bitfield","bit_position":11,"bit_length":1,"type":{"kind":"base","name":"u64"}}},"PageFileLow":{"offset":0,"type":{"kind":"bitfield","bit_position":12,"bit_length":4,"type":{"kind":"base","name":"u64"}}},"PageFileHigh":{"offset":0,"type":{"kind":"bitfield","bit_position":32,"bit_length":32,"type":{"kind":"base","name":"u64"}}}}});
        // Fixture maps K+0x3000 using the fourth leaf PTE.
        b[0x4018..0x4020].copy_from_slice(&((1u64 << 32) | (3 << 12)).to_le_bytes());
        let image = image(&b);
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&vec![0; 4096]).unwrap();
        f.write_all(&vec![0x5a; 4096]).unwrap();
        let options = Options {
            pagefiles: vec![Attachment {
                index: 3,
                path: f.path().into(),
            }],
            ..Options::default()
        };
        let sources = Sources::open(&options, &Job::default()).unwrap();
        let vm = Memory::new(&image, 0x1000, &isf, Some(&sources));
        let mut out = [0; 16];
        vm.read(K + 0x3010, &mut out).unwrap();
        assert_eq!(out, [0x5a; 16]);
        assert!(sources.read(3, 8190, &mut out).is_err());
        assert!(sources.read(4, 4096, &mut out).is_err());
        assert_eq!(
            sources.manifest().unwrap()["pages_read"][0]["file_offset"],
            4096
        );
        f.write_all(&[1]).unwrap();
        assert!(vm.read(K + 0x3000, &mut out).is_err());
        assert!(parse_attachment("16=x").is_err());
        assert!(parse_attachment("0=").is_err());
        assert!(
            Sources::open(
                &Options {
                    pagefiles: vec![options.pagefiles[0].clone(), options.pagefiles[0].clone()],
                    ..Options::default()
                },
                &Job::default()
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod prototype_recovery_tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use std::io::Write;
    #[test]
    fn prototype_target_recovers_explicit_pagefile_and_rejects_chains() {
        let (mut b, mut isf) = fixture();
        let bit = |pos, len| serde_json::json!({"offset":0,"type":{"kind":"bitfield","bit_position":pos,"bit_length":len,"type":{"kind":"base","name":"u64"}}});
        isf.data["user_types"]["_MMPTE_SOFTWARE"] = serde_json::json!({"size":8,"fields":{"Prototype":bit(10,1),"Transition":bit(11,1),"PageFileLow":bit(12,4),"PageFileHigh":bit(32,32)}});
        let prototype = ((K + 0x4000) << 16) | (1 << 10);
        put(&mut b, 0x4018, prototype);
        put(&mut b, 0xc000, (1 << 32) | (3 << 12));
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&vec![0; 4096]).unwrap();
        file.write_all(&vec![0x77; 4096]).unwrap();
        let options = Options {
            pagefiles: vec![Attachment {
                index: 3,
                path: file.path().into(),
            }],
            ..Default::default()
        };
        let sources = Sources::open(&options, &Job::default()).unwrap();
        let img = image(&b);
        let vm = Memory::new(&img, 0x1000, &isf, Some(&sources));
        let mut out = [0; 23];
        vm.read(K + 0x3011, &mut out).unwrap();
        assert_eq!(out, [0x77; 23]);
        put(&mut b, 0xc000, prototype);
        let img = image(&b);
        let vm = Memory::new(&img, 0x1000, &isf, Some(&sources));
        assert!(format!("{:#}", vm.read(K + 0x3011, &mut out).unwrap_err()).contains("循环"));
        assert!(vm.read(K + 0x3011, &mut out).is_err());
    }
}
