//! 从文件缓存提取驻留文件内容，对齐 vol3 dumpfiles 的 ControlArea 页收集：
//! DataSectionObject(.dat) 与 ImageSectionObject(.img) 两类缓存；SharedCacheMap
//! 的 VACB 视图不在此列。字节直接来自物理驻留页，空洞保持稀疏，绝不伪造。
use super::dump::sanitized_component;
use super::*;
use sha2::{Digest, Sha256};
use std::io::Write;

const FILE_DEVICE_DISK: u64 = 0x7;
const FILE_DEVICE_NETWORK_FILE_SYSTEM: u64 = 0x14;
/// 单个文件的 PTE 收集上限：256 MiB / 4 KiB。
const MAX_FILE_PAGES: u64 = 65536;

/// ISF 位域描述（bit_position, bit_length）。
type Bits = (u64, u64);
fn bits(isf: &Isf, path: &str) -> Result<Bits> {
    let field = isf.field("_MMPTE", path)?;
    Ok((
        field["type"]["bit_position"]
            .as_u64()
            .context("PTE 位域缺少位置")?,
        field["type"]["bit_length"]
            .as_u64()
            .context("PTE 位域缺少长度")?,
    ))
}
fn field_bits(value: u64, (pos, len): Bits) -> u64 {
    if len >= 64 {
        value >> pos
    } else {
        (value >> pos) & ((1u64 << len) - 1)
    }
}
/// `_MMPTE` 各视图的位布局，符号文件属性，解析一次。
struct PteLayout {
    size: u64,
    valid: Bits,
    hard_pfn: Bits,
    transition: Bits,
    trans_pfn: Bits,
}
fn pte_layout(isf: &Isf) -> Result<PteLayout> {
    Ok(PteLayout {
        size: isf.data["user_types"]["_MMPTE"]["size"]
            .as_u64()
            .context("缺少 _MMPTE")?,
        valid: bits(isf, "u.Hard.Valid")?,
        hard_pfn: bits(isf, "u.Hard.PageFrameNumber")?,
        transition: bits(isf, "u.Trans.Transition")?,
        trans_pfn: bits(isf, "u.Trans.PageFrameNumber")?,
    })
}
/// vol3 只认硬件有效与 transition 两种驻留；prototype/换出页无数据可得。
fn pte_frame(entry: u64, layout: &PteLayout) -> Option<u64> {
    if field_bits(entry, layout.valid) == 1 {
        Some(field_bits(entry, layout.hard_pfn))
    } else if field_bits(entry, layout.transition) == 1 {
        // transition PFN 的自定义高位（vol3 #475）按 33 位截断。
        Some(field_bits(entry, layout.trans_pfn) & ((1 << 33) - 1))
    } else {
        None
    }
}

/// (物理页, 文件偏移) 收集结果。
struct CachedFile {
    cache: &'static str,
    name: String,
    pages: BTreeMap<u64, u64>,
}

impl Windows<'_> {
    /// 校验并收集一个 _CONTROL_AREA 的全部驻留页（Subsection 单链表）。
    fn control_area_pages(&self, ca: u64, job: &Job) -> Result<BTreeMap<u64, u64>> {
        let isf = self.vm.isf;
        // vol3 CONTROL_AREA.is_valid：Segment 回指且尺寸吻合。
        let segment = self.number(ca, "_CONTROL_AREA", "Segment")?;
        ensure!(self.vm.kernel(segment), "Segment 无效");
        ensure!(
            self.number(segment, "_SEGMENT", "ControlArea")? == ca,
            "Segment 回指不一致"
        );
        let total_ptes = self.number(segment, "_SEGMENT", "TotalNumberOfPtes")?;
        ensure!(
            self.number(segment, "_SEGMENT", "SizeOfSegment")? == total_ptes * 4096,
            "Segment 尺寸与 PTE 数不一致"
        );
        ensure!(total_ptes <= MAX_FILE_PAGES, "文件 PTE 数超限");
        let image = self.number(ca, "_CONTROL_AREA", "u.Flags.Image")? == 1;
        // ImageSection 按 0x200 扇区对齐磁盘；DataSection 按页。
        let sector = if image { 0x200 } else { 0x1000 };
        let layout = pte_layout(isf)?;
        let ca_size = isf.data["user_types"]["_CONTROL_AREA"]["size"]
            .as_u64()
            .context("缺少 _CONTROL_AREA 大小")?;
        let mut pages = BTreeMap::new();
        let mut subsection = add(ca, ca_size)?;
        let mut seen = HashSet::new();
        loop {
            job.check()?;
            if subsection == 0 || !seen.insert(subsection) || seen.len() > MAX_OBJECTS {
                break;
            }
            let read = (|| -> Result<bool> {
                if self.number(subsection, "_SUBSECTION", "ControlArea")? != ca {
                    return Ok(false);
                }
                let base = self.number(subsection, "_SUBSECTION", "SubsectionBase")?;
                ensure!(self.vm.kernel(base), "SubsectionBase 无效");
                let count = self.number(subsection, "_SUBSECTION", "PtesInSubsection")?;
                ensure!(count <= MAX_FILE_PAGES, "Subsection PTE 数超限");
                let start = self
                    .number(subsection, "_SUBSECTION", "StartingSector")?
                    .checked_mul(sector)
                    .context("文件偏移溢出")?;
                for index in 0..count {
                    job.check()?;
                    let address = add(base, index * layout.size)?;
                    let entry = self.vm.uint(address, layout.size as usize)?;
                    if let Some(frame) = pte_frame(entry, &layout)
                        && frame != 0
                        && pages.insert(start + index * 4096, frame << 12).is_none()
                    {
                        ensure!(pages.len() <= MAX_FILE_PAGES as usize, "文件页数超限");
                    }
                }
                Ok(true)
            })();
            if !read? {
                break;
            }
            subsection = self.number(subsection, "_SUBSECTION", "NextSubsection")?;
        }
        Ok(pages)
    }

    /// 一个 FILE_OBJECT 的两类缓存；DeviceType 限定磁盘文件（排除管道/TCP 等）。
    fn file_caches(
        &self,
        file_object: u64,
        job: &Job,
    ) -> Result<Vec<(&'static str, BTreeMap<u64, u64>)>> {
        let device = self.number(file_object, "_FILE_OBJECT", "DeviceObject")?;
        ensure!(self.vm.kernel(device), "DeviceObject 无效");
        let device_type = self.number(device, "_DEVICE_OBJECT", "DeviceType")?;
        ensure!(
            device_type == FILE_DEVICE_DISK || device_type == FILE_DEVICE_NETWORK_FILE_SYSTEM,
            "非磁盘文件对象"
        );
        let pointers = self.number(file_object, "_FILE_OBJECT", "SectionObjectPointer")?;
        ensure!(self.vm.kernel(pointers), "SectionObjectPointer 无效");
        let mut out = Vec::new();
        for (field, cache) in [
            ("DataSectionObject", "DataSection"),
            ("ImageSectionObject", "ImageSection"),
        ] {
            let read = (|| -> Result<Option<u64>> {
                let ca = self.number(pointers, "_SECTION_OBJECT_POINTERS", field)?;
                if ca == 0 || !self.vm.kernel(ca) {
                    return Ok(None);
                }
                Ok(Some(ca))
            })();
            match read {
                Ok(Some(ca)) => out.push((cache, self.control_area_pages(ca, job)?)),
                Ok(None) => {}
                // 单个缓存不可用不影响另一类。
                Err(_) => {}
            }
        }
        Ok(out)
    }

    /// 该进程涉及的 FILE_OBJECT：句柄表 + 文件映射 VAD，去重。
    fn file_objects(&self, process: &Process, r: &mut Results, job: &Job) -> Result<Vec<u64>> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        let handles = (|| -> Result<Vec<u64>> {
            let table = self.number(process.address, "_EPROCESS", "ObjectTable")?;
            if table == 0 {
                return Ok(Vec::new());
            }
            self.handle_files(table, job)
        })();
        match handles {
            Ok(files) => out.extend(files),
            Err(e) => Self::issue(r, format!("PID {} handles", process.pid), e),
        }
        let vads = (|| -> Result<Vec<u64>> {
            let layout = self.vad_layout();
            let mut files = Vec::new();
            for vad in self.vads(process, job)? {
                job.check()?;
                let read = (|| -> Result<()> {
                    let control = if layout.direct_control {
                        self.number(vad.address, "_MMVAD", "ControlArea")?
                    } else {
                        let subsection = self.number(vad.address, "_MMVAD", "Subsection")?;
                        if subsection == 0 {
                            return Ok(());
                        }
                        self.number(subsection, "_SUBSECTION", "ControlArea")?
                    };
                    if control == 0 {
                        return Ok(());
                    }
                    let file_object = self.number(control, "_CONTROL_AREA", "FilePointer")?;
                    if file_object != 0 && self.vm.kernel(file_object) {
                        files.push(file_object);
                    }
                    Ok(())
                })();
                if let Err(e) = read {
                    Self::issue(
                        r,
                        format!("PID {} VAD {:#x}", process.pid as u32, vad.address),
                        e,
                    );
                }
            }
            Ok(files)
        })();
        match vads {
            Ok(files) => out.extend(files),
            Err(e) => Self::issue(r, format!("PID {} VAD", process.pid), e),
        }
        out.retain(|address| seen.insert(*address));
        ensure!(out.len() <= MAX_OBJECTS, "文件对象数量超限");
        Ok(out)
    }

    /// windows.dumpfiles：进程句柄与文件映射 VAD 涉及的驻留文件内容。
    pub(super) fn run_dumpfiles(
        &self,
        process: &Process,
        options: &DumpOptions,
        mut r: Results,
        job: &Job,
    ) -> Result<Results> {
        crate::dump::directory(&options.directory)?;
        let mut total = 0u64;
        let file_objects = self.file_objects(process, &mut r, job)?;
        for file_object in file_objects {
            job.check()?;
            let read = (|| -> Result<Vec<CachedFile>> {
                let name = self
                    .vm
                    .unicode(self.field(file_object, "_FILE_OBJECT", "FileName")?)
                    .unwrap_or_default();
                self.file_caches(file_object, job)?
                    .into_iter()
                    .filter(|(_, pages)| !pages.is_empty())
                    .map(|(cache, pages)| {
                        Ok(CachedFile {
                            cache,
                            name: name.clone(),
                            pages,
                        })
                    })
                    .collect()
            })();
            let caches = match read {
                Ok(caches) => caches,
                Err(e) => {
                    Self::issue(&mut r, hex(file_object), e);
                    continue;
                }
            };
            for cached in caches {
                job.check()?;
                let write = (|| -> Result<Vec<String>> {
                    let written = self.write_cached_file(
                        &cached,
                        process.pid as u32,
                        file_object,
                        options,
                        &mut total,
                        job,
                    )?;
                    Ok(written)
                })();
                match write {
                    Ok(row) => r.rows.push(row),
                    Err(e) => {
                        job.check()?;
                        Self::issue(&mut r, format!("文件 {file_object:#x}"), e);
                    }
                }
            }
        }
        Ok(r)
    }

    /// 按文件偏移写出驻留页；空洞保持稀疏（写零保留对齐）并计入哈希。
    fn write_cached_file(
        &self,
        cached: &CachedFile,
        pid: u32,
        file_object: u64,
        options: &DumpOptions,
        total: &mut u64,
        job: &Job,
    ) -> Result<Vec<String>> {
        let mut position = 0u64;
        let mut data = 0u64;
        let mut pages = 0u64;
        let extension = if cached.cache == "ImageSection" {
            "img"
        } else {
            "dat"
        };
        let base = sanitized_component(
            cached
                .name
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(&cached.name),
        );
        let mut tmp = tempfile::NamedTempFile::new_in(&options.directory)?;
        let mut hash = Sha256::new();
        let zeros = [0; 4096];
        for (offset, physical) in &cached.pages {
            job.check()?;
            let gap = offset.checked_sub(position).context("文件偏移倒置")?;
            Self::account(total, gap)?;
            let mut remaining = gap;
            while remaining > 0 {
                let n = (remaining as usize).min(zeros.len());
                tmp.write_all(&zeros[..n])?;
                hash.update(&zeros[..n]);
                remaining -= n as u64;
            }
            position += gap;
            let mut page = vec![0; 4096];
            self.vm.image.read(*physical, &mut page)?;
            tmp.write_all(&page)?;
            hash.update(&page);
            position += 4096;
            data += 4096;
            pages += 1;
            Self::account(total, 4096)?;
        }
        job.check()?;
        tmp.as_file().sync_all()?;
        let digest = format!("{:x}", hash.finalize());
        let file = Self::persist_dump(
            tmp,
            &options.directory,
            &format!(
                "windows-file-pid{pid}-{:#x}-{}-{base}-{extension}.{extension}",
                file_object,
                &digest[..16],
            ),
        )?;
        Ok(vec![
            pid.to_string(),
            cached.cache.into(),
            hex(file_object),
            cached.name.clone(),
            data.to_string(),
            pages.to_string(),
            digest,
            file,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;

    /// 构造 VAD → Subsection → ControlArea → FILE_OBJECT 链与两页驻留数据，
    /// 验证 dat 提取、空洞补零、哈希与清单一致。
    #[test]
    fn dumpfiles_extracts_resident_pages_with_sparse_holes() {
        let (mut b, mut isf) = fixture();
        let bit = |pos, len| serde_json::json!({"offset":0,"type":{"kind":"bitfield","bit_position":pos,"bit_length":len,"type":{"kind":"base","name":"u32"}}});
        let ptr = |offset| serde_json::json!({"offset":offset,"type":{"kind":"pointer"}});
        let number =
            |offset| serde_json::json!({"offset":offset,"type":{"kind":"base","name":"u64"}});
        isf.data["user_types"]["_MMVAD_SHORT"] = serde_json::json!({
            "size": 56,
            "fields": {
                "VadNode": {"offset": 0, "type": {"kind": "struct", "name": "_RTL_BALANCED_NODE"}},
                "StartingVpn": number(24),
                "EndingVpn": number(32),
                "u": {"offset": 40, "type": {"kind": "struct", "name": "_MMVAD_FLAGS"}}
            }
        });
        isf.data["user_types"]["_MMVAD"] = serde_json::json!({
            "size": 64,
            "fields": {"Subsection": ptr(56)}
        });
        isf.data["user_types"]["_RTL_BALANCED_NODE"] = serde_json::json!({
            "size": 24,
            "fields": {
                "LeftChild": ptr(0), "RightChild": ptr(8), "ParentValue": ptr(16)
            }
        });
        isf.data["user_types"]["_MMVAD_FLAGS"] = serde_json::json!({
            "size": 16,
            "fields": {"Protection": number(0), "PrivateMemory": number(8)}
        });
        isf.data["user_types"]["_EPROCESS"]["fields"]["VadRoot"] =
            serde_json::json!({"offset": 120, "type": {"kind": "pointer"}});
        isf.data["user_types"]["_SUBSECTION"] = serde_json::json!({
            "size": 32,
            "fields": {
                "ControlArea": ptr(0), "SubsectionBase": ptr(8),
                "PtesInSubsection": {"offset": 16, "type": {"kind": "base", "name": "u16"}},
                "StartingSector": {"offset": 20, "type": {"kind": "base", "name": "u32"}},
                "NextSubsection": ptr(24)
            }
        });
        isf.data["user_types"]["_MMSECTION_FLAGS"] =
            serde_json::json!({"size": 4, "fields": {"Image": bit(5, 1)}});
        isf.data["user_types"]["_CONTROL_AREA_U"] = serde_json::json!({
            "size": 4,
            "fields": {
                "Flags": {"offset": 0, "type": {"kind": "struct", "name": "_MMSECTION_FLAGS"}}
            }
        });
        isf.data["user_types"]["_CONTROL_AREA"] = serde_json::json!({
            "size": 24,
            "fields": {
                "Segment": ptr(0), "FilePointer": ptr(8),
                "u": {"offset": 16, "type": {"kind": "union", "name": "_CONTROL_AREA_U"}}
            }
        });
        isf.data["user_types"]["_SEGMENT"] = serde_json::json!({
            "size": 24,
            "fields": {"ControlArea": ptr(0), "SizeOfSegment": number(8), "TotalNumberOfPtes": number(16)}
        });
        isf.data["user_types"]["_FILE_OBJECT"] = serde_json::json!({
            "size": 32,
            "fields": {
                "DeviceObject": ptr(0),
                "SectionObjectPointer": ptr(8),
                "FileName": {"offset": 16, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
            }
        });
        isf.data["user_types"]["_DEVICE_OBJECT"] = serde_json::json!({
            "size": 8,
            "fields": {"DeviceType": {"offset": 0, "type": {"kind": "base", "name": "u32"}}}
        });
        isf.data["user_types"]["_SECTION_OBJECT_POINTERS"] = serde_json::json!({
            "size": 16,
            "fields": {"DataSectionObject": ptr(0), "ImageSectionObject": ptr(8)}
        });
        isf.data["user_types"]["_MMPTE"] = serde_json::json!({
            "size": 8,
            "fields": {
                "u": {"offset": 0, "type": {"kind": "struct", "name": "_MMPTE_UNION"}}
            }
        });
        isf.data["user_types"]["_MMPTE_UNION"] = serde_json::json!({
            "size": 8,
            "fields": {
                "Hard": {"offset": 0, "type": {"kind": "struct", "name": "_MMPTE_HARDWARE"}},
                "Trans": {"offset": 0, "type": {"kind": "struct", "name": "_MMPTE_TRANSITION"}},
                "Soft": {"offset": 0, "type": {"kind": "struct", "name": "_MMPTE_SOFTWARE"}}
            }
        });
        isf.data["user_types"]["_MMPTE_HARDWARE"] = serde_json::json!({"size": 8, "fields": {"Valid": bit(0, 1), "PageFrameNumber": bit(12, 36)}});
        isf.data["user_types"]["_MMPTE_TRANSITION"] = serde_json::json!({"size": 8, "fields": {"Transition": bit(11, 1), "PageFrameNumber": bit(12, 36)}});
        isf.data["user_types"]["_MMPTE_SOFTWARE"] =
            serde_json::json!({"size": 8, "fields": {"Prototype": bit(10, 1)}});
        isf.data["base_types"]["u32"] = serde_json::json!({"size": 4});
        isf.invalidate_layouts();

        // 用户 VA 0x9000（VAD 页）不需要映射：dumpfiles 只读内核侧结构。
        let node = 0x26000;
        put(&mut b, node + 16, K + 0x1e000);
        put(&mut b, node + 24, 9);
        put(&mut b, node + 32, 9);
        put(&mut b, node + 40, 4);
        put(&mut b, node + 48, 1); // private：跳过 VAD 文件名解析
        put(&mut b, node + 56, K + 0x1e118); // Subsection
        put(&mut b, 0xa000 + 120, K + 0x1e000); // child EPROCESS VadRoot

        let ca = 0x26100;
        put(&mut b, ca, K + 0x1e140); // Segment
        put(&mut b, ca + 8, K + 0x1e300); // FilePointer
        put(&mut b, ca + 16, 0); // DataSection（Image=0 → 0x1000 扇区）
        let subsection = ca + 24;
        put(&mut b, subsection, K + 0x1e100);
        put(&mut b, subsection + 8, K + 0x1e200); // PTE 数组
        b[subsection + 16..subsection + 18].copy_from_slice(&2u16.to_le_bytes());
        b[subsection + 20..subsection + 24].copy_from_slice(&2u32.to_le_bytes()); // 文件偏移 0x2000 起
        put(&mut b, subsection + 24, 0);
        let segment = 0x26140;
        put(&mut b, segment, K + 0x1e100);
        put(&mut b, segment + 8, 2 * 4096);
        put(&mut b, segment + 16, 2);
        // PTE[0] valid → 物理 0x11000；PTE[1] transition → 物理 0x12000。
        put(&mut b, 0x26200, 1 | (0x11 << 12));
        put(&mut b, 0x26208, 0x800 | (0x12 << 12));
        b[0x11000..0x12000].fill(0xAA);
        b[0x12000..0x13000].fill(0xBB);

        let file_object = 0x26300;
        put(&mut b, file_object, K + 0x1e400);
        put(&mut b, file_object + 8, K + 0x1e500);
        b[file_object + 16..file_object + 18].copy_from_slice(&18u16.to_le_bytes());
        b[file_object + 18..file_object + 20].copy_from_slice(&20u16.to_le_bytes());
        put(&mut b, file_object + 24, K + 0x1e600);
        b[0x26400..0x26404].copy_from_slice(&7u32.to_le_bytes()); // FILE_DEVICE_DISK
        put(&mut b, 0x26500, K + 0x1e100); // DataSectionObject
        let name: Vec<u8> = "notes.txt"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        b[0x26600..0x26600 + name.len()].copy_from_slice(&name);

        let image = image(&b);
        let engine = Windows {
            vm: Memory::new(&image, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let dir = tempfile::tempdir().unwrap();
        let options = DumpOptions {
            pid: 8,
            directory: dir.path().into(),
            start: None,
            end: None,
        };
        let r = engine
            .run_dump(Plugin::WinDumpfiles, &options, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 1);
        let row = &r.rows[0];
        assert_eq!(
            &row[..4],
            &["8", "DataSection", &hex(K + 0x1e300), "notes.txt"]
        );
        assert_eq!(row[4], "8192");
        assert_eq!(row[5], "2");
        let mut expected = vec![0u8; 0x2000];
        expected.extend_from_slice(&b[0x11000..0x13000]);
        assert_eq!(row[6], format!("{:x}", Sha256::digest(&expected)));
        assert_eq!(std::fs::read(&row[7]).unwrap(), expected);
        let name = row[7].rsplit('/').next().unwrap();
        assert!(
            name.starts_with("windows-file-pid8-0xffff80000001e300-")
                && name.ends_with("-notes.txt-dat.dat"),
            "{name}"
        );
    }

    /// Segment 校验失败（回指不一致）时该文件跳过并诊断，不影响整体。
    #[test]
    fn dumpfiles_rejects_inconsistent_segment_backreference() {
        let (mut b, mut isf) = fixture();
        let bit = |pos, len| serde_json::json!({"offset":0,"type":{"kind":"bitfield","bit_position":pos,"bit_length":len,"type":{"kind":"base","name":"u32"}}});
        let ptr = |offset| serde_json::json!({"offset":offset,"type":{"kind":"pointer"}});
        isf.data["user_types"]["_MMPTE"] = serde_json::json!({
            "size": 8,
            "fields": {"u": {"offset": 0, "type": {"kind": "struct", "name": "_MMPTE_UNION"}}}
        });
        isf.data["user_types"]["_MMPTE_UNION"] = serde_json::json!({
            "size": 8,
            "fields": {
                "Hard": {"offset": 0, "type": {"kind": "struct", "name": "_MMPTE_HARDWARE"}},
                "Trans": {"offset": 0, "type": {"kind": "struct", "name": "_MMPTE_TRANSITION"}},
                "Soft": {"offset": 0, "type": {"kind": "struct", "name": "_MMPTE_SOFTWARE"}}
            }
        });
        isf.data["user_types"]["_MMPTE_HARDWARE"] = serde_json::json!({"size": 8, "fields": {"Valid": bit(0, 1), "PageFrameNumber": bit(12, 36)}});
        isf.data["user_types"]["_MMPTE_TRANSITION"] = serde_json::json!({"size": 8, "fields": {"Transition": bit(11, 1), "PageFrameNumber": bit(12, 36)}});
        isf.data["user_types"]["_MMPTE_SOFTWARE"] =
            serde_json::json!({"size": 8, "fields": {"Prototype": bit(10, 1)}});
        isf.data["user_types"]["_SEGMENT"] = serde_json::json!({
            "size": 24,
            "fields": {"ControlArea": ptr(0), "SizeOfSegment": {"offset": 8, "type": {"kind": "base", "name": "u64"}}, "TotalNumberOfPtes": {"offset": 16, "type": {"kind": "base", "name": "u64"}}}
        });
        isf.data["user_types"]["_CONTROL_AREA"] = serde_json::json!({
            "size": 24,
            "fields": {"Segment": ptr(0)}
        });
        isf.invalidate_layouts();
        // Segment.ControlArea 指向别处：校验失败。
        put(&mut b, 0x26100, K + 0x1e140);
        put(&mut b, 0x26140, K + 0x1ffff);
        let image = image(&b);
        let engine = Windows {
            vm: Memory::new(&image, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = engine
            .control_area_pages(K + 0x1e100, &Job::default())
            .unwrap_err();
        assert!(r.to_string().contains("回指不一致"));
    }
}
