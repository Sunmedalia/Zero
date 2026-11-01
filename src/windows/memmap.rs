//! Intel page-table mappings, projected to the pinned Memmap contract.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Backing {
    Physical,
    Pagefile(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Mapping {
    pub(super) virtual_start: u64,
    pub(super) physical_start: u64,
    pub(super) size: u64,
    pub(super) backing: Backing,
}
struct Walker<'a, 'b> {
    vm: &'a Memory<'b>,
    geometry: Paging,
    job: &'a Job,
    maps: Vec<Mapping>,
    tables: usize,
    omitted: usize,
    first_error: Option<String>,
}
impl Walker<'_, '_> {
    fn omit(&mut self, error: impl std::fmt::Display) {
        self.omitted += 1;
        self.first_error.get_or_insert_with(|| error.to_string());
    }
    fn mask(&self) -> u64 {
        let bits = match (self.geometry.arch, self.geometry.pae) {
            (Architecture::X64, _) => 45,
            (_, true) => 40,
            _ => 32,
        };
        ((1u64 << bits) - 1) & !0xfff
    }
    fn captured(&self, backing: Backing, start: u64, size: u64) -> bool {
        match backing {
            Backing::Pagefile(index) => self
                .vm
                .sources
                .is_some_and(|s| s.mapping_valid(index, start, size)),
            Backing::Physical => {
                let Some(end) = start.checked_add(size) else {
                    return false;
                };
                let mut at = start;
                for segment in &self.vm.image.segments {
                    if segment.end <= at {
                        continue;
                    }
                    if segment.start > at {
                        return false;
                    }
                    at = segment.end.min(end);
                    if at == end {
                        return true;
                    }
                }
                false
            }
        }
    }
    fn append(&mut self, map: Mapping) -> Result<()> {
        if !self.captured(map.backing, map.physical_start, map.size) {
            self.omit(format!(
                "未采集映射 {:?} {:#x}+{:#x}",
                map.backing, map.physical_start, map.size
            ));
            return Ok(());
        }
        if let Some(last) = self.maps.last_mut()
            && last.backing == map.backing
            && last.virtual_start + last.size == map.virtual_start
            && last.physical_start + last.size == map.physical_start
        {
            last.size += map.size;
            return Ok(());
        }
        ensure!(self.maps.len() < MAX_OBJECTS, "Memmap 区间超过上限");
        self.maps.push(map);
        Ok(())
    }
    fn table(&mut self, address: u64, level: usize, virtual_base: u64) -> Result<()> {
        self.job.check()?;
        self.tables += 1;
        ensure!(self.tables <= 262144, "Memmap 页表读取超过上限");
        let mut bytes = [0u8; 4096];
        if let Err(error) = self.vm.image.read(address, &mut bytes) {
            self.omit(format!("页表 {address:#x}: {error:#}"));
            return Ok(());
        }
        let width = self.geometry.width();
        if bytes
            .chunks_exact(width)
            .all(|chunk| chunk == &bytes[..width])
        {
            if bytes[..width].iter().any(|b| *b != 0) {
                self.omit(format!("重复内容页表 {address:#x}"));
            }
            return Ok(());
        }
        let shift = self.geometry.shifts()[level];
        let limit = if self.geometry.arch == Architecture::X64 {
            (1u64 << 48) - 1
        } else {
            u32::MAX as u64
        };
        for (index, chunk) in bytes
            .chunks_exact(width)
            .take(self.geometry.entries(level))
            .enumerate()
        {
            if index.is_multiple_of(64) {
                self.job.check()?;
            }
            let mut word = [0; 8];
            word[..width].copy_from_slice(chunk);
            let entry = u64::from_le_bytes(word);
            let virtual_start = virtual_base + ((index as u64) << shift);
            let size = (1u64 << shift).min(limit - virtual_start);
            if size == 0 {
                continue;
            }
            let valid = entry & 1 != 0 || (entry & (1 << 11) != 0 && entry & (1 << 10) == 0);
            if !valid {
                let swap_shift = match (self.geometry.arch, self.geometry.pae) {
                    (Architecture::X64, _) => 32,
                    (_, true) => 32,
                    _ => 12,
                };
                let page = entry.checked_shr(swap_shift).unwrap_or(0);
                if entry & ((1 << 11) | (1 << 10) | 1) == 0 && entry & 128 != 0 && page != 0 {
                    let backing = Backing::Pagefile(((entry >> 1) & 15) as u8);
                    if let Some(physical_start) = page.checked_mul(1u64 << shift) {
                        self.append(Mapping {
                            virtual_start,
                            physical_start,
                            size,
                            backing,
                        })?;
                    } else {
                        self.omit("分页映射偏移溢出");
                    }
                }
                continue;
            }
            let large = entry & 128 != 0
                && (shift == 21 || shift == 30 || (shift == 22 && !self.geometry.pae));
            if shift == 12 || large {
                // The reference clears PAT but otherwise keeps the PFN bits,
                // including reserved bits in malformed large-page entries.
                let physical_start =
                    (entry & self.mask()) & if large { !(1 << 12) } else { u64::MAX };
                self.append(Mapping {
                    virtual_start,
                    physical_start,
                    size,
                    backing: Backing::Physical,
                })?;
            } else {
                self.table(entry & self.mask(), level + 1, virtual_start)?;
            }
        }
        Ok(())
    }
}
pub(super) fn mappings(vm: &Memory<'_>, job: &Job) -> Result<(Vec<Mapping>, Vec<String>)> {
    let geometry = vm.paging()?;
    ensure!(
        matches!(geometry.arch, Architecture::X86 | Architecture::X64),
        "Memmap 目前仅支持 Intel x86/x64 页表"
    );
    let mut walker = Walker {
        vm,
        geometry,
        job,
        maps: Vec::new(),
        tables: 0,
        omitted: 0,
        first_error: None,
    };
    let root_mask = walker.mask() | if geometry.pae { 0xfe0 } else { 0 };
    let walk = walker.table(vm.root & root_mask, 0, 0);
    job.check()?;
    if let Err(error) = walk {
        walker.omit(error);
    }
    let diagnostics = walker
        .first_error
        .map(|first| {
            vec![format!(
                "Memmap 省略 {} 处不可读／无效映射；首处：{first}",
                walker.omitted
            )]
        })
        .unwrap_or_default();
    Ok((walker.maps, diagnostics))
}
impl Windows<'_> {
    pub(super) fn memmap(
        &self,
        options: &Options,
        dump: Option<&DumpOptions>,
        job: &Job,
    ) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "Memmap 不支持此架构"
        );
        let (processes, diagnostics) = self.processes_partial(job)?;
        let pid = dump
            .map(|d| u64::from(d.pid))
            .or(options.pid.map(u64::from));
        let mut result = self.result(Plugin::WinMemmap);
        result.complete = diagnostics.is_empty();
        result.diagnostics = diagnostics;
        let mut matched = false;
        'processes: for process in processes
            .into_iter()
            .filter(|p| pid.is_none_or(|pid| pid == p.pid))
        {
            matched = true;
            job.check()?;
            let vm = match self.process_memory(&process) {
                Ok(vm) => vm,
                Err(error) => {
                    Self::issue(&mut result, format!("Memmap PID {}", process.pid), error);
                    continue;
                }
            };
            let (maps, diagnostics) = mappings(&vm, job)?;
            for diagnostic in diagnostics {
                Self::issue(&mut result, format!("PID {}", process.pid), diagnostic);
            }
            let output = if let Some(options) = dump {
                {
                    let (name, digest, size) =
                        self.export_memmap(&vm, process.pid, &maps, options, job)?;
                    result.kernel_identity["memmap_export"] = serde_json::json!({"pid":process.pid,"filename":name,"sha256":digest,"bytes":size});
                    name
                }
            } else {
                "Disabled".to_owned()
            };
            let mut file_offset = 0u64;
            for map in maps {
                if result.rows.len() == MAX_OBJECTS {
                    Self::issue(&mut result, "Memmap", "总映射区间超过上限");
                    break 'processes;
                }
                result.rows.push(vec![
                    hex(map.virtual_start),
                    hex(map.physical_start),
                    hex(map.size),
                    hex(file_offset),
                    output.clone(),
                ]);
                file_offset += map.size;
            }
        }
        ensure!(pid.is_none() || matched, "目标 PID 不存在");
        Ok(result)
    }
    fn export_memmap(
        &self,
        vm: &Memory<'_>,
        pid: u64,
        maps: &[Mapping],
        options: &DumpOptions,
        job: &Job,
    ) -> Result<(String, String, u64)> {
        use std::io::Write;
        options.validate(Plugin::WinMemmap)?;
        let mut total = 0;
        for map in maps {
            Self::account(&mut total, map.size)?;
        }
        crate::dump::directory(&options.directory)?;
        let mut tmp = tempfile::NamedTempFile::new_in(&options.directory)?;
        let mut bytes = vec![0; 1024 * 1024];
        let mut hash = sha2::Sha256::new();
        for map in maps {
            let mut offset = 0;
            while offset < map.size {
                job.check()?;
                let count = usize::try_from((map.size - offset).min(bytes.len() as u64))?;
                match map.backing {
                    Backing::Physical => vm
                        .image
                        .read(map.physical_start + offset, &mut bytes[..count])?,
                    Backing::Pagefile(index) => vm.sources.context("缺少分页附件")?.read(
                        index,
                        map.physical_start + offset,
                        &mut bytes[..count],
                    )?,
                }
                tmp.write_all(&bytes[..count])?;
                hash.update(&bytes[..count]);
                offset += count as u64;
            }
        }
        job.check()?;
        tmp.as_file().sync_all()?;
        let name = format!("pid.{pid}.dmp");
        Self::persist_dump(tmp, &options.directory, &name)?;
        Ok((name, format!("{:x}", hash.finalize()), total))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{fixture, image, put};
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn large_page_pat_and_transition_pfn_mask() {
        let (mut bytes, isf) = fixture();
        bytes.resize(0x600000, 0);
        bytes[0x1000..0x5000].fill(0);
        put(&mut bytes, 0x1000, 0x2003);
        put(&mut bytes, 0x2000, 0x3003);
        put(&mut bytes, 0x3000, 0x201083); // 2 MiB + PAT
        put(&mut bytes, 0x3008, 0x4003);
        put(&mut bytes, 0x4000, (1 << 45) | 0x8800);
        let img = image(&bytes);
        let vm = Memory::new(&img, 0x1000, &isf, None);
        let (maps, diagnostics) = mappings(&vm, &Job::default()).unwrap();
        assert!(diagnostics.is_empty());
        assert_eq!(maps[0].size, 0x200000);
        assert_eq!(maps[0].physical_start, 0x200000);
        assert_eq!(maps[1].physical_start, 0x8000);
        // A large page must be fully present: one physical hole excludes it.
        let mut img = image(&bytes);
        img.segments[0].end = 0x300000;
        let vm = Memory::new(&img, 0x1000, &isf, None);
        let (maps, diagnostics) = mappings(&vm, &Job::default()).unwrap();
        assert_eq!(maps.len(), 1);
        assert!(!diagnostics.is_empty());
    }
    #[test]
    fn atomic_export_hash_limit_and_target_policy() {
        let (bytes, isf) = fixture();
        let img = image(&bytes);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: super::super::tests::K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let dir = tempfile::tempdir().unwrap();
        let options = DumpOptions {
            pid: 4,
            directory: dir.path().to_owned(),
            start: None,
            end: None,
        };
        let maps = vec![
            Mapping {
                virtual_start: 0,
                physical_start: 0x8000,
                size: 4096,
                backing: Backing::Physical,
            },
            Mapping {
                virtual_start: 8192,
                physical_start: 0xa000,
                size: 4096,
                backing: Backing::Physical,
            },
        ];
        let (name, digest, size) = engine
            .export_memmap(&engine.vm, 4, &maps, &options, &Job::default())
            .unwrap();
        let expected = [&bytes[0x8000..0x9000], &bytes[0xa000..0xb000]].concat();
        assert_eq!(std::fs::read(dir.path().join(&name)).unwrap(), expected);
        assert_eq!(digest, format!("{:x}", sha2::Sha256::digest(&expected)));
        assert_eq!(size, 8192);
        let too_large = [Mapping {
            size: crate::dump::MAX_DUMP_BYTES + 1,
            ..maps[0]
        }];
        assert!(
            engine
                .export_memmap(&engine.vm, 8, &too_large, &options, &Job::default())
                .is_err()
        );
        assert!(!dir.path().join("pid.8.dmp").exists());
        let bad_read = [Mapping {
            physical_start: 0xfffff000,
            ..maps[0]
        }];
        assert!(
            engine
                .export_memmap(&engine.vm, 8, &bad_read, &options, &Job::default())
                .is_err()
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(
            DumpOptions {
                pid: 0,
                ..options.clone()
            }
            .validate(Plugin::WinMemmap)
            .is_err()
        );
        assert!(
            DumpOptions {
                start: Some(0),
                end: Some(4096),
                ..options
            }
            .validate(Plugin::WinMemmap)
            .is_err()
        );
    }
    #[test]
    fn explicit_pagefile_mapping_and_read_provenance() {
        use std::io::Write;
        let (mut bytes, isf) = fixture();
        bytes[0x1000..0x5000].fill(0);
        put(&mut bytes, 0x1000, 0x2003);
        put(&mut bytes, 0x2000, 0x3003);
        put(&mut bytes, 0x3000, 0x4003);
        put(&mut bytes, 0x4000, (1 << 32) | 128 | (3 << 1));
        let img = image(&bytes);
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&vec![0x5a; 8192]).unwrap();
        let options = Options {
            pagefiles: vec![paging::Attachment {
                index: 3,
                path: file.path().to_owned(),
            }],
            ..Options::default()
        };
        let sources = paging::Sources::open(&options, &Job::default()).unwrap();
        let vm = Memory::new(&img, 0x1000, &isf, Some(&sources));
        let (maps, diagnostics) = mappings(&vm, &Job::default()).unwrap();
        assert!(diagnostics.is_empty());
        assert_eq!(
            maps,
            vec![Mapping {
                virtual_start: 0,
                physical_start: 4096,
                size: 4096,
                backing: Backing::Pagefile(3)
            }]
        );
        let engine = Windows {
            vm,
            base: super::super::tests::K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let dir = tempfile::tempdir().unwrap();
        let dump = DumpOptions {
            pid: 4,
            directory: dir.path().to_owned(),
            start: None,
            end: None,
        };
        engine
            .export_memmap(&engine.vm, 4, &maps, &dump, &Job::default())
            .unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("pid.4.dmp")).unwrap(),
            vec![0x5a; 4096]
        );
        assert!(sources.manifest().unwrap().to_string().contains("4096"));
        let unattached = Memory::new(&img, 0x1000, &isf, None);
        let (maps, diagnostics) = mappings(&unattached, &Job::default()).unwrap();
        assert!(maps.is_empty());
        assert!(diagnostics[0].contains("Pagefile(3)"));
        // PAE entries are 64 bits, but the reference swap encoding shifts
        // by its 32-bit register width, just like x64's half-width shift.
        let mut pae_isf =
            Isf::parse(&serde_json::to_vec(&isf.data).unwrap(), "pae.json".into()).unwrap();
        pae_isf.data["metadata"]["windows"]["pdb"]["machine_type"] = serde_json::json!(0x14c);
        pae_isf.data["metadata"]["windows"]["paging"] = serde_json::json!("pae");
        pae_isf.data["base_types"]["pointer"]["size"] = serde_json::json!(4);
        put(&mut bytes, 0x3000, (1 << 32) | 128 | (3 << 1));
        let pae_img = image(&bytes);
        let pae_vm = Memory::new(&pae_img, 0x1000, &pae_isf, Some(&sources));
        let (maps, diagnostics) = mappings(&pae_vm, &Job::default()).unwrap();
        assert!(diagnostics.is_empty());
        assert_eq!(maps[0].physical_start, 4096);
        assert_eq!(maps[0].backing, Backing::Pagefile(3));
    }
    #[test]
    fn listing_filters_processes_internally_and_export_uses_same_rows() {
        let (bytes, isf) = fixture();
        let img = image(&bytes);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: super::super::tests::K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let options = Options {
            pid: Some(4),
            ..Options::default()
        };
        let listed = engine.memmap(&options, None, &Job::default()).unwrap();
        assert!(!listed.rows.is_empty());
        assert!(listed.rows.iter().all(|row| row[4] == "Disabled"));
        let all = engine
            .memmap(&Options::default(), None, &Job::default())
            .unwrap();
        assert!(all.rows.len() > listed.rows.len());
        let dir = tempfile::tempdir().unwrap();
        let dump = DumpOptions {
            pid: 4,
            directory: dir.path().to_owned(),
            start: None,
            end: None,
        };
        let exported = engine
            .run_dump(Plugin::WinMemmap, &dump, &Job::default())
            .unwrap();
        assert_eq!(listed.rows.len(), exported.rows.len());
        for (left, right) in listed.rows.iter().zip(&exported.rows) {
            assert_eq!(left[..4], right[..4]);
            assert_eq!(right[4], "pid.4.dmp");
        }
        assert_eq!(
            exported.kernel_identity["memmap_export"]["filename"],
            "pid.4.dmp"
        );
        assert!(
            engine
                .memmap(
                    &Options {
                        pid: Some(999),
                        ..Options::default()
                    },
                    None,
                    &Job::default()
                )
                .is_err()
        );
    }
    #[test]
    fn present_transition_prototype_and_both_axes_merge() {
        let (mut bytes, isf) = fixture();
        bytes[0x1000..0x5000].fill(0);
        put(&mut bytes, 0x1000, 0x2003);
        put(&mut bytes, 0x2000, 0x3003);
        put(&mut bytes, 0x3000, 0x4003);
        put(&mut bytes, 0x4000, 0x8003);
        put(&mut bytes, 0x4008, 0x9800); // transition
        put(&mut bytes, 0x4010, 0xac00); // prototype, excluded
        put(&mut bytes, 0x4018, 0xb003);
        put(&mut bytes, 0x4020, 0xd003); // physical discontinuity
        let img = image(&bytes);
        let vm = Memory::new(&img, 0x1000, &isf, None);
        let (maps, diagnostics) = mappings(&vm, &Job::default()).unwrap();
        assert!(diagnostics.is_empty());
        assert_eq!(
            maps,
            vec![
                Mapping {
                    virtual_start: 0,
                    physical_start: 0x8000,
                    size: 8192,
                    backing: Backing::Physical
                },
                Mapping {
                    virtual_start: 0x3000,
                    physical_start: 0xb000,
                    size: 4096,
                    backing: Backing::Physical
                },
                Mapping {
                    virtual_start: 0x4000,
                    physical_start: 0xd000,
                    size: 4096,
                    backing: Backing::Physical
                },
            ]
        );
    }
    #[test]
    fn aliases_are_retained_and_cancel_propagates() {
        let (mut bytes, isf) = fixture();
        bytes[0x1000..0x5000].fill(0);
        put(&mut bytes, 0x1000, 0x2003);
        put(&mut bytes, 0x1008, 0x2003);
        put(&mut bytes, 0x2000, 0x3003);
        put(&mut bytes, 0x3000, 0x4003);
        put(&mut bytes, 0x4000, 0x8003);
        let img = image(&bytes);
        let vm = Memory::new(&img, 0x1000, &isf, None);
        let (maps, _) = mappings(&vm, &Job::default()).unwrap();
        assert_eq!(maps.len(), 2);
        assert_eq!(maps[1].virtual_start, 1 << 39);
        let job = Job::default();
        job.cancel.store(true, Ordering::Relaxed);
        assert!(mappings(&vm, &job).is_err());
    }
    #[test]
    fn uniform_tables_and_missing_physical_pages_are_excluded() {
        let (mut bytes, isf) = fixture();
        bytes[0x1000..0x5000].fill(0);
        put(&mut bytes, 0x1000, 0x2003);
        put(&mut bytes, 0x2000, 0x3003);
        put(&mut bytes, 0x3000, 0x4003);
        for i in 0..512 {
            put(&mut bytes, 0x4000 + 8 * i, 0x8003);
        }
        let img = image(&bytes);
        let vm = Memory::new(&img, 0x1000, &isf, None);
        let (maps, diagnostics) = mappings(&vm, &Job::default()).unwrap();
        assert!(maps.is_empty());
        assert_eq!(diagnostics.len(), 1);
        put(&mut bytes, 0x4000, 0x90003);
        bytes[0x4008..0x5000].fill(0);
        let img = image(&bytes);
        let vm = Memory::new(&img, 0x1000, &isf, None);
        let (maps, diagnostics) = mappings(&vm, &Job::default()).unwrap();
        assert!(maps.is_empty());
        assert!(diagnostics[0].contains("未采集映射"));
    }
    #[test]
    fn highest_address_uses_raw_48_bits_and_excludes_last_byte() {
        let (mut bytes, isf) = fixture();
        bytes[0x1000..0x5000].fill(0);
        for (at, entry) in [
            (0x1ff8, 0x2003),
            (0x2ff8, 0x3003),
            (0x3ff8, 0x4003),
            (0x4ff8, 0x8003),
        ] {
            put(&mut bytes, at, entry);
        }
        let img = image(&bytes);
        let vm = Memory::new(&img, 0x1000, &isf, None);
        let (maps, _) = mappings(&vm, &Job::default()).unwrap();
        assert_eq!(maps[0].virtual_start, 0xfffffffff000);
        assert_eq!(maps[0].size, 4095);
    }
    #[test]
    fn x86_and_pae_geometry() {
        let (mut bytes, mut isf) = fixture();
        isf.data["metadata"]["windows"]["pdb"]["machine_type"] = serde_json::json!(0x14c);
        isf.data["base_types"]["pointer"]["size"] = serde_json::json!(4);
        bytes[0x1000..0x5000].fill(0);
        bytes[0x1000..0x1004].copy_from_slice(&0x2003u32.to_le_bytes());
        bytes[0x2000..0x2004].copy_from_slice(&0x8003u32.to_le_bytes());
        let img = image(&bytes);
        let vm = Memory::new(&img, 0x1000, &isf, None);
        assert_eq!(
            mappings(&vm, &Job::default()).unwrap().0[0].physical_start,
            0x8000
        );
        isf.data["metadata"]["windows"]["paging"] = serde_json::json!("pae");
        bytes[0x1000..0x5000].fill(0);
        put(&mut bytes, 0x1020, 0x2003);
        put(&mut bytes, 0x2000, 0x3003);
        put(&mut bytes, 0x3000, 0x9003);
        let img = image(&bytes);
        let vm = Memory::new(&img, 0x1020, &isf, None);
        assert_eq!(
            mappings(&vm, &Job::default()).unwrap().0[0].physical_start,
            0x9000
        );
    }
}
