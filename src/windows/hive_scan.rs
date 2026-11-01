//! Registry pool allocation candidates, independent of the live hive list.
use super::*;
use std::collections::BTreeSet;

impl Windows<'_> {
    pub(super) fn hive_scan(&self, job: &Job) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "HiveScan 仅支持 x86/x64"
        );
        let mut r = self.result(Plugin::WinHiveScan);
        if let Err(error) = self.hive_scan_rows(&mut r, job) {
            job.check()?;
            Self::issue(&mut r, "HiveScan", format!("{error:#}"));
        }
        Ok(r)
    }
    fn hive_scan_rows(&self, r: &mut Results, job: &Job) -> Result<()> {
        let build = self.build_number()?;
        let big_pool = self.vm.pointer_size() == 8 && build >= 9600;
        let size = self.vm.isf.data.key("user_types")["_CMHIVE"]
            .key("size")
            .as_u64()
            .context("缺少 _CMHIVE 类型")?;
        ensure!((800..=65536).contains(&size), "CMHIVE 类型大小无效");
        if big_pool {
            *r.kernel_identity.key_mut("hive_scan")? = serde_json::json!({"source":"allocated CM10 big-pool entries", "offset_layer":"kernel virtual", "validation":"allocation candidates; no CMHIVE signature test"});
            return self.walk_big_pool_entries(r, job, |va, key, _, r| {
                if key == u32::from_le_bytes(*b"CM10") {
                    ensure!(r.rows.len() < MAX_OBJECTS, "hive 候选数量超限");
                    r.rows.push(vec![hex(va)]);
                }
                Ok(())
            });
        }
        let pool_size = self.vm.isf.data.key("user_types")["_POOL_HEADER"]
            .key("size")
            .as_u64()
            .context("缺少 POOL_HEADER 大小")?;
        ensure!((8..=64).contains(&pool_size), "池头大小无效");
        let tag_offset = self.vm.isf.offset("_POOL_HEADER", "PoolTag")?;
        ensure!(tag_offset + 4 <= pool_size, "池 tag 越界");
        let align = if self.vm.pointer_size() == 4 { 8 } else { 16 };
        let mut candidates = BTreeSet::new();
        let mut header_bytes = vec![0; usize::try_from(pool_size)?];
        self.prefetch_pool_tags(job)?;
        for hit in self.vm.image.scan(b"CM10", job)? {
            job.check()?;
            let Some(header) = hit.checked_sub(tag_offset) else {
                continue;
            };
            if self.vm.image.read(header, &mut header_bytes).is_err() {
                continue;
            }
            let block =
                objects::physical_number(self.vm.isf, &header_bytes, "_POOL_HEADER", "BlockSize")?
                    .checked_mul(align)
                    .context("hive 池大小溢出")?;
            // Reference HiveScan requires only total size >= 800. It does not
            // enforce physical alignment or validate the CMHIVE body, so even
            // incidental text can qualify as an allocation candidate.
            if block < 800 {
                continue;
            }
            let page_type =
                objects::physical_number(self.vm.isf, &header_bytes, "_POOL_HEADER", "PoolType")?;
            let paged = if build >= 6000 {
                page_type % 2 == 1
            } else {
                page_type > 0 && page_type % 2 == 0
            };
            if page_type == 0 || paged {
                candidates.insert(add(header, pool_size)?);
                ensure!(candidates.len() <= MAX_OBJECTS, "hive 候选数量超限");
            }
        }
        let virtual_scan = build >= 10240;
        let mut unmapped = 0;
        if virtual_scan {
            let mapped = self.mapped_pool_candidates(&candidates, job)?;
            for candidate in &candidates {
                job.check()?;
                if let Some(aliases) = mapped.get(candidate) {
                    for &address in aliases {
                        ensure!(r.rows.len() < MAX_OBJECTS, "hive 候选数量超限");
                        r.rows.push(vec![hex(address)]);
                    }
                } else {
                    unmapped += 1;
                }
            }
        } else {
            r.rows
                .extend(candidates.into_iter().map(|address| vec![hex(address)]));
        }
        if unmapped > 0 {
            Self::issue(
                r,
                "hive 池覆盖",
                format!("{unmapped} 个物理候选缺少可验证内核映射"),
            );
        }
        *r.kernel_identity.key_mut("hive_scan")? = serde_json::json!({"source":"CM10 paged/free small-pool allocations", "offset_layer":if virtual_scan {"kernel virtual"} else {"physical"}, "unmapped_positions":unmapped,"validation":"allocation candidates; no CMHIVE signature test"});
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, image, put};
    use super::*;
    use serde_json::json;

    fn fixture(x86: bool, build: u64) -> (Vec<u8>, Isf, u64) {
        let (mut bytes, mut isf, base, _) =
            super::super::driver_irp::tests::driver_fixture(x86, false, false);
        put(&mut bytes, 0x8200, build);
        isf.data["user_types"]["_CMHIVE"] = json!({"size":1504,"fields":{}});
        isf.data["user_types"]["_POOL_HEADER"]["size"] = json!(if x86 { 8 } else { 16 });
        let align = if x86 { 8 } else { 16 };
        bytes[0xb000..0xb002].copy_from_slice(&(1024u16 / align).to_le_bytes());
        bytes[0xb002..0xb004]
            .copy_from_slice(&(if build < 6000 { 2u16 } else { 1u16 }).to_le_bytes());
        bytes[0xb004..0xb008].copy_from_slice(b"CM10");
        (bytes, isf, base)
    }
    fn engine<'a>(image: &'a Image, isf: &'a Isf, base: u64) -> Windows<'a> {
        Windows {
            vm: Memory::new(image, 0x1000, isf, None),
            base,
            pdb: PdbIdentity::from_isf(isf).unwrap(),
        }
    }
    fn big_fixture() -> (Vec<u8>, Isf, u64) {
        let (mut bytes, mut isf, base) = fixture(false, 15063);
        isf.data["symbols"]["PoolBigPageTable"] = json!({"address":0x6000});
        isf.data["symbols"]["PoolBigPageTableSize"] = json!({"address":0x6008});
        let field = |offset, name| json!({"offset":offset,"type":{"kind":"base","name":name}});
        isf.data["base_types"]["u32"] = json!({"size":4});
        // HiveScan only needs Va and Key, not optional pool-type/size fields.
        isf.data["user_types"]["_POOL_TRACKER_BIG_PAGES"] =
            json!({"size":24,"fields":{"Va":field(0,"pointer"),"Key":field(8,"u32")}});
        put(&mut bytes, 0xe000, base + 0x7000);
        put(&mut bytes, 0xe008, 0xaabbccdd00000004);
        for (index, va, key) in [
            (0, base + 0x12000, *b"CM10"),
            (1, base + 0x13001, *b"CM10"),
            (2, base + 0x14000, *b"Else"),
            (3, base + 0x15000, [0; 4]),
        ] {
            put(&mut bytes, 0xf000 + index * 24, va);
            bytes[0xf008 + index * 24..0xf00c + index * 24].copy_from_slice(&key);
        }
        (bytes, isf, base)
    }
    #[test]
    fn old_small_pools_keep_physical_candidates_without_signature_or_list_dependencies() {
        for (x86, build) in [
            (true, 3790),
            (false, 3790),
            (true, 6001),
            (false, 7601),
            (false, 9200),
        ] {
            let (bytes, isf, base) = fixture(x86, build);
            let img = image(&bytes);
            let result = engine(&img, &isf, base).hive_scan(&Job::default()).unwrap();
            assert_eq!(
                result.rows,
                vec![vec![hex(0xb000 + if x86 { 8 } else { 16 })]],
                "{x86} {build} {:?}",
                result.diagnostics
            );
            assert!(result.complete, "{:?}", result.diagnostics);
            assert_eq!(
                result.kernel_identity["hive_scan"]["offset_layer"],
                "physical"
            );
        }
    }
    #[test]
    fn small_pool_matches_reference_size_type_and_unaligned_candidate_semantics() {
        for (pool_type, block, misaligned, expected) in [
            (0, 64, false, 1),
            (1, 64, false, 1),
            (2, 64, false, 0),
            (1, 49, false, 0),
            (1, 50, false, 1),
            (1, 300, false, 1),
            (1, 64, true, 1),
        ] {
            let (mut bytes, isf, base) = fixture(false, 7601);
            bytes[0xb000..0xb002].copy_from_slice(&(block as u16).to_le_bytes());
            bytes[0xb002..0xb004].copy_from_slice(&(pool_type as u16).to_le_bytes());
            if misaligned {
                bytes.copy_within(0xb000..0xb010, 0xb001);
                bytes[0xb000] = 0;
            }
            let img = image(&bytes);
            let result = engine(&img, &isf, base).hive_scan(&Job::default()).unwrap();
            let rows = if expected == 0 {
                Vec::new()
            } else {
                vec![vec![hex(0xb010 + u64::from(misaligned))]]
            };
            assert_eq!(result.rows, rows);
            assert!(result.complete);
        }
    }
    #[test]
    fn modern_x86_small_pool_preserves_virtual_aliases_and_marks_unmapped_coverage() {
        let (mut bytes, isf, base) = fixture(true, 15063);
        // The same physical body is visible at two distinct kernel addresses.
        bytes[0x2020..0x2024].copy_from_slice(&0xb003u32.to_le_bytes());
        let img = image(&bytes);
        let r = engine(&img, &isf, base).hive_scan(&Job::default()).unwrap();
        assert_eq!(
            r.rows,
            vec![vec![hex(base + 0x3008)], vec![hex(base + 0x8008)]]
        );
        assert_eq!(
            r.kernel_identity["hive_scan"]["offset_layer"],
            "kernel virtual"
        );
        bytes[0x200c..0x2010].fill(0);
        bytes[0x2020..0x2024].fill(0);
        let img = image(&bytes);
        let r = engine(&img, &isf, base).hive_scan(&Job::default()).unwrap();
        assert!(r.rows.is_empty());
        assert!(!r.complete);
        assert!(r.diagnostics.iter().any(|s| s.contains("hive 池覆盖")));
    }
    #[test]
    fn big_pool_uses_ulong_count_and_exact_allocated_tag_without_optional_fields() {
        let (bytes, isf, base) = big_fixture();
        let img = image(&bytes);
        let r = engine(&img, &isf, base).hive_scan(&Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows, vec![vec![hex(base + 0x12000)]]);
        assert_eq!(
            r.kernel_identity["hive_scan"]["source"],
            "allocated CM10 big-pool entries"
        );
    }
    #[test]
    fn missing_big_pool_page_retains_readable_entries_on_both_sides() {
        let (mut bytes, isf, base) = big_fixture();
        bytes[0xf000..0x13000].fill(0);
        put(&mut bytes, 0xe008, 512);
        for (index, va) in [(0, base + 0x12000), (400, base + 0x14000)] {
            put(&mut bytes, 0xf000 + index * 24, va);
            bytes[0xf008 + index * 24..0xf00c + index * 24].copy_from_slice(b"CM10");
        }
        put(&mut bytes, 0x4040, 0);
        let img = image(&bytes);
        let r = engine(&img, &isf, base).hive_scan(&Job::default()).unwrap();
        assert_eq!(
            r.rows,
            vec![vec![hex(base + 0x12000)], vec![hex(base + 0x14000)]]
        );
        assert!(!r.complete);
        assert_eq!(r.diagnostics.len(), 1);
        assert!(r.diagnostics[0].contains("保留其余可读项"));
    }
    #[test]
    fn empty_tables_bad_layout_and_cancellation_never_claim_false_success() {
        let (mut bytes, mut isf, base) = big_fixture();
        put(&mut bytes, 0xe008, 0);
        put(&mut bytes, 0xe000, 0);
        let img = image(&bytes);
        let r = engine(&img, &isf, base).hive_scan(&Job::default()).unwrap();
        assert!(r.complete);
        assert!(r.rows.is_empty());
        put(&mut bytes, 0xe008, 16 * 1024 * 1024 + 1);
        let img = image(&bytes);
        let r = engine(&img, &isf, base).hive_scan(&Job::default()).unwrap();
        assert!(!r.complete);
        assert!(r.diagnostics.iter().any(|s| s.contains("超限")));
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(engine(&img, &isf, base).hive_scan(&job).is_err());
        isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0xaa64);
        assert!(engine(&img, &isf, base).hive_scan(&Job::default()).is_err());
        assert_eq!(base, K);
    }
}
