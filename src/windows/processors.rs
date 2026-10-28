//! Bounded processor roots shared by KPCR projection and timer enumeration.
use super::*;

const MAX_PROCESSORS: u64 = 2048;

impl Windows<'_> {
    fn processor_count(&self, r: &mut Results) -> Result<u64> {
        let isf = self.vm.isf;
        let arch = Architecture::from_isf(isf)?;
        let global = &isf.data["symbols"]["KeNumberProcessors"];
        ensure!(
            global["type_conflict"] != true,
            "KeNumberProcessors 类型冲突"
        );
        let (count, source) = if isf
            .field("_KUSER_SHARED_DATA", "ActiveProcessorCount")
            .is_ok()
        {
            let address = match arch {
                Architecture::X86 => 0xffdf0000,
                Architecture::X64 => 0xfffff78000000000,
                _ => bail!("不支持此架构的共享处理器计数地址"),
            };
            (
                self.number(address, "_KUSER_SHARED_DATA", "ActiveProcessorCount")?,
                "KUSER_SHARED_DATA.ActiveProcessorCount",
            )
        } else if let Some(ty) = global.get("type") {
            ensure!(ty["kind"] == "base", "KeNumberProcessors 不是标量类型");
            let width = isf.symbol_size("KeNumberProcessors")?;
            ensure!([1, 2, 4, 8].contains(&width), "KeNumberProcessors 宽度无效");
            (
                self.vm
                    .uint(self.symbol("KeNumberProcessors")?, width as usize)?,
                "typed KeNumberProcessors",
            )
        } else {
            // The exported XP-and-later compatibility variable is a byte.
            // On group-aware systems this alone cannot certify all groups.
            let build = self.build_number()?;
            ensure!(
                build >= 2600,
                "不支持 XP 以前的 KeNumberProcessors 指针布局"
            );
            if build >= 7600 {
                Self::issue(
                    r,
                    "处理器计数",
                    "仅有旧版八位兼容计数，无法验证全部处理器组覆盖",
                );
            }
            (
                self.vm.uint(self.symbol("KeNumberProcessors")?, 1)?,
                "legacy byte KeNumberProcessors",
            )
        };
        ensure!(
            (1..=MAX_PROCESSORS).contains(&count),
            "处理器数量无效: {count}"
        );
        if r.kernel_identity.is_object() {
            r.kernel_identity["processors"] =
                serde_json::json!({"count":count,"count_source":source});
        }
        Ok(count)
    }

    pub(super) fn processor_roots(&self, r: &mut Results, job: &Job) -> Result<Vec<(u64, u64)>> {
        job.check()?;
        let count = self.processor_count(r)?;
        // This symbol is the array itself, not a pointer to the array.
        let blocks = self.symbol("KiProcessorBlock")?;
        ensure!(self.vm.kernel(blocks), "KiProcessorBlock 非内核地址");
        let width = self.vm.pointer_size() as u64;
        let mut roots = Vec::new();
        let mut seen = HashSet::new();
        for cpu in 0..count {
            job.check()?;
            let read = (|| -> Result<u64> {
                let prcb = self.vm.pointer(add(blocks, cpu * width)?)?;
                ensure!(
                    self.vm.kernel(prcb) && prcb % width == 0,
                    "KPRCB 指针无效: {prcb:#x}"
                );
                self.vm.uint(prcb, width as usize)?;
                ensure!(seen.insert(prcb), "重复 KPRCB 指针: {prcb:#x}");
                Ok(prcb)
            })();
            match read {
                Ok(prcb) => roots.push((cpu, prcb)),
                Err(e) => Self::issue(r, format!("CPU {cpu}"), format!("{e:#}")),
            }
        }
        Ok(roots)
    }

    pub(super) fn kpcrs(&self, job: &Job) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "KPCRs 仅支持 x86/x64"
        );
        let isf = self.vm.isf;
        let embedded = ["Prcb", "PrcbData"]
            .into_iter()
            .find(|name| {
                isf.field("_KPCR", name)
                    .is_ok_and(|f| f["type"]["kind"] == "struct" && f["type"]["name"] == "_KPRCB")
            })
            .context("不支持: _KPCR 缺少内嵌 _KPRCB")?;
        let relative = isf.offset("_KPCR", embedded)?;
        let self_field = ["Self", "SelfPcr"]
            .into_iter()
            .find(|name| {
                isf.field("_KPCR", name)
                    .is_ok_and(|f| f["type"]["kind"] == "pointer")
            })
            .context("不支持: _KPCR 缺少自指针")?;
        let prcb_field = ["CurrentPrcb", "Prcb"]
            .into_iter()
            .find(|name| {
                isf.field("_KPCR", name)
                    .is_ok_and(|f| f["type"]["kind"] == "pointer")
            })
            .context("不支持: _KPCR 缺少 PRCB 回指针")?;
        let mut r = self.result(Plugin::WinKpcrs);
        for (cpu, prcb) in self.processor_roots(&mut r, job)? {
            job.check()?;
            let read = (|| -> Result<Vec<String>> {
                let kpcr = prcb.checked_sub(relative).context("KPCR 地址下溢")?;
                ensure!(self.vm.kernel(kpcr), "KPCR 非内核地址");
                ensure!(
                    self.number(kpcr, "_KPCR", self_field)? == kpcr,
                    "KPCR 自指针不一致"
                );
                let current = self.number(kpcr, "_KPCR", prcb_field)?;
                ensure!(current == prcb, "KPCR PRCB 回指针不一致");
                Ok(vec![hex(kpcr), hex(current)])
            })();
            match read {
                Ok(row) => r.rows.push(row),
                Err(e) => Self::issue(&mut r, format!("CPU {cpu} KPCR"), format!("{e:#}")),
            }
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;

    fn prepared(x86: bool) -> (Vec<u8>, Isf, u64) {
        let (mut b, mut isf) = fixture();
        let base = if x86 { 0x80000000 } else { K };
        let ptr = if x86 { 4 } else { 8 };
        if x86 {
            isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
            isf.data["base_types"]["pointer"]["size"] = json!(4);
            b[0x1000..0x2000].fill(0);
            b[0x4000..0x5000].fill(0);
            b[0x1800..0x1804].copy_from_slice(&0x4003u32.to_le_bytes());
            for i in 0..32 {
                b[0x4000 + i * 4..0x4004 + i * 4]
                    .copy_from_slice(&(0x8003u32 + i as u32 * 4096).to_le_bytes());
            }
        }
        isf.data["base_types"]["u8"] = json!({"size":1});
        isf.data["base_types"]["u32"] = json!({"size":4});
        isf.data["symbols"]["KeNumberProcessors"] =
            json!({"address":0x2c0,"type":{"kind":"base","name":"u8"}});
        isf.data["symbols"]["KiProcessorBlock"] = json!({"address":0x300});
        let embedded = if x86 { "PrcbData" } else { "Prcb" };
        let relative = if x86 { 0x120 } else { 0x180 };
        let self_name = if x86 { "SelfPcr" } else { "Self" };
        let current_name = if x86 { "Prcb" } else { "CurrentPrcb" };
        isf.data["user_types"]["_KPCR"] = json!({"size":0x300,"fields":{
            embedded:{"offset":relative,"type":{"kind":"struct","name":"_KPRCB"}},
            self_name:{"offset":0x18,"type":{"kind":"pointer"}},
            current_name:{"offset":0x20,"type":{"kind":"pointer"}}
        }});
        isf.data["user_types"]["_KPRCB"] = json!({"size":0x100,"fields":{}});
        put(&mut b, 0x82c0, 0xdeadbe00 | 2);
        b[0x8200..0x8204].copy_from_slice(&6001u32.to_le_bytes());
        for cpu in 0..2 {
            let kpcr = base + 0x3000 + cpu as u64 * 4096;
            let phys = 0xb000 + cpu * 4096;
            let prcb = kpcr + relative;
            b[0x8300 + cpu * ptr..0x8300 + (cpu + 1) * ptr]
                .copy_from_slice(&prcb.to_le_bytes()[..ptr]);
            b[phys + 0x18..phys + 0x18 + ptr].copy_from_slice(&kpcr.to_le_bytes()[..ptr]);
            b[phys + 0x20..phys + 0x20 + ptr].copy_from_slice(&prcb.to_le_bytes()[..ptr]);
        }
        (b, isf, base)
    }
    fn engine<'a>(img: &'a Image, isf: &'a Isf, base: u64) -> Windows<'a> {
        Windows {
            vm: Memory::new(img, 0x1000, isf, None),
            base,
            pdb: PdbIdentity::from_isf(isf).unwrap(),
        }
    }
    #[test]
    fn kpcr_embedded_layout_and_pointer_array_on_both_intel_architectures() {
        for x86 in [false, true] {
            let (b, isf, base) = prepared(x86);
            let img = image(&b);
            let r = engine(&img, &isf, base).kpcrs(&Job::default()).unwrap();
            assert!(r.complete, "{:?}", r.diagnostics);
            assert_eq!(r.rows.len(), 2);
            assert_eq!(
                r.rows[0],
                vec![
                    hex(base + 0x3000),
                    hex(base + 0x3000 + if x86 { 0x120 } else { 0x180 })
                ]
            );
            assert_eq!(r.kernel_identity["processors"]["count"], 2);
        }
    }
    #[test]
    fn independent_bad_roots_and_backlinks_retain_other_processors() {
        for bad in [0, K + 0x3180, K + 0x40000] {
            let (mut b, isf, base) = prepared(false);
            put(&mut b, 0x8308, bad);
            let img = image(&b);
            let r = engine(&img, &isf, base).kpcrs(&Job::default()).unwrap();
            assert!(!r.complete);
            assert_eq!(r.rows.len(), 1);
            assert!(r.diagnostics.iter().any(|s| s.contains("CPU 1")));
        }
        let (mut b, isf, base) = prepared(false);
        put(&mut b, 0xc020, K + 0x9180);
        let img = image(&b);
        let r = engine(&img, &isf, base).kpcrs(&Job::default()).unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
        assert!(r.diagnostics.iter().any(|s| s.contains("回指针")));
    }
    #[test]
    fn legacy_byte_count_bounds_conflicts_and_cancellation() {
        let (mut b, mut isf, base) = prepared(false);
        isf.data["symbols"]["KeNumberProcessors"]
            .as_object_mut()
            .unwrap()
            .remove("type");
        let img = image(&b);
        assert!(
            engine(&img, &isf, base)
                .kpcrs(&Job::default())
                .unwrap()
                .complete
        );
        b[0x8200..0x8204].copy_from_slice(&7601u32.to_le_bytes());
        let img = image(&b);
        let r = engine(&img, &isf, base).kpcrs(&Job::default()).unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 2);
        isf.data["symbols"]["KeNumberProcessors"]["type_conflict"] = json!(true);
        assert!(engine(&img, &isf, base).kpcrs(&Job::default()).is_err());
        let (mut b, isf, base) = prepared(false);
        b[0x82c0] = 0;
        let img = image(&b);
        assert!(engine(&img, &isf, base).kpcrs(&Job::default()).is_err());
        let (b, mut isf, base) = prepared(false);
        isf.data["symbols"]["KeNumberProcessors"]["type"] = json!({"kind":"base","name":"u32"});
        let img = image(&b);
        assert!(engine(&img, &isf, base).kpcrs(&Job::default()).is_err());
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(engine(&img, &isf, base).kpcrs(&job).is_err());
    }
    #[test]
    fn shared_processor_count_supersedes_untyped_compatibility_global() {
        let (mut b, mut isf, base) = prepared(false);
        isf.data["symbols"]["KeNumberProcessors"]
            .as_object_mut()
            .unwrap()
            .remove("type");
        isf.data["user_types"]["_KUSER_SHARED_DATA"] = json!({"size":0x1000,"fields":{"ActiveProcessorCount":{"offset":0x3c0,"type":{"kind":"base","name":"u32"}}}});
        let va = 0xfffff78000000000u64;
        let mut table = 0x1000usize;
        for (shift, next) in [(39, 0x5000), (30, 0x6000), (21, 0x7000), (12, 0xd000)] {
            put(
                &mut b,
                table + ((va >> shift) & 511) as usize * 8,
                next as u64 | 3,
            );
            table = next;
        }
        b[0xd3c0..0xd3c4].copy_from_slice(&2u32.to_le_bytes());
        b[0x82c0] = 255;
        let img = image(&b);
        let r = engine(&img, &isf, base).kpcrs(&Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(
            r.kernel_identity["processors"]["count_source"],
            "KUSER_SHARED_DATA.ActiveProcessorCount"
        );
        // Preserve processor-group totals wider than the legacy byte and reject
        // corrupt totals before walking any pointer slots.
        b[0xd3c0..0xd3c4].copy_from_slice(&256u32.to_le_bytes());
        let img = image(&b);
        let w = engine(&img, &isf, base);
        assert_eq!(
            w.processor_count(&mut w.result(Plugin::WinKpcrs)).unwrap(),
            256
        );
        b[0xd3c0..0xd3c4].copy_from_slice(&2049u32.to_le_bytes());
        let img = image(&b);
        assert!(engine(&img, &isf, base).kpcrs(&Job::default()).is_err());
    }
}
