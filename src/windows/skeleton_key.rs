//! Locate RC4-HMAC KERB_ECRYPT instances in the first usable lsass cryptdll mapping.
use super::*;
use crate::bytes::{le_u32, le_u64};
use crate::{byte_regex::ByteRegex, regex_scan};
use capstone::{arch::x86::X86OperandType, prelude::*};
const ECRYPT_SIZE: usize = 128;
const ARRAY_LIMIT: u32 = 65536;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Array {
    start: u64,
    count: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Expected {
    initialize: u64,
    decrypt: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ecrypt {
    encryption_type: u32,
    encrypt: u64,
    finish: u64,
    initialize: u64,
    decrypt: u64,
}
impl Ecrypt {
    fn parse(bytes: &[u8; ECRYPT_SIZE]) -> Self {
        let pointer = |at| le_u64(bytes, at).unwrap_or_default();
        Self {
            encryption_type: le_u32(bytes, 0).unwrap_or_default(),
            initialize: pointer(40),
            encrypt: pointer(48),
            decrypt: pointer(56),
            finish: pointer(64),
        }
    }
    fn hooked(self, base: u64, end: u64, expected: Option<Expected>) -> bool {
        if let Some(expected) = expected.filter(|e| e.initialize != 0 && e.decrypt != 0) {
            self.initialize != expected.initialize || self.decrypt != expected.decrypt
        } else {
            // The fixed reference uses inclusive upper bounds here, unlike its scan validation.
            !(base <= self.initialize
                && self.initialize <= end
                && base <= self.decrypt
                && self.decrypt <= end)
        }
    }
    fn scan_valid(self, base: u64, end: u64) -> bool {
        base < self.encrypt && self.encrypt < end && base < self.finish && self.finish < end
    }
}
fn array_from_symbols(
    isf: &Isf,
    base: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<(Array, Expected)> {
    let address = |name| -> Result<u64> { add(base, isf.raw_address(name)?) };
    // Pinned count lookup is relative to the cryptdll module base.
    let mut count = [0; 4];
    let count = if read(address("cCSystems")?, &mut count).is_ok() {
        u32::from_le_bytes(count)
    } else {
        16
    };
    Ok((
        Array {
            start: address("CSystems")?,
            count,
        },
        Expected {
            initialize: address("rc4HmacInitialize")?,
            decrypt: address("rc4HmacDecrypt")?,
        },
    ))
}
fn analyze_export(
    bytes: &[u8],
    start: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    job: &Job,
) -> Result<Option<Array>> {
    let cs = Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .map_err(|e| anyhow::anyhow!("Capstone: {e}"))?;
    let instructions = cs
        .disasm_all(bytes, start)
        .map_err(|e| anyhow::anyhow!("反汇编: {e}"))?;
    let mut count = None;
    let mut array = None;
    for instruction in instructions.iter() {
        job.check()?;
        let op = instruction.mnemonic().unwrap_or_default();
        if op == "int3" {
            break;
        }
        if !(op == "lea" || op == "mov" && count.is_none()) {
            continue;
        }
        let detail = cs
            .insn_detail(instruction)
            .map_err(|e| anyhow::anyhow!("指令详情: {e}"))?;
        let arch = detail.arch_detail();
        let x86 = arch.x86().context("非 x86 指令")?;
        let target = x86.operands().nth(1).and_then(|operand| {
            if let X86OperandType::Mem(mem) = operand.op_type
                && cs.reg_name(mem.base()).as_deref() == Some("rip")
            {
                return instruction
                    .address()
                    .checked_add(instruction.bytes().len() as u64)?
                    .checked_add_signed(mem.disp());
            }
            None
        });
        if op == "mov" {
            let mut value = 16;
            if let Some(target) = target.filter(|t| *t != 0) {
                let mut bytes = [0; 4];
                if read(target, &mut bytes).is_ok() {
                    value = u32::from_le_bytes(bytes);
                }
            }
            count = Some(value);
        } else {
            array = target.filter(|t| *t != 0);
            break; // First LEA terminates reference analysis, even if it is not RIP-relative.
        }
    }
    Ok(array
        .zip(count.filter(|n| *n != 0))
        .map(|(start, count)| Array { start, count }))
}
#[derive(Default)]
struct Evidence {
    method: &'static str,
    array: Option<Array>,
    expected: Option<Expected>,
    scanned: Option<regex_scan::Coverage>,
    unreadable_records: usize,
    scanned_candidates: usize,
}
impl Windows<'_> {
    pub(super) fn skeleton_key(
        &self,
        resources: Option<(&std::path::Path, bool)>,
        job: &Job,
    ) -> Result<Results> {
        ensure!(
            Architecture::from_isf(self.vm.isf)? == Architecture::X64,
            "Skeleton_Key_Check 仅支持 Windows x64"
        );
        let mut result = self.result(Plugin::WinSkeletonKeyCheck);
        let (processes, diagnostics) = self.processes_partial(job)?;
        if !diagnostics.is_empty() {
            result.complete = false;
            result.diagnostics.extend(diagnostics);
        }
        let mut selected = None;
        for process in processes.iter().filter(|p| p.name == "lsass.exe") {
            job.check()?;
            match self.process_memory(process) {
                Ok(vm) => {
                    selected = Some((process, vm));
                    break;
                }
                Err(e) => Self::issue(
                    &mut result,
                    format!("PID {} lsass 地址空间", process.pid),
                    e,
                ),
            }
        }
        let Some((process, vm)) = selected else {
            Self::issue(
                &mut result,
                "Skeleton_Key_Check",
                "未找到可读的 lsass.exe 地址空间",
            );
            return Ok(result);
        };
        let vads = self.tagged_vads_with_paths(process, &mut result, job)?;
        let Some(vad) = vads
            .iter()
            .find(|v| v.path.to_lowercase().ends_with("cryptdll.dll"))
        else {
            Self::issue(
                &mut result,
                "Skeleton_Key_Check",
                "lsass 中未找到 cryptdll.dll 映射",
            );
            return Ok(result);
        };
        *result.kernel_identity.key_mut("skeleton_key")? = serde_json::json!({"pid":process.pid,"cryptdll_base":hex(vad.start),"cryptdll_size":vad.end-vad.start});
        let acquired = (|| -> Result<Isf> {
            let mut header = [0; 4096];
            vm.read_reference(vad.start, &mut header)?;
            let header = pe_symbols::export_header(&header)?;
            ensure!(
                header.wide && u64::from(header.size) <= vad.end - vad.start,
                "cryptdll PE 位宽／范围无效"
            );
            let identity = network::pe_identity_for_machine(&vm, vad.start, 0x8664)?;
            ensure!(identity.name == "cryptdll.pdb", "cryptdll PDB 名称不匹配");
            let (cache, network) = resources.context("缺少模块 PDB 资源上下文")?;
            let isf = windows_symbols::acquire(&identity, cache, network, job)?;
            ensure!(
                PdbIdentity::from_isf(&isf)? == identity
                    && Architecture::from_isf(&isf)? == Architecture::X64,
                "cryptdll PDB 身份／架构不匹配"
            );
            Ok(isf)
        })();
        job.check()?;
        match &acquired {
            Ok(isf) => {
                *result
                    .kernel_identity
                    .key_mut("skeleton_key")?
                    .key_mut("pdb_sha256")? = serde_json::json!(isf.digest)
            }
            Err(e) => {
                *result
                    .kernel_identity
                    .key_mut("skeleton_key")?
                    .key_mut("optional_pdb_failure")? = serde_json::json!(format!("{e:#}"))
            }
        }
        self.skeleton_records(
            &vm,
            process.pid,
            vad,
            acquired.as_ref().ok(),
            &mut result,
            job,
        )?;
        Ok(result)
    }
    fn skeleton_records(
        &self,
        vm: &Memory<'_>,
        pid: u64,
        vad: &memory::Vad,
        isf: Option<&Isf>,
        r: &mut Results,
        job: &Job,
    ) -> Result<()> {
        let mut evidence = Evidence::default();
        let mut addresses = Vec::new();
        if let Some(isf) = isf {
            match array_from_symbols(isf, vad.start, |at, b| vm.read_reference(at, b)) {
                Ok((array, expected)) => {
                    evidence.array = Some(array);
                    evidence.expected = Some(expected);
                    evidence.method = "pdb";
                }
                Err(e) => {
                    job.check()?;
                    *r.kernel_identity
                        .key_mut("skeleton_key")?
                        .key_mut("pdb_array_failure")? = serde_json::json!(format!("{e:#}"));
                }
            }
        }
        if evidence.array.is_none() {
            let found = (|| -> Result<Option<Array>> {
                let mut header = [0; 4096];
                vm.read_reference(vad.start, &mut header)?;
                let header = pe_symbols::export_header(&header)?;
                ensure!(
                    header.wide && u64::from(header.size) <= vad.end - vad.start,
                    "cryptdll PE 范围无效"
                );
                let mut diagnostics = Vec::new();
                let symbols = pe_symbols::export_symbols(
                    header.size,
                    header.exports,
                    |rva, b| vm.read_reference(add(vad.start, u64::from(rva))?, b),
                    job,
                    &mut diagnostics,
                )?;
                for diagnostic in diagnostics {
                    Self::issue(r, "cryptdll exports", diagnostic);
                }
                let Some((_, rva)) = symbols.iter().find(|(name, _)| name == "CDLocateCSystem")
                else {
                    return Ok(None);
                };
                let start = add(vad.start, u64::from(*rva))?;
                let mut function = [0; 0x50];
                vm.read_reference(start, &mut function)?;
                analyze_export(&function, start, |at, b| vm.read_reference(at, b), job)
            })();
            match found {
                Ok(Some(array)) => {
                    evidence.array = Some(array);
                    evidence.method = "exports";
                }
                Ok(None) => (),
                Err(e) => {
                    job.check()?;
                    *r.kernel_identity
                        .key_mut("skeleton_key")?
                        .key_mut("export_failure")? = serde_json::json!(format!("{e:#}"));
                }
            }
        }
        if let Some(array) = evidence.array {
            if array.count > ARRAY_LIMIT {
                Self::issue(r, "CSystems", "数组数量超过 65536 上限；保留可验证前缀");
            }
            for index in 0..array.count.min(ARRAY_LIMIT) {
                job.check()?;
                addresses.push(add(array.start, u64::from(index) * ECRYPT_SIZE as u64)?);
            }
        } else {
            evidence.method = "scan";
            let regex = ByteRegex::compile(r"(?=\x17\x00\x00\x00\x01\x00\x00\x00)", false)?;
            let coverage = vm.scan_reference(
                &regex,
                &[(vad.start, vad.end)],
                &mut Default::default(),
                job,
                |at| {
                    evidence.scanned_candidates += 1;
                    if evidence.scanned_candidates > MAX_OBJECTS {
                        return Ok(false);
                    }
                    let mut bytes = [0; ECRYPT_SIZE];
                    if vm.read_reference(at, &mut bytes).is_err() {
                        evidence.unreadable_records += 1;
                        return Ok(true);
                    }
                    if Ecrypt::parse(&bytes).scan_valid(vad.start, vad.end) {
                        addresses.push(at);
                    }
                    Ok(true)
                },
            )?;
            if !coverage.complete() {
                Self::issue(
                    r,
                    "cryptdll scan",
                    format!(
                        "扫描 {} / {} 字节；缺页 {} 字节；区间合并省略 {} 字节；{}",
                        coverage.scanned_bytes,
                        coverage.requested_bytes,
                        coverage.unreadable_bytes,
                        coverage.reference_coalescing_omitted_bytes,
                        coverage.stop_reason.as_deref().unwrap_or("扫描结束")
                    ),
                );
            }
            evidence.scanned = Some(coverage);
        }
        for address in &addresses {
            job.check()?;
            let mut bytes = [0; ECRYPT_SIZE];
            if vm.read_reference(*address, &mut bytes).is_err() {
                evidence.unreadable_records += 1;
                continue;
            }
            let e = Ecrypt::parse(&bytes);
            if e.encryption_type != 23 {
                continue;
            }
            r.rows.push(vec![
                pid.to_string(),
                "lsass.exe".into(),
                e.hooked(vad.start, vad.end, evidence.expected).to_string(),
                hex(e.initialize),
                hex(e.decrypt),
            ]);
        }
        if evidence.unreadable_records > 0 {
            Self::issue(
                r,
                "CSystems",
                format!("{} 个候选记录未完整采集", evidence.unreadable_records),
            );
        }
        let meta = r.kernel_identity.key_mut("skeleton_key")?;
        if !meta.is_object() {
            *meta = serde_json::json!({});
        }
        meta["method"] = serde_json::json!(evidence.method);
        meta["array"] = evidence
            .array
            .map(|a| serde_json::json!({"start":hex(a.start),"count":a.count}))
            .unwrap_or(serde_json::Value::Null);
        meta["expected"] = evidence
            .expected
            .map(|e| serde_json::json!({"initialize":hex(e.initialize),"decrypt":hex(e.decrypt)}))
            .unwrap_or(serde_json::Value::Null);
        meta["scan"] = serde_json::json!(evidence.scanned);
        meta["scan_candidates"] = serde_json::json!(evidence.scanned_candidates);
        meta["unreadable_records"] = serde_json::json!(evidence.unreadable_records);
        meta["layout"] = serde_json::json!({"size":128,"encryption_type":0,"initialize":40,"encrypt":48,"decrypt":56,"finish":64,"hook_range_end":"inclusive"});
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, image, put};
    use super::*;
    use serde_json::json;
    #[test]
    fn fixed_reference_export_and_hook_boundary_vectors() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/skeleton-key.json"
        ))
        .unwrap();
        assert_eq!(
            v["reference_commit"],
            "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
        );
        for c in v["export_cases"].as_array().unwrap() {
            let code = c["code"]
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
                .collect::<Vec<_>>();
            let found = analyze_export(
                &code,
                c["start"].as_u64().unwrap(),
                |at, b| {
                    ensure!(
                        at == c["count_address"].as_u64().unwrap(),
                        "unexpected address"
                    );
                    let count = c["count"].as_u64().context("missing count")? as u32;
                    b.copy_from_slice(&count.to_le_bytes());
                    Ok(())
                },
                &Job::default(),
            )
            .unwrap()
            .map(|a| json!({"start":a.start,"count":a.count}))
            .unwrap_or(serde_json::Value::Null);
            assert_eq!(found, c["expected"], "{}", c["id"]);
        }
        for c in v["hook_cases"].as_array().unwrap() {
            let e = Ecrypt {
                encryption_type: 23,
                initialize: c["initialize"].as_u64().unwrap(),
                decrypt: c["decrypt"].as_u64().unwrap(),
                encrypt: 0,
                finish: 0,
            };
            let expected = c["expected"].as_object().map(|e| Expected {
                initialize: e["initialize"].as_u64().unwrap(),
                decrypt: e["decrypt"].as_u64().unwrap(),
            });
            assert_eq!(
                e.hooked(0x1000, 0x2000, expected),
                c["hooked"].as_bool().unwrap()
            );
        }
    }
    fn prepared() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = super::super::regex::tests::prepared();
        b[0xa030..0xa040].fill(0);
        b[0xa030..0xa039].copy_from_slice(b"lsass.exe");
        // One long, file-backed VAD, referencing cryptdll.dll.
        b[0xb000 - 12..0xb000 - 8].copy_from_slice(b"VadL");
        put(&mut b, 0xb008, 0);
        put(&mut b, 0xb020, 2);
        isf.data["user_types"]["_MMVAD"] =
            json!({"size":80,"fields":{"Subsection":{"offset":48,"type":{"kind":"pointer"}}}});
        isf.data["user_types"]["_SUBSECTION"] =
            json!({"size":8,"fields":{"ControlArea":{"offset":0,"type":{"kind":"pointer"}}}});
        isf.data["user_types"]["_CONTROL_AREA"] =
            json!({"size":8,"fields":{"FilePointer":{"offset":0,"type":{"kind":"pointer"}}}});
        isf.data["user_types"]["_FILE_OBJECT"] = json!({"size":16,"fields":{"FileName":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}});
        put(&mut b, 0xb030, K + 0x4000);
        put(&mut b, 0xc000, K + 0x5000);
        put(&mut b, 0xd000, K + 0x6000);
        let name: Vec<_> = "C:\\Windows\\cryptdll.dll"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        b[0xe000..0xe002].copy_from_slice(&(name.len() as u16).to_le_bytes());
        b[0xe002..0xe004].copy_from_slice(&(name.len() as u16).to_le_bytes());
        put(&mut b, 0xe008, K + 0x7000);
        b[0xf000..0xf000 + name.len()].copy_from_slice(&name);
        b[0x20000..0x21000].fill(0);
        b[0x25000..0x26000].fill(0);
        record(&mut b, 0x20400, 23, 0x1100, 0x1300, 0x1200, 0x1400);
        (b, isf)
    }
    fn record(
        b: &mut [u8],
        at: usize,
        kind: u32,
        initialize: u64,
        encrypt: u64,
        decrypt: u64,
        finish: u64,
    ) {
        b[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
        for (offset, value) in [(40, initialize), (48, encrypt), (56, decrypt), (64, finish)] {
            put(b, at + offset, value);
        }
    }
    fn engine<'a>(img: &'a Image, isf: &'a Isf) -> Windows<'a> {
        Windows {
            vm: Memory::new(img, 0x1000, isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(isf).unwrap(),
        }
    }
    fn vad() -> memory::Vad {
        memory::Vad {
            address: K + 0x3000,
            start: 0x1000,
            end: 0x3000,
            protection: 0,
            private: false,
            path: "cryptdll.dll".into(),
        }
    }
    #[test]
    fn full_plugin_scans_cryptdll_and_detects_unlinked_function_pointers() {
        let (mut b, isf) = prepared();
        let img = image(&b);
        let r = engine(&img, &isf)
            .skeleton_key(None, &Job::default())
            .unwrap();
        assert_eq!(
            r.rows,
            [vec![
                "8",
                "lsass.exe",
                "false",
                "0x0000000000001100",
                "0x0000000000001200"
            ]]
        );
        assert_eq!(r.kernel_identity["skeleton_key"]["method"], "scan");
        assert!(r.complete, "{:?}", r.diagnostics);
        put(&mut b, 0x20400 + 56, 0x9000);
        let img = image(&b);
        let r = engine(&img, &isf)
            .skeleton_key(None, &Job::default())
            .unwrap();
        assert_eq!(r.rows[0][2], "true");
        put(&mut b, 0x20400 + 48, 0x3000);
        let img = image(&b);
        let r = engine(&img, &isf)
            .skeleton_key(None, &Job::default())
            .unwrap();
        assert!(r.rows.is_empty()); // scan Encrypt/Finish bounds are strict.
    }
    #[test]
    fn pdb_array_has_priority_and_uses_exact_expected_handlers() {
        let (b, mut isf) = prepared();
        for (name, address) in [
            ("CSystems", 0x400),
            ("cCSystems", 0x300),
            ("rc4HmacInitialize", 0x100),
            ("rc4HmacDecrypt", 0x201),
        ] {
            isf.data["symbols"][name] = json!({"address":address});
        }
        let mut b = b;
        b[0x20300..0x20304].copy_from_slice(&1u32.to_le_bytes());
        let img = image(&b);
        let w = engine(&img, &isf);
        let vm = w.process_memory(&w.process(K + 0x2000).unwrap()).unwrap();
        let mut r = w.result(Plugin::WinSkeletonKeyCheck);
        w.skeleton_records(&vm, 8, &vad(), Some(&isf), &mut r, &Job::default())
            .unwrap();
        assert_eq!(r.kernel_identity["skeleton_key"]["method"], "pdb");
        assert_eq!(r.rows[0][2], "true");
        assert_eq!(
            r.kernel_identity["skeleton_key"]["expected"]["decrypt"],
            "0x0000000000001201"
        );
        let (a, _) = array_from_symbols(&isf, 0x1000, |_, _| bail!("missing count")).unwrap();
        assert_eq!(a.count, 16);
        b[0x20300..0x20304].fill(0);
        let img = image(&b);
        let w = engine(&img, &isf);
        let vm = w.process_memory(&w.process(K + 0x2000).unwrap()).unwrap();
        let mut r = w.result(Plugin::WinSkeletonKeyCheck);
        w.skeleton_records(&vm, 8, &vad(), Some(&isf), &mut r, &Job::default())
            .unwrap();
        assert!(r.rows.is_empty());
        assert_eq!(r.kernel_identity["skeleton_key"]["method"], "pdb");
    }
    fn export_pe(b: &mut [u8]) {
        let base = 0x20000;
        b[base..base + 2].copy_from_slice(b"MZ");
        b[base + 60..base + 64].copy_from_slice(&0x80u32.to_le_bytes());
        b[base + 0x80..base + 0x84].copy_from_slice(b"PE\0\0");
        b[base + 0x84..base + 0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[base + 0x94..base + 0x96].copy_from_slice(&240u16.to_le_bytes());
        b[base + 0x98..base + 0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        for (at, value) in [
            (0xd0, 0x2000u32),
            (0x104, 16),
            (0x108, 0x600),
            (0x10c, 0x40),
            (0x614, 1),
            (0x618, 1),
            (0x61c, 0x680),
            (0x620, 0x688),
            (0x624, 0x690),
            (0x680, 0x800),
            (0x688, 0x6a0),
        ] {
            b[base + at..base + at + 4].copy_from_slice(&value.to_le_bytes());
        }
        b[base + 0x6a0..base + 0x6b0].copy_from_slice(b"CDLocateCSystem\0");
        // mov ecx,[rip-0x506]; lea rdx,[rip-0x40d] -> count at 0x1300, array at 0x1400.
        b[base + 0x800..base + 0x80d]
            .copy_from_slice(b"\x8b\x0d\xfa\xfa\xff\xff\x48\x8d\x15\xf3\xfb\xff\xff");
        b[base + 0x300..base + 0x304].copy_from_slice(&1u32.to_le_bytes());
    }
    #[test]
    fn export_analysis_precedes_scan_and_unreadable_arrays_are_partial() {
        let (mut b, isf) = prepared();
        export_pe(&mut b);
        let img = image(&b);
        let r = engine(&img, &isf)
            .skeleton_key(None, &Job::default())
            .unwrap();
        assert_eq!(r.rows.len(), 1, "{:?}", r.diagnostics);
        assert_eq!(r.kernel_identity["skeleton_key"]["method"], "exports");
        assert_eq!(
            r.kernel_identity["skeleton_key"]["array"]["start"],
            "0x0000000000001400"
        );
        assert!(!r.rows[0][2].parse::<bool>().unwrap());
        b[0x2080c] = 0x7f; // array moved out of captured mappings, should not fall through to scan.
        let img = image(&b);
        let r = engine(&img, &isf)
            .skeleton_key(None, &Job::default())
            .unwrap();
        assert!(r.rows.is_empty());
        assert!(!r.complete);
        assert_eq!(r.kernel_identity["skeleton_key"]["method"], "exports");
    }
    #[test]
    fn capture_holes_do_not_create_records_and_cancel_is_propagated() {
        let (mut b, isf) = prepared();
        b[0x20400..0x20480].fill(0);
        record(&mut b, 0x20fc0, 23, 0x1100, 0x1300, 0x1200, 0x1400);
        // The record crosses a virtually contiguous but physically unrelated next page.
        let tail = b[0x21000..0x21040].to_vec();
        b[0x25000..0x25040].copy_from_slice(&tail);
        let img = image(&b);
        let r = engine(&img, &isf)
            .skeleton_key(None, &Job::default())
            .unwrap();
        assert_eq!(r.rows.len(), 1);
        put(&mut b, 0x7010, 0);
        let img = image(&b);
        let r = engine(&img, &isf)
            .skeleton_key(None, &Job::default())
            .unwrap();
        assert!(r.rows.is_empty());
        assert!(!r.complete);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(engine(&img, &isf).skeleton_key(None, &job).is_err());
    }
}
