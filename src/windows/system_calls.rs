//! Direct/indirect syscall block validation against the pinned reference contract.
use super::*;
use crate::byte_regex::ByteRegex;
use capstone::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Technique {
    Direct,
    Indirect,
}
impl Technique {
    fn plugin(self) -> Plugin {
        match self {
            Self::Direct => Plugin::WinDirectSystemCalls,
            Self::Indirect => Plugin::WinIndirectSystemCalls,
        }
    }
    fn pattern(self) -> &'static str {
        // Lookahead retains overlapping Yara hits, including two syscalls before one ret.
        match self {
            Self::Direct => r"(?=\x0f\x05[^\xc3]{0,24}\xc3)",
            Self::Indirect => r"(?=\xff\x25[^\xc3]{0,24}\xc3)",
        }
    }
}
fn decoder(wow_or_x86: bool) -> Result<Capstone> {
    Capstone::new()
        .x86()
        .mode(if wow_or_x86 {
            capstone::arch::x86::ArchMode::Mode32
        } else {
            capstone::arch::x86::ArchMode::Mode64
        })
        .detail(true)
        .build()
        .map_err(|e| anyhow::anyhow!("Capstone: {e}"))
}
struct Block {
    text: String,
    end: u64,
}
fn block(cs: &Capstone, technique: Technique, bytes: &[u8], address: u64) -> Result<Option<Block>> {
    let instructions = cs
        .disasm_all(bytes, address)
        .map_err(|e| anyhow::anyhow!("反汇编: {e}"))?;
    let (mut rax, mut r10, mut syscall) = (false, false, false);
    let mut text = String::new();
    for instruction in instructions.iter() {
        let op = instruction.mnemonic().unwrap_or_default();
        use std::fmt::Write;
        write!(
            text,
            "{:#x}: {} {}; ",
            instruction.address(),
            op,
            instruction.op_str().unwrap_or_default()
        )?;
        let detail = cs
            .insn_detail(instruction)
            .map_err(|e| anyhow::anyhow!("指令详情: {e}"))?;
        let arch = detail.arch_detail();
        let x86 = arch.x86().context("非 x86 指令详情")?;
        if x86.opcode().iter().all(|b| *b == 0) {
            break;
        }
        let invalid = match technique {
            Technique::Direct => matches!(op, "jmp" | "call" | "leave" | "int3"),
            Technique::Indirect => matches!(op, "call" | "leave" | "int3" | "ret"),
        };
        if invalid {
            break;
        }
        let termination = match technique {
            Technique::Direct => op == "ret",
            Technique::Indirect => op == "jmp",
        };
        if termination {
            return Ok(
                (rax && r10 && (technique == Technique::Indirect || syscall)).then_some(Block {
                    text,
                    end: instruction.address(),
                }),
            );
        }
        if op == "syscall" {
            syscall = true;
            if technique == Technique::Indirect || !rax || !r10 {
                break;
            }
        } else {
            for register in detail.regs_write() {
                match cs.reg_name(*register).as_deref() {
                    Some("eax" | "rax") => rax = true,
                    Some("r10") => r10 = true,
                    _ => {}
                }
            }
        }
    }
    Ok(None)
}
fn handler(path: &str) -> bool {
    let path = path.to_lowercase();
    path.ends_with("ntdll.dll") || path.ends_with("win32u.dll")
}
fn path_at(vads: &[memory::Vad], address: u64) -> Option<&str> {
    vads.iter()
        .find(|v| v.start <= address && address < v.end)
        .map(|v| v.path.as_str())
}
fn indirect_target(mut read: impl FnMut(u64, &mut [u8]) -> Result<()>, end: u64) -> Option<u64> {
    let mut jump = [0; 6];
    read(end, &mut jump).ok()?;
    if jump[..2] != [0xff, 0x25] {
        return None;
    }
    // Pinned reference uses unsigned u32 displacement and 8-byte pointer, even in x86.
    let displacement = u32::from_le_bytes(jump[2..].try_into().ok()?) as u64;
    if displacement == 0 {
        return None;
    }
    let pointer = end.checked_add(displacement)?.checked_add(6)?;
    let mut target = [0; 8];
    read(pointer, &mut target).ok()?;
    let target = u64::from_le_bytes(target);
    let mut opcode = [0; 2];
    read(target, &mut opcode).ok()?;
    (opcode == [0x0f, 0x05] && target != 0).then_some(target)
}
fn validate(
    cs: &Capstone,
    technique: Technique,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    vads: &[memory::Vad],
    hit: u64,
    job: &Job,
) -> Result<Option<(u64, String)>> {
    let Some(start) = hit.checked_sub(32) else {
        return Ok(None);
    };
    let mut bytes = [0; 64];
    if read(start, &mut bytes).is_err() {
        return Ok(None);
    }
    for offset in 0..32 {
        job.check()?;
        if let Some(found) = block(cs, technique, bytes.at(offset..)?, start + offset as u64)? {
            if technique == Technique::Indirect {
                let Some(target) = indirect_target(&mut read, found.end) else {
                    continue;
                };
                if !path_at(vads, target).is_some_and(handler) {
                    continue;
                }
            }
            return Ok(Some((start + offset as u64, found.text)));
        }
    }
    Ok(None)
}
// Reference compares two freshly allocated UnreadableValue objects by identity.
// Its handle-count predicate therefore never excludes missing HandleCount fields.
fn active(p: &Process, current_year: u32) -> bool {
    let year = timeline::filetime_utc(p.created)
        .get(..4)
        .and_then(|s| s.parse::<u32>().ok());
    p.pid != 0
        && p.pid != 4
        && p.pid <= 0xffff_fffc
        && p.pid.is_multiple_of(4)
        && p.ppid != 4
        && p.threads > 0
        && p.exited == 0
        && p.dtb & !4095 != 0
        && year.is_some_and(|y| y > 1998 && y < current_year + 10)
        && p.name != "MsMpEng.exe"
}
impl Windows<'_> {
    pub(super) fn system_calls(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        let technique = match plugin {
            Plugin::WinDirectSystemCalls => Technique::Direct,
            Plugin::WinIndirectSystemCalls => Technique::Indirect,
            _ => bail!("非系统调用检测入口"),
        };
        let arch = Architecture::from_isf(self.vm.isf)?;
        ensure!(
            matches!(arch, Architecture::X86 | Architecture::X64),
            "系统调用检测仅支持 Intel x86/x64"
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let current_year =
            timeline::filetime_utc((now + 11_644_473_600) * 10_000_000)[..4].parse()?;
        let regex = ByteRegex::compile(technique.pattern(), false)?;
        let cs32 = decoder(true)?;
        let cs64 = decoder(false)?;
        let mut result = self.result(technique.plugin());
        let (processes, diagnostics) = self.processes_partial(job)?;
        if !diagnostics.is_empty() {
            result.complete = false;
            result.diagnostics.extend(diagnostics);
        }
        let mut reports = Vec::new();
        let mut output_bytes = 0usize;
        let mut stopped = false;
        for process in processes.iter().filter(|p| active(p, current_year)) {
            job.check()?;
            job.report(format!("{}: PID {}", plugin.name(), process.pid));
            let read = (|| -> Result<()> {
                let head = self.field(process.address, "_EPROCESS", "ThreadListHead")?;
                if self.vm.pointer(head)? < 0x8000_0000
                    || self.vm.pointer(add(head, self.vm.pointer_size() as u64)?)? < 0x8000_0000
                {
                    return Ok(());
                }
                let wow = if arch == Architecture::X86 {
                    true
                } else {
                    ["WoW64Process", "Wow64Process"]
                        .into_iter()
                        .find(|f| self.vm.isf.has_field("_EPROCESS", f))
                        .map(|f| self.number(process.address, "_EPROCESS", f))
                        .transpose()?
                        .is_some_and(|p| p != 0)
                };
                let cs = if wow { &cs32 } else { &cs64 };
                let vm = self.process_memory(process)?;
                let vads = self.tagged_vads_with_paths(process, &mut result, job)?;
                let vads: Vec<_> = vads
                    .into_iter()
                    .filter(|v| v.end - v.start < 10_000_000)
                    .collect();
                let regions: Vec<_> = vads.iter().map(|v| (v.start, v.end)).collect();
                let (mut hits, mut unreadable_context) = (0usize, 0usize);
                let coverage =
                    vm.scan_reference(&regex, &regions, &mut Default::default(), job, |hit| {
                        if hits >= MAX_OBJECTS
                            || result.rows.len() >= MAX_OBJECTS
                            || output_bytes >= 128 * 1024 * 1024
                        {
                            stopped = true;
                            return Ok(false);
                        }
                        hits += 1;
                        let path = path_at(&vads, hit).unwrap_or_default();
                        if handler(path) {
                            return Ok(true);
                        }
                        if hit < 32
                            || vm
                                .read_reference(hit.saturating_sub(32), &mut [0; 64])
                                .is_err()
                        {
                            unreadable_context += 1;
                            return Ok(true);
                        }
                        if let Some((start, disasm)) = validate(
                            cs,
                            technique,
                            |at, bytes| vm.read_reference(at, bytes),
                            &vads,
                            hit,
                            job,
                        )? {
                            output_bytes += disasm.len() + path.len() + process.name.len() + 64;
                            result.rows.push(vec![
                                process.name.clone(),
                                process.pid.to_string(),
                                if path.is_empty() {
                                    "N/A".into()
                                } else {
                                    path.into()
                                },
                                hex(start),
                                disasm,
                            ]);
                        }
                        Ok(true)
                    })?;
                if !coverage.complete() || unreadable_context > 0 {
                    Self::issue(
                        &mut result,
                        format!("PID {} syscall scan", process.pid),
                        format!(
                            "扫描 {} / {} 字节；缺页 {} 字节；区间合并省略 {} 字节；不可读候选上下文 {}；{}",
                            coverage.scanned_bytes,
                            coverage.requested_bytes,
                            coverage.unreadable_bytes,
                            coverage.reference_coalescing_omitted_bytes,
                            unreadable_context,
                            coverage.stop_reason.as_deref().unwrap_or("扫描结束")
                        ),
                    );
                }
                if reports.len() < 65536 {
                    reports.push(serde_json::json!({"pid":process.pid,"wow_or_x86":wow,"vads":vads.len(),"hits":hits,"unreadable_context":unreadable_context,"coverage":coverage}));
                } else {
                    stopped = true;
                }
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                Self::issue(&mut result, format!("PID {} syscall scan", process.pid), e);
            }
            if stopped {
                Self::issue(
                    &mut result,
                    "syscall scan",
                    "命中／输出／元数据达到资源上限，保留已读取记录",
                );
                break;
            }
        }
        *result.kernel_identity.key_mut("system_calls")? = serde_json::json!({"disassembler":"Capstone 5.0.6 / capstone-rs 0.14.0; Intel syntax","candidate_rule":technique.pattern(),"context_bytes":64,"behind_bytes":32,"vad_size_exclusive_limit":10_000_000,"read_contract":"captured valid/transition mappings only","indirect_displacement":"unsigned u32; pointer width 8 (pinned reference)","processes":reports,"stopped":stopped});
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, image, put};
    use super::*;
    const DIRECT: &[u8] = b"\x4c\x8b\xd1\xb8\x3f\x00\x00\x00\x0f\x05\xc3";
    #[test]
    fn direct_blocks_require_register_writes_syscall_and_ret() {
        let cs = decoder(false).unwrap();
        let got = block(&cs, Technique::Direct, DIRECT, 0x1000)
            .unwrap()
            .unwrap();
        assert_eq!(got.end, 0x100a);
        assert_eq!(
            got.text,
            "0x1000: mov r10, rcx; 0x1003: mov eax, 0x3f; 0x1008: syscall ; 0x100a: ret ; "
        );
        for bytes in [
            b"\x0f\x05\xc3".as_slice(),
            b"\x4c\x8b\xd1\x0f\x05\xb8\x01\x00\x00\x00\xc3",
            b"\x4c\x8b\xd1\xb8\x01\x00\x00\x00\xcc\x0f\x05\xc3",
            b"\x4c\x8b\xd1\xb8\x01\x00\x00\x00\x00\x00\x0f\x05\xc3",
        ] {
            assert!(
                block(&cs, Technique::Direct, bytes, 0x1000)
                    .unwrap()
                    .is_none()
            );
        }
        // regs_access matters: arithmetic writes are accepted; no mov-only shortcut.
        assert!(
            block(
                &cs,
                Technique::Direct,
                b"\x49\x87\xca\x31\xc0\x0f\x05\xc3",
                0x1000
            )
            .unwrap()
            .is_some()
        );
        assert!(
            block(&decoder(true).unwrap(), Technique::Direct, DIRECT, 0x1000)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn indirect_blocks_end_on_jump_and_reject_syscall_or_ret_before_it() {
        let cs = decoder(false).unwrap();
        let bytes = b"\x4c\x8b\xd1\xb8\x01\x00\x00\x00\xff\x25\x10\x00\x00\x00\xc3";
        let got = block(&cs, Technique::Indirect, bytes, 0x1000)
            .unwrap()
            .unwrap();
        assert_eq!(got.end, 0x1008);
        assert!(got.text.ends_with("0x1008: jmp qword ptr [rip + 0x10]; "));
        assert!(
            block(&cs, Technique::Indirect, DIRECT, 0x1000)
                .unwrap()
                .is_none()
        );
        assert!(
            block(&cs, Technique::Direct, bytes, 0x1000)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn indirect_target_preserves_unsigned_reference_displacement_and_fixed_width() {
        let end = 0x1000;
        let mut visited = Vec::new();
        let target = indirect_target(
            |at, b| {
                visited.push((at, b.len()));
                match at {
                    0x1000 => b.copy_from_slice(b"\xff\x25\xff\xff\xff\xff"),
                    0x100001005 => b.copy_from_slice(&0x8000u64.to_le_bytes()),
                    0x8000 => b.copy_from_slice(b"\x0f\x05"),
                    _ => bail!("unexpected read"),
                };
                Ok(())
            },
            end,
        );
        assert_eq!(target, Some(0x8000));
        assert_eq!(visited, [(0x1000, 6), (0x100001005, 8), (0x8000, 2)]);
        assert!(indirect_target(|_, _| bail!("missing"), end).is_none());
        assert!(
            indirect_target(
                |_, b| {
                    b.fill(0);
                    Ok(())
                },
                end
            )
            .is_none()
        );
    }
    #[test]
    fn candidate_regex_keeps_overlaps_and_twenty_four_byte_boundary() {
        for technique in [Technique::Direct, Technique::Indirect] {
            let regex = ByteRegex::compile(technique.pattern(), false).unwrap();
            let prefix = if technique == Technique::Direct {
                [0x0f, 0x05]
            } else {
                [0xff, 0x25]
            };
            let mut data = prefix.to_vec();
            data.extend(prefix);
            data.push(0xc3);
            let mut hits = Vec::new();
            regex
                .for_each(&data, &Job::default(), |m| {
                    hits.push(m.start);
                    Ok(true)
                })
                .unwrap();
            assert_eq!(hits, [0, 2]);
            for n in [24, 25] {
                let mut data = prefix.to_vec();
                data.extend(vec![0x90; n]);
                data.push(0xc3);
                let mut hits = Vec::new();
                regex
                    .for_each(&data, &Job::default(), |m| {
                        hits.push(m.start);
                        Ok(true)
                    })
                    .unwrap();
                assert_eq!(hits.len(), usize::from(n == 24));
            }
        }
        assert!(handler("\\Windows\\NTDLL.DLL"));
        assert!(!handler("ntdll.dll.bak"));
    }
    #[test]
    fn validator_matches_pinned_reference_vectors_including_indirect_positive_hits() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/system-calls.json"
        ))
        .unwrap();
        assert_eq!(
            vectors["reference_commit"],
            "881e970121c16f0932fb9d16fbd5fb258cbcbf75"
        );
        for case in vectors["cases"].as_array().unwrap() {
            let cs = decoder(case["x86"].as_bool().unwrap()).unwrap();
            let technique = if case["indirect"].as_bool().unwrap() {
                Technique::Indirect
            } else {
                Technique::Direct
            };
            let segments: Vec<_> = case["segments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| {
                    let hex = s["hex"].as_str().unwrap();
                    let bytes: Vec<_> = hex
                        .as_bytes()
                        .chunks_exact(2)
                        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
                        .collect();
                    (s["address"].as_u64().unwrap(), bytes)
                })
                .collect();
            let vads: Vec<_> = case["vads"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| memory::Vad {
                    address: 0,
                    start: v["start"].as_u64().unwrap(),
                    end: v["start"].as_u64().unwrap() + v["size"].as_u64().unwrap(),
                    protection: 0,
                    private: false,
                    path: v["path"].as_str().unwrap().into(),
                })
                .collect();
            let got = validate(
                &cs,
                technique,
                |at, b| {
                    for (start, data) in &segments {
                        if *start <= at
                            && at
                                .checked_add(b.len() as u64)
                                .is_some_and(|end| end <= *start + data.len() as u64)
                        {
                            b.copy_from_slice(
                                &data[(at - start) as usize..(at - start) as usize + b.len()],
                            );
                            return Ok(());
                        }
                    }
                    bail!("missing synthetic context")
                },
                &vads,
                case["hit"].as_u64().unwrap(),
                &Job::default(),
            )
            .unwrap();
            let got = got
                .map(|(address, disasm)| serde_json::json!({"address":address,"disasm":disasm}))
                .unwrap_or(serde_json::Value::Null);
            assert_eq!(got, case["expected"], "{}", case["id"]);
        }
    }
    fn prepared() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = super::super::regex::tests::prepared();
        isf.data["user_types"]["_EPROCESS"]["fields"]["ThreadListHead"] =
            serde_json::json!({"offset":192,"type":{"kind":"struct","name":"_LIST_ENTRY"}});
        isf.data["user_types"]["_HANDLE_TABLE"] = serde_json::json!({"size":8,"fields":{"HandleCount":{"offset":0,"type":{"kind":"base","name":"u64"}}}});
        put(&mut b, 0xa028, 12); // Not a direct child of System.
        put(&mut b, 0xa050, K + 0x4000);
        put(&mut b, 0xc000, 1);
        put(&mut b, 0xa0c0, K + 0x20c0);
        put(&mut b, 0xa0c8, K + 0x20c0);
        b[0x20100..0x20100 + DIRECT.len()].copy_from_slice(DIRECT);
        (b, isf)
    }
    fn run(bytes: &[u8], isf: &Isf, plugin: Plugin, job: &Job) -> Result<Results> {
        let image = image(bytes);
        Windows {
            vm: Memory::new(&image, 0x1000, isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(isf)?,
        }
        .run(plugin, &Options::default(), job)
    }
    #[test]
    fn full_scan_uses_active_filter_and_captured_pages_and_cancel() {
        let (mut b, isf) = prepared();
        let r = run(&b, &isf, Plugin::WinDirectSystemCalls, &Job::default()).unwrap();
        assert_eq!(r.rows.len(), 1, "{:?}", r.diagnostics);
        assert_eq!(&r.rows[0][..4], ["child", "8", "N/A", "0x0000000000001100"]);
        assert!(r.complete, "{:?}", r.diagnostics);
        put(&mut b, 0xa028, 4);
        assert!(
            run(&b, &isf, Plugin::WinDirectSystemCalls, &Job::default())
                .unwrap()
                .rows
                .is_empty()
        );
        put(&mut b, 0xa028, 12);
        put(&mut b, 0x7008, 0); // missing code page cannot become a match
        let r = run(&b, &isf, Plugin::WinDirectSystemCalls, &Job::default()).unwrap();
        assert!(r.rows.is_empty());
        assert!(!r.complete);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(run(&b, &isf, Plugin::WinDirectSystemCalls, &job).is_err());
    }
    #[test]
    fn tagged_scanner_recovers_parent_mismatch_without_needing_protection_fields() {
        let (mut b, mut isf) = prepared();
        b[0x20100..0x20100 + DIRECT.len()].fill(0);
        b[0x25080..0x25080 + DIRECT.len()].copy_from_slice(DIRECT);
        isf.data["user_types"]
            .as_object_mut()
            .unwrap()
            .remove("_MMVAD_FLAGS");
        isf.data["user_types"]["_RTL_BALANCED_NODE"]["fields"]["ParentValue"] =
            serde_json::json!({"offset":16,"type":{"kind":"base","name":"u64"}});
        let r = run(&b, &isf, Plugin::WinDirectSystemCalls, &Job::default()).unwrap();
        assert_eq!(r.rows.len(), 1, "{:?}", r.diagnostics);
        assert_eq!(r.rows[0][3], "0x0000000000002080");
        assert!(!r.complete);
        assert!(r.diagnostics.iter().any(|d| d.contains("父指针")));
        b[0xb100 - 12..0xb100 - 8].fill(0);
        let r = run(&b, &isf, Plugin::WinDirectSystemCalls, &Job::default()).unwrap();
        assert!(r.rows.is_empty());
        assert!(r.diagnostics.iter().any(|d| d.contains("tag")));
    }
    #[test]
    fn active_filter_rejects_terminated_kernel_defender_and_invalid_identity() {
        let (b, isf) = prepared();
        let image = image(&b);
        let w = Windows {
            vm: Memory::new(&image, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let process = w.process(K + 0x2000).unwrap();
        assert!(active(&process, 2026));
        let mut unreadable_handles = process.clone();
        unreadable_handles.handles = None;
        assert!(active(&unreadable_handles, 2026)); // Reference absent-value inequality is identity-based.
        for index in 0..7 {
            let mut p = process.clone();
            match index {
                0 => p.threads = 0,
                1 => p.exited = 1,
                2 => p.ppid = 4,
                3 => p.name = "MsMpEng.exe".into(),
                4 => p.created = 0,
                5 => p.pid = 9,
                _ => p.dtb = 0,
            };
            assert!(!active(&p, 2026));
        }
    }
}
