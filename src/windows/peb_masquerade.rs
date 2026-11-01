//! EPROCESS/audit/PEB names and independent Unicode descriptor length checks.
use super::*;

/// Read only Length and Buffer: MaximumLength is evidence to compare, not a
/// prerequisite that may suppress a spoofed descriptor. Match reference UTF-16
/// replacement and NUL termination, including a dangling final byte.
fn descriptor_text(vm: &Memory<'_>, address: u64) -> Result<(String, u64)> {
    let length = vm.number(address, "_UNICODE_STRING", "Length")?;
    ensure!(length <= u16::MAX as u64, "UNICODE_STRING 长度超过 USHORT");
    let mut bytes = vec![0; usize::try_from(length)?];
    if length != 0 {
        vm.read(vm.number(address, "_UNICODE_STRING", "Buffer")?, &mut bytes)?;
    }
    let mut text = String::from_utf16_lossy(
        &bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
    );
    if length % 2 != 0 {
        text.push('\u{fffd}');
    }
    text.truncate(text.find('\0').unwrap_or(text.len()));
    Ok((text, length))
}

fn length_mismatch(text: &str, length: u64, maximum: u64) -> bool {
    let characters = text.chars().count() as u64;
    length / 2 != characters || (maximum / 2).checked_sub(1) != Some(characters)
}

impl Windows<'_> {
    pub(super) fn peb_masquerade(&self, options: &Options, job: &Job) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "PebMasquerade 仅支持 x86/x64"
        );
        ensure!(options.pids.len() <= 4096, "PID 列表超过 4096 项");
        let pids: std::collections::BTreeSet<u64> = options
            .pids
            .iter()
            .copied()
            .chain(options.pid)
            .map(u64::from)
            .collect();
        let mut r = self.result(Plugin::WinPebMasquerade);
        let (processes, diagnostics) = self.processes_partial(job)?;
        r.complete &= diagnostics.is_empty();
        r.diagnostics = diagnostics;
        r.kernel_identity["peb_masquerade"] = serde_json::json!({
            "view":"native EPROCESS.Peb, including WOW64 processes; no WOW64 PEB substitution",
            "true_means":"descriptor length mismatch only; not proof of malicious process masquerading",
            "flags":"independent ImagePathName and CommandLine checks; false means no mismatch established, not proof of no spoofing",
            "reference_column_order":"pinned reference swaps the two flags; native column names follow the descriptor actually checked"
        });
        for process in processes
            .into_iter()
            .filter(|p| pids.is_empty() || pids.contains(&p.pid))
        {
            job.check()?;
            let audit = (|| -> Result<String> {
                let info =
                    self.field(process.address, "_EPROCESS", "SeAuditProcessCreationInfo")?;
                let name = self.number(info, "_SE_AUDIT_PROCESS_CREATION_INFO", "ImageFileName")?;
                if name == 0 {
                    return Ok(String::new());
                }
                let address = self.field(name, "_OBJECT_NAME_INFORMATION", "Name")?;
                Ok(descriptor_text(&self.vm, address)?.0)
            })();
            let audit = match audit {
                Ok(s) => s,
                Err(error) => {
                    Self::issue(
                        &mut r,
                        format!("PID {} audit name", process.pid),
                        format!("{error:#}"),
                    );
                    String::new()
                }
            };
            let params = (|| -> Result<Option<(Memory<'_>, u64)>> {
                let Some(peb) = self.peb(&process)? else {
                    return Ok(None);
                };
                let vm = self.process_memory(&process)?;
                let params = vm.number(peb, "_PEB", "ProcessParameters")?;
                Ok((params != 0).then_some((vm, params)))
            })();
            let mut path = String::new();
            let mut flags = [false; 2];
            match params {
                Ok(Some((vm, params))) => {
                    for (i, field) in ["ImagePathName", "CommandLine"].into_iter().enumerate() {
                        job.check()?;
                        let read = (|| -> Result<()> {
                            let address = add(
                                params,
                                vm.isf.offset("_RTL_USER_PROCESS_PARAMETERS", field)?,
                            )?;
                            let (text, length) = descriptor_text(&vm, address)?;
                            if i == 0 {
                                path = text.clone();
                            }
                            // The reference only checks nonempty extracted strings.
                            if !text.is_empty() {
                                let maximum =
                                    vm.number(address, "_UNICODE_STRING", "MaximumLength")?;
                                flags[i] = length_mismatch(&text, length, maximum);
                            }
                            Ok(())
                        })();
                        if let Err(error) = read {
                            Self::issue(
                                &mut r,
                                format!("PID {} PEB {field}", process.pid),
                                format!("{error:#}"),
                            );
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => Self::issue(
                    &mut r,
                    format!("PID {} PEB", process.pid),
                    format!("{error:#}"),
                ),
            }
            let optional = |s: String| if s.is_empty() { "N/A".into() } else { s };
            r.rows.push(vec![
                process.pid.to_string(),
                process.name,
                optional(audit),
                optional(path),
                flags[0].to_string(),
                flags[1].to_string(),
            ]);
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;

    fn unicode(bytes: &mut [u8], at: usize, buffer: usize, pointer: u64, text: &str, maximum: u16) {
        let encoded: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        bytes[at..at + 2].copy_from_slice(&(encoded.len() as u16).to_le_bytes());
        bytes[at + 2..at + 4].copy_from_slice(&maximum.to_le_bytes());
        put(bytes, at + 8, pointer);
        bytes[buffer..buffer + encoded.len()].copy_from_slice(&encoded);
    }
    fn names_fixture() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        put(&mut b, 0x1000, 0x2003); // User and kernel views of the test pages.
        let ptr = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        let structure =
            |offset, name| json!({"offset":offset,"type":{"kind":"struct","name":name}});
        isf.data["user_types"]["_EPROCESS"]["fields"]["SeAuditProcessCreationInfo"] =
            structure(128, "_SE_AUDIT_PROCESS_CREATION_INFO");
        isf.data["user_types"]["_SE_AUDIT_PROCESS_CREATION_INFO"] =
            json!({"size":8,"fields":{"ImageFileName":ptr(0)}});
        isf.data["user_types"]["_OBJECT_NAME_INFORMATION"] =
            json!({"size":16,"fields":{"Name":structure(0,"_UNICODE_STRING")}});
        isf.data["user_types"]["_PEB"] = json!({"size":8,"fields":{"ProcessParameters":ptr(0)}});
        isf.data["user_types"]["_RTL_USER_PROCESS_PARAMETERS"] = json!({"size":32,"fields":{"ImagePathName":structure(0,"_UNICODE_STRING"),"CommandLine":structure(16,"_UNICODE_STRING")}});
        put(&mut b, 0xa068, 0x9000);
        put(&mut b, 0x11000, 0xa000);
        unicode(&mut b, 0x12000, 0x13000, 0xb000, "C:\\child.exe", 26);
        unicode(&mut b, 0x12010, 0x14000, 0xc000, "child.exe -x", 26);
        put(&mut b, 0xa080, K + 0xd000);
        unicode(
            &mut b,
            0x15000,
            0x16000,
            K + 0xe000,
            "\\Device\\child.exe",
            36,
        );
        (b, isf)
    }
    fn run(bytes: &[u8], isf: &Isf, options: &Options, job: &Job) -> Result<Results> {
        let img = image(bytes);
        Windows {
            vm: Memory::new(&img, 0x1000, isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(isf)?,
        }
        .run(Plugin::WinPebMasquerade, options, job)
    }
    #[test]
    fn native_names_and_independent_flags_include_kernel_and_exited_processes() {
        let (mut b, isf) = names_fixture();
        put(&mut b, 0xa060, 130000000000000001); // An exited process stays in this view.
        let r = run(&b, &isf, &Options::default(), &Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
        let row = r.rows.iter().find(|r| r[0] == "8").unwrap();
        assert_eq!(
            row[1..],
            [
                "child",
                "\\Device\\child.exe",
                "C:\\child.exe",
                "false",
                "false"
            ]
        );
        // Path has spare capacity; command line retains its original capacity.
        b[0x12002..0x12004].copy_from_slice(&40u16.to_le_bytes());
        let r = run(&b, &isf, &Options::default(), &Job::default()).unwrap();
        assert_eq!(r.rows[1][4..], ["true", "false"]);
        b[0x12002..0x12004].copy_from_slice(&26u16.to_le_bytes());
        b[0x12012..0x12014].copy_from_slice(&40u16.to_le_bytes());
        let r = run(&b, &isf, &Options::default(), &Job::default()).unwrap();
        assert_eq!(r.rows[1][4..], ["false", "true"]);
    }
    #[test]
    fn malformed_capacity_is_compared_without_discarding_readable_names() {
        let (mut b, isf) = names_fixture();
        b[0x12002..0x12004].copy_from_slice(&0u16.to_le_bytes());
        let r = run(&b, &isf, &Options::default(), &Job::default()).unwrap();
        assert!(r.complete);
        assert_eq!(r.rows[1][3], "C:\\child.exe");
        assert_eq!(r.rows[1][4], "true");
        assert!(length_mismatch("x", 2, 0));
        assert!(length_mismatch("x", 2, 1));
        assert!(!length_mismatch("x", 2, 4));
    }
    #[test]
    fn utf16_scalar_count_nul_and_odd_byte_follow_reference_decoding() {
        assert!(length_mismatch("😀", 4, 6)); // Python counts Unicode scalars, not UTF-16 units.
        for x86 in [false, true] {
            let (mut b, mut isf, base, _) =
                super::super::driver_irp::tests::driver_fixture(x86, false, false);
            unicode(&mut b, 0x11000, 0x12000, base + 0xa000, "a\0b", 8);
            if x86 {
                b[0x11004..0x11008].copy_from_slice(&((base + 0xa000) as u32).to_le_bytes());
            }
            let img = image(&b);
            let vm = Memory::new(&img, 0x1000, &isf, None);
            let (s, n) = descriptor_text(&vm, base + 0x9000).unwrap();
            assert_eq!((s.as_str(), n), ("a", 6));
            assert!(length_mismatch(&s, n, 8));
            b[0x11000..0x11002].copy_from_slice(&3u16.to_le_bytes());
            b[0x12002] = 0xff;
            let img = image(&b);
            let vm = Memory::new(&img, 0x1000, &isf, None);
            assert_eq!(descriptor_text(&vm, base + 0x9000).unwrap().0, "a�");
            // Missing descriptor type cannot become an invented empty string.
            isf.data["user_types"]["_UNICODE_STRING"]["fields"]
                .as_object_mut()
                .unwrap()
                .remove("Length");
            let isf = Isf::parse(
                &serde_json::to_vec(&isf.data).unwrap(),
                "missing-layout.json".into(),
            )
            .unwrap();
            let vm = Memory::new(&img, 0x1000, &isf, None);
            assert!(descriptor_text(&vm, base + 0x9000).is_err());
        }
    }
    #[test]
    fn absent_peb_and_audit_pointer_are_not_spoofing_verdicts() {
        let (mut b, isf) = names_fixture();
        put(&mut b, 0xa068, 0);
        put(&mut b, 0xa080, 0);
        let r = run(&b, &isf, &Options::default(), &Job::default()).unwrap();
        assert!(r.complete);
        assert_eq!(r.rows[1][2..], ["N/A", "N/A", "false", "false"]);
        assert!(
            r.kernel_identity["peb_masquerade"]["flags"]
                .as_str()
                .unwrap()
                .contains("not proof")
        );
    }
    #[test]
    fn unreadable_inputs_preserve_other_fields_and_mark_partial() {
        let (mut b, isf) = names_fixture();
        put(&mut b, 0x12008, 0x300000); // Unmapped path, readable command line.
        b[0x12012..0x12014].copy_from_slice(&40u16.to_le_bytes());
        let r = run(&b, &isf, &Options::default(), &Job::default()).unwrap();
        assert!(!r.complete);
        assert_eq!(
            r.rows[1][2..],
            ["\\Device\\child.exe", "N/A", "false", "true"]
        );
        assert!(r.diagnostics.iter().any(|d| d.contains("ImagePathName")));
        put(&mut b, 0xa080, K + 0x300000);
        let r = run(&b, &isf, &Options::default(), &Job::default()).unwrap();
        assert!(r.diagnostics.iter().any(|d| d.contains("audit name")));
    }
    #[test]
    fn pid_selection_missing_layout_cancellation_and_arm64_are_explicit() {
        let (b, mut isf) = names_fixture();
        let r = run(
            &b,
            &isf,
            &Options {
                pid: Some(8),
                ..Options::default()
            },
            &Job::default(),
        )
        .unwrap();
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0][0], "8");
        let r = run(
            &b,
            &isf,
            &Options {
                pid: Some(4),
                pids: vec![8, 8],
                ..Options::default()
            },
            &Job::default(),
        )
        .unwrap();
        assert_eq!(r.rows.len(), 2);
        assert!(
            run(
                &b,
                &isf,
                &Options {
                    pids: vec![8; 4097],
                    ..Options::default()
                },
                &Job::default()
            )
            .is_err()
        );
        isf.data["user_types"]["_RTL_USER_PROCESS_PARAMETERS"]["fields"]
            .as_object_mut()
            .unwrap()
            .remove("ImagePathName");
        let mut isf = Isf::parse(
            &serde_json::to_vec(&isf.data).unwrap(),
            "missing-layout.json".into(),
        )
        .unwrap();
        let r = run(&b, &isf, &Options::default(), &Job::default()).unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 2);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(run(&b, &isf, &Options::default(), &job).is_err());
        isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0xaa64);
        assert!(run(&b, &isf, &Options::default(), &Job::default()).is_err());
    }
}
