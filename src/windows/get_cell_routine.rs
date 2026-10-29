//! Registry handler ownership against the loaded module view.
use super::*;

/// The pinned reference treats the end of a SizedModule as inclusive for a
/// point lookup. Preserve every overlapping owner rather than first-match wins.
fn handler_owners(modules: &[KernelModule], handler: u64) -> Vec<String> {
    modules
        .iter()
        .filter(|m| {
            !m.name.is_empty()
                && handler >= m.base
                && m.base.checked_add(m.size).is_some_and(|end| handler <= end)
        })
        .map(|m| {
            m.name
                .rsplit_once('.')
                .filter(|(stem, _)| !stem.is_empty())
                .map_or(m.name.as_str(), |(stem, _)| stem)
                .to_owned()
        })
        .collect()
}
fn kernel_owner(name: &str) -> bool {
    matches!(name, "ntkrnlmp" | "ntkrnlpa" | "ntkrpamp" | "ntoskrnl")
}

impl Windows<'_> {
    pub(super) fn get_cell_routine(&self, job: &Job) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "GetCellRoutine 仅支持 x86/x64"
        );
        // Missing exact layouts must fail even when the list happens to be empty.
        self.vm.isf.field("_HHIVE", "GetCellRoutine")?;
        self.vm.isf.field("_HHIVE", "Signature")?;
        self.vm.isf.field("_CMHIVE", "Hive")?;
        let mut r = self.result(Plugin::WinGetCellRoutine);
        let modules = self.module_entries(job, &mut r, false)?;
        let hives = self.registry(Plugin::WinHivelist, &Options::default(), job)?;
        r.complete &= hives.complete;
        r.diagnostics.extend(hives.diagnostics);
        let listed_hives = hives.rows.len();
        let mut checked_hives = 0usize;
        let mut kernel_only_handlers = 0usize;
        for row in hives.rows {
            job.check()?;
            let read = (|| -> Result<()> {
                let address = u64::from_str_radix(row[0].trim_start_matches("0x"), 16)?;
                let hive = self.field(address, "_CMHIVE", "Hive")?;
                ensure!(
                    self.number(hive, "_HHIVE", "Signature")? == 0xbee0bee0,
                    "无效 HHIVE.Signature"
                );
                let handler = self.number(hive, "_HHIVE", "GetCellRoutine")?;
                let name = if row[1].is_empty() {
                    "[NONAME]"
                } else {
                    &row[1]
                };
                let owners = handler_owners(&modules, handler);
                checked_hives += 1;
                if !owners.is_empty() && owners.iter().all(|owner| kernel_owner(owner)) {
                    kernel_only_handlers += 1;
                }
                if owners.is_empty() {
                    r.rows
                        .push(vec![hex(hive), name.to_owned(), "N/A".into(), hex(handler)]);
                } else {
                    for owner in owners.into_iter().filter(|name| !kernel_owner(name)) {
                        r.rows
                            .push(vec![hex(hive), name.to_owned(), owner, hex(handler)]);
                    }
                }
                Ok(())
            })();
            if let Err(e) = read {
                Self::issue(
                    &mut r,
                    format!("hive {} GetCellRoutine", row[0]),
                    format!("{e:#}"),
                );
            }
        }
        r.kernel_identity["getcellroutine"] = serde_json::json!({
            "source": "CmpHiveListHead / HHIVE.GetCellRoutine / PsLoadedModuleList",
            "range_policy": "inclusive end for point lookups, matching pinned reference",
            "meaning": "non-kernel or unattributed handler is a lead, not proof of a hook; empty output does not prove absence",
            "scope": "listed hives and loaded modules; unreadable objects retain partial diagnostics",
            "listed_hives": listed_hives, "checked_hives": checked_hives,
            "rejected_or_unreadable_hives": listed_hives - checked_hives,
            "kernel_only_handlers": kernel_only_handlers, "report_rows": r.rows.len(),
            "loaded_module_entries": modules.len()
        });
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;

    fn prepare() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        let ptr = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        let list = |offset| json!({"offset":offset,"type":{"kind":"struct","name":"_LIST_ENTRY"}});
        let string =
            |offset| json!({"offset":offset,"type":{"kind":"struct","name":"_UNICODE_STRING"}});
        isf.data["symbols"]["CmpHiveListHead"] = json!({"address":0x600});
        isf.data["user_types"]["_CMHIVE"] = json!({"size":80,"fields":{
            "HiveList":list(0),"FileFullPath":string(16),
            "Hive":{"offset":40,"type":{"kind":"struct","name":"_HHIVE"}}
        }});
        isf.data["user_types"]["_HHIVE"] =
            json!({"size":16,"fields":{"Signature":ptr(0),"GetCellRoutine":ptr(8)}});
        isf.data["user_types"]["_KLDR_DATA_TABLE_ENTRY"] = json!({"size":64,"fields":{
            "InLoadOrderLinks":list(0),"DllBase":ptr(16),"SizeOfImage":ptr(24),
            "BaseDllName":string(32),"FullDllName":string(48)
        }});
        // Two hives, first non-kernel handler and then unknown/null handler.
        put(&mut b, 0x8600, K + 0x4000);
        put(&mut b, 0x8608, K + 0x5000);
        put(&mut b, 0xc000, K + 0x5000);
        put(&mut b, 0xc008, K + 0x600);
        put(&mut b, 0xd000, K + 0x600);
        put(&mut b, 0xd008, K + 0x4000);
        put(&mut b, 0xc028, 0xbee0bee0);
        put(&mut b, 0xd028, 0xbee0bee0);
        put(&mut b, 0xc030, K + 0x9020);
        put(&mut b, 0x8700, K + 0x6000);
        put(&mut b, 0x8708, K + 0x6000);
        put(&mut b, 0xe000, K + 0x700);
        put(&mut b, 0xe008, K + 0x700);
        put(&mut b, 0xe010, K + 0x9000);
        put(&mut b, 0xe018, 0x100);
        let name: Vec<u8> = "driver.sys"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        b[0xe100..0xe100 + name.len()].copy_from_slice(&name);
        b[0xe020..0xe022].copy_from_slice(&(name.len() as u16).to_le_bytes());
        b[0xe022..0xe024].copy_from_slice(&(name.len() as u16 + 2).to_le_bytes());
        put(&mut b, 0xe028, K + 0x6100);
        (b, isf)
    }
    fn run(b: &[u8], isf: &Isf, job: &Job) -> Result<Results> {
        let img = image(b);
        Windows {
            vm: Memory::new(&img, 0x1000, isf, None),
            base: if Architecture::from_isf(isf)? == Architecture::X86 {
                0x8000_0000
            } else {
                K
            },
            pdb: PdbIdentity::from_isf(isf)?,
        }
        .run(Plugin::WinGetCellRoutine, &Options::default(), job)
    }
    #[test]
    fn reads_embedded_hhive_address_driver_name_and_unknown_handler() {
        let (b, isf) = prepare();
        let r = run(&b, &isf, &Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows,
            vec![
                vec![
                    hex(K + 0x4028),
                    "[NONAME]".into(),
                    "driver".into(),
                    hex(K + 0x9020)
                ],
                vec![hex(K + 0x5028), "[NONAME]".into(), "N/A".into(), hex(0)]
            ]
        );
    }
    #[test]
    fn missing_handler_page_keeps_other_hive_and_diagnostics() {
        let (mut b, isf) = prepare();
        // Move the second hive to the page end: its list and path descriptor
        // remain readable, while its embedded HHIVE handler crosses the hole.
        put(&mut b, 0x8608, K + 0x5fd8);
        put(&mut b, 0xc000, K + 0x5fd8);
        put(&mut b, 0xdfd8, K + 0x600);
        put(&mut b, 0xdfe0, K + 0x4000);
        put(&mut b, 0x4000 + 6 * 8, 0);
        let r = run(&b, &isf, &Job::default()).unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
        assert!(r.diagnostics.iter().any(|d| d.contains("GetCellRoutine")));
    }
    #[test]
    fn exact_layout_and_cancellation_are_required() {
        let (b, mut isf) = prepare();
        isf.data["user_types"]["_HHIVE"]["fields"]
            .as_object_mut()
            .unwrap()
            .remove("GetCellRoutine");
        assert!(run(&b, &isf, &Job::default()).is_err());
        let (_, isf) = prepare();
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(run(&b, &isf, &job).is_err());
    }
    #[test]
    fn named_hive_and_unused_module_path_pages() {
        let (mut b, isf) = prepare();
        let name: Vec<u8> = "\\REGISTRY\\MACHINE\\SYSTEM"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        b[0xc100..0xc100 + name.len()].copy_from_slice(&name);
        b[0xc010..0xc012].copy_from_slice(&(name.len() as u16).to_le_bytes());
        b[0xc012..0xc014].copy_from_slice(&(name.len() as u16 + 2).to_le_bytes());
        put(&mut b, 0xc018, K + 0x4100);
        // Invalid FullDllName is irrelevant to GetCellRoutine, but still
        // diagnosed by ordinary module enumeration, which displays paths.
        b[0xe030..0xe032].copy_from_slice(&0xffffu16.to_le_bytes());
        let r = run(&b, &isf, &Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows[0][1], "\\REGISTRY\\MACHINE\\SYSTEM");
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = engine
            .run(Plugin::WinModules, &Options::default(), &Job::default())
            .unwrap();
        assert!(!r.complete);
        assert!(r.diagnostics.iter().any(|d| d.contains("FullDllName")));
    }
    #[test]
    fn invalid_signature_is_not_reported_as_a_hook() {
        let (mut b, isf) = prepare();
        put(&mut b, 0xc028, 0);
        let r = run(&b, &isf, &Job::default()).unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0][0], hex(K + 0x5028));
        assert!(r.diagnostics.iter().any(|d| d.contains("HHIVE.Signature")));
    }
    #[test]
    fn kernel_handler_is_suppressed_and_arm64_is_explicit() {
        let (mut b, mut isf) = prepare();
        let name: Vec<u8> = "ntoskrnl.exe"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        b[0xe100..0xe100 + name.len()].copy_from_slice(&name);
        b[0xe020..0xe022].copy_from_slice(&(name.len() as u16).to_le_bytes());
        b[0xe022..0xe024].copy_from_slice(&(name.len() as u16 + 2).to_le_bytes());
        let r = run(&b, &isf, &Job::default()).unwrap();
        assert!(r.complete);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0][3], hex(0));
        isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(43620);
        assert!(
            run(&b, &isf, &Job::default())
                .unwrap_err()
                .to_string()
                .contains("x86/x64")
        );
    }
    #[test]
    fn x86_uses_four_byte_handlers_and_embedded_hhive() {
        let (mut b, mut isf) = prepare();
        isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(332);
        isf.data["base_types"]["pointer"]["size"] = json!(4);
        for bytes in b.chunks_exact_mut(8) {
            let v = u64::from_le_bytes(bytes.try_into().unwrap());
            if (K..K + 0x10000).contains(&v) {
                bytes.copy_from_slice(&(0x8000_0000 + v - K).to_le_bytes());
            }
        }
        for at in [0x8600usize, 0xc000, 0xd000, 0x8700, 0xe000] {
            let blink = b[at + 8..at + 12].to_vec();
            b[at + 4..at + 8].copy_from_slice(&blink);
        }
        b[0x1000..0x3000].fill(0);
        b[0x1800..0x1804].copy_from_slice(&0x2003u32.to_le_bytes());
        for i in 0..32usize {
            b[0x2000 + i * 4..0x2004 + i * 4]
                .copy_from_slice(&(0x8003u32 + i as u32 * 4096).to_le_bytes());
        }
        let r = run(&b, &isf, &Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.rows[0][0], hex(0x8000_4028));
        assert_eq!(r.rows[0][3], hex(0x8000_9020));
    }
    #[test]
    fn inclusive_ranges_overlaps_kernel_names_and_overflow() {
        let module = |name: &str, base, size| KernelModule {
            name: name.into(),
            base,
            size,
            path: String::new(),
        };
        let modules = vec![
            module("ntoskrnl.exe", 10, 10),
            module("driver.sys", 20, 0),
            module("overflow.sys", u64::MAX, 1),
        ];
        assert_eq!(handler_owners(&modules, 20), vec!["ntoskrnl", "driver"]);
        assert!(handler_owners(&modules, 21).is_empty());
        assert!(handler_owners(&modules, u64::MAX).is_empty());
        for name in ["ntoskrnl", "ntkrnlmp", "ntkrnlpa", "ntkrpamp"] {
            assert!(kernel_owner(name));
        }
        assert!(!kernel_owner("NTOSKRNL"));
    }
}
