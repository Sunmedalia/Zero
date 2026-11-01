//! Live thread hardware debug registers, attributed to file VADs and exact symbols.
use super::thread_symbols::file_for_address;
use super::*;
use crate::bytes::MapAt as _;
use std::collections::BTreeMap;

struct DebugThread {
    owner: u64,
    tid: u64,
    state: u64,
    dr7: u64,
    addresses: [u64; 4],
}

impl Windows<'_> {
    fn debug_thread(&self, thread: u64) -> Result<Option<DebugThread>> {
        let trap = self.number(thread, "_ETHREAD", "Tcb.TrapFrame")?;
        ensure!(self.vm.kernel(trap), "调试寄存器 TrapFrame 地址无效");
        let dr7 = self.number(trap, "_KTRAP_FRAME", "Dr7")?;
        let state = self.number(thread, "_ETHREAD", "Tcb.State")?;
        if dr7 == 0 || state == 4 {
            return Ok(None);
        }
        let owner = self.thread_owner(thread)?;
        let mut addresses = [0; 4];
        for (i, field) in ["Dr0", "Dr1", "Dr2", "Dr3"].into_iter().enumerate() {
            *addresses.at_mut(i)? = self.number(trap, "_KTRAP_FRAME", field)?;
        }
        if addresses.iter().all(|address| *address == 0) {
            return Ok(None);
        }
        let tid = self.number(thread, "_ETHREAD", "Cid.UniqueThread")?;
        ensure!(tid <= u32::MAX as u64, "线程 TID 越界");
        Ok(Some(DebugThread {
            owner,
            tid,
            state,
            dr7,
            addresses,
        }))
    }

    pub(super) fn debug_registers(
        &self,
        resources: Option<(&std::path::Path, bool)>,
        job: &Job,
    ) -> Result<Results> {
        self.debug_registers_bounded(resources, job, MAX_OBJECTS, 128 * 1024 * 1024)
    }

    fn debug_registers_bounded(
        &self,
        resources: Option<(&std::path::Path, bool)>,
        job: &Job,
        max_threads: usize,
        max_bytes: usize,
    ) -> Result<Results> {
        job.check()?;
        ensure!(
            self.vm.paging()?.arch != Architecture::Arm64,
            "DebugRegisters 尚未验证 ARM64 布局"
        );
        let mut result = self.result(Plugin::WinDebugRegisters);
        let (processes, diagnostics) = self.processes_partial(job)?;
        if !diagnostics.is_empty() {
            result.complete = false;
            result.diagnostics.extend(diagnostics);
        }
        let offset = self.vm.isf.offset("_ETHREAD", "ThreadListEntry")?;
        let mut owners = BTreeMap::new();
        let mut examined = 0usize;
        let mut active = 0usize;
        let mut unmapped = 0usize;
        let mut vad_bytes = 0usize;
        let mut output_bytes = 0usize;
        'processes: for process in processes {
            job.check()?;
            let (threads, diagnostics) = match self.list_partial(
                self.field(process.address, "_EPROCESS", "ThreadListHead")?,
                offset,
                job,
            ) {
                Ok(value) => value,
                Err(error) => {
                    job.check()?;
                    Self::issue(&mut result, format!("PID {} threads", process.pid), error);
                    continue;
                }
            };
            for diagnostic in diagnostics {
                Self::issue(
                    &mut result,
                    format!("PID {} threads", process.pid),
                    diagnostic,
                );
            }
            for thread in threads {
                job.check()?;
                if examined >= max_threads {
                    Self::issue(
                        &mut result,
                        "DebugRegisters",
                        "线程遍历超过上限，保留已读取记录",
                    );
                    break 'processes;
                }
                examined += 1;
                let read = (|| -> Result<Option<Vec<String>>> {
                    let Some(debug) = self.debug_thread(thread)? else {
                        return Ok(None);
                    };
                    active += 1;
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        owners.entry(debug.owner)
                    {
                        let owner = self.process(debug.owner)?;
                        let vads = self.vads_partial_order(&owner, job, Some(&mut result), true)?;
                        let vads: Vec<_> =
                            vads.into_iter().filter(|v| v.path.contains('\\')).collect();
                        let bytes = vads
                            .iter()
                            .try_fold(0usize, |total, v| {
                                total.checked_add(std::mem::size_of::<memory::Vad>() + v.path.len())
                            })
                            .context("VAD 缓存大小溢出")?;
                        ensure!(
                            bytes <= max_bytes.saturating_sub(vad_bytes),
                            "VAD 缓存超过上限"
                        );
                        vad_bytes += bytes;
                        entry.insert((owner, vads));
                    }
                    let (owner, vads) = owners.at(&debug.owner)?;
                    if vads.is_empty() {
                        return Ok(None);
                    }
                    let files = debug
                        .addresses
                        .map(|address| file_for_address(vads, address));
                    if files.iter().all(Option::is_none) {
                        unmapped += 1;
                        return Ok(None);
                    }
                    let mut row = vec![
                        owner.name.clone(),
                        owner.pid.to_string(),
                        debug.tid.to_string(),
                        debug.state.to_string(),
                        debug.dr7.to_string(),
                    ];
                    for (address, file) in debug.addresses.into_iter().zip(files) {
                        row.extend([
                            hex(address),
                            file.unwrap_or_default().to_owned(),
                            String::new(),
                        ]);
                    }
                    Ok(Some(row))
                })();
                match read {
                    Ok(Some(row)) => {
                        let bytes: usize = row.iter().map(|s| s.len()).sum();
                        if bytes > max_bytes.saturating_sub(output_bytes) {
                            Self::issue(
                                &mut result,
                                "DebugRegisters",
                                "输出文本超过上限，保留已读取记录",
                            );
                            break 'processes;
                        }
                        output_bytes += bytes;
                        result.rows.push(row);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        job.check()?;
                        Self::issue(&mut result, format!("thread {thread:#x}"), error);
                    }
                }
            }
        }
        job.check()?;
        let symbol_queries = self.thread_address_symbols(
            &mut result,
            &[(6, 7, 5), (9, 10, 8), (12, 13, 11), (15, 16, 14)],
            resources,
            job,
        )?;
        *result.kernel_identity.key_mut("debug_registers")? = serde_json::json!({"examined":examined,"active_debug_threads":active,"no_file_mapping":unmapped,"owner_vad_views":owners.len(),"symbol_queries":symbol_queries,"vad_cache_bytes":vad_bytes,"output_text_bytes":output_bytes,"max_threads":max_threads,"max_vad_bytes":max_bytes});
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, image, put, thread_exports_fixture};
    use super::*;
    use serde_json::json;
    use std::sync::atomic::Ordering;

    fn fixture() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = thread_exports_fixture("\\Windows\\fixture.dll");
        let ptr = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        isf.data["user_types"]["_KTHREAD"]["size"] = json!(32);
        isf.data["user_types"]["_KTHREAD"]["fields"]["TrapFrame"] = ptr(24);
        isf.data["user_types"]["_KTRAP_FRAME"] = json!({"size":40,"fields":{"Dr7":ptr(0),"Dr0":ptr(8),"Dr1":ptr(16),"Dr2":ptr(24),"Dr3":ptr(32)}});
        for (thread, frame) in [(0xb000, 0x10000), (0xb100, 0x10100)] {
            put(&mut b, thread + 56, K + (frame as u64 - 0x8000));
            for (offset, value) in [
                (0, 0x401),
                (8, 0x10500),
                (16, 0),
                (24, 0x10500),
                (32, 0x11000),
            ] {
                put(&mut b, frame + offset, value);
            }
        }
        (b, isf)
    }

    fn analyze(b: &[u8], isf: &Isf) -> Results {
        let img = image(b);
        Windows {
            vm: Memory::new(&img, 0x1000, isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(isf).unwrap(),
        }
        .debug_registers(None, &Job::default())
        .unwrap()
    }

    #[test]
    fn live_debug_registers_use_file_vads_exact_symbols_and_owner_pid() {
        let (mut b, isf) = fixture();
        // The owner EPROCESS supplies PID; reference does not use Cid.UniqueProcess.
        put(&mut b, 0xb010, 777);
        let r = analyze(&b, &isf);
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(
            r.rows[0],
            vec![
                "child",
                "8",
                "99",
                "5",
                "1025",
                "0x0000000000010500",
                "\\Windows\\fixture.dll",
                "Entry",
                "0x0000000000000000",
                "",
                "",
                "0x0000000000010500",
                "\\Windows\\fixture.dll",
                "Entry",
                "0x0000000000011000",
                "",
                ""
            ]
        );
        assert_eq!(r.kernel_identity["debug_registers"]["symbol_queries"], 1);
    }

    #[test]
    fn a_file_mapping_without_an_exact_symbol_keeps_the_thread_and_no_nearest_guess() {
        let (mut b, isf) = fixture();
        put(&mut b, 0x10018, 0x10800);
        let r = analyze(&b, &isf);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.rows[0][7], "Entry");
        assert_eq!(r.rows[0][12], "\\Windows\\fixture.dll");
        assert!(r.rows[0][13].is_empty());
        assert!(!r.complete);
        assert!(r.diagnostics.iter().any(|d| d.contains("PDB")));
    }

    #[test]
    fn inactive_terminated_zero_and_unmapped_threads_do_not_report() {
        for case in 0..4 {
            let (mut b, isf) = fixture();
            // Leave only the first thread eligible for examination.
            put(&mut b, 0x10100, 0);
            match case {
                0 => put(&mut b, 0x10000, 0),
                1 => put(&mut b, 0xb028, 4),
                2 => {
                    for offset in [8, 16, 24, 32] {
                        put(&mut b, 0x10000 + offset, 0);
                    }
                }
                _ => {
                    for offset in [8, 16, 24, 32] {
                        put(&mut b, 0x10000 + offset, 0x11000);
                    }
                }
            }
            let r = analyze(&b, &isf);
            assert!(r.complete, "{:?}", r.diagnostics);
            assert!(r.rows.is_empty());
            assert_eq!(r.kernel_identity["debug_registers"]["symbol_queries"], 0);
        }
    }

    #[test]
    fn legacy_owner_precedes_tcb_and_missing_trap_data_is_partial() {
        let (mut b, mut isf) = fixture();
        isf.data["user_types"]["_ETHREAD"]["fields"]["ThreadsProcess"] =
            json!({"offset":72,"type":{"kind":"pointer"}});
        for at in [0xb000, 0xb100] {
            put(&mut b, at + 48, 1);
            put(&mut b, at + 72, K + 0x2000);
        }
        let r = analyze(&b, &isf);
        assert_eq!(r.rows.len(), 2);
        assert!(r.complete, "{:?}", r.diagnostics);
        put(&mut b, 0xb038, 0);
        let r = analyze(&b, &isf);
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
        assert!(r.diagnostics.iter().any(|d| d.contains("TrapFrame")));
    }

    #[test]
    fn x86_trap_registers_use_four_byte_symbol_fields() {
        let (mut b, mut isf) = fixture();
        isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
        isf.data["base_types"]["pointer"]["size"] = json!(4);
        // Two-level Intel32 kernel mapping; adjacent bytes must not leak into Dr values.
        b[0x1000..0x3000].fill(0);
        b[0x1800..0x1804].copy_from_slice(&0x2003u32.to_le_bytes());
        for i in 0..32 {
            b[0x2000 + i * 4..0x2004 + i * 4]
                .copy_from_slice(&(0x8003 + i as u32 * 4096).to_le_bytes());
        }
        let k = 0x80000000u64;
        put(&mut b, 0xb030, k + 0x2000);
        put(&mut b, 0xb038, k + 0x8000);
        for at in [0x10000, 0x10008, 0x10010, 0x10018, 0x10020] {
            b[at + 4..at + 8].fill(0xff);
        }
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: k,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let t = engine.debug_thread(k + 0x3000).unwrap().unwrap();
        assert_eq!(t.owner, k + 0x2000);
        assert_eq!(t.dr7, 0x401);
        assert_eq!(t.addresses, [0x10500, 0, 0x10500, 0x11000]);
    }

    #[test]
    fn missing_register_field_and_arm64_fail_with_explicit_coverage() {
        let (b, mut isf) = fixture();
        isf.data["user_types"]["_KTRAP_FRAME"]["fields"]
            .as_object_mut()
            .unwrap()
            .remove("Dr2");
        let r = analyze(&b, &isf);
        assert!(r.rows.is_empty());
        assert!(!r.complete);
        assert!(r.diagnostics.iter().any(|d| d.contains("Dr2")));
        isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0xaa64);
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert!(
            engine
                .debug_registers(None, &Job::default())
                .unwrap_err()
                .to_string()
                .contains("ARM64")
        );
    }

    #[test]
    fn debug_register_limits_and_cancellation_preserve_honest_coverage() {
        let (b, isf) = fixture();
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = engine
            .debug_registers_bounded(None, &Job::default(), 1, 128 * 1024 * 1024)
            .unwrap();
        assert_eq!(r.rows.len(), 1);
        assert!(!r.complete);
        let r = engine
            .debug_registers_bounded(None, &Job::default(), 100, 0)
            .unwrap();
        assert!(r.rows.is_empty());
        assert!(!r.complete);
        let job = Job::default();
        job.cancel.store(true, Ordering::Relaxed);
        assert!(
            engine
                .debug_registers(None, &job)
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
    }
}
