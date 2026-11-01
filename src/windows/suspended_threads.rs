//! Suspended live threads, with file-backed VAD and exact module-symbol attribution.
use super::thread_symbols::file_for_address;
use super::*;
use crate::bytes::{JsonKey as _, MapAt as _};
use std::collections::BTreeMap;

struct SuspendedThread {
    owner: u64,
    pid: u64,
    tid: u64,
    start: u64,
    win32_start: u64,
}

impl Windows<'_> {
    fn suspended_thread(&self, thread: u64) -> Result<Option<SuspendedThread>> {
        if self.number(thread, "_ETHREAD", "Tcb.SuspendCount")? == 0
            || self.number(thread, "_ETHREAD", "Tcb.State")? == 4
        {
            return Ok(None);
        }
        let owner = self.thread_owner(thread)?;
        let pid = self.number(thread, "_ETHREAD", "Cid.UniqueProcess")?;
        let tid = self.number(thread, "_ETHREAD", "Cid.UniqueThread")?;
        ensure!(
            pid <= u32::MAX as u64 && tid <= u32::MAX as u64,
            "线程 CID 越界"
        );
        Ok(Some(SuspendedThread {
            owner,
            pid,
            tid,
            start: self.number(thread, "_ETHREAD", "StartAddress")?,
            win32_start: self.number(thread, "_ETHREAD", "Win32StartAddress")?,
        }))
    }

    pub(super) fn suspended_threads(
        &self,
        resources: Option<(&std::path::Path, bool)>,
        job: &Job,
    ) -> Result<Results> {
        self.suspended_threads_bounded(resources, job, MAX_OBJECTS, 128 * 1024 * 1024)
    }

    fn suspended_threads_bounded(
        &self,
        resources: Option<(&std::path::Path, bool)>,
        job: &Job,
        max_threads: usize,
        max_vad_bytes: usize,
    ) -> Result<Results> {
        job.check()?;
        ensure!(
            self.vm.paging()?.arch != Architecture::Arm64,
            "SuspendedThreads 尚未验证 ARM64 布局"
        );
        let mut result = self.result(Plugin::WinSuspendedThreads);
        let (processes, diagnostics) = self.processes_partial(job)?;
        if !diagnostics.is_empty() {
            result.complete = false;
            result.diagnostics.extend(diagnostics);
        }
        let offset = self.vm.isf.offset("_ETHREAD", "ThreadListEntry")?;
        let mut owner_vads = BTreeMap::new();
        let mut examined = 0usize;
        let mut suspended = 0usize;
        let mut excluded = 0usize;
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
                        "SuspendedThreads",
                        "线程遍历超过上限，保留已读取记录",
                    );
                    break 'processes;
                }
                examined += 1;
                let read = (|| -> Result<Option<Vec<String>>> {
                    let Some(t) = self.suspended_thread(thread)? else {
                        return Ok(None);
                    };
                    suspended += 1;
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        owner_vads.entry(t.owner)
                    {
                        let owner = self.process(t.owner)?;
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
                            bytes <= max_vad_bytes.saturating_sub(vad_bytes),
                            "VAD 缓存超过上限"
                        );
                        vad_bytes += bytes;
                        entry.insert((owner, vads));
                    }
                    let (owner, vads) = owner_vads.at(&t.owner)?;
                    ensure!(owner.pid == t.pid, "线程 CID 与归属进程 PID 不一致");
                    if vads.is_empty() {
                        return Ok(None);
                    }
                    let start_file = file_for_address(vads, t.start);
                    let win32_file = file_for_address(vads, t.win32_start);
                    if [start_file, win32_file]
                        .into_iter()
                        .flatten()
                        .any(|path| path.ends_with("\\WorkFoldersShell.dll"))
                    {
                        excluded += 1;
                        return Ok(None);
                    }
                    Ok(Some(vec![
                        owner.name.clone(),
                        t.pid.to_string(),
                        t.tid.to_string(),
                        start_file.unwrap_or_default().to_owned(),
                        String::new(),
                        hex(t.start),
                        win32_file.unwrap_or_default().to_owned(),
                        String::new(),
                        hex(t.win32_start),
                    ]))
                })();
                match read {
                    Ok(Some(row)) => {
                        let bytes: usize = row.iter().map(|s| s.len()).sum();
                        if bytes > max_vad_bytes.saturating_sub(output_bytes) {
                            Self::issue(
                                &mut result,
                                "SuspendedThreads",
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
        let symbol_queries =
            self.thread_address_symbols(&mut result, &[(3, 4, 5), (6, 7, 8)], resources, job)?;
        *result.kernel_identity.key_mut("suspended_threads")? = serde_json::json!({"examined":examined,"suspended_live":suspended,"excluded_workfolders":excluded,"owner_vad_views":owner_vads.len(),"symbol_queries":symbol_queries,"vad_cache_bytes":vad_bytes,"output_text_bytes":output_bytes,"max_threads":max_threads,"max_vad_bytes":max_vad_bytes});
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put, suspended_fixture, thread_exports_fixture};
    use super::*;
    use serde_json::json;
    use std::sync::atomic::Ordering;
    #[test]
    fn suspended_output_retains_rows_and_reports_symbol_and_resource_failures() {
        let (b, isf) = suspended_fixture("\\Windows\\fixture.dll");
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = engine.suspended_threads(None, &Job::default()).unwrap();
        assert_eq!(r.rows.len(), 2, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows[0],
            vec![
                "child",
                "8",
                "99",
                "\\Windows\\fixture.dll",
                "",
                "0x0000000000001234",
                "",
                "",
                "0x0000000000000000"
            ]
        );
        assert_eq!(r.kernel_identity["suspended_threads"]["symbol_queries"], 1);
        // Fixture has no readable PE module: keep factual thread/path data, no symbol guesses.
        assert!(!r.complete);
        assert!(!r.diagnostics.is_empty());
        let limited = engine
            .suspended_threads_bounded(None, &Job::default(), 1, 128 * 1024 * 1024)
            .unwrap();
        assert_eq!(limited.rows.len(), 1);
        assert!(
            limited
                .diagnostics
                .iter()
                .any(|d| d.contains("线程遍历超过上限"))
        );
        let limited = engine
            .suspended_threads_bounded(None, &Job::default(), 100, 0)
            .unwrap();
        assert!(limited.rows.is_empty());
        assert!(!limited.complete);
        assert!(
            limited
                .diagnostics
                .iter()
                .any(|d| d.contains("VAD 缓存超过上限"))
        );
    }

    #[test]
    fn suspended_output_resolves_exact_exports_for_both_entry_points() {
        let (b, isf) = thread_exports_fixture("\\Windows\\fixture.dll");
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = engine.suspended_threads(None, &Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(
            r.rows[0],
            vec![
                "child",
                "8",
                "99",
                "\\Windows\\fixture.dll",
                "Entry",
                "0x0000000000010500",
                "\\Windows\\fixture.dll",
                "Entry",
                "0x0000000000010500"
            ]
        );
        assert_eq!(r.kernel_identity["suspended_threads"]["symbol_queries"], 1);
    }

    #[test]
    fn workfolders_filter_and_missing_suspend_fields_are_explicit() {
        let (b, mut isf) = suspended_fixture("\\Windows\\WorkFoldersShell.dll");
        let img = image(&b);
        let run = |isf: &Isf, job: &Job| {
            Windows {
                vm: Memory::new(&img, 0x1000, isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(isf).unwrap(),
            }
            .suspended_threads(None, job)
        };
        let r = run(&isf, &Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert!(r.rows.is_empty());
        assert_eq!(
            r.kernel_identity["suspended_threads"]["excluded_workfolders"],
            2
        );
        isf.data["user_types"]["_KTHREAD"]["fields"]
            .as_object_mut()
            .unwrap()
            .remove("SuspendCount");
        let isf = Isf::parse(
            &serde_json::to_vec(&isf.data).unwrap(),
            "missing-suspend.json".into(),
        )
        .unwrap();
        let r = run(&isf, &Job::default()).unwrap();
        assert!(!r.complete);
        assert!(r.rows.is_empty());
        assert!(r.diagnostics.iter().any(|d| d.contains("SuspendCount")));
        let job = Job::default();
        job.cancel.store(true, Ordering::Relaxed);
        assert!(
            run(&isf, &job)
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
    }

    #[test]
    fn suspended_thread_reads_live_state_owner_and_both_entry_points() {
        let (mut bytes, mut isf) = fixture();
        let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        isf.data["user_types"]["_ETHREAD"] = json!({"size":64,"fields":{
            "Tcb":{"offset":0,"type":{"kind":"struct","name":"_KTHREAD"}},
            "Cid":{"offset":24,"type":{"kind":"struct","name":"_CLIENT_ID"}},
            "StartAddress":pointer(40),"Win32StartAddress":pointer(48)}});
        isf.data["user_types"]["_KTHREAD"] = json!({"size":24,"fields":{"SuspendCount":pointer(0),"State":pointer(8),"Process":pointer(16)}});
        isf.data["user_types"]["_CLIENT_ID"] =
            json!({"size":16,"fields":{"UniqueProcess":pointer(0),"UniqueThread":pointer(8)}});
        for (offset, value) in [
            (0, 1),
            (8, 5),
            (16, K + 0x2000),
            (24, 8),
            (32, 99),
            (40, 0x1234),
            (48, 0x5678),
        ] {
            put(&mut bytes, 0xb000 + offset, value);
        }
        for (suspend, state, expected) in [(1, 5, true), (0, 5, false), (1, 4, false)] {
            put(&mut bytes, 0xb000, suspend);
            put(&mut bytes, 0xb008, state);
            let img = image(&bytes);
            let engine = Windows {
                vm: Memory::new(&img, 0x1000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let t = engine.suspended_thread(K + 0x3000).unwrap();
            assert_eq!(t.is_some(), expected);
            if let Some(t) = t {
                assert_eq!(
                    (t.owner, t.pid, t.tid, t.start, t.win32_start),
                    (K + 0x2000, 8, 99, 0x1234, 0x5678)
                );
            }
        }
        // Legacy ETHREAD ownership takes precedence over Tcb.Process.
        put(&mut bytes, 0xb000, 1);
        put(&mut bytes, 0xb008, 5);
        put(&mut bytes, 0xb038, K + 0x1000);
        isf.data["user_types"]["_ETHREAD"]["fields"]["ThreadsProcess"] = pointer(56);
        let img = image(&bytes);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert_eq!(
            engine.suspended_thread(K + 0x3000).unwrap().unwrap().owner,
            K + 0x1000
        );
    }
    #[test]
    fn address_attribution_is_half_open_and_requires_a_file_path() {
        let vads = [memory::Vad {
            address: 1,
            start: 0x1000,
            end: 0x2000,
            protection: 0,
            private: false,
            path: "\\Windows\\a.dll".into(),
        }];
        assert!(file_for_address(&vads, 0).is_none());
        assert!(file_for_address(&vads, 0x2000).is_none());
        assert_eq!(file_for_address(&vads, 0x1000), Some("\\Windows\\a.dll"));
        assert_eq!(file_for_address(&vads, 0x1fff), Some("\\Windows\\a.dll"));
    }
}
