//! Suspended live threads, with file-backed VAD and exact module-symbol attribution.
use super::*;
use crate::analysis::{PEQuery, PESource};
use std::collections::BTreeMap;

struct SuspendedThread {
    owner: u64,
    pid: u64,
    tid: u64,
    start: u64,
    win32_start: u64,
}

fn file_for_address(vads: &[memory::Vad], address: u64) -> Option<&str> {
    (address != 0).then_some(())?;
    vads.iter()
        .find(|v| v.start <= address && address < v.end && v.path.contains('\\'))
        .map(|v| v.path.as_str())
}

impl Windows<'_> {
    fn suspended_thread(&self, thread: u64) -> Result<Option<SuspendedThread>> {
        if self.number(thread, "_ETHREAD", "Tcb.SuspendCount")? == 0
            || self.number(thread, "_ETHREAD", "Tcb.State")? == 4
        {
            return Ok(None);
        }
        let owner_field = if self.vm.isf.has_field("_ETHREAD", "ThreadsProcess") {
            "ThreadsProcess"
        } else {
            "Tcb.Process"
        };
        let owner = self.number(thread, "_ETHREAD", owner_field)?;
        ensure!(self.vm.kernel(owner), "线程归属进程地址无效");
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

    fn suspended_symbols(
        &self,
        result: &mut Results,
        resources: Option<(&std::path::Path, bool)>,
        job: &Job,
    ) -> Result<usize> {
        let mut queries: BTreeMap<String, std::collections::BTreeSet<u64>> = BTreeMap::new();
        for row in &result.rows {
            job.check()?;
            for (file, address) in [(3, 5), (6, 8)] {
                if !row[file].is_empty() {
                    let module = row[file].rsplit('\\').next().unwrap().to_lowercase();
                    let address = u64::from_str_radix(row[address].trim_start_matches("0x"), 16)?;
                    queries.entry(module).or_default().insert(address);
                }
            }
        }
        let count = queries.values().map(|a| a.len()).sum();
        let mut symbols = BTreeMap::new();
        for (module, addresses) in queries {
            let addresses: Vec<_> = addresses.into_iter().collect();
            for chunk in addresses.chunks(4096) {
                job.check()?;
                let query = Options {
                    pe: PEQuery {
                        source: Some(PESource::Processes),
                        module: Some(module.clone()),
                        names: Vec::new(),
                        addresses: chunk.to_vec(),
                    },
                    ..Default::default()
                };
                match self.pe_symbols(&query, resources, job) {
                    Ok(found) => {
                        if !found.complete {
                            result.complete = false;
                            result.diagnostics.extend(found.diagnostics);
                        }
                        for row in found.rows {
                            let address = u64::from_str_radix(row[2].trim_start_matches("0x"), 16)?;
                            symbols
                                .entry((module.clone(), address))
                                .or_insert(row[1].clone());
                        }
                    }
                    Err(error) => {
                        job.check()?;
                        Self::issue(result, format!("{module} thread symbols"), error);
                    }
                }
            }
        }
        for row in &mut result.rows {
            job.check()?;
            for (file, symbol, address) in [(3, 4, 5), (6, 7, 8)] {
                let module = row[file].rsplit('\\').next().unwrap().to_lowercase();
                let address = u64::from_str_radix(row[address].trim_start_matches("0x"), 16)?;
                row[symbol] = symbols.get(&(module, address)).cloned().unwrap_or_default();
            }
        }
        Ok(count)
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
                    let (owner, vads) = &owner_vads[&t.owner];
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
        let symbol_queries = self.suspended_symbols(&mut result, resources, job)?;
        result.kernel_identity["suspended_threads"] = serde_json::json!({"examined":examined,"suspended_live":suspended,"excluded_workfolders":excluded,"owner_vad_views":owner_vads.len(),"symbol_queries":symbol_queries,"vad_cache_bytes":vad_bytes,"output_text_bytes":output_bytes,"max_threads":max_threads,"max_vad_bytes":max_vad_bytes});
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    use std::sync::atomic::Ordering;
    fn suspended_fixture(path: &str) -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        let ptr = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        let number = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u64"}});
        isf.data["user_types"]["_EPROCESS"]["fields"]["ThreadListHead"] =
            json!({"offset":144,"type":{"kind":"struct","name":"_LIST_ENTRY"}});
        isf.data["user_types"]["_ETHREAD"] = json!({"size":80,"fields":{
            "ThreadListEntry":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}},
            "Cid":{"offset":16,"type":{"kind":"struct","name":"_CLIENT_ID"}},
            "Tcb":{"offset":32,"type":{"kind":"struct","name":"_KTHREAD"}},
            "StartAddress":ptr(56),"Win32StartAddress":ptr(64)}});
        isf.data["user_types"]["_CLIENT_ID"] =
            json!({"size":16,"fields":{"UniqueProcess":ptr(0),"UniqueThread":ptr(8)}});
        isf.data["user_types"]["_KTHREAD"] = json!({"size":24,"fields":{"SuspendCount":number(0),"State":number(8),"Process":ptr(16)}});
        isf.data["user_types"]["_EPROCESS"]["fields"]["VadRoot"] =
            json!({"offset":128,"type":{"kind":"struct","name":"_RTL_AVL_TREE"}});
        isf.data["user_types"]["_RTL_AVL_TREE"] = json!({"size":8,"fields":{"Root":ptr(0)}});
        isf.data["user_types"]["_RTL_BALANCED_NODE"] =
            json!({"size":24,"fields":{"Left":ptr(0),"Right":ptr(8)}});
        isf.data["user_types"]["_MMVAD_SHORT"] = json!({"size":64,"fields":{
            "VadNode":{"offset":0,"type":{"kind":"struct","name":"_RTL_BALANCED_NODE"}},
            "StartingVpn":number(24),"EndingVpn":number(32),"u":{"offset":40,"type":{"kind":"struct","name":"_MMVAD_FLAGS"}}}});
        isf.data["user_types"]["_MMVAD_FLAGS"] = json!({"size":8,"fields":{
            "Protection":{"offset":0,"type":{"kind":"bitfield","bit_position":0,"bit_length":5,"type":{"kind":"base","name":"u64"}}},
            "PrivateMemory":{"offset":0,"type":{"kind":"bitfield","bit_position":5,"bit_length":1,"type":{"kind":"base","name":"u64"}}}}});
        isf.data["user_types"]["_MMVAD"] = json!({"size":64,"fields":{"ControlArea":ptr(48)}});
        isf.data["user_types"]["_CONTROL_AREA"] = json!({"size":8,"fields":{"FilePointer":ptr(0)}});
        isf.data["user_types"]["_FILE_OBJECT"] = json!({"size":16,"fields":{"FileName":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}});
        // Empty System thread list; two live suspended child threads.
        put(&mut b, 0x9090, K + 0x1090);
        put(&mut b, 0x9098, K + 0x1090);
        put(&mut b, 0xa090, K + 0x3000);
        put(&mut b, 0xa098, K + 0x3100);
        for (at, previous, next, tid) in [
            (0xb000, K + 0x2090, K + 0x3100, 99),
            (0xb100, K + 0x3000, K + 0x2090, 100),
        ] {
            for (offset, value) in [
                (0, next),
                (8, previous),
                (16, 8),
                (24, tid),
                (32, 1),
                (40, 5),
                (48, K + 0x2000),
                (56, 0x1234),
                (64, 0),
            ] {
                put(&mut b, at + offset, value);
            }
        }
        put(&mut b, 0xa080, K + 0x4000);
        for (at, value) in [
            (0xc018, 1),
            (0xc020, 1),
            (0xc028, 4),
            (0xc030, K + 0x5000),
            (0xd000, K + 0x6000),
        ] {
            put(&mut b, at, value);
        }
        let text: Vec<_> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        b[0xe000..0xe002].copy_from_slice(&(text.len() as u16).to_le_bytes());
        b[0xe002..0xe004].copy_from_slice(&(text.len() as u16).to_le_bytes());
        put(&mut b, 0xe008, K + 0x7000);
        b[0xf000..0xf000 + text.len()].copy_from_slice(&text);
        (b, isf)
    }

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
        let (mut b, isf) = suspended_fixture("\\Windows\\fixture.dll");
        // Map a user-mode PE independently of the kernel/process objects.
        put(&mut b, 0x1000, 0x2003);
        put(&mut b, 0xc018, 16);
        put(&mut b, 0xc020, 16);
        for at in [0xb000, 0xb100] {
            put(&mut b, at + 56, 0x10500);
            put(&mut b, at + 64, 0x10500);
        }
        let pe = &mut b[0x18000..0x19000];
        pe[..2].copy_from_slice(b"MZ");
        pe[60..64].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        pe[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        for (at, value) in [
            (0xd0, 0x1000u32),
            (0x104, 16),
            (0x108, 0x300),
            (0x10c, 0x40),
            (0x314, 1),
            (0x318, 1),
            (0x31c, 0x400),
            (0x320, 0x410),
            (0x324, 0x420),
            (0x400, 0x500),
            (0x410, 0x440),
        ] {
            pe[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        pe[0x440..0x446].copy_from_slice(b"Entry\0");
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
