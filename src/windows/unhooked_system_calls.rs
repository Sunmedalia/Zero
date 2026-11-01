//! Compare the pinned ntdll syscall byte windows across process address spaces.
use super::*;
use crate::analysis::{PEQuery, PESource};

const FUNCTIONS: &[&str] = &[
    "NtCreateThread",
    "NtProtectVirtualMemory",
    "NtReadVirtualMemory",
    "NtOpenProcess",
    "NtWriteFile",
    "NtQueryVirtualMemory",
    "NtAllocateVirtualMemory",
    "NtWorkerFactoryWorkerReady",
    "NtAcceptConnectPort",
    "NtAddDriverEntry",
    "NtAdjustPrivilegesToken",
    "NtAlpcCreatePort",
    "NtClose",
    "NtCreateFile",
    "NtCreateMutant",
    "NtOpenFile",
    "NtOpenIoCompletion",
    "NtOpenJobObject",
    "NtOpenKey",
    "NtOpenKeyEx",
    "NtOpenThread",
    "NtOpenThreadToken",
    "NtOpenThreadTokenEx",
    "NtWriteVirtualMemory",
    "NtTraceEvent",
    "NtTranslateFilePath",
    "NtUmsThreadYield",
    "NtUnloadDriver",
    "NtUnloadKey",
    "NtUnloadKey2",
    "NtUnloadKeyEx",
    "NtCreateKey",
    "NtCreateSection",
    "NtDeleteKey",
    "NtDeleteValueKey",
    "NtDuplicateObject",
    "NtQueryValueKey",
    "NtReplaceKey",
    "NtRequestWaitReplyPort",
    "NtRestoreKey",
    "NtSetContextThread",
    "NtSetSecurityObject",
    "NtSetValueKey",
    "NtSystemDebugControl",
    "NtTerminateProcess",
];
#[derive(Default)]
struct Groups {
    /// The reference dict retains discovery order, including equal-size groups.
    lookup: BTreeMap<[u8; 32], usize>,
    owners: Vec<Vec<usize>>,
}
impl Groups {
    fn insert(&mut self, code: [u8; 32], process: usize) {
        let index = *self.lookup.entry(code).or_insert_with(|| {
            self.owners.push(Vec::new());
            self.owners.len() - 1
        });
        if let Some(owners) = self.owners.get_mut(index) {
            owners.push(process);
        }
    }
    fn row(&self, name: &str, owner: impl Fn(usize) -> String) -> Option<Vec<String>> {
        let first = self.owners.first()?;
        if self.owners.len() == 1 {
            return Some(vec![name.into(), String::new(), first.len().to_string()]);
        }
        // Pinned v2.28.2 compares only the first two implementations, not all groups.
        // A tie chooses the second group as majority and reports the first as distinct.
        let majority = usize::from(first.len() <= self.owners.get(1)?.len());
        let minority = 1 - majority;
        Some(vec![
            name.into(),
            self.owners
                .get(minority)?
                .iter()
                .map(|p| owner(*p))
                .collect::<Vec<_>>()
                .join(", "),
            self.owners.get(majority)?.len().to_string(),
        ])
    }
}
impl Windows<'_> {
    pub(super) fn unhooked_system_calls(
        &self,
        resources: Option<(&std::path::Path, bool)>,
        job: &Job,
    ) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "UnhookedSystemCalls 仅支持 Intel x86/x64"
        );
        let options = Options {
            pe: PEQuery {
                source: Some(PESource::Processes),
                module: Some("ntdll.dll".into()),
                names: FUNCTIONS.iter().map(|s| (*s).into()).collect(),
                addresses: Vec::new(),
            },
            ..Options::default()
        };
        let symbols = self.pe_symbols_captured(&options, resources, job)?;
        let mut result = self.result(Plugin::WinUnhookedSystemCalls);
        result.complete = symbols.complete;
        result.diagnostics = symbols.diagnostics;
        *result.kernel_identity.key_mut("pe_symbols")? =
            symbols.kernel_identity.key("pe_symbols").clone();
        let mut functions = Vec::new();
        for row in symbols.rows {
            ensure!(row.len() == 3, "PESymbols 输出结构无效");
            functions.push((
                row.at(1)?.clone(),
                u64::from_str_radix(row.at(2)?.trim_start_matches("0x"), 16)?,
            ));
        }
        let (processes, diagnostics) = self.processes_partial(job)?;
        if !diagnostics.is_empty() {
            result.complete = false;
            result.diagnostics.extend(diagnostics);
        }
        let mut groups: Vec<_> = functions.iter().map(|_| Groups::default()).collect();
        let mut reads = 0usize;
        let mut missing = 0usize;
        let mut reached_limit = false;
        'processes: for (index, process) in processes.iter().enumerate() {
            job.check()?;
            let vm = match self.process_memory(process) {
                Ok(vm) => vm,
                Err(e) => {
                    Self::issue(&mut result, format!("PID {} 地址空间", process.pid), e);
                    continue;
                }
            };
            for (group, (_, address)) in groups.iter_mut().zip(&functions) {
                job.check()?;
                if reads == MAX_OBJECTS {
                    Self::issue(
                        &mut result,
                        "syscall implementations",
                        "实现数量超过资源上限；已保留读取结果",
                    );
                    reached_limit = true;
                    break 'processes;
                }
                let mut bytes = [0; 32];
                if vm.read_captured(*address, &mut bytes).is_ok() {
                    group.insert(bytes, index);
                    reads += 1;
                } else {
                    missing += 1;
                }
            }
        }
        let extra_groups = groups.iter().filter(|g| g.owners.len() > 2).count();
        for ((name, _), group) in functions.iter().zip(&groups) {
            job.check()?;
            if let Some(row) = group.row(name, |i| {
                processes
                    .get(i)
                    .map_or_else(String::new, |p| format!("{}:{}", p.pid, p.name))
            }) {
                result.rows.push(row);
            }
        }
        *result.kernel_identity.key_mut("syscall_implementations")? = serde_json::json!({
            "window_bytes":32,"resolved_functions":functions.len(),"processes":processes.len(),
            "readable_windows":reads,"unreadable_windows":missing,"resource_limit_reached":reached_limit,
            "functions_with_more_than_two_groups":extra_groups,
            "comparison":"pinned reference compares only the first two distinct implementations"
        });
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unchanged_functions_omit_distinct_names_and_keep_process_multiplicity() {
        let mut g = Groups::default();
        assert!(g.row("NtClose", |_| unreachable!()).is_none());
        for i in [3, 4, 3] {
            g.insert([0x90; 32], i);
        }
        assert_eq!(
            g.row("NtClose", |i| format!("{i}:proc")).unwrap(),
            ["NtClose", "", "3"]
        );
    }
    #[test]
    fn majority_minority_ties_and_third_implementations_keep_reference_order() {
        let mut g = Groups::default();
        g.insert([1; 32], 0);
        g.insert([2; 32], 1);
        assert_eq!(
            g.row("NtClose", |i| format!("{i}:proc")).unwrap(),
            ["NtClose", "0:proc", "1"]
        );
        g.insert([1; 32], 2);
        assert_eq!(
            g.row("NtClose", |i| format!("{i}:proc")).unwrap(),
            ["NtClose", "1:proc", "2"]
        );
        for i in 3..9 {
            g.insert([3; 32], i);
        }
        assert_eq!(
            g.row("NtClose", |i| format!("{i}:proc")).unwrap(),
            ["NtClose", "1:proc", "2"]
        );
        g.insert([2; 32], 9);
        g.insert([2; 32], 10);
        g.insert([2; 32], 11);
        assert_eq!(
            g.row("NtClose", |i| format!("{i}:proc")).unwrap(),
            ["NtClose", "0:proc, 2:proc", "4"]
        );
    }
    #[test]
    fn captured_reads_allow_transition_but_do_not_reconstruct_prototypes() {
        use super::super::tests::{K, fixture, image, put};
        let (mut b, isf) = fixture();
        put(&mut b, 0x4000 + 8, 0x9800);
        b[0x9000] = 42;
        let prototype = K + 0x5000;
        put(
            &mut b,
            0x4000 + 16,
            (prototype & 0xffffffffffff) << 16 | 1024,
        );
        put(&mut b, 0xd000, 0xe800);
        b[0xe000] = 19;
        let image = image(&b);
        let vm = Memory::new(&image, 0x1000, &isf, None);
        let mut value = [0];
        vm.read_captured(K + 0x1000, &mut value).unwrap();
        assert_eq!(value, [42]);
        vm.read(K + 0x2000, &mut value).unwrap();
        assert_eq!(value, [19]);
        assert!(vm.read_captured(K + 0x2000, &mut value).is_err());
        assert!(vm.read_captured(u64::MAX, &mut [0; 2]).is_err());
    }
    #[test]
    fn cancelled_collection_stops_before_module_or_process_reads() {
        use super::super::tests::{K, fixture, image};
        let (bytes, isf) = fixture();
        let image = image(&bytes);
        let engine = Windows {
            vm: Memory::new(&image, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let error = engine.unhooked_system_calls(None, &job).unwrap_err();
        assert!(error.to_string().contains("cancelled"), "{error:#}");
    }
    #[test]
    fn every_byte_in_the_32_byte_window_distinguishes_implementations() {
        for at in 0..32 {
            let mut g = Groups::default();
            g.insert([0; 32], 0);
            let mut second = [0; 32];
            second[at] = 1;
            g.insert(second, 1);
            assert_eq!(g.owners.len(), 2);
        }
        assert_eq!(FUNCTIONS.len(), 45);
        assert_eq!(FUNCTIONS.iter().collect::<HashSet<_>>().len(), 45);
    }
}
