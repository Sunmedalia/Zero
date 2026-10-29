//! Shared module intervals and exact per-module PDB aliases for dispatch analysis.
use super::*;

pub(super) struct DispatchModules {
    modules: Vec<KernelModule>,
    symbols: BTreeMap<u64, Vec<String>>,
    kernel_base: u64,
    external: BTreeMap<u64, BTreeMap<u64, Vec<String>>>,
    attempted: HashSet<u64>,
    evidence: Vec<serde_json::Value>,
    symbol_bytes: usize,
    symbol_count: usize,
}
impl DispatchModules {
    pub(super) fn new(
        mut modules: Vec<KernelModule>,
        isf: &Isf,
        kernel_base: u64,
        job: &Job,
    ) -> Result<Self> {
        let mut names = HashSet::<String>::new();
        for module in &mut modules {
            job.check()?;
            if module.name.is_empty() {
                continue;
            }
            let stem = module
                .name
                .rsplit_once('.')
                .map_or(module.name.as_str(), |(stem, _)| stem)
                .to_string();
            let mut count = names
                .iter()
                .filter(|name| {
                    name.strip_prefix(&stem)
                        .is_some_and(|suffix| suffix.bytes().all(|byte| byte.is_ascii_digit()))
                })
                .count();
            let unique = if count == 0 {
                stem.clone()
            } else {
                while names.contains(&format!("{stem}{count}")) {
                    count += 1;
                }
                format!("{stem}{count}")
            };
            names.insert(unique.clone());
            module.name = unique;
        }
        let mut symbols: BTreeMap<u64, Vec<String>> = BTreeMap::new();
        for (name, entry) in isf.data["symbols"].as_object().context("缺少符号映射")? {
            job.check()?;
            if let Some(rva) = entry["address"].as_u64() {
                symbols.entry(rva).or_default().push(name.clone());
            }
        }
        for names in symbols.values_mut() {
            names.sort();
        }
        Ok(Self {
            modules,
            symbols,
            kernel_base,
            external: BTreeMap::new(),
            attempted: HashSet::new(),
            evidence: Vec::new(),
            symbol_bytes: 0,
            symbol_count: 0,
        })
    }
    /// Resolve only modules containing a used dispatch address. Failures are
    /// remembered for this analysis so missing pages/PDBs never cause retry storms.
    pub(super) fn resolve_at(
        &mut self,
        target: u64,
        vm: &Memory<'_>,
        resources: Option<(&std::path::Path, bool)>,
        r: &mut Results,
        job: &Job,
    ) -> Result<()> {
        for module in &self.modules {
            job.check()?;
            if module.base == self.kernel_base
                || module.name.is_empty()
                || target < module.base
                || module
                    .base
                    .checked_add(module.size)
                    .is_none_or(|end| target >= end)
                || !self.attempted.insert(module.base)
            {
                continue;
            }
            let mut evidence =
                serde_json::json!({"base":hex(module.base),"module":module.name,"resolved":false});
            let result = (|| -> Result<BTreeMap<u64, Vec<String>>> {
                let (cache, network) = resources.context("缺少外部模块符号资源上下文")?;
                let mut header = [0; 4096];
                vm.read(module.base, &mut header)?;
                ensure!(
                    u64::from(pe_header(&header)?.0) == module.size,
                    "模块范围与 PE SizeOfImage 不一致"
                );
                let identity = network::pe_identity(vm, module.base)?;
                evidence["pdb"] = serde_json::json!(identity.key());
                let isf = windows_symbols::acquire(&identity, cache, network, job)?;
                ensure!(
                    PdbIdentity::from_isf(&isf)? == identity,
                    "模块 PDB 身份不匹配"
                );
                ensure!(
                    Architecture::from_isf(&isf)? == Architecture::from_isf(vm.isf)?,
                    "模块 PDB 架构冲突"
                );
                evidence["isf_sha256"] = serde_json::json!(isf.digest);
                let mut symbols = BTreeMap::<u64, Vec<String>>::new();
                for (name, entry) in isf.data["symbols"]
                    .as_object()
                    .context("缺少模块符号映射")?
                {
                    job.check()?;
                    if let Some(rva) = entry["address"].as_u64().filter(|rva| *rva < module.size) {
                        ensure!(
                            self.symbol_bytes.saturating_add(name.len()) <= 128 * 1024 * 1024,
                            "外部模块符号文本超限"
                        );
                        ensure!(self.symbol_count < 1_000_000, "外部模块符号数量超限");
                        self.symbol_count += 1;
                        self.symbol_bytes += name.len();
                        symbols.entry(rva).or_default().push(name.clone());
                    }
                }
                for names in symbols.values_mut() {
                    names.sort();
                }
                Ok(symbols)
            })();
            match result {
                Ok(symbols) => {
                    evidence["resolved"] = serde_json::json!(true);
                    self.external.insert(module.base, symbols);
                }
                Err(error) => {
                    job.check()?;
                    evidence["error"] = serde_json::json!(format!("{error:#}"));
                    Windows::issue(r, format!("模块符号 {}", module.name), format!("{error:#}"));
                }
            }
            self.evidence.push(evidence);
        }
        Ok(())
    }
    pub(super) fn evidence(&self) -> serde_json::Value {
        serde_json::json!({"scope":"exact per-module PDB; no cross-module fallback", "modules":self.evidence,
            "match":"exact address; all aliases; half-open module ranges"})
    }
    pub(super) fn at(&self, target: u64) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for module in &self.modules {
            if module.name.is_empty()
                || target < module.base
                || module
                    .base
                    .checked_add(module.size)
                    .is_none_or(|end| target >= end)
            {
                continue;
            }
            let name = &module.name;
            let symbols = if module.base == self.kernel_base {
                Some(&self.symbols)
            } else {
                self.external.get(&module.base)
            };
            if let Some(names) = symbols.and_then(|symbols| symbols.get(&(target - module.base))) {
                out.extend(names.iter().map(|symbol| (name.clone(), symbol.clone())));
            } else {
                out.push((name.clone(), String::new()));
            }
        }
        if out.is_empty() {
            out.push((String::new(), String::new()));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image};
    use super::*;
    use serde_json::json;

    fn external_fixture() -> (Vec<u8>, Isf, tempfile::TempDir) {
        let (mut bytes, mut isf) = fixture();
        bytes[0x8618..0x8625].copy_from_slice(b"testdrv1.pdb\0");
        isf.data["metadata"]["windows"]["pdb"]["database"] = json!("testdrv1.pdb");
        isf.data["symbols"] = json!({"DriverDispatch":{"address":0x800},"DispatchAlias":{"address":0x800},"OutsideImage":{"address":0x8000}});
        let cache = tempfile::tempdir().unwrap();
        let identity = PdbIdentity::from_isf(&isf).unwrap();
        let directory = cache.path().join("symbols/isf/windows");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(format!(
                "{}-{}{:X}.json",
                identity.name, identity.guid, identity.age
            )),
            serde_json::to_vec(&isf.data).unwrap(),
        )
        .unwrap();
        (bytes, isf, cache)
    }
    fn index(isf: &Isf) -> DispatchModules {
        DispatchModules::new(
            vec![KernelModule {
                name: "testdrv1.sys".into(),
                base: K,
                size: 0x8000,
                path: String::new(),
            }],
            isf,
            K + 0x100000,
            &Job::default(),
        )
        .unwrap()
    }
    #[test]
    fn exact_cached_driver_symbols_preserve_aliases_and_never_borrow_kernel_symbols() {
        let (bytes, mut isf, cache) = external_fixture();
        isf.data["symbols"] = json!({"WrongKernelSymbol":{"address":0x800}});
        let image = image(&bytes);
        let vm = Memory::new(&image, 0x1000, &isf, None);
        let mut modules = index(&isf);
        let mut result = Results {
            plugin: "windows.driverirp.DriverIrp".into(),
            columns: vec![],
            rows: vec![],
            complete: true,
            diagnostics: vec![],
            banner: String::new(),
            symbol: String::new(),
            page_table: 0,
            historical: false,
            system: "windows".into(),
            kernel_identity: json!({}),
        };
        modules
            .resolve_at(
                K + 0x800,
                &vm,
                Some((cache.path(), false)),
                &mut result,
                &Job::default(),
            )
            .unwrap();
        assert_eq!(
            modules.at(K + 0x800),
            vec![
                ("testdrv1".into(), "DispatchAlias".into()),
                ("testdrv1".into(), "DriverDispatch".into())
            ]
        );
        assert_eq!(
            modules.at(K + 0x801),
            vec![("testdrv1".into(), String::new())]
        );
        assert_eq!(modules.at(K + 0x8000), vec![(String::new(), String::new())]);
        assert_eq!(modules.evidence()["modules"][0]["resolved"], true);
        assert!(result.diagnostics.is_empty());
        // An already loaded table is stable within this analysis, even if the
        // regenerable cache disappears. The next analysis resolves it afresh.
        std::fs::remove_dir_all(cache.path().join("symbols")).unwrap();
        modules
            .resolve_at(
                K + 0x800,
                &vm,
                Some((cache.path(), false)),
                &mut result,
                &Job::default(),
            )
            .unwrap();
        assert_eq!(modules.evidence()["modules"].as_array().unwrap().len(), 1);
    }
    #[test]
    fn offline_missing_symbols_and_wrong_machine_remain_partial_once() {
        let (bytes, mut isf, cache) = external_fixture();
        isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
        isf.data["base_types"]["pointer"]["size"] = json!(4);
        let directory = cache.path().join("symbols/isf/windows");
        let file = std::fs::read_dir(&directory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        std::fs::write(&file, serde_json::to_vec(&isf.data).unwrap()).unwrap();
        let (_, kernel) = fixture();
        let image = image(&bytes);
        let vm = Memory::new(&image, 0x1000, &kernel, None);
        let mut modules = index(&kernel);
        let mut r = Results {
            plugin: "windows.driverirp.DriverIrp".into(),
            columns: vec![],
            rows: vec![],
            complete: true,
            diagnostics: vec![],
            banner: String::new(),
            symbol: String::new(),
            page_table: 0,
            historical: false,
            system: "windows".into(),
            kernel_identity: json!({}),
        };
        modules
            .resolve_at(
                K + 0x800,
                &vm,
                Some((cache.path(), false)),
                &mut r,
                &Job::default(),
            )
            .unwrap();
        assert!(r.diagnostics.iter().any(|s| s.contains("架构冲突")));
        assert!(!r.complete);
        assert_eq!(
            modules.at(K + 0x800),
            vec![("testdrv1".into(), String::new())]
        );
        modules
            .resolve_at(
                K + 0x801,
                &vm,
                Some((cache.path(), false)),
                &mut r,
                &Job::default(),
            )
            .unwrap();
        assert_eq!(r.diagnostics.len(), 1);
        std::fs::remove_file(file).unwrap();
        let mut modules = index(&kernel);
        let mut r = Results {
            plugin: "windows.driverirp.DriverIrp".into(),
            columns: vec![],
            rows: vec![],
            complete: true,
            diagnostics: vec![],
            banner: String::new(),
            symbol: String::new(),
            page_table: 0,
            historical: false,
            system: "windows".into(),
            kernel_identity: json!({}),
        };
        modules
            .resolve_at(
                K + 0x800,
                &vm,
                Some((cache.path(), false)),
                &mut r,
                &Job::default(),
            )
            .unwrap();
        assert!(r.diagnostics.iter().any(|s| s.contains("离线模式缺少 PDB")));
    }
    #[test]
    fn module_size_mismatch_cancellation_and_symbol_budget_are_explicit() {
        let (bytes, isf, cache) = external_fixture();
        let image = image(&bytes);
        let vm = Memory::new(&image, 0x1000, &isf, None);
        let windows = Windows {
            vm: Memory::new(&image, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let mut modules = index(&isf);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let mut r = windows.result(Plugin::WinDriverIrp);
        assert!(
            modules
                .resolve_at(K + 0x800, &vm, Some((cache.path(), false)), &mut r, &job)
                .is_err()
        );
        assert!(modules.attempted.is_empty());
        modules.modules[0].size = 0x9000;
        modules
            .resolve_at(
                K + 0x800,
                &vm,
                Some((cache.path(), false)),
                &mut r,
                &Job::default(),
            )
            .unwrap();
        assert!(!r.complete);
        assert!(r.diagnostics[0].contains("SizeOfImage"));
        let mut modules = index(&isf);
        modules.symbol_count = 1_000_000;
        let mut r = windows.result(Plugin::WinDriverIrp);
        modules
            .resolve_at(
                K + 0x800,
                &vm,
                Some((cache.path(), false)),
                &mut r,
                &Job::default(),
            )
            .unwrap();
        assert!(!r.complete);
        assert!(r.diagnostics[0].contains("符号数量超限"));
        assert!(modules.external.is_empty());
    }
}
