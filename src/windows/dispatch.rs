//! Shared module intervals and exact per-module PDB aliases for dispatch analysis.
use super::*;

pub(super) struct DispatchModules {
    reference_collection: bool,
    modules: Vec<KernelModule>,
    symbols: BTreeMap<u64, Vec<String>>,
    kernel_base: u64,
    external: BTreeMap<u64, BTreeMap<u64, Vec<String>>>,
    attempted: HashSet<u64>,
    evidence: Vec<serde_json::Value>,
    symbol_bytes: usize,
    symbol_count: usize,
    dependencies: BTreeMap<String, windows_symbols::CacheState>,
    stable: bool,
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
        for (name, entry) in isf
            .data
            .key("symbols")
            .as_object()
            .context("缺少符号映射")?
        {
            job.check()?;
            if let Some(rva) = entry.key("address").as_u64() {
                symbols.entry(rva).or_default().push(name.clone());
            }
        }
        for names in symbols.values_mut() {
            names.sort();
        }
        Ok(Self {
            reference_collection: false,
            modules,
            symbols,
            kernel_base,
            external: BTreeMap::new(),
            attempted: HashSet::new(),
            evidence: Vec::new(),
            symbol_bytes: 0,
            symbol_count: 0,
            dependencies: BTreeMap::new(),
            stable: true,
        })
    }
    pub(super) fn reference(
        modules: Vec<KernelModule>,
        isf: &Isf,
        kernel_base: u64,
        job: &Job,
    ) -> Result<Self> {
        let mut collection = Self::new(modules, isf, kernel_base, job)?;
        collection.reference_collection = true;
        Ok(collection)
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
        if self.reference_collection {
            job.check()?;
            return Ok(());
        }
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
            let mut dependency = None;
            let result = (|| -> Result<BTreeMap<u64, Vec<String>>> {
                let (cache, network) = resources.context("缺少外部模块符号资源上下文")?;
                let mut header = [0; 4096];
                vm.read(module.base, &mut header)?;
                ensure!(
                    u64::from(pe_header(&header)?.0) == module.size,
                    "模块范围与 PE SizeOfImage 不一致"
                );
                let identity = network::pe_identity(vm, module.base)?;
                *evidence.key_mut("pdb")? = serde_json::json!(identity.key());
                dependency = Some((
                    identity.clone(),
                    windows_symbols::cache_state(&identity, cache, job).ok(),
                ));
                let isf = windows_symbols::acquire(&identity, cache, network, job)?;
                ensure!(
                    PdbIdentity::from_isf(&isf)? == identity,
                    "模块 PDB 身份不匹配"
                );
                ensure!(
                    Architecture::from_isf(&isf)? == Architecture::from_isf(vm.isf)?,
                    "模块 PDB 架构冲突"
                );
                *evidence.key_mut("isf_sha256")? = serde_json::json!(isf.digest);
                let mut symbols = BTreeMap::<u64, Vec<String>>::new();
                for (name, entry) in isf
                    .data
                    .key("symbols")
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
            if let Some((identity, before)) = dependency {
                let after = resources.and_then(|(cache, _)| {
                    windows_symbols::cache_state(&identity, cache, job).ok()
                });
                job.check()?;
                if let Some(after) = after {
                    if result.is_ok() {
                        self.stable &= after.isf.as_deref() == evidence.key("isf_sha256").as_str();
                    } else {
                        self.stable &= before.as_ref() == Some(&after);
                    }
                    if let Some(old) = self.dependencies.insert(identity.key(), after.clone()) {
                        self.stable &= old == after;
                    }
                } else {
                    self.stable = false;
                }
            }
            match result {
                Ok(symbols) => {
                    *evidence.key_mut("resolved")? = serde_json::json!(true);
                    self.external.insert(module.base, symbols);
                }
                Err(error) => {
                    job.check()?;
                    *evidence.key_mut("error")? = serde_json::json!(format!("{error:#}"));
                    Windows::issue(r, format!("模块符号 {}", module.name), format!("{error:#}"));
                }
            }
            self.evidence.push(evidence);
        }
        Ok(())
    }
    pub(super) fn evidence(
        &self,
        resources: Option<(&std::path::Path, bool)>,
    ) -> serde_json::Value {
        if self.reference_collection {
            return serde_json::json!({"scope":"pinned SSDT module collection; kernel ISF bound at every loaded module base","match":"exact RVA; all aliases; inclusive module endpoints","mode":"reference-kernel-isf","external_resources":false});
        }
        serde_json::json!({"scope":"exact per-module PDB; no cross-module fallback", "modules":self.evidence,
            "match":"exact address; all aliases; half-open module ranges",
            "cache_dependencies": CacheDependencies {version:1,converter:windows_symbols::CONVERTER_VERSION.into(),
                network:resources.map(|(_, network)| network), stable:self.stable, entries:self.dependencies.clone()}})
    }
    pub(super) fn at(&self, target: u64) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for module in &self.modules {
            if module.name.is_empty()
                || target < module.base
                || module.base.checked_add(module.size).is_none_or(|end| {
                    if self.reference_collection {
                        target > end
                    } else {
                        target >= end
                    }
                })
            {
                continue;
            }
            let name = &module.name;
            let symbols = if self.reference_collection || module.base == self.kernel_base {
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

#[derive(serde::Serialize, serde::Deserialize)]
struct CacheDependencies {
    version: u32,
    converter: String,
    network: Option<bool>,
    stable: bool,
    entries: BTreeMap<String, windows_symbols::CacheState>,
}
/// Validate content and absence dependencies without acquiring or downloading.
/// Online acquisition failures must be retried rather than becoming sticky.
pub(super) fn dependencies_match(
    result: &Results,
    cache: &std::path::Path,
    network: bool,
    job: &Job,
) -> Result<bool> {
    job.check()?;
    let evidence = result.kernel_identity.key("dispatch_symbols");
    if evidence["mode"] == "reference-kernel-isf" {
        return Ok(true);
    }
    let Ok(deps) =
        serde_json::from_value::<CacheDependencies>(evidence["cache_dependencies"].clone())
    else {
        return Ok(false);
    };
    if deps.version != 1
        || deps.converter != windows_symbols::CONVERTER_VERSION
        || deps.network != Some(network)
        || !deps.stable
        || deps.entries.len() > 4096
    {
        return Ok(false);
    }
    let Some(modules) = evidence["modules"].as_array() else {
        return Ok(false);
    };
    if network && modules.iter().any(|module| module["resolved"] != true) {
        return Ok(false);
    }
    let identities: HashSet<_> = modules
        .iter()
        .filter_map(|module| module["pdb"].as_str())
        .collect();
    if identities.len() != deps.entries.len()
        || deps
            .entries
            .keys()
            .any(|key| !identities.contains(key.as_str()))
    {
        return Ok(false);
    }
    for (key, expected) in deps.entries {
        let Ok(identity) = PdbIdentity::from_key(&key) else {
            return Ok(false);
        };
        match windows_symbols::cache_state(&identity, cache, job) {
            Ok(actual) if actual == expected => {}
            _ => {
                job.check()?;
                return Ok(false);
            }
        }
    }
    Ok(true)
}

pub(super) fn load_cached(
    cache: &std::path::Path,
    key: &str,
    network: bool,
    job: &Job,
) -> Result<Option<Results>> {
    for partial in [false, true] {
        let candidate = if partial {
            store::load_partial(cache, key)
        } else {
            store::load(cache, key)
        };
        if let Some(candidate) = candidate
            && dependencies_match(&candidate, cache, network, job)?
        {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image};
    use super::*;
    #[test]
    fn pinned_collection_binds_kernel_table_at_every_base_and_keeps_inclusive_ends() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/dispatch-collection.json"
        ))
        .unwrap();
        let (_, mut isf) = super::super::tests::fixture();
        isf.data["symbols"] = serde_json::json!({"Zero":{"address":0},"AliasA":{"address":16},"AliasB":{"address":16},"End":{"address":32}});
        for case in vectors["cases"].as_array().unwrap() {
            let modules = case["modules"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| KernelModule {
                    name: m[0].as_str().unwrap().into(),
                    base: m[1].as_u64().unwrap(),
                    size: m[2].as_u64().unwrap(),
                    path: String::new(),
                })
                .collect();
            let index = DispatchModules::reference(modules, &isf, 0x1000, &Job::default()).unwrap();
            for query in case["expected"].as_array().unwrap() {
                assert_eq!(
                    serde_json::json!(index.at(query["query"].as_u64().unwrap())),
                    query["rows"],
                    "{}",
                    case["id"]
                );
            }
        }
    }
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
        assert_eq!(
            modules.evidence(Some((cache.path(), false)))["modules"][0]["resolved"],
            true
        );
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
        assert_eq!(
            modules.evidence(Some((cache.path(), false)))["modules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
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
    fn result_for(modules: &DispatchModules, cache: &std::path::Path, network: bool) -> Results {
        Results {
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
            kernel_identity: json!({"dispatch_symbols":modules.evidence(Some((cache,network)))}),
        }
    }
    #[test]
    fn cached_dispatch_requires_exact_resources_and_policy_and_keeps_partial_separate() {
        let (bytes, isf, cache) = external_fixture();
        let image = image(&bytes);
        let vm = Memory::new(&image, 0x1000, &isf, None);
        let job = Job::default();
        let mut modules = index(&isf);
        let mut r = result_for(&modules, cache.path(), false);
        modules
            .resolve_at(K + 0x800, &vm, Some((cache.path(), false)), &mut r, &job)
            .unwrap();
        let r = result_for(&modules, cache.path(), false);
        assert!(dependencies_match(&r, cache.path(), false, &job).unwrap());
        assert!(!dependencies_match(&r, cache.path(), true, &job).unwrap());
        let file = std::fs::read_dir(cache.path().join("symbols/isf/windows"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let original = std::fs::read(&file).unwrap();
        let modified = String::from_utf8(original.clone())
            .unwrap()
            .replace("DriverDispatch", "DriverNewNameX");
        assert_eq!(
            modified.len(),
            original.len(),
            "same-size replacement regression"
        );
        store::atomic_write(&file, modified.as_bytes()).unwrap();
        assert!(!dependencies_match(&r, cache.path(), false, &job).unwrap());
        std::fs::remove_file(&file).unwrap();
        assert!(!dependencies_match(&r, cache.path(), false, &job).unwrap());
        let mut missing = index(&isf);
        let mut partial = result_for(&missing, cache.path(), false);
        missing
            .resolve_at(
                K + 0x800,
                &vm,
                Some((cache.path(), false)),
                &mut partial,
                &job,
            )
            .unwrap();
        assert!(!partial.complete);
        partial.kernel_identity["dispatch_symbols"] = missing.evidence(Some((cache.path(), false)));
        assert!(dependencies_match(&partial, cache.path(), false, &job).unwrap());
        store::save_any(
            cache.path(),
            "partial",
            &store::Owner::default(),
            &partial,
            &job,
        )
        .unwrap();
        assert!(store::load(cache.path(), "partial").is_none());
        assert!(store::load_partial(cache.path(), "partial").is_some());
        // A stale successful entry must not hide a current partial entry.
        store::save_any(cache.path(), "partial", &store::Owner::default(), &r, &job).unwrap();
        let reused = load_cached(cache.path(), "partial", false, &job)
            .unwrap()
            .unwrap();
        assert!(!reused.complete);
        assert_eq!(reused, partial);
        let mut online = partial.clone();
        online.kernel_identity["dispatch_symbols"]["cache_dependencies"]["network"] = json!(true);
        assert!(
            !dependencies_match(&online, cache.path(), true, &job).unwrap(),
            "online failures must retry"
        );
        store::atomic_write(&file, &original).unwrap();
        assert!(
            !dependencies_match(&partial, cache.path(), false, &job).unwrap(),
            "new exact ISF invalidates missing dependency"
        );
        let mut unstable = r.clone();
        unstable.kernel_identity["dispatch_symbols"]["cache_dependencies"]["stable"] = json!(false);
        assert!(!dependencies_match(&unstable, cache.path(), false, &job).unwrap());
        let mut old = r;
        old.kernel_identity["dispatch_symbols"]["cache_dependencies"] = json!(null);
        assert!(!dependencies_match(&old, cache.path(), false, &job).unwrap());
        let cancelled = Job::default();
        cancelled
            .cancel
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(dependencies_match(&partial, cache.path(), false, &cancelled).is_err());
    }

    #[test]
    #[ignore = "requires public Win10/Server2008 images and exact local mup ISF/PDBs"]
    fn real_external_driver_resources_and_cache_lifecycle() -> Result<()> {
        for (variable, default, kernel_file, driver_key) in [
            (
                "ZERO_WINDOWS10_IMAGE",
                "images/feat-windows-plugins/WinDump/WinDump.mem",
                "ntkrnlmp.pdb-0C9CC659210046EC84231597DADFDB3B1.json",
                "mup.pdb/8443AA648B71EE252D2008EB6EBBC0311",
            ),
            (
                "ZERO_WINDOWS2008_IMAGE",
                "images/feat-windows-plugins/server2008/memdump.mem",
                "ntkrpamp.pdb-37D328E3BAE5460F8E662756ED80951D2.json",
                "mup.pdb/2383AD05D3F9414EB69278AB890373CA2",
            ),
        ] {
            let cache = tempfile::tempdir()?;
            let job = Job::default();
            let path = std::env::var(variable).unwrap_or_else(|_| default.into());
            let image = Image::open(std::path::Path::new(&path), cache.path(), &job)?;
            let kernel_path =
                std::path::Path::new(".zero/rust/symbols/isf/windows").join(kernel_file);
            let isf = Isf::parse(
                &std::fs::read(&kernel_path)?,
                kernel_path.display().to_string(),
            )?;
            let (root, base) = super::super::discover(&image, &isf, &job)?;
            let windows = Windows {
                vm: Memory::new(&image, root, &isf, None),
                base,
                pdb: PdbIdentity::from_isf(&isf)?,
            };
            let mut inventory = windows.result(Plugin::WinModules);
            let modules = windows.modules_partial(&job, &mut inventory)?;
            let module = modules
                .iter()
                .find(|m| m.name.eq_ignore_ascii_case("mup.sys"))
                .context("sample has no mup.sys module")?
                .clone();
            let identity = PdbIdentity::from_key(driver_key)?;
            let stem = format!("{}-{}{:X}", identity.name, identity.guid, identity.age);
            let source = std::path::Path::new(".zero/rust/symbols");
            let driver_bytes =
                std::fs::read(source.join("isf/windows").join(format!("{stem}.json")))?;
            let driver = Isf::parse(&driver_bytes, driver_key.into())?;
            assert_eq!(PdbIdentity::from_isf(&driver)?, identity);
            let rva = driver.data["symbols"]
                .as_object()
                .context("driver symbols missing")?
                .values()
                .filter_map(|s| s["address"].as_u64())
                .find(|rva| *rva > 0 && *rva < module.size)
                .context("no driver symbol in image")?;
            let target = module
                .base
                .checked_add(rva)
                .context("driver target overflow")?;
            let local_isf = cache
                .path()
                .join("symbols/isf/windows")
                .join(format!("{stem}.json"));
            store::atomic_write(&local_isf, &driver_bytes)?;
            let mut prior: Option<Results> = None;
            for (phase, named) in [(0, true), (1, true), (2, false), (3, false), (4, true)] {
                if phase == 2 {
                    std::fs::remove_file(&local_isf)?;
                    assert!(!dependencies_match(
                        prior.as_ref().unwrap(),
                        cache.path(),
                        false,
                        &job
                    )?);
                }
                if phase == 4 {
                    let pdb = std::fs::read(source.join("build/pdb").join(format!("{stem}.pdb")))?;
                    store::atomic_write(
                        &cache
                            .path()
                            .join("symbols/build/pdb")
                            .join(format!("{stem}.pdb")),
                        &pdb,
                    )?;
                    assert!(!dependencies_match(
                        prior.as_ref().unwrap(),
                        cache.path(),
                        false,
                        &job
                    )?);
                }
                let mut index = DispatchModules::new(vec![module.clone()], &isf, base, &job)?;
                let mut result = result_for(&index, cache.path(), false);
                index.resolve_at(
                    target,
                    &windows.vm,
                    Some((cache.path(), false)),
                    &mut result,
                    &job,
                )?;
                result.kernel_identity["dispatch_symbols"] =
                    index.evidence(Some((cache.path(), false)));
                assert_eq!(
                    result.kernel_identity["dispatch_symbols"]["modules"][0]["resolved"], named,
                    "{variable} phase {phase}"
                );
                let hits = index.at(target);
                assert!(!hits.is_empty());
                assert!(hits.iter().all(|(_, symbol)| symbol.is_empty() != named));
                if named {
                    for (_, symbol) in hits {
                        assert_eq!(
                            driver.data["symbols"][&symbol]["address"].as_u64(),
                            Some(rva)
                        );
                    }
                    assert!(result.complete && result.diagnostics.is_empty());
                } else {
                    assert!(!result.complete && !result.diagnostics.is_empty());
                }
                assert!(dependencies_match(&result, cache.path(), false, &job)?);
                store::save_any(
                    cache.path(),
                    "external-driver",
                    &store::Owner::default(),
                    &result,
                    &job,
                )?;
                assert_eq!(
                    load_cached(cache.path(), "external-driver", false, &job)?,
                    Some(result.clone())
                );
                prior = Some(result);
            }
        }
        Ok(())
    }
}
