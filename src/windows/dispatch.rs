//! Shared module intervals and exact kernel-symbol aliases for dispatch analysis.
use super::*;

pub(super) struct DispatchModules {
    modules: Vec<KernelModule>,
    symbols: BTreeMap<u64, Vec<String>>,
    kernel_base: u64,
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
        })
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
            // Only the exact kernel ISF is available. A driver's RVA must not
            // be looked up in an unrelated kernel symbol table.
            if module.base == self.kernel_base
                && let Some(names) = self.symbols.get(&(target - module.base))
            {
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
