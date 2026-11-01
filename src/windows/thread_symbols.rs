//! Shared file VAD lookup and batched exact symbol queries for thread artifacts.
use super::*;
use crate::analysis::{PEQuery, PESource};
use std::collections::BTreeMap;

pub(super) fn file_for_address(vads: &[memory::Vad], address: u64) -> Option<&str> {
    (address != 0).then_some(())?;
    vads.iter()
        .find(|v| v.start <= address && address < v.end && v.path.contains('\\'))
        .map(|v| v.path.as_str())
}

impl Windows<'_> {
    pub(super) fn thread_owner(&self, thread: u64) -> Result<u64> {
        let field = if self.vm.isf.has_field("_ETHREAD", "ThreadsProcess") {
            "ThreadsProcess"
        } else {
            "Tcb.Process"
        };
        let owner = self.number(thread, "_ETHREAD", field)?;
        ensure!(self.vm.kernel(owner), "线程归属进程地址无效");
        Ok(owner)
    }

    pub(super) fn thread_address_symbols(
        &self,
        result: &mut Results,
        columns: &[(usize, usize, usize)],
        resources: Option<(&std::path::Path, bool)>,
        job: &Job,
    ) -> Result<usize> {
        let mut queries: BTreeMap<String, std::collections::BTreeSet<u64>> = BTreeMap::new();
        for row in &result.rows {
            job.check()?;
            for &(file, _, address) in columns {
                if !row.at(file)?.is_empty() {
                    let module = row
                        .at(file)?
                        .rsplit('\\')
                        .next()
                        .unwrap_or_default()
                        .to_lowercase();
                    let address =
                        u64::from_str_radix(row.at(address)?.trim_start_matches("0x"), 16)?;
                    queries.entry(module).or_default().insert(address);
                }
            }
        }
        let count = queries.values().map(|a| a.len()).sum();
        let mut symbols = BTreeMap::new();
        let mut symbol_bytes = 0usize;
        const TEXT_LIMIT: usize = 128 * 1024 * 1024;
        'queries: for (module, addresses) in queries {
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
                            let address =
                                u64::from_str_radix(row.at(2)?.trim_start_matches("0x"), 16)?;
                            if let std::collections::btree_map::Entry::Vacant(entry) =
                                symbols.entry((module.clone(), address))
                            {
                                let bytes = module.len() + row.at(1)?.len();
                                if bytes > TEXT_LIMIT.saturating_sub(symbol_bytes) {
                                    Self::issue(
                                        result,
                                        "thread symbols",
                                        "符号缓存文本超过上限，保留已解析符号",
                                    );
                                    break 'queries;
                                }
                                symbol_bytes += bytes;
                                entry.insert(row.at(1)?.clone());
                            }
                        }
                    }
                    Err(error) => {
                        job.check()?;
                        Self::issue(result, format!("{module} thread symbols"), error);
                    }
                }
            }
        }
        let mut output_bytes: usize = result.rows.iter().flatten().map(|s| s.len()).sum();
        let mut limit = false;
        'rows: for row in &mut result.rows {
            job.check()?;
            for &(file, symbol, address) in columns {
                let module = row
                    .at(file)?
                    .rsplit('\\')
                    .next()
                    .unwrap_or_default()
                    .to_lowercase();
                let address = u64::from_str_radix(row.at(address)?.trim_start_matches("0x"), 16)?;
                if let Some(value) = symbols.get(&(module, address)) {
                    if value.len() > TEXT_LIMIT.saturating_sub(output_bytes) {
                        limit = true;
                        break 'rows;
                    }
                    output_bytes += value.len();
                    *row.at_mut(symbol)? = value.clone();
                }
            }
        }
        if limit {
            Self::issue(
                result,
                "thread symbols",
                "符号输出文本超过上限，保留已解析记录",
            );
        }
        Ok(count)
    }
}
