//! Saved kernel stack-word candidates attributed to runtime symbol intervals.
use super::*;
use crate::{
    analysis::Options,
    stack_scan,
    symbol_index::{Entry, SymbolIndex},
};
fn display_address(value: u64, arm64: bool) -> u64 {
    if arm64 {
        value
    } else {
        let value = value & 0x0000_ffff_ffff_ffff;
        if value & (1 << 47) != 0 {
            value | 0xffff_0000_0000_0000
        } else {
            value
        }
    }
}

fn reference_module_elf_bounds(symbols: &[(u64, u64)], mask: u64) -> Option<(u64, u64)> {
    let mut ordered = symbols.to_vec();
    ordered.sort_by_key(|entry| entry.0);
    let minimum = ordered.get(1)?.0 & mask;
    let last = ordered.last()?;
    // Keep Python's + before &: this is not (st_value & mask) + st_size.
    let maximum = (u128::from(last.0) & (u128::from(mask) + u128::from(last.1))) as u64;
    Some((minimum, maximum))
}

#[derive(serde::Serialize)]
struct ModuleLookupBounds {
    global_inclusive: (u64, u64),
    module_bounds: Vec<(String, u64, u64)>,
    owned_ranges: BTreeMap<String, Vec<(u64, u64)>>,
}

fn module_owned_ranges(
    regions: &[(String, u64, u64)],
    global: (u64, u64),
    job: &Job,
) -> Result<BTreeMap<String, Vec<(u64, u64)>>> {
    let mut entries = Vec::new();
    for (ordinal, (name, low, high)) in regions.iter().enumerate() {
        let start = (*low).max(global.0);
        let end = (*high).min(global.1.saturating_add(1));
        if global.0 <= global.1 && start < end {
            entries.push(Entry {
                start,
                end,
                priority: 0,
                ordinal,
                name: name.clone(),
                kind: String::new(),
                module: name.clone(),
            });
        }
    }
    let index = SymbolIndex::build(entries, job)?;
    let mut owned: BTreeMap<String, Vec<(u64, u64)>> = BTreeMap::new();
    for (low, high, module) in index.selected_ranges() {
        owned
            .entry(module.name.clone())
            .or_default()
            .push((low, high));
    }
    Ok(owned)
}

impl Linux<'_> {
    fn stack_global_module_bounds(&self) -> Result<(u64, u64)> {
        let (low, high) =
            if let Some(tree) = self.isf.address("mod_tree").ok().filter(|tree| *tree != 0) {
                (
                    self.number(tree, "mod_tree_root", "addr_min")?,
                    self.number(tree, "mod_tree_root", "addr_max")?,
                )
            } else {
                // KASConfig records symbol locations, not the stored pointer values.
                let low = self.isf.address("module_addr_min")?;
                let high = self.isf.address("module_addr_max")?;
                ensure!(low != 0 && high != 0, "缺少非零模块符号查询边界");
                (low, high)
            };
        Ok((
            display_address(low, self.arm64()),
            display_address(high, self.arm64()),
        ))
    }
    fn stack_module_lookup_bounds(&self, job: &Job) -> Result<ModuleLookupBounds> {
        let global_inclusive = self.stack_global_module_bounds()?;
        let mut module_bounds = Vec::new();
        let mut names = HashSet::new();
        let mut budget = 1_000_000u64;
        for module in self.listed_modules(job)? {
            job.check()?;
            let name = self.string(module, "module", "name")?;
            ensure!(
                names.insert(name.clone()),
                "模块名重复，无法唯一绑定符号查询范围"
            );
            let symbols = self.module_symbols(module)?;
            ensure!(symbols.count <= budget, "模块边界读取超过 100 万项上限");
            budget -= symbols.count;
            let mut values = Vec::with_capacity(usize::try_from(symbols.count)?);
            for index in 0..symbols.count {
                job.check()?;
                let symbol = add(symbols.table, index * 24)?;
                values.push((
                    self.number(symbol, "Elf64_Sym", "st_value")?,
                    self.number(symbol, "Elf64_Sym", "st_size")?,
                ));
            }
            let mask = if self.arm64() {
                u64::MAX
            } else {
                0xffff_ffff_ffff
            };
            let (low, high) = reference_module_elf_bounds(&values, mask)
                .context("模块 ELF 边界至少需要两个符号")?;
            module_bounds.push((
                name,
                display_address(low, self.arm64()),
                display_address(high, self.arm64()),
            ));
        }
        let owned_ranges = module_owned_ranges(&module_bounds, global_inclusive, job)?;
        Ok(ModuleLookupBounds {
            global_inclusive,
            module_bounds,
            owned_ranges,
        })
    }
    fn stack_symbol_index(&self, job: &Job) -> Result<(SymbolIndex, Results)> {
        let mut result = self.kallsyms(Default::default(), job)?;
        let mut core_ranges = Vec::new();
        for (low, high) in [("_stext", "_etext"), ("_sinittext", "_einittext")] {
            match (self.isf.address(low), self.isf.address(high)) {
                (Ok(low), Ok(high)) if low < high => core_ranges.push((low, high)),
                _ if low == "_stext" => partial(
                    &mut result,
                    "符号查询核心代码范围",
                    anyhow::anyhow!("缺少 _stext/_etext；不对范围外数据推断代码符号"),
                ),
                _ => {}
            }
        }
        let has_modules = result
            .rows
            .iter()
            .any(|r| r.get(4).is_some_and(|s| s == "module"));
        let module_bounds = if has_modules {
            match self.stack_module_lookup_bounds(job) {
                Ok(bounds) => Some(bounds),
                Err(error) => {
                    job.check()?;
                    partial(&mut result, "模块符号查询范围", error);
                    None
                }
            }
        } else {
            None
        };
        let mut invalid_ranges = 0u64;
        let mut entries = Vec::new();
        for (ordinal, row) in std::mem::take(&mut result.rows).into_iter().enumerate() {
            job.check()?;
            let [
                address,
                kind,
                size,
                _exported,
                source,
                module,
                name,
                _description,
            ]: [String; 8] = row
                .try_into()
                .map_err(|_| anyhow::anyhow!("Kallsyms 字段数量错误"))?;
            if size.is_empty() {
                continue;
            }
            let start = u64::from_str_radix(address.trim_start_matches("0x"), 16)?;
            let Some(end) = start
                .checked_add(size.parse::<u64>()?)
                .filter(|end| start < *end)
            else {
                invalid_ranges += 1;
                continue;
            };
            let priority = match source.as_str() {
                "core" => 0,
                "module" => 1,
                "bpf" => 2,
                "ftrace" => 3,
                _ => anyhow::bail!("未知运行时符号来源 {source}"),
            };
            let bounds = if priority == 0 {
                Some(core_ranges.as_slice())
            } else if priority == 1 {
                module_bounds
                    .as_ref()
                    .and_then(|bounds| bounds.owned_ranges.get(&module))
                    .map(Vec::as_slice)
            } else {
                None
            };
            let ranges = if let Some(bounds) = bounds {
                bounds
                    .iter()
                    .map(|&(low, high)| (start.max(low), end.min(high)))
                    .filter(|(low, high)| low < high)
                    .collect::<Vec<_>>()
            } else if priority == 1 {
                Vec::new()
            } else {
                vec![(start, end)]
            };
            for (start, end) in ranges {
                entries.push(Entry {
                    start,
                    end,
                    priority,
                    ordinal,
                    name: name.clone(),
                    kind: kind.clone(),
                    module: module.clone(),
                });
            }
        }
        if invalid_ranges > 0 {
            partial(
                &mut result,
                "符号查询范围",
                anyhow::anyhow!("{invalid_ranges} 项长度无效或溢出；未加入索引"),
            );
        }
        if !result.kernel_identity.is_object() {
            result.kernel_identity = serde_json::json!({});
        }
        result.kernel_identity["lookup_bounds"] = serde_json::json!({"core_text_ranges":core_ranges,"module_lookup":module_bounds,"invalid_symbol_ranges":invalid_ranges});
        Ok((SymbolIndex::build(entries, job)?, result))
    }
    pub(super) fn ps_callstack(&self, options: &Options, job: &Job) -> Result<Results> {
        ensure!(
            self.isf.data["base_types"]["pointer"]["size"]
                .as_u64()
                .unwrap_or(8)
                == 8,
            "PsCallStack 当前仅支持 64 位内核"
        );
        self.require(&[("task_struct", "stack"), ("task_struct", "flags")])?;
        let (index, symbols) = self.stack_symbol_index(job)?;
        self.callstacks_with_index(options, &index, symbols, job)
    }
    fn callstacks_with_index(
        &self,
        options: &Options,
        index: &SymbolIndex,
        symbols: Results,
        job: &Job,
    ) -> Result<Results> {
        ensure!(options.pids.len() <= 4096, "PID 列表超过 4096 项");
        let pids: std::collections::BTreeSet<_> =
            options.pids.iter().copied().chain(options.pid).collect();
        let mut result = self.selected_task_list_with_threads(true, &pids, job)?;
        let tasks = std::mem::take(&mut result.rows);
        result.plugin = Plugin::PsCallStack.name().into();
        result.columns = Plugin::PsCallStack
            .descriptor()
            .columns
            .iter()
            .map(|s| (*s).into())
            .collect();
        result.complete &= symbols.complete;
        result.diagnostics.extend(symbols.diagnostics);
        let stack_size = 16384u64;
        let width = 8usize;
        let mut reports = Vec::new();
        let mut attempts = 0;
        let mut failed = 0u64;
        let mut first_error = None;
        let mut read_budget = 64 * 1024 * 1024u64;
        let mut read_bytes = 0u64;
        let mut output_bytes = 0usize;
        let mut output_stopped = false;
        let sp_field = if self.isf.field("task_struct", "thread.sp").is_ok() {
            "thread.sp"
        } else {
            "thread.cpu_context.sp"
        };
        self.isf.layout("task_struct", sp_field)?;
        for task in tasks {
            job.check()?;
            let tgid = task[1].parse::<u32>()?;
            attempts += 1;
            let address = u64::from_str_radix(&task[4][2..], 16)?;
            let read = (|| -> Result<Option<serde_json::Value>> {
                let flags = self.number(address, "task_struct", "flags")?;
                let kernel_thread = flags & 0x0020_0000 != 0;
                let process = if kernel_thread {
                    None
                } else {
                    match self.process_vm(address)? {
                        Some(vm) => Some(vm),
                        None => return Ok(None),
                    }
                };
                let base =
                    display_address(self.number(address, "task_struct", "stack")?, self.arm64());
                let mut sp = self.number(address, "task_struct", sp_field)?;
                if !self.arm64()
                    && self.isf.field("task_struct", sp_field)?["type"]["kind"] == "pointer"
                {
                    sp &= 0xffff_ffff_ffff;
                }
                let top = base.checked_add(stack_size).context("栈顶溢出")?;
                ensure!(
                    base <= sp && sp < top,
                    "保存的 SP {sp:#x} 不在栈 {base:#x}..{top:#x}"
                );
                let vm = process.as_ref().unwrap_or(&self.vm);
                let mut resolved = 0u64;
                let mut unresolved = 0u64;
                let coverage = stack_scan::words(
                    base,
                    sp,
                    stack_size,
                    width,
                    job,
                    |at, out| {
                        ensure!(read_budget >= out.len() as u64, "栈读取达到 64 MiB 上限");
                        read_budget -= out.len() as u64;
                        vm.read(at, out)?;
                        read_bytes += out.len() as u64;
                        Ok(())
                    },
                    |word| {
                        let value = display_address(word.value, self.arm64());
                        let symbol = index.lookup(value);
                        if symbol.is_some() {
                            resolved += 1;
                        } else {
                            unresolved += 1;
                            if !options.unresolved {
                                return Ok(true);
                            }
                        }
                        let (name, kind, module) = symbol
                            .map(|s| (s.name.as_str(), s.kind.as_str(), s.module.as_str()))
                            .unwrap_or(("N/A", "N/A", "N/A"));
                        let row = vec![
                            task[0].clone(),
                            task[3].clone(),
                            word.position.to_string(),
                            hex(word.address),
                            hex(value),
                            name.into(),
                            kind.into(),
                            module.into(),
                        ];
                        let size = row.iter().map(String::len).sum::<usize>();
                        if result.rows.len() >= 1_000_000 || output_bytes + size > 128 * 1024 * 1024
                        {
                            output_stopped = true;
                            return Ok(false);
                        }
                        output_bytes += size;
                        result.rows.push(row);
                        Ok(true)
                    },
                )?;
                if let Some(error) = coverage.first_unreadable.clone() {
                    failed += 1;
                    first_error.get_or_insert(error);
                }
                Ok(Some(
                    serde_json::json!({"tid":task[0],"tgid":tgid,"base":hex(base),"sp":hex(sp),"scan_bytes":stack_size,"layer":if kernel_thread {"kernel"} else {"task"},"coverage":coverage,"resolved_words":resolved,"unresolved_words":unresolved}),
                ))
            })();
            match read {
                Ok(Some(report)) => {
                    if reports.len() < 65536 {
                        reports.push(report);
                    } else {
                        output_stopped = true;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    job.check()?;
                    failed += 1;
                    first_error.get_or_insert_with(|| format!("TID {}: {e:#}", task[0]));
                }
            }
            if output_stopped || read_budget == 0 {
                break;
            }
        }
        if failed > 0 {
            partial(
                &mut result,
                "任务栈读取",
                anyhow::anyhow!(
                    "{failed} 个任务无效或栈未完整读取；首处 {}",
                    first_error.unwrap_or_default()
                ),
            );
        }
        if output_stopped || read_budget == 0 {
            partial(
                &mut result,
                "栈扫描资源",
                anyhow::anyhow!("命中/文本/覆盖记录或总读取达到上限"),
            );
        }
        if !result.kernel_identity.is_object() {
            result.kernel_identity = serde_json::json!({});
        }
        result.kernel_identity["pscallstack"] = serde_json::json!({"model":"saved SP linear nonzero word scan; not frame unwinding","stack_bytes":stack_size,"stack_size_source":"fixed reference page_size(4096) << 2; kernel configuration not inferred","sp_field":sp_field,"pointer_width":width,"pids":pids,"include_unresolved":options.unresolved,"complete_scope":"word starts inside captured fixed window; actual THREAD_SIZE not proven","x86_value_mask":"48-bit reference address mask, sign extended for native display","symbol_index_entries":index.len(),"symbol_sources":symbols.kernel_identity,"source_priority":["core","module","bpf","ftrace"],"attempted_tasks":attempts,"failed_tasks":failed,"kernel_mapping_fallbacks":0,"word_read_bytes":read_bytes,"word_read_attempt_bytes":64*1024*1024-read_budget,"reports":reports,"output_stopped":output_stopped});
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{engine, image};
    use super::*;
    use serde_json::json;
    #[test]
    fn fixed_module_global_gates_use_symbol_locations_or_tree_values() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/callstack-module-gates.json"
        ))
        .unwrap();
        for case in vectors["global_bounds"].as_array().unwrap() {
            let (mut bytes, mut isf) = fixture();
            let low = case["minimum"].as_u64().unwrap();
            let high = case["maximum"].as_u64().unwrap();
            if case["tree"].as_bool().unwrap() {
                isf.data["symbols"]["mod_tree"] = json!({"address":0x300c0});
                isf.data["user_types"]["mod_tree_root"] = json!({"size":16,"fields":{"addr_min":{"offset":0,"type":{"kind":"base","name":"u64"}},"addr_max":{"offset":8,"type":{"kind":"base","name":"u64"}}}});
                put(&mut bytes, 0x300c0, low);
                put(&mut bytes, 0x300c8, high);
            } else {
                isf.data["symbols"]["module_addr_min"] = json!({"address":low});
                isf.data["symbols"]["module_addr_max"] = json!({"address":high});
            }
            let snapshot = image(&bytes);
            let (a, b) = engine(&snapshot, &isf)
                .stack_global_module_bounds()
                .unwrap();
            assert_eq!(
                serde_json::json!([a & 0xffff_ffff_ffff, b & 0xffff_ffff_ffff]),
                case["expected_bounds"],
                "{}",
                case["id"]
            );
        }
    }
    #[test]
    fn fixed_module_elf_boundary_expression_preserves_sorting_and_python_precedence() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/callstack-module-gates.json"
        ))
        .unwrap();
        for case in vectors["module_bounds"].as_array().unwrap() {
            let entries: Vec<_> = case["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| (e[0].as_u64().unwrap(), e[1].as_u64().unwrap()))
                .collect();
            assert_eq!(
                serde_json::json!(reference_module_elf_bounds(&entries, 0xffff_ffff_ffff)),
                case["expected_bounds"],
                "{}",
                case["id"]
            );
        }
    }
    #[test]
    fn first_module_ownership_does_not_fall_through_a_symbol_hole_to_the_next_module() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/callstack-module-gates.json"
        ))
        .unwrap();
        for case in vectors["routing"].as_array().unwrap() {
            let regions: Vec<_> = case["regions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| {
                    (
                        r[0].as_str().unwrap().to_owned(),
                        r[1].as_u64().unwrap(),
                        r[2].as_u64().unwrap(),
                    )
                })
                .collect();
            let owned = module_owned_ranges(&regions, (0x1000, 0x4000), &Job::default()).unwrap();
            let mut entries = Vec::new();
            for region in case["regions"].as_array().unwrap() {
                let module = region[0].as_str().unwrap();
                for (ordinal, symbol) in region[3].as_array().unwrap().iter().enumerate() {
                    let start = symbol[0].as_u64().unwrap();
                    let end = start + symbol[1].as_u64().unwrap();
                    for &(low, high) in owned.get(module).map(Vec::as_slice).unwrap_or_default() {
                        let low = start.max(low);
                        let high = end.min(high);
                        if low < high {
                            entries.push(Entry {
                                start: low,
                                end: high,
                                priority: 0,
                                ordinal,
                                name: symbol[2].as_str().unwrap().into(),
                                kind: "t".into(),
                                module: module.into(),
                            });
                        }
                    }
                }
            }
            let index = SymbolIndex::build(entries, &Job::default()).unwrap();
            assert_eq!(
                serde_json::json!(
                    index
                        .lookup(case["query"].as_u64().unwrap())
                        .map(|e| &e.name)
                ),
                case["expected"],
                "{}",
                case["id"]
            );
        }
    }
    fn put(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture() -> (Vec<u8>, Isf) {
        let (mut bytes, mut isf) = super::super::kallsyms::tests::fixture();
        isf.data["symbols"]["module_addr_min"] = json!({"address":0x30080});
        isf.data["symbols"]["module_addr_max"] = json!({"address":0x30088});
        isf.data["user_types"]["thread_struct"] =
            json!({"size":8,"fields":{"sp":{"offset":0,"type":{"kind":"base","name":"u64"}}}});
        for (field, offset, ty) in [
            ("stack", 72, json!({"kind":"pointer"})),
            (
                "thread",
                80,
                json!({"kind":"struct","name":"thread_struct"}),
            ),
            ("flags", 88, json!({"kind":"base","name":"u64"})),
            (
                "thread_group",
                96,
                json!({"kind":"struct","name":"list_head"}),
            ),
        ] {
            isf.data["user_types"]["task_struct"]["fields"][field] =
                json!({"offset":offset,"type":ty});
        }
        for (task, stack) in [(0xa000, 0x20000), (0xa100, 0x25000)] {
            bytes[stack..stack + 16384].fill(0);
            put(&mut bytes, task + 72, stack as u64);
            put(&mut bytes, task + 80, stack as u64);
            put(&mut bytes, task + 88, 0x200000);
            put(&mut bytes, task + 96, (task + 96) as u64);
            put(&mut bytes, task + 104, (task + 96) as u64);
        }
        put(&mut bytes, 0x20008, 0x18003);
        put(&mut bytes, 0x20010, 0x18010);
        put(&mut bytes, 0x20018, 0xdeadbeef);
        (bytes, isf)
    }
    #[test]
    fn runtime_first_alias_zero_positions_core_text_guard_and_unresolved_values() {
        let (bytes, isf) = fixture();
        let image = image(&bytes);
        let r = engine(&image, &isf)
            .ps_callstack(&Options::default(), &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(
            r.rows[0],
            vec![
                "1",
                "init",
                "1",
                "0x0000000000020008",
                "0x0000000000018003",
                "entry",
                "T",
                "kernel"
            ]
        );
        let r = engine(&image, &isf)
            .ps_callstack(
                &Options {
                    unresolved: true,
                    pids: vec![1],
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert_eq!(r.rows.len(), 3);
        assert_eq!(&r.rows[1][5..], &["N/A", "N/A", "N/A"]);
        assert_eq!(r.rows[1][4], "0x0000000000018010");
        assert_eq!(r.kernel_identity["pscallstack"]["attempted_tasks"], 1);
    }
    #[test]
    fn thread_group_pid_filter_includes_threads_and_bad_sp_does_not_drop_other_tasks() {
        let (mut bytes, isf) = fixture();
        // Add a non-leader thread: TID 7, TGID 1.
        bytes.copy_within(0xa000..0xa080, 0xa200);
        put(&mut bytes, 0xa210, 7);
        put(&mut bytes, 0xa218, 2); // stale TGID must not undo leader PID selection
        put(&mut bytes, 0xa060, 0xa260);
        put(&mut bytes, 0xa068, 0xa260);
        put(&mut bytes, 0xa260, 0xa060);
        put(&mut bytes, 0xa268, 0xa060);
        put(&mut bytes, 0xa150, 0xdeadbeef);
        let image = image(&bytes);
        let options = Options {
            pid: Some(1),
            ..Default::default()
        };
        let r = engine(&image, &isf)
            .ps_callstack(&options, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows.iter().map(|row| row[0].as_str()).collect::<Vec<_>>(),
            ["1", "7"]
        );
        let r = engine(&image, &isf)
            .ps_callstack(&Options::default(), &Job::default())
            .unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 2);
    }
    #[test]
    fn first_unavailable_stack_word_and_cancellation_are_explicit() {
        let (mut bytes, isf) = fixture();
        // Base remains in range but captured data ends after two nonzero words.
        put(&mut bytes, 0xa048, 0x3f000);
        put(&mut bytes, 0xa050, 0x3fff0);
        put(&mut bytes, 0x3fff0, 0x18003);
        put(&mut bytes, 0x3fff8, 0x18004);
        let image = image(&bytes);
        let r = engine(&image, &isf)
            .ps_callstack(
                &Options {
                    pid: Some(1),
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert_eq!(r.rows.len(), 2);
        assert!(!r.complete);
        assert_eq!(r.kernel_identity["pscallstack"]["failed_tasks"], 1);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            engine(&image, &isf)
                .ps_callstack(&Options::default(), &job)
                .is_err()
        );
    }
    #[test]
    fn task_stack_fault_does_not_fall_back_to_kernel_and_integer_sp_is_not_repaired() {
        for bad_integer_sp in [false, true] {
            let (mut bytes, isf) = fixture();
            if bad_integer_sp {
                put(&mut bytes, 0xa050, 0x1234000000020000);
            } else {
                put(&mut bytes, 0xa058, 0); // user task, its mm maps no saved stack
            }
            let snapshot = image(&bytes);
            let linux = engine(&snapshot, &isf);
            assert!(linux.vm.read(0x20000, &mut [0; 8]).is_ok());
            if !bad_integer_sp {
                assert!(
                    linux
                        .process_vm(0xa000)
                        .unwrap()
                        .unwrap()
                        .read(0x20000, &mut [0; 8])
                        .is_err()
                );
            }
            let result = linux
                .ps_callstack(
                    &Options {
                        pid: Some(1),
                        unresolved: true,
                        ..Default::default()
                    },
                    &Job::default(),
                )
                .unwrap();
            assert!(result.rows.is_empty());
            assert!(!result.complete);
            assert_eq!(result.kernel_identity["pscallstack"]["failed_tasks"], 1);
            assert_eq!(
                result.kernel_identity["pscallstack"]["kernel_mapping_fallbacks"],
                0
            );
        }
    }
}
