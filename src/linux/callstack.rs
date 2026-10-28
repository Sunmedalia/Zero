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
impl Linux<'_> {
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
            match self.module_extraction_bounds() {
                Ok(bounds) => Some(bounds),
                Err(error) => {
                    job.check()?;
                    partial(&mut result, "模块符号分配范围", error);
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
                module_bounds.as_ref().map(|(ranges, _)| ranges.as_slice())
            } else {
                None
            };
            let ranges = if let Some(bounds) = bounds {
                bounds
                    .iter()
                    .map(|&(low, high)| (start.max(low), end.min(high)))
                    .filter(|(low, high)| low < high)
                    .collect::<Vec<_>>()
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
        result.kernel_identity["lookup_bounds"] = serde_json::json!({"core_text_ranges":core_ranges,"module_allocator":module_bounds,"invalid_symbol_ranges":invalid_ranges});
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
        let mut fallback_count = 0u64;
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
                let sp =
                    display_address(self.number(address, "task_struct", sp_field)?, self.arm64());
                let top = base.checked_add(stack_size).context("栈顶溢出")?;
                ensure!(
                    base <= sp && sp < top,
                    "保存的 SP {sp:#x} 不在栈 {base:#x}..{top:#x}"
                );
                let mut fallback = false;
                if let Some(vm) = process.as_ref() {
                    let mut probe = [0; 8];
                    if vm.read(sp, &mut probe).is_err() && self.vm.read(sp, &mut probe).is_ok() {
                        fallback = true;
                        fallback_count += 1;
                    }
                }
                let vm = if fallback {
                    &self.vm
                } else {
                    process.as_ref().unwrap_or(&self.vm)
                };
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
                if coverage.first_unreadable.is_some() {
                    failed += 1;
                    first_error.get_or_insert_with(|| coverage.first_unreadable.clone().unwrap());
                }
                Ok(Some(
                    serde_json::json!({"tid":task[0],"tgid":tgid,"base":hex(base),"sp":hex(sp),"scan_bytes":stack_size,"layer":if fallback {"kernel fallback"} else if kernel_thread {"kernel"} else {"task"},"coverage":coverage,"resolved_words":resolved,"unresolved_words":unresolved}),
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
        if fallback_count > 0 {
            partial(
                &mut result,
                "内核栈映射",
                anyhow::anyhow!(
                    "{fallback_count} 个任务地址空间不可读保存的内核栈，但已验证的内核页表可读；使用内核映射并记录来源"
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
        result.kernel_identity["pscallstack"] = serde_json::json!({"model":"saved SP linear nonzero word scan; not frame unwinding","stack_bytes":stack_size,"stack_size_source":"fixed reference page_size(4096) << 2; kernel configuration not inferred","sp_field":sp_field,"pointer_width":width,"pids":pids,"include_unresolved":options.unresolved,"complete_scope":"captured fixed window; actual THREAD_SIZE not proven","x86_value_mask":"48-bit reference address mask, sign extended for native display","symbol_index_entries":index.len(),"symbol_sources":symbols.kernel_identity,"source_priority":["core","module","bpf","ftrace"],"attempted_tasks":attempts,"failed_tasks":failed,"kernel_mapping_fallbacks":fallback_count,"word_read_bytes":read_bytes,"word_read_attempt_bytes":64*1024*1024-read_budget,"reports":reports,"output_stopped":output_stopped});
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{engine, image};
    use super::*;
    use serde_json::json;
    fn put(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture() -> (Vec<u8>, Isf) {
        let (mut bytes, mut isf) = super::super::kallsyms::tests::fixture();
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
}
