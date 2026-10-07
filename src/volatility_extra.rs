//! Native resource trees, ptrace relationships and keyboard notifier callbacks.
use crate::{
    Job,
    linux::{Linux, Plugin},
    report::{hex, partial},
    store::Results,
};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, HashSet};

const LIMIT: usize = 1_000_000;
const DEPTH_LIMIT: usize = 1024;
impl Linux<'_> {
    pub(crate) fn run_volatility_extra(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        job.check()?;
        let mut result = self.result(plugin);
        match plugin {
            Plugin::Iomem | Plugin::Ioports => {
                self.require(&[
                    ("resource", "name"),
                    ("resource", "start"),
                    ("resource", "end"),
                    ("resource", "flags"),
                    ("resource", "child"),
                    ("resource", "sibling"),
                ])?;
                let symbol = if plugin == Plugin::Iomem {
                    "iomem_resource"
                } else {
                    "ioport_resource"
                };
                let root = self
                    .isf
                    .address(symbol)
                    .with_context(|| format!("不支持: 缺少 {symbol}"))?;
                self.resources(root, &mut result, job, LIMIT)?;
            }
            Plugin::Ptrace => self.ptrace(&mut result, job)?,
            Plugin::KeyboardNotifiers => self.keyboard_notifiers(&mut result, job)?,
            _ => unreachable!(),
        }
        job.check()?;
        job.report(format!("{}: {} 条", plugin.name(), result.rows.len()));
        Ok(result)
    }
    fn resources(&self, root: u64, result: &mut Results, job: &Job, limit: usize) -> Result<()> {
        // Iterative pre-order traversal also keeps siblings when a child is corrupt.
        let mut pending = vec![(root, 0)];
        let mut seen = HashSet::new();
        while let Some((address, depth)) = pending.pop() {
            job.check()?;
            if seen.len() >= limit {
                partial(
                    result,
                    hex(address),
                    anyhow::anyhow!("资源遍历达到 {limit} 项上限"),
                );
                break;
            }
            if !seen.insert(address) {
                partial(
                    result,
                    hex(address),
                    anyhow::anyhow!("资源树循环或重复引用"),
                );
                continue;
            }
            // Follow links independently of payload/name readability.
            for (field, next_depth) in [("sibling", depth), ("child", depth + 1)] {
                match self.number(address, "resource", field) {
                    Ok(0) => {}
                    Ok(next) if next_depth <= DEPTH_LIMIT => pending.push((next, next_depth)),
                    Ok(_) => partial(
                        result,
                        hex(address),
                        anyhow::anyhow!("资源树超过 {DEPTH_LIMIT} 层"),
                    ),
                    Err(e) => partial(result, format!("resource {} {field}", hex(address)), e),
                }
            }
            let read = (|| -> Result<Vec<String>> {
                let start = self.number(address, "resource", "start")?;
                let end = self.number(address, "resource", "end")?;
                ensure!(start <= end, "资源范围倒置");
                let name = match self.kernel_text(self.number(address, "resource", "name")?, 4096) {
                    Ok(name) => name,
                    Err(e) => {
                        partial(result, format!("resource {} name", hex(address)), e);
                        "[unreadable]".into()
                    }
                };
                Ok(vec![
                    name,
                    hex(start),
                    hex(end),
                    depth.to_string(),
                    hex(self.number(address, "resource", "flags")?),
                    hex(address),
                ])
            })();
            match read {
                Ok(row) => result.rows.push(row),
                Err(e) => partial(result, format!("resource {}", hex(address)), e),
            }
        }
        Ok(())
    }
    fn ptrace(&self, result: &mut Results, job: &Job) -> Result<()> {
        self.require(&[
            ("task_struct", "ptrace"),
            ("task_struct", "parent"),
            ("task_struct", "ptraced"),
            ("task_struct", "ptrace_entry"),
            ("task_struct", "pid"),
            ("task_struct", "tgid"),
            ("list_head", "next"),
            ("list_head", "prev"),
        ])?;
        let threads = self.run(Plugin::Threads, job)?;
        result.complete &= threads.complete;
        result.diagnostics.extend(threads.diagnostics);
        let mut tasks = BTreeMap::new();
        for row in threads.rows {
            let address = u64::from_str_radix(&row[4][2..], 16)?;
            tasks.insert(address, row);
        }
        for (address, task) in tasks {
            job.check()?;
            let context = format!("TID {} @ {}", task[2], hex(address));
            let read = (|| -> Result<()> {
                let flags = self.number(address, "task_struct", "ptrace")?;
                let tracer = if flags == 0 {
                    "[none]".into()
                } else {
                    let parent = self.number(address, "task_struct", "parent")?;
                    ensure!(parent != 0, "ptrace parent 为空");
                    self.number(parent, "task_struct", "pid")?.to_string()
                };
                let head = self.field_address(address, "task_struct", "ptraced")?;
                let offset = self.isf.offset("task_struct", "ptrace_entry")?;
                let mut tracees = Vec::new();
                let walk = (|| -> Result<()> {
                    let mut entry = self.number(head, "list_head", "next")?;
                    let mut previous = head;
                    let mut seen = HashSet::new();
                    while entry != head {
                        job.check()?;
                        ensure!(entry != 0 && seen.insert(entry), "ptraced 链表空指针或循环");
                        ensure!(seen.len() <= LIMIT, "ptraced 链表超过 {LIMIT} 项");
                        ensure!(
                            self.number(entry, "list_head", "prev")? == previous,
                            "ptraced next/prev 不一致"
                        );
                        let tracee = entry.checked_sub(offset).context("ptrace_entry 地址下溢")?;
                        tracees.push(self.number(tracee, "task_struct", "pid")?.to_string());
                        previous = entry;
                        entry = self.number(entry, "list_head", "next")?;
                    }
                    ensure!(
                        self.number(head, "list_head", "prev")? == previous,
                        "ptraced 尾指针不一致"
                    );
                    Ok(())
                })();
                if let Err(e) = walk {
                    job.check()?;
                    partial(result, &context, e);
                }
                if flags != 0 && tracees.is_empty() {
                    tracees.push("[none]".into());
                }
                for tracee in tracees {
                    result.rows.push(vec![
                        task[3].clone(),
                        self.number(address, "task_struct", "tgid")?.to_string(),
                        task[2].clone(),
                        tracer.clone(),
                        tracee,
                        hex(flags),
                    ]);
                }
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                partial(result, context, e);
            }
        }
        Ok(())
    }
    fn keyboard_notifiers(&self, result: &mut Results, job: &Job) -> Result<()> {
        self.require(&[
            ("atomic_notifier_head", "head"),
            ("notifier_block", "next"),
            ("notifier_block", "notifier_call"),
            ("notifier_block", "priority"),
        ])?;
        let head = self
            .isf
            .address("keyboard_notifier_list")
            .context("不支持: 缺少 keyboard_notifier_list")?;
        let mut address = match self.number(head, "atomic_notifier_head", "head") {
            Ok(value) => value,
            Err(e) => {
                partial(result, "keyboard_notifier_list", e);
                return Ok(());
            }
        };
        if address == 0 {
            return Ok(());
        }
        let start = self
            .isf
            .address("_stext")
            .or_else(|_| self.isf.address("_text"))
            .context("不支持: 缺少内核代码起始符号")?;
        let end = self.isf.address("_etext").context("不支持: 缺少 _etext")?;
        ensure!(start < end, "不支持: 内核代码范围无效");
        let mut ranges = vec![(start, end, "kernel".into())];
        let module_head = self
            .isf
            .address("modules")
            .context("不支持: 缺少 modules")?;
        let module_offset = self
            .isf
            .offset("module", "list")
            .context("不支持: 缺少 module.list")?;
        let modules = match self.list_objects(module_head, module_offset, job) {
            Ok(modules) => modules,
            Err(e) => {
                job.check()?;
                partial(result, "modules", e);
                Vec::new()
            }
        };
        for module in modules {
            let read = (|| -> Result<_> {
                let (start, end) = self.module_range(module)?;
                ensure!(start < end, "模块代码范围无效");
                Ok((
                    start,
                    end,
                    self.kernel_text(self.field_address(module, "module", "name")?, 128)?,
                ))
            })();
            match read {
                Ok(range) => ranges.push(range),
                Err(e) => partial(result, format!("module {}", hex(module)), e),
            }
        }
        let mut symbols: Vec<_> = self.isf.data["symbols"]
            .as_object()
            .context("ISF symbols 缺失")?
            .iter()
            .filter_map(|(name, value)| value["address"].as_u64().map(|_| name))
            .map(|name| Ok((self.isf.address(name)?, name.as_str())))
            .collect::<Result<_>>()?;
        symbols.sort_unstable();
        let mut seen = HashSet::new();
        while address != 0 {
            job.check()?;
            if !seen.insert(address) || seen.len() > LIMIT {
                partial(
                    result,
                    hex(address),
                    anyhow::anyhow!("notifier 链表循环或超过 {LIMIT} 项"),
                );
                break;
            }
            let read = (|| -> Result<Vec<String>> {
                let callback = self.number(address, "notifier_block", "notifier_call")?;
                ensure!(callback != 0, "notifier_call 为空");
                let owner = ranges
                    .iter()
                    .find(|(start, end, _)| callback >= *start && callback < *end);
                // Only resolve ISF symbols inside kernel text; never attribute a module/unknown address to a nearby kernel symbol.
                let symbol = if owner.is_some_and(|(_, _, name)| name == "kernel") {
                    let index = symbols.partition_point(|(a, _)| *a <= callback);
                    symbols
                        .get(index.wrapping_sub(1))
                        .filter(|(a, _)| *a >= start)
                        .map(|(a, name)| {
                            if *a == callback {
                                (*name).into()
                            } else {
                                format!("{name}+{:#x}", callback - a)
                            }
                        })
                        .unwrap_or_else(|| "[unknown]".into())
                } else {
                    "[unknown]".into()
                };
                let size = self.isf.size("notifier_block", "priority")?;
                ensure!((1..=8).contains(&size), "priority 大小无效");
                let priority = self.number(address, "notifier_block", "priority")?;
                let shift = 64 - size * 8;
                let priority = ((priority << shift) as i64) >> shift;
                Ok(vec![
                    hex(callback),
                    owner
                        .map(|(_, _, name)| name.clone())
                        .unwrap_or_else(|| "[unknown]".into()),
                    symbol,
                    priority.to_string(),
                    hex(address),
                ])
            })();
            match read {
                Ok(row) => result.rows.push(row),
                Err(e) => partial(result, format!("notifier {}", hex(address)), e),
            }
            match self.number(address, "notifier_block", "next") {
                Ok(next) => address = next,
                Err(e) => {
                    partial(result, format!("notifier {} next", hex(address)), e);
                    break;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extended::tests::{engine, fixture, image};
    use serde_json::json;
    fn put(bytes: &mut [u8], address: usize, value: u64) {
        bytes[address..address + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn structure(fields: &[(&str, usize)], size: usize) -> serde_json::Value {
        let fields: serde_json::Map<_, _> = fields
            .iter()
            .map(|(name, offset)| {
                (
                    name.to_string(),
                    json!({"offset":offset,"type":{"kind":"base","name":"u64"}}),
                )
            })
            .collect();
        json!({"size":size,"fields":fields})
    }
    fn resources_fixture() -> (Vec<u8>, crate::symbols::Isf) {
        let (mut bytes, mut isf) = fixture();
        isf.data["symbols"]["iomem_resource"] = json!({"address":0x12000});
        isf.data["symbols"]["ioport_resource"] = json!({"address":0x12000});
        isf.data["user_types"]["resource"] = structure(
            &[
                ("name", 0),
                ("start", 8),
                ("end", 16),
                ("flags", 24),
                ("child", 32),
                ("sibling", 40),
            ],
            48,
        );
        for (address, name, start, end, child, sibling) in [
            (0x12000, "PCI mem", 0, 0xffff, 0x12100, 0),
            (0x12100, "System RAM", 0x1000, 0x3fff, 0x12200, 0x12300),
            (0x12200, "Kernel code", 0x1000, 0x1fff, 0, 0),
            (0x12300, "Reserved", 0x4000, 0x4fff, 0, 0),
        ] {
            let ptr = address + 64;
            bytes[ptr..ptr + name.len()].copy_from_slice(name.as_bytes());
            for (offset, value) in [
                (0, ptr as u64),
                (8, start),
                (16, end),
                (24, 0x200),
                (32, child),
                (40, sibling),
            ] {
                put(&mut bytes, address + offset, value);
            }
        }
        (bytes, isf)
    }
    #[test]
    fn resource_tree_fields_order_relocation_and_limits() {
        let (bytes, isf) = resources_fixture();
        let im = image(&bytes);
        let linux = engine(&im, &isf);
        for plugin in [Plugin::Iomem, Plugin::Ioports] {
            let result = linux.run(plugin, &Job::default()).unwrap();
            assert!(result.complete);
            assert_eq!(
                result
                    .rows
                    .iter()
                    .map(|r| (&r[0], &r[3]))
                    .collect::<Vec<_>>(),
                vec![
                    (&"PCI mem".into(), &"0".into()),
                    (&"System RAM".into(), &"1".into()),
                    (&"Kernel code".into(), &"2".into()),
                    (&"Reserved".into(), &"1".into())
                ]
            );
            assert_eq!(&result.rows[2][1..3], &[hex(0x1000), hex(0x1fff)]);
        }
        let mut result = linux.result(Plugin::Iomem);
        linux
            .resources(0x12000, &mut result, &Job::default(), 2)
            .unwrap();
        assert!(!result.complete);
        assert_eq!(result.rows.len(), 2);
        assert!(result.diagnostics[0].contains("上限"));
        isf.slide
            .store(0x1000, std::sync::atomic::Ordering::Relaxed);
        // Shift a symbol, not an inferred struct layout, to the same physical root.
        let mut isf = isf;
        isf.data["symbols"]["iomem_resource"]["address"] = json!(0x11000);
        assert_eq!(
            engine(&im, &isf)
                .run(Plugin::Iomem, &Job::default())
                .unwrap()
                .rows
                .len(),
            4
        );
    }
    #[test]
    fn corrupt_resource_children_names_and_ranges_keep_other_branches() {
        let (mut bytes, isf) = resources_fixture();
        put(&mut bytes, 0x12100, 0x800000); // missing name
        put(&mut bytes, 0x12220, 0x12100); // child points back to parent
        put(&mut bytes, 0x12208, 0x3000); // invalid start/end
        let im = image(&bytes);
        let r = engine(&im, &isf)
            .run(Plugin::Iomem, &Job::default())
            .unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 3);
        assert_eq!(r.rows[1][0], "[unreadable]");
        assert_eq!(r.rows[2][0], "Reserved");
        assert!(r.diagnostics.iter().any(|s| s.contains("循环")));
        assert!(r.diagnostics.iter().any(|s| s.contains("倒置")));
        put(&mut bytes, 0x12120, 0x800000); // missing child also leaves sibling accessible
        let im = image(&bytes);
        assert_eq!(
            engine(&im, &isf)
                .run(Plugin::Iomem, &Job::default())
                .unwrap()
                .rows
                .last()
                .unwrap()[0],
            "Reserved"
        );
    }
    #[test]
    fn resource_depth_limit_is_reported_without_recursive_stack_growth() {
        let (mut bytes, isf) = resources_fixture();
        bytes[0x3f000..0x3f002].copy_from_slice(b"r\0");
        for index in 0..1027 {
            let address = 0x12000 + index * 64;
            for (offset, value) in [
                (0, 0x3f000),
                (8, 0),
                (16, 1),
                (24, 0),
                (
                    32,
                    if index == 1026 {
                        0
                    } else {
                        (address + 64) as u64
                    },
                ),
                (40, 0),
            ] {
                put(&mut bytes, address + offset, value);
            }
        }
        let im = image(&bytes);
        let result = engine(&im, &isf)
            .run(Plugin::Iomem, &Job::default())
            .unwrap();
        assert!(!result.complete);
        assert_eq!(result.rows.len(), DEPTH_LIMIT + 1);
        assert!(result.diagnostics.iter().any(|s| s.contains("1024 层")));
    }
    fn ptrace_fixture() -> (Vec<u8>, crate::symbols::Isf) {
        let (mut bytes, mut isf) = fixture();
        isf.data["user_types"]["task_struct"]["size"] = json!(160);
        for (field, offset, ty) in [
            ("group_leader", 72, json!({"kind":"pointer"})),
            (
                "thread_group",
                80,
                json!({"kind":"struct","name":"list_head"}),
            ),
            ("ptrace", 96, json!({"kind":"base","name":"u64"})),
            ("parent", 104, json!({"kind":"pointer"})),
            ("ptraced", 112, json!({"kind":"struct","name":"list_head"})),
            (
                "ptrace_entry",
                128,
                json!({"kind":"struct","name":"list_head"}),
            ),
        ] {
            isf.data["user_types"]["task_struct"]["fields"][field] =
                json!({"offset":offset,"type":ty});
        }
        for a in [0xa000, 0xa100, 0xa200] {
            put(&mut bytes, a + 72, a as u64);
            for offset in [80, 112, 128] {
                put(&mut bytes, a + offset, (a + offset) as u64);
                put(&mut bytes, a + offset + 8, (a + offset) as u64);
            }
        }
        put(&mut bytes, 0xa210, 3); // TID 3 in process 1, not in global task list
        put(&mut bytes, 0xa218, 1);
        put(&mut bytes, 0xa220, 0x9000);
        bytes[0xa228..0xa22d].copy_from_slice(b"child");
        put(&mut bytes, 0xa248, 0xa000);
        for (at, next) in [
            (0xa050, 0xa250),
            (0xa058, 0xa250),
            (0xa250, 0xa050),
            (0xa258, 0xa050),
        ] {
            put(&mut bytes, at, next);
        }
        (bytes, isf)
    }
    #[test]
    fn ptrace_includes_nonleader_tracees_and_tracers_and_normal_empty() {
        let (mut bytes, isf) = ptrace_fixture();
        let im = image(&bytes);
        let r = engine(&im, &isf)
            .run(Plugin::Ptrace, &Job::default())
            .unwrap();
        assert!(r.complete && r.rows.is_empty(), "{:?}", r.diagnostics);
        put(&mut bytes, 0xa260, 1);
        put(&mut bytes, 0xa268, 0xa100);
        for (at, next) in [
            (0xa170, 0xa280),
            (0xa178, 0xa280),
            (0xa280, 0xa170),
            (0xa288, 0xa170),
        ] {
            put(&mut bytes, at, next);
        }
        let im = image(&bytes);
        let r = engine(&im, &isf)
            .run(Plugin::Ptrace, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows,
            vec![
                vec![
                    "kth".into(),
                    "2".into(),
                    "2".into(),
                    "[none]".into(),
                    "3".into(),
                    hex(0)
                ],
                vec![
                    "child".into(),
                    "1".into(),
                    "3".into(),
                    "2".into(),
                    "[none]".into(),
                    hex(1)
                ]
            ]
        );
        put(&mut bytes, 0xa280, 0xa280); // loop must retain the already parsed relationship
        let im = image(&bytes);
        let r = engine(&im, &isf)
            .run(Plugin::Ptrace, &Job::default())
            .unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 2);
        assert!(r.diagnostics.iter().any(|s| s.contains("循环")));
    }
    fn notifier_fixture() -> (Vec<u8>, crate::symbols::Isf) {
        let (mut bytes, mut isf) = fixture();
        for (name, address) in [
            ("keyboard_notifier_list", 0x12000),
            ("modules", 0x15000),
            ("_stext", 0x18000),
            ("_etext", 0x19000),
            ("keyboard_callback", 0x18000),
        ] {
            isf.data["symbols"][name] = json!({"address":address});
        }
        isf.data["user_types"]["atomic_notifier_head"] = structure(&[("head", 0)], 8);
        isf.data["user_types"]["notifier_block"] =
            structure(&[("notifier_call", 0), ("next", 8), ("priority", 16)], 24);
        isf.data["user_types"]["notifier_block"]["fields"]["priority"]["type"] =
            json!({"kind":"base","name":"int"});
        isf.data["base_types"]["int"] = json!({"size":4,"signed":true});
        isf.data["user_types"]["module"] = structure(
            &[
                ("list", 0),
                ("name", 16),
                ("module_core", 64),
                ("core_size", 72),
            ],
            128,
        );
        put(&mut bytes, 0x15000, 0x15100);
        put(&mut bytes, 0x15008, 0x15100);
        put(&mut bytes, 0x15100, 0x15000);
        put(&mut bytes, 0x15108, 0x15000);
        bytes[0x15110..0x15115].copy_from_slice(b"audit");
        put(&mut bytes, 0x15140, 0x1a000);
        put(&mut bytes, 0x15148, 0x1000);
        put(&mut bytes, 0x12000, 0x12100);
        for (address, callback, next) in [
            (0x12100, 0x18010, 0x12200),
            (0x12200, 0x1a010, 0x12300),
            (0x12300, 0x1f000, 0),
        ] {
            put(&mut bytes, address, callback);
            put(&mut bytes, address + 8, next);
            bytes[address + 16..address + 20].copy_from_slice(&(-2_i32).to_le_bytes());
        }
        (bytes, isf)
    }
    #[test]
    fn notifiers_resolve_kernel_modules_unknown_and_signed_priority() {
        let (mut bytes, isf) = notifier_fixture();
        let im = image(&bytes);
        let r = engine(&im, &isf)
            .run(Plugin::KeyboardNotifiers, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            &r.rows[0][1..4],
            &["kernel", "keyboard_callback+0x10", "-2"]
        );
        assert_eq!(&r.rows[1][1..3], &["audit", "[unknown]"]);
        assert_eq!(&r.rows[2][1..3], &["[unknown]", "[unknown]"]);
        put(&mut bytes, 0x12308, 0x12100);
        let im = image(&bytes);
        let r = engine(&im, &isf)
            .run(Plugin::KeyboardNotifiers, &Job::default())
            .unwrap();
        assert!(!r.complete && r.rows.len() == 3);
        put(&mut bytes, 0x12000, 0);
        let im = image(&bytes);
        let r = engine(&im, &isf)
            .run(Plugin::KeyboardNotifiers, &Job::default())
            .unwrap();
        assert!(r.complete && r.rows.is_empty());
    }
    #[test]
    fn unsupported_symbols_fields_and_cancellation_are_explicit() {
        let (bytes, isf) = fixture();
        let im = image(&bytes);
        for plugin in [
            Plugin::Iomem,
            Plugin::Ioports,
            Plugin::Ptrace,
            Plugin::KeyboardNotifiers,
        ] {
            let e = engine(&im, &isf).run(plugin, &Job::default()).unwrap_err();
            assert!(format!("{e:#}").contains("不支持"));
            let job = Job::default();
            job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            assert!(
                engine(&im, &isf)
                    .run(plugin, &job)
                    .unwrap_err()
                    .to_string()
                    .contains("cancelled")
            );
        }
    }
}
