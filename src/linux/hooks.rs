//! Kernel hook surfaces: netfilter hooks, tracepoint probes, ftrace
//! callbacks and loaded eBPF programs.
use super::*;

const HOOK_LIMIT: usize = 65536;
/// NF_INET_NUMHOOKS; ARP uses the first three slots.
const INET_HOOKS: [&str; 5] = [
    "PRE_ROUTING",
    "LOCAL_IN",
    "FORWARD",
    "LOCAL_OUT",
    "POST_ROUTING",
];
const ARP_HOOKS: [&str; 3] = ["IN", "OUT", "FORWARD"];

pub(super) fn nf_protocol(family: u64) -> &'static str {
    match family {
        0 => "UNSPEC",
        1 => "INET",
        2 => "IPV4",
        3 => "ARP",
        5 => "NETDEV",
        7 => "BRIDGE",
        10 => "IPV6",
        12 => "DECNET",
        _ => "OTHER",
    }
}
pub(super) fn nf_hook(family: u64, hook: u64) -> String {
    let names: &[&str] = if family == 3 { &ARP_HOOKS } else { &INET_HOOKS };
    names
        .get(hook as usize)
        .map_or_else(|| hook.to_string(), |name| (*name).to_string())
}

impl Linux<'_> {
    /// netfilter: legacy global `nf_hooks` lists, or the per-namespace
    /// `nf_hook_entries` arrays used since 4.13.
    pub(super) fn netfilter(&self, r: &mut Results, job: &Job) -> Result<()> {
        let code = self.code_map(job)?;
        let push = |r: &mut Results,
                    namespace: String,
                    family: u64,
                    hook: u64,
                    priority: String,
                    handler: u64| {
            let (symbol, owner, reason) = code.describe(handler);
            r.rows.push(vec![
                namespace,
                nf_protocol(family).into(),
                nf_hook(family, hook),
                priority,
                hex(handler),
                symbol,
                owner,
                reason.into(),
            ]);
        };
        if let Ok(table) = self.isf.address("nf_hooks") {
            let families = self.isf.data["symbols"]["nf_hooks"]["type"]["count"]
                .as_u64()
                .context("nf_hooks 缺少协议数")?;
            let hooks = self.isf.data["symbols"]["nf_hooks"]["type"]["subtype"]["count"]
                .as_u64()
                .context("nf_hooks 缺少 hook 数")?;
            ensure!(families <= 32 && hooks <= 16, "nf_hooks 维度无效");
            let size = self.isf.data["user_types"]["list_head"]["size"]
                .as_u64()
                .unwrap_or(16);
            let offset = self.isf.offset("nf_hook_ops", "list")?;
            for family in 0..families {
                for hook in 0..hooks {
                    job.check()?;
                    let head = add(table, (family * hooks + hook) * size)?;
                    match self.list_objects(head, offset, job) {
                        Ok(ops) => {
                            for op in ops {
                                let read = (|| -> Result<(u64, i64)> {
                                    Ok((
                                        self.number(op, "nf_hook_ops", "hook")?,
                                        self.number(op, "nf_hook_ops", "priority")? as u32 as i32
                                            as i64,
                                    ))
                                })();
                                match read {
                                    Ok((handler, priority)) => push(
                                        r,
                                        "global".into(),
                                        family,
                                        hook,
                                        priority.to_string(),
                                        handler,
                                    ),
                                    Err(e) => partial(r, format!("nf_hook_ops {op:#x}"), e),
                                }
                            }
                        }
                        Err(e) => partial(r, format!("nf_hooks[{family}][{hook}]"), e),
                    }
                }
            }
            return Ok(());
        }
        ensure!(
            self.isf.field("netns_nf", "hooks_ipv4").is_ok(),
            "不支持: 缺少 nf_hooks 与 netns_nf.hooks_ipv4"
        );
        for namespace in self.net_namespaces(job)? {
            let nf = self.field_address(namespace, "net", "nf")?;
            for (family, field) in [
                (2u64, "hooks_ipv4"),
                (10, "hooks_ipv6"),
                (3, "hooks_arp"),
                (7, "hooks_bridge"),
            ] {
                if self.isf.field("netns_nf", field).is_err() {
                    continue;
                }
                let count = self.isf.field("netns_nf", field)?["type"]["count"]
                    .as_u64()
                    .context("netns_nf hook 数缺失")?;
                ensure!(count <= 16, "netns_nf hook 数无效");
                let base = self.field_address(nf, "netns_nf", field)?;
                for hook in 0..count {
                    job.check()?;
                    let read = (|| -> Result<Vec<(u64, String)>> {
                        let entries = self.vm.uint(add(base, hook * 8)?, 8)?;
                        if entries == 0 {
                            return Ok(vec![]);
                        }
                        let n = self.number(entries, "nf_hook_entries", "num_hook_entries")?;
                        ensure!(n as usize <= HOOK_LIMIT, "nf_hook_entries 数量超限");
                        let hooks = self.field_address(entries, "nf_hook_entries", "hooks")?;
                        let size = self.isf.data["user_types"]["nf_hook_entry"]["size"]
                            .as_u64()
                            .context("nf_hook_entry 大小缺失")?;
                        // The original nf_hook_ops pointers follow the hooks array.
                        let origin = add(hooks, n * size)?;
                        let mut out = Vec::new();
                        for i in 0..n {
                            let handler =
                                self.number(add(hooks, i * size)?, "nf_hook_entry", "hook")?;
                            let priority = self
                                .vm
                                .uint(add(origin, i * 8)?, 8)
                                .and_then(|ops| self.number(ops, "nf_hook_ops", "priority"))
                                .map_or_else(|_| "-".into(), |p| (p as u32 as i32).to_string());
                            out.push((handler, priority));
                        }
                        Ok(out)
                    })();
                    match read {
                        Ok(hooks) => {
                            for (handler, priority) in hooks {
                                push(r, hex(namespace), family, hook, priority, handler);
                            }
                        }
                        Err(e) => partial(r, format!("netns {namespace:#x} {field}[{hook}]"), e),
                    }
                }
            }
        }
        Ok(())
    }
    fn net_namespaces(&self, job: &Job) -> Result<Vec<u64>> {
        match self.isf.address("net_namespace_list") {
            Ok(head) => self.list_objects(head, self.isf.offset("net", "list")?, job),
            Err(_) => Ok(vec![self.isf.address("init_net")?]),
        }
    }
    /// tracepoints: probes attached to built-in kernel tracepoints.
    pub(super) fn tracepoints(&self, r: &mut Results, job: &Job) -> Result<()> {
        let start = self
            .isf
            .address("__start___tracepoints_ptrs")
            .context("不支持: 缺少 __start___tracepoints_ptrs")?;
        let stop = self.isf.address("__stop___tracepoints_ptrs")?;
        ensure!(
            start <= stop && (stop - start) / 4 <= HOOK_LIMIT as u64,
            "tracepoint 指针表无效"
        );
        // Since 4.19 the table may hold 32-bit relative offsets.
        let relative = self.isf.data["metadata"]["zero"]["tracepoint_relative"]
            .as_bool()
            .unwrap_or(false);
        let width = if relative { 4 } else { 8 };
        let code = self.code_map(job)?;
        let size = self.isf.data["user_types"]["tracepoint_func"]["size"]
            .as_u64()
            .context("tracepoint_func 大小缺失")?;
        for slot in (start..stop).step_by(width) {
            job.check()?;
            let read = (|| -> Result<()> {
                let point = if relative {
                    slot.wrapping_add_signed(i64::from(self.vm.uint(slot, 4)? as u32 as i32))
                } else {
                    self.vm.uint(slot, 8)?
                };
                let funcs = self.number(point, "tracepoint", "funcs")?;
                if funcs == 0 {
                    return Ok(());
                }
                let name = self.kernel_text(self.number(point, "tracepoint", "name")?, 256)?;
                for i in 0..HOOK_LIMIT as u64 {
                    let entry = add(funcs, i * size)?;
                    let handler = self.number(entry, "tracepoint_func", "func")?;
                    if handler == 0 {
                        break;
                    }
                    let (symbol, owner, reason) = code.describe(handler);
                    r.rows.push(vec![
                        name.clone(),
                        hex(handler),
                        symbol,
                        owner,
                        reason.into(),
                    ]);
                }
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                partial(r, format!("tracepoint slot {slot:#x}"), e);
            }
        }
        Ok(())
    }
    /// ftrace: registered ftrace_ops callbacks.
    pub(super) fn ftrace(&self, r: &mut Results, job: &Job) -> Result<()> {
        let head = self
            .isf
            .address("ftrace_ops_list")
            .context("不支持: 缺少 ftrace_ops_list")?;
        let end = self.isf.address("ftrace_list_end").unwrap_or(0);
        let code = self.code_map(job)?;
        let mut ops = self.vm.uint(head, 8)?;
        let mut seen = HashSet::new();
        while ops != 0 && ops != end {
            job.check()?;
            ensure!(
                seen.insert(ops) && seen.len() <= HOOK_LIMIT,
                "ftrace_ops 链表循环或超限"
            );
            let handler = self.number(ops, "ftrace_ops", "func")?;
            let (symbol, owner, reason) = code.describe(handler);
            r.rows
                .push(vec![hex(ops), hex(handler), symbol, owner, reason.into()]);
            ops = self.number(ops, "ftrace_ops", "next")?;
        }
        Ok(())
    }
    /// perf_events: events each process owns and their overflow handlers.
    pub(super) fn perf_events(&self, job: &Job) -> Result<Results> {
        self.require(&[
            ("task_struct", "perf_event_list"),
            ("perf_event", "owner_entry"),
            ("perf_event", "attr"),
            ("perf_event_attr", "type"),
            ("perf_event_attr", "config"),
        ])?;
        let (mut r, tasks) = self.tasks(Plugin::PerfEvents, job)?;
        let code = self.code_map(job)?;
        let offset = self.isf.offset("perf_event", "owner_entry")?;
        let handler_field = self.isf.field("perf_event", "overflow_handler").is_ok();
        for task in tasks {
            job.check()?;
            let read = (|| -> Result<()> {
                let head = self.field_address(task.address, "task_struct", "perf_event_list")?;
                for event in self.list_objects(head, offset, job)? {
                    let attr = self.field_address(event, "perf_event", "attr")?;
                    let handler = if handler_field {
                        self.number(event, "perf_event", "overflow_handler")?
                    } else {
                        0
                    };
                    let (symbol, owner, reason) = if handler == 0 {
                        ("-".into(), "-".into(), "NoOverflowHandler")
                    } else {
                        code.describe(handler)
                    };
                    r.rows.push(vec![
                        task.pid.clone(),
                        task.name.clone(),
                        hex(event),
                        self.number(attr, "perf_event_attr", "type")?.to_string(),
                        format!("{:#x}", self.number(attr, "perf_event_attr", "config")?),
                        hex(handler),
                        symbol,
                        owner,
                        reason.into(),
                    ]);
                }
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                partial(&mut r, format!("PID {} perf_event_list", task.pid), e);
            }
        }
        Ok(r)
    }
    /// ebpf: programs indexed by `prog_idr`.
    pub(super) fn ebpf(&self, r: &mut Results, job: &Job) -> Result<()> {
        let idr = self
            .isf
            .address("prog_idr")
            .context("不支持: 缺少 prog_idr（内核早于 4.13 或未启用 BPF syscall）")?;
        let xa = self.field_address(idr, "idr", "idr_rt")?;
        let types = self.isf.data["enums"]["bpf_prog_type"]["constants"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        for program in self.xarray_entries(xa, job)? {
            job.check()?;
            let read = (|| -> Result<Vec<String>> {
                let aux = self.number(program, "bpf_prog", "aux")?;
                let kind = self.number(program, "bpf_prog", "type")?;
                let name = types
                    .iter()
                    .find(|(_, value)| value.as_u64() == Some(kind))
                    .map_or_else(|| kind.to_string(), |(name, _)| name.clone());
                Ok(vec![
                    self.number(aux, "bpf_prog_aux", "id")?.to_string(),
                    self.string(aux, "bpf_prog_aux", "name")?,
                    name,
                    hex(program),
                    hex(self.number(program, "bpf_prog", "bpf_func")?),
                ])
            })();
            match read {
                Ok(row) => r.rows.push(row),
                Err(e) => partial(r, format!("bpf_prog {program:#x}"), e),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};
    use serde_json::json;
    fn put(bytes: &mut [u8], address: usize, value: u64) {
        bytes[address..address + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn u64_field(offset: u64) -> serde_json::Value {
        json!({"offset":offset,"type":{"kind":"base","name":"u64"}})
    }
    /// Kernel text 0x18000..0x19000 with a "handler" symbol and no modules.
    fn kernel() -> (Vec<u8>, crate::symbols::Isf) {
        let (mut bytes, mut isf) = fixture();
        for (name, address) in [
            ("_stext", 0x18000),
            ("_etext", 0x19000),
            ("handler", 0x18000),
            ("modules", 0x31000),
        ] {
            isf.data["symbols"][name] = json!({"address":address});
        }
        isf.data["user_types"]["module"] = json!({"size":128,"fields":{
            "list":{"offset":0,"type":{"kind":"struct","name":"list_head"}},
        }});
        put(&mut bytes, 0x31000, 0x31000);
        put(&mut bytes, 0x31008, 0x31000);
        (bytes, isf)
    }

    #[test]
    fn perf_events_list_owned_events_and_attribute_handlers() {
        let (mut b, mut isf) = kernel();
        let task = &mut isf.data["user_types"]["task_struct"];
        task["size"] = json!(176);
        task["fields"]["perf_event_list"] =
            json!({"offset":160,"type":{"kind":"struct","name":"list_head"}});
        isf.data["user_types"]["perf_event"] = json!({"size":64,"fields":{
            "owner_entry":{"offset":0,"type":{"kind":"struct","name":"list_head"}},
            "attr":{"offset":16,"type":{"kind":"struct","name":"perf_event_attr"}},
            "overflow_handler":u64_field(40),
        }});
        isf.data["user_types"]["perf_event_attr"] =
            json!({"size":16,"fields":{"type":u64_field(0),"config":u64_field(8)}});
        // init (0xa000) owns one event with a hooked handler; kth owns none.
        for (head, first) in [(0xa0a0usize, 0x36000u64), (0xa1a0, 0xa1a0)] {
            put(&mut b, head, first);
            put(&mut b, head + 8, first);
        }
        put(&mut b, 0x36000, 0xa0a0);
        put(&mut b, 0x36008, 0xa0a0);
        put(&mut b, 0x36010, 4);
        put(&mut b, 0x36018, 0x3c);
        put(&mut b, 0x36028, 0x1f000);
        let im = image(&b);
        let r = engine(&im, &isf)
            .run(Plugin::PerfEvents, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(&r.rows[0][..5], ["1", "init", &hex(0x36000), "4", "0x3c"]);
        assert_eq!(r.rows[0][8], "OutsideKnownExecutableRanges");
    }
    #[test]
    fn hook_names_follow_netfilter_numbering() {
        assert_eq!(nf_protocol(2), "IPV4");
        assert_eq!(nf_hook(2, 1), "LOCAL_IN");
        assert_eq!(nf_hook(3, 1), "OUT");
        assert_eq!(nf_hook(10, 7), "7");
    }
    #[test]
    fn legacy_nf_hooks_report_priority_and_owner() {
        let (mut b, mut isf) = kernel();
        isf.data["symbols"]["nf_hooks"] = json!({"address":0x32000,"type":{"kind":"array","count":3,"subtype":{"kind":"array","count":5,"subtype":{"kind":"struct","name":"list_head"}}}});
        isf.data["base_types"]["int"] = json!({"size":4,"signed":true});
        isf.data["user_types"]["nf_hook_ops"] = json!({"size":40,"fields":{
            "list":{"offset":0,"type":{"kind":"struct","name":"list_head"}},
            "hook":u64_field(16),
            "priority":{"offset":24,"type":{"kind":"base","name":"int"}},
        }});
        // Every list head is empty except IPV4 (family 2) LOCAL_IN (hook 1).
        for i in 0..15 {
            let head = 0x32000 + i * 16;
            put(&mut b, head, head as u64);
            put(&mut b, head + 8, head as u64);
        }
        let head = 0x32000 + (2 * 5 + 1) * 16;
        put(&mut b, head, 0x33000);
        put(&mut b, head + 8, 0x33000);
        put(&mut b, 0x33000, head as u64);
        put(&mut b, 0x33008, head as u64);
        put(&mut b, 0x33010, 0x1f000);
        b[0x33018..0x3301c].copy_from_slice(&(-200i32).to_le_bytes());
        let im = image(&b);
        let r = engine(&im, &isf)
            .run(Plugin::Netfilter, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows,
            [[
                "global",
                "IPV4",
                "LOCAL_IN",
                "-200",
                &hex(0x1f000),
                "_etext+0x6000",
                "[unknown]",
                "OutsideKnownExecutableRanges"
            ]
            .map(String::from)
            .to_vec()]
        );
    }
    #[test]
    fn tracepoint_probes_ftrace_ops_and_unsupported_layouts() {
        let (mut b, mut isf) = kernel();
        isf.data["symbols"]["__start___tracepoints_ptrs"] = json!({"address":0x34000});
        isf.data["symbols"]["__stop___tracepoints_ptrs"] = json!({"address":0x34010});
        isf.data["user_types"]["tracepoint"] =
            json!({"size":32,"fields":{"name":u64_field(0),"funcs":u64_field(8)}});
        isf.data["user_types"]["tracepoint_func"] =
            json!({"size":16,"fields":{"func":u64_field(0)}});
        put(&mut b, 0x34000, 0x34100); // probed tracepoint
        put(&mut b, 0x34008, 0x34200); // no probes
        put(&mut b, 0x34100, 0x34300);
        put(&mut b, 0x34108, 0x34400);
        b[0x34300..0x3430c].copy_from_slice(b"sched_switch");
        put(&mut b, 0x34400, 0x18040);
        put(&mut b, 0x34410, 0x1f000);
        let im = image(&b);
        let r = engine(&im, &isf)
            .run(Plugin::Tracepoints, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        let rows: Vec<_> = r
            .rows
            .iter()
            .map(|row| (row[0].as_str(), row[4].as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("sched_switch", "KernelText"),
                ("sched_switch", "OutsideKnownExecutableRanges")
            ]
        );
        isf.data["symbols"]["ftrace_ops_list"] = json!({"address":0x35000});
        isf.data["symbols"]["ftrace_list_end"] = json!({"address":0x35800});
        isf.data["user_types"]["ftrace_ops"] =
            json!({"size":16,"fields":{"func":u64_field(0),"next":u64_field(8)}});
        put(&mut b, 0x35000, 0x35100);
        put(&mut b, 0x35100, 0x18080);
        put(&mut b, 0x35108, 0x35800);
        let im = image(&b);
        let r = engine(&im, &isf)
            .run(Plugin::Ftrace, &Job::default())
            .unwrap();
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0][2], "handler+0x80");
        for plugin in [Plugin::Ebpf, Plugin::Netfilter] {
            let e = engine(&im, &isf).run(plugin, &Job::default()).unwrap_err();
            assert!(format!("{e:#}").contains("不支持"), "{plugin:?}");
        }
    }
}
