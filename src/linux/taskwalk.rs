//! Independent directional recovery of captured task-list objects.
use super::*;
use crate::bytes::JsonKey as _;
use crate::bytes::float_to_i128;

fn evidence(result: &mut Results, direction: &str, address: u64, kind: &str, message: String) {
    result.complete = false;
    result
        .diagnostics
        .push(format!("任务链表 {direction} @ {address:#x}: {message}"));
    if !result.kernel_identity.is_object() {
        result.kernel_identity = serde_json::json!({"system": "linux"});
    }
    if let Some(recoveries) = result.kernel_identity.as_object_mut().and_then(|identity| {
        identity
            .entry("task_recovery")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
    }) {
        recoveries.push(serde_json::json!({
            "source": "init_task.tasks", "direction": direction,
            "address": hex(address), "kind": kind, "message": message,
        }));
    }
}

impl Linux<'_> {
    pub(super) fn process_list(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        self.process_list_with_parent(plugin, true, job)
    }
    #[cfg(test)]
    pub(super) fn process_identities(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        self.process_list_with_parent(plugin, false, job)
    }
    fn process_list_with_parent(
        &self,
        plugin: Plugin,
        read_parent: bool,
        job: &Job,
    ) -> Result<Results> {
        self.require(&[
            ("task_struct", "tasks"),
            ("task_struct", "pid"),
            ("task_struct", "tgid"),
            ("task_struct", "comm"),
            ("task_struct", "real_parent"),
            ("list_head", "next"),
            ("list_head", "prev"),
        ])?;
        let width = self.isf.size("list_head", "next")?;
        ensure!(matches!(width, 4 | 8), "任务链指针宽度无效");
        let offset = self.isf.offset("task_struct", "tasks")?;
        let head = self.field_address(self.isf.address("init_task")?, "task_struct", "tasks")?;
        let mut result = self.result(plugin);
        let mut emitted = HashSet::new();
        let mut pids = std::collections::HashMap::new();
        let comm_size = self.isf.size("task_struct", "comm")?;
        ensure!((1..=256).contains(&comm_size), "任务名称长度无效");
        for (direction, opposite) in [("next", "prev"), ("prev", "next")] {
            let mut previous = head;
            let mut current = head;
            let mut visited = HashSet::new();
            let diagnostics_before = result.diagnostics.len();
            let mut closed_at_head = false;
            loop {
                job.check()?;
                let link = self.number(current, "list_head", direction);
                let node = match link {
                    Ok(node) => node,
                    Err(error) => {
                        evidence(
                            &mut result,
                            direction,
                            current,
                            "unreadable_link",
                            format!("{error:#}"),
                        );
                        break;
                    }
                };
                if node == head {
                    match self.number(head, "list_head", opposite) {
                        Ok(back) if back == previous => closed_at_head = true,
                        other => evidence(
                            &mut result,
                            direction,
                            head,
                            "head_backlink",
                            format!("表头回指不一致: expected={previous:#x}, actual={other:?}"),
                        ),
                    }
                    break;
                }
                if node == 0
                    || node & (width as u64 - 1) != 0
                    || !visited.insert(node)
                    || visited.len() > LIMIT
                {
                    evidence(
                        &mut result,
                        direction,
                        node,
                        "invalid_link",
                        "链表指针无效、循环未回到表头或超过上限".into(),
                    );
                    break;
                }
                match self.number(node, "list_head", opposite) {
                    Ok(back) if back == previous => (),
                    other => evidence(
                        &mut result,
                        direction,
                        node,
                        "backlink",
                        format!("相邻回指不一致: expected={previous:#x}, actual={other:?}"),
                    ),
                }
                let object = match node.checked_sub(offset) {
                    Some(object) => object,
                    None => {
                        evidence(
                            &mut result,
                            direction,
                            node,
                            "invalid_object",
                            "任务对象地址下溢".into(),
                        );
                        break;
                    }
                };
                // Each direction follows its own recorded links even if the
                // other direction has already emitted this object's identity.
                if !emitted.contains(&object) {
                    let identity = (|| -> Result<(u64, u64, String)> {
                        let pid = self.number(object, "task_struct", "pid")?;
                        let tgid = self.number(object, "task_struct", "tgid")?;
                        ensure!(
                            pid > 0
                                && pid <= i32::MAX as u64
                                && tgid > 0
                                && tgid <= i32::MAX as u64,
                            "非法 PID/TGID @ {object:#x}"
                        );
                        let mut name = vec![0; comm_size];
                        self.vm.read(
                            self.field_address(object, "task_struct", "comm")?,
                            &mut name,
                        )?;
                        let end = name
                            .iter()
                            .position(|b| *b == 0)
                            .context("任务名称未终止")?;
                        ensure!(
                            end > 0 && !name.at(..end)?.iter().any(|b| b.is_ascii_control()),
                            "任务名称无效"
                        );
                        Ok((
                            pid,
                            tgid,
                            String::from_utf8_lossy(name.at(..end)?).into_owned(),
                        ))
                    })();
                    match identity {
                        Ok((pid, tgid, name)) => {
                            if let Some(other) = pids.get(&pid) {
                                evidence(
                                    &mut result,
                                    direction,
                                    object,
                                    "duplicate_pid",
                                    format!("重复 PID {pid}: first={other:#x}"),
                                );
                            } else {
                                let ppid = if !read_parent {
                                    "0".into()
                                } else {
                                    let parent = (|| -> Result<u64> {
                                        let parent =
                                            self.number(object, "task_struct", "real_parent")?;
                                        let pid = self.number(parent, "task_struct", "pid")?;
                                        ensure!(pid <= i32::MAX as u64, "非法 PPID");
                                        Ok(pid)
                                    })();
                                    match parent {
                                        Ok(pid) => pid.to_string(),
                                        Err(error) => {
                                            evidence(
                                                &mut result,
                                                direction,
                                                object,
                                                "unreadable_parent",
                                                format!("父进程读取失败: {error:#}"),
                                            );
                                            String::new()
                                        }
                                    }
                                };
                                result.rows.push(vec![
                                    pid.to_string(),
                                    tgid.to_string(),
                                    ppid,
                                    name,
                                    hex(object),
                                ]);
                                emitted.insert(object);
                                pids.insert(pid, object);
                            }
                        }
                        Err(error) => evidence(
                            &mut result,
                            direction,
                            object,
                            "invalid_task",
                            format!("{error:#}"),
                        ),
                    }
                }
                previous = node;
                current = node;
            }
            // If the forward pass verified every backlink and closed cleanly at
            // `head` with zero diagnostics, the backward ring is identical.
            if direction == "next"
                && closed_at_head
                && result.diagnostics.len() == diagnostics_before
            {
                break;
            }
        }
        // Preserve the established informational warning. A parent outside the
        // leader list can be a thread or exited task; it does not prove a gap.
        let ids: HashSet<_> = result.rows.iter().map(|r| r.cell(0)).collect();
        let orphans: Vec<_> = result
            .rows
            .iter()
            .filter(|r| !r.cell(2).is_empty() && r.cell(2) != "0" && !ids.contains(r.cell(2)))
            .map(|r| r.cell(0).to_owned())
            .collect();
        if !orphans.is_empty() {
            result.diagnostics.push(format!(
                "父进程不在 tasks 链表（可能为线程或已退出）: {}",
                orphans.join(",")
            ));
        }
        job.check()?;
        job.report(format!(
            "{}: {} 条 · 正反向任务恢复",
            plugin.name(),
            result.rows.len()
        ));
        Ok(result)
    }
}

impl Linux<'_> {
    /// Apply PID selection to leaders before enumerating their entire groups,
    /// matching the reference even when a recovered thread's TGID is stale.
    pub(super) fn selected_task_list_with_threads(
        &self,
        include_threads: bool,
        pids: &std::collections::BTreeSet<u32>,
        job: &Job,
    ) -> Result<Results> {
        let mut result = self.reference_process_rows(Plugin::Pslist, job)?;
        if !pids.is_empty() {
            result.rows.retain(|r| {
                r.cell(0)
                    .parse::<u32>()
                    .is_ok_and(|pid| pids.contains(&pid))
            });
        }
        if include_threads {
            let leaders = std::mem::take(&mut result.rows);
            for row in leaders {
                let leader = u64::from_str_radix(&row.at(4)?[2..], 16)?;
                result.rows.push(row);
                for task in self.reference_threads(leader, job)? {
                    result.rows.push(self.reference_task_row(task)?);
                }
            }
        }
        Ok(result)
    }
    pub(super) fn process_details(&self, job: &Job) -> Result<Results> {
        self.process_details_with_options(&crate::analysis::Options::default(), None, job)
    }
    pub(super) fn process_details_with_options(
        &self,
        options: &crate::analysis::Options,
        dump: Option<&crate::dump::DumpOptions>,
        job: &Job,
    ) -> Result<Results> {
        let pids = options.pids.iter().copied().chain(options.pid).collect();
        let mut result =
            self.selected_task_list_with_threads(options.include_threads, &pids, job)?;
        result.plugin = Plugin::LinuxPslist.name().into();
        result.columns = Plugin::LinuxPslist
            .descriptor()
            .columns
            .iter()
            .map(|s| (*s).into())
            .collect();
        let mut boot = self.result(Plugin::Boottime);
        let boot_seconds = self.boottime(&mut boot).and_then(|()| {
            boot.rows
                .iter()
                .find(|r| r.cell(0) == "BootTimeUnix")
                .context("缺少启动时间")?
                .at(1)?
                .parse::<i128>()
                .context("启动时间无效")
        });
        let mut total_dumped = 0u64;
        let mut rows = std::mem::take(&mut result.rows);
        for row in &mut rows {
            job.check()?;
            let task = u64::from_str_radix(&row.at(4)?[2..], 16)?;
            match self
                .number(task, "task_struct", "real_parent")
                .and_then(|parent| self.number(parent, "task_struct", "tgid"))
            {
                Ok(ppid) if ppid <= i32::MAX as u64 => *row.at_mut(2)? = ppid.to_string(),
                other => {
                    row.at_mut(2)?.clear();
                    result.complete = false;
                    result
                        .diagnostics
                        .push(format!("PID {} parent TGID: {other:?}", *row.at(0)?));
                }
            }
            if options.decorate_comm {
                match self.number(task, "task_struct", "flags") {
                    Ok(flags) if flags & 0x0020_0000 != 0 => {
                        *row.at_mut(3)? = format!("[{}]", *row.at(3)?)
                    }
                    Ok(_) if *row.at(0)? != *row.at(1)? => {
                        *row.at_mut(3)? = format!("{{{}}}", *row.at(3)?)
                    }
                    Ok(_) => (),
                    Err(error) => {
                        result.complete = false;
                        result
                            .diagnostics
                            .push(format!("PID {} thread flags: {error:#}", *row.at(0)?));
                    }
                }
            }
            let cred = self.number(task, "task_struct", "cred");
            for field in ["uid", "gid", "euid", "egid"] {
                let value = cred
                    .as_ref()
                    .map_err(|e| anyhow::anyhow!("{e:#}"))
                    .and_then(|cred| {
                        ensure!(*cred != 0, "cred 为空");
                        self.credential(*cred, field)
                    });
                match value {
                    Ok(value) => row.push(value.to_string()),
                    Err(error) => {
                        row.push(String::new());
                        result.complete = false;
                        result
                            .diagnostics
                            .push(format!("PID {} {field}: {error:#}", *row.at(0)?));
                    }
                }
            }
            let creation = boot_seconds
                .as_ref()
                .map_err(|e| anyhow::anyhow!("{e:#}"))
                .and_then(|boot| self.task_creation_time(task, *boot));
            match creation {
                Ok(time) => row.push(time),
                Err(error) => {
                    row.push(String::new());
                    result.complete = false;
                    result
                        .diagnostics
                        .push(format!("PID {} creation time: {error:#}", *row.at(0)?));
                }
            }
            let file_output = if let Some(dump_opts) = dump {
                let pid_str = row.at(0)?.clone();
                let comm_str = row.at(3)?.clone();
                self.dump_task_executable(
                    task,
                    &pid_str,
                    &comm_str,
                    dump_opts,
                    &mut total_dumped,
                    &mut result,
                    job,
                )
            } else {
                "Disabled".into()
            };
            row.push(file_output);
        }
        result.rows = rows;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn dump_task_executable(
        &self,
        task: u64,
        pid: &str,
        comm: &str,
        dump: &crate::dump::DumpOptions,
        total_dumped: &mut u64,
        result: &mut Results,
        job: &Job,
    ) -> String {
        use std::io::Write;
        let run = (|| -> Result<Option<String>> {
            let mm = self.number(task, "task_struct", "mm")?;
            if mm == 0 {
                return Ok(None);
            }
            let Some(vm) = self.process_vm(task)? else {
                return Ok(None);
            };
            let exe_file = self.number(mm, "mm_struct", "exe_file").unwrap_or(0);
            let nodes = self.vma_nodes(mm, job, result)?;
            let mut target_range = None;
            for node in nodes {
                job.check()?;
                let Ok(start) = self.number(node, "vm_area_struct", "vm_start") else {
                    continue;
                };
                let Ok(end) = self.number(node, "vm_area_struct", "vm_end") else {
                    continue;
                };
                if start >= end {
                    continue;
                }
                let file = self.number(node, "vm_area_struct", "vm_file").unwrap_or(0);
                let mut magic = [0u8; 4];
                let is_elf = vm.read(start, &mut magic).is_ok() && magic == *b"\x7fELF";
                if !is_elf {
                    continue;
                }
                if exe_file != 0 && file == exe_file {
                    target_range = Some((start, end));
                    break;
                }
                if target_range.is_none() {
                    target_range = Some((start, end));
                }
            }
            let Some((start, end)) = target_range else {
                return Ok(None);
            };
            let size = end.saturating_sub(start);
            ensure!(
                total_dumped
                    .checked_add(size)
                    .is_some_and(|n| n <= crate::dump::MAX_DUMP_BYTES),
                "pslist 导出累计超过 256 MiB 上限"
            );
            crate::dump::directory(&dump.directory)?;
            let mut tmp = tempfile::NamedTempFile::new_in(&dump.directory)?;
            let mut offset = 0u64;
            let mut buf = [0u8; 4096];
            let mut missing = 0u64;
            while offset < size {
                job.check()?;
                let chunk = usize::try_from((size - offset).min(4096))?;
                if vm.read(start + offset, buf.at_mut(..chunk)?).is_err() {
                    buf.at_mut(..chunk)?.fill(0);
                    missing += 1;
                }
                tmp.write_all(buf.at(..chunk)?)?;
                offset += chunk as u64;
            }
            if missing > 0 {
                result.complete = false;
                result.diagnostics.push(format!(
                    "PID {pid} ELF 导出 {start:#x}: {missing} 页不可读已补零"
                ));
            }
            job.check()?;
            tmp.as_file().sync_all()?;
            let safe_comm: String = comm
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                        c
                    } else {
                        '_'
                    }
                })
                .take(32)
                .collect();
            let filename = format!("pid.{pid}.{safe_comm}.{start:#x}.elf");
            let path = dump.directory.join(&filename);
            tmp.persist_noclobber(&path).map_err(|e| e.error)?;
            *total_dumped += size;
            Ok(Some(filename))
        })();
        match run {
            Ok(Some(name)) => name,
            Ok(None) => "N/A".into(),
            Err(e) => {
                result.complete = false;
                result
                    .diagnostics
                    .push(format!("PID {pid} 导出失败: {e:#}"));
                "Error outputting file".into()
            }
        }
    }

    fn task_creation_time(&self, task: u64, boot_seconds: i128) -> Result<String> {
        let mut start = None;
        for field in ["start_boottime", "real_start_time", "start_time"] {
            if let Ok(layout) = self.isf.field("task_struct", field) {
                let nanos = if *layout["type"].key("kind") == "struct" {
                    let name = layout["type"]
                        .key("name")
                        .as_str()
                        .context("开始时间结构无类型")?;
                    let address = self.field_address(task, "task_struct", field)?;
                    let seconds = self.number(address, name, "tv_sec")? as i64 as i128;
                    let ns = self.number(address, name, "tv_nsec")? as i64 as i128;
                    ensure!((0..1_000_000_000).contains(&ns), "开始时间纳秒无效");
                    seconds * 1_000_000_000 + ns
                } else {
                    self.number(task, "task_struct", field)? as i128
                };
                ensure!(nanos >= 0, "开始时间为负");
                start = Some(nanos);
                break;
            }
        }
        let nanos = start.context("缺少任务开始时间字段")?;
        // The reference's datetime interface represents microseconds. Use the
        // same ties-to-even rounding, without losing high address precision.
        let micros = start_time_micros(nanos);
        let total = boot_seconds
            .checked_mul(1_000_000)
            .and_then(|b| b.checked_add(micros))
            .context("创建时间溢出")?;
        let seconds = i64::try_from(total.div_euclid(1_000_000))?;
        ensure!(
            (-62_135_596_800..=253_402_300_799).contains(&seconds),
            "创建时间超出 datetime 年份 1-9999 范围"
        );
        let date = crate::report::utc(seconds).replace(' ', "T");
        let date = date.strip_suffix("TUTC").context("UTC 时间格式无效")?;
        Ok(format!("{date}.{:06}+00:00", total.rem_euclid(1_000_000)))
    }
}

/// Match the reference datetime boundary: form floating-point seconds from a
/// timespec, then round its fractional second to microseconds. Rounding the
/// integer nanosecond total directly differs at long-uptime half-microseconds.
fn start_time_micros(nanos: i128) -> i128 {
    let seconds = (nanos / 1_000_000_000) as f64 + (nanos % 1_000_000_000) as f64 / 1_000_000_000.0;
    float_to_i128(seconds.trunc()) * 1_000_000
        + float_to_i128(((seconds - seconds.trunc()) * 1_000_000.0).round_ties_even())
}

#[cfg(test)]
mod tests {
    #[test]
    fn datetime_microseconds_match_reference_at_long_uptime_boundaries() {
        // Expected values independently obtained with CPython timedelta from
        // the pinned reference's seconds/nanoseconds representation.
        for (nanos, micros) in [
            (500, 0),
            (1500, 2),
            (2500, 2),
            (1_234_567_890_123_500, 1_234_567_890_124),
            (1_234_567_890_124_500, 1_234_567_890_125),
            (1_234_567_890_125_500, 1_234_567_890_126),
        ] {
            assert_eq!(super::start_time_micros(nanos), micros);
        }
    }
}
