//! Independent directional recovery of captured task-list objects.
use super::*;

fn evidence(result: &mut Results, direction: &str, address: u64, kind: &str, message: String) {
    result.complete = false;
    result
        .diagnostics
        .push(format!("任务链表 {direction} @ {address:#x}: {message}"));
    if !result.kernel_identity.is_object() {
        result.kernel_identity = serde_json::json!({"system": "linux"});
    }
    let identity = result.kernel_identity.as_object_mut().unwrap();
    identity
        .entry("task_recovery")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "source": "init_task.tasks", "direction": direction,
            "address": hex(address), "kind": kind, "message": message,
        }));
}

impl Linux<'_> {
    pub(super) fn process_list(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        self.require(&[
            ("task_struct", "tasks"),
            ("task_struct", "pid"),
            ("task_struct", "tgid"),
            ("task_struct", "comm"),
            ("task_struct", "real_parent"),
            ("list_head", "next"),
            ("list_head", "prev"),
        ])?;
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
                        Ok(back) if back == previous => (),
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
                if node == 0 || node & 7 != 0 || !visited.insert(node) || visited.len() > LIMIT {
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
                            end > 0 && !name[..end].iter().any(|b| b.is_ascii_control()),
                            "任务名称无效"
                        );
                        Ok((
                            pid,
                            tgid,
                            String::from_utf8_lossy(&name[..end]).into_owned(),
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
                                let parent = (|| -> Result<u64> {
                                    let parent =
                                        self.number(object, "task_struct", "real_parent")?;
                                    let pid = self.number(parent, "task_struct", "pid")?;
                                    ensure!(pid <= i32::MAX as u64, "非法 PPID");
                                    Ok(pid)
                                })();
                                let ppid = match parent {
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
        }
        // Preserve the established informational warning. A parent outside the
        // leader list can be a thread or exited task; it does not prove a gap.
        let ids: HashSet<_> = result.rows.iter().map(|r| r[0].as_str()).collect();
        let orphans: Vec<_> = result
            .rows
            .iter()
            .filter(|r| !r[2].is_empty() && r[2] != "0" && !ids.contains(r[2].as_str()))
            .map(|r| r[0].clone())
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
    /// The official entry point exposes supplementary fields without changing
    /// the established five-column pslist API and its cached history records.
    pub(super) fn process_details(&self, job: &Job) -> Result<Results> {
        self.process_details_with_options(&crate::analysis::Options::default(), job)
    }
    pub(super) fn process_details_with_options(
        &self,
        options: &crate::analysis::Options,
        job: &Job,
    ) -> Result<Results> {
        let mut result = self.process_list(Plugin::Pslist, job)?;
        if options.include_threads {
            let leaders = std::mem::take(&mut result.rows);
            let mut seen: HashSet<_> = leaders.iter().map(|r| r[4].clone()).collect();
            let mut tids: HashSet<_> = leaders.iter().map(|r| r[0].clone()).collect();
            for row in leaders {
                let leader = u64::from_str_radix(&row[4][2..], 16)?;
                result.rows.push(row);
                let nodes = match self.thread_nodes(leader, job) {
                    Ok(nodes) => nodes,
                    Err(error) => {
                        partial(&mut result, format!("thread group {leader:#x}"), error);
                        continue;
                    }
                };
                for task in nodes {
                    job.check()?;
                    if seen.contains(&hex(task)) {
                        continue;
                    }
                    let read = (|| -> Result<Vec<String>> {
                        let pid = self.number(task, "task_struct", "pid")?;
                        let tgid = self.number(task, "task_struct", "tgid")?;
                        ensure!(
                            pid > 0
                                && pid <= i32::MAX as u64
                                && tgid > 0
                                && tgid <= i32::MAX as u64,
                            "非法线程 PID/TGID"
                        );
                        let parent = self.number(task, "task_struct", "real_parent")?;
                        let ppid = self.number(parent, "task_struct", "tgid")?;
                        ensure!(ppid <= i32::MAX as u64, "非法线程 PPID");
                        let size = self.isf.size("task_struct", "comm")?;
                        ensure!((1..=256).contains(&size), "线程名称长度无效");
                        let mut bytes = vec![0; size];
                        self.vm
                            .read(self.field_address(task, "task_struct", "comm")?, &mut bytes)?;
                        let end = bytes
                            .iter()
                            .position(|b| *b == 0)
                            .context("线程名称未终止")?;
                        let name = String::from_utf8_lossy(&bytes[..end]).into_owned();
                        ensure!(
                            !name.is_empty() && !name.chars().any(char::is_control),
                            "线程名称无效"
                        );
                        Ok(vec![
                            pid.to_string(),
                            tgid.to_string(),
                            ppid.to_string(),
                            name,
                            hex(task),
                        ])
                    })();
                    match read {
                        Ok(row) => {
                            if !tids.insert(row[0].clone()) {
                                evidence(
                                    &mut result,
                                    "thread_group",
                                    task,
                                    "duplicate_pid",
                                    format!("重复线程 PID {}", row[0]),
                                );
                                continue;
                            }
                            seen.insert(hex(task));
                            result.rows.push(row);
                        }
                        Err(error) => partial(&mut result, format!("thread {task:#x}"), error),
                    }
                }
            }
        }
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
                .find(|r| r[0] == "BootTimeUnix")
                .context("缺少启动时间")?[1]
                .parse::<i128>()
                .context("启动时间无效")
        });
        for row in &mut result.rows {
            job.check()?;
            let task = u64::from_str_radix(&row[4][2..], 16)?;
            match self
                .number(task, "task_struct", "real_parent")
                .and_then(|parent| self.number(parent, "task_struct", "tgid"))
            {
                Ok(ppid) if ppid <= i32::MAX as u64 => row[2] = ppid.to_string(),
                other => {
                    row[2].clear();
                    result.complete = false;
                    result
                        .diagnostics
                        .push(format!("PID {} parent TGID: {other:?}", row[0]));
                }
            }
            if options.decorate_comm {
                match self.number(task, "task_struct", "flags") {
                    Ok(flags) if flags & 0x0020_0000 != 0 => row[3] = format!("[{}]", row[3]),
                    Ok(_) if row[0] != row[1] => row[3] = format!("{{{}}}", row[3]),
                    Ok(_) => (),
                    Err(error) => {
                        result.complete = false;
                        result
                            .diagnostics
                            .push(format!("PID {} thread flags: {error:#}", row[0]));
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
                            .push(format!("PID {} {field}: {error:#}", row[0]));
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
                        .push(format!("PID {} creation time: {error:#}", row[0]));
                }
            }
            row.push("Disabled".into());
        }
        Ok(result)
    }

    fn task_creation_time(&self, task: u64, boot_seconds: i128) -> Result<String> {
        let mut start = None;
        for field in ["start_boottime", "real_start_time", "start_time"] {
            if let Ok(layout) = self.isf.field("task_struct", field) {
                let nanos = if layout["type"]["kind"] == "struct" {
                    let name = layout["type"]["name"]
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
    seconds.trunc() as i128 * 1_000_000
        + ((seconds - seconds.trunc()) * 1_000_000.0).round_ties_even() as i128
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
