//! Kernel-wide views: printk, resources, notifiers, modules, syscalls and cross-views.
use super::*;
impl Linux<'_> {
    pub(crate) fn kernel_text(&self, ptr: u64, limit: usize) -> Result<String> {
        ensure!(ptr != 0, "字符串指针为空");
        let mut bytes = Vec::new();
        for i in 0..limit {
            let b = self
                .vm
                .uint(ptr.checked_add(i as u64).context("字符串地址溢出")?, 1)?
                as u8;
            if b == 0 {
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
            bytes.push(b);
        }
        anyhow::bail!("内核字符串超过 {limit} 字节")
    }
    pub(super) fn logs(&self, result: &mut Results, job: &Job) -> Result<()> {
        let read = (|| -> Result<()> {
            if self.isf.address("prb").is_ok() {
                return self.modern_logs(result, job);
            }
            let ptr = self.vm.uint(self.isf.address("log_buf")?, 8)?;
            let size = self.vm.uint(self.isf.address("log_buf_len")?, 4)?;
            ensure!(
                size > 0 && size <= 16 * 1024 * 1024 && size.is_power_of_two(),
                "printk 缓冲区长度无效/超过 16 MiB"
            );
            // Linux 3.2 SYSLOG_ACTION_READ_ALL / kdb_syslog_data semantics.
            // log_start tracks the consuming syslog reader, not retained history.
            let end = self.vm.uint(self.isf.address("log_end")?, 4)? as u32;
            let length = self
                .vm
                .uint(self.isf.address("logged_chars")?, 4)?
                .min(size);
            let start = end.wrapping_sub(length as u32);
            let mut bytes = Vec::with_capacity(length as usize);
            let mut pos = start as u64;
            while bytes.len() < (length as usize) {
                job.check()?;
                let index = pos & (size - 1);
                let n = (size - index).min(length - bytes.len() as u64).min(4096) as usize;
                let old = bytes.len();
                bytes.resize(old + n, 0);
                self.vm.read(
                    ptr.checked_add(index).context("日志地址溢出")?,
                    &mut bytes[old..],
                )?;
                pos += n as u64;
            }
            for (i, line) in String::from_utf8_lossy(&bytes)
                .split_terminator('\n')
                .enumerate()
            {
                result.rows.push(vec![i.to_string(), line.into()]);
            }
            Ok(())
        })();
        if let Err(e) = read {
            job.check()?;
            partial(result, "dmesg", e);
        }
        Ok(())
    }
    pub(crate) fn modern_logs(&self, result: &mut Results, job: &Job) -> Result<()> {
        let prb = self.vm.uint(self.isf.address("prb")?, 8)?;
        let desc = self.field_address(prb, "printk_ringbuffer", "desc_ring")?;
        let data = self.field_address(prb, "printk_ringbuffer", "text_data_ring")?;
        let count_bits = self.number(desc, "prb_desc_ring", "count_bits")?;
        let size_bits = self.number(data, "prb_data_ring", "size_bits")?;
        ensure!(
            count_bits <= 20 && size_bits <= 24,
            "printk ring 超过安全上限"
        );
        let count = 1u64 << count_bits;
        let size = 1u64 << size_bits;
        let descs = self.number(desc, "prb_desc_ring", "descs")?;
        let infos = self.number(desc, "prb_desc_ring", "infos")?;
        let bytes = self.number(data, "prb_data_ring", "data")?;
        let tail = self.number(desc, "prb_desc_ring", "tail_id.counter")?;
        let head = self.number(desc, "prb_desc_ring", "head_id.counter")?;
        let mask = (1u64 << 62) - 1;
        let length = head.wrapping_sub(tail) & mask;
        ensure!(length < count, "printk descriptor 范围无效");
        for n in 0..=length {
            job.check()?;
            let id = tail.wrapping_add(n) & mask;
            let idx = id & (count - 1);
            let read = (|| -> Result<Option<Vec<String>>> {
                let d = descs
                    + idx
                        * self.isf.data["user_types"]["prb_desc"]["size"]
                            .as_u64()
                            .context("prb_desc size")?;
                let state = self.number(d, "prb_desc", "state_var.counter")?;
                if state & mask != id || !matches!(state >> 62, 1 | 2) {
                    return Ok(None);
                }
                let info = infos
                    + idx
                        * self.isf.data["user_types"]["printk_info"]["size"]
                            .as_u64()
                            .context("printk_info size")?;
                let len = self.number(info, "printk_info", "text_len")?;
                let begin = self.number(d, "prb_desc", "text_blk_lpos.begin")?;
                let next = self.number(d, "prb_desc", "text_blk_lpos.next")?;
                if begin & 1 != 0 {
                    ensure!(len == 0, "printk dataless 记录长度不为 0");
                    return Ok(None);
                }
                ensure!(begin & 7 == 0 && next & 7 == 0, "printk block 未对齐");
                let (pos, capacity) = if begin / size == next / size && begin < next {
                    (begin & (size - 1), next - begin)
                } else if begin.wrapping_add(size) / size == next / size {
                    (0, next & (size - 1))
                } else {
                    anyhow::bail!("printk block wrap 无效");
                };
                ensure!(
                    capacity >= 8 && len <= capacity - 8 && pos + capacity <= size,
                    "printk 记录越界"
                );
                ensure!(
                    self.vm.uint(bytes + pos, 8)? == id,
                    "printk 文本 descriptor ID 不一致"
                );
                let mut text = vec![0; len as usize];
                self.vm.read(bytes + pos + 8, &mut text)?;
                Ok(Some(vec![
                    self.number(info, "printk_info", "seq")?.to_string(),
                    String::from_utf8_lossy(&text).into_owned(),
                ]))
            })();
            match read {
                Ok(Some(row)) => result.rows.push(row),
                Ok(None) => {}
                Err(e) => {
                    result.complete = false;
                    result
                        .diagnostics
                        .push(format!("printk descriptor {id:#x}: {e:#}"));
                }
            }
        }
        Ok(())
    }
    pub(super) fn systeminfo(&self) -> Result<Results> {
        let mut r = self.result(Plugin::Systeminfo);
        let arm = self
            .vm
            .image
            .arm64_va_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        for (key, value) in [
            (
                "Architecture",
                if arm == 0 {
                    "x86_64".into()
                } else {
                    "aarch64".into()
                },
            ),
            ("Kernel", r.banner.clone()),
            ("ImageFormat", self.vm.image.format.into()),
            ("ImageSHA256", self.vm.image.digest.clone()),
            ("PageSize", "4096".into()),
            (
                "VABits",
                if arm == 0 {
                    "48".into()
                } else {
                    arm.to_string()
                },
            ),
            (
                "KernelSlide",
                hex(self.isf.slide.load(std::sync::atomic::Ordering::Relaxed)),
            ),
            ("PageTable", hex(self.vm.root)),
            ("SymbolSource", self.isf.label.clone()),
            ("SymbolSHA256", self.isf.digest.clone()),
            (
                "Validation",
                "完整 banner／init_task／双向链表／页表已验证".into(),
            ),
        ] {
            r.rows.push(vec![key.into(), value]);
        }
        Ok(r)
    }
    /// Cross-view of tasks list, thread groups and PID index.
    pub(super) fn psxview_result(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::Psxview);
        let (listed, tasks) = self.tasks(Plugin::Psxview, job)?;
        r.complete = listed.complete;
        r.diagnostics = listed.diagnostics;
        self.psxview(&tasks, &mut r, job)?;
        Ok(r)
    }
    /// Printk ring buffer, legacy log_buf or structured prb.
    pub(super) fn dmesg(&self, job: &Job) -> Result<Results> {
        for s in if self.isf.address("prb").is_ok() {
            vec!["prb"]
        } else {
            vec!["log_buf", "log_buf_len", "logged_chars", "log_end"]
        } {
            self.isf
                .address(s)
                .with_context(|| format!("不支持: 缺少 {s}（目前支持旧式 printk 环形缓冲区）"))?;
        }
        let mut result = self.result(Plugin::Dmesg);
        self.logs(&mut result, job)?;
        job.check()?;
        Ok(result)
    }
    /// iomem / ioports / ptrace / keyboard_notifiers: kernel-wide relationships.
    pub(super) fn kernel_relations(&self, plugin: Plugin, job: &Job) -> Result<Results> {
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
            _ => return Err(unrouted(plugin)),
        }
        job.check()?;
        job.report(format!("{}: {} 条", plugin.name(), result.rows.len()));
        Ok(result)
    }
    pub(super) fn resources(
        &self,
        root: u64,
        result: &mut Results,
        job: &Job,
        limit: usize,
    ) -> Result<()> {
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
    pub(super) fn keyboard_notifiers(&self, result: &mut Results, job: &Job) -> Result<()> {
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
    pub(crate) fn module_range(&self, module: u64) -> Result<(u64, u64)> {
        if self.isf.field("module", "module_core").is_ok() {
            let start = self.number(module, "module", "module_core")?;
            return Ok((
                start,
                start
                    .checked_add(self.number(module, "module", "core_size")?)
                    .context("module range 溢出")?,
            ));
        }
        if self.isf.field("module", "core_layout").is_ok() {
            let layout = self.field_address(module, "module", "core_layout")?;
            let start = self.number(layout, "module_layout", "base")?;
            return Ok((
                start,
                start
                    .checked_add(self.number(layout, "module_layout", "size")?)
                    .context("module range 溢出")?,
            ));
        }
        let count = self.isf.field("module", "mem")?["type"]["count"]
            .as_u64()
            .context("module.mem count 缺失")?;
        let text = self.isf.data["enums"]["mod_mem_type"]["constants"]["MOD_TEXT"]
            .as_u64()
            .context("MOD_TEXT enum 缺失")?;
        let size = self.isf.data["user_types"]["module_memory"]["size"]
            .as_u64()
            .context("module_memory size 缺失")?;
        ensure!(text < count && count <= 32, "module mem enum 越界");
        let mem = self
            .field_address(module, "module", "mem")?
            .checked_add(text.checked_mul(size).context("module mem 溢出")?)
            .context("module mem 溢出")?;
        let start = self.number(mem, "module_memory", "base")?;
        Ok((
            start,
            start
                .checked_add(self.number(mem, "module_memory", "size")?)
                .context("module range 溢出")?,
        ))
    }
    pub(super) fn check_modules(&self, r: &mut Results, job: &Job) -> Result<()> {
        let listed = self.list_objects(
            self.isf
                .address("modules")
                .context("不支持: 缺少 modules")?,
            self.isf.offset("module", "list")?,
            job,
        )?;
        let kset = self.vm.uint(
            self.isf
                .address("module_kset")
                .context("不支持: 缺少 module_kset")?,
            8,
        )?;
        let objects = self.list_objects(
            self.field_address(kset, "kset", "list")?,
            self.isf.offset("kobject", "entry")?,
            job,
        )?;
        let mut views: BTreeMap<u64, (bool, bool)> =
            listed.into_iter().map(|p| (p, (true, false))).collect();
        for kobj in objects {
            let read = (|| -> Result<()> {
                let name = self.kernel_text(self.number(kobj, "kobject", "name")?, 128)?;
                let holder = kobj
                    .checked_sub(self.isf.offset("module_kobject", "kobj")?)
                    .context("module kobject 下溢")?;
                let module = self.number(holder, "module_kobject", "mod")?;
                if module == 0 {
                    return Ok(());
                }
                ensure!(
                    self.field_address(module, "module", "mkobj")? == holder,
                    "模块 kobject 反向引用不一致"
                );
                ensure!(
                    self.kernel_text(self.field_address(module, "module", "name")?, 128)? == name,
                    "模块名称不一致"
                );
                views.entry(module).or_default().1 = true;
                Ok(())
            })();
            if let Err(e) = read {
                partial(r, format!("module kobject {kobj:#x}"), e);
            }
        }
        for (module, (list, sysfs)) in views {
            let read = (|| -> Result<Vec<String>> {
                let (start, end) = self.module_range(module)?;
                Ok(vec![
                    self.kernel_text(self.field_address(module, "module", "name")?, 128)?,
                    hex(module),
                    hex(start),
                    hex(end),
                    list.to_string(),
                    sysfs.to_string(),
                    if list && sysfs {
                        "Consistent"
                    } else {
                        "ViewMismatch; inspect lifecycle/unloading"
                    }
                    .into(),
                ])
            })();
            match read {
                Ok(row) => r.rows.push(row),
                Err(e) => partial(r, format!("module {module:#x}"), e),
            }
        }
        Ok(())
    }
    pub(super) fn check_syscall(&self, r: &mut Results, job: &Job) -> Result<()> {
        let table = self
            .isf
            .address("sys_call_table")
            .context("不支持: 缺少 sys_call_table")?;
        let size = self.isf.data["metadata"]["zero"]["symbol_sizes"]["sys_call_table"]
            .as_u64()
            .or_else(|| {
                self.isf.data["symbols"]["sys_call_table"]["type"]["count"]
                    .as_u64()
                    .filter(|n| *n > 0)
                    .and_then(|n| n.checked_mul(8))
            })
            .context("不支持: ISF 缺少准确的 sys_call_table 长度；请从调试 ELF 生成符号")?;
        ensure!(
            size > 0 && size % 8 == 0 && size / 8 <= 4096,
            "sys_call_table 长度无效"
        );
        let start = self
            .isf
            .address("_stext")
            .or_else(|_| self.isf.address("_text"))?;
        let end = self.isf.address("_etext")?;
        let modules = self.list_objects(
            self.isf.address("modules")?,
            self.isf.offset("module", "list")?,
            job,
        )?;
        let mut ranges = vec![(start, end, "kernel".to_string())];
        for module in modules {
            let (start, end) = self.module_range(module)?;
            ranges.push((
                start,
                end,
                self.kernel_text(self.field_address(module, "module", "name")?, 128)?,
            ));
        }
        let mut symbols = Vec::new();
        for (name, value) in self.isf.data["symbols"]
            .as_object()
            .context("ISF symbols 缺失")?
        {
            if value["address"].as_u64().is_some() {
                symbols.push((self.isf.address(name)?, name.as_str()));
            }
        }
        symbols.sort_unstable();
        for i in 0..size / 8 {
            job.check()?;
            let read = (|| -> Result<Vec<String>> {
                let target = self.vm.uint(table + i * 8, 8)?;
                let index = symbols.partition_point(|(a, _)| *a <= target);
                let symbol = if index == 0 {
                    "[unknown]".into()
                } else {
                    let (address, name) = symbols[index - 1];
                    if address == target {
                        name.into()
                    } else {
                        format!("{name}+{:#x}", target - address)
                    }
                };
                let owner = ranges
                    .iter()
                    .find(|(a, b, _)| target >= *a && target < *b)
                    .map(|(_, _, name)| name.clone())
                    .unwrap_or_else(|| "[unknown]".into());
                let reason = if owner == "kernel" {
                    "KernelText"
                } else if owner == "[unknown]" {
                    "OutsideKnownExecutableRanges"
                } else {
                    "ModuleTarget; inspect hook"
                };
                let mut byte = [0];
                self.vm.read(target, &mut byte)?;
                Ok(vec![
                    "sys_call_table".into(),
                    i.to_string(),
                    hex(target),
                    symbol,
                    owner,
                    reason.into(),
                ])
            })();
            match read {
                Ok(row) => r.rows.push(row),
                Err(e) => partial(r, format!("sys_call_table[{i}]"), e),
            }
        }
        Ok(())
    }
    pub(super) fn psxview(&self, tasks: &[Task], r: &mut Results, job: &Job) -> Result<()> {
        let mut views: BTreeMap<u64, (bool, bool, bool)> = BTreeMap::new();
        for row in tasks {
            let task = row.address;
            views.entry(task).or_default().0 = true;
            let leader = self.number(task, "task_struct", "group_leader")?;
            match self.thread_nodes(leader, job) {
                Ok(nodes) => {
                    for n in nodes {
                        views.entry(n).or_default().2 = true;
                    }
                }
                Err(e) => partial(r, format!("thread group {leader:#x}"), e),
            }
        }
        let pids = self.pid_objects(job).context("不支持或 PID 索引损坏")?;
        let modern = self.isf.field("task_struct", "pid_links").is_ok();
        let task_offset = if modern {
            self.isf.offset("task_struct", "pid_links")?
        } else {
            self.isf.offset("task_struct", "pids")? + self.isf.offset("pid_link", "node")?
        };
        for pid in pids {
            let read = (|| -> Result<()> {
                let head = self.field_address(pid, "pid", "tasks")?;
                let mut node = self.number(head, "hlist_head", "first")?;
                let mut seen = HashSet::new();
                let mut expected = head;
                while node != 0 {
                    job.check()?;
                    ensure!(
                        seen.insert(node) && seen.len() <= 1_000_000,
                        "PID task hlist 循环或上限"
                    );
                    ensure!(
                        self.number(node, "hlist_node", "pprev")? == expected,
                        "PID task hlist pprev 不一致"
                    );
                    let task = node.checked_sub(task_offset).context("PID task 地址下溢")?;
                    let nr = self.number(task, "task_struct", "pid")?;
                    if nr != 0 {
                        views.entry(task).or_default().1 = true;
                    }
                    expected = self.field_address(node, "hlist_node", "next")?;
                    node = self.number(node, "hlist_node", "next")?;
                }
                Ok(())
            })();
            if let Err(e) = read {
                partial(r, format!("PID object {pid:#x}"), e);
            }
        }
        for (task, (tasks, pid, threads)) in views {
            let read = (|| -> Result<Vec<String>> {
                let nr = self.number(task, "task_struct", "pid")?;
                let tgid = self.number(task, "task_struct", "tgid")?;
                ensure!(nr > 0 && nr <= i32::MAX as u64, "PID 数值异常");
                let reason = if tasks && pid && threads {
                    "Consistent"
                } else if nr != tgid && !tasks && pid && threads {
                    "ThreadOnly"
                } else {
                    "ViewMismatch; inspect exit/lifecycle"
                };
                Ok(vec![
                    nr.to_string(),
                    self.kernel_text(self.field_address(task, "task_struct", "comm")?, 16)?,
                    hex(task),
                    tasks.to_string(),
                    pid.to_string(),
                    threads.to_string(),
                    reason.into(),
                ])
            })();
            match read {
                Ok(row) => r.rows.push(row),
                Err(e) => partial(r, format!("task {task:#x}"), e),
            }
        }
        Ok(())
    }
    pub(super) fn pid_objects(&self, job: &Job) -> Result<Vec<u64>> {
        if self.isf.field("pid_namespace", "idr").is_ok() {
            let ns = self.isf.address("init_pid_ns")?;
            let idr = self.field_address(ns, "pid_namespace", "idr")?;
            let xa = self.field_address(idr, "idr", "idr_rt")?;
            let mut stack = vec![self.number(xa, "xarray", "xa_head")?];
            let mut seen = HashSet::new();
            let mut pids = Vec::new();
            while let Some(entry) = stack.pop() {
                job.check()?;
                if entry == 0 {
                    continue;
                }
                ensure!(
                    seen.insert(entry) && seen.len() <= 1_000_000,
                    "PID xarray 循环或上限"
                );
                if entry & 3 == 2 {
                    ensure!(entry > 4096, "PID xarray 保留节点／sibling 不支持");
                    let node = entry - 2;
                    let slots = self.field_address(node, "xa_node", "slots")?;
                    let count = self.isf.field("xa_node", "slots")?["type"]["count"]
                        .as_u64()
                        .context("xa slots count")?;
                    ensure!(count <= 256, "PID xarray slot count 越界");
                    for i in 0..count {
                        stack.push(self.vm.uint(slots + i * 8, 8)?);
                    }
                } else {
                    ensure!(entry & 3 == 0, "PID xarray 值节点不支持");
                    pids.push(entry);
                }
            }
            return Ok(pids);
        }
        let hash = self.vm.uint(self.isf.address("pid_hash")?, 8)?;
        let shift = self.vm.uint(self.isf.address("pidhash_shift")?, 4)?;
        ensure!(shift <= 20, "PID hash 达到上限");
        let ns = self.isf.address("init_pid_ns")?;
        let mut pids = Vec::new();
        let mut seen = HashSet::new();
        for i in 0..(1u64 << shift) {
            job.check()?;
            let head = hash
                + i * self.isf.data["user_types"]["hlist_head"]["size"]
                    .as_u64()
                    .context("hlist size")?;
            let mut n = self.number(head, "hlist_head", "first")?;
            while n != 0 {
                ensure!(
                    seen.insert(n) && seen.len() <= 1_000_000,
                    "PID hash 循环或上限"
                );
                let upid = n
                    .checked_sub(self.isf.offset("upid", "pid_chain")?)
                    .context("upid 地址下溢")?;
                if self.number(upid, "upid", "ns")? == ns {
                    pids.push(
                        upid.checked_sub(self.isf.offset("pid", "numbers")?)
                            .context("pid 地址下溢")?,
                    );
                }
                n = self.number(n, "hlist_node", "next")?;
            }
        }
        Ok(pids)
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
