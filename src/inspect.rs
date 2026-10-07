//! Evidence-oriented analyses. Cross-view differences are leads, not verdicts.
use crate::{
    Job,
    image::VirtualMemory,
    linux::{Linux, Plugin},
    report::{hex, partial},
    store::Results,
};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, HashSet};
fn header(bytes: &[u8], arm: bool) -> Result<(String, u64)> {
    ensure!(bytes.len() >= 64 && &bytes[..4] == b"\x7fELF", "非 ELF 头");
    ensure!(
        bytes[4] == 2 && bytes[5] == 1 && bytes[6] == 1,
        "不支持的 ELF class／字节序／版本"
    );
    let machine = u16::from_le_bytes(bytes[18..20].try_into()?);
    ensure!(machine == if arm { 183 } else { 62 }, "ELF 架构不一致");
    let kind = u16::from_le_bytes(bytes[16..18].try_into()?);
    ensure!(matches!(kind, 2 | 3), "ELF 非 EXEC／DYN");
    ensure!(
        u16::from_le_bytes(bytes[52..54].try_into()?) == 64,
        "ELF header size 无效"
    );
    Ok((
        if kind == 2 { "EXEC" } else { "DYN" }.into(),
        u64::from_le_bytes(bytes[24..32].try_into()?),
    ))
}
impl Linux<'_> {
    pub(crate) fn process_vm(&self, task: u64) -> Result<Option<VirtualMemory<'_>>> {
        let mm = self.number(task, "task_struct", "mm")?;
        if mm == 0 {
            return Ok(None);
        }
        let pgd = self.number(mm, "mm_struct", "pgd")?;
        let root = self.vm.translate(pgd)?;
        ensure!(root & 4095 == 0, "用户页表未对齐");
        Ok(Some(VirtualMemory {
            image: self.vm.image,
            root,
        }))
    }
    pub(crate) fn vma_nodes(&self, mm: u64, job: &Job) -> Result<Vec<u64>> {
        if self.isf.field("mm_struct", "mmap").is_err() {
            return self.maple_vmas(mm, job, 1_000_000);
        }
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut n = self.number(mm, "mm_struct", "mmap")?;
        while n != 0 {
            job.check()?;
            ensure!(
                seen.insert(n) && seen.len() <= 1_000_000,
                "VMA 循环或达到上限"
            );
            out.push(n);
            n = self.number(n, "vm_area_struct", "vm_next")?;
        }
        Ok(out)
    }
    pub(crate) fn run_inspect(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        let mut r = self.result(plugin);
        if plugin == Plugin::Systeminfo {
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
            return Ok(r);
        }
        if plugin == Plugin::CheckModules {
            self.check_modules(&mut r, job)?;
            return Ok(r);
        }
        if plugin == Plugin::CheckSyscall {
            self.check_syscall(&mut r, job)?;
            return Ok(r);
        }
        let tasks = self.run(Plugin::Pslist, job)?;
        r.complete = tasks.complete;
        r.diagnostics = tasks.diagnostics.clone();
        if plugin == Plugin::Psxview {
            self.psxview(&tasks.rows, &mut r, job)?;
            return Ok(r);
        }
        for row in tasks.rows {
            job.check()?;
            let task = u64::from_str_radix(&row[4][2..], 16)?;
            if matches!(plugin, Plugin::Bash | Plugin::History) && row[3] != "bash" {
                continue;
            }
            let read = (|| -> Result<()> {
                let mm = self.number(task, "task_struct", "mm")?;
                if mm == 0 {
                    return Ok(());
                }
                let vm = self.process_vm(task)?.context("用户地址空间为空")?;
                let nodes = self.vma_nodes(mm, job)?;
                if matches!(plugin, Plugin::Bash | Plugin::History) {
                    return self.bash_history(
                        &vm,
                        &nodes,
                        &row[..1]
                            .iter()
                            .cloned()
                            .chain(std::iter::once(row[3].clone()))
                            .collect::<Vec<_>>(),
                        &mut r,
                        job,
                    );
                }
                let mut budget = 256 * 1024 * 1024u64;
                for node in nodes {
                    job.check()?;
                    let read = (|| -> Result<()> {
                        let start = self.number(node, "vm_area_struct", "vm_start")?;
                        let end = self.number(node, "vm_area_struct", "vm_end")?;
                        ensure!(start < end, "VMA 地址倒置");
                        let flags = self.number(node, "vm_area_struct", "vm_flags")?;
                        let file = self.number(node, "vm_area_struct", "vm_file")?;
                        if flags & 1 == 0 {
                            return Ok(());
                        }
                        if plugin == Plugin::Malfind
                            && !(flags & 4 != 0 && (flags & 2 != 0 || file == 0))
                        {
                            return Ok(());
                        }
                        let amount = if plugin == Plugin::Elfs { 64 } else { 32 };
                        ensure!(budget >= amount, "用户读取达到 256 MiB 上限");
                        budget -= amount;
                        let mut bytes = vec![0; amount as usize];
                        vm.read(start, &mut bytes)?;
                        if plugin == Plugin::Elfs && !bytes.starts_with(b"\x7fELF") {
                            return Ok(());
                        }
                        let path = if file == 0 {
                            "[anonymous]".into()
                        } else {
                            match self.file_path(task, file, job) {
                                Ok(v) => v,
                                Err(e) => {
                                    partial(
                                        &mut r,
                                        format!("PID {} VMA {node:#x} 路径", row[0]),
                                        e,
                                    );
                                    "[unresolved]".into()
                                }
                            }
                        };
                        let mut values = vec![row[0].clone(), row[3].clone(), hex(start), hex(end)];
                        if plugin == Plugin::Elfs {
                            let (kind, entry) = header(
                                &bytes,
                                self.vm
                                    .image
                                    .arm64_va_bits
                                    .load(std::sync::atomic::Ordering::Relaxed)
                                    != 0,
                            )?;
                            values.extend([kind, hex(entry), path]);
                        } else {
                            let perms = format!(
                                "{}{}{}{}",
                                if flags & 1 != 0 { 'r' } else { '-' },
                                if flags & 2 != 0 { 'w' } else { '-' },
                                if flags & 4 != 0 { 'x' } else { '-' },
                                if flags & 8 != 0 { 's' } else { 'p' }
                            );
                            let reason = if flags & 2 != 0 {
                                "WritableExecutable"
                            } else {
                                "AnonymousExecutable"
                            };
                            values.extend([
                                perms,
                                path,
                                reason.into(),
                                bytes
                                    .iter()
                                    .map(|b| format!("{b:02x}"))
                                    .collect::<Vec<_>>()
                                    .join(" "),
                            ]);
                        }
                        r.rows.push(values);
                        Ok(())
                    })();
                    if let Err(e) = read {
                        job.check()?;
                        partial(&mut r, format!("PID {} VMA {node:#x}", row[0]), e);
                    }
                }
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                partial(&mut r, format!("PID {} {task:#x}", row[0]), e);
            }
            job.report(format!("{}: {} 条", plugin.name(), r.rows.len()));
        }
        job.check()?;
        Ok(r)
    }
    fn bash_history(
        &self,
        vm: &VirtualMemory<'_>,
        nodes: &[u64],
        prefix: &[String],
        r: &mut Results,
        job: &Job,
    ) -> Result<()> {
        let mut timestamps = BTreeMap::new();
        let mut blocks = Vec::new();
        let mut budget = 256 * 1024 * 1024usize;
        for &node in nodes {
            let flags = self.number(node, "vm_area_struct", "vm_flags")?;
            if flags & 3 != 3 {
                continue;
            }
            let start = self.number(node, "vm_area_struct", "vm_start")?;
            let end = self.number(node, "vm_area_struct", "vm_end")?;
            ensure!(start < end, "Bash VMA 地址倒置");
            let mut pos = start;
            while pos < end {
                job.check()?;
                let n = (end - pos).min(1024 * 1024 + 24) as usize;
                ensure!(budget >= n, "Bash 扫描达到每进程 256 MiB 上限");
                budget -= n;
                let mut bytes = vec![0; n];
                match vm.read(pos, &mut bytes) {
                    Ok(()) => {
                        for i in memchr::memchr_iter(b'#', &bytes) {
                            let candidate = &bytes[i + 1..];
                            let len = candidate.iter().take_while(|b| b.is_ascii_digit()).count();
                            if (9..=12).contains(&len) && candidate.get(len) == Some(&0) {
                                let value =
                                    std::str::from_utf8(&candidate[..len])?.parse::<u64>()?;
                                if (315532800..=4102444800).contains(&value) {
                                    timestamps.insert(pos + i as u64, value.to_string());
                                }
                            }
                        }
                        blocks.push((pos, bytes));
                    }
                    Err(e) => partial(r, format!("PID {} Bash 区域 {pos:#x}", prefix[0]), e),
                }
                pos += (n as u64).min(1024 * 1024);
            }
        }
        let mut seen = HashSet::new();
        for (start, bytes) in &blocks {
            for i in (0..bytes.len().saturating_sub(23)).step_by(8) {
                job.check()?;
                let ts = u64::from_le_bytes(bytes[i + 8..i + 16].try_into()?);
                if let Some(time) = timestamps.get(&ts) {
                    let line = u64::from_le_bytes(bytes[i..i + 8].try_into()?);
                    let data = u64::from_le_bytes(bytes[i + 16..i + 24].try_into()?);
                    let ceiling = 1u64
                        << if self
                            .vm
                            .image
                            .arm64_va_bits
                            .load(std::sync::atomic::Ordering::Relaxed)
                            == 0
                        {
                            47
                        } else {
                            self.vm
                                .image
                                .arm64_va_bits
                                .load(std::sync::atomic::Ordering::Relaxed)
                        };
                    if line == 0 || line >= ceiling || (data != 0 && data >= ceiling) {
                        continue;
                    }
                    ensure!(budget >= 65536, "Bash 用户读取达到 256 MiB 上限");
                    budget -= 65536;
                    let command = match user_string(vm, line, 65536, job) {
                        Ok(value) => value,
                        Err(e) => {
                            job.check()?;
                            partial(
                                r,
                                format!("PID {} Bash record {:#x}", prefix[0], start + i as u64),
                                e,
                            );
                            continue;
                        }
                    };
                    if command.is_empty() || command.chars().any(|c| c == '\0') {
                        continue;
                    }
                    let addr = start + i as u64;
                    if seen.insert(addr) {
                        r.rows.push(
                            [prefix.to_vec(), vec![time.clone(), command, hex(addr)]].concat(),
                        );
                    }
                }
            }
        }
        // Recover untimestamped entries only from pointer arrays anchored by a
        // validated timestamped HIST_ENTRY, never from arbitrary pointer pairs.
        let mut arrays = HashSet::new();
        for (start, bytes) in &blocks {
            for i in (0..bytes.len().saturating_sub(7)).step_by(8) {
                let pointer = u64::from_le_bytes(bytes[i..i + 8].try_into()?);
                if seen.contains(&pointer) {
                    arrays.insert(start + i as u64);
                }
            }
        }
        for anchor in arrays {
            for direction in [false, true] {
                for n in 1..=4096u64 {
                    job.check()?;
                    let address = if direction {
                        anchor.checked_add(n * 8)
                    } else {
                        anchor.checked_sub(n * 8)
                    };
                    let Some(address) = address else {
                        break;
                    };
                    ensure!(budget >= 32, "Bash 用户读取达到 256 MiB 上限");
                    budget -= 32;
                    let entry = match vm.uint(address, 8) {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    if entry == 0 || entry & 7 != 0 {
                        break;
                    }
                    let mut record = [0; 24];
                    if vm.read(entry, &mut record).is_err() {
                        break;
                    }
                    let line = u64::from_le_bytes(record[..8].try_into()?);
                    let ts = u64::from_le_bytes(record[8..16].try_into()?);
                    if ts != 0 && !timestamps.contains_key(&ts) {
                        break;
                    }
                    if seen.contains(&entry) {
                        continue;
                    }
                    ensure!(budget >= 65536, "Bash 用户读取达到 256 MiB 上限");
                    budget -= 65536;
                    let command = match user_string(vm, line, 65536, job) {
                        Ok(v) if !v.is_empty() => v,
                        _ => break,
                    };
                    if seen.insert(entry) {
                        r.rows.push(
                            [
                                prefix.to_vec(),
                                vec![
                                    timestamps
                                        .get(&ts)
                                        .cloned()
                                        .unwrap_or_else(|| "[missing]".into()),
                                    command,
                                    hex(entry),
                                ],
                            ]
                            .concat(),
                        );
                    }
                    ensure!(n < 4096, "Bash 历史指针数组达到 4096 项边界");
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
    fn check_modules(&self, r: &mut Results, job: &Job) -> Result<()> {
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
    fn check_syscall(&self, r: &mut Results, job: &Job) -> Result<()> {
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
    fn psxview(&self, tasks: &[Vec<String>], r: &mut Results, job: &Job) -> Result<()> {
        let mut views: BTreeMap<u64, (bool, bool, bool)> = BTreeMap::new();
        for row in tasks {
            let task = u64::from_str_radix(&row[4][2..], 16)?;
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
    fn pid_objects(&self, job: &Job) -> Result<Vec<u64>> {
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
fn user_string(vm: &VirtualMemory<'_>, start: u64, limit: usize, job: &Job) -> Result<String> {
    let mut bytes = Vec::new();
    while bytes.len() < limit {
        job.check()?;
        let addr = start
            .checked_add(bytes.len() as u64)
            .context("用户字符串地址溢出")?;
        let n = (4096 - (addr & 4095) as usize).min(limit - bytes.len());
        let mut chunk = vec![0; n];
        vm.read(addr, &mut chunk)?;
        if let Some(end) = chunk.iter().position(|b| *b == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.extend(chunk);
    }
    anyhow::bail!("用户字符串超过 {limit} 字节")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn elf_header_validation() {
        let mut bytes = [0; 64];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16] = 3;
        bytes[18] = 183;
        bytes[52] = 64;
        assert_eq!(header(&bytes, true).unwrap().0, "DYN");
        assert!(header(&bytes, false).is_err());
        bytes[5] = 2;
        assert!(header(&bytes, true).is_err());
    }
    fn put(b: &mut [u8], p: usize, v: u64) {
        b[p..p + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn fields(names: &[(&str, u64)], size: u64) -> serde_json::Value {
        serde_json::json!({"size":size,"fields":names.iter().map(|(name,offset)|((*name).to_string(),serde_json::json!({"offset":offset,"type":{"kind":"base","name":"u64"}}))).collect::<serde_json::Map<_,_>>()})
    }
    #[test]
    fn elf_malfind_bash_empty_missing_timestamp_and_missing_pages() {
        use crate::extended::tests::{engine, fixture, image};
        let (mut b, isf) = fixture();
        put(&mut b, 0xb028, 0xc800);
        put(&mut b, 0xc808, 0x200000);
        put(&mut b, 0xc810, 0x201000);
        put(&mut b, 0xc818, 7);
        b[0x20000..0x20007].copy_from_slice(b"\x7fELF\x02\x01\x01");
        b[0x20010] = 3;
        b[0x20012] = 62;
        b[0x20034] = 64;
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::Elfs, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0][4], "DYN");
        let r = engine(&img, &isf)
            .run(Plugin::Malfind, &Job::default())
            .unwrap();
        assert_eq!(r.rows[0][6], "WritableExecutable");
        b[0xa028..0xa02c].copy_from_slice(b"bash");
        b[0x20000..0x20080].fill(0);
        put(&mut b, 0x20010, 0x200040);
        put(&mut b, 0x20018, 0x200080);
        b[0x20040..0x2004a].copy_from_slice(b"echo test\0");
        b[0x20080..0x2008c].copy_from_slice(b"#1700000000\0");
        put(&mut b, 0x20090, 0x2000b0);
        b[0x200b0..0x200b3].copy_from_slice(b"id\0");
        put(&mut b, 0x20100, 0x200010);
        put(&mut b, 0x20108, 0x200090);
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::Bash, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert!(
            r.rows
                .iter()
                .any(|r| r[2] == "1700000000" && r[3] == "echo test")
        );
        assert!(r.rows.iter().any(|r| r[2] == "[missing]" && r[3] == "id"));
        put(&mut b, 0xc800, 0xc900);
        put(&mut b, 0xc908, 0x202000);
        put(&mut b, 0xc910, 0x203000);
        put(&mut b, 0xc918, 7);
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::Malfind, &Job::default())
            .unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
        put(&mut b, 0xb028, 0);
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::Bash, &Job::default())
            .unwrap();
        assert!(r.complete);
        assert!(r.rows.is_empty());
    }
    #[test]
    fn pid_cross_view_detects_unlinked_task_and_rejects_cycles() {
        use crate::extended::tests::{engine, fixture, image};
        use serde_json::json;
        let (mut b, mut isf) = fixture();
        for (name, offset) in [
            ("group_leader", 72),
            ("thread_group", 80),
            ("pid_links", 96),
        ] {
            isf.data["user_types"]["task_struct"]["fields"][name] =
                json!({"offset":offset,"type":{"kind":"base","name":"u64"}});
        }
        for (task, pid) in [(0xa000, 1), (0xa100, 2), (0xa200, 3)] {
            put(&mut b, task + 72, task as u64);
            put(&mut b, task + 80, (task + 80) as u64);
            put(&mut b, task + 88, (task + 80) as u64);
            if pid == 3 {
                put(&mut b, task + 16, pid);
                put(&mut b, task + 24, pid);
                b[task + 40..task + 47].copy_from_slice(b"hidden\0");
            }
        }
        isf.data["symbols"]["init_pid_ns"] = json!({"address":0x15000});
        isf.data["user_types"]["pid_namespace"] = fields(&[("idr", 0)], 16);
        isf.data["user_types"]["idr"] = fields(&[("idr_rt", 0)], 16);
        isf.data["user_types"]["xarray"] = fields(&[("xa_head", 0)], 8);
        isf.data["user_types"]["xa_node"] = json!({"size":24,"fields":{"slots":{"offset":0,"type":{"kind":"array","count":3,"subtype":{"kind":"pointer"}}}}});
        isf.data["user_types"]["pid"] = fields(&[("tasks", 0)], 16);
        isf.data["user_types"]["hlist_head"] = fields(&[("first", 0)], 8);
        isf.data["user_types"]["hlist_node"] = fields(&[("next", 0), ("pprev", 8)], 16);
        put(&mut b, 0x15000, 0x16002);
        for (i, task) in [0xa000, 0xa100, 0xa200].iter().enumerate() {
            let pid = 0x17000 + i * 32;
            put(&mut b, 0x16000 + i * 8, pid as u64);
            put(&mut b, pid, (task + 96) as u64);
            put(&mut b, task + 96, 0);
            put(&mut b, task + 104, pid as u64);
        }
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::Psxview, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        let hidden = r.rows.iter().find(|r| r[0] == "3").unwrap();
        assert_eq!(&hidden[3..6], &["false", "true", "false"]);
        assert!(hidden[6].starts_with("ViewMismatch"));
        put(&mut b, 0x16000, 0x16002);
        let img = image(&b);
        assert!(
            engine(&img, &isf)
                .run(Plugin::Psxview, &Job::default())
                .is_err()
        );
    }
    #[test]
    fn syscall_and_module_views_detect_hooks_and_unlinked_modules() {
        use crate::extended::tests::{engine, fixture, image};
        use serde_json::json;
        let (mut b, mut isf) = fixture();
        isf.data["symbols"]["modules"] = json!({"address":0x15000});
        isf.data["symbols"]["module_kset"] = json!({"address":0x15020});
        isf.data["user_types"]["module"] = fields(
            &[
                ("list", 0),
                ("name", 16),
                ("module_core", 32),
                ("core_size", 40),
                ("mkobj", 64),
            ],
            128,
        );
        isf.data["user_types"]["kset"] = fields(&[("list", 0)], 16);
        isf.data["user_types"]["module_kobject"] = fields(&[("kobj", 0), ("mod", 32)], 48);
        isf.data["user_types"]["kobject"] = fields(&[("entry", 0), ("name", 16)], 32);
        put(&mut b, 0x15000, 0x16000);
        put(&mut b, 0x15008, 0x16000);
        put(&mut b, 0x16000, 0x15000);
        put(&mut b, 0x16008, 0x15000);
        put(&mut b, 0x15020, 0x15100);
        put(&mut b, 0x15100, 0x16040);
        put(&mut b, 0x15108, 0x16140);
        put(&mut b, 0x16040, 0x16140);
        put(&mut b, 0x16048, 0x15100);
        put(&mut b, 0x16140, 0x15100);
        put(&mut b, 0x16148, 0x16040);
        for (at, name) in [
            (0x16000, b"normal\0".as_slice()),
            (0x16100, b"hidden\0".as_slice()),
        ] {
            b[at + 16..at + 16 + name.len()].copy_from_slice(name);
            put(&mut b, at + 32, 0x20000);
            put(&mut b, at + 40, 4096);
            put(&mut b, at + 80, (at + 16) as u64);
            put(&mut b, at + 96, at as u64);
        }
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::CheckModules, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        let hidden = r.rows.iter().find(|r| r[0] == "hidden").unwrap();
        assert_eq!(&hidden[4..6], &["false", "true"]);
        isf.data["symbols"]["sys_call_table"] = json!({"address":0x15500,"type":{"count":2}});
        isf.data["symbols"]["_stext"] = json!({"address":0x18000});
        isf.data["symbols"]["_etext"] = json!({"address":0x19000});
        isf.data["symbols"]["sys_test"] = json!({"address":0x18000});
        put(&mut b, 0x15500, 0x18000);
        put(&mut b, 0x15508, 0x30000);
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::CheckSyscall, &Job::default())
            .unwrap();
        assert!(r.complete);
        assert_eq!(r.rows[0][5], "KernelText");
        assert_eq!(r.rows[1][5], "OutsideKnownExecutableRanges");
        put(&mut b, 0x15508, 0x400000);
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::CheckSyscall, &Job::default())
            .unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
    }
}
