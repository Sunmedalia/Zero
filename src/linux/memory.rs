//! Process memory views: mappings, ELF headers, injected code and bash history.
use super::*;
use crate::bytes::JsonKey as _;
pub(super) fn header(bytes: &[u8], arm: bool) -> Result<(String, u64)> {
    ensure!(
        bytes.len() >= 64 && bytes.at(..4)? == b"\x7fELF",
        "非 ELF 头"
    );
    ensure!(
        *bytes.at(4)? == 2 && *bytes.at(5)? == 1 && *bytes.at(6)? == 1,
        "不支持的 ELF class／字节序／版本"
    );
    let machine = u16::from_le_bytes(bytes.at(18..20)?.try_into()?);
    ensure!(machine == if arm { 183 } else { 62 }, "ELF 架构不一致");
    let kind = u16::from_le_bytes(bytes.at(16..18)?.try_into()?);
    ensure!(matches!(kind, 2 | 3), "ELF 非 EXEC／DYN");
    ensure!(
        u16::from_le_bytes(bytes.at(52..54)?.try_into()?) == 64,
        "ELF header size 无效"
    );
    Ok((
        if kind == 2 { "EXEC" } else { "DYN" }.into(),
        u64::from_le_bytes(bytes.at(24..32)?.try_into()?),
    ))
}
/// Validated fields of one zsh `struct histent`.
struct Histent {
    nam: u64,
    up: u64,
    down: u64,
    stim: u64,
    ftim: u64,
    histnum: u64,
}
impl Linux<'_> {
    pub(super) fn maps(
        &self,
        task: u64,
        prefix: Vec<String>,
        result: &mut Results,
        job: &Job,
    ) -> Result<()> {
        self.maps_bounded(task, prefix, result, job, OBJECT_LIMIT)
    }
    pub(super) fn maps_bounded(
        &self,
        task: u64,
        prefix: Vec<String>,
        result: &mut Results,
        job: &Job,
        limit: u64,
    ) -> Result<()> {
        let mm = self.number(task, "task_struct", "mm")?;
        if mm == 0 {
            return Ok(());
        }
        let modern = self.isf.field("mm_struct", "mmap").is_err();
        let mut nodes = if modern {
            self.maple_vmas_partial(mm, job, limit, result)?.into_iter()
        } else {
            Vec::new().into_iter()
        };
        let mut node = if modern {
            nodes.next().unwrap_or(0)
        } else {
            self.number(mm, "mm_struct", "mmap")?
        };
        // Rows are `prefix + 5 columns`; building them in place avoids a second
        // Vec allocation per VMA, and permission spellings repeat.
        let mut permissions_cache: std::collections::HashMap<u64, String> =
            std::collections::HashMap::new();
        // One root per process: `file_path` otherwise re-reads it per mapping.
        // A failure is not reported here: it must surface per VMA so the
        // diagnostic order stays what callers already depend on.
        let root = self.process_root(task).ok();
        let mut visited = HashSet::new();
        let mut processed = 0u64;
        while node != 0 {
            job.check()?;
            if !modern {
                ensure!(visited.insert(node), "VMA 循环 @ {}", hex(node));
            }
            processed += 1;
            ensure!(processed <= limit, "VMA 超过 100 万项上限");
            let next = if modern {
                nodes.next().unwrap_or(0)
            } else {
                self.number(node, "vm_area_struct", "vm_next")?
            };
            let row = (|| -> Result<Vec<String>> {
                let start = self.number(node, "vm_area_struct", "vm_start")?;
                let end = self.number(node, "vm_area_struct", "vm_end")?;
                ensure!(start < end, "VMA 地址倒置");
                let flags = self.number(node, "vm_area_struct", "vm_flags")?;
                let offset = self
                    .number(node, "vm_area_struct", "vm_pgoff")?
                    .checked_mul(4096)
                    .context("VMA 文件偏移溢出")?;
                let file = self.number(node, "vm_area_struct", "vm_file")?;
                let path = if file == 0 {
                    "[anonymous]".into()
                } else {
                    match root.map_or_else(
                        || self.file_path(task, file, job),
                        |root| self.file_path_from(root, file, job),
                    ) {
                        Ok(path) => path,
                        Err(e) => {
                            job.check()?;
                            partial(
                                result,
                                format!("PID {} VMA {} 路径", *prefix.at(0)?, hex(node)),
                                e,
                            );
                            "[unresolved]".into()
                        }
                    }
                };
                let permissions = permissions_cache
                    .entry(flags)
                    .or_insert_with(|| permissions(flags))
                    .clone();
                let mut row = Vec::with_capacity(prefix.len() + 5);
                row.extend_from_slice(&prefix);
                row.push(hex(start));
                row.push(hex(end));
                row.push(permissions);
                row.push(offset.to_string());
                row.push(path);
                Ok(row)
            })();
            match row {
                Ok(row) => result.rows.push(row),
                Err(e) => partial(
                    result,
                    format!("PID {} VMA {}", *prefix.at(0)?, hex(node)),
                    e,
                ),
            }
            node = next;
        }
        Ok(())
    }
    /// elfs / library_list / malfind / bash / zsh: bounded reads of each
    /// task's mapped regions.
    pub(super) fn vma_scan(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        let mut r = self.result(plugin);
        let (listed, tasks) = self.tasks(plugin, job)?;
        r.complete = listed.complete;
        r.diagnostics = listed.diagnostics;
        for row in tasks {
            job.check()?;
            let task = row.address;
            if plugin == Plugin::Bash && !matches!(row.name.as_str(), "bash" | "sh" | "dash")
                || plugin == Plugin::Zsh && !row.name.starts_with("zsh")
            {
                continue;
            }
            let read = (|| -> Result<()> {
                let mm = self.number(task, "task_struct", "mm")?;
                if mm == 0 {
                    return Ok(());
                }
                let vm = self.process_vm(task)?.context("用户地址空间为空")?;
                let nodes = self.vma_nodes(mm, job, &mut r)?;
                if plugin == Plugin::Zsh {
                    return self.zsh_history(
                        mm,
                        &vm,
                        &nodes,
                        &[row.pid.clone(), row.name.clone()],
                        &mut r,
                        job,
                    );
                }
                if plugin == Plugin::Bash {
                    return self.bash_history(
                        mm,
                        &vm,
                        &nodes,
                        &[row.pid.clone(), row.name.clone()],
                        &mut r,
                        job,
                    );
                }
                let mut budget = 256 * 1024 * 1024u64;
                // One root per process, and one buffer for the header probe:
                // both would otherwise be redone for every mapped region.
                let root = self.process_root(task).ok();
                let mut bytes = vec![0; 64];
                let headers = matches!(plugin, Plugin::Elfs | Plugin::LibraryList);
                // library_list: the main program is not a library, and each
                // library is reported once at its lowest mapping.
                let exe = if plugin == Plugin::LibraryList {
                    self.number(mm, "mm_struct", "exe_file")
                        .ok()
                        .filter(|file| *file != 0)
                        .and_then(|file| {
                            root.map_or_else(
                                || self.file_path(task, file, job),
                                |root| self.file_path_from(root, file, job),
                            )
                            .ok()
                        })
                } else {
                    None
                };
                let mut libraries = HashSet::new();
                for node in nodes {
                    job.check()?;
                    let read = (|| -> Result<()> {
                        let start = self.number(node, "vm_area_struct", "vm_start")?;
                        let end = self.number(node, "vm_area_struct", "vm_end")?;
                        ensure!(start < end, "VMA 地址倒置");
                        let flags = self.number(node, "vm_area_struct", "vm_flags")?;
                        let file = self.number(node, "vm_area_struct", "vm_file")?;
                        if flags & 1 == 0 || (plugin == Plugin::LibraryList && file == 0) {
                            return Ok(());
                        }
                        if plugin == Plugin::Malfind
                            && !(flags & 4 != 0 && (flags & 2 != 0 || file == 0))
                        {
                            return Ok(());
                        }
                        let amount = if headers { 64 } else { 32 };
                        ensure!(budget >= amount, "用户读取达到 256 MiB 上限");
                        budget -= amount;
                        bytes.at_mut(..usize::try_from(amount)?)?.fill(0);
                        vm.read(start, bytes.at_mut(..usize::try_from(amount)?)?)?;
                        if headers && !bytes.starts_with(b"\x7fELF") {
                            return Ok(());
                        }
                        let arm = self
                            .vm
                            .image
                            .arm64_va_bits
                            .load(std::sync::atomic::Ordering::Relaxed)
                            != 0;
                        if plugin == Plugin::LibraryList
                            && header(&bytes, arm).map(|(kind, _)| kind)? != "DYN"
                        {
                            return Ok(());
                        }
                        let path = if file == 0 {
                            "[anonymous]".into()
                        } else {
                            match root.map_or_else(
                                || self.file_path(task, file, job),
                                |root| self.file_path_from(root, file, job),
                            ) {
                                Ok(v) => v,
                                Err(e) => {
                                    partial(
                                        &mut r,
                                        format!("PID {} VMA {node:#x} 路径", row.pid),
                                        e,
                                    );
                                    "[unresolved]".into()
                                }
                            }
                        };
                        if plugin == Plugin::LibraryList {
                            if exe.as_ref() != Some(&path)
                                && (path == "[unresolved]" || libraries.insert(path.clone()))
                            {
                                r.rows.push(vec![
                                    row.pid.clone(),
                                    row.name.clone(),
                                    hex(start),
                                    path,
                                ]);
                            }
                            return Ok(());
                        }
                        let mut values =
                            vec![row.pid.clone(), row.name.clone(), hex(start), hex(end)];
                        if plugin == Plugin::Elfs {
                            let (kind, entry) = header(&bytes, arm)?;
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
                                    .at(..usize::try_from(amount)?)?
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
                        partial(&mut r, format!("PID {} VMA {node:#x}", row.pid), e);
                    }
                }
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                partial(&mut r, format!("PID {} {task:#x}", row.pid), e);
            }
            job.report(format!("{}: {} 条", plugin.name(), r.rows.len()));
        }
        job.check()?;
        Ok(r)
    }
    /// vmayarascan: every readable VMA of each task, searched for `pattern`.
    pub(crate) fn vma_pattern_scan(
        &self,
        pattern: &crate::pattern::Pattern,
        job: &Job,
    ) -> Result<Results> {
        let (mut r, tasks) = self.tasks(Plugin::Vmayarascan, job)?;
        let mut remaining = 100_000usize;
        for task in tasks {
            job.check()?;
            let read = (|| -> Result<()> {
                let mm = self.number(task.address, "task_struct", "mm")?;
                if mm == 0 {
                    return Ok(());
                }
                let vm = self.process_vm(task.address)?.context("用户地址空间为空")?;
                let root = self.process_root(task.address).ok();
                let mut budget = 256 * 1024 * 1024u64;
                let mut unreadable = 0u64;
                for node in self.vma_nodes(mm, job, &mut r)? {
                    job.check()?;
                    let start = self.number(node, "vm_area_struct", "vm_start")?;
                    let end = self.number(node, "vm_area_struct", "vm_end")?;
                    let flags = self.number(node, "vm_area_struct", "vm_flags")?;
                    if flags & 1 == 0 || start >= end {
                        continue;
                    }
                    if end - start > crate::pattern::REGION_LIMIT {
                        partial(
                            &mut r,
                            format!("PID {} VMA {start:#x}", task.pid),
                            anyhow::anyhow!("区域超过 1 GiB，未扫描"),
                        );
                        continue;
                    }
                    let scan = crate::pattern::scan_region(
                        pattern,
                        start,
                        end,
                        &mut budget,
                        remaining,
                        |at, out| {
                            job.check()?;
                            vm.read(at, out)
                        },
                    )?;
                    unreadable += scan.unreadable;
                    if scan.hits.is_empty() {
                        continue;
                    }
                    let file = self.number(node, "vm_area_struct", "vm_file")?;
                    let path = if file == 0 {
                        "[anonymous]".into()
                    } else {
                        root.map_or_else(
                            || self.file_path(task.address, file, job),
                            |root| self.file_path_from(root, file, job),
                        )
                        .unwrap_or_else(|_| "[unresolved]".into())
                    };
                    for (address, bytes) in scan.hits {
                        remaining -= 1;
                        r.rows.push(vec![
                            task.pid.clone(),
                            task.name.clone(),
                            hex(address),
                            hex(start),
                            permissions(flags),
                            path.clone(),
                            crate::pattern::context(&bytes),
                        ]);
                    }
                    ensure!(remaining > 0, "命中数达到 100000 上限");
                }
                // Unscanned pages mean an absent match proves nothing.
                ensure!(unreadable == 0, "{unreadable} 个页不可读，未扫描");
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                partial(&mut r, format!("PID {} {:#x}", task.pid, task.address), e);
            }
        }
        *r.kernel_identity.key_mut("pattern")? = serde_json::json!(pattern.source());
        Ok(r)
    }
    /// Bash history in the style of volatility3 `linux.bash`: candidate
    /// `HIST_ENTRY { line, timestamp, data }` records whose timestamp pointer
    /// targets a `#<epoch>` string, scanned in the heap (VMAs overlapping
    /// `start_brk..brk`). Pages are read one at a time so an absent page only
    /// skips itself; every gap or limit is reported, and rows recovered before
    /// it are kept.
    pub(super) fn bash_history(
        &self,
        mm: u64,
        vm: &VirtualMemory<'_>,
        nodes: &[u64],
        prefix: &[String],
        r: &mut Results,
        job: &Job,
    ) -> Result<()> {
        let pid = prefix.first().cloned().unwrap_or_default();
        let ceiling = self.user_ceiling();
        let blocks = self.heap_blocks(mm, vm, nodes, &format!("PID {pid} Bash"), r, job)?;
        let mut limited = None;

        let mut timestamps = BTreeMap::new();
        for (start, bytes) in &blocks {
            for i in memchr::memchr_iter(b'#', bytes) {
                let candidate = bytes.at(i + 1..)?;
                let len = candidate.iter().take_while(|b| b.is_ascii_digit()).count();
                if (9..=12).contains(&len) && candidate.get(len) == Some(&0) {
                    let value = std::str::from_utf8(candidate.at(..len)?)?.parse::<u64>()?;
                    if (315532800..=4102444800).contains(&value) {
                        timestamps.insert(start + i as u64, value);
                    }
                }
            }
        }

        let mut strings = 64 * 1024 * 1024usize;
        let mut unreadable = 0u64;
        let mut seen = HashSet::new();
        let mut found: Vec<(Option<u64>, u64, String)> = Vec::new();
        for (start, bytes) in &blocks {
            for i in (0..bytes.len().saturating_sub(23)).step_by(8) {
                job.check()?;
                let ts = u64::from_le_bytes(bytes.at(i + 8..i + 16)?.try_into()?);
                let Some(&time) = timestamps.get(&ts) else {
                    continue;
                };
                let line = u64::from_le_bytes(bytes.at(i..i + 8)?.try_into()?);
                let data = u64::from_le_bytes(bytes.at(i + 16..i + 24)?.try_into()?);
                if line == 0 || line >= ceiling || (data != 0 && data >= ceiling) {
                    continue;
                }
                if strings == 0 {
                    limited = Some("Bash 命令字符串读取达到 64 MiB 上限");
                    break;
                }
                let Ok(command) = user_string(vm, line, 65536, job) else {
                    job.check()?;
                    unreadable += 1;
                    continue;
                };
                strings = strings.saturating_sub(command.len() + 1);
                let addr = start + i as u64;
                if !command.is_empty() && seen.insert(addr) {
                    found.push((Some(time), addr, command));
                }
            }
        }

        // Recover untimestamped entries only from pointer arrays anchored by a
        // validated timestamped HIST_ENTRY, never from arbitrary pointer pairs.
        // Each array slot is walked once, so long histories stay linear.
        let mut anchors = Vec::new();
        for (start, bytes) in &blocks {
            for i in (0..bytes.len().saturating_sub(7)).step_by(8) {
                let pointer = u64::from_le_bytes(bytes.at(i..i + 8)?.try_into()?);
                if seen.contains(&pointer) {
                    anchors.push(start + i as u64);
                }
            }
        }
        let mut visited: HashSet<u64> = anchors.iter().copied().collect();
        let mut recovered = Vec::new();
        'arrays: for anchor in anchors {
            for forward in [false, true] {
                for n in 1..=LIMIT as u64 {
                    job.check()?;
                    let Some(address) = (if forward {
                        anchor.checked_add(n * 8)
                    } else {
                        anchor.checked_sub(n * 8)
                    }) else {
                        break;
                    };
                    if !visited.insert(address) {
                        break;
                    }
                    let Ok(entry) = vm.uint(address, 8) else {
                        break;
                    };
                    if entry == 0 || entry & 7 != 0 {
                        break;
                    }
                    let mut record = [0; 24];
                    if vm.read(entry, &mut record).is_err() {
                        break;
                    }
                    let line = u64::from_le_bytes(record.at(..8)?.try_into()?);
                    let ts = u64::from_le_bytes(record.at(8..16)?.try_into()?);
                    if ts != 0 && !timestamps.contains_key(&ts) {
                        break;
                    }
                    if seen.contains(&entry) {
                        continue;
                    }
                    if strings == 0 {
                        limited = Some("Bash 命令字符串读取达到 64 MiB 上限");
                        break 'arrays;
                    }
                    let command = match user_string(vm, line, 65536, job) {
                        Ok(v) if !v.is_empty() => v,
                        _ => break,
                    };
                    strings = strings.saturating_sub(command.len() + 1);
                    if seen.insert(entry) {
                        recovered.push((timestamps.get(&ts).copied(), entry, command));
                    }
                    if n == LIMIT as u64 {
                        limited = Some("Bash 历史指针数组达到项数上限");
                    }
                }
            }
        }
        found.extend(recovered);
        // volatility3 orders history by timestamp; untimestamped entries keep
        // their array order after them.
        found.sort_by_key(|(time, _, _)| (time.is_none(), *time));
        for (time, address, command) in found {
            r.rows.push(
                [
                    prefix.to_vec(),
                    vec![
                        time.map_or_else(|| "[missing]".into(), |t| t.to_string()),
                        command,
                        hex(address),
                    ],
                ]
                .concat(),
            );
        }
        if unreadable > 0 {
            partial(
                r,
                format!("PID {pid} Bash 记录"),
                anyhow::anyhow!("{unreadable} 个候选记录的命令字符串不可读"),
            );
        }
        if let Some(reason) = limited {
            partial(r, format!("PID {pid} Bash 扫描"), anyhow::anyhow!(reason));
        }
        Ok(())
    }
    /// Exclusive upper bound of user virtual addresses for the image architecture.
    fn user_ceiling(&self) -> u64 {
        let bits = self
            .vm
            .image
            .arm64_va_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        1u64 << if bits == 0 { 47 } else { bits }
    }
    /// Resident heap pages of one process as contiguous runs: VMAs overlapping
    /// `start_brk..brk` (every writable VMA without brk fields or a heap
    /// mapping). Pages are read one at a time, so an absent page only skips
    /// itself; gaps and the 256 MiB bound become diagnostics and the runs read
    /// before them are kept.
    fn heap_blocks(
        &self,
        mm: u64,
        vm: &VirtualMemory<'_>,
        nodes: &[u64],
        context: &str,
        r: &mut Results,
        job: &Job,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        let heap = self
            .number(mm, "mm_struct", "start_brk")
            .and_then(|start| Ok((start, self.number(mm, "mm_struct", "brk")?)))
            .ok();
        let mut heap_ranges = Vec::new();
        let mut writable = Vec::new();
        for &node in nodes {
            let vma = (|| -> Result<(u64, u64, u64)> {
                let start = self.number(node, "vm_area_struct", "vm_start")?;
                let end = self.number(node, "vm_area_struct", "vm_end")?;
                ensure!(start < end, "VMA 地址倒置");
                Ok((start, end, self.number(node, "vm_area_struct", "vm_flags")?))
            })();
            match vma {
                Ok((start, end, flags)) => {
                    if heap.is_some_and(|(low, high)| start <= high && end >= low) {
                        heap_ranges.push((start, end));
                    }
                    if flags & 3 == 3 {
                        writable.push((start, end));
                    }
                }
                Err(e) => partial(r, format!("{context} VMA {}", hex(node)), e),
            }
        }
        let ranges = if heap_ranges.is_empty() {
            writable
        } else {
            heap_ranges
        };
        let mut budget = 256 * 1024 * 1024usize;
        let mut missing = 0u64;
        let mut first_missing = None;
        let mut blocks: Vec<(u64, Vec<u8>)> = Vec::new();
        'scan: for (start, end) in ranges {
            let mut run: Option<(u64, Vec<u8>)> = None;
            let mut pos = start & !4095;
            while pos < end {
                job.check()?;
                if budget < 4096 {
                    blocks.extend(run.take());
                    partial(
                        r,
                        format!("{context} 扫描"),
                        anyhow::anyhow!("达到每进程 256 MiB 上限"),
                    );
                    break 'scan;
                }
                budget -= 4096;
                let mut page = [0u8; 4096];
                if vm.read(pos, &mut page).is_ok() {
                    run.get_or_insert_with(|| (pos, Vec::new()))
                        .1
                        .extend_from_slice(&page);
                } else {
                    missing += 1;
                    first_missing.get_or_insert(pos);
                    blocks.extend(run.take());
                }
                pos += 4096;
            }
            blocks.extend(run);
        }
        if missing > 0 {
            partial(
                r,
                format!("{context} 扫描"),
                anyhow::anyhow!(
                    "{missing} 个页面不可读，已跳过（首个 {:#x}）",
                    first_missing.unwrap_or_default()
                ),
            );
        }
        Ok(blocks)
    }
    /// Zsh history (zsh 4.3–5.9 `struct histent`, LP64): the heap is scanned
    /// for entries `{ node.next, node.nam, node.flags, up, down, zle_text,
    /// stim, ftim, words, nwords, histnum }` whose up/down neighbour links
    /// back to them and whose start time is a plausible epoch, then the
    /// validated doubly linked ring is followed. zsh records times in memory
    /// regardless of EXTENDED_HISTORY.
    pub(super) fn zsh_history(
        &self,
        mm: u64,
        vm: &VirtualMemory<'_>,
        nodes: &[u64],
        prefix: &[String],
        r: &mut Results,
        job: &Job,
    ) -> Result<()> {
        const NAM: usize = 8;
        const UP: usize = 24;
        const DOWN: usize = 32;
        const STIM: usize = 48;
        const FTIM: usize = 56;
        const NWORDS: usize = 72;
        const HISTNUM: usize = 80;
        const SIZE: usize = 88;
        let pid = prefix.first().cloned().unwrap_or_default();
        let ceiling = self.user_ceiling();
        let user = |p: u64| p != 0 && p & 7 == 0 && p < ceiling;
        let epoch = |t: u64| (315532800..=4102444800).contains(&t);
        // Field checks shared by scanned and linked entries.
        let shape = |e: &[u8]| -> Result<Option<Histent>> {
            let word =
                |o: usize| -> Result<u64> { Ok(u64::from_le_bytes(e.at(o..o + 8)?.try_into()?)) };
            let (nam, up, down) = (word(NAM)?, word(UP)?, word(DOWN)?);
            let (stim, ftim, histnum) = (word(STIM)?, word(FTIM)?, word(HISTNUM)?);
            let nwords = i32::from_le_bytes(e.at(NWORDS..NWORDS + 4)?.try_into()?);
            let valid = nam != 0
                && nam < ceiling
                && user(up)
                && user(down)
                && epoch(stim)
                && (ftim == 0 || (ftim >= stim && epoch(ftim)))
                && (1..1 << 40).contains(&histnum)
                && (0..=1 << 20).contains(&nwords);
            Ok(valid.then_some(Histent {
                nam,
                up,
                down,
                stim,
                ftim,
                histnum,
            }))
        };
        let blocks = self.heap_blocks(mm, vm, nodes, &format!("PID {pid} Zsh"), r, job)?;
        let linked = |address: u64, next: u64, back: usize| -> bool {
            vm.uint(next + back as u64, 8).is_ok_and(|v| v == address)
        };
        let mut queue = Vec::new();
        for (start, bytes) in &blocks {
            for i in (0..bytes.len().saturating_sub(SIZE - 1)).step_by(8) {
                job.check()?;
                let Some(Histent { up, down, .. }) = shape(bytes.at(i..i + SIZE)?)? else {
                    continue;
                };
                let address = start + i as u64;
                if linked(address, down, UP) || linked(address, up, DOWN) {
                    queue.push(address);
                }
            }
        }
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        let mut strings = 64 * 1024 * 1024usize;
        let mut unreadable = 0u64;
        let mut limited = false;
        while let Some(address) = queue.pop() {
            job.check()?;
            if !seen.insert(address) {
                continue;
            }
            if seen.len() > LIMIT {
                limited = true;
                break;
            }
            let mut e = [0u8; SIZE];
            if vm.read(address, &mut e).is_err() {
                continue;
            }
            let Some(Histent {
                nam,
                up,
                down,
                stim,
                ftim,
                histnum,
            }) = shape(&e)?
            else {
                continue;
            };
            // Follow the ring both ways, but only across mutual links.
            if linked(address, down, UP) {
                queue.push(down);
            }
            if linked(address, up, DOWN) {
                queue.push(up);
            }
            if strings == 0 {
                limited = true;
                break;
            }
            match user_string(vm, nam, 65536, job) {
                Ok(command) if !command.is_empty() => {
                    strings = strings.saturating_sub(command.len() + 1);
                    entries.push((histnum, stim, ftim, command, address));
                }
                Ok(_) => {}
                Err(_) => {
                    job.check()?;
                    unreadable += 1;
                }
            }
        }
        entries.sort_by_key(|e| (e.0, e.4));
        for (histnum, stim, ftim, command, address) in entries {
            r.rows.push(
                [
                    prefix.to_vec(),
                    vec![
                        histnum.to_string(),
                        stim.to_string(),
                        if ftim == 0 {
                            "[none]".into()
                        } else {
                            ftim.to_string()
                        },
                        command,
                        hex(address),
                    ],
                ]
                .concat(),
            );
        }
        if unreadable > 0 {
            partial(
                r,
                format!("PID {pid} Zsh 记录"),
                anyhow::anyhow!("{unreadable} 个历史条目的命令字符串不可读"),
            );
        }
        if limited {
            partial(
                r,
                format!("PID {pid} Zsh 扫描"),
                anyhow::anyhow!("达到历史条目或 64 MiB 字符串上限"),
            );
        }
        Ok(())
    }
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
        use crate::linux::tests::{engine, fixture, image};
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
        // library_list ignores anonymous ELF images such as this one.
        let r = engine(&img, &isf)
            .run(Plugin::LibraryList, &Job::default())
            .unwrap();
        assert!(r.complete && r.rows.is_empty(), "{:?}", r.rows);
        let mut file_backed = b.clone();
        put(&mut file_backed, 0xc828, 0x3f000);
        let library = image(&file_backed);
        let r = engine(&library, &isf)
            .run(Plugin::LibraryList, &Job::default())
            .unwrap();
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0][2..], [hex(0x200000), "[unresolved]".into()]);
        assert!(!r.complete, "an unresolved path must stay a partial result");
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
    fn bash_skips_absent_pages_orders_by_time_and_accepts_sh() {
        use crate::linux::tests::{engine, fixture, image};
        let (mut b, mut isf) = fixture();
        for (name, offset) in [("start_brk", 48), ("brk", 56)] {
            isf.data["user_types"]["mm_struct"]["fields"][name] =
                serde_json::json!({"offset":offset,"type":{"kind":"base","name":"u64"}});
        }
        isf.invalidate_layouts();
        b[0xa028..0xa02b].copy_from_slice(b"sh\0");
        put(&mut b, 0xb028, 0xc800);
        put(&mut b, 0xb030, 0x200000);
        put(&mut b, 0xb038, 0x202800);
        // One heap VMA of three pages; the third page is absent.
        put(&mut b, 0xc808, 0x200000);
        put(&mut b, 0xc810, 0x203000);
        put(&mut b, 0xc818, 3);
        b[0x20000..0x21000].fill(0);
        put(&mut b, 0x20010, 0x200040);
        put(&mut b, 0x20018, 0x200080);
        b[0x20040..0x2004a].copy_from_slice(b"echo test\0");
        b[0x20080..0x2008c].copy_from_slice(b"#1700000000\0");
        b[0x25000..0x26000].fill(0);
        put(&mut b, 0x25200, 0x201240);
        put(&mut b, 0x25208, 0x201280);
        b[0x25240..0x25247].copy_from_slice(b"whoami\0");
        b[0x25280..0x2528c].copy_from_slice(b"#1600000000\0");
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::Bash, &Job::default())
            .unwrap();
        let commands: Vec<_> = r
            .rows
            .iter()
            .map(|r| (r[2].as_str(), r[3].as_str()))
            .collect();
        assert_eq!(
            commands,
            [("1600000000", "whoami"), ("1700000000", "echo test")]
        );
        assert!(!r.complete);
        assert!(
            r.diagnostics.iter().any(|d| d.contains("1 个页面不可读")),
            "{:?}",
            r.diagnostics
        );
    }
    #[test]
    fn zsh_follows_mutually_linked_histent_ring_and_rejects_decoys() {
        use crate::linux::tests::{engine, fixture, image};
        let (mut b, isf) = fixture();
        // VA 0x200000 -> 0x20000 and 0x201000 -> 0x25000; 0x202000 is absent.
        let phys = |va: u64| -> usize {
            if va >= 0x201000 {
                (va - 0x201000 + 0x25000) as usize
            } else {
                (va - 0x200000 + 0x20000) as usize
            }
        };
        b[0xa028..0xa02c].copy_from_slice(b"zsh\0");
        put(&mut b, 0xb028, 0xc800);
        put(&mut b, 0xc808, 0x200000);
        put(&mut b, 0xc810, 0x203000);
        put(&mut b, 0xc818, 3);
        b[0x20000..0x21000].fill(0);
        b[0x25000..0x26000].fill(0);
        let curline = 0x201f00u64;
        let entries = [
            (
                0x200100u64,
                0x200800u64,
                "ls -la",
                1u64,
                1_700_000_000u64,
                1_700_000_005u64,
            ),
            (0x200200, 0x200840, "whoami", 2, 1_700_000_010, 0),
            (0x201100, 0x201800, "id", 3, 1_700_000_020, 1_700_000_021),
        ];
        for (n, (at, nam, command, histnum, stim, ftim)) in entries.iter().enumerate() {
            let up = if n == 0 { curline } else { entries[n - 1].0 };
            let down = entries.get(n + 1).map_or(curline, |e| e.0);
            let e = phys(*at);
            put(&mut b, e + 8, *nam);
            put(&mut b, e + 24, up);
            put(&mut b, e + 32, down);
            put(&mut b, e + 48, *stim);
            put(&mut b, e + 56, *ftim);
            put(&mut b, e + 72, 2);
            put(&mut b, e + 80, *histnum);
            let s = phys(*nam);
            b[s..s + command.len()].copy_from_slice(command.as_bytes());
        }
        // The current-line sentinel closes the ring but has no start time.
        put(&mut b, phys(curline) + 24, entries[2].0);
        put(&mut b, phys(curline) + 32, entries[0].0);
        // A completion-table node: plausible name, no mutual links.
        put(&mut b, 0x20408, 0x200880);
        put(&mut b, 0x20418, 0x200500);
        put(&mut b, 0x20420, 0x200600);
        put(&mut b, 0x20430, 1_700_000_000);
        put(&mut b, 0x20450, 4);
        b[0x20880..0x20886].copy_from_slice(b"lsblk\0");
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::Zsh, &Job::default())
            .unwrap();
        assert_eq!(
            r.columns,
            [
                "PID", "Name", "HistNum", "Started", "Finished", "Command", "Address"
            ]
        );
        let rows: Vec<_> = r.rows.iter().map(|r| r[2..6].to_vec()).collect();
        assert_eq!(
            rows,
            [
                ["1", "1700000000", "1700000005", "ls -la"],
                ["2", "1700000010", "[none]", "whoami"],
                ["3", "1700000020", "1700000021", "id"],
            ]
        );
        assert!(!r.complete);
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.contains("Zsh 扫描") && d.contains("1 个页面不可读")),
            "{:?}",
            r.diagnostics
        );
        // Other shells are not scanned.
        b[0xa028..0xa02c].copy_from_slice(b"ksh\0");
        let img = image(&b);
        let r = engine(&img, &isf)
            .run(Plugin::Zsh, &Job::default())
            .unwrap();
        assert!(r.rows.is_empty() && r.complete, "{:?}", r.diagnostics);
    }
    #[test]
    fn pid_cross_view_detects_unlinked_task_and_rejects_cycles() {
        use crate::linux::tests::{engine, fixture, image};
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
        // pidhashtable sees the unlinked task through the PID index alone.
        let r = engine(&img, &isf)
            .run(Plugin::Pidhashtable, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        let pids: Vec<_> = r.rows.iter().map(|row| row[1].as_str()).collect();
        assert_eq!(pids, ["1", "2", "3"]);
        assert_eq!(r.rows[2][0], hex(0xa200));
        assert_eq!(r.rows[2][4], "hidden");
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
        use crate::linux::tests::{engine, fixture, image};
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

impl Linux<'_> {
    /// Compare the recorded main-code interval against its VMA and exe_file.
    /// No disk bytes are read; this is a structural hollowing lead only.
    pub(super) fn check_exec(&self, job: &Job) -> Result<Results> {
        self.require(&[
            ("mm_struct", "start_code"),
            ("mm_struct", "end_code"),
            ("mm_struct", "exe_file"),
        ])?;
        let (mut result, tasks) = self.tasks(Plugin::CheckExec, job)?;
        for task in tasks {
            job.check()?;
            let read = (|| -> Result<()> {
                let mm = self.number(task.address, "task_struct", "mm")?;
                if mm == 0 {
                    return Ok(());
                }
                let start = self.number(mm, "mm_struct", "start_code")?;
                let end = self.number(mm, "mm_struct", "end_code")?;
                ensure!(start < end, "主程序代码范围无效");
                let exe = self.number(mm, "mm_struct", "exe_file")?;
                let nodes = self.vma_nodes(mm, job, &mut result)?;
                let mut ranges = Vec::new();
                for node in nodes {
                    job.check()?;
                    let vstart = self.number(node, "vm_area_struct", "vm_start")?;
                    let vend = self.number(node, "vm_area_struct", "vm_end")?;
                    ensure!(vstart < vend, "VMA 地址倒置");
                    ranges.push((vstart, vend, node));
                }
                ranges.sort_unstable();
                ranges.dedup();
                ensure!(
                    ranges
                        .windows(2)
                        .all(|pair| matches!(pair, [a, b] if a.1 <= b.0)),
                    "VMA 范围重叠"
                );
                let mut covered = start;
                for (vstart, vend, node) in ranges {
                    job.check()?;
                    if vend <= start || vstart >= end {
                        continue;
                    }
                    let flags = self.number(node, "vm_area_struct", "vm_flags")?;
                    let file = self.number(node, "vm_area_struct", "vm_file")?;
                    let mut reasons = Vec::new();
                    if vstart > covered {
                        reasons.push("MainCodeMappingGap");
                    }
                    covered = covered.max(vend.min(end));
                    if flags & 4 == 0 {
                        reasons.push("MainCodeNotExecutable");
                    }
                    if file == 0 {
                        reasons.push("AnonymousMainCode");
                    }
                    // Distinct file objects can refer to the same inode.
                    if exe != 0 && file != 0 && file != exe {
                        let inode = |f| -> Result<u64> {
                            if self.isf.field("file", "f_inode").is_ok() {
                                self.number(f, "file", "f_inode")
                            } else {
                                let path = self.field_address(f, "file", "f_path")?;
                                let dentry = self.number(path, "path", "dentry")?;
                                self.number(dentry, "dentry", "d_inode")
                            }
                        };
                        let expected = inode(exe)?;
                        let actual = inode(file)?;
                        ensure!(expected != 0 && actual != 0, "代码映射 inode 不存在");
                        if expected != actual {
                            reasons.push("MainCodeFileMismatch");
                        }
                    }
                    if !reasons.is_empty() {
                        let path = if file == 0 {
                            "[anonymous]".into()
                        } else {
                            match self.file_path(task.address, file, job) {
                                Ok(path) => path,
                                Err(e) => {
                                    job.check()?;
                                    partial(&mut result, format!("PID {} code path", task.pid), e);
                                    "[unresolved]".into()
                                }
                            }
                        };
                        result.rows.push(vec![
                            task.pid.clone(),
                            task.name.clone(),
                            hex(vstart),
                            hex(vend),
                            permissions(flags),
                            path,
                            reasons.join("; "),
                        ]);
                    }
                }
                if covered < end {
                    result.rows.push(vec![
                        task.pid.clone(),
                        task.name.clone(),
                        hex(covered),
                        hex(end),
                        String::new(),
                        String::new(),
                        "MissingMainCodeMapping".into(),
                    ]);
                }
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                partial(&mut result, format!("PID {} check_exec", task.pid), e);
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod check_exec_tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};
    use serde_json::json;
    fn put(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    #[test]
    fn main_code_anomalies_gaps_and_corrupt_vma_are_distinct() {
        let (mut bytes, mut isf) = fixture();
        for (name, offset) in [("start_code", 48), ("end_code", 56), ("exe_file", 64)] {
            isf.data["user_types"]["mm_struct"]["fields"][name] =
                json!({"offset":offset,"type":{"kind":"pointer"}});
        }
        isf.data["user_types"]["mm_struct"]["size"] = json!(72);
        put(&mut bytes, 0xb030, 0x200000);
        put(&mut bytes, 0xb038, 0x201000);
        put(&mut bytes, 0xb028, 0xc800);
        put(&mut bytes, 0xc808, 0x200000);
        put(&mut bytes, 0xc810, 0x201000);
        put(&mut bytes, 0xc818, 5);
        let analyze = |bytes: &[u8]| {
            let img = image(bytes);
            engine(&img, &isf)
                .run(Plugin::CheckExec, &Job::default())
                .unwrap()
        };
        let r = analyze(&bytes);
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0][6], "AnonymousMainCode");
        put(&mut bytes, 0xc818, 1);
        assert!(analyze(&bytes).rows[0][6].contains("MainCodeNotExecutable"));
        put(&mut bytes, 0xc808, 0x200800);
        assert!(analyze(&bytes).rows[0][6].contains("MainCodeMappingGap"));
        put(&mut bytes, 0xc800, 0xc800);
        let r = analyze(&bytes);
        assert!(!r.complete);
        assert!(
            r.rows.is_empty(),
            "corrupt traversal must not imply a missing mapping"
        );
        put(&mut bytes, 0xb028, 0);
        assert_eq!(analyze(&bytes).rows[0][6], "MissingMainCodeMapping");
        // A distinct file object for the same inode is not a file mismatch.
        put(&mut bytes, 0xb028, 0xc800);
        put(&mut bytes, 0xc800, 0);
        put(&mut bytes, 0xc808, 0x200000);
        put(&mut bytes, 0xc818, 5);
        put(&mut bytes, 0xb040, 0xc900);
        put(&mut bytes, 0xc828, 0xca00);
        let path_offset = isf.offset("file", "f_path").unwrap() as usize;
        let dentry_offset = isf.offset("path", "dentry").unwrap() as usize;
        let inode_offset = isf.offset("dentry", "d_inode").unwrap() as usize;
        put(&mut bytes, 0xc900 + path_offset + dentry_offset, 0xcb00);
        put(&mut bytes, 0xca00 + path_offset + dentry_offset, 0xcc00);
        put(&mut bytes, 0xcb00 + inode_offset, 0xcd00);
        put(&mut bytes, 0xcc00 + inode_offset, 0xcd00);
        let r = analyze(&bytes);
        assert!(r.complete, "{:?}", r.diagnostics);
        assert!(r.rows.is_empty());
    }
}
