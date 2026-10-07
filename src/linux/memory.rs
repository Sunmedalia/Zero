//! Process memory views: mappings, ELF headers, injected code and bash history.
use super::*;
pub(super) fn header(bytes: &[u8], arm: bool) -> Result<(String, u64)> {
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
            self.maple_vmas(mm, job, limit)?.into_iter()
        } else {
            Vec::new().into_iter()
        };
        let mut node = if modern {
            nodes.next().unwrap_or(0)
        } else {
            self.number(mm, "mm_struct", "mmap")?
        };
        let mut visited = HashSet::new();
        while node != 0 {
            job.check()?;
            ensure!(visited.insert(node), "VMA 循环 @ {}", hex(node));
            ensure!(visited.len() as u64 <= limit, "VMA 超过 100 万项上限");
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
                    match self.file_path(task, file, job) {
                        Ok(path) => path,
                        Err(e) => {
                            job.check()?;
                            partial(
                                result,
                                format!("PID {} VMA {} 路径", prefix[0], hex(node)),
                                e,
                            );
                            "[unresolved]".into()
                        }
                    }
                };
                Ok([
                    prefix.clone(),
                    vec![
                        hex(start),
                        hex(end),
                        permissions(flags),
                        offset.to_string(),
                        path,
                    ],
                ]
                .concat())
            })();
            match row {
                Ok(row) => result.rows.push(row),
                Err(e) => partial(result, format!("PID {} VMA {}", prefix[0], hex(node)), e),
            }
            node = next;
        }
        Ok(())
    }
    /// elfs / malfind / bash / history: bounded reads of each task's mapped regions.
    pub(super) fn vma_scan(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        let mut r = self.result(plugin);
        let (listed, tasks) = self.tasks(plugin, job)?;
        r.complete = listed.complete;
        r.diagnostics = listed.diagnostics;
        for row in tasks {
            job.check()?;
            let task = row.address;
            if matches!(plugin, Plugin::Bash | Plugin::History) && row.name != "bash" {
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
                        &[row.pid.clone(), row.name.clone()],
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
                                        format!("PID {} VMA {node:#x} 路径", row.pid),
                                        e,
                                    );
                                    "[unresolved]".into()
                                }
                            }
                        };
                        let mut values =
                            vec![row.pid.clone(), row.name.clone(), hex(start), hex(end)];
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
    pub(super) fn bash_history(
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
                let nodes = self.vma_nodes(mm, job)?;
                let mut ranges = Vec::new();
                for node in nodes {
                    job.check()?;
                    let vstart = self.number(node, "vm_area_struct", "vm_start")?;
                    let vend = self.number(node, "vm_area_struct", "vm_end")?;
                    ensure!(vstart < vend, "VMA 地址倒置");
                    ranges.push((vstart, vend, node));
                }
                ranges.sort_by_key(|range| range.0);
                ensure!(
                    ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0),
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
