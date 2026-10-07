//! Bounded user-memory scans. Layout facts: Volatility 3 v2.28 service/conhost ISFs.
//! These are independent Rust parsers, not runtime Python plugins.
use super::user_layout::{self, ServiceLayout};
use super::*;
fn layout_tag_offset(layout: &ServiceLayout) -> Result<u64> {
    layout
        .fields
        .get("Tag")
        .copied()
        .context("服务记录缺少 Tag 偏移")
}
const SCAN_LIMIT: u64 = 128 * 1024 * 1024;
fn user(vm: &Memory<'_>, address: u64) -> bool {
    address >= 0x10000 && !vm.kernel(address) && vm.paging().is_ok_and(|p| p.canonical(address))
}
fn wide_string(vm: &Memory<'_>, address: u64) -> Result<String> {
    ensure!(
        user(vm, address) && address.is_multiple_of(2),
        "无效用户字符串地址"
    );
    let mut units = Vec::new();
    for i in 0..2048 {
        let n = vm.uint(add(address, i * 2)?, 2)? as u16;
        if n == 0 {
            return String::from_utf16(&units).context("用户字符串 UTF-16 无效");
        }
        units.push(n);
    }
    bail!("用户字符串未终止/超限")
}
fn command(vm: &Memory<'_>, address: u64) -> Result<String> {
    let length = vm.uint(add(address, 16)?, 4)?;
    let allocated = vm.uint(add(address, 24)?, 4)?;
    ensure!(
        length > 0 && length <= 32768 && allocated >= length && allocated <= 32768,
        "命令字符串长度无效"
    );
    let source = if allocated < 8 {
        address
    } else {
        vm.pointer(address)?
    };
    ensure!(user(vm, source), "命令字符串指针无效");
    let mut b = vec![0; length as usize * 2];
    vm.read(source, &mut b)?;
    String::from_utf16(
        &b.chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect::<Vec<_>>(),
    )
    .context("命令 UTF-16 无效")
}
impl Windows<'_> {
    pub(super) fn user_artifacts(
        &self,
        plugin: Plugin,
        options: &Options,
        job: &Job,
    ) -> Result<Results> {
        let mut result = self.result(plugin);
        let (processes, diagnostics) = self.processes_partial(job)?;
        result.complete = diagnostics.is_empty();
        result.diagnostics = diagnostics;
        for p in processes
            .into_iter()
            .filter(|p| options.pid.is_none_or(|pid| p.pid == u64::from(pid)))
        {
            let expected = if plugin == Plugin::WinSvcscan {
                "services.exe"
            } else {
                "conhost.exe"
            };
            if !p.name.eq_ignore_ascii_case(expected) {
                continue;
            }
            job.check()?;
            let read = (|| -> Result<()> {
                let vm = self.process_memory(&p)?;
                let arch = Architecture::from_isf(self.vm.isf)?;
                let mut dll_result = self.result(Plugin::WinDlllist);
                let modules = self.dlls(&p, job, &mut dll_result)?;
                if !dll_result.complete {
                    result.complete = false;
                    result.diagnostics.extend(dll_result.diagnostics);
                }
                let base = modules
                    .iter()
                    .find(|m| {
                        m.2.rsplit(['\\', '/'])
                            .next()
                            .is_some_and(|name| name.eq_ignore_ascii_case(expected))
                    })
                    .map(|m| m.0)
                    .context("缺少可验证的进程 PE 模块")?;
                let version = match network_layout::file_version(&vm, base) {
                    Ok(version) => version,
                    Err(e) if plugin == Plugin::WinSvcscan => {
                        let version = self.declared_kernel_version()?;
                        user_layout::service(arch, version)?;
                        Self::issue(
                            &mut result,
                            format!("PID {} services identity", p.pid),
                            format!("PE 版本不可读，使用声明的内核构建布局: {e:#}"),
                        );
                        version
                    }
                    Err(e) => return Err(e),
                };
                let service_layout = if plugin == Plugin::WinSvcscan {
                    Some(user_layout::service(arch, version)?)
                } else {
                    None
                };
                let console_layout = if plugin != Plugin::WinSvcscan {
                    Some(user_layout::console(arch, version)?)
                } else {
                    None
                };
                let source = service_layout
                    .as_ref()
                    .map(|l| l.source.as_str())
                    .or_else(|| console_layout.as_ref().map(|l| l.source.as_str()))
                    .unwrap();
                result.kernel_identity[format!("pid{}_layout", p.pid)] = serde_json::json!({"file_version":version,"source":source,"validation":"synthetic"});
                Self::issue(
                    &mut result,
                    format!("PID {} layout", p.pid),
                    "版本布局尚未完成此精确 PE 身份的真实样本验收",
                );
                let vads = self.vads_partial(&p, job, Some(&mut result))?;
                let mut scanned = 0;
                let mut seen = HashSet::new();
                let mut missing = 0;
                for vad in vads {
                    let mut address = vad.start;
                    while address < vad.end {
                        job.check()?;
                        if scanned >= SCAN_LIMIT {
                            Self::issue(
                                &mut result,
                                format!("PID {} scan", p.pid),
                                "达到 128 MiB 扫描上限",
                            );
                            return Ok(());
                        }
                        let length = (vad.end - address).min(4096) as usize;
                        let mut bytes = vec![0; length];
                        if vm.read(address, &mut bytes).is_err() {
                            missing += 1;
                            address += length as u64;
                            scanned += length as u64;
                            continue;
                        }
                        if plugin == Plugin::WinSvcscan {
                            let layout = service_layout.as_ref().expect("service layout");
                            let tag: &[u8] = if version[0] < 6 { b"sErv" } else { b"serH" };
                            for hit in memchr::memmem::find_iter(&bytes, tag) {
                                let header = address + hit as u64;
                                let record = if version[0] < 6 {
                                    header
                                        .checked_sub(layout_tag_offset(layout)?)
                                        .context("service tag 下溢")
                                } else {
                                    vm.pointer(add(header, layout.header_record)?)
                                };
                                if let Ok(record) = record {
                                    self.services_chain(
                                        &vm,
                                        record,
                                        layout,
                                        &mut seen,
                                        &mut result,
                                        job,
                                    )?;
                                }
                            }
                        } else {
                            for at in (0..length).step_by(8) {
                                let candidate = address + at as u64;
                                // Cheap local structural tests before reading candidate pointers.
                                if plugin == Plugin::WinCmdscan {
                                    if at + 42 > bytes.len() {
                                        continue;
                                    }
                                    let max =
                                        u16::from_le_bytes(bytes[at + 40..at + 42].try_into()?);
                                    if !(1..=4096).contains(&max) {
                                        continue;
                                    }
                                    let begin =
                                        u64::from_le_bytes(bytes[at + 16..at + 24].try_into()?);
                                    let end =
                                        u64::from_le_bytes(bytes[at + 24..at + 32].try_into()?);
                                    if !user(&vm, begin)
                                        || end <= begin
                                        || end - begin > u64::from(max) * 32
                                        || !(end - begin).is_multiple_of(32)
                                    {
                                        continue;
                                    }
                                    if let Ok((app, commands)) = history(&vm, candidate, job)
                                        && seen.insert(candidate)
                                    {
                                        for (index, text) in commands.into_iter().enumerate() {
                                            result.rows.push(vec![
                                                p.pid.to_string(),
                                                p.name.clone(),
                                                hex(candidate),
                                                app.clone(),
                                                index.to_string(),
                                                text,
                                            ]);
                                        }
                                    }
                                } else {
                                    let layout = console_layout.as_ref().expect("console layout");
                                    let size_offset = 0;
                                    if at + size_offset + 6 > bytes.len() {
                                        continue;
                                    }
                                    let maximum = u16::from_le_bytes(
                                        bytes[at + size_offset..at + size_offset + 2].try_into()?,
                                    );
                                    let buffers = u16::from_le_bytes(
                                        bytes[at + size_offset + 4..at + size_offset + 6]
                                            .try_into()?,
                                    );
                                    if !(1..=4096).contains(&maximum)
                                        || !(1..=64).contains(&buffers)
                                    {
                                        continue;
                                    }
                                    let Some(candidate) =
                                        (address + at as u64).checked_sub(layout.maximum)
                                    else {
                                        continue;
                                    };
                                    if !user(&vm, candidate) {
                                        continue;
                                    }
                                    let read = (|| -> Result<Vec<String>> {
                                        let slot =
                                            user_layout::signed_add(candidate, layout.history)?;
                                        let head = vm.pointer(slot)?;
                                        let flink = vm.pointer(head)?;
                                        let blink = vm.pointer(add(head, 8)?)?;
                                        ensure!(
                                            user(&vm, flink)
                                                && user(&vm, blink)
                                                && vm.pointer(add(flink, 8)?)? == head
                                                && vm.pointer(blink)? == head,
                                            "console 双向链表不一致"
                                        );
                                        let count = vm.uint(add(slot, 8)?, 2)?;
                                        ensure!(
                                            count <= u64::from(buffers),
                                            "console history count 越界"
                                        );
                                        let title = wide_string(
                                            &vm,
                                            vm.pointer(add(candidate, layout.title)?)?,
                                        )?;
                                        ensure!(!title.is_empty(), "console 标题为空");
                                        Ok(vec![
                                            p.pid.to_string(),
                                            p.name.clone(),
                                            hex(candidate),
                                            title,
                                            maximum.to_string(),
                                            count.to_string(),
                                        ])
                                    })();
                                    if let Ok(row) = read
                                        && seen.insert(candidate)
                                    {
                                        result.rows.push(row);
                                    }
                                }
                            }
                        }
                        address += length as u64;
                        scanned += length as u64;
                    }
                }
                if missing > 0 {
                    Self::issue(
                        &mut result,
                        format!("PID {} scan", p.pid),
                        format!("{missing} 个不可读内存块"),
                    );
                }
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                Self::issue(
                    &mut result,
                    format!("PID {} {expected}", p.pid),
                    format!("{e:#}"),
                );
            }
        }
        Ok(result)
    }
    fn services_chain(
        &self,
        vm: &Memory<'_>,
        mut record: u64,
        layout: &ServiceLayout,
        seen: &mut HashSet<u64>,
        r: &mut Results,
        job: &Job,
    ) -> Result<()> {
        let mut chain = HashSet::new();
        for _ in 0..65536 {
            job.check()?;
            if record == 0 {
                return Ok(());
            }
            if !chain.insert(record) {
                Self::issue(r, "service chain", "服务链循环");
                return Ok(());
            }
            if seen.contains(&record) {
                return Ok(());
            }
            let read = (|| -> Result<(Vec<String>, u64)> {
                ensure!(
                    user(vm, record) && record.is_multiple_of(layout.pointer_size as u64),
                    "service record 地址无效"
                );
                let start = vm.uint(add(record, layout.fields["Start"])?, 4)?;
                let kind = vm.uint(add(record, layout.fields["Type"])?, 4)?;
                let state = vm.uint(add(record, layout.fields["State"])?, 4)?;
                ensure!(
                    start <= 4 && (1..=7).contains(&state) && kind != 0 && kind & !0x3ff == 0,
                    "service record 枚举无效"
                );
                let name =
                    wide_string(vm, vm.pointer(add(record, layout.fields["ServiceName"])?)?)?;
                ensure!(!name.is_empty(), "service 名称为空");
                let display = match vm
                    .pointer(add(record, layout.fields["DisplayName"])?)
                    .and_then(|pointer| wide_string(vm, pointer))
                {
                    Ok(text) => text,
                    Err(e) => {
                        Self::issue(r, format!("service {record:#x} display"), e);
                        String::new()
                    }
                };
                let mut pid = String::new();
                let mut binary = String::new();
                if state == 4 {
                    let read_binary = (|| -> Result<()> {
                        let pointer = vm.pointer(add(
                            record,
                            layout.fields[if kind & 0x30 != 0 {
                                "ServiceProcess"
                            } else {
                                "DriverName"
                            }],
                        )?)?;
                        ensure!(user(vm, pointer), "运行中服务指针无效");
                        if kind & 0x30 != 0 {
                            pid = vm.uint(add(pointer, layout.pid)?, 4)?.to_string();
                            binary = wide_string(vm, vm.pointer(add(pointer, layout.binary)?)?)?;
                        } else {
                            binary = wide_string(vm, pointer)?;
                        }
                        Ok(())
                    })();
                    if let Err(e) = read_binary {
                        Self::issue(r, format!("service {record:#x} binary"), e);
                    }
                }
                Ok((
                    vec![
                        pid,
                        hex(record),
                        name,
                        display,
                        state.to_string(),
                        start.to_string(),
                        format!("{kind:#x}"),
                        binary,
                    ],
                    if let Some(offset) = layout.previous {
                        vm.pointer(add(record, offset)?)?
                    } else {
                        0
                    },
                ))
            })();
            match read {
                Ok((row, previous)) => {
                    seen.insert(record);
                    r.rows.push(row);
                    record = previous;
                }
                Err(e) => {
                    if !chain.is_empty() && chain.len() > 1 {
                        Self::issue(r, format!("service record {record:#x}"), format!("{e:#}"));
                    }
                    return Ok(());
                }
            }
        }
        Self::issue(r, "service chain", "服务链超过 65536 项");
        Ok(())
    }
}
fn history(vm: &Memory<'_>, address: u64, job: &Job) -> Result<(String, Vec<String>)> {
    let app = command(vm, add(address, 48)?)?;
    let begin = vm.pointer(add(address, 16)?)?;
    let end = vm.pointer(add(address, 24)?)?;
    let capacity = vm.pointer(add(address, 32)?)?;
    let max = vm.uint(add(address, 40)?, 2)?;
    ensure!(
        user(vm, begin)
            && begin <= end
            && end <= capacity
            && (end - begin).is_multiple_of(32)
            && (capacity - begin).is_multiple_of(32)
            && (capacity - begin) / 32 <= max
            && max <= 4096,
        "命令 vector 无效"
    );
    let mut commands = Vec::new();
    for at in (begin..end).step_by(32) {
        job.check()?;
        commands.push(command(vm, at)?);
    }
    ensure!(!commands.is_empty(), "命令历史为空");
    Ok((app, commands))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{fixture, image, put};
    use super::*;
    #[test]
    fn command_vector_validates_strings_capacity_and_bounds() {
        let (mut b, isf) = fixture();
        put(&mut b, 0x1000, 0x2003);
        let text = |b: &mut [u8], at: usize, s: &str| {
            let units: Vec<_> = s.encode_utf16().collect();
            for (i, u) in units.iter().enumerate() {
                b[at + i * 2..at + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
            }
            b[at + 16..at + 20].copy_from_slice(&(units.len() as u32).to_le_bytes());
            b[at + 24..at + 28].copy_from_slice(&7u32.to_le_bytes());
        };
        put(&mut b, 0x1b010, 0x14000);
        put(&mut b, 0x1b018, 0x14020);
        put(&mut b, 0x1b020, 0x14040);
        b[0x1b028..0x1b02a].copy_from_slice(&50u16.to_le_bytes());
        text(&mut b, 0x1b030, "cmd.exe");
        text(&mut b, 0x1c000, "whoami");
        let img = image(&b);
        let vm = Memory::new(&img, 0x1000, &isf, None);
        assert_eq!(
            history(&vm, 0x13000, &Job::default()).unwrap(),
            ("cmd.exe".into(), vec!["whoami".into()])
        );
        put(&mut b, 0x1b020, 0x14010);
        let img = image(&b);
        let vm = Memory::new(&img, 0x1000, &isf, None);
        assert!(history(&vm, 0x13000, &Job::default()).is_err());
    }
    #[test]
    fn service_records_keep_runtime_ownership_and_detect_bad_layout() {
        let (mut b, isf) = fixture();
        put(&mut b, 0x1000, 0x2003);
        b[0x1b024..0x1b028].copy_from_slice(&2u32.to_le_bytes());
        b[0x1b048..0x1b04c].copy_from_slice(&16u32.to_le_bytes());
        b[0x1b04c..0x1b050].copy_from_slice(&4u32.to_le_bytes());
        put(&mut b, 0x1b038, 0x14000);
        put(&mut b, 0x1b040, 0x14040);
        put(&mut b, 0x1b0e8, 0x15000);
        put(&mut b, 0x1d018, 0x14080);
        b[0x1d020..0x1d024].copy_from_slice(&123u32.to_le_bytes());
        for (at, text) in [
            (0x1c000, "Svc"),
            (0x1c040, "Service"),
            (0x1c080, "C:\\svc.exe"),
        ] {
            let bytes: Vec<u8> = text
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect();
            b[at..at + bytes.len()].copy_from_slice(&bytes);
        }
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: super::super::tests::K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let mut r = engine.result(Plugin::WinSvcscan);
        let mut seen = HashSet::new();
        engine
            .services_chain(
                &engine.vm,
                0x13000,
                &user_layout::service(Architecture::X64, [10, 0, 15063, 0]).unwrap(),
                &mut seen,
                &mut r,
                &Job::default(),
            )
            .unwrap();
        assert_eq!(r.rows[0][0], "123");
        assert_eq!(r.rows[0][7], "C:\\svc.exe");
        let mut r = engine.result(Plugin::WinSvcscan);
        engine
            .services_chain(
                &engine.vm,
                0x13000,
                &user_layout::service(Architecture::X64, [10, 0, 19041, 0]).unwrap(),
                &mut HashSet::new(),
                &mut r,
                &Job::default(),
            )
            .unwrap();
        assert_eq!(r.rows.len(), 1);
        assert!(r.rows[0][7].is_empty());
        assert!(!r.complete);
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    #[test]
    fn every_declared_service_layout_reads_names_pid_binary_and_cycles() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("user_layouts.json")).unwrap();
        for (name, data) in manifest["services"].as_object().unwrap() {
            let layout: ServiceLayout = serde_json::from_value(data.clone()).unwrap();
            let (mut b, mut isf) = fixture();
            if layout.pointer_size == 4 {
                isf.data["base_types"]["pointer"]["size"] = json!(4);
                isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
                b[0x1000..0x3000].fill(0);
                b[0x1000..0x1004].copy_from_slice(&0x2003u32.to_le_bytes());
                for i in 0..32 {
                    b[0x2000 + i * 4..0x2000 + i * 4 + 4]
                        .copy_from_slice(&(0x8003 + i as u32 * 4096).to_le_bytes());
                }
            } else {
                put(&mut b, 0x1000, 0x2003);
            }
            b[0x1b000..0x1e000].fill(0);
            let store = |b: &mut [u8], at: u64, n: u64, width: usize| {
                b[at as usize..at as usize + width].copy_from_slice(&n.to_le_bytes()[..width]);
            };
            for (field, value) in [("Start", 2), ("Type", 16), ("State", 4)] {
                store(&mut b, 0x1b000 + layout.fields[field], value, 4);
            }
            for (field, pointer) in [
                ("ServiceName", 0x14000),
                ("DisplayName", 0x14040),
                ("ServiceProcess", 0x15000),
            ] {
                store(
                    &mut b,
                    0x1b000 + layout.fields[field],
                    pointer,
                    layout.pointer_size,
                );
            }
            store(
                &mut b,
                0x1d000 + layout.binary,
                0x14080,
                layout.pointer_size,
            );
            store(&mut b, 0x1d000 + layout.pid, 123, 4);
            if let Some(offset) = layout.previous {
                store(&mut b, 0x1b000 + offset, 0x13000, layout.pointer_size);
            }
            for (at, text) in [
                (0x1c000, "TestSvc"),
                (0x1c040, "Test Service"),
                (0x1c080, "C:\\svc.exe"),
            ] {
                let text: Vec<u8> = text
                    .encode_utf16()
                    .chain([0])
                    .flat_map(u16::to_le_bytes)
                    .collect();
                b[at..at + text.len()].copy_from_slice(&text);
            }
            let img = image(&b);
            let w = Windows {
                vm: Memory::new(&img, 0x1000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let mut r = w.result(Plugin::WinSvcscan);
            w.services_chain(
                &w.vm,
                0x13000,
                &layout,
                &mut HashSet::new(),
                &mut r,
                &Job::default(),
            )
            .unwrap();
            assert_eq!(r.rows.len(), 1, "{name}: {:?}", r.diagnostics);
            assert_eq!(r.rows[0][0], "123", "{name}");
            assert_eq!(r.rows[0][2], "TestSvc");
            assert_eq!(r.rows[0][7], "C:\\svc.exe");
            assert_eq!(r.complete, layout.previous.is_none());
        }
    }
}
