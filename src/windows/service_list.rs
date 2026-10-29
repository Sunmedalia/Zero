//! Services anchored in the executable VAD, with registry binary information.
use super::user_layout::{self, ServiceLayout};
use super::*;

const NA: &str = "N/A";
const MAX_CHAIN: usize = 65536;
const MAX_SCAN: u64 = 128 * 1024 * 1024;
type BinaryMap = BTreeMap<String, [String; 2]>; // ImagePath, Parameters.ServiceDll
const START: [&str; 5] = [
    "SERVICE_BOOT_START",
    "SERVICE_SYSTEM_START",
    "SERVICE_AUTO_START",
    "SERVICE_DEMAND_START",
    "SERVICE_DISABLED",
];
const STATE: [&str; 7] = [
    "SERVICE_STOPPED",
    "SERVICE_START_PENDING",
    "SERVICE_STOP_PENDING",
    "SERVICE_RUNNING",
    "SERVICE_CONTINUE_PENDING",
    "SERVICE_PAUSE_PENDING",
    "SERVICE_PAUSED",
];

fn types(kind: u64) -> String {
    [
        (1, "SERVICE_KERNEL_DRIVER"),
        (2, "SERVICE_FILE_SYSTEM_DRIVER"),
        (4, "SERVICE_ADAPTOR"),
        (8, "SERVICE_RECOGNIZER_DRIVER"),
        (16, "SERVICE_WIN32_OWN_PROCESS"),
        (32, "SERVICE_WIN32_SHARE_PROCESS"),
        (256, "SERVICE_INTERACTIVE_PROCESS"),
    ]
    .into_iter()
    .filter(|(bit, _)| kind & bit != 0)
    .map(|(_, name)| name)
    .collect::<Vec<_>>()
    .join("|")
}
fn memory_string(vm: &Memory<'_>, address: u64) -> Result<String> {
    ensure!(address != 0, "空服务字符串指针");
    let mut b = [0; 512];
    vm.read(address, &mut b)?;
    let units: Vec<_> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    Ok(String::from_utf16_lossy(&units))
}
fn registry_string(bytes: &[u8]) -> Result<String> {
    ensure!(
        bytes.len().is_multiple_of(2),
        "服务注册表字符串 UTF-16 截断"
    );
    let (bytes, be) = if bytes.starts_with(&[0xfe, 0xff]) {
        (&bytes[2..], true)
    } else if bytes.starts_with(&[0xff, 0xfe]) {
        (&bytes[2..], false)
    } else {
        (bytes, false)
    };
    let units: Vec<_> = bytes
        .chunks_exact(2)
        .map(|c| {
            if be {
                u16::from_be_bytes([c[0], c[1]])
            } else {
                u16::from_le_bytes([c[0], c[1]])
            }
        })
        .collect();
    Ok(String::from_utf16(&units)?
        .trim_end_matches('\0')
        .to_owned())
}
fn valid_record(vm: &Memory<'_>, at: u64, layout: &ServiceLayout) -> Result<(u64, u64, u64)> {
    let read = |field| vm.uint(add(at, layout.fields[field])?, 4);
    let (order, start, state) = (read("Order")?, read("Start")?, read("State")?);
    ensure!(
        order <= 0xffff && start <= 4 && (1..=7).contains(&state),
        "无效服务 Order/Start/State"
    );
    Ok((order, start, state))
}
impl Windows<'_> {
    pub(super) fn service_list(&self, options: &Options, job: &Job) -> Result<Results> {
        ensure!(
            options.pid.is_none(),
            "SvcList 不接受 PID 筛选；枚举 services.exe 内的服务链表"
        );
        let version = self.declared_kernel_version()?;
        ensure!(
            Architecture::from_isf(self.vm.isf)? == Architecture::X64
                && version[..2] == [10, 0]
                && version[2] >= 15063,
            "SvcList 仅支持 Win10 15063+ x64"
        );
        let layout = user_layout::service(Architecture::X64, version)?;
        let mut r = self.result(Plugin::WinSvcList);
        let (processes, diagnostics) = self.processes_partial(job)?;
        r.complete = diagnostics.is_empty();
        r.diagnostics = diagnostics;
        let owners: Vec<_> = processes
            .iter()
            .filter(|p| p.name == "Registry" && p.ppid == 4 && p.exited == 0)
            .collect();
        ensure!(owners.len() <= 1, "Registry 进程归属歧义");
        let registry_vm = owners.first().map(|p| self.process_memory(p)).transpose();
        let map = match registry_vm {
            Ok(vm) => {
                let registry = Windows {
                    vm: vm.unwrap_or(Memory::new(
                        self.vm.image,
                        self.vm.root,
                        self.vm.isf,
                        self.vm.sources,
                    )),
                    base: self.base,
                    pdb: self.pdb.clone(),
                };
                registry.service_registry_map(job, &mut r)?
            }
            Err(e) => {
                Self::issue(&mut r, "Registry 进程视图", format!("{e:#}"));
                self.service_registry_map(job, &mut r)?
            }
        };
        let mut found = 0;
        for p in processes
            .iter()
            .filter(|p| p.name.eq_ignore_ascii_case("services.exe"))
        {
            job.check()?;
            found += 1;
            let read = (|| -> Result<()> {
                let vm = self.process_memory(p)?;
                let vads = self.vads_partial(p, job, Some(&mut r))?;
                let vad = vads
                    .into_iter()
                    .find(|v| v.path.to_ascii_lowercase().ends_with("\\services.exe"))
                    .context("未找到 services.exe 映像 VAD")?;
                let before = r.rows.len();
                let (headers, pages, missing) =
                    self.service_vad(&vm, vad.start, vad.end, &layout, &map, &mut r, job)?;
                r.kernel_identity[format!("pid{}_services", p.pid)] = serde_json::json!({"vad_start":hex(vad.start),"vad_end":hex(vad.end),"headers":headers,"pages_read":pages,"missing_pages":missing,"rows":r.rows.len()-before});
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                Self::issue(&mut r, format!("PID {} services", p.pid), format!("{e:#}"));
            }
        }
        if found == 0 {
            Self::issue(
                &mut r,
                "SvcList",
                "未找到 services.exe 进程，无法建立服务列表",
            );
        }
        r.kernel_identity["services_list"] = serde_json::json!({"kernel_version":version,"layout":layout.source,"registry_entries":map.len(),"processes":found,"scope":"Sc27 in first services.exe image VAD; enumerate each header's backward chain","limits":{"scan_bytes_per_process":MAX_SCAN,"chain_records":MAX_CHAIN},"offset_semantics":"pinned Volatility output: first row is record VA, subsequent rows are previous record PrevEntry field VA; diagnostics use actual record VA","meaning":"listed service records; empty output does not prove absence of hidden services"});
        Ok(r)
    }
    fn service_registry_map(&self, job: &Job, r: &mut Results) -> Result<BinaryMap> {
        let hives = self.registry(Plugin::WinHivelist, &Options::default(), job);
        let hives = match hives {
            Ok(h) => h,
            Err(e) => {
                job.check()?;
                Self::issue(r, "service registry hives", format!("{e:#}"));
                return Ok(BinaryMap::new());
            }
        };
        if !hives.complete {
            r.complete = false;
            r.diagnostics.extend(hives.diagnostics);
        }
        for row in hives
            .rows
            .into_iter()
            .filter(|h| h[1].to_ascii_lowercase().contains("machine\\system"))
        {
            job.check()?;
            let read = (|| -> Result<BinaryMap> {
                let address = u64::from_str_radix(row[0].trim_start_matches("0x"), 16)?;
                let hive = self.field(address, "_CMHIVE", "Hive")?;
                ensure!(
                    self.number(hive, "_HHIVE", "Signature")? == 0xbee0bee0,
                    "无效 SYSTEM hive 签名"
                );
                // The base block is often discarded in live captures. The fixed
                // first HBIN cell is the reference fallback, still validated by
                // the allocation header, nk signature and exact path traversal.
                let root = (|| -> Result<u32> {
                    let base = self.number(hive, "_HHIVE", "BaseBlock")?;
                    ensure!(self.vm.uint(base, 4)? == 0x66676572, "缺少 regf base block");
                    Ok(self.number(base, "_HBASE_BLOCK", "RootCell")? as u32)
                })();
                let root = match root {
                    Ok(root) => root,
                    Err(e) => {
                        job.check()?;
                        Self::issue(
                            r,
                            "service hive root",
                            format!("{e:#}；验证首个 HBIN cell 0x20"),
                        );
                        0x20
                    }
                };
                let root = self
                    .service_registry_index(
                        hive,
                        root,
                        "CurrentControlSet\\Services",
                        job,
                        r,
                        false,
                    )
                    .or_else(|_| {
                        job.check()?;
                        self.service_registry_index(
                            hive,
                            root,
                            "ControlSet001\\Services",
                            job,
                            r,
                            false,
                        )
                    })?;
                let node = self.cell(hive, root)?;
                let mut map = BinaryMap::new();
                for child in self.subkeys(hive, &node, job)? {
                    job.check()?;
                    let record = (|| -> Result<(String, [String; 2])> {
                        let node = self.cell(hive, child)?;
                        let name = self.key_name(&node)?;
                        let path = self.service_registry_value(hive, child, "ImagePath", job, r);
                        let dll = match self.service_registry_index(
                            hive,
                            child,
                            "Parameters",
                            job,
                            r,
                            true,
                        ) {
                            Ok(key) => self.service_registry_value(hive, key, "ServiceDll", job, r),
                            Err(e) if e.to_string().starts_with("注册表键不存在:") => {
                                NA.into()
                            }
                            Err(e) => {
                                Self::issue(
                                    r,
                                    format!("service {name} Parameters"),
                                    format!("{e:#}"),
                                );
                                NA.into()
                            }
                        };
                        Ok((name, [path, dll]))
                    })();
                    match record {
                        Ok((name, info)) => {
                            map.insert(name, info);
                        }
                        Err(e) => {
                            job.check()?;
                            Self::issue(
                                r,
                                format!("service registry cell {child:#x}"),
                                format!("{e:#}"),
                            );
                        }
                    }
                }
                Ok(map)
            })();
            match read {
                Ok(map) => return Ok(map),
                Err(e) => {
                    job.check()?;
                    Self::issue(r, "service SYSTEM hive", format!("{e:#}"));
                }
            }
        }
        Self::issue(
            r,
            "service registry",
            "未取得 SYSTEM 服务配置；保留内存记录，注册表字段为 N/A",
        );
        Ok(BinaryMap::new())
    }
    pub(super) fn service_registry_index(
        &self,
        hive: u64,
        mut cell: u32,
        key: &str,
        job: &Job,
        r: &mut Results,
        case_sensitive: bool,
    ) -> Result<u32> {
        for part in key.split('\\').filter(|s| !s.is_empty()) {
            job.check()?;
            let node = self.cell(hive, cell)?;
            let mut found = None;
            for index in self.subkeys(hive, &node, job)? {
                job.check()?;
                let name = self.cell(hive, index).and_then(|n| self.key_name(&n));
                match name {
                    Ok(name)
                        if if case_sensitive {
                            name == part
                        } else {
                            name.eq_ignore_ascii_case(part)
                        } =>
                    {
                        ensure!(found.is_none(), "注册表键名称歧义");
                        found = Some(index);
                    }
                    Ok(_) => {}
                    Err(e) => Self::issue(
                        r,
                        format!("service registry sibling {index:#x}"),
                        format!("{e:#}"),
                    ),
                }
            }
            cell = found.with_context(|| format!("注册表键不存在: {part}"))?;
        }
        Ok(cell)
    }
    pub(super) fn service_registry_value(
        &self,
        hive: u64,
        key: u32,
        name: &str,
        job: &Job,
        r: &mut Results,
    ) -> String {
        let read = (|| -> Result<Option<String>> {
            for index in self.value_indices(hive, key)? {
                job.check()?;
                let (value_name, _, bytes) = self.value_bytes(hive, index, job)?;
                // The pinned service plugin compares these value names exactly.
                if value_name == name {
                    return registry_string(&bytes).map(Some);
                }
            }
            Ok(None)
        })();
        match read {
            Ok(Some(text)) => text,
            Ok(None) => NA.into(),
            Err(e) => {
                Self::issue(
                    r,
                    format!("service registry {key:#x} {name}"),
                    format!("{e:#}"),
                );
                NA.into()
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn service_vad(
        &self,
        vm: &Memory<'_>,
        start: u64,
        end: u64,
        layout: &ServiceLayout,
        map: &BinaryMap,
        r: &mut Results,
        job: &Job,
    ) -> Result<(usize, usize, usize)> {
        ensure!(start < end, "服务 VAD 范围无效");
        let mut at = start;
        let mut headers = 0;
        let mut pages = 0;
        let mut missing = 0;
        while at < end {
            job.check()?;
            if at - start >= MAX_SCAN {
                Self::issue(r, "SvcList scan", "达到 128 MiB 扫描上限");
                break;
            }
            let length = (end - at).min(4096 - (at & 4095)) as usize;
            let mut bytes = vec![0; length];
            match vm.read(at, &mut bytes) {
                Ok(()) => {
                    pages += 1;
                    for hit in memchr::memmem::find_iter(&bytes, b"Sc27") {
                        job.check()?;
                        let header = at + hit as u64;
                        if !header.is_multiple_of(8) {
                            continue;
                        }
                        let record = vm.pointer(add(header, layout.header_record)?);
                        match record
                            .and_then(|record| valid_record(vm, record, layout).map(|_| record))
                        {
                            Ok(record) => {
                                headers += 1;
                                self.service_list_chain(vm, record, layout, map, r, job)?;
                            }
                            Err(e) => {
                                Self::issue(r, format!("Sc27 header {header:#x}"), format!("{e:#}"))
                            }
                        }
                    }
                }
                Err(_) => missing += 1,
            }
            at = add(at, length as u64)?;
        }
        if missing > 0 {
            Self::issue(r, "SvcList VAD", format!("{missing} 个页面无法读取"));
        }
        Ok((headers, pages, missing))
    }
    #[allow(clippy::too_many_arguments)]
    fn service_list_chain(
        &self,
        vm: &Memory<'_>,
        mut record: u64,
        layout: &ServiceLayout,
        map: &BinaryMap,
        r: &mut Results,
        job: &Job,
    ) -> Result<()> {
        // Match the pinned renderer: the first row reports the record address;
        // later rows report the PrevEntry pointer object storage address.
        // Diagnostics continue to use the dereferenced record address.
        let mut reported_offset = record;
        let mut seen = HashSet::new();
        for _ in 0..MAX_CHAIN {
            job.check()?;
            if record == 0 {
                return Ok(());
            }
            if !seen.insert(record) {
                Self::issue(r, "SvcList chain", format!("服务链循环 {record:#x}"));
                return Ok(());
            }
            let (order, start, state) = match valid_record(vm, record, layout) {
                Ok(fields) => fields,
                Err(e) => {
                    Self::issue(r, format!("service {record:#x}"), format!("{e:#}"));
                    return Ok(());
                }
            };
            let kind = vm.uint(add(record, layout.fields["Type"])?, 4);
            let kind = match kind {
                Ok(k) => k,
                Err(e) => {
                    Self::issue(r, format!("service {record:#x} Type"), format!("{e:#}"));
                    0
                }
            };
            let mut string = |field: &str| -> Result<String> {
                match vm
                    .pointer(add(record, layout.fields[field])?)
                    .and_then(|p| memory_string(vm, p))
                {
                    Ok(s) => Ok(s),
                    Err(e) => {
                        Self::issue(r, format!("service {record:#x} {field}"), format!("{e:#}"));
                        Ok(NA.into())
                    }
                }
            };
            let name: String = string("ServiceName")?;
            let display = string("DisplayName")?;
            let mut pid = NA.to_owned();
            let mut binary = NA.to_owned();
            if state == 4 {
                let read = (|| -> Result<String> {
                    let pointer = vm.pointer(add(
                        record,
                        layout.fields[if kind & 0x130 != 0 {
                            "ServiceProcess"
                        } else {
                            "DriverName"
                        }],
                    )?)?;
                    if kind & 0x130 != 0 {
                        match vm.uint(add(pointer, layout.pid)?, 4) {
                            Ok(value) => pid = value.to_string(),
                            Err(e) => {
                                Self::issue(r, format!("service {record:#x} PID"), format!("{e:#}"))
                            }
                        };
                        memory_string(vm, vm.pointer(add(pointer, layout.binary)?)?)
                    } else {
                        memory_string(vm, pointer)
                    }
                })();
                match read {
                    Ok(text) => binary = text,
                    Err(e) => {
                        Self::issue(r, format!("service {record:#x} Binary"), format!("{e:#}"))
                    }
                }
            }
            let registry = map.get(&name).cloned().unwrap_or([NA.into(), NA.into()]);
            ensure!(r.rows.len() < MAX_OBJECTS, "服务结果数量超限");
            r.rows.push(vec![
                hex(reported_offset),
                order.to_string(),
                pid,
                START[start as usize].into(),
                STATE[state as usize - 1].into(),
                types(kind),
                name,
                display,
                binary,
                registry[0].clone(),
                registry[1].clone(),
            ]);
            let previous = layout.previous.context("SvcList 布局缺少前驱偏移")?;
            match vm.pointer(add(record, previous)?) {
                Ok(next) => {
                    reported_offset = add(record, previous)?;
                    record = next;
                }
                Err(e) => {
                    Self::issue(r, format!("service {record:#x} previous"), format!("{e:#}"));
                    return Ok(());
                }
            }
        }
        Self::issue(r, "SvcList chain", "服务链达到 65536 条上限");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;

    fn prepare() -> (Vec<u8>, Isf, ServiceLayout) {
        let (mut b, isf) = fixture();
        put(&mut b, 0x1000, 0x2003);
        let layout = user_layout::service(Architecture::X64, [10, 0, 15063, 0]).unwrap();
        b[0x19000..0x19004].copy_from_slice(b"Sc27");
        put(&mut b, 0x19000 + layout.header_record as usize, 0x12000);
        for (field, value) in [("Order", 0), ("Start", 2), ("State", 4), ("Type", 16)] {
            let at = 0x1a000 + layout.fields[field] as usize;
            b[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
        put(
            &mut b,
            0x1a000 + layout.fields["ServiceName"] as usize,
            0x13000,
        );
        put(
            &mut b,
            0x1a000 + layout.fields["DisplayName"] as usize,
            0x13200,
        );
        put(
            &mut b,
            0x1a000 + layout.fields["ServiceProcess"] as usize,
            0x15000,
        );
        put(&mut b, 0x1d000 + layout.binary as usize, 0x16000);
        b[0x1d000 + layout.pid as usize..0x1d004 + layout.pid as usize]
            .copy_from_slice(&1234u32.to_le_bytes());
        for (at, text) in [
            (0x1b000, "svc"),
            (0x1b200, "A service"),
            (0x1e000, "service.exe"),
        ] {
            let data: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            b[at..at + data.len()].copy_from_slice(&data);
        }
        (b, isf, layout)
    }
    fn scan(b: &[u8], isf: &Isf, layout: &ServiceLayout, end: u64, job: &Job) -> Result<Results> {
        let img = image(b);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(isf)?,
        };
        let mut r = w.result(Plugin::WinSvcList);
        let map = BTreeMap::from([("svc".into(), ["registry.exe".into(), "service.dll".into()])]);
        w.service_vad(&w.vm, 0x11000, end, layout, &map, &mut r, job)?;
        Ok(r)
    }
    #[test]
    fn executable_header_yields_all_eleven_fields_and_zero_order() {
        let (b, isf, layout) = prepare();
        let r = scan(&b, &isf, &layout, 0x12000, &Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows,
            vec![vec![
                hex(0x12000),
                "0".into(),
                "1234".into(),
                "SERVICE_AUTO_START".into(),
                "SERVICE_RUNNING".into(),
                "SERVICE_WIN32_OWN_PROCESS".into(),
                "svc".into(),
                "A service".into(),
                "service.exe".into(),
                "registry.exe".into(),
                "service.dll".into()
            ]]
        );
    }
    #[test]
    fn only_aligned_headers_in_requested_vad_are_enumerated_and_duplicates_preserved() {
        let (mut b, isf, layout) = prepare();
        let header = b[0x19000..0x19020].to_vec();
        b[0x19040..0x19060].copy_from_slice(&header);
        b[0x19101..0x19121].copy_from_slice(&header);
        assert_eq!(
            scan(&b, &isf, &layout, 0x11040, &Job::default())
                .unwrap()
                .rows
                .len(),
            1
        );
        assert_eq!(
            scan(&b, &isf, &layout, 0x12000, &Job::default())
                .unwrap()
                .rows
                .len(),
            2
        );
    }
    #[test]
    fn backward_chain_reports_reference_pointer_storage_offsets() {
        let (mut b, isf, layout) = prepare();
        let record = b[0x1a000..0x1a100].to_vec();
        b[0x1c000..0x1c100].copy_from_slice(&record);
        put(&mut b, 0x1a000 + layout.previous.unwrap() as usize, 0x14000);
        let r = scan(&b, &isf, &layout, 0x12000, &Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.rows[0][0], hex(0x12000));
        assert_eq!(r.rows[1][0], hex(0x12000 + layout.previous.unwrap()));
        assert_eq!(r.rows[1][6], "svc");
    }
    #[test]
    fn stopped_service_omits_pid_and_binary_but_keeps_registry() {
        let (mut b, isf, layout) = prepare();
        let at = 0x1a000 + layout.fields["State"] as usize;
        b[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        let r = scan(&b, &isf, &layout, 0x12000, &Job::default()).unwrap();
        assert_eq!(r.rows[0][2], NA);
        assert_eq!(r.rows[0][8], NA);
        assert_eq!(r.rows[0][10], "service.dll");
    }
    #[test]
    fn driver_binary_and_interactive_process_type_follow_reference() {
        let (mut b, isf, layout) = prepare();
        let at = 0x1a000 + layout.fields["Type"] as usize;
        b[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        put(
            &mut b,
            0x1a000 + layout.fields["DriverName"] as usize,
            0x16000,
        );
        let r = scan(&b, &isf, &layout, 0x12000, &Job::default()).unwrap();
        assert_eq!(r.rows[0][2], NA);
        assert_eq!(r.rows[0][8], "service.exe");
        assert_eq!(
            types(0x111),
            "SERVICE_KERNEL_DRIVER|SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS"
        );
        assert_eq!(types(0x8000), "");
    }
    #[test]
    fn cycles_and_missing_fields_preserve_other_fields() {
        let (mut b, isf, layout) = prepare();
        put(&mut b, 0x1a000 + layout.previous.unwrap() as usize, 0x12000);
        put(
            &mut b,
            0x1a000 + layout.fields["DisplayName"] as usize,
            0x40000,
        );
        let r = scan(&b, &isf, &layout, 0x12000, &Job::default()).unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0][7], NA);
        assert_eq!(r.rows[0][2], "1234");
        assert!(r.diagnostics.iter().any(|d| d.contains("循环")));
        assert!(r.diagnostics.iter().any(|d| d.contains("DisplayName")));
    }
    #[test]
    fn missing_pages_and_invalid_records_are_explicit_and_cancel_propagates() {
        let (mut b, isf, layout) = prepare();
        put(&mut b, 0x4000 + 0x17 * 8, 0);
        let r = scan(&b, &isf, &layout, 0x18000, &Job::default()).unwrap();
        assert_eq!(r.rows.len(), 1);
        assert!(!r.complete);
        let at = 0x1a000 + layout.fields["Order"] as usize;
        b[at..at + 4].copy_from_slice(&65536u32.to_le_bytes());
        let r = scan(&b, &isf, &layout, 0x12000, &Job::default()).unwrap();
        assert!(r.rows.is_empty());
        assert!(!r.complete);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(scan(&b, &isf, &layout, 0x12000, &job).is_err());
    }
    #[test]
    fn unsupported_builds_and_pid_filters_fail_explicitly() {
        let (mut b, isf, _) = prepare();
        b[0x8200..0x8204].copy_from_slice(&7601u32.to_le_bytes());
        let img = image(&b);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert!(
            w.service_list(&Options::default(), &Job::default())
                .unwrap_err()
                .to_string()
                .contains("15063")
        );
        assert!(
            w.service_list(
                &Options {
                    pid: Some(4),
                    ..Default::default()
                },
                &Job::default()
            )
            .unwrap_err()
            .to_string()
            .contains("PID")
        );
    }
    #[test]
    fn registry_decode_is_strict_and_only_trims_trailing_nuls() {
        assert_eq!(
            registry_string(&[0xff, 0xfe, 65, 0, 0, 0, 66, 0, 0, 0]).unwrap(),
            "A\0B"
        );
        assert_eq!(registry_string(&[0xfe, 0xff, 0, 65, 0, 0]).unwrap(), "A");
        assert!(registry_string(&[65]).is_err());
        assert!(registry_string(&[0, 0xd8]).is_err());
    }
}
