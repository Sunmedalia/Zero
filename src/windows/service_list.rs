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
fn service_difference(scan: &[Vec<String>], listed: &[Vec<String>]) -> Vec<Vec<String>> {
    let names: HashSet<_> = listed.iter().map(|row| row[6].as_str()).collect();
    let mut records = BTreeMap::new();
    for row in scan {
        records.insert(row[6].as_str(), row);
    }
    records
        .into_iter()
        .filter(|(name, _)| !names.contains(name))
        .map(|(_, row)| row.clone())
        .collect()
}
impl Windows<'_> {
    pub(super) fn service_list(&self, options: &Options, job: &Job) -> Result<Results> {
        self.service_records(false, options, job)
    }
    pub(super) fn service_scan(&self, options: &Options, job: &Job) -> Result<Results> {
        self.service_records(true, options, job)
    }
    pub(super) fn service_diff(&self, options: &Options, job: &Job) -> Result<Results> {
        // Check support before scanning so an unsupported list cannot become a
        // misleading report containing every scanned service.
        self.service_list_support()?;
        let scan = self.service_scan(options, job)?;
        let listed = self.service_list(options, job)?;
        job.check()?;
        let mut r = self.result(Plugin::WinSvcDiff);
        r.complete = scan.complete && listed.complete;
        r.diagnostics
            .extend(scan.diagnostics.iter().map(|d| format!("scan: {d}")));
        r.diagnostics
            .extend(listed.diagnostics.iter().map(|d| format!("list: {d}")));
        r.rows = service_difference(&scan.rows, &listed.rows);
        r.kernel_identity["services_diff"] = serde_json::json!({
            "scan_records":scan.rows.len(),"list_records":listed.rows.len(),
            "scan_names":scan.rows.iter().map(|r| &r[6]).collect::<HashSet<_>>().len(),
            "list_names":listed.rows.iter().map(|r| &r[6]).collect::<HashSet<_>>().len(),
            "scan_complete":scan.complete,"list_complete":listed.complete,
            "comparison":"case-sensitive service name; last scanned record per name",
            "meaning":"scan-only service names are leads; incomplete views cannot prove hiding or absence",
            "scan_coverage":scan.kernel_identity["services_scan"],
            "list_coverage":listed.kernel_identity["services_list"]
        });
        Ok(r)
    }
    fn service_list_support(&self) -> Result<()> {
        let version = self.declared_kernel_version()?;
        ensure!(
            Architecture::from_isf(self.vm.isf)? == Architecture::X64
                && version[..2] == [10, 0]
                && version[2] >= 15063,
            "SvcList/SvcDiff 仅支持 Win10 15063+ x64"
        );
        Ok(())
    }
    fn service_records(&self, scan: bool, options: &Options, job: &Job) -> Result<Results> {
        ensure!(
            options.pid.is_none(),
            "标准服务插件不接受 PID 筛选；枚举 services.exe 内的服务记录"
        );
        let version = self.declared_kernel_version()?;
        if !scan {
            self.service_list_support()?;
        }
        let layout = user_layout::service(Architecture::from_isf(self.vm.isf)?, version)?;
        let mut r = self.result(if scan {
            Plugin::WinSvcScanV4
        } else {
            Plugin::WinSvcList
        });
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
                let before = r.rows.len();
                let mut headers = 0;
                let mut pages = 0;
                let mut missing = 0;
                let mut bytes = 0u64;
                let mut ranges = Vec::new();
                if scan {
                    for vad in vads {
                        job.check()?;
                        if bytes >= MAX_SCAN {
                            Self::issue(&mut r, "SvcScan", "达到每进程 128 MiB 扫描上限");
                            break;
                        }
                        let end = vad.end.min(add(vad.start, MAX_SCAN - bytes)?);
                        if end <= vad.start {
                            continue;
                        }
                        let (h, p, m) = self.service_tag_vad(
                            &vm,
                            vad.start,
                            end,
                            &layout,
                            &map,
                            &mut r,
                            job,
                            if version[0] < 6 { b"sErv" } else { b"serH" },
                            version[0] < 6,
                        )?;
                        headers += h;
                        pages += p;
                        missing += m;
                        bytes += end - vad.start;
                        ranges.push((hex(vad.start), hex(end)));
                        if end < vad.end {
                            Self::issue(&mut r, "SvcScan", "VAD 在 128 MiB 上限截断");
                        }
                    }
                } else {
                    let vad = vads
                        .into_iter()
                        .find(|v| v.path.to_ascii_lowercase().ends_with("\\services.exe"))
                        .context("未找到 services.exe 映像 VAD")?;
                    (headers, pages, missing) =
                        self.service_vad(&vm, vad.start, vad.end, &layout, &map, &mut r, job)?;
                    ranges.push((hex(vad.start), hex(vad.end)));
                }
                r.kernel_identity[format!("pid{}_services", p.pid)] = serde_json::json!({"vad_ranges":ranges,"headers":headers,"pages_read":pages,"missing_pages":missing,"rows_before_scan_dedup":r.rows.len()-before});
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
        if scan {
            // The reference breaks a header traversal at its first repeated
            // complete tuple, rather than deduplicating record addresses.
            // Each header is handled before insertion in service_tag_vad.
            r.kernel_identity["services_scan"] = serde_json::json!({"kernel_version":version,"layout":layout.source,"registry_entries":map.len(),"processes":found,"scope":"serH headers in all services.exe VADs; NT5 sErv records","limits":{"scan_bytes_per_process":MAX_SCAN,"chain_records":MAX_CHAIN},"meaning":"scanned service records; partial views cannot prove absence"});
        } else {
            r.kernel_identity["services_list"] = serde_json::json!({"kernel_version":version,"layout":layout.source,"registry_entries":map.len(),"processes":found,"scope":"Sc27 in first services.exe image VAD; enumerate each header's backward chain","limits":{"scan_bytes_per_process":MAX_SCAN,"chain_records":MAX_CHAIN},"offset_semantics":"pinned Volatility output: first row is record VA, subsequent rows are previous record PrevEntry field VA; diagnostics use actual record VA","meaning":"listed service records; empty output does not prove absence of hidden services"});
        }
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
                    Ok(u32::try_from(self.number(
                        base,
                        "_HBASE_BLOCK",
                        "RootCell",
                    )?)?)
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
                    .registry_index_partial(
                        hive,
                        root,
                        "CurrentControlSet\\Services",
                        job,
                        r,
                        false,
                    )
                    .or_else(|_| {
                        job.check()?;
                        self.registry_index_partial(
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
                        let dll = match self.registry_index_partial(
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
                if index == 0 {
                    continue;
                }
                let value_name = match self.value_name(hive, index) {
                    Ok(name) => name,
                    Err(e) => {
                        // RegistryHive.get_values skips invalid value nodes.
                        // Keep the independent target readable and retain the
                        // missing metadata as a partial-view diagnostic.
                        Self::issue(
                            r,
                            format!("service value {index:#x} name"),
                            format!("{e:#}"),
                        );
                        continue;
                    }
                };
                // The pinned service plugin compares these value names exactly
                // before reading data, so unrelated paged-out values are skipped.
                if value_name == name {
                    let (_, _, bytes) = self
                        .value_bytes(hive, index, job)
                        .with_context(|| format!("value {index:#x} data"))?;
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
        self.service_tag_vad(vm, start, end, layout, map, r, job, b"Sc27", false)
    }
    #[allow(clippy::too_many_arguments)]
    fn service_tag_vad(
        &self,
        vm: &Memory<'_>,
        start: u64,
        end: u64,
        layout: &ServiceLayout,
        map: &BinaryMap,
        r: &mut Results,
        job: &Job,
        tag: &[u8],
        direct: bool,
    ) -> Result<(usize, usize, usize)> {
        ensure!(start < end, "服务 VAD 范围无效");
        let mut at = start;
        let mut headers = 0;
        let mut pages = 0;
        let mut missing = 0;
        let mut carry = Vec::new();
        let mut scan_seen: HashSet<Vec<String>> = r.rows.iter().cloned().collect();
        while at < end {
            job.check()?;
            if at - start >= MAX_SCAN {
                Self::issue(r, "SvcList scan", "达到 128 MiB 扫描上限");
                break;
            }
            let length = usize::try_from((end - at).min(4096 - (at & 4095)))?;
            let mut bytes = vec![0; length];
            match vm.read(at, &mut bytes) {
                Ok(()) => {
                    pages += 1;
                    let prefix = carry.len();
                    let mut joined = std::mem::take(&mut carry);
                    joined.extend_from_slice(&bytes);
                    for hit in memchr::memmem::find_iter(&joined, tag) {
                        job.check()?;
                        let header = at - prefix as u64 + hit as u64;
                        if !direct && !header.is_multiple_of(8) {
                            continue;
                        }
                        let record = if direct {
                            header
                                .checked_sub(layout.fields["Tag"])
                                .context("服务 tag 下溢")
                        } else {
                            vm.pointer(add(header, layout.header_record)?)
                        };
                        match record
                            .and_then(|record| valid_record(vm, record, layout).map(|_| record))
                        {
                            Ok(record) => {
                                headers += 1;
                                let before = r.rows.len();
                                self.service_list_chain(vm, record, layout, map, r, job)?;
                                if tag == b"serH" {
                                    let rows = r.rows.split_off(before);
                                    for row in rows {
                                        // The reference creates fresh absent-value objects in
                                        // get_pid/get_name/get_display/get_binary. They compare
                                        // by object identity, so such tuples never deduplicate.
                                        // Registry absences in the prebuilt map are shared;
                                        // fallback absences for an unknown name are fresh.
                                        let comparable = [2, 6, 7, 8].iter().all(|&i| row[i] != NA)
                                            && (map.contains_key(&row[6])
                                                || (row[9] != NA && row[10] != NA));
                                        if comparable && !scan_seen.insert(row.clone()) {
                                            break;
                                        }
                                        r.rows.push(row);
                                    }
                                }
                            }
                            Err(e) => Self::issue(
                                r,
                                format!("service header {header:#x}"),
                                format!("{e:#}"),
                            ),
                        }
                    }
                    carry = joined[joined.len().saturating_sub(3)..].to_vec();
                }
                Err(_) => {
                    missing += 1;
                    carry.clear();
                }
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
                START[usize::try_from(start)?].into(),
                STATE[usize::try_from(state)? - 1].into(),
                types(kind),
                name,
                display,
                binary,
                registry[0].clone(),
                registry[1].clone(),
            ]);
            let Some(previous) = layout.previous else {
                return Ok(());
            };
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
mod tests;
