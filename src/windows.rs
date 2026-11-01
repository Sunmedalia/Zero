//! Native Windows x64 memory analysis. Offsets come from exact ISF types.
use crate::{
    Job,
    analysis::Options,
    dump::DumpOptions,
    image::Image,
    linux::{Outcome, Plugin, Request},
    report::hex,
    store::{self, Results},
    symbols::Isf,
    windows_symbols::{self, PdbIdentity},
};
use anyhow::{Context, Result, bail, ensure};
use sha2::Digest;
use std::collections::{BTreeMap, HashSet};

pub mod arch;
pub use arch::Architecture;
use arch::Paging;
mod address_space;
mod amcache;
mod analyze;
mod artifacts;
mod codec;
mod compatibility;
mod compressed;
pub mod container;
mod creds;
mod crypto;
mod debugregisters;
mod discovery;
mod dispatch;
mod driver_irp;
mod driver_module;
mod drivers;
mod dump;
mod files;
mod get_cell_routine;
pub mod hiber;
mod hive_scan;
mod integrity;
mod legacy_network;
mod malware;
mod memmap;
mod memory;
mod mft;
mod network;
mod network_layout;
mod objects;
pub mod paging;
mod pe_info;
mod pe_symbols;
mod peb_masquerade;
mod pool;
mod poolscanner;
mod process;
mod process_checks;
mod processors;
mod reference_layer;
mod regex;
mod registry;
mod registry_artifacts;
mod scheduled_tasks;
mod security;
mod service_list;
mod shimcache;
mod skeleton_key;
mod strings;
mod suspended_threads;
mod system_calls;
mod thread_symbols;
mod timeline;
mod truecrypt;
mod unhooked_system_calls;
mod user_artifacts;
mod user_layout;
mod userassist;
#[cfg(test)]
mod vadwalk_tests;
mod windowstations;
mod wow64;
pub use address_space::Memory;
pub use analyze::analyze;
pub(crate) use analyze::{analyze_resolved, validate_request};
pub use discovery::discover;
pub(crate) use discovery::pe_header;

const MAX_OBJECTS: usize = 1_000_000;
const PHYSICAL_MASK: u64 = 0x000f_ffff_ffff_f000;
fn add(base: u64, offset: u64) -> Result<u64> {
    base.checked_add(offset).context("Windows 对象地址溢出")
}
fn kernel(pointer: u64) -> bool {
    pointer >= 0xffff_8000_0000_0000 && pointer != u64::MAX
}
fn filetime(value: u64) -> String {
    if value == 0 {
        String::new()
    } else {
        value.to_string()
    }
}

fn json_number(isf: &Isf, n: u64, structure: &str, field: &str) -> Result<u64> {
    // The memoized layout answers the common case; fall back to the raw field
    // so a field that fails outer bounds checks still decodes as before.
    let bits = match isf.layout(structure, field) {
        Ok(layout) => layout.bits,
        Err(_) => {
            let ty = &isf.field(structure, field)?["type"];
            (ty["kind"] == "bitfield")
                .then(|| (ty["bit_position"].as_u64(), ty["bit_length"].as_u64()))
        }
    };
    if let Some((pos, len)) = bits {
        let pos = pos.context("缺少位域位置")?;
        let len = len.context("缺少位域长度")?;
        ensure!(len > 0 && pos + len <= 64, "无效 Windows 位域");
        Ok((n >> pos) & (u64::MAX >> (64 - len)))
    } else {
        Ok(n)
    }
}

pub struct Windows<'a> {
    pub vm: Memory<'a>,
    pub base: u64,
    pub pdb: PdbIdentity,
}
#[derive(Clone, Debug)]
pub struct Process {
    pub address: u64,
    pub physical: bool,
    pub pid: u64,
    pub ppid: u64,
    pub name: String,
    pub dtb: u64,
    pub threads: u64,
    pub handles: Option<u64>,
    pub created: u64,
    pub exited: u64,
}
/// One entry of `PsLoadedModuleList`, shared by `modules` and moddump.
#[derive(Clone, Debug)]
pub(super) struct KernelModule {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub path: String,
}
impl Process {
    fn row(&self) -> Vec<String> {
        vec![
            self.pid.to_string(),
            self.ppid.to_string(),
            self.name.clone(),
            if self.physical {
                format!("physical:{:#x}", self.address)
            } else {
                hex(self.address)
            },
            self.threads.to_string(),
            self.handles.map(|h| h.to_string()).unwrap_or_default(),
            filetime(self.created),
            filetime(self.exited),
        ]
    }
}
impl Windows<'_> {
    fn number(&self, b: u64, t: &str, f: &str) -> Result<u64> {
        self.vm.number(b, t, f)
    }
    fn field(&self, b: u64, t: &str, f: &str) -> Result<u64> {
        add(b, self.vm.isf.offset(t, f)?)
    }
    fn symbol(&self, name: &str) -> Result<u64> {
        add(self.base, self.vm.isf.raw_address(name)?)
    }
    fn result(&self, p: Plugin) -> Results {
        Results {
            plugin: p.name().into(),
            columns: p.descriptor().columns.iter().map(|s| (*s).into()).collect(),
            rows: vec![],
            complete: true,
            diagnostics: vec![],
            banner: format!(
                "Windows {:?} {}",
                Architecture::from_isf(self.vm.isf).unwrap_or_default(),
                self.pdb.key()
            ),
            symbol: self.vm.isf.label.clone(),
            page_table: self.vm.root,
            historical: false,
            system: "windows".into(),
            kernel_identity: serde_json::json!({"version":self.version_identity(),"pdb":self.pdb,"architecture":Architecture::from_isf(self.vm.isf).unwrap_or_default(),"container":self.vm.image.format,"kernel_base":self.base,"time_format":"FILETIME"}),
        }
    }
    fn list_partial(&self, head: u64, offset: u64, job: &Job) -> Result<(Vec<u64>, Vec<String>)> {
        ensure!(self.vm.kernel(head), "Windows 链表头非内核地址");
        let mut nodes = Vec::new();
        let mut diagnostics = Vec::new();
        let mut all = HashSet::new();
        for direction in [0, self.vm.pointer_size() as u64] {
            let mut previous = head;
            let mut current = self.vm.pointer(add(head, direction)?)?;
            let mut seen = HashSet::new();
            while current != head {
                job.check()?;
                let read = (|| -> Result<u64> {
                    ensure!(
                        self.vm.kernel(current) && current % self.vm.pointer_size() as u64 == 0,
                        "无效链表地址 {current:#x}"
                    );
                    ensure!(
                        seen.insert(current) && seen.len() <= MAX_OBJECTS,
                        "Windows 链表循环或超限 {current:#x}"
                    );
                    let opposite = self
                        .vm
                        .pointer(add(current, self.vm.pointer_size() as u64 - direction)?)?;
                    if opposite != previous {
                        diagnostics.push(format!("Windows 链表不一致 @ {current:#x} direction {direction}: expected {previous:#x}, found {opposite:#x}"));
                    }
                    let object = current.checked_sub(offset).context("链表成员地址下溢")?;
                    if all.insert(object) {
                        nodes.push(object);
                    }
                    self.vm.pointer(add(current, direction)?)
                })();
                match read {
                    Ok(next) => {
                        previous = current;
                        current = next
                    }
                    Err(e) => {
                        diagnostics.push(format!("链表 @ {head:#x} direction {direction}: {e:#}"));
                        break;
                    }
                }
            }
            if current == head
                && self
                    .vm
                    .pointer(add(head, self.vm.pointer_size() as u64 - direction)?)?
                    != previous
            {
                diagnostics.push(format!(
                    "Windows 链表末尾未闭合 @ {head:#x} direction {direction}"
                ));
            }
        }
        Ok((nodes, diagnostics))
    }
    fn process(&self, address: u64) -> Result<Process> {
        let len = self.vm.isf.size("_EPROCESS", "ImageFileName")?;
        ensure!(len <= 256, "进程名称过长");
        let mut b = vec![0; len];
        self.vm
            .read(self.field(address, "_EPROCESS", "ImageFileName")?, &mut b)?;
        let end = b.iter().position(|b| *b == 0).unwrap_or(b.len());
        let name = String::from_utf8_lossy(&b[..end]).into_owned();
        let pid = self.number(address, "_EPROCESS", "UniqueProcessId")?;
        ensure!(
            pid <= u32::MAX as u64 && !name.is_empty() && !name.chars().any(char::is_control),
            "无效 EPROCESS"
        );
        let dtb =
            self.number(address, "_EPROCESS", "Pcb.DirectoryTableBase")? & self.vm.root_mask();
        Ok(Process {
            address,
            physical: false,
            pid,
            ppid: self.number(address, "_EPROCESS", "InheritedFromUniqueProcessId")?,
            name,
            dtb,
            threads: self.number(address, "_EPROCESS", "ActiveThreads")?,
            handles: self
                .number(address, "_EPROCESS", "ObjectTable")
                .ok()
                .filter(|p| *p != 0)
                .and_then(|p| self.number(p, "_HANDLE_TABLE", "HandleCount").ok()),
            created: self.number(address, "_EPROCESS", "CreateTime")?,
            exited: self.number(address, "_EPROCESS", "ExitTime")?,
        })
    }
    fn processes_partial(&self, job: &Job) -> Result<(Vec<Process>, Vec<String>)> {
        let (nodes, mut diagnostics) = self.list_partial(
            self.symbol("PsActiveProcessHead")?,
            self.vm.isf.offset("_EPROCESS", "ActiveProcessLinks")?,
            job,
        )?;
        let mut out = Vec::new();
        for address in nodes {
            job.check()?;
            match self.process(address) {
                Ok(p) => out.push(p),
                Err(e) => diagnostics.push(format!("EPROCESS {address:#x}: {e:#}")),
            }
        }
        Ok((out, diagnostics))
    }
    fn process_memory(&self, p: &Process) -> Result<Memory<'_>> {
        ensure!(!p.physical, "扫描进程没有已验证虚拟地址");
        let user = self
            .number(p.address, "_EPROCESS", "Pcb.UserDirectoryTableBase")
            .unwrap_or(0)
            & self.vm.root_mask();
        ensure!(p.dtb != 0 || user != 0, "进程没有地址空间");
        Ok(Memory::new(
            self.vm.image,
            if p.dtb != 0 { p.dtb } else { user },
            self.vm.isf,
            self.vm.sources,
        ))
    }
    fn issue(r: &mut Results, context: impl std::fmt::Display, error: impl std::fmt::Display) {
        r.complete = false;
        r.diagnostics.push(format!("{context}: {error}"));
    }
    pub fn run(&self, p: Plugin, options: &Options, job: &Job) -> Result<Results> {
        job.check()?;
        if p == Plugin::WinDebugRegisters {
            return self.debug_registers(None, job);
        }
        if p == Plugin::WinPoolScanner {
            return self.pool_scanner(job);
        }
        if p == Plugin::WinWindowStations {
            return self.window_stations(job);
        }
        if p == Plugin::WinDesktops {
            return self.desktops(job);
        }
        if p == Plugin::WinDeskScan {
            return self.deskscan(job);
        }
        if p == Plugin::WinWindows {
            return self.windows(job);
        }
        if p == Plugin::WinSuspendedThreads {
            return self.suspended_threads(None, job);
        }
        if p == Plugin::WinUnhookedSystemCalls {
            return self.unhooked_system_calls(None, job);
        }
        if matches!(
            p,
            Plugin::WinDirectSystemCalls | Plugin::WinIndirectSystemCalls
        ) {
            return self.system_calls(p, job);
        }
        if p == Plugin::WinSkeletonKeyCheck {
            return self.skeleton_key(None, job);
        }
        if p == Plugin::WinTruecryptPassphrase {
            return self.truecrypt_passphrase(options, job);
        }
        if p == Plugin::WinStrings {
            return self.strings(options, job);
        }
        if p == Plugin::WinPESymbols {
            return self.pe_symbols(options, None, job);
        }
        if p == Plugin::WinMemmap {
            return self.memmap(options, None, job);
        }
        if p == Plugin::WinSvcScanV4 {
            return self.service_scan(options, job);
        }
        if p == Plugin::WinSvcDiff {
            return self.service_diff(options, job);
        }
        if p == Plugin::WinSvcList {
            return self.service_list(options, job);
        }
        if p == Plugin::WinGetCellRoutine {
            return self.get_cell_routine(job);
        }
        if p == Plugin::WinPebMasquerade {
            return self.peb_masquerade(options, job);
        }
        if p == Plugin::WinDriverModule {
            return self.driver_module(job);
        }
        if p == Plugin::WinDriverIrp {
            return self.driver_irp(job);
        }
        if p == Plugin::WinKpcrs {
            return self.kpcrs(job);
        }
        if p == Plugin::WinVadWalk {
            return self.vad_walk(options, job);
        }
        if p == Plugin::WinVadRegExScan {
            return self.vad_regex_scan(options, job);
        }
        let mut result = self.result(p);
        if p == Plugin::WinSysteminfo {
            result.rows = vec![
                vec!["OS".into(), "Windows".into()],
                vec![
                    "Architecture".into(),
                    format!("{:?}", Architecture::from_isf(self.vm.isf)?),
                ],
                vec!["PDB".into(), self.pdb.key()],
                vec!["KernelBase".into(), hex(self.base)],
                vec!["DTB".into(), hex(self.vm.root)],
                vec!["ImageSHA256".into(), self.vm.image.digest.clone()],
                vec!["ISFSHA256".into(), self.vm.isf.digest.clone()],
                vec![
                    "Validation".into(),
                    "PE/PDB/System/DTB/list entry validated".into(),
                ],
            ];
            if let Ok(address) = self.symbol("NtBuildNumber") {
                result.rows.push(vec![
                    "Build".into(),
                    (self.vm.uint(address, 4)? & 0xffff).to_string(),
                ]);
            }
            for key in ["product", "major", "minor", "product_type", "evidence"] {
                if let Some(value) = result.kernel_identity["version"].get(key) {
                    result.rows.push(vec![key.into(), value.to_string()]);
                }
            }
            return Ok(result);
        }
        if matches!(p, Plugin::WinCallbacks | Plugin::WinUnloadedmodules) {
            return self.kernel_artifacts(p, job);
        }
        if matches!(
            p,
            Plugin::WinFilescan
                | Plugin::WinMutantscan
                | Plugin::WinSymlinkscan
                | Plugin::WinThrdscan
        ) {
            return self.pool_artifacts(p, job);
        }
        if matches!(p, Plugin::WinConnscan | Plugin::WinSockscan) {
            return self.legacy_network(p, job);
        }
        if matches!(p, Plugin::WinDriverscan | Plugin::WinDrivercheck) {
            return self.drivers(p, job);
        }
        if matches!(
            p,
            Plugin::WinSvcscan | Plugin::WinCmdscan | Plugin::WinConsoles
        ) {
            return self.user_artifacts(p, options, job);
        }
        if p == Plugin::WinModules {
            return self.modules(p, job);
        }
        if p == Plugin::WinSsdt {
            return self.ssdt(job);
        }
        if p == Plugin::WinModscan {
            return self.modscan(job);
        }
        if p == Plugin::WinTimeliner {
            return self.timeliner(job);
        }
        if p == Plugin::WinOrphanThreads {
            let threads = self.run(
                Plugin::WinThreads,
                &Options {
                    pid: Some(4),
                    ..Default::default()
                },
                job,
            )?;
            result.complete = threads.complete;
            result.diagnostics = threads.diagnostics;
            for row in threads.rows {
                let start = u64::from_str_radix(row[5].trim_start_matches("0x"), 16).unwrap_or(0);
                if self.vm.kernel(start) && row[6].is_empty() {
                    result.rows.push(vec![
                        row[0].clone(),
                        row[2].clone(),
                        row[3].clone(),
                        row[5].clone(),
                        row[7].clone(),
                    ]);
                }
            }
            return Ok(result);
        }
        if p == Plugin::WinVirtmap {
            return self.virtmap();
        }
        if p == Plugin::WinStatistics {
            return self.statistics(job);
        }
        if p == Plugin::WinTimers {
            return self.timers(job);
        }
        if p == Plugin::WinMbrscan {
            return self.mbrscan(job);
        }
        if p == Plugin::WinMftscan {
            return self.mftscan(job);
        }
        if p == Plugin::WinBigpools {
            return self.bigpools(job);
        }
        if p == Plugin::WinDevicetree {
            return self.devicetree(job);
        }
        if p == Plugin::WinHiveScan {
            return self.hive_scan(job);
        }
        if p == Plugin::WinHivelist {
            return self.registry(p, options, job);
        }
        if matches!(
            p,
            Plugin::WinPrintkey
                | Plugin::WinAutoruns
                | Plugin::WinUserassist
                | Plugin::WinUserAssistV4
                | Plugin::WinGetservicesids
                | Plugin::WinScheduledTasks
                | Plugin::WinScheduledTasksV4
                | Plugin::WinAmcache
                | Plugin::WinAmcacheV4
                | Plugin::WinCertificates
                | Plugin::WinShimcache
                | Plugin::WinHashdump
                | Plugin::WinLsadump
                | Plugin::WinCachedump
        ) {
            let (processes, diagnostics) = self.processes_partial(job)?;
            let owners: Vec<_> = processes
                .iter()
                .filter(|process| {
                    process.name == "Registry" && process.ppid == 4 && process.exited == 0
                })
                .collect();
            ensure!(owners.len() <= 1, "Registry 进程归属歧义");
            let registry_vm = owners
                .first()
                .map(|process| self.process_memory(process))
                .transpose()?;
            let registry = Windows {
                vm: registry_vm.unwrap_or(Memory::new(
                    self.vm.image,
                    self.vm.root,
                    self.vm.isf,
                    self.vm.sources,
                )),
                base: self.base,
                pdb: self.pdb.clone(),
            };
            let run = |engine: &Windows<'_>| -> Result<Results> {
                match p {
                    Plugin::WinAutoruns => engine.autoruns(options, job),
                    Plugin::WinUserassist => engine.userassist(options, job),
                    Plugin::WinUserAssistV4 => engine.userassist_canonical(options, job),
                    Plugin::WinGetservicesids => engine.service_sids(job),
                    Plugin::WinScheduledTasksV4 => engine.scheduled_tasks_canonical(job),
                    Plugin::WinScheduledTasks => engine.scheduled_tasks(job),
                    Plugin::WinAmcache => engine.amcache(job),
                    Plugin::WinAmcacheV4 => engine.amcache_canonical(job),
                    Plugin::WinCertificates => engine.certificates(job),
                    Plugin::WinShimcache => engine.shimcache(job),
                    Plugin::WinHashdump => engine.hashdump(job),
                    Plugin::WinLsadump => engine.lsadump(job),
                    Plugin::WinCachedump => engine.cachedump(job),
                    _ => engine.registry(p, options, job),
                }
            };
            let mut result = if owners.is_empty() {
                run(&registry)?
            } else {
                // Registry 进程视图失败（如 crash dump 未保存其页表）时回退内核视图。
                match run(&registry) {
                    Ok(result) => result,
                    Err(rehosted) => {
                        let mut result = run(self)?;
                        result.complete = false;
                        result.diagnostics.push(format!(
                            "Registry 进程视图失败，已回退内核视图: {rehosted:#}"
                        ));
                        result
                    }
                }
            };
            if !diagnostics.is_empty() {
                result.complete = false;
                result.diagnostics.extend(diagnostics);
            }
            if let Some(owner) = owners.first() {
                result.kernel_identity["registry_process"] = serde_json::json!({"pid":owner.pid,"address":owner.address,"dtb":registry.vm.root,"kernel_dtb":self.vm.root});
            }
            return Ok(result);
        }
        if p == Plugin::WinNetscan {
            return self.netscan(job, None);
        }
        if p == Plugin::WinNetstat {
            return self.netstat(job, None);
        }
        if p == Plugin::WinShimcacheMem {
            return self.shimcache_memory(job);
        }
        if matches!(p, Plugin::WinPsscan | Plugin::WinPsxview) {
            return self.scan_processes(p, options, job);
        }
        let (processes, diagnostics) = self.processes_partial(job)?;
        result.complete = diagnostics.is_empty();
        result.diagnostics = diagnostics;
        let thread_modules = if p == Plugin::WinThreads {
            Some(self.modules(Plugin::WinModules, job)?)
        } else {
            None
        };
        if let Some(modules) = &thread_modules
            && !modules.complete
        {
            result.complete = false;
            result.diagnostics.extend(modules.diagnostics.clone());
        }
        for process in processes
            .into_iter()
            .filter(|p| options.pid.is_none_or(|pid| p.pid == u64::from(pid)))
        {
            job.check()?;
            let read = match p {
                Plugin::WinPslist | Plugin::WinPstree => {
                    result.rows.push(process.row());
                    Ok(())
                }
                Plugin::WinCmdline => self.cmdline(&process, &mut result),
                Plugin::WinGetsids => self.sids(&process, &mut result, job),
                Plugin::WinEnvars => self.environments(&process, &mut result, job),
                Plugin::WinThreads => thread_modules
                    .as_ref()
                    .context("线程模块未加载")
                    .and_then(|modules| self.thread_rows(&process, &mut result, modules, job)),
                Plugin::WinLdrmodules
                | Plugin::WinHollowprocesses
                | Plugin::WinSuspiciousThreads => self.malware(&process, p, &mut result, job),
                Plugin::WinDlllist => self.dlllist(&process, &mut result, job),
                Plugin::WinVadinfo | Plugin::WinMalfind => {
                    self.vad_result(&process, p, &mut result, job)
                }
                Plugin::WinHandles => self.handles(&process, &mut result, job),
                Plugin::WinPrivileges => self.privileges(&process, &mut result),
                Plugin::WinSessions => self.session(&process, &mut result),
                Plugin::WinIat => self.iat(&process, &mut result, job),
                Plugin::WinVerinfo => self.verinfo(&process, &mut result, job),
                Plugin::WinEtwpatch => self.etwpatch(&process, &mut result, job),
                Plugin::WinProcessghosting => self.processghosting(&process, &mut result),
                Plugin::WinJoblinks => self.joblink(&process, &mut result),
                Plugin::WinVadyarascan => {
                    let pattern = crate::pattern::Pattern::parse(
                        options
                            .pattern
                            .as_deref()
                            .context("windows.vadyarascan 需要 --pattern")?,
                    )?;
                    self.vad_pattern_scan(&process, &pattern, &mut result, job)
                }
                _ => bail!("不支持的 Windows 插件 {}", p.name()),
            };
            if let Err(e) = read {
                job.check()?;
                Self::issue(
                    &mut result,
                    format!("PID {} @ {:#x}", process.pid, process.address),
                    format!("{e:#}"),
                );
            }
        }
        if p == Plugin::WinVerinfo && options.pid.is_none() {
            self.module_versions(&mut result, job)?;
        }
        Ok(result)
    }
    fn module_type(&self) -> Result<&'static str> {
        for name in ["_KLDR_DATA_TABLE_ENTRY", "_LDR_DATA_TABLE_ENTRY"] {
            if self.vm.isf.offset(name, "InLoadOrderLinks").is_ok() {
                return Ok(name);
            }
        }
        bail!("缺少内核模块条目类型")
    }
    fn modules(&self, p: Plugin, job: &Job) -> Result<Results> {
        let mut r = self.result(p);
        for module in self.modules_partial(job, &mut r)? {
            r.rows.push(vec![
                module.name,
                hex(module.base),
                module.size.to_string(),
                module.path,
            ]);
        }
        Ok(r)
    }
    /// PsLoadedModuleList 遍历，供 modules 与 moddump 共用。
    fn modules_partial(&self, job: &Job, r: &mut Results) -> Result<Vec<KernelModule>> {
        self.module_entries(job, r, true)
    }
    /// Ownership lookups need BaseDllName and ranges; do not read optional
    /// FullDllName pages unless the caller actually displays the path.
    fn module_entries(&self, job: &Job, r: &mut Results, paths: bool) -> Result<Vec<KernelModule>> {
        let module_type = self.module_type()?;
        let (modules, diagnostics) = self.list_partial(
            self.symbol("PsLoadedModuleList")?,
            self.vm.isf.offset(module_type, "InLoadOrderLinks")?,
            job,
        )?;
        if !diagnostics.is_empty() {
            r.complete = false;
            r.diagnostics.extend(diagnostics);
        }
        let mut out = Vec::new();
        for address in modules {
            let read = (|| -> Result<KernelModule> {
                Ok(KernelModule {
                    base: self.number(address, module_type, "DllBase")?,
                    size: self.number(address, module_type, "SizeOfImage")?,
                    name: match self
                        .vm
                        .unicode(self.field(address, module_type, "BaseDllName")?)
                    {
                        Ok(name) => name,
                        Err(e) => {
                            Self::issue(r, format!("module {address:#x} BaseDllName"), e);
                            String::new()
                        }
                    },
                    path: if paths {
                        match self
                            .vm
                            .unicode(self.field(address, module_type, "FullDllName")?)
                        {
                            Ok(path) => path,
                            Err(e) => {
                                Self::issue(r, format!("module {address:#x} FullDllName"), e);
                                String::new()
                            }
                        }
                    } else {
                        String::new()
                    },
                })
            })();
            match read {
                Ok(module) => out.push(module),
                Err(e) => Self::issue(r, hex(address), e),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
