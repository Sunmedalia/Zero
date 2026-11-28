//! Native Windows x64 memory analysis. Offsets come from exact ISF types.
use crate::bytes::{Checked as _, JsonKey as _};
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
pub(crate) use analyze::{analyze_resolved, analyze_with_yara, validate_request};
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
    let layout = match isf.layout(structure, field) {
        Ok(layout) => layout,
        Err(_) => {
            let ty = &isf.field(structure, field)?["type"];
            // Width unknown here: bound bitfields by the full 64-bit read.
            crate::symbols::Layout {
                offset: 0,
                size: 8,
                bits: (ty["kind"] == "bitfield")
                    .then(|| (ty["bit_position"].as_u64(), ty["bit_length"].as_u64())),
            }
        }
    };
    layout.decode(n)
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
    pub session_id: Option<u64>,
    pub wow64: bool,
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
            self.session_id.map(|s| s.to_string()).unwrap_or_default(),
            self.wow64.to_string(),
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
        let name = crate::bytes::c_str_lossy(&b);
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
            session_id: self
                .number(address, "_EPROCESS", "Session")
                .ok()
                .filter(|&s| self.vm.kernel(s))
                .and_then(|s| self.number(s, "_MM_SESSION_SPACE", "SessionId").ok()),
            wow64: self
                .number(address, "_EPROCESS", "Wow64Process")
                .or_else(|_| self.number(address, "_EPROCESS", "WoW64Process"))
                .is_ok_and(|p| p != 0),
        })
    }
    pub(crate) fn processes_partial(&self, job: &Job) -> Result<(Vec<Process>, Vec<String>)> {
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
    pub(crate) fn process_memory(&self, p: &Process) -> Result<Memory<'_>> {
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
        self.run_with_yara(p, options, None, job)
    }
    pub fn run_with_yara(
        &self,
        p: Plugin,
        options: &Options,
        precompiled_yara: Option<&crate::yara::YaraSpec>,
        job: &Job,
    ) -> Result<Results> {
        job.check()?;
        use Plugin::*;
        // Exhaustive on purpose: a new Plugin variant must be routed (or rejected) here.
        match p {
            // Container metadata is answered by container::analyze before any engine exists.
            WinCrashinfo => {
                bail!("windows.crashinfo 仅适用于崩溃转储/小型转储容器，RAW 镜像没有转储头")
            }
            WinDebugRegisters => self.debug_registers(None, job),
            WinPoolScanner => self.pool_scanner(job),
            WinWindowStations => self.window_stations(job),
            WinDesktops => self.desktops(job),
            WinDeskScan => self.deskscan(job),
            WinWindows => self.windows(job),
            WinSuspendedThreads => self.suspended_threads(None, job),
            WinUnhookedSystemCalls => self.unhooked_system_calls(None, job),
            WinDirectSystemCalls | WinIndirectSystemCalls => self.system_calls(p, job),
            WinSkeletonKeyCheck => self.skeleton_key(None, job),
            WinTruecryptPassphrase => self.truecrypt_passphrase(options, job),
            WinStrings => self.strings(options, job),
            WinPESymbols => self.pe_symbols(options, None, job),
            WinMemmap => self.memmap(options, None, job),
            WinSvcScanV4 => self.service_scan(options, job),
            WinSvcDiff => self.service_diff(options, job),
            WinSvcList => self.service_list(options, job),
            WinGetCellRoutine => self.get_cell_routine(job),
            WinPebMasquerade => self.peb_masquerade(options, job),
            WinDriverModule => self.driver_module(job),
            WinDriverIrp => self.driver_irp(job),
            WinKpcrs => self.kpcrs(job),
            WinVadWalk => self.vad_walk(options, job),
            WinVadRegExScan => self.vad_regex_scan(options, job),
            WinSysteminfo => self.system_info(),
            WinCallbacks | WinUnloadedmodules => self.kernel_artifacts(p, job),
            WinFilescan | WinMutantscan | WinSymlinkscan | WinThrdscan => {
                self.pool_artifacts(p, job)
            }
            WinConnscan | WinSockscan => self.legacy_network(p, job),
            WinDriverscan | WinDrivercheck => self.drivers(p, job),
            WinSvcscan | WinCmdscan | WinConsoles => self.user_artifacts(p, options, job),
            WinModules => self.modules(p, job),
            WinSsdt => self.ssdt(job),
            WinModscan => self.modscan(job),
            WinTimeliner => self.timeliner(job),
            WinOrphanThreads => self.orphan_threads(job),
            WinVirtmap => self.virtmap(),
            WinStatistics => self.statistics(job),
            WinTimers => self.timers(job),
            WinMbrscan => self.mbrscan(job),
            WinMftscan => self.mftscan(job),
            WinMftscanAds | WinMftscanResidentData => self.mftscan_streams(p, job),
            WinBigpools => self.bigpools(options, job),
            WinDevicetree => self.devicetree(job),
            WinHiveScan => self.hive_scan(job),
            WinHivelist => self.registry(p, options, job),
            WinPrintkey | WinAutoruns | WinUserassist | WinUserAssistV4 | WinGetservicesids
            | WinScheduledTasks | WinScheduledTasksV4 | WinAmcache | WinAmcacheV4
            | WinCertificates | WinShimcache | WinHashdump | WinLsadump | WinCachedump => {
                self.registry_plugin(p, options, job)
            }
            WinNetscan => self.netscan(job, None),
            WinNetstat => self.netstat(job, None),
            WinShimcacheMem => self.shimcache_memory(job),
            WinPsscan | WinPsxview => self.scan_processes(p, options, job),
            WinPslist | WinPstree | WinCmdline | WinGetsids | WinEnvars | WinThreads
            | WinLdrmodules | WinHollowprocesses | WinSuspiciousThreads | WinDlllist
            | WinVadinfo | WinMalfind | WinHandles | WinPrivileges | WinSessions | WinIat
            | WinVerinfo | WinEtwpatch | WinProcessghosting | WinJoblinks => {
                self.process_plugin(p, options, job)
            }
            WinYarascan | WinVadyarascan => {
                let spec = precompiled_yara
                    .with_context(|| format!("{} 缺少预编译的规则或字节模式", p.name()))?;
                let mut result = if p == WinYarascan {
                    crate::yara::physical_results(self.vm.image, p, spec, job)?
                } else {
                    self.process_plugin_with_yara(p, options, Some(spec), job)?
                };
                spec.annotate_library_result(&mut result);
                Ok(result)
            }
            // File exports go through run_dump with atomic publishing.
            WinProcdump | WinMemdump | WinPedump | WinVaddump | WinDlldump | WinModdump
            | WinDumpfiles => bail!("{} 是转储插件，请使用 dump 入口", p.name()),
            LinuxBoottime
            | LinuxTimeliner
            | LinuxCapabilities
            | LinuxEnvars
            | LinuxPsaux
            | LinuxPstree
            | LinuxMaps
            | LinuxLsof
            | LinuxSockstat
            | LinuxKmsg
            | LinuxMalfind
            | LinuxMountinfo
            | LinuxPagecacheFiles
            | LinuxPagecacheInodePages
            | LinuxPagecacheRecoverFs
            | LinuxBash
            | LinuxElfs
            | LinuxLibraryList
            | LinuxIpAddr
            | LinuxIpLink
            | Fbdev
            | PsCallStack
            | VmaRegExScan
            | LinuxSockscan
            | LinuxPsscan
            | Kallsyms
            | ModuleExtract
            | Modxview
            | ProcessSpoofing
            | LinuxPslist
            | CheckExec
            | Iomem
            | Ioports
            | Ptrace
            | KeyboardNotifiers
            | Psstate
            | Capabilities
            | Fdsummary
            | Procdump
            | Memdump
            | Elfdump
            | Pslist
            | Pstree
            | Lsmod
            | Psaux
            | Envars
            | Maps
            | Lsof
            | Sockstat
            | Netscan
            | Banners
            | Pwd
            | Pscred
            | Threads
            | Mountinfo
            | CheckCreds
            | Dmesg
            | Systeminfo
            | Elfs
            | Bash
            | Zsh
            | Malfind
            | Psxview
            | CheckModules
            | CheckSyscall
            | CheckIdt
            | TtyCheck
            | HiddenModules
            | LibraryList
            | Pidhashtable
            | Vmcoreinfo
            | IpAddr
            | IpLink
            | CheckAfinfo
            | Kthreads
            | Netfilter
            | Tracepoints
            | Ftrace
            | Ebpf
            | Boottime
            | Pagecache
            | PerfEvents
            | Vmayarascan
            | LinuxYarascan => bail!("{} 不是 Windows 插件", p.name()),
        }
    }
    fn system_info(&self) -> Result<Results> {
        let mut result = self.result(Plugin::WinSysteminfo);
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
            if let Some(value) = result.kernel_identity.key("version").get(key) {
                result.rows.push(vec![key.into(), value.to_string()]);
            }
        }
        Ok(result)
    }
    /// Kernel-mode System threads whose start address has no owning module.
    fn orphan_threads(&self, job: &Job) -> Result<Results> {
        let mut result = self.result(Plugin::WinOrphanThreads);
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
            let start = u64::from_str_radix(row.at(5)?.trim_start_matches("0x"), 16).unwrap_or(0);
            if self.vm.kernel(start) && row.at(6)?.is_empty() {
                result.rows.push(vec![
                    row.at(0)?.clone(),
                    row.at(2)?.clone(),
                    row.at(3)?.clone(),
                    row.at(5)?.clone(),
                    row.at(7)?.clone(),
                ]);
            }
        }
        Ok(result)
    }
    /// Registry plugins run against the Registry process view, falling back to the kernel view.
    fn registry_plugin(&self, p: Plugin, options: &Options, job: &Job) -> Result<Results> {
        let (processes, diagnostics) = self.processes_partial(job)?;
        let owners: Vec<_> = processes
            .iter()
            .filter(|process| {
                process.name == "Registry" && process.ppid == 4 && process.exited == 0
            })
            .collect();
        ensure!(owners.len() <= 1, "Registry 进程归属歧义");
        let registry = owners
            .first()
            .map(|process| {
                Ok::<_, anyhow::Error>(Windows {
                    vm: self.process_memory(process)?,
                    base: self.base,
                    pdb: self.pdb.clone(),
                })
            })
            .transpose()?;
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
                Plugin::WinPrintkey => engine.registry(p, options, job),
                other => bail!("注册表路由缺少插件 {}", other.name()),
            }
        };
        let mut result = match &registry {
            None => run(self)?,
            Some(registry) => {
                // Registry 进程视图失败（如 crash dump 未保存其页表）时回退内核视图。
                match run(registry) {
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
            }
        };
        if !diagnostics.is_empty() {
            result.complete = false;
            result.diagnostics.extend(diagnostics);
        }
        if let (Some(owner), Some(registry)) = (owners.first(), registry.as_ref()) {
            *result.kernel_identity.key_mut("registry_process")? = serde_json::json!({"pid":owner.pid,"address":owner.address,"dtb":registry.vm.root,"kernel_dtb":self.vm.root});
        }
        Ok(result)
    }
    /// Per-process plugins over the (possibly partial) active process list.
    fn process_plugin(&self, p: Plugin, options: &Options, job: &Job) -> Result<Results> {
        self.process_plugin_with_yara(p, options, None, job)
    }

    fn process_plugin_with_yara(
        &self,
        p: Plugin,
        options: &Options,
        precompiled_yara: Option<&crate::yara::YaraSpec>,
        job: &Job,
    ) -> Result<Results> {
        let mut result = self.result(p);
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
        let handle_layout = (p == Plugin::WinHandles).then(|| self.object_header_layout());
        let mut vad_yara_scanner = precompiled_yara.map(crate::yara::YaraSpec::scanner);
        for process in processes
            .into_iter()
            .filter(|p| options.pid.is_none_or(|pid| p.pid == u64::from(pid)))
        {
            job.check()?;
            let mut output_limit = false;
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
                Plugin::WinDlllist => self.dlllist(&process, options, &mut result, job),
                Plugin::WinVadinfo | Plugin::WinMalfind => {
                    self.vad_result(&process, p, options, &mut result, job)
                }
                Plugin::WinHandles => handle_layout
                    .as_ref()
                    .context("句柄对象头布局未初始化")
                    .and_then(|layout| {
                        self.handles_with_layout(&process, layout, &mut result, job)
                    }),
                Plugin::WinPrivileges => self.privileges(&process, &mut result),
                Plugin::WinSessions => self.session(&process, &mut result),
                Plugin::WinIat => self.iat(&process, &mut result, job),
                Plugin::WinVerinfo => self.verinfo(&process, &mut result, job),
                Plugin::WinEtwpatch => self.etwpatch(&process, &mut result, job),
                Plugin::WinProcessghosting => self.processghosting(&process, &mut result),
                Plugin::WinJoblinks => self.joblink(&process, &mut result),
                Plugin::WinVadyarascan => vad_yara_scanner
                    .as_mut()
                    .context("windows.vadyarascan 缺少预编译的规则或字节模式")
                    .and_then(|scanner| {
                        self.vad_yara_scan_with_scanner(&process, scanner, &mut result, job)
                            .map(|limit_reached| output_limit = limit_reached)
                    }),
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
            if output_limit {
                break;
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
