//! Plugin identities, display metadata and categories shared by every platform.
use clap::ValueEnum;

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Plugin {
    #[value(
        name = "linux.boottime.full",
        alias = "linux.boottime",
        alias = "linux.boottime.Boottime"
    )]
    LinuxBoottime,
    #[value(
        name = "linux.timeliner",
        alias = "timeliner.Timeliner",
        alias = "timeliner"
    )]
    LinuxTimeliner,
    #[value(
        name = "linux.capabilities.full",
        alias = "linux.capabilities",
        alias = "linux.capabilities.Capabilities"
    )]
    LinuxCapabilities,
    #[value(
        name = "linux.envars.full",
        alias = "linux.envars",
        alias = "linux.envars.Envars"
    )]
    LinuxEnvars,
    #[value(
        name = "linux.psaux.full",
        alias = "linux.psaux",
        alias = "linux.psaux.PsAux"
    )]
    LinuxPsaux,
    #[value(
        name = "linux.pstree.full",
        alias = "linux.pstree",
        alias = "linux.pstree.PsTree"
    )]
    LinuxPstree,
    #[value(
        name = "linux.maps.full",
        alias = "linux.maps",
        alias = "linux.proc.Maps"
    )]
    LinuxMaps,
    #[value(
        name = "linux.lsof.full",
        alias = "linux.lsof",
        alias = "linux.lsof.Lsof"
    )]
    LinuxLsof,
    #[value(
        name = "linux.sockstat.full",
        alias = "linux.sockstat",
        alias = "linux.sockstat.Sockstat"
    )]
    LinuxSockstat,
    #[value(name = "linux.kmsg", alias = "linux.kmsg.Kmsg", alias = "kmsg")]
    LinuxKmsg,
    #[value(
        name = "linux.malfind.full",
        alias = "linux.malfind",
        alias = "linux.malware.malfind.Malfind"
    )]
    LinuxMalfind,
    #[value(
        name = "linux.mountinfo.full",
        alias = "linux.mountinfo",
        alias = "linux.mountinfo.MountInfo"
    )]
    LinuxMountinfo,
    #[value(name = "linux.pagecache.files", alias = "linux.pagecache.Files")]
    LinuxPagecacheFiles,
    #[value(
        name = "linux.pagecache.inode_pages",
        alias = "linux.pagecache.InodePages",
        alias = "linux.pagecache.inodepages"
    )]
    LinuxPagecacheInodePages,
    #[value(
        name = "linux.pagecache.recover_fs",
        alias = "linux.pagecache.RecoverFs",
        alias = "linux.pagecache.recoverfs"
    )]
    LinuxPagecacheRecoverFs,
    #[value(
        name = "linux.bash.full",
        alias = "linux.bash",
        alias = "linux.bash.Bash"
    )]
    LinuxBash,
    #[value(
        name = "linux.elfs.full",
        alias = "linux.elfs",
        alias = "linux.elfs.Elfs"
    )]
    LinuxElfs,
    #[value(
        name = "linux.library_list.full",
        alias = "linux.library_list",
        alias = "linux.library_list.LibraryList"
    )]
    LinuxLibraryList,
    #[value(
        name = "linux.ip.addr.full",
        alias = "linux.ip.addr",
        alias = "linux.ip.Addr"
    )]
    LinuxIpAddr,
    #[value(
        name = "linux.ip.link.full",
        alias = "linux.ip.link",
        alias = "linux.ip.Link"
    )]
    LinuxIpLink,
    #[value(
        name = "windows.debugregisters",
        alias = "windows.debugregisters.DebugRegisters"
    )]
    WinDebugRegisters,
    #[value(
        name = "windows.poolscanner",
        alias = "windows.poolscanner.PoolScanner"
    )]
    WinPoolScanner,
    #[value(
        name = "windows.windowstations",
        alias = "windows.windowstations.WindowStations"
    )]
    WinWindowStations,
    #[value(name = "windows.desktops", alias = "windows.desktops.Desktops")]
    WinDesktops,
    #[value(name = "windows.netstat", alias = "windows.netstat.NetStat")]
    WinNetstat,
    #[value(
        name = "windows.shimcachemem",
        alias = "windows.shimcachemem.ShimcacheMem"
    )]
    WinShimcacheMem,
    #[value(name = "windows.deskscan", alias = "windows.deskscan.DeskScan")]
    WinDeskScan,
    #[value(name = "windows.windows", alias = "windows.windows.Windows")]
    WinWindows,
    #[value(name = "windows.pe_symbols", alias = "windows.pe_symbols.PESymbols")]
    WinPESymbols,
    #[value(name = "windows.strings", alias = "windows.strings.Strings")]
    WinStrings,
    #[value(
        name = "windows.truecrypt.passphrase",
        alias = "windows.truecrypt.Passphrase",
        alias = "windows.truecrypt"
    )]
    WinTruecryptPassphrase,
    #[value(
        name = "windows.skeleton_key_check",
        alias = "windows.malware.skeleton_key_check.Skeleton_Key_Check"
    )]
    WinSkeletonKeyCheck,
    #[value(
        name = "windows.direct_system_calls",
        alias = "windows.malware.direct_system_calls.DirectSystemCalls"
    )]
    WinDirectSystemCalls,
    #[value(
        name = "windows.indirect_system_calls",
        alias = "windows.malware.indirect_system_calls.IndirectSystemCalls"
    )]
    WinIndirectSystemCalls,
    #[value(
        name = "windows.unhooked_system_calls",
        alias = "windows.malware.unhooked_system_calls.UnhookedSystemCalls"
    )]
    WinUnhookedSystemCalls,
    #[value(
        name = "windows.suspended_threads",
        alias = "windows.suspended_threads.SuspendedThreads"
    )]
    WinSuspendedThreads,
    #[value(
        name = "windows.registry.amcache.full",
        alias = "windows.registry.amcache.Amcache"
    )]
    WinAmcacheV4,
    #[value(
        name = "windows.registry.userassist.full",
        alias = "windows.registry.userassist.UserAssist"
    )]
    WinUserAssistV4,
    #[value(name = "windows.memmap", alias = "windows.memmap.Memmap")]
    WinMemmap,
    #[value(name = "windows.svcscan.full", alias = "windows.svcscan.SvcScan")]
    WinSvcScanV4,
    #[value(name = "windows.svcdiff", alias = "windows.malware.svcdiff.SvcDiff")]
    WinSvcDiff,
    #[value(name = "windows.svclist", alias = "windows.svclist.SvcList")]
    WinSvcList,
    #[value(
        name = "windows.registry.getcellroutine",
        alias = "windows.registry.getcellroutine.GetCellRoutine",
        alias = "windows.getcellroutine"
    )]
    WinGetCellRoutine,
    #[value(
        name = "windows.pebmasquerade",
        alias = "windows.malware.pebmasquerade.PebMasquerade"
    )]
    WinPebMasquerade,
    #[value(
        name = "windows.registry.hivescan",
        alias = "windows.registry.hivescan.HiveScan",
        alias = "windows.hivescan"
    )]
    WinHiveScan,
    #[value(
        name = "windows.drivermodule",
        alias = "windows.malware.drivermodule.DriverModule"
    )]
    WinDriverModule,
    #[value(name = "windows.driverirp", alias = "windows.driverirp.DriverIrp")]
    WinDriverIrp,
    #[value(name = "windows.kpcrs", alias = "windows.kpcrs.KPCRs")]
    WinKpcrs,
    #[value(name = "windows.vadwalk", alias = "windows.vadwalk.VadWalk")]
    WinVadWalk,
    #[value(
        name = "windows.vadregexscan",
        alias = "windows.vadregexscan.VadRegExScan"
    )]
    WinVadRegExScan,
    #[value(
        name = "linux.fbdev",
        alias = "linux.graphics.fbdev.Fbdev",
        alias = "fbdev"
    )]
    Fbdev,
    #[value(
        name = "linux.pscallstack",
        alias = "linux.pscallstack.PsCallStack",
        alias = "pscallstack"
    )]
    PsCallStack,
    #[value(
        name = "linux.vmaregexscan",
        alias = "linux.vmaregexscan.VmaRegExScan",
        alias = "vmaregexscan"
    )]
    VmaRegExScan,
    #[value(
        name = "linux.sockscan",
        alias = "linux.sockscan.Sockscan",
        alias = "sockscan"
    )]
    LinuxSockscan,
    #[value(name = "linux.psscan", alias = "linux.psscan.PsScan", alias = "psscan")]
    LinuxPsscan,
    #[value(
        name = "linux.kallsyms",
        alias = "linux.kallsyms.Kallsyms",
        alias = "kallsyms"
    )]
    Kallsyms,
    #[value(
        name = "linux.module_extract",
        alias = "linux.module_extract.ModuleExtract",
        alias = "module_extract"
    )]
    ModuleExtract,
    #[value(
        name = "linux.modxview",
        alias = "linux.malware.modxview.Modxview",
        alias = "modxview"
    )]
    Modxview,
    #[value(
        name = "linux.process_spoofing",
        alias = "linux.malware.process_spoofing.ProcessSpoofing",
        alias = "process_spoofing"
    )]
    ProcessSpoofing,
    #[value(
        name = "linux.pslist.full",
        alias = "linux.pslist",
        alias = "linux.pslist.PsList"
    )]
    LinuxPslist,
    #[value(name = "windows.ldrmodules")]
    WinLdrmodules,
    #[value(name = "windows.hollowprocesses")]
    WinHollowprocesses,
    #[value(name = "windows.suspicious_threads")]
    WinSuspiciousThreads,
    #[value(name = "linux.check_exec", alias = "check_exec", alias = "check-exec")]
    CheckExec,
    #[value(name = "windows.callbacks")]
    WinCallbacks,
    #[value(name = "windows.unloadedmodules")]
    WinUnloadedmodules,
    #[value(name = "windows.filescan")]
    WinFilescan,
    #[value(name = "windows.mutantscan")]
    WinMutantscan,
    #[value(name = "windows.getsids")]
    WinGetsids,
    #[value(name = "windows.connscan")]
    WinConnscan,
    #[value(name = "windows.sockscan")]
    WinSockscan,
    #[value(name = "windows.consoles")]
    WinConsoles,
    #[value(name = "windows.cmdscan")]
    WinCmdscan,
    #[value(name = "windows.drivercheck")]
    WinDrivercheck,
    #[value(name = "windows.driverscan")]
    WinDriverscan,
    #[value(name = "windows.svcscan")]
    WinSvcscan,
    #[value(name = "windows.crashinfo")]
    WinCrashinfo,
    #[value(name = "windows.autoruns")]
    WinAutoruns,
    #[value(name = "windows.envars")]
    WinEnvars,
    #[value(name = "windows.threads")]
    WinThreads,
    #[value(name = "windows.systeminfo")]
    WinSysteminfo,
    #[value(name = "windows.pslist")]
    WinPslist,
    #[value(name = "windows.pstree")]
    WinPstree,
    #[value(name = "windows.cmdline")]
    WinCmdline,
    #[value(name = "windows.modules")]
    WinModules,
    #[value(name = "windows.dlllist")]
    WinDlllist,
    #[value(name = "windows.vadinfo")]
    WinVadinfo,
    #[value(name = "windows.handles")]
    WinHandles,
    #[value(name = "windows.malfind")]
    WinMalfind,
    #[value(name = "windows.netscan")]
    WinNetscan,
    #[value(name = "windows.hivelist")]
    WinHivelist,
    #[value(name = "windows.printkey")]
    WinPrintkey,
    #[value(name = "windows.psscan")]
    WinPsscan,
    #[value(name = "windows.psxview")]
    WinPsxview,
    #[value(name = "windows.procdump")]
    WinProcdump,
    #[value(name = "windows.memdump")]
    WinMemdump,
    #[value(name = "windows.pedump")]
    WinPedump,
    #[value(name = "windows.vaddump")]
    WinVaddump,
    #[value(name = "windows.dlldump")]
    WinDlldump,
    #[value(name = "windows.moddump")]
    WinModdump,
    #[value(name = "windows.hashdump")]
    WinHashdump,
    #[value(name = "windows.lsadump")]
    WinLsadump,
    #[value(name = "windows.cachedump")]
    WinCachedump,
    #[value(name = "windows.dumpfiles")]
    WinDumpfiles,
    #[value(name = "windows.thrdscan")]
    WinThrdscan,
    #[value(name = "windows.ssdt")]
    WinSsdt,
    #[value(name = "windows.modscan")]
    WinModscan,
    #[value(name = "windows.privileges")]
    WinPrivileges,
    #[value(name = "windows.sessions")]
    WinSessions,
    #[value(name = "windows.registry.userassist")]
    WinUserassist,
    #[value(name = "windows.bigpools")]
    WinBigpools,
    #[value(name = "windows.symlinkscan")]
    WinSymlinkscan,
    #[value(name = "windows.devicetree")]
    WinDevicetree,
    #[value(name = "windows.getservicesids")]
    WinGetservicesids,
    #[value(name = "windows.iat")]
    WinIat,
    #[value(name = "windows.verinfo")]
    WinVerinfo,
    #[value(name = "windows.mftscan")]
    WinMftscan,
    #[value(name = "windows.mftscan.ads", alias = "windows.mftscan.ADS")]
    WinMftscanAds,
    #[value(
        name = "windows.mftscan.resident_data",
        alias = "windows.mftscan.ResidentData",
        alias = "windows.mftscan.residentdata"
    )]
    WinMftscanResidentData,
    #[value(name = "windows.orphan_kernel_threads")]
    WinOrphanThreads,
    #[value(name = "windows.etwpatch")]
    WinEtwpatch,
    #[value(name = "windows.registry.scheduled_tasks")]
    WinScheduledTasks,
    #[value(
        name = "windows.registry.scheduled_tasks.full",
        alias = "windows.registry.scheduled_tasks.ScheduledTasks"
    )]
    WinScheduledTasksV4,
    #[value(name = "windows.registry.amcache")]
    WinAmcache,
    #[value(name = "windows.registry.certificates")]
    WinCertificates,
    #[value(name = "windows.processghosting")]
    WinProcessghosting,
    #[value(name = "windows.joblinks")]
    WinJoblinks,
    #[value(name = "windows.timeliner")]
    WinTimeliner,
    #[value(name = "windows.mbrscan")]
    WinMbrscan,
    #[value(name = "windows.timers")]
    WinTimers,
    #[value(name = "windows.statistics")]
    WinStatistics,
    #[value(name = "windows.registry.shimcache")]
    WinShimcache,
    #[value(name = "windows.virtmap")]
    WinVirtmap,
    #[value(name = "windows.vadyarascan")]
    WinVadyarascan,
    #[value(name = "windows.yarascan", alias = "windows.yarascan.YaraScan")]
    WinYarascan,
    #[value(name = "linux.iomem", alias = "iomem")]
    Iomem,
    #[value(name = "linux.ioports", alias = "ioports")]
    Ioports,
    #[value(name = "linux.ptrace", alias = "ptrace")]
    Ptrace,
    #[value(
        name = "linux.keyboard_notifiers",
        alias = "keyboard_notifiers",
        alias = "keyboard-notifiers"
    )]
    KeyboardNotifiers,
    #[value(name = "linux.psstate", alias = "psstate")]
    Psstate,
    #[value(name = "linux.capabilities.basic", alias = "capabilities")]
    Capabilities,
    #[value(name = "linux.fdsummary", alias = "fdsummary")]
    Fdsummary,
    #[value(name = "linux.procdump", alias = "procdump")]
    Procdump,
    #[value(name = "linux.memdump", alias = "memdump")]
    Memdump,
    #[value(name = "linux.elfdump", alias = "elfdump")]
    Elfdump,
    #[value(name = "linux.pslist.basic", alias = "pslist")]
    Pslist,
    #[value(name = "linux.pstree.basic", alias = "pstree")]
    Pstree,
    #[value(name = "linux.lsmod", alias = "lsmod")]
    Lsmod,
    #[value(name = "linux.psaux.basic", alias = "psaux")]
    Psaux,
    #[value(name = "linux.envars.basic", alias = "envars")]
    Envars,
    #[value(name = "linux.maps.basic", alias = "maps")]
    Maps,
    #[value(name = "linux.lsof.basic", alias = "lsof")]
    Lsof,
    #[value(name = "linux.sockstat.basic", alias = "sockstat")]
    Sockstat,
    #[value(name = "linux.netscan", alias = "netscan")]
    Netscan,
    #[value(name = "linux.banners", alias = "banners")]
    Banners,
    #[value(name = "linux.pwd", alias = "pwd")]
    Pwd,
    #[value(name = "linux.pscred", alias = "pscred")]
    Pscred,
    #[value(name = "linux.threads", alias = "threads")]
    Threads,
    #[value(name = "linux.mountinfo.basic", alias = "mountinfo")]
    Mountinfo,
    #[value(
        name = "linux.check_creds",
        alias = "check_creds",
        alias = "check-creds"
    )]
    CheckCreds,
    #[value(name = "linux.dmesg", alias = "dmesg")]
    Dmesg,
    #[value(name = "linux.systeminfo", alias = "systeminfo")]
    Systeminfo,
    #[value(name = "linux.elfs.basic", alias = "elfs")]
    Elfs,
    #[value(name = "linux.bash.basic", alias = "bash", alias = "history")]
    Bash,
    #[value(name = "linux.zsh", alias = "zsh", alias = "zsh_history")]
    Zsh,
    #[value(name = "linux.malfind.basic", alias = "malfind")]
    Malfind,
    #[value(name = "linux.psxview", alias = "psxview")]
    Psxview,
    #[value(
        name = "linux.check_modules",
        alias = "check_modules",
        alias = "check-modules"
    )]
    CheckModules,
    #[value(
        name = "linux.check_syscall",
        alias = "check_syscall",
        alias = "check-syscall"
    )]
    CheckSyscall,
    #[value(name = "linux.check_idt", alias = "check_idt", alias = "check-idt")]
    CheckIdt,
    #[value(name = "linux.tty_check", alias = "tty_check", alias = "tty-check")]
    TtyCheck,
    #[value(
        name = "linux.hidden_modules",
        alias = "hidden_modules",
        alias = "hidden-modules"
    )]
    HiddenModules,
    #[value(
        name = "linux.library_list.basic",
        alias = "library_list",
        alias = "library-list"
    )]
    LibraryList,
    #[value(name = "linux.pidhashtable", alias = "pidhashtable")]
    Pidhashtable,
    #[value(name = "linux.vmcoreinfo", alias = "vmcoreinfo")]
    Vmcoreinfo,
    #[value(name = "linux.ip.addr.basic", alias = "ip_addr", alias = "ip.addr")]
    IpAddr,
    #[value(name = "linux.ip.link.basic", alias = "ip_link", alias = "ip.link")]
    IpLink,
    #[value(
        name = "linux.check_afinfo",
        alias = "check_afinfo",
        alias = "check-afinfo"
    )]
    CheckAfinfo,
    #[value(name = "linux.kthreads", alias = "kthreads")]
    Kthreads,
    #[value(name = "linux.netfilter", alias = "netfilter")]
    Netfilter,
    #[value(name = "linux.tracepoints", alias = "tracepoints")]
    Tracepoints,
    #[value(name = "linux.ftrace", alias = "ftrace")]
    Ftrace,
    #[value(name = "linux.ebpf", alias = "ebpf")]
    Ebpf,
    #[value(name = "linux.boottime.basic", alias = "boottime")]
    Boottime,
    #[value(name = "linux.pagecache", alias = "pagecache")]
    Pagecache,
    #[value(
        name = "linux.perf_events",
        alias = "perf_events",
        alias = "perf-events"
    )]
    PerfEvents,
    #[value(name = "linux.vmayarascan", alias = "vmayarascan")]
    Vmayarascan,
    #[value(
        name = "linux.yarascan",
        alias = "yarascan",
        alias = "yarascan.YaraScan",
        alias = "linux.yarascan.YaraScan"
    )]
    LinuxYarascan,
}
mod catalog;
pub use catalog::PLUGINS;

/// `Plugin` discriminant to `PLUGINS` position. Built at compile time, which also proves
/// that every variant has exactly one descriptor, so `Plugin::descriptor` cannot miss.
#[allow(clippy::indexing_slicing)] // Evaluated at compile time: out of range cannot build.
const DESCRIPTOR_INDEX: [usize; PLUGINS.len()] = {
    const UNSET: usize = usize::MAX;
    let mut index = [UNSET; PLUGINS.len()];
    let mut position = 0;
    while position < PLUGINS.len() {
        let plugin = PLUGINS[position].plugin as usize;
        assert!(index[plugin] == UNSET, "duplicate plugin descriptor");
        index[plugin] = position;
        position += 1;
    }
    index
};
pub struct Descriptor {
    pub plugin: Plugin,
    pub name: &'static str,
    pub label: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub columns: &'static [&'static str],
    /// Fixed widths; zero gives remaining space to text.
    pub widths: &'static [u16],
}
impl Plugin {
    /// Some listing plugins also support explicitly requested artifact exports.
    pub fn accepts_dump(self) -> bool {
        self.is_dump()
            || matches!(
                self,
                Self::Fbdev
                    | Self::WinMemmap
                    | Self::WinHivelist
                    | Self::WinMalfind
                    | Self::WinTimeliner
                    | Self::Lsmod
                    | Self::CheckModules
                    | Self::HiddenModules
                    | Self::LinuxMaps
                    | Self::LinuxMalfind
                    | Self::LinuxElfs
                    | Self::LinuxPslist
                    | Self::LinuxTimeliner
                    | Self::LinuxPagecacheInodePages
                    | Self::LinuxPagecacheRecoverFs
            )
    }
    pub fn is_linux_mapping_export(self) -> bool {
        matches!(self, Self::LinuxMaps | Self::LinuxMalfind | Self::LinuxElfs)
    }
    pub fn dump_uses_analysis_pid(self) -> bool {
        self.is_linux_mapping_export() || self == Self::LinuxPslist
    }
    pub fn is_regex_scan(self) -> bool {
        matches!(self, Self::VmaRegExScan | Self::WinVadRegExScan)
    }
    pub fn accepts_pid_list(self) -> bool {
        self.is_regex_scan()
            || matches!(
                self,
                Self::PsCallStack
                    | Self::WinVadWalk
                    | Self::WinPebMasquerade
                    | Self::WinStrings
                    | Self::LinuxCapabilities
                    | Self::LinuxEnvars
                    | Self::LinuxPsaux
                    | Self::LinuxPslist
                    | Self::LinuxPstree
                    | Self::LinuxMaps
                    | Self::LinuxLsof
                    | Self::LinuxSockstat
                    | Self::LinuxMalfind
                    | Self::LinuxMountinfo
                    | Self::LinuxBash
                    | Self::LinuxElfs
                    | Self::LinuxLibraryList
            )
    }
    // DESCRIPTOR_INDEX is proven complete and in range at compile time.
    #[allow(clippy::indexing_slicing)]
    pub fn descriptor(self) -> &'static Descriptor {
        &PLUGINS[DESCRIPTOR_INDEX[self as usize]]
    }
    pub fn is_dump(self) -> bool {
        matches!(
            self,
            Self::ModuleExtract
                | Self::Procdump
                | Self::Memdump
                | Self::Elfdump
                | Self::WinProcdump
                | Self::WinMemdump
                | Self::WinPedump
                | Self::WinVaddump
                | Self::WinDlldump
                | Self::WinModdump
                | Self::WinDumpfiles
        )
    }
    pub fn is_windows(self) -> bool {
        self.name().starts_with("windows.")
    }
    /// Reference-parity Linux plugins that walk tasks via `reference_process_rows`.
    pub fn uses_reference_tasks(self) -> bool {
        matches!(
            self,
            Self::LinuxBoottime
                | Self::LinuxTimeliner
                | Self::LinuxCapabilities
                | Self::LinuxEnvars
                | Self::LinuxPsaux
                | Self::LinuxPstree
                | Self::LinuxMaps
                | Self::LinuxLsof
                | Self::LinuxSockstat
                | Self::LinuxKmsg
                | Self::LinuxMalfind
                | Self::LinuxMountinfo
                | Self::LinuxPagecacheFiles
                | Self::LinuxPagecacheInodePages
                | Self::LinuxPagecacheRecoverFs
                | Self::LinuxBash
                | Self::LinuxElfs
                | Self::LinuxLibraryList
                | Self::LinuxIpAddr
                | Self::LinuxIpLink
                | Self::Fbdev
                | Self::PsCallStack
                | Self::VmaRegExScan
                | Self::LinuxSockscan
                | Self::LinuxPsscan
                | Self::Kallsyms
                | Self::ModuleExtract
                | Self::Modxview
                | Self::ProcessSpoofing
                | Self::LinuxPslist
        )
    }
    /// Plugins that scan memory with YARA rules or literal byte patterns.
    pub fn is_yara_scan(self) -> bool {
        matches!(
            self,
            Self::Vmayarascan | Self::WinVadyarascan | Self::LinuxYarascan | Self::WinYarascan
        )
    }
    /// Plugins that scan memory for a user-supplied byte pattern or YARA rule.
    pub fn is_pattern_scan(self) -> bool {
        self.is_yara_scan()
    }
    pub fn is_tree(self) -> bool {
        self.tree_columns().is_some()
    }
    pub fn tree_columns(self) -> Option<crate::result_view::TreeColumns> {
        use crate::result_view::TreeColumns;
        match self {
            Self::Pstree => Some(TreeColumns::simple(2, 3)),
            Self::WinPstree => Some(TreeColumns::simple(1, 2)),
            Self::LinuxPstree => Some(TreeColumns {
                id: 2,
                parent: 3,
                leader: Some(1),
                name: 4,
            }),
            _ => None,
        }
    }
    pub fn category(self) -> &'static str {
        self.descriptor().category
    }
    pub fn name(self) -> &'static str {
        self.descriptor().name
    }
    /// One-line Chinese description used by the interface search and help.
    pub fn description(self) -> &'static str {
        self.descriptor().description
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_plugin_has_one_descriptor_named_like_its_cli_value() {
        for plugin in Plugin::value_variants() {
            let matches: Vec<_> = PLUGINS.iter().filter(|d| d.plugin == *plugin).collect();
            assert_eq!(matches.len(), 1, "{plugin:?}");
            let cli = plugin.to_possible_value().unwrap();
            assert_eq!(cli.get_name(), matches[0].name, "{plugin:?}");
            assert_eq!(
                matches[0].columns.len(),
                matches[0].widths.len(),
                "{plugin:?}"
            );
        }
        assert_eq!(PLUGINS.len(), Plugin::value_variants().len());
    }

    #[test]
    fn every_plugin_follows_unified_naming_and_label_rules() {
        for d in PLUGINS {
            let (prefix, short) = d
                .name
                .split_once('.')
                .unwrap_or_else(|| panic!("missing os prefix: {}", d.name));
            assert!(
                matches!(prefix, "linux" | "windows"),
                "invalid os prefix: {}",
                d.name
            );
            assert!(
                d.name.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'_'
                    || b == b'.'),
                "non-canonical plugin name: {}",
                d.name
            );
            assert!(
                !d.name.contains(".malware.")
                    && !d.name.contains(".graphics.")
                    && !d.name.contains(".proc."),
                "redundant namespace in plugin name: {}",
                d.name
            );
            assert_eq!(d.label, short, "label must match short name for {}", d.name);
        }
    }

    #[test]
    fn linux_netscan_and_windows_netscan_have_distinct_identities() {
        assert_eq!(
            Plugin::from_str("linux.netscan", false).unwrap(),
            Plugin::Netscan
        );
        assert_eq!(Plugin::from_str("netscan", false).unwrap(), Plugin::Netscan);
        assert_eq!(
            Plugin::from_str("windows.netscan", false).unwrap(),
            Plugin::WinNetscan
        );
        assert!(!Plugin::Netscan.is_windows());
        assert_eq!(Plugin::Netscan.category(), "Network");
        assert_eq!(Plugin::Netscan.descriptor().columns.len(), 7);
    }

    #[test]
    fn bash_history_and_bare_bash_still_select_the_basic_plugin() {
        assert_eq!(Plugin::from_str("history", false).unwrap(), Plugin::Bash);
        assert_eq!(Plugin::from_str("bash", false).unwrap(), Plugin::Bash);
        assert!(!PLUGINS.iter().any(|d| d.name == "history"));
    }

    #[test]
    fn linux_legacy_names_keep_their_cli_and_mcp_plugin_identity() {
        for (full, basic, legacy, class_path, bare) in [
            (
                Plugin::LinuxBoottime,
                Plugin::Boottime,
                "linux.boottime",
                "linux.boottime.Boottime",
                "boottime",
            ),
            (
                Plugin::LinuxCapabilities,
                Plugin::Capabilities,
                "linux.capabilities",
                "linux.capabilities.Capabilities",
                "capabilities",
            ),
            (
                Plugin::LinuxEnvars,
                Plugin::Envars,
                "linux.envars",
                "linux.envars.Envars",
                "envars",
            ),
            (
                Plugin::LinuxPsaux,
                Plugin::Psaux,
                "linux.psaux",
                "linux.psaux.PsAux",
                "psaux",
            ),
            (
                Plugin::LinuxPstree,
                Plugin::Pstree,
                "linux.pstree",
                "linux.pstree.PsTree",
                "pstree",
            ),
            (
                Plugin::LinuxMaps,
                Plugin::Maps,
                "linux.maps",
                "linux.proc.Maps",
                "maps",
            ),
            (
                Plugin::LinuxLsof,
                Plugin::Lsof,
                "linux.lsof",
                "linux.lsof.Lsof",
                "lsof",
            ),
            (
                Plugin::LinuxSockstat,
                Plugin::Sockstat,
                "linux.sockstat",
                "linux.sockstat.Sockstat",
                "sockstat",
            ),
            (
                Plugin::LinuxMalfind,
                Plugin::Malfind,
                "linux.malfind",
                "linux.malware.malfind.Malfind",
                "malfind",
            ),
            (
                Plugin::LinuxMountinfo,
                Plugin::Mountinfo,
                "linux.mountinfo",
                "linux.mountinfo.MountInfo",
                "mountinfo",
            ),
            (
                Plugin::LinuxBash,
                Plugin::Bash,
                "linux.bash",
                "linux.bash.Bash",
                "bash",
            ),
            (
                Plugin::LinuxElfs,
                Plugin::Elfs,
                "linux.elfs",
                "linux.elfs.Elfs",
                "elfs",
            ),
            (
                Plugin::LinuxLibraryList,
                Plugin::LibraryList,
                "linux.library_list",
                "linux.library_list.LibraryList",
                "library_list",
            ),
            (
                Plugin::LinuxIpAddr,
                Plugin::IpAddr,
                "linux.ip.addr",
                "linux.ip.Addr",
                "ip_addr",
            ),
            (
                Plugin::LinuxIpLink,
                Plugin::IpLink,
                "linux.ip.link",
                "linux.ip.Link",
                "ip_link",
            ),
            (
                Plugin::LinuxPslist,
                Plugin::Pslist,
                "linux.pslist",
                "linux.pslist.PsList",
                "pslist",
            ),
        ] {
            assert_eq!(full.name(), format!("{legacy}.full"));
            assert_eq!(basic.name(), format!("{legacy}.basic"));
            for ignore_case in [false, true] {
                for (name, expected) in [
                    (legacy, full),
                    (class_path, full),
                    (full.name(), full),
                    (bare, basic),
                    (basic.name(), basic),
                ] {
                    assert_eq!(Plugin::from_str(name, ignore_case), Ok(expected), "{name}");
                }
            }
        }
    }
}
