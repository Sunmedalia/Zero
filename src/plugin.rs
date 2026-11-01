//! Plugin identities, display metadata and categories shared by every platform.
use clap::ValueEnum;

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Plugin {
    #[value(name = "linux.boottime.Boottime", alias = "linux.boottime")]
    LinuxBoottime,
    #[value(name = "linux.capabilities.Capabilities", alias = "linux.capabilities")]
    LinuxCapabilities,
    #[value(name = "linux.envars.Envars", alias = "linux.envars")]
    LinuxEnvars,
    #[value(name = "linux.psaux.PsAux", alias = "linux.psaux")]
    LinuxPsaux,
    #[value(name = "windows.debugregisters.DebugRegisters")]
    WinDebugRegisters,
    #[value(
        name = "windows.poolscanner.PoolScanner",
        alias = "windows.poolscanner"
    )]
    WinPoolScanner,
    #[value(
        name = "windows.windowstations.WindowStations",
        alias = "windows.windowstations"
    )]
    WinWindowStations,
    #[value(name = "windows.desktops.Desktops", alias = "windows.desktops")]
    WinDesktops,
    #[value(name = "windows.netstat.NetStat", alias = "windows.netstat")]
    WinNetstat,
    #[value(
        name = "windows.shimcachemem.ShimcacheMem",
        alias = "windows.shimcachemem"
    )]
    WinShimcacheMem,
    #[value(name = "windows.deskscan.DeskScan", alias = "windows.deskscan")]
    WinDeskScan,
    #[value(name = "windows.windows.Windows", alias = "windows.windows")]
    WinWindows,
    #[value(name = "windows.pe_symbols.PESymbols")]
    WinPESymbols,
    #[value(name = "windows.strings.Strings", alias = "windows.strings")]
    WinStrings,
    #[value(name = "windows.truecrypt.Passphrase", alias = "windows.truecrypt")]
    WinTruecryptPassphrase,
    #[value(
        name = "windows.malware.skeleton_key_check.Skeleton_Key_Check",
        alias = "windows.skeleton_key_check"
    )]
    WinSkeletonKeyCheck,
    #[value(
        name = "windows.malware.direct_system_calls.DirectSystemCalls",
        alias = "windows.direct_system_calls"
    )]
    WinDirectSystemCalls,
    #[value(
        name = "windows.malware.indirect_system_calls.IndirectSystemCalls",
        alias = "windows.indirect_system_calls"
    )]
    WinIndirectSystemCalls,
    #[value(
        name = "windows.malware.unhooked_system_calls.UnhookedSystemCalls",
        alias = "windows.unhooked_system_calls"
    )]
    WinUnhookedSystemCalls,
    #[value(name = "windows.suspended_threads.SuspendedThreads")]
    WinSuspendedThreads,
    #[value(name = "windows.registry.amcache.Amcache")]
    WinAmcacheV4,
    #[value(name = "windows.registry.userassist.UserAssist")]
    WinUserAssistV4,
    #[value(name = "windows.memmap.Memmap", alias = "windows.memmap")]
    WinMemmap,
    #[value(name = "windows.svcscan.SvcScan")]
    WinSvcScanV4,
    #[value(name = "windows.malware.svcdiff.SvcDiff", alias = "windows.svcdiff")]
    WinSvcDiff,
    #[value(name = "windows.svclist.SvcList", alias = "windows.svclist")]
    WinSvcList,
    #[value(
        name = "windows.registry.getcellroutine.GetCellRoutine",
        alias = "windows.getcellroutine"
    )]
    WinGetCellRoutine,
    #[value(
        name = "windows.malware.pebmasquerade.PebMasquerade",
        alias = "windows.pebmasquerade"
    )]
    WinPebMasquerade,
    #[value(
        name = "windows.registry.hivescan.HiveScan",
        alias = "windows.hivescan"
    )]
    WinHiveScan,
    #[value(
        name = "windows.malware.drivermodule.DriverModule",
        alias = "windows.drivermodule"
    )]
    WinDriverModule,
    #[value(name = "windows.driverirp.DriverIrp", alias = "windows.driverirp")]
    WinDriverIrp,
    #[value(name = "windows.kpcrs.KPCRs", alias = "windows.kpcrs")]
    WinKpcrs,
    #[value(name = "windows.vadwalk.VadWalk", alias = "windows.vadwalk")]
    WinVadWalk,
    #[value(
        name = "windows.vadregexscan.VadRegExScan",
        alias = "windows.vadregexscan"
    )]
    WinVadRegExScan,
    #[value(name = "linux.graphics.fbdev.Fbdev", alias = "linux.fbdev")]
    Fbdev,
    #[value(name = "linux.pscallstack.PsCallStack", alias = "linux.pscallstack")]
    PsCallStack,
    #[value(name = "linux.vmaregexscan.VmaRegExScan", alias = "linux.vmaregexscan")]
    VmaRegExScan,
    #[value(name = "linux.sockscan.Sockscan", alias = "linux.sockscan")]
    LinuxSockscan,
    #[value(name = "linux.psscan.PsScan", alias = "linux.psscan")]
    LinuxPsscan,
    #[value(name = "linux.kallsyms.Kallsyms", alias = "linux.kallsyms")]
    Kallsyms,
    #[value(
        name = "linux.module_extract.ModuleExtract",
        alias = "linux.module_extract"
    )]
    ModuleExtract,
    #[value(name = "linux.malware.modxview.Modxview", alias = "linux.modxview")]
    Modxview,
    #[value(
        name = "linux.malware.process_spoofing.ProcessSpoofing",
        alias = "linux.process_spoofing"
    )]
    ProcessSpoofing,
    #[value(name = "linux.pslist.PsList", alias = "linux.pslist")]
    LinuxPslist,
    #[value(name = "windows.ldrmodules")]
    WinLdrmodules,
    #[value(name = "windows.hollowprocesses")]
    WinHollowprocesses,
    #[value(name = "windows.suspicious_threads")]
    WinSuspiciousThreads,
    #[value(name = "check_exec", alias = "check-exec")]
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
    #[value(name = "windows.orphan_kernel_threads")]
    WinOrphanThreads,
    #[value(name = "windows.etwpatch")]
    WinEtwpatch,
    #[value(name = "windows.registry.scheduled_tasks")]
    WinScheduledTasks,
    #[value(name = "windows.registry.scheduled_tasks.ScheduledTasks")]
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
    Iomem,
    Ioports,
    Ptrace,
    #[value(name = "keyboard_notifiers", alias = "keyboard-notifiers")]
    KeyboardNotifiers,
    Psstate,
    Capabilities,
    Fdsummary,
    Procdump,
    Memdump,
    Elfdump,
    Pslist,
    Pstree,
    Lsmod,
    Psaux,
    Envars,
    Maps,
    Lsof,
    Sockstat,
    Netscan,
    Banners,
    Pwd,
    Pscred,
    Threads,
    Mountinfo,
    #[value(name = "check_creds", alias = "check-creds")]
    CheckCreds,
    Dmesg,
    Systeminfo,
    Elfs,
    #[value(alias = "history")]
    Bash,
    Malfind,
    Psxview,
    #[value(name = "check_modules", alias = "check-modules")]
    CheckModules,
    #[value(name = "check_syscall", alias = "check-syscall")]
    CheckSyscall,
    #[value(name = "check_idt", alias = "check-idt")]
    CheckIdt,
    #[value(name = "tty_check", alias = "tty-check")]
    TtyCheck,
    #[value(name = "hidden_modules", alias = "hidden-modules")]
    HiddenModules,
    #[value(name = "library_list", alias = "library-list")]
    LibraryList,
    Pidhashtable,
    Vmcoreinfo,
    #[value(name = "ip_addr", alias = "ip.addr")]
    IpAddr,
    #[value(name = "ip_link", alias = "ip.link")]
    IpLink,
    #[value(name = "check_afinfo", alias = "check-afinfo")]
    CheckAfinfo,
    Kthreads,
    Netfilter,
    Tracepoints,
    Ftrace,
    Ebpf,
    Boottime,
    Pagecache,
    #[value(name = "perf_events", alias = "perf-events")]
    PerfEvents,
    Vmayarascan,
}
mod catalog;
pub use catalog::PLUGINS;

/// `Plugin` discriminant to `PLUGINS` position. Built at compile time, which also proves
/// that every variant has exactly one descriptor, so `Plugin::descriptor` cannot miss.
const DESCRIPTOR_INDEX: [u16; PLUGINS.len()] = {
    const UNSET: u16 = u16::MAX;
    let mut index = [UNSET; PLUGINS.len()];
    let mut position = 0;
    while position < PLUGINS.len() {
        let plugin = PLUGINS[position].plugin as usize;
        assert!(index[plugin] == UNSET, "duplicate plugin descriptor");
        index[plugin] = position as u16;
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
        self.is_dump() || matches!(self, Self::Fbdev | Self::WinMemmap | Self::Lsmod)
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
            )
    }
    pub fn descriptor(self) -> &'static Descriptor {
        &PLUGINS[DESCRIPTOR_INDEX[self as usize] as usize]
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
    /// Plugins that scan memory for a user-supplied byte pattern.
    pub fn is_pattern_scan(self) -> bool {
        matches!(self, Self::Vmayarascan | Self::WinVadyarascan)
    }
    pub fn is_tree(self) -> bool {
        matches!(self, Self::Pstree | Self::WinPstree)
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
    fn linux_netscan_and_windows_netscan_have_distinct_identities() {
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
    fn bash_history_has_one_plugin_and_legacy_commands_use_the_same_identity() {
        assert_eq!(Plugin::from_str("history", false).unwrap(), Plugin::Bash);
        assert_eq!(PLUGINS.iter().filter(|d| d.name == "bash").count(), 1);
        assert!(!PLUGINS.iter().any(|d| d.name == "history"));
    }
}
