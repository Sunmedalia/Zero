//! Plugin identities, display metadata and categories shared by every platform.
use clap::ValueEnum;

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Plugin {
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
pub struct Descriptor {
    pub plugin: Plugin,
    pub name: &'static str,
    pub label: &'static str,
    pub columns: &'static [&'static str],
    /// Fixed widths; zero gives remaining space to text.
    pub widths: &'static [u16],
}
pub const PLUGINS: &[Descriptor] = &[
    Descriptor {
        plugin: Plugin::WinLdrmodules,
        name: "windows.ldrmodules",
        label: "windows.ldrmodules",
        columns: &[
            "PID", "Name", "Base", "View", "InLoad", "InInit", "InMem", "Path", "Reason",
        ],
        widths: &[0; 9],
    },
    Descriptor {
        plugin: Plugin::WinHollowprocesses,
        name: "windows.hollowprocesses",
        label: "windows.hollowprocesses",
        columns: &[
            "PID",
            "Name",
            "View",
            "Address",
            "Protection",
            "Path",
            "Reason",
        ],
        widths: &[0; 7],
    },
    Descriptor {
        plugin: Plugin::WinSuspiciousThreads,
        name: "windows.suspicious_threads",
        label: "windows.suspicious_threads",
        columns: &[
            "PID",
            "Name",
            "TID",
            "Context",
            "Address",
            "Protection",
            "Path",
            "Reason",
        ],
        widths: &[0; 8],
    },
    Descriptor {
        plugin: Plugin::CheckExec,
        name: "check_exec",
        label: "check_exec",
        columns: &[
            "PID",
            "Name",
            "Start",
            "End",
            "Permissions",
            "Path",
            "Reason",
        ],
        widths: &[0; 7],
    },
    Descriptor {
        plugin: Plugin::WinCallbacks,
        name: "windows.callbacks",
        label: "windows.callbacks",
        columns: &["Type", "Address", "Function", "Module", "Details"],
        widths: &[0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinUnloadedmodules,
        name: "windows.unloadedmodules",
        label: "windows.unloadedmodules",
        columns: &["Name", "Start", "End", "UnloadTime"],
        widths: &[0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinFilescan,
        name: "windows.filescan",
        label: "windows.filescan",
        columns: &[
            "Physical",
            "Address",
            "Name",
            "DeviceObject",
            "ReadAccess",
            "WriteAccess",
            "DeleteAccess",
        ],
        widths: &[0, 0, 0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinMutantscan,
        name: "windows.mutantscan",
        label: "windows.mutantscan",
        columns: &["Physical", "Address", "Name", "OwnerThread", "SignalState"],
        widths: &[0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinGetsids,
        name: "windows.getsids",
        label: "windows.getsids",
        columns: &["PID", "Name", "SID", "Attributes", "Account"],
        widths: &[0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinConnscan,
        name: "windows.connscan",
        label: "windows.connscan",
        columns: &[
            "Physical",
            "PID",
            "LocalAddress",
            "LocalPort",
            "RemoteAddress",
            "RemotePort",
        ],
        widths: &[0, 0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinSockscan,
        name: "windows.sockscan",
        label: "windows.sockscan",
        columns: &[
            "Physical",
            "PID",
            "LocalAddress",
            "LocalPort",
            "Protocol",
            "CreateTime",
        ],
        widths: &[0, 0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinConsoles,
        name: "windows.consoles",
        label: "windows.consoles",
        columns: &[
            "PID",
            "Name",
            "Address",
            "Title",
            "HistorySize",
            "HistoryCount",
        ],
        widths: &[0, 0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinCmdscan,
        name: "windows.cmdscan",
        label: "windows.cmdscan",
        columns: &["PID", "Name", "History", "Application", "Index", "Command"],
        widths: &[0, 0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinDrivercheck,
        name: "windows.drivercheck",
        label: "windows.drivercheck",
        columns: &[
            "Address",
            "DriverName",
            "Function",
            "Target",
            "TargetModule",
            "InDriverRange",
        ],
        widths: &[0, 0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinDriverscan,
        name: "windows.driverscan",
        label: "windows.driverscan",
        columns: &[
            "Address",
            "DriverName",
            "Start",
            "Size",
            "Module",
            "DriverInit",
        ],
        widths: &[0, 0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinSvcscan,
        name: "windows.svcscan",
        label: "windows.svcscan",
        columns: &[
            "PID",
            "Address",
            "ServiceName",
            "DisplayName",
            "State",
            "Start",
            "Type",
            "BinaryPath",
        ],
        widths: &[0, 0, 0, 0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinCrashinfo,
        name: "windows.crashinfo",
        label: "windows.crashinfo",
        columns: &["Key", "Value"],
        widths: &[0, 0],
    },
    Descriptor {
        plugin: Plugin::WinAutoruns,
        name: "windows.autoruns",
        label: "windows.autoruns",
        columns: &[
            "Hive",
            "Key",
            "Kind",
            "Name",
            "Type",
            "Data",
            "LastWriteTime",
        ],
        widths: &[0, 0, 0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinEnvars,
        name: "windows.envars",
        label: "windows.envars",
        columns: &["PID", "Name", "View", "Variable", "Value"],
        widths: &[0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinThreads,
        name: "windows.threads",
        label: "windows.threads",
        columns: &[
            "PID",
            "Name",
            "TID",
            "Address",
            "State",
            "StartAddress",
            "StartModule",
            "CreateTime",
            "ExitTime",
        ],
        widths: &[0, 0, 0, 0, 0, 0, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinSysteminfo,
        name: "windows.systeminfo",
        label: "windows.systeminfo",
        columns: &["Key", "Value"],
        widths: &[12, 0],
    },
    Descriptor {
        plugin: Plugin::WinPslist,
        name: "windows.pslist",
        label: "windows.pslist",
        columns: &[
            "PID",
            "PPID",
            "Name",
            "Address",
            "Threads",
            "Handles",
            "CreateTime",
            "ExitTime",
        ],
        widths: &[12, 12, 0, 12, 12, 12, 12, 12],
    },
    Descriptor {
        plugin: Plugin::WinPstree,
        name: "windows.pstree",
        label: "windows.pstree",
        columns: &[
            "PID",
            "PPID",
            "Name",
            "Address",
            "Threads",
            "Handles",
            "CreateTime",
            "ExitTime",
        ],
        widths: &[12, 12, 0, 12, 12, 12, 12, 12],
    },
    Descriptor {
        plugin: Plugin::WinCmdline,
        name: "windows.cmdline",
        label: "windows.cmdline",
        columns: &["PID", "Name", "CommandLine", "View"],
        widths: &[12, 0, 0, 10],
    },
    Descriptor {
        plugin: Plugin::WinModules,
        name: "windows.modules",
        label: "windows.modules",
        columns: &["Name", "Base", "Size", "Path"],
        widths: &[0, 12, 12, 0],
    },
    Descriptor {
        plugin: Plugin::WinDlllist,
        name: "windows.dlllist",
        label: "windows.dlllist",
        columns: &["PID", "Name", "Base", "Size", "Path", "View"],
        widths: &[12, 0, 12, 12, 0, 10],
    },
    Descriptor {
        plugin: Plugin::WinVadinfo,
        name: "windows.vadinfo",
        label: "windows.vadinfo",
        columns: &[
            "PID",
            "Name",
            "Start",
            "End",
            "Protection",
            "Private",
            "Path",
            "Address",
        ],
        widths: &[12, 0, 12, 12, 12, 12, 0, 12],
    },
    Descriptor {
        plugin: Plugin::WinHandles,
        name: "windows.handles",
        label: "windows.handles",
        columns: &[
            "PID",
            "Name",
            "Handle",
            "Type",
            "Object",
            "GrantedAccess",
            "ObjectName",
        ],
        widths: &[12, 0, 12, 12, 12, 12, 0],
    },
    Descriptor {
        plugin: Plugin::WinMalfind,
        name: "windows.malfind",
        label: "windows.malfind",
        columns: &[
            "PID",
            "Name",
            "Start",
            "End",
            "Protection",
            "Reason",
            "Preview",
        ],
        widths: &[12, 0, 12, 12, 12, 12, 12],
    },
    Descriptor {
        plugin: Plugin::WinNetscan,
        name: "windows.netscan",
        label: "windows.netscan",
        columns: &[
            "Address",
            "Protocol",
            "LocalEndpoint",
            "RemoteEndpoint",
            "State",
            "PID",
            "Name",
            "CreateTime",
        ],
        widths: &[12, 12, 12, 12, 12, 12, 0, 12],
    },
    Descriptor {
        plugin: Plugin::WinHivelist,
        name: "windows.hivelist",
        label: "windows.hivelist",
        columns: &["Address", "Path"],
        widths: &[12, 0],
    },
    Descriptor {
        plugin: Plugin::WinPrintkey,
        name: "windows.printkey",
        label: "windows.printkey",
        columns: &[
            "Hive",
            "Key",
            "Kind",
            "Name",
            "Type",
            "Data",
            "LastWriteTime",
        ],
        widths: &[12, 12, 12, 0, 12, 0, 12],
    },
    Descriptor {
        plugin: Plugin::WinPsscan,
        name: "windows.psscan",
        label: "windows.psscan",
        columns: &[
            "PID",
            "PPID",
            "Name",
            "Address",
            "Threads",
            "Handles",
            "CreateTime",
            "ExitTime",
        ],
        widths: &[12, 12, 0, 12, 12, 12, 12, 12],
    },
    Descriptor {
        plugin: Plugin::WinPsxview,
        name: "windows.psxview",
        label: "windows.psxview",
        columns: &["PID", "Name", "Address", "Pslist", "Psscan", "ExitTime"],
        widths: &[12, 0, 12, 12, 12, 12],
    },
    Descriptor {
        plugin: Plugin::WinProcdump,
        name: "windows.procdump",
        label: "windows.procdump",
        columns: &["PID", "Name", "Start", "End", "Size", "SHA256", "File"],
        widths: &[12, 0, 12, 12, 12, 12, 12],
    },
    Descriptor {
        plugin: Plugin::WinMemdump,
        name: "windows.memdump",
        label: "windows.memdump",
        columns: &["PID", "Name", "Start", "End", "Size", "SHA256", "File"],
        widths: &[12, 0, 12, 12, 12, 12, 12],
    },
    Descriptor {
        plugin: Plugin::WinPedump,
        name: "windows.pedump",
        label: "windows.pedump",
        columns: &["PID", "Name", "Start", "End", "Size", "SHA256", "File"],
        widths: &[12, 0, 12, 12, 12, 12, 12],
    },
    Descriptor {
        plugin: Plugin::WinVaddump,
        name: "windows.vaddump",
        label: "windows.vaddump",
        columns: &[
            "PID",
            "Name",
            "Start",
            "End",
            "Size",
            "Protection",
            "Private",
            "Path",
            "SHA256",
            "File",
        ],
        widths: &[12, 0, 12, 12, 10, 16, 8, 0, 12, 0],
    },
    Descriptor {
        plugin: Plugin::WinDlldump,
        name: "windows.dlldump",
        label: "windows.dlldump",
        columns: &[
            "PID", "Name", "Module", "Base", "Size", "View", "SHA256", "File",
        ],
        widths: &[12, 0, 0, 12, 10, 8, 12, 0],
    },
    Descriptor {
        plugin: Plugin::WinModdump,
        name: "windows.moddump",
        label: "windows.moddump",
        columns: &["Module", "Base", "Size", "Path", "SHA256", "File"],
        widths: &[0, 12, 10, 0, 12, 0],
    },
    Descriptor {
        plugin: Plugin::WinDumpfiles,
        name: "windows.dumpfiles",
        label: "windows.dumpfiles",
        columns: &[
            "PID",
            "Cache",
            "FileObject",
            "FileName",
            "Size",
            "Pages",
            "SHA256",
            "File",
        ],
        widths: &[12, 14, 12, 0, 10, 8, 12, 0],
    },
    Descriptor {
        plugin: Plugin::WinThrdscan,
        name: "windows.thrdscan",
        label: "windows.thrdscan",
        columns: &[
            "Physical",
            "Address",
            "PID",
            "TID",
            "StartAddress",
            "Win32StartAddress",
            "CreateTime",
            "ExitTime",
        ],
        widths: &[0, 0, 8, 8, 12, 12, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinHashdump,
        name: "windows.hashdump",
        label: "windows.hashdump",
        columns: &["User", "RID", "LM", "NT"],
        widths: &[0, 8, 34, 34],
    },
    Descriptor {
        plugin: Plugin::WinLsadump,
        name: "windows.lsadump",
        label: "windows.lsadump",
        columns: &["Name", "Text", "Hex", "Size"],
        widths: &[20, 0, 0, 8],
    },
    Descriptor {
        plugin: Plugin::WinCachedump,
        name: "windows.cachedump",
        label: "windows.cachedump",
        columns: &["User", "Domain", "DomainName", "Iterations", "DCC"],
        widths: &[0, 12, 16, 10, 0],
    },
    Descriptor {
        plugin: Plugin::WinSsdt,
        name: "windows.ssdt",
        label: "windows.ssdt",
        columns: &["Index", "Address", "Module", "Symbol", "Reason"],
        widths: &[6, 18, 16, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinModscan,
        name: "windows.modscan",
        label: "windows.modscan",
        columns: &["Physical", "Name", "Base", "Size", "Path", "InList"],
        widths: &[18, 16, 18, 10, 0, 6],
    },
    Descriptor {
        plugin: Plugin::WinPrivileges,
        name: "windows.privileges",
        label: "windows.privileges",
        columns: &["PID", "Name", "Value", "Privilege", "Attributes"],
        widths: &[8, 16, 6, 0, 24],
    },
    Descriptor {
        plugin: Plugin::WinSessions,
        name: "windows.sessions",
        label: "windows.sessions",
        columns: &["SessionID", "PID", "Name", "CreateTime", "SessionAddress"],
        widths: &[9, 8, 0, 20, 18],
    },
    Descriptor {
        plugin: Plugin::WinUserassist,
        name: "windows.registry.userassist",
        label: "windows.registry.userassist",
        columns: &[
            "Hive",
            "GUID",
            "Name",
            "Count",
            "FocusCount",
            "FocusTime",
            "LastUpdated",
        ],
        widths: &[0, 0, 0, 6, 10, 10, 20],
    },
    Descriptor {
        plugin: Plugin::WinBigpools,
        name: "windows.bigpools",
        label: "windows.bigpools",
        columns: &["Allocation", "Tag", "PoolType", "NumberOfBytes"],
        widths: &[18, 6, 10, 0],
    },
    Descriptor {
        plugin: Plugin::WinSymlinkscan,
        name: "windows.symlinkscan",
        label: "windows.symlinkscan",
        columns: &["Physical", "Address", "Name", "Target", "CreateTime"],
        widths: &[18, 18, 0, 0, 20],
    },
    Descriptor {
        plugin: Plugin::WinDevicetree,
        name: "windows.devicetree",
        label: "windows.devicetree",
        columns: &[
            "Driver",
            "DriverName",
            "Level",
            "Device",
            "DeviceName",
            "DeviceType",
        ],
        widths: &[18, 0, 6, 18, 0, 10],
    },
    Descriptor {
        plugin: Plugin::WinGetservicesids,
        name: "windows.getservicesids",
        label: "windows.getservicesids",
        columns: &["SID", "Service"],
        widths: &[0, 0],
    },
    Descriptor {
        plugin: Plugin::WinIat,
        name: "windows.iat",
        label: "windows.iat",
        columns: &["PID", "Name", "Library", "Function", "Bound"],
        widths: &[8, 16, 16, 0, 18],
    },
    Descriptor {
        plugin: Plugin::WinVerinfo,
        name: "windows.verinfo",
        label: "windows.verinfo",
        columns: &[
            "PID",
            "Name",
            "Base",
            "Path",
            "FileVersion",
            "ProductVersion",
        ],
        widths: &[8, 16, 18, 0, 16, 16],
    },
    Descriptor {
        plugin: Plugin::WinMftscan,
        name: "windows.mftscan",
        label: "windows.mftscan",
        columns: &[
            "Physical",
            "Record",
            "Type",
            "InUse",
            "Name",
            "Parent",
            "SICreated",
            "SIModified",
            "FNCreated",
            "FNModified",
            "Size",
        ],
        widths: &[18, 8, 9, 5, 0, 8, 18, 18, 18, 18, 10],
    },
    Descriptor {
        plugin: Plugin::WinOrphanThreads,
        name: "windows.orphan_kernel_threads",
        label: "windows.orphan_kernel_threads",
        columns: &["PID", "TID", "Address", "StartAddress", "CreateTime"],
        widths: &[6, 8, 18, 18, 20],
    },
    Descriptor {
        plugin: Plugin::WinEtwpatch,
        name: "windows.etwpatch",
        label: "windows.etwpatch",
        columns: &[
            "PID", "Name", "Module", "Function", "Address", "Bytes", "Reason",
        ],
        widths: &[8, 16, 0, 14, 18, 24, 0],
    },
    Descriptor {
        plugin: Plugin::WinScheduledTasks,
        name: "windows.registry.scheduled_tasks",
        label: "windows.registry.scheduled_tasks",
        columns: &[
            "Path",
            "TaskId",
            "Command",
            "Arguments",
            "WorkingDirectory",
            "Created",
            "LastRun",
        ],
        widths: &[0, 0, 0, 0, 0, 20, 20],
    },
    Descriptor {
        plugin: Plugin::WinAmcache,
        name: "windows.registry.amcache",
        label: "windows.registry.amcache",
        columns: &[
            "Path",
            "SHA1",
            "Publisher",
            "Version",
            "LinkDate",
            "LastWriteTime",
        ],
        widths: &[0, 40, 0, 16, 20, 20],
    },
    Descriptor {
        plugin: Plugin::WinCertificates,
        name: "windows.registry.certificates",
        label: "windows.registry.certificates",
        columns: &[
            "Hive",
            "Store",
            "Thumbprint",
            "FriendlyName",
            "Subject",
            "Issuer",
            "NotBefore",
            "NotAfter",
        ],
        widths: &[0, 10, 40, 0, 0, 0, 15, 15],
    },
    Descriptor {
        plugin: Plugin::WinProcessghosting,
        name: "windows.processghosting",
        label: "windows.processghosting",
        columns: &[
            "PID",
            "Name",
            "FileObject",
            "DeletePending",
            "DataSection",
            "ImageSection",
            "Path",
            "Reason",
        ],
        widths: &[8, 16, 18, 8, 18, 18, 0, 0],
    },
    Descriptor {
        plugin: Plugin::WinJoblinks,
        name: "windows.joblinks",
        label: "windows.joblinks",
        columns: &["Job", "SessionID", "Active", "Total", "PID", "Name"],
        widths: &[18, 9, 6, 6, 8, 0],
    },
    Descriptor {
        plugin: Plugin::WinTimeliner,
        name: "windows.timeliner",
        label: "windows.timeliner",
        columns: &["Time", "FILETIME", "Plugin", "Event", "Description"],
        widths: &[23, 18, 24, 24, 0],
    },
    Descriptor {
        plugin: Plugin::WinMbrscan,
        name: "windows.mbrscan",
        label: "windows.mbrscan",
        columns: &[
            "Physical",
            "DiskSignature",
            "Partition",
            "Bootable",
            "Type",
            "StartLBA",
            "Sectors",
            "BootCodeSHA256",
        ],
        widths: &[18, 10, 4, 6, 6, 12, 12, 0],
    },
    Descriptor {
        plugin: Plugin::WinTimers,
        name: "windows.timers",
        label: "windows.timers",
        columns: &[
            "CPU", "Timer", "DueTime", "Period", "DPC", "Routine", "Module",
        ],
        widths: &[4, 18, 20, 8, 18, 18, 0],
    },
    Descriptor {
        plugin: Plugin::WinStatistics,
        name: "windows.statistics",
        label: "windows.statistics",
        columns: &["Key", "Value"],
        widths: &[30, 0],
    },
    Descriptor {
        plugin: Plugin::WinShimcache,
        name: "windows.registry.shimcache",
        label: "windows.registry.shimcache",
        columns: &["Order", "Path", "LastModified"],
        widths: &[6, 0, 20],
    },
    Descriptor {
        plugin: Plugin::WinVirtmap,
        name: "windows.virtmap",
        label: "windows.virtmap",
        columns: &["Region", "Start", "End", "Size"],
        widths: &[0, 18, 18, 16],
    },
    Descriptor {
        plugin: Plugin::WinVadyarascan,
        name: "windows.vadyarascan",
        label: "windows.vadyarascan",
        columns: &[
            "PID",
            "Name",
            "Address",
            "Start",
            "Protection",
            "Path",
            "Context",
        ],
        widths: &[8, 16, 18, 18, 0, 0, 0],
    },
    Descriptor {
        plugin: Plugin::Vmayarascan,
        name: "vmayarascan",
        label: "vmayarascan",
        columns: &[
            "PID",
            "Name",
            "Address",
            "Start",
            "Permissions",
            "Path",
            "Context",
        ],
        widths: &[6, 14, 18, 18, 5, 0, 0],
    },
    Descriptor {
        plugin: Plugin::Pslist,
        name: "pslist",
        label: "pslist",
        columns: &["PID", "TGID", "PPID", "Name", "Address"],
        widths: &[5, 5, 5, 0, 18],
    },
    Descriptor {
        plugin: Plugin::Pstree,
        name: "pstree",
        label: "pstree",
        columns: &["PID", "TGID", "PPID", "Name", "Address"],
        widths: &[5, 5, 5, 0, 18],
    },
    Descriptor {
        plugin: Plugin::Lsmod,
        name: "lsmod",
        label: "lsmod",
        columns: &["Name", "Base", "Size"],
        widths: &[0, 18, 10],
    },
    Descriptor {
        plugin: Plugin::Psaux,
        name: "psaux",
        label: "psaux",
        columns: &["PID", "Name", "CommandLine", "Status"],
        widths: &[5, 12, 0, 12],
    },
    Descriptor {
        plugin: Plugin::Envars,
        name: "envars",
        label: "envars",
        columns: &["PID", "Name", "Key", "Value"],
        widths: &[5, 12, 16, 0],
    },
    Descriptor {
        plugin: Plugin::Maps,
        name: "maps",
        label: "maps",
        columns: &[
            "PID",
            "Name",
            "Start",
            "End",
            "Permissions",
            "FileOffset",
            "Path",
        ],
        widths: &[5, 12, 18, 18, 4, 10, 0],
    },
    Descriptor {
        plugin: Plugin::Lsof,
        name: "lsof",
        label: "lsof",
        columns: &["PID", "Name", "FD", "Type", "Inode", "Path", "FileAddress"],
        widths: &[5, 12, 4, 8, 10, 0, 18],
    },
    Descriptor {
        plugin: Plugin::Sockstat,
        name: "sockstat",
        label: "sockstat",
        columns: &[
            "PID",
            "Name",
            "FD",
            "Family",
            "Type",
            "Protocol",
            "LocalEndpoint",
            "RemoteEndpoint",
            "State",
            "SocketAddress",
        ],
        widths: &[5, 12, 4, 6, 8, 8, 0, 0, 12, 18],
    },
    Descriptor {
        plugin: Plugin::Netscan,
        name: "netscan",
        label: "netscan",
        columns: &[
            "PID",
            "Name",
            "Protocol",
            "LocalEndpoint",
            "RemoteEndpoint",
            "State",
            "SocketAddress",
        ],
        widths: &[5, 12, 6, 0, 0, 12, 18],
    },
    Descriptor {
        plugin: Plugin::Banners,
        name: "banners",
        label: "banners",
        columns: &["Offset", "Banner"],
        widths: &[18, 0],
    },
    Descriptor {
        plugin: Plugin::Pwd,
        name: "pwd",
        label: "pwd",
        columns: &["PID", "Name", "Root", "CWD"],
        widths: &[5, 12, 0, 0],
    },
    Descriptor {
        plugin: Plugin::Pscred,
        name: "pscred",
        label: "pscred",
        columns: &[
            "PID",
            "Name",
            "UID",
            "GID",
            "EUID",
            "EGID",
            "SUID",
            "SGID",
            "FSUID",
            "FSGID",
            "CredAddress",
        ],
        widths: &[5, 12, 6, 6, 6, 6, 6, 6, 6, 6, 18],
    },
    Descriptor {
        plugin: Plugin::Threads,
        name: "threads",
        label: "threads",
        columns: &["PID", "Name", "TID", "ThreadName", "Address"],
        widths: &[5, 12, 6, 0, 18],
    },
    Descriptor {
        plugin: Plugin::Mountinfo,
        name: "mountinfo",
        label: "mountinfo",
        columns: &[
            "PID",
            "Name",
            "MountID",
            "ParentID",
            "Device",
            "MountPoint",
            "FileSystem",
            "Flags",
            "Address",
        ],
        widths: &[5, 12, 6, 6, 0, 0, 8, 10, 18],
    },
    Descriptor {
        plugin: Plugin::CheckCreds,
        name: "check_creds",
        label: "check_creds",
        columns: &["CredAddress", "PIDs", "Names", "UID", "EUID"],
        widths: &[18, 0, 0, 6, 6],
    },
    Descriptor {
        plugin: Plugin::Dmesg,
        name: "dmesg",
        label: "dmesg",
        columns: &["Index", "Message"],
        widths: &[8, 0],
    },
    Descriptor {
        plugin: Plugin::Systeminfo,
        name: "systeminfo",
        label: "systeminfo",
        columns: &["Key", "Value"],
        widths: &[22, 0],
    },
    Descriptor {
        plugin: Plugin::Elfs,
        name: "elfs",
        label: "elfs",
        columns: &["PID", "Name", "Start", "End", "Type", "Entry", "Path"],
        widths: &[6, 14, 18, 18, 6, 18, 0],
    },
    Descriptor {
        plugin: Plugin::Bash,
        name: "bash",
        label: "bash",
        columns: &["PID", "Name", "Timestamp", "Command", "Address"],
        widths: &[6, 14, 12, 0, 18],
    },
    Descriptor {
        plugin: Plugin::Malfind,
        name: "malfind",
        label: "malfind",
        columns: &[
            "PID",
            "Name",
            "Start",
            "End",
            "Permissions",
            "Path",
            "Reason",
            "Preview",
        ],
        widths: &[6, 14, 18, 18, 6, 0, 24, 32],
    },
    Descriptor {
        plugin: Plugin::Psxview,
        name: "psxview",
        label: "psxview",
        columns: &[
            "PID",
            "Name",
            "Address",
            "Tasks",
            "PIDIndex",
            "ThreadGroup",
            "Reason",
        ],
        widths: &[6, 14, 18, 6, 8, 12, 0],
    },
    Descriptor {
        plugin: Plugin::CheckModules,
        name: "check_modules",
        label: "check_modules",
        columns: &[
            "Name",
            "Address",
            "Start",
            "End",
            "ModuleList",
            "Sysfs",
            "Reason",
        ],
        widths: &[18, 18, 18, 18, 10, 6, 0],
    },
    Descriptor {
        plugin: Plugin::CheckSyscall,
        name: "check_syscall",
        label: "check_syscall",
        columns: &["Table", "Index", "Target", "Symbol", "Owner", "Reason"],
        widths: &[18, 6, 18, 24, 18, 0],
    },
    Descriptor {
        plugin: Plugin::CheckIdt,
        name: "check_idt",
        label: "check_idt",
        columns: &["Index", "Address", "Symbol", "Owner", "Present", "Reason"],
        widths: &[6, 18, 24, 18, 8, 0],
    },
    Descriptor {
        plugin: Plugin::TtyCheck,
        name: "tty_check",
        label: "tty_check",
        columns: &["Name", "Address", "Symbol", "Owner", "Reason"],
        widths: &[12, 18, 24, 18, 0],
    },
    Descriptor {
        plugin: Plugin::HiddenModules,
        name: "hidden_modules",
        label: "hidden_modules",
        columns: &["Name", "Address", "Start", "End", "State", "Reason"],
        widths: &[18, 18, 18, 18, 9, 0],
    },
    Descriptor {
        plugin: Plugin::LibraryList,
        name: "library_list",
        label: "library_list",
        columns: &["PID", "Name", "LoadAddress", "Path"],
        widths: &[6, 14, 18, 0],
    },
    Descriptor {
        plugin: Plugin::Pidhashtable,
        name: "pidhashtable",
        label: "pidhashtable",
        columns: &["Address", "PID", "TGID", "PPID", "Name"],
        widths: &[18, 6, 6, 6, 0],
    },
    Descriptor {
        plugin: Plugin::Vmcoreinfo,
        name: "vmcoreinfo",
        label: "vmcoreinfo",
        columns: &["Key", "Value"],
        widths: &[32, 0],
    },
    Descriptor {
        plugin: Plugin::IpAddr,
        name: "ip_addr",
        label: "ip_addr",
        columns: &[
            "Namespace",
            "Interface",
            "MAC",
            "Promiscuous",
            "Address",
            "Prefix",
            "Scope",
            "State",
        ],
        widths: &[18, 12, 17, 6, 0, 6, 8, 10],
    },
    Descriptor {
        plugin: Plugin::IpLink,
        name: "ip_link",
        label: "ip_link",
        columns: &["Namespace", "Interface", "MAC", "State", "MTU", "Flags"],
        widths: &[18, 12, 17, 10, 6, 0],
    },
    Descriptor {
        plugin: Plugin::CheckAfinfo,
        name: "check_afinfo",
        label: "check_afinfo",
        columns: &[
            "Structure",
            "Member",
            "Address",
            "Symbol",
            "Owner",
            "Reason",
        ],
        widths: &[20, 18, 18, 0, 16, 0],
    },
    Descriptor {
        plugin: Plugin::Kthreads,
        name: "kthreads",
        label: "kthreads",
        columns: &["PID", "Name", "ThreadFunction", "Symbol", "Owner", "Reason"],
        widths: &[6, 16, 18, 0, 16, 0],
    },
    Descriptor {
        plugin: Plugin::Netfilter,
        name: "netfilter",
        label: "netfilter",
        columns: &[
            "Namespace",
            "Protocol",
            "Hook",
            "Priority",
            "Handler",
            "Symbol",
            "Owner",
            "Reason",
        ],
        widths: &[18, 8, 12, 8, 18, 0, 16, 0],
    },
    Descriptor {
        plugin: Plugin::Tracepoints,
        name: "tracepoints",
        label: "tracepoints",
        columns: &["Tracepoint", "Handler", "Symbol", "Owner", "Reason"],
        widths: &[0, 18, 0, 16, 0],
    },
    Descriptor {
        plugin: Plugin::Ftrace,
        name: "ftrace",
        label: "ftrace",
        columns: &["Ops", "Handler", "Symbol", "Owner", "Reason"],
        widths: &[18, 18, 0, 16, 0],
    },
    Descriptor {
        plugin: Plugin::PerfEvents,
        name: "perf_events",
        label: "perf_events",
        columns: &[
            "PID", "Name", "Event", "Type", "Config", "Handler", "Symbol", "Owner", "Reason",
        ],
        widths: &[6, 14, 18, 6, 10, 18, 0, 16, 0],
    },
    Descriptor {
        plugin: Plugin::Ebpf,
        name: "ebpf",
        label: "ebpf",
        columns: &["ID", "Name", "Type", "Address", "Function"],
        widths: &[6, 16, 0, 18, 18],
    },
    Descriptor {
        plugin: Plugin::Boottime,
        name: "boottime",
        label: "boottime",
        columns: &["Key", "Value"],
        widths: &[16, 0],
    },
    Descriptor {
        plugin: Plugin::Pagecache,
        name: "pagecache",
        label: "pagecache",
        columns: &[
            "SuperBlock",
            "Device",
            "FileSystem",
            "Inode",
            "InodeAddress",
            "Mode",
            "Size",
            "CachedPages",
            "Path",
        ],
        widths: &[18, 10, 10, 10, 18, 8, 12, 8, 0],
    },
    Descriptor {
        plugin: Plugin::Psstate,
        name: "psstate",
        label: "psstate",
        columns: &["PID", "Name", "State", "ExitState", "Flags"],
        widths: &[6, 16, 18, 18, 18],
    },
    Descriptor {
        plugin: Plugin::Capabilities,
        name: "capabilities",
        label: "capabilities",
        columns: &[
            "PID",
            "Name",
            "Inheritable",
            "Permitted",
            "Effective",
            "Bounding",
            "CredAddress",
        ],
        widths: &[6, 16, 18, 18, 18, 18, 18],
    },
    Descriptor {
        plugin: Plugin::Fdsummary,
        name: "fdsummary",
        label: "fdsummary",
        columns: &["PID", "Name", "Total", "Regular", "Sockets", "Pipes"],
        widths: &[6, 16, 8, 8, 8, 8],
    },
    Descriptor {
        plugin: Plugin::Iomem,
        name: "iomem",
        label: "iomem",
        columns: &["Name", "Start", "End", "Depth", "Flags", "Address"],
        widths: &[0, 18, 18, 5, 18, 18],
    },
    Descriptor {
        plugin: Plugin::Ioports,
        name: "ioports",
        label: "ioports",
        columns: &["Name", "Start", "End", "Depth", "Flags", "Address"],
        widths: &[0, 18, 18, 5, 18, 18],
    },
    Descriptor {
        plugin: Plugin::Ptrace,
        name: "ptrace",
        label: "ptrace",
        columns: &["Process", "PID", "TID", "TracerTID", "TraceeTID", "Flags"],
        widths: &[0, 6, 6, 10, 10, 18],
    },
    Descriptor {
        plugin: Plugin::KeyboardNotifiers,
        name: "keyboard_notifiers",
        label: "keyboard_notifiers",
        columns: &["Address", "Module", "Symbol", "Priority", "NotifierAddress"],
        widths: &[18, 16, 0, 9, 18],
    },
    Descriptor {
        plugin: Plugin::Procdump,
        name: "procdump",
        label: "procdump",
        columns: &["PID", "Name", "Start", "End", "Size", "SHA256", "File"],
        widths: &[6, 12, 18, 18, 12, 0, 0],
    },
    Descriptor {
        plugin: Plugin::Memdump,
        name: "memdump",
        label: "memdump",
        columns: &["PID", "Name", "Start", "End", "Size", "SHA256", "File"],
        widths: &[6, 12, 18, 18, 12, 0, 0],
    },
    Descriptor {
        plugin: Plugin::Elfdump,
        name: "elfdump",
        label: "elfdump",
        columns: &["PID", "Name", "Start", "End", "Size", "SHA256", "File"],
        widths: &[6, 12, 18, 18, 12, 0, 0],
    },
    Descriptor {
        plugin: Plugin::LinuxPslist,
        name: "linux.pslist.PsList",
        label: "pslist·完整",
        columns: &[
            "PID",
            "TGID",
            "PPID",
            "Name",
            "Address",
            "UID",
            "GID",
            "EUID",
            "EGID",
            "CreationTime",
            "FileOutput",
        ],
        widths: &[5, 5, 5, 16, 18, 6, 6, 6, 6, 32, 12],
    },
    Descriptor {
        plugin: Plugin::ProcessSpoofing,
        name: "linux.malware.process_spoofing.ProcessSpoofing",
        label: "process_spoofing",
        columns: &[
            "PID",
            "PPID",
            "Exe_Path",
            "Cmdline_Basename",
            "Comm",
            "Cmdline_Spoofed",
            "Comm_Spoofed",
            "Exe_Deleted",
        ],
        widths: &[6, 6, 0, 20, 16, 16, 16, 12],
    },
    Descriptor {
        plugin: Plugin::Modxview,
        name: "linux.malware.modxview.Modxview",
        label: "modxview",
        columns: &[
            "Name",
            "Address",
            "In procfs",
            "In sysfs",
            "In scan",
            "Taints",
        ],
        widths: &[20, 18, 10, 10, 10, 0],
    },
    Descriptor {
        plugin: Plugin::ModuleExtract,
        name: "linux.module_extract.ModuleExtract",
        label: "module_extract",
        columns: &["Base", "File Size", "File output"],
        widths: &[18, 12, 0],
    },
    Descriptor {
        plugin: Plugin::Kallsyms,
        name: "linux.kallsyms.Kallsyms",
        label: "kallsyms",
        columns: &[
            "Addr",
            "Type",
            "Size",
            "Exported",
            "SubSystem",
            "ModuleName",
            "SymbolName",
            "Description",
        ],
        widths: &[18, 5, 12, 10, 8, 20, 0, 0],
    },
];
impl Plugin {
    pub fn descriptor(self) -> &'static Descriptor {
        PLUGINS.iter().find(|d| d.plugin == self).unwrap()
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
        match self {
            Self::WinSysteminfo => "System",
            Self::WinLdrmodules
            | Self::WinHollowprocesses
            | Self::WinSuspiciousThreads
            | Self::CheckExec => "Integrity",
            Self::WinCallbacks => "Integrity",
            Self::WinUnloadedmodules => "System",
            Self::WinFilescan => "Files",
            Self::WinMutantscan => "System",
            Self::WinGetsids => "Process",
            Self::WinConnscan => "Network",
            Self::WinSockscan => "Network",

            Self::WinConsoles => "Process",
            Self::WinCmdscan => "Process",
            Self::WinDrivercheck => "Integrity",
            Self::WinDriverscan => "System",
            Self::WinSvcscan => "System",
            Self::WinCrashinfo => "System",
            Self::WinAutoruns => "Integrity",
            Self::WinEnvars => "Process",
            Self::WinThreads => "Process",
            Self::WinPslist => "Process",
            Self::WinPstree => "Process",
            Self::WinCmdline => "Process",
            Self::WinModules => "System",
            Self::WinDlllist => "Process",
            Self::WinVadinfo => "Memory",
            Self::WinHandles => "Files",
            Self::WinMalfind => "Integrity",
            Self::WinNetscan => "Network",
            Self::WinHivelist => "Files",
            Self::WinPrintkey => "Files",
            Self::WinPsscan => "Integrity",
            Self::WinPsxview => "Integrity",
            Self::WinProcdump => "Process",
            Self::WinMemdump => "Memory",
            Self::WinPedump => "Memory",
            Self::WinVaddump => "Memory",
            Self::WinThrdscan => "Integrity",
            Self::WinDlldump => "Memory",
            Self::WinModdump => "Memory",
            Self::WinDumpfiles => "Files",
            Self::WinHashdump => "Files",
            Self::WinLsadump => "Files",
            Self::WinCachedump => "Files",
            Self::WinSsdt | Self::WinModscan => "Integrity",
            Self::WinPrivileges | Self::WinSessions => "Process",
            Self::WinUserassist => "Files",
            Self::WinBigpools => "Memory",
            Self::WinSymlinkscan => "Files",
            Self::WinDevicetree => "System",
            Self::WinGetservicesids => "System",
            Self::WinIat | Self::WinVerinfo => "Process",
            Self::WinMftscan => "Files",
            Self::WinOrphanThreads | Self::WinEtwpatch => "Integrity",
            Self::WinScheduledTasks | Self::WinAmcache | Self::WinCertificates => "Files",
            Self::WinProcessghosting => "Integrity",
            Self::WinJoblinks => "Process",
            Self::WinTimeliner => "System",
            Self::WinMbrscan => "Files",
            Self::WinTimers => "Integrity",
            Self::WinStatistics => "Memory",
            Self::WinShimcache => "Files",
            Self::WinVirtmap => "Memory",
            Self::WinVadyarascan | Self::Vmayarascan => "Memory",
            Self::Kallsyms
            | Self::Banners
            | Self::Systeminfo
            | Self::Dmesg
            | Self::Lsmod
            | Self::Iomem
            | Self::Ioports
            | Self::Vmcoreinfo => "System",
            Self::Ptrace
            | Self::Psstate
            | Self::Capabilities
            | Self::Pslist
            | Self::LinuxPslist
            | Self::Pstree
            | Self::Psaux
            | Self::Pscred
            | Self::Threads
            | Self::Envars
            | Self::Pwd
            | Self::Pidhashtable
            | Self::Procdump => "Process",
            Self::Maps
            | Self::Elfs
            | Self::LibraryList
            | Self::Bash
            | Self::Memdump
            | Self::Elfdump => "Memory",
            Self::Fdsummary | Self::Lsof | Self::Mountinfo => "Files",
            Self::Sockstat | Self::Netscan | Self::IpAddr | Self::IpLink => "Network",
            Self::ModuleExtract
            | Self::Modxview
            | Self::ProcessSpoofing
            | Self::KeyboardNotifiers
            | Self::CheckCreds
            | Self::Malfind
            | Self::Psxview
            | Self::CheckModules
            | Self::CheckSyscall
            | Self::CheckIdt
            | Self::TtyCheck
            | Self::HiddenModules
            | Self::CheckAfinfo
            | Self::Kthreads
            | Self::Netfilter
            | Self::Tracepoints
            | Self::Ftrace
            | Self::PerfEvents
            | Self::Ebpf => "Integrity",
            Self::Boottime => "System",
            Self::Pagecache => "Files",
        }
    }
    pub fn name(self) -> &'static str {
        self.descriptor().name
    }
    /// One-line Chinese description used by the interface search and help.
    pub fn description(self) -> &'static str {
        use Plugin::*;
        match self {
            WinLdrmodules => "对照 PE 映射与三条 PEB 模块链表",
            WinHollowprocesses => "检查主程序基址及映像映射异常",
            WinSuspiciousThreads => "检查活动线程起点所在的 VAD",
            Kallsyms => "枚举核心、模块、ftrace 与 BPF 的运行时符号",
            ModuleExtract => "从指定 struct module 地址重建并导出模块 ELF",
            Modxview => "对照模块链表、sysfs 与独立内存扫描，并解析 taint 标记",
            ProcessSpoofing => "比较可执行路径、argv[0] 与进程名称，识别身份伪装线索",
            CheckExec => "检查 Linux 主程序代码映射与可执行文件",
            Pslist | LinuxPslist | WinPslist => "列出活动进程及其地址",
            Pstree | WinPstree => "按父进程关系浏览进程树",
            Psaux | WinCmdline => "读取进程命令行",
            Envars | WinEnvars => "读取进程环境变量",
            Lsmod | WinModules => "列出内核模块及地址范围",
            Maps | WinVadinfo => "查看进程虚拟内存映射",
            Lsof | WinHandles => "列出进程打开的文件或对象",
            Sockstat | Netscan | WinNetscan => "查看网络连接及端点",
            Banners => "识别完整内核身份，无需符号",
            Pwd => "读取进程工作目录",
            Pscred => "查看进程身份和凭据",
            Threads | WinThreads => "列出进程线程",
            Mountinfo => "查看文件系统挂载关系",
            CheckCreds => "检查进程凭据异常",
            Dmesg => "读取内核日志缓冲区",
            Systeminfo | WinSysteminfo => "查看系统和内核信息",
            Elfs => "识别进程中的 ELF 映射",
            Bash => "恢复内存中的 Bash 历史记录",
            Malfind | WinMalfind => "检查可疑的可执行内存映射",
            Psxview | WinPsxview => "对比多种进程发现方式",
            CheckModules | WinDrivercheck => "检查模块或驱动异常",
            CheckSyscall => "检查系统调用表",
            CheckIdt => "检查中断描述符表处理函数归属（x86_64）",
            TtyCheck => "检查 TTY 行规程 receive_buf 是否被挂钩",
            HiddenModules => "从模块内存雕刻不在模块链表中的隐藏模块",
            LibraryList => "列出进程映射的共享库",
            Pidhashtable => "从 PID 索引列出任务，独立于 tasks 链表",
            Vmcoreinfo => "读取内核为崩溃转储准备的 vmcoreinfo",
            IpAddr => "列出各网络命名空间中网卡的 IPv4／IPv6 地址",
            IpLink => "列出各网络命名空间中的网卡及状态",
            CheckAfinfo => "检查网络协议 /proc 处理函数是否被挂钩",
            Kthreads => "列出内核线程及其线程函数归属",
            Netfilter => "列出 netfilter 钩子及处理函数归属",
            Tracepoints => "列出挂在内核 tracepoint 上的探针",
            Ftrace => "列出已注册的 ftrace 回调",
            Ebpf => "列出已加载的 eBPF 程序",
            PerfEvents => "列出进程持有的 perf 事件及溢出处理函数",
            Boottime => "根据时间保持偏移计算系统启动时间",
            Pagecache => "列出页缓存中各文件系统的 inode 及缓存页数",
            Iomem => "查看物理内存资源范围",
            Ioports => "查看 I/O 端口资源",
            Ptrace => "检查进程跟踪关系",
            KeyboardNotifiers => "查看键盘通知回调",
            Psstate => "查看进程状态",
            Capabilities => "查看进程能力集合",
            Fdsummary => "汇总进程文件描述符",
            WinCallbacks => "查看内核回调及模块归属",
            WinUnloadedmodules => "读取已卸载驱动记录",
            WinFilescan => "扫描文件对象",
            WinMutantscan => "扫描互斥对象",
            WinGetsids => "读取进程令牌 SID",
            WinConnscan => "扫描旧版 Windows 连接对象",
            WinSockscan => "扫描旧版 Windows 套接字对象",
            WinConsoles => "恢复控制台保存的记录",
            WinCmdscan => "扫描命令历史记录",
            WinDriverscan => "扫描驱动对象",
            WinSvcscan => "扫描 Windows 服务",
            WinCrashinfo => "读取转储容器故障信息，无需完整内核符号",
            WinAutoruns => "查看注册表自启动配置",
            WinDlllist => "列出进程加载的 DLL",
            WinHivelist => "列出注册表 hive 地址",
            WinPrintkey => "读取指定 hive 中的注册表键",
            WinPsscan => "扫描进程对象",
            Procdump | WinProcdump => "转储指定进程的可读内存",
            Memdump | WinMemdump => "转储指定进程的地址范围",
            Elfdump => "导出进程中含 ELF 头的映射",
            WinPedump => "按 PE 节表重建可读文件",
            WinVaddump => "按 VAD 逐段转储进程内存并保留 VAD 元数据",
            WinDlldump => "按基址选择并重建导出进程 DLL 的 PE 文件",
            WinModdump => "重建并导出内核模块的 PE 文件",
            WinDumpfiles => "从文件缓存（句柄与 VAD）提取驻留文件内容",
            WinThrdscan => "扫描线程对象（含已退出或脱离链表的线程）",
            WinHashdump => "解密 SAM hive 中的用户 NTLM/LM 哈希",
            WinLsadump => "解密 SECURITY hive 中的 LSA 机密",
            WinCachedump => "解密 SECURITY hive 中的域缓存凭据（DCC）",
            WinSsdt => "检查系统服务表项的模块与符号归属",
            WinModscan => "扫描 MmLd 池中的内核模块条目并对照模块链表",
            WinPrivileges => "列出进程令牌拥有的特权及启用状态",
            WinSessions => "按登录会话归类进程",
            WinUserassist => "解码 NTUSER 中的 UserAssist 程序执行记录",
            WinBigpools => "列出大页池分配表中的已分配块及池标签",
            WinSymlinkscan => "扫描符号链接对象及其目标",
            WinDevicetree => "按驱动列出设备对象及附加设备链",
            WinGetservicesids => "按当前 ControlSet 服务名计算服务 SID",
            WinIat => "列出进程主映像的导入表及绑定地址",
            WinVerinfo => "读取进程 DLL 与内核模块的版本资源",
            WinMftscan => "从物理内存雕刻 NTFS MFT 记录及两组时间戳",
            WinOrphanThreads => "列出起始地址不在任何内核模块中的系统线程",
            WinEtwpatch => "检查各进程 ntdll ETW 入口是否被打补丁",
            WinScheduledTasks => "解码注册表 TaskCache 中的计划任务及命令",
            WinAmcache => "读取 Amcache.hve 的程序文件清单",
            WinCertificates => "列出注册表证书存储中的证书",
            WinProcessghosting => "检查进程映像文件是否删除挂起或未关联节对象",
            WinJoblinks => "列出进程所属的作业对象及计数",
            WinTimeliner => "汇总多个插件的时间戳为统一时间线",
            WinMbrscan => "扫描内存中的主引导记录及分区表",
            WinTimers => "列出各处理器的内核定时器及 DPC 例程归属",
            WinStatistics => "统计内核地址空间的有效、换出与空页表项",
            WinShimcache => "解码 SYSTEM hive 中的 AppCompatCache 执行痕迹",
            WinVirtmap => "列出内核虚拟地址空间按用途划分的区域",
            WinVadyarascan => "在进程 VAD 中搜索指定的文本或十六进制字节模式",
            Vmayarascan => "在进程 VMA 中搜索指定的文本或十六进制字节模式",
        }
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
