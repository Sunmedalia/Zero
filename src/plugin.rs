//! Plugin identities, display metadata and categories shared by every platform.
use clap::ValueEnum;

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Plugin {
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
    Iomem,
    Ioports,
    Ptrace,
    #[value(name = "keyboard_notifiers", alias = "keyboard-notifiers")]
    KeyboardNotifiers,
    Psstate,
    Capabilities,
    Fdsummary,
    History,
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
    Bash,
    Malfind,
    Psxview,
    #[value(name = "check_modules", alias = "check-modules")]
    CheckModules,
    #[value(name = "check_syscall", alias = "check-syscall")]
    CheckSyscall,
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
        plugin: Plugin::History,
        name: "history",
        label: "history",
        columns: &["PID", "Shell", "Timestamp", "Command", "Address"],
        widths: &[6, 12, 14, 0, 18],
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
];
impl Plugin {
    pub fn descriptor(self) -> &'static Descriptor {
        PLUGINS.iter().find(|d| d.plugin == self).unwrap()
    }
    pub fn is_dump(self) -> bool {
        matches!(
            self,
            Self::Procdump
                | Self::Memdump
                | Self::Elfdump
                | Self::WinProcdump
                | Self::WinMemdump
                | Self::WinPedump
        )
    }
    pub fn is_windows(self) -> bool {
        self.name().starts_with("windows.")
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
            Self::Banners
            | Self::Systeminfo
            | Self::Dmesg
            | Self::Lsmod
            | Self::Iomem
            | Self::Ioports => "System",
            Self::Ptrace
            | Self::Psstate
            | Self::Capabilities
            | Self::Pslist
            | Self::Pstree
            | Self::Psaux
            | Self::Pscred
            | Self::Threads
            | Self::Envars
            | Self::Pwd
            | Self::History
            | Self::Procdump => "Process",
            Self::Maps | Self::Elfs | Self::Bash | Self::Memdump | Self::Elfdump => "Memory",
            Self::Fdsummary | Self::Lsof | Self::Mountinfo => "Files",
            Self::Sockstat => "Network",
            Self::KeyboardNotifiers
            | Self::CheckCreds
            | Self::Malfind
            | Self::Psxview
            | Self::CheckModules
            | Self::CheckSyscall => "Integrity",
        }
    }
    pub fn name(self) -> &'static str {
        self.descriptor().name
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
}
