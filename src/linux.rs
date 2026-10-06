use crate::{
    Job,
    image::{Image, VirtualMemory},
    store::{self, Results},
    symbols::{self, Isf},
};
use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use std::{collections::HashSet, path::Path};

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Plugin {
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
            _ => "Integrity",
        }
    }
    pub fn name(self) -> &'static str {
        self.descriptor().name
    }
}
pub enum Outcome {
    Ready(Results),
    Choose(Vec<String>),
}
pub fn analyze(
    image_path: &Path,
    symbols_path: &Path,
    choice: Option<&str>,
    plugin: Plugin,
    cache: &Path,
    use_cache: bool,
    job: &Job,
) -> Result<Outcome> {
    Session::default().analyze(
        &Request {
            image: image_path,
            symbols: symbols_path,
            choice,
            plugin,
            cache,
            use_cache,
            network: false,
        },
        job,
    )
}
pub struct Request<'a> {
    pub image: &'a Path,
    pub symbols: &'a Path,
    pub choice: Option<&'a str>,
    pub plugin: Plugin,
    pub cache: &'a Path,
    pub use_cache: bool,
    pub network: bool,
}
#[derive(Default)]
pub struct Session {
    image: Option<std::sync::Arc<Image>>,
    image_stamp: String,
    physical_stamp: String,
    symbol_stamp: String,
    symbols: Vec<std::sync::Arc<Isf>>,
    roots: std::collections::HashMap<String, u64>,
}
fn source_stamp(path: &Path, job: &Job) -> Result<String> {
    fn visit(path: &Path, out: &mut Vec<String>, depth: usize, job: &Job) -> Result<()> {
        job.check()?;
        ensure!(depth < 128, "符号目录超过 128 层");
        if !path.exists() {
            out.push(format!("{}:missing", path.display()));
            return Ok(());
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            out.push(format!(
                "{}:{}",
                path.display(),
                crate::image::metadata_stamp(&metadata)?
            ));
            if depth == 0 {
                visit(&path.canonicalize()?, out, depth + 1, job)?;
            }
            return Ok(());
        }
        out.push(format!(
            "{}:{}",
            path.display(),
            crate::image::metadata_stamp(&metadata)?
        ));
        if metadata.is_dir() {
            let mut entries = std::fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
            entries.sort_by_key(|e| e.path());
            for entry in entries {
                visit(&entry.path(), out, depth + 1, job)?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    visit(path, &mut out, 0, job)?;
    Ok(out.join("\n"))
}
impl Session {
    pub fn clear(&mut self) {
        *self = Self::default();
    }
    pub fn prepare_image(
        &mut self,
        path: &Path,
        cache: &Path,
        job: &Job,
    ) -> Result<std::sync::Arc<Image>> {
        job.check()?;
        let image_stamp = source_stamp(path, job)?;
        if self.image.is_none()
            || self.image_stamp != image_stamp
            || self
                .image
                .as_ref()
                .is_some_and(|i| i.stamp().ok().as_ref() != Some(&self.physical_stamp))
        {
            self.clear();
            let image = Image::open(path, cache, job)?;
            self.physical_stamp = image.stamp()?;
            self.image = Some(std::sync::Arc::new(image));
            self.image_stamp = image_stamp;
        }
        Ok(self.image.as_ref().context("镜像未准备")?.clone())
    }
    pub fn analyze(&mut self, request: &Request<'_>, job: &Job) -> Result<Outcome> {
        self.analyze_with_dump(request, None, job)
    }
    pub fn analyze_with_dump(
        &mut self,
        request: &Request<'_>,
        dump: Option<&crate::dump::DumpOptions>,
        job: &Job,
    ) -> Result<Outcome> {
        if request.plugin.is_dump() {
            dump.context("Dump 插件需要 --pid、--dump-dir；memdump 还需要 --start、--end")?
                .validate(request.plugin)?;
        } else {
            ensure!(dump.is_none(), "非 Dump 插件不接受转储参数");
        }
        job.check()?;
        let image = self.prepare_image(request.image, request.cache, job)?;
        if request.plugin.is_windows() {
            return crate::windows::analyze(
                &image,
                request,
                dump,
                &crate::analysis::Options::default(),
                job,
            );
        }

        if request.plugin == Plugin::Banners {
            let key = store::key(&image.digest, "no-isf", "banners");
            if request.use_cache
                && let Some(result) = store::load(request.cache, &key)
            {
                return Ok(Outcome::Ready(result));
            }
            let result = banner_result(&image, job)?;
            if request.use_cache {
                store::save(request.cache, &key, &result, job)?;
            }
            return Ok(Outcome::Ready(result));
        }
        let symbols_stamp = || -> Result<String> {
            Ok(format!(
                "{}\n{}",
                source_stamp(request.symbols, job)?,
                source_stamp(&request.cache.join("symbols/isf"), job)?
            ))
        };
        let stamp = symbols_stamp()?;
        if self.symbol_stamp != stamp || self.symbols.is_empty() {
            self.symbols =
                symbols::resolve(request.symbols, &image, request.cache, request.network, job)?
                    .into_iter()
                    .map(std::sync::Arc::new)
                    .collect();
            // Resolving may download a new ISF; record the resulting cache state.
            self.symbol_stamp = symbols_stamp()?;
            self.roots.clear();
        } else {
            job.report("复用已验证镜像和符号；无需重新计算摘要／扫描");
        }
        let symbol = if let Some(choice) = request.choice {
            self.symbols
                .iter()
                .find(|s| s.label == choice)
                .context("指定符号不在完整 banner 匹配候选中")?
                .clone()
        } else {
            if self.symbols.len() > 1 {
                return Ok(Outcome::Choose(
                    self.symbols.iter().map(|s| s.label.clone()).collect(),
                ));
            }
            self.symbols[0].clone()
        };
        let key = store::key(&image.digest, &symbol.digest, request.plugin.name());
        if !request.plugin.is_dump()
            && request.use_cache
            && let Some(mut result) = store::load(request.cache, &key)
        {
            job.check()?;
            result.symbol = symbol.label.clone();
            job.report("读取成功缓存");
            return Ok(Outcome::Ready(result));
        }
        let root = if let Some(root) = self.roots.get(&symbol.digest) {
            *root
        } else {
            job.report("验证内核页表和完整 banner");
            let root = discover(&image, &symbol, job)?;
            self.roots.insert(symbol.digest.clone(), root);
            root
        };
        let engine = Linux {
            vm: VirtualMemory {
                image: &image,
                root,
            },
            isf: &symbol,
        };
        let result = if request.plugin.is_dump() {
            engine.run_dump(request.plugin, dump.unwrap(), job)?
        } else {
            engine.run(request.plugin, job)?
        };
        job.check()?;
        if request.use_cache && !request.plugin.is_dump() {
            store::save(request.cache, &key, &result, job)?;
        }
        Ok(Outcome::Ready(result))
    }
}
pub fn banner_result(image: &Image, job: &Job) -> Result<Results> {
    let rows = image
        .banners(job)?
        .into_iter()
        .map(|(p, b)| {
            vec![
                format!("{p:#018x}"),
                String::from_utf8_lossy(&b[..b.len() - 1]).into_owned(),
            ]
        })
        .collect();
    let rows: Vec<Vec<String>> = rows;
    let mut rows = if rows.is_empty() {
        image
            .windows_candidates(job)?
            .iter()
            .map(|c| {
                vec![
                    format!("{:#018x}", c.offset),
                    format!("Windows PDB {}", c.pdb.key()),
                ]
            })
            .collect()
    } else {
        rows
    };
    if rows.is_empty() && image.windows_container.is_some() {
        rows.push(vec![
            "[container]".into(),
            format!("Windows container {}", image.format),
        ]);
    }
    let system = if image.windows_container.is_some()
        || rows.iter().any(|r| r[1].starts_with("Windows PDB "))
    {
        "windows"
    } else {
        "linux"
    };
    Ok(Results {
        plugin: "banners".into(),
        columns: Plugin::Banners
            .descriptor()
            .columns
            .iter()
            .map(|s| (*s).into())
            .collect(),
        rows,
        complete: true,
        diagnostics: vec![],
        banner: String::new(),
        symbol: String::new(),
        page_table: 0,
        historical: false,
        system: system.into(),
        kernel_identity: serde_json::Value::Null,
    })
}

fn add(base: u64, offset: u64) -> Result<u64> {
    base.checked_add(offset).context("对象地址溢出")
}

pub fn discover(image: &Image, isf: &Isf, job: &Job) -> Result<u64> {
    if isf.data["metadata"]["linux"]["architecture"].as_str() == Some("AArch64")
        || isf.data["metadata"]["zero"]["architecture"].as_str() == Some("aarch64")
        || String::from_utf8_lossy(&isf.banner).contains("aarch64-linux")
    {
        return discover_arm64(image, isf, job);
    }
    let banner = isf.address("linux_banner")?;
    let init = isf.address("init_task")?;
    let tasks = isf.offset("task_struct", "tasks")?;
    let next = isf.offset("list_head", "next")?;
    let prev = isf.offset("list_head", "prev")?;
    let pid = isf.offset("task_struct", "pid")?;
    let comm = isf.offset("task_struct", "comm")?;
    let mut valid = HashSet::new();
    let mut errors = Vec::new();
    for physical in &isf.locations {
        for name in ["init_top_pgt", "init_level4_pgt", "swapper_pg_dir"] {
            job.check()?;
            if let Ok(address) = isf.address(name) {
                let candidate = *physical as i128 + address as i128 - banner as i128;
                if candidate < 0 || candidate > u64::MAX as i128 || candidate & 4095 != 0 {
                    continue;
                }
                let root = candidate as u64;
                let vm = VirtualMemory { image, root };
                let checked = (|| -> Result<()> {
                    ensure!(vm.translate(banner)? == *physical, "banner 虚实地址不一致");
                    let mut b = vec![0; isf.banner.len()];
                    vm.read(banner, &mut b)?;
                    ensure!(b == isf.banner, "banner 内容不一致");
                    ensure!(
                        vm.uint(add(init, pid)?, isf.size("task_struct", "pid")?)? == 0,
                        "init_task PID 非 0"
                    );
                    ensure!(
                        vm.string(add(init, comm)?, isf.size("task_struct", "comm")?)?
                            .starts_with("swapper"),
                        "init_task 名称无效"
                    );
                    let head = add(init, tasks)?;
                    let n = vm.uint(add(head, next)?, 8)?;
                    let p = vm.uint(add(head, prev)?, 8)?;
                    ensure!(
                        vm.uint(add(n, prev)?, 8)? == head && vm.uint(add(p, next)?, 8)? == head,
                        "init_task 双向链表不一致"
                    );
                    Ok(())
                })();
                match checked {
                    Ok(()) => {
                        valid.insert(root);
                    }
                    Err(e) => errors.push(format!("{root:#x}: {e:#}")),
                }
            }
        }
    }
    ensure!(
        !valid.is_empty(),
        "无法验证页表；可能是错误符号、缺页或未支持的内核重定位。{}",
        errors.join("; ")
    );
    ensure!(valid.len() == 1, "多个有效页表候选，拒绝猜测: {valid:?}");
    Ok(*valid.iter().next().unwrap())
}
fn discover_arm64(image: &Image, isf: &Isf, job: &Job) -> Result<u64> {
    use std::sync::atomic::Ordering;
    let config = &isf.data["metadata"]["zero"];
    ensure!(
        config["page_shift"].as_u64() == Some(12),
        "ARM64 需要已核对的 4 KiB 内核配置；请通过符号生成入口附加配置"
    );
    let bits = u8::try_from(
        config["va_bits"]
            .as_u64()
            .context("缺少 ARM64 VA_BITS 配置")?,
    )
    .context("ARM64 VA_BITS 越界")?;
    ensure!(matches!(bits, 39 | 48), "尚未支持此 ARM64 VA_BITS");
    image.arm64_va_bits.store(bits, Ordering::Relaxed);
    let banner = isf.raw_address("linux_banner")?;
    let init = isf.raw_address("init_task")?;
    let pgd = isf.raw_address("swapper_pg_dir")?;
    let mut valid = Vec::new();
    let mut errors = Vec::new();
    for &physical in &isf.locations {
        job.check()?;
        let check = (|| -> Result<(u64, u64)> {
            let physical_at = |symbol: u64| -> Result<u64> {
                u64::try_from(physical as i128 + symbol as i128 - banner as i128)
                    .context("ARM64 内核物理地址溢出")
            };
            let init_phys = physical_at(init)?;
            let real_parent =
                image.u64(add(init_phys, isf.offset("task_struct", "real_parent")?)?)?;
            let slide = real_parent.wrapping_sub(init);
            ensure!(slide & 4095 == 0, "内核重定位未按页对齐");
            let root = physical_at(pgd)?;
            ensure!(root & 4095 == 0, "ARM64 页表未对齐");
            let vm = VirtualMemory { image, root };
            let runtime_banner = banner.wrapping_add(slide);
            ensure!(
                vm.translate(runtime_banner)? == physical,
                "ARM64 banner 虚实地址不一致"
            );
            let mut bytes = vec![0; isf.banner.len()];
            vm.read(runtime_banner, &mut bytes)?;
            ensure!(bytes == isf.banner, "ARM64 banner 不一致");
            ensure!(
                vm.uint(
                    add(real_parent, isf.offset("task_struct", "pid")?)?,
                    isf.size("task_struct", "pid")?
                )? == 0,
                "ARM64 init_task PID 非 0"
            );
            ensure!(
                vm.string(
                    add(real_parent, isf.offset("task_struct", "comm")?)?,
                    isf.size("task_struct", "comm")?
                )?
                .starts_with("swapper"),
                "ARM64 init_task 名称不一致"
            );
            let head = add(real_parent, isf.offset("task_struct", "tasks")?)?;
            let next = vm.uint(head, 8)?;
            let prev = vm.uint(add(head, 8)?, 8)?;
            ensure!(
                vm.uint(add(next, 8)?, 8)? == head && vm.uint(prev, 8)? == head,
                "ARM64 init_task 双向链表错误"
            );
            Ok((root, slide))
        })();
        match check {
            Ok(v) => valid.push(v),
            Err(e) => errors.push(format!("{physical:#x}: {e:#}")),
        }
    }
    valid.sort_unstable();
    valid.dedup();
    ensure!(
        valid.len() == 1,
        "无法唯一验证 ARM64 页表／重定位: {}",
        errors.join("; ")
    );
    isf.slide.store(valid[0].1, Ordering::Relaxed);
    job.report(format!(
        "ARM64 页表已验证 · DTB {:#x} · 重定位 {:#x}",
        valid[0].0, valid[0].1
    ));
    Ok(valid[0].0)
}
pub struct Linux<'a> {
    pub vm: VirtualMemory<'a>,
    pub isf: &'a Isf,
}
impl Linux<'_> {
    pub(crate) fn field_address(&self, base: u64, structure: &str, field: &str) -> Result<u64> {
        base.checked_add(self.isf.offset(structure, field)?)
            .context("对象地址溢出")
    }
    pub(crate) fn number(&self, base: u64, structure: &str, field: &str) -> Result<u64> {
        if structure == "vfsmount"
            && self.modern_mount()
            && self.isf.field(structure, field).is_err()
        {
            let offset = self.isf.offset("mount", "mnt")?;
            let mount = base.checked_sub(offset).context("mount 地址下溢")?;
            let value = self.number(mount, "mount", field)?;
            return if field == "mnt_parent" {
                value.checked_add(offset).context("mount 地址溢出")
            } else {
                Ok(value)
            };
        }
        let value = self.vm.uint(
            self.field_address(base, structure, field)?,
            self.isf.size(structure, field)?,
        )?;
        let ty = &self.isf.field(structure, field)?["type"];
        if ty["kind"] == "bitfield" {
            let position = ty["bit_position"]
                .as_u64()
                .context("ISF bit position 无效")?;
            let length = ty["bit_length"].as_u64().context("ISF bit length 无效")?;
            ensure!(
                length > 0
                    && position.checked_add(length).is_some_and(
                        |end| end <= (self.isf.size(structure, field).unwrap_or(0) * 8) as u64
                    ),
                "ISF 位域越界"
            );
            Ok((value >> position) & (u64::MAX >> (64 - length)))
        } else {
            Ok(value)
        }
    }
    fn string(&self, base: u64, structure: &str, field: &str) -> Result<String> {
        self.vm.string(
            self.field_address(base, structure, field)?,
            self.isf.size(structure, field)?,
        )
    }
    pub fn run(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        if matches!(
            plugin,
            Plugin::Iomem | Plugin::Ioports | Plugin::Ptrace | Plugin::KeyboardNotifiers
        ) {
            return self.run_volatility_extra(plugin, job);
        }
        if plugin == Plugin::Banners {
            return banner_result(self.vm.image, job);
        }
        if matches!(
            plugin,
            Plugin::Psstate | Plugin::Capabilities | Plugin::Fdsummary
        ) {
            return self.run_process_extra(plugin, job);
        }

        if matches!(
            plugin,
            Plugin::Systeminfo
                | Plugin::Elfs
                | Plugin::Bash
                | Plugin::History
                | Plugin::Malfind
                | Plugin::Psxview
                | Plugin::CheckModules
                | Plugin::CheckSyscall
        ) {
            return self.run_inspect(plugin, job);
        }
        if matches!(
            plugin,
            Plugin::Pwd
                | Plugin::Pscred
                | Plugin::Threads
                | Plugin::Mountinfo
                | Plugin::CheckCreds
                | Plugin::Dmesg
        ) {
            return self.run_more(plugin, job);
        }
        if !matches!(plugin, Plugin::Pslist | Plugin::Pstree | Plugin::Lsmod) {
            return self.run_extended(plugin, job);
        }
        let process = plugin != Plugin::Lsmod;
        let structure = if process { "task_struct" } else { "module" };
        let member = if process { "tasks" } else { "list" };
        let offset = self.isf.offset(structure, member)?;
        let head = if process {
            self.field_address(self.isf.address("init_task")?, structure, member)?
        } else {
            self.isf.address("modules")?
        };
        let next = self.isf.offset("list_head", "next")?;
        let prev = self.isf.offset("list_head", "prev")?;
        let mut result = Results {
            plugin: plugin.name().into(),
            columns: plugin
                .descriptor()
                .columns
                .iter()
                .map(|s| (*s).into())
                .collect(),
            rows: Vec::new(),
            complete: true,
            diagnostics: Vec::new(),
            banner: String::from_utf8_lossy(&self.isf.banner[..self.isf.banner.len() - 1])
                .trim_end()
                .into(),
            symbol: self.isf.label.clone(),
            page_table: self.vm.root,
            historical: false,
            system: "linux".into(),
            kernel_identity: serde_json::Value::Null,
        };
        let traversal = (|| -> Result<()> {
            let mut node = self.vm.uint(add(head, next)?, 8)?;
            let mut previous = head;
            let mut visited = HashSet::new();
            let mut pids = HashSet::new();
            while node != head {
                job.check()?;
                ensure!(visited.insert(node), "链表循环未回到表头 @ {node:#x}");
                ensure!(visited.len() <= 1_000_000, "链表超过安全上限");
                ensure!(
                    self.vm.uint(add(node, prev)?, 8)? == previous,
                    "链表 prev 不一致 @ {node:#x}"
                );
                let successor = self.vm.uint(add(node, next)?, 8)?;
                ensure!(
                    self.vm.uint(add(successor, prev)?, 8)? == node,
                    "链表 next/prev 不一致 @ {node:#x}"
                );
                let object = node.checked_sub(offset).context("对象地址下溢")?;
                let row = (|| -> Result<Vec<String>> {
                    Ok(if process {
                        let pid = self.number(object, structure, "pid")?;
                        let tgid = self.number(object, structure, "tgid")?;
                        ensure!(
                            pid > 0
                                && pid <= i32::MAX as u64
                                && tgid > 0
                                && tgid <= i32::MAX as u64,
                            "非法 PID/TGID @ {object:#x}"
                        );
                        ensure!(pids.insert(pid), "重复 PID {pid}");
                        let parent = self.number(object, structure, "real_parent")?;
                        let ppid = self.number(parent, structure, "pid")?;
                        ensure!(ppid <= i32::MAX as u64, "非法 PPID @ {object:#x}");
                        vec![
                            pid.to_string(),
                            tgid.to_string(),
                            ppid.to_string(),
                            self.string(object, structure, "comm")?,
                            format!("{object:#018x}"),
                        ]
                    } else {
                        let (base, size) = if self.isf.field("module", "module_core").is_ok() {
                            (
                                self.number(object, structure, "module_core")?,
                                self.number(object, structure, "core_size")?,
                            )
                        } else if self.isf.field("module", "mem").is_ok() {
                            let mem = self.field_address(object, "module", "mem")?;
                            let n = self.isf.field("module", "mem")?["type"]["count"]
                                .as_u64()
                                .context("module.mem count")?;
                            ensure!((1..=32).contains(&n), "module.mem count 无效");
                            let size = self.isf.data["user_types"]["module_memory"]["size"]
                                .as_u64()
                                .context("module_memory size")?;
                            let text =
                                self.isf.data["enums"]["mod_mem_type"]["constants"]["MOD_TEXT"]
                                    .as_u64()
                                    .context("MOD_TEXT enum 缺失")?;
                            ensure!(text < n, "MOD_TEXT enum 越界");
                            let mut total = 0u64;
                            for kind in ["MOD_TEXT", "MOD_DATA", "MOD_RODATA", "MOD_RO_AFTER_INIT"]
                            {
                                let i = self.isf.data["enums"]["mod_mem_type"]["constants"][kind]
                                    .as_u64()
                                    .with_context(|| format!("{kind} enum 缺失"))?;
                                ensure!(i < n, "module memory enum 越界");
                                total = total
                                    .checked_add(self.number(
                                        mem + i * size,
                                        "module_memory",
                                        "size",
                                    )?)
                                    .context("模块大小溢出")?;
                            }
                            (
                                self.number(mem + text * size, "module_memory", "base")?,
                                total,
                            )
                        } else {
                            let layout = self.field_address(object, "module", "core_layout")?;
                            (
                                self.number(layout, "module_layout", "base")?,
                                self.number(layout, "module_layout", "size")?,
                            )
                        };
                        ensure!(base != 0 && size > 0, "模块基址或大小无效 @ {object:#x}");
                        vec![
                            self.string(object, structure, "name")?,
                            format!("{base:#018x}"),
                            size.to_string(),
                        ]
                    })
                })();
                match row {
                    Ok(row) => result.rows.push(row),
                    Err(error) => {
                        job.check()?;
                        result.complete = false;
                        result
                            .diagnostics
                            .push(format!("对象 {object:#018x}: {error:#}"));
                    }
                }
                previous = node;
                node = successor;
                job.report(format!("{}: {} 条", plugin.name(), result.rows.len()));
            }
            ensure!(
                self.vm.uint(add(head, prev)?, 8)? == previous,
                "链表表头 prev 不一致"
            );
            Ok(())
        })();
        if let Err(error) = traversal {
            job.check()?;
            result.complete = false;
            result.diagnostics.push(format!("部分结果: {error:#}"));
        }
        if process && result.complete {
            let pids: HashSet<_> = result.rows.iter().map(|r| r[0].as_str()).collect();
            let orphans: Vec<_> = result
                .rows
                .iter()
                .filter(|r| r[2] != "0" && !pids.contains(r[2].as_str()))
                .map(|r| r[0].clone())
                .collect();
            if !orphans.is_empty() {
                result.diagnostics.push(format!(
                    "父进程不在 tasks 链表（可能为线程或已退出）: {}",
                    orphans.join(",")
                ));
            }
        }
        Ok(result)
    }
}
