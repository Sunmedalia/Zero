//! The plugin catalog: identity, category, description and result layout, one row per plugin.
//! Table order is the display order. `DESCRIPTOR_INDEX` proves at compile time that every
//! `Plugin` has exactly one row.
use super::{Descriptor, Plugin};

macro_rules! catalog {
    ($($plugin:ident, $name:literal, $label:literal, $category:ident, $description:literal,
       [$($column:literal),*], [$($width:literal),*];)*) => {
        pub const PLUGINS: &[Descriptor] = &[$(Descriptor {
            plugin: Plugin::$plugin,
            name: $name,
            label: $label,
            category: stringify!($category),
            description: $description,
            columns: &[$($column),*],
            widths: &[$($width),*],
        }),*];
    };
}

catalog! {
    WinPoolScanner, "windows.poolscanner", "poolscanner", Memory,
        "按内核版本扫描内置池标签并校验对象结构",
        ["Tag", "Offset", "Layer", "Name"], [8, 18, 16, 0];
    WinWindowStations, "windows.windowstations", "windowstations", GUI,
        "扫描窗口站池并在对应会话地址空间中读取名称",
        ["Offset", "Name", "SessionId"], [18, 24, 0];
    WinWindows, "windows.windows", "windows", GUI,
        "枚举每个桌面的窗口、过程地址和所属进程",
        ["Offset", "Station", "Session", "Desktop", "Window", "Procedure", "Process", "PID"], [18, 24, 8, 32, 32, 18, 16, 0];
    WinDeskScan, "windows.deskscan", "deskscan", GUI,
        "扫描桌面池并读取父窗口站与线程所属进程",
        ["Offset", "Window Station", "Session", "Desktop", "Process", "PID"], [18, 24, 8, 32, 16, 0];
    WinDesktops, "windows.desktops", "desktops", GUI,
        "枚举每个窗口站的桌面及其线程所属进程",
        ["Offset", "Window Station", "Session", "Desktop", "Process", "PID"], [18, 24, 8, 32, 16, 0];
    WinDebugRegisters, "windows.debugregisters", "debugregisters", Integrity,
        "读取活动线程硬件调试寄存器及精确文件和符号归属",
        ["Process", "PID", "TID", "State", "Dr7", "Dr0", "Range0", "Symbol0", "Dr1", "Range1", "Symbol1", "Dr2", "Range2", "Symbol2", "Dr3", "Range3", "Symbol3"], [20, 7, 7, 7, 10, 18, 0, 0, 18, 0, 0, 18, 0, 0, 18, 0, 0];
    WinSuspendedThreads, "windows.suspended_threads", "suspended_threads", Integrity,
        "列出仍挂起的活动线程及起始地址文件和符号",
        ["Process", "PID", "TID", "StartFile", "StartSymbol", "StartAddress", "Win32StartFile", "Win32StartSymbol", "Win32StartAddress"], [20, 7, 7, 0, 0, 18, 0, 0, 18];
    WinUnhookedSystemCalls, "windows.unhooked_system_calls", "unhooked_system_calls", Integrity,
        "对比进程 ntdll 系统调用入口的 32 字节实现",
        ["Function", "Distinct Implementations", "Total Implementations"], [32, 0, 24];
    WinDirectSystemCalls, "windows.direct_system_calls", "direct_system_calls", Integrity,
        "检测系统 DLL 之外的直接系统调用指令块",
        ["Process", "PID", "Range", "Address", "Disasm"], [20, 7, 0, 18, 0];
    WinIndirectSystemCalls, "windows.indirect_system_calls", "indirect_system_calls", Integrity,
        "检测跳转至系统 DLL 的间接系统调用指令块",
        ["Process", "PID", "Range", "Address", "Disasm"], [20, 7, 0, 18, 0];
    WinSkeletonKeyCheck, "windows.skeleton_key_check", "skeleton_key_check", Integrity,
        "定位 lsass cryptdll RC4-HMAC 结构并检测函数指针挂钩",
        ["PID", "Process", "Skeleton Key Found", "rc4HmacInitialize", "rc4HmacDecrypt"], [7, 20, 20, 18, 18];
    WinTruecryptPassphrase, "windows.truecrypt.passphrase", "truecrypt.passphrase", Memory,
        "扫描 truecrypt.sys 数据段中的缓存口令",
        ["Offset", "Length", "Password"], [18, 8, 0];
    WinStrings, "windows.strings", "strings", Memory,
        "读取外部字符串偏移文件并反查内核／进程映射归属",
        ["String", "Physical Address", "Result"], [0, 18, 0];
    WinPESymbols, "windows.pe_symbols", "pe_symbols", Process,
        "通过精确 PDB 和 PE 导出表查询内核或进程模块符号",
        ["Module", "Symbol", "Address"], [28, 50, 18];
    WinAmcacheV4, "windows.registry.amcache.full", "registry.amcache.full", Files,
        "读取 Amcache 驱动、程序与文件的 11 列标准输出",
        ["EntryType", "Path", "Company", "LastModifyTime", "LastModifyTime2", "InstallTime", "CompileTime", "SHA1", "Service", "ProductName", "ProductVersion"], [8, 45, 25, 25, 25, 25, 25, 40, 25, 30, 20];
    WinUserAssistV4, "windows.registry.userassist.full", "registry.userassist.full", Files,
        "列出 UserAssist 键、子键与值的 12 列标准输出，保留原始字节",
        ["Hive Offset", "Hive Name", "Path", "Last Write Time", "Type", "Name", "ID", "Count", "Focus Count", "Time Focused", "Last Updated", "Raw Data"], [18, 32, 45, 25, 8, 45, 8, 8, 8, 22, 25, 48];
    WinMemmap, "windows.memmap", "memmap", Memory,
        "枚举 Intel 进程页表映射，可按 PID 定向导出（256 MiB 上限）",
        ["Virtual", "Physical", "Size", "Offset in File", "File output"], [18, 18, 18, 18, 24];
    WinSvcScanV4, "windows.svcscan.full", "svcscan.full", System,
        "扫描 services.exe 全部 VAD 并输出 11 列服务记录（固定参考契约）",
        ["Offset", "Order", "PID", "Start", "State", "Type", "Name", "Display", "Binary", "Binary (Registry)", "Dll"], [18, 8, 8, 22, 22, 36, 28, 40, 40, 40, 40];
    WinSvcDiff, "windows.svcdiff", "svcdiff", Integrity,
        "比较服务扫描与链表中的名称差异；缺页视图不能证明隐藏服务",
        ["Offset", "Order", "PID", "Start", "State", "Type", "Name", "Display", "Binary", "Binary (Registry)", "Dll"], [18, 8, 8, 22, 22, 36, 28, 40, 40, 40, 40];
    WinSvcList, "windows.svclist", "svclist", System,
        "在 services.exe 映像 VAD 中定位 Sc27 并枚举服务链表（Win10 15063+ x64）",
        ["Offset", "Order", "PID", "Start", "State", "Type", "Name", "Display", "Binary", "Binary (Registry)", "Dll"], [18, 8, 8, 22, 22, 36, 28, 40, 40, 40, 40];
    WinGetCellRoutine, "windows.registry.getcellroutine", "registry.getcellroutine", Files,
        "检查注册表 hive 的 GetCellRoutine 是否指向内核外；无法归属和缺页保留诊断",
        ["Hive Offset", "Hive Name", "GetCellRoutine Module", "GetCellRoutine Handler"], [18, 40, 24, 18];
    WinPebMasquerade, "windows.pebmasquerade", "pebmasquerade", Integrity,
        "对照 EPROCESS、审计和 PEB 路径，检查映像路径及命令行长度异常",
        ["PID", "EPROCESS_ImageFileName", "EPROCESS_SeAudit_ImageFileName", "PEB_ImageFilePath", "PEB_ImageFilePath_Spoofed", "PEB_CommandLine_Spoofed"], [8, 18, 30, 30, 12, 12];
    WinLdrmodules, "windows.ldrmodules", "ldrmodules", Integrity,
        "对照 PE 映射与三条 PEB 模块链表",
        ["PID", "Name", "Base", "View", "InLoad", "InInit", "InMem", "Path", "Reason"], [0, 0, 0, 0, 0, 0, 0, 0, 0];
    WinHollowprocesses, "windows.hollowprocesses", "hollowprocesses", Integrity,
        "检查主程序基址及映像映射异常",
        ["PID", "Name", "View", "Address", "Protection", "Path", "Reason"], [0, 0, 0, 0, 0, 0, 0];
    WinSuspiciousThreads, "windows.suspicious_threads", "suspicious_threads", Integrity,
        "检查活动线程起点所在的 VAD",
        ["PID", "Name", "TID", "Context", "Address", "Protection", "Path", "Reason"], [0, 0, 0, 0, 0, 0, 0, 0];
    CheckExec, "linux.check_exec", "check_exec", Integrity,
        "检查 Linux 主程序代码映射与可执行文件",
        ["PID", "Name", "Start", "End", "Permissions", "Path", "Reason"], [0, 0, 0, 0, 0, 0, 0];
    WinCallbacks, "windows.callbacks", "callbacks", Integrity,
        "查看内核回调及模块归属",
        ["Type", "Address", "Function", "Module", "Details"], [0, 0, 0, 0, 0];
    WinUnloadedmodules, "windows.unloadedmodules", "unloadedmodules", System,
        "读取已卸载驱动记录",
        ["Name", "Start", "End", "UnloadTime"], [0, 0, 0, 0];
    WinFilescan, "windows.filescan", "filescan", Files,
        "扫描文件对象",
        ["Physical", "Address", "Name", "DeviceObject", "ReadAccess", "WriteAccess", "DeleteAccess"], [0, 0, 0, 0, 0, 0, 0];
    WinMutantscan, "windows.mutantscan", "mutantscan", System,
        "扫描互斥对象",
        ["Physical", "Address", "Name", "OwnerThread", "SignalState"], [0, 0, 0, 0, 0];
    WinGetsids, "windows.getsids", "getsids", Process,
        "读取进程令牌 SID",
        ["PID", "Name", "SID", "Attributes", "Account"], [0, 0, 0, 0, 0];
    WinConnscan, "windows.connscan", "connscan", Network,
        "扫描旧版 Windows 连接对象",
        ["Physical", "PID", "LocalAddress", "LocalPort", "RemoteAddress", "RemotePort"], [0, 0, 0, 0, 0, 0];
    WinSockscan, "windows.sockscan", "sockscan", Network,
        "扫描旧版 Windows 套接字对象",
        ["Physical", "PID", "LocalAddress", "LocalPort", "Protocol", "CreateTime"], [0, 0, 0, 0, 0, 0];
    WinConsoles, "windows.consoles", "consoles", Process,
        "恢复控制台保存的记录",
        ["PID", "Name", "Address", "Title", "HistorySize", "HistoryCount"], [0, 0, 0, 0, 0, 0];
    WinCmdscan, "windows.cmdscan", "cmdscan", Process,
        "扫描命令历史记录",
        ["PID", "Name", "History", "Application", "Index", "Command"], [0, 0, 0, 0, 0, 0];
    WinDrivercheck, "windows.drivercheck", "drivercheck", Integrity,
        "检查模块或驱动异常",
        ["Address", "DriverName", "Function", "Target", "TargetModule", "InDriverRange"], [0, 0, 0, 0, 0, 0];
    WinDriverscan, "windows.driverscan", "driverscan", System,
        "扫描驱动对象",
        ["Address", "DriverName", "Start", "Size", "Module", "DriverInit"], [0, 0, 0, 0, 0, 0];
    WinSvcscan, "windows.svcscan", "svcscan", System,
        "扫描 Windows 服务",
        ["PID", "Address", "ServiceName", "DisplayName", "State", "Start", "Type", "BinaryPath"], [0, 0, 0, 0, 0, 0, 0, 0];
    WinCrashinfo, "windows.crashinfo", "crashinfo", System,
        "读取转储容器故障信息，无需完整内核符号",
        ["Key", "Value"], [0, 0];
    WinAutoruns, "windows.autoruns", "autoruns", Integrity,
        "查看注册表自启动配置",
        ["Hive", "Key", "Kind", "Name", "Type", "Data", "LastWriteTime"], [0, 0, 0, 0, 0, 0, 0];
    WinEnvars, "windows.envars", "envars", Process,
        "读取进程环境变量",
        ["PID", "Name", "View", "Variable", "Value"], [0, 0, 0, 0, 0];
    WinThreads, "windows.threads", "threads", Process,
        "列出进程线程",
        ["PID", "Name", "TID", "Address", "State", "StartAddress", "StartModule", "CreateTime", "ExitTime"], [0, 0, 0, 0, 0, 0, 0, 0, 0];
    WinSysteminfo, "windows.systeminfo", "systeminfo", System,
        "查看系统和内核信息",
        ["Key", "Value"], [12, 0];
    WinPslist, "windows.pslist", "pslist", Process,
        "列出活动进程、会话与 WOW64 状态",
        ["PID", "PPID", "Name", "Address", "Threads", "Handles", "CreateTime", "ExitTime", "SessionId", "Wow64"], [12, 12, 0, 12, 10, 10, 12, 12, 10, 6];
    WinPstree, "windows.pstree", "pstree", Process,
        "按父进程关系浏览进程树、会话与 WOW64 状态",
        ["PID", "PPID", "Name", "Address", "Threads", "Handles", "CreateTime", "ExitTime", "SessionId", "Wow64"], [12, 12, 0, 12, 10, 10, 12, 12, 10, 6];
    WinCmdline, "windows.cmdline", "cmdline", Process,
        "读取进程命令行",
        ["PID", "Name", "CommandLine", "View"], [12, 0, 0, 10];
    WinModules, "windows.modules", "modules", System,
        "列出内核模块及地址范围",
        ["Name", "Base", "Size", "Path"], [0, 12, 12, 0];
    WinDlllist, "windows.dlllist", "dlllist", Process,
        "列出进程加载的 DLL（含 LoadCount 与 LoadTime）",
        ["PID", "Name", "Base", "Size", "Path", "View", "LoadCount", "LoadTime"], [12, 0, 12, 12, 0, 10, 10, 20];
    WinVadinfo, "windows.vadinfo", "vadinfo", Memory,
        "查看进程虚拟内存映射（含 Tag、Parent 与 CommitCharge）",
        ["PID", "Name", "Start", "End", "Protection", "Private", "Path", "Address", "Tag", "Parent", "CommitCharge"], [12, 0, 12, 12, 12, 8, 0, 12, 6, 12, 12];
    WinHandles, "windows.handles", "handles", Files,
        "列出进程打开的文件或对象",
        ["PID", "Name", "Handle", "Type", "Object", "GrantedAccess", "ObjectName"], [12, 0, 12, 12, 12, 12, 0];
    WinMalfind, "windows.malfind", "malfind", Integrity,
        "检查可疑的可执行内存映射，支持反汇编与可选导出",
        ["PID", "Name", "Start", "End", "Protection", "Reason", "Preview", "Disasm", "File output"], [12, 0, 12, 12, 12, 12, 24, 32, 16];
    WinNetscan, "windows.netscan", "netscan", Network,
        "查看网络连接及端点",
        ["Address", "Protocol", "LocalEndpoint", "RemoteEndpoint", "State", "PID", "Name", "CreateTime"], [12, 12, 12, 12, 12, 12, 0, 12];
    WinNetstat, "windows.netstat", "netstat", Network,
        "遍历 tcpip.sys 分区表与端口池中的活动端点",
        ["Offset", "Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID", "Owner", "Created"], [18, 8, 24, 8, 24, 8, 14, 8, 16, 0];
    WinShimcacheMem, "windows.shimcachemem", "shimcachemem", Files,
        "从 ahcache 或内核模块的 LRU 链表读取内存 Shimcache",
        ["Order", "Last Modified", "Last Update", "Exec Flag", "File Size", "File Path"], [8, 24, 24, 12, 12, 0];
    WinHiveScan, "windows.registry.hivescan", "registry.hivescan", Files,
        "按构建版本扫描 CM10 小池或大页池中的注册表 hive 候选",
        ["Offset"], [18];
    WinHivelist, "windows.hivelist", "hivelist", Files,
        "列出注册表 hive 地址",
        ["Address", "Path"], [12, 0];
    WinPrintkey, "windows.printkey", "printkey", Files,
        "读取指定 hive 中的注册表键",
        ["Hive", "Key", "Kind", "Name", "Type", "Data", "LastWriteTime"], [12, 12, 12, 0, 12, 0, 12];
    WinPsscan, "windows.psscan", "psscan", Integrity,
        "扫描进程对象（含会话与 WOW64 状态）",
        ["PID", "PPID", "Name", "Address", "Threads", "Handles", "CreateTime", "ExitTime", "SessionId", "Wow64"], [12, 12, 0, 12, 10, 10, 12, 12, 10, 6];
    WinPsxview, "windows.psxview", "psxview", Integrity,
        "对比活动链表、池扫描、线程扫描与 csrss 句柄表四种视图",
        ["PID", "Name", "Address", "Pslist", "Psscan", "Thrdscan", "Csrss", "ExitTime"], [12, 0, 12, 8, 8, 8, 8, 12];
    WinProcdump, "windows.procdump", "procdump", Process,
        "转储指定进程的可读内存",
        ["PID", "Name", "Start", "End", "Size", "SHA256", "File"], [12, 0, 12, 12, 12, 12, 12];
    WinMemdump, "windows.memdump", "memdump", Memory,
        "转储指定进程的地址范围",
        ["PID", "Name", "Start", "End", "Size", "SHA256", "File"], [12, 0, 12, 12, 12, 12, 12];
    WinPedump, "windows.pedump", "pedump", Memory,
        "按 PE 节表重建可读文件",
        ["PID", "Name", "Start", "End", "Size", "SHA256", "File"], [12, 0, 12, 12, 12, 12, 12];
    WinVaddump, "windows.vaddump", "vaddump", Memory,
        "按 VAD 逐段转储进程内存并保留 VAD 元数据",
        ["PID", "Name", "Start", "End", "Size", "Protection", "Private", "Path", "SHA256", "File"], [12, 0, 12, 12, 10, 16, 8, 0, 12, 0];
    WinDlldump, "windows.dlldump", "dlldump", Memory,
        "按基址选择并重建导出进程 DLL 的 PE 文件",
        ["PID", "Name", "Module", "Base", "Size", "View", "SHA256", "File"], [12, 0, 0, 12, 10, 8, 12, 0];
    WinModdump, "windows.moddump", "moddump", Memory,
        "重建并导出内核模块的 PE 文件",
        ["Module", "Base", "Size", "Path", "SHA256", "File"], [0, 12, 10, 0, 12, 0];
    WinDumpfiles, "windows.dumpfiles", "dumpfiles", Files,
        "从文件缓存（句柄与 VAD）提取驻留文件内容",
        ["PID", "Cache", "FileObject", "FileName", "Size", "Pages", "SHA256", "File"], [12, 14, 12, 0, 10, 8, 12, 0];
    WinThrdscan, "windows.thrdscan", "thrdscan", Integrity,
        "扫描线程对象（含已退出或脱离链表的线程）并解析起始内核模块",
        ["Physical", "Address", "PID", "TID", "StartAddress", "Win32StartAddress", "CreateTime", "ExitTime", "StartModule", "Win32StartModule"], [0, 0, 8, 8, 12, 12, 0, 0, 18, 18];
    WinHashdump, "windows.hashdump", "hashdump", Files,
        "解密 SAM hive 中的用户 NTLM/LM 哈希",
        ["User", "RID", "LM", "NT"], [0, 8, 34, 34];
    WinLsadump, "windows.lsadump", "lsadump", Files,
        "解密 SECURITY hive 中的 LSA 机密",
        ["Name", "Text", "Hex", "Size"], [20, 0, 0, 8];
    WinCachedump, "windows.cachedump", "cachedump", Files,
        "解密 SECURITY hive 中的域缓存凭据（DCC）",
        ["User", "Domain", "DomainName", "Iterations", "DCC"], [0, 12, 16, 10, 0];
    WinSsdt, "windows.ssdt", "ssdt", Integrity,
        "检查系统服务表项的模块与符号归属",
        ["Index", "Address", "Module", "Symbol", "Reason"], [6, 18, 16, 0, 0];
    WinModscan, "windows.modscan", "modscan", Integrity,
        "扫描 MmLd 池中的内核模块条目并对照模块链表",
        ["Physical", "Name", "Base", "Size", "Path", "InList"], [18, 16, 18, 10, 0, 6];
    WinPrivileges, "windows.privileges", "privileges", Process,
        "列出进程令牌拥有的特权及启用状态",
        ["PID", "Name", "Value", "Privilege", "Attributes"], [8, 16, 6, 0, 24];
    WinSessions, "windows.sessions", "sessions", Process,
        "按登录会话归类进程（含会话类型与用户名）",
        ["SessionID", "PID", "Name", "CreateTime", "SessionAddress", "SessionType", "UserName"], [9, 8, 0, 20, 18, 12, 18];
    WinUserassist, "windows.registry.userassist", "registry.userassist", Files,
        "解码 NTUSER 中的 UserAssist 程序执行记录",
        ["Hive", "GUID", "Name", "Count", "FocusCount", "FocusTime", "LastUpdated"], [0, 0, 0, 6, 10, 10, 20];
    WinBigpools, "windows.bigpools", "bigpools", Memory,
        "列出大页池分配表中的块、池标签与分配状态（支持 --show-free / --tags）",
        ["Allocation", "Tag", "PoolType", "NumberOfBytes", "Status"], [18, 6, 10, 14, 10];
    WinSymlinkscan, "windows.symlinkscan", "symlinkscan", Files,
        "扫描符号链接对象及其目标",
        ["Physical", "Address", "Name", "Target", "CreateTime"], [18, 18, 0, 0, 20];
    WinDevicetree, "windows.devicetree", "devicetree", System,
        "按驱动列出设备对象及附加设备链",
        ["Driver", "DriverName", "Level", "Device", "DeviceName", "DeviceType"], [18, 0, 6, 18, 0, 10];
    WinGetservicesids, "windows.getservicesids", "getservicesids", System,
        "按当前 ControlSet 服务名计算服务 SID",
        ["SID", "Service"], [0, 0];
    WinIat, "windows.iat", "iat", Process,
        "列出进程主映像的导入表及绑定地址",
        ["PID", "Name", "Library", "Function", "Bound"], [8, 16, 16, 0, 18];
    WinVerinfo, "windows.verinfo", "verinfo", Process,
        "读取进程 DLL 与内核模块的版本资源",
        ["PID", "Name", "Base", "Path", "FileVersion", "ProductVersion"], [8, 16, 18, 0, 16, 16];
    WinMftscan, "windows.mftscan", "mftscan", Files,
        "从物理内存雕刻 NTFS MFT 记录及两组时间戳",
        ["Physical", "Record", "Type", "InUse", "Name", "Parent", "SICreated", "SIModified", "FNCreated", "FNModified", "Size"], [18, 8, 9, 5, 0, 8, 18, 18, 18, 18, 10];
    WinMftscanAds, "windows.mftscan.ads", "mftscan.ads", Files,
        "从物理内存雕刻 NTFS MFT 中的备用数据流（ADS）及常驻内容",
        ["Offset", "Record Type", "Record Number", "MFT Type", "Filename", "ADS Filename", "Hexdump"], [18, 11, 13, 18, 24, 24, 0];
    WinMftscanResidentData, "windows.mftscan.resident_data", "mftscan.resident_data", Files,
        "从物理内存雕刻 NTFS MFT 中的常驻文件数据（$DATA）",
        ["Offset", "Record Type", "Record Number", "MFT Type", "Filename", "Hexdump"], [18, 11, 13, 18, 28, 0];
    WinOrphanThreads, "windows.orphan_kernel_threads", "orphan_kernel_threads", Integrity,
        "列出起始地址不在任何内核模块中的系统线程",
        ["PID", "TID", "Address", "StartAddress", "CreateTime"], [6, 8, 18, 18, 20];
    WinEtwpatch, "windows.etwpatch", "etwpatch", Integrity,
        "检查各进程 ntdll ETW 入口是否被打补丁",
        ["PID", "Name", "Module", "Function", "Address", "Bytes", "Reason"], [8, 16, 0, 14, 18, 24, 0];
    WinScheduledTasksV4, "windows.registry.scheduled_tasks.full", "registry.scheduled_tasks.full", Files,
        "解码计划任务的动作、触发器、主体与执行历史",
        ["Task Name", "Principal ID", "Display Name", "Enabled", "Creation Time", "Last Run Time", "Last Successful Run Time", "Trigger Type", "Trigger Description", "Action Type", "Action", "Action Arguments", "Action Context", "Working Directory", "Key Name"], [24, 16, 16, 8, 24, 24, 24, 16, 0, 16, 0, 0, 16, 0, 38];
    WinScheduledTasks, "windows.registry.scheduled_tasks", "registry.scheduled_tasks", Files,
        "解码注册表 TaskCache 中的计划任务及命令",
        ["Path", "TaskId", "Command", "Arguments", "WorkingDirectory", "Created", "LastRun"], [0, 0, 0, 0, 0, 20, 20];
    WinAmcache, "windows.registry.amcache", "registry.amcache", Files,
        "读取 Amcache.hve 的程序文件清单",
        ["Path", "SHA1", "Publisher", "Version", "LinkDate", "LastWriteTime"], [0, 40, 0, 16, 20, 20];
    WinCertificates, "windows.registry.certificates", "registry.certificates", Files,
        "列出注册表证书存储中的证书",
        ["Hive", "Store", "Thumbprint", "FriendlyName", "Subject", "Issuer", "NotBefore", "NotAfter"], [0, 10, 40, 0, 0, 0, 15, 15];
    WinProcessghosting, "windows.processghosting", "processghosting", Integrity,
        "检查进程映像文件是否删除挂起或未关联节对象",
        ["PID", "Name", "FileObject", "DeletePending", "DataSection", "ImageSection", "Path", "Reason"], [8, 16, 18, 8, 18, 18, 0, 0];
    WinJoblinks, "windows.joblinks", "joblinks", Process,
        "列出进程所属的作业对象及计数",
        ["Job", "SessionID", "Active", "Total", "PID", "Name"], [18, 9, 6, 6, 8, 0];
    WinTimeliner, "windows.timeliner", "timeliner", System,
        "汇总多个 Windows 插件时间戳为统一时间线，支持导出 bodyfile",
        ["Time", "FILETIME", "Plugin", "Event", "Description"], [23, 18, 24, 24, 0];
    WinMbrscan, "windows.mbrscan", "mbrscan", Files,
        "扫描内存中的主引导记录、分区表与引导代码反汇编",
        ["Physical", "DiskSignature", "Partition", "Bootable", "Type", "StartLBA", "Sectors", "BootCodeSHA256", "Disasm"], [18, 10, 4, 6, 6, 12, 12, 20, 0];
    WinTimers, "windows.timers", "timers", Integrity,
        "列出各处理器的内核定时器、触发状态及 DPC 例程归属与符号",
        ["CPU", "Timer", "DueTime", "Period", "DPC", "Routine", "Module", "Signaled", "Symbol"], [4, 18, 20, 8, 18, 18, 18, 8, 0];
    WinStatistics, "windows.statistics", "statistics", Memory,
        "统计内核地址空间的有效、换出与空页表项",
        ["Key", "Value"], [30, 0];
    WinShimcache, "windows.registry.shimcache", "registry.shimcache", Files,
        "解码 SYSTEM hive 中的 AppCompatCache 执行痕迹",
        ["Order", "Path", "LastModified"], [6, 0, 20];
    WinVirtmap, "windows.virtmap", "virtmap", Memory,
        "列出内核虚拟地址空间按用途划分的区域",
        ["Region", "Start", "End", "Size"], [0, 18, 18, 16];
    WinVadyarascan, "windows.vadyarascan", "vadyarascan", Memory,
        "在进程 VAD 中执行 YARA-X 规则或字节模式扫描",
        ["PID", "Name", "Rule", "Component", "Address", "Start", "Protection", "Path", "Context"], [8, 16, 20, 14, 18, 18, 0, 0, 0];
    WinYarascan, "windows.yarascan", "yarascan", Memory,
        "使用 YARA-X 规则或字节模式扫描 Windows 物理内存镜像",
        ["Physical", "Rule", "Component", "Context"], [18, 24, 16, 0];
    Vmayarascan, "linux.vmayarascan", "vmayarascan", Memory,
        "在进程 VMA 中执行 YARA-X 规则或字节模式扫描",
        ["PID", "Name", "Rule", "Component", "Address", "Start", "Permissions", "Path", "Context"], [6, 14, 20, 14, 18, 18, 5, 0, 0];
    LinuxYarascan, "linux.yarascan", "yarascan", Memory,
        "使用 YARA-X 规则或字节模式扫描物理内存镜像",
        ["Physical", "Rule", "Component", "Context"], [18, 24, 16, 0];
    Pslist, "linux.pslist.basic", "pslist.basic", Process,
        "列出活动进程及其地址",
        ["PID", "TGID", "PPID", "Name", "Address"], [5, 5, 5, 0, 18];
    Pstree, "linux.pstree.basic", "pstree.basic", Process,
        "按父进程关系浏览进程树",
        ["PID", "TGID", "PPID", "Name", "Address"], [5, 5, 5, 0, 18];
    Lsmod, "linux.lsmod", "lsmod", System,
        "列出内核模块及地址范围",
        ["Offset", "Module Name", "Code Size", "Taints", "Load Arguments", "File Output"], [18, 18, 10, 16, 0, 16];
    Psaux, "linux.psaux.basic", "psaux.basic", Process,
        "读取进程命令行",
        ["PID", "PPID", "Name", "CommandLine", "Status"], [5, 5, 12, 0, 12];
    Envars, "linux.envars.basic", "envars.basic", Process,
        "读取进程环境变量",
        ["PID", "Name", "Key", "Value"], [5, 12, 16, 0];
    Maps, "linux.maps.basic", "maps.basic", Memory,
        "查看进程虚拟内存映射",
        ["PID", "Name", "Start", "End", "Permissions", "FileOffset", "Path"], [5, 12, 18, 18, 4, 10, 0];
    Lsof, "linux.lsof.basic", "lsof.basic", Files,
        "列出进程打开的文件或对象",
        ["PID", "Name", "FD", "Type", "Inode", "Path", "FileAddress"], [5, 12, 4, 8, 10, 0, 18];
    Sockstat, "linux.sockstat.basic", "sockstat.basic", Network,
        "查看网络连接及端点",
        ["PID", "Name", "FD", "Family", "Type", "Protocol", "LocalEndpoint", "RemoteEndpoint", "State", "SocketAddress"], [5, 12, 4, 6, 8, 8, 0, 0, 12, 18];
    Netscan, "linux.netscan", "netscan", Network,
        "查看网络连接及端点",
        ["PID", "Name", "Protocol", "LocalEndpoint", "RemoteEndpoint", "State", "SocketAddress"], [5, 12, 6, 0, 0, 12, 18];
    Banners, "linux.banners", "banners", System,
        "识别完整内核身份，无需符号",
        ["Offset", "Banner"], [18, 0];
    Pwd, "linux.pwd", "pwd", Process,
        "读取进程工作目录",
        ["PID", "Name", "Root", "CWD"], [5, 12, 0, 0];
    Pscred, "linux.pscred", "pscred", Process,
        "查看进程身份和凭据",
        ["PID", "Name", "UID", "GID", "EUID", "EGID", "SUID", "SGID", "FSUID", "FSGID", "CredAddress"], [5, 12, 6, 6, 6, 6, 6, 6, 6, 6, 18];
    Threads, "linux.threads", "threads", Process,
        "列出进程线程",
        ["PID", "Name", "TID", "ThreadName", "Address"], [5, 12, 6, 0, 18];
    Mountinfo, "linux.mountinfo.basic", "mountinfo.basic", Files,
        "查看文件系统挂载关系",
        ["PID", "Name", "MountID", "ParentID", "Device", "MountPoint", "FileSystem", "Flags", "Address"], [5, 12, 6, 6, 0, 0, 8, 10, 18];
    CheckCreds, "linux.check_creds", "check_creds", Integrity,
        "检查进程凭据异常",
        ["CredAddress", "PIDs", "Names", "UID", "EUID"], [18, 0, 0, 6, 6];
    Dmesg, "linux.dmesg", "dmesg", System,
        "读取内核日志缓冲区",
        ["Index", "Message"], [8, 0];
    Systeminfo, "linux.systeminfo", "systeminfo", System,
        "查看系统和内核信息",
        ["Key", "Value"], [22, 0];
    Elfs, "linux.elfs.basic", "elfs.basic", Memory,
        "识别进程中的 ELF 映射",
        ["PID", "Name", "Start", "End", "Type", "Entry", "Path"], [6, 14, 18, 18, 6, 18, 0];
    Bash, "linux.bash.basic", "bash.basic", Memory,
        "恢复内存中的 Bash 历史记录",
        ["PID", "Name", "Timestamp", "Command", "Address"], [6, 14, 12, 0, 18];
    Zsh, "linux.zsh", "zsh", Memory,
        "恢复内存中的 Zsh 历史记录（命令、开始与结束时间）",
        ["PID", "Name", "HistNum", "Started", "Finished", "Command", "Address"], [6, 14, 7, 12, 12, 0, 18];
    Malfind, "linux.malfind.basic", "malfind.basic", Integrity,
        "检查可疑的可执行内存映射",
        ["PID", "Name", "Start", "End", "Permissions", "Path", "Reason", "Preview"], [6, 14, 18, 18, 6, 0, 24, 32];
    Psxview, "linux.psxview", "psxview", Integrity,
        "对比多种进程发现方式",
        ["PID", "Name", "Address", "Tasks", "PIDIndex", "ThreadGroup", "Reason"], [6, 14, 18, 6, 8, 12, 0];
    CheckModules, "linux.check_modules", "check_modules", Integrity,
        "检查模块或驱动异常",
        ["Name", "Address", "Start", "End", "ModuleList", "Sysfs", "Reason"], [18, 18, 18, 18, 10, 6, 0];
    CheckSyscall, "linux.check_syscall", "check_syscall", Integrity,
        "检查系统调用表",
        ["Table", "Index", "Target", "Symbol", "Owner", "Reason"], [18, 6, 18, 24, 18, 0];
    CheckIdt, "linux.check_idt", "check_idt", Integrity,
        "检查中断描述符表处理函数归属（x86_64）",
        ["Index", "Address", "Symbol", "Owner", "Present", "Reason"], [6, 18, 24, 18, 8, 0];
    TtyCheck, "linux.tty_check", "tty_check", Integrity,
        "检查 TTY 行规程 receive_buf 是否被挂钩",
        ["Name", "Address", "Symbol", "Owner", "Reason"], [12, 18, 24, 18, 0];
    HiddenModules, "linux.hidden_modules", "hidden_modules", Integrity,
        "从模块内存雕刻不在模块链表中的隐藏模块",
        ["Name", "Address", "Start", "End", "State", "Reason"], [18, 18, 18, 18, 9, 0];
    LibraryList, "linux.library_list.basic", "library_list.basic", Memory,
        "列出进程映射的共享库",
        ["PID", "Name", "LoadAddress", "Path"], [6, 14, 18, 0];
    Pidhashtable, "linux.pidhashtable", "pidhashtable", Process,
        "从 PID 索引列出任务，独立于 tasks 链表",
        ["Address", "PID", "TGID", "PPID", "Name"], [18, 6, 6, 6, 0];
    Vmcoreinfo, "linux.vmcoreinfo", "vmcoreinfo", System,
        "读取内核为崩溃转储准备的 vmcoreinfo",
        ["Key", "Value"], [32, 0];
    IpAddr, "linux.ip.addr.basic", "ip.addr.basic", Network,
        "列出各网络命名空间中网卡的 IPv4／IPv6 地址",
        ["Namespace", "Interface", "MAC", "Promiscuous", "Address", "Prefix", "Scope", "State"], [18, 12, 17, 6, 0, 6, 8, 10];
    IpLink, "linux.ip.link.basic", "ip.link.basic", Network,
        "列出各网络命名空间中的网卡及状态",
        ["Namespace", "Interface", "MAC", "State", "MTU", "Flags"], [18, 12, 17, 10, 6, 0];
    CheckAfinfo, "linux.check_afinfo", "check_afinfo", Integrity,
        "检查网络协议 /proc 处理函数是否被挂钩",
        ["Structure", "Member", "Address", "Symbol", "Owner", "Reason"], [20, 18, 18, 0, 16, 0];
    Kthreads, "linux.kthreads", "kthreads", Integrity,
        "列出内核线程及其线程函数归属",
        ["PID", "Name", "ThreadFunction", "Symbol", "Owner", "Reason"], [6, 16, 18, 0, 16, 0];
    Netfilter, "linux.netfilter", "netfilter", Integrity,
        "列出 netfilter 钩子及处理函数归属",
        ["Namespace", "Protocol", "Hook", "Priority", "Handler", "Symbol", "Owner", "Reason"], [18, 8, 12, 8, 18, 0, 16, 0];
    Tracepoints, "linux.tracepoints", "tracepoints", Integrity,
        "列出挂在内核 tracepoint 上的探针与优先级",
        ["Tracepoint", "Handler", "Symbol", "Owner", "Reason", "Priority"], [0, 18, 0, 16, 0, 8];
    Ftrace, "linux.ftrace", "ftrace", Integrity,
        "列出已注册的 ftrace 回调、标志与挂钩符号",
        ["Ops", "Handler", "Symbol", "Owner", "Reason", "Flags", "HookedSymbols"], [18, 18, 0, 16, 0, 18, 24];
    PerfEvents, "linux.perf_events", "perf_events", Integrity,
        "列出进程持有的 perf 事件及溢出处理函数",
        ["PID", "Name", "Event", "Type", "Config", "Handler", "Symbol", "Owner", "Reason"], [6, 14, 18, 6, 10, 18, 0, 16, 0];
    Ebpf, "linux.ebpf", "ebpf", Integrity,
        "列出已加载的 eBPF 程序及其 Tag",
        ["ID", "Name", "Type", "Address", "Function", "Tag"], [6, 16, 0, 18, 18, 18];
    Boottime, "linux.boottime.basic", "boottime.basic", System,
        "根据时间保持偏移计算系统启动时间",
        ["Key", "Value"], [16, 0];
    LinuxBoottime, "linux.boottime.full", "boottime.full", System,
        "按任务遍历顺序列出各时间命名空间的启动时间",
        ["TIME NS", "Boot Time"], [12, 32];
    LinuxTimeliner, "linux.timeliner", "timeliner", System,
        "汇总多个 Linux 插件时间戳为统一时间线，支持导出 bodyfile",
        ["Time", "Plugin", "Event", "Description"], [32, 24, 20, 0];
    Pagecache, "linux.pagecache", "pagecache", Files,
        "列出页缓存中各文件系统的 inode 及缓存页数",
        ["SuperBlock", "Device", "FileSystem", "Inode", "InodeAddress", "Mode", "Size", "CachedPages", "Path"], [18, 10, 10, 10, 18, 8, 12, 8, 0];
    Psstate, "linux.psstate", "psstate", Process,
        "查看进程状态",
        ["PID", "Name", "State", "ExitState", "Flags"], [6, 16, 18, 18, 18];
    Capabilities, "linux.capabilities.basic", "capabilities.basic", Process,
        "查看进程能力集合",
        ["PID", "Name", "Inheritable", "Permitted", "Effective", "Bounding", "CredAddress"], [6, 16, 18, 18, 18, 18, 18];
    LinuxCapabilities, "linux.capabilities.full", "capabilities.full", Process,
        "解码 real_cred 能力集合、ambient 与 cred EUID；可按 PID 列表筛选",
        ["Name", "Tid", "Pid", "PPid", "EUID", "cap_inheritable", "cap_permitted", "cap_effective", "cap_bounding", "cap_ambient"], [16, 6, 6, 6, 6, 0, 0, 0, 0, 0];
    LinuxEnvars, "linux.envars.full", "envars.full", Process,
        "读取完整环境区并按参考处理损坏条目；支持 PID 列表筛选",
        ["PID", "PPID", "COMM", "KEY", "VALUE"], [6, 6, 16, 20, 0];
    LinuxPsaux, "linux.psaux.full", "psaux.full", Process,
        "读取完整命令行、父进程 TGID 和内核线程名称；支持 PID 列表",
        ["PID", "PPID", "COMM", "ARGS"], [6, 6, 16, 0];
    LinuxPstree, "linux.pstree.full", "pstree.full", Process,
        "按父子层级输出完整进程树；支持 PID 列表、用户线程与名称标记",
        ["OFFSET (V)", "PID", "TID", "PPID", "COMM"], [18, 6, 6, 6, 0];
    LinuxMaps, "linux.maps.full", "maps.full", Memory,
        "列出进程完整 VMA（主次设备号、Inode、特殊映射及可选地址过滤与导出）",
        ["PID", "Process", "Start", "End", "Flags", "PgOff", "Major", "Minor", "Inode", "File Path", "File output"], [6, 16, 18, 18, 5, 10, 6, 6, 10, 0, 16];
    LinuxLsof, "linux.lsof.full", "lsof.full", Files,
        "列出进程打开文件完整元数据（设备、权限、时间戳、大小）；支持 PID 列表与仅文件筛选",
        ["PID", "TID", "Process", "FD", "Path", "Device", "Inode", "Type", "Mode", "Changed", "Modified", "Accessed", "Size"], [6, 6, 16, 5, 0, 8, 10, 6, 10, 26, 26, 26, 10];
    LinuxSockstat, "linux.sockstat.full", "sockstat.full", Network,
        "列出进程全部协议族套接字与 BPF 过滤器；支持 PID 列表与 NetNS 筛选",
        ["NetNS", "Process Name", "PID", "TID", "FD", "Sock Offset", "Family", "Type", "Proto", "Source Addr", "Source Port", "Destination Addr", "Destination Port", "State", "Filter"], [10, 16, 6, 6, 5, 18, 12, 10, 10, 0, 10, 0, 10, 14, 0];
    LinuxKmsg, "linux.kmsg", "kmsg", System,
        "解析三代 Linux printk 日志缓冲区（facility、level、时间戳、caller 与正文）",
        ["facility", "level", "timestamp", "caller", "line"], [10, 8, 14, 10, 0];
    LinuxMalfind, "linux.malfind.full", "malfind.full", Integrity,
        "检测可疑可执行／可写或匿名 VMA 并输出十六进制预览与反汇编；支持脏页展开与导出",
        ["PID", "Process", "Start", "End", "Path", "Protection", "Hexdump", "Disasm", "File output"], [6, 16, 18, 18, 0, 6, 0, 0, 16];
    LinuxMountinfo, "linux.mountinfo.full", "mountinfo.full", Files,
        "按挂载命名空间去重列出完整 mountinfo（设备号、挂载选项、共享组、超级块选项）",
        ["MNT_NS_ID", "MOUNT_ID", "PARENT_ID", "MAJOR:MINOR", "ROOT", "MOUNT_POINT", "MOUNT_OPTIONS", "FIELDS", "FSTYPE", "MOUNT_SRC", "SB_OPTIONS"], [12, 8, 9, 11, 14, 0, 18, 12, 10, 18, 14];
    LinuxPagecacheFiles, "linux.pagecache.files", "pagecache.files", Files,
        "列出页缓存 inode 完整元数据（挂载点、设备号、类型、权限、三组时间戳）；支持类型与路径筛选",
        ["SuperblockAddr", "MountPoint", "Device", "InodeNum", "InodeAddr", "FileType", "InodePages", "CachedPages", "FileMode", "AccessTime", "ModificationTime", "ChangeTime", "FilePath", "InodeSize"], [18, 16, 8, 10, 18, 6, 8, 8, 11, 26, 26, 26, 0, 10];
    LinuxPagecacheInodePages, "linux.pagecache.inode_pages", "pagecache.inode_pages", Files,
        "枚举指定 inode 的驻留页缓存（XArray/RadixTree）并支持按路径或地址导出文件内容",
        ["PageVAddr", "PagePAddr", "MappingAddr", "Index", "DumpSafe", "Flags", "Output File"], [18, 18, 18, 8, 8, 18, 0];
    LinuxPagecacheRecoverFs, "linux.pagecache.recover_fs", "pagecache.recover_fs", Files,
        "统计并可选从页缓存批量恢复常规文件内容（受 256 MiB 累计上限保护）",
        ["SuperblockAddr", "MountPoint", "Device", "InodeNum", "InodeAddr", "FileType", "InodePages", "CachedPages", "FileMode", "AccessTime", "ModificationTime", "ChangeTime", "FilePath", "InodeSize", "Recovered FileSize"], [18, 16, 8, 10, 18, 6, 8, 8, 11, 26, 26, 26, 0, 10, 14];
    LinuxBash, "linux.bash.full", "bash.full", Process,
        "按标准 4 列恢复 bash 进程命令历史；支持 PID 列表筛选",
        ["PID", "Process", "CommandTime", "Command"], [6, 16, 24, 0];
    LinuxElfs, "linux.elfs.full", "elfs.full", Memory,
        "列出进程 ELF32/ELF64 内存映射并支持 PID 列表与可选段导出",
        ["PID", "Process", "Start", "End", "File Path", "File Output"], [6, 16, 18, 18, 0, 16];
    LinuxLibraryList, "linux.library_list.full", "library_list.full", Memory,
        "按标准列顺序列出进程共享库加载地址与路径；支持 PID 列表筛选",
        ["Name", "Pid", "LoadAddress", "Path"], [16, 6, 18, 0];
    LinuxIpAddr, "linux.ip.addr.full", "ip.addr.full", Network,
        "列出各网络命名空间接口索引、MAC、混杂状态及 IPv4/IPv6 地址",
        ["NetNS", "Index", "Interface", "MAC", "Promiscuous", "IP", "Prefix", "Scope Type", "State"], [12, 6, 14, 18, 11, 0, 6, 10, 10];
    LinuxIpLink, "linux.ip.link.full", "ip.link.full", Network,
        "列出各网络命名空间接口状态、MTU、队列规则 Qdisc、Qlen 与标志",
        ["NS", "Interface", "MAC", "State", "MTU", "Qdisc", "Qlen", "Flags"], [12, 14, 18, 10, 6, 12, 6, 0];
    Fdsummary, "linux.fdsummary", "fdsummary", Files,
        "汇总进程文件描述符",
        ["PID", "Name", "Total", "Regular", "Sockets", "Pipes"], [6, 16, 8, 8, 8, 8];
    Iomem, "linux.iomem", "iomem", System,
        "查看物理内存资源范围",
        ["Name", "Start", "End", "Depth", "Flags", "Address"], [0, 18, 18, 5, 18, 18];
    Ioports, "linux.ioports", "ioports", System,
        "查看 I/O 端口资源",
        ["Name", "Start", "End", "Depth", "Flags", "Address"], [0, 18, 18, 5, 18, 18];
    Ptrace, "linux.ptrace", "ptrace", Process,
        "检查进程跟踪关系",
        ["Process", "PID", "TID", "TracerTID", "TraceeTID", "Flags"], [0, 6, 6, 10, 10, 18];
    KeyboardNotifiers, "linux.keyboard_notifiers", "keyboard_notifiers", Integrity,
        "查看键盘通知回调",
        ["Address", "Module", "Symbol", "Priority", "NotifierAddress"], [18, 16, 0, 9, 18];
    Procdump, "linux.procdump", "procdump", Process,
        "转储指定进程的可读内存",
        ["PID", "Name", "Start", "End", "Size", "SHA256", "File"], [6, 12, 18, 18, 12, 0, 0];
    Memdump, "linux.memdump", "memdump", Memory,
        "转储指定进程的地址范围",
        ["PID", "Name", "Start", "End", "Size", "SHA256", "File"], [6, 12, 18, 18, 12, 0, 0];
    Elfdump, "linux.elfdump", "elfdump", Memory,
        "导出进程中含 ELF 头的映射",
        ["PID", "Name", "Start", "End", "Size", "SHA256", "File"], [6, 12, 18, 18, 12, 0, 0];
    LinuxPslist, "linux.pslist.full", "pslist.full", Process,
        "列出活动进程及其地址",
        ["PID", "TGID", "PPID", "Name", "Address", "UID", "GID", "EUID", "EGID", "CreationTime", "FileOutput"], [5, 5, 5, 16, 18, 6, 6, 6, 6, 32, 12];
    ProcessSpoofing, "linux.process_spoofing", "process_spoofing", Integrity,
        "比较可执行路径、argv[0] 与进程名称，识别身份伪装线索",
        ["PID", "PPID", "Exe_Path", "Cmdline_Basename", "Comm", "Cmdline_Spoofed", "Comm_Spoofed", "Exe_Deleted"], [6, 6, 0, 20, 16, 16, 16, 12];
    Modxview, "linux.modxview", "modxview", Integrity,
        "对照模块链表、sysfs 与独立内存扫描，并解析 taint 标记",
        ["Name", "Address", "In procfs", "In sysfs", "In scan", "Taints"], [20, 18, 10, 10, 10, 0];
    ModuleExtract, "linux.module_extract", "module_extract", Integrity,
        "从指定 struct module 地址重建并导出模块 ELF",
        ["Base", "File Size", "File output"], [18, 12, 0];
    Kallsyms, "linux.kallsyms", "kallsyms", System,
        "枚举核心、模块、ftrace 与 BPF 的运行时符号",
        ["Addr", "Type", "Size", "Exported", "SubSystem", "ModuleName", "SymbolName", "Description"], [18, 5, 12, 10, 8, 20, 0, 0];
    LinuxPsscan, "linux.psscan", "psscan", Process,
        "独立扫描物理内存中的调度类指针，发现链表之外的任务",
        ["OFFSET (P)", "PID", "TID", "PPID", "COMM", "EXIT_STATE"], [18, 8, 8, 8, 18, 0];
    LinuxSockscan, "linux.sockscan", "sockscan", Network,
        "从 file-ops 与 sock destructor 指针独立扫描物理套接字",
        ["Sock Offset", "Family", "Type", "Proto", "Source Addr", "Source Port", "Destination Addr", "Destination Port", "State", "Filter"], [18, 12, 10, 12, 20, 12, 20, 12, 14, 0];
    VmaRegExScan, "linux.vmaregexscan", "vmaregexscan", Memory,
        "按字节正则扫描进程全部虚拟内存区域",
        ["PID", "Process", "Offset", "Text", "Hex"], [8, 18, 18, 40, 0];
    PsCallStack, "linux.pscallstack", "pscallstack", Process,
        "逐字扫描保存的内核栈，并查询运行时符号；不等同帧展开",
        ["TID", "Comm", "Position", "Address", "Value", "Name", "Type", "Module"], [8, 18, 10, 18, 18, 32, 6, 16];
    Fbdev, "linux.fbdev", "fbdev", System,
        "列举 fbdev framebuffer；可显式导出 PNG 或原始像素",
        ["Address", "Device", "ID", "Size", "Virtual resolution", "BPP", "State", "Filename"], [18, 20, 16, 12, 20, 6, 12, 32];
    WinVadRegExScan, "windows.vadregexscan", "vadregexscan", Memory,
        "按字节正则扫描 Windows 全部 VAD，保留缺页覆盖诊断",
        ["PID", "Process", "Offset", "Text", "Hex"], [8, 20, 18, 40, 48];
    WinDriverModule, "windows.drivermodule", "drivermodule", Integrity,
        "交叉核验驱动入口与已加载模块，列出未归属驱动及已知例外",
        ["Offset", "Known Exception", "Driver Name", "Service Key", "Alternative Name"], [18, 16, 28, 32, 36];
    WinDriverIrp, "windows.driverirp", "driverirp", Integrity,
        "扫描驱动的 28 个 IRP 派发入口及模块、精确符号归属",
        ["Offset", "Driver Name", "IRP", "Address", "Module", "Symbol"], [18, 24, 32, 18, 20, 36];
    WinKpcrs, "windows.kpcrs", "kpcrs", System,
        "枚举处理器 KPCR 与 PRCB，验证自指针和回指针",
        ["Offset", "PRCB Offset"], [18, 18];
    WinVadWalk, "windows.vadwalk", "vadwalk", Memory,
        "遍历 VAD 父子链接、虚拟范围与 pool tag，保留链路异常诊断",
        ["PID", "Process", "Offset", "Parent", "Left", "Right", "Start", "End", "Tag"], [8, 20, 18, 18, 18, 18, 18, 18, 6];
}
