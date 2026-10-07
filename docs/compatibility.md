# Windows 兼容范围与验收证据

[返回项目入口](../README.md) · [操作指南](usage.md)

## Windows 内存镜像分析

Windows 使用独立的 x86／x64／ARM64 地址翻译与对象解析器；具体容器、分页和验证范围见下方扩展阶段。RSDS 提供内核 PDB 的 GUID/age；符号从 Microsoft symbol server 精确下载，并在 Rust 中转换为 ISF。分析前验证内核 PE 身份、页表和 System 进程，避免按版本猜测结构。离线运行需要已准备的匹配 ISF；镜像始终留在本地。

```sh
zero symbols --image images/Win11Dump/Win11Dump.mem --download
zero analyze --os windows --image image.mem --plugin windows.pslist --output exports/processes.json
zero analyze --os windows --image image.mem --plugin windows.vadinfo --pid 1234 --output exports/vads.json
zero analyze --os windows --hive 0xffff800000000000 --key 'Software' --image image.mem --plugin windows.printkey --output exports/registry.json
zero dump --os windows --image image.mem --mode range --pid 1234 --start 0x100000 --end 0x101000 --dump-dir exports/range --output exports/range.json
```

`--hive` 使用 `windows.hivelist` 返回的虚拟地址。运行 `zero --help` 和子命令帮助查看参数。MCP 的 `zero_analyze` 提供 `os`、`pid`、`hive`、`key`；`zero_dump` 支持 Windows `process`、`range`、`pe`。TUI 顶部提供可直接点击的 Linux／Windows／自动系统按钮，当前选择高亮；也可按 `F6` 或点击底部系统按钮选择。选 Windows 后立即显示对应插件，更换镜像会保留手动选择。自动模式在选用镜像后检查 Linux 内核 banner、Windows PDB 标识或转储容器格式，并切换插件列表；点击“自动”可重新识别当前镜像。未识别时提示手动选择。TUI 插件名省略 `windows.` 前缀，CLI／MCP 仍使用完整插件标识。`P` 编辑适用参数，F7 展开 Windows 高级配置；保存后等待 Ctrl+R，Dump 提供 PE 模式。

插件包括 `windows.systeminfo`、`pslist`、`pstree`、`cmdline`、`modules`、`dlllist`、`vadinfo`、`handles`、`malfind`、`netscan`、`hivelist`、`printkey`、`psscan`、`psxview`、`procdump`、`memdump`、`pedump`（名称均带 `windows.` 前缀）。`malfind` 标记可疑的可执行内存区域，不直接判定恶意；pool 扫描和交叉视图也不直接判定隐藏进程。

结果导出新增 `system` 与 `kernel_identity`，兼容旧历史 JSON。时间字段为 FILETIME 十进制 100 ns ticks（1601 UTC 起）；`physical:` 表示物理地址，其余对象地址为虚拟地址。缺页、损坏链表和不可解析字段通过 `complete: false` 与 `diagnostics` 报告，部分结果不会进入成功缓存。转储使用原子写入及 SHA256 清单，单次累计上限 256 MiB。

公开验收镜像：[Windows 10 build 15063](https://www.osforensics.com/downloads/WinDump.zip)、[Windows 11 build 22000](https://www.osforensics.com/downloads/Win11Dump.zip)。下载解压到 `images/` 并准备符号后运行 `make windows-acceptance`。`examples/verify_windows.rs` 可在共享分析会话中导出所有非转储插件供独立参考工具比较；Python/Volatility 只用于验证，不是运行依赖。样本包含断裂的进程链表，正常输出应保留不完整标志。

边界：真实镜像验收覆盖 Server 2003 SP0／2008 SP1 x86、Server 2012／2012 R2 和 Windows 7 SP1／10／11 x64 RAW，以及 Windows 10 build 19041／Server 2019 build 17763／Server 2022 build 20348 bitmap crash dump。其他架构、用户 minidump、注册表分段值、外部分页和休眠新增路径主要依赖合成测试；内核 summary 小型转储仅提供头部元数据，triage 转储支持保存的内核虚拟范围和上下文，不能宣称 Windows 7–11 全架构的所有插件均已验证。压缩 store 需要私有元数据，ARM64 store 尚不支持；未知容器、布局和缺页均明确报告。

参考交叉检查：准备独立 Volatility 3 v2.28 符号与 JSON 输出后，运行 `python3 tests/reference/windows.py /tmp/zero-win11- /tmp/zero-ref-win11-`（Windows 10 同理）。脚本逐字段检查共有记录，并分别报告覆盖范围；参考工具读不到的字段和缺失记录不会被当作相等的证据。

## Windows 扩展阶段

多架构基础提供 `--arch auto|x86|x64|arm64`，MCP 对应 `arch`，TUI 的 Windows 参数页可选择架构。指针和 PDB 机器类型必须一致；架构冲突明确报错。x86 普通／PAE、ARM64 4 KiB 页表有合成测试；Server 2003／2008 x86 和 Server 2012／2012 R2／Windows 7／10／11 x64 有真实 RAW 验收；不应据此宣称所有架构的所有插件已完成。

容器阶段新增 PAGE/DUMP（x86）与 PAGE/DU64（x64/ARM64）的物理 run 表、SDMP/FDMP 位图，以及 MDMP 的 MemoryList/Memory64、模块、线程栈和系统元数据读取。内核 summary 小型转储开放头部信息；triage 转储开放故障上下文、保存的驱动记录和内核虚拟范围；用户态 minidump 开放进程范围的模块、范围/进程/PE 导出，需要文件记录 PID。它不提供系统进程列表或内核模块列表。缺失地址保持缺页；未知布局不会按 RAW 读取。

进程兼容阶段增加 WOW64 32 位 PEB、命令行和 DLL 链表读取，`windows.cmdline` 与 `windows.dlllist` 新增 `View` 列（`native` / `wow64` / `minidump`）；PE32 和 PE32+ 使用统一节重建。注册表 `db` 分段大值按分段索引重建并校验计数、重复项与实际长度，当前值大小上限仍为 1 MiB。上述新增路径包含合成测试；x86／ARM64 的全插件覆盖仍需真实镜像验收。

新增公开 crash dump 验证来源：https://mirror.nju.edu.cn/gentoo/distfiles/e4/volatility3-win-10_19041-2025_03.dmp.gz 。Windows 10 build 19041 的 FDMP bitmap 容器可直接以 gzip 导入，已解析出 120 个完整进程记录。

网络阶段优先读取精确 tcpip.sys PDB 的类型；缺少类型时使用带来源的架构／驱动版本布局。字段宽度、对象尺寸及 pool 对齐按架构解析，未知版本不会选择最近版本。Windows 7–10 x86/x64 的声明式布局通过字段边界测试；仅版本系列匹配的结果带未验证身份诊断，不写成功缓存。ARM64 当前需要可用的精确驱动类型。公开 Windows 10 build 15063、19041 与 Windows 11 build 22000 已按精确驱动身份验证；19041 crash dump 的 108 条网络记录与独立 Volatility 3 结果一致（84 组去重连接）。

外部分页参数为可重复的 `--pagefile INDEX=PATH` 和 `--swapfile PATH`；MCP 对应 `pagefiles: [{"index": 0, "path": "..."}]` 与 `swapfile`。只使用显式提供的同次采集附件。pagefile 索引由调用者指定，swapfile 必须通过精确内核符号唯一验证索引；不会猜测默认索引或搜索相邻文件。读取支持 software PTE 和分页页表，附件使用只读文件描述符，分析前后验证摘要及文件状态，结果记录实际读取页的文件偏移；摘要参与缓存键。

压缩 store 路径要求精确 `SmGlobals`、分页文件全局符号及 SMKM 类型，以及已验证的虚拟分页索引。当前实现 Windows 10 x86/x64 的页键、两级 B-tree、chunk/record 链、owner 地址空间和原生 XPRESS 解压，并限制递归、循环、索引、输入与输出长度。公开 Microsoft PDB 往往缺少这些私有元数据，缺少时仍报告缺页。该路径目前仅有合成端到端验证，恢复时结果会标为部分；Windows 11 x64 已知 build 22000／22621／22631／26100 支持 store 读取，22621／22631／26100 读取 SmPa 间接管理器，26100 使用原生 LZ4；未知 build 和 ARM64 store 明确报不支持。XPRESS Huffman 使用固定版本的纯 Rust `xpress-huffman`，不调用 Windows API 或外部分析程序。

休眠阶段新增 Windows 7 range array 和 NT6.2+ restoration set 物理页映射，支持有页索引的 full／Fast Startup 文件、普通 XPRESS 与 XPRESS Huffman 块。文件头指针宽度、恢复集合页数、解压长度和物理范围均校验，解压块缓存限 8 MiB；损坏块形成明确缺页并记录文件偏移。已知 Windows 10 头部的 `Hiberboot` 标记用于提示内核会话范围，不能从文件大小推断 full/reduced 类型。恢复后的 WAKE 或未知头部只提供能验证的信息。当前休眠路径仅经合成测试（含内核引导）验证，所有结果明确标为部分，尚无真实 hiberfil 验收。

Windows 10 RAW 样本额外验证了 4 个 WOW64 进程（PID 4428、5684、5932、6492）的命令行和 210 条兼容视图 DLL；共有 DLL 记录与独立参考工具没有字段冲突。

旧版对象兼容使用 ISF 选择 LDR 模块结构、VAD 根／子节点、原始或编码句柄指针；x86 句柄表采用 1024 指针扇出和 8 字节 pool 对齐。transition PFN 和 prototype 地址按架构解码；现代 nonswizzled 分页偏移依赖精确 `MiState.Hardware.InvalidPteMask`，缺少私有元数据时不猜测掩码。

兼容改动后再次通过 3 项 Windows 与 4 项 Linux 真实镜像验收。Windows 10／11 共有句柄分别为 43,438／49,658 条，类型、对象地址和访问权限与独立参考工具无冲突；句柄名称的设备路径和 PID 注释表示不同，不计入该一致性结论。参考脚本现包含这三项句柄字段检查。


## Windows 第二轮扩展

新增 `windows.threads`、`windows.envars`、`windows.svcscan`、`windows.driverscan`、`windows.drivercheck`、`windows.autoruns`、`windows.cmdscan`、`windows.consoles` 和 `windows.crashinfo`，CLI、MCP 和 TUI 共用插件目录。线程／环境变量支持 PID 筛选；环境变量保留 native/WOW64 视图及驱动器变量。线程的 ExitTime 仅在符号中的 Terminated 标志置位时解释，异常时间保留诊断；模块归属只使用已读取的模块范围。

驱动扫描校验对象类型、尺寸、地址范围以及 DRIVER_EXTENSION 回引用；`drivercheck` 显示初始化、卸载及 28 个 IRP 分派函数的模块归属，地址位于其他模块本身不表示恶意。扫描只能覆盖保存且可验证的对象，不保证恢复已释放对象。

服务扫描读取 services.exe 的运行状态和二进制路径；`--pid` 在该插件中筛选服务管理宿主。当前声明布局覆盖 Server 2003 至 Server 2025、Windows 7 至 Windows 11 的已列明 x86／x64 构建，映射见 `src/windows/user_layouts.json`；PE 版本不可读时，仅已声明的精确内核构建可采用降级布局，并明确标为部分。控制台／命令历史布局覆盖已声明的 conhost.exe x64 build 17763／18362／19041／20348／22000／22621 及部分修订版本；未知构建或修订明确诊断；每个宿主扫描最多 128 MiB。布局事实来源于 [Volatility 3 v2.28 的服务与控制台符号定义](https://github.com/volatilityfoundation/volatility3/tree/v2.28.0/volatility3/framework/symbols/windows)，运行时不执行 Python。控制台输出当前为标题及历史缓冲元数据，不包含屏幕文本；现有真实 RAW 样本没有可验收的支持版本控制台记录。

`autoruns` 输出 Run/RunOnce、Winlogon、IFEO 和当前 ControlSet 的服务配置原始值，支持 `--hive` 限定；不会展开环境变量或把所有值判为恶意，也不涵盖所有持久化机制。现代 hive 同时存在新旧 HMAP 字段时优先使用 PermanentBinAddress/BlockOffset；已验证的 Registry 进程映射用于读取其用户地址中的 hive 页。

`crashinfo` 可直接读取容器中的故障码、异常地址和实际保存的控制／整数寄存器组（暂不解析 FP／SIMD／debug 寄存器），无需完整内核符号。PAGE triage 转储支持 x86／x64／ARM64 的虚拟数据块、原始栈范围、异常记录和保存的驱动清单，均有合成测试；调用栈不自动展开。`windows.modules` 在 triage 上只列出保存记录；范围转储使用保存的虚拟地址，沿用统一接口时 `--pid 0` 表示内核范围，实际不建立进程归属。未保存范围报缺页，不补零。summary 类型仍只开放头部。

公开用户 minidump 验收样本来自 [rust-minidump testdata/test.dmp](https://github.com/rust-minidump/rust-minidump/blob/main/testdata/test.dmp)，Windows XP x86，SHA256 `24b0ea7794b2d2523c46c9aea72c03ccbb0ab88ad76d8258d3752c7b71d233ff`；保存到 `images/rust-minidump-test.dmp` 后随 `make windows-acceptance` 验证异常 `0xc0000005`、地址 `0x40429e` 和三组上下文。合法的重复 UnusedStream 被忽略，非 Windows 平台不会按 Windows minidump 分析。

架构与恢复改动包括 ISF 指针宽度、注册表目录指针宽度、prototype PTE 链指向显式分页／压缩来源的读取，以及循环和深度限制。休眠现有损坏块／保存页／取消与源文件变化测试继续执行；尚未取得可核验的真实休眠样本。ARM64 压缩 store 缺少可证实的布局和端到端样本，继续明确报不支持；本轮不增加推测布局。

新增插件可通过 `examples/verify_windows.rs IMAGE PREFIX PLUGINS` 单独导出（PLUGINS 为逗号分隔的完整插件名）。`tests/reference/windows_artifacts.py` 对比独立 Volatility JSON 导出中的共有线程、native 环境变量、驱动和服务字段，同时报告覆盖差异；不将缺失记录或参考工具不可读字段视为一致性证据。

新增插件独立复核：Windows 10 共有线程 1,637 条（对象／起始地址）、native 环境变量 3,679 项（值）及驱动 136 个（名称／范围）均无字段冲突；Windows 11 恢复的 3 个启动项值也与独立注册表读取一致。共有记录一致不表示完整覆盖；本地样本的断链、缺页和未验证布局诊断继续保留。

## Windows 插件与版本兼容矩阵

新增 `windows.callbacks`、`windows.unloadedmodules`、`windows.filescan`、`windows.mutantscan`、`windows.getsids`、`windows.connscan` 和 `windows.sockscan`，CLI、MCP 与 TUI 共用目录。TUI 显示短名称，自动系统识别继续按镜像标识切换插件。

`getsids` 读取进程令牌 SID，支持 PID 筛选，仅给已知内置 SID 标注账户名称。`callbacks` 当前读取进程／线程／镜像加载及注册表回调；没有覆盖参考工具的所有回调类别。`unloadedmodules` 读取已卸载驱动环形记录。`filescan`／`mutantscan` 校验 pool、对象结构和对象类型，只输出能够反向映射并验证的对象；分别保留物理与虚拟地址，不能宣称恢复了所有已释放对象。未知名称或损坏记录保留部分结果诊断。Server 2003 使用 NT5 `connscan`／`sockscan`；NT6+ 使用 `netscan`，不会跨代套用布局。

矩阵按插件和架构记录四级证据。**真实**仅代表列出的样本构建与容器；**合成**验证解析路径或指针宽度，不能证明该系统的完整布局；**待验证**缺少实测证据；**不支持**没有对应解析模型。零条扫描结果不作为恢复能力的真实验证。具体插件、样本哈希、精确 PDB 与范围见 [机器可读矩阵](../src/windows/compatibility.json) 和 [验收基线](../tests/fixtures/windows.json)。Server 2003 与 R2 共用内核构建，系统身份会保留歧义；Server 2025 与 Windows 11 的 26100 使用有效的 ProductType 区分。所有版本仍要求精确符号，未知构建不会选择最近版本。

<!-- windows-compatibility:start -->
| 系统 | 构建 | 架构：真实 / 合成 / 待验证 / 不支持插件数 | 真实样本范围 |
| --- | --- | --- | --- |
| Windows Server 2003 | 3790 | x86: 22 / 3 / 5 / 3; x64: 0 / 8 / 22 / 3 | 3790 x86 raw |
| Windows Server 2003 R2 | 3790 | x86: 0 / 8 / 22 / 3; x64: 0 / 8 / 22 / 3 | 待采集 |
| Windows Server 2008 | 6001, 6002 | x86: 14 / 0 / 15 / 4; x64: 0 / 6 / 23 / 4 | 6001 x86 raw |
| Windows Server 2008 R2 | 7600, 7601 | x64: 0 / 6 / 23 / 4 | 待采集 |
| Windows Server 2012 | 9200 | x64: 14 / 0 / 15 / 4 | 9200 x64 raw |
| Windows Server 2012 R2 | 9600 | x64: 14 / 0 / 15 / 4 | 9600 x64 raw |
| Windows Server 2016 | 14393 | x64: 2 / 6 / 23 / 2 | 14393 x64 kernel-triage |
| Windows Server 2019 | 17763 | x64: 14 / 1 / 16 / 2 | 17763 x64 kernel-crash |
| Windows Server 2022 | 20348 | x64: 14 / 1 / 16 / 2 | 20348 x64 kernel-crash |
| Windows Server 2025 | 26100 | x64: 0 / 6 / 25 / 2 | 待采集 |
| Windows 7 | 7600, 7601 | x86: 0 / 6 / 23 / 4; x64: 14 / 0 / 15 / 4 | 7601 x64 raw |
| Windows 8 | 9200 | x86: 0 / 6 / 23 / 4; x64: 0 / 6 / 23 / 4 | 待采集 |
| Windows 8.1 | 9600 | x86: 0 / 6 / 23 / 4; x64: 0 / 6 / 23 / 4 | 待采集 |
| Windows 10 | 10240, 10586, 14393, 15063, 16299, 17134, 17763, 18362, 18363, 19041, 19042, 19043, 19044, 19045 | x86: 0 / 6 / 23 / 4; x64: 14 / 0 / 17 / 2 | 15063 x64 raw, 19041 x64 kernel-crash |
| Windows 11 | 22000, 22621, 22631, 26100, 26200 | x64: 13 / 0 / 18 / 2 | 22000 x64 raw |
<!-- windows-compatibility:end -->

表格由 `python3 scripts/windows_compatibility.py` 生成；`--check` 检查同步状态。构建列表表示识别目标，不能解释为每个构建和插件都已通过真实验收。RAW 和内核 crash 是本轮优先范围，休眠／用户 minidump 沿用既有受限支持；ARM64 沿用既有范围，不计入本轮 x86／x64 矩阵。

新增公开样本：[NIST Server 2003 基础内存镜像](https://cfreds-archive.nist.gov/mem/Basic_Memory_Images.html) 的 `boomer-win2003-2006-03-17.img`，以及 [InCTF Notch It Up 发布页](https://blog.bi0s.in/2019/09/24/Forensics/InCTFi19-NotchItUp/) 的 Windows 7 SP1 `Challenge.raw`。按基线路径保存后运行 `make windows-acceptance`。Server 2003 的精确 PDB 从微软返回 HTTP 404 时，在线模式自动按需查找 [Volatility 官方符号包](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip) 中相同 PDB 名称、GUID/age 的 ISF，校验后缓存供离线复用；不接受临近版本替代。镜像与符号不提交仓库。

独立对比计数和不可读字段见 [参考基线](../tests/fixtures/windows_reference.json)。独立比较使用 `python3 tests/reference/windows_compatibility.py NATIVE_PREFIX REFERENCE_PREFIX PLUGINS`，PLUGINS 为逗号分隔短名称；Windows 7 的 pool 参考地址使用 `--pool-space physical`。共有可读字段无冲突：Server 2003 的 22 个进程与 132 组 SID；Windows 7 的 53 个进程、705 组 SID、82 组网络连接、3,231 个文件对象和 403 个互斥对象；Windows 10 的 1,662 组 SID、16 个卸载模块、14 个本实现覆盖的回调、32,261 个文件对象和 765 个互斥对象。名称不可读字段单独统计，不算一致证据；卸载时间比较到参考输出的整秒精度。服务比较仅确认 Windows 7 的 58 条共有记录，不能证明全部服务均已恢复。缺页、断链、声明布局降级及未验证路径继续保留部分结果诊断。

## Windows Server 实测扩展

新增 Server 2008 SP1 x86 build 6001、Server 2012 x64 build 9200、Server 2012 R2 x64 build 9600 的 RAW 验收，以及 Server 2019 x64 build 17763、Server 2022 x64 build 20348 的 SDMP type 6 内核 crash 验收。来源分别为 [Sam Bowne 公开教学镜像](https://samsclass.info/121/proj/p5-Vol.htm)、[公开 PSExec 活动样本目录](https://memoryforensic.com/memory-dumps-collection-volume-1)、[DFIR Madness 的 DC01-memory.zip](https://dfirmadness.com/the-stolen-szechuan-sauce/) 、[Server 2019 发布者的故障讨论](https://superuser.com/questions/1824128/windows-server-2019-blue-screen-hal-initialization-failed) 和 [Server 2022 发布者的故障讨论](https://www.reddit.com/r/sysadmin/comments/11n4baa)。真实内核身份以精确 PDB、构建和有效 ProductType 核验，样本哈希与每个插件的行数／完整状态记录于验收基线。

这批样本修复了三项实际兼容问题：旧 PE32 PDB 符号的 C 调用约定修饰、Windows 8 的 41 位句柄对象指针符号扩展，以及旧 AVL 节点的带标记父指针校验。后者阻止损坏树枝扩展到不相关的内存；Windows 7 回归样本的一个父指针不一致分支因此被排除，VAD 基线从 7,325 条调整为 7,265 条，并保留诊断。PDB 转换器版本升级会从已缓存的精确 PDB 重建 ISF；离线模式仍可使用这些本地缓存。

另有 [发布者标为 Server 2016 的小型内核转储](https://www.reddit.com/r/sysadmin/comments/kmmgs8)，头部确认 x64 build 14393，仅验收故障信息、实际保存的寄存器与 162 个模块。它没有可验证的 ProductType，不作为完整 Server 2016 内核插件证据。真实文件把相同栈字节存储于不同文件偏移；容器现在逐字节验证重叠内容，保留可读取的非重叠尾部，冲突内容仍报错。复核命令：`python3 tests/reference/windows_triage.py images/server2016-triage.dmp /tmp/zero-server2016-`。

独立 Volatility 3 2.28 的插件复核可用 `tests/reference/windows_server.py`：Server 2008 的稀疏 PAE 页表使用 `--pae-dtb 0x122000 --kernel-base 0x8183a000`，Server 2019／2022 type 6 位图使用 `--bitmap-type6`。适配器只显式提供页表或启用已有的位图读取路径，不修改样本或符号字段。共有记录字段比较见 `tests/reference/windows_compatibility.py` 与参考基线。Server 2012 的独立句柄插件返回零条，不能声称句柄已交叉验证；其原生指针恢复另外有位宽测试与实测记录。

Server 2012 R2 的 7,612 组共有网络连接一致，但参考工具还输出 2 组 UDP 通配连接；相应 LocalAddr 指针不符合规范地址，本工具拒绝读取并保留诊断。用 `--pool-space physical --expected-missing-network 2` 检查该精确缺失基线；默认要求所有可读参考连接被恢复。缺失记录不会计作相等证据，其他插件的缺页与覆盖差异也继续保留。

Server 2003 R2、Server 2008 R2 和 Server 2025 尚无可取得并单独核验的本地真实样本，继续标为待验证；同内核的客户端测试不用于替代 Server 验收。Server 2016 除上述 triage 元数据外也仍需 RAW／完整内核 crash 样本。

Server 2022 的分散位图页段暴露出物理读取的线性查找开销；现已改为二分查找，并测试连续跨段、边界和空洞行为。该内核转储的服务用户页缺失，零条服务记录不作为恢复验证。

Server 2022 的独立复核已覆盖 198 个进程、2,602 组 SID、168 个模块、4,944 个线程、75,583 条共有句柄、50,177 条共有文件名称、892 个共有互斥对象、27,593 条 VAD 及全部 74 组可读参考网络连接。VAD 中 16,612 个不可读字段、互斥对象中 475 个不可读名称、97 条不可读参考网络记录不计为一致证据；实测 TCP/IP PDB 身份已单独加入允许列表，其他驱动身份保留原验证等级。

