# Volatility 能力对齐进度

对照固定为官方 Volatility 3 v2.28.2，提交
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`。范围包括 Linux 和 Windows，
不包括 macOS 分析。Zero 继续使用原生 Rust；Python/Volatility 只用于开发时差分测试。
目前**尚未完成全面对齐**。

[冻结清单与验收工具](../tests/reference/parity/README.md)记录了 135 个正式插件
（Linux 49、Windows 86）和 28 个弃用别名。名称相近、空表相同或共有字段相同都不算
插件完全对齐；必须检查参数、完整输出、异常和真实样本。现有 Zero 插件与官方插件的
候选映射都保留为未验证。

## 本次已验证

公开 Debian 3.2 样本 SHA256：
`8ce57b7c7b423173ce970fe8f51e7016c04ef1b4a5f73d5c5f1001d5c18780bc`。
使用同一份精确 ISF，两个引擎离线运行并逐字段比较：

| `linux.pslist.PsList` 用例 | Zero / Volatility 行数 | 11 个字段 |
| --- | --- | --- |
| 默认 | 133 / 133 | 全部一致 |
| `--threads` | 316 / 316 | 全部一致 |
| `--decorate-comm` | 133 / 133 | 全部一致 |
| 两个参数同时启用 | 316 / 316 | 全部一致 |
| `--pid 1` | 1 / 1 | 全部一致 |

[用例证据](../tests/reference/parity/evidence.json)保存摘要、映射和输出哈希；
[示例配置](../tests/reference/parity/debian.example.json)记录样本来源、镜像与符号哈希。
默认输出包含 TID、TGID、PPID、名称、地址、UID/GID/EUID/EGID、创建时间与文件输出状态。
Zero 保留既有列名和顺序，比较器明确映射官方字段。原 `pslist` 五列接口不变。
`linux.pslist` 是新入口别名。

```sh
zero --offline analyze --image images/linux-sample-1.bin --symbols /path/to/exact.json.xz \
  --plugin linux.pslist.PsList --threads --decorate-comm --output processes.json
```

MCP 的 `zero_analyze` 对应 `include_threads`、`decorate_comm` 布尔参数；TUI 参数窗口
在该插件下显示这两项。缺少凭据或时间字段时保留进程并标记部分结果，不填造值。
现代 `tk_core` 匿名结构也改为按 ISF 的实际类型读取，修复 Kali 启动时间读取失败。
`--dump` 行为、多 PID 列表、其他内核/架构和全部其余插件仍需实现或完成差分验收；
因此当前完整插件验收数仍为 0，不能将上述五项描述为整个 PsList 已对齐。

## 内核与任务链恢复

针对原诊断中“精确 banner/PID 0/swapper 通过，但任务链不一致”的情况，内核发现
增加独立 `init_files` 指针及虚实地址验证：只有独立证据成立，才允许带警告使用该页表。
缺少此符号时保留原有严格链表验证与受限的旧尾节点恢复。所有候选仍须唯一；不按
相近内核版本选择符号。

进程遍历分别沿捕获的 next/prev 链读取，每个对象独立校验。反向链可提供正向断点之外
的对象；不补写指针，不虚构缺页，重复 PID、断链、回指冲突和缺字段保留诊断与部分标记。
异常不再作为拒绝所有内核插件的唯一理由。合成回归覆盖损坏链、独立证据失败、重复 PID
与取消操作；这不能替代真实损坏镜像验证。

用户提供的 Debian 6.12.105 AVML/LiME 镜像未在本机，本次未验证它能够恢复。其 SHA256
未找到可确认的公开下载来源，不能拿旧 Debian 样本冒充该镜像。

## release 中的字符串

诊断里的 TypeScript、测试和 JSON-RPC 文本来自镜像扫描命中的内存字符串，不能据此
判断发布包包含这些文件。当前打包脚本明确只收录原生可执行文件、README 和 TUI 文档；
参考框架、测试工具和样本不进入发布包。内存中的文件页缓存/进程数据可能保留源码，
应过滤身份候选和诊断展示，不能清改取证镜像。完整候选过滤已经保留在引擎中。

## 回归验证边界

本次 Debian 的基础/扩展字段与定向转储回归通过，Kali ARM64 的既有字段基线也通过。
Kali 的扫描用例显式提供 ELF 模式，x86 专用 IDT 插件在 ARM64 上验证明确拒绝。
Windows 本地可用样本的 11 项回归通过（含精确符号准备后复跑的 Windows 10 bitmap
crash），Server 2012 R2 缺少解压后的样本，未运行。上述是 Zero 自身的回归，不能替代
针对固定 Volatility v2.28.2 的全插件差分验收。发布包通过空 PATH 启动检查。

## 后续批次：ProcessSpoofing（native-30）

[实施计划](volatility-implementation-plan.md)已先行写入仓库。新增正式入口
`linux.malware.process_spoofing.ProcessSpoofing`（别名 `linux.process_spoofing`），
CLI/TUI/MCP 通过公共插件描述使用；比较 exe_file 路径、argv[0] basename 与 comm。
包含 15 字符名称截断、已删除文件标记和进程进入 chroot 后仍引用根目录外可执行文件的情况。

固定参考版本的公开 Debian 3.2 差分：默认 133 行、`--pid 1` 1 行，全部 8 字段一致。
样本中 PID 1 和 2344 的 argv 页面缺失，参考输出 N/A；Zero 也输出 N/A，并额外保留
缺页诊断和部分结果标记。映射显式允许部分结果比较，未将它当作完整成功缓存。
合成测试另外验证真实身份不一致、空来源、删除标记、未以 NUL 结尾的有界参数和取消。

该插件仍未完成多 PID 参数、更多真实内核和伪装攻击样本的验收，因此不计为完整插件
对齐。截至该批累计 7 项正向全字段用例通过，完整插件验收数仍为 0。

## 后续批次：Modxview（native-31）

新增 `linux.malware.modxview.Modxview`（别名 `linux.modxview`），独立汇总 modules
链表、module_kset/sysfs 和分配器范围内的模块对象雕刻。链表中的对象也实际经过扫描，
“In scan” 不由链表存在推导。缺少或损坏某个视图时，其他视图已验证的对象仍保留，
无法确认的缺失值留空并标记部分结果，不将它输出为 false。

共享模块基础移入 `src/linux/modules.rs`，供既有 `check_modules`、`hidden_modules`
与新插件复用；支持旧式 module_addr_min/max、mod_tree 和现代 module.mem 布局。
扫描验证结构完整可读、回指、名称、状态和模块内存大小；已释放的空分配不算有效对象。
扫描上限、覆盖不足与缺少捕获页面均保留诊断。静态和内核 taint_flags 两种 taint 表均支持。
CLI `--plain-taints`、MCP `plain_taints` 和 TUI 的布尔参数可切换简写，并分别缓存。

同一公开 Debian 3.2 样本默认和 `--plain-taints` 两项均为 79 行，全部 6 字段与固定
Volatility 版本一致。参考用 null 表示无 taint；此字段的映射明确将该已知空值比较为
空文本，其余字段缺值规则不变，且此用例不允许部分输出冒充完整输出。

真实样本未包含隐藏/tainted 模块；链表外对象、失效分配、未知视图、现代分段内存和
动态 taint 标志目前只有合成回归。这些边界尚需真实样本差分，不能声称全插件已验收。

截至该批累计 9 项正向全字段差分用例通过，完整插件验收数仍为 0。

## 后续批次：ModuleExtract（native-32）

新增 `linux.module_extract.ModuleExtract`（别名 `linux.module_extract`），以及统一转储
模式 `kernel-module`。Base / Start 是 `struct module` 地址，不是模块代码起点，不需要 PID。
CLI 支持 `--base`；MCP `zero_dump` 使用 `mode: "kernel-module"` 和 `start`；TUI D 窗口
用 Alt+4 切换。入口均复用原子写入，不覆盖已有文件，不使用成功或部分分析缓存复用转储。

共享基础包括旧式/新式模块符号表读取、模块 section 属性读取，以及 SHA256 校验的
重建文件原子发布。支持 nsections 与新式属性组计数、旧式 name/mattr 与 battr 名称布局。
驻留节按参考规则排列，符号地址与类型按参考格式重建。节尺寸及部分索引来自启发式，
该输出不能当作原始磁盘 .ko。当前仅实现 x86_64 ELF；Linux 32 位重建与 ARM64 不在该入口
已实现能力中，不能据此声称完整插件对齐。

公开 Debian 3.2 样本的两个模块已逐字段、逐文件比较：

| 模块 | `struct module` 地址 | 文件字节数 | 文件 SHA256 与参考 |
| --- | --- | ---: | --- |
| scsi_mod | `0xffffffffa00230f0` | 198956 | 完全一致 |
| ata_generic | `0xffffffffa003a5a0` | 223686 | 完全一致 |

该样本中缺失的模块页按参考重建格式补零，Zero 明确标记部分结果，并在
`kernel_identity.module_extract` 中保留补零的内存地址、文件偏移、长度、文件路径、
SHA256，以及尾节是否采用 64 KiB 推断尺寸。普通虚拟内存读取不使用这种补零策略。
符号表不可读时不发布文件；取消、名称失效、参数缺失、覆盖保护和新式布局由回归覆盖。
真实现代内核、Linux 32 位及更多模块/损坏类型仍需补齐验收。

差分工具现在还比较非空输出文件集合、每个文件的长度和 SHA256。模块提取的证据缺少
一致的二进制文件时不能通过验收门禁，不能只比较输出文件名与大小。

截至该批累计 12 项正向全字段差分用例通过，其中 3 项同时核对二进制文件内容；完整插件验收数仍为 0。

另以 `0xffffa00230f0` 验证参考框架常见的 48 位截断地址：读取时补全 canonical 高位，结果行和文件名保留输入形式；提取内容同样逐字节一致。

## 后续批次：Kallsyms（native-33）

新增 `linux.kallsyms.Kallsyms`（别名 `linux.kallsyms`），接入 CLI/TUI/MCP。
`--core`、`--modules`、`--ftrace`、`--bpf` 可任意组合，不选则枚举全部来源，参数分别缓存。
实现核心压缩名称/地址表、模块 ELF 符号、ftrace 模块/跳板及新旧 BPF 符号链表。
继承原生只读地址空间与精确 ISF；不以 ISF 的静态符号列表代替运行时枚举。

核心支持绝对地址、两种相对偏移、别名尺寸及扩展压缩长度。相对模式须由至少两个不同
ISF 地址确认；无法确认时给出诊断。名称流损坏时可借助独立 markers 恢复下一块，并明确
记录跳过范围。模块导出表不可读时保留其他字段，导出状态为空；单个来源失败保留其他来源。
最多 100 万行、128 MiB 文本及 64 MiB 压缩解码输入；达到上限标记部分，不当作完整结果。
双相对地址配置与扩展长度依据 [Linux 6.8 核心实现](https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/kallsyms.c)，
补足固定参考仅假设 absolute-percpu 的范围；不将尚未通过差分的配置算作已对齐。

同一公开 Debian 3.2 样本与固定参考逐字段比较，全部 8 列一致：

| 用例 | 两端行数 |
| --- | ---: |
| 默认 | 34472 |
| `--core` | 24648 |
| `--modules` | 9824 |
| `--core --modules` | 34472 |

映射明确允许 Size/Exported 两端同时缺值，并单独统计数量；单边缺值仍不能通过，
普通缺值规则不变，且这四个用例要求 Zero 完整结果。名称/说明中的已知空文本也明确映射。
Kali ARM64 原生 `--core` 完整读取 53912 行，选择 unsigned-relative 模式（4 个地址命中），
并结合独立发现的重定位核对 `_stext`、`_etext`、`schedule`、`do_exit` 的运行时地址。
这是原生实际样本验证，不计入 Volatility 差分用例。

Ftrace/BPF 的正向对象、新式模块 typetab、导出表损坏、markers 恢复和相对配置目前有
合成回归；公开 Debian 用例中的 ftrace/BPF 没有正向对象，不能据此证明这两个来源完全
对齐。32 位内核、现代配置的全字段差分及更多损坏样本仍需补齐。

也尝试了固定参考框架对同一 Kali 样本运行 `--core`；本地执行在 `_bootstrap` 的
relative-base 读取处报 `TypeError: NoneType & int`，退出码为 1，没有可比较 JSON。
因此该样本只保留原生验证结论，不把参考执行失败算成差分通过，也不据此归因于单一配置。

目前累计 16 项正向全字段差分用例通过，完整插件验收数仍为 0。

## 物理任务扫描 PsScan（native-34）

新增共享物理指针扫描器：有界分块、4/8 字节指针、跨连续物理区段拼接、LiME 文件头隔离、
空洞不补零、命中去重、取消及覆盖统计。候选验证使用 ISF 物理字段读取；指针的目标由
调用方选择虚拟层。命中/输出/父对象读取上限均显式记录，不能把受限扫描报告为完整。

`linux.psscan.PsScan`（别名 `linux.psscan`）从 `_sched_class` 符号获得运行时指针，
独立扫描捕获物理内存，按官方 TID 和 exit_state 规则生成对象。输出物理地址、TGID、TID、
虚拟父对象的 TGID、comm 和退出状态。物理地址为唯一键，同 PID 的不同对象不会合并。
扫描命中不自动证明当前活动或恶意隐藏。

同一公开 Debian 3.2 镜像和精确 ISF，默认参数在两个引擎均输出 **321 条**，全部六字段
一致，无遗漏、额外或冲突行。Zero 扫描 536870912 / 536870912 字节，373 次指针命中、
321 个对象，无读取失败或资源上限，结果完整。可复现配置为
`tests/reference/parity/psscan.example.json`，全字段映射及二进制/输出/镜像/符号哈希已入证据表。

Kali 6.8.11 ARM64 原生实测扫描 130 个 LiME 区段、2141913084 字节，918 次指针命中、
873 个对象。扫描覆盖完整，无候选字段读取失败或上限；其中一个父对象不可读，PPID 按
参考规则显示 0，同时将结果标为部分，不进入成功缓存。此项仅为原生实际验证，未计入
Volatility 差分通过数。合成测试另覆盖未链接任务、四种退出状态、TGID/TID 区分、
虚拟父对象、物理空洞、跨块指针、重叠匹配、截断读取、资源停止及取消。

当前仅实现 64 位 PsScan；32 位、更多内核与真实损坏镜像的对等验收仍待补齐。
累计 **17 项**正向全字段差分通过，覆盖 6 个 Linux 插件；完整插件验收数仍为 0。
入口缺失清单现为 Linux 4 / Windows 30，已有入口仍需按参数、字段和异常矩阵验收。

## 物理套接字扫描 Sockscan（native-35）

新增区分物理嵌入字段和虚拟指针目标的套接字字段读取器，再实现
`linux.sockscan.Sockscan`（别名 `linux.sockscan`）。复用物理指针扫描基础，两个来源为
`file.f_op`（socket_file_ops / sockfs_dentry_operations）和 `sock.sk_destruct`（五种
析构符号）。file-ops 命中沿虚拟 dentry/inode/socket.sk 追踪，最后转换为物理 sock 地址。
来源独立于任务 fd 链表，按解析后的物理地址去重；缺失或损坏来源保留其他来源及诊断。

实现 Unix、IPv4/IPv6、Netlink、Packet、Vsock、XDP、Bluetooth，及 socket/reuseport
过滤器信息。当时 IPv6 端点通过内核虚拟层读取，端点不可读时保留其余字段并
标记部分结果；native77 已修正为实际固定参考规则。32 位仍未实现，罕见家族和
更多内核仍缺真实差分样本。

当时公开 Debian 默认运行：Zero 477 条，固定参考 404 条，默认严格比较**未通过**；
native77 已按实际生成器／地址方法修复，完整默认 404/404 通过，详见下方 native77。
以下保留当时的差异记录，不将旧基线写成默认对齐通过：

- 参考的 file-ops 分支未更新用于去重的物理地址，以 None 作为键，和 destructor
  来源出现一条重复 Unix 行。当时 Zero 按最终物理地址去重，没有保留该重复行。
- 当时将端点不可用主要归因于参考 inet_sock 的原始物理层读取。native77 进一步
  确认本批宿主的 AF_INET6 门槛先返回 None，这一旧归因不完整。12 个共有对象两端
  地址均不可用，而当时 Zero 能读取这些地址。参考随后以源地址不可用参与空对象过滤，
  排除的 74 个 IPv6 候选在 Zero 中保留。额外对象均为 UNCONNECTED，不能据此认定活动
  或隐藏连接。默认比较没有遗漏参考对象，差异报告保留 74 个额外对象、一组重复键及
  24 处单边地址不可用，不忽略这些差异来计算默认通过。

独立局部验收显式选择 AF_INET / AF_NETLINK：两端均 59 条、全部 10 字段一致。此范围
之外 Zero 418 行、参考 345 行明确记录为排除；原始产物不变。映射允许原生部分结果，
因为 442 个 file-ops 候选、17 个 destructor 候选无法完成读取（包括可能的非对象），
Zero 保留来源计数及诊断，不将扫描覆盖完整误报为所有候选验证完整。
空字段只在明确声明的列中将 N/A 映射为缺失，空字符串与缺失不合并。

Kali ARM64 原生扫描 130 个 LiME 区段、2141913084 字节，3265 次指针命中、1221 个对象。
物理覆盖完整，未触及上限；一处 destructor 候选缺页，结果标为部分并不写入成功缓存。
此项只计原生实际验证。合成测试覆盖两个独立来源、最终地址去重、不可读来源、虚拟
IPv6 目标、IPv6 缺页保留字段、cBPF/eBPF/reuseport、Netlink、Packet、Vsock、Bluetooth、
XDP、端口回退读取以及取消。

`make check` 通过（453 项 Rust、19 项 Python 测试），Debian/Kali 四项实际样本验收通过。
目前 18 项正向差分用例中 **1 项仅限上述 IPv4/Netlink 范围**；未限定行范围的正向用例仍为
17 项。涉及 7 个 Linux 插件，完整插件验收数仍为 0。入口缺失清单为 Linux 3 / Windows 30，
原完整 Linux/Windows 目标及已有入口的未验收边界保持不变。

## VMA 字节正则扫描 VmaRegExScan（native-36）

先新增原生 PCRE2 字节封装和共享驻留虚拟区域扫描器，再接入
`linux.vmaregexscan.VmaRegExScan`（别名 `linux.vmaregexscan`）。支持分组、前后查找、
命名反向引用、空与零宽匹配；搜索默认 DOTALL，显示时按固定参考重新进行不默认 DOTALL
的锚定匹配。Text 为 UTF-8 替换解码，Hex 比较完整原始字节，非截取共有字段。

扫描全部 VMA，合并相邻范围；物理不连续但虚拟连续的页面可以跨页匹配，缺页切断主体。
分块为 16 MiB、重叠 4 KiB，与固定参考的有限跨块模型一致。每进程驻留读取 256 MiB、
100 万次页面尝试，整次输出 10 万行 / 128 MiB；模式 4096 字节，匹配计数 100000、
深度 1000、匹配堆 8 MiB，每个分块主体累计 1000 万次自动 callout 工作计数；匹配中也可取消。触及上限保留此前结果并标记部分。上下文补零只用于显示，
不进入搜索；不可读字节与进程扫描覆盖分别记录在 `kernel_identity.vma_regex_scan`。

CLI `--pid` / `--pids` 在扫描前按 TGID 取并集，TUI 支持 PID 列表并保留正则空格，MCP
提供 pids/maxsize。模式、PID 参数及上下文长度均参与缓存身份。PCRE2 静态链接且不开启
UTF/UCP/JIT，原生包不依赖 Python 或外部 PCRE2 动态库；依赖许可随包分发。

公开 Debian 的六项逐字段比较通过：

| 用例 | Zero / 参考行数 | 验证 |
| --- | --- | --- |
| PID 1 普通匹配 | 2 / 2 | 全部五字段一致 |
| PID 1 lookbehind | 2 / 2 | 全部五字段一致，包含完整回退上下文 |
| PID 1 命名反向引用 | 2 / 2 | 全部五字段一致 |
| PID 列表 1、2344 | 6 / 6 | 全部五字段一致，两 PID 均有匹配 |
| 全进程搜索 | 403 / 403 | 全部五字段一致 |
| 单 PID 与列表并集 | 6 / 6 | 全部五字段一致 |

这些样本有大量不可读页面：PID 1 读取/扫描 712704 / 10903552 字节，另外 10190848 字节
不可读；PID 2344 读取/扫描 200704 / 17072128 字节，另外 16871424 字节不可读。Zero 显式
标记部分，而非以参考静默跳过页面证明无遗漏。因此映射允许有诊断的部分结果；这些通过
证明可读范围的结果一致，不证明所有用户内存均被扫描。

固定参考虽然声明 maxsize，输出代码仍读取 MAXSIZE_DEFAULT 128 字节。独立配置
`vmaregexscan-maxsize.example.json` 使用 maxsize=4：匹配位置/行数一致，Text 与 Hex 共
四处差异。Zero 实际应用参数，不将这项差异转换成通过，也不忽略这两个字段。

Kali ARM64 PID 1 搜索 ELF 魔数的原生实际验证得到 9 条；读取/扫描 9191424 / 24793088
字节，15601664 字节缺页，上下文没有补零；保留任务链父对象诊断和扫描缺页诊断，不进入
成功缓存。此项未计入参考差分。合成测试另覆盖跨页、跨块短尾、非 VM_READ 区域、缺页、
补零统计、资源停止、取消、空匹配推进，以及 TUI 列表/上下文参数和缓存身份。

PCRE2 不是完整 Python re 实现，罕见语法、零宽输出的完整差分矩阵、32 位、更多内核与
损坏样本仍需验收。`make check`、Debian/Kali 四项实际验收及本地空 PATH 原生包启动验证
通过。目前正向差分共 24 项，其中 1 项仍为 Sockscan 的显式局部范围；涉及 8 个 Linux
插件，完整插件验收数仍为 0。入口缺失清单现为 Linux 2 / Windows 30，完整目标不变。

## 保存栈字扫描 PsCallStack（native-37）

先加入共享的有界栈字扫描器与运行时符号区间索引，再接入
`linux.pscallstack.PsCallStack`。共享任务枚举按进程 PID 选择组长后展开线程，支持
单 PID、PID 列表并集和 `--unresolved`；CLI、MCP、TUI 与缓存身份同步支持。
独立 `PsList --threads` 回归为 316 / 316 行、全部 16 字段一致。

此插件从保存的 SP 开始线性读取非零栈字，**不是帧链展开**。按固定参考扫描 16 KiB
窗口，Position 包含零字位置；实际内核 THREAD_SIZE 未由配置证实，覆盖范围写入元数据。
运行时符号按 core、module、BPF、ftrace 优先级查询，重叠别名保持原始次序；核心符号
限制在代码段内，模块采用正长度 ELF 区间及模块分配范围。共享索引构建后以二分查询，
没有对每个栈字重新线性遍历全部符号。读取、输出、文本和覆盖报告均有上限，缺页保留
前缀并标记部分，取消可中断扫描与索引构建。

公开 Debian 的正向八字段差分：

| 用例 | Zero / 参考行数 | 范围 |
| --- | --- | --- |
| PID 2 | 6 / 6 | 未限定行范围 |
| PID 2，包含未解析值 | 341 / 341 | 未限定行范围 |
| PID 3874 的线程组 | 180 / 180 | 未限定行范围 |
| PID 2 与 PID 列表 3874 并集 | 186 / 186 | 未限定行范围 |
| 全任务的核心符号行 | 8120 / 8120 | 显式限定 Module=kernel，排除 Zero 342 行 |

当时默认全任务比较未通过：Zero 8462 / 参考 8120 行，342 条额外行均为模块符号归属；
没有遗漏参考行或共有字段冲突。PID 1 默认 38 / 37 行，含未解析值时两端均 383 行，
但 Name、Type、Module 有三处参考单边不可用。因此这三项不计入正向证据，完整默认输出
仍独立比较；摘要哈希和差异计数保存在 `pscallstack-known-differences.json`。
固定参考的模块范围计算源码包含 `value & mask + size` 的运算优先级问题，且旧内核
模块分配范围取自配置中的符号地址。当时尚未用直接方法向量确认全部差异的因果；
native78 已补这些向量并按实际地址查询门槛实现，全默认输出通过。Kallsyms 的
模块枚举／ELF 导出没有删除模块数据，PsCallStack --unresolved 仍保留原始非零栈字。

Kali ARM64 的原生 PID 1 实际验证读取 `thread.cpu_context.sp`，得到 1 条符号行。
任务页表不可读该保存的内核栈时，已验证的内核映射可读；回退来源、一次回退及原有任务
父对象诊断均保留，结果标为部分。这不是与参考的差分通过。32 位、更多内核、BPF/ftrace
实际栈命中及更多损坏场景仍需补齐验收。

`make check` 通过（474 项 Rust、19 项 Python 测试），Debian/Kali 四项实际样本验收通过。
累计 29 项正向差分，其中 2 项为显式局部范围，涉及 9 个 Linux 插件；完整插件验收数
仍为 0。入口缺失清单为 Linux 1（Fbdev）/ Windows 30，完整目标不变。

## Framebuffer Fbdev（native-38）

共享 packed-pixel / PNG 基础先独立提交，再接入 `linux.graphics.fbdev.Fbdev`（别名
`linux.fbdev`）。默认八字段与参考一致：Address、Device、ID、Size、Virtual resolution、
BPP、State、Filename。读取 num_registered_fb 和前 N 个 registered_fb 槽位（最多 32），
按 ISF 解码 fb_info、内嵌 fix/var 和 device.kobj.name。注册符号不可用、负计数、空槽、
重复对象、设备名缺页均显式诊断；设备名不可读保留对象，注册计数为零才是完整空表。

显式导出可用 `analyze --dump-dir`、`dump --mode framebuffer`、MCP zero_dump 的
framebuffer 模式、TUI D / Alt+5。Start 可选一个已注册 fb_info，PID/End 拒绝；没有选择器
时导出所有注册设备。新增共享流式证据写入器，累计 SHA256 和字节数、检查上限与取消，
最终不覆盖发布；模块 ELF 原有输出复用该写入器。PNG/RAW 缺页不补零，失败不发布文件，
同名文件报诊断而不替换。可选导出同时绕过结果缓存读写，真实样本测试先缓存列表，再导出，
最后确认列表缓存仍为 Disabled，不能用缓存命中代替一次导出。

PNG 使用小端 packed bitfields，RGBA/msb_right、无 alpha 不透明；按固定参考保留未缩放
颜色值并在 255 饱和，未实现 palette 转换。支持 8..64 位字节对齐像素，16 Mi 像素、
单缓冲与文件 256 MiB 上限，逐行读取、64 KiB IDAT 分块。grayscale >1 的 FOURCC 按原始
字节导出 RAW。零尺寸、错误位域或超限格式导出失败并标记部分，不输出伪造的黑色图像。

公开 Debian 样本的注册数量为 0，列表与导出两项都没有正向对象证据，不计为通过。
本地原始 Kali ARM64 样本读取到 1 个 1024×768、32bpp、stride=4096 的设备，原生完整
读取 3145728 字节像素并导出 16591 字节 PNG，SHA256
`2ef200e46715c3eb8e953007ca2d357229cd2a25f5b2a80b647c447d7a607bfe`。
该样本不公开分发，结果图像不进入仓库。固定参考的 LINUX_ARCHS 仅声明 Intel32/Intel64；
实际保存配置将此 ARM64 镜像建成 LinuxIntel，符号 mask 为 32 位，随后页表缺页，在输出
对象前退出。因此 Kali 两项真实样本差分不能成立，没有修改参考层或将它们计为通过。
摘要哈希与失败原因保存在 `fbdev-known-limitations.json`。

独立的、生成数据上的参考函数比较覆盖 RGB565、RGBA8、64 位通道（含 alpha、位翻转与
饱和）和 FOURCC RAW，共 7 项字节/完整 RGBA 像素一致。有行 padding 的第 8 项为显式
已知差异：参考按连续像素消耗缓冲，Zero 按 line_length 跳过 padding，保留正确的第二行。
这些只验证转换函数，不是实际镜像的完整插件验收，不计入原有 29 项差分证据。
运行方式与固定 Python/Pillow 测试依赖见差分目录说明。PNG 编码压缩字节不要求与 Pillow
完全相同，比较解码后的全部像素；RAW 比较完整字节。

`make check` 通过（481 项 Rust、19 项 Python 测试），另上述参考函数比较单测通过，
Debian/Kali 四项实际验收通过。原生插件现为 124 个（Linux 62 / Windows 62）。固定参考
Linux 49 个正式插件均已有对应入口；入口缺失清单仍有 Windows 30 个，已有入口仍需完整
参数、架构、损坏场景和真实非空样本验收。累计正向实际镜像差分仍为 29 项（2 项限定行
范围），涉及 9 个 Linux 插件，完整插件验收数仍为 0，完整目标保持不变。

## Windows VAD 正则 VadRegExScan（native-39）

新增 `windows.vadregexscan.VadRegExScan`（别名 `windows.vadregexscan`），复用已有 PCRE2
字节引擎与驻留范围扫描器。先共享上下文补零统计、独立非 DOTALL 锚定重匹配、Text/Hex
格式化，再接入 Windows。CLI/MCP/TUI 支持模式、PID 列表与 maxsize；Windows 缓存身份
包含列表与上下文长度，单 PID 和列表取并集后不能再被结果后置筛选截掉。会话测试分别
验证并集、单 PID、两种上下文长度与再次命中缓存，模式中的空格保持不变。

真实样本暴露并补齐两项基础：

- 大型保留 VAD 需要稀疏遍历。共享扫描器接受已确认不可映射区间；Windows 只有在读到
  零页表项时提供提示。非零软件 PTE、prototype、pagefile 和缺失表页不提供空区间提示，
  仍走原有恢复与逐页路径。跳过字节全部计入未读覆盖，不能作为零字节搜索。合成 512 GiB
  保留区间后仍读到驻留命中，页面尝试少于 3000 次。实际 PID 7688 请求范围
  2199629770752 字节，读取/扫描 113393664 字节，零页表项确认未映射
  2199482527744 字节，页面尝试 112843 次，未触及资源停止。
- 扫描不依赖富 VAD 文件名或保护字段。抽取共享树布局后，最小扫描遍历验证 pool tag、
  地址、范围、循环、深度 100 与对象上限。父链异常报告诊断，并继续独立验证带 tag 的
  子节点；无 tag 的根仅访问子节点，其他无 tag 对象不作为扫描范围。原有富 VAD 详情
  校验行为保留。另记录每个恢复命中的起始页来源，不把它当成整个跨页匹配的来源清单。

使用公开 OSForensics Windows 10 15063 样本，SHA256
`d58f62e92b8c4ef913ac09b2c36a10482034c10b88d0c154dead3aaaa49cf875`，精确
`ntkrnlmp.pdb/0C9CC659210046EC84231597DADFDB3B1`。两端使用同一份原生 PDB 转换 ISF，
因此这些用例验证提取器行为，不独立证明 PDB 类型转换正确。所有用例比较完整五字段，
不丢弃不一致行或只比较共有列：

| 用例 | Zero / 参考 | 验收 |
| --- | --- | --- |
| PID 7688 普通 MZ、lookbehind、命名反向引用，各一项 | 各 709 / 701 | 未通过：各 8 条额外行 |
| PID 列表 844/7688、单 PID 与列表并集，各一项 | 各 736 / 727 | 未通过：各 9 条额外行 |
| PID 356 | 4 / 3 | 未通过：1 条额外行 |
| PID 列表 356/468 | 31 / 30 | 未通过：1 条额外行 |
| 独立 PID 844 对照 | 27 / 26 | 未通过：1 条额外行 |
| 独立 PID 468 对照 | 27 / 27 | 全部五字段通过 |

上述八项未通过用例都没有遗漏参考行，也没有共有字段冲突；逐条匹配元数据证明全部
额外行恰好是 prototype 起始页恢复命中。固定参考扫描层只接受 present 或非 prototype
的 transition PTE；Zero 读取这些 prototype 页后保留结果，不删除它们制造默认一致。
这也不是隐藏内存的结论。父链/缺页诊断依然存在，正向 PID 468 用例允许显式部分结果，
证明所读范围字段一致，不证明整份镜像或全进程扫描完整。

独立 maxsize=4 用例使用 MZ 后接六字节的模式：Zero 709 / 参考 701，仍有 8 条 prototype
额外行，701 个共有记录的 Text/Hex 合计 1402 处差异。参考声明参数但仍固定读取 128 字节，
Zero 实际使用四字节上下文。此项继续失败，计数/原始输出摘要与其他差异保存于
`vadregexscan-known-differences.json`。x86、ARM64、更多 Windows 构建、全进程与更多损坏
样本、PCRE2/Python re 完整语法矩阵仍需验收，不能以这些用例关闭插件完整合同。

`make check` 通过（489 项 Rust、19 项 Python 测试）；Linux 六项正则全字段回归通过，
Debian/Kali 四项实际验收通过。可用的 11 项 Windows 实际回归通过；其中 bitmap 样本先前
因缺少主缓存中的精确 ISF 失败，使用已准备的精确符号复跑通过，补入缓存后整组通过。
Server 2012 R2 用例因本地原始样本未解包，本批未运行，不能计为通过。本地发布包检查
通过，包内不包含测试源码，空 PATH、无关工作目录下原生 TUI 可启动退出；没有发布版本。

原生入口现为 125 个（Linux 62 / Windows 63），固定参考缺失入口为 Windows 29 个。
正向实际镜像差分累计 30 项，包含 2 项显式局部范围，涉及 9 个 Linux 插件和 1 个 Windows
插件；完整插件验收数仍为 0。完整 Linux/Windows 对齐目标保持不变。

## Windows VAD 链接遍历 VadWalk（native-40）

新增 `windows.vadwalk.VadWalk`（别名 `windows.vadwalk`）。先将带 tag 的最小遍历抽成共享
访问器，输出对象地址、可用的父子字段、范围、tag 与访问统计；正则扫描收集范围，VadWalk
收集全部九字段。父字段按 ParentValue / u1.Parent 清除平衡位，旧版直接 Parent 保留原值；
x86 tag 位于对象前 4 字节，x64 前 12 字节。内部 End 为不包含边界，表中 End 减一，与参考
的最后一个可访问字节一致。支持单 PID、PID 列表并集及不筛选的全进程入口。

tag、地址、循环、深度 100 与每进程百万节点校验保留；父链异常不丢弃可独立验证的子节点。
无有效 tag 的根仅访问子节点，其他无 tag 节点不输出。未读链接显示 N/A，父字段缺失按进程
汇总诊断，不写成零。全局百万行 / 128 MiB 文本、65536 项覆盖报告上限，停止时保留前缀并
标为部分。合成用例覆盖九字段、父平衡位、直接 Parent、x86 四字节 tag、高 VPN、PID 并集、
缺字段、无效 tag、循环、访问器停止与中途取消；TUI 独立验证列表参数且不提供正则参数。

对固定参考的七项正向逐字段比较全部通过，无记录选择或字段删除：

| 样本与参数 | Zero / 参考行数 | 字段 |
| --- | --- | --- |
| Windows 10 15063 x64，全进程 | 16165 / 16165 | 全部九字段一致 |
| Windows 10，PID 7688 | 596 / 596 | 全部九字段一致 |
| Windows 10，PID 468 | 159 / 159 | 全部九字段一致 |
| Windows 10，PID 列表 468/7688 | 755 / 755 | 全部九字段一致 |
| Windows 10，单 PID 与列表并集 | 755 / 755 | 全部九字段一致 |
| Windows Server 2008 6001 x86，全进程 | 5229 / 5229 | 全部九字段一致，原生完整 |
| Windows 11 22000 x64，全进程 | 17405 / 17405 | 全部九字段一致 |

Windows 10 全进程保留 538 条、Windows 11 保留 67 条链路/覆盖诊断，原生结果为部分，
不进入成功缓存。映射显式允许有诊断的部分结果；行/字段一致不证明整份镜像完整，也不证明
VAD 树之外不存在对象。三个样本的计数加入实际回归基线，对应构建/架构的兼容记录标为
真实样本验证；没有推广为所有 Windows 构建均已验证。两端仍共用精确 PDB 转换 ISF，这些
用例不独立证明符号转换正确。Parent 等内核地址只做声明的 48 位掩码显示归一化，Start/End
按原始用户地址严格比较。

共享正则回归：PID 468 仍为 27 / 27 五字段一致；PID 7688 仍为 709 / 701，没有遗漏或
共有字段冲突，全部 8 条额外结果恰好来自 prototype 页恢复。后者继续失败，新的输出摘要与
来源验证保存在 `vadwalk-regex-regression.json`，不以共享代码重构掩盖差异。

`make check` 通过（494 项 Rust、19 项 Python 测试）；Debian/Kali 四项与本地可用的 11 项
Windows 实际回归通过。Windows 回归现在包含三份样本的新 VadWalk 计数；Server 2012 R2
原始样本仍未解包，此项本批未运行。本地发布包验证通过，仅检查原生包与空 PATH TUI，
没有发布版本或标签。罕见布局、其他版本、更多损坏/上限情形仍需完善完整插件合同。

原生入口现为 126 个（Linux 62 / Windows 64），固定参考缺失入口为 Windows 28 个。
正向实际镜像差分累计 37 项，含 2 项限定行范围，涉及 9 个 Linux 和 2 个 Windows 插件；
完整插件验收数仍为 0。完整 Linux/Windows 对齐目标保持不变。

Windows 全局符号类型公共基础（native41）：PDB 转换器升级为 pdb-native-6，保留可解析
Data 记录类型，同地址 Public/Data 合并顺序无关；地址冲突拒绝，类型冲突显式记录并禁止
读取变量大小。ISF 提供 symbol_size，不根据符号名称猜测宽度。旧派生缓存由精确 PDB
重建，不修改原始 PDB。实际 Win10/Win11 公共 PDB 中 KeNumberProcessors 和 KiProcessorBlock
仅有地址，没有可用 Data 类型；测试明确要求这些变量不能伪造类型，此基础本身尚未
解决处理器计数路径。三项合成测试及两份真实 PDB 确定性转换验证通过。
make check 通过（497 项 Rust、19 项 Python），Debian/Kali 四项与本地可用 Windows
十一项实际回归通过。本批没有新增插件，缺失入口仍为 Windows 28 个。

Windows KPCRs（native42）：新增 `windows.kpcrs.KPCRs`（别名 `windows.kpcrs`），输出 Offset、
PRCB Offset。共享有界处理器根枚举供 KPCRs / Timers 使用：优先按精确符号读取共享数据
ActiveProcessorCount，支持超过八位的组计数；其次使用可用全局类型，旧系统按八位兼容
变量读取。只有兼容计数且可能存在处理器组时标记部分覆盖；拒绝零、超过 2048 的计数、
类型冲突、重复或不可读根。各 CPU 独立诊断，取消直接终止，不将部分结果写入成功缓存。
KPCR 从符号声明的内嵌 Prcb/PrcbData 投影，并验证 Self/SelfPcr 及 CurrentPrcb/Prcb 回指，
不将指针字段偏移当作结构偏移。ARM64 明确不支持 KPCRs，其他未测版本仍标为待验证。

原生 PDB 转换器升级 pdb-native-7，补齐 Windows ABI 的 int / unsigned int 标准 ISF 类型名；
不会为没有类型的全局变量补猜测类型。真实 Win10 / Win11 确定性转换测试验证这些标量。
固定参考两端使用同一份精确 PDB 转换 ISF，逐字段比较 Win10 15063 x64、Win11 22000 x64，
均为 4 / 4 条、两字段全一致，无遗漏、额外或冲突。仅对参考内核指针显示做声明的 48 位
归一化；比较配置和类型文件摘要见 kpcrs.example.json，不独立证明 PDB 转换布局正确。

Server 2008 6001 x86 原生输出 1 条且自指针/回指均验证通过。固定参考读取 unsigned int
得到 3405774849，而八位值为 1；Prcb 指针成员偏移 32，内嵌 PrcbData 偏移 288，SelfPcr
偏移 28。独立开发探针仅读取计数和符号布局，保存在 parity/probes，参考原插件未修改。
参考 KPCRs 在该样本页错误退出，本例不登记为全字段通过。摘要与限制见
kpcrs-known-differences.json。Timers 的共享枚举读出 4 个处理器，但 Win10 定时器/DPC
解析仍为部分结果（456 条、181 项诊断）；本批不宣称修复或对齐该解析。

make check 通过（501 项 Rust、19 项 Python）；Debian/Kali 四项、可用 Windows 十一项
实际回归通过。Win10/11 与 Server 2008 的 KPCRs 计数加入实际回归和兼容矩阵。入口现为
127 个（Linux 62 / Windows 65），固定参考缺失入口为 Windows 27 个。正向全字段用例累计
39 项，含 2 项限定行范围，覆盖 9 个 Linux / 3 个 Windows 插件；完整插件合同验收仍为 0。

## Windows DriverIrp 与共享池映射

native43 新增 `windows.driverirp.DriverIrp`（别名 `windows.driverirp`），读取 28 个标准
IRP 入口并输出 Offset、Driver Name、IRP、Address、Module、Symbol。旧版物理池对象不再
依赖本体的存活虚拟映射；保护标签与普通标签分别计算旧版结构尾部。新版扫描保留共享
页表下的虚拟别名，以有界相对映射缓存避免重复展开。模块名称/路径缺失时保留可读地址
范围，并保持 partial；handler 单个缺页不再使可读入口整体丢失。

当时三份实际镜像的默认输出为 Win10 4255、Server 2008 x86 3724、Win11 3444 行。前五字段
唯一投影与参考一致；完整六字段默认比较仍失败，不能视为完整对齐。参考把内核 ISF
用于外部模块，产生 250/96/158 个外部符号行（Win11 另有 9 行别名），当时 Zero 保留
外部 Symbol 缺失；native79 按实际 SSDT 模块集合规则另行修复。内核模块范围的六字段用例分别有 2066/1723/1656 行通过；范围限制
写入映射，完整失败证据见 [差异记录](../tests/reference/parity/driverirp-known-differences.json)。

累计正式入口对应 109/135，仍缺 26 个 Windows 插件；42 项正向差分用例中有 5 项明确
限定记录范围。完整插件合同通过数仍为 0。当时计划补外部驱动精确 PDB/模块符号解析；该能力
后来实现，但 native79 确认它并非默认 DriverIrp 的参考符号域，
并继续完成其余插件、参数及跨版本验收。

## Windows 外部模块精确符号（native44）

共享 dispatch 索引现按命中的模块读取 PE CodeView，校验模块 SizeOfImage、机器类型、
debug directory / CodeView 范围和声明长度；多个 RSDS 身份冲突时拒绝选择。读取不再
固定跨入后续 512 字节。每模块只尝试一次，复用 exact PDB acquire 的缓存、离线门控、
下载及原生转换；只在该模块范围内按精确 RVA 查找，保留同地址别名。失败保留 Module、
空 Symbol 和 partial 诊断，不借用内核符号表。外部符号有百万条 / 128 MiB 文本预算。
DriverIrp 的结果缓存暂时禁用，待缓存键覆盖外部符号依赖后再恢复。

Win10 15063 实际镜像验证：93 个命中的外部模块均取得 PE RSDS 身份。未准备驱动符号
时离线输出 4255 行、外部具名符号 0 行；按精确身份获取并原生转换 MUP 的 PDB 后，
离线仍输出 4255 行，其中 28 行取得真实驱动符号。专项实际验收逐行核对 handler RVA
与精确 ISF 符号地址，并验证不复用结果缓存；其余 92 个模块缺 PDB 缓存，仍标记 partial。
此验收使用原生转换 ISF 作为查找依据，不独立证明 PDB 全部记录/类型的转换正确性。

三份实际镜像的六字段差分重新执行：默认比较仍全部失败，内核模块范围 2066 / 1723 /
1656 行保持通过。新获得的外部符号不会通过复现参考的跨模块错误归属来强求一致。
证据（仅身份、计数和哈希）见 [模块符号差异记录](../tests/reference/parity/module-symbols-known-differences.json)。
新增 6 项合成边界测试和 1 项实际驱动符号测试；make check 为 515 项 Rust / 19 项 Python
通过，另有 Linux 4 项、Windows 原有 11 项及新驱动符号专项 1 项实际验收通过。
入口覆盖仍为 109/135，正向差分仍为 42 项（5 项限定范围），完整插件合同仍为 0。
下一步继续扩展外部模块符号的跨版本验收、缓存依赖及剩余 Windows 插件。

Windows DriverIrp 缓存依赖（native45）：恢复结果缓存，按精确 PDB 身份记录本地 ISF/PDB
的存在状态、SHA256 和元数据快照，同时校验转换器版本及网络策略。复用及写入前重新
核验；解析期间资源变化的结果不缓存。在线未解析的模块会重试，离线缺符号结果仅进入
独立 partial 缓存；新增、替换或删除资源均使旧结果失效。旧成功缓存失效后仍检查当前
partial 缓存，避免旧条目遮挡有效部分结果。验证依赖本身不发起网络请求。

Win10 x64 / Server 2008 x86 两份实际镜像均通过五阶段验证：冷解析、缓存命中、删除
ISF、负依赖缓存命中、仅恢复原始 PDB 后离线原生转换。两份镜像的 MUP 具名行数均为
28 / 28 / 0 / 0 / 28，缓存命中标记为 false / true / false / true / false，所有阶段保持
partial。逐行 handler RVA 对照精确驱动 ISF；此查找验证不独立证明 PDB 全部记录转换。
证据见 [缓存依赖验收](../tests/reference/parity/module-cache-known-differences.json)。

make check 通过 517 Rust / 19 Python；实际回归 Linux 4 项、Windows 13 项通过，
加强后的两个离线 PDB 专项再次通过。六字段差分仍为默认三个失败、内核范围三个通过，
不增加独立正向用例。入口仍为 109/135，缺 26 个 Windows 插件，正向用例 42 项
（5 项限定范围），完整插件合同仍为 0。原用户镜像尚未取得，未验收其故障是否解决。

Windows DriverModule（native46）：新增 `windows.malware.drivermodule.DriverModule`
（短别名 `windows.drivermodule`），输出 Offset、Known Exception、Driver Name、Service
Key、Alternative Name 五列。按 Windows 构建选择物理或虚拟池对象，保留零 DriverStart，
以已加载模块范围交叉核验入口。对象名、服务键和备用名独立读取；完全没有名称的候选
不输出，读取失败仍留诊断。六个已知例外按对象名精确、区分大小写匹配。

模块区间采用半开范围，溢出范围不参与归属；参考的包含末端行为不用于制造边界误报。
模块名称不可读时不把该模块作为可证明的归属，并保留模块覆盖诊断。
`MmSystemRangeStart` 无法读取时使用参考定义的架构默认边界，并额外标记 partial；
缺少符号或无效边界不伪造完整结果。ARM64 明确不支持。

固定参考的五字段差分：Win10 15063 x64 为 3 / 3，Server 2008 6001 x86 为 2 / 2，
Win11 22000 x64 为 1 / 1，均无缺失、额外记录、重复或字段冲突。三个结果均为 partial；
映射明确允许部分输出，不把可见记录一致解释为完整恢复或根除隐藏驱动。
配置见 [DriverModule 差分配置](../tests/reference/parity/drivermodule.example.json)，
证据见 [差分证据](../tests/reference/parity/evidence.json)。

本批新增 6 项合成测试，make check 通过 523 Rust / 19 Python。入口对应提升至
110/135，尚缺 25 个 Windows 正式插件；正向差分用例 45 项，其中 5 项限定范围，
覆盖 9 个 Linux / 4 个 Windows 插件。完整插件合同仍为 0，更多隐藏驱动攻击样本、
更广构建和损坏场景仍需补齐。

Windows HiveScan（native47）：新增 `windows.registry.hivescan.HiveScan`
（短别名 `windows.hivescan`），输出 Offset 一列。Windows 8.1+ x64 按 CM10 标签
枚举已分配大页池表项；较旧系统扫描 CM10 小池头，保留 paged/free 且总块大小至少
800 字节的候选。Win10 x86 按内核虚拟映射保留别名；较旧系统输出物理地址。

按固定参考的实际语义，不额外要求小池头地址对齐，也不验证 CMHIVE 签名或活动链表。
Win7 样本中有 4 个来自普通 CM10 文本的候选，参考也输出这些记录；候选字段不证明
其为真实或活动 hive。结果元数据明确说明 allocation candidates。未映射候选、
缺页及数量/布局边界均保留失败或 partial 诊断；ARM64 明确不支持。

大页池共用读取器改为按 4 字节 ULONG 读取表项数；遇到缺页的批次逐项重读，保留
缺页两侧的可读记录。正 Key、Va 低位为零是已分配项条件，Va 为零本身不额外排除。
BigPools 两份实际镜像回归与 native46 逐行一致，Win10 为 30323 条、Win11 为 8442 条。
这不代表 BigPools 的全部字段、参数或参考静态布局回退已经对齐。

HiveScan 四份完整字段差分：Win10 15063 x64 为 22 / 22，Server 2008 6001 x86 为
17 / 17，Win11 22000 x64 为 38 / 38，Win7 7601 x64 为 16 / 16，均无缺失、额外、
重复或字段冲突。四份均无读取诊断；complete 只表示本次分配候选扫描没有发现读取
故障，不证明没有隐藏 hive 或每个候选均为真实 hive。配置见
[HiveScan 差分配置](../tests/reference/parity/hivescan.example.json)，边界和版本回归见
[HiveScan 验收记录](../tests/reference/parity/hivescan-known-limitations.json)。

本批新增 6 项合成测试，make check 通过 529 Rust / 19 Python；实际回归 Linux 4 项、
Windows 13 项通过（Server 2012 R2 样本仍缺失，未计入）。入口对应提升至 111/135，
尚缺 24 个 Windows 正式插件；正向差分 49 项，其中 5 项限定范围，覆盖 9 个 Linux /
5 个 Windows 插件。完整插件合同仍为 0；原用户镜像尚未取得，未验收其故障是否解决。

Windows PebMasquerade（native48）：新增
`windows.malware.pebmasquerade.PebMasquerade`（短别名 `windows.pebmasquerade`），输出
PID、EPROCESS 短名、审计路径、原生 PEB 映像路径及路径/命令行长度异常标志六列。
包括仍在活动链表中的已退出进程；WOW64 进程也使用原生 EPROCESS.Peb，保持参考视图。
`--pid` 和 `--pids` 取并集并去重，TUI 使用既有 PID 列表控件，最多 4096 个列表项。

长度检查独立于字符串提取，不以 Length <= MaximumLength 为读取先决条件，因此可读的
异常容量字段仍能产生线索。UTF-16 使用替换解码和 NUL 终止，按 Unicode scalar 数与
Length/2、MaximumLength/2-1 比较；空字符串不检查。两条描述符分别检查，读取失败
保留其他字段与 partial 诊断。true 只表示描述符长度异常，false 只表示未建立异常，
均不是恶意/无恶意结论；空 PEB 或空审计指针也不是路径恢复证据。ARM64 明确不支持。

固定参考的生成器将 CommandLine 标志写入 ImageFilePath 列，反之亦然；Zero 保持列名
与实际描述符相符，差分映射显式交换参考两列，不改变字段内容或筛掉行。审计和 PEB
路径两侧均缺失时只计 matched_absent，不声称恢复；单侧缺失仍失败。

实际默认六字段差分：Win10 15063 x64 为 139 / 139，Server 2008 6001 x86 为 48 / 48，
Win7 7601 x64 为 53 / 53，均无缺失、额外或可读字段冲突。Win11 22000 x64 为
102 / 103：参考多输出一个 PID 超过 32 位、来自损坏链表的无效 EPROCESS，Zero 保留
无效对象诊断而不输出伪进程。这份默认差分仍记录为失败，不排除行来制造通过。
另有 Win10 PID 4、PID 468 及二者 PID 并集三项调用通过。全部实际结果保持 partial。
配置见 [PebMasquerade 差分配置](../tests/reference/parity/pebmasquerade.example.json)，
详情见 [已知差异](../tests/reference/parity/pebmasquerade-known-differences.json)。

本批新增 6 项合成测试，make check 通过 535 Rust / 19 Python；实际回归 Linux 4 项、
Windows 13 项通过，Server 2012 R2 仍无样本。入口对应提升至 112/135，尚缺 23 个
Windows 正式插件；独立正向用例 55 项（5 项限定范围，另含本批 3 项显式 PID 调用），
覆盖 9 个 Linux / 6 个 Windows 插件。完整插件合同仍为 0；原用户镜像仍未取得。

Windows GetCellRoutine（native49）：新增
`windows.registry.getcellroutine.GetCellRoutine`（短别名 `windows.getcellroutine`），
检查列表中 hive 的 HHIVE.GetCellRoutine 是否落在已加载内核模块范围内，输出
Hive Offset、Hive Name、GetCellRoutine Module、GetCellRoutine Handler 四列。
Hive Offset 是嵌入的 HHIVE 地址；名称缺失使用参考 RegistryHive 的 `[NONAME]`。
使用精确符号验证 HHIVE.Signature，损坏对象不作为 hook 输出，但保留 partial 诊断。
模块归属保留重叠范围，并按固定参考的 SizedModule 点查询语义包含模块末端；内核名
按参考的四个无扩展名身份比较，未知归属为 N/A，不猜测符号所属模块。ARM64 明确拒绝。

共用模块读取器允许归属查询跳过未使用的 FullDllName；普通 modules/moddump 等调用
仍读取路径，原有缺页诊断保持。结果额外记录 listed_hives、checked_hives、
rejected_or_unreadable_hives、kernel_only_handlers 和 report_rows，区分实际检查后
没有异常与没有读到对象。非内核/未知指针只是一条排查线索，不直接证明发生 hook。

四份实际镜像（Win10 15063 x64、Server 2008 6001 x86、Win11 22000 x64、Win7 7601
x64）与固定参考均输出零行异常。Win10、Win11 保持 partial；Server 2008、Win7
本次读取无诊断。这四项只记阴性调用一致，不计入正向差分通过数。没有真实的
GetCellRoutine hook 样本；参考 HiveList 在双向链表均损坏后的池扫描恢复路线仍待对齐，
不宣称完整插件合同通过。配置见
[GetCellRoutine 差分配置](../tests/reference/parity/getcellroutine.example.json)，实际检查
数量、哈希与边界见 [验收记录](../tests/reference/parity/getcellroutine-known-limitations.json)。

本批新增 8 项合成测试，覆盖 x86/x64、真实 HHIVE 偏移、内核/驱动/未知指针、
名称、签名、缺页、模块重叠/边界、可选路径、取消及 ARM64 拒绝。make check 通过
543 Rust / 19 Python；实际回归 Linux 4 项、Windows 13 项通过，Server 2012 R2
仍缺样本。入口对应为 113/135，尚缺 22 个 Windows 正式插件；独立正向差分仍为
55 项，完整插件合同仍为 0。原用户镜像仍未取得，未宣称其页表故障已解决。

Windows UserAssist（native53）：新增标准十二列入口
`windows.registry.userassist.UserAssist`，保留七列旧入口。默认输出包含父键、直接子键、
ROT13 值名、XP/现代运行计数、焦点计数与时间、整秒 FILETIME 和完整原始字节。
按精确 ISF 中的 CookiePad 判断记录布局，未知布局及短值只保留原始字节。已知文件夹
GUID 的显示替换遵循固定参考的大小写规则，显示数据保留来源与许可。

修正标准入口的 Registry 进程地址空间选择。BaseBlock 不可读或没有有效 regf 签名时，
只允许使用已独立验证 nk 单元的 0x20 根键；查找路径时记录并跳过不可读的无关兄弟键。
无效 vk 引用保留诊断、不冒充已恢复值；有效值的数据缺失保留 N/A，不能填零。
显式 hive 地址独立验证 HHIVE.Signature，不依赖对象仍在已加载 hive 链中。

默认十二字段差分覆盖 Win10 15063 x64 83 条、Server2008 6001 x86 51 条、
Win11 22000 x64 58 条、Win7 7601 x64 60 条、Server2003 3790 x86 11 条。
另有前四份镜像的显式 hive 选择调用。比较器使用 hive/path/type 分组并比较完整
多重集合，包含所有 Name 和原始字节；父键的 Name 本来为空，不能作为必填身份。
前四份默认调用保持 partial，NT5 调用完整；没有筛除参考记录来取得一致。

同批补充 NT5 非 PAE Memmap：PID 4 列举和导出均为 8,044 条，导出 138,715,136
字节，SHA256 与参考一致。对应源、符号、完整性和行数登记到机器可读矩阵及验收基线。
差分工具现在固定开始时的可执行文件哈希，并在执行期间拒绝构建变化，避免混合构建证据。
上述用例不能证明完整插件合同通过，原用户 Debian 镜像也仍未取得。

本批 `make check` 通过 568 Rust / 25 Python 测试；真实回归 Linux 4 项、Windows
13 项通过，Server2012R2 仍缺本地样本。固定构建的 UserAssist 九项调用及 NT5 Memmap
两项调用均通过；累计正向差分 78 项，覆盖 20 个插件（其中 5 项限定记录范围）。
候选入口对应为 117/135，尚缺 18 个标准 Windows 插件；完整插件合同仍为 0。
本批最终可执行文件 SHA256 为
`cab7ad951d29f5f44a44f12589865ddf5b191b9ba207155e79f6f0d844110316`。

Windows Amcache（native54）：新增标准十一列入口
`windows.registry.amcache.Amcache`，保留旧六列入口。原生读取驱动、程序、文件三类记录，
覆盖 `Root\InventoryDriverBinary`、`Root\Programs`、双层 `Root\File`、
`Root\InventoryApplication`、`Root\InventoryApplicationFile`。值名精确匹配，
UTF-16 替换解码只移除尾部 NUL；DWORD/QWORD/大端 DWORD 按实际类型处理。
旧布局文件时间为整秒 FILETIME，Unix 时间独立校验范围。SHA1 移除前导零遵循固定参考。
程序按 ID 归组，重复 ID 保留最后值及最初插入顺序；原生表为平面输出，尚无参考树缩进。

默认使用已加载 hive 中首个名称包含 amcache 的对象，经过共享 Registry 进程地址空间
路由。无关值的数据页不读取；目标值缺页保留 N/A 和诊断。键、子键、输出均有上限，
输出上限保留已恢复记录及 partial，取消继续向上传播。合成测试覆盖现代/旧版键遍历、
缺失数据、未知字段、标量类型边界、非法时间和取消操作。

固定 v2.28.2 参考的 `_get_datetime_str_value` 先要求整数、再要求字符串，故现代
InstallDate/LinkDate 始终输出缺值。此标准入口明确保留该行为，不能将缺值作为时间恢复
证据；旧六列入口仍可查看原始 LinkDate 文本。Timeliner、更多架构/构建、hive pool-scan
回退、任意非 ASCII 键名及更多损坏输入仍未建立完整插件合同。

最终固定构建的十一字段全记录差分：Win10 15063 x64 为 1,230 / 1,230 条，
Win11 22000 x64 为 665 / 665 条，均无缺失、额外或字段冲突；两份均保留 partial
诊断。配置见 [Amcache 用例](../tests/reference/parity/amcache.example.json)，
字段映射见 [十一字段映射](../tests/reference/parity/mappings/windows-amcache.json)。
Server2008、Win7、Server2003 的空输出另外登记，不作为正向恢复证据。

本批 `make check` 通过 571 Rust / 25 Python 测试；真实镜像回归 Linux 4/4、Windows
13/13 通过，Server2012R2 仍无本地样本。新增两项正向用例后累计为 80 项，覆盖
21 个插件，其中 5 项仍明确限定记录范围。候选入口对应为 118/135，尚缺 17 个标准
Windows 插件；完整插件合同仍为 0。最终 native54 可执行文件 SHA256 为
`cda77c2a0a51ea0a7d1c72cf1b8d895b36758aeb5af4242aab999e26a6a39453`。
原用户 Debian 镜像仍未取得，其页表故障尚未实样验收。


## native55：PE 模块符号查询

新增原生 `windows.pe_symbols.PESymbols`，输出 Module、Symbol、Address 三列，
接入 CLI、MCP 和 TUI。支持内核/驱动与进程文件映射 VAD，精确名称或绝对地址、
重复查询及名称优先。所有实例先尝试精确 RSDS/PDB，再回退到可读 PE 命名导出；
WOW64 按模块自身机器类型校验。VAD 使用 root/left/right 次序，其他 VAD 消费者仍
保留地址次序。查询来源记录基址、页表及 PE 头是否需要恢复。

PE 头验证机器类型、可选头和 section 表范围；导出、名称、实例和文本数量均有上限。
不可读命名导出保留已解码前缀和 partial 诊断，转发项保留原始 RVA，不伪造目标地址。
缺页不补零。外部 PDB 尚未纳入结果缓存依赖追踪，因此该入口禁用结果缓存读写。

固定可执行文件对五份公开 Intel 镜像运行 16 项三字段全记录比较：**14 项正向通过**，
覆盖五份内核名称查询、五份内核绝对地址查询、Win10/11 进程绝对地址、Win11 进程名称、
Win10 驱动名称。重复查询及名称优先也包含在这些用例中。
配置见 [PESymbols 用例](../tests/reference/parity/pe-symbols.example.json)，
边界与未通过记录见 [验收限制](../tests/reference/parity/pe-symbols-known-limitations.json)。

Win10 进程名称查询仍存在地址差异：Zero 通过 prototype PTE 恢复第一个 WOW64 实例的
PE 头，固定 Volatility 在读取该实例 MZ 头时抛出 PagedInvalidAddressException，转而
选中后面的原生 x64 实例。保留 Zero 的恢复能力，并将此项登记为未通过，不能声称
完整 PESymbols 对齐。Win11 fltmgr 两边均为空：导出页缺失且精确外部 PDB 未缓存；
这是负向观察，不计为正向通过。外部 PDB 成功获取、更多别名/损坏输入、其他版本及
完整插件参数合同仍待验证。

本批 `make check` 通过 **582 Rust / 25 Python** 测试；真实镜像回归 **Linux 4/4、
Windows 13/13**，Server2012R2 仍缺本地样本。累计 **94 项正向全字段用例，覆盖
22 个插件**，其中 5 项限定记录范围。候选入口对应 **119/135**，尚缺 16 个标准
Windows 入口；完整插件合同仍为 0。native55 可执行文件 SHA256：
`f64ef19d21dbcf2a8868332d13bc1225faca7b0ed542ff0060ea466c8e64cff4`。
原始用户 Debian 镜像尚未取得，其页表故障仍未实样验收。


## native56：挂起线程及起始符号

新增原生 `windows.suspended_threads.SuspendedThreads`，接入 CLI、MCP 和 TUI，
输出固定参考插件的九列。按 SuspendCount/State 筛选、读取线程归属和两个起始地址，
按文件 VAD 半开范围关联路径；排除 WorkFoldersShell.dll，按模块批量查询精确地址符号。
缺页、字段错误和符号不可读保留记录与 partial 诊断；不查询最近符号。
线程数量、VAD 缓存、输出文本均有限额，超限保留已有输出；外部 PDB 依赖尚未追踪，
因此禁用此插件的结果缓存。ARM64 明确未支持。

五项针对性合成测试覆盖完整九列及两个地址的精确 PE 导出符号、批量去重、
旧版归属优先级、非挂起/已终止排除、WorkFolders 排除、缺字段、取消、范围边界、
符号缺失和资源超限后的记录保留。真实五份 Intel 镜像最终差分均为 0/0；Win11 的
五条挂起候选全部被 WorkFolders 规则排除。Win10/11/Win7 仍带链表或缺页诊断。
**这些空结果不算正向通过**，正向真实挂起线程与 PDB 归属仍待样本验收。
[用例](../tests/reference/parity/suspended-threads.example.json)和
[冻结验收限制](../tests/reference/parity/suspended-threads-known-limitations.json)记录全部观察。

本批 `make check` 通过 **587 Rust / 25 Python** 测试；真实回归 **Linux 4/4、
Windows 13/13**，Server2012R2 仍缺本地样本。正向差分累计维持 **94 项、22 个插件**
（5 项限定记录范围）；候选入口对应 **120/135**，尚缺 15 个；完整插件合同仍为 0。
最终可执行文件 SHA256：`83db7e831a87099bab752c16aa249d4e36d27460ab9365d8411daed8b806907e`。
原始用户 Debian 镜像仍不可用，不能宣称其页表故障已实样解决。


## native57：线程硬件调试寄存器

新增原生 `windows.debugregisters.DebugRegisters`，与固定参考插件一致输出 17 列，
包括归属进程/PID、线程 TID/State、Dr7，以及 Dr0–Dr3 地址、文件路径和精确符号。
按 Dr7、线程状态和文件 VAD 关联筛选；不对调试寄存器值作恶意判定。
PID 来自归属 EPROCESS，旧布局优先 ThreadsProcess，TID 来自线程 Cid。
挂起线程与调试寄存器共享文件 VAD 和批量精确符号解析，不根据最近符号推断名称。
共享符号缓存与符号输出也限制为 128 MiB，超限保留记录并标记 partial；
外部 PDB 依赖尚未进入缓存键，所以两插件都禁用结果缓存。

七项新合成测试覆盖完整 17 列、精确导出符号、归属 PID 语义、四条排除路径、
半开映射边界、旧归属优先级、缺少 TrapFrame/寄存器字段、未解析符号、
x86 四字节读取、取消、资源上限及 ARM64 明确拒绝。五项挂起线程测试也重新通过。

五份真实 Intel 镜像差分中，**Server 2008 SP1 x86 build 6001 的 3/3 条记录，
全部 17 字段一致**。原生仍带 561 条覆盖诊断，此项配置显式允许 partial；
证明的是已恢复记录一致，不能据此声称线程视图完整。
该样本所有 Symbol 字段均为空；真实非空 PDB/导出符号归属尚未验证。
Win10/Win11/Win7/Server2003 均为 0/0，保留为负向观察。
[用例](../tests/reference/parity/debugregisters.example.json)与
[冻结验收限制](../tests/reference/parity/debugregisters-known-limitations.json)保存身份和哈希。

新增真实全记录 17 列摘要回归基线，五份 Intel 的 DebugRegisters/SuspendedThreads 行数
与 complete 状态也纳入长期回归。本批 `make check` 通过 **594 Rust / 25 Python**；
真实回归 **Linux 4/4、Windows 13/13**，Server2012R2 仍缺本地样本。
累计 **95 项正向全字段差分，覆盖 23 个插件**（5 项限定记录范围）；
候选入口对应 **121/135**，尚缺 14 个；完整插件合同仍为 0。
原始 Debian 镜像仍未取得，其页表故障不能宣称完成实样验收。

最终 native57 可执行文件 SHA256：`7a503c0d5f9e65c71e9294300134038b220ba1dcfa30193aad3859119db46cfe`。

## native58：内核池扫描

`windows.poolscanner.PoolScanner` 现按固定参考实现扫描全部 15 个内核内置池约束。低版本扫描物理内存，Windows 10 及以后扫描内核虚拟映射；对象头按版本使用自底向上或自顶向下恢复，进程、线程、文件和 hive 保留结构校验。输出四列为 Tag、Offset、Layer、Name。Tag 使用参考渲染的类型名，空名称输出空字符串。

Server 2003 x86 为 2154/2154，仅一条文件名因孤立代理项的 UTF-16 替换而不同。Server 2008 x86 为 3316/3323，参考多出的 7 条位于代码或字符串中的标签字节，不是有效池头。Win7、Win10、Win11 仍有记录差异，尤其 Win10 虚拟扫描覆盖尚未对齐，因此本批不登记正向差分。入口对应提升至 **122/135**，尚缺 13 个；完整插件合同仍为 0。原始 Debian 镜像仍未取得。

## native59：窗口站

`windows.windowstations.WindowStations` 按参考插件扫描 `Wind` 池标签，只接受 x64，并按版本选择同一套 GUI 符号表。候选先在内核扫描层读取会话号，再进入该会话的进程地址空间读取对象名和 `rpwinstaNext`。当时名称保留 UNICODE 长度检查但额外拒绝控制字符；native73 已移除这一非参考限制。地址按参考 JSON 的 48 位值渲染。当时 Win10 15063 有 8 条共有窗口站观察；当时参考另有 7 条记录未恢复；native73 已定位名称解码、名称位检查和 padding 减法差异并修复，不能再以“错误链”为由排除。Win7 7601 两侧均为 0。完整插件合同仍为 0，候选入口对应提升至 **123/135**，尚缺 12 个。

## native60：桌面

`windows.desktops.Desktops` 复用窗口站扫描，只接受 x64，并按同一套 GUI 符号表读取 `rpdeskList`。桌面名称在会话地址空间解析，线程链表按 `tagTHREADINFO.PtiLink` 前进。进程先从内核层读取 `ImageFileName` 和 `UniqueProcessId`；内核页缺失时退回发现该指针的会话地址空间。指针按页截断时仍按参考的 `ppi.Process` 取值，进程名读不出则保留空名称和截断 PID。地址按参考 JSON 渲染为 48 位。Win10 15063 的 28 行全字段一致，其中一行是参考自身的截断进程记录。Win7 7601 两侧均为 0。完整插件合同仍为 0，候选入口对应提升至 **124/135**，尚缺 11 个。

## native61：桌面池扫描

`windows.deskscan.DeskScan` 扫描 `Desk` 池标签，而不是只跟随窗口站的 `rpdeskList`。每个候选都要有桌面名、父窗口站名和会话号，线程仍按 `PtiLink` 解析。Win10 15063 的 28 行全字段一致，比窗口站链表多出 `Winlogon` 桌面，并保留同一条截断进程记录。Win7 7601 两侧均为 0。完整插件合同仍为 0，候选入口对应提升至 **125/135**，尚缺 10 个。

## native62：窗口枚举

`windows.windows.Windows` 沿用桌面链表，读取每个桌面的顶层窗口，再按参考实现的指针字段遍历相邻窗口和子窗口。第一个窗口报告持有它的字段地址，后续窗口报告 `spwndNext` 或 `spwndChild` 的字段地址。过程地址为零时输出 `N/A`；名称读不到时保留空字符串。进程名按参考的分段读取保留前缀，PID 必须完整读出。

Win10 15063 在此批为 3059/3063。已输出的 3059 行全字段一致。参考多出的 4 行都指向 `0x853101c00a40`，进程名为空，PID 为 2743092250712。此处最初将名称判断为不可读、PID 判断为截断；native71 的逐字节检查已纠正该解释：名称首字节是无效 UTF-8，参考在替换字符处截断，而 PID 的 8 字节实际完整可读。修复与最终差分见 native71。Win7 7601 两侧均为 0。x64 大页翻译现在清除 PAT 位，避免把属性位算进物理地址。完整插件合同仍为 0，候选入口对应提升至 **126/135**，尚缺 9 个。

## native63：活动网络端点

`windows.netstat.NetStat` 按参考实现读取 `tcpip.sys` 的 `PartitionTable` 和 TCP/UDP 端口池。对象字段来自该驱动身份对应的已发布 netscan 布局，全局符号地址来自精确 PDB。分区哈希项必须是双向链表，用来排除槽位里残留的旧端点。地址按参考 JSON 渲染为 48 位。

Win10 15063 为 92/92，Win7 7601 为 121/121，全部字段一致。完整插件合同仍为 0，候选入口对应提升至 **127/135**，尚缺 8 个。

## native64：内存 Shimcache

`windows.shimcachemem.ShimcacheMem` 按参考实现定位 `SHIM_CACHE_HANDLE` 和随后的 LRU 链表。Windows 10 使用 `ahcache.sys` 的第二个句柄，Windows 7 在 NT 内核 `.data` 中使用内联句柄。AVL 例程必须落在模块 `PAGE` 节内，链表头的双向指针必须指向内核地址。

Win10 15063 为 13/13，Win7 7601 为 220/220，全部字段一致。完整插件合同仍为 0，候选入口对应提升至 **128/135**，尚缺 7 个。


## native65：规范计划任务

新增 windows.registry.scheduled_tasks.ScheduledTasks，从原始注册表值解码动作、主体、
可选设置、触发器和 DynamicInfo，输出全部 15 列。Tree 下的 Id 关联任务短名称，动作与
触发器按笛卡尔积保留多行和重复次数。命令、COM、消息框、Email（参考返回空对象）以及
时间、事件查询、登录用户、会话、WNF、启动／空闲／注册触发器均有解析路径。

固定参考中的 DynamicInfo 字段交换、GUID 非补零格式、空 Time 描述和空命令参数行为
有显式回归测试与说明。长度读取受原始值边界限制；未知 magic 停止该列表；已识别但
截断的触发器报告 partial，并保留此前可读记录。每值解析数量与最终输出都有上限，
遍历和组合支持取消。

通过固定 checkout 的离线差分：Win10 15063 为 **232/232**，Win7 7601 为 **92/92**，
全部 15 列、空字段与记录重复次数一致。两份结果仍为 partial：保留 hive 和
进程链的损坏诊断。非空事件查询、消息框／Email、截断和资源边界主要依赖合成夹具，
其他内核／x86 与完整插件合同仍待验收。
候选入口对应为 **129/135**，尚缺 6 个；完整插件合同仍为 0。


## native66：系统调用实现比较

新增 windows.malware.unhooked_system_calls.UnhookedSystemCalls。复用 PE 符号解析，
以固定的 45 个 ntdll 函数查询运行时地址，再在每个进程的地址空间读取前 32 字节分组。
输出全部三列：函数名、较少实现组的进程字符串、多数组的数量。发现顺序、平票以及只
比较前两组的行为保留固定 v2.28.2 语义，三组以上的数量另记入诊断元数据。

该入口使用直接映射捕获页（含 transition），匹配参考 Intel 层，不对这些代码字节执行
prototype/pagefile 重建；否则 WOW64 ntdll 的恢复页会改变首先解析到的符号和比较地址。
原有 PESymbols 页面恢复保持不变。外部 PDB 依赖不使用成功／部分结果缓存，避免符号
缓存变化后复用旧比较。缺页仅计入未读窗口，不填零，不把空差异当成全进程覆盖证明。

Win10 15063、Win7 7601 分别为 **45/45**，三列全字段一致。Win10 有三个函数报告
software_repor 的不同实现，Win7 有多个函数报告三个 Chrome 进程的不同实现。
原有进程／VAD 损坏诊断保持 partial。分组、平票、第三组、32 个字节变化、transition
与 prototype 读取区别以及取消有回归测试。其他构建、x86、跨分页来源和完整故障合同
仍待验收。候选入口对应为 **130/135**，尚缺 5 个；完整插件合同仍为 0。


## native67：外部字符串归属

新增 windows.strings.Strings，并贯通 CLI 的 strings-file、MCP 的 strings_file 和终端
参数草稿。输入文件的内容 SHA256、记录数和反查页数写入结果；文件在分析期间改变会
报错。输入路径只用于该插件，缺少必填参数或误传给其他插件会在镜像 I/O 前失败。
外部文件变化后每次重新计算，成功／部分结果缓存均不用于该入口。

复用 Memmap 的 Intel 页表遍历，按输入涉及的页建立反查集合。保留固定参考的进程虚拟
页反查键、连续映射起点和忽略底层来源标签的行为，避免扩建整个内存映像的反向字典。
Latin-1、行末换行、数字前缀回溯和重复输入都有回归测试。归属集合稳定排序，差分只
忽略参考集合的随机成员顺序；每个成员的名称和地址、输入记录数和全部列仍严格比较。

Win7 7601 的 PID 4 为 966/966，Win10 15063 的全部进程为 967/967；包含内核／进程归属、FREE MEMORY 和重复输入。
更广的 PID 列表与全进程用例见 strings.example.json 和证据摘要。参数入口、输入文件
变化后的缓存隔离、映射来源语义、取消及输入边界有测试。远程 URI／压缩字符串文件、
更大的输入和完整故障合同尚待验收。候选入口对应 131/135，完整插件合同仍为 0。

本批最终验证：Win7 PID 4 与 PID 4/2440 联合筛选均为 966/966，Win10 不存在的 PID
为 967/967；后者仍保留内核归属。Win10 全进程最终 native67 输出复用已完成的固定参考
JSON 逐字段比较，967/967；复用来源和哈希单独记录，没有冒充新的参考执行。四例证据
已登记，累计 103 个通过用例，完整插件验收仍为 0。已知限制见
`tests/reference/parity/strings-known-limitations.json`。


## native68：直接／间接系统调用指令块

新增 DirectSystemCalls 和 IndirectSystemCalls，两项共享固定字节候选规则、活动进程
筛选和 Capstone 5.0.6 反汇编。仅编译 Intel 后端，依赖静态链接且 release 带许可文本，
无需运行时 Python、Yara 或 Capstone 动态库。

按参考检查所有寄存器写入（含算术、交换、隐式写入），而非只识别 mov；候选向后
32 字节逐字节尝试反汇编。直接调用需要 syscall 之前已写 RAX/EAX 和 R10，终止于
ret；间接调用终止于 jmp，并验证指针目标是系统 DLL 中的 syscall。保留参考无符号
u32 位移和固定 8 字节指针、重叠候选及重复指令块输出。参考活动筛选中缺失句柄计数
与新建 UnreadableValue 的比较是身份比较，不会排除 Win10 缺少 HandleCount 的进程；
本实现不把这个分支误改成严格的句柄可读性要求。

扫描改用现有带 tag 的 VAD 遍历，父反链损坏只报告诊断，继续验证子节点 tag 和范围，
不让无关的 protection 字段阻止扫描。指令字节仅来自 valid/transition 捕获页；缺页、
不可读上下文、资源上限和损坏链表保持 partial。

固定参考生成的 14 个合成验证向量包含直接／间接正向命中、x86 模式、算术寄存器
写入、零 opcode、错误目标／路径、无符号位移和缺失上下文。合成向量不等于真实
恶意样本验收，尤其间接调用还需要真实正向镜像。候选入口对应提升至 133/135，
尚缺 Skeleton_Key_Check 和 Truecrypt Passphrase；完整插件验收仍为 0。

最终真实差分：Win7 DirectSystemCalls 9505/9505，Win10 99/99，五列、重复命中数及
匿名区域的空路径全部一致。IndirectSystemCalls 两侧在这两个镜像均为 0，单独标记
empty agreement，不计正向通过用例。累计正向差分用例为 105。两项原始参考 JSON
来自已完成的未修改固定源码调用，最终 native68 重新执行，比较记录显式写明参考
输出复用来源与 SHA256；未把复用产物冒充新的 run.py 执行。详见
`tests/reference/parity/system-calls-known-limitations.json`。

## native69：Skeleton Key 函数指针检查

新增 `windows.malware.skeleton_key_check.Skeleton_Key_Check`，从第一个可用 lsass
地址空间中的首个 cryptdll VAD 开始，按精确 PDB、CDLocateCSystem 导出函数分析、
RC4-HMAC 签名扫描的顺序定位结构。复用带 tag 的 VAD 视图和 PE 导出解析，不引入
运行时 Python。PDB 要求 RSDS 身份、cryptdll.pdb 名称和 x64 架构一致。

固定参考的 KERB_ECRYPT 为 128 字节，关键偏移 0/40/48/56/64。count 缺页默认 16，
导出代码中首个 MOV 设置计数，首个 LEA 结束分析；非 RIP 相对 MOV 仍使用默认计数。
数组路径按 EncryptionType 23 筛选，签名扫描另外验证 Encrypt/Finish 严格位于 VAD
内部；hook 范围判断包含 VAD 上界，精确函数地址可用时优先比较地址。
数组已定位后不因记录缺页而改用扫描；缺页保留诊断。

8 个导出指令向量和 6 个 hook 边界向量来自未修改固定参考，并记录源码及布局摘要。
原生合成测试覆盖 PDB 优先级、零计数、缺失计数默认值、导出优先级、跨页结构、
扫描目标指针排除和取消。Win10 15063 的 1/1 条、全部五列与参考一致，真实命中来自
导出分析；Win7 双方均为 0，仅记录空结果一致。候选入口对应 134/135，剩余
Truecrypt Passphrase；完整插件合同仍为 0，真实恶意挂钩和更多构建仍待验收。

本批在线尝试获取精确 cryptdll PDB 时服务器返回 HTTP 503，备用下载连接也失败；
因此真实 PDB 路径不计为已验证，记录在已知限制中。导出／扫描回退不依赖该下载。

最终使用 native69 可执行文件重新运行正式差分配置，两例比较通过；Win10 登记正向
证据，Win7 空结果不计入正向用例，累计正向用例 106。`make check` 全部通过：576 个
库测试、6 个 CLI/MCP 测试、50 个协议集成测试及 28 个 Python 差分工具测试；未执行
的样本验收保持 ignored。发布包在空 PATH、不同工作目录下启动与退出通过。
详见 `tests/reference/parity/skeleton-key-known-limitations.json`。


## native70：TrueCrypt 缓存口令

新增 `windows.truecrypt.Passphrase`，扫描模块链中第一个 truecrypt.sys 的首个精确
`.data` section，按 section 相对 DWORD 网格读取 signed 长度，ASCII 和三个零填充
字节按固定参考验证。保留跳过 NUL 字节、口令可跨 section 尾部、0 长度和超过 64
的最小长度参数语义。选中的负长度候选与参考一样无法构造记录而报错。

min-length 接入 CLI、MCP 和终端插件草稿；其他插件拒绝该参数。TrueCrypt 结果
缓存绕过，参数变化不会借用旧结果。缺页不补零，记录扫描／候选读取失败计数；
64 MiB 扫描与 100,000 行输出上限会标记部分结果。

固定参考生成的 16 个 PE32/PE32+ 和口令布局用例逐项验证，包含异常；原生测试
另覆盖模块枚举、大小写、无需 FullDllName、缓存隔离、缺页、取消及资源上限。
本批公开 Win7/Win10 镜像没有 TrueCrypt 驱动，参考均为空，不能证明真实正向恢复。
已找到公共挑战中的相关线索，但没有取得并校验含缓存口令的真实镜像，因此不登记
真实正向用例。

**正式入口已有候选映射为 135/135，别名 28，缺失入口 0。** 这是入口清单覆盖率，
完整插件合同仍为 0/135；不能解释为 Volatility 全能力已对齐。接下来继续修复已知
行差异、补齐参数／故障／架构矩阵和真实正向样本，保留此前 Debian 原镜像未取得、
Direct/Indirect/Skeleton/TrueCrypt 等实际证据边界。

最终 native70 四个真实镜像调用（Win7/Win10 默认和 Win10 min-length 4/65）均与参考
为空结果一致，全部标记为非正向证据，累计正向用例仍为 106。16 个参考合成向量
重新生成后一致。`make check` 全部通过：583 个库测试、8 个 CLI/MCP 测试、50 个
协议集成测试及 28 个 Python 差分工具测试；发布包独立工作目录／空 PATH 验证通过。
完整限制和输出摘要见 `tests/reference/parity/truecrypt-known-limitations.json`。

## native71：GUI 进程名的固定参考解码

Windows GUI 此前的四条缺失记录来自字符串解码差异。固定参考先以 UTF-8 replacement
模式解码，再于第一个 NUL 或 U+FFFD 截断；这也包括输入中合法编码的 U+FFFD。
Zero 原先保留替换字符，随后因后续控制字符而丢弃该记录。现在在窗口进程身份的首选与
部分名称回退路径上使用相同规则；首字节缺页仍不构造名称，PID 仍要求完整读取。

对公开 Win10 样本的观察纠正此前诊断：名称首字节实际可读但为无效 UTF-8，参考
因此输出空名称；PID 的完整 8 字节为 2743092250712，并非截断。该值作为原始字段
保留，不把这条损坏／复用内存中的进程引用解释为有效进程身份。

8 个固定参考合成解码向量覆盖有效 UTF-8、无效首字节／尾部、合法 U+FFFD、NUL、
控制字符和截断多字节字符；另有跨页名称前缀、首字节缺页与 PID 缺页测试。修复后
Win10 Windows 由 3059/3063 提升为 3063/3063，八列和重复记录全部一致，无行筛选。
该单个真实用例仍不代表 GUI 插件全部版本、故障和架构合同已完成。

最终构建后重新执行 `run.py`：Win10 为 3063/3063、八列与重复数完全一致，Win7
双方为 0（独立记录为空结果，不计正向证据）。累计正向差分用例提升至 107，完整
插件验收仍为 0。`make check` 全部通过：585 个库测试、8 个 CLI/MCP 测试、50 个
协议测试及 28 个 Python 差分工具测试；发布包空 PATH／独立工作目录启动退出通过。


## native72：不可读窗口过程地址

固定参考的 Windows 生成器对不可读过程地址保留记录并输出 NotAvailableValue。
Zero 此前将它与 1..0x1000 的无效小地址一并跳过；现在不可读值输出 N/A，并在
窗口结果中记录 partial 诊断；0 输出 0x0，小地址仍跳过。直接字段与 subPointer
两条读取路径共用规则，不再用未经参考支持的 kernel-only 条件排除可读 subPointer。

8 个由实际固定生成器执行的分类向量覆盖不可读、零、边界及用户／内核地址；完整
原生窗口链合成用例验证过程字段所在页缺失时保留窗口、进程、会话和诊断，另验
较新布局的缺失及可读 subPointer。合成程序身份仅用于隔离分类规则，不冒充真实
故障镜像。

差分映射 version 2 将可缺失的 Procedure 移出记录键，仍比较八列和全部重复数。
双方缺失可明确匹配，单侧缺失、0 与缺失、地址值差异和重复数差异均必须失败。
真实默认样本复核用于防止回归，不增加重复的正向用例数量；不可读过程地址仍需
更多真实故障镜像对照，完整插件验收尚未完成。

最终 native72 在构建结束后正式重跑两例：Win10 3063/3063、八列及重复数一致；
Win7 0/0 仍为非正向证据。该结果替换同名 baseline 的旧证据，正向用例仍为 107，
完整插件验收仍为 0。`make check` 全部通过（587 库、8 CLI/MCP、50 协议、29 Python
差分工具测试）；发布包空 PATH／独立目录启动退出通过。源码及比较摘要见
`tests/reference/parity/windows-known-limitations.json`。


## native73：窗口站原始观察和 GUI carving

本轮实际基线为 native72 10 条、参考 15 条：8 条共有，7 条少出，2 条多出。
名称读取移除非参考的控制字符和 128 字符限制，保留最少两个 Unicode 字符的规则；
UTF-16 BOM、奇数尾字节替换和首个 NUL 截断与固定 String 构造器一致。NameInfo
不额外验证 InfoMask 的名称位，而是使用固定参考的表索引规则。

GUI Wind/Desk 扫描不再将标签对应池头地址向下取整，这曾把标签归到其他对象上。
共享 top-down padding 则保留 Python 的 signed 减法与原条件，0 字段减 4 得到 -4
仍可成为候选。8 个 UTF-16、9 个站信息和 4 个实际 get_object carving 合成向量
分别验证这些分支；测试桩不代表完整对象有效性验证。临时真实内存追踪代码已移除。

修复后 Win10 WindowStations 为 15/15、三列一致，没有过滤原始异常名称；这些
是参考算法的原始观察，不证明每条都是活动窗口站。GUI offset 映射 v2 比较两侧
实际报告的 48-bit object offset，纠正之前只扩展参考端导致的比较域不一致。共享
逻辑对其他 GUI 入口的影响另做联合真实差分，不把本轮当作完整插件合同完成。

最终 native73 联合真实差分全部通过：WindowStations 15/15（三列）、Desktops 28/28、
DeskScan 28/28、Windows 3063/3063（八列），均比较全部重复数，无记录过滤。
Win7 WindowStations 0/0 单独登记为空结果一致，不计正向证据。新增三个独立正向
用例，Windows 同名基线替换，累计为 110 项，完整插件合同仍为 0/135。
`make check` 通过：590 库、8 CLI/MCP、50 协议和 30 Python 测试；native73
发布包在空 PATH 和独立工作目录启动退出通过。


## native74：PoolScanner 精确池头与文件名缺页继续扫描

native73 的五套真实基线为 Win10 3801/36172、Win11 8861/8709、Server 2008
3316/3323、Win7 4909/4926、Server 2003 2154/2154（后一例仍有一处名称差异）。
它们都不计正向证据。此前把 Server 2008 七条缺失直接解释为非池头是未经充分
验证的排除，不能作为保持不同行为的理由。

固定 PoolHeaderScanner 直接从标签位置减 PoolTag 偏移取头，不对地址取整或要求
对齐。native74 将此规则同步到 canonical PoolScanner；十个实际固定扫描器向量
覆盖两种标签与五种对齐／未对齐地址。alignment 仍用于 BlockSize 和对象布局。

Win10 提前结束的直接原因是一个可翻译文件名首地址的后续页缺失：文件名读取错误
从生成器传播到整个扫描。参考对 FileName.String 的 InvalidAddressException 跳过
当前文件继续；原生现在保留相同行为。实际固定生成器的缺页／后续文件向量和
原生跨页缺失测试验证继续行为；这不代表所有缺页合同完成。

文件名还复用已由固定 String 构造器验证的 UTF-16 解码：保留 BOM、奇数尾字节
替换与首 NUL 截断。Server 2003 唯一名称差异是单个尾字节被原生丢弃；该差异
不能以“孤立代理项”解释，最终真实差分另行确认。

最终 native74 五套真实差分：Server 2008 3323/3323、Server 2003 2154/2154，
四列与全部重复数一致；新增两项正向证据，累计 112 项（其中原有 5 项限定范围），
完整插件合同仍为 0。Win10 36119/36172，缺 53／多 0；Win11 8873/8709，缺 51／
多 213；Win7 4921/4926，缺 5／多 0。后三例保持失败，不能以共有字段一致登记通过。
剩余差异和五例可复现摘要见 poolscanner-known-limitations.json。

最终源码 `make check` 全部通过：591 库、8 CLI/MCP、50 协议、30 Python 测试。
固定参考向量重新生成逐字节一致；发布包空 PATH／独立目录启动退出通过。


## native75：PoolScanner 类型表、原始 hive 观察和补零窗口

固定参考的非 executive get_object 路径直接返回结构，不调用 is_valid；canonical
CMHIVE 不能额外要求 Hive.Signature。native75 移除这项过滤，但不把输出的原始
观察宣称为已验证活动 hive。实际固定 get_object 合成向量验证该分支。

PoolScanner 的类型表按实际 Handles.get_type_map 读取最多 100 项，索引 0 之后
遇到首个空指针就停止；名称不可读只跳过该索引，不能用导出的对象类型变量补名。
旧式 Type 指针还保留参考 Name.Length 的 1..128 检查。该路径独立于其他插件的
类型恢复策略；六个固定函数向量覆盖表边界、空哨兵与不可读名称。

原始 Pointer 按 native layer 的 address mask 截断，Zero 内部再转换成等价的
canonical 地址用于翻译。PoolScanner 文件名允许内核 DTB 实际映射的用户地址，
不附加 kernel-only 限制；实际 Pointer._unmarshall 的五个向量和用户映射读名字的
合成用例验证。Win7 缺失文件的原始 Buffer 为 0xd10000000001011c，参考将其
截断为 0x1011c，不能按高位的非 canonical 值直接排除。

共享 top-down carving 按参考请求 padded window，读取长度为可选头上限加
InfoMask 偏移；缺失字节补零，保留可读前缀。实际固定 get_object 测试桩确认
pad=True 与候选保留；原生另验证物理区段末尾缺字节。完整对象有效性不属于这些
合成向量的证明范围，真实 GUI 与五套 PoolScanner 结果单独回归。

Win10 的剩余六条文件记录位于页表递归映射区域。真实根表 self-map 索引为 319；
原生额外跳过根表指向自身的分支，而参考 Intel32e.mapping 可翻译该区域。遍历
已有固定页表层数界限，native75 取消这项排除；实际固定 Intel32e 的合成递归
映射和原生遍历验证物理页一致。最终差分使用包含此修改的最终二进制重新运行。

扫描层还需覆盖参考 primary layer 中实际映射的用户半区，不能只按“池对象通常在
内核”裁掉根表下半区。遍历现在保留两半区，并按地址最高有效位正确补齐
canonical 前缀；同一固定 Intel32e 向量另验证用户地址 0 的物理映射。

最终 native75 在全部构建完成后重新运行十例，两个差分报告使用相同二进制
SHA256 `4f28868a08fd6e5e0093d646afc8b922c98d7344787d8592afa100b2de2fbadb`：
PoolScanner Win10 36172/36172、Win11 8709/8709、Win7 4926/4926、Server 2008
3323/3323、Server 2003 2154/2154，四列与全部重复数一致，没有过滤原始记录。
GUI 为 WindowStations 15/15、Desktops 28/28、DeskScan 28/28、Windows 3063/3063；
Win7 WindowStations 0/0 仍是非正向证据。

新增长期 case 身份的正向用例三个（Win10／Win11／Win7 PoolScanner），其他
七例只更新同名基线、不重复计数。累计正向差分 115 项，其中原有 5 项限定范围，
完整插件合同仍为 0/135。原生 PoolScanner 的部分缺页诊断仍使结果 partial；
默认行集一致不能证明异常报告、所有故障场景或全部构建的完整合同一致。

最终 `make check` 通过：596 库、8 CLI/MCP、50 协议、30 Python 测试；新参考
向量重生成逐字节一致。最终发布包空 PATH／独立目录启动退出验证通过。


## native76：进程／线程有效性的公历与字段域

PoolScanner 的 EPROCESS／ETHREAD 有效性原先用 365.25 天估算年份，并写死
2036 为上限。固定参考实际将有符号 LARGE_INTEGER FILETIME 按整秒下取整，
转换为公历 datetime，再要求 1998 < year < datetime.now().year + 10。
原生现在采用精确公历与系统本地年份；Unix 使用 localtime_r，Windows 使用
GetLocalTime，不把 UTC 跨年时刻当成本地年份。本地年份在实际需要校验创建时间的每个对象上读取，保留跨年时刻的参考行为。

退出时间比较也按参考截断到秒。同秒内较小的退出 tick 不再额外排除进程；无法
转换为 datetime 的退出值保留参考的忽略行为。负 FILETIME 与旧 ETHREAD 的
算术右移按有符号值处理。名称有效性使用实际参考 utility 的 UTF-8／替换字符
截断规则，生成器的输出名称仍保留其 String 解码规则，两者并非同一规则。

PID／线程链表指针保留 native-layer 地址掩码；DTB 按符号字段类型处理，array
在参考中 cast 成 pointer 后再检查，普通整数不额外掩成物理页框。33 个实际
EPROCESS.is_valid 和 11 个 ETHREAD.is_valid 向量覆盖这些边界，分别冻结
2026 与 2035 年本地时钟；合成字段适配器明确隔离内存读取和完整 carving。
这些向量不登记为真实正向差分，也不代表完整故障合同完成。

最终 native76 源码 `make check` 全部通过：597 库、8 CLI/MCP、50 协议、30 Python
测试；44 个固定参考向量重新生成逐字节一致。构建完成后重跑五套真实默认池扫描，
Win10 36172/36172、Win11 8709/8709、Win7 4926/4926、Server 2008 3323/3323、
Server 2003 2154/2154，四列及全部重复数一致，无行过滤。证据替换同名 baseline，
正向用例仍为 115，完整插件合同仍为 0。最终发布包空 PATH／独立目录启动退出通过。
Windows 本地时钟分支未在本批真实 Windows 宿主上运行；缺页名称读取与完整字段
故障矩阵也仍待验收，不以这些合成向量或默认行集一致宣称整插件已完成。


## native77：Linux Sockscan 的完整默认输出

本批 native76 默认基线为原生 477 行、固定参考 404 行，74 条 IPv6 额外键、
24 个单侧地址缺失字段和参考的一组重复键；IPv4／Netlink 限定范围仍为 59/59。
不再以限定范围通过代表整个默认输出。

实际固定生成器在 file-ops 分支没有把解析出的物理 socket 地址写回去重键，
因而首个成功解析的 file-only 候选使用 None 键，后续 file-only 候选均被抑制；
该键在字段解码之前插入，即使第一条随后被过滤也会影响后续候选。析构函数
来源按命中偏移减字段偏移去重。同一模式属于两来源时，file 分支替换对象但
保留析构分支的键。原生现在保留这些来源语义，而非统一按解析后的物理地址去重。
六个实际固定生成器向量与原生完整文件／dentry／inode 读取链分别验证。

状态依赖于首个命中，通用物理指针扫描器需按地址合并全部模式，不能按模式
分组扫描整个 chunk。现在用有界最小堆合并每个模式的下一处命中，保留重叠字节、
chunk／LiME 区段边界及取消／上限。固定 MultiStringScanner 的 4／8 字节向量
验证混合模式次序及截断前缀；Linux PsScan 使用同一原语，另做真实回归。

IPv6 地址读取还存在两个独立参考行为：get_src_addr／get_dst_addr 比较的
AF_INET6 来自 Python 宿主 socket 常量（Linux 10、macOS 30、Windows 23），
而镜像里的 Linux 家族值为 10。在本批 macOS 宿主上先因该门槛返回 None，
不能把这里的不可用值全部归因于物理层缺页。若分支可达，参考先通过 pinet6
得到字段地址，再交回 inet_sock 原始层读取字节；物理雕刻对象不会把最后这次
字节读取切换到内核虚拟层。原生保留这两条规则，包括 native-layer 指针掩码。
四个实际地址方法／Pointer 解码向量分别隔离高地址、可读低地址、零和被掩码
的指针；原生按宿主常量和原始物理层独立验证，不把平台差异硬编码为所有
IPv6 都缺失。

完整比较映射 version 2 严格检查全部十列、重复数和显式成对缺失值，没有记录
筛选；单侧缺失、不同端口或重复数不同均必须失败。原有 IPv4／Netlink 范围
证据继续独立保留，新的合成向量不计入真实正向用例数。

宿主 AF_INET6 已进入 Sockscan 缓存身份与 kernel_identity，避免把一个平台的
缓存行集复用到另一平台。物理候选数量与来源去重键数量分开记录，None 来源键
不再冒充一个物理 socket 地址。

最终 native77 构建结束后正式重跑：Sockscan 默认 404/404、IPv4／Netlink 范围
59/59，十列、重复数和成对缺失全部一致；PsScan 321/321 全字段回归通过，三例
使用同一个最终可执行文件 SHA。默认 Sockscan 新增一项正向证据，范围与 PsScan
只替换同名基线，累计 116 项，其中原有 5 项限定范围，完整插件合同仍为 0/135。
本批真实默认对照宿主为 macOS；Linux／Windows 的真实宿主对照、32-bit 内核、
所有家族与完整故障行为仍待验收。

最终 `make check` 通过：600 库、8 CLI/MCP、50 协议、31 Python 测试；新固定
参考向量重生成逐字节一致（同一生成宿主）。最终发布包空 PATH／独立目录启动
退出通过。来源和缺失诊断仍可能使原生结果 partial，行集一致不等于完整故障
合同完成。原始差分保存在本地 run.py 产物，提交摘要绑定完整比较与输出哈希。


## native78：PsCallStack 地址查询门槛与栈字边界

native77 重新复现旧差异：PID 1 为 38/37，完整任务为 8462/8120，342 个额外
位置均来自模块符号；PID 1 --unresolved 为 383/383，但一个模块符号的 Name／
Type／Module 仍是单侧有值。这些用例原先保持失败，不能用核心行范围代替。

固定 KASConfig 把 module_addr_min/max 配置成符号所在地址，查询门槛没有读取
变量内容；mod_tree 分支才读取 addr_min/max。native78 为地址查询建立独立门槛，
不复用模块雕刻／ELF 导出的分配区间。单模块边界来自按 st_value 稳定排序的
ELF 表第二项及最后一项，其中最大值的实际表达式为 st_value & (mask + st_size)，
不能改写成普通的 masked address + size。15 个固定方法向量覆盖全局门槛、别名
排序、宽整数优先级以及首模块归属。模块被选中后如果没有匹配符号，不能再查
另一个重叠模块；原生先构造模块所属区间，再截取各模块符号范围。

固定 get_task_callstack 的七个合成字节层向量还验证了零字位置、4／8 字节未
对齐尾字、首个缺字、SP 等于栈顶及异常高位。循环按 word start < top 终止，
并允许最后一个指针跨过 top；缺页即停止。原生不再修复整数 SP 的高位，也
不在任务栈页表缺页时使用内核页表补出行。合成实际页表验证内核层可读、任务
层不可读时仍停止，且保持明确 partial 诊断。这些向量不替代真实异常镜像。

完整映射 v2 比较八列和重复数，未解析 Name／Type／Module 显式成对缺失可
匹配；单侧有值、不同值及缺行／重复数不同仍失败。合成向量不增加真实正向
用例数量。现代 latch-tree 路由、BPF／ftrace 边界、32-bit 和完整字段故障合同
仍需进一步审查，不能把默认行集通过解释为整插件完成。

最终 native78 构建后重跑八例：PID 1 37/37、PID 1 --unresolved 383/383、
全任务 8120/8120、PID 2 6/6、PID 2 --unresolved 341/341、PID 3874 线程组
180/180、PID 并集 186/186，七例均无记录筛选，八列／全部重复数一致；核心
范围例仍独立保留 8120/8120，本样本双方排除数变为 0。前三项新增真实正向证据，
其余只替换同名基线，累计 119 项（5 项限定范围），完整插件合同仍为 0/135。
`make check` 全部通过：605 库、8 CLI/MCP、50 协议、32 Python 测试；22 个新
固定方法向量重新生成逐字节一致。最终发布包空 PATH／独立目录启动退出通过。


## native79：DriverIrp 的实际模块集合符号域

固定 SSDT.build_module_collection 为每个已加载模块构造 SizedModule，全部
绑定 kernel.symbol_table_name。DriverIrp 在模块基址减去后的精确 RVA 上查询
同一份内核 ISF，保留别名和 inclusive 模块末端；不会在此路径请求外部驱动
PDB。此前将默认 DriverIrp 对齐差异解释为必须取得独立外部 PDB 并不符合这条
实际参考调用链。

原生增加独立 reference collection 模式用于默认 DriverIrp；原有按精确外部
PDB 身份解析的代码和测试保留，不混用其符号表。新模式不进行外部资源获取，
缓存依赖记录明确标注 reference-kernel-isf，不会被外部 PDB 缓存变化影响。
四个固定 SSDT/Context 方法向量覆盖外部相同 RVA 别名、重叠且 inclusive 的
模块边界、零大小模块和数字后缀名称分配。向量使用合成模块字段和精确符号表
查询适配器，不代表所有模块加载／驱动池恢复合同。

最终 native79 在全部构建结束后重跑六例：完整默认 Win10 4255/4255、Server 2008
3724/3724、Win11 3453/3453，六列和所有别名行严格一致，无记录筛选或五字段
投影。内核范围基线分别 2066/2066、1723/1723、1656/1656，单独保留范围声明。
三个完整默认新增正向证据，三个范围只替换同名基线；累计 122 项（其中原有
5 项限定范围），完整插件合同仍为 0/135。默认 DriverIrp 的名称／指针域／
MmSystemRangeStart 和专用驱动池路径仍需完整故障审查，不据此宣称整插件完成。

最终 `make check` 通过：606 库、8 CLI/MCP、50 协议、32 Python 测试；四个
固定模块集合向量重生成逐字节一致。最终发布包空 PATH／独立目录启动退出通过。


## native80：DriverIrp 的内核门槛和 handler 指针域

固定 Modules.get_kernel_space_start 读取 MmSystemRangeStart 的整数内容，
只在该标量缺页时采用默认门槛（x64 0xffff800000000000、x86 0x80000000），
随后应用地址层掩码。MajorFunction 是 Pointer，参考也先按 48／32 位地址域
掩码截断，再以 target >= kernel_start 过滤。旧原生 vm.kernel 固定范围判断
会遗漏较低的合法门槛、保留低于较高实际门槛的值，并错误处理带杂高位指针。

原生现在按实际门槛和指针域过滤，输出／模块索引内部将 masked x64 内核地址
恢复为等价 canonical 表示；缺失 MmSystemRangeStart 符号仍作为布局错误，
不会假装是成功读取的默认值。新八个向量实际执行固定 scalar helper、Pointer
unmarshal 和 DriverIrp._generator，覆盖 x86/x64 默认、缺页回退、提升门槛、
零门槛、边界相等、全一指针及杂高位。固定生成器包含一个 handler 缺页后
继续下一项；原生原有跨页处理函数数组回归另外验证完整读取链。向量的驱动池
和名称／模块符号部分是测试桩，不代表这些合同已经验收。

最终 native80 构建后重跑完整默认 Win10 4255/4255、Server 2008 3724/3724、
Win11 3453/3453，六列／全部别名行一致；三个内核范围回归仍为 2066/2066、
1723/1723、1656/1656。本批只更新同名证据，不增加真实用例数量，累计仍为
122（5 项限定范围），完整插件合同仍为 0/135。最终 `make check` 通过：
607 库、8 CLI/MCP、50 协议、32 Python 测试；8 个固定方法向量重生成一致。
最终发布包空 PATH／独立目录启动退出通过。


## native81：DriverIrp 的直接名称读取链

固定 DRIVER_OBJECT.get_driver_name 读取 get_object_header().NameInfo.Name.String，
而不是 OBJECT_HEADER.get_name 的额外长度过滤。NameInfo 优先读取旧式
NameInfoOffset；该成员不存在才用 InfoMask & 3 查询 native layer 的
ObpInfoMaskToOffset，不能要求名称 bit 0x2 预先存在。偏移为零在参考中产生
ValueError，由 DriverIrp 渲染 NotApplicable；它不是成功定位到空名称头。

原生增加 DriverIrp 独立名称读取，保留物理／虚拟 NameInfo 描述符的原始层、
Buffer 的 native-layer 指针掩码及虚拟层读取。长度仅使用 UNICODE_STRING.Length，
不检查 MaximumLength、偶数长度或 GUI 名称长度规则；实际 String 解码保留
UTF-16 BOM、奇数尾字节替换与首 NUL 截断。零长度即使 Buffer 无效也可表示
空字符串；非零 Buffer 缺页仍保留名称诊断和其他可读处理函数。其他插件的
通用对象名称验证未改变。

15 个固定 NameInfo 属性／DRIVER_OBJECT 方法／UNICODE_STRING.String 与
String 构造器向量隔离描述符字段提取；原生另用真实合成页表在 x86/x64、
物理／虚拟四种组合读取同样描述符，覆盖旧成员优先、名称位缺失、偏移零、
MaximumLength 不一致、BOM／NUL／奇数尾字节、无效与掩码 Buffer。它们不能
替代专用驱动池扫描、所有破损描述符或真实跨页故障镜像的完整合同。

名称输出与比较同时区分偏移缺失／读取失败的 N/A 和可读零长度字符串。
Driver Name 映射 v2 使用显式成对缺失，不再将 None 与空串无条件归一；新增
工具回归确认单侧缺失、真实空串与不同名称不能互相替代。

最终 native81 构建后正式重跑六例：完整默认 Win10 4255/4255、Server 2008
3724/3724、Win11 3453/3453；三个内核范围分别 2066/2066、1723/1723、
1656/1656，六列／全部别名行一致。严格名称映射记录 Win10 默认 27 行成对
Driver Name 缺失，未把它们等同于可读空串；其他字段没有忽略或行过滤。
本批只替换同名基线，正向用例仍为 122（5 项限定范围），完整插件合同仍为 0。
最终 make check 通过：608 库、8 CLI/MCP、50 协议、33 Python 测试；15 个
固定名称向量重生成一致，四种原生组合通过。最终发布包空 PATH／独立目录启动
退出通过。真实名称跨页故障和专用驱动池的完整错误行为仍待验收。


## native82：DriverIrp／DriverModule 共享固定池候选恢复

驱动派遣原先从物理池头恢复对象后重新映射虚拟地址，保留了额外对齐／
4096-byte 分配上限、未完整对齐的 padding 检查和独立对象类型解析。固定
DriverScan.scan_drivers 实际复用 canonical PoolScanner 的两个 Driver 约束。
原生现在共享精确标签相对池头、版本化物理／primary 虚拟扫描范围、可选头
padded window、有符号 padding、TypeMap 和旧对象类型名称规则；删除旧的
驱动专用 carving 和不再调用的物理类型辅助函数。GUI 包装器也通过同一
候选恢复入口，保留 GUI 的标签、大小和 page-type 约束。

候选需先通过 Driver 类型校验；随后与固定 DriverScan 一致，DriverStart
位置必须有八个可读字节，x86 也不能只验证四字节。读取 native Pointer 并
应用地址域后，只保留 start==0 或 start>MmSystemRangeStart（严格大于，
与 IRP handler 的包含边界不同）。14 个实际 DriverScan／内置约束／内核
门槛方法向量隔离这条分支；原生另验证部分捕获的八字节窗口，并在真实
合成页表下确认零 padding、未对齐池头和虚拟别名。

无效的雕刻候选按参考拒绝，不把正常候选拒绝逐条记为结果缺页；原生在
kernel_identity.driver_pool 记录 rejected_candidate_reads。扫描区段读取
失败／候选资源上限仍保留覆盖诊断。候选出现次数保留，不能用物理地址集合合并不同来源或虚拟别名；标签遍历
的完整输出排序仍需另外审查。DriverModule 也受本批共享路径影响，需
与 DriverIrp、GUI 包装器分别回归。这不代表所有损坏分页／pool-header
跨边界、32-bit 宿主或专用插件故障合同已完成。

最终 native82 在构建结束后并行跑三个配置、14 例：DriverIrp 完整默认
4255/4255、3724/3724、3453/3453，三个内核范围 2066/2066、1723/1723、
1656/1656；DriverModule 默认 3/3、2/2、1/1；GUI WindowStations 15/15、
Desktops 28/28、DeskScan 28/28、Windows 3063/3063，Win7 WindowStations
0/0 单独为空结果一致。所有映射字段及重复数通过，三个报告绑定同一最终
可执行文件。仅替换已有 case，累计正向仍为 122（5 项限定范围），完整
插件合同仍为 0/135。

最终 make check 通过：610 库、8 CLI/MCP、50 协议、33 Python 测试；14 个
固定 DriverScan 向量重生成一致。最终发布包空 PATH／独立目录启动退出通过。

## native83：DriverModule 模块归属、名称及正向链语义

DriverModule 对照固定 SSDT／ModuleCollection，使用含结束地址的模块区间；
零大小模块拥有基址本身，可读的空 BaseDllName 同样参与归属。DriverStart 与
DllBase 都进入原生层的 32／48-bit 指针域，区间加法使用足够宽的整数，避免
宿主整数溢出改变 Python 判断。集合只读取 BaseDllName、DllBase、SizeOfImage，
不再读取此插件不需要的 FullDllName。

模块遍历遵循实际 LIST_ENTRY.to_list：只沿 Flink，验证整个 LIST_ENTRY 和
包含对象首字节；不要求反向指针闭合，也不沿 Blink 补链。补回的旧条目可能
错误地覆盖孤立驱动地址，故不能把额外恢复视为此插件的等价行为。普通循环
按 seen 停止，不额外加入未对齐／用户半区过滤。区段缺页仍记覆盖诊断。

驱动的三种名称分别调用直接 NameInfo.Name.String、ServiceKeyName.String、
DriverName.String 语义，共享 native81 的 NameInfo 优先级、指针掩码与 UTF16
解码。不额外读取 MaximumLength，不拒绝奇数字节／可读用户半区扩展；单个
名称不可读不会隐藏另外两种名称。空名称仍映射该插件的不可用值，已知系统
驱动例外按固定六个名称区分大小写。MmSystemRangeStart 读取失败与固定参考
一致使用架构默认值；缺失符号仍失败。

新增 [固定 DriverModule 向量](../tests/reference/parity/driver_module_vectors.py)：
50 个真实 generator／SSDT 集合／DriverScan 名称助手用例，加 16 个实际
LIST_ENTRY.to_list 用例。向量适配的是合成字段和可读性，不能替代真实镜像。
原生测试通过实际 x86／x64 页表、物理／虚拟池候选读取名称与范围，并覆盖
MaximumLength 为零、奇数 UTF16、扩展指针掩码和用户／内核虚拟别名。generator
接受等于内核边界，而上游 DriverScan 先拒绝该非零值，两层分别验证。

最终 native83 的九个真实差分全部通过：DriverModule 在 Win10／Server 2008
x86／Win11 为 3/3、2/2、1/1；前两个原生结果 complete，Win11 仍有 10516 条
名称缺页诊断。DriverIrp 完整默认为 4255/4255、3724/3724、3453/3453，三个内核
限定范围为 2066/2066、1723/1723、1656/1656，字段及重复数全部一致。原始
差分保存在 target/reference/results/{drivermodule,driverirp}-native83-final。
证据只替换同名 case，累计仍为 122 项（5 项限定范围），完整插件合同仍为
0/135。名称读错仍保留原生 partial 诊断，未与参考静默不可用值完全对齐；
更广的损坏输入、模块标量缺页、池扫描排序和平台组合仍待验收。原始用户
Debian 镜像仍未取得，不能声称该镜像已能分析。

最终 make check 通过：613 库、8 CLI/MCP、50 协议、33 Python 测试；固定向量
重生成一致。最终发布包在空 PATH、发布目录及独立目录的启动／退出通过。
可执行文件 SHA256：`558eb283b56b04e038069fdde35f6a2db131388f6067838f231cb49dbc32d51f`。


## native84：共享池标签交错顺序及可选记录顺序验收

固定 MultiStringScanner 在同一输入块内按命中地址返回不同标签，按匹配长度
消费字节。原生此前按 constraint 先后扫完一种标签；驱动的两种标签还各自
重复读取全部扫描范围。现在共享合并器只保留每种四字节标签的下一个命中，
按地址归并并消费四字节，不收集整段命中后排序。即使先前命中因 header
约束失败，被消费的重叠标签也不重新产生。两种驱动标签在同一遍范围读取
中交错雕刻，保留重复候选及虚拟别名；GUI 单标签包装器复用该路径。

新增 [固定标签顺序向量](../tests/reference/parity/pool_order_vectors.py)，实际
调用 MultiStringScanner／PoolHeaderScanner，覆盖 11 个交错、约束反转、重叠、
拒绝首个 header、二进制及空输入用例；header 标量由合成适配器提供。原生
还验证 x86／x64、物理／虚拟驱动双标签交错及 canonical PoolScanner 的
跨类型输出顺序。合并器针对池标签四字节合同，不声称任意长度正则等价。

差分工具新增可选 `--record-order`。除原有字段、缺失值、重复键及覆盖门槛，
它还比较按声明映射规范化后的原始发出顺序，包括所有重复出现，限定范围
仍明确保留。报告保存首个差异位置及双方序列摘要，默认多重集合比较不变。
新增三项工具回归，验证地址规范化、顺序反转、同键不同值、重复次数、
限定范围及 partial 门槛；顺序一致不能把空结果变为正向证据。

最终 19 例真实联合差分的全字段及重复数全部通过，含一项 Win7 空结果：
PoolScanner 的 Win10／Win11／Server 2008 x86／Win7／Server 2003 x86 分别
36172、8709、3323、4926、2154 行，五例发出顺序也完全一致。DriverIrp 三个
完整默认为 4255、3724、3453 行，三个内核限定范围为 2066、1723、1656 行；
DriverModule 为 3、2、1 行，九例顺序一致。GUI 的 WindowStations 15 行、
Desktops 28 行、DeskScan 28 行和 Win7 0 行顺序一致。

GUI Windows 的 3063 行多重集合一致，严格顺序检查在索引 245（第 246 条）
失败，该失败如实保留，未排序后冒充严格通过。固定参考的 tagDESKTOP 子窗口
递归遍历窗口对象 set，tagWND 继承对象身份 hash／相等行为。核对 native82
与 native84 保存的两次固定参考原始输出：3063 行全字段多重集合一致，但
顺序从索引 262 起不同；镜像、映射、参考参数及参考 commit 均一致。因此
该子窗口序列不是跨运行稳定的验收合同。观察及两份参考输出摘要记录于
[Windows 已知限制](../tests/reference/parity/windows-known-limitations.json)。
这也不证明循环／损坏指针／所有 GUI 遍历语义已经对齐。

所有真实报告绑定同一最终二进制，保存在 target/reference/results 下各
*-native84 目录；附加 ordered-comparison.json／order.json 保留顺序检查。
只替换同名 case，累计仍为 122 项正向证据（5 项限定范围），完整插件合同
仍为 0/135。层扫描分块／overlap、跨区段标签与 header、损坏页及更广平台
覆盖仍待验收。原始用户 Debian 镜像仍未取得。

最终 make check 通过：615 库、8 CLI/MCP、50 协议、36 Python 测试；固定
向量重生成一致；发布包空 PATH／独立目录启动退出通过。可执行文件 SHA256：
`16cc7e0d097276d67ed7dcddc26d489b3d53d4a8b410e9c8eab7b90067f9014a`。


## native85：池头字段跨扫描缓冲区读取

固定 PoolHeaderScanner 在标签命中后按需要读取 BlockSize／PoolType，并不
要求整个 _POOL_HEADER 都在传入扫描缓冲区内。原生此前用缓冲区内局部偏移
定位 header，要求 header 起点不早于缓冲区且完整尾部也在缓冲区内，导致
标签处于范围起点或未使用尾部缺失时漏掉候选。

canonical PoolScanner 与驱动／GUI 共享雕刻路径现在都按扫描层绝对地址
减去 PoolTag 偏移定位 header；分别读取约束所用字段。字段完全在缓冲区内
时复用其字节，否则按该字段准确地址向物理／虚拟层补读，保留 ISF 位域
解码。不读取未使用尾部，不填零伪造必需字段；BlockSize／PoolType 不能
读取时仍拒绝该候选。雕刻方式、类型检查和别名重复次数不由此改写。

新增 [固定边界向量](../tests/reference/parity/pool_boundary_vectors.py)：实际
PoolHeaderScanner 加 pre-Vista／Vista 池类型谓词，48 例覆盖完整 header、
仅标签、部分前缀、未使用尾部缺失、必要大小／页类型字段缺页及不同池类型。
字段读取由独立合成适配器提供；原生分别用真实 x86／x64 页表、物理／虚拟
读取及缺失 Image 区段验证，共 192 个组合。另外直接测试共享雕刻器：标签
独占新区段，池头前缀位于前一区段，未使用尾部为空洞，仍产生预期对象。
这些不证明跨扫描范围拆分的标签能够被发现，也不证明层扫描分块／overlap
已完整对齐；更广 pool-header 布局和损坏页合同仍需验收。

最终 native85 十九例真实联合差分的字段和重复次数全部通过：PoolScanner 五个
样本分别 36172/36172、8709/8709、3323/3323、4926/4926、2154/2154；DriverIrp
三个完整默认 4255/4255、3724/3724、3453/3453，三个内核限定范围 2066/2066、
1723/1723、1656/1656；DriverModule 为 3/3、2/2、1/1。GUI 的 WindowStations
15/15、Desktops 28/28、DeskScan 28/28、Windows 3063/3063，Win7 WindowStations
0/0 只为空结果一致。十八例严格记录顺序一致；Windows 子窗口仍在索引 245
出现顺序差异，保留失败，不改变 native84 已记录的参考自身序列不稳定观察。

报告保存在 target/reference/results/{poolscanner,driverirp,drivermodule,gui}-native85，
全部绑定同一最终二进制。证据只替换同名 case，仍为 122 个正向用例，其中
5 个限定范围，完整插件合同 0/135。最终 make check 通过：617 库、8 CLI/MCP、
50 协议、36 Python 测试；固定向量重生成一致。发布包空 PATH／独立目录
启动退出通过。最终可执行文件 SHA256：`cff08a8bac35524e92dabb9f42e373e756ff696805aa5439ed2683879812d7d9`。


## native86：池扫描的固定层分块与重叠发出规则

此前 canonical PoolScanner、驱动及 GUI 共享路径将一个映射范围整体读入。
现在按固定 ScannerInterface 的 16 MiB chunk／4 KiB overlap 分块，每次
最多读 16 MiB + 4 KiB。标签扫描仍使用 native84 的交错匹配顺序，但只
发出局部起点小于 16 MiB 的命中；跨块标签可在前一块的重叠字节中完整
识别，重叠区自身的命中按实际后续块发出。不可读块记覆盖诊断并继续，
避免一次失败吞掉整个大范围。

分别保留 DataLayerInterface 和 TranslationLayerInterface 的实际尾块推进：
前者在剩余长度大于 chunk、但小于 chunk+overlap 时，以本次读取长度减去
4 KiB 推进，可能再次输出 chunk 末尾之前的部分记录；后者按固定 chunk
步长推进。不能为结果看起来更干净而去掉固定参考自身产生的重复次数。
RAW 采用 data-layer 路径，虚拟扫描和映射容器采用 translation-layer 路径。
物理层默认扫描长度按 maximum_address-minimum_address 计算，因此最大
有效地址本身不在扫描区间，独立保留这个边界语义。

新增 [固定分块向量](../tests/reference/parity/pool_chunk_vectors.py)，调用
实际两种 layer iterator、_scan_chunk 和 MultiStringScanner：26 组范围／
尾块／相邻映射／空范围计划，以及 12 组跨块标签、只处于 overlap 的命中、
短尾块重复、精确 overlap 长度及读取失败后的继续行为。映射和读错由适配器
提供，不替代真实页表枚举验证。另有默认范围最后字节排除的实际参考用例。
原生逐组验证计划、发出偏移和重复次数，并通过共享雕刻器恢复跨 16 MiB
边界的对象及 RAW 短尾块预期重复对象。映射范围之间不新增拼接规则；不同
底层格式的完整 mapping、所有跨映射边界标签和缺页诊断合同仍待验收。

最终 native86 十九例联合差分的字段及重复次数全部通过。PoolScanner 五个
样本仍为 36172、8709、3323、4926、2154 行；DriverIrp 三个默认 4255、3724、
3453 行，三个内核范围 2066、1723、1656 行；DriverModule 3、2、1 行；GUI
WindowStations 15、Desktops 28、DeskScan 28、Windows 3063 行，Win7 0 行
为空结果一致。十八例严格发出顺序一致；Windows 仍在索引 245 有子窗口
顺序差异，继续保留该失败及 native84 的参考自身顺序不稳定证据。

报告在 target/reference/results 下四个 *-native86 目录，均绑定同一最终
二进制；只替换同名证据，累计仍为 122 个正向用例，其中 5 个限定范围，
完整插件合同 0/135。最终 make check 通过：619 库、8 CLI/MCP、50 协议、
36 Python 测试。固定分块向量重生成一致，发布包空 PATH／独立目录启动
退出通过。最终可执行文件 SHA256：`4ab2ebc564dac5238b61a64325ce48b3e0d05a722e9cc91c4907438b1ded3874`。


## native87：池扫描的实际 Windows Intel 映射范围

虚拟池扫描此前仅枚举页表叶子，并未像固定 Intel.mapping 一样检查底层
捕获范围的完整可用性。现在在合并连续 VA／PFN 前确认整段物理 backing
存在，空洞页不再并入随后会整体读错的范围。大页对应物理范围有缺口时，
按参考拒绝该完整映射块，避免臆造部分有效页。相邻 VA 只有 PFN 也连续才
合并，保留重复映射／递归别名。

默认范围在 32／48-bit 原生地址域排除 maximum_address；最后一个虚拟页
输出 4095 字节，避免 canonical u64::MAX 之后的地址加法溢出。映射内部保留
虚拟起点、长度、物理起点三列，再提供给现有分块扫描，不借助对象扫描结果
反推覆盖范围。

页表读取对齐实际 _get_valid_table：包括只有四个可索引项的 PAE 根，也
读取完整 4 KiB 页进行可读性及全页重复项检查；不会因前四项相同而丢弃
完整页其余内容不同的根。大页标志仅在架构允许的层生效：x86 的目录层、
PAE 的 2 MiB 目录层、x64 的 1 GiB／2 MiB 层；根层的同一位不再错误地
提前终止枚举。PAE PFN 限制到固定 IntelPAE 的 40-bit 物理域；transition／
prototype 标志按实际 Windows 层判断，允许大页时移除 PAT 位。

新增 [实际 Windows Intel 映射向量](../tests/reference/parity/pool_mapping_vectors.py)：
38 例使用完整合成页表字节，调用未修改的 WindowsIntel／WindowsIntelPAE／
WindowsIntel32e.mapping，比较全部 VA、长度和物理起点。底层 BufferDataLayer
仅通过显式范围模拟缺失 backing。覆盖连续／不连续 PFN、backing 空洞和
缺失尾字节、页表缺失／全页重复、transition／prototype、地址域最后一页、
大页／PAT、根层标志及 PAE 根／高物理位。原生通过真实 Memory／Image 页表
与缺失区段逐列验证；这不代表任意畸形保留 PFN、各容器解压与 mapping、
自定义 transition 布局、资源／取消上限和完整故障报告合同已经验收。

最终 native87 十九例真实联合差分的字段和重复次数全部通过：PoolScanner
五例为 36172、8709、3323、4926、2154 行；DriverIrp 三个完整默认 4255、3724、
3453 行，三个内核范围 2066、1723、1656 行；DriverModule 3、2、1 行；GUI
WindowStations 15、Desktops 28、DeskScan 28、Windows 3063 行，Win7 0 行
仍为空结果一致。十八例严格顺序一致；Windows 子窗口在索引 245 的顺序
差异继续保留，不把 native84 已确认的参考自身顺序变化伪装成严格通过。

Win11 DriverIrp／DriverModule 的记录不变，native86 各有 5258 条不可读
pool range 诊断，native87 均为 0 且结果 complete；这是先按实际 mapping
可用性排除无 backing 范围的效果，而不是隐藏扫描读错。早期 native82 的
同样路径因双标签重复扫描各有 10516 条，此处不混用历史数量。其余样本
仍可能因实际名称／对象读错而 partial，完整故障合同仍需验收。

报告保存在 target/reference/results 下四个 *-native87 目录，全部绑定
同一最终二进制；只替换同名 case，累计仍为 122 个正向用例（5 个限定
范围），完整插件合同 0/135。最终 make check 通过：620 库、8 CLI/MCP、
50 协议、36 Python 测试；固定映射向量重生成一致。发布包空 PATH／独立
目录启动退出通过。最终可执行文件 SHA256：`d681a4f7276d01f90fcfa9dc3de09c9da3fca3e91fee06308013181ff7663f6c`。


## native88：Windows Intel PFN 域及 bitmap crash 实际差分

新增 Win10 19041 系列公开 bitmap crash dump 的完整默认 PoolScanner、
DriverIrp、DriverModule 差分，首次 native87 运行发现 PoolScanner 8080/8090：
少的十条全部是 _FILE_OBJECT，来自可读文件对象而非需要删除的字符串命中。
逐对象检查显示名称 Buffer 的翻译被带到 `0x200115678bd0` 等捕获范围以外；
固定参考在同一 DTB 下翻译为 `0x115678bd0`。定位到 WindowsIntel32e 独立于
Intel32e 的 `_maxphyaddr = 45`：这是固定参考对 transition PFN 软件高位的
处理，不能用通用 x64 的 52-bit mask 替代。

Windows Paging 现在按实际层固定物理域：x86 32-bit、PAE 40-bit、Windows
x64 45-bit，ARM64 保留其原有域。Intel transition PFN 从原始 entry 的该域
提取，ISF 中较宽 PageFrameNumber 字段不能把软件标志重新带进物理地址。
根表／中间表、普通页、大页、缓存后的翻译及根候选自引用比较使用一致的
域。大页判断在 Paging 中统一为架构允许的层，PAE 根或 x64 PML4 上的
同一位不再被当作大页。共享池枚举复用这一规则。

实际 Windows Intel 映射向量从 38 增至 42：加入 present／transition 的
bit45、present 的 bit51 和表指针 bit45。原生同时验证所有返回范围的起点
和末字节的 Memory.translate 结果，并特意提供包含软件标志的较宽 ISF
transition PFN，防止只修扫描范围却仍读错对象字段。

另新增 [实际 crash 层容器向量](../tests/reference/parity/crash_mapping_vectors.py)：
14 例直接构造完整文件，使用固定 WindowsCrashDump32Layer／64Layer 及其
真实 crash／crash64／crash_common 符号表。原生逐段比较物理起止与文件偏移，
逐字节比较读取，包括 full dump 相邻／分离 run、bitmap ULONG 字边界、
全置位／零字、空洞以及跨区段读取。解析器在这些有效容器用例中一致，无需
为获得通过而放宽截断和范围校验；畸形／截断／未使用 bitmap 尾位合同仍待
单独审查。

Win10 的 gzip 原文件 SHA256 与解压后 2094154496 字节的 SHA256 均独立核对。
固定 ResourceAccessor 将本地 gzip 直接包装为 gzip.GzipFile，反复随机 seek
导致参考首例持续解压；该诊断尝试被主动停止并保留，未产生正向证据。
正式插件差分双方使用已验证的解压后相同字节，配置额外绑定原 gzip 摘要。
Server 2019 公开镜像是 dump type 6，而固定 crash 层仅支持 1／5，三个参考
需求失败保留为不可比较记录，不能计算为“双方一致”或正向证据。

最终 native88 的 22 例真实差分字段与重复数全部通过。新增 bitmap crash 的
PoolScanner 8090/8090（修复前 8080/8090）、DriverIrp 3972/3972、DriverModule
1/1，全默认、无记录范围过滤，三例严格发出顺序也一致。原有十九例维持
通过；Windows 子窗口的索引 245 顺序差异仍如实保留。全批 21 个严格顺序
检查通过，另一个已知差异不影响记录多重集合一致；Win7 空结果仍不计正向。

新增三个独立正向 case，累计从 122 增至 125，仍含 5 个限定范围，完整插件
合同仍为 0/135。原始报告在 target/reference/results 下五个 *-native88 目录，
新样本的旧版漏项、压缩输入摘要、容器向量及不支持的 Server 2019 参考
失败记录见 [crash 验收限制](../tests/reference/parity/crash-pool-known-limitations.json)。
所有最终报告绑定同一二进制。最终 make check 通过：621 库、8 CLI/MCP、
50 协议、36 Python 测试；42 个映射／14 个容器向量重生成一致。发布包
空 PATH／独立目录启动退出通过。可执行文件 SHA256：`ed4748ca3b066be86818c46fb10ccf985cbb2d89c70656362e6df91b1a8e7b18`。


另以标准 release 配置运行 public_bitmap_crash_processes_and_networks，直接
使用 gzip 输入，校验解压摘要、DTB、完整 PsList 120 行、Netscan 108 行及
精确 TCP/IP PDB，全部通过。该额外验收不增加全字段正向差分计数。


## native89：捕获页表验证与读取地址域末字节

固定 Windows Intel `_get_valid_table` 会读取完整 4 KiB 表，并拒绝整页内容
由同一个 PTE 重复组成的情况，包括全零页。池映射枚举已有这一判断，但
普通 Memory.translate 此前只读取目标项，prototype／分页路径也能绕过
检查，可能从参考拒绝的表中恢复出额外对象。

现在捕获页表有统一入口：Intel 的普通翻译、prototype 表遍历、分页附件
遍历中仍位于物理捕获层的部分，以及缺页跳过提示，都先验证完整页表。
ARM64 保留其独立 descriptor 规则；swap-backed 页表的完整故障合同仍待
另行审查。缓存仅存储只读表的成功／失败判定，最多 1025 项，并受用户
page_cache_entries 上限约束，每项仅保存判定。关闭缓存或
只保留一项时，输出与拒绝行为不变。

[实际 Windows Intel 向量](../tests/reference/parity/pool_mapping_vectors.py)
扩展至 45 例、186 个直接查询：除 mapping 三列，直接调用固定层的
_translate 和 read，验证成功与失败地址。新增每个架构只有目标条目可读、
其余表页缺失的情况；整页重复表不能经 prototype／分页回退重新产生数据。
缓存回归独立覆盖禁用／单项／正常预算，以及重复读取后的有效与拒绝结果。

直接读取查询还发现地址域末字节差异：默认扫描确实排除 maximum_address，
但固定层 read 仍可读取该有效字节。native x64 canonical u64::MAX 地址
此前被“起点+长度”的溢出判断拒绝，且循环尾部无条件递增也可能溢出。
两个读取入口改为检查最后一个有效字节，并只在还有待读数据时推进地址；
末页映射及其最后字节的实际参考查询均通过。该改动不声称异常类型／日志
文本、所有畸形表、分页附件及容器组合的完整故障合同已对齐。

最终 native89 的 22 例真实差分字段与重复次数全部通过：PoolScanner 五个
RAW 样本为 36172、8709、3323、4926、2154 行，bitmap crash 为 8090 行；
DriverIrp 三个 RAW 默认 4255、3724、3453 行，三个内核限定范围 2066、1723、
1656 行，crash 默认 3972 行；DriverModule 为 3、2、1、1 行；GUI 的窗口站
15、桌面 28、DeskScan 28、Windows 3063 行，Win7 0 行仍非正向证据。
21 例严格发出顺序一致；Windows 子窗口索引 245 的已知顺序差异继续保留。

原始报告在 target/reference/results 下五个 *-native89 目录，绑定同一
最终二进制。只替换同名 case，正向仍为 125 项（5 项限定范围），完整
插件合同 0/135。最终 make check 通过：622 库、8 CLI/MCP、50 协议、36
Python 测试。45 例／186 直接查询向量重生成一致。公开 gzip crash 的
release 验收仍通过：完整 PsList 120、Netscan 108，校验 DTB 与精确 TCP/IP
PDB；不额外增加正向差分计数。发布包空 PATH／独立目录启动退出通过。
最终可执行文件 SHA256：`5bcae63a969ba5284650667e2360377299780ec6a8797ce6d613bf04db14588f`。


## native90：实际大页 PFN 组合及跨 4 KiB 读取

固定 Intel 层从大页 entry 去掉 PAT 后直接提取 PFN，再与大页内虚拟偏移
按位 OR。原生此前额外清除了所有低于大页边界的物理地址位；对于带保留
PFN 位的捕获 entry，这会读取与参考不同的物理页。现在 Intel 大页保留
这些实际地址位，ARM64 仍使用自身对齐 descriptor 规则。

固定层的 read 按当前 mapping 的连续长度读取。对于保留 PFN 位，整个
映射范围按线性物理区间表示，而重新从另一个起点调用直接 translate 又会
执行 OR，两个 API 的观察不具有普通有效 PFN 的线性关系。原生此前每
4 KiB 重算一次翻译，在这样的跨边界 read 中返回不同字节。缓存现在保留
映射 shift；读取在当前大页映射范围内一次消费所需字节，只在映射结束后
重新翻译，匹配实际 read。缺页的 prototype／pagefile 恢复仍按原路径处理。

Intel transition entry 的标志也保留到允许大页的层级检查；之前将它直接
改写为 PFN|Present，会丢失参考使用的大页位并错误进入下级表。ARM64 的
transition descriptor 归一化仍独立保留。缺页跳过提示使用同样的标志规则。

实际 Windows Intel 向量扩为 54 例、240 个直接翻译／读取查询，覆盖 x86
4 MiB、PAE／x64 2 MiB 的保留 bit13／bit20、transition 大页和跨 4 KiB
读取。大页 backing 每个物理页填充不同标记，32 字节跨界读取会暴露错误
的二次翻译，而非只比较全零数据。whole-range mapping 三列与直接 API
结果分别对照实际参考；保留位用例不再用非参考的“物理起点+长度”推导
直接 API 终点。所有保留位组合、canonical 中点拼接、软件／分页大页及
完整故障合同仍未完成。

最终 native90 的 22 例真实差分字段及重复次数全部通过，21 例严格顺序通过；
Windows GUI 子节点顺序仍在 index 245 不同，保留该失败而不排序消除。
五组原始报告在 target/reference/results 下 *-native90，绑定同一二进制
SHA256 `c091fcb17225cc22425efe719467e70cd2ca4813c9200b0a144e3f783351bb23`。同名案例替换旧证据，累计仍为
125 个正向案例（5 个限定范围），完整插件合同 0/135。

最终 make check 通过：622 库、8 CLI/MCP、50 协议及 36 Python 测试；
release gzip crash 验收通过 PsList 120、Netscan 108，检查 DTB 及精确
TCP/IP PDB。发布包在项目目录及无关目录、空 PATH 下启动退出通过。
读取长度先以 u64 限定到输出缓冲区，再转 usize，避免 32 位宿主对巨大
映射长度截断为零。54 例参考向量重新生成与提交文件逐字节一致。

## native91：Intel 地址别名与 canonical 中点合并

固定 Intel 层按分页层的地址位索引，不把传入地址是否已符号扩展作为
翻译前置条件。此前原生拒绝 x86 超出 32 位的别名及 x64 未规范扩展的
48-bit 别名，即使相同低位页表映射可读。新增实际参考查询先在原生复现
失败；现在 Intel 翻译入口归一化架构地址位，缓存键也使用同一归一化
地址。prototype 和 pagefile 路径沿用相同解释；canonical 指针有效性
判断本身仍独立存在，ARM64 的地址校验保持独立。

参考 mapping 在原始地址域合并虚拟和物理都连续的范围。原生此前先对
x64 地址符号扩展，导致跨 bit47 中点的连续两页被拆开。现在先在架构
地址域裁剪和合并，再扩展输出起点；跨中点 read 的后续页也通过同一
翻译入口解释。新增完整页表样本在 0x7ffffffff000 映射连续 8192 字节，
两页边界填不同标记，32 字节跨界读取比较实际返回字节。

实际参考向量现为 55 例、257 次查询，显式包含原始及规范扩展地址、
高位别名和跨中点读取；原生不再在测试调用前替参考归一化地址。普通
及 captured 读取均检查成功字节和失败状态。所有架构、超过 u64 地址
上界的读取、所有软件分页组合和完整异常合同仍未验证。

最终 native91 的五组共 22 个真实案例字段与重复次数全部通过，21 个
严格顺序通过；Windows GUI 已知 index 245 顺序差异继续保留。
原始报告为 target/reference/results 下 *-native91，绑定二进制
SHA256 `328ed3e63513204a1d6d81806882a46d277be1d3b97306eb1cbc4e6600aef81f`。同名案例替换旧证明，
累计仍为 125 个正向案例（5 个限定范围），完整插件合同 0/135。
make check 通过：622 库、8 CLI/MCP、50 协议及 36 Python 测试；
release gzip crash 验收 PsList 120／Netscan 108（含 DTB 与精确 TCP/IP
PDB 检查）及发布包空 PATH、无关目录启动退出检查通过。向量重新生成
与提交文件逐字节一致。这些回归结果不证明所有畸形别名或软件恢复组合。

## native92：Linux Boottime 的标准入口和时间命名空间

新增 linux.boottime.Boottime（别名 linux.boottime），按固定参考的两列
TIME NS／Boot Time 输出。按任务链表顺序对命名空间 ID 去重；旧内核
或空时间命名空间使用 N/A，ID 0 也按参考显示 N/A，但其去重身份与
没有命名空间不同。time_namespace.offsets 存在时减去 boottime 偏移，
缺少该成员时保留根启动时间。传统 boottime 仍输出原有 Key／Value
数据，和 PsList 共用内核时间读取函数。

内核时间读取按参考优先级支持 tk_core.timekeeper 的整型纳秒或
ktime_t.tv64、全局 timekeeper 的 wall_to_monotonic＋total_sleep_time、
旧版全局 wall_to_monotonic 及可选的 timespec／标量秒休眠时间。
匿名 tk_core 类型通过 ISF 实际类型解析；timespec 字段按实际宽度
有符号读取。标准入口不施加传统摘要的 2100 年上限。

参考 Timespec64Concrete 使用浮点 NSEC_PER_SEC，new_from_nsec 先将
纳秒转为浮点再执行 divmod，因此 namespace 偏移后的时间可能与精确
整数计算相差 1 微秒。标准入口复现该 divmod，再复现 fromtimestamp
的微秒舍入；无效或超出 datetime 范围的日期显示 N/A。

22 例实际固定方法向量覆盖以上布局、命名空间首次出现顺序与重复、
空任务列表、缺少支持的符号、epoch 附近及年份上界。参考方法与
PsList 迭代器使用合成字段对象及链表适配器，未修改参考源码；
原生使用完整合成内存和 ISF 字段。它们不证明真实新内核／时间
命名空间镜像、所有 32-bit／ARM64 布局、完整损坏页故障合同或
TimeLiner 集成。完整插件合同仍未验收。

最终 native92 真实 Debian Boottime 默认两列全字段及严格顺序通过，
启动时间为 2014-06-24T10:22:33.691776+00:00，TIME NS 按旧内核语义
为空。依赖时间保持读取的 5 个 PsList 默认／线程／装饰／PID 案例
全字段、重复次数及严格顺序全部通过；传统 Boottime 摘要与 native91
的列及行完全相同。原始报告为 target/reference/results/boottime-native92
及 debian-native92，统一绑定二进制 SHA256
`a691b1661d46a3c2a65dcd089c7457675181a64e18b856c5fd2af596ead39de0`。新增一个正向身份，累计
126 个正向案例（5 个限定范围），完整插件合同仍 0/135。
make check 通过：623 库、8 CLI/MCP、50 协议及 36 Python 测试；
发布包在项目／无关目录、空 PATH 下启动退出通过。22 例向量重新
生成与提交文件逐字节一致。新内核真实时间命名空间样本尚未验收。

## native93：Capabilities 的 real_cred、解码及筛选

新增标准 linux.capabilities.Capabilities（别名 linux.capabilities）。
输出完整 10 列，区分 Tid／Pid／父进程 TGID，EUID 从 task.cred 读取，
五组能力从 task.real_cred 读取；ambient 成员不存在时显示 N/A。
旧 capabilities 十六进制接口保留。支持旧 kernel_cap_struct 的标量
或 1／2 个 u32 数组、现代 kernel_cap_t.val，按 cap_last_cap 屏蔽位，
缺少该符号时使用固定参考的 41 项名称表。空集合、all 与名称顺序
对齐参考；超出已知名称的位遵循参考显示规则，完整警告合同仍待验证。

单 PID 与 PID 列表取并集，按 task.pid 在能力字段读取之前筛选；重复
选择不会复制行，也不会误按输出 Pid（TGID）筛选。缓存键包含两种
选择器。标准插件使用只提取任务身份的链表读取路径，再自行按参考
检查父进程整个对象可读性，缺失时输出 PPid 0；普通任务列表保留既有
父进程读取诊断。链表损坏／任务身份验证没有被跳过。

96 例实际固定方法向量覆盖所有 41 个已知名称、scalar／array1／array2
及 val、缺少 cap_last_cap、未来上界、空／全能力、ambient 缺失、
不可读父进程及非法数组长度／负位移。原生完整合成内存故意让 cred
与 real_cred、PID 与 TGID 不同，并验证选择器排除任务后不会触碰其
能力读取错误。这些方法向量不等于全插件真实样本通过。

真实样本暴露了固定参考的限制：Debian 3.2 的 ISF 将旧式 cap 数组命名
为 kernel_cap_t，但参考扩展要求 val，实际报 Unsupported kernel
capabilities implementation；原生标准入口也拒绝缺少 val。未修改
符号或参考来强行通过。Kali ARM64 的原生标准入口完整输出 169 行，
固定参考在 Intel 层读取 VA 0x80e4d000 时失败。两组原始失败报告
capabilities-native93／capabilities-kali-native93 和 -vvv 诊断均保留。
Debian 未匹配 PID 仅为空结果一致，不计正向证据。

一个隔离缓存的真实 MCP 会话在 Kali 上依次得到 169／1／1／1／2 行，
验证默认、单 PID、列表、缓存命中重读及并集，四个独立缓存条目。
该证明绑定输入／二进制／完整响应／日志摘要，是原生回归而非 Vol
差分。原始记录为 capabilities-kali-cache-native93。5 个 PsList 及
Boottime 真实 Debian 全字段、重复次数和严格顺序回归通过；累计正向
仍为 126（5 项限定范围），完整插件合同 0/135。make check 通过
624 库、8 CLI/MCP、50 协议及 36 Python 测试；发布包在项目／无关
目录、空 PATH 下启动退出通过。完整原生／参考故障及架构合同仍待验收。

本轮最终二进制 SHA256 `ad9f0563498653e7bf5485e88dacebadcfac46188e4d5c36cfd2b71ceb62ecbc`。
96 例向量重新生成与提交文件逐字节一致。

## native94：Envars 的完整环境区与损坏条目语义

新增 linux.envars.Envars（别名 linux.envars），输出 PID／PPID／COMM／
KEY／VALUE，支持单 PID、PID 列表及并集，缓存键独立记录两种选择。
标准入口按 task.pid 筛选后检查 PF_KTHREAD；父进程字段与能力插件
共用整对象可读性／TGID 回退规则。传统 envars 四列接口仍保留。

参考只接受 1..8192 字节的环境区。进程层不可构建或整个缓冲区不可读
时跳过当前任务，不输出已读前缀，也不以补零恢复环境文本。标准入口
直接从进程层读取完整缓冲区，未沿用旧接口的 1 MiB／用户地址上界
策略。缺少 ISF pgd 布局仍报告错误，与捕获页缺失分开处理。

解析仅去掉末尾 NUL，再逐个保留条目顺序；第一个等号分隔键和值，
空键／空值／重复键保留，UTF-8 错误使用替代字符。遇到不含等号的
条目（包括中间空项）立即停止该任务，之前的有效条目保留。这与
旧接口把畸形项当作空值并继续输出的行为不同。

28 例固定参考方法向量覆盖解析、非法 UTF-8、8192 包含边界、8193
跳过、倒置范围、不可读尾页、无法构建进程层、内核线程和父进程
回退。原生以完整合成页表／ISF／不连续物理页读取，包含跨三页
缓冲区，并验证 PID 与 TGID 不同及筛选并集。向量不证明所有真实
层构建、体系结构、损坏字段或完整资源／故障合同。

最终 native94 的真实 Debian 默认环境区共 1402 行；单 shell PID3976
为 26 行，两个 shell、重复 PID 和并集各 38 行。五个非空案例全字段、
重复次数及严格输出顺序均通过；未匹配 PID 的空结果不计正向。
5 个 PsList 与 1 个 Boottime 既有案例也全部通过严格顺序回归。
原始报告为 target/reference/results 下 envars-native94、debian-native94
及 boottime-native94，绑定最终二进制 SHA256
`dcbc7792967740c87d0d6a0e837d8cf77b211c613e8366f38d93fa562c0d0574`。

隔离缓存的原生 MCP 会话得到 1402／26／12／26／38 行，比较接口前
200 行及总数，并核对四个缓存文件的全部行与无缓存输出一致，保留
实际缓存命中日志。该回归不额外增加差分案例。累计正向从 126 增至
131（仍有 5 项限定范围），完整插件合同 0/135。make check 通过：
625 库、8 CLI/MCP、50 协议及 36 Python 测试；发布包在项目／无关
目录、空 PATH 下启动退出通过。28 例向量重生成逐字节一致。

## native95：PsAux 的参数完整性及空 mm 语义

新增标准 linux.psaux.PsAux（别名 linux.psaux），输出 PID／PPID／COMM／
ARGS，支持单 PID、列表及并集，缓存键区分这两种选择器。按 task.pid
筛选之后才读取命令行；父进程列复用整对象可读性和 TGID 回退。
传统 psaux 接口及其状态列保留。

标准命令行只接受 1..4096 字节，进程层不可构建、参数区范围无效
或整段读取失败时仍保留进程行，ARGS 为 N/A。mm 为空或该指针不可
读取时按参考输出 [COMM]，不使用 PF_KTHREAD 代替这项判断；因此
即使该标志设置，只要 mm 有效，仍读取用户参数。缺少 ISF mm／pgd
布局不伪装为缺页。读取顺序保持先建进程层、再访问参数边界。

参数按 UTF-8 replace 解码，将每个 NUL 换为空格，仅在总长度大于
一个字符时删除一个末尾 ASCII 空格。这包括参数原本的末尾空格，
并不等同于 trim_end；单个空格保留，多个末尾 NUL 可能仍留下空格。
29 例固定方法向量覆盖这些区别、边界、缺页／缺进程层、空及不可读
mm、父进程回退和 UTF-8。原生以内存／ISF／不连续用户页及缺字节
物理区段读取，并检查 PID 与 TGID 不同及筛选并集。方法适配器不
证明 list_tasks 的全部有效性规则或所有真实层构建、架构和损坏
页表／字段／故障／资源合同；完整插件验收仍未完成。

最终 native95 的 PsAux 默认 133 行、单 shell 1 行及成对／重复／并集
各 2 行均全字段、重复次数和严格顺序通过；未匹配 PID 为空结果
一致，不计正向。Envars 的 1402 行默认及其选择器、5 个 PsList 和
Boottime 也全部通过严格顺序回归。四组共 18 例，16 个非空、2 个
空结果；同名案例替换旧证明，仅新增 5 个正向身份。累计 136 个
正向案例（5 项限定范围），完整插件合同仍 0/135。

原始报告在 target/reference/results 下 psaux-native95、envars-native95、
debian-native95 及 boottime-native95，绑定最终二进制 SHA256
`defa5c09defa8de4ac62ef3c17b13b96d248dc1a290a29e036e947d2947a1f48`。隔离缓存原生 MCP 会话
得到 133／1／1／1／2 行，核对全部响应及四个缓存文件的完整行，并
确认实际命中日志；不额外增加差分案例。make check 通过：626 库、
8 CLI/MCP、50 协议及 36 Python 测试；发布包在项目／无关目录、
空 PATH 下启动退出通过。29 例向量重生成逐字节一致。

## native96：标准任务准入与实际双向遍历

标准 linux.* 任务消费者以及 PsList／PsCallStack 的 leader 路径改用
固定参考的 task_struct.is_valid 与 list_head.to_list 规则：完整 task
对象可读，PID／TGID 按 ISF 的实际有符号类型判断负数；可选 signal、
nsproxy、real_parent 存在时必须非零且目标完整可读；active_mm 非零
必须完整可读；mm 非零必须可读并与 active_mm 相同。零 ID 和无符号
高位 ID 不再由原生额外的“正整数”规则丢弃。缺少符号布局仍报错。

双向遍历按对象地址去重，参考允许两个不同对象具有同一 PID。每个
方向按实际链接、目标 list_head 读取及任务首字节可读性前进；失效
任务仍记入全局已见集合，避免逆向重试。没有因单向回指不一致另造
结果；传统 pslist 恢复接口仍保留原有诊断。标准 COMM 不要求 NUL，
空和控制字符保留，并按参考在首个 NUL／替代字符处截断。线程枚举
仍使用已有恢复路径，完整 get_threads 合同尚未对齐。

方法验证为 50 个有效性例和 18 个实际遍历／名称／选择例，调用
未修改的 task_struct.is_valid、list_head.to_list、PsList.list_tasks
及 array_to_string，使用明确捕获空洞的字节存储适配器。原生用相同
字段字节、完整 x64 页表与物理区段。4／8 字节指针测试仅证明字段
及目标范围处理，不证明 Linux Intel32 页表／发现能力。针对直接
传入参考 generator 的旧合成例，原生现在也经单独方法适配路径测试
提取行为，避免把这些例误当作全插件任务准入通过。

最终 native96 共重跑 35 例：PsAux 6、Envars 6、PsList 5、Boottime 1、
ProcessSpoofing 2、VmaRegExScan 6、maxsize 1、PsCallStack 8。34 例
字段／重复次数通过（32 非空、2 空），这些例严格输出顺序也通过；
maxsize=4 的既有 Text／Hex 4 处冲突继续保留失败，不录入正向证据。
默认 PsAux133、Envars1402、PsCallStack8120 记录无意外变化。
三个隔离缓存 MCP 会话分别验证 PsAux133／1／1／1／2、
Envars1402／26／12／26／38、Kali 能力169／1／1／1／2，包含实际
缓存命中。Kali 是原生回归，不是参考差分。

八组原始报告在 target/reference/results 下 *-native96，最终二进制
SHA256 `af2d9589ad93808abfd2a9c599b4e8db8390049e518f044105419536012df396`。同名案例替换旧
证明，累计仍 136 正向案例（5 项限定范围），完整插件合同 0/135。
make check 通过：628 库、8 CLI/MCP、50 协议及 36 Python 测试；
发布包在项目／无关目录、空 PATH 下启动退出通过。68 例向量重新
生成逐字节一致。资源边界、异常文字、任意 ISF、架构和线程损坏
合同仍待验证。

## native97：PsList 先选主进程，再展开完整线程组

修复实际差分发现的漏行：`linux.pslist.PsList --pid 3874 --threads`
在 Debian 3.2 样本上原来只返回主线程 1 行，固定参考返回 7 行。原因是
通用结果过滤在展开线程后按 TID 再次筛选。现在标准入口接受 `--pids`，
单 PID 与列表取并集，在主进程阶段筛选，然后展开整个组；缓存键包含两个
选择器以及 threads/decorate，避免选择器之间复用错误结果。

线程枚举按固定参考的 `get_threads` / `_get_tasks_iterable` / `list_head.to_list`
语义：优先 signal_struct.thread_head / task_struct.thread_node，旧布局回退
thread_group；前向遍历，逐任务应用完整准入，按组内地址去重，不再按全局
地址或 TID 去重。保留零 ID、重复 ID、空名称和控制字符等参考允许的值，
不额外要求反向链接一致。旧版恢复链路径仍单独保留。

28 个新增字节适配器用例直接执行固定参考方法，覆盖布局优先级、主进程
筛选、重复选择器、无效线程、组间共享线程、环、空链接、缺页与控制字符。
它们补充此前 50 个任务准入和 18 个遍历／名称用例；现代布局还没有真实
镜像线程差分证明，也不代表已覆盖所有异常、采集竞争或平台合同。

最终 19 个真实用例（选择器 6、原 PsList 5、PsCallStack 8）全字段和严格行序
通过，其中 18 个为非空正向结果、1 个为空结果一致。选择器各输出
7/8/8/8/2/0 行；原 PsList 默认 133 行、含线程 316 行。持续 MCP 会话
8 次请求分别 133/7/8/8/7/8/2/0 行，7 个缓存项，重复命中和完整缓存行均
与无缓存结果一致。通过 make check：629 库、8 CLI/MCP、50 协议、36 Python；
发布包通过原目录及无关目录、空 PATH 的启动与退出检查。

证明存于 `pslist-selection-known-limitations.json`，原始输出在
`target/reference/results/{pslist-selection,debian,pscallstack}-native97`。
最终二进制 SHA256 `ca38931e01ee55afb7cd95fb64608f3fb6d3ee5aa105db745a1d0cb74053c62b`。
同名基线替换，仅增加 5 个正向用例，累计 141 个正向用例（5 个限定范围），
完整插件合同仍为 0/135。既有 regex maxsize=4 差异尚未修复；原始 Debian6.12
用户镜像仍不可得，不能据此声称该镜像已可分析。

## native98：标准正则入口的固定上下文与实际符号来源

固定参考的 Linux VmaRegExScan 和 Windows VadRegExScan 都声明 `maxsize`，
但生成器实际调用 `read(offset, MAXSIZE_DEFAULT, pad=True)`，没有读取配置值。
两个标准原生入口现在同样固定读取 128 字节，再用非 DOTALL 正则锚定重匹配；
匹配不成立或超出上下文时输出整段上下文。CLI/MCP/TUI 接受 signed64 整数兼容
参数，包括负数、零和大于 4096 的值，但不会据此分配内存或改变显示长度。
诊断元数据同时保留 effective `maxsize=128` 与 `requested_maxsize`，界面与帮助
说明这一行为。Python 任意精度整数仍不属于当前输入合同。

同时修复 Linux 正则按 TGID 过滤的问题：参考先按 task.pid 筛选，再输出
task.tgid；现在二者分开。96 个生成器适配器用例直接执行固定参考的 Linux /
Windows `_generator` 和 RegExScanner，覆盖默认／负数／零／大参数、普通匹配、
lookbehind、DOTALL 显示回退、160 字节长匹配、命名反向引用和无效 UTF-8。
另有 5 个 PID/TGID 不同的筛选方法用例；原生测试使用实际页表与结构字节对照。
这些适配器不证明所有页表、VMA/VAD 准入、分块、缺页和 Python/PCRE2 语义。

验证时发现旧 Windows 配置指定的 converter5 ISF 会被当前转换器规则跳过，
CLI 实际从本机缓存读取 converter8 ISF，而参考仍读取旧文件。本轮不使用该组
输出作为新证据；改为冻结同一份 converter8 ISF 给两端，SHA256 为
`d07a9e3b68f1596d77f51a987cc361391b658bd2873e066a60aa105bb8d67ce4`。
随后从 native97 发布包恢复原二进制，使用这份符号重建修复前基线。两个工具
仍共享同源 PDB 派生布局，不是独立符号布局验证。

差分工具新增实际符号来源保护：对显式 JSON ISF 输入，比较结果所载符号文件
与配置文件的实际 SHA256；不同的缓存回退使该用例失败。归档也逐例重新检查
来源。目录／归档符号选择不受这个额外文件保护覆盖。4 个新增 Python 测试
验证缓存换源拒绝、相同字节异路径接受、实际文件缺失拒绝和保护的适用范围。

最终两组 Linux 10 例均全字段／严格行序通过，包括原 maxsize4 的 4 个 Text/Hex
冲突归零。Windows 使用同一 ISF 重跑 13 例，4 例通过：PID468 默认 27 行，
maxsize=-1/0/4097 各 27 行。其余 9 例仍失败，保留全部额外原生记录；原
PID7688 maxsize4 共有 701 行的 1402 个字段冲突已归零，但仍为 709/701，
额外 8 行不作正向对齐证明。没有为了通过比较而过滤页面恢复结果。

Linux／Windows 持续 MCP 会话各 8 次参数请求分别始终为 2／27 行；逐次验证
完整行、effective/requested 元数据和 partial 状态。两组均有缺页，成功缓存
文件均为 0，证明没有将 partial 结果落为成功缓存；不声称真实样本缓存命中。
原有完整合成 Windows 会话测试继续覆盖参数间缓存隔离。最终 make check：
632 库、10 CLI/MCP、50 协议、40 Python 全过，发布包启动／退出检查通过。

新证明见 `regex-context-known-limitations.json`，保留修复前计数与输出哈希，
不提交恢复的 Text/Hex 内容。真实原始报告位于 target/reference/results 下
`vmaregexscan[-maxsize]-native98`、`vadregexscan[-maxsize]-exact-native98`；
最终二进制 SHA256 `b5fba34b76bf8c71a43d11466ab322a687616deda36af2ffea80eb32ac9b2163`。
同名基线替换，只新增 7 个正向身份，累计 148 正向案例（5 项限定范围），
完整插件合同仍为 0/135。Windows 页面恢复与参考的差异、广泛平台／异常／
资源合同、原始 Debian6.12 镜像复测等工作仍未完成。

## native99：VadRegExScan 使用固定参考的 Intel 读取策略

修复 native98 保留的 9 个 Windows 正则失败用例。差异发生在输入读取阶段：
原生通用读取器会跟随 prototype PTE，或从软件分页／压缩 store 重建页面；
固定参考的 Windows Intel 层读取驻留／transition 页面，仅按固定规则处理显式
swap layer，不跟随 prototype。标准 VadRegExScan 的搜索输入和显示上下文现在
使用新的 `Memory::read_reference`，在进入正则搜索前应用这些规则，而不是
过滤已有结果。通用 `Memory::read` 的 prototype／软件页／压缩恢复功能保留；
ARM64 路径也保留原生策略，诊断元数据明确区分两种策略，不将其计为参考证据。

新的 Intel 读取器复用经过验证的物理翻译，保留固定参考的 swap 位判断、索引、
x86/PAE/x64 偏移宽度、无效大页上的 PAT 清除及未对齐调用的实际 swap-base
语义。它不使用 ISF PageFileLow/High 或 SwizzleBit 来替代参考固定规则。
附件允许短尾和空的普通文件；每次读取仍校验边界、文件身份及修改状态，
不足的字节报不可读。没有要求附件长度必须为 4096 的倍数。

`windows_layer_read_vectors.py` 直接执行固定参考的 WindowsIntel /
WindowsIntelPAE / WindowsIntel32e `.read`，以完整合成页表、捕获空洞和显式
swap BufferDataLayer 对照。57 组共 570 次读取覆盖驻留／transition／prototype、
索引 0/3、附件缺失或索引错误、标记位、高偏移、未对齐和跨页调用、上层软件
条目、PAT、短尾／空文件及物理／页表缺页。原生逐次比较成功字节或读取失败，
没有声称异常类型／文本完全相同；这些也不代替全平台发现或完整扫描分块合同。
新增扫描集成测试证明显式 pagefile 仍能提供命中，并证明通用读取器仍可恢复
标准扫描层不接受的 prototype 页面。

真实 Win10 15063 使用与 native98 相同的冻结 converter8 ISF，两组 13 例全部
全字段和严格行序通过：PID7688 的普通、lookbehind、反向引用和 maxsize4 各
701 行；多 PID 与并集各 727 行；PID356 为 3 行；PID356/468 为 30 行；
PID844 为 26 行；PID468 默认及 -1/0/4097 参数各 27 行。9 个旧失败用例的
修复前计数／输出哈希继续保留，实际符号来源逐例校验，没有删除历史记录。

持续 MCP 会话执行 8 次分析和 20 次协议调用，完整读取每个不可变快照的全部
分页，再与无缓存 CLI 输出按顺序比较。行数依次为
701/701/27/27/30/701/3/727，重复请求、PID 列表／并集和 maxsize 均通过。
捕获／链表／VAD 诊断继续保留 partial，成功结果缓存文件为 0，不把字段一致
解释为完整捕获。最终 make check 通过：634 库、10 CLI/MCP、50 协议、40
Python；发布包通过原目录／无关目录和空 PATH 的启动、退出检查。

证明在 `windows-layer-read-known-limitations.json`，原始报告在
`target/reference/results/{vadregexscan,vadregexscan-maxsize}-native99`。
最终二进制 SHA256 `2f7f6c4abbf5da8f98f9fae91099c3d7e643e9a7542e5dd37a51ef22e75878ec`。
同名基线替换、新增 9 个正向身份，累计 157 个正向用例（5 个限定范围）。
完整插件合同仍为 0/135；其他消费者的读取策略、扫描映射／分块／补零、
任意 Python/PCRE2 语义、全部异常／资源／平台合同仍未全面验收。

## native100：嵌套扫描区间与空匹配分块边界

直接对照固定参考的 `_coalesce_sections` 发现，其合并行为不是数学区间并集：
后续区间的终点会替换前一区间的终点，嵌套或零长度区间也可能缩短先前范围。
例如 `(start=0,length=12)` 与 `(4,4)` 合并为 `(0,8)`，原生此前保留到 12。
共享正则扫描器现在保留这个固定参考行为，也保留零长度区间参与合并。
同时修复 RegExScanner 的边界条件：不论缓冲区是否包含 overlap，命中起点
只要达到 chunk_size 就不输出；此前原生会多出正好位于完整块末端的空匹配。

覆盖统计单独保留原始请求的并集字节数，并将参考合并规则省略的字节记录到
`reference_coalescing_omitted_bytes`。因此参考行为省略了部分请求时，原生结果
保持 partial，各消费者的诊断明确列出省略数量，不将较小选定范围的扫描结束
解释为原始范围全部完成。这个字段与实际缺页和资源中止分开记录。

`regex_sections_vectors.py` 直接执行固定参考的区间合并、TranslationLayer
分块迭代、`_scan_chunk` 和 RegExScanner。36 组区间合并与 13 组连续映射分块
用例通过，覆盖嵌套／零长度／相邻／重叠区间、块首锚点、跨块命中、短尾和
空匹配。算法测试使用 8/4 缩小分块几何，生产仍为 16 MiB/4 KiB；已有真实
大小的跨块／短尾测试继续通过。修复前的两次断言失败日志保留哈希。

同时保留两个明确未解决的合成方法差异：不连续物理 backing 的映射边界尚未
传给共享扫描器，原生可能拼出参考分开扫描时不会发现的命中；固定参考还会
在首个正地址映射前扫描一个空块，某些可匹配空串的模式因此额外命中地址 0。
`unresolved_mapping_chunks_match_pinned_methods` 单独标为 ignored，显式运行仍
以 101 退出并列出两项差异；它不是通过用例，也不是完整插件的真实镜像差分。
后续需要让标准插件向扫描器提供真实映射块，不能靠过滤结果修复。

共享扫描器影响六组真实回归：Linux 正则 10、Windows 正则 13、系统调用检测
4、Skeleton Key 2，共 29 例。最终二进制全部全字段／严格行序通过，其中 26
项非空正向、3 项为空结果一致。系统调用正向分别为 Win10 的 99 行、Win7 的
9505 行，Skeleton Key 的 Win10 为 1 行。原始请求计数补充前已重新运行固定
Vol；最终原生二进制再完整重跑，复用这些参考输出前验证输入／符号／参数／
映射及输出哈希、参考 checkout。每项记录的 `reference_execution` 保留来源
summary 路径、SHA256 和复用说明，没有将其记为新启动的参考执行。

最终 make check 通过：635 库测试、10 CLI/MCP、50 协议、40 Python；库中另有
4 项 ignored，包含上述已知失败测试。发布包启动／退出检查通过。新证明在
`regex-sections-known-limitations.json`，原始最终输出在
`target/reference/results/*-native100-final`。最终二进制 SHA256 为
`ca1395c19f8dd1760c6a1827c090bd9b8857abc863575f376ddcfbab96306b78`。
本批只刷新既有用例，累计仍为 157 个正向案例（5 项限定范围），完整插件合同
仍为 0/135。映射分块、层边界裁剪、补零、异常文本、资源和更广平台合同继续
未完成，原始 Debian6.12 用户镜像也尚无法复测。

## native101：真实映射事件驱动扫描分块

修复 native100 明确保留的物理 backing 不连续与首个空块差异。新增独立 Intel
选区映射器，按固定参考的完整页表读取／重复页拒绝、架构 PFN／PAT、有效／
transition／显式 swap 标记和底层可读范围产生映射，只有虚拟及底层地址同时
连续且属于同一 backing 才合并。映射器同时提供对应读取，Linux x64 和
Windows x86/PAE/x64 标准正则扫描使用实际映射块；系统调用和 Skeleton Key
后备扫描也接入。ARM64 继续使用单独原生路径，不声称固定参考平台对齐。

映射扫描器逐块实现固定 TranslationLayer 的 16 MiB/4 KiB overlap，保留首个
正地址映射前的空块、每个底层不连续映射边界和失败块的空 subject；扫描后
没有过滤／去重结果。原有嵌套区间合并和省略字节统计继续保留。字节／页数
预算耗尽会保留前缀并标 partial，取消继续向上传播，不把原生资源限额解释为
参考等价。实际命中重复偏移按完整记录多重集比较，并额外检查严格行序。

此前被忽略的两个失败方法用例已移入正常通过测试，另加失败读取空块用例。
36 个合并、13 个连续分块、3 个映射事件场景直接执行固定参考方法。新增
`intel_scan_vectors.py` 包含 Linux Intel32e 和 Windows 三种 Intel 层，87 组
场景、870 次字节读取、261 次选区映射，对照驻留／transition／prototype、
完整及短尾／空 pagefile、索引、上层软件 PTE、PAT、高 PFN 位、重复表及
物理／页表缺页。原有 57 组 Windows 层 fixture 重新生成后字节结构不变。

新增真实 anchor 用例先在 native100 上复现失败：Linux 空块 0/7、块首43/128；
Windows 空块0/42、块首425/1241。native101 分别为7/7、128/128、42/42、
1241/1241，全字段比较通过。这些模式保留重复偏移，专用映射配置声明完整
多重集比较，不将重复压缩为一条。真实样本的新 anchor 用例不代替全部正则
语法、层边界／溢出别名、采集竞争、异常文本和资源／平台合同。

额外固定 Intel32e 探针确认一个尚未修复的边界：有效零长度选区 `(4096, 0)`
仍产生零长度映射事件，参考扫描迭代器由此发出地址 0 的空 subject；`^$`
命中 0。当前原生映射器直接跳过零长度选区，不能把本批非零范围的 anchor
通过扩展为该边界通过。探针保存在
`target/reference/results/native102-zero-section-probe.json`，留给下一批补齐。

本次还实际执行了大样本验收：默认路径缺失的调用保留失败日志，指定本地
实际路径后 Debian 三项通过，Kali 原路径一项通过。Windows 指定实际路径
后 9 项通过、2 项失败；失败分别为 Server 2008 DriverModule 的旧
`complete=false` 基线和 Win10/11 联合测试的同类硬编码断言。另两项独立
驱动符号集成测试仍要求 native79 前的 DriverIrp 策略，在当前 canonical
参考符号域下缺少其预期的独立 PDB 观察而失败。上述验收债务如实保留；
没有把这些测试称为通过，也没有回退参考符号策略。Server 2012 R2 镜像
仍未解压，本次未运行。

最终 `make check` 通过，发布包在原目录／无关目录和空 PATH 下启动及退出
检查通过。七组 33 项真实差分全部全字段、完整重复次数和严格行序一致，
其中 30 项非空正向、3 项空结果一致；均重新执行固定参考，没有复用旧
二进制对应的报告。最终二进制 SHA256 为
`8e904349328fc6800a9cc513fd74989aa76e1bc4b8775edbdc5b464728017af8`。
证据为 `tests/reference/parity/scan-mapping-known-limitations.json`，原始报告
为 `target/reference/results/*-native101-final`。仅新增四个 anchor 身份，
正向用例累计 **161 项**（5 项限定范围），完整插件合同仍为 **0/135**。

## native102：零长度 Intel 选区事件

补齐 native101 保留的 `(4096, 0)` 边界。零长度请求现在只执行一次地址翻译，
并验证翻译后的底层一个字节；有效时输出零长度映射，无效页表或底层范围不产生
事件。扫描器仅在原始选区也是零长度时接收该事件，保留固定参考的正地址首个
空 subject：`^$` 命中地址 0；地址零的零长度事件与未映射事件均不产生 chunk。
不读取或填充扫描字节，不改变 ARM64 sparse 分支；引擎版本更新使旧缓存失效。

新增向量先复现原生缺失事件及扫描器拒绝零事件的失败，再验证修复。实际执行
固定参考的 99 组 Intel 场景，共 792 次选区映射、990 次读取；覆盖四种既有层、
驻留／transition／显式 swap、缺失 backing、分页末端和仅一个字节可读的底层。
另有 6 个映射分块场景，其中 3 个新增零长度事件；既有 36 个合并和 13 个连续
扫描场景保留。合成方法验证不代表真实镜像具备零长度 VMA/VAD 正向证据。

`make check` 通过；指定实际本地路径的 `make acceptance` 四项全部通过。
重新执行 Linux／Windows 的四项真实 anchor 差分，完整字段、重复次数及严格
行序分别为 7/7、128/128、42/42、1241/1241，均保留原有 partial 诊断。
证据见 `tests/reference/parity/zero-section-known-limitations.json`，原始结果位于
`target/reference/results/scan-mapping-native102`。Windows 首轮默认路径缺失，指定
实际路径重跑后为 9 项通过、4 项失败：两项 DriverModule 旧完整性断言和两项
DriverIrp 独立 PDB 旧策略；Server2012R2 未解压，未运行。未以本批方法通过
替代完整验收；完整插件合同仍为 **0/135**。

## 驱动验收入口修正

本批仅更新验收与证据，不改变 native102 运行时策略。独立实测 Win10 15063、
Win11 22000、Server2008 的 DriverModule 分别为 3、1、2 行，均 complete=true
且无诊断；完整性 fixture 据此更新，既有字段、行数与名称校验保留。

canonical DriverIrp 验收使用当前 reference-kernel-isf 符号域，取实际已加载模块
基址核对每个有名 handler 的精确内核 ISF RVA，并验证无名 RVA 不存在对应符号。
六阶段覆盖冷／热缓存、独立驱动 ISF 删除后的缓存及禁缓存重算、加入独立 PDB
后的缓存及禁缓存重算。每阶段完整比较 rows、kernel_identity、diagnostics 和
complete，Win10 与 Server2008 两项通过；原有 partial 断言保留。

独立模块 PDB 解析验收移至 dispatch 内部的 ignored 真实样本测试，显式使用
DispatchModules::new/resolve_at/acquire。在 Win10 与 Server2008 分别执行五阶段，
验证本地 ISF、删除后的依赖失效／缺失诊断、partial 缓存和本地 PDB 重新转换。
资源缺失即失败，不通过静默跳过伪造成功。该测试已实际执行通过。

Server2012R2 本地原始 ZIP 仅含一个 2 GiB 内存文件，无路径穿越或符号链接，
已解压至独立新目录并通过 public_server2012r2_x64 验收；原归档保持不变。
Win10/Win11 联合验收已通过。重新执行的六项 DriverIrp 固定参考差分全部完整
字段通过：默认 Win10 4255/4255、Server2008 3724/3724、Win11 3453/3453；
限定 kernel 模块范围分别为 2066/2066、1723/1723、1656/1656。前两种样本
继续 partial，Win11 为完整结果，不能将单一样本完整性推导到其他样本。
原始报告为 `target/reference/results/driverirp-acceptance-refresh/summary.json`。
上述测试不能替代完整插件故障／平台合同，完整插件合同仍为 **0/135**。

## Intel 48 位地址别名向量

对 Linux Intel32e 与 WindowsIntel32e 新增实际固定参考的 `2^48`、`2^48+3`
读取，以及 `2^48` 零长度／非零长度选区映射。既有驻留、transition、swap、
缺失 backing 和页表故障场景均执行：翻译按 48 位掩码取索引，映射起点保留
请求地址。100 次新增读取和 100 次新增映射全部通过，无需修改运行时。

Intel 向量累计 99 组、1090 次读取、892 次映射；`make check` 通过，非 extended
Windows 层 fixture 重新生成后逐字节不变。证据见 intel-alias-known-limitations.json。
这不代表 32 位／PAE 地址别名、五级页表、所有溢出或完整插件合同通过。

## Boottime 缺字段故障向量

固定参考方法新增三项缺字段故障：tk_core 缺 timekeeper、旧 timekeeper 缺
 total_sleep_time、namespace offsets 缺 boottime。参考均抛异常，原生均返回
错误，未生成伪造完整行；方法场景由 22 增至 25。重新执行 Debian 3.2 默认
真实差分为 1/1、完整字段通过。另加原生四字节 timespec 秒／纳秒和 unsigned
sleep 标量读取测试，验证负秒数符号扩展与两条总休眠路径；它仍使用现有宿主
测试地址空间，不代表 Intel32 页表或真实镜像验收。现代命名空间真实镜像、
Intel32 平台及 timeline 接入仍缺验证，不能据此提升完整插件合同。
