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
过滤器信息。IPv6 端点指针始终通过内核虚拟层读取，端点不可读时保留端口等其余字段并
标记部分结果。32 位仍未实现，罕见家族和更多内核仍缺真实差分样本。

公开 Debian 默认运行：Zero 477 条，固定参考 404 条。默认严格比较**未通过**，
并保留原始输出与差异，不将其写成默认对齐通过。具体差异为：

- 参考的 file-ops 分支未更新用于去重的物理地址，以 None 作为键，和 destructor
  来源出现一条重复 Unix 行。Zero 按最终物理地址去重，不复制该重复行。
- 参考 inet_sock 从当前物理层读取 pinet6 指向的虚拟 IPv6 地址，12 个共有对象的两端
  地址均返回不可用；Zero 能读取这些地址。参考随后以源地址不可用参与空对象过滤，
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

默认全任务比较仍未通过：Zero 8462 / 参考 8120 行，342 条额外行均为模块符号归属；
没有遗漏参考行或共有字段冲突。PID 1 默认 38 / 37 行，含未解析值时两端均 383 行，
但 Name、Type、Module 有三处参考单边不可用。因此这三项不计入正向证据，完整默认输出
仍独立比较；摘要哈希和差异计数保存在 `pscallstack-known-differences.json`。
固定参考的模块范围计算源码包含 `value & mask + size` 的运算优先级问题，且旧内核
模块分配范围取自配置中的符号地址；这些源码行为尚不能单独证明本样本全部差异的因果。
Zero 不通过删除模块解析结果或忽略字段来制造通过。

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

三份实际镜像的默认输出为 Win10 4255、Server 2008 x86 3724、Win11 3444 行。前五字段
唯一投影与参考一致；完整六字段默认比较仍失败，不能视为完整对齐。参考把内核 ISF
用于外部模块，产生 250/96/158 个外部符号行（Win11 另有 9 行别名），Zero 目前保留
外部 Symbol 缺失。内核模块范围的六字段用例分别有 2066/1723/1656 行通过；范围限制
写入映射，完整失败证据见 [差异记录](../tests/reference/parity/driverirp-known-differences.json)。

累计正式入口对应 109/135，仍缺 26 个 Windows 插件；42 项正向差分用例中有 5 项明确
限定记录范围。完整插件合同通过数仍为 0。下一步需补外部驱动精确 PDB/模块符号解析，
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

`windows.windowstations.WindowStations` 按参考插件扫描 `Wind` 池标签，只接受 x64，并按版本选择同一套 GUI 符号表。候选先在内核扫描层读取会话号，再进入该会话的进程地址空间读取对象名和 `rpwinstaNext`。名称保留参考的 UNICODE 长度检查，并拒绝控制字符。地址按参考 JSON 的 48 位值渲染。Win10 15063 的 8 条真实窗口站与固定参考一致；参考另有 7 条非规范短名称来自错误链，不作为正向记录。Win7 7601 两侧均为 0。完整插件合同仍为 0，候选入口对应提升至 **123/135**，尚缺 12 个。

## native60：桌面

`windows.desktops.Desktops` 复用窗口站扫描，只接受 x64，并按同一套 GUI 符号表读取 `rpdeskList`。桌面名称在会话地址空间解析，线程链表按 `tagTHREADINFO.PtiLink` 前进。进程先从内核层读取 `ImageFileName` 和 `UniqueProcessId`；内核页缺失时退回发现该指针的会话地址空间。指针按页截断时仍按参考的 `ppi.Process` 取值，进程名读不出则保留空名称和截断 PID。地址按参考 JSON 渲染为 48 位。Win10 15063 的 28 行全字段一致，其中一行是参考自身的截断进程记录。Win7 7601 两侧均为 0。完整插件合同仍为 0，候选入口对应提升至 **124/135**，尚缺 11 个。
