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
