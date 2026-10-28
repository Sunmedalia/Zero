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
