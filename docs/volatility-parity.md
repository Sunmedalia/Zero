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
