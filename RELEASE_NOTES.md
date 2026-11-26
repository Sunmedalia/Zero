# Zero v0.2.9

## 镜像格式

- 支持 QEMU/KVM ELF core（`virsh dump --memory-only`、`dump-guest-memory`），并读取其中的 VMCOREINFO 用于从镜像生成符号。
- 支持 VMware `.vmem` 配合 `.vmsn`／`.vmss`／`.vmsst` 快照重建物理内存。容器中的 vCPU CR3 会作为 Windows 页表发现的提示。
- 支持 AVML Snappy v2，以及 `.zst`／`.xz` 压缩镜像的自动识别。解压写入本地缓存时上限为 256 GiB。

## YARA 扫描

- 内置纯 Rust 的 YARA-X 规则引擎，支持多字符串条件、十六进制通配与跳转、正则，以及 `pe`、`elf`、`math`、`hash` 等模块，不依赖外部动态库。
- 新增无需符号的整镜像物理内存扫描 `linux.yarascan`／`windows.yarascan`。`linux.vmayarascan` 与 `windows.vadyarascan` 也可执行完整规则，原有 `--pattern` 字面量扫描保持兼容。
- CLI、MCP 和 TUI 均支持 `--yara-file`（单个规则文件或目录）与 `--yara-rules`（内联规则）。每次分析只编译一次规则。
- YARA 支持仍在持续完善，后续版本会继续改进。

## 分析能力

- 进一步对齐 Volatility 3 v2.28.2 的功能，例如：
  - Windows：MFT 备用数据流与常驻数据、注册表递归与 hive 导出、`psxview` 四视图、`malfind` 反汇编与导出、`callbacks` 补齐 BugCheck／Shutdown／文件系统回调、`pslist` 增加 SessionId／Wow64；
  - Linux：页缓存 inode 页与文件系统恢复、模块导出、eBPF／ftrace／tracepoint 补充字段、`timeliner` 与 SleuthKit bodyfile 导出。
- 新增进程全景档案（`zero dossier --pid`）和应急初筛剧本（`zero triage`），会跨插件关联指定 PID 的血缘、命令行、文件、网络与权限，并汇总异常信号。
- 新增只读内存检查器（`zero inspect`），支持内核、进程及物理地址空间的十六进制查看，按 ISF／PDB 展开结构体并跟随指针，并提供 Capstone 反汇编。
- CLI 新增 `zero plugins` 与 `zero diagnose`。MCP 新增 `zero_symbols_generate`、`zero_diagnose`、`zero_doctor`、`zero_dossier`、`zero_triage`、`zero_inspect`。dump 新增 `lsmod` 与 `memmap` 模式。

## 插件名称

- 全部 186 个插件统一为小写 `<系统>.<名称>` 形式（如 `linux.pslist`、`windows.registry.printkey`），双版本插件统一使用 `.full` 后缀。旧名称与 Volatility 3 类路径名称仍可作为别名使用。
- 修复 Windows 路由误收 Linux 或 dump 类插件时，可能返回标记为完整的空结果。
- 本版分析结果格式有变化，升级后首次分析会重新计算并刷新缓存。

## 界面

- 结果表头的列分隔线可拖动调整列宽，双击恢复自动宽度。命令面板新增 `<`／`>`／`=` 调整或重置列宽。列宽随结果视图保存。
- 分析页结果行按 `E` 打开进程档案，按 `T` 运行初筛剧本，按 `x` 打开内存检查器。
- 修复参数表单部分字段无法编辑的问题。
- 已知问题：选择符号期间切换到另一个插件再确认时，重试结果的标签与显示内容可能不一致（[#26](https://github.com/sunmedalia/zero/issues/26)）。

## 安装

提供 Linux x86_64、Linux ARM64 和 macOS ARM64 归档。下载对应归档及 `SHA256SUMS`，校验后解压运行。

[使用指南](https://github.com/sunmedalia/zero/blob/v0.2.9/docs/usage.md) · [界面说明](https://github.com/sunmedalia/zero/blob/v0.2.9/docs/tui.md) · [兼容矩阵](https://github.com/sunmedalia/zero/blob/v0.2.9/docs/compatibility.md)
