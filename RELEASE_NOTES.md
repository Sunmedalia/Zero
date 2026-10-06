# Zero v0.1.0

原生 Rust Linux／Windows 内存取证工具，包含 CLI、TUI 和 stdio MCP。

- 新增 Windows callbacks、unloadedmodules、filescan、mutantscan、getsids，以及 NT5 connscan／sockscan。
- TUI 支持切换系统视图，插件显示短名称；自动模式根据镜像证据识别系统。
- 新增 Server 2008、2012、2012 R2、2019、2022 真实样本验收和逐插件兼容矩阵。
- 修复旧 x86 PDB 符号修饰、41 位句柄指针、VAD 父指针与损坏路径、triage 重叠范围；优化分散物理页段读取。
- 支持精确 ISF／PDB、本地离线符号、受限 crash／minidump／休眠与分页读取；部分分析保留诊断。

本地验证：169 项常规测试、12 项 Windows 真实镜像验收、4 项 Linux 真实镜像回归通过。CI 使用合成测试，不下载真实镜像或符号。

Server 2016 仅验证发布者标注的小型内核转储的上下文与模块；Server 2003 R2、2008 R2、2025 仍待单独真实样本验证。兼容范围以 README 和逐插件矩阵为准。

发布包提供 Linux／macOS 的 x86_64 和 ARM64 构建，每包包含 `zero`、`zero-tui`、`zero-mcp` 和 README。Windows 指分析镜像系统；本版本没有 Windows 宿主可执行文件。Linux 包在 Ubuntu 24.04 构建，需要兼容的 glibc 环境。使用 `SHA256SUMS` 核验下载文件。
