# Zero v0.1.1

原生 Rust Linux／Windows 内存取证工具，包含 CLI、TUI 和 stdio MCP。

## 恶意检测

- 新增 `windows.ldrmodules`：对照文件映射中的 PE 与 PEB 三条模块链表，支持 native/WOW64；读取失败的链表显示 unknown。
- 新增 `windows.hollowprocesses`：检查主程序基址不一致、私有映像、异常 VAD 属性和主程序映射缺失。
- 新增 `windows.suspicious_threads`：检查活动线程的两个起点字段与所属 VAD，跳过已终止线程和内核起点。
- 新增 Linux `check_exec`：检查主程序代码映射、执行权限和文件 inode 一致性。
- 四个插件均接入 CLI、TUI 和 MCP，支持 PID 筛选。检测结果是核查线索；缺页和结构损坏保留诊断，部分结果不进入成功缓存。真实恶意样本检出率尚未验证。

## TUI、性能与符号

- 重建 TUI 资源库与分析工作台，改进主题、窄窗口适配、插件激活和任务取消流程。
- TUI 筛选和排序复用行索引，结果缓存与导出流式写入原子文件。
- Windows Session 复用精确解析的 ISF，页表／扫描缓存提供可配置资源预算。
- 精确 Microsoft PDB 请求返回 HTTP 404 时，从 Volatility 官方 Windows 符号 ZIP 按需取得精确 ISF，校验 PDB 名称、GUID/age 和架构后缓存；支持离线复用。
- Linux 分析引擎和 TUI 按功能拆分模块，共享插件注册与字段解析逻辑。

## MCP 迁移

`zero_analyze.offset` 已移除。请使用返回的 `result_id` 调用 `zero_results` 分页或导出；快照有有效期且仅存在于当前进程。长任务支持取消和忙碌状态，输入大小受限。详见 [MCP 文档](https://github.com/Sunmedalia/Zero/blob/v0.1.1/docs/mcp.md) 与 [资源预算](https://github.com/Sunmedalia/Zero/blob/v0.1.1/docs/development.md)。

## 验证与下载

本地 `make check` 通过：格式检查、Clippy、224 项自动测试和 release 构建。新增检测包含五项合成测试；Linux `check_exec` 另通过本地 Debian 3.2 镜像 PID 1 的离线 CLI 验证。兼容矩阵区分真实、合成和待验证范围，详见 [兼容文档](https://github.com/Sunmedalia/Zero/blob/v0.1.1/docs/compatibility.md)。CI 不下载真实镜像或符号。

发布包提供 Linux／macOS 的 x86_64 和 ARM64 构建，每包包含 `zero`、`zero-tui`、`zero-mcp` 和 README。Windows 指分析镜像系统；本版本没有 Windows 宿主可执行文件。Linux 包在 Ubuntu 24.04 构建，需要兼容的 glibc 环境。使用 `SHA256SUMS` 核验下载文件。
