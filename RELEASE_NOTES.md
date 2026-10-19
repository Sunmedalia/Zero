# Zero v0.1.4

本次更新加入 Linux `netscan`，改进资源操作与小窗口布局，并优化镜像准备、TUI 和 Linux／Windows 插件的执行开销。

- Linux 新增 `netscan`，通过进程 FD 枚举 TCP／UDP IPv4／IPv6 socket，显示端点、状态和所属进程；同一进程的重复引用合并，共享 socket 的不同进程分别保留。CLI、TUI 和 MCP 均可使用。它不扫描无进程 FD 引用的对象或已释放连接。
- Bash 历史恢复在插件列表中统一为 `bash`，旧命令中的 `history` 保留为兼容别名。
- 资源库操作集中到底部工具栏，随当前区域切换；搜索框按需显示。布局根据可用空间调整工具栏、详情、插件列表和对话框，修复长路径、插件名称、标题和选中行被裁切或移出视口的问题，并保持焦点与实际显示区域一致。
- 减少 TUI 每帧分配，缓存路径、资源及远程索引筛选结果，忽略不需要重绘的鼠标移动。Windows 句柄扫描缓存对象类型名，pool 扫描与页表遍历复用缓冲区；Linux 路径扫描按进程复用根目录解析。部分镜像摘要路径并行读取与哈希。
- 增加跨页面和终端尺寸的布局回归测试，以及恶意结果文本、分页边界、畸形 ELF 和镜像读取边界测试；WOW64 loader 列表与对应偏移在同一表中维护。

发布工作流对 Linux／macOS 的 x86_64 和 ARM64 四个目标执行格式检查、Clippy、自动测试、release 构建、兼容文档检查和命令行冒烟测试，通过后发布安装包与 `SHA256SUMS`。需要本地镜像或符号数据的 ignored 验收测试不在此工作流中执行。

每包包含 `zero`、`zero-tui`、`zero-mcp` 和 README。Windows 指分析镜像系统；本版本没有 Windows 宿主可执行文件。Linux 包在 Ubuntu 24.04 构建，需要兼容的 glibc 环境。使用 `SHA256SUMS` 核验下载文件。

用法与兼容范围见 [使用文档](https://github.com/sunmedalia/zero/blob/v0.1.4/docs/usage.md) 和 [兼容文档](https://github.com/sunmedalia/zero/blob/v0.1.4/docs/compatibility.md)。
