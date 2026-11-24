# Zero v0.2.8

## Linux 内存取证

- 新增 13 个使用 Volatility 3 完整名称的分析入口，涵盖进程树、内存映射、打开文件、套接字、内核日志、可疑内存映射、挂载、页缓存、Bash 历史、ELF、共享库及网络接口。部分入口支持按 PID 或命名空间筛选，以及导出对应的内存片段。
- 新增 Zsh 内存历史分析，包含命令开始和结束时间。Bash 历史扫描会保留缺页前后已恢复的条目，`psaux` 会保留命令行不可读的进程并给出诊断。
- 改善 Linux 7.0 内核兼容性及 Ubuntu ddebs 调试包自动发现。

## 符号生成

- 支持在 CLI 和 TUI 中离线从 x86_64 镜像生成 Linux 符号。生成使用内核自带的 BTF 与 kallsyms，结果在保存前经过页表验证。缺少生成所需数据时，可验证并复用已有的精确匹配 ISF。
- TUI 增加生成日志，显示扫描、解析和保存进度。同一镜像再次生成时可复用通过校验的产物。

## 扫描与界面

- 修复内存模式扫描的重叠命中和跨页覆盖，保留部分扫描中已收集的结果。
- 优化镜像读取、地址转换、符号字段查找及 Linux 和 Windows 分析的常用路径。
- 改善大型结果和后台任务运行时的 TUI 响应速度，修复结果尚在生成时的导出和启动阶段的粘贴处理。

## 安装

提供 Linux x86_64、Linux ARM64 和 macOS ARM64 归档。下载对应归档及 `SHA256SUMS`，校验后解压运行。

[使用指南](https://github.com/sunmedalia/zero/blob/v0.2.8/docs/usage.md) · [界面说明](https://github.com/sunmedalia/zero/blob/v0.2.8/docs/tui.md) · [兼容矩阵](https://github.com/sunmedalia/zero/blob/v0.2.8/docs/compatibility.md)
