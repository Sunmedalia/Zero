# Zero v0.1.2

本次更新优化分析工作台的滚动与界面布局。

- 结果区域滚轮每次上下移动 1 行，连续滚动跨过原来的页边界时不再整页跳动；方向键逐行导航，PgUp／PgDn 和 `[`／`]` 保留翻页操作。
- 表头显示当前可见行范围，滚动后的鼠标点击定位保持准确；自定义行数下，点击列表底部空白处不会选中未显示的行。
- 删除搜索框上方的插件介绍、适用参数、草稿及运行／编辑参数按钮，搜索框直接置顶，释放空间显示更多结果。运行和参数编辑仍可通过快捷键操作。
- 分析页底部按钮统一为“操作名 快捷键”，统一颜色、背景和间距；窄窗口保留“详情”和“更多”入口。

本地 `make check` 通过：格式检查、Clippy、225 项自动测试和 release 构建。回归覆盖逐行滚动、页边界、首尾边界、鼠标定位、键盘翻页及 TUI 布局。

发布包提供 Linux／macOS 的 x86_64 和 ARM64 构建，每包包含 `zero`、`zero-tui`、`zero-mcp` 和 README。Windows 指分析镜像系统；本版本没有 Windows 宿主可执行文件。Linux 包在 Ubuntu 24.04 构建，需要兼容的 glibc 环境。使用 `SHA256SUMS` 核验下载文件。

用法与兼容范围见 [使用文档](https://github.com/Sunmedalia/Zero/blob/v0.1.2/docs/usage.md) 和 [兼容文档](https://github.com/Sunmedalia/Zero/blob/v0.1.2/docs/compatibility.md)。
