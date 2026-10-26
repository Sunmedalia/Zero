# Zero v0.2.0

终端界面迁移为 Rust 原生实现，与取证引擎一起编译进 `zero`。下载对应平台归档后即可启动，不再需要 Node、npm、TypeScript 界面或独立后端进程。

## 原生界面

- Ratatui + Crossterm 渲染，后台线程直接调用共享引擎服务；保留 CLI、MCP 和兼容 JSON-RPC 接口。
- 资源库支持镜像、本地符号和远程索引；保留既有设置、项目清单、缓存及导出记录格式。
- 选用镜像后先校验 SHA256、识别系统并匹配精确符号；匹配成功自动进入对应 Linux／Windows 分析页，不自动运行插件。系统按钮只显示 Linux／Windows，也支持手动切换。
- 远程索引搜索框常驻，支持读取已保存索引、全部／镜像匹配视图以及下载并选用或仅下载。
- 分析页提供结果标签、筛选、排序、树折叠、详情、导出和历史记录；窄屏详情覆盖结果区，宽屏使用侧栏，缩放时保留选择及滚动位置。
- 缓存页按镜像分组，支持范围清理与条目删除的二次确认；进入缓存页不会中断正在运行的分析。
- 保留主题、参数与七种转储模式；补齐鼠标命中、常用快捷键、诊断分类和缓存来源／耗时提示。

## 验证与发布包

本地通过格式检查、Clippy、386 项常规测试和真实 Linux 样本的原生界面／兼容后端验收。CI 在 Linux、macOS 的 x86_64 和 ARM64 上检查、构建、打包，并通过 PTY 在空 PATH 与不同工作目录中验证启动、退出及终端恢复。真实样本验收不在 CI 中执行。

归档包含原生可执行文件与文档，不包含镜像、符号或本地运行数据。Linux 包在 Ubuntu 24.04 构建，需兼容的 glibc。

## 安装

下载对应平台归档及 `SHA256SUMS`，校验后解压运行：

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar xzf zero-0.2.0-<平台>.tar.gz
cd zero-0.2.0-<平台>
./zero
```

详见[使用指南](https://github.com/sunmedalia/zero/blob/v0.2.0/docs/usage.md)、[原生界面说明](https://github.com/sunmedalia/zero/blob/v0.2.0/docs/tui.md)及[功能对齐记录](https://github.com/sunmedalia/zero/blob/v0.2.0/docs/tui-parity.md)。
