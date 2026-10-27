# Zero v0.2.1

新增 Rust 原生 TUI 内核诊断，改进分析页面交互与符号下载。

## 内核诊断

- 在资源库、分析页操作栏或命令面板选择“内核诊断”，也可按 `J` 打开。
- 离线检查镜像格式、SHA256、物理区段、内核身份、精确符号及内核页表，支持 Linux 与 Windows。
- 保留符号候选的失败证据；Linux 校验错误包含重定位候选、`init_task`、链表头及双向回指，便于区分符号、缺页和重定位问题。保留完整校验条件。
- 报告支持滚动查看、`r` 重新诊断、`e` 导出 JSON/TXT，不运行分析插件，保留已有结果与标签页。
- 此功能用于定位问题，不代表已解决所有 Debian 6.12 镜像的页表验证失败。

## 界面与通信

- 分析标签页增加横向移动按钮；插件面板通过 `<<` 收起，在内容区右下角通过 `>>` 展开。
- `/` 搜索窗口跟随当前插件区或内容区；符号、镜像等弹窗支持点击外部关闭。
- 优化镜像、符号和校验状态布局。
- 移除迁移期间的 TUI JSON-RPC 兼容后端，使用 Rust 原生任务通信；标准 MCP 接口保留。
- 符号下载增加 `gh-proxy.com` 代理路径。

## 验证与平台

本地通过格式检查、Clippy、396 项常规测试、真实 Linux 镜像的 TUI 诊断验收及发布包启动检查。发布流水线对以下三个平台重新检查、测试、构建和验证：

- Linux x86_64
- Linux ARM64
- macOS Apple Silicon（ARM64）

macOS 不再发布 Intel 包。Linux 包在 Ubuntu 24.04 构建，需要兼容的 glibc。归档包含原生可执行文件与文档，不包含镜像、符号或本地运行数据。

## 安装

下载对应平台归档及 `SHA256SUMS`，校验后解压运行：

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar xzf zero-0.2.1-<平台>.tar.gz
cd zero-0.2.1-<平台>
./zero
```

详见[使用指南](https://github.com/Sunmedalia/Zero/blob/v0.2.1/docs/usage.md)与[原生界面说明](https://github.com/Sunmedalia/Zero/blob/v0.2.1/docs/tui.md)。
