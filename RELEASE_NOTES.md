# Zero v0.2.6

当配置的 GitHub 符号仓库没有对应内核时，现在可以从 Ubuntu、Debian、Kali 官方调试包生成精确 ISF，并持久保存到本地符号库。

## Linux 符号生成

- 资源库按 `K`、分析页按 `g` 打开生成入口。自动查找官方调试包，展示构建、下载来源与可用大小，确认后下载生成。
- CLI：`zero symbols-generate --image memory.raw --auto`；多个候选使用 `--candidate <序号>`。保留本地 ELF／config／工具输入及固定 Kali 入口。
- 同一构建的多个 banner 与官方来源合并为一个候选；生成结果的完整 banner 必须同时匹配镜像和选中的构建。
- 支持 XZ、gzip、Zstandard 的 deb／ddeb 数据成员，仅提取所需文件，不安装内核或执行包脚本。

## 缓存、重试与本地保存

- CLI、TUI 与 Kali 入口使用同一生成服务。成品保存到配置的本地符号目录（默认 `symbols/`），附带官方包 URL、包版本及文件摘要。
- 官方目录索引缓存 24 小时，未命中时在线刷新一次，网络失败可回退有效旧缓存；CLI 使用 `--auto --refresh`、候选弹窗按 `F5` 强制刷新。
- 重试会验证下载、提取与生成阶段的文件，跳过已完成阶段；构建、转换工具和成品保存使用并发锁。
- 同内容成品保留已有来源记录；附件缺失或损坏不阻止有效符号离线复用。清理构建缓存不删除本地成品。

## 验证与安装

通过本地全量检查及 Debian／Kali 四项真实样本回归。真实 Kali 验收覆盖官方包生成、阶段恢复、缓存清理和来源附件缺失后的离线分析，恢复 169 个进程。

下载对应平台归档和 `SHA256SUMS`，校验后解压运行。首次自动准备符号转换工具需要 Git 与 Go，也可指定已有工具。官方源需仍保留对应调试构建；本版不扩大分析引擎的内核兼容范围。

详见[使用指南](https://github.com/sunmedalia/zero/blob/v0.2.6/docs/usage.md)、[界面说明](https://github.com/sunmedalia/zero/blob/v0.2.6/docs/tui.md)和[兼容矩阵](https://github.com/sunmedalia/zero/blob/v0.2.6/docs/compatibility.md)。
