# Zero v0.2.2

本版汇总 v0.2.1 之后的原生 Linux／Windows 取证改进，重点是固定 Volatility 参考差分、Linux 模块导出、页表与 maple VMA 恢复。分析仍全部由 Rust 执行，运行发布包无需 Python 或 Volatility。

## Linux 模块与内存恢复

- `lsmod` 提供 Offset、Module Name、Code Size、Taints、Load Arguments、File Output 六列，按实际 ISF 布局读取模块参数与代码大小。
- 支持通过 CLI、TUI 和 MCP 导出指定模块的 ELF，校验固定参考的文件名、内容及故障行为；导出使用原子写入，避免覆盖已有证据。
- 模块名按固定参考保留可读前缀、控制字符，并在 NUL 或非法 UTF-8 替换字符处截断；模块扫描按 ISF 指针宽度与对齐相位处理。
- maple 遍历覆盖 dense、leaf、range 和 arange 全部 slot，验证父回指，保留重复 VMA；遇重复子树、已删除节点和 map_count 不一致时，尽可能保留可读兄弟子树并明确标记 partial。
- Kali 真实样本的受损进程恢复 6 条映射及对应 ELF／可执行匿名映射线索；仍保留缺页与覆盖不足诊断，不将部分结果写入成功缓存。
- 改进 Boottime 的 timekeeper 布局、时间命名空间和时间线类型，并补充字段读取故障边界验证。

## 页表、Windows 与验证工具

- 增加 Linux32／PAE 页表、PROT_NONE 与 ELF32 模块重建的内部基础和固定参考向量。公开 Linux32 ISF 入口仍关闭，真实 Linux32 端到端验收尚未建立。
- Windows 新增／完善 DebugRegisters、SuspendedThreads、PESymbols、Strings、WindowStations、Windows、KPCRs、VadWalk 与 VadRegExScan 等原生入口，并为对应场景补充实际参考差分。
- Linux 增加／完善 PsCallStack、Sockscan、Kallsyms、Capabilities 与 PsList 参数化输出，复用有界栈扫描、符号索引及 socket 解码。
- 改进 Windows Intel 地址别名、映射扫描、驱动精确符号及验收样本定位；保留分页、压缩页和部分覆盖诊断。
- 加强参考证据校验，拒绝失败导出和符号链接文件作为产物一致性证据。
- 更新 README、使用指南和开发说明，区分真实样本、合成向量与完整插件合同，移除过期的前端构建说明。

## 验证范围

发布前运行本地 `make check`；GitHub Actions 在 Linux x86_64、Linux ARM64、macOS ARM64 上重新执行检查、测试、release 构建和归档启动验证。真实镜像验收需要本地镜像与精确符号，CI 不下载大型样本。

当前冻结参考为 Volatility 3 v2.28.2：登记 162 个通过案例，其中 5 个限定记录范围；**完整插件合同为 0/135，尚未全面对齐 Volatility**。固定参考不提供 ARM64 翻译层，Kali 原生验收不能视为完整 Volatility ARM64 插件差分。

## 安装

下载对应平台归档和 `SHA256SUMS`，校验后解压运行。Linux 包使用 Ubuntu 24.04 构建，需兼容的 glibc。发布包不包含镜像、符号、凭据或本地运行数据。

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar xzf zero-0.2.2-<平台>.tar.gz
cd zero-0.2.2-<平台>
./zero
```

详见[使用指南](https://github.com/Sunmedalia/Zero/blob/v0.2.2/docs/usage.md)、[兼容矩阵](https://github.com/Sunmedalia/Zero/blob/v0.2.2/docs/compatibility.md)和[对齐进度](https://github.com/Sunmedalia/Zero/blob/v0.2.2/docs/volatility-parity.md)。
