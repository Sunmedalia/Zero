# Zero v0.1.3

本次更新加入跨会话 banner 识别缓存复用，并修复 x86_64 KASLR 下符号匹配成功但页表验证失败的问题。

- 首次完成识别后，将完整 banner 与物理地址原子保存到 `.zero/rust/identification/`。再次启动或选用相同镜像时，核对源文件和解压文件元数据并读取候选位置，直接复用识别结果，省去全镜像扫描。TUI、CLI 和 MCP 的识别与符号匹配均使用该缓存。
- 源文件变化、识别缓存损坏、gzip 解压文件损坏或丢失时自动重新准备；正式分析仍校验完整镜像摘要，分析结果缓存仍以已验证摘要为依据。
- x86_64 页表定位从 `init_task.real_parent` 自指针推导 KASLR 偏移候选，再用运行时地址验证完整 banner、PID 0、swapper 名称和双向任务链表。验证成功后将偏移用于后续符号访问，拒绝错误或歧义候选。
- 分析引擎缓存版本更新为 `native-15`，旧版分析结果缓存自动失效。

本地 `make check` 通过：格式检查、Clippy、230 项自动测试和 release 构建。新增回归覆盖跨会话识别、TUI 重启、缓存损坏恢复、gzip 解压缓存失效、LiME 跨段边界，以及高于 4 GiB 的物理地址与非零 x86_64 KASLR 偏移；后者复现了未重定位虚拟地址在 `level 21` 缺页的失败，并验证修复后的进程与模块读取。

x86_64 KASLR 验证使用合成 LiME 镜像，尚未对用户报告的 Debian 6.12.105 实际镜像完成验收。未压缩的 AVML LiME 输出可按 LiME 读取；AVML 的 Snappy 压缩格式不属于当前支持的 gzip 格式。五级页表仍不支持。

发布包提供 Linux／macOS 的 x86_64 和 ARM64 构建，每包包含 `zero`、`zero-tui`、`zero-mcp` 和 README。Windows 指分析镜像系统；本版本没有 Windows 宿主可执行文件。Linux 包在 Ubuntu 24.04 构建，需要兼容的 glibc 环境。使用 `SHA256SUMS` 核验下载文件。

用法与兼容范围见 [使用文档](https://github.com/Sunmedalia/Zero/blob/v0.1.3/docs/usage.md) 和 [兼容文档](https://github.com/Sunmedalia/Zero/blob/v0.1.3/docs/compatibility.md)。
