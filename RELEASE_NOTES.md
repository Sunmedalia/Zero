# Zero v0.1.9

修复发布包启动时报 `Cannot find package 'ink'` 的问题。四个平台的归档现在同时包含 Node 运行时和界面生产依赖，下载解压即可运行，无需预装 Node、npm，也无需在线安装依赖。

## 独立运行的发布包

- Linux／macOS 的 x86_64、ARM64 包各自包含对应平台的 `runtime/node`、Node 许可证和 `ts/node_modules`。
- `zero` 优先使用归档内的运行时与界面，支持从其它工作目录启动；源码开发仍可使用系统 Node。
- CI 对每个平台的归档执行解压启动验证，在系统 Node 不可用的环境中启动真实终端界面、连接 Rust 后端并退出。
- CLI、MCP、取证引擎的运行方式保持一致。归档不包含镜像、符号或本地运行数据。

## 安装

下载对应平台的归档及 `SHA256SUMS`，核验后解压：

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar xzf zero-0.1.9-<平台>.tar.gz
cd zero-0.1.9-<平台>
./zero
```

请保留 `zero`、`runtime/` 和 `ts/` 的相对目录结构。Linux 包在 Ubuntu 24.04 构建，仍需兼容的 glibc；不需要系统安装 Node 或 npm。

v0.1.8 新增的凭证提取、VAD／DLL／模块／文件缓存转储与线程池扫描均包含在本版本中。具体范围与限制见[使用指南](https://github.com/Sunmedalia/Zero/blob/v0.1.9/docs/usage.md)和[兼容矩阵](https://github.com/Sunmedalia/Zero/blob/v0.1.9/docs/compatibility.md)。
