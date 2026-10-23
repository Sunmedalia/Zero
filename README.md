# Zero · Rust 原生终端取证

本地 Linux x86_64／ARM64 和 Windows 内存取证工具。分析引擎使用 Rust 2024，终端界面使用 TypeScript（Ink，自绘字符画布）并通过本地 JSON-RPC 驱动该引擎；键盘与鼠标都完整可用。提供 TUI、CLI 和原生 stdio MCP，取证分析本身无需 Python、Node 或 HTTP 服务。

发布包包含 `zero` 可执行文件、README 和 `ts/` 界面源码。直接运行 `zero` 会启动 TypeScript 界面（需要 Node ≥ 22），使用子命令执行 CLI 操作，`zero mcp` 启动 MCP 服务，`zero tui-backend` 启动界面使用的本地后端。

## 快速开始

```sh
cargo build --release --locked
cd ts && npm install --no-audit --no-fund && npm run build && cd ..
./target/release/zero
# 同一个可执行文件也提供 MCP 服务
./target/release/zero mcp
# 使用明确的本地镜像和精确匹配符号
./target/release/zero --offline analyze \
  --image /evidence/memory.raw --symbols /evidence/kernel.json.xz \
  --plugin pslist --output exports/processes.json
```

不带参数进入资源库；导入镜像和符号后进入分析。默认镜像目录为 `images/`，符号目录为 `symbols/`，运行数据保存到 `.zero/rust/`。镜像只读，资产移除只修改项目清单。界面目录可用 `ZERO_TUI_DIR` 指定，后端可执行文件由 `zero` 自动传递。

## 文档

- [TUI、CLI、插件与转储操作](docs/usage.md)
- [TypeScript 界面的架构与开发](docs/tui.md)
- [MCP 接口、快照分页与取消](docs/mcp.md)
- [Windows 兼容矩阵和真实样本验收证据](docs/compatibility.md)
- [开发检查、资源预算、CI 与发布](docs/development.md)
- [性能测量](docs/performance.md)
- [Agent skill](.agents/skills/zero-forensics/SKILL.md) 与 [调用示例](.agents/skills/zero-forensics/references/calls.md)

## 能力边界

支持 RAW、LiME、Windows crash/minidump、已识别布局的休眠容器及 gzip 镜像；符号支持 JSON、JSON.XZ 和 ZIP 内 ISF。Linux 按完整 banner 匹配，Windows 按精确 PDB GUID/age 匹配；不猜测相近版本。微软 PDB 返回 404 时，在线模式自动从 Volatility 官方 Windows 符号包按需取得精确 ISF，并缓存供离线复用。

缺页、布局未验证或对象损坏会保留部分结果及诊断，部分结果不写入成功缓存。休眠和压缩 store 的部分路径只有合成验证，具体范围以兼容矩阵为准。在线模式只查询／下载符号，`--offline` 禁止网络请求。

MCP 分页现使用 `zero_analyze` 返回的 `result_id` 调用 `zero_results`；旧 `zero_analyze.offset` 已移除，迁移方法见 MCP 文档。

## 检查

```sh
make check
python3 scripts/windows_compatibility.py --check
```

`make check` 会先构建 TypeScript 界面，再运行 fmt、Clippy、Rust 测试、`tsc --noEmit`、界面单元测试和 release 构建。

真实镜像验收需本地样本，命令和环境变量见开发文档。
