# MCP 与 Agent 调用

[返回项目入口](../README.md) · [调用示例](../.agents/skills/zero-forensics/references/calls.md)

构建 `cargo build --release --locked --bin zero-mcp`。通过项目的 `.codex/config.toml` 或 `.mcp.json` 配置 stdio 服务；移动项目后检查配置路径。相对路径以 `ZERO_ROOT` 为基准，未设置时使用启动目录。镜像始终留在本地，在线请求只用于符号。

## 工具与快照分页

工具包括 `zero_plugins`、`zero_symbols`、`zero_analyze`、`zero_results`、`zero_dump` 和 `zero_cache_list`。

1. 调用 `zero_analyze`，传入镜像、插件、精确符号以及可选 `limit`、`output`。默认返回 50 行，最多 200 行，并返回 `result_id`。
2. 用 `zero_results` 传入 `result_id`、`offset: next_offset` 和 `limit`，直到 `next_offset` 为 null。
3. `zero_results` 的可选 `output` 导出整个快照，不受当前页影响。JSON 保留完整状态和诊断，CSV 只包含表格。

```json
{"result_id":"使用首次分析返回的 ID","offset":50,"limit":50,"output":"exports/all.json"}
```

**接口迁移：** `zero_analyze` 不再接受 `offset`，包括 `offset: 0`；旧调用会返回迁移提示。首次分析直接省略 offset，后续分页改用 `zero_results`。更新客户端工具清单并重启服务。

快照固定本次执行的结果，即使源文件后来变化也不重新分析。新分析返回新 ID。默认最多 8 个快照，闲置 30 分钟过期，服务重启后全部 ID 失效；失效时重新分析。部分结果保留 `complete: false` 和全部诊断，快照不属于成功结果缓存。`no_cache: true` 跳过成功缓存，仍可生成分页快照。

## 任务与错误

同时只执行一个分析、符号查询／下载或转储任务。繁忙时新的此类请求返回 JSON-RPC `-32000`，任务结束后重试；ping 和已有快照读取仍可用。发送 `notifications/cancelled`，其 `params.requestId` 指向正在执行的请求，可取消该任务；等待原请求结束后再提交新任务。

每条输入请求上限 1 MiB，超限时丢弃该行并保留连接。参数按 schema 校验。工具失败检查 `isError`，分析结果另检查 `complete` 和 `diagnostics`；零行不代表完整覆盖。

`offline: true` 禁止该调用的符号网络请求。离线且没有远程索引时，用 `zero_analyze` 的 `banners` 插件识别内核，`zero_symbols` 仍需要索引。`zero_results` 只读取本服务快照，不访问镜像或网络。

`zero_dump` 要求显式 PID、目录和清单路径，最多返回 200 条清单行；完整清单见 output，不使用分析快照分页。

```sh
cargo test --locked --test native mcp_
```

## Windows 符号下载兜底

在线下载精确 PDB 时，微软返回 HTTP 404 会自动转向 [Volatility 官方 Windows 符号包](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)。程序用 HTTPS Range 读取 ZIP 目录和精确条目，不下载整个包；按 PDB 名称、GUID 和 Age 找到候选后，再校验 ISF 内部身份和架构。未知或多个候选明确报错，禁止使用邻近构建。

取得的 ISF 和来源清单保存到 `.zero/rust/symbols/isf/windows/`，后续可以离线复用。`offline: true` 不访问微软或官方 ZIP。超时、503、损坏 PDB 与转换失败不会自动触发官方包下载；已有 PDB 缓存失效后重新下载若返回 404，则会使用同一兜底路径。官方包也无精确匹配时，错误会保留身份及原因，TUI 提示导入精确符号。
