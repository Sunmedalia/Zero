# Rust 原生终端界面

[← 项目首页](../README.md) · [使用指南](usage.md) · [开发与发布](development.md) · [功能对齐检查](tui-parity.md)

TUI 使用 Ratatui + Crossterm，与分析引擎一起编译进 `zero`。构建和运行不需要 Node、npm 或外部界面文件。直接运行 `zero` 打开资源库，传入 `--image` 时打开分析工作台；选择镜像后先校验 SHA256，再匹配本地精确符号；资源库选用并匹配成功后自动进入对应 Linux／Windows 分析页，不自动运行插件。分析页只显示 Linux／Windows 按钮，可手动切换，系统自动识别在后台完成。

## 架构与启动

```text
zero
├─ 无子命令       Rust TUI → 后台线程 → 共享引擎服务
├─ analyze|dump|… CLI → Rust 分析引擎
├─ mcp           stdio MCP
└─ tui-backend   保留兼容的 JSON-RPC over stdio
```

`src/tui.rs` 管理终端生命周期与事件循环；`src/tui/` 按应用状态、动作、布局、页面、对话框、任务、标签、滚动条和主题拆分。`src/engine_service.rs` 共享项目路径、镜像校验、识别、匹配、分析、缓存清单和符号保存逻辑；`src/tui_backend.rs` 保留协议适配。原生界面使用 Rust 类型传递请求与结果，不启动子进程或编码 JSON-RPC。

项目根目录使用 `ZERO_ROOT`，未设置时使用当前目录。设置中的相对路径、输入路径和 CLI 初始选择均按项目根目录解析。`--offline`、`--image`、`--symbols`、`--os`、`--arch`、`--pagefile`、`--swapfile`、`--hive`、`--key`、`--pattern` 保持支持。旧设置、项目清单、缓存、部分结果与导出记录继续使用，无需迁移。`ZERO_TUI_DIR`、`ZERO_TUI_BACKEND` 不再用于原生界面。

## 布局与输入

- `1`／`2`／`3` 切换资源库、分析、缓存；兼容 F2／F3／F4。`?` 或 Ctrl+P 打开命令面板，`,` 打开设置。
- `H` 帮助、`S` 系统、`R` 运行、`V` 校验镜像；兼容原功能键。
- 资源库的镜像、本地库、远程索引分别占满内容区域，Tab／Shift+Tab 切换来源。路径按显示宽度换行，多行条目与点击共用矩形；`d` 打开详情。
- 分析页 100 列且 24 行起使用插件／结果双栏；80×24 显示聚焦区域；顶部按钮或 `B` 收起／展开插件列表，收起后结果使用全部可用宽度。详情默认关闭，160 列且 28 行起可显示 38 列侧栏，其余尺寸覆盖结果区。
- 小于 60×16 显示尺寸提示。中文宽字符与组合字符由终端 Buffer 绘制，控制字符转义显示。
- 结果表支持筛选、排序、树折叠、水平滚动和结果标签。Ctrl+PgUp／PgDn 切换标签，Ctrl+W 关闭；标签支持点击、关闭按钮及中键关闭；标签保持可读宽度，超出时用右侧 `<`／`>` 平移展示，不改变当前结果。关闭运行中的插件前须先取消。
- 鼠标支持页面、来源、按钮、列表行和表头；滚轮滚动列表，右边框滚动条支持跳转及拖动。绘制使用的区域同时注册为命中区域。点击弹窗外会关闭弹窗，并消费该次点击。
- 缓存页提供范围与条目两列，Tab 或 ←／→ 切换焦点，Space 勾选范围；鼠标第一次点击高亮，第二次执行。结果按镜像分组，Enter 折叠／展开组或打开导出记录；Delete 删除条目／组，x 清理勾选范围（兼容 C），同一清理键再次确认后执行，Esc 撤销。
- dump 表单用 Alt+1…7 选择当前系统支持的模式；保留 F2…F4。支持现有 Process、Range、ELF／PE、VAD、DLL、Module、Files 模式。参数表单支持 PID、hive、键、架构、分页文件和扫描模式，Ctrl+T 展开高级配置。

远程页始终显示搜索框，点击或 `/` 输入，Enter 确认、Esc 撤销；优先读取已保存的完整索引，不自动下载；`z` 或顶部按钮切换全部／当前镜像匹配，`g` 获取、`r` 刷新。进入缓存页使用独立清单查询，保留正在执行的分析。

分析页的系统按钮与页面导航同列，下一行直接显示镜像、符号及验证信息，不重复显示系统名称。

动作表统一定义命令、标签、快捷键、适用页面和展示位置；命令面板、资源工具栏与页脚复用该表。布局阈值集中在 `layout.rs`。

## 任务、取消和结果

文件分析、校验、符号操作、缓存清理、导出与历史加载在后台线程执行，使用引擎已有的 `Job` 进度及协作取消标志。任务在启动线程前分配标识；事件携带任务号和对象版本，旧会话和被取消的结果不会更新当前界面。同一时刻只执行一个长任务，重复请求取消旧任务后只执行最后一个请求。

Esc 按层级关闭弹窗／详情、清除筛选，最后取消任务。取消清空自动后续流程，下一次任务使用新的取消标志。退出时取消并回收 worker，恢复 raw mode、鼠标、括号粘贴和备用屏幕；UI panic 也恢复终端。

插件结果底边显示本次分析／缓存来源及耗时。部分结果保留诊断，可导出，沿用独立部分缓存；成功缓存语义不变。导出成功后记录校验副本；记录失败仍显示已导出，并报告记录错误。导出记录在内存中使用共享引用，标签切换无需复制行数据。

## 主题

保留石板、纸白、Solarized、荧光绿和高对比主题，设置中的 `theme` id 保持兼容。未知 id 回退到石板。`auto` 在 Unix 终端启动时查询 OSC 11，DA1 或最长一秒结束等待；无回复时使用 `COLORFGBG`，再回退深色。其他宿主使用 `COLORFGBG` 回退。调色板按 UI 线程保存，测试和截图可独立选择主题。

## 构建与检查

```sh
cargo build --release --locked
cargo run --release --bin zero
make check
make ui-test          # Rust TUI 单元测试的兼容入口
make tui-acceptance   # 需要本地真实样本
make screenshots     # Rust 示例使用真实引擎与同一个 Buffer 输出 SVG
```

常规测试使用内存结果和合成样本，覆盖状态机、任务竞态、布局、鼠标命中、宽字符、主题和终端尺寸。真实样本路径可通过 `ZERO_TEST_IMAGE`／`ZERO_TEST_SYMBOLS` 覆盖。发布包只包含原生可执行文件和文档，PTY 验证在空 PATH 及不同工作目录中运行。

## 协议

每行一个 JSON 对象。请求带 `id`，响应回带同一个 `id`：

```json
{"jsonrpc":"2.0","id":1,"method":"hello","params":{}}
{"jsonrpc":"2.0","id":1,"result":{"instance":"…","plugins":[…],"settings":{…}}}
```

长操作走任务协议，启动立即返回任务号，完成和失败以通知推送：

```json
{"jsonrpc":"2.0","id":2,"method":"task.start","params":{"op":"analyze","args":{…}}}
{"jsonrpc":"2.0","id":2,"result":{"task":"t1"}}
{"jsonrpc":"2.0","method":"task.progress","params":{"id":"t1","message":"验证内核页表和完整 banner"}}
{"jsonrpc":"2.0","method":"task.done","params":{"id":"t1","result":{"result":{…}}}}
```

同一时刻只允许一个任务，第二个 `task.start` 返回 `-32001`。`task.cancel` 设置引擎已有的协作取消标志；被取消的任务不会继续下载、选用或分析。任务结束时后端会自行释放任务槽，因此客户端即使收到结果后立即退出也不会挂住。

回复行和完成通知可能落在同一个管道读取块里。缓存命中的任务是毫秒级的，`task.start` 的 Promise 回调可能晚于 `task.done` 执行；客户端必须在启动阶段就接受带任务号的通知，否则完成事件会被当成未知任务丢弃，界面会永久停在“执行中”。兼容客户端仍须处理此顺序；Rust 原生 TUI 不经过管道，任务标识在启动 worker 前分配。

方法分两类：

| 类别 | 方法 |
| --- | --- |
| 同步查询 | `hello`、`assets`、`browse`、`cache.inventory`、`settings.get`、`settings.save`、`history.list`、`symbols.cached`、`registry.select`、`registry.register`、`registry.remove`、`registry.selected`、`session.reset`、`ping` |
| 任务 | `verify`、`analyze`、`dump`、`identify`、`matchLocal`、`remote`、`download`、`generate`、`inspectSymbols`、`cacheClear`、`cacheRemove`、`record`、`export`、`history` |

`verify` 为本次会话校验镜像内容（SHA256），回复 `digest`、`computed`（false 表示本会话已校验过，或设置允许复用上次记录）与 `seconds`；它把校验过的镜像留在会话中，之后的 `analyze` 直接使用。界面在选用镜像时先调用它，再做 `matchLocal`，所以插件请求不再承担整镜像读取。`assets` 中镜像条目的 `digest` 是上次完整校验记录的摘要（文件元数据未变时），只用于显示。

`cache.inventory` 返回 `entries`（含 `modified`；分析结果另带 `result`：所属镜像 SHA256 `image`、分析路径 `source`、`plugin`、`complete`、`rows`、`diagnostics`，旧版条目为空值）和 `records`（导出记录，最新在前）。结果文件把这些字段写在行数据之前，清单只读文件开头 64 KiB；界面按 `image` 把结果分组，并用资产的 `digest` 找到镜像名称。`cacheRemove` 只接受清单中的路径，删除导出记录时连同副本一起删除。`record` 按记录键从已校验副本重新打开导出。`export` 的回复包含 `record`，记录失败时为 `record_error`，导出本身仍然成功。目录模式的 `remote` 接受 `limit`（默认 500），回复包含 `total` 和 `index`（`banners`、`entries`、`bytes`、`age_seconds`）。

`analyze` 与 `dump` 接受与 CLI 相同的 `options`（`os`、`arch`、`pid`、`hive`、`key`、`pagefiles`、`swapfile`）。内核地址超出 JSON 安全整数范围，`hive`、`start`、`end` 以十进制字符串传输，后端也接受整数。部分结果保留 `complete: false` 和全部诊断，保存在单独的部分结果缓存（`<键>.partial.json`），不写入成功缓存。`analyze` 的回复带 `source`：`fresh` 表示本次运行了分析，`cache` 表示读取了成功结果缓存或部分结果缓存（`no_cache: true` 时始终是 `fresh`）；`prepared: true` 表示这次请求包含新打开镜像的内容摘要校验（镜像已经 `verify` 过时为 false）；界面据此在结果底边显示来源和请求用时。
