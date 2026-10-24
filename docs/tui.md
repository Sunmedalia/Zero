# TypeScript 终端界面

[← 项目首页](../README.md) · [使用指南](usage.md) · [开发与发布](development.md)

终端界面是 `ts/` 下的 TypeScript 程序（Ink + React），通过本地 JSON-RPC 驱动 Rust 引擎。分析、符号匹配、缓存、导出和取消全部仍在原生引擎里完成；界面只负责布局、焦点、对话框和按键，因此界面进程永远不会直接读取证据。

## 进程结构

```
zero                       # Rust 可执行文件
├─ zero analyze|dump|…     # CLI，行为不变
├─ zero mcp                # stdio MCP，行为不变
├─ zero tui-backend        # 界面后端：JSON-RPC over stdio
└─ zero（无子命令）        # 定位 ts/dist/main.js 并以 node 启动界面
                            # 通过 ZERO_TUI_BACKEND 把自己的路径交给界面
```

`zero` 按 `ZERO_TUI_DIR`、当前目录下的 `ts/`、可执行文件旁的 `ts/` 顺序查找界面目录；找不到或尚未构建时会给出明确提示。`--offline`、`--image`、`--symbols`、`--os`、`--arch`、`--pagefile`、`--swapfile`、`--hive`、`--key` 会转交给界面作为初始选择。

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

回复行和完成通知可能落在同一个管道读取块里。缓存命中的任务是毫秒级的，`task.start` 的 Promise 回调可能晚于 `task.done` 执行；客户端必须在启动阶段就接受带任务号的通知，否则完成事件会被当成未知任务丢弃，界面会永久停在“执行中”。`ts/src/test/rpc.test.ts` 用一次写入同时发送回复和完成通知来固定这一点。

方法分两类：

| 类别 | 方法 |
| --- | --- |
| 同步查询 | `hello`、`assets`、`browse`、`cache.inventory`、`settings.get`、`settings.save`、`history.list`、`symbols.cached`、`registry.select`、`registry.register`、`registry.remove`、`registry.selected`、`session.reset`、`ping` |
| 任务 | `analyze`、`dump`、`identify`、`matchLocal`、`remote`、`download`、`generate`、`inspectSymbols`、`cacheClear`、`cacheRemove`、`record`、`export`、`history` |

`cache.inventory` 返回 `entries`（含 `modified`）和 `records`（导出记录，最新在前）。`cacheRemove` 只接受清单中的路径，删除导出记录时连同副本一起删除。`record` 按记录键从已校验副本重新打开导出。`export` 的回复包含 `record`，记录失败时为 `record_error`，导出本身仍然成功。目录模式的 `remote` 接受 `limit`（默认 500），回复包含 `total` 和 `index`（`banners`、`entries`、`bytes`、`age_seconds`）。

`analyze` 与 `dump` 接受与 CLI 相同的 `options`（`os`、`arch`、`pid`、`hive`、`key`、`pagefiles`、`swapfile`）。内核地址超出 JSON 安全整数范围，`hive`、`start`、`end` 以十进制字符串传输，后端也接受整数。部分结果保留 `complete: false` 和全部诊断，不写入成功缓存。`analyze` 的回复带 `source`：`fresh` 表示本次运行了分析，`cache` 表示读取了成功结果缓存（`no_cache: true` 时始终是 `fresh`）；`prepared: true` 表示这次请求包含新打开镜像的内容摘要校验；界面据此在结果底边显示来源和请求用时。

## 目录布局

| 文件 | 职责 |
| --- | --- |
| `src/main.ts` | 解析启动参数，连接后端，挂载 Ink |
| `src/rpc.ts` | JSON-RPC 客户端：一个子进程、一个任务、逐行编解码 |
| `src/engine.ts` | 状态机依赖的 `Engine` 接口，测试用内存实现替换 |
| `src/app.ts` | 状态机：准备流程、任务生命周期、选择、对话框、鼠标、命令分发 |
| `src/actions.ts` | 唯一的动作表：按键、标签、可用性、命令面板／工具栏／底部位置 |
| `src/state.ts` | 派生选择器与索引化结果视图（筛选、排序、树折叠） |
| `src/layout.ts` | 所有布局阈值，一处回答“当前终端能显示什么” |
| `src/layoutTree.ts` | 每帧的矩形树：页面、面板、列表行、表头列、工具栏、对话框；渲染与点击共用 |
| `src/canvas.ts` | 单元格画布：自己合成整屏网格，保证每行等宽、宽字符不撕裂 |
| `src/views/paint.ts` | 各区域的绘制函数，只写画布，不做布局 |
| `src/mouse.ts` | SGR 鼠标解析，直接监听原始 stdin |
| `src/text.ts` | 单元格宽度、截断、路径压缩、转义 |
| `src/dialogs.ts` | 对话框尺寸、文本编辑、参数与 dump 表单解析 |
| `src/views/root.tsx` | Ink 根组件：组装画布、路由按键、挂鼠标监听 |
| `src/test/` | 内存引擎与单元测试 |

## 布局与输入

不带镜像启动时入口为资源库，命令行指定 `--image` 时为分析工作台。资源库、分析、缓存三个页面用 `1`／`2`／`3` 切换，其后是系统选择；打开的页面标签画在分析页结果表的标题行上。公共区域只占顶部两行和底部两行。120×35 使用插件／结果双栏，80×24 按焦点切换区域；详情常规尺寸覆盖结果区，160 列且 28 行起使用 38 列侧栏。资源库的镜像／本地库／远程索引通过上方标签（或 Tab／Shift+Tab）切换，各页单独占满内容区域；镜像文件名和目录按显示宽度换行，渲染与鼠标点击共用多行条目矩形，详情通过 d 打开。低于 60×16 显示尺寸提示。默认不打开详情，不自动运行插件，也不自动开启在线模式。

`renderFrame` 合成 Ink 实际输出的画布，并在绘制表头之后提交命中矩形，因此表头排序与屏幕列一致。整屏回归测试覆盖主要尺寸、准备入口、详情与缩放、点击排序、任务／结果状态和小尺寸保护。

一帧的顺序是固定的：

1. `computeLayout(state, columns, rows)` 算出所有矩形：标签、系统行、页头、列表、列表内可点击的行、表头列、工具栏按钮、对话框及其行与按钮。
2. `paint*` 系列只往 `Canvas` 上写字符，从不自己决定位置。
3. `hitMap(layout, state)` 把同一份矩形交给状态机，鼠标点击直接用 `inside(rect, x, y)` 判断。

这样“画在哪”和“点在哪”是同一份数据，不可能漂移。三个实现细节值得记住：

- **画布而不是 flexbox。** Ink 的增量渲染按行 diff，绝对定位的区域会留下上一帧的行，嵌套 Box 还会让内容错位一格。画布每帧输出恰好 `rows` 行、每行 `columns` 列，因此帧是确定的。
- **宽字符占两格。** `Canvas.write` 用显示宽度推进，宽字符的第二格标记为 continuation，后续写入不会把它劈开；所有布局宽度都用 `width()` 而不是 `string.length`。
- **鼠标走原始 stdin。** Ink 的输入解析器会把无法映射为按键的 CSI 序列直接丢弃，而 SGR 鼠标上报正是这种序列，所以 `useInput` 永远收不到它们。`listenMouse` 在原始流上旁听，不消费数据，键盘与粘贴仍由 Ink 处理。滚轮按 64/65 解码，一次滚动三行。
- **一批按键逐个处理。** Ink 可能把一次读取里的多个可打印字符（快速输入或粘贴）作为一个 `input` 字符串交出来；`handleKey` 先拆成单个字符（包括结尾的 Enter），再走同一条按键路由，因此插件搜索框里的 `lsmod` 不会整段丢失。

## 规则

- **一个动作只有一个定义。** 按键、标签和可用性都在 `actions.ts`；界面只按放置位置挑选条目，因此不会出现“命令面板里有、工具栏里没有”。
- **状态机不碰终端。** `App` 的每个变更都能在测试里驱动；Ink 只是它的纯函数视图。
- **取消是真实的。** 取消会通知引擎，且被取消的任务不会产生结果；排队中的后续请求只保留最后一个。
- **部分结果可见。** 诊断、`部分结果 / 未缓存` 和历史记录状态都会显示，并可导出。
- **证据只读。** 界面不写镜像、不复制证据；资产移除只改项目清单。

## 构建与检查

```sh
cd ts
npm install --no-audit --no-fund
npm run build
npm test          # 构建后运行单元测试
npm run typecheck # tsc --noEmit
```

`make check` 会先构建界面，再运行 fmt、Clippy、Rust 测试、`tsc --noEmit`、界面单元测试和 release 构建。`make tui-acceptance` 使用真实镜像驱动 `zero tui-backend`，覆盖识别、精确匹配、分析和页表验证；样本路径可用 `ZERO_TEST_IMAGE`／`ZERO_TEST_SYMBOLS` 覆盖。

## 取消

取消是**协作式**的：界面发 `task.cancel`，引擎在下一个检查点（每 4 MiB 扫描、每个对象、每个符号文件）返回「任务已取消」，界面丢弃结果并把状态设为「已取消；可重试」。三条容易出错的路径都有测试固定：

- **`task.start` 尚未回复时按 Esc。** 任务已经在 worker 里跑了，但客户端还没有任务号。客户端记住取消意图，收到回复后立即转发，并短暂等待任务号以便当场取消；否则一次 1 秒的扫描会跑完，用户只看到「正在取消…」。
- **取消标志不能跨任务残留。** 任务结束（成功、失败或取消）时清零；否则下一次请求会在 `runTask` 入口被静默跳过，表现为「取消之后再也跑不起来」。
- **排队中的后续请求。** 取消会清空队列，只有最后一次请求在旧任务退出后执行；它是用户最新的意图，不受之前的取消影响。

`Esc` 是分层的：先关弹窗或详情面板，再清除分析页内容筛选，最后才取消任务；运行中也保留这个顺序。

## 鼠标

终端先被置入 SGR 上报模式（`CSI ? 1000 h` + `CSI ? 1002 h` + `CSI ? 1006 h`），退出时恢复。1002 只在按住按键时上报移动，用于拖动滚动条，不上报悬停。可点击的区域：

- 顶部三个页面标签、系统选择（Linux／Windows；自动识别时高亮识别出的系统）
- 结果表标题行上的已打开页面标签（点击切换，`×` 或中键关闭，`‹n`／`n›` 跳到被隐藏的相邻标签）
- 资源库来源标签、当前页面的列表条目（包括换行区域）、搜索框
- 页头的镜像／符号行（打开对应选择器）
- 底部工具栏的每个按钮
- 分析页的插件菜单每一行、结果表每一行、表头（点击排序）、搜索框
- 对话框的每一行与每个按钮；点击模态外部不穿透到页面

滚轮在列表、菜单、结果表、详情面板与缓存页两列上滚动。内容超出时，右边框显示滚动条（`layoutTree.ts` 的 `scrollbars`），绘制和点击共用同一轨道矩形；点击轨道跳到对应位置；按住滑块拖动时视图跟随指针（`scrollbarDragIndex`：列表的滚动位置由选中行推导，第一页之后每个位置只对应“视图底行被选中”这一种选择，因此拖动选中底行即可精确跟随）。指针离开一列宽的轨道后仍继续拖动，松开左键结束。左键按下触发一次点击，松开只结束拖动，不会重复触发动作。

## 页面标签与主题

截图由 `scripts/screenshots.mjs` 用真实引擎与同一个 `renderFrame` 生成（`make screenshots`），因此 README 中的画面就是终端实际显示的内容。

打开的插件结果和导出记录以浏览器式标签画在结果表的上边框，取代原来的标题（`state.openTabs`，矩形为 `layout.pageTabs`）；当前标签高亮并带完整／部分／历史状态，标签之间露出边框线。用户打开插件（`activatePlugin`）或得到结果时加入标签，静默的默认选择不开标签；同一插件只占一个标签，导出记录按来源（记录键或文件路径）去重。从未显示过内容的插件标签会被下一个打开的插件原位复用。标题先按共同宽度收缩（18 到 6 列），仍放不下时只显示活动标签周围的一段，两端显示隐藏数量。关闭标签会丢弃其内存结果（再次打开读取成功缓存或重新运行），内核 banner 列表作为识别状态保留；关闭当前标签时切到右侧相邻标签，没有右侧时切到左侧。正在运行的插件标签需先取消。更换镜像或符号来源后，旧插件标签随结果一起清除，导出记录标签保留。键盘：Ctrl+PgUp／Ctrl+PgDn 切换，Ctrl+W 关闭。

主题定义在 `text.ts` 的 `THEMES`（石板、纸白、Solarized、荧光绿、高对比），颜色常量是 ES 模块的实时绑定，`applyTheme` 重新赋值后下一帧生效。画布写入未指定背景的文字时沿用下方已绘制的背景，所以浅色主题不会露出终端默认背景。主题 id 保存在设置的 `theme` 字段；未知 id 回退到默认主题。

## 已知边界

- 需要支持 SGR 鼠标上报的终端（xterm、iTerm2、Windows Terminal、tmux 均可）。不支持的终端仍可完全用键盘操作。
- 界面需要 Node ≥ 22；分析引擎本身不需要 Node，CLI 和 MCP 也不经过界面。
