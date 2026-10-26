# Zero v0.1.8

本次更新把 Windows 取证能力补齐到 Volatility 3 的对应插件：凭证提取（hashdump／lsadump／cachedump）、内存与文件转储（vaddump／dlldump／moddump／dumpfiles）以及线程池扫描（thrdscan）。所有新插件均为原生 Rust 实现，不执行任何外部脚本或符号文件。

## 凭证提取

- **`windows.hashdump`**：读取内存中的 SAM，输出 `User,RID,LM,NT,LastWrite`。bootkey 由 `JD`／`Skew1`／`GBG`／`Data` 四个子键的 class 数据拼接后按固定置换表打散；F 值在 Vista+ 用 AES-128-CBC、XP／2003 用 RC4+MD5 解出 hbootkey；V 值按 CredDump 血统的偏移解码用户名与 LM／NT 哈希，空密码输出公认常量。
- **`windows.lsadump`**：从 SECURITY hive 的 `Policy\Secrets` 逐条解密。Win7 及以后走 `PolEKList`（AES-256 逐块），XP 走 `PolSecretEncryptionKey`（RC4）。
- **`windows.cachedump`**：取 `NL$KM` 解密域缓存槽位，输出 hashcat 2100 可用的 `$DCC2$` 格式。是否有条目取决于样本中是否保存了域用户的缓存登录记录；空表本身不能证明未发生域登录。
- 三个插件优先在 Registry 进程地址空间解析 hive，缺失时回退内核映射；两种视图都读不到的 hive 降级为零行并给出诊断，不输出猜测值。样本布局超出已知 revision 时同样报诊断而不是猜哈希。

## 内存与文件转储

新增 `dump --mode vad|dll|module|files`（TUI 中依次为 Alt+4–7）：

- **`vad`**：逐 VAD 导出进程内存，语义对齐 vol3 vaddump（不做可读过滤，读不出的段逐段诊断并跳过）。
- **`dll`**：按 PE 节表重建进程 DLL，与 `pedump` 同一套逻辑，节间空洞补零、缺页报错，绝不伪造缺失字节。
- **`module`**：重建 `PsLoadedModuleList` 中的内核模块，无需 PID。
- **`files`**：从进程句柄表的 File 对象与文件映射 VAD 两个来源提取驻留缓存内容，走 DataSection／ImageSection 两类 ControlArea → Subsection → PTE 链（含 transition 页的 vol3 #475 掩码修正）。只提取磁盘文件，管道与网络设备被过滤；稀疏空洞补零并计入 SHA256；同一 FILE_OBJECT 的句柄与 VAD 来源只导出一次。SharedCacheMap／VACB 视图不提取。

`vad`／`dll`／`module` 单次转储上限 256 MiB，`files` 按进程累计计费；文件名中的模块名净化为 `[A-Za-z0-9._-]`。minidump 容器不提供这些结构时会明确拒绝，而不是输出空结果。

## 线程池扫描

- **`windows.thrdscan`**：扫描 `Thre` 池标签恢复 `_ETHREAD` 对象，包含已退出或已脱离线程链表的线程。候选要求 CID 两项非零、可整除 4 且在上限内，链表与起始地址落在内核地址空间；CreateTime 按 vol3 语义处理（含 `ThreadsProcess` 字段的老结构右移 3 位）。

## 其它

- `handles` 与 `dumpfiles` 共用同一份句柄表遍历与指针解码实现。
- 时间显示统一加了 9999 年上限，池残留的垃圾时间值渲染为空而不是巨大的整数。
- 兼容矩阵的生成检查并入 `make check`，矩阵与 `compatibility.json` 的漂移在本地即可发现。

## 实测

Server 2012 R2 DC01 样本验证了凭证提取、79 段 VAD 导出和 4 个 DLL 重建。Server 2012 psexec 样本的 thrdscan 恢复 149 个线程，dumpfiles 对 explorer.exe 提取 18 个文件（部分 `.mui` 输出具有 MZ 文件头，已复核文件的 SHA256 与清单相符）；文件缓存读取仍有诊断，因此该次 dumpfiles 结果标记为不完整。这些冒烟结果不代表已与 Volatility 逐字段比对，也不代表所有 Windows 构建均已验证。

## 安装

每个归档包含 `zero` 可执行文件、README、`docs/tui.md`，以及界面的 `ts/dist`、`ts/src`、`package.json` 与 `package-lock.json`。解压后在 `ts/` 运行 `npm ci --omit=dev` 安装界面依赖（需要 Node ≥ 22），然后运行 `./zero`；CLI 与 `zero mcp` 不需要 Node。Linux 包在 Ubuntu 24.04 构建，需要兼容的 glibc。用 `SHA256SUMS` 核验下载文件。

发布工作流在 Linux／macOS 的 x86_64 与 ARM64 四个目标上执行格式检查、Clippy、自动测试、release 构建、兼容文档检查和命令行冒烟测试，全部通过后才发布。需要本地真实镜像或符号的验收测试不在工作流中执行。

用法与兼容范围见[使用指南](https://github.com/sunmedalia/zero/blob/v0.1.8/docs/usage.md)和[兼容矩阵](https://github.com/sunmedalia/zero/blob/v0.1.8/docs/compatibility.md)。
