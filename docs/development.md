# 开发、资源预算与性能验证

[← 项目首页](../README.md) · [使用指南](usage.md) · [终端界面架构](tui.md)

## 检查与验收

```sh
make check
python3 scripts/windows_compatibility.py --check
make acceptance
make windows-acceptance
make tui-acceptance
```

`make check` 包含 Rust 格式检查、Clippy、引擎与原生界面测试以及 release 构建；`make ui-test` 可单独运行界面测试。

常规检查使用合成样本。后三项验收需要本地真实镜像和精确符号；不会自动下载大型镜像。样本基线见 `tests/fixtures/`，各测试顶部列出环境变量覆盖方式。Windows 的宿主支持与被分析系统兼容性是不同维度。

## 资源预算

`.zero/rust/settings.json` 可增加以下配置，省略字段自动使用默认值。修改后重新启动服务／TUI；页表与扫描预算在准备新镜像时加载。

```json
{
  "resources": {
    "page_cache_entries": 65536,
    "scan_cache_bytes": 67108864,
    "snapshot_memory_bytes": 134217728,
    "snapshot_count": 8,
    "snapshot_idle_seconds": 1800
  }
}
```

页表预算按地址空间计数，扫描预算按镜像计算键和命中地址的估算字节数，设置为 0 可关闭对应缓存。页表采用 LRU 淘汰；扫描结果超过预算时仍完整返回，只是不缓存。预算约束缓存，并非整个进程的 RSS 上限；结果构建、符号类型和正在执行的扫描仍需内存。

快照数量和有效期必须大于 0。行数据超过快照内存预算时落入系统临时目录中的私有 `zero-snapshots-*` 目录，分页每 200 行设置一个文件偏移索引。元数据、索引和临时分页缓冲另占内存。快照在过期、淘汰及正常退出时删除；异常终止可能遗留临时目录，可在确认服务退出后清理。临时磁盘写入失败会返回错误，不返回可用结果 ID。

Windows Session 按镜像摘要、符号来源文件状态和 PDB 转换器版本复用 ISF；每次仍验证符号选择、架构和分页附件。TUI 按结果修订、查询、排序与折叠状态复用行索引；导出使用未加树缩进的全部匹配行。

## 可重复性能基准

```sh
cargo build --release --locked --examples
./target/release/examples/benchmark_results views 10000
./target/release/examples/benchmark_results views 100000
./target/release/examples/benchmark_results snapshots 100000
./target/release/examples/benchmark_results export-legacy-json 100000
./target/release/examples/benchmark_results export-stream-json 100000
./target/release/examples/benchmark_results export-legacy-csv 100000
./target/release/examples/benchmark_results export-stream-csv 100000
./target/release/examples/benchmark_windows_session IMAGE SYMBOLS
./target/release/examples/bench_plugins IMAGE SYMBOLS [ROUNDS]
```

`bench_plugins` 与 `bench_windows_plugins` 输出每个插件的耗期中位数与最小值，以及对象字段读取的单元成本（`vm.uint`、`vm.translate`、`isf.layout`）。用最小耗时判断真实成本：单次运行的波动（同一插件 391–445 ms）会大于要测的效应，而首个插件还会吸收符号加载——单次运行曾把 `check_exec` 显示成 2.69 s，实际是 23 ms。

## 已确认的成本下限

以下项目经测量确认没有剩余优化空间，改动前应先复核这些数字：

| 项目 | 成本 | 构成 |
| --- | ---: | --- |
| RAW 镜像 `prepare_image` | 约 10 s / 3.7 GB | SHA256 0.52 GB/s × 镜像大小；banner 偏移必须按序记录，无法与读取并行 |
| `windows.filescan` | 约 250 ms | 全镜像 pool tag 扫描，约 13.7 GB/s，即内存带宽 |
| `windows.vadinfo` | 约 133 ms | 每行 8 µs 中约 5.5 µs 是必需字段读取（16–18 次 × 327 ns） |
| `windows.svcscan` | 约 200 ms | 用户 VAD 中搜索服务标签；降低成本需改搜索策略（行为变更） |

单次字段读取 327 ns 中页表翻译只占 22 ns，其余是物理读取；把页内容缓存起来实测反而更慢（501 ns），因此没有保留。

## 已完成的优化

- TUI 每帧路径：`escaped`（37×）、插件列表（136×）、`display_path`（108×）、资产与远程索引过滤（约 1000×）、视图缓存键（3.7×）
- 事件循环：鼠标移动事件不再触发重绘，也不再复制命中图
- `windows.handles`：391 → 157 ms（对象类型名按索引缓存，行不变量只构造一次）
- `windows.filescan`：375 → 247 ms（复用扫描缓冲区）
- `linux.maps`：195 → 165 ms（进程根目录每进程解析一次）
- `linux.elfs`：92 → 81 ms（同上）
- gzip 源摘要与分页附件摘要：读取与哈希并行，约 26%

一个反复出现的模式：**缓存或提升循环内的不变量**。真正有效的是缓存“结果”（如 256 个对象类型名），而不只是缓存“解析”（如字段偏移）。

`views` 对比旧绘制路径的三次全量筛选／排序／复制与建立一次索引后的 20 次分页读取，并校验排序内容一致；这是数据准备基准，不包括终端实际绘制。`snapshots` 测量完整与部分结果的强制落盘及分页。Windows 基准交替执行独立解析与 Session 复用，关闭成功结果缓存，逐项校验输出一致并报告符号命中数。

分别用独立进程运行导出场景：macOS 使用 `/usr/bin/time -l`，Linux 使用 `/usr/bin/time -v` 采集峰值 RSS。旧导出模式重现改动前的克隆和整体序列化路径；JSON 的空白布局不同，比较解析后的内容。绝对耗时不作为 CI 门槛；CI 检查复用、失效、容量边界和结果一致性。

实测记录见 [性能结果](performance.md)。

## CI 与发布

GitHub Actions 在 Linux x86_64／ARM64 和 macOS ARM64 上运行 `make check` 与 CLI 启动检查，并为每个目标生成归档：原生 `zero` 可执行文件、README 和 `docs/tui.md`。无需 Node、npm 或外部界面目录。打包后在空 PATH 和不同工作目录中通过 PTY 验证界面启动及退出。CI 不下载真实镜像或符号；真实镜像验收在本地运行。

`v` 前缀标签触发发布流程：三个目标检查通过后，校验标签与 Cargo 版本一致，以 [RELEASE_NOTES.md](../RELEASE_NOTES.md) 为说明发布归档和 `SHA256SUMS`。发布新版本：

```sh
# 1. 同步 Cargo.toml／Cargo.lock 的版本号，并重写 RELEASE_NOTES.md
# 2. 本地通过 make check（可选 make tui-acceptance）
git tag -a vX.Y.Z -m "Zero vX.Y.Z"
git push origin main vX.Y.Z
```

宿主构建使用 [GitHub 官方 runner 标签](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)；Windows 镜像分析兼容范围与宿主平台分别记录。

`make tui-acceptance` 通过真实镜像驱动 `zero tui-backend`（保留兼容协议），并测试 Rust 原生界面共享服务，覆盖识别、精确匹配、分析和页表验证；样本路径可用 `ZERO_TEST_IMAGE`／`ZERO_TEST_SYMBOLS` 覆盖。界面本身的单元测试用内存引擎，不读取镜像：

```sh
cargo test --locked --lib tui::
```

界面架构、协议和目录说明见 [Rust 原生终端界面](tui.md)。

## README 截图

`docs/assets/*.svg` 由真实引擎生成：`cargo run --release --example screenshots` 把本地公开样本复制到临时项目，经与终端相同的 Rust `App` 和共享引擎服务运行插件，再把 Ratatui Buffer 转为 SVG，所以截图不含本机路径，也不会与界面实际效果脱节。界面改动后重新生成：

```sh
make build
make screenshots   # 默认 images/linux-sample-1.bin 与 symbols/linux.zip，可用 IMAGE= SYMBOLS= 覆盖
```
