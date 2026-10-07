# 开发、资源预算与性能验证

[返回项目入口](../README.md)

## 检查与验收

```sh
make check
python3 scripts/windows_compatibility.py --check
make acceptance
make windows-acceptance
make tui-acceptance
```

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
```

`views` 对比旧绘制路径的三次全量筛选／排序／复制与建立一次索引后的 20 次分页读取，并校验排序内容一致；这是数据准备基准，不包括终端实际绘制。`snapshots` 测量完整与部分结果的强制落盘及分页。Windows 基准交替执行独立解析与 Session 复用，关闭成功结果缓存，逐项校验输出一致并报告符号命中数。

分别用独立进程运行导出场景：macOS 使用 `/usr/bin/time -l`，Linux 使用 `/usr/bin/time -v` 采集峰值 RSS。旧导出模式重现改动前的克隆和整体序列化路径；JSON 的空白布局不同，比较解析后的内容。绝对耗时不作为 CI 门槛；CI 检查复用、失效、容量边界和结果一致性。

实测记录见 [性能结果](performance.md)。

## CI 与发布

GitHub Actions 在 Linux／macOS 的 x86_64 和 ARM64 上运行 `make check`、兼容表同步检查与 CLI 启动检查，并生成包含三个可执行文件的归档。CI 不下载真实镜像或符号；真实镜像验收在本地运行。

`v` 前缀标签触发发布流程：四个平台检查通过后，校验标签与 Cargo 版本一致，发布归档和 `SHA256SUMS`。发布说明见 [RELEASE_NOTES.md](../RELEASE_NOTES.md)。宿主构建使用 [GitHub 官方 runner 标签](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)；Windows 镜像分析兼容范围与宿主平台分别记录。

TUI 状态机的本地离线验收可运行 `make tui-acceptance`；可用 `ZERO_TEST_IMAGE`／`ZERO_TEST_SYMBOLS` 和 `ZERO_TUI_WINDOWS_IMAGE`／`ZERO_TUI_WINDOWS_SYMBOLS` 覆盖样本路径。
