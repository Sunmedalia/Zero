# Zero v0.2.7

本版不新增分析功能，重点是导出安全、分析速度和界面响应。所有插件的输出与 v0.2.6 一致。

## 导出安全

- Windows 进程、PE、范围等导出改为原子落盘且拒绝覆盖：目标文件已存在时，只有内容完全一致才算成功。
- 注册表插件路由改为穷尽匹配；`windows.crashinfo` 在 RAW 镜像上给出明确报错。

## 分析速度

- 符号匹配先探测 ISF banner，跳过确定不匹配的文件；压缩符号逐个解压处理。
- Linux kallsyms 按页读取，32 位／PAE 页表缓存跨读取复用，地址翻译增加上一页快路径。Debian 3.2 样本上 kallsyms 约 2.0–2.5 秒降到 1.25 秒。
- Windows 压缩页缓存改为 LRU（1024 页）。
- 计算镜像摘要时同时记录 Windows pool 标签位置，filescan、netscan 不再整读镜像。Win11 3.5 GB 样本上 filescan 43 秒 → 20 秒，netscan 41 秒 → 16 秒。小镜像每个插件约多 0.2 秒 CPU 开销。
- 调整资源上限时保留已有的扫描缓存。

## 界面与命令行

- 终端事件合并后再重绘：连续滚轮、按住方向键、大段粘贴只重绘一次。
- 资产列表只为可见区域附近的远程索引行做文件检查；结果表列宽做了缓存。
- `--help` 中的插件参数按用途分组显示，参数名和用法不变。
- MCP `zero_analyze` 的 `plugin` 参数增加说明，指向 `zero_plugins`。

## 维护

- 内部模块整理，去掉一处可能 panic 的 `expect`；依赖 `base64` 统一到 0.23；声明最低 Rust 版本 1.95。
- 新增结果视图（排序、过滤、树形折叠）单元测试，修复一个与文件时间戳相关的偶发失败测试。

## 安装

下载对应平台归档和 `SHA256SUMS`，校验后解压运行。

详见[使用指南](https://github.com/sunmedalia/zero/blob/v0.2.7/docs/usage.md)、[界面说明](https://github.com/sunmedalia/zero/blob/v0.2.7/docs/tui.md)和[兼容矩阵](https://github.com/sunmedalia/zero/blob/v0.2.7/docs/compatibility.md)。
