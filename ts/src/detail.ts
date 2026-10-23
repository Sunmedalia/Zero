/**
 * Prose shown in detail modals: asset detail, remote detail, help, task log and
 * diagnostics.
 *
 * These strings are user-facing documentation of the current state, so they are
 * assembled from the same selectors the panes use rather than duplicated.
 */
import type { AppState } from './state.js';
import { assetActions, footerActions } from './actions.js';
import { pluginDescriptor, pluginMatches, selectedAsset, result, viewIndex, visibleRow } from './state.js';
import type { Asset, RemoteMatch, Results } from './types.js';
import { escaped, mib } from './text.js';
import { resultState } from './format.js';

/** Escape evidence fields independently so structural line breaks stay readable. */
export function rowDetailText(state: AppState): string {
  const current = result(state);
  const row = visibleRow(state, viewIndex(state), state.row);
  return current && row
    ? current.columns.map((column, index) => `${escaped(column)}: ${escaped(row[index] ?? '')}`).join('\n')
    : '选择一行查看完整字段。';
}

/** Text of the asset detail panel and modal. */
export function assetDetailText(state: AppState, asset: Asset): string {
  const lines = [
    `${escaped(asset.name)}`,
    '',
    `路径: ${escaped(asset.path)}`,
    `格式: ${asset.format}`,
    `大小: ${mib(asset.bytes)} MiB`,
    `来源: ${asset.origin}`,
    `状态: ${asset.available ? '可用' : '文件缺失；重新导入路径'}`,
    '',
    'Space 选用 · Enter 进入分析控制台 · d 详情 · Delete 移出清单（保留文件）',
  ];
  if (asset.kind === 'symbols') {
    const labels = state.localMatches.get(asset.path);
    if (labels) {
      lines.push('', `完整 banner 匹配: ${labels.length} 个 ISF`, ...labels.map(escaped));
      lines.push('Space 选用；x 开始分析并验证页表。');
    }
    const errors = state.localMatchErrors.filter((error) => error.startsWith(asset.path));
    if (errors.length > 0) {
      lines.push('', '匹配诊断（其余成员继续读取）:', ...errors.map(escaped));
    }
    const detail = state.assetDetails.get(asset.path);
    if (detail) {
      lines.push('', ...detail.split('\n').map(escaped));
    } else {
      lines.push('', 'd 查看符号详情：读取完整 banner、符号摘要和架构配置。');
    }
  } else if (state.image !== null && state.image === asset.path) {
    const banners = state.results.get('banners');
    if (banners) {
      lines.push('', `共 ${banners.rows.length} 个原始候选；优先展示完整格式，banners 插件保留全部命中。`);
      for (const row of banners.rows) {
        lines.push('', `候选 @ ${row[0]}: ${escaped(row[1] ?? '')}`);
      }
    } else {
      lines.push('', 'b 识别内核候选；M 获取远程符号匹配。');
    }
  }
  return lines.join('\n');
}

/** Text of the remote candidate detail modal. */
export function remoteDetailText(state: AppState, candidate: RemoteMatch): string {
  const saved = state.downloads.get(candidate.url);
  const status =
    state.busy && state.status.includes('下载')
      ? '正在下载'
      : saved
        ? '已保存到本地库'
        : '尚未下载';
  return [
    `完整 banner: ${escaped(candidate.banner)}`,
    '',
    `仓库路径: ${escaped(candidate.path)}`,
    '',
    `下载链接: ${escaped(candidate.url)}`,
    '',
    `状态: ${status}`,
    `保存位置: ${saved ? escaped(saved) : state.settings.symbols}`,
    '',
    escaped(state.status),
    state.lastError ? escaped(state.lastError) : '',
  ].join('\n');
}

/** Help text generated from the action table, so a binding cannot be missing. */
export function helpText(): string {
  const lines = [
    'ZERO 取证工作台',
    '',
    '1 资源库 · 2 分析 · S 自动/Linux/Windows · R 运行 · ? 命令面板 · Ctrl+←/→ 切换页面',
    'Tab / Shift+Tab 切换区域；↑↓ 或 j/k 导航；PgUp/PgDn/Home/End 翻页',
    '',
    '默认进入分析工作台；i 选择镜像，准备完成后 R 运行插件。',
    '80×24 按区域切换；120×35 双栏；160 列且 28 行起详情使用右侧栏。',
    'd 查看行字段，方向键／PgUp／PgDn 滚动，d／Esc 关闭；Enter 查看结果与诊断。',
    '',
    '镜像与符号：',
    '资源库上方标签切换镜像／本地库／远程索引，Tab／Shift+Tab 循环切换，各页保留筛选和选中位置。',
    '资源库 Space 选用；Enter 选用高亮项并进入分析（匹配完成后自动进入）；再次点击高亮行等同 Space；d 查看详情。',
    '选用镜像后自动识别内核并匹配本地；x 进入分析；点击或 Enter 选择插件即显示已有结果或运行。',
    'M 使用 GitHub 完整 banner / Windows PDB 精确查询、下载并选用；多候选手动选择。独立下载 w 只保存文件。',
  ];
  for (const section of ['images', 'symbols', 'remote'] as const) {
    const title = section === 'images' ? '镜像' : section === 'symbols' ? '本地符号' : '远程符号';
    lines.push('', `${title}：`, assetActions(section).map((action) => action.label).join(' · '));
  }
  lines.push('', '分析页操作（随焦点变化）：');
  for (const [title, focus] of [
    ['镜像信息', 'context'],
    ['插件', 'navigation'],
    ['内容', 'content'],
    ['详情', 'detail'],
  ] as const) {
    const actions = footerActions(focus);
    if (actions.length > 0) {
      lines.push(`${title}：${actions.map((action) => action.label).join(' · ')}`);
    }
  }
  lines.push(
    '',
    '远程详情：w 下载到 symbols · L 在本地库定位 · c 取消下载 · Esc 返回',
    '',
    '分析：P 适用参数 · Ctrl+R 运行 · D Dump · Alt+←/→ 横向滚动',
    '资源库 K / 分析页 g 生成当前镜像符号表',
    '',
    'Ctrl+P / ? 命令面板（空格分隔多个词，不区分大小写，可用 cache、dump、pid 等英文词）',
    'Esc 关闭弹窗；分析页先清除筛选，再取消任务 · q 退出（任务中需按两次）· Ctrl+C 立即退出',
    '文件弹窗：Space 选用 · Enter 打开目录／进入分析控制台，d 详情 · Shift+Space 选用符号目录 · ← 上级 · Tab 切换目录 · p 输入路径',
    'Dump：Alt+1/2/3 切换模式 · Tab 字段 · Ctrl+Enter 运行',
  );
  return lines.join('\n');
}

/** Task log modal body. */
export function logText(logs: string[]): string {
  return ['任务日志（最近 200 条）', '', ...logs.map(escaped)].join('\n');
}

/** Diagnostics modal body for the active result. */
export function diagnosticsText(current: Results): string {
  return current.diagnostics.length === 0
    ? '没有诊断；结果完整。'
    : current.diagnostics.map(escaped).join('\n\n');
}

export { assetActions, pluginDescriptor, pluginMatches, selectedAsset, result, viewIndex, visibleRow, resultState };
