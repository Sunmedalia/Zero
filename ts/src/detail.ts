/**
 * Prose shown in detail modals: asset detail, remote detail, help, task log and
 * diagnostics.
 *
 * These strings are user-facing documentation of the current state, so they are
 * assembled from the same selectors the panes use rather than duplicated.
 */
import type { AppState } from './state.js';
import { ACTIONS, assetActions, footerActions } from './actions.js';
import { pluginDescriptor, pluginMatches, selectedAsset, result, viewIndex, visibleRow } from './state.js';
import type { Asset, RemoteMatch, Results } from './types.js';
import { escaped, mib, width } from './text.js';
import { DIAGNOSTIC_KINDS, diagnosticCounts, diagnosticKind, resultState } from './format.js';

/** Escape evidence fields independently so structural line breaks stay readable. */
export function rowDetailText(state: AppState): string {
  const current = result(state);
  const row = visibleRow(state, viewIndex(state), state.row);
  return current && row
    ? current.columns.map((column, index) => `${escaped(column)}: ${escaped(row[index] ?? '')}`).join('\n')
    : '选择一行查看完整字段。';
}

/** Text of the asset detail panel and modal. */
export function assetDetailText(state: AppState, asset: Asset, readOnly = false): string {
  const lines = [
    `${escaped(asset.name)}`,
    '',
    `路径: ${escaped(asset.path)}`,
    `格式: ${asset.format}`,
    `大小: ${mib(asset.bytes)} MiB`,
    `来源: ${asset.origin}`,
    `状态: ${asset.available ? '可用' : '文件缺失；重新导入路径'}`,
    '',
    readOnly ? '当前分析对象 · Esc／Enter 关闭' : 'Space 选用 · Enter 进入分析控制台 · d 详情 · Delete 移出清单（保留文件）',
  ];
  if (asset.kind === 'image') {
    const identity = asset.identity;
    const verified = state.verified.get(asset.path);
    lines.push(
      '',
      verified !== undefined && verified.stamp === (asset.stamp ?? '')
        ? `SHA256: ${verified.digest}（本次会话已校验）`
        : asset.digest
          ? `SHA256: ${asset.digest}（上次校验的记录，文件未变；选用时重新校验）`
          : 'SHA256: 尚未校验（选用时校验）',
      '',
      identity
        ? `已识别 ${identity.system === 'linux' ? 'Linux' : 'Windows'} 内核（与此镜像绑定；文件变化后需重新识别）:`
        : '尚未识别：首次选用时扫描内核 banner／PDB 签名，结果与此镜像绑定，再次选用无需重新扫描。',
      ...(identity?.kernels.map(escaped) ?? []),
    );
  }
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
/**
 * Fields a reader looks for in a remote entry, read from its banner and file
 * name (`Ubuntu_5.4.0-1098-kvm_5.4.0-1098.104_amd64.json.xz`). Only Linux
 * banners have this shape; anything else yields no fields.
 */
export function remoteFields(candidate: RemoteMatch): [string, string][] {
  if (!candidate.banner.startsWith('Linux version ')) {
    return [];
  }
  const file = candidate.path.split('/').at(-1) ?? candidate.path;
  const parts = file.replace(/\.json(\.xz)?$/u, '').split('_');
  const compiler = /\(((?:gcc|clang)[^()]*(?:\([^()]*\))?[^()]*)\)/u.exec(candidate.banner)?.[1];
  const build = /#\d+\S*.*$/u.exec(candidate.banner)?.[0];
  const fields: [string, string][] = [];
  if (parts.length >= 3) fields.push(['发行版', parts[0] as string]);
  fields.push(['内核版本', candidate.banner.split(/\s+/u)[2] ?? '']);
  if (parts.length >= 3) fields.push(['架构', parts.at(-1) as string]);
  if (compiler) fields.push(['编译器', compiler.trim()]);
  if (build) fields.push(['构建', build.trim()]);
  return fields;
}

export function remoteDetailText(state: AppState, candidate: RemoteMatch): string {
  const saved = state.downloads.get(candidate.url);
  const status =
    state.busy && state.status.includes('下载')
      ? '正在下载'
      : saved
        ? '已保存到本地库'
        : '尚未下载';
  const fields: [string, string][] = [
    ...remoteFields(candidate),
    ['状态', status],
    ['保存位置', saved ?? state.settings.symbols],
  ];
  const label = Math.max(...fields.map(([name]) => width(name)));
  const actions = [
    state.image === null ? null : 'Space 下载并选用（按当前镜像校验 banner）',
    'w 仅下载到本地库',
    saved ? 'L 在本地库中查看' : null,
  ].filter((entry) => entry !== null);
  return [
    ...fields.map(([name, value]) => `${name}${' '.repeat(label - width(name))}  ${escaped(value)}`),
    '',
    '完整 banner',
    escaped(candidate.banner),
    '',
    `文件  ${escaped(candidate.path.split('/').at(-1) ?? candidate.path)}`,
    `链接  ${escaped(candidate.url)}`,
    '',
    `操作：${actions.join(' · ')}`,
    ...(state.lastError ? ['', escaped(state.lastError)] : []),
  ].join('\n');
}

/** Help text generated from the action table, so a binding cannot be missing. */
export function helpText(): string {
  const lines = [
    'ZERO 取证工作台',
    '',
    '1 资源库 · 2 分析 · 3 缓存 · S 自动识别/Linux/Windows · R 运行 · ? 命令面板 · Ctrl+←/→ 切换页面',
    'Tab / Shift+Tab 切换区域；↑↓ 或 j/k 导航；PgUp/PgDn/Home/End 翻页',
    '',
    '启动时进入资源库；Space 选用镜像，Enter 进入分析，准备完成后 R 运行插件。',
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
    '缓存页（3 / c）：左侧缓存范围，右侧该范围的文件；←→ / Tab 切换列表，鼠标可点击或拖动滚动条。',
    '每次导出（e）都会在「导出记录」保留元数据与已校验副本，原导出文件被移动后仍可 Enter 重新打开。',
    ACTIONS.filter((action) => action.scope === 'cache').map((action) => action.label).join(' · '),
    '',
    '远程详情：w 下载到 symbols · L 在本地库定位 · c 取消下载 · Esc 返回',
    '',
    '分析：P 适用参数 · Ctrl+R 运行 · D Dump · Alt+←/→ 横向滚动',
    '页面标签：打开的插件结果与导出记录显示在顶部 · 点击切换 · × 或鼠标中键关闭 · Ctrl+PgUp/PgDn 切换 · Ctrl+W 关闭',
    '主题：, 打开设置，在“界面主题”行按 Enter 或 ←→ 切换，立即生效并保存',
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
  if (current.diagnostics.length === 0) {
    return '没有诊断；结果完整。';
  }
  const lines = [
    `${current.diagnostics.length} 条诊断。表中每一行都来自已读取并通过校验的对象；诊断列出无法读取或前后矛盾、因此没有列出的部分，所以结果标为“部分”。部分结果连同诊断单独保存在部分结果缓存中，下次直接读取，但不会当作完整结果写入成功缓存。`,
    '',
  ];
  for (const kind of diagnosticCounts(current.diagnostics)) {
    const known = DIAGNOSTIC_KINDS.find((entry) => entry.id === kind.id);
    lines.push(`· ${kind.label} ${kind.count}${known ? `：${known.explanation}` : ''}`);
  }
  // Grouped in the same order as the summary, original order within a group.
  for (const kind of diagnosticCounts(current.diagnostics)) {
    lines.push('', `── ${kind.label} ${kind.count} ──`);
    for (const diagnostic of current.diagnostics) {
      if (diagnosticKind(diagnostic) === kind.id) {
        lines.push('', escaped(diagnostic));
      }
    }
  }
  return lines.join('\n');
}

export { assetActions, pluginDescriptor, pluginMatches, selectedAsset, result, viewIndex, visibleRow, resultState };
