/**
 * Painters: each one draws a region of the frame into the {@link Canvas}.
 *
 * Painting is separate from layout and from input. Every painter receives the
 * rectangles computed by {@link computeLayout}, so what is drawn and what a click
 * hits are by construction the same coordinates.
 */
import type { App } from '../app.js';
import type { Dialog, AppState } from '../state.js';
import {
  assetListFor,
  menuItems,
  navigationPlugins,
  pluginMatches,
  remoteList,
  result,
  sectionTitle,
  settingsLabels,
  treeColumns,
  viewIndex,
  visibleRow,
} from '../state.js';
import { commandMatches } from '../actions.js';
import type { Layout, PaneLayout, Rect } from '../layoutTree.js';
import { frameInner } from '../layoutTree.js';
import { Canvas, type Style } from '../canvas.js';
import {
  ACCENT,
  BORDER,
  DANGER,
  FOCUS,
  MUTED,
  RAISED,
  SELECTED_BG,
  STRIPE,
  SUCCESS,
  SURFACE,
  TEXT,
  WARN,
  charWidth,
  compactRemotePath,
  escaped,
  mib,
  summariseBanner,
  truncate,
  truncatePath,
  width,
  wrapLines,
} from '../text.js';
import { fitFields, preparationBadge } from '../components.js';
import { dumpModes, inputTitle, parameterFields } from '../dialogs.js';
import { entryBadge, resultState, shortPlugin } from '../format.js';
import { assetDetailText, remoteDetailText } from '../detail.js';
import { fullDigest, space } from '../layout.js';

const plain = (color?: string): Style => (color === undefined ? {} : { color });

/** Fill the whole canvas with the base surface. */
export function paintBackground(canvas: Canvas): void {
  canvas.fill(0, 0, canvas.columns, canvas.rows, { background: SURFACE });
}

/* ------------------------------------------------------------------ */
/* Chrome                                                               */
/* ------------------------------------------------------------------ */

export function paintTabs(canvas: Canvas, app: App, layout: Layout): void {
  const state = app.state;
  canvas.fill(layout.tabs.x, layout.tabs.y, layout.tabs.width, 1, { background: RAISED });
  const labels = [' F2 资源库 ', ' F3 分析 '];
  layout.tabsHits.forEach((tab, index) => {
    const active = state.page === tab.page;
    canvas.write(
      tab.rect.x,
      tab.rect.y,
      labels[index] ?? '',
      { color: active ? FOCUS : TEXT, background: active ? SELECTED_BG : RAISED, bold: active },
      tab.rect.width,
    );
  });
  const pulse = state.busy ? ['●··', '·●·', '··●', '·●·'][Math.floor(Date.now() / 180) % 4] : null;
  const right = pulse ? `运行中 ${pulse} ` : 'ZERO · 内存取证 ';
  if (layout.columns > width(right) + 22) {
    canvas.write(
      layout.columns - width(right),
      0,
      right,
      { color: pulse ? ACCENT : MUTED, background: RAISED },
      width(right),
    );
  }
}

export function paintSystems(canvas: Canvas, app: App, layout: Layout): void {
  const state = app.state;
  if (layout.regionHits.length > 0) {
    // Narrow analysis layouts replace the system picker with region tabs.
    const labels: { text: string; focus: 'navigation' | 'content' }[] = [
      { text: ' 插件 ', focus: 'navigation' },
      { text: ' 内容 ', focus: 'content' },
    ];
    for (const region of layout.regionHits) {
      const label = labels.find((entry) => entry.focus === region.focus);
      if (!label) {
        continue;
      }
      canvas.write(
        region.rect.x,
        region.rect.y,
        label.text,
        { color: state.focus === region.focus ? FOCUS : ACCENT },
        region.rect.width,
      );
    }
    return;
  }
  if (layout.columns >= 29) {
    canvas.write(0, 1, ' 系统: ', plain(MUTED), 7);
  }
  const labels: { text: string; os: 'linux' | 'windows' | 'auto' }[] = [
    { text: ' Linux ', os: 'linux' },
    { text: ' Windows ', os: 'windows' },
    { text: ' 自动 ', os: 'auto' },
  ];
  for (const hit of layout.systemHits) {
    const label = labels.find((entry) => entry.os === hit.os);
    if (!label) {
      continue;
    }
    const active = state.analysisOptions.os === hit.os;
    canvas.fill(hit.rect.x, hit.rect.y, hit.rect.width, 1, {
      background: active ? SELECTED_BG : RAISED,
    });
    canvas.write(
      hit.rect.x,
      hit.rect.y,
      label.text,
      { color: active ? FOCUS : ACCENT, background: active ? SELECTED_BG : RAISED, bold: active },
      hit.rect.width,
    );
  }
}

export function paintResourceHeader(canvas: Canvas, app: App, layout: Layout): void {
  const state = app.state;
  const image =
    state.image === null
      ? '尚未选择；i 导入或 Space 选用清单中的镜像'
      : truncatePath(state.image, Math.max(layout.columns - 12, 8));
  const banner = summariseBanner(app.bannerLine());
  const identified = state.results.has('banners');
  drawFields(canvas, 0, 2, layout.columns, [
    { label: '镜像: ', value: image, color: TEXT },
    { label: '内核: ', value: banner, color: identified ? TEXT : MUTED },
  ]);

  const symbol =
    state.symbols === ''
      ? '未选用；m 本地匹配，M 匹配并获取符号'
      : state.preparation === 'ready'
        ? (state.choice ?? truncatePath(state.symbols, Math.max(layout.columns - 12, 8)))
        : `待匹配 ${truncatePath(state.symbols, Math.max(layout.columns - 16, 8))}`;
  const badge = preparationBadge(state.preparation);
  const mode = state.settings.remote_symbols ? '在线' : '离线';
  const badgeText = ` ${badge.label} · ${mode} `;
  const showBadge = layout.columns >= width(badgeText) + 16;
  const symbolWidth = layout.columns - (showBadge ? width(badgeText) + 1 : 0);
  drawFields(canvas, 0, 3, symbolWidth, [{ label: '符号: ', value: symbol, color: TEXT }]);
  if (showBadge) {
    const x = layout.columns - width(badgeText);
    canvas.fill(x, 3, width(badgeText), 1, { background: RAISED });
    canvas.write(x, 3, ` ${badge.label}`, { color: badge.color, background: RAISED });
    canvas.write(x + width(` ${badge.label}`), 3, ' · ', { color: BORDER, background: RAISED });
    canvas.write(
      x + width(` ${badge.label} · `),
      3,
      `${mode} `,
      { color: state.settings.remote_symbols ? MUTED : WARN, background: RAISED },
    );
  }
}

export function paintAnalysisHeader(canvas: Canvas, app: App, layout: Layout): void {
  const state = app.state;
  const image = state.image ?? '未加载；按 i 输入路径';
  const verified = [...state.results.values()].find(
    (entry) => !entry.historical && entry.page_table > 0,
  );
  const kernel = verified
    ? `页表已验证 0x${verified.page_table.toString(16)}`
    : state.preparation === 'ready'
      ? '运行时验证页表'
      : '尚未验证页表';
  const kernelColor = verified ? SUCCESS : state.preparation === 'ready' ? TEXT : WARN;
  const active = [...state.results.values()].find(
    (entry) => !entry.historical && entry.symbol !== '',
  );
  const symbol = active?.symbol ?? (state.symbols === '' ? '未选择 · F2 资源库' : state.symbols);
  const symbolColor = active ? TEXT : state.symbols === '' ? WARN : TEXT;
  const platform = state.windows ? 'Windows' : 'Linux';
  let x = canvas.write(0, 2, platform, { color: TEXT, bold: true }, layout.columns);
  for (const field of [
    { label: '验证: ', value: kernel, color: kernelColor },
    { label: '符号: ', value: symbol, color: symbolColor },
    { label: '镜像: ', value: image, color: TEXT },
  ]) {
    const cells = 3 + width(field.label) + width(field.value);
    if (x + cells > layout.columns) {
      break;
    }
    x += canvas.write(x, 2, ' · ', { color: BORDER }, 3);
    x += canvas.write(x, 2, field.label, { color: MUTED });
    x += canvas.write(x, 2, escaped(field.value), { color: field.color }, layout.columns - x);
  }
}

export function paintFooter(canvas: Canvas, app: App, layout: Layout): void {
  const state = app.state;
  const region =
    state.focus === 'context'
      ? '镜像信息'
      : state.focus === 'detail'
        ? '详情'
        : state.page === 'assets'
          ? sectionTitle(state.section)
          : state.focus === 'navigation'
            ? '插件'
            : '内容';
  const isError = state.lastError !== null && state.lastError === state.status;
  const color = isError ? DANGER : state.busy ? ACCENT : TEXT;
  canvas.fill(layout.status.x, layout.status.y, layout.status.width, 1, { background: SURFACE });
  let x = canvas.write(layout.status.x, layout.status.y, ` ${region} `, {
    color: ACCENT,
    bold: true,
  });
  x += canvas.write(x, layout.status.y, '│ ', { color: BORDER });
  canvas.write(x, layout.status.y, escaped(app.statusText()), { color }, layout.columns - x);

  if (state.page === 'assets' && layout.actions.height > 0) {
    canvas.write(0, layout.actions.y, ' 操作 ', plain(MUTED));
    canvas.write(
      6,
      layout.actions.y,
      `· ${sectionTitle(state.section)} · Tab 切换区域 `,
      { color: ACCENT, bold: true },
    );
  }
  for (const button of layout.buttons) {
    const disabled = app.commandDisabledForKey(button.key);
    const primary = button.key === 'x';
    const background = primary ? SELECTED_BG : RAISED;
    canvas.fill(button.rect.x, button.rect.y, button.rect.width, 1, { background });
    const label =
      button.key === '?'
        ? ' 更多 ? '
        : ` ${truncate(button.action, Math.max(button.rect.width - 2, 1))} `;
    canvas.write(
      button.rect.x,
      button.rect.y,
      label,
      {
        color: disabled ? MUTED : primary ? FOCUS : state.page === 'assets' ? TEXT : FOCUS,
        background,
        bold: primary,
      },
      button.rect.width,
    );
  }
}

/* ------------------------------------------------------------------ */
/* Resource library                                                     */
/* ------------------------------------------------------------------ */

export function paintSources(canvas: Canvas, app: App, layout: Layout): void {
  if (!layout.sources) {
    return;
  }
  const state = app.state;
  const labels: { text: string; section: 'images' | 'symbols' | 'remote' }[] = [
    { text: ' 镜像 ', section: 'images' },
    { text: ' 本地库 ', section: 'symbols' },
    { text: ' 远程索引 ', section: 'remote' },
  ];
  for (const hit of layout.sourceHits) {
    const label = labels.find((entry) => entry.section === hit.section);
    if (!label) {
      continue;
    }
    const active = state.section === hit.section;
    canvas.fill(hit.rect.x, hit.rect.y, hit.rect.width, 1, {
      background: active ? SELECTED_BG : SURFACE,
    });
    canvas.write(
      hit.rect.x,
      hit.rect.y,
      label.text,
      { color: active ? FOCUS : ACCENT, background: active ? SELECTED_BG : SURFACE, bold: active },
      hit.rect.width,
    );
  }
}

export function paintPane(canvas: Canvas, app: App, pane: PaneLayout): void {
  const state = app.state;
  const query = state.assetQueries[pane.section === 'images' ? 0 : pane.section === 'symbols' ? 1 : 2];
  const count =
    pane.section === 'remote' ? remoteList(state).length : assetListFor(state, pane.section).length;
  if (pane.search) {
    paintSearch(canvas, pane.search, query, {
      editing:
        state.dialog?.kind === 'input' &&
        state.dialog.input === 'assetsSearch' &&
        state.section === pane.section,
      title: '搜索 / · Enter 确认 · Esc 取消',
    });
  }
  const focused = state.section === pane.section && state.focus === 'navigation';
  const mode =
    pane.section === 'symbols' && state.localOnlyMatches
      ? ' · 完整 banner 匹配'
      : pane.section === 'remote' && !state.remoteCatalog
        ? ' · 镜像精确匹配'
        : ' · 全部';
  paintFrame(canvas, pane.list, `${sectionTitle(pane.section)}${mode} · ${count} 项`, {
    color: focused ? ACCENT : BORDER,
  });
  if (count === 0) {
    paintEmpty(canvas, pane.rows, emptyTitle(app, pane.section, query), emptyHint(app, pane.section, query));
    return;
  }
  const selected = state.assetRows[pane.section === 'images' ? 0 : pane.section === 'symbols' ? 1 : 2];
  for (let index = 0; index < pane.visible; index += 1) {
    const absolute = pane.offset + index;
    if (absolute >= count) {
      break;
    }
    const y = pane.rows.y + index;
    const isSelected = absolute === selected;
    if (isSelected) {
      canvas.fill(pane.rows.x, y, pane.rows.width, 1, { background: SELECTED_BG });
    }
    canvas.write(pane.rows.x, y, isSelected ? '› ' : '  ', { color: FOCUS, background: isSelected ? SELECTED_BG : undefined });
    paintPaneRow(canvas, app, pane, absolute, y, isSelected);
  }
}

function paintPaneRow(
  canvas: Canvas,
  app: App,
  pane: PaneLayout,
  absolute: number,
  y: number,
  selected: boolean,
): void {
  const state = app.state;
  const x = pane.rows.x + 2;
  const room = pane.rows.width - 2;
  const background = selected ? SELECTED_BG : undefined;
  if (pane.section === 'remote') {
    const candidate = remoteList(state)[absolute];
    if (!candidate) {
      return;
    }
    const saved = state.downloads.has(candidate.url);
    const tag = saved ? '[已保存]' : '[待下载]';
    let cursor = canvas.write(x, y, tag, { color: saved ? SUCCESS : MUTED, background }, room);
    cursor += canvas.write(
      x + cursor,
      y,
      ` ${escaped(compactRemotePath(candidate.path, room - width(tag)))}`,
      { color: TEXT, background },
      room - cursor,
    );
    return;
  }
  const asset = assetListFor(state, pane.section)[absolute];
  if (!asset) {
    return;
  }
  const active = asset.kind === 'image' ? state.image === asset.path : asset.path === state.symbols;
  const matched = state.localMatches.has(asset.path);
  const marker = active ? '●已选用' : matched ? '✓匹配' : ' ';
  const markerColor = active ? SUCCESS : matched ? ACCENT : MUTED;
  const digest = fullDigest(space(pane.rows.width, 24));
  const metadata = digest ? ` · #${asset.id} · ${asset.format}` : ` · ${asset.format}`;
  const suffix = asset.available ? '' : ' · 缺失';
  const pathRoom = Math.max(room - width(marker) - width(metadata) - width(suffix) - 1, 8);
  let cursor = canvas.write(
    x,
    y,
    marker,
    { color: markerColor, background, bold: active || matched },
    room,
  );
  cursor += canvas.write(
    x + cursor,
    y,
    ` ${truncatePath(asset.path, pathRoom)}`,
    { color: asset.available ? TEXT : MUTED, background },
    pathRoom + 1,
  );
  cursor += canvas.write(x + cursor, y, metadata, { color: MUTED, background }, room - cursor);
  if (!asset.available) {
    canvas.write(x + cursor, y, suffix, { color: DANGER, background }, room - cursor);
  }
}

export function paintAssetDetail(canvas: Canvas, app: App, layout: Layout): void {
  if (!layout.assetDetail) {
    return;
  }
  const state = app.state;
  const scroll = state.assetScroll[state.section === 'images' ? 0 : state.section === 'symbols' ? 1 : 2];
  paintFrame(canvas, layout.assetDetail, '详情 · d 完整内容 · Tab 聚焦', {
    color: state.focus === 'content' ? ACCENT : BORDER,
  });
  const box = frameInner(layout.assetDetail);
  const lines = wrapLines(app.assetText(), box.width).slice(scroll, scroll + box.height);
  lines.forEach((line, index) => {
    canvas.write(box.x, box.y + index, escaped(line), plain(TEXT), box.width);
  });
}

/* ------------------------------------------------------------------ */
/* Analysis workbench                                                   */
/* ------------------------------------------------------------------ */

export function paintMenu(canvas: Canvas, app: App, layout: Layout): void {
  if (!layout.menu) {
    return;
  }
  const state = app.state;
  const items = menuItems(state);
  const box = frameInner(layout.menu);
  const offset = Math.min(
    Math.max(state.menu - box.height + 1, 0),
    Math.max(items.length - box.height, 0),
  );
  const category = navigationPlugins(state)[state.menu]?.category ?? 'Dump';
  paintFrame(canvas, layout.menu, `插件 · ${category}`, {
    color: state.focus === 'navigation' ? ACCENT : BORDER,
  });
  items.slice(offset, offset + box.height).forEach((label, index) => {
    const absolute = offset + index;
    const selected = absolute === state.menu;
    const y = box.y + index;
    if (selected) {
      canvas.fill(box.x, y, box.width, 1, { background: SELECTED_BG });
    }
    canvas.write(
      box.x,
      y,
      `${selected ? '› ' : '  '}${label}`,
      { color: selected ? FOCUS : TEXT, background: selected ? SELECTED_BG : undefined, bold: selected },
      box.width,
    );
  });
}

export function paintContent(canvas: Canvas, app: App, layout: Layout): void {
  if (!layout.content) {
    return;
  }
  const state = app.state;
  const current = result(state);
  const index = viewIndex(state);
  if (layout.contentSearch) {
    paintSearch(canvas, layout.contentSearch, state.query, {
      editing: state.dialog?.kind === 'input' && state.dialog.input === 'search',
      title: '内容搜索 · / 编辑 · Enter 确认 · Esc 撤销',
    });
  }
  const title = current
    ? ` ${shortPlugin(current.plugin)} · ${resultState(current)} `
    : ` ${app.shortPlugin()} `;
  const box = frameInner(layout.content);
  const summary = current
    ? box.width >= 40
      ? ` ${index.filtered.length} / ${current.rows.length} 条 · 显示 ${
          index.visible.length === 0 ? 0 : layout.pageStart + 1
        }–${Math.min(layout.pageStart + layout.pageSize, index.visible.length)} 行 `
      : ` ${index.filtered.length} / ${current.rows.length} 条 `
    : undefined;
  paintFrame(canvas, layout.content, title, {
    color: state.focus === 'content' ? ACCENT : BORDER,
    subtitle: summary,
  });
  if (!current) {
    paintEmpty(
      canvas,
      box,
      state.busy
        ? '任务进行中'
        : state.image === null
          ? '先选用一个镜像'
          : state.symbols === '' && state.plugin !== 'banners'
            ? '尚未选择符号'
            : '尚无结果',
      state.busy
        ? '完成后显示结果 · Esc 取消'
        : state.image === null
          ? 'F2 资源库 · i 导入镜像'
          : state.symbols === '' && state.plugin !== 'banners'
            ? 'F2 资源库 · M 精确匹配'
            : 'Enter 运行插件 · p 搜索插件',
    );
    return;
  }
  const widths = columnWidths(app, index);
  const virtual = widths.reduce((total, value) => total + value, 0) + Math.max(widths.length - 1, 0);
  const scroll = Math.min(state.horizontal, Math.max(virtual - box.width, 0));
  layout.columns_ = columnRects(widths, box.x + 2, box.y, scroll);
  const header = headerLine(state, widths, scroll, Math.max(box.width - 2, 1));
  canvas.fill(box.x, box.y, box.width, 1, { background: RAISED });
  canvas.write(box.x, box.y, `  ${header}`, { color: ACCENT, background: RAISED, bold: true }, box.width);

  if (index.visible.length === 0) {
    paintEmpty(
      canvas,
      { x: box.x, y: box.y + 1, width: box.width, height: box.height - 1 },
      state.query !== '' && current.rows.length > 0
        ? '没有匹配的结果'
        : current.complete
          ? '分析完成 · 未发现记录'
          : '暂无记录 · 分析不完整',
      state.query !== '' && current.rows.length > 0
        ? '/ 修改搜索条件'
        : current.complete
          ? 'd 查看详情 · r 重新运行'
          : 'd 查看详情与诊断',
    );
    return;
  }
  const selectedRow = Math.min(state.row, Math.max(index.visible.length - 1, 0));
  for (let offset = 0; offset < layout.pageSize; offset += 1) {
    const absolute = layout.pageStart + offset;
    const row = visibleRow(state, index, absolute);
    const y = box.y + 1 + offset;
    if (!row || y >= box.y + box.height) {
      break;
    }
    const selected = absolute === selectedRow;
    const background = selected ? SELECTED_BG : absolute % 2 === 1 ? STRIPE : SURFACE;
    canvas.fill(box.x, y, box.width, 1, { background });
    canvas.write(box.x, y, selected ? '› ' : '  ', { color: FOCUS, background });
    canvas.write(
      box.x + 2,
      y,
      rowLine(row, widths, scroll, Math.max(box.width - 2, 1)),
      { color: selected ? FOCUS : TEXT, background, bold: selected },
      box.width - 2,
    );
  }
}

export function paintInspector(canvas: Canvas, app: App, layout: Layout): void {
  if (!layout.inspector) {
    return;
  }
  const state = app.state;
  const current = result(state);
  const row = visibleRow(state, viewIndex(state), state.row);
  const text =
    current && row
      ? current.columns.map((column, index) => `${column}: ${row[index] ?? ''}`).join('\n')
      : '选择一行查看完整字段。';
  paintFrame(canvas, layout.inspector, '详情 · Tab 聚焦 · d 关闭', {
    color: state.focus === 'detail' ? ACCENT : BORDER,
  });
  const box = frameInner(layout.inspector);
  const lines = wrapLines(text, box.width).slice(state.detailScroll, state.detailScroll + box.height);
  lines.forEach((line, index) => {
    canvas.write(box.x, box.y + index, escaped(line), plain(TEXT), box.width);
  });
}

/* ------------------------------------------------------------------ */
/* Modals                                                               */
/* ------------------------------------------------------------------ */

export function paintDialog(canvas: Canvas, app: App, layout: Layout): void {
  const state = app.state;
  const dialog = state.dialog;
  if (!dialog || !layout.popup) {
    return;
  }
  if (dialog.kind === 'input' && (dialog.input === 'search' || dialog.input === 'assetsSearch')) {
    return;
  }
  const popup = layout.popup;
  // Opaque interior: Ink would otherwise let the page show through.
  canvas.fill(popup.x, popup.y, popup.width, popup.height, { background: SURFACE });
  canvas.frame(popup.x, popup.y, popup.width, popup.height, { color: ACCENT });
  paintDialogBody(canvas, app, dialog, popup);
  for (const button of layout.buttons) {
    if (!insidePopup(popup, button.rect) || button.key.startsWith('row:')) {
      continue;
    }
    canvas.fill(button.rect.x, button.rect.y, button.rect.width, 1, { background: SURFACE });
    canvas.write(
      button.rect.x,
      button.rect.y,
      `[${button.action}]`,
      { color: button.key === 'Esc' ? MUTED : FOCUS, background: SURFACE },
      button.rect.width,
    );
  }
}

function insidePopup(popup: Rect, region: Rect): boolean {
  return (
    region.x >= popup.x &&
    region.x < popup.x + popup.width &&
    region.y >= popup.y &&
    region.y < popup.y + popup.height
  );
}

function paintDialogBody(canvas: Canvas, app: App, dialog: Dialog, popup: Rect): void {
  const state = app.state;
  const box = frameInner(popup);
  const title = (text: string) => {
    canvas.fill(box.x, popup.y, box.width, 1, { background: SURFACE });
    canvas.write(box.x, popup.y, ` ${truncate(text, Math.max(box.width - 2, 1))} `, {
      color: TEXT,
      background: SURFACE,
    });
  };
  switch (dialog.kind) {
    case 'system':
    case 'settings':
    case 'plugins':
    case 'commands':
    case 'links':
    case 'symbols':
    case 'sort':
    case 'files':
    case 'cache': {
      const items =
        dialog.kind === 'system'
          ? ['自动识别镜像系统', 'Linux', 'Windows']
          : dialog.kind === 'settings'
            ? settingsLabels(state)
            : dialog.kind === 'plugins'
              ? pluginMatches(state, dialog.query).map((plugin) => plugin.label)
              : dialog.kind === 'commands'
                ? commandMatches(
                    dialog.query,
                    state.page,
                    state.focus,
                    state.page === 'assets' ? state.section : null,
                  ).map((entry) => entry.label)
                : dialog.kind === 'links'
                  ? dialog.matches.map((match) => escaped(match.path))
                  : dialog.kind === 'symbols'
                    ? dialog.labels.map(escaped)
                    : dialog.kind === 'sort'
                      ? (result(state)?.columns ?? [])
                      : dialog.kind === 'files'
                        ? dialog.entries.map((entry) => `${entryBadge(entry)} ${escaped(entry.name)}`)
                        : cacheItems(app, dialog);
      const selected =
        dialog.kind === 'sort'
          ? dialog.column
          : 'selected' in dialog
            ? dialog.selected
            : 0;
      const offset = Math.min(
        Math.max(selected - box.height + 1, 0),
        Math.max(items.length - box.height, 0),
      );
      title(
        dialog.kind === 'system'
          ? '分析系统 · Enter 选择 · Esc 取消'
          : dialog.kind === 'settings'
            ? '目录与分页设置 · Enter 修改 · Esc 关闭'
            : dialog.kind === 'plugins'
              ? `插件搜索: ${escaped(dialog.query)} · Enter 选择`
              : dialog.kind === 'commands'
                ? dialog.query === ''
                  ? '命令 · 输入以筛选 · Enter 执行'
                  : `命令 · ${escaped(dialog.query)} · Enter 执行`
                : dialog.kind === 'links'
                  ? '匹配符号 · Space 下载并选用 · Enter 进入控制台 · d 详情'
                  : dialog.kind === 'symbols'
                    ? '多个完整 banner 匹配 · Space 选用 · Enter 进入控制台 · d 详情'
                    : dialog.kind === 'sort'
                      ? '排序列 · 再选同列反转 · Esc 取消'
                      : dialog.kind === 'files'
                        ? `${app.filesTitle(dialog.input)} · Space 选用 · Enter 打开 · d 详情 · ← 上级 · p 路径`
                        : '缓存管理 · Space 勾选 · Enter 预览／清理',
      );
      items.slice(offset, offset + box.height).forEach((item, index) => {
        const absolute = offset + index;
        const active = absolute === selected;
        const y = box.y + index;
        if (active) {
          canvas.fill(box.x, y, box.width, 1, { background: SELECTED_BG });
        }
        canvas.write(
          box.x,
          y,
          `${active ? '› ' : '  '}${item}`,
          { color: active ? FOCUS : TEXT, background: active ? SELECTED_BG : SURFACE, bold: active },
          box.width,
        );
      });
      if (dialog.kind === 'cache') {
        canvas.write(
          box.x,
          popup.y + popup.height - 3,
          truncate(cacheSummary(app, dialog), box.width),
          { color: MUTED, background: SURFACE },
          box.width,
        );
      }
      if (dialog.kind === 'files') {
        canvas.write(
          box.x,
          popup.y + popup.height - 1,
          truncate(`目录: ${escaped(dialog.root)}`, box.width),
          { color: MUTED, background: SURFACE },
          box.width,
        );
      }
      return;
    }
    case 'dump': {
      title('DUMP · Tab 字段 · Ctrl+Enter 运行 · Esc 取消');
      const hint = dialog.mode.endsWith('memdump')
        ? '指定 PID、Start 和 End；读取该进程的用户虚拟地址范围'
        : dialog.mode.endsWith('pedump')
          ? '指定 PID；按 PE 节表重建可读 PE'
          : dialog.mode.endsWith('elfdump')
            ? '指定 PID；导出含 ELF 头的可读映射（不重建磁盘 ELF）'
            : '指定 PID；导出可读 VMA；Start / End 可限制范围';
      canvas.write(box.x, box.y, truncate(hint, box.width), { color: MUTED, background: SURFACE }, box.width);
      dumpModes(state.windows).forEach((mode, index) => {
        const active = dialog.mode === mode.plugin;
        const x = box.x + index * 12;
        canvas.write(
          x,
          box.y + 1,
          ` ${mode.label} `,
          { color: active ? FOCUS : ACCENT, background: active ? SELECTED_BG : SURFACE },
          11,
        );
      });
      ['PID (必填)', 'Start (0x / 十进制)', 'End (不包含)', '转储目录 (必填)'].forEach(
        (label, index) => {
          const active = dialog.field === index;
          const y = box.y + 2 + index;
          if (active) {
            canvas.fill(box.x, y, box.width, 1, { background: SELECTED_BG });
          }
          canvas.write(
            box.x,
            y,
            truncate(`${label}: ${escaped(dialog.fields[index] ?? '')}`, box.width),
            { color: active ? FOCUS : TEXT, background: active ? SELECTED_BG : SURFACE },
            box.width,
          );
        },
      );
      canvas.write(
        box.x,
        popup.y + popup.height - 4,
        truncate(dialog.error, box.width),
        { color: FOCUS, background: SURFACE },
        box.width,
      );
      return;
    }
    case 'windowsParameters': {
      title('适用参数 · 保存后 Ctrl+R 运行');
      canvas.write(
        box.x,
        box.y,
        state.windows ? 'F7 展开／收起 Windows 高级配置' : '参数按插件保存草稿',
        { color: TEXT, background: SURFACE },
        box.width,
      );
      const labels = [
        'Hive 地址',
        '键路径（空为根）',
        'PID 筛选（可选）',
        '架构 auto / x86 / x64 / arm64',
        'pagefile（索引=路径；分号分隔）',
        'swapfile（可选路径）',
      ];
      let row = box.y + 1;
      for (const field of parameterFields(state, dialog.advanced)) {
        if (field === 6) {
          canvas.write(
            box.x,
            row,
            `${dialog.field === 6 ? '›' : ' '} 保存参数 · Tab 字段 · Ctrl+Enter 保存`,
            { color: dialog.field === 6 ? FOCUS : TEXT, background: SURFACE },
            box.width,
          );
          row += 1;
          continue;
        }
        const active = dialog.field === field;
        canvas.write(box.x, row, `${active ? '›' : ' '} ${labels[field] ?? ''}`, {
          color: ACCENT,
          background: SURFACE,
        });
        row += 1;
        canvas.write(
          box.x + 2,
          row,
          truncate(escaped(dialog.fields[field] ?? ''), box.width - 2),
          { color: TEXT, background: SURFACE },
          box.width - 2,
        );
        row += 1;
      }
      canvas.write(
        box.x,
        popup.y + popup.height - 3,
        truncate(dialog.error, box.width),
        { color: FOCUS, background: SURFACE },
        box.width,
      );
      return;
    }
    case 'generateSymbols': {
      title('生成当前镜像符号表');
      const mode = dialog.automatic
        ? '自动获取当前内核调试资料（Kali 6.8.11-1kali2 ARM64）；F7 手动输入'
        : '使用当前内核的调试 ELF 和配置；F7 切换自动获取（支持的构建）';
      const lines = [
        `当前镜像：${escaped(state.image ?? '')}`,
        '符号表用于解析内核结构；生成后校验完整 banner，保存到本地库并选用。',
        mode,
        dialog.automatic
          ? state.settings.remote_symbols
            ? '将复用精确本地符号；缺少时下载官方调试包并生成。'
            : '离线：仅复用已有精确符号、调试包和生成工具。'
          : undefined,
      ];
      lines.forEach((line, index) => {
        if (line === undefined) {
          return;
        }
        canvas.write(box.x, box.y + index, truncate(line, box.width), { color: TEXT, background: SURFACE }, box.width);
      });
      if (!dialog.automatic) {
        ['调试 ELF', '内核配置', 'dwarf2json 路径'].forEach((label, index) => {
          const active = dialog.field === index;
          canvas.write(
            box.x,
            box.y + 3 + index,
            truncate(`${active ? '›' : ' '} ${label}: ${escaped(dialog.fields[index] ?? '')}`, box.width),
            { color: active ? FOCUS : ACCENT, background: SURFACE },
            box.width,
          );
        });
      }
      canvas.write(
        box.x,
        popup.y + popup.height - 4,
        'Tab 切换字段；Ctrl+Enter 执行。内存镜像保持只读。',
        { color: MUTED, background: SURFACE },
        box.width,
      );
      canvas.write(
        box.x,
        popup.y + popup.height - 3,
        truncate(dialog.error, box.width),
        { color: DANGER, background: SURFACE },
        box.width,
      );
      return;
    }
    case 'input': {
      title(inputTitle(dialog.input));
      const lines = wrapLines(dialog.text, box.width);
      lines.slice(0, Math.max(box.height - 1, 1)).forEach((line, index) => {
        if (dialog.selected) {
          canvas.fill(box.x, box.y + index, box.width, 1, { background: SELECTED_BG });
        }
        canvas.write(box.x, box.y + index, escaped(line), {
          color: TEXT,
          background: dialog.selected ? SELECTED_BG : SURFACE,
        });
      });
      canvas.write(
        box.x,
        popup.y + popup.height - 3,
        '[确认] [取消] Ctrl+u 清空 · ←→ 编辑',
        { color: ACCENT, background: SURFACE },
        box.width,
      );
      return;
    }
    case 'assetDetail':
    case 'remoteDetail':
    case 'detail': {
      const text =
        dialog.kind === 'assetDetail'
          ? assetDetailText(state, dialog.asset)
          : dialog.kind === 'remoteDetail'
            ? remoteDetailText(state, dialog.candidate)
            : dialog.text;
      title(
        dialog.kind === 'assetDetail'
          ? dialog.asset.kind === 'symbols'
            ? '符号表分析 · ↑↓ / PgUp PgDn · Esc 返回'
            : '镜像详情 · ↑↓ / PgUp PgDn · Esc 返回'
          : dialog.kind === 'remoteDetail'
            ? '远程符号详情 · ↑↓ 滚动 · Esc 返回'
            : '详情 · ↑↓ / PgUp PgDn · Esc 关闭',
      );
      const lines = wrapLines(text, box.width).slice(dialog.scroll, dialog.scroll + box.height);
      lines.forEach((line, index) => {
        canvas.write(box.x, box.y + index, escaped(line), { color: TEXT, background: SURFACE }, box.width);
      });
      return;
    }
  }
}

function cacheItems(app: App, dialog: Extract<Dialog, { kind: 'cache' }>): string[] {
  return app.scopes().map((scope) => {
    const files = dialog.entries.filter((entry) => entry.scope === scope.id);
    const bytes = files.reduce((total, entry) => total + entry.bytes, 0);
    return `[${dialog.scopes.includes(scope.id) ? 'x' : ' '}] ${scope.label} · ${files.length} 个文件 · ${mib(bytes)} MiB`;
  });
}

function cacheSummary(app: App, dialog: Extract<Dialog, { kind: 'cache' }>): string {
  const totals = app.cacheTotals(dialog.entries, dialog.scopes);
  return `${dialog.confirm ? '再次 Enter 清理：' : '已选：'}${totals.files} 个文件 / ${mib(totals.bytes)} MiB · 保留原镜像、导出、配置和迁移备份`;
}

/* ------------------------------------------------------------------ */
/* Shared pieces                                                        */
/* ------------------------------------------------------------------ */

/** Rounded frame with the title on the top border and an optional bottom hint. */
export function paintFrame(
  canvas: Canvas,
  region: Rect,
  title?: string,
  options: { color?: string; subtitle?: string } = {},
): void {
  if (region.width < 2 || region.height < 2) {
    return;
  }
  canvas.frame(region.x, region.y, region.width, region.height, {
    color: options.color ?? BORDER,
  });
  if (title !== undefined) {
    const text = ` ${truncate(title, Math.max(region.width - 4, 1))} `;
    canvas.write(region.x + 2, region.y, text, { color: TEXT }, region.width - 4);
  }
  if (options.subtitle !== undefined) {
    const text = ` ${truncate(options.subtitle, Math.max(region.width - 4, 1))} `;
    canvas.write(region.x + 2, region.y + region.height - 1, text, { color: MUTED }, region.width - 4);
  }
}

/** Inline search field: a framed row with its commit/cancel hints. */
export function paintSearch(
  canvas: Canvas,
  region: Rect,
  value: string,
  options: { editing: boolean; title: string },
): void {
  paintFrame(canvas, region, options.title, {
    color: options.editing ? FOCUS : BORDER,
  });
  const box = frameInner(region);
  canvas.write(box.x, box.y, truncate(escaped(value), box.width), { color: TEXT }, box.width);
  if (options.editing && box.width >= 30) {
    canvas.write(box.x + box.width - 14, box.y, '[确认]', { color: FOCUS }, 6);
    canvas.write(box.x + box.width - 7, box.y, '[撤销]', { color: ACCENT }, 6);
  }
}

/** Centred empty state: the heading survives first, guidance if there is room. */
export function paintEmpty(canvas: Canvas, region: Rect, title: string, hint: string): void {
  if (region.width <= 0 || region.height <= 0) {
    return;
  }
  const lines = region.height >= 3 ? 2 : 1;
  const y = region.y + Math.floor((region.height - lines) / 2);
  const heading = truncate(title, region.width);
  canvas.write(region.x + Math.floor((region.width - width(heading)) / 2), y, heading, {
    color: TEXT,
    bold: true,
  });
  if (lines > 1) {
    const text = truncate(hint, region.width);
    canvas.write(region.x + Math.floor((region.width - width(text)) / 2), y + 1, text, {
      color: MUTED,
    });
  }
}

/** `label: value` pairs across `columns`, dropping whole trailing pairs. */
function drawFields(
  canvas: Canvas,
  x: number,
  y: number,
  columns: number,
  fields: { label: string; value: string; color?: string }[],
): void {
  const fitted = fitFields(fields, columns);
  let cursor = x;
  fitted.forEach((field, index) => {
    if (index > 0) {
      cursor += canvas.write(cursor, y, ' · ', { color: BORDER }, 3);
    }
    cursor += canvas.write(cursor, y, field.label, { color: MUTED });
    cursor += canvas.write(cursor, y, escaped(field.value), { color: field.color ?? TEXT }, x + columns - cursor);
  });
}

function emptyTitle(app: App, section: PaneLayout['section'], query: string): string {
  if (query !== '') {
    return '没有匹配的资源';
  }
  switch (section) {
    case 'images':
      return '尚未导入镜像';
    case 'symbols':
      return app.state.localOnlyMatches ? '无本地匹配符号' : '尚未导入符号';
    default:
      return app.state.settings.remote_symbols ? '尚无远程条目' : '当前为离线模式';
  }
}

function emptyHint(app: App, section: PaneLayout['section'], query: string): string {
  if (query !== '') {
    return '/ 修改搜索条件';
  }
  switch (section) {
    case 'images':
      return 'i 导入镜像 · Space 选用';
    case 'symbols':
      return app.state.localOnlyMatches ? 'M 远程匹配 · z 查看全部' : 'y 导入符号 · M 精确匹配';
    default:
      return app.state.settings.remote_symbols ? 'g 获取索引 · M 精确匹配' : '使用本地符号，或 o 切换在线';
  }
}

/** Column widths from the header and a bounded sample of all visible rows. */
export function columnWidths(app: App, index: ReturnType<typeof viewIndex>): number[] {
  const current = result(app.state);
  if (!current) {
    return [];
  }
  const sample = Math.min(index.visible.length, 200);
  return current.columns.map((column, columnIndex) => {
    let best = width(escaped(column));
    for (let offset = 0; offset < sample; offset += 1) {
      const row = visibleRow(app.state, index, offset);
      if (row) {
        best = Math.max(best, width(escaped(row[columnIndex] ?? '')));
      }
    }
    return Math.min(Math.max(best, 3), 120);
  });
}

function columnRects(widths: number[], x: number, y: number, scroll: number): Rect[] {
  let cursor = x;
  return widths.map((cells) => {
    const region = { x: cursor - scroll, y, width: cells, height: 1 };
    cursor += cells + 1;
    return region;
  });
}

function headerLine(state: AppState, widths: number[], scroll: number, columns: number): string {
  const current = result(state);
  if (!current) {
    return '';
  }
  const cells = current.columns.map((column, index) => {
    const label =
      state.sort === index ? `${escaped(column)} ${state.descending ? '↓' : '↑'}` : escaped(column);
    const budget = widths[index] ?? width(label);
    return width(label) > budget ? padCells(truncate(label, budget), budget) : padCells(label, budget);
  });
  return sliceCells(cells.join(' '), scroll, Math.max(columns, 1));
}

function rowLine(row: string[], widths: number[], scroll: number, columns: number): string {
  const cells = row.map((cell, index) => {
    const budget = widths[index] ?? width(cell);
    const text = escaped(cell);
    return width(text) > budget ? padCells(truncate(text, budget), budget) : padCells(text, budget);
  });
  return sliceCells(cells.join(' '), scroll, Math.max(columns, 1));
}

function padCells(text: string, cells: number): string {
  return text + ' '.repeat(Math.max(cells - width(text), 0));
}

function sliceCells(text: string, start: number, length: number): string {
  let out = '';
  let cursor = 0;
  for (const character of text) {
    const cells = charWidth(character);
    if (cursor + cells > start && cursor < start + length) {
      out += character;
    }
    cursor += cells;
    if (cursor >= start + length) {
      break;
    }
  }
  return out;
}

export { treeColumns };
