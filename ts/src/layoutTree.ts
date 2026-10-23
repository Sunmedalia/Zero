/**
 * Layout: every rectangle on screen, computed once per frame from state and the
 * terminal size.
 *
 * The renderer draws *into* these rectangles and the mouse handler hit-tests
 * *against* them, so a click target and the thing the user sees cannot drift
 * apart. Nothing here depends on Ink's flexbox: views position themselves
 * absolutely inside the rects below, which also means a modal can be drawn
 * without the page underneath leaking through.
 */
import type { AppState, Dialog, HitMap } from './state.js';
import type { Focus, Page, Section } from './actions.js';
import {
  actionRows,
  assetDetail as assetDetailSpace,
  assetPanesSideBySide,
  assetTwoPanes,
  inspector as inspectorSpace,
  menuWidth,
  space,
  systemRow,
  twoPanes,
} from './layout.js';
import { dialogHeight, dialogWidth } from './dialogs.js';
import { assetListFor, remoteList, result, settingsLabels, viewIndex } from './state.js';
import { commandMatches, footerActions, toolbarActions } from './actions.js';
import { menuLength as menuLengthOf, pluginMatches } from './state.js';
import { cellWidth, wrapLines } from './text.js';

export interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}

export function rect(x: number, y: number, width: number, height: number): Rect {
  return { x, y, width: Math.max(width, 0), height: Math.max(height, 0) };
}

/** Interior rectangle of a framed region, where content rows start. */
export function frameInner(region: Rect): Rect {
  return {
    x: region.x + 1,
    y: region.y + 1,
    width: Math.max(region.width - 2, 1),
    height: Math.max(region.height - 2, 1),
  };
}

export function inside(region: Rect, x: number, y: number): boolean {
  return (
    region.width > 0 &&
    region.height > 0 &&
    x >= region.x &&
    x < region.x + region.width &&
    y >= region.y &&
    y < region.y + region.height
  );
}

/** Rows a list pane spends on its search field. */
export const SEARCH_ROWS = 3;
/** Maximum toolbar rows on the resource page. */
const TOOLBAR_ROWS = 3;

export interface PaneLayout {
  section: Section;
  /** Whole pane, including its frame and optional search field. */
  frame: Rect;
  /** Search field rect, when the pane shows one. */
  search: Rect | null;
  /** List rect: the framed area below the search field. */
  list: Rect;
  /** Interior of the list frame, where rows start. */
  rows: Rect;
  /** Index of the first visible row. */
  offset: number;
  /** Rows the list can show. */
  visible: number;
}

export interface ButtonLayout {
  rect: Rect;
  key: string;
  /** What the button does, for tests and accessibility labels. */
  action: string;
}

export interface Layout {
  columns: number;
  rows: number;
  page: Page;
  /** Navigation tabs row. */
  tabs: Rect;
  /** System picker row, or the region switcher on a narrow analysis page. */
  systems: Rect;
  /** Header: two rows on the resource page, one on the analysis page. */
  header: Rect;
  headerImage: Rect;
  headerSymbol: Rect;
  body: Rect;
  /** Status line, always the first footer row. */
  status: Rect;
  /** Resource toolbar, or the analysis action strip. */
  actions: Rect;
  /** Resource page: source tabs row. */
  sources: Rect | null;
  /** Resource page: list panes in draw order. */
  panes: PaneLayout[];
  /** Resource page: inline detail panel. */
  assetDetail: Rect | null;
  /** Analysis page: plugin menu. */
  menu: Rect | null;
  /** Analysis page: search field above the table. */
  contentSearch: Rect | null;
  /** Analysis page: framed result table. */
  content: Rect | null;
  /** Analysis page: table interior where rows start. */
  contentRows: Rect | null;
  /** Analysis page: right-hand inspector. */
  inspector: Rect | null;
  /** Analysis page: first visible row and page size. */
  pageStart: number;
  pageSize: number;
  /** Column rectangles of the table header. */
  columns_: Rect[];
  /** Modal, when one is open. */
  popup: Rect | null;
  /** Clickable chips and rows. */
  buttons: ButtonLayout[];
  /** Clickable tabs, systems, sources and regions. */
  tabsHits: { rect: Rect; page: Page }[];
  systemHits: { rect: Rect; os: 'auto' | 'linux' | 'windows' }[];
  sourceHits: { rect: Rect; section: Section }[];
  regionHits: { rect: Rect; focus: Focus }[];
  /** List row click regions, with the absolute row index. */
  rowHits: { rect: Rect; section: Section | null; index: number }[];
}

/** Compute the whole frame. Pure: same inputs, same rects. */
export function computeLayout(state: AppState, columns: number, rows: number): Layout {
  const layout = space(columns, rows);
  const tabs = rect(0, 0, columns, 1);
  const systems = rect(0, 1, columns, 1);
  const headerHeight = state.page === 'analysis' ? 1 : 2;
  const header = rect(0, 2, columns, headerHeight);
  const footerHeight = footerRows(state, columns, rows);
  const body = rect(0, 2 + headerHeight, columns, Math.max(rows - 2 - headerHeight - footerHeight, 1));
  const status = rect(0, body.y + body.height, columns, Math.min(footerHeight, 1));
  const actions = rect(0, status.y + 1, columns, Math.max(footerHeight - 1, 0));

  const base: Layout = {
    columns,
    rows,
    page: state.page,
    tabs,
    systems,
    header,
    headerImage: rect(header.x, header.y, header.width, 1),
    headerSymbol: header.height > 1 ? rect(header.x, header.y + 1, header.width, 1) : rect(0, 0, 0, 0),
    body,
    status,
    actions,
    sources: null,
    panes: [],
    assetDetail: null,
    menu: null,
    contentSearch: null,
    content: null,
    contentRows: null,
    inspector: null,
    pageStart: 0,
    pageSize: 0,
    columns_: [],
    popup: null,
    buttons: [],
    tabsHits: [],
    systemHits: [],
    sourceHits: [],
    regionHits: [],
    rowHits: [],
  };

  base.tabsHits = [
    { rect: rect(0, 0, cellWidth(' F2 资源库 '), 1), page: 'assets' },
    { rect: rect(12, 0, cellWidth(' F3 分析 '), 1), page: 'analysis' },
  ];
  if (state.page === 'analysis' && !systemRow(layout)) {
    // Narrow analysis layouts replace the system picker with region tabs, so
    // the only visible control stays reachable.
    base.regionHits = [
      { rect: rect(0, 1, 6, 1), focus: 'navigation' },
      { rect: rect(6, 1, 6, 1), focus: 'content' },
    ];
  } else {
    const start = columns >= 29 ? 7 : 0;
    const labels: { os: 'linux' | 'windows' | 'auto'; text: string }[] = [
      { os: 'linux', text: ' Linux ' },
      { os: 'windows', text: ' Windows ' },
      { os: 'auto', text: ' 自动 ' },
    ];
    let x = start;
    for (const label of labels) {
      const cells = cellWidth(label.text);
      if (x + cells > columns) {
        continue;
      }
      base.systemHits.push({ rect: rect(x, 1, cells, 1), os: label.os });
      x += cells;
    }
  }

  if (state.page === 'assets') {
    layoutAssets(base, state, layout);
  } else {
    layoutAnalysis(base, state, layout);
  }
  layoutActions(base, state);
  layoutDialog(base, state);
  return base;
}

function footerRows(state: AppState, columns: number, rows: number): number {
  if (state.page === 'analysis') {
    return 2;
  }
  const labels = toolbarActions(state.section, state.busy).map((action) => action.label);
  const wanted = 2 + actionRows(labels, columns, TOOLBAR_ROWS);
  return Math.min(wanted, Math.max(Math.floor(rows / 3), 3));
}

function layoutAssets(base: Layout, state: AppState, layout: ReturnType<typeof space>): void {
  const { columns } = base;
  let y = base.body.y;
  base.sources = rect(0, y, columns, 1);
  base.sourceHits = [
    { rect: rect(0, y, cellWidth(' 镜像 '), 1), section: 'images' },
    { rect: rect(7, y, cellWidth(' 本地库 '), 1), section: 'symbols' },
    { rect: rect(18, y, cellWidth(' 远程索引 '), 1), section: 'remote' },
  ];
  y += 1;

  const detailVisible = assetDetailSpace(layout);
  const detailHeight = detailVisible ? 6 : 0;
  const paneArea = rect(0, y, columns, Math.max(base.body.height - 1 - detailHeight, 1));
  if (detailVisible) {
    base.assetDetail = rect(0, paneArea.y + paneArea.height, columns, detailHeight);
  }

  const paneHeight = paneArea.height;
  if (!assetTwoPanes(layout)) {
    base.panes.push(paneFor(base, state, state.section, paneArea.x, paneArea.y, columns, paneHeight));
  } else if (assetPanesSideBySide(layout)) {
    const leftWidth = Math.floor(columns * 0.42);
    base.panes.push(paneFor(base, state, 'images', 0, paneArea.y, leftWidth, paneHeight));
    base.panes.push(
      paneFor(base, state, state.symbolSource, leftWidth, paneArea.y, columns - leftWidth, paneHeight),
    );
  } else {
    const top = Math.floor(paneHeight / 2);
    base.panes.push(paneFor(base, state, 'images', 0, paneArea.y, columns, top));
    base.panes.push(
      paneFor(base, state, state.symbolSource, 0, paneArea.y + top, columns, paneHeight - top),
    );
  }
}

/** One resource list pane, including its search field and row hit regions. */
function paneFor(
  base: Layout,
  state: AppState,
  section: Section,
  x: number,
  y: number,
  width: number,
  height: number,
): PaneLayout {
  const searchVisible = searchShown(state, section);
  const searchHeight = searchVisible ? SEARCH_ROWS : 0;
  const listHeight = Math.max(height - searchHeight, 3);
  const search = searchVisible ? rect(x, y, width, SEARCH_ROWS) : null;
  const list = rect(x, y + searchHeight, width, listHeight);
  const rowsRect = rect(list.x + 1, list.y + 1, Math.max(list.width - 2, 1), Math.max(list.height - 2, 1));
  const count = section === 'remote' ? remoteList(state).length : assetListFor(state, section).length;
  const selected = state.assetRows[section === 'images' ? 0 : section === 'symbols' ? 1 : 2];
  const visible = Math.max(rowsRect.height, 1);
  const offset = clampOffset(selected, count, visible);
  const pane: PaneLayout = {
    section,
    frame: rect(x, y, width, height),
    search,
    list,
    rows: rowsRect,
    offset,
    visible,
  };
  for (let index = 0; index < visible; index += 1) {
    const absolute = offset + index;
    if (absolute >= count) {
      break;
    }
    base.rowHits.push({
      rect: rect(rowsRect.x, rowsRect.y + index, rowsRect.width, 1),
      section,
      index: absolute,
    });
  }
  return pane;
}

function searchShown(state: AppState, section: Section): boolean {
  const editing =
    state.dialog?.kind === 'input' &&
    state.dialog.input === 'assetsSearch' &&
    state.section === section;
  return editing || state.assetQueries[section === 'images' ? 0 : section === 'symbols' ? 1 : 2] !== '';
}

function clampOffset(selected: number, count: number, visible: number): number {
  if (count <= visible) {
    return 0;
  }
  if (selected < visible) {
    return 0;
  }
  return Math.min(selected - visible + 1, count - visible);
}

function layoutAnalysis(base: Layout, state: AppState, layout: ReturnType<typeof space>): void {
  const { columns } = base;
  const wide = twoPanes(layout);
  const menuColumns = wide ? menuWidth(layout) : state.focus === 'navigation' ? columns : 0;
  let x = 0;
  if (menuColumns > 0) {
    base.menu = rect(0, base.body.y, menuColumns, base.body.height);
    const rowsRect = rect(1, base.body.y + 1, Math.max(menuColumns - 2, 1), Math.max(base.body.height - 2, 1));
    const count = menuLength(state);
    const offset = clampOffset(state.menu, count, Math.max(rowsRect.height, 1));
    for (let index = 0; index < rowsRect.height; index += 1) {
      const absolute = offset + index;
      if (absolute >= count) {
        break;
      }
      base.rowHits.push({
        rect: rect(rowsRect.x, rowsRect.y + index, rowsRect.width, 1),
        section: null,
        index: absolute,
      });
    }
    x = menuColumns;
  }

  const mainWidth = columns - x;
  const inspectorVisible = inspectorSpace(layout) && state.inspector;
  const inspectorColumns = inspectorVisible ? 42 : 0;
  if (inspectorVisible) {
    base.inspector = rect(columns - inspectorColumns, base.body.y, inspectorColumns, base.body.height);
  }
  const contentWidth = Math.max(mainWidth - inspectorColumns, 0);
  const searching =
    (state.dialog?.kind === 'input' && state.dialog.input === 'search') || state.query !== '';
  const searchHeight = searching ? SEARCH_ROWS : 0;
  if (searching) {
    base.contentSearch = rect(x, base.body.y, contentWidth, SEARCH_ROWS);
  }
  const tableY = base.body.y + searchHeight;
  const tableHeight = Math.max(base.body.height - searchHeight, 1);
  base.content = rect(x, tableY, contentWidth, tableHeight);
  base.contentRows = rect(
    x + 1,
    tableY + 2,
    Math.max(contentWidth - 2, 1),
    Math.max(tableHeight - 3, 1),
  );
  const pageSize = Math.max(base.contentRows.height, 1);
  base.pageSize = pageSize;
  const total = viewIndex(state).visible.length;
  const selected = Math.min(state.row, Math.max(total - 1, 0));
  base.pageStart = clampPageStart(selected, pageSize, total);
  for (let index = 0; index < pageSize; index += 1) {
    const absolute = base.pageStart + index;
    if (absolute >= total) {
      break;
    }
    base.rowHits.push({
      rect: rect(base.contentRows.x, base.contentRows.y + index, base.contentRows.width, 1),
      section: null,
      index: absolute,
    });
  }
}

function clampPageStart(selected: number, pageSize: number, total: number): number {
  const start = selected >= pageSize ? selected + 1 - pageSize : 0;
  return Math.min(start, Math.max(total - pageSize, 0));
}

function menuLength(state: AppState): number {
  return menuLengthOf(state);
}

/** Toolbar chips (resource page) or action chips (analysis page). */
function layoutActions(base: Layout, state: AppState): void {
  if (base.actions.height === 0) {
    return;
  }
  if (state.page === 'assets') {
    const actions = toolbarActions(state.section, state.busy);
    const more = ' 更多 ? ';
    const moreWidth = more.length;
    const rows = base.actions.height;
    let x = 0;
    let row = 0;
    let shown = 0;
    for (const action of actions) {
      const label = ` ${action.label} `;
      const cells = cellWidth(label);
      if (cells > base.columns) {
        continue;
      }
      if (x + cells + moreWidth > base.columns) {
        x = 0;
        row += 1;
      }
      if (row >= rows) {
        break;
      }
      base.buttons.push({
        rect: rect(x, base.actions.y + row, cells, 1),
        key: action.key,
        action: action.label,
      });
      x += cells + 1;
      shown += 1;
    }
    if (shown < actions.length) {
      const moreX = base.columns - x >= moreWidth ? x : 0;
      const moreY = base.actions.y + Math.min(row, rows - 1);
      base.buttons.push({ rect: rect(moreX, moreY, moreWidth, 1), key: '?', action: '更多' });
    }
    return;
  }
  const actions = actionLabels(state);
  const more = ' 更多 ? ';
  let x = 0;
  let row = 0;
  let shown = 0;
  for (const action of actions) {
    const label = ` ${action.label} `;
    const cells = cellWidth(label);
    if (cells > base.columns) {
      continue;
    }
    if (x + cells + more.length > base.columns) {
      if (row + 1 >= base.actions.height) {
        break;
      }
      x = 0;
      row += 1;
    }
    base.buttons.push({
      rect: rect(x, base.actions.y + row, cells, 1),
      key: action.key,
      action: action.label,
    });
    x += cells + 1;
    shown += 1;
  }
  if (shown < actions.length) {
    const moreX = base.columns - x >= more.length ? x : 0;
    base.buttons.push({ rect: rect(moreX, base.actions.y + row, more.length, 1), key: '?', action: '更多' });
  }
}

/** Footer action labels for the focused region, from the action table. */
function actionLabels(state: AppState): { label: string; key: string }[] {
  const actions = footerActions(state.focus);
  if (state.focus === 'navigation') {
    actions.unshift({ label: '内容 Tab', key: 'Tab' });
  }
  if (state.busy) {
    actions.unshift({ label: '取消 Esc', key: 'Esc' });
  }
  return actions;
}

/** Modal geometry plus its clickable rows and buttons. */
function layoutDialog(base: Layout, state: AppState): void {
  const dialog = state.dialog;
  if (!dialog) {
    return;
  }
  // Search fields are drawn inline by their pane; every other input is modal.
  if (dialog.kind === 'input' && (dialog.input === 'search' || dialog.input === 'assetsSearch')) {
    return;
  }
  const width = dialogWidth(state, dialog, base.columns);
  const height = dialogHeight(state, dialog, base.rows);
  const workbench =
    state.page === 'analysis' && base.content
      ? base.content
      : rect(0, base.body.y, base.columns, base.body.height);
  const popup =
    (dialog.kind === 'dump' || (dialog.kind === 'detail' && base.columns < 140)) && workbench.width > 0
      ? workbench
      : rect(
          Math.floor((base.columns - Math.min(width, base.columns)) / 2),
          Math.floor((base.rows - Math.min(height, base.rows)) / 2),
          Math.min(width, base.columns),
          Math.min(height, base.rows),
        );
  base.popup = popup;
  layoutDialogButtons(base, state, dialog, popup);
  layoutDialogRows(base, state, dialog, popup);
}

function layoutDialogButtons(base: Layout, state: AppState, dialog: Dialog, popup: Rect): void {
  const inner = rect(popup.x + 1, popup.y + 1, Math.max(popup.width - 2, 1), Math.max(popup.height - 2, 1));
  switch (dialog.kind) {
    case 'dump':
      base.buttons.push({
        rect: rect(inner.x, popup.y + popup.height - 3, 12, 1),
        key: 'Enter',
        action: '开始转储',
      });
      base.buttons.push({
        rect: rect(inner.x + 13, popup.y + popup.height - 3, 6, 1),
        key: 'Esc',
        action: '取消',
      });
      return;
    case 'generateSymbols':
      base.buttons.push({
        rect: rect(inner.x, popup.y + popup.height - 5, 18, 1),
        key: 'Enter',
        action: '生成并选用',
      });
      base.buttons.push({
        rect: rect(inner.x + 20, popup.y + popup.height - 5, 14, 1),
        key: 'F7',
        action: '切换方式',
      });
      base.buttons.push({
        rect: rect(inner.x + 36, popup.y + popup.height - 5, 10, 1),
        key: 'Esc',
        action: '取消',
      });
      return;
    case 'input':
      base.buttons.push({ rect: rect(popup.x + 1, popup.y + popup.height - 3, 6, 1), key: 'Enter', action: '确认' });
      base.buttons.push({ rect: rect(popup.x + 8, popup.y + popup.height - 3, 6, 1), key: 'Esc', action: '取消' });
      return;
    case 'cache':
      base.buttons.push({
        rect: rect(inner.x, popup.y + popup.height - 3, 12, 1),
        key: 'Enter',
        action: dialog.confirm ? '确认清理' : '预览清理',
      });
      break;
    default:
      break;
  }
  // Every other modal closes with Esc from a chip in the bottom-right corner.
  base.buttons.push({
    rect: rect(Math.max(popup.x + popup.width - 9, popup.x), popup.y + popup.height - 2, 8, 1),
    key: 'Esc',
    action: '取消',
  });
  void state;
}

/** Clickable rows of the modal's list, if it has one. */
function layoutDialogRows(base: Layout, state: AppState, dialog: Dialog, popup: Rect): void {
  const first = popup.y + 1;
  const available = Math.max(popup.height - 2, 1);
  const add = (count: number, selected: number, activation: string) => {
    const offset = clampOffset(selected, count, available);
    for (let index = 0; index < available; index += 1) {
      const absolute = offset + index;
      if (absolute >= count) {
        break;
      }
      base.buttons.push({
        rect: rect(popup.x + 1, first + index, Math.max(popup.width - 2, 1), 1),
        key: `row:${absolute}`,
        action: activation,
      });
    }
  };
  switch (dialog.kind) {
    case 'system':
      add(3, dialog.selected, '选择系统');
      return;
    case 'settings':
      add(settingsLabels(state).length, dialog.selected, '修改设置');
      return;
    case 'plugins':
      add(pluginMatches(state, dialog.query).length, dialog.selected, '选择插件');
      return;
    case 'commands':
      add(
        commandMatches(
          dialog.query,
          state.page,
          state.focus,
          state.page === 'assets' ? state.section : null,
        ).length,
        dialog.selected,
        '执行命令',
      );
      return;
    case 'links':
      add(dialog.matches.length, dialog.selected, '下载符号');
      return;
    case 'symbols':
      add(dialog.labels.length, dialog.selected, '选用符号');
      return;
    case 'sort':
      add(result(state)?.columns.length ?? 0, dialog.column, '选择排序列');
      return;
    case 'files':
      add(dialog.entries.length, dialog.selected, '打开条目');
      return;
    case 'cache':
      add(state.hello?.scopes.length ?? 0, dialog.selected, '切换缓存范围');
      return;
    default:
      return;
  }
}

/** Convert the layout into the hit map the state machine reads. */
export function hitMap(layout: Layout, state: AppState): HitMap {
  const zero = rect(0, 0, 0, 0);
  return {
    header: layout.header,
    headerImage: layout.headerImage,
    headerSymbol: layout.headerSymbol,
    tabs: layout.tabsHits,
    systems: layout.systemHits,
    regions: layout.regionHits,
    sources: layout.sourceHits,
    assetLists: layout.panes.map((pane) => ({
      rect: pane.list,
      section: pane.section,
      offset: pane.offset,
    })),
    assetSearches: layout.panes
      .filter((pane) => pane.search !== null)
      .map((pane) => ({ rect: pane.search as Rect, section: pane.section })),
    assetButtons: layout.buttons
      .filter(() => state.page === 'assets' && !layout.popup)
      .map((button) => ({
        rect: button.rect,
        section: state.section,
        key: button.key,
      })),
    assets: layout.panes.find((pane) => pane.section === state.section)?.list ?? zero,
    assetOffset: layout.panes.find((pane) => pane.section === state.section)?.offset ?? 0,
    assetDetail: layout.assetDetail ?? zero,
    search: layout.contentSearch ?? zero,
    menu: layout.menu ?? zero,
    menuOffset: layout.menu
      ? clampOffset(state.menu, menuLength(state), Math.max((layout.menu.height - 2), 1))
      : 0,
    result: layout.content ?? zero,
    workbench: layout.content ?? zero,
    inspector: layout.inspector ?? zero,
    popup: layout.popup ?? zero,
    popupOffset: 0,
    rowOffset: layout.pageStart,
    columns: layout.columns_,
    buttons: layout.buttons
      .filter((button) => (layout.popup ? inside(layout.popup, button.rect.x, button.rect.y) : true))
      .map((button) => ({ rect: button.rect, key: button.key })),
    dumpFields: [],
    dumpModes: [],
  };
}

/** Rows a detail modal can scroll, given its popup. */
export function scrollLimit(text: string, popup: Rect, reserved = 2): number {
  const width = Math.max(popup.width - 2, 1);
  const lines = wrapLines(text, width).length;
  return Math.max(lines - Math.max(popup.height - reserved, 1), 0);
}

export { viewIndex };
