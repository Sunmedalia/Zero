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
import type { CachePane, Focus, Page, Section } from './actions.js';
import {
  inspector as inspectorSpace,
  menuWidth,
  space,
  twoPanes,
} from './layout.js';
import { imageLines } from './assetView.js';
import { dialogHeight, dialogWidth } from './dialogs.js';
import { activeTab, assetListFor, cacheItems, cacheScopes, remoteList, result, settingsLabels, tabLabel, viewIndex } from './state.js';
import { actionOf, cacheToolbarActions, commandMatches, footerActions, toolbarActions } from './actions.js';
import { rowDetailText } from './detail.js';
import { menuLength as menuLengthOf, pluginMatches } from './state.js';
import { cellWidth, truncate, wrapLines } from './text.js';
import { resultState } from './format.js';

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

/** Page tab labels; painting and hit-testing share them so widths agree. */
export const TAB_LABELS = [' 1 资源库 ', ' 2 分析 ', ' 3 缓存 '] as const;
const TAB_PAGES: Page[] = ['assets', 'analysis', 'cache'];

/** What a scrollbar scrolls; clicks on its track jump there. */
export type ScrollTarget = 'content' | 'menu' | 'pane' | 'inspector' | 'cacheScopes' | 'cacheEntries';

export interface Scrollbar {
  target: ScrollTarget;
  /** One column on the region's right border, alongside the rows it scrolls. */
  track: Rect;
  total: number;
  offset: number;
  visible: number;
  thumb: { y: number; height: number };
}

/** A scrollbar for a region, or null when everything already fits. */
export function scrollbar(
  target: ScrollTarget,
  track: Rect,
  total: number,
  offset: number,
  visible: number,
): Scrollbar | null {
  if (total <= visible || track.height < 2 || visible <= 0) {
    return null;
  }
  const height = Math.max(1, Math.min(track.height, Math.round((track.height * visible) / total)));
  const travel = track.height - height;
  const start = Math.max(0, Math.min(offset, total - visible));
  const y = track.y + Math.round((travel * start) / (total - visible));
  return { target, track, total, offset: start, visible, thumb: { y, height } };
}

/**
 * The row (or line offset) that puts the thumb's top at `y - grab`, where
 * `grab` is how far below the thumb's top the pointer took hold of it.
 *
 * Lists derive their scroll offset from the selected row, and any offset past
 * the first page is produced by exactly one selection: the row at the bottom
 * of the view. Selecting that row makes the view follow the pointer exactly.
 */
export function scrollbarDragIndex(bar: Scrollbar, y: number, grab: number): number {
  const travel = bar.track.height - bar.thumb.height;
  const top = Math.max(0, Math.min(y - grab - bar.track.y, travel));
  const offset = travel === 0 ? 0 : Math.round((top * (bar.total - bar.visible)) / travel);
  if (bar.target === 'inspector') {
    return offset;
  }
  return offset === 0 ? 0 : Math.min(offset + bar.visible - 1, bar.total - 1);
}

/** The first row (or line) a click at `y` on the track should bring into view. */
export function scrollbarIndex(bar: Scrollbar, y: number): number {
  const fraction = Math.max(0, Math.min((y - bar.track.y) / Math.max(bar.track.height - 1, 1), 1));
  // Rows are selected, so any row may be the target; line offsets stop at the last page.
  const last = bar.target === 'inspector' ? bar.total - bar.visible : bar.total - 1;
  return Math.round(fraction * last);
}

/** One opened page in the tab strip, or an overflow chip for hidden pages. */
export interface PageTabHit {
  rect: Rect;
  /** The `×` close target inside the tab; overflow chips have none. */
  close: Rect | null;
  /** Index into `state.openTabs` the tab (or chip) activates. */
  index: number;
  /** Text to draw, already fitted to the rect. */
  label: string;
  kind: 'tab' | 'before' | 'after';
}

/** Widest and narrowest tab title in cells, like a browser shrinking its tabs. */
const TAB_TITLE_MAX = 18;
const TAB_TITLE_MIN = 6;

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
  /** Each entry may occupy several terminal lines (wrapped image names/paths). */
  entries: { index: number; rect: Rect }[];
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
  /** One shared context row for the selected image and symbol readiness. */
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
  /** Cache page: scope list, entry list and the selected entry's detail. */
  cacheScopes: Rect | null;
  cacheEntries: Rect | null;
  cacheDetail: Rect | null;
  cacheOffsets: { scopes: number; entries: number };
  cacheHits: { rect: Rect; pane: CachePane; index: number }[];
  /** Vertical scrollbars, drawn over the right border of scrolling regions. */
  scrollbars: Scrollbar[];
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
  /** Opened result pages, drawn on the result table's top border. */
  pageTabs: PageTabHit[];
  /** Border columns the tab strip may use. */
  pageTabsArea: Rect;
  systemHits: { rect: Rect; os: 'auto' | 'linux' | 'windows' }[];
  sourceHits: { rect: Rect; section: Section }[];
  /** Remote section only: whole index / the image's exact matches. */
  remoteViewHits: { rect: Rect; catalog: boolean; label: string }[];
  regionHits: { rect: Rect; focus: Focus }[];
  /** List row click regions, with the absolute row index. */
  rowHits: { rect: Rect; section: Section | null; index: number }[];
}

/** Compute the whole frame. Pure: same inputs, same rects. */
export function computeLayout(state: AppState, columns: number, rows: number): Layout {
  const layout = space(columns, rows);
  const tabs = rect(0, 0, columns, 1);
  const systems = rect(29, 0, Math.max(columns - 29, 0), 1);
  const headerHeight = 1;
  const header = rect(0, 1, columns, headerHeight);
  const footerHeight = 2;
  const body = rect(0, 1 + headerHeight, columns, Math.max(rows - 1 - headerHeight - footerHeight, 1));
  const status = rect(0, body.y + body.height, columns, Math.min(footerHeight, 1));
  const actions = rect(0, status.y + 1, columns, Math.max(footerHeight - 1, 0));

  const base: Layout = {
    columns,
    rows,
    page: state.page,
    tabs,
    systems,
    header,
    headerImage: rect(0, header.y, Math.floor(columns * 0.55), 1),
    headerSymbol: rect(Math.floor(columns * 0.55), header.y, columns - Math.floor(columns * 0.55), 1),
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
    cacheScopes: null,
    cacheEntries: null,
    cacheDetail: null,
    cacheOffsets: { scopes: 0, entries: 0 },
    cacheHits: [],
    scrollbars: [],
    pageStart: 0,
    pageSize: 0,
    columns_: [],
    popup: null,
    buttons: [],
    tabsHits: [],
    pageTabs: [],
    pageTabsArea: rect(0, 0, 0, 0),
    systemHits: [],
    sourceHits: [],
    remoteViewHits: [],
    regionHits: [],
    rowHits: [],
  };

  let tabX = 0;
  base.tabsHits = TAB_LABELS.map((label, index) => {
    const hit = { rect: rect(tabX, 0, cellWidth(label), 1), page: TAB_PAGES[index] as Page };
    tabX += cellWidth(label) + 1;
    return hit;
  });
  if (state.page === 'analysis' && !twoPanes(layout)) {
    // Narrow analysis layouts replace the system picker with region tabs, so
    // the only visible control stays reachable.
    base.regionHits = [
      { rect: rect(29, 0, 6, 1), focus: 'navigation' },
      { rect: rect(35, 0, 6, 1), focus: 'content' },
    ];
  } else {
    const start = 29;
    // Automatic detection has no chip of its own: the detected system's chip
    // is shown active, and `S` can return to automatic detection.
    const labels: { os: 'linux' | 'windows'; text: string }[] = [
      { os: 'linux', text: ' Linux ' },
      { os: 'windows', text: ' Windows ' },
    ];
    let x = start;
    for (const label of labels) {
      const cells = cellWidth(label.text);
      if (x + cells > columns) {
        continue;
      }
      base.systemHits.push({ rect: rect(x, systems.y, cells, 1), os: label.os });
      x += cells;
    }
  }

  if (state.page === 'assets') {
    layoutAssets(base, state);
  } else if (state.page === 'cache') {
    layoutCache(base, state);
  } else {
    layoutAnalysis(base, state, layout);
    layoutPageTabs(base, state);
  }
  layoutScrollbars(base, state);
  layoutActions(base, state);
  layoutDialog(base, state);
  return base;
}

/**
 * Opened pages as browser-style tabs: titles shrink to share the strip, and
 * when even the narrowest titles do not fit, a window around the active tab
 * is shown with `‹n` / `n›` chips that step to the hidden neighbours.
 */
function layoutPageTabs(base: Layout, state: AppState): void {
  if (!base.content) {
    return;
  }
  // The strip replaces the table title on its top border, after "╭─".
  base.pageTabsArea = rect(base.content.x + 2, base.content.y, Math.max(base.content.width - 4, 0), 1);
  const area = base.pageTabsArea;
  const tabs = state.openTabs;
  if (tabs.length === 0 || area.width < TAB_TITLE_MIN + 4) {
    return;
  }
  // The shown tab also carries the result state the title used to show.
  const shown = activeTab(state);
  const current = result(state);
  const titles = tabs.map((tab, index) =>
    index === shown && current ? `${tabLabel(tab)} · ${resultState(current)}` : tabLabel(tab));
  const widest = (index: number, budget: number) =>
    index === shown ? Math.max(budget, Math.min(cellWidth(titles[index]!), TAB_TITLE_MAX + 8)) : budget;
  // A tab is " title ×" plus a one-cell gap: title + 4 cells.
  const span = (index: number, budget: number) => Math.min(cellWidth(titles[index]!), widest(index, budget)) + 4;
  const total = (budget: number, from = 0, to = tabs.length) => {
    let cells = 0;
    for (let index = from; index < to; index += 1) cells += span(index, budget);
    return cells;
  };
  // The widest common title budget that fits every tab.
  let budget = TAB_TITLE_MAX;
  while (budget > TAB_TITLE_MIN && total(budget) > area.width + 1) {
    budget -= 1;
  }
  let first = 0;
  let last = tabs.length;
  const chip = 5;
  if (total(budget) > area.width + 1) {
    // Grow a window around the active tab, leaving room for both chips.
    const room = area.width + 1 - 2 * chip;
    const active = Math.max(activeTab(state), 0);
    first = active;
    last = active + 1;
    let used = span(active, budget);
    for (;;) {
      const right = last < tabs.length && used + span(last, budget) <= room;
      if (right) used += span(last++, budget);
      const left = first > 0 && used + span(first - 1, budget) <= room;
      if (left) used += span(--first, budget);
      if (!right && !left) break;
    }
  }
  let x = area.x;
  if (first > 0) {
    base.pageTabs.push({ rect: rect(x, area.y, chip - 1, 1), close: null, index: first - 1, label: truncate(` ‹${first}`, chip - 1), kind: 'before' });
    x += chip;
  }
  for (let index = first; index < last; index += 1) {
    const name = truncate(titles[index]!, widest(index, budget));
    const cells = cellWidth(name) + 3;
    if (x + cells > area.x + area.width) {
      last = index;
      break;
    }
    base.pageTabs.push({ rect: rect(x, area.y, cells, 1), close: rect(x + cells - 1, area.y, 1, 1), index, label: ` ${name} `, kind: 'tab' });
    x += cells + 1;
  }
  const hidden = tabs.length - last;
  if (hidden > 0 && x + chip - 1 <= area.x + area.width) {
    base.pageTabs.push({ rect: rect(x, area.y, chip - 1, 1), close: null, index: last, label: truncate(` ${hidden}›`, chip - 1), kind: 'after' });
  }
}

function layoutAssets(base: Layout, state: AppState): void {
  const { columns } = base;
  const y = base.body.y;
  base.sources = rect(0, y, columns, 1);
  base.sourceHits = [
    { rect: rect(0, y, cellWidth(' 镜像 '), 1), section: 'images' },
    { rect: rect(7, y, cellWidth(' 本地库 '), 1), section: 'symbols' },
    { rect: rect(18, y, cellWidth(' 远程索引 '), 1), section: 'remote' },
  ];
  if (state.section === 'remote') {
    let x = 32;
    for (const view of [
      { catalog: true, label: ` 全部索引 ${state.remoteTotal} ` },
      { catalog: false, label: ` 镜像匹配 ${state.remoteMatches === null ? '—' : state.remoteMatches.length} ` },
    ]) {
      const cells = cellWidth(view.label);
      if (x + cells > columns) {
        break;
      }
      base.remoteViewHits.push({ rect: rect(x, y, cells, 1), ...view });
      x += cells + 1;
    }
  }
  // Source tabs are pages: only the active source owns the full content area.
  base.panes.push(paneFor(base, state, state.section, 0, y + 1, columns, base.body.height - 1));
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
  const assets = assetListFor(state, section);
  const count = section === 'remote' ? remoteList(state).length : assets.length;
  const selected = Math.min(state.assetRows[section === 'images' ? 0 : section === 'symbols' ? 1 : 2], Math.max(count - 1, 0));
  const visible = Math.max(rowsRect.height, 1);
  const entryHeight = (index: number): number => section === 'images' && assets[index]
    ? imageLines(assets[index]!, Math.max(rowsRect.width - 2, 1)).length
    : 1;
  let offset = clampOffset(selected, count, visible);
  if (section === 'images') {
    offset = selected;
    let used = entryHeight(selected);
    while (offset > 0 && used + entryHeight(offset - 1) <= visible) {
      used += entryHeight(--offset);
    }
  }
  const pane: PaneLayout = {
    section,
    frame: rect(x, y, width, height),
    search,
    list,
    rows: rowsRect,
    offset,
    visible,
    entries: [],
  };
  let row = 0;
  for (let absolute = offset; absolute < count && row < visible; absolute += 1) {
    const wanted = entryHeight(absolute);
    if (wanted > visible - row && row > 0) break;
    const height = Math.min(wanted, visible - row);
    const entry = { index: absolute, rect: rect(rowsRect.x, rowsRect.y + row, rowsRect.width, height) };
    pane.entries.push(entry);
    base.rowHits.push({ ...entry, section });
    row += height;
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

/** Detail rows under the cache entry list, when the body has room for them. */
const CACHE_DETAIL_ROWS = 7;

function layoutCache(base: Layout, state: AppState): void {
  const { columns, body } = base;
  const left = Math.max(Math.min(Math.floor(columns * 0.32), 40), 28);
  base.cacheScopes = rect(0, body.y, left, body.height);
  const detail = body.height >= 16 ? CACHE_DETAIL_ROWS : 0;
  base.cacheEntries = rect(left, body.y, columns - left, body.height - detail);
  base.cacheDetail = detail > 0 ? rect(left, body.y + body.height - detail, columns - left, detail) : null;
  const lists: [CachePane, Rect, number, number][] = [
    ['scopes', base.cacheScopes, cacheScopes(state).length, state.cache.scope],
    ['entries', base.cacheEntries, cacheItems(state).length, state.cache.entry],
  ];
  for (const [pane, frame, count, selected] of lists) {
    const rows = frameInner(frame);
    const offset = clampOffset(selected, count, rows.height);
    base.cacheOffsets[pane] = offset;
    for (let index = 0; index < rows.height && offset + index < count; index += 1) {
      base.cacheHits.push({ rect: rect(rows.x, rows.y + index, rows.width, 1), pane, index: offset + index });
    }
  }
}

/** Scrollbars for every scrolling region of the current page. */
function layoutScrollbars(base: Layout, state: AppState): void {
  const push = (bar: Scrollbar | null) => {
    if (bar) base.scrollbars.push(bar);
  };
  const border = (frame: Rect, rows: Rect): Rect => rect(frame.x + frame.width - 1, rows.y, 1, rows.height);
  for (const pane of base.panes) {
    const count = pane.section === 'remote' ? remoteList(state).length : assetListFor(state, pane.section).length;
    push(scrollbar('pane', border(pane.list, pane.rows), count, pane.offset, Math.max(pane.entries.length, 1)));
  }
  if (base.menu) {
    const rows = frameInner(base.menu);
    const count = menuLength(state);
    push(scrollbar('menu', border(base.menu, rows), count, clampOffset(state.menu, count, rows.height), rows.height));
  }
  if (base.content && base.contentRows && result(state)) {
    const track = border(base.content, base.contentRows);
    // A narrow inspector covers the table; its own scrollbar takes the border.
    if (!base.inspector || !inside(base.inspector, track.x, track.y)) {
      push(scrollbar('content', track, viewIndex(state).visible.length, base.pageStart, base.pageSize));
    }
  }
  if (base.inspector) {
    const rows = frameInner(base.inspector);
    const lines = wrapLines(rowDetailText(state), rows.width).length;
    push(scrollbar('inspector', border(base.inspector, rows), lines, Math.min(state.detailScroll, Math.max(lines - rows.height, 0)), rows.height));
  }
  if (base.cacheScopes && base.cacheEntries) {
    const scopes = frameInner(base.cacheScopes);
    push(scrollbar('cacheScopes', border(base.cacheScopes, scopes), cacheScopes(state).length, base.cacheOffsets.scopes, scopes.height));
    const entries = frameInner(base.cacheEntries);
    push(scrollbar('cacheEntries', border(base.cacheEntries, entries), cacheItems(state).length, base.cacheOffsets.entries, entries.height));
  }
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

  // A narrow navigation view owns the body; do not paint a zero-width table.
  if (!wide && state.focus === 'navigation') {
    return;
  }
  const mainWidth = columns - x;
  const inspectorVisible = inspectorSpace(layout) && state.inspector;
  const inspectorColumns = inspectorVisible ? 38 : 0;
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
  if (state.inspector && !inspectorVisible) {
    base.inspector = rect(x, base.body.y, mainWidth, base.body.height);
  }
  if (!result(state) && !state.busy && tableHeight >= 10) {
    const command = state.image === null ? 'importImage' : state.symbols === '' && state.plugin !== 'banners' ? 'matchRemote' : 'run';
    const { key, label } = actionOf(command);
    const cells = cellWidth(label) + 2;
    base.buttons.push({
      rect: rect(x + Math.max(Math.floor((contentWidth - cells) / 2), 1), tableY + Math.floor(tableHeight / 2) + 2, cells, 1),
      key, action: label,
    });
  }
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
  const actions = state.page === 'assets'
    ? toolbarActions(state.section, state.busy)
    : state.page === 'cache'
      ? cacheToolbarActions(state.busy)
      : actionLabels(state);
  const more = ' 更多 ? ';
  const moreWidth = cellWidth(more);
  let x = 0;
  for (const action of actions.filter((entry) => entry.key !== '?')) {
    const cells = cellWidth(` ${action.label} `);
    if (x + cells + 1 + moreWidth > base.columns) {
      break;
    }
    base.buttons.push({ rect: rect(x, base.actions.y, cells, 1), key: action.key, action: action.label });
    x += cells + 1;
  }
  base.buttons.push({
    rect: rect(Math.max(base.columns - moreWidth, 0), base.actions.y, Math.min(moreWidth, base.columns), 1),
    key: '?', action: '更多',
  });
}

/** Footer action labels for the focused region, from the action table. */
function actionLabels(state: AppState): { label: string; key: string }[] {
  const actions = state.focus === 'content' && !result(state)
    ? (state.image === null
      ? [actionOf('importImage'), actionOf('pageAssets'), actionOf('plugins')]
      : state.preparation !== 'ready' && state.plugin !== 'banners'
        ? [actionOf('importSymbols'), actionOf('matchLocal'), actionOf('matchRemote')]
        : [actionOf('run'), actionOf('parameters'), actionOf('plugins')])
      .map(({ label, key }) => ({ label, key }))
    : footerActions(state.focus);
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
    (dialog.kind === 'dump' || (dialog.kind === 'detail' && !inspectorSpace(space(base.columns, base.rows)))) && workbench.width > 0
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
        key: 'Ctrl+t',
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
    case 'remoteDetail': {
      // Download actions as chips on the bottom border, Esc at the right.
      const chips = [
        state.image === null ? null : { key: ' ', action: '下载并选用 Space' },
        { key: 'w', action: '仅下载 w' },
        state.downloads.has(dialog.candidate.url) ? { key: 'L', action: '本地库查看 L' } : null,
      ].filter((chip) => chip !== null);
      let x = inner.x + 1;
      const y = popup.y + popup.height - 2;
      const right = popup.x + popup.width - 10;
      for (const chip of chips) {
        const cells = cellWidth(chip.action) + 2;
        if (x + cells > right) {
          break;
        }
        base.buttons.push({ rect: rect(x, y, cells, 1), key: chip.key, action: chip.action });
        x += cells + 1;
      }
      break;
    }
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
