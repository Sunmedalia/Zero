/**
 * Application state and the derived views the renderer and dispatcher share.
 *
 * This mirrors the previous `src/tui/state.rs` field-for-field where the field
 * affects behaviour, and adds only what a JSON boundary requires (promises are
 * never stored; tasks are tracked by the backend client).
 */
import { resolve } from 'node:path';
import type {
  AnalyzeReply,
  Arch,
  Asset,
  AssetKind,
  CacheEntry,
  DumpSpec,
  Hello,
  Options,
  Os,
  PluginDescriptor,
  RemoteMatch,
  Results,
  ScopeId,
  Settings,
} from './types.js';
import {
  commandApplies,
  commandForKey,
  commandMatches,
  footerActions,
  queryMatches,
  type Command,
  type Focus,
  type Page,
  type Section,
} from './actions.js';
import { compareValues } from './resultView.js';

export type InputKind =
  | 'image'
  | 'symbols'
  | 'search'
  | 'assetsSearch'
  | 'export'
  | 'history'
  | 'imageDirectory'
  | 'symbolsDirectory'
  | 'exportDirectory'
  | 'pageSize';

export type Preparation =
  | 'chooseImage'
  | 'matching'
  | 'chooseSystem'
  | 'missingSymbols'
  | 'chooseSymbols'
  | 'ready'
  | 'cancelled';

export interface FieldDialog {
  fields: string[];
  field: number;
  cursor: number;
  selected: boolean;
  error: string;
}

export type Dialog =
  | ({ kind: 'generateSymbols'; automatic: boolean } & FieldDialog)
  | ({ kind: 'dump'; mode: string; force: boolean } & FieldDialog)
  | {
      kind: 'files';
      input: InputKind;
      root: string;
      entries: { path: string; name: string; directory: boolean; kind: string }[];
      selected: number;
    }
  | { kind: 'settings'; selected: number }
  | { kind: 'system'; selected: number }
  | {
      kind: 'cache';
      entries: CacheEntry[];
      scopes: ScopeId[];
      selected: number;
      confirm: boolean;
    }
  | { kind: 'commands'; query: string; selected: number }
  | ({ kind: 'windowsParameters'; advanced: boolean } & FieldDialog)
  | { kind: 'plugins'; query: string; selected: number }
  | { kind: 'links'; matches: RemoteMatch[]; selected: number }
  | { kind: 'assetDetail'; asset: Asset; scroll: number }
  | { kind: 'remoteDetail'; candidate: RemoteMatch; scroll: number }
  | { kind: 'detail'; text: string; scroll: number }
  | {
      kind: 'input';
      input: InputKind;
      text: string;
      original: string;
      cursor: number;
      selected: boolean;
    }
  | { kind: 'sort'; column: number }
  | { kind: 'symbols'; labels: string[]; selected: number };

/** Browsing state kept per plugin + parameter combination. */
export interface SavedView {
  query: string;
  sort: number | null;
  descending: boolean;
  row: number;
  collapsed: string[];
  horizontal: number;
}

export interface ExecutionSnapshot {
  force: boolean;
  plugin: string;
  options: Options;
  dump: { plugin: string; options: DumpSpec } | null;
}

export interface Execution {
  plugin: string;
  key: string;
  parameters: string;
  snapshot: ExecutionSnapshot;
}

export interface PendingWork {
  kind:
    | 'clear'
    | 'prepareKali'
    | 'generateSymbols'
    | 'identify'
    | 'inspectSymbols'
    | 'refreshLookup'
    | 'analyze'
    | 'fetchMatched'
    | 'matchLocal'
    | 'download'
    | 'catalog'
    | 'catalogDownload';
  force?: boolean;
  paths?: string[];
  stamp?: string;
  candidate?: RemoteMatch;
  query?: string;
  refresh?: boolean;
  fields?: { elf?: string; config?: string; tool?: string };
  scopes?: ScopeId[];
  path?: string;
}

export interface HitRegion {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface HitMap {
  header: HitRegion;
  headerImage: HitRegion;
  headerSymbol: HitRegion;
  tabs: { rect: HitRegion; page: Page }[];
  systems: { rect: HitRegion; os: Os }[];
  regions: { rect: HitRegion; focus: Focus }[];
  sources: { rect: HitRegion; section: Section }[];
  assetLists: { rect: HitRegion; section: Section; offset: number }[];
  assetButtons: { rect: HitRegion; section: Section; key: string }[];
  assetSearches: { rect: HitRegion; section: Section }[];
  dumpFields: { rect: HitRegion; index: number }[];
  dumpModes: { rect: HitRegion; plugin: string }[];
  assets: HitRegion;
  assetOffset: number;
  assetDetail: HitRegion;
  search: HitRegion;
  menu: HitRegion;
  result: HitRegion;
  workbench: HitRegion;
  inspector: HitRegion;
  popup: HitRegion;
  menuOffset: number;
  rowOffset: number;
  popupOffset: number;
  columns: HitRegion[];
  buttons: { rect: HitRegion; key: string }[];
}

export function emptyHits(): HitMap {
  const zero: HitRegion = { x: 0, y: 0, width: 0, height: 0 };
  return {
    header: zero,
    headerImage: zero,
    headerSymbol: zero,
    tabs: [],
    systems: [],
    regions: [],
    sources: [],
    assetLists: [],
    assetButtons: [],
    assetSearches: [],
    dumpFields: [],
    dumpModes: [],
    assets: zero,
    assetOffset: 0,
    assetDetail: zero,
    search: zero,
    menu: zero,
    result: zero,
    workbench: zero,
    inspector: zero,
    popup: zero,
    menuOffset: 0,
    rowOffset: 0,
    popupOffset: 0,
    columns: [],
    buttons: [],
  };
}

export function contains(region: HitRegion, x: number, y: number): boolean {
  return (
    region.width > 0 &&
    region.height > 0 &&
    x >= region.x &&
    x < region.x + region.width &&
    y >= region.y &&
    y < region.y + region.height
  );
}

export interface AppState {
  hello: Hello | null;
  page: Page;
  section: Section;
  symbolSource: Section;
  assets: Asset[];
  assetRows: [number, number, number];
  assetScroll: [number, number, number];
  assetQueries: [string, string, string];
  assetDetails: Map<string, string>;
  remote: RemoteMatch[];
  remoteCatalog: boolean;
  downloads: Map<string, string>;
  hiddenCacheCopies: Set<string>;
  localMatches: Map<string, string[]>;
  localMatchStamp: string | null;
  preparedStamp: string | null;
  localMatchErrors: string[];
  localOnlyMatches: boolean;
  image: string | null;
  symbols: string;
  settings: Settings;
  focus: Focus;
  menu: number;
  menuScroll: number;
  plugin: string;
  windows: boolean;
  analysisOptions: Options;
  results: Map<string, Results>;
  resultsRevision: number;
  history: Results | null;
  historyRevision: number;
  query: string;
  sort: number | null;
  descending: boolean;
  row: number;
  collapsed: Set<string>;
  status: string;
  lastError: string | null;
  logs: string[];
  startedAt: number | null;
  progress: number | null;
  dialog: Dialog | null;
  choice: string | null;
  dumpOptions: { plugin: string; options: DumpSpec } | null;
  backDialog: Dialog | null;
  pendingWork: PendingWork | null;
  pendingPath: { input: InputKind; path: string } | null;
  pendingExecution: ExecutionSnapshot | null;
  preparation: Preparation;
  preparationCandidates: { path: string; label: string }[];
  objectVersion: number;
  activeRequest: Execution | null;
  symbolRetry: ExecutionSnapshot | null;
  preparationLookup: boolean;
  parameterDrafts: Map<string, Options>;
  resultRequests: Map<string, string>;
  pendingOs: Os | null;
  horizontal: number;
  inspector: boolean;
  detailScroll: number;
  views: Map<string, SavedView>;
  enterWhenReady: boolean;
  quitArmed: boolean;
  busy: boolean;
  cancelled: boolean;
  hits: HitMap;
  /** Terminal size of the last frame, so keys can decide layout-dependent behaviour. */
  columns: number;
  rows: number;
}

export function defaultOptions(): Options {
  return {
    os: 'auto',
    arch: 'auto',
    pid: null,
    hive: null,
    key: '',
    pagefiles: [],
    swapfile: null,
  };
}

export function defaultView(): SavedView {
  return { query: '', sort: null, descending: false, row: 0, collapsed: [], horizontal: 0 };
}

export function initialState(hello: Hello, launch: { image: string | null; symbols: string | null }): AppState {
  const options = defaultOptions();
  return {
    hello,
    page: 'assets',
    section: 'images',
    symbolSource: 'symbols',
    assets: [],
    assetRows: [0, 0, 0],
    assetScroll: [0, 0, 0],
    assetQueries: ['', '', ''],
    assetDetails: new Map(),
    remote: [],
    remoteCatalog: true,
    downloads: new Map(),
    hiddenCacheCopies: new Set(),
    localMatches: new Map(),
    localMatchStamp: null,
    preparedStamp: null,
    localMatchErrors: [],
    localOnlyMatches: false,
    image: launch.image,
    symbols: launch.symbols ?? '',
    settings: hello.settings,
    focus: 'navigation',
    menu: 0,
    menuScroll: 0,
    plugin: 'pslist',
    windows: false,
    analysisOptions: options,
    results: new Map(),
    resultsRevision: 0,
    history: null,
    historyRevision: 0,
    query: '',
    sort: null,
    descending: false,
    row: 0,
    collapsed: new Set(),
    status: 'Space 选用镜像 · Enter 选用并进入分析 · i 导入 · ? 命令面板',
    lastError: null,
    logs: [],
    startedAt: null,
    progress: null,
    dialog: null,
    choice: null,
    dumpOptions: null,
    backDialog: null,
    pendingWork: null,
    pendingPath: null,
    pendingExecution: null,
    preparation: 'chooseImage',
    preparationCandidates: [],
    objectVersion: 0,
    activeRequest: null,
    symbolRetry: null,
    preparationLookup: false,
    parameterDrafts: new Map(),
    resultRequests: new Map(),
    pendingOs: null,
    horizontal: 0,
    inspector: false,
    detailScroll: 0,
    views: new Map(),
    enterWhenReady: false,
    quitArmed: false,
    busy: false,
    cancelled: false,
    hits: emptyHits(),
    columns: 100,
    rows: 30,
  };
}

/* ------------------------------------------------------------------ */
/* Derived selectors                                                    */
/* ------------------------------------------------------------------ */

export function pluginDescriptor(state: AppState, name: string): PluginDescriptor | undefined {
  return state.hello?.plugins.find((plugin) => plugin.name === name);
}

/** Short label: `windows.pslist` reads as `pslist` everywhere but the registry. */
export function pluginLabel(plugin: PluginDescriptor | undefined, name: string): string {
  if (!plugin) {
    return name;
  }
  if (plugin.dump) {
    return 'dump';
  }
  return plugin.name.startsWith('windows.') ? plugin.name.slice('windows.'.length) : plugin.name;
}

const CATEGORIES = ['Process', 'System', 'Memory', 'Files', 'Network', 'Integrity'];

/** Menu order for the active platform, built once per platform switch. */
export function navigationPlugins(state: AppState): PluginDescriptor[] {
  const plugins = state.hello?.plugins ?? [];
  const ordered: PluginDescriptor[] = [];
  for (const category of CATEGORIES) {
    for (const plugin of plugins) {
      if (!plugin.dump && plugin.os === (state.windows ? 'windows' : 'linux') && plugin.category === category) {
        ordered.push(plugin);
      }
    }
  }
  return ordered;
}

/** Number of selectable rows in the plugin menu, including `dump`. */
export function menuLength(state: AppState): number {
  return menuItems(state).length;
}

export function menuItems(state: AppState): string[] {
  return [...navigationPlugins(state).map((plugin) => pluginLabel(plugin, plugin.name)), 'dump'];
}

/** Plugins are found by name, short label, Chinese description or category. */
export function pluginMatches(state: AppState, query: string): PluginDescriptor[] {
  const plugins = (state.hello?.plugins ?? []).filter(
    (plugin) =>
      !plugin.dump &&
      plugin.os === (state.windows ? 'windows' : 'linux') &&
      queryMatches(`${plugin.name} ${pluginLabel(plugin, plugin.name)} ${plugin.description} ${plugin.category}`, query),
  );
  if ('dump'.includes(query.toLowerCase())) {
    const dump = state.hello?.plugins.find((plugin) => plugin.name === (state.windows ? 'windows.procdump' : 'procdump'));
    if (dump) {
      plugins.push(dump);
    }
  }
  return plugins;
}

export function samePath(a: string, b: string): boolean {
  if (a === b) {
    return true;
  }
  if (!a || !b) {
    return false;
  }
  try {
    return resolve(a) === resolve(b);
  } catch {
    return false;
  }
}

export function sectionSlot(section: Section): 0 | 1 | 2 {
  return section === 'images' ? 0 : section === 'symbols' ? 1 : 2;
}

export function sectionTitle(section: Section): string {
  return section === 'images' ? '镜像' : section === 'symbols' ? '本地符号' : '远程符号';
}

export function assetListFor(state: AppState, section: Section): Asset[] {
  const kind: AssetKind = section === 'images' ? 'image' : 'symbols';
  const query = state.assetQueries[sectionSlot(section)].toLowerCase();
  return state.assets.filter(
    (asset) =>
      asset.kind === kind &&
      !state.hiddenCacheCopies.has(asset.path) &&
      (section !== 'symbols' || !state.localOnlyMatches || state.localMatches.has(asset.path)) &&
      asset.path.toLowerCase().includes(query),
  );
}

export function assetList(state: AppState): Asset[] {
  return assetListFor(state, state.section);
}

export function remoteList(state: AppState): RemoteMatch[] {
  const query = state.assetQueries[2].toLowerCase();
  const words = query.split(/\s+/u).filter(Boolean);
  return state.remote.filter((candidate) => {
    const text = `${candidate.path} ${candidate.banner} ${candidate.url}`.toLowerCase();
    return words.every((word) => text.includes(word));
  });
}

export function assetCount(state: AppState): number {
  return state.section === 'remote' ? remoteList(state).length : assetList(state).length;
}

export function selectedAsset(state: AppState): Asset | null {
  return assetList(state)[state.assetRows[sectionSlot(state.section)]] ?? null;
}

export function selectedRemote(state: AppState): RemoteMatch | null {
  return remoteList(state)[state.assetRows[2]] ?? null;
}

export function remoteCached(state: AppState, candidate: RemoteMatch): boolean {
  const saved = state.downloads.get(candidate.url);
  return Boolean(saved);
}

export function assetActive(state: AppState, asset: Asset): boolean {
  return asset.kind === 'image'
    ? state.image !== null && samePath(state.image, asset.path)
    : samePath(state.symbols, asset.path);
}

export function requestKey(state: AppState): string {
  return `${state.plugin}:${JSON.stringify(state.analysisOptions)}:${JSON.stringify(state.dumpOptions)}`;
}

export function parameterSummary(state: AppState): string {
  const options = state.analysisOptions;
  return `PID=${options.pid ?? '全部'} · hive=${options.hive === null ? '' : `0x${BigInt(options.hive).toString(16)}`} · key=${options.key} · arch=${options.arch} · pagefile=${JSON.stringify(options.pagefiles)} · swapfile=${options.swapfile ?? ''}`;
}

export function result(state: AppState): Results | null {
  if (state.history) {
    return state.history;
  }
  return state.results.get(requestKey(state)) ?? state.results.get(state.plugin) ?? null;
}

/** Tree layout columns for `pstree`, or `null` when the result is not a tree. */
export function treeColumns(state: AppState): { parent: number; name: number } | null {
  if (state.history) {
    return null;
  }
  const plugin = pluginDescriptor(state, state.plugin);
  if (!plugin?.tree) {
    return null;
  }
  return state.plugin === 'windows.pstree' ? { parent: 1, name: 2 } : { parent: 2, name: 3 };
}

export interface ViewIndex {
  /** Row indices into `result.rows` that survive the query, in display order. */
  filtered: number[];
  /** Rows actually drawn, with optional tree decoration. */
  visible: { row: number; decoration: { column: number; depth: number; marker: string } | null }[];
}

/**
 * Indexed result view: no cell copies during filtering, sorting or tree
 * traversal. Collapsing a node hides its subtree without dropping rows from
 * `filtered`, so export still contains every match.
 */
export function viewIndex(state: AppState): ViewIndex {
  const current = result(state);
  if (!current) {
    return { filtered: [], visible: [] };
  }
  const query = state.query.toLowerCase();
  let filtered = current.rows
    .map((row, index) => ({ row, index }))
    .filter(({ row }) => query === '' || row.some((cell) => cell.toLowerCase().includes(query)))
    .map(({ index }) => index);
  if (state.sort !== null) {
    const column = state.sort;
    filtered = [...filtered].sort((a, b) => {
      const left = current.rows[a]?.[column] ?? '';
      const right = current.rows[b]?.[column] ?? '';
      const order = compareValues(left, right);
      return state.descending ? -order : order;
    });
  }
  const tree = treeColumns(state);
  if (!tree) {
    return { filtered, visible: filtered.map((row) => ({ row, decoration: null })) };
  }
  const ids = new Set(filtered.map((index) => current.rows[index]?.[0] ?? ''));
  const children = new Map<string, number[]>();
  const roots: number[] = [];
  for (const index of filtered) {
    const row = current.rows[index] ?? [];
    const id = row[0] ?? '';
    const parent = row[tree.parent] ?? '0';
    if (parent === '0' || parent === id || !ids.has(parent)) {
      roots.push(index);
    } else {
      const bucket = children.get(parent);
      if (bucket) {
        bucket.push(index);
      } else {
        children.set(parent, [index]);
      }
    }
  }
  const visited = new Set<number>();
  const visible: ViewIndex['visible'] = [];
  for (const root of [...roots, ...filtered]) {
    const stack: { row: number; depth: number; hidden: boolean }[] = [{ row: root, depth: 0, hidden: false }];
    while (stack.length > 0) {
      const frame = stack.pop() as { row: number; depth: number; hidden: boolean };
      if (visited.has(frame.row)) {
        continue;
      }
      visited.add(frame.row);
      const row = current.rows[frame.row] ?? [];
      const id = row[0] ?? '';
      const kids = children.get(id);
      const closed = state.collapsed.has(id);
      if (!frame.hidden) {
        visible.push({
          row: frame.row,
          decoration: {
            column: tree.name,
            depth: Math.min(frame.depth, 64),
            marker: kids === undefined ? '·' : closed ? '▸' : '▾',
          },
        });
      }
      if (kids) {
        for (let index = kids.length - 1; index >= 0; index -= 1) {
          stack.push({ row: kids[index] as number, depth: frame.depth + 1, hidden: frame.hidden || closed });
        }
      }
    }
  }
  return { filtered, visible };
}

/** Cells for one visible row, with the tree decoration applied to one column. */
export function visibleRow(state: AppState, index: ViewIndex, position: number): string[] | null {
  const current = result(state);
  const line = index.visible[position];
  if (!current || !line) {
    return null;
  }
  const row = current.rows[line.row];
  if (!row) {
    return null;
  }
  if (!line.decoration) {
    return row;
  }
  const cells = [...row];
  const { column, depth, marker } = line.decoration;
  if (cells[column] !== undefined) {
    cells[column] = `${'  '.repeat(depth)}${marker} ${cells[column]}`;
  }
  return cells;
}

export function detailText(state: AppState): string {
  const current = result(state);
  const row = visibleRow(state, viewIndex(state), state.row);
  if (!current || !row) {
    return '选择一行查看完整字段。';
  }
  return current.columns.map((column, index) => `${column}: ${row[index] ?? ''}`).join('\n\n');
}

export function footerActionsFor(state: AppState): { label: string; key: string }[] {
  if (state.page !== 'analysis') {
    return [];
  }
  const actions = footerActions(state.focus);
  if (state.focus === 'navigation') {
    actions.unshift({ label: '内容 Tab', key: 'Tab' });
  }
  if (state.busy) {
    actions.unshift({ label: '取消 Esc', key: 'Esc' });
  }
  return actions;
}


/** Availability for a command, decided by identity rather than by key. */
export function commandDisabled(state: AppState, command: Command): string | null {
  if (state.page === 'assets' && !commandApplies(command, state.section)) {
    return '当前资源区不适用该操作';
  }
  const busy = state.busy;
  switch (command) {
    case 'generateSymbols':
      if (state.windows) {
        return 'Windows 请使用 M 获取精确 PDB 符号';
      }
      break;
    case 'enterAnalysis':
    case 'matchLocal':
    case 'matchRemote':
    case 'identify':
      if (state.image === null) {
        return '请先选用镜像';
      }
      break;
    case 'selectAndEnter':
      if (
        state.section !== 'remote' &&
        state.image === null &&
        (state.section !== 'images' || assetList(state).length === 0)
      ) {
        return '请先选用镜像';
      }
      break;
    case 'importCurrent':
      if (state.section === 'remote') {
        return '远程符号请使用下载';
      }
      break;
    case 'download':
      if (state.section !== 'remote' || selectedRemote(state) === null) {
        return '请先选择远程符号';
      }
      break;
    case 'select':
    case 'assetDetail':
    case 'deleteAsset': {
      const empty = state.section === 'remote' ? remoteList(state).length === 0 : assetList(state).length === 0;
      if (empty) {
        return '列表为空，请导入或搜索';
      }
      break;
    }
    case 'export':
    case 'sort':
    case 'rows':
      if (result(state) === null) {
        return '尚无结果；先运行插件';
      }
      break;
    default:
      break;
  }
  if (
    busy &&
    [
      'run',
      'rerun',
      'matchLocal',
      'matchRemote',
      'identify',
      'importCurrent',
      'fetchIndex',
      'download',
      'refreshAssets',
      'toggleOnline',
      'importImage',
      'importSymbols',
    ].includes(command)
  ) {
    return '任务执行中，请等待或取消';
  }
  return null;
}


export function availableCommands(state: AppState, query: string): { label: string; key: string; command: Command }[] {
  return commandMatches(query, state.page, state.focus, state.page === 'assets' ? state.section : null).map(
    (entry) => ({ label: entry.label, key: entry.key, command: entry.command }),
  );
}


/** Resolve a key for the active page, honouring section-specific actions. */
export function resolveCommand(state: AppState, key: string): Command | null {
  const command = commandForKey(state.page, key);
  if (!command) {
    return null;
  }
  if (state.page === 'assets' && !commandApplies(command, state.section)) {
    const replacement = commandForKey('analysis', key);
    if (replacement && commandApplies(replacement, state.section)) {
      return replacement;
    }
  }
  return command;
}

export function settingsLabels(state: AppState): string[] {
  const settings = state.settings;
  return [
    `镜像目录: ${settings.image_dir}`,
    `符号目录: ${settings.symbols}`,
    `导出目录: ${settings.export_dir}`,
    `每页行数: ${settings.page_size === 0 ? '自动填满' : String(settings.page_size)}（Enter 输入）`,
    `远程模式: ${settings.remote_symbols ? '在线' : '离线'}（Enter 切换）`,
  ];
}

/** Whether the current image is the Kali build the preparation flow supports. */
export function supportsKaliSymbols(state: AppState): boolean {
  if (state.windows) {
    return false;
  }
  const banners = state.results.get('banners');
  return Boolean(
    banners?.rows.some((row) =>
      row.some(
        (banner) => banner.includes('Linux version 6.8.11-arm64') && banner.includes('6.8.11-1kali2'),
      ),
    ),
  );
}

/** Clean kernel banners for display, falling back to every row. */
export function bannerCandidates(current: Results): string[][] {
  const clean = current.rows.filter((row) => {
    const banner = (row[1] ?? '').replace(/[\n\0]+$/u, '');
    return (
      banner.length <= 512 &&
      banner.startsWith('Linux version ') &&
      banner.includes('#') &&
      (banner.includes('gcc') || banner.includes('clang')) &&
      !/[\u0000-\u001f\u007f]/u.test(banner)
    );
  });
  return clean.length > 0 ? clean : current.rows;
}

export interface AnalyzeResult {
  choose?: string[];
  result?: Results;
}

export function applyAnalyzeReply(reply: AnalyzeReply): AnalyzeResult {
  return reply as AnalyzeResult;
}

export type { Arch, Os, RemoteMatch, Results, Settings };
