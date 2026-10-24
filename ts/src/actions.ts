/**
 * One action table drives keyboard dispatch, availability, the command palette,
 * the resource toolbar, the analysis footer and the help text.
 *
 * Every user-invokable action has exactly one `Command`, one label and one
 * binding. Surfaces select from this table by placement, so a binding cannot
 * exist in the palette but be missing from the toolbar, or be implemented twice
 * with drifting status text.
 *
 * Ported one-for-one from the previous `src/tui/actions.rs`; the key set and
 * labels are user-visible contract, not implementation detail.
 */

/** Identity of an action, independent of the key that triggers it. */
export type Command =
  // Global
  | 'quit'
  | 'help'
  | 'palette'
  | 'settings'
  | 'cache'
  | 'taskLog'
  | 'history'
  | 'diagnostics'
  | 'pageAssets'
  | 'pageAnalysis'
  | 'systemSelect'
  | 'toggleOnline'
  | 'cancel'
  // Image and symbol intake, valid on both pages
  | 'importImage'
  | 'importSymbols'
  | 'matchLocal'
  | 'matchRemote'
  | 'identify'
  // Resource library
  | 'importCurrent'
  | 'select'
  | 'selectAndEnter'
  | 'assetDetail'
  | 'deleteAsset'
  | 'refreshAssets'
  | 'searchAssets'
  | 'enterAnalysis'
  | 'toggleSource'
  | 'generateSymbols'
  | 'fetchIndex'
  | 'download'
  | 'toggleMatchFilter'
  // Analysis
  | 'run'
  | 'rerun'
  | 'plugins'
  | 'parameters'
  | 'dump'
  | 'export'
  | 'sort'
  | 'rows'
  | 'prevPage'
  | 'nextPage'
  | 'detail'
  | 'searchContent'
  | 'enter'
  // Cache page
  | 'cacheToggle'
  | 'cacheClear'
  | 'cacheRemove'
  | 'cacheOpen'
  | 'cacheRefresh';

/** Which page an action belongs to. */
export type Scope = 'anywhere' | 'assets' | 'analysis' | 'cache';
export type Page = 'assets' | 'analysis' | 'cache';
export type CachePane = 'scopes' | 'entries';
export type Section = 'images' | 'symbols' | 'remote';
export type Focus = 'context' | 'navigation' | 'content' | 'detail';

/** A key binding, encoded once so every surface compares the same value. */
export type KeyCode = string;

export const KEYS = {
  quit: 'q',
  help: 'H',
  palette: '?',
  settings: ',',
  cache: 'c',
  taskLog: 'l',
  history: 'h',
  diagnostics: 'v',
  pageAssets: '1',
  pageAnalysis: '2',
  systemSelect: 'S',
  toggleOnline: 'o',
  cancel: 'Esc',
  importImage: 'i',
  importSymbols: 'y',
  matchLocal: 'm',
  matchRemote: 'M',
  identify: 'b',
  importCurrent: 'a',
  select: ' ',
  selectAndEnter: 'Enter',
  assetDetail: 'd',
  deleteAsset: 'Delete',
  refreshAssets: 'r',
  searchAssets: '/',
  enterAnalysis: 'x',
  toggleSource: 't',
  generateSymbols: 'K',
  fetchIndex: 'g',
  download: 'w',
  toggleMatchFilter: 'z',
  run: 'R',
  rerun: 'r',
  plugins: 'p',
  parameters: 'P',
  dump: 'D',
  export: 'e',
  sort: 's',
  rows: 'n',
  prevPage: '[',
  nextPage: ']',
  detail: 'd',
  searchContent: '/',
  enter: 'Enter',
  cacheToggle: ' ',
  cacheClear: 'x',
  cacheRemove: 'Delete',
  cacheOpen: 'Enter',
  cacheRefresh: 'r',
} as const satisfies Record<Command, KeyCode>;

const PALETTE = 1;
const TOOLBAR = 2;
const FOOTER = 4;

const CONTEXT_FOCUS = 1;
const NAV_FOCUS = 2;
const CONTENT_FOCUS = 4;
const DETAIL_FOCUS = 8;
const ANY_FOCUS = 0xf;

const IMAGES = 1;
const SYMBOLS = 2;
const REMOTE = 4;
const ALL_SECTIONS = 7;

export interface Action {
  command: Command;
  label: string;
  key: KeyCode;
  scope: Scope;
  placement: number;
  sections: number;
  paletteFocus: number;
  footerFocus: number;
}

function action(
  command: Command,
  label: string,
  key: KeyCode,
  scope: Scope,
  placement: number,
): Action {
  return {
    command,
    label,
    key,
    scope,
    placement,
    sections: ALL_SECTIONS,
    paletteFocus: ANY_FOCUS,
    footerFocus: 0,
  };
}

/** English aliases so the palette matches the words users already know. */
export function keywords(command: Command): string {
  switch (command) {
    case 'quit':
      return 'quit exit';
    case 'help':
      return 'help f1';
    case 'palette':
      return 'command palette';
    case 'settings':
      return 'settings directory page size theme color';
    case 'cache':
      return 'cache clear page';
    case 'taskLog':
      return 'log task';
    case 'history':
      return 'history export';
    case 'diagnostics':
      return 'diagnostics partial';
    case 'pageAssets':
      return 'assets library resource';
    case 'pageAnalysis':
      return 'analysis console';
    case 'systemSelect':
      return 'os system linux windows auto';
    case 'toggleOnline':
      return 'offline online network';
    case 'cancel':
      return 'cancel abort';
    case 'importImage':
      return 'image raw lime import';
    case 'importSymbols':
      return 'symbols isf json zip import';
    case 'matchLocal':
      return 'match local symbol';
    case 'matchRemote':
      return 'match remote pdb download';
    case 'identify':
      return 'identify banner kernel';
    case 'importCurrent':
      return 'import asset';
    case 'select':
      return 'select use';
    case 'selectAndEnter':
      return 'select enter analysis';
    case 'assetDetail':
      return 'detail info';
    case 'deleteAsset':
      return 'remove delete registry';
    case 'refreshAssets':
      return 'refresh reload';
    case 'searchAssets':
      return 'search filter';
    case 'enterAnalysis':
      return 'enter analysis console';
    case 'toggleSource':
      return 'local remote source';
    case 'generateSymbols':
      return 'generate symbols dwarf2json kali';
    case 'fetchIndex':
      return 'index catalog fetch';
    case 'download':
      return 'download save';
    case 'toggleMatchFilter':
      return 'filter matched';
    case 'run':
      return 'run plugin';
    case 'rerun':
      return 'rerun force';
    case 'plugins':
      return 'plugins search';
    case 'parameters':
      return 'parameters options pid hive key arch pagefile';
    case 'dump':
      return 'dump procdump memdump elfdump pedump';
    case 'export':
      return 'export csv json';
    case 'sort':
      return 'sort order';
    case 'rows':
      return 'rows page size';
    case 'prevPage':
      return 'previous page';
    case 'nextPage':
      return 'next page';
    case 'detail':
      return 'detail inspector';
    case 'searchContent':
      return 'search content filter';
    case 'enter':
      return 'enter open';
    case 'cacheToggle':
      return 'cache scope select';
    case 'cacheClear':
      return 'cache clear purge';
    case 'cacheRemove':
      return 'cache delete remove entry';
    case 'cacheOpen':
      return 'cache export record open reopen';
    case 'cacheRefresh':
      return 'cache refresh inventory';
  }
}

export const ACTIONS: Action[] = [
  // Global actions, valid on both pages.
  action('quit', '退出 q', 'q', 'anywhere', PALETTE),
  action('help', '帮助 H', 'H', 'anywhere', PALETTE),
  action('palette', '命令面板 ?', '?', 'anywhere', PALETTE | TOOLBAR),
  action('settings', '设置与主题 ,', ',', 'anywhere', PALETTE | TOOLBAR),
  action('cache', '缓存管理页 c / 3', 'c', 'anywhere', PALETTE),
  action('taskLog', '任务日志 l', 'l', 'anywhere', PALETTE),
  action('history', '历史导出记录 h', 'h', 'anywhere', PALETTE),
  action('diagnostics', '查看诊断 v', 'v', 'anywhere', PALETTE),
  action('pageAssets', '打开资源库 1', '1', 'anywhere', PALETTE),
  action('pageAnalysis', '打开分析页 2', '2', 'anywhere', PALETTE),
  {
    ...action('systemSelect', '选择分析系统 S', 'S', 'anywhere', PALETTE | FOOTER),
    footerFocus: ANY_FOCUS,
  },
  action('toggleOnline', '在线／离线 o', 'o', 'anywhere', PALETTE | TOOLBAR),
  action('cancel', '取消 Esc', 'Esc', 'anywhere', TOOLBAR),
  // Intake actions, valid on both pages.
  { ...action('importImage', '选择镜像 i', 'i', 'anywhere', PALETTE | FOOTER), footerFocus: CONTEXT_FOCUS },
  {
    ...action('importSymbols', '选择本地符号 y', 'y', 'anywhere', PALETTE | FOOTER),
    footerFocus: CONTEXT_FOCUS,
  },
  {
    ...action('matchLocal', '当前镜像 → 本地匹配 m', 'm', 'anywhere', PALETTE | TOOLBAR | FOOTER),
    footerFocus: CONTEXT_FOCUS,
  },
  {
    ...action('matchRemote', '精确匹配符号 M', 'M', 'anywhere', PALETTE | TOOLBAR),
    footerFocus: CONTEXT_FOCUS,
  },
  {
    ...action('identify', '识别内核候选 b', 'b', 'anywhere', PALETTE | FOOTER),
    footerFocus: CONTEXT_FOCUS,
  },
  // Resource library actions.
  action('importCurrent', '导入当前资产 a', 'a', 'assets', PALETTE | TOOLBAR),
  action('select', '选用 Space', ' ', 'assets', PALETTE | TOOLBAR),
  action('selectAndEnter', '选用并分析 Enter', 'Enter', 'assets', PALETTE),
  action('assetDetail', '详情 d', 'd', 'assets', PALETTE | TOOLBAR),
  { ...action('deleteAsset', '移出清单 Delete', 'Delete', 'assets', PALETTE), sections: IMAGES | SYMBOLS },
  action('refreshAssets', '刷新资产 r', 'r', 'assets', PALETTE),
  action('searchAssets', '搜索列表 /', '/', 'assets', PALETTE),
  action('enterAnalysis', '进入分析 x', 'x', 'assets', PALETTE | TOOLBAR),
  action('toggleSource', '本地／远程 t', 't', 'assets', PALETTE),
  action('generateSymbols', '生成当前镜像符号表 K', 'K', 'assets', PALETTE),
  { ...action('fetchIndex', '获取索引 g', 'g', 'assets', PALETTE | TOOLBAR), sections: REMOTE },
  { ...action('download', '仅下载 w', 'w', 'assets', PALETTE | TOOLBAR), sections: REMOTE },
  {
    ...action('toggleMatchFilter', '全部／匹配 z', 'z', 'assets', PALETTE | TOOLBAR),
    sections: SYMBOLS,
  },
  // Analysis actions.
  {
    ...action('run', '运行插件 R', 'R', 'analysis', PALETTE | FOOTER),
    footerFocus: NAV_FOCUS,
  },
  { ...action('rerun', '重新分析 r', 'r', 'analysis', PALETTE | FOOTER), footerFocus: NAV_FOCUS },
  { ...action('plugins', '搜索插件 p', 'p', 'analysis', PALETTE | FOOTER), footerFocus: NAV_FOCUS },
  action('parameters', '编辑适用参数 P', 'P', 'analysis', PALETTE),
  {
    ...action('dump', 'Dump 导出进程／地址范围／ELF', 'D', 'analysis', PALETTE | FOOTER),
    footerFocus: NAV_FOCUS | CONTENT_FOCUS,
  },
  {
    ...action('export', '导出结果 e', 'e', 'analysis', PALETTE | FOOTER),
    paletteFocus: CONTENT_FOCUS | DETAIL_FOCUS,
    footerFocus: CONTENT_FOCUS,
  },
  {
    ...action('sort', '排序 s', 's', 'analysis', PALETTE | FOOTER),
    paletteFocus: CONTENT_FOCUS | DETAIL_FOCUS,
    footerFocus: CONTENT_FOCUS,
  },
  {
    ...action('rows', '每页行数 n', 'n', 'analysis', PALETTE | FOOTER),
    paletteFocus: CONTENT_FOCUS | DETAIL_FOCUS,
    footerFocus: CONTENT_FOCUS,
  },
  {
    ...action('prevPage', '前一页 [', '[', 'analysis', PALETTE | FOOTER),
    paletteFocus: CONTENT_FOCUS | DETAIL_FOCUS,
    footerFocus: CONTENT_FOCUS,
  },
  {
    ...action('nextPage', '后一页 ]', ']', 'analysis', PALETTE | FOOTER),
    paletteFocus: CONTENT_FOCUS | DETAIL_FOCUS,
    footerFocus: CONTENT_FOCUS,
  },
  {
    ...action('detail', '详情 d', 'd', 'analysis', PALETTE | FOOTER),
    paletteFocus: CONTENT_FOCUS | DETAIL_FOCUS,
    footerFocus: CONTENT_FOCUS | DETAIL_FOCUS,
  },
  {
    ...action('searchContent', '搜索内容 /', '/', 'analysis', PALETTE | FOOTER),
    footerFocus: CONTENT_FOCUS,
  },
  // Enter is key-only: its meaning depends on the focused region.
  action('enter', '打开 Enter', 'Enter', 'analysis', 0),
  // Cache page actions.
  action('cacheToggle', '勾选范围 Space', ' ', 'cache', PALETTE | TOOLBAR),
  action('cacheClear', '清理已勾选 x', 'x', 'cache', PALETTE | TOOLBAR),
  action('cacheRemove', '删除条目 Delete', 'Delete', 'cache', PALETTE | TOOLBAR),
  action('cacheOpen', '打开导出记录 Enter', 'Enter', 'cache', PALETTE | TOOLBAR),
  action('cacheRefresh', '刷新 r', 'r', 'cache', PALETTE | TOOLBAR),
];

/** Cache page toolbar, in presentation order. */
const CACHE_TOOLBAR: Command[] = ['cacheToggle', 'cacheClear', 'cacheRemove', 'cacheOpen', 'cacheRefresh', 'palette'];

export function cacheToolbarActions(busy: boolean): { label: string; key: KeyCode }[] {
  const commands = busy ? (['cancel', ...CACHE_TOOLBAR] as Command[]) : CACHE_TOOLBAR;
  return commands.map((command) => {
    const entry = actionOf(command);
    return { label: entry.label, key: entry.key };
  });
}

/** Toolbar order is presentation, not identity. */
const TOOLBAR_ORDER: Command[] = [
  'enterAnalysis',
  'importCurrent',
  'select',
  'assetDetail',
  'toggleMatchFilter',
  'fetchIndex',
  'download',
  'matchLocal',
  'matchRemote',
  'toggleOnline',
  'settings',
  'palette',
];

/** Footer order is presentation: the most used actions lead. */
const FOOTER_ORDER: Command[] = [
  'run',
  'searchContent',
  'detail',
  'sort',
  'export',
  'rows',
  'prevPage',
  'nextPage',
  'plugins',
  'rerun',
  'dump',
  'importImage',
  'importSymbols',
  'identify',
  'matchLocal',
  'systemSelect',
];

const BY_COMMAND = new Map<Command, Action>(ACTIONS.map((entry) => [entry.command, entry]));

export function actionOf(command: Command): Action {
  const found = BY_COMMAND.get(command);
  if (!found) {
    throw new Error(`missing action table entry for ${command}`);
  }
  return found;
}

function focusBit(focus: Focus): number {
  switch (focus) {
    case 'context':
      return CONTEXT_FOCUS;
    case 'navigation':
      return NAV_FOCUS;
    case 'content':
      return CONTENT_FOCUS;
    case 'detail':
      return DETAIL_FOCUS;
  }
}

function sectionBit(section: Section): number {
  switch (section) {
    case 'images':
      return IMAGES;
    case 'symbols':
      return SYMBOLS;
    case 'remote':
      return REMOTE;
  }
}

/** Whether `command` applies to `section` at all. */
export function commandApplies(command: Command, section: Section): boolean {
  return (actionOf(command).sections & sectionBit(section)) !== 0;
}

/** Actions offered on the resource toolbar. Cancellation leads when busy. */
export function toolbarCommands(section: Section, busy: boolean): Command[] {
  const commands = TOOLBAR_ORDER.filter((command) => {
    const entry = actionOf(command);
    return (entry.placement & TOOLBAR) !== 0 && (entry.sections & sectionBit(section)) !== 0;
  });
  return busy ? ['cancel', ...commands] : commands;
}

export function toolbarActions(
  section: Section,
  busy: boolean,
): { label: string; key: KeyCode }[] {
  return toolbarCommands(section, busy).map((command) => {
    const entry = actionOf(command);
    return { label: entry.label, key: entry.key };
  });
}

/** Every action reachable on the resource page, for the help text. */
export function assetActions(section: Section): { label: string; key: KeyCode }[] {
  return ACTIONS.filter(
    (entry) => (entry.scope === 'anywhere' || entry.scope === 'assets') && (entry.sections & sectionBit(section)) !== 0,
  ).map((entry) => ({ label: entry.label, key: entry.key }));
}

export function footerActions(focus: Focus): { label: string; key: KeyCode }[] {
  const actions: { label: string; key: KeyCode }[] = [];
  for (const command of FOOTER_ORDER) {
    const entry = actionOf(command);
    if ((entry.placement & FOOTER) !== 0 && (entry.footerFocus & focusBit(focus)) !== 0) {
      actions.push({ label: entry.label, key: entry.key });
    }
  }
  return actions;
}

/** Case-insensitive, order-free token match: every space-separated term must appear. */
export function queryMatches(haystack: string, query: string): boolean {
  const text = haystack.toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/u)
    .filter(Boolean)
    .every((term) => text.includes(term));
}

/** Palette entries for a page, focus and — on the resource page — section. */
export function commandMatches(
  query: string,
  page: Page,
  focus: Focus,
  section: Section | null,
): Action[] {
  return ACTIONS.filter((entry) => {
    const inScope =
      entry.scope === 'anywhere' ||
      entry.scope === page;
    return (
      (entry.placement & PALETTE) !== 0 &&
      inScope &&
      (section === null || (entry.sections & sectionBit(section)) !== 0) &&
      (entry.paletteFocus & focusBit(focus)) !== 0 &&
      (queryMatches(entry.label, query) || queryMatches(keywords(entry.command), query))
    );
  });
}

/**
 * Resolve a key for the active page. Keys that mean different things on the two
 * pages (`d`, `r`, `/`, `g`) are disambiguated here instead of in two
 * independent match blocks that could drift apart.
 */
export function commandForKey(page: Page, key: KeyCode): Command | null {
  switch (key) {
    case 'H':
      return 'help';
    case '1':
      return 'pageAssets';
    case '2':
      return 'pageAnalysis';
    case 'S':
      return 'systemSelect';
    case '?':
      return 'palette';
    case ',':
      return 'settings';
    case 'c':
    case '3':
      return 'cache';
    case 'l':
      return 'taskLog';
    case 'h':
      return 'history';
    case 'v':
      return 'diagnostics';
    case 'q':
      return 'quit';
    case 'o':
      return 'toggleOnline';
    case 'Esc':
      return 'cancel';
    case 'i':
      return 'importImage';
    case 'y':
      return 'importSymbols';
    case 'm':
      return 'matchLocal';
    case 'M':
      return 'matchRemote';
    case 'b':
      return 'identify';
    default:
      break;
  }
  if (page === 'assets') {
    switch (key) {
      case 'a':
        return 'importCurrent';
      case ' ':
        return 'select';
      case 'Enter':
        return 'selectAndEnter';
      case 'd':
        return 'assetDetail';
      case 'Delete':
        return 'deleteAsset';
      case 'r':
        return 'refreshAssets';
      case '/':
        return 'searchAssets';
      case 'x':
        return 'enterAnalysis';
      case 't':
        return 'toggleSource';
      case 'K':
        return 'generateSymbols';
      case 'g':
        return 'fetchIndex';
      case 'w':
        return 'download';
      case 'z':
        return 'toggleMatchFilter';
      default:
        return null;
    }
  }
  if (page === 'cache') {
    switch (key) {
      case ' ':
        return 'cacheToggle';
      case 'x':
        return 'cacheClear';
      case 'Delete':
        return 'cacheRemove';
      case 'Enter':
        return 'cacheOpen';
      case 'r':
        return 'cacheRefresh';
      default:
        return null;
    }
  }
  switch (key) {
    case 'R':
      return 'run';
    case 'r':
      return 'rerun';
    case 'p':
      return 'plugins';
    case 'P':
      return 'parameters';
    case 'D':
      return 'dump';
    case 'e':
      return 'export';
    case 's':
      return 'sort';
    case 'n':
      return 'rows';
    case '[':
      return 'prevPage';
    case ']':
      return 'nextPage';
    case 'd':
      return 'detail';
    case '/':
      return 'searchContent';
    case 'K':
    case 'g':
      return 'generateSymbols';
    case 'Enter':
      return 'enter';
    default:
      return null;
  }
}
