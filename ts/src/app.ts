/**
 * The application state machine.
 *
 * Every mutation lives here, in one reducer-style class: preparation, task
 * lifecycle, selection, dialogs, browsing and the command table. The React tree
 * is a pure function of this state, and tests drive the same object without a
 * terminal, so behaviour cannot diverge between the two.
 *
 * The rules that matter and are easy to regress:
 *
 * - one background task at a time; a new request cancels the old one and runs
 *   only the last request;
 * - a cancelled task never continues into download, selection or analysis;
 * - partial results keep their diagnostics and never enter the success cache
 *   (the engine enforces the cache rule; the UI keeps the diagnostics visible);
 * - switching the image or symbol invalidates every result bound to the old one.
 */
import { inspector, space } from './layout.js';
import { computeLayout, inside, type Layout } from './layoutTree.js';
import {
  assetActive,
  assetListFor,
  bannerCandidates,
  commandDisabled,
  defaultOptions,
  initialState,
  detailText,
  menuItems,
  navigationPlugins,
  parameterSummary,
  pluginDescriptor,
  pluginLabel,
  pluginMatches,
  remoteList,
  requestKey,
  result,
  samePath,
  sectionSlot,
  selectedAsset,
  selectedRemote,
  settingsLabels,
  supportsKaliSymbols,
  treeColumns,
  viewIndex,
  visibleRow,
  type AppState,
  type Dialog,
  type ExecutionSnapshot,
  type HitMap,
  type InputKind,
  type PendingWork,
} from './state.js';
import {
  actionOf,
  assetActions,
  commandApplies,
  commandForKey,
  commandMatches,
  footerActions,
  toolbarActions,
  type Command,
  type Focus,
  type Page,
  type Section,
} from './actions.js';
import type { Engine, TaskEvent } from './engine.js';
import type {
  AnalyzeReply,
  Asset,
  AssetKind,
  CacheEntry,
  ClearReport,
  Hello,
  Os,
  RemoteMatch,
  RemoteReply,
  Results,
  ScopeId,
  Settings,
} from './types.js';
import {
  dialogHeight,
  dialogWidth,
  dumpModes,
  editInput,
  filesTitle,
  inputText,
  inputTitle,
  parameterFields,
  parseOptions,
  pasteInto,
  pickerFilter,
  type KeyLike,
} from './dialogs.js';
import { failureStatus, formatAddress, mib, parseAddress, progressPercent, shortPlugin } from './format.js';
import { charWidth, truncate, wrapLines } from './text.js';
import { compareValues } from './resultView.js';
import { assetDetailText, remoteDetailText, helpText, logText, diagnosticsText, rowDetailText } from './detail.js';

/** Result of a state transition: what the shell must do next. */
export interface Transition {
  quit?: boolean;
  /** Awaitable work; the shell runs it after committing the new state. */
  work?: () => Promise<void>;
}

export interface LaunchOptions {
  image: string | null;
  symbols: string | null;
  offline: boolean;
  os: Os;
  arch: 'auto' | 'x86' | 'x64' | 'arm64';
  pagefiles: { index: number; path: string }[];
  swapfile: string | null;
  /** Decimal address string; see `Options.hive`. */
  hive: string | null;
  key: string;
}

type Listener = () => void;

export class App {
  state: AppState;
  private readonly engine: Engine;
  private readonly hello: Hello;
  private readonly launch: LaunchOptions;
  private readonly listeners = new Set<Listener>();
  /** Progress messages arrive from a worker thread; they queue until a tick. */
  private queuedProgress: string[] = [];
  private pendingTick: NodeJS.Timeout | null = null;

  constructor(engine: Engine, hello: Hello, launch: LaunchOptions) {
    this.engine = engine;
    this.hello = hello;
    this.launch = launch;
    this.state = {
      ...initialState(hello, { image: launch.image, symbols: launch.symbols }),
      settings: hello.settings,
    };
  }

  private quitHandlers = new Set<() => void>();

  /** Register the action that tears down the terminal when `q` confirms exit. */
  onQuit(handler: () => void): void {
    this.quitHandlers.add(handler);
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(): void {
    for (const listener of this.listeners) {
      listener();
    }
  }

  private update(patch: Partial<AppState>): void {
    this.state = { ...this.state, ...patch };
    this.emit();
  }

  /* ---------------------------------------------------------------- */
  /* Startup                                                           */
  /* ---------------------------------------------------------------- */

  async initialize(): Promise<void> {
    await this.refreshAssets();
    if (this.launch.os !== 'auto' || this.launch.hive !== null || this.launch.key !== '') {
      this.state.analysisOptions = {
        ...this.state.analysisOptions,
        os: this.launch.os,
        arch: this.launch.arch,
        pagefiles: this.launch.pagefiles,
        swapfile: this.launch.swapfile,
        hive: this.launch.hive,
        key: this.launch.key,
      };
      this.state.windows = this.launch.os === 'windows';
    }
    this.state.plugin = this.state.windows ? 'windows.pslist' : 'pslist';
    this.state.menu = Math.max(
      navigationPlugins(this.state).findIndex((plugin) => plugin.name === this.state.plugin),
      0,
    );
    if (this.launch.image) {
      await this.registerLaunchAssets();
      await this.prepareSelectedImage();
    }
    this.emit();
  }

  private async registerLaunchAssets(): Promise<void> {
    if (this.launch.image) {
      await this.engine.select('image', this.launch.image).catch((error: Error) => {
        this.state.lastError = `资产登记失败: ${error.message}`;
      });
    }
    if (this.launch.symbols) {
      await this.engine.select('symbols', this.launch.symbols).catch((error: Error) => {
        this.state.lastError = `资产登记失败: ${error.message}`;
      });
    }
  }

  /* ---------------------------------------------------------------- */
  /* Assets                                                            */
  /* ---------------------------------------------------------------- */

  async refreshAssets(): Promise<void> {
    try {
      const assets = await this.engine.assets();
      this.state.assets = assets;
      this.rebuildDownloads();
      if (
        this.state.localMatchStamp !== null &&
        this.state.localMatchStamp !== this.localStamp()
      ) {
        this.state.localMatchStamp = null;
        this.state.localMatches = new Map();
        this.state.localOnlyMatches = false;
      }
      for (const section of ['images', 'symbols', 'remote'] as Section[]) {
        const count = section === 'remote' ? remoteList(this.state).length : assetListFor(this.state, section).length;
        this.state.assetRows[sectionSlot(section)] = Math.max(
          0,
          Math.min(this.state.assetRows[sectionSlot(section)], count - 1),
        );
      }
      this.emit();
    } catch (error) {
      this.fail(`资产清单读取失败: ${(error as Error).message}`);
    }
  }

  /**
   * Map repository URL → saved local path from the source sidecars, and hide a
   * regenerable cache copy that duplicates a managed library entry.
   */
  private rebuildDownloads(): void {
    const downloads = new Map<string, string>();
    const cached: { path: string; url: string }[] = [];
    const ordered = [
      ...this.state.assets.filter((asset) => asset.origin === '下载／生成'),
      ...this.state.assets.filter((asset) => asset.origin !== '下载／生成'),
    ];
    for (const asset of ordered) {
      if (asset.kind !== 'symbols' || !asset.source_url) {
        continue;
      }
      downloads.set(asset.source_url, asset.path);
      if (asset.origin === '下载／生成') {
        cached.push({ path: asset.path, url: asset.source_url });
      }
    }
    this.state.downloads = downloads;
    this.state.hiddenCacheCopies = new Set(
      cached
        .filter(({ path, url }) => {
          const local = downloads.get(url);
          return local !== undefined && local !== path;
        })
        .map(({ path }) => path),
    );
  }

  /* ---------------------------------------------------------------- */
  /* Preparation                                                       */
  /* ---------------------------------------------------------------- */

  async prepareSelectedImage(): Promise<void> {
    await this.refreshAssets();
    if (this.state.image === null) {
      this.update({ preparation: 'chooseImage' });
      return;
    }
    this.update({ preparation: 'matching' });
    const stamp = this.localStamp();
    if (this.state.localMatchStamp === stamp) {
      this.applyLocalPreparation();
      this.state.localOnlyMatches = true;
      this.update({ status: '复用内核识别与本地符号匹配；x 进入分析' });
      return;
    }
    const paths = this.state.assets
      .filter(
        (asset) =>
          asset.kind === 'symbols' &&
          asset.available &&
          !asset.directory &&
          !this.state.hiddenCacheCopies.has(asset.path),
      )
      .map((asset) => asset.path);
    await this.runTask(
      'matchLocal',
      (progress) =>
        this.engine.matchLocal(this.state.image as string, paths, progress),
      (reply) => {
        this.applyIdentification(reply.banner);
        this.state.results.set('banners', reply.banner);
        // One file can contain several ISFs, so labels are grouped per path
        // rather than collapsed into a single entry.
        const matches = new Map<string, string[]>();
        for (const entry of reply.matched) {
          const existing = matches.get(entry.path);
          if (existing) {
            existing.push(...entry.labels);
          } else {
            matches.set(entry.path, [...entry.labels]);
          }
        }
        this.state.localMatches = matches;
        this.state.localMatchErrors = reply.diagnostics;
        this.state.localMatchStamp = stamp;
        this.state.localOnlyMatches = true;
        this.state.assetRows[1] = 0;
        const identification = this.identificationStatus(reply.banner);
        this.state.status = `${identification} · 本地符号匹配：${this.state.localMatches.size} 个文件 · ${reply.diagnostics.length} 条诊断；Space 选用，Enter 进入控制台，d 详情，t 远程，z 全部`;
        if (reply.diagnostics.length > 0) {
          this.state.lastError = reply.diagnostics.join('\n');
        }
        this.applyLocalPreparation();
      },
    );
  }

  applyLocalPreparation(): void {
    this.state.preparationCandidates = [...this.state.localMatches.entries()]
      .flatMap(([path, labels]) => labels.map((label) => ({ path, label })))
      .sort((a, b) => (a.path + a.label < b.path + b.label ? -1 : 1));
    const identified = (this.state.results.get('banners')?.rows.length ?? 0) > 0;
    if (!identified && this.state.analysisOptions.os === 'auto') {
      this.state.preparation = 'chooseSystem';
      this.state.status = '系统识别不明确；S 选择 Linux／Windows 后重试';
      return;
    }
    this.state.preparedStamp = this.localStamp();
    const candidates = this.state.preparationCandidates;
    if (candidates.length === 0) {
      this.state.preparation = 'missingSymbols';
      this.state.status = '没有本地精确匹配；M 在线获取匹配符号，y 导入本地符号';
    } else if (candidates.length === 1) {
      const only = candidates[0] as { path: string; label: string };
      this.state.symbols = only.path;
      this.state.choice = only.label;
      this.state.preparation = 'ready';
      this.state.status = '唯一精确匹配已选用；可开始分析，运行时验证页表';
    } else {
      this.state.preparation = 'chooseSymbols';
      this.state.status = '多个精确匹配；请选择符号（ZIP 内候选分别列出）';
      this.state.dialog = {
        kind: 'symbols',
        labels: candidates.map((candidate) => candidate.label),
        selected: 0,
      };
    }
  }

  localStamp(): string {
    const image = this.state.image;
    const stamp = image === null ? '' : image;
    const symbols = this.state.assets
      .filter(
        (asset) =>
          asset.kind === 'symbols' &&
          !asset.directory &&
          !this.state.hiddenCacheCopies.has(asset.path),
      )
      .map((asset) => `${asset.path}:${asset.stamp ?? ''}`)
      .sort();
    return `${stamp}:${symbols.join(',')}`;
  }

  identificationStatus(banner: Results): string {
    if (this.state.analysisOptions.os !== 'auto') {
      return '保留手动系统选择';
    }
    const windows =
      banner.system === 'windows' || banner.rows.some((row) => (row[1] ?? '').startsWith('Windows PDB '));
    const linux =
      banner.rows.some((row) => (row[1] ?? '').startsWith('Linux version ')) ||
      (banner.system === 'linux' && banner.rows.length > 0);
    if (windows) {
      return '自动识别 Windows · 已切换插件列表';
    }
    if (linux) {
      return '自动识别 Linux · 已切换插件列表';
    }
    return '未识别系统 · 可手动选择 Linux / Windows';
  }

  applyIdentification(banner: Results): void {
    const detectedWindows =
      banner.system === 'windows' || banner.rows.some((row) => (row[1] ?? '').startsWith('Windows PDB '));
    const detectedLinux =
      banner.rows.some((row) => (row[1] ?? '').startsWith('Linux version ')) ||
      (banner.system === 'linux' && banner.rows.length > 0);
    if (this.state.analysisOptions.os === 'auto' && !detectedWindows && !detectedLinux) {
      return;
    }
    const windows =
      this.state.analysisOptions.os === 'windows'
        ? true
        : this.state.analysisOptions.os === 'linux'
          ? false
          : detectedWindows;
    if (this.state.windows === windows) {
      return;
    }
    this.state.windows = windows;
    this.state.plugin = windows ? 'windows.pslist' : 'pslist';
    this.state.menu = Math.max(
      navigationPlugins(this.state).findIndex((plugin) => plugin.name === this.state.plugin),
      0,
    );
    this.state.analysisOptions = {
      ...this.state.analysisOptions,
      pid: null,
      hive: null,
      key: '',
      ...(windows ? {} : { arch: 'auto' as const, pagefiles: [], swapfile: null }),
    };
    this.resetView();
    this.state.historyRevision += 1;
    this.state.history = null;
  }

  /* ---------------------------------------------------------------- */
  /* Selection                                                         */
  /* ---------------------------------------------------------------- */

  async selectOs(os: Os): Promise<void> {
    if (this.state.busy) {
      await this.cancel();
      this.state.pendingOs = os;
      this.state.status = '正在取消任务并切换分析系统…';
      this.emit();
      return;
    }
    this.state.parameterDrafts.clear();
    this.state.preparedStamp = null;
    this.state.analysisOptions = { ...this.state.analysisOptions, os };
    const banner = this.state.results.get('banners');
    this.state.windows = os === 'windows' ? true : os === 'linux' ? false : this.state.windows;
    if (banner) {
      this.applyIdentification(banner);
    }
    this.state.plugin = this.state.windows ? 'windows.pslist' : 'pslist';
    this.state.menu = Math.max(
      navigationPlugins(this.state).findIndex((plugin) => plugin.name === this.state.plugin),
      0,
    );
    this.state.analysisOptions = {
      ...this.state.analysisOptions,
      pid: null,
      hive: null,
      key: '',
      ...(this.state.windows ? {} : { arch: 'auto' as const, pagefiles: [], swapfile: null }),
    };
    this.state.results.clear();
    if (banner) {
      this.state.results.set('banners', banner);
    }
    this.state.localMatches.clear();
    this.state.localMatchStamp = null;
    this.state.localMatchErrors = [];
    this.state.localOnlyMatches = false;
    this.resetView();
    this.state.views.clear();
    this.state.historyRevision += 1;
    this.state.history = null;
    this.state.choice = null;
    this.state.dumpOptions = null;
    this.state.lastError = null;
    this.state.objectVersion += 1;
    this.state.page = 'assets';
    this.state.focus = 'navigation';
    this.state.status = `已选择 ${os === 'auto' ? '自动识别系统' : os === 'linux' ? 'Linux' : 'Windows'} · i 镜像 / y 符号 / p 插件`;
    if (this.state.image) {
      await this.prepareSelectedImage();
    }
    this.emit();
  }

  /** Enter on a highlighted but unused asset: select it, then open analysis. */
  async selectAndEnter(): Promise<void> {
    const pending =
      this.state.section !== 'remote' &&
      selectedAsset(this.state) !== null &&
      !assetActive(this.state, selectedAsset(this.state) as Asset);
    if (!pending) {
      this.enterWorkbench();
      return;
    }
    if (!(await this.useSelectedAsset())) {
      return;
    }
    if (this.state.section === 'images') {
      this.state.symbolSource = 'symbols';
      await this.prepareSelectedImage();
    }
    if (this.state.preparation === 'ready' && !this.state.busy && this.state.dialog === null) {
      this.enterWorkbench();
    } else {
      this.state.enterWhenReady = true;
      this.state.status = '已选用；匹配完成后自动进入分析（Esc 取消）';
    }
    this.emit();
  }

  async useSelectedAsset(): Promise<boolean> {
    const asset = selectedAsset(this.state);
    if (!asset) {
      this.update({ status: '没有选中的资产；按 a 导入路径' });
      return false;
    }
    if (this.state.busy) {
      await this.cancel();
      this.state.pendingPath = {
        input: asset.kind === 'image' ? 'image' : 'symbols',
        path: asset.path,
      };
      this.update({ status: '正在取消；随后选用新对象' });
      return false;
    }
    if (!asset.available) {
      this.update({ status: '文件缺失；按 a 导入新路径' });
      return false;
    }
    try {
      await this.engine.select(asset.kind, asset.path);
    } catch (error) {
      this.update({ status: `资产登记失败: ${(error as Error).message}` });
      return false;
    }
    const changed =
      asset.kind === 'image'
        ? this.state.image === null || !samePath(this.state.image, asset.path)
        : !samePath(this.state.symbols, asset.path);
    if (changed) {
      if (asset.kind === 'symbols') {
        this.invalidateSymbols();
      } else {
        this.invalidateSource();
        this.state.symbols = '';
        this.state.choice = null;
      }
    }
    if (asset.kind === 'image') {
      this.state.image = asset.path;
    } else {
      const labels = this.state.localMatches.get(asset.path);
      this.state.choice = labels?.length === 1 ? (labels[0] as string) : null;
      this.state.symbols = asset.path;
    }
    if (asset.kind === 'symbols') {
      if (this.state.choice !== null) {
        this.state.preparation = 'ready';
      } else {
        const labels = this.state.localMatches.get(this.state.symbols);
        if (labels && labels.length > 1) {
          this.state.dialog = { kind: 'symbols', labels, selected: 0 };
          this.state.preparation = 'chooseSymbols';
        } else if (this.state.image) {
          this.state.page = 'assets';
          await this.prepareSelectedImage();
        }
      }
    }
    this.state.status =
      this.state.preparation === 'ready'
        ? '已选用；可进入工作台，运行时验证页表'
        : '已选用；完成精确匹配后可进入工作台';
    this.emit();
    return true;
  }

  enterWorkbench(): boolean {
    if (this.state.image === null) {
      this.update({ status: '请先用 Space 选用镜像，再按 Enter 进入分析控制台' });
      return false;
    }
    this.state.dialog = null;
    this.state.backDialog = null;
    this.state.page = 'analysis';
    this.selectPlugin(this.state.windows ? 'windows.pslist' : 'pslist');
    this.state.focus = 'navigation';
    this.update({ status: '已进入分析控制台；点击插件立即分析，运行时验证页表' });
    return true;
  }

  /* ---------------------------------------------------------------- */
  /* Invalidation                                                      */
  /* ---------------------------------------------------------------- */

  invalidateSource(): void {
    this.state.objectVersion += 1;
    this.state.preparedStamp = null;
    this.state.symbolRetry = null;
    this.state.preparation = 'chooseImage';
    this.state.preparationCandidates = [];
    this.state.resultRequests.clear();
    this.state.parameterDrafts.clear();
    this.state.localMatches.clear();
    this.state.localMatchStamp = null;
    this.state.localMatchErrors = [];
    this.state.localOnlyMatches = false;
    this.state.dumpOptions = null;
    this.state.analysisOptions = {
      os: this.state.analysisOptions.os,
      arch: this.state.analysisOptions.arch,
      pid: null,
      hive: null,
      key: '',
      pagefiles: [],
      swapfile: null,
    };
    this.state.results.clear();
    this.state.views.clear();
    this.state.historyRevision += 1;
    this.state.history = null;
    this.state.choice = null;
    this.resetView();
    this.state.remote = [];
    this.state.assetRows[2] = 0;
    this.state.assetQueries[2] = '';
  }

  invalidateSymbols(): void {
    const banner = this.state.results.get('banners');
    const matched = this.state.localMatches;
    const stamp = this.state.localMatchStamp;
    const errors = this.state.localMatchErrors;
    const only = this.state.localOnlyMatches;
    this.invalidateSource();
    if (banner) {
      this.state.results.set('banners', banner);
    }
    this.state.localMatches = matched;
    this.state.localMatchStamp = stamp;
    this.state.localMatchErrors = errors;
    this.state.localOnlyMatches = only;
  }

  private resetView(): void {
    this.state.query = '';
    this.state.sort = null;
    this.state.row = 0;
    this.state.horizontal = 0;
    this.state.collapsed = new Set();
  }

  /* ---------------------------------------------------------------- */
  /* Plugin selection                                                  */
  /* ---------------------------------------------------------------- */

  selectPlugin(plugin: string): void {
    if (!this.inspectorAvailable()) this.state.inspector = false;
    this.saveView();
    this.state.page = 'analysis';
    this.state.parameterDrafts.set(this.state.plugin, { ...this.state.analysisOptions });
    const shared = this.state.analysisOptions;
    const draft = this.state.parameterDrafts.get(plugin);
    this.state.analysisOptions = draft
      ? { ...draft }
      : {
          ...defaultOptions(),
          os: shared.os,
          arch: shared.arch,
          pagefiles: shared.pagefiles,
          swapfile: shared.swapfile,
        };
    this.state.plugin = plugin;
    const descriptor = pluginDescriptor(this.state, plugin);
    if (plugin !== 'windows.printkey') {
      this.state.analysisOptions.hive = null;
      this.state.analysisOptions.key = '';
    }
    if (!descriptor?.columns.includes('PID')) {
      this.state.analysisOptions.pid = null;
    }
    this.state.lastError = null;
    this.state.menu = descriptor?.dump
      ? menuItems(this.state).length - 1
      : Math.max(navigationPlugins(this.state).findIndex((entry) => entry.name === plugin), 0);
    this.state.historyRevision += 1;
    this.state.history = null;
    this.resetView();
    this.restoreView();
    this.state.detailScroll = 0;
    const cached = this.state.results.get(plugin);
    this.state.focus = 'content';
    this.state.status = cached
      ? `${pluginLabel(descriptor, plugin)} · ${cached.rows.length} 条 · ${cached.complete ? '完整' : '部分'} · ${cached.diagnostics.length} 条诊断（v）`
      : '已选择插件；检查参数后按 Ctrl+R 运行';
    if (descriptor?.dump) {
      this.openDump(plugin, false);
    }
    this.emit();
  }

  async activatePlugin(plugin: string): Promise<void> {
    this.selectPlugin(plugin);
    this.state.focus = 'content';
    if (pluginDescriptor(this.state, plugin)?.dump) {
      return;
    }
    if (this.state.image !== null && !this.state.busy) {
      await this.refreshAssets();
      if (this.state.preparedStamp !== null && this.state.preparedStamp !== this.localStamp()) {
        await this.requestAnalysis(false);
        return;
      }
    }
    const cached =
      this.state.results.has(requestKey(this.state)) ||
      (this.state.results.has(plugin) &&
        (this.state.resultRequests.get(plugin) ?? '') === parameterSummary(this.state));
    const running =
      this.state.activeRequest?.key === requestKey(this.state) && this.state.busy;
    if (!cached && !running) {
      await this.requestAnalysis(false);
    }
  }

  saveView(): void {
    this.state.views.set(requestKey(this.state), {
      query: this.state.query,
      sort: this.state.sort,
      descending: this.state.descending,
      row: this.state.row,
      collapsed: [...this.state.collapsed],
      horizontal: this.state.horizontal,
    });
  }

  restoreView(): void {
    const key = requestKey(this.state);
    const view = this.state.views.get(key);
    this.state.views.delete(key);
    if (!view) {
      return;
    }
    this.state.query = view.query;
    this.state.sort = view.sort;
    this.state.descending = view.descending;
    this.state.row = view.row;
    this.state.collapsed = new Set(view.collapsed);
    this.state.horizontal = view.horizontal;
  }

  /* ---------------------------------------------------------------- */
  /* Task lifecycle                                                    */
  /* ---------------------------------------------------------------- */

  /**
   * Run one engine task with uniform progress, cancellation and error
   * handling. `apply` runs only for an uncancelled success, which is what makes
   * "a cancelled task never continues" true for every caller.
   */
  private async runTask<T>(
    label: string,
    start: (progress: (event: TaskEvent) => void) => Promise<T>,
    apply: (value: T) => void | Promise<void>,
  ): Promise<void> {
    if (this.state.cancelled) {
      // Cancelled while the request was still preparing: nothing runs.
      this.state.cancelled = false;
      this.state.status = '已取消；可重试';
      this.emit();
      return;
    }
    this.state.busy = true;
    // A fresh task always starts uncancelled. Leaving a stale flag set here made
    // the *next* request silently skip its work, which read as "cancel is broken".
    this.state.cancelled = false;
    this.state.startedAt = Date.now();
    this.state.progress = null;
    this.state.status = `${label}启动中`;
    this.state.lastError = null;
    this.emit();
    let cancelled = false;
    try {
      const value = await start((event) => {
        if (event.message !== undefined) {
          this.queuedProgress.push(event.message);
          this.scheduleTick();
        }
      });
      if (this.state.cancelled) {
        cancelled = true;
      } else {
        await apply(value);
      }
    } catch (error) {
      if (this.state.cancelled) {
        cancelled = true;
      } else {
        const message = (error as Error).message;
        this.state.lastError = message;
        if (this.state.preparation === 'matching') {
          this.state.preparation = 'missingSymbols';
        }
        this.state.status = failureStatus(message);
        this.state.logs.push(this.state.status);
      }
    } finally {
      this.state.busy = false;
      this.state.startedAt = null;
      this.state.progress = null;
      this.state.activeRequest = null;
      if (cancelled) {
        this.state.status = '已取消；可重试';
        if (this.state.preparation === 'matching') {
          this.state.preparation = 'cancelled';
        }
      }
      // The flag has served its purpose once the task has settled; a later
      // request must not inherit it.
      this.state.cancelled = false;
      this.flushProgress();
      await this.afterTask();
      this.emit();
    }
  }

  private async afterTask(): Promise<void> {
    if (this.state.busy) {
      return;
    }
    if (this.state.pendingOs) {
      const os = this.state.pendingOs;
      this.state.pendingOs = null;
      await this.selectOs(os);
    }
    if (this.state.pendingPath) {
      const { input, path } = this.state.pendingPath;
      this.state.pendingPath = null;
      this.acceptPath(input, path);
    } else if (this.state.pendingWork) {
      const work = this.state.pendingWork;
      this.state.pendingWork = null;
      const snapshot = this.state.pendingExecution;
      this.state.pendingExecution = null;
      if (snapshot) {
        await this.startSnapshot(snapshot);
      } else {
        await this.runWork(work);
      }
    }
    if (
      this.state.enterWhenReady &&
      !this.state.busy &&
      this.state.preparation === 'ready' &&
      this.state.dialog === null
    ) {
      this.state.enterWhenReady = false;
      this.enterWorkbench();
    }
  }

  /** Debounce progress so a chatty scanner cannot starve the renderer. */
  private scheduleTick(): void {
    if (this.pendingTick) {
      return;
    }
    this.pendingTick = setTimeout(() => {
      this.pendingTick = null;
      this.flushProgress();
      this.emit();
    }, 60);
  }

  private flushProgress(): void {
    if (this.queuedProgress.length === 0) {
      return;
    }
    for (const message of this.queuedProgress) {
      this.state.logs.push(message);
      this.state.status = message;
      const percent = progressPercent(message);
      if (percent !== null) {
        this.state.progress = percent;
      }
    }
    this.queuedProgress = [];
    if (this.state.logs.length > 200) {
      this.state.logs = this.state.logs.slice(-200);
    }
  }

  async cancel(): Promise<void> {
    this.state.enterWhenReady = false;
    this.state.pendingWork = null;
    this.state.pendingPath = null;
    this.state.pendingExecution = null;
    this.state.preparationLookup = false;
    this.state.pendingOs = null;
    // The flag is set even when no worker is running yet: a request that is
    // still preparing must not start after the user cancelled it.
    this.state.cancelled = true;
    if (!this.state.busy) {
      this.state.status = '已取消；可重试';
      this.emit();
      return;
    }
    this.state.status = '正在取消…';
    this.emit();
    await this.engine.cancel();
  }

  async cancelContext(): Promise<void> {
    if (this.state.inspector) {
      this.state.inspector = false;
      if (this.state.focus === 'detail') {
        this.state.focus = 'content';
      }
      this.emit();
      return;
    }
    if (this.state.page === 'analysis' && this.state.query !== '') {
      this.state.query = '';
      this.state.row = 0;
      this.update({ status: '已清除内容筛选' });
      return;
    }
    await this.cancel();
  }

  requestQuit(): boolean {
    if (!this.state.busy || this.state.quitArmed) {
      for (const handler of this.quitHandlers) {
        handler();
      }
      return true;
    }
    this.state.quitArmed = true;
    this.update({ status: '任务执行中；再按 q 退出，Esc 取消任务' });
    return false;
  }

  /* ---------------------------------------------------------------- */
  /* Analysis                                                          */
  /* ---------------------------------------------------------------- */

  async requestAnalysis(force: boolean): Promise<void> {
    if (this.state.plugin === 'windows.printkey' && this.state.analysisOptions.hive === null) {
      this.openWindowsParameters();
      this.update({ status: 'printkey 必须填写 hive 地址' });
      return;
    }
    if (this.state.image !== null && !this.state.busy) {
      await this.refreshAssets();
      if (this.state.preparedStamp !== null && this.state.preparedStamp !== this.localStamp()) {
        this.invalidateSource();
        this.state.page = 'assets';
        await this.prepareSelectedImage();
        this.update({ status: '对象文件发生变化，正在重新识别并匹配符号' });
        return;
      }
    }
    if (pluginDescriptor(this.state, this.state.plugin)?.dump) {
      this.openDump(this.state.plugin, force);
      return;
    }
    await this.runWork({ kind: 'analyze', force });
  }

  async runWork(work: PendingWork): Promise<void> {
    if (this.state.busy) {
      // `cancel` clears the queue, so the last request is recorded after it:
      // exactly one follow-up runs, and it is always the newest.
      const snapshot =
        work.kind === 'analyze' ? this.executionSnapshot(work.force === true) : null;
      await this.cancel();
      this.state.pendingExecution = snapshot;
      this.state.pendingWork = work;
      // The follow-up is the user's newest intent; the cancel only applied to the
      // task it replaced, so it must not suppress the one that runs next.
      this.state.cancelled = false;
      this.update({ status: '正在取消；随后执行最后一次请求' });
      return;
    }
    const imageFree = ['clear', 'inspectSymbols', 'refreshLookup', 'catalog', 'catalogDownload'];
    if (this.state.image === null && !imageFree.includes(work.kind)) {
      this.state.pendingWork = work;
      this.openFiles('image');
      this.emit();
      return;
    }
    if (work.kind === 'analyze') {
      this.state.activeRequest = {
        plugin: this.state.plugin,
        key: requestKey(this.state),
        parameters: parameterSummary(this.state),
        snapshot: this.executionSnapshot(work.force === true),
      };
      this.state.historyRevision += 1;
      this.state.history = null;
      const dump = this.state.dumpOptions?.plugin === this.state.plugin ? this.state.dumpOptions : null;
      await this.runTask(
        pluginLabel(pluginDescriptor(this.state, this.state.plugin), this.state.plugin),
        (progress) =>
          this.engine.analyze(
            {
              image: this.state.image as string,
              symbols: this.state.symbols === '' ? this.state.settings.symbols : this.state.symbols,
              plugin: this.state.plugin,
              symbol_choice: this.state.choice,
              options: this.state.analysisOptions,
              dump: dump ? { ...dump.options, plugin: dump.plugin } : null,
              no_cache: work.force === true,
            },
            progress,
          ),
        (reply: AnalyzeReply) => this.applyAnalysisReply(reply),
      );
      return;
    }
    switch (work.kind) {
      case 'identify':
        await this.runTask(
          '识别内核',
          (progress) => this.engine.identify(this.state.image as string, progress),
          ({ banner }) => {
            this.applyIdentification(banner);
            this.state.results.set('banners', banner);
            this.state.status = `${this.identificationStatus(banner)} · ${banner.rows.length} 个候选；尚未验证页表`;
          },
        );
        return;
      case 'refreshLookup':
        await this.fetchRemote({ image: this.state.image, catalog: false, refresh: this.state.settings.remote_symbols });
        return;
      case 'fetchMatched':
        await this.fetchRemote({ image: this.state.image, catalog: false, refresh: false, matched: true });
        return;
      case 'catalog':
        await this.fetchRemote({
          image: this.state.windows ? this.state.image : null,
          catalog: true,
          query: work.query ?? '',
          refresh: work.refresh === true,
        });
        return;
      case 'download':
      case 'catalogDownload': {
        const candidate = work.candidate as RemoteMatch;
        await this.runTask(
          '下载符号',
          (progress) =>
            this.engine.download(
              candidate,
              {
                image: work.kind === 'download' ? this.state.image : null,
                catalog: work.kind === 'catalogDownload',
              },
              progress,
            ),
          ({ path }) => this.applyDownloaded(path, candidate, work.kind === 'download'),
        );
        return;
      }
      case 'inspectSymbols':
        await this.runTask(
          '读取符号详情',
          (progress) => this.engine.inspectSymbols(work.path as string, progress),
          ({ text }) => {
            this.state.assetDetails.set(work.path as string, text);
            this.state.status = '符号详情已读取；选用后通过镜像验证匹配';
          },
        );
        return;
      case 'generateSymbols':
        await this.runTask(
          work.fields?.elf ? '生成符号表' : '准备 Kali 符号',
          (progress) =>
            this.engine.generate(
              {
                image: this.state.image as string,
                kali: work.fields?.elf === undefined,
                elf: work.fields?.elf,
                config: work.fields?.config,
                tool: work.fields?.tool,
              },
              progress,
            ),
          async ({ path }) => {
            await this.applyGenerated(path);
          },
        );
        return;
      case 'clear':
        await this.runTask(
          '清理缓存',
          (progress) => this.engine.cacheClear(work.scopes ?? [], progress),
          (report) => this.applyCleared(report),
        );
        return;
      default:
        return;
    }
  }

  private executionSnapshot(force: boolean): ExecutionSnapshot {
    return {
      force,
      plugin: this.state.plugin,
      options: { ...this.state.analysisOptions },
      dump: this.state.dumpOptions ? { ...this.state.dumpOptions } : null,
    };
  }

  async startSnapshot(snapshot: ExecutionSnapshot): Promise<void> {
    const viewing = this.executionSnapshot(false);
    this.state.plugin = snapshot.plugin;
    this.state.analysisOptions = snapshot.options;
    this.state.dumpOptions = snapshot.dump;
    await this.runWork({ kind: 'analyze', force: snapshot.force });
    this.state.plugin = viewing.plugin;
    this.state.analysisOptions = viewing.options;
    this.state.dumpOptions = viewing.dump;
  }

  private applyAnalysisReply(reply: AnalyzeReply): void {
    if (reply.choose) {
      this.state.symbolRetry = this.state.activeRequest?.snapshot ?? null;
      this.state.status = '多个匹配 ISF，必须选择';
      this.state.dialog = { kind: 'symbols', labels: reply.choose, selected: 0 };
      return;
    }
    const analyzed = reply.result;
    if (!analyzed) {
      return;
    }
    this.state.lastError = null;
    this.state.status = `${analyzed.plugin} · ${analyzed.rows.length} 条 · ${
      analyzed.complete ? '完整' : '部分结果 / 未缓存'
    }${
      analyzed.diagnostics.length > 0 ? ` · ${analyzed.diagnostics.length} 条诊断（v 查看）` : ''
    }`;
    const execution = this.state.activeRequest;
    const viewing =
      this.state.history === null &&
      (execution === null ||
        (execution.plugin === this.state.plugin && execution.key === requestKey(this.state)));
    if (execution) {
      this.state.resultRequests.set(execution.plugin, execution.parameters);
      this.state.results.set(execution.key, analyzed);
    }
    this.state.results.set(analyzed.plugin, analyzed);
    this.state.resultsRevision += 1;
    if (viewing) {
      this.state.row = Math.max(0, Math.min(this.state.row, viewIndex(this.state).visible.length - 1));
      this.state.focus = 'content';
    }
  }

  async fetchRemote(options: {
    image: string | null;
    catalog: boolean;
    query?: string;
    refresh?: boolean;
    matched?: boolean;
  }): Promise<void> {
    if (options.catalog) {
      this.state.remoteCatalog = true;
    }
    this.state.preparationLookup = options.matched === true;
    await this.runTask(
      options.catalog ? '获取远程索引' : '精确匹配符号',
      (progress) =>
        this.engine.remote(
          {
            image: options.image,
            catalog: options.catalog,
            query: options.query ?? '',
            refresh: options.refresh === true,
          },
          progress,
        ),
      (reply: RemoteReply) => {
        this.state.remote = reply.matches;
        this.state.remoteCatalog = reply.catalog;
        this.state.assetRows[2] = Math.min(
          this.state.assetRows[2],
          Math.max(remoteList(this.state).length - 1, 0),
        );
        if (reply.catalog) {
          this.state.status = `远程索引：${reply.matches.length} 项；可输入多个关键词缩小范围`;
          return;
        }
        this.state.status = `${reply.matches.length} 个完整 banner 匹配 · Enter 进入控制台 · d 详情 · w 下载到 symbols`;
        if (!this.state.preparationLookup) {
          if (reply.matches.length === 0) {
            this.state.status = '仓库没有完整 banner 匹配；t 切换本地，g 获取索引，/ 手动搜索';
          }
          return;
        }
        this.state.preparationLookup = false;
        if (reply.matches.length === 1) {
          const candidate = reply.matches[0] as RemoteMatch;
          void this.runWork({ kind: 'download', candidate });
        } else if (reply.matches.length > 1) {
          this.state.dialog = { kind: 'links', matches: reply.matches, selected: 0 };
        } else {
          if (this.state.preparation !== 'ready') {
            this.state.preparation = 'missingSymbols';
          }
          this.state.status = this.state.windows
            ? '未找到精确 PDB 身份；b 重新识别，y 导入本地符号'
            : supportsKaliSymbols(this.state)
              ? `GitHub 没有该完整 banner 的精确符号；K 生成当前镜像符号表 · ${this.hello.repository}`
              : `GitHub 没有该完整 banner 的精确符号；y 导入，M 重试 · ${this.hello.repository}`;
        }
      },
    );
  }

  private async applyDownloaded(
    path: string,
    candidate: RemoteMatch,
    selectAfter: boolean,
  ): Promise<void> {
    this.state.downloads.set(candidate.url, path);
    if (!selectAfter) {
      this.state.status = `已保存到 ${path}；在本地库定位后可选用`;
      await this.refreshAssets();
      return;
    }
    this.state.symbols = path;
    this.state.choice = null;
    const banner = this.state.results.get('banners');
    this.state.results.clear();
    if (banner) {
      this.state.results.set('banners', banner);
    }
    this.state.views.clear();
    this.state.historyRevision += 1;
    this.state.history = null;
    this.resetView();
    await this.refreshAssets();
    this.focusAsset('symbols', path);
    this.state.preparation = 'ready';
    this.state.preparedStamp = this.localStamp();
    this.state.status = '符号已选用；x 进入分析，点击插件运行并验证页表';
  }

  private async applyGenerated(path: string): Promise<void> {
    this.state.symbols = path;
    this.state.choice = null;
    this.state.preparation = 'ready';
    this.state.preparedStamp = this.localStamp();
    await this.refreshAssets();
    this.focusAsset('symbols', path);
    this.state.status = `符号已生成并选用: ${path}；x 进入分析`;
  }

  private applyCleared(report: ClearReport): void {
    this.state.results.clear();
    this.state.views.clear();
    void this.refreshAssets();
    this.state.status = `已清理 ${report.removed} 个文件 · 释放 ${mib(report.bytes)} MiB · ${report.failures.length} 项失败`;
    if (report.failures.length > 0) {
      this.state.lastError = report.failures.join('\n');
    }
  }

  focusAsset(kind: AssetKind, path: string): void {
    const slot = kind === 'symbols' ? 1 : 0;
    this.state.assetQueries[slot] = '';
    const list = this.state.assets.filter(
      (asset) =>
        asset.kind === kind &&
        !this.state.hiddenCacheCopies.has(asset.path) &&
        (kind !== 'symbols' ||
          !this.state.localOnlyMatches ||
          this.state.localMatches.has(asset.path)),
    );
    const index = list.findIndex((asset) => samePath(asset.path, path));
    this.state.assetRows[slot] = Math.max(index, 0);
    this.state.assetScroll[slot] = 0;
  }

  async symbolTarget(remote: boolean): Promise<void> {
    if (this.state.busy) {
      this.update({ status: '等待当前任务完成；Esc 可取消后匹配符号' });
      return;
    }
    await this.switchSection(remote ? 'remote' : 'symbols');
    if (remote) {
      this.state.remoteCatalog = false;
      this.state.assetQueries[2] = '';
      await this.runWork({ kind: 'fetchMatched' });
    } else {
      this.state.assetQueries[1] = '';
      this.state.assetRows[1] = 0;
      const stamp = this.localStamp();
      if (this.state.image !== null && this.state.localMatchStamp === stamp) {
        this.state.localOnlyMatches = true;
        this.state.status = `复用本地完整 banner 匹配：${this.state.localMatches.size} 个文件；t 远程，x 开始分析`;
        this.emit();
      } else {
        this.state.localOnlyMatches = false;
        await this.prepareSelectedImage();
      }
    }
  }

  /* ---------------------------------------------------------------- */
  /* Navigation                                                        */
  /* ---------------------------------------------------------------- */

  switchPage(page: Page): void {
    const changed = this.state.page !== page;
    if (changed) this.state.inspector = false;
    this.state.page = page;
    if (changed && !this.state.busy && this.state.lastError !== this.state.status) {
      this.state.status =
        page === 'analysis'
          ? this.state.image === null
            ? '尚未选用镜像；1 资源库选用'
            : '点击或 Enter 运行插件 · / 筛选 · ? 命令面板'
          : 'Space 选用 · Enter 选用并进入分析 · ? 命令面板';
    }
    this.state.focus = page === 'analysis' ? 'content' : 'navigation';
    if (page !== 'analysis') {
      void this.refreshAssets();
    }
    this.emit();
  }

  async switchSection(section: Section): Promise<void> {
    this.state.page = 'assets';
    this.state.section = section;
    this.state.focus = 'navigation';
    if (section !== 'images') {
      this.state.symbolSource = section;
    }
    await this.refreshAssets();
  }

  toggleSource(): void {
    void this.switchSection(this.state.symbolSource === 'symbols' ? 'remote' : 'symbols');
  }

  async fetchIndex(): Promise<void> {
    if (this.state.section !== 'remote') {
      return;
    }
    await this.switchSection('remote');
    this.state.remoteCatalog = true;
    this.state.assetQueries[2] = '';
    await this.runWork({
      kind: 'catalog',
      query: '',
      refresh: this.state.settings.remote_symbols,
    });
  }

  async downloadCandidate(): Promise<void> {
    if (this.state.section !== 'remote') {
      return;
    }
    const candidate = selectedRemote(this.state);
    if (candidate) {
      await this.runWork({ kind: 'catalogDownload', candidate });
    }
  }

  toggleMatchFilter(): void {
    if (this.state.section !== 'symbols') {
      return;
    }
    this.state.localOnlyMatches = !this.state.localOnlyMatches;
    this.state.assetRows[1] = 0;
    this.emit();
  }

  async refreshAssetList(): Promise<void> {
    if (this.state.section === 'remote') {
      if (this.state.remoteCatalog) {
        await this.runWork({
          kind: 'catalog',
          query: this.state.assetQueries[2],
          refresh: this.state.settings.remote_symbols,
        });
      } else {
        await this.runWork({ kind: 'refreshLookup' });
      }
      return;
    }
    this.state.assetDetails.clear();
    await this.refreshAssets();
    this.update({ status: '资产清单已刷新' });
  }

  async deleteAsset(): Promise<void> {
    if (this.state.section === 'remote') {
      this.update({ status: '远程索引条目无需移出；w 可下载到本地库' });
      return;
    }
    if (this.state.busy) {
      this.update({ status: '任务执行中；Esc 取消后再移出资产' });
      return;
    }
    const asset = selectedAsset(this.state);
    if (!asset) {
      this.update({ status: '没有选中的资产' });
      return;
    }
    try {
      await this.engine.remove(asset.path);
    } catch (error) {
      this.update({ status: `清单保存失败: ${(error as Error).message}` });
      return;
    }
    if (this.state.image !== null && samePath(this.state.image, asset.path)) {
      this.invalidateSource();
      this.state.image = null;
    } else if (samePath(this.state.symbols, asset.path)) {
      this.invalidateSource();
      this.state.symbols = '';
    }
    await this.refreshAssets();
    this.update({ status: '已移出项目清单，原文件保留' });
  }

  async toggleOnline(): Promise<void> {
    if (this.state.busy) {
      this.update({ status: '任务执行中；等待完成或按 Esc 取消后再切换' });
      return;
    }
    const settings: Settings = {
      ...this.state.settings,
      remote_symbols: !this.state.settings.remote_symbols,
    };
    await this.persistSettings(settings);
    this.update({
      status: settings.remote_symbols
        ? '在线符号匹配已开启；仅请求仓库，不上传镜像'
        : '离线模式：使用本地 ISF 和已下载缓存',
    });
  }

  async persistSettings(settings: Settings): Promise<void> {
    try {
      this.state.settings = await this.engine.saveSettings(settings);
    } catch (error) {
      this.fail(`设置保存失败: ${(error as Error).message}`);
    }
  }

  /* ---------------------------------------------------------------- */
  /* File pickers and inputs                                           */
  /* ---------------------------------------------------------------- */

  async openFiles(input: InputKind): Promise<void> {
    const base =
      input === 'image' || input === 'imageDirectory'
        ? this.state.settings.image_dir
        : input === 'symbols' || input === 'symbolsDirectory'
          ? this.state.settings.symbols
          : this.state.settings.export_dir;
    let root = expandHome(base);
    if (!(await this.isDirectory(root)) && (await this.isFile(root))) {
      root = dirname(root);
    }
    if (!(await this.isDirectory(root))) {
      this.openInput(input);
      this.update({ status: `配置目录不可用: ${root}；输入路径或按 , 修改目录` });
      return;
    }
    await this.browse(input, root);
  }

  private async isDirectory(path: string): Promise<boolean> {
    try {
      const fs = await import('node:fs/promises');
      return (await fs.stat(path)).isDirectory();
    } catch {
      return false;
    }
  }

  private async isFile(path: string): Promise<boolean> {
    try {
      const fs = await import('node:fs/promises');
      return (await fs.stat(path)).isFile();
    } catch {
      return false;
    }
  }

  async browse(input: InputKind, root: string): Promise<void> {
    try {
      const listing = await this.engine.browse(root, pickerFilter(input));
      this.state.dialog = {
        kind: 'files',
        input,
        root: listing.root,
        entries: listing.entries,
        selected: 0,
      };
      this.emit();
    } catch (error) {
      this.update({ status: `读取目录失败: ${(error as Error).message}；p 手动输入路径` });
    }
  }

  openInput(input: InputKind): void {
    if (input === 'search') {
      this.state.focus = 'content';
    }
    const text = inputText(this.state, input);
    this.state.dialog = {
      kind: 'input',
      input,
      text,
      original: text,
      cursor: text.length,
      selected: input !== 'search' && input !== 'assetsSearch',
    };
    this.emit();
  }

  /** A path chosen in the picker: open the text field and submit it. */
  async acceptPath(input: InputKind, path: string): Promise<void> {
    this.openInput(input);
    const dialog = this.state.dialog;
    if (dialog?.kind === 'input') {
      this.state.dialog = {
        ...dialog,
        text: path,
        cursor: path.length,
        selected: false,
      };
    }
    await this.dialogKey('Enter', {});
  }

  openWindowsParameters(): void {
    const options = this.state.analysisOptions;
    const descriptor = pluginDescriptor(this.state, this.state.plugin);
    const fields = [
      formatAddress(options.hive),
      options.key,
      options.pid === null ? '' : String(options.pid),
      options.arch,
      options.pagefiles.map((file) => `${file.index}=${file.path}`).join('; '),
      options.swapfile ?? '',
    ];
    const field =
      this.state.plugin === 'windows.printkey'
        ? 0
        : descriptor?.columns.includes('PID')
          ? 2
          : 6;
    this.state.dialog = {
      kind: 'windowsParameters',
      advanced: false,
      fields,
      field,
      cursor: 0,
      selected: true,
      error: '',
    };
    this.emit();
  }

  openDump(mode: string, force: boolean): void {
    const normalized = this.state.windows
      ? mode === 'procdump'
        ? 'windows.procdump'
        : mode === 'memdump'
          ? 'windows.memdump'
          : mode === 'elfdump'
            ? 'windows.pedump'
            : mode
      : mode;
    const previous = this.state.dumpOptions?.plugin === normalized ? this.state.dumpOptions : null;
    const current = result(this.state);
    const pidColumn = current?.columns.indexOf('PID') ?? -1;
    const row = visibleRow(this.state, viewIndex(this.state), this.state.row);
    const pid =
      previous !== null
        ? String(previous.options.pid)
        : pidColumn >= 0 && row
          ? (row[pidColumn] ?? '')
          : '';
    const fields = [
      pid,
      formatAddress(previous?.options.start ?? null),
      formatAddress(previous?.options.end ?? null),
      previous?.options.directory ?? `${expandHome(this.state.settings.export_dir)}/dumps`,
    ];
    this.state.dialog = {
      kind: 'dump',
      mode: normalized,
      fields,
      field: 0,
      cursor: fields[0]?.length ?? 0,
      selected: true,
      force,
      error: '',
    };
    this.emit();
  }

  async openCache(): Promise<void> {
    try {
      const { entries } = await this.engine.cacheInventory();
      this.state.dialog = {
        kind: 'cache',
        entries,
        scopes: ['results', 'identification'],
        selected: 0,
        confirm: false,
      };
      this.emit();
    } catch (error) {
      this.fail(`缓存清单失败: ${(error as Error).message}`);
    }
  }

  openSymbolGeneration(): void {
    if (this.state.image === null) {
      this.update({ status: '请先在资源库用 Space 选用镜像' });
      return;
    }
    if (this.state.windows) {
      this.update({ status: 'Windows 使用 M 获取当前镜像的精确 PDB 符号' });
      return;
    }
    this.state.backDialog = null;
    const automatic = supportsKaliSymbols(this.state);
    const tool = `${this.hello.cache}/symbols/build/dwarf2json/dwarf2json`;
    this.state.dialog = {
      kind: 'generateSymbols',
      automatic,
      fields: ['', '', tool],
      field: automatic ? 3 : 0,
      cursor: 0,
      selected: true,
      error: '',
    };
    this.emit();
  }

  openHistory(): void {
    void this.openFiles('history');
  }

  openSystemDialog(): void {
    this.state.dialog = {
      kind: 'system',
      selected: this.state.analysisOptions.os === 'auto' ? 0 : this.state.analysisOptions.os === 'linux' ? 1 : 2,
    };
    this.emit();
  }

  openTaskLog(): void {
    this.state.dialog = { kind: 'detail', text: logText(this.state.logs), scroll: 0 };
    this.emit();
  }

  openHelp(): void {
    this.state.dialog = { kind: 'detail', text: helpText(), scroll: 0 };
    this.emit();
  }

  openDiagnostics(): void {
    if (this.state.lastError) {
      this.state.dialog = { kind: 'detail', text: this.state.lastError, scroll: 0 };
      this.emit();
      return;
    }
    const current = result(this.state);
    if (current) {
      this.state.dialog = { kind: 'detail', text: diagnosticsText(current), scroll: 0 };
      this.emit();
    }
  }

  openAssetDetail(): void {
    if (this.state.section === 'remote') {
      const candidate = selectedRemote(this.state);
      if (candidate) {
        this.state.dialog = { kind: 'remoteDetail', candidate, scroll: 0 };
        this.emit();
      }
      return;
    }
    const asset = selectedAsset(this.state);
    if (!asset) {
      return;
    }
    this.state.dialog = { kind: 'assetDetail', asset, scroll: 0 };
    this.emit();
    if (asset.kind === 'symbols' && !asset.directory && !this.state.assetDetails.has(asset.path) && !this.state.busy) {
      void this.runWork({ kind: 'inspectSymbols', path: asset.path });
    }
  }

  async viewAssetPath(path: string, kind: AssetKind): Promise<void> {
    const asset =
      this.state.assets.find((candidate) => samePath(candidate.path, path)) ??
      ({
        id: '',
        path,
        name: path.split('/').pop() ?? path,
        kind,
        bytes: 0,
        available: true,
        directory: false,
        format: kind === 'image' ? 'RAW/LiME' : 'ISF',
        origin: '文件浏览',
        stamp: null,
        source_url: null,
      } satisfies Asset);
    this.state.dialog = { kind: 'assetDetail', asset, scroll: 0 };
    this.emit();
    if (kind === 'symbols' && !this.state.assetDetails.has(path) && !this.state.busy) {
      await this.runWork({ kind: 'inspectSymbols', path });
    }
  }

  openDetail(): void {
    if (result(this.state)) {
      this.state.dialog = { kind: 'detail', text: detailText(this.state), scroll: 0 };
      this.emit();
    }
  }

  /* ---------------------------------------------------------------- */
  /* Command dispatch                                                  */
  /* ---------------------------------------------------------------- */

  /** Resolve a key for the active page, honouring section-specific actions. */
  resolveKey(key: string): Command | null {
    const command = commandForKey(this.state.page, key);
    if (!command) {
      return null;
    }
    if (this.state.page === 'assets' && !commandApplies(command, this.state.section)) {
      const replacement = commandForKey('analysis', key);
      if (replacement && commandApplies(replacement, this.state.section)) {
        return replacement;
      }
    }
    return command;
  }

  /** The single entry point for every command, whatever triggered it. */
  async runCommand(command: Command): Promise<boolean> {
    const disabled = commandDisabled(this.state, command);
    if (disabled) {
      this.update({ status: disabled });
      return false;
    }
    switch (command) {
      case 'quit':
        return this.requestQuit();
      case 'help':
        this.openHelp();
        break;
      case 'palette':
        this.state.dialog = { kind: 'commands', query: '', selected: 0 };
        this.emit();
        break;
      case 'settings':
        this.state.dialog = { kind: 'settings', selected: 0 };
        this.emit();
        break;
      case 'cache':
        await this.openCache();
        break;
      case 'taskLog':
        this.openTaskLog();
        break;
      case 'history':
        this.openHistory();
        break;
      case 'diagnostics':
        this.openDiagnostics();
        break;
      case 'pageAssets':
        this.switchPage('assets');
        break;
      case 'pageAnalysis':
        this.switchPage('analysis');
        break;
      case 'systemSelect':
        this.openSystemDialog();
        break;
      case 'toggleOnline':
        await this.toggleOnline();
        break;
      case 'cancel':
        await this.cancelContext();
        break;
      case 'importImage':
        await this.openFiles('image');
        break;
      case 'importSymbols':
        await this.openFiles('symbols');
        break;
      case 'importCurrent':
        await this.openFiles(this.state.section === 'images' ? 'image' : 'symbols');
        break;
      case 'select':
        await this.selectAsset();
        break;
      case 'selectAndEnter':
        await this.selectAndEnter();
        break;
      case 'assetDetail':
        this.openAssetDetail();
        break;
      case 'deleteAsset':
        await this.deleteAsset();
        break;
      case 'refreshAssets':
        await this.refreshAssetList();
        break;
      case 'searchAssets':
        this.openInput('assetsSearch');
        break;
      case 'matchLocal':
        await this.symbolTarget(false);
        break;
      case 'matchRemote':
        await this.symbolTarget(true);
        break;
      case 'identify':
        await this.runWork({ kind: 'identify' });
        break;
      case 'enterAnalysis':
        this.enterWorkbench();
        break;
      case 'toggleSource':
        this.toggleSource();
        break;
      case 'generateSymbols':
        this.openSymbolGeneration();
        break;
      case 'fetchIndex':
        await this.fetchIndex();
        break;
      case 'download':
        await this.downloadCandidate();
        break;
      case 'toggleMatchFilter':
        this.toggleMatchFilter();
        break;
      case 'run':
        await this.requestAnalysis(false);
        break;
      case 'rerun':
        await this.requestAnalysis(true);
        break;
      case 'plugins':
        this.state.dialog = { kind: 'plugins', query: '', selected: 0 };
        this.emit();
        break;
      case 'parameters':
        this.openWindowsParameters();
        break;
      case 'dump':
        this.openDump(
          pluginDescriptor(this.state, this.state.plugin)?.dump ? this.state.plugin : 'procdump',
          false,
        );
        break;
      case 'export':
        this.openInput('export');
        break;
      case 'sort':
        this.state.dialog = { kind: 'sort', column: this.state.sort ?? 0 };
        this.emit();
        break;
      case 'rows':
        this.openInput('pageSize');
        break;
      case 'prevPage':
        this.moveResultPage(false);
        break;
      case 'nextPage':
        this.moveResultPage(true);
        break;
      case 'detail':
        this.state.inspector = !this.state.inspector;
        this.state.detailScroll = 0;
        this.state.focus = this.state.inspector ? 'detail' : 'content';
        this.emit();
        break;
      case 'searchContent':
        this.openInput('search');
        break;
      case 'enter':
        await this.enterFocused();
        break;
    }
    return false;
  }

  async selectAsset(): Promise<void> {
    if (this.state.section === 'remote') {
      if (this.state.image === null) {
        this.update({ status: '请先用 Space 选用镜像；远程 w 可独立下载' });
      } else {
        const candidate = selectedRemote(this.state);
        if (candidate) {
          await this.runWork({ kind: 'download', candidate });
        }
      }
      return;
    }
    if (await this.useSelectedAsset()) {
      if (this.state.section === 'images') {
        this.state.symbolSource = 'symbols';
        await this.prepareSelectedImage();
      }
    }
  }

  inspectorAvailable(): boolean {
    return inspector(space(this.state.columns, this.state.rows));
  }

  moveResultPage(down: boolean): void {
    const size = this.pageRows();
    const length = viewIndex(this.state).visible.length;
    this.state.row = down
      ? Math.min(this.state.row + size, Math.max(length - 1, 0))
      : Math.max(this.state.row - size, 0);
    this.emit();
  }

  /**
   * Rows per page.
   *
   * `height` is the table region being drawn. Callers that already know it pass
   * it, so the first frame — before any hit map has been measured — reports the
   * real page instead of a single row; keyboard paging, which runs between
   * frames, falls back to the last measured region.
   */
  pageRows(height = this.state.hits.result.height): number {
    const available = Math.max(height - 3, 1);
    if (this.state.settings.page_size === 0) {
      return available;
    }
    return height === 0 ? this.state.settings.page_size : Math.min(this.state.settings.page_size, available);
  }

  async enterFocused(): Promise<void> {
    if (this.state.focus === 'detail') {
      this.openDetail();
      return;
    }
    if (this.state.focus === 'context') {
      await this.openFiles('image');
      return;
    }
    if (this.state.focus === 'navigation') {
      if (this.state.menu === menuItems(this.state).length - 1) {
        this.openDump('procdump', false);
        return;
      }
      const plugin = navigationPlugins(this.state)[this.state.menu];
      if (plugin) {
        await this.activatePlugin(plugin.name);
      }
      return;
    }
    if (treeColumns(this.state) && this.state.history === null) {
      const row = visibleRow(this.state, viewIndex(this.state), this.state.row);
      if (row) {
        const pid = row[0] as string;
        if (this.state.collapsed.has(pid)) {
          this.state.collapsed.delete(pid);
        } else {
          this.state.collapsed.add(pid);
        }
        this.emit();
      }
      return;
    }
    this.openDetail();
  }

  /* ---------------------------------------------------------------- */
  /* Mouse                                                             */
  /* ---------------------------------------------------------------- */

  /**
   * Resolve a click against the current layout tree.
   *
   * The rectangles come from the same computation the renderer used, so a click
   * lands on exactly what the user sees. Order matters: a modal owns the whole
   * screen, then footer chips, then panes, then the chrome.
   */
  async click(x: number, y: number): Promise<void> {
    const layout = this.layout();
    const state = this.state;
    if (state.columns < 60 || state.rows < 16) return;
    if (state.dialog) {
      if (layout.popup && !inside(layout.popup, x, y)) {
        return;
      }
      for (const button of layout.buttons) {
        if (!inside(button.rect, x, y)) {
          continue;
        }
        if (button.key.startsWith('row:')) {
          await this.dialogRow(Number(button.key.slice(4)));
          return;
        }
        await this.dialogKey(button.key, {});
        return;
      }
      // A click inside the modal but not on a row or chip is a no-op: it must
      // not fall through to the page underneath.
      return;
    }

    if (layout.inspector && inside(layout.inspector, x, y)) {
      state.focus = 'detail';
      this.emit();
      return;
    }

    for (const button of layout.buttons) {
      if (!inside(button.rect, x, y)) {
        continue;
      }
      if (state.page === 'assets') {
        const command = commandForKey('assets', button.key);
        if (command) {
          await this.runCommand(command);
        }
      } else {
        const command = this.resolveKey(button.key);
        if (command) {
          await this.runCommand(command);
        }
      }
      return;
    }

    for (const tab of layout.tabsHits) {
      if (inside(tab.rect, x, y)) {
        this.switchPage(tab.page);
        return;
      }
    }
    for (const system of layout.systemHits) {
      if (inside(system.rect, x, y)) {
        await this.selectOs(system.os);
        return;
      }
    }
    for (const region of layout.regionHits) {
      if (inside(region.rect, x, y)) {
        state.inspector = false;
        state.focus = region.focus;
        this.emit();
        return;
      }
    }
    if (inside(layout.headerSymbol, x, y)) {
      await this.openFiles('symbols');
      return;
    }
    if (inside(layout.headerImage, x, y)) {
      await this.openFiles('image');
      return;
    }
    for (const source of layout.sourceHits) {
      if (inside(source.rect, x, y)) {
        await this.switchSection(source.section);
        return;
      }
    }
    for (const pane of layout.panes) {
      if (pane.search && inside(pane.search, x, y)) {
        await this.switchSection(pane.section);
        this.openInput('assetsSearch');
        return;
      }
      if (!inside(pane.list, x, y)) {
        continue;
      }
      const already =
        state.section === pane.section && state.focus === 'navigation' && pane.section !== 'remote';
      state.section = pane.section;
      if (pane.section !== 'images') {
        state.symbolSource = pane.section;
      }
      state.focus = 'navigation';
      const row = layout.rowHits.find(
        (hit) => hit.section === pane.section && inside(hit.rect, x, y),
      );
      if (!row) {
        this.emit();
        return;
      }
      if (
        already &&
        row.index === state.assetRows[sectionSlot(pane.section)] &&
        pane.section !== 'remote' &&
        !assetActive(this.state, assetListFor(state, pane.section)[row.index] as Asset)
      ) {
        // Clicking the already-highlighted row selects it, like Space.
        await this.runCommand('select');
        return;
      }
      state.assetRows[sectionSlot(pane.section)] = row.index;
      state.assetScroll[sectionSlot(pane.section)] = 0;
      this.emit();
      if (pane.section === 'remote') {
        this.openAssetDetail();
      }
      return;
    }
    if (layout.contentSearch && inside(layout.contentSearch, x, y)) {
      this.openInput('search');
      return;
    }
    if (layout.content && inside(layout.content, x, y)) {
      state.focus = 'content';
      const column = layout.buttons.find(
        (button) => button.key === 'header' && inside(button.rect, x, y),
      );
      void column;
      const row = layout.rowHits.find(
        (hit) => hit.section === null && inside(hit.rect, x, y),
      );
      if (row) {
        state.row = row.index;
        this.emit();
        return;
      }
      if (y === layout.content.y + 1 && state.hits.columns.length > 0) {
        const index = state.hits.columns.findIndex((rect) => x >= rect.x && x < rect.x + rect.width);
        if (index >= 0) {
          state.descending = state.sort === index && !state.descending;
          state.sort = index;
          state.row = 0;
        }
      }
      this.emit();
      return;
    }
    if (layout.menu && inside(layout.menu, x, y)) {
      state.focus = 'navigation';
      const row = layout.rowHits.find((hit) => hit.section === null && inside(hit.rect, x, y));
      if (row) {
        state.menu = row.index;
        const plugins = navigationPlugins(state);
        const plugin = plugins[row.index];
        if (plugin) {
          await this.activatePlugin(plugin.name);
        } else {
          this.openDump('procdump', false);
        }
      } else {
        this.emit();
      }
      return;
    }
    if (inside(layout.header, x, y)) {
      if (y > layout.header.y) {
        await this.openFiles('symbols');
      } else {
        await this.openFiles('image');
      }
    }
  }

  /** Layout of the last frame, recomputed from the current terminal size. */
  layout(): Layout {
    return computeLayout(this.state, this.state.columns, this.state.rows);
  }

  /* ---------------------------------------------------------------- */
  /* Dialog rows and keys                                              */
  /* ---------------------------------------------------------------- */

  private async dialogRow(index: number): Promise<void> {
    const dialog = this.state.dialog;
    if (!dialog || index < 0) {
      return;
    }
    switch (dialog.kind) {
      case 'files':
        if (index < dialog.entries.length) {
          this.state.dialog = { ...dialog, selected: index };
          await this.dialogKey('Enter', {});
        }
        return;
      case 'system':
        if (index < 3) {
          this.state.dialog = { ...dialog, selected: index };
          await this.dialogKey('Enter', {});
        }
        return;
      case 'settings':
        if (index < 5) {
          this.state.dialog = { ...dialog, selected: index };
          await this.dialogKey('Enter', {});
        }
        return;
      case 'plugins': {
        const matches = pluginMatches(this.state, dialog.query);
        if (index < matches.length) {
          this.state.dialog = { ...dialog, selected: index };
          await this.dialogKey('Enter', {});
        }
        return;
      }
      case 'cache':
        if (index < this.hello.scopes.length) {
          this.state.dialog = { ...dialog, selected: index, confirm: false };
          await this.dialogKey(' ', {});
        }
        return;
      case 'commands': {
        const matches = commandMatches(dialog.query, this.state.page, this.state.focus, this.state.page === 'assets' ? this.state.section : null);
        if (index < matches.length) {
          this.state.dialog = { ...dialog, selected: index };
          await this.dialogKey('Enter', {});
        }
        return;
      }
      case 'links':
        if (index < dialog.matches.length) {
          this.state.dialog = { ...dialog, selected: index };
          await this.dialogKey(' ', {});
        }
        return;
      case 'sort': {
        const count = result(this.state)?.columns.length ?? 0;
        if (index < count) {
          this.state.dialog = { ...dialog, column: index };
          await this.dialogKey('Enter', {});
        }
        return;
      }
      case 'symbols':
        if (index < dialog.labels.length) {
          this.state.dialog = { ...dialog, selected: index };
          await this.dialogKey(' ', {});
        }
        return;
      default:
        return;
    }
  }

  async dialogKey(token: string, key: Partial<KeyLike>, input = ''): Promise<void> {
    const dialog = this.state.dialog;
    if (!dialog) {
      return;
    }
    if (token === 'Esc') {
      if (dialog.kind === 'symbols') {
        this.state.symbolRetry = null;
        this.state.enterWhenReady = false;
      }
      this.state.pendingWork = null;
      if (['detail', 'remoteDetail', 'assetDetail'].includes(dialog.kind) && this.state.backDialog) {
        this.state.dialog = this.state.backDialog;
        this.state.backDialog = null;
        this.emit();
        return;
      }
      if (dialog.kind === 'input') {
        if (dialog.input === 'search') {
          this.state.query = dialog.original;
          this.state.row = 0;
        } else if (dialog.input === 'assetsSearch') {
          this.state.assetQueries[sectionSlot(this.state.section)] = dialog.original;
          this.state.assetRows[sectionSlot(this.state.section)] = 0;
        }
      }
      this.state.dialog = null;
      this.emit();
      return;
    }
    switch (dialog.kind) {
      case 'system':
        await this.systemKey(dialog, token);
        return;
      case 'generateSymbols':
        await this.generationKey(dialog, token, key, input);
        return;
      case 'windowsParameters':
        await this.parametersKey(dialog, token, key, input);
        return;
      case 'dump':
        await this.dumpKey(dialog, token, key, input);
        return;
      case 'files':
        await this.filesKey(dialog, token, key);
        return;
      case 'settings':
        await this.settingsKey(dialog, token);
        return;
      case 'cache':
        await this.cacheKey(dialog, token);
        return;
      case 'commands':
        await this.commandsKey(dialog, token, input);
        return;
      case 'plugins':
        await this.pluginsKey(dialog, token, key, input);
        return;
      case 'links':
        await this.linksKey(dialog, token);
        return;
      case 'assetDetail':
        await this.assetDetailKey(dialog, token);
        return;
      case 'remoteDetail':
        await this.remoteDetailKey(dialog, token);
        return;
      case 'detail':
        this.state.dialog = {
          ...dialog,
          scroll: this.scrollAmount(token, dialog.scroll, this.detailMaximum(dialog)),
        };
        this.emit();
        return;
      case 'input':
        await this.inputKey(dialog, token, input);
        return;
      case 'sort':
        await this.sortKey(dialog, token);
        return;
      case 'symbols':
        await this.symbolsKey(dialog, token);
        return;
    }
  }

  private detailMaximum(dialog: { text: string }): number {
    const rows = this.state.hits.popup.height > 0 ? this.state.hits.popup.height : 12;
    const columns = this.state.hits.popup.width > 0 ? this.state.hits.popup.width : 78;
    return Math.max(this.wrapCount(dialog.text, columns - 2) - (rows - 2), 0);
  }

  private wrapCount(text: string, columns: number): number {
    let lines = 0;
    for (const paragraph of text.split('\n')) {
      lines += Math.max(Math.ceil(this.widthOf(paragraph) / Math.max(columns, 1)), 1);
    }
    return lines;
  }

  private widthOf(text: string): number {
    let total = 0;
    for (const character of text) {
      total += charWidth(character);
    }
    return total;
  }

  private scrollAmount(token: string, scroll: number, maximum: number): number {
    switch (token) {
      case 'Up':
      case 'k':
        return Math.max(scroll - 1, 0);
      case 'Down':
      case 'j':
        return Math.min(scroll + 1, maximum);
      case 'PageUp':
        return Math.max(scroll - 10, 0);
      case 'PageDown':
        return Math.min(scroll + 10, maximum);
      case 'Home':
        return 0;
      case 'End':
        return maximum;
      default:
        return scroll;
    }
  }

  private async systemKey(dialog: Dialog, token: string): Promise<void> {
    if (dialog.kind !== 'system') {
      return;
    }
    switch (token) {
      case 'Up':
      case 'k':
        this.state.dialog = { ...dialog, selected: Math.max(dialog.selected - 1, 0) };
        this.emit();
        return;
      case 'Down':
      case 'j':
        this.state.dialog = { ...dialog, selected: Math.min(dialog.selected + 1, 2) };
        this.emit();
        return;
      case 'Enter': {
        const os: Os = (['auto', 'linux', 'windows'] as Os[])[dialog.selected] ?? 'auto';
        this.state.dialog = null;
        await this.selectOs(os);
        return;
      }
      default:
        return;
    }
  }

  private async generationKey(
    dialog: Dialog,
    token: string,
    key: Partial<KeyLike>,
    input: string,
  ): Promise<void> {
    if (dialog.kind !== 'generateSymbols') {
      return;
    }
    if (token === 'Ctrl+t') {
      if (supportsKaliSymbols(this.state)) {
        const automatic = !dialog.automatic;
        this.state.dialog = {
          ...dialog,
          automatic,
          field: automatic ? 3 : 0,
          cursor: 0,
          selected: true,
          error: '',
        };
      } else {
        this.state.dialog = {
          ...dialog,
          error: '该内核尚不支持自动获取调试资料；请填写匹配的 ELF 和配置',
        };
      }
      this.emit();
      return;
    }
    if (token === 'Enter' && (dialog.field === 3 || key.ctrl)) {
      if (dialog.automatic) {
        this.state.dialog = null;
        await this.runWork({ kind: 'generateSymbols', fields: {} });
        return;
      }
      const [elf, config, tool] = dialog.fields.map((value) => expandHome(value.trim())) as [
        string,
        string,
        string,
      ];
      const missing = [
        ['调试 ELF', elf],
        ['内核配置', config],
        ['dwarf2json', tool],
      ].find(([, value]) => value === '');
      if (missing) {
        this.state.dialog = { ...dialog, error: `${missing[0]} 路径不能为空` };
        this.emit();
        return;
      }
      this.state.dialog = null;
      await this.runWork({ kind: 'generateSymbols', fields: { elf, config, tool } });
      return;
    }
    if (['Tab', 'BackTab', 'Down', 'Up', 'Enter'].includes(token)) {
      if (!dialog.automatic) {
        const back = token === 'BackTab' || token === 'Up';
        const field = (dialog.field + (back ? 3 : 1)) % 4;
        this.state.dialog = {
          ...dialog,
          field,
          cursor: field < 3 ? (dialog.fields[field] ?? '').length : 0,
          selected: true,
        };
        this.emit();
      }
      return;
    }
    if (dialog.field < 3 && !dialog.automatic) {
      const editor = editInput(
        { text: dialog.fields[dialog.field] ?? '', cursor: dialog.cursor, selected: dialog.selected },
        token,
        input,
      );
      const fields = [...dialog.fields];
      fields[dialog.field] = editor.text;
      this.state.dialog = { ...dialog, fields, cursor: editor.cursor, selected: editor.selected };
      this.emit();
    }
  }

  private async parametersKey(
    dialog: Dialog,
    token: string,
    key: Partial<KeyLike>,
    input: string,
  ): Promise<void> {
    if (dialog.kind !== 'windowsParameters') {
      return;
    }
    if (token === 'Ctrl+t' && this.state.windows) {
      const advanced = !dialog.advanced;
      const field = !advanced && dialog.field >= 3 ? 6 : dialog.field;
      this.state.dialog = { ...dialog, advanced, field };
      this.emit();
      return;
    }
    if (token === 'Enter' && (dialog.field === 6 || key.ctrl)) {
      const { options, error } = parseOptions(this.state, dialog.fields);
      if (error || !options) {
        this.state.dialog = { ...dialog, error: error ?? '参数无效' };
        this.emit();
        return;
      }
      this.saveView();
      this.state.analysisOptions = options;
      this.restoreView();
      this.state.dialog = null;
      this.update({ status: '参数已保存；Ctrl+R 明确运行' });
      return;
    }
    if (['Tab', 'BackTab', 'Up', 'Down', 'Enter'].includes(token)) {
      const visible = parameterFields(this.state, dialog.advanced);
      const index = Math.max(visible.indexOf(dialog.field), 0);
      const back = token === 'BackTab' || token === 'Up';
      const field = visible[(index + (back ? visible.length - 1 : 1)) % visible.length] as number;
      this.state.dialog = {
        ...dialog,
        field,
        cursor: field < 6 ? (dialog.fields[field] ?? '').length : 0,
        selected: true,
      };
      this.emit();
      return;
    }
    if (dialog.field < 6) {
      const editor = editInput(
        { text: dialog.fields[dialog.field] ?? '', cursor: dialog.cursor, selected: dialog.selected },
        token,
        input,
      );
      const fields = [...dialog.fields];
      fields[dialog.field] = editor.text;
      this.state.dialog = { ...dialog, fields, cursor: editor.cursor, selected: editor.selected };
      this.emit();
    }
  }

  private async dumpKey(
    dialog: Dialog,
    token: string,
    key: Partial<KeyLike>,
    input: string,
  ): Promise<void> {
    if (dialog.kind !== 'dump') {
      return;
    }
    const modeKey = /^Alt\+([123])$/u.exec(token);
    if (modeKey) {
      const modes = dumpModes(this.state.windows);
      const next = modes[Number(modeKey[1]) - 1];
      if (next) {
        const fields = [...dialog.fields];
        if (next.plugin.endsWith('elfdump') || next.plugin.endsWith('pedump')) {
          fields[1] = '';
          fields[2] = '';
        }
        this.state.dialog = { ...dialog, mode: next.plugin, fields, error: '' };
        this.emit();
      }
      return;
    }
    if (token === 'Enter' && (dialog.field === 4 || key.ctrl)) {
      try {
        const pid = Number((dialog.fields[0] ?? '').trim());
        if (!Number.isInteger(pid) || pid <= 0) {
          throw new Error('请输入有效 PID');
        }
        const address = (text: string): string | null =>
          text.trim() === '' ? null : parseAddress(text);
        const start = address(dialog.fields[1] ?? '');
        const end = address(dialog.fields[2] ?? '');
        if ((start === null) !== (end === null)) {
          throw new Error('Start 和 End 必须同时填写');
        }
        if (start !== null && end !== null) {
          const startValue = BigInt(start);
          const endValue = BigInt(end);
          if (startValue >= endValue) {
            throw new Error('Start 必须小于 End（End 不包含在范围内）');
          }
          if (endValue - startValue > 256n * 1024n * 1024n) {
            throw new Error('转储范围超过 256 MiB 上限');
          }
        }
        const plugin = dialog.mode;
        if (plugin.endsWith('memdump') && (start === null || end === null)) {
          throw new Error('memdump 必须指定 --start 和 --end');
        }
        if ((plugin.endsWith('elfdump') || plugin.endsWith('pedump')) && start !== null) {
          throw new Error('PE/ELF 转储不接受地址范围；使用 memdump 精确导出范围');
        }
        const directory = expandHome((dialog.fields[3] ?? '').trim());
        if (directory === '') {
          throw new Error('必须指定转储目录');
        }
        this.state.dumpOptions = {
          plugin,
          options: { plugin, pid, directory, start, end },
        };
        this.state.plugin = plugin;
        this.state.page = 'analysis';
        this.state.menu = menuItems(this.state).length - 1;
        this.state.historyRevision += 1;
        this.state.history = null;
        this.resetView();
        this.state.dialog = null;
        await this.runWork({ kind: 'analyze', force: dialog.force });
      } catch (error) {
        this.state.dialog = { ...dialog, error: (error as Error).message };
        this.emit();
      }
      return;
    }
    if (['Tab', 'BackTab', 'Up', 'Down', 'Enter'].includes(token)) {
      const back = token === 'BackTab' || token === 'Up';
      const field = (dialog.field + (back ? 4 : 1)) % 5;
      this.state.dialog = {
        ...dialog,
        field,
        cursor: field < 4 ? (dialog.fields[field] ?? '').length : 0,
        selected: true,
      };
      this.emit();
      return;
    }
    if (dialog.field < 4) {
      const editor = editInput(
        { text: dialog.fields[dialog.field] ?? '', cursor: dialog.cursor, selected: dialog.selected },
        token,
        input,
      );
      const fields = [...dialog.fields];
      fields[dialog.field] = editor.text;
      this.state.dialog = { ...dialog, fields, cursor: editor.cursor, selected: editor.selected, error: '' };
      this.emit();
    }
  }

  private async filesKey(dialog: Dialog, token: string, key: Partial<KeyLike>): Promise<void> {
    if (dialog.kind !== 'files') {
      return;
    }
    const fileInputs = dialog.input === 'image' || dialog.input === 'symbols';
    switch (token) {
      case 'Up':
        this.state.dialog = { ...dialog, selected: Math.max(dialog.selected - 1, 0) };
        break;
      case 'Down':
        this.state.dialog = {
          ...dialog,
          selected: Math.min(dialog.selected + 1, Math.max(dialog.entries.length - 1, 0)),
        };
        break;
      case 'PageUp':
        this.state.dialog = { ...dialog, selected: Math.max(dialog.selected - 10, 0) };
        break;
      case 'PageDown':
        this.state.dialog = {
          ...dialog,
          selected: Math.min(dialog.selected + 10, Math.max(dialog.entries.length - 1, 0)),
        };
        break;
      case 'Home':
        this.state.dialog = { ...dialog, selected: 0 };
        break;
      case 'End':
        this.state.dialog = { ...dialog, selected: Math.max(dialog.entries.length - 1, 0) };
        break;
      case 'Tab':
      case 'BackTab':
        if (fileInputs) {
          this.state.dialog = null;
          await this.openFiles(dialog.input === 'image' ? 'symbols' : 'image');
          return;
        }
        break;
      case 'w':
        if (fileInputs) {
          this.state.dialog = null;
          await this.openFiles(dialog.input);
          return;
        }
        break;
      case 'Left':
      case 'Backspace':
        await this.browse(dialog.input, dirname(dialog.root));
        return;
      case 'p':
        this.openInput(dialog.input);
        return;
      case ' ':
        if (dialog.input === 'symbols' && key.shift) {
          await this.acceptPath(dialog.input, dialog.root);
          return;
        }
        if (fileInputs) {
          const entry = dialog.entries[dialog.selected];
          if (entry) {
            if (!entry.directory || dialog.input === 'symbols') {
              await this.acceptPath(dialog.input, entry.path);
            } else {
              this.update({ status: '镜像目录用 Enter 打开；Space 选用镜像文件' });
            }
          }
          return;
        }
        await this.acceptPath(dialog.input, dialog.root);
        return;
      case 'd':
        if (fileInputs) {
          const entry = dialog.entries[dialog.selected];
          if (entry) {
            this.state.backDialog = dialog;
            await this.viewAssetPath(entry.path, entry.kind === 'symbols' ? 'symbols' : 'image');
            return;
          }
        }
        break;
      case 'Enter':
      case 'Right': {
        const entry = dialog.entries[dialog.selected];
        if (!entry) {
          return;
        }
        if (entry.directory) {
          await this.browse(dialog.input, entry.path);
        } else if (fileInputs) {
          if (!this.enterWorkbench()) {
            this.state.dialog = dialog;
            this.emit();
          }
        } else {
          await this.acceptPath(dialog.input, entry.path);
        }
        return;
      }
      default:
        break;
    }
    this.emit();
  }

  private async settingsKey(dialog: Dialog, token: string): Promise<void> {
    if (dialog.kind !== 'settings') {
      return;
    }
    switch (token) {
      case 'Up':
        this.state.dialog = { ...dialog, selected: Math.max(dialog.selected - 1, 0) };
        this.emit();
        return;
      case 'Down':
        this.state.dialog = { ...dialog, selected: Math.min(dialog.selected + 1, 4) };
        this.emit();
        return;
      case 'Enter':
        this.state.dialog = null;
        switch (dialog.selected) {
          case 0:
            await this.openFiles('imageDirectory');
            return;
          case 1:
            await this.openFiles('symbolsDirectory');
            return;
          case 2:
            await this.openFiles('exportDirectory');
            return;
          case 3:
            this.openInput('pageSize');
            return;
          default: {
            const settings = {
              ...this.state.settings,
              remote_symbols: !this.state.settings.remote_symbols,
            };
            await this.persistSettings(settings);
            this.state.dialog = dialog;
            this.emit();
            return;
          }
        }
      default:
        return;
    }
  }

  private async cacheKey(dialog: Dialog, token: string): Promise<void> {
    if (dialog.kind !== 'cache') {
      return;
    }
    switch (token) {
      case 'Up':
        this.state.dialog = { ...dialog, selected: Math.max(dialog.selected - 1, 0), confirm: false };
        this.emit();
        return;
      case 'Down':
        this.state.dialog = {
          ...dialog,
          selected: Math.min(dialog.selected + 1, this.hello.scopes.length - 1),
          confirm: false,
        };
        this.emit();
        return;
      case ' ':
      case 'Enter': {
        if (token === ' ' && dialog.confirm) {
          break;
        }
        const scope = this.hello.scopes[dialog.selected]?.id;
        if (!scope) {
          return;
        }
        const scopes = dialog.scopes.includes(scope)
          ? dialog.scopes.filter((value) => value !== scope)
          : [...dialog.scopes, scope];
        this.state.dialog = { ...dialog, scopes, confirm: false };
        this.emit();
        return;
      }
      default:
        break;
    }
    if (token === 'Enter' && dialog.confirm) {
      if (dialog.scopes.length === 0) {
        return;
      }
      this.state.dialog = null;
      await this.runWork({ kind: 'clear', scopes: dialog.scopes });
      return;
    }
    this.emit();
  }

  private async commandsKey(dialog: Dialog, token: string, input: string): Promise<void> {
    if (dialog.kind !== 'commands') {
      return;
    }
    const matches = commandMatches(
      dialog.query,
      this.state.page,
      this.state.focus,
      this.state.page === 'assets' ? this.state.section : null,
    );
    switch (token) {
      case 'Backspace':
        this.state.dialog = { ...dialog, query: dialog.query.slice(0, -1), selected: 0 };
        this.emit();
        return;
      case 'Up':
        this.state.dialog = { ...dialog, selected: Math.max(dialog.selected - 1, 0) };
        this.emit();
        return;
      case 'Down':
        this.state.dialog = { ...dialog, selected: Math.min(dialog.selected + 1, Math.max(matches.length - 1, 0)) };
        this.emit();
        return;
      case 'Enter': {
        const chosen = matches[dialog.selected];
        this.state.dialog = null;
        this.emit();
        if (chosen) {
          await this.runCommand(chosen.command);
        }
        return;
      }
      default:
        if (input.length === 1) {
          this.state.dialog = { ...dialog, query: dialog.query + input, selected: 0 };
          this.emit();
        }
    }
  }

  private async pluginsKey(
    dialog: Dialog,
    token: string,
    key: Partial<KeyLike>,
    input: string,
  ): Promise<void> {
    if (dialog.kind !== 'plugins') {
      return;
    }
    const matches = pluginMatches(this.state, dialog.query);
    switch (token) {
      case 'Backspace':
        this.state.dialog = { ...dialog, query: dialog.query.slice(0, -1), selected: 0 };
        this.emit();
        return;
      case 'Up':
        this.state.dialog = { ...dialog, selected: Math.max(dialog.selected - 1, 0) };
        this.emit();
        return;
      case 'Down':
        this.state.dialog = { ...dialog, selected: Math.min(dialog.selected + 1, Math.max(matches.length - 1, 0)) };
        this.emit();
        return;
      case 'Enter': {
        const chosen = matches[dialog.selected];
        this.state.dialog = null;
        this.emit();
        if (chosen) {
          if (chosen.dump) {
            this.openDump(chosen.name, false);
          } else {
            await this.activatePlugin(chosen.name);
          }
        }
        return;
      }
      default:
        if (input.length === 1 && !key.ctrl) {
          this.state.dialog = { ...dialog, query: dialog.query + input, selected: 0 };
          this.emit();
        }
    }
  }

  private async linksKey(dialog: Dialog, token: string): Promise<void> {
    if (dialog.kind !== 'links') {
      return;
    }
    switch (token) {
      case 'Up':
        this.state.dialog = { ...dialog, selected: Math.max(dialog.selected - 1, 0) };
        this.emit();
        return;
      case 'Down':
        this.state.dialog = {
          ...dialog,
          selected: Math.min(dialog.selected + 1, Math.max(dialog.matches.length - 1, 0)),
        };
        this.emit();
        return;
      case ' ':
      case 'Enter': {
        const candidate = dialog.matches[dialog.selected];
        this.state.dialog = null;
        this.emit();
        if (candidate) {
          await this.runWork({ kind: 'download', candidate });
        }
        return;
      }
      case 'd': {
        const candidate = dialog.matches[dialog.selected];
        if (candidate) {
          this.state.backDialog = { ...dialog };
          this.state.dialog = { kind: 'remoteDetail', candidate, scroll: 0 };
          this.emit();
        }
        return;
      }
      default:
        return;
    }
  }

  private async assetDetailKey(dialog: Dialog, token: string): Promise<void> {
    if (dialog.kind !== 'assetDetail') {
      return;
    }
    if (token === 'Enter') {
      this.state.dialog = null;
      this.enterWorkbench();
      return;
    }
    if (token === ' ') {
      const back = this.state.backDialog;
      this.state.dialog = null;
      if (back && back.kind === 'symbols') {
        this.state.dialog = back;
        this.state.backDialog = null;
        await this.dialogKey(' ', {});
        return;
      }
      await this.acceptPath(dialog.asset.kind === 'image' ? 'image' : 'symbols', dialog.asset.path);
      return;
    }
    const maximum = Math.max(
      this.wrapCount(assetDetailText(this.state, dialog.asset), this.state.hits.popup.width - 2) -
        Math.max(this.state.hits.popup.height - 2, 1),
      0,
    );
    this.state.dialog = { ...dialog, scroll: this.scrollAmount(token, dialog.scroll, maximum) };
    this.emit();
  }

  private async remoteDetailKey(dialog: Dialog, token: string): Promise<void> {
    if (dialog.kind !== 'remoteDetail') {
      return;
    }
    switch (token) {
      case 'Enter':
        this.state.dialog = null;
        this.enterWorkbench();
        return;
      case ' ':
        if (this.state.image === null) {
          this.update({ status: '请先用 Space 选用镜像；w 可独立下载' });
          return;
        }
        this.state.backDialog = null;
        this.state.dialog = null;
        await this.runWork({ kind: 'download', candidate: dialog.candidate });
        return;
      case 'w':
        this.state.dialog = null;
        await this.runWork({ kind: 'catalogDownload', candidate: dialog.candidate });
        return;
      case 'L': {
        if (this.state.busy) {
          this.update({ status: '任务执行中，请等待或取消' });
          return;
        }
        const saved = this.state.downloads.get(dialog.candidate.url);
        if (!saved) {
          return;
        }
        this.state.localOnlyMatches = false;
        this.state.dialog = null;
        this.state.backDialog = null;
        await this.switchSection('symbols');
        this.focusAsset('symbols', saved);
        this.emit();
        return;
      }
      case 'c':
        await this.cancel();
        return;
      default: {
        const maximum = Math.max(
          this.wrapCount(remoteDetailText(this.state, dialog.candidate), this.state.hits.popup.width - 2) -
            Math.max(this.state.hits.popup.height - 5, 1),
          0,
        );
        this.state.dialog = { ...dialog, scroll: this.scrollAmount(token, dialog.scroll, maximum) };
        this.emit();
      }
    }
  }

  private async inputKey(
    dialog: Dialog,
    token: string,
    input: string,
  ): Promise<void> {
    if (dialog.kind !== 'input') {
      return;
    }
    if (token === 'Enter') {
      const value = dialog.text.trim();
      if (value === '' && dialog.input !== 'search' && dialog.input !== 'assetsSearch') {
        this.update({ status: '路径不能为空' });
        return;
      }
      const path = expandHome(value);
      switch (dialog.input) {
        case 'image':
        case 'symbols': {
          if (this.state.busy) {
            await this.cancel();
            this.state.pendingPath = { input: dialog.input, path };
            this.update({ status: '正在取消；随后选用新对象并重新准备' });
            return;
          }
          const assetKind: AssetKind = dialog.input === 'image' ? 'image' : 'symbols';
          let imported: string;
          try {
            imported = (await this.engine.select(assetKind, path)).path;
          } catch (error) {
            this.update({ status: `导入失败: ${(error as Error).message}` });
            return;
          }
          if (dialog.input === 'image') {
            this.invalidateSource();
            this.state.symbols = '';
            this.state.choice = null;
            this.state.image = imported;
          } else {
            this.invalidateSymbols();
            this.state.symbols = imported;
          }
          await this.refreshAssets();
          this.focusAsset(assetKind, imported);
          this.state.dialog = null;
          this.state.pendingWork = null;
          this.state.pendingExecution = null;
          this.state.page = 'assets';
          this.state.symbolSource = 'symbols';
          this.update({ status: '路径已加载并选用；x 进入分析' });
          if (this.state.image) {
            await this.prepareSelectedImage();
          }
          return;
        }
        case 'pageSize': {
          const auto = value.toLowerCase() === 'auto' || value === '自动';
          const size = auto ? 0 : Number(value);
          if (!auto && (!Number.isInteger(size) || size < 1 || size > 10000)) {
            this.update({ status: '请输入 auto、0 或 1–10000 的行数' });
            return;
          }
          this.state.row = 0;
          this.state.dialog = null;
          await this.persistSettings({ ...this.state.settings, page_size: size });
          this.emit();
          return;
        }
        case 'imageDirectory':
        case 'symbolsDirectory':
        case 'exportDirectory': {
          try {
            await (await import('node:fs/promises')).mkdir(path, { recursive: true });
          } catch (error) {
            this.update({ status: `创建目录失败: ${(error as Error).message}` });
            return;
          }
          const settings = { ...this.state.settings };
          if (dialog.input === 'imageDirectory') {
            settings.image_dir = path;
          } else if (dialog.input === 'symbolsDirectory') {
            settings.symbols = path;
          } else {
            settings.export_dir = path;
            settings.history_dir = path;
          }
          this.state.dialog = null;
          await this.persistSettings(settings);
          await this.refreshAssets();
          return;
        }
        case 'search':
          this.state.query = value;
          this.state.row = 0;
          this.state.dialog = null;
          this.emit();
          return;
        case 'assetsSearch':
          this.state.assetQueries[sectionSlot(this.state.section)] = value;
          this.state.assetRows[sectionSlot(this.state.section)] = 0;
          this.state.dialog = null;
          if (
            this.state.section === 'remote' &&
            this.state.remoteCatalog &&
            this.state.remote.length === 0 &&
            !this.state.busy
          ) {
            await this.runWork({ kind: 'catalog', query: '', refresh: false });
          }
          this.emit();
          return;
        case 'export': {
          const current = result(this.state);
          this.state.dialog = null;
          if (!current) {
            this.emit();
            return;
          }
          const rows = viewIndex(this.state).filtered.map((index) => current.rows[index] as string[]);
          await this.runTask(
            '导出结果',
            (progress) => this.engine.export({ path, result: current, rows }, progress),
            ({ path: written, rows: count }) => {
              this.state.status = `已导出 ${count} 条: ${written}${current.complete ? '' : ' (部分/历史结果)'}`;
            },
          );
          return;
        }
        case 'history': {
          if (this.state.busy) {
            this.update({ status: '请先取消任务' });
            return;
          }
          this.state.dialog = null;
          await this.runTask(
            '加载导出记录',
            (progress) => this.engine.history(path, progress),
            ({ result: loaded }) => {
              this.state.historyRevision += 1;
              this.state.history = loaded;
              this.state.page = 'analysis';
              this.resetView();
              this.state.focus = 'content';
              this.state.status = '导出记录：历史内容，未重新验证镜像';
            },
          );
          return;
        }
      }
      return;
    }
    const editor = editInput(
      { text: dialog.text, cursor: dialog.cursor, selected: dialog.selected },
      token,
      input,
    );
    this.state.dialog = { ...dialog, text: editor.text, cursor: editor.cursor, selected: editor.selected };
    if (dialog.input === 'search') {
      this.state.query = editor.text;
      this.state.row = 0;
    } else if (dialog.input === 'assetsSearch') {
      this.state.assetQueries[sectionSlot(this.state.section)] = editor.text;
      this.state.assetRows[sectionSlot(this.state.section)] = 0;
    }
    this.emit();
  }

  private async sortKey(dialog: Dialog, token: string): Promise<void> {
    if (dialog.kind !== 'sort') {
      return;
    }
    const count = result(this.state)?.columns.length ?? 0;
    switch (token) {
      case 'Up':
        this.state.dialog = { ...dialog, column: Math.max(dialog.column - 1, 0) };
        this.emit();
        return;
      case 'Down':
        this.state.dialog = { ...dialog, column: Math.min(dialog.column + 1, Math.max(count - 1, 0)) };
        this.emit();
        return;
      case 'Enter':
        this.state.descending = this.state.sort === dialog.column && !this.state.descending;
        this.state.sort = dialog.column;
        this.state.row = 0;
        this.state.dialog = null;
        this.emit();
        return;
      default:
        return;
    }
  }

  private async symbolsKey(dialog: Dialog, token: string): Promise<void> {
    if (dialog.kind !== 'symbols') {
      return;
    }
    switch (token) {
      case 'Up':
        this.state.dialog = { ...dialog, selected: Math.max(dialog.selected - 1, 0) };
        this.emit();
        return;
      case 'Down':
        this.state.dialog = {
          ...dialog,
          selected: Math.min(dialog.selected + 1, Math.max(dialog.labels.length - 1, 0)),
        };
        this.emit();
        return;
      case ' ':
      case 'Enter': {
        const label = dialog.labels[dialog.selected];
        this.state.dialog = null;
        if (!label) {
          this.emit();
          return;
        }
        if (this.state.choice !== label) {
          for (const key of [...this.state.results.keys()]) {
            if (key !== 'banners') {
              this.state.results.delete(key);
            }
          }
          this.state.resultRequests.clear();
          this.state.views.clear();
          this.state.historyRevision += 1;
          this.state.history = null;
          this.resetView();
        }
        this.state.objectVersion += 1;
        this.state.choice = label;
        if (this.state.symbolRetry) {
          const snapshot = this.state.symbolRetry;
          this.state.symbolRetry = null;
          await this.startSnapshot(snapshot);
          return;
        }
        const candidate = this.state.preparationCandidates.find((entry) => entry.label === label);
        if (candidate) {
          this.state.symbols = candidate.path;
          this.state.preparation = 'ready';
          this.update({ status: '可开始分析，运行时验证页表' });
        } else {
          await this.requestAnalysis(false);
        }
        return;
      }
      case 'd': {
        const candidate = this.state.preparationCandidates.find((entry) => entry.label === dialog.labels[dialog.selected]);
        this.state.backDialog = dialog;
        this.state.dialog = null;
        await this.viewAssetPath(candidate?.path ?? this.state.symbols, 'symbols');
        return;
      }
      default:
        return;
    }
  }

  /* ---------------------------------------------------------------- */
  /* Detail text helpers used by the renderer                          */
  /* ---------------------------------------------------------------- */

  assetText(): string {
    if (this.state.section === 'remote') {
      const candidate = selectedRemote(this.state);
      return candidate
        ? remoteDetailText(this.state, candidate)
        : 'g 获取或刷新完整符号索引。\n/ 输入关键词筛选；选中条目后按 d 查看详情，Enter 进入分析控制台，w 下载。\nM 按当前镜像 banner 精确匹配。';
    }
    const asset = selectedAsset(this.state);
    if (!asset) {
      return '按 a 导入路径，或将文件放入配置的 images／symbols 目录。\n\nSpace 选用；Enter 进入分析控制台；d 详情；Delete 移出清单，原文件保留。';
    }
    return assetDetailText(this.state, asset);
  }

  visibleRows(): string[][] {
    const index = viewIndex(this.state);
    const rows: string[][] = [];
    for (let position = 0; position < index.visible.length; position += 1) {
      const row = visibleRow(this.state, index, position);
      if (row) {
        rows.push(row);
      }
    }
    return rows;
  }

  fail(status: string): void {
    this.state.lastError = status;
    this.update({ status });
  }

  /* ---------------------------------------------------------------- */
  /* Render bookkeeping                                                */
  /* ---------------------------------------------------------------- */

  setHits(hits: HitMap): void {
    this.state.hits = hits;
  }

  resize(columns: number, rows: number): void {
    this.state.columns = columns;
    this.state.rows = rows;
    if (this.state.focus === 'detail' && !this.state.inspector) {
      this.state.focus = 'content';
    }
    this.emit();
  }

  /** Plugin list plus `dump`, the menu the navigation pane draws. */
  menuEntries(): { label: string; plugin: string | null; category: string }[] {
    const plugins = navigationPlugins(this.state);
    return [
      ...plugins.map((plugin) => ({
        label: pluginLabel(plugin, plugin.name),
        plugin: plugin.name,
        category: plugin.category,
      })),
      { label: 'dump', plugin: null, category: 'Dump' },
    ];
  }

  plugins(): typeof this.hello.plugins {
    return this.hello.plugins;
  }

  scopes(): typeof this.hello.scopes {
    return this.hello.scopes;
  }

  get menuIndex(): number {
    return this.state.menu;
  }

  statusText(): string {
    const seconds = this.state.startedAt === null ? null : Math.floor((Date.now() - this.state.startedAt) / 1000);
    if (this.state.progress !== null && seconds !== null) {
      return `${this.state.progress}% · ${seconds}s · ${this.state.status}`;
    }
    return seconds === null ? this.state.status : `${this.state.status} · ${seconds}s · Esc 取消`;
  }

  assetActions(): { label: string; key: string }[] {
    return assetActions(this.state.section);
  }

  toolbarActions(): { label: string; key: string }[] {
    return toolbarActions(this.state.section, this.state.busy);
  }

  footerActions(): { label: string; key: string }[] {
    return footerActions(this.state.focus);
  }

  settingsLabels(): string[] {
    return settingsLabels(this.state);
  }

  availableCommands(query: string): { label: string; key: string; command: Command }[] {
    return commandMatches(query, this.state.page, this.state.focus, this.state.page === 'assets' ? this.state.section : null).map(
      (entry) => ({ label: entry.label, key: entry.key, command: entry.command }),
    );
  }

  parameterFields(advanced: boolean): number[] {
    return parameterFields(this.state, advanced);
  }

  /** Whether the action bound to `key` is unavailable right now. */
  commandDisabledForKey(key: string): string | null {
    const command = this.resolveKey(key);
    return command ? commandDisabled(this.state, command) : null;
  }

  dialogWidth(dialog: Dialog, columns: number): number {
    return dialogWidth(this.state, dialog, columns);
  }

  dialogHeight(dialog: Dialog, rows: number): number {
    return dialogHeight(this.state, dialog, rows);
  }

  filesTitle(input: InputKind): string {
    return filesTitle(input);
  }

  inputTitle(input: InputKind): string {
    return inputTitle(input);
  }

  paste(value: string): void {
    const dialog = this.state.dialog;
    if (!dialog) {
      return;
    }
    const next = pasteInto(dialog, value);
    if (next) {
      this.state.dialog = next;
      if (next.kind === 'input') {
        if (next.input === 'search') {
          this.state.query = next.text;
          this.state.row = 0;
        } else if (next.input === 'assetsSearch') {
          this.state.assetQueries[sectionSlot(this.state.section)] = next.text;
          this.state.assetRows[sectionSlot(this.state.section)] = 0;
        }
      }
      this.emit();
    }
  }

  bannerLine(): string {
    const banners = this.state.results.get('banners');
    if (!banners) {
      return '尚未识别；选用镜像后自动识别';
    }
    const candidates = bannerCandidates(banners);
    return candidates[0]?.[1] ?? '尚未识别；选用镜像后自动识别';
  }

  bannerCandidates(): string[][] {
    const banners = this.state.results.get('banners');
    return banners ? bannerCandidates(banners) : [];
  }

  resultStateLabel(): string {
    const current = result(this.state);
    if (!current) {
      return '';
    }
    return current.historical ? '历史' : current.complete ? '完整' : '部分';
  }

  shortPlugin(name = this.state.plugin): string {
    return shortPlugin(name);
  }

  selectionSummary(): { filtered: number; total: number } {
    const current = result(this.state);
    return {
      filtered: viewIndex(this.state).filtered.length,
      total: current?.rows.length ?? 0,
    };
  }

  cacheTotals(entries: CacheEntry[], scopes: ScopeId[]): { files: number; bytes: number } {
    const selected = entries.filter((entry) => scopes.includes(entry.scope) || scopes.includes('all'));
    return {
      files: selected.length,
      bytes: selected.reduce((total, entry) => total + entry.bytes, 0),
    };
  }

  truncate(value: string, columns: number): string {
    return truncate(value, columns);
  }

  compareValues(left: string, right: string): number {
    return compareValues(left, right);
  }

  /** Draw one frame's hit map, then let the renderer commit it. */
  commitHits(hits: HitMap): void {
    this.state.hits = hits;
  }

  /** Wheel scrolling: three list rows, or one detail line, per notch. */
  async wheel(direction: -1 | 1, x?: number, y?: number): Promise<void> {
    if (this.state.columns < 60 || this.state.rows < 16) return;
    if (!this.state.dialog && x !== undefined && y !== undefined) {
      const layout = this.layout();
      if (layout.inspector && inside(layout.inspector, x, y)) this.state.focus = 'detail';
      else if (layout.menu && inside(layout.menu, x, y)) this.state.focus = 'navigation';
      else if (layout.content && inside(layout.content, x, y)) this.state.focus = 'content';
      else {
        const pane = layout.panes.find((entry) => inside(entry.list, x, y));
        if (!pane) return;
        this.state.section = pane.section;
        this.state.focus = 'navigation';
      }
    }
    if (!this.state.dialog && this.state.page === 'analysis' && this.state.focus === 'detail') {
      this.scrollDetail(direction === -1 ? 'Up' : 'Down');
      return;
    }
    if (this.state.dialog) {
      await this.dialogKey(direction === -1 ? 'Up' : 'Down', {});
      return;
    }
    for (let step = 0; step < 3; step += 1) {
      await this.runKeyToken(direction === -1 ? 'Up' : 'Down');
    }
  }

  private async runKeyToken(token: string): Promise<void> {
    const command = this.resolveKey(token);
    if (command) {
      await this.runCommand(command);
      return;
    }
    const state = this.state;
    if (state.page === 'assets') {
      const slot = sectionSlot(state.section);
      state.assetRows[slot] = Math.max(
        0,
        Math.min(
          state.assetRows[slot] + (token === 'Down' ? 1 : -1),
          Math.max((state.section === 'remote' ? remoteList(state).length : assetListFor(state, state.section).length) - 1, 0),
        ),
      );
      this.emit();
      return;
    }
    if (state.focus === 'navigation') {
      state.menu = Math.max(0, Math.min(state.menu + (token === 'Down' ? 1 : -1), menuItems(state).length - 1));
    } else if (state.focus === 'content') {
      state.row = Math.max(
        0,
        Math.min(state.row + (token === 'Down' ? 1 : -1), Math.max(viewIndex(state).visible.length - 1, 0)),
      );
    }
    this.emit();
  }

  currentRowValue(): string[] | null {
    return visibleRow(this.state, viewIndex(this.state), this.state.row);
  }

  /** Public repaint request for handlers that mutate state directly. */
  emitChange(): void {
    this.emit();
  }

  async shutdown(): Promise<void> {
    await this.engine.close();
    this.emit();
  }

  /** Immediate exit, bypassing the "press q twice" guard. */
  async quitNow(): Promise<void> {
    for (const handler of this.quitHandlers) {
      handler();
    }
  }

  remoteCount(): number {
    return remoteList(this.state).length;
  }

  assetCountFor(section: Section): number {
    return assetListFor(this.state, section).length;
  }

  visibleCount(): number {
    return viewIndex(this.state).visible.length;
  }

  menuLength(): number {
    return menuItems(this.state).length;
  }

  treeVisible(): boolean {
    return treeColumns(this.state) !== null;
  }

  horizontalScroll(delta: number): void {
    this.state.horizontal = Math.max(0, Math.min(this.state.horizontal + delta, 2048));
    this.emit();
  }

  scrollDetail(token: string): void {
    const text = rowDetailText(this.state);
    const region = this.layout().inspector;
    if (!region) return;
    const maximum = Math.max(wrapLines(text, Math.max(region.width - 2, 1)).length - (region.height - 2), 0);
    this.state.detailScroll = Math.min(this.scrollAmount(token, this.state.detailScroll, maximum), maximum);
    this.emit();
  }

  /** Next focusable region, honouring which panes the current layout draws. */
  nextFocus(back: boolean): Focus {
    const layout = this.layout();
    const overlay = this.state.inspector && !this.inspectorAvailable();
    const regions: Focus[] = overlay ? ['detail'] : ['context', 'navigation', 'content'];
    if (!overlay && layout.inspector) regions.push('detail');
    const current = Math.max(regions.indexOf(this.state.focus), 0);
    const step = back ? (current + regions.length - 1) % regions.length : (current + 1) % regions.length;
    return regions[step] as Focus;
  }

  get image(): string | null {
    return this.state.image;
  }

  get symbols(): string {
    return this.state.symbols;
  }
}

/* ------------------------------------------------------------------ */
/* Module helpers                                                     */
/* ------------------------------------------------------------------ */

export function expandHome(path: string): string {
  if (path.startsWith('~/') && process.env.HOME) {
    return `${process.env.HOME}/${path.slice(2)}`;
  }
  return path;
}

export function dirname(path: string): string {
  const trimmed = path.replace(/\/+$/u, '');
  const at = trimmed.lastIndexOf('/');
  if (at <= 0) {
    return at === 0 ? '/' : '.';
  }
  return trimmed.slice(0, at);
}

export { actionOf, assetActions, footerActions, toolbarActions, commandDisabled, pluginMatches, navigationPlugins, menuItems };
