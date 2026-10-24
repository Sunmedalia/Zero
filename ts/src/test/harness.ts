/**
 * Test harness: an in-memory engine plus a small fixture, so the state machine
 * can be driven without a terminal or a child process.
 */
import { App, type LaunchOptions } from '../app.js';
import type {
  AnalyzeArgs,
  DumpArgs,
  Engine,
  TaskProgress,
} from '../engine.js';
import type {
  Asset,
  BrowseResult,
  CacheEntry,
  CacheInventory,
  ClearReport,
  ExportRecord,
  ExportReply,
  Hello,
  MatchLocalReply,
  RemoteMatch,
  RemoteReply,
  Results,
  Settings,
} from '../types.js';

export const BANNER = 'Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 4.6.3) #1 SMP Debian 3.2.57-3+deb7u2';

export function results(overrides: Partial<Results> = {}): Results {
  return {
    plugin: 'pslist',
    columns: ['PID', 'Name'],
    rows: [['1', 'systemd']],
    complete: true,
    diagnostics: [],
    banner: '',
    symbol: '',
    page_table: 0,
    historical: false,
    system: 'linux',
    kernel_identity: null,
    ...overrides,
  };
}

export function bannerResults(): Results {
  return results({
    plugin: 'banners',
    columns: ['Offset', 'Banner'],
    rows: [['0x0000000000001000', BANNER]],
    system: 'linux',
  });
}

export function asset(overrides: Partial<Asset> = {}): Asset {
  return {
    id: 'abcdef123456',
    path: '/evidence/memory.raw',
    name: 'memory.raw',
    kind: 'image',
    bytes: 1048576,
    available: true,
    directory: false,
    format: 'RAW/LiME',
    origin: '项目',
    stamp: 'stamp',
    source_url: null,
    ...overrides,
  };
}

export function hello(settings: Partial<Settings> = {}): Hello {
  return {
    instance: 'test',
    root: '/evidence',
    cache: '/evidence/.zero/rust',
    version: '0.1.4',
    engine: '0.1.4-native-15',
    settings: {
      layout_version: 2,
      image_dir: 'images',
      page_size: 0,
      export_dir: 'exports',
      symbols: 'symbols',
      history_dir: 'exports',
      enable_cache: true,
      remote_symbols: false,
      theme: 'slate',
      resources: {
        page_cache_entries: 65536,
        scan_cache_bytes: 67108864,
        snapshot_memory_bytes: 134217728,
        snapshot_count: 8,
        snapshot_idle_seconds: 1800,
      },
      ...settings,
    },
    plugins: [
      {
        name: 'pslist',
        label: 'pslist',
        columns: ['PID', 'Name'],
        widths: [0, 0],
        category: 'Process',
        os: 'linux',
        dump: false,
        tree: false,
        description: '列出活动进程及其地址',
      },
      {
        name: 'lsmod',
        label: 'lsmod',
        columns: ['Name', 'Base', 'Size'],
        widths: [0, 18, 10],
        category: 'Kernel',
        os: 'linux',
        dump: false,
        tree: false,
        description: '列出已加载内核模块',
      },
      {
        name: 'pstree',
        label: 'pstree',
        columns: ['PID', 'TGID', 'PPID', 'Name', 'Address'],
        widths: [5, 5, 5, 0, 18],
        category: 'Process',
        os: 'linux',
        dump: false,
        tree: true,
        description: '按父进程关系浏览进程树',
      },
      {
        name: 'windows.printkey',
        label: 'windows.printkey',
        columns: ['Hive', 'Key', 'Value'],
        widths: [0, 0, 0],
        category: 'Files',
        os: 'windows',
        dump: false,
        tree: false,
        description: '读取指定 hive 中的注册表键',
      },
      {
        name: 'windows.pslist',
        label: 'windows.pslist',
        columns: ['PID', 'Name'],
        widths: [0, 0],
        category: 'Process',
        os: 'windows',
        dump: false,
        tree: false,
        description: '列出活动进程及其地址',
      },
      {
        name: 'procdump',
        label: 'procdump',
        columns: ['PID', 'File'],
        widths: [0, 0],
        category: 'Process',
        os: 'linux',
        dump: true,
        tree: false,
        description: '转储指定进程的可读内存',
      },
    ],
    scopes: [
      { id: 'results', label: '分析结果' },
      { id: 'exports', label: '导出记录' },
      { id: 'identification', label: '识别信息' },
      { id: 'images', label: '解压镜像' },
      { id: 'symbols', label: '符号／构建缓存' },
      { id: 'dumps', label: '进程转储' },
    ],
    repository: 'https://github.com/Abyss-W4tcher/volatility3-symbols',
    platform: 'unix',
  };
}

export function launch(overrides: Partial<LaunchOptions> = {}): LaunchOptions {
  return {
    image: null,
    symbols: null,
    offline: true,
    os: 'auto',
    arch: 'auto',
    pagefiles: [],
    swapfile: null,
    hive: null,
    key: '',
    pattern: null,
    ...overrides,
  };
}

export class MemoryEngine implements Engine {
  busy = false;
  assetsList: Asset[] = [];
  matchReply: MatchLocalReply = {
    banner: bannerResults(),
    matched: [],
    diagnostics: [],
  };
  remoteReply: RemoteReply = { matches: [], catalog: false };
  remoteCalls: { query?: string; catalog?: boolean; limit?: number }[] = [];
  cacheEntries: CacheEntry[] = [];
  cacheRecords: ExportRecord[] = [];
  removedPaths: string[] = [];
  clearedScopes: string[][] = [];
  openedRecords: string[] = [];
  exportRecord: ExportRecord | null = null;
  analyzeReply: { choose?: string[]; result?: Results } = { result: results() };
  analyzeCalls: AnalyzeArgs[] = [];
  cancelled = false;
  closed = false;
  exported: { path: string; rows: number } | null = null;
  clearReport: ClearReport = { removed: 0, bytes: 0, failures: [] };
  historyResult: Results = results();
  settings: Settings = hello().settings;

  assets(): Promise<Asset[]> {
    return Promise.resolve(this.assetsList);
  }

  select(): Promise<{ path: string }> {
    return Promise.resolve({ path: '' });
  }

  register(): Promise<{ path: string }> {
    return Promise.resolve({ path: '' });
  }

  remove(): Promise<{ removed: string }> {
    return Promise.resolve({ removed: '' });
  }

  browse(root: string): Promise<BrowseResult> {
    return Promise.resolve({ root, entries: [] });
  }

  cacheInventory(): Promise<CacheInventory> {
    return Promise.resolve({ entries: this.cacheEntries, records: this.cacheRecords });
  }

  saveSettings(settings: Settings): Promise<Settings> {
    this.settings = settings;
    return Promise.resolve(settings);
  }

  historyList(): Promise<{ paths: string[] }> {
    return Promise.resolve({ paths: [] });
  }

  symbolsCached(paths: string[]): Promise<{ cached: boolean[] }> {
    return Promise.resolve({ cached: paths.map(() => false) });
  }

  analyze(args: AnalyzeArgs): Promise<{ choose?: string[]; result?: Results }> {
    this.analyzeCalls.push(args);
    return Promise.resolve(this.analyzeReply);
  }

  dump(_args: DumpArgs): Promise<{ choose?: string[]; result?: Results }> {
    return Promise.resolve(this.analyzeReply);
  }

  identify(): Promise<{ banner: Results }> {
    return Promise.resolve({ banner: bannerResults() });
  }

  matchLocal(): Promise<MatchLocalReply> {
    return Promise.resolve(this.matchReply);
  }

  remote(args: { query?: string; catalog?: boolean; limit?: number }): Promise<RemoteReply> {
    this.remoteCalls.push(args);
    return Promise.resolve(this.remoteReply);
  }

  download(): Promise<{ path: string }> {
    return Promise.resolve({ path: '/evidence/symbols/downloaded.json.xz' });
  }

  generate(): Promise<{ path: string }> {
    return Promise.resolve({ path: '/evidence/symbols/generated.json.xz' });
  }

  inspectSymbols(): Promise<{ text: string }> {
    return Promise.resolve({ text: '符号详情' });
  }

  cacheClear(scopes: string[], progress: TaskProgress): Promise<ClearReport> {
    void progress;
    this.clearedScopes.push(scopes);
    return Promise.resolve(this.clearReport);
  }

  cacheRemove(paths: string[]): Promise<ClearReport> {
    this.removedPaths.push(...paths);
    return Promise.resolve(this.clearReport);
  }

  record(key: string): Promise<{ result: Results }> {
    this.openedRecords.push(key);
    return Promise.resolve({ result: this.historyResult });
  }

  export(args: { path: string; rows?: string[][] }): Promise<ExportReply> {
    const rows = args.rows?.length ?? 0;
    this.exported = { path: args.path, rows };
    return Promise.resolve({ path: args.path, rows, record: this.exportRecord, record_error: null });
  }

  history(): Promise<{ result: Results }> {
    return Promise.resolve({ result: this.historyResult });
  }

  cancel(): Promise<void> {
    this.cancelled = true;
    return Promise.resolve();
  }

  close(): Promise<void> {
    this.closed = true;
    return Promise.resolve();
  }
}

export async function app(options: {
  assets?: Asset[];
  launch?: Partial<LaunchOptions>;
  settings?: Partial<Settings>;
  engine?: MemoryEngine;
} = {}): Promise<{ app: App; engine: MemoryEngine }> {
  const engine = options.engine ?? new MemoryEngine();
  engine.assetsList = options.assets ?? [asset()];
  const instance = new App(engine, hello(options.settings), launch(options.launch));
  await instance.initialize();
  return { app: instance, engine };
}

export type { Engine, RemoteMatch };
