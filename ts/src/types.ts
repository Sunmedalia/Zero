/**
 * Wire types for the `zero tui-backend` JSON-RPC stream.
 *
 * Everything the engine reports is defined here once; the UI never re-declares
 * a shape it receives, so a field rename in Rust fails `tsc` instead of
 * silently rendering `undefined`.
 */

export type Os = 'auto' | 'linux' | 'windows';
export type Arch = 'auto' | 'x86' | 'x64' | 'arm64';
export type AssetKind = 'image' | 'symbols';
export type ScopeId = 'results' | 'identification' | 'images' | 'symbols' | 'dumps' | 'all';

export interface PluginDescriptor {
  name: string;
  label: string;
  columns: string[];
  widths: number[];
  category: string;
  os: 'linux' | 'windows';
  dump: boolean;
  tree: boolean;
  description: string;
}

export interface Settings {
  layout_version: number;
  image_dir: string;
  page_size: number;
  export_dir: string;
  symbols: string;
  history_dir: string;
  enable_cache: boolean;
  remote_symbols: boolean;
  resources: {
    page_cache_entries: number;
    scan_cache_bytes: number;
    snapshot_memory_bytes: number;
    snapshot_count: number;
    snapshot_idle_seconds: number;
  };
}

export interface Hello {
  instance: string;
  root: string;
  cache: string;
  version: string;
  engine: string;
  settings: Settings;
  plugins: PluginDescriptor[];
  scopes: { id: ScopeId; label: string }[];
  repository: string;
  platform: 'unix' | 'windows';
}

export interface Asset {
  id: string;
  path: string;
  name: string;
  kind: AssetKind;
  bytes: number;
  available: boolean;
  directory: boolean;
  format: string;
  origin: string;
  stamp: string | null;
  /** Repository URL recorded beside a downloaded or generated symbol. */
  source_url: string | null;
}

export interface RemoteMatch {
  banner: string;
  path: string;
  url: string;
}

export interface Results {
  plugin: string;
  columns: string[];
  rows: string[][];
  complete: boolean;
  diagnostics: string[];
  banner: string;
  symbol: string;
  page_table: number;
  historical: boolean;
  system: string;
  kernel_identity: unknown;
}

export interface Options {
  os: Os;
  arch: Arch;
  pid: number | null;
  /**
   * Kernel virtual address as a decimal string.
   *
   * Kernel addresses exceed `Number.MAX_SAFE_INTEGER`, so they are carried as
   * strings end to end; formatting for display goes through `formatAddress`.
   */
  hive: string | null;
  key: string;
  /** Byte pattern for the memory scans; see `--pattern`. */
  pattern: string | null;
  pagefiles: { index: number; path: string }[];
  swapfile: string | null;
}

export interface DumpSpec {
  plugin: string;
  pid: number;
  directory: string;
  /** Addresses as decimal strings, for the same reason as `Options.hive`. */
  start: string | null;
  end: string | null;
}

export interface BrowseEntry {
  path: string;
  name: string;
  directory: boolean;
  kind: 'image' | 'symbols' | 'file';
}

export interface BrowseResult {
  root: string;
  entries: BrowseEntry[];
}

export interface CacheEntry {
  path: string;
  scope: Exclude<ScopeId, 'all'>;
  bytes: number;
}

export interface ClearReport {
  removed: number;
  bytes: number;
  failures: string[];
}

export interface AnalyzeReply {
  choose?: string[];
  result?: Results;
}

export interface RemoteReply {
  matches: RemoteMatch[];
  catalog: boolean;
}

export interface MatchLocalReply {
  banner: Results;
  matched: { path: string; labels: string[] }[];
  diagnostics: string[];
}

export type TaskOp =
  | 'analyze'
  | 'dump'
  | 'identify'
  | 'matchLocal'
  | 'remote'
  | 'download'
  | 'generate'
  | 'inspectSymbols'
  | 'cacheClear'
  | 'export'
  | 'history';

/** Launch flags forwarded by `zero` to the interface. */
export interface Launch {
  offline: boolean;
  image: string | null;
  symbols: string | null;
  os: Os;
  arch: Arch;
  pagefiles: { index: number; path: string }[];
  swapfile: string | null;
  hive: string | null;
  key: string;
}
