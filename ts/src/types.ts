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
export type ScopeId = 'results' | 'exports' | 'identification' | 'images' | 'symbols' | 'dumps' | 'all';

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
  theme: string;
  /** GitHub repository of the remote symbol index and ISF downloads. */
  symbol_repository: string;
  /**
   * Reuse the image digest an earlier session recorded while the file's
   * metadata and content sample are unchanged; off means a full pass per session.
   */
  reuse_recorded_digest: boolean;
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
  /**
   * Images only: the system and kernel banners / PDB identities an earlier
   * identification bound to this file, while its metadata is unchanged.
   */
  identity?: { system: 'linux' | 'windows'; kernels: string[] } | null;
  /** Images only: the SHA256 the last full verification recorded, while the file is unchanged. */
  digest?: string | null;
}

/** The image's content verified for this backend session. */
export interface VerifyReply {
  digest: string;
  /** False when this session had already verified it, or settings reused a recorded digest. */
  computed: boolean;
  seconds: number;
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
  /** Modification time, seconds since the Unix epoch. */
  modified: number | null;
  /** Analysis results only: the header naming the image and plugin. */
  result?: CacheSummary | null;
}

/** Header of a cached analysis result. Empty fields mean an entry from before it was recorded. */
export interface CacheSummary {
  /** SHA256 of the image content the result was computed from. */
  image: string;
  /** Path the image was analysed from. */
  source: string;
  plugin: string;
  complete: boolean;
  rows: number;
  diagnostics: number;
}

/** One recorded export; the engine keeps a verified copy beside it. */
export interface ExportRecord {
  key: string;
  recorded: number;
  destination: string;
  format: 'csv' | 'json';
  plugin: string;
  rows: number;
  bytes: number;
  sha256: string;
  complete: boolean;
  diagnostics: number;
  banner: string;
  symbol: string;
}

export interface CacheInventory {
  entries: CacheEntry[];
  records: ExportRecord[];
}

export interface ExportReply {
  path: string;
  rows: number;
  record: ExportRecord | null;
  record_error: string | null;
}

export interface ClearReport {
  removed: number;
  bytes: number;
  failures: string[];
}

export interface AnalyzeReply {
  choose?: string[];
  result?: Results;
  /** `cache` when the engine read the successful-result cache instead of analysing. */
  source?: 'cache' | 'fresh';
  /** The request included verifying a newly opened image's content digest. */
  prepared?: boolean;
}

export interface RemoteIndex {
  /** Banners of every system in the index file. */
  banners: number;
  /** Searchable Linux x86_64 / ARM64 entries. */
  entries: number;
  bytes: number;
  age_seconds: number | null;
}

export interface RemoteReply {
  matches: RemoteMatch[];
  catalog: boolean;
  /** Matches before the catalog page limit. */
  total?: number;
  index?: RemoteIndex | null;
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
  | 'cacheRemove'
  | 'record'
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
