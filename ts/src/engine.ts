/**
 * The engine surface the state machine depends on.
 *
 * Declared as an interface so the whole interface — preparation, dispatch,
 * dialogs, layout — can be exercised with an in-memory engine in tests. The
 * real implementation is {@link Backend}, which speaks JSON-RPC to the native
 * `zero tui-backend` process.
 */
import type {
  Asset,
  AssetKind,
  BrowseResult,
  CacheInventory,
  ClearReport,
  ExportReply,
  MatchLocalReply,
  RemoteMatch,
  RemoteReply,
  Results,
  Settings,
  VerifyReply,
} from './types.js';

export interface TaskEvent {
  message?: string;
  result?: unknown;
  error?: string;
  cancelled?: boolean;
}

export type TaskProgress = (event: TaskEvent) => void;

export interface AnalyzeArgs {
  image: string;
  symbols: string | null;
  plugin: string;
  symbol_choice: string | null;
  options: unknown;
  dump: unknown;
  no_cache: boolean;
}

export interface DumpArgs {
  image: string;
  symbols: string | null;
  symbol_choice: string | null;
  mode: 'process' | 'range' | 'elf' | 'pe' | 'vad' | 'dll' | 'module' | 'files';
  pid: number;
  directory: string;
  start: string | null;
  end: string | null;
  options: unknown;
}

export interface Engine {
  readonly busy: boolean;
  assets(): Promise<Asset[]>;
  select(kind: AssetKind, path: string): Promise<{ path: string }>;
  register(kind: AssetKind, path: string): Promise<{ path: string }>;
  remove(path: string): Promise<{ removed: string }>;
  browse(path: string, filter: string): Promise<BrowseResult>;
  cacheInventory(): Promise<CacheInventory>;
  saveSettings(settings: Settings): Promise<Settings>;
  historyList(): Promise<{ paths: string[] }>;
  symbolsCached(paths: string[]): Promise<{ cached: boolean[] }>;
  analyze(args: AnalyzeArgs, progress: TaskProgress): Promise<{ choose?: string[]; result?: Results }>;
  dump(args: DumpArgs, progress: TaskProgress): Promise<{ choose?: string[]; result?: Results }>;
  identify(image: string, progress: TaskProgress): Promise<{ banner: Results }>;
  matchLocal(image: string, paths: string[], progress: TaskProgress): Promise<MatchLocalReply>;
  /** Verify the image content (SHA256) once for this session; analysis reuses it. */
  verify(image: string, progress: TaskProgress): Promise<VerifyReply>;
  remote(
    args: {
      image?: string | null;
      query?: string;
      refresh?: boolean;
      catalog?: boolean;
      limit?: number;
      local_only?: boolean;
    },
    progress: TaskProgress,
  ): Promise<RemoteReply>;
  download(
    candidate: RemoteMatch,
    args: { image: string | null; catalog: boolean },
    progress: TaskProgress,
  ): Promise<{ path: string }>;
  generate(
    args: { image: string; kali: boolean; elf?: string; config?: string; tool?: string },
    progress: TaskProgress,
  ): Promise<{ path: string }>;
  inspectSymbols(path: string, progress: TaskProgress): Promise<{ text: string }>;
  cacheClear(scopes: string[], progress: TaskProgress): Promise<ClearReport>;
  /** Remove individual inventory entries; an export record goes with its copy. */
  cacheRemove(paths: string[], progress: TaskProgress): Promise<ClearReport>;
  /** Reopen a recorded export from its verified local copy. */
  record(key: string, progress: TaskProgress): Promise<{ result: Results }>;
  export(
    args: { path: string; result: Results; rows?: string[][] },
    progress: TaskProgress,
  ): Promise<ExportReply>;
  history(path: string, progress: TaskProgress): Promise<{ result: Results }>;
  cancel(): Promise<void>;
  close(): Promise<void>;
}
