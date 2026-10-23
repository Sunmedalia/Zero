/**
 * JSON-RPC client for the native engine.
 *
 * One child process, one active task, one line per message. The client is the
 * only module that knows the wire format; everything above it speaks the
 * {@link Engine} interface, so tests can substitute an in-memory engine.
 */
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createInterface } from 'node:readline';
import type {
  Asset,
  AssetKind,
  BrowseResult,
  CacheEntry,
  ClearReport,
  Hello,
  MatchLocalReply,
  RemoteMatch,
  RemoteReply,
  Results,
  Settings,
} from './types.js';
import type { AnalyzeArgs, DumpArgs, Engine, TaskEvent, TaskProgress } from './engine.js';

class EngineError extends Error {}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
}

interface Completion {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  progress: TaskProgress;
}

export class RpcEngine implements Engine {
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly pending = new Map<number, Pending>();
  private sequence = 0;
  /**
   * The running task's id, or `null`.
   *
   * `starting` covers the window between sending `task.start` and receiving its
   * reply: a cancel during that window must not be dropped, because the task is
   * already running in the worker.
   */
  private taskId: string | null = null;
  private starting = false;
  private cancelRequested = false;
  private completion: Completion | null = null;
  private stderr = '';
  private closed = false;

  constructor(binary: string, cwd: string) {
    this.child = spawn(binary, ['tui-backend'], {
      cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env,
    });
    this.child.on('error', (error) => this.fail(error));
    this.child.on('exit', (code) => {
      if (!this.closed) {
        const detail = this.stderr.trim();
        this.fail(new EngineError(`引擎已退出（${code ?? 'signal'}）${detail ? `：${detail}` : ''}`));
      }
    });
    this.child.stderr.on('data', (chunk: Buffer) => {
      this.stderr = (this.stderr + chunk.toString('utf8')).slice(-4096);
    });
    createInterface({ input: this.child.stdout }).on('line', (line) => this.receive(line));
  }

  private fail(error: Error): void {
    for (const pending of this.pending.values()) {
      pending.reject(error);
    }
    this.pending.clear();
    this.starting = false;
    this.taskId = null;
    if (this.completion) {
      const completion = this.completion;
      this.completion = null;
      completion.reject(error);
    }
  }

  private receive(line: string): void {
    let message: {
      id?: unknown;
      method?: unknown;
      params?: unknown;
      result?: unknown;
      error?: { message?: string };
    };
    try {
      message = JSON.parse(line) as typeof message;
    } catch {
      return;
    }
    if (typeof message.method === 'string') {
      const params = (message.params ?? {}) as Record<string, unknown>;
      // A fast task (a cache hit) can report completion before the `task.start`
      // reply is processed, especially when both lines arrive in one read. The
      // id is only known from that reply, so a notification is accepted while
      // the start is still in flight; otherwise its result would be dropped and
      // the interface would stay busy forever.
      const current = params.id === this.taskId || (this.starting && this.taskId === null);
      if (!current || !this.completion) {
        return;
      }
      const completion = this.completion;
      switch (message.method) {
        case 'task.progress':
          completion.progress({ message: String(params.message ?? '') });
          return;
        case 'task.done':
          this.completion = null;
          this.taskId = null;
          this.starting = false;
          this.cancelRequested = false;
          completion.resolve(params.result);
          void this.call('task.finish').catch(() => undefined);
          return;
        default:
          this.completion = null;
          this.taskId = null;
          this.starting = false;
          this.cancelRequested = false;
          completion.reject(new EngineError(String(params.message ?? '任务失败')));
          void this.call('task.finish').catch(() => undefined);
          return;
      }
    }
    const id = Number(message.id);
    const pending = this.pending.get(id);
    if (!pending) {
      return;
    }
    this.pending.delete(id);
    if (message.error) {
      pending.reject(new EngineError(message.error.message ?? '未知错误'));
    } else {
      pending.resolve(message.result);
    }
  }

  private call<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    if (this.closed) {
      return Promise.reject(new EngineError('引擎已关闭'));
    }
    const id = ++this.sequence;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (value: unknown) => void, reject });
      this.child.stdin.write(
        `${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`,
        (error) => {
          if (error) {
            this.pending.delete(id);
            reject(error);
          }
        },
      );
    });
  }

  get busy(): boolean {
    return this.taskId !== null || this.starting;
  }

  /**
   * Run one task. The completion handler is installed before `task.start` is
   * sent, because a fast task can finish before the start reply arrives.
   */
  private task<T>(
    op: string,
    args: Record<string, unknown>,
    progress: TaskProgress,
  ): Promise<T> {
    if (this.busy) {
      return Promise.reject(new EngineError('任务执行中，请等待或取消'));
    }
    return new Promise<T>((resolve, reject) => {
      const completion: Completion = {
        resolve: resolve as (value: unknown) => void,
        reject,
        progress,
      };
      this.completion = completion;
      this.starting = true;
      this.cancelRequested = false;
      void this.call<{ task: string }>('task.start', { op, args }).then(
        (started) => {
          // The task already settled before this reply arrived; `receive` owns
          // that completion and a late reply must not resurrect its state.
          if (this.completion !== completion) {
            return;
          }
          this.taskId = started.task;
          this.starting = false;
          // A cancel that arrived before the reply is applied now, so the
          // worker stops at its next checkpoint instead of running to the end.
          if (this.cancelRequested) {
            void this.call('task.cancel', { id: started.task }).catch(() => undefined);
          }
        },
        (error: unknown) => {
          if (this.completion !== completion) {
            return;
          }
          this.completion = null;
          this.starting = false;
          reject(error instanceof Error ? error : new EngineError(String(error)));
        },
      );
    });
  }

  hello(): Promise<Hello> {
    return this.call<Hello>('hello');
  }

  assets(): Promise<Asset[]> {
    return this.call<Asset[]>('assets');
  }

  select(kind: AssetKind, path: string): Promise<{ path: string }> {
    return this.call('registry.select', { kind, path });
  }

  register(kind: AssetKind, path: string): Promise<{ path: string }> {
    return this.call('registry.register', { kind, path });
  }

  remove(path: string): Promise<{ removed: string }> {
    return this.call('registry.remove', { path });
  }

  browse(path: string, filter: string): Promise<BrowseResult> {
    return this.call('browse', { path, filter });
  }

  cacheInventory(): Promise<{ entries: CacheEntry[] }> {
    return this.call('cache.inventory');
  }

  saveSettings(settings: Settings): Promise<Settings> {
    return this.call('settings.save', { ...settings });
  }

  historyList(): Promise<{ paths: string[] }> {
    return this.call('history.list');
  }

  symbolsCached(paths: string[]): Promise<{ cached: boolean[] }> {
    return this.call('symbols.cached', { paths });
  }

  analyze(args: AnalyzeArgs, progress: TaskProgress): Promise<{ choose?: string[]; result?: Results }> {
    return this.task('analyze', { ...args }, progress);
  }

  dump(args: DumpArgs, progress: TaskProgress): Promise<{ choose?: string[]; result?: Results }> {
    return this.task('dump', { ...args }, progress);
  }

  identify(image: string, progress: TaskProgress): Promise<{ banner: Results }> {
    return this.task('identify', { image }, progress);
  }

  matchLocal(image: string, paths: string[], progress: TaskProgress): Promise<MatchLocalReply> {
    return this.task('matchLocal', { image, paths }, progress);
  }

  remote(
    args: { image?: string | null; query?: string; refresh?: boolean; catalog?: boolean },
    progress: TaskProgress,
  ): Promise<RemoteReply> {
    return this.task('remote', { ...args }, progress);
  }

  download(
    candidate: RemoteMatch,
    args: { image: string | null; catalog: boolean },
    progress: TaskProgress,
  ): Promise<{ path: string }> {
    return this.task('download', { candidate, ...args }, progress);
  }

  generate(
    args: { image: string; kali: boolean; elf?: string; config?: string; tool?: string },
    progress: TaskProgress,
  ): Promise<{ path: string }> {
    return this.task('generate', { ...args }, progress);
  }

  inspectSymbols(path: string, progress: TaskProgress): Promise<{ text: string }> {
    return this.task('inspectSymbols', { path }, progress);
  }

  cacheClear(scopes: string[], progress: TaskProgress): Promise<ClearReport> {
    return this.task('cacheClear', { scopes }, progress);
  }

  export(
    args: { path: string; result: Results; rows?: string[][] },
    progress: TaskProgress,
  ): Promise<{ path: string; rows: number }> {
    return this.task('export', { ...args }, progress);
  }

  history(path: string, progress: TaskProgress): Promise<{ result: Results }> {
    return this.task('history', { path }, progress);
  }

  /**
   * Ask the worker to stop.
   *
   * Cancellation is cooperative: the engine checks the flag between objects, so
   * this returns as soon as the request is sent. When the task has not been
   * acknowledged yet the intent is remembered and forwarded on the reply, which
   * is the difference between "cancel works" and "cancel silently does nothing".
   */
  async cancel(): Promise<void> {
    if (!this.busy) {
      return;
    }
    this.cancelRequested = true;
    if (this.taskId) {
      await this.call('task.cancel', { id: this.taskId }).catch(() => undefined);
      return;
    }
    // `task.start` is still in flight. Wait briefly for the id so the cancel is
    // delivered now rather than on the reply: a scan that takes a second would
    // otherwise run to completion while the user watches "正在取消…".
    for (let attempt = 0; attempt < 40 && this.starting; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    if (this.taskId) {
      await this.call('task.cancel', { id: this.taskId }).catch(() => undefined);
    }
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    await this.cancel();
    this.closed = true;
    this.child.stdin.end();
    this.child.kill();
  }
}

export { EngineError };
export type { TaskEvent };
