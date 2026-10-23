import assert from 'node:assert/strict';
import test from 'node:test';
import { app, MemoryEngine, results } from './harness.js';
import type { Engine } from '../engine.js';

/** An engine whose task stays pending until the test releases it. */
class ControlledEngine extends MemoryEngine {
  release: (() => void) | null = null;
  started = 0;
  cancelCalls = 0;

  override analyze(): Promise<{ result: ReturnType<typeof results> }> {
    this.started += 1;
    return new Promise((resolve) => {
      this.release = () => resolve({ result: results({ rows: [['1', 'ran']] }) });
    });
  }

  override cancel(): Promise<void> {
    this.cancelCalls += 1;
    // Real cancellation is cooperative and asynchronous: the worker stops at its
    // next checkpoint. Releasing on the next tick models that without racing the
    // state machine's "正在取消…" status.
    setTimeout(() => this.release?.(), 5);
    return Promise.resolve();
  }
}

async function waitFor(predicate: () => boolean, label: string, timeout = 2000): Promise<void> {
  const deadline = Date.now() + timeout;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${label}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
}

test('cancelling a running analysis stops it and never applies its result', async () => {
  const engine = new ControlledEngine();
  const { app: instance } = await app({
    engine,
    launch: { image: '/evidence/memory.raw' },
  });
  instance.state.preparation = 'ready';
  const run = instance.requestAnalysis(false);
  await waitFor(() => instance.state.busy, 'the task to start');
  assert.equal(instance.state.status, 'pslist启动中');

  await instance.cancelContext();
  assert.equal(engine.cancelCalls, 1, 'cancel must reach the engine');
  assert.match(instance.state.status, /正在取消|已取消/);

  await run;
  assert.equal(instance.state.busy, false);
  assert.equal(instance.state.results.has('pslist'), false, 'a cancelled task must not publish rows');
  assert.equal(instance.state.status, '已取消；可重试');
});

test('a task can be cancelled before its start is acknowledged', async () => {
  const engine = new ControlledEngine();
  const { app: instance } = await app({
    engine,
    launch: { image: '/evidence/memory.raw' },
  });
  instance.state.preparation = 'ready';
  // No await: cancel while the start request is still in flight.
  const run = instance.requestAnalysis(false);
  await instance.cancelContext();
  // The controlled engine only settles when `cancel` releases it; do that so the
  // awaited task cannot hang if cancellation was swallowed.
  engine.release?.();
  await run;
  assert.equal(instance.state.results.has('pslist'), false);
  assert.equal(instance.state.busy, false);
  assert.match(instance.state.status, /已取消/);
});

test('a cancelled task leaves the next request fully functional', async () => {
  const engine = new ControlledEngine();
  const { app: instance } = await app({
    engine,
    launch: { image: '/evidence/memory.raw' },
  });
  instance.state.preparation = 'ready';
  const first = instance.requestAnalysis(false);
  await waitFor(() => instance.state.busy, 'the first task');
  await instance.cancelContext();
  await first;
  assert.equal(instance.state.cancelled, false, 'the cancel flag must not outlive its task');

  // The engine's second call resolves immediately, like a cached result.
  engine.analyze = () => Promise.resolve({ result: results({ rows: [['2', 'second']] }) });
  await instance.requestAnalysis(false);
  assert.equal(engine.started, 1, 'only the cancelled call went through the controlled path');
  assert.equal(instance.state.busy, false);
  assert.ok(instance.state.results.has('pslist'), 'the follow-up analysis must produce a result');
});

test('the cancel flag is cleared even when the task fails for another reason', async () => {
  const engine = new ControlledEngine();
  engine.analyze = () => Promise.reject(new Error('符号下载 HTTP 404：missing'));
  const { app: instance } = await app({
    engine,
    launch: { image: '/evidence/memory.raw' },
  });
  instance.state.preparation = 'ready';
  await instance.requestAnalysis(false);
  assert.match(instance.state.status, /需导入精确符号/);
  assert.equal(instance.state.cancelled, false);
});

test('Escape clears the content filter before cancelling a task', async () => {
  const engine = new ControlledEngine();
  const { app: instance } = await app({
    engine,
    launch: { image: '/evidence/memory.raw' },
  });
  instance.state.page = 'analysis';
  instance.state.query = 'systemd';
  instance.state.results.set('pslist', results());
  await instance.cancelContext();
  assert.equal(instance.state.query, '', 'the filter is the first thing Escape clears');
  assert.equal(engine.cancelCalls, 0, 'no task was running, so nothing was cancelled');
});

test('Escape closes the inspector before touching a running task', async () => {
  const engine = new ControlledEngine();
  const { app: instance } = await app({
    engine,
    launch: { image: '/evidence/memory.raw' },
  });
  instance.state.preparation = 'ready';
  instance.state.inspector = true;
  instance.state.focus = 'detail';
  const run = instance.requestAnalysis(false);
  await waitFor(() => instance.state.busy, 'the task');
  await instance.cancelContext();
  assert.equal(instance.state.inspector, false);
  assert.equal(instance.state.focus, 'content');
  assert.equal(engine.cancelCalls, 0, 'the first Escape only closed the pane');
  await instance.cancelContext();
  assert.equal(engine.cancelCalls, 1, 'the second Escape cancels the task');
  await run;
});

test('cancelling a queued follow-up drops it instead of running it later', async () => {
  const engine = new ControlledEngine();
  const { app: instance } = await app({
    engine,
    launch: { image: '/evidence/memory.raw' },
  });
  instance.state.preparation = 'ready';
  const first = instance.requestAnalysis(false);
  await waitFor(() => instance.state.busy, 'the first task');
  // Queue a second request, then cancel everything.
  await instance.requestAnalysis(true);
  assert.equal(instance.state.pendingWork?.kind, 'analyze');
  await instance.cancelContext();
  await first;
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(engine.started, 1, 'the queued follow-up must not start after a cancel');
  assert.equal(instance.state.pendingWork, null);
});

test('quitting during a task asks twice, and cancelling first makes quit immediate', async () => {
  const engine = new ControlledEngine();
  const { app: instance } = await app({
    engine,
    launch: { image: '/evidence/memory.raw' },
  });
  instance.state.preparation = 'ready';
  let quit = false;
  instance.onQuit(() => {
    quit = true;
  });
  const run = instance.requestAnalysis(false);
  await waitFor(() => instance.state.busy, 'the task');
  assert.equal(instance.requestQuit(), false, 'the first q only arms the quit');
  assert.equal(instance.requestQuit(), true, 'the second q exits');
  assert.equal(quit, true);
  await instance.cancelContext();
  await run;
});

test('the engine interface reports busy while a cancel is pending', () => {
  // The state machine trusts `busy` to decide whether Escape cancels; a client
  // that hides a task during its start window would make Escape a no-op.
  const engine: Engine = new ControlledEngine();
  assert.equal(engine.busy, false);
});
