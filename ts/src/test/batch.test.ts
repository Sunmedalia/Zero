import assert from 'node:assert/strict';
import test from 'node:test';
import { App } from '../app.js';
import { app, hello, launch, MemoryEngine, results } from './harness.js';
import { handleKey } from '../views/root.js';

/** A synchronous instance for handlers that do not await anything. */
function appSync(): { app: App; engine: MemoryEngine } {
  const engine = new MemoryEngine();
  return { app: new App(engine, hello(), launch()), engine };
}

test('a batched paste types the whole plugin query and Enter selects it', async () => {
  const { app: instance, engine } = await app({
    launch: { image: '/evidence/memory.raw', symbols: '/evidence/symbols/test.json.xz' },
  });
  instance.state.page = 'analysis';
  instance.state.focus = 'navigation';
  instance.state.preparation = 'ready';
  engine.analyzeReply = {
    result: results({ plugin: 'lsmod', columns: ['Name', 'Base', 'Size'], rows: [] }),
  };

  await handleKey(instance, 'p', {});
  assert.equal(instance.state.dialog?.kind, 'plugins');
  await handleKey(instance, 'lsmod\r', {});

  assert.equal(instance.state.dialog, null);
  assert.equal(instance.state.plugin, 'lsmod');
  assert.equal(engine.analyzeCalls.at(-1)?.plugin, 'lsmod');
  assert.equal(instance.state.busy, false);
});

test('a chunk with repeated newlines confirms only once', async () => {
  const { app: instance } = await app({
    launch: { image: '/evidence/memory.raw', symbols: '/evidence/symbols/test.json.xz' },
  });
  instance.state.page = 'analysis';
  instance.state.dialog = { kind: 'plugins', query: 'lsmod', selected: 0 };
  // The first Enter selects the plugin; the second would reopen nothing and is
  // dropped by the dialog handler, so the plugin must not change afterwards.
  await handleKey(instance, '\r\n\r\n', {});
  assert.equal(instance.state.dialog, null);
  assert.equal(instance.state.plugin, 'lsmod');
});

test('a bracketed paste fills the plugin query without running anything', () => {
  const { app: instance, engine } = appSync();
  instance.state.page = 'analysis';
  instance.state.dialog = { kind: 'plugins', query: '', selected: 0 };
  instance.paste('lsmod\r');
  assert.equal(instance.state.dialog?.kind, 'plugins');
  assert.equal(instance.state.dialog?.query, 'lsmod\r');
  assert.equal(engine.analyzeCalls.length, 0, 'a paste must never start a task');
});
