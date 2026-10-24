import assert from 'node:assert/strict';
import test from 'node:test';
import { app, results } from './harness.js';
import { renderFrame, handleKey } from '../views/root.js';
import { cacheItems, requestKey } from '../state.js';
import { scrollbar, scrollbarIndex, rect } from '../layoutTree.js';
import type { ExportRecord } from '../types.js';

function text(frame: ReturnType<typeof renderFrame>): string {
  return frame.canvas.lines().map((line) => line.filter((cell) => !cell.continuation).map((cell) => cell.text).join('')).join('\n');
}

const KEY = 'a'.repeat(64);
const CACHE = '/evidence/.zero/rust';

function record(overrides: Partial<ExportRecord> = {}): ExportRecord {
  return {
    key: KEY,
    recorded: 1761286000,
    destination: '/evidence/exports/pslist.csv',
    format: 'csv',
    plugin: 'pslist',
    rows: 200,
    bytes: 52000,
    sha256: 'd'.repeat(64),
    complete: true,
    diagnostics: 0,
    banner: '',
    symbol: '',
    ...overrides,
  };
}

async function cachePage() {
  const { app: instance, engine } = await app();
  engine.cacheEntries = [
    { path: `${CACHE}/${'b'.repeat(64)}.result.json`, scope: 'results', bytes: 2048, modified: 10 },
    { path: `${CACHE}/exports/${KEY}.export.json`, scope: 'exports', bytes: 400, modified: 20 },
    { path: `${CACHE}/exports/${KEY}.csv`, scope: 'exports', bytes: 52000, modified: 20 },
    // A copy whose metadata was lost stays listed so it can still be removed.
    { path: `${CACHE}/exports/${'e'.repeat(64)}.json`, scope: 'exports', bytes: 7, modified: 5 },
  ];
  engine.cacheRecords = [record()];
  instance.resize(120, 35);
  await handleKey(instance, '3', {});
  await new Promise((resolve) => setImmediate(resolve));
  return { instance, engine };
}

test('scrollbar thumb tracks the offset and a track click maps back to a row', () => {
  const track = rect(10, 5, 1, 20);
  assert.equal(scrollbar('content', track, 20, 0, 20), null, 'nothing to scroll');
  const top = scrollbar('content', track, 200, 0, 20)!;
  const bottom = scrollbar('content', track, 200, 180, 20)!;
  assert.deepEqual(top.thumb, { y: 5, height: 2 });
  assert.equal(bottom.thumb.y + bottom.thumb.height, 25);
  assert.equal(scrollbarIndex(top, 5), 0);
  assert.equal(scrollbarIndex(top, 24), 199);
  const lines = scrollbar('inspector', track, 100, 0, 20)!;
  assert.equal(scrollbarIndex(lines, 24), 80, 'line offsets stop at the last page');
});

test('the result table shows a scrollbar and clicking its track jumps there', async () => {
  const { app: instance } = await app();
  const rows = Array.from({ length: 300 }, (_, index) => [String(index), `proc${index}`]);
  instance.state.results.set(requestKey(instance.state), results({ rows }));
  instance.resize(120, 35);
  let frame = renderFrame(instance, 120, 35);
  const bar = frame.layout.scrollbars.find((entry) => entry.target === 'content');
  assert.ok(bar, 'content scrollbar');
  assert.equal(bar.track.x, frame.layout.content!.x + frame.layout.content!.width - 1, 'drawn on the right border');
  assert.equal(frame.canvas.lines()[bar.thumb.y]![bar.track.x]!.text, '┃');
  await instance.click(bar.track.x, bar.track.y + bar.track.height - 1);
  assert.equal(instance.state.row, 299);
  frame = renderFrame(instance, 120, 35);
  const moved = frame.layout.scrollbars.find((entry) => entry.target === 'content')!;
  assert.equal(moved.thumb.y + moved.thumb.height, moved.track.y + moved.track.height);
  // Short results keep the plain border.
  instance.state.results.set(requestKey(instance.state), results());
  frame = renderFrame(instance, 120, 35);
  assert.equal(frame.layout.scrollbars.some((entry) => entry.target === 'content'), false);
});

test('cache page lists scopes, groups an export record with its copy and reopens it', async () => {
  const { instance, engine } = await cachePage();
  assert.equal(instance.state.page, 'cache');
  assert.ok(instance.state.cache.loaded);
  let frame = renderFrame(instance, 120, 35);
  assert.match(text(frame), /3 缓存/);
  assert.match(text(frame), /缓存范围/);
  await handleKey(instance, '', { downArrow: true });
  assert.equal(instance.state.cache.scope, 1);
  const items = cacheItems(instance.state);
  assert.equal(items.length, 2, 'one record plus one orphan copy');
  assert.equal(items[0]!.record?.key, KEY);
  assert.equal(items[0]!.bytes, 52400);
  frame = renderFrame(instance, 120, 35);
  assert.match(text(frame), /pslist · 200 条 · CSV/);
  await handleKey(instance, '', { rightArrow: true });
  assert.equal(instance.state.cache.pane, 'entries');
  await handleKey(instance, '', { return: true });
  assert.deepEqual(engine.openedRecords, [KEY]);
  assert.equal(instance.state.page, 'analysis');
  assert.ok(instance.state.history);
});

test('cache deletions and clears need a second press', async () => {
  const { instance, engine } = await cachePage();
  await handleKey(instance, '', { downArrow: true });
  await handleKey(instance, '', { rightArrow: true });
  await handleKey(instance, '', { delete: true });
  assert.equal(engine.removedPaths.length, 0);
  assert.equal(instance.state.cache.confirm, 'remove');
  await handleKey(instance, '', { downArrow: true });
  assert.equal(instance.state.cache.confirm, null, 'moving disarms');
  await handleKey(instance, '', { upArrow: true });
  await handleKey(instance, '', { delete: true });
  await handleKey(instance, '', { delete: true });
  assert.deepEqual(engine.removedPaths, [`${CACHE}/exports/${KEY}.export.json`]);

  // The default ticks are results and identification.
  await handleKey(instance, 'x', {});
  assert.equal(engine.clearedScopes.length, 0);
  assert.match(instance.state.status, /再按 x 确认清理 1 个文件/);
  await handleKey(instance, 'x', {});
  assert.deepEqual(engine.clearedScopes, [['results', 'identification']]);
});

test('cache rows respond to the mouse: first click highlights, second acts', async () => {
  const { instance } = await cachePage();
  const frame = renderFrame(instance, 120, 35);
  const exportsRow = frame.layout.cacheHits.find((hit) => hit.pane === 'scopes' && hit.index === 1)!;
  await instance.click(exportsRow.rect.x + 2, exportsRow.rect.y);
  assert.equal(instance.state.cache.scope, 1);
  assert.equal(instance.state.cache.scopes.includes('exports'), false);
  await instance.click(exportsRow.rect.x + 2, exportsRow.rect.y);
  assert.equal(instance.state.cache.scopes.includes('exports'), true);
});

test('a catalog search queries the whole index in the engine and shows the total', async () => {
  const { app: instance, engine } = await app();
  engine.remoteReply = {
    catalog: true,
    total: 1234,
    index: { banners: 11683, entries: 10255, bytes: 4354630, age_seconds: 7200 },
    matches: Array.from({ length: 500 }, (_, index) => ({
      banner: `Linux version 5.15.0-${index}-generic`,
      path: `releases/download/isf-Ubuntu-amd64-5.15.0/Ubuntu_5.15.0-${index}-generic_amd64.json.xz`,
      url: `https://github.com/Abyss-W4tcher/volatility3-symbols/releases/download/isf-Ubuntu-amd64-5.15.0/Ubuntu_5.15.0-${index}-generic_amd64.json.xz`,
    })),
  };
  instance.resize(120, 35);
  await instance.switchSection('remote');
  instance.state.remoteCatalog = true;
  instance.openInput('assetsSearch');
  for (const character of '5.15.0') {
    await handleKey(instance, character, {});
  }
  await handleKey(instance, '', { return: true });
  const call = engine.remoteCalls.at(-1)!;
  assert.equal(call.query, '5.15.0');
  assert.equal(call.catalog, true);
  assert.equal(call.limit, 500);
  assert.equal(instance.state.remoteTotal, 1234);
  assert.match(instance.state.status, /显示前 500 \/ 1234 项/);
  assert.match(instance.state.status, /2 小时前/);
  const frame = renderFrame(instance, 120, 35);
  assert.match(text(frame), /显示 500 \/ 1234 项/);
  assert.doesNotMatch(text(frame), /releases\/download\//, 'the shared release prefix is not repeated');
  assert.ok(frame.layout.scrollbars.some((bar) => bar.target === 'pane'));
});
