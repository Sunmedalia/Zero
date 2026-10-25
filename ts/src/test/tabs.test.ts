import assert from 'node:assert/strict';
import test from 'node:test';
import { app, results } from './harness.js';
import { renderFrame, handleKey } from '../views/root.js';
import { activeTab, requestKey, result } from '../state.js';
import { rect, scrollbar, scrollbarDragIndex } from '../layoutTree.js';
import { decodeMouse } from '../mouse.js';
import { SURFACE, THEMES, applyTheme } from '../text.js';
import type { App } from '../app.js';

function text(frame: ReturnType<typeof renderFrame>): string {
  return frame.canvas.lines().map((line) => line.filter((cell) => !cell.continuation).map((cell) => cell.text).join('')).join('\n');
}

/** Open `plugin` as a page with a ready result, so activating it never runs. */
async function open(instance: App, plugin: string, rows = 3): Promise<void> {
  instance.selectPlugin(plugin);
  instance.state.results.set(
    requestKey(instance.state),
    results({ plugin, rows: Array.from({ length: rows }, (_, index) => [String(index), `${plugin}${index}`]) }),
  );
  await instance.activatePlugin(plugin);
}

test('motion with a held button decodes as a drag; bare hover is ignored', () => {
  const { events } = decodeMouse('\u001b[<32;5;9M\u001b[<35;6;9M\u001b[<0;5;9m');
  assert.deepEqual(
    events.map((event) => ({ kind: event.kind, button: event.button, x: event.x, y: event.y })),
    [
      { kind: 'drag', button: 0, x: 4, y: 8 },
      { kind: 'release', button: 0, x: 4, y: 8 },
    ],
  );
});

test('dragging the thumb maps its top to the offset the view must show', () => {
  const track = rect(10, 5, 1, 20);
  const bar = scrollbar('content', track, 200, 0, 20)!;
  assert.equal(bar.thumb.height, 2);
  assert.equal(scrollbarDragIndex(bar, 5, 0), 0);
  // The bottom row of the view is selected, so the offset follows the pointer.
  assert.equal(scrollbarDragIndex(bar, 14, 0), Math.round((9 * 180) / 18) + 19);
  assert.equal(scrollbarDragIndex(bar, 99, 0), 199, 'clamped past the end');
  assert.equal(scrollbarDragIndex(bar, 6, 1), 0, 'the grab point keeps the thumb under the pointer');
  const lines = scrollbar('inspector', track, 100, 0, 20)!;
  assert.equal(scrollbarDragIndex(lines, 24, 0), 80);
});

test('the result scrollbar thumb can be dragged and released', async () => {
  const { app: instance } = await app();
  instance.resize(120, 35);
  await open(instance, 'pslist', 300);
  let frame = renderFrame(instance, 120, 35);
  const bar = frame.layout.scrollbars.find((entry) => entry.target === 'content')!;
  await instance.click(bar.track.x, bar.thumb.y);
  assert.ok(instance.isDragging());
  assert.equal(instance.state.row, 0, 'grabbing the thumb does not jump');
  // The pointer may leave the one-column track while the button is held.
  instance.drag(bar.track.x + 5, bar.track.y + Math.floor(bar.track.height / 2));
  const middle = instance.state.row;
  assert.ok(middle > 100 && middle < 220, `row ${middle}`);
  frame = renderFrame(instance, 120, 35);
  const moved = frame.layout.scrollbars.find((entry) => entry.target === 'content')!;
  assert.ok(Math.abs(moved.thumb.y - (bar.track.y + Math.floor(bar.track.height / 2))) <= 1, 'thumb follows the pointer');
  instance.drag(bar.track.x, bar.track.y + bar.track.height + 4);
  assert.equal(instance.state.row, 299);
  instance.release();
  assert.equal(instance.isDragging(), false);
  instance.drag(bar.track.x, bar.track.y);
  assert.equal(instance.state.row, 299, 'motion after release does nothing');
});

test('opened plugins and exports appear as browser-style tabs', async () => {
  const { app: instance, engine } = await app();
  instance.resize(140, 35);
  await open(instance, 'pslist');
  await open(instance, 'lsmod');
  await open(instance, 'pslist');
  assert.deepEqual(instance.state.openTabs.map((tab) => tab.kind === 'plugin' && tab.plugin), ['pslist', 'lsmod'], 'reopening reuses the tab');
  assert.equal(activeTab(instance.state), 0);
  let frame = renderFrame(instance, 140, 35);
  const row = frame.layout.content!.y;
  const first = text(frame).split('\n')[row]!;
  assert.match(first, /╭─ pslist · 完整 ×─ lsmod ×─/u, 'tabs replace the table title; the shown one keeps its state');
  assert.doesNotMatch(text(frame).split('\n')[0]!, /pslist/u, 'the page row keeps only the pages and the system picker');
  assert.ok(frame.layout.pageTabs.every((tab) => tab.rect.y === row));
  const lsmod = frame.layout.pageTabs.find((tab) => tab.index === 1)!;
  await instance.click(lsmod.rect.x + 1, row);
  assert.equal(instance.state.plugin, 'lsmod');
  assert.equal(activeTab(instance.state), 1);

  // Reopen an export record from the cache page: it gets a tab of its own.
  engine.historyResult = results({ plugin: 'netstat', rows: [['9', 'old']], historical: true });
  engine.cacheEntries = [{ path: `/evidence/.zero/rust/exports/${'a'.repeat(64)}.export.json`, scope: 'exports', bytes: 1, modified: 1 }];
  engine.cacheRecords = [{
    key: 'a'.repeat(64), recorded: 1, destination: '/evidence/exports/netstat.csv', format: 'csv', plugin: 'netstat',
    rows: 1, bytes: 1, sha256: 'd'.repeat(64), complete: true, diagnostics: 0, banner: '', symbol: '',
  }];
  await handleKey(instance, '3', {});
  await new Promise((resolve) => setImmediate(resolve));
  await handleKey(instance, '', { downArrow: true });
  await handleKey(instance, '', { rightArrow: true });
  await handleKey(instance, '', { return: true });
  assert.equal(instance.state.page, 'analysis');
  assert.equal(instance.state.openTabs.length, 3);
  assert.equal(activeTab(instance.state), 2);
  frame = renderFrame(instance, 140, 35);
  assert.match(text(frame).split('\n')[row]!, /记录·netstat · 历史 ×/u);

  // Ctrl+PgUp walks left and leaves the export.
  await handleKey(instance, '', { ctrl: true, pageUp: true });
  assert.equal(instance.state.history, null);
  assert.equal(instance.state.plugin, 'lsmod');
  await handleKey(instance, '', { ctrl: true, pageDown: true });
  assert.equal(result(instance.state)?.plugin, 'netstat');
});

test('closing a tab discards its rows and shows the neighbour', async () => {
  const { app: instance } = await app();
  instance.resize(140, 35);
  await open(instance, 'pslist');
  await open(instance, 'lsmod');
  await open(instance, 'netstat');
  await instance.activateTab(1);
  await handleKey(instance, 'w', { ctrl: true });
  assert.deepEqual(instance.state.openTabs.map((tab) => tab.kind === 'plugin' && tab.plugin), ['pslist', 'netstat']);
  assert.equal(instance.state.plugin, 'netstat', 'the right neighbour takes over');
  assert.equal([...instance.state.results.keys()].some((key) => key.startsWith('lsmod')), false);
  // The × target closes; middle click closes too.
  let frame = renderFrame(instance, 140, 35);
  const netstat = frame.layout.pageTabs.find((tab) => tab.index === 1)!;
  await instance.click(netstat.close!.x, netstat.close!.y);
  assert.equal(instance.state.plugin, 'pslist', 'the last tab hands over to its left neighbour');
  frame = renderFrame(instance, 140, 35);
  await instance.middleClick(frame.layout.pageTabs[0]!.rect.x + 2, frame.layout.pageTabs[0]!.rect.y);
  assert.equal(instance.state.openTabs.length, 0);
  assert.equal(instance.state.focus, 'navigation');
  assert.match(instance.state.status, /已关闭全部页面/u);
});

test('many tabs shrink, then scroll around the active one with overflow chips', async () => {
  const { app: instance } = await app();
  instance.resize(80, 24);
  for (const plugin of ['pslist', 'pstree', 'lsmod', 'lsof', 'netstat', 'bash', 'dmesg', 'mount', 'elfs']) {
    await open(instance, plugin);
  }
  const frame = renderFrame(instance, 80, 24);
  const tabs = frame.layout.pageTabs;
  const area = frame.layout.pageTabsArea;
  assert.ok(tabs.some((tab) => tab.kind === 'before'), 'hidden tabs on the left');
  assert.ok(tabs.some((tab) => tab.kind === 'tab' && tab.index === 8), 'the active tab stays visible');
  for (const tab of tabs) {
    assert.ok(tab.rect.x >= area.x && tab.rect.x + tab.rect.width <= area.x + area.width, 'inside the strip');
  }
  const before = tabs.find((tab) => tab.kind === 'before')!;
  await instance.click(before.rect.x, before.rect.y);
  assert.equal(activeTab(instance.state), before.index);
});

test('themes switch from the settings dialog, persist and repaint', async () => {
  const { app: instance, engine } = await app();
  instance.resize(120, 35);
  assert.equal(SURFACE, THEMES[0]!.palette.surface);
  await handleKey(instance, ',', {});
  assert.equal(instance.state.dialog?.kind, 'settings');
  for (let index = 0; index < 5; index += 1) {
    await handleKey(instance, '', { downArrow: true });
  }
  assert.match(text(renderFrame(instance, 120, 35)), /界面主题: 石板/u);
  await handleKey(instance, '', { return: true });
  assert.equal(engine.settings.theme, THEMES[1]!.id, 'saved to settings');
  assert.equal(SURFACE, THEMES[1]!.palette.surface);
  assert.equal(instance.state.dialog?.kind, 'settings', 'the dialog stays open to compare themes');
  const frame = renderFrame(instance, 120, 35);
  assert.equal(frame.canvas.lines()[30]![2]!.style.background, THEMES[1]!.palette.surface);
  await handleKey(instance, '', { leftArrow: true });
  await handleKey(instance, '', { leftArrow: true });
  assert.equal(engine.settings.theme, 'auto', 'auto comes first in the cycle');
  await handleKey(instance, '', { leftArrow: true });
  assert.equal(engine.settings.theme, THEMES[THEMES.length - 1]!.id, 'wraps around');
  // Unknown ids from an older or edited settings file fall back to the default.
  assert.equal(applyTheme('missing').id, THEMES[0]!.id);
});

test('the default plugin chosen on entering analysis opens no tab', async () => {
  const { app: instance } = await app({ launch: { image: '/evidence/memory.raw', symbols: '/evidence/kernel.json' } });
  instance.switchPage('assets');
  await instance.runCommand('enterAnalysis');
  assert.equal(instance.state.page, 'analysis');
  assert.deepEqual(instance.state.openTabs, [], 'selected but never opened');
});

test('a tab that never loaded is reused instead of piling up', async () => {
  const { app: instance, engine } = await app();
  instance.resize(140, 35);
  await open(instance, 'pslist');
  // lsmod is opened but its analysis fails, so its tab never shows anything.
  engine.analyzeReply = {};
  await instance.activatePlugin('lsmod');
  assert.deepEqual(instance.state.openTabs.map((tab) => tab.kind === 'plugin' && tab.plugin), ['pslist', 'lsmod']);
  // Opening pstree now takes over the empty lsmod tab rather than adding one.
  await instance.activatePlugin('pstree');
  assert.deepEqual(instance.state.openTabs.map((tab) => tab.kind === 'plugin' && tab.plugin), ['pslist', 'pstree']);
  // A loaded tab is never replaced.
  await open(instance, 'pstree');
  await open(instance, 'lsmod');
  assert.deepEqual(instance.state.openTabs.map((tab) => tab.kind === 'plugin' && tab.plugin), ['pslist', 'pstree', 'lsmod']);
});

test('reopening the same export record reuses its tab', async () => {
  const { app: instance, engine } = await app();
  instance.resize(140, 35);
  await open(instance, 'pslist');
  engine.historyResult = results({ plugin: 'netstat', rows: [['9', 'old']], historical: true });
  engine.cacheEntries = [{ path: `/evidence/.zero/rust/exports/${'a'.repeat(64)}.export.json`, scope: 'exports', bytes: 1, modified: 1 }];
  engine.cacheRecords = [{
    key: 'a'.repeat(64), recorded: 1, destination: '/evidence/exports/netstat.csv', format: 'csv', plugin: 'netstat',
    rows: 1, bytes: 1, sha256: 'd'.repeat(64), complete: true, diagnostics: 0, banner: '', symbol: '',
  }];
  for (let round = 0; round < 2; round += 1) {
    await handleKey(instance, '3', {});
    await new Promise((resolve) => setImmediate(resolve));
    instance.state.cache = { ...instance.state.cache, scope: 1, entry: 0, pane: 'entries' };
    await handleKey(instance, '', { return: true });
  }
  assert.equal(engine.openedRecords.length, 2);
  assert.deepEqual(instance.state.openTabs.map((tab) => tab.kind), ['plugin', 'history'], 'one tab for the record');
  assert.equal(activeTab(instance.state), 1);
});
