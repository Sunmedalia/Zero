import assert from 'node:assert/strict';
import test from 'node:test';
import { app, results } from './harness.js';
import { renderFrame, handleKey } from '../views/root.js';
import { requestKey } from '../state.js';
import { width } from '../text.js';

function text(frame: ReturnType<typeof renderFrame>): string {
  return frame.canvas.lines().map((line) => line.filter((cell) => !cell.continuation).map((cell) => cell.text).join('')).join('\n');
}

for (const [columns, rows] of [[80, 24], [120, 35], [160, 45]]) {
  test(`workbench renders and prepares without analysis at ${columns}×${rows}`, async () => {
    const { app: instance, engine } = await app();
    instance.state.settings.image_dir = process.cwd();
    instance.resize(columns!, rows!);
    const frame = renderFrame(instance, columns!, rows!);
    assert.match(text(frame), /选择镜像，开始内存分析/);
    assert.equal(frame.canvas.lines().length, rows);
    for (const line of text(frame).split('\n')) assert.equal(width(line), columns);
    const choose = frame.layout.buttons.find((button) => button.key === 'i');
    assert.ok(choose);
    await instance.click(choose.rect.x, choose.rect.y);
    assert.equal(instance.state.dialog?.kind, 'files');
    assert.equal(engine.analyzeCalls.length, 0);
  });
}

test('details keep the selected row through overlay, docked view and resize', async () => {
  const { app: instance } = await app();
  const current = results({ rows: [['1', 'first'], ['2', '完整字段'.repeat(1000)]] });
  instance.state.results.set(requestKey(instance.state), current);
  instance.state.row = 1;
  instance.resize(120, 35);
  renderFrame(instance, 120, 35);
  await handleKey(instance, 'd', {});
  let frame = renderFrame(instance, 120, 35);
  assert.equal(frame.layout.inspector?.width, frame.layout.content?.width);
  assert.equal(instance.nextFocus(false), 'detail');
  await handleKey(instance, '', { end: true });
  assert.ok(instance.state.detailScroll > 0);
  const detail = frame.layout.inspector!;
  await instance.click(detail.x + 1, detail.y + 2);
  assert.equal(instance.state.row, 1, 'covered rows cannot receive clicks');
  instance.resize(160, 45);
  frame = renderFrame(instance, 160, 45);
  assert.equal(frame.layout.inspector?.width, 38);
  assert.equal(instance.state.row, 1);
  instance.resize(80, 24);
  frame = renderFrame(instance, 80, 24);
  assert.equal(frame.layout.inspector?.width, 80);
  await handleKey(instance, '', { escape: true });
  assert.equal(instance.state.inspector, false);
  assert.equal(instance.state.focus, 'content');
  assert.equal(instance.state.row, 1);
});

test('rendered column targets sort the table by mouse', async () => {
  const { app: instance } = await app();
  instance.state.results.set(requestKey(instance.state), results({ rows: [['2', 'b'], ['1', 'a']] }));
  instance.resize(120, 35);
  const frame = renderFrame(instance, 120, 35);
  const column = frame.layout.columns_[0]!;
  await instance.click(column.x, column.y);
  assert.equal(instance.state.sort, 0);
  await instance.click(column.x, column.y);
  assert.equal(instance.state.descending, true);
});

test('partial, historical, empty, failed and cancelled states stay distinguishable', async () => {
  const { app: instance } = await app();
  instance.resize(120, 35);
  instance.state.image = '/evidence/memory.raw';
  instance.state.symbols = '/evidence/symbols.json';
  const key = requestKey(instance.state);
  instance.state.results.set(key, results({ complete: false, diagnostics: ['缺页'] }));
  assert.match(text(renderFrame(instance, 120, 35)), /部分/);
  instance.state.results.set(key, results({ historical: true }));
  assert.match(text(renderFrame(instance, 120, 35)), /历史/);
  instance.state.results.set(key, results({ rows: [] }));
  assert.match(text(renderFrame(instance, 120, 35)), /未发现记录/);
  instance.state.results.delete(key);
  instance.state.cancelled = true;
  assert.match(text(renderFrame(instance, 120, 35)), /任务已取消/);
  instance.state.cancelled = false;
  instance.state.lastError = instance.state.status = '读取失败';
  assert.match(text(renderFrame(instance, 120, 35)), /分析未完成/);
  assert.match(text(renderFrame(instance, 120, 35)), /读取失败/);
});

test('compact navigation and result regions switch without painting over each other', async () => {
  const { app: instance } = await app();
  instance.resize(80, 24);
  instance.state.focus = 'navigation';
  let frame = renderFrame(instance, 80, 24);
  assert.equal(frame.layout.content, null);
  assert.ok(frame.layout.menu);
  const target = frame.layout.regionHits.find((hit) => hit.focus === 'content')!;
  await instance.click(target.rect.x, target.rect.y);
  frame = renderFrame(instance, 80, 24);
  assert.equal(frame.layout.menu, null);
  assert.ok(frame.layout.content);
});

test('small terminal accepts quit but cannot start commands or click hidden controls', async () => {
  const { app: instance, engine } = await app();
  instance.resize(50, 12);
  assert.match(text(renderFrame(instance, 50, 12)), /终端过小/);
  await handleKey(instance, 'i', {});
  await instance.click(1, 1);
  assert.equal(instance.state.dialog, null);
  assert.equal(engine.analyzeCalls.length, 0);
  let quit = false;
  instance.onQuit(() => { quit = true; });
  await handleKey(instance, 'q', {});
  assert.equal(quit, true);
});


test('an unavailable configured image directory falls back to path input', async () => {
  const { app: instance } = await app();
  instance.state.settings.image_dir = '/zero-missing-test-directory/does-not-exist';
  await instance.runCommand('importImage');
  assert.equal(instance.state.dialog?.kind, 'input');
  assert.match(instance.state.status, /配置目录不可用/);
});


test('each plugin restores its own filter, sorting, row and horizontal position', async () => {
  const { app: instance } = await app();
  instance.state.query = 'system';
  instance.state.sort = 1;
  instance.state.descending = true;
  instance.state.row = 4;
  instance.state.horizontal = 12;
  instance.selectPlugin('lsmod');
  assert.equal(instance.state.query, '');
  instance.selectPlugin('pslist');
  assert.equal(instance.state.query, 'system');
  assert.equal(instance.state.sort, 1);
  assert.equal(instance.state.descending, true);
  assert.equal(instance.state.row, 4);
  assert.equal(instance.state.horizontal, 12);
});

test('wheel over details scrolls fields rather than the covered result rows', async () => {
  const { app: instance } = await app();
  instance.resize(120, 35);
  instance.state.results.set(requestKey(instance.state), results({ rows: [['1', '字段'.repeat(2000)]] }));
  await instance.runCommand('detail');
  const frame = renderFrame(instance, 120, 35);
  instance.state.focus = 'content';
  await instance.wheel(1, frame.layout.inspector!.x + 1, frame.layout.inspector!.y + 2);
  assert.equal(instance.state.focus, 'detail');
  assert.equal(instance.state.detailScroll, 1);
  assert.equal(instance.state.row, 0);
});


test('details render separate fields while escaping control characters inside evidence', async () => {
  const { app: instance } = await app();
  instance.resize(120, 35);
  instance.state.results.set(requestKey(instance.state), results({ rows: [['1', 'a\nb']] }));
  await instance.runCommand('detail');
  const frame = renderFrame(instance, 120, 35);
  const lines = text(frame).split('\n');
  const pid = lines.findIndex((line) => line.includes('PID: 1'));
  assert.ok(pid > 0);
  assert.match(lines[pid + 1]!, /Name: a\\u\{a\}b/);
  assert.ok(!lines[pid]!.includes('Name:'));
});
