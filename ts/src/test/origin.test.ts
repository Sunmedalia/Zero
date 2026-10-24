import assert from 'node:assert/strict';
import test from 'node:test';
import { app as start, results } from './harness.js';
import { renderFrame } from '../views/root.js';
import { diagnosticCounts, diagnosticKind, formatDuration } from '../format.js';
import { diagnosticsText } from '../detail.js';
import { result } from '../state.js';

/** An analysis console with an image chosen, so activating a plugin runs it. */
async function app() {
  const opened = await start({ launch: { image: '/evidence/memory.raw', symbols: '/evidence/symbols/test.json.xz' } });
  opened.app.state.preparation = 'ready';
  return opened;
}

function text(frame: ReturnType<typeof renderFrame>): string {
  return frame.canvas.lines().map((line) => line.filter((cell) => !cell.continuation).map((cell) => cell.text).join('')).join('\n');
}

/** Diagnostics as the Windows engine words them on a live-acquired image. */
const WINDOWS = [
  'Windows 链表不一致 @ 0xffffde8ced813508 direction 0: expected 0xffffde8ced890548, found 0x737265646165682d',
  '链表 @ 0xfffff8002a41bea0 direction 0: 无效链表地址 0x65736f7078652d6c',
  'EPROCESS 0xffffde8ced8130c0: 无效 EPROCESS',
  'PID 668 native environment: Windows 缺页 VA 0x1a7bb810000 level 12 PTE 0x1ccc200002084; 不是 prototype PTE: 缺少显式分页附件 index 2；该索引也未验证为虚拟压缩 store',
  'TCP/IP 布局: 该驱动版本系列仅有合成布局验证，尚未验证此精确驱动身份',
  'PID 712 C:\\Windows\\system32\\AUTHZ.dll: 资源目录项超限',
  'PID 1 something new',
];

test('a fresh analysis and a cache read are labelled differently, with their time', async () => {
  const { app: instance, engine } = await app();
  instance.resize(140, 35);
  instance.state.page = 'analysis';
  engine.analyzeReply = { result: results({ plugin: 'pslist' }), source: 'fresh' };
  await instance.activatePlugin('pslist');
  assert.match(instance.state.status, /pslist · 1 条 · 重新分析 · \d+\.\d s · 完整/u);
  assert.match(text(renderFrame(instance, 140, 35)), /重新分析 · \d+\.\d s/u);

  engine.analyzeReply = { result: results({ plugin: 'lsmod', columns: ['Name'], rows: [['ext4']] }), source: 'cache', prepared: true };
  await instance.activatePlugin('lsmod');
  assert.match(instance.state.status, /lsmod · 1 条 · 读取缓存 · \d+\.\d s（含镜像校验）/u);
  assert.match(text(renderFrame(instance, 140, 35)), /读取缓存 · \d+\.\d s/u);
});

test('progress reported just before the reply never replaces the result status', async () => {
  const { app: instance, engine } = await app();
  instance.state.page = 'analysis';
  engine.analyzeProgress = ['读取成功缓存'];
  engine.analyzeReply = { result: results({ plugin: 'pslist' }), source: 'cache' };
  await instance.activatePlugin('pslist');
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.match(instance.state.status, /^pslist · 1 条 · 读取缓存/u);
  assert.equal(instance.state.logs.at(-1), '读取成功缓存');
});

test('returning to a result already in this session says it was not run again', async () => {
  const { app: instance, engine } = await app();
  instance.state.page = 'analysis';
  engine.analyzeReply = { result: results({ plugin: 'pslist' }), source: 'fresh' };
  await instance.activatePlugin('pslist');
  engine.analyzeReply = { result: results({ plugin: 'lsmod', columns: ['Name'], rows: [['ext4']] }), source: 'fresh' };
  await instance.activatePlugin('lsmod');
  const calls = engine.analyzeCalls.length;
  await instance.activatePlugin('pslist');
  assert.equal(engine.analyzeCalls.length, calls);
  assert.match(instance.state.status, /本次会话已加载，未重新运行（r 重新分析）/u);
  // The frame keeps describing how the shown result was obtained.
  assert.equal(instance.state.origins.get(result(instance.state)!)?.source, 'fresh');
});

test('partial results name what kind of diagnostics they carry', async () => {
  const { app: instance, engine } = await app();
  instance.state.page = 'analysis';
  engine.analyzeReply = {
    result: results({ plugin: 'windows.pslist', system: 'windows', complete: false, diagnostics: WINDOWS.slice(0, 3) }),
    source: 'fresh',
  };
  await instance.activatePlugin('pslist');
  assert.match(instance.state.status, /部分（未写入缓存） · 3 条诊断：对象前后矛盾 3（v 查看）/u);
});

test('diagnostics fall into one family each and the modal groups them', () => {
  assert.deepEqual(WINDOWS.map(diagnosticKind), ['inconsistent', 'inconsistent', 'inconsistent', 'page', 'layout', 'limit', 'other']);
  assert.deepEqual(
    diagnosticCounts(WINDOWS).map((kind) => `${kind.label} ${kind.count}`),
    ['页面不在镜像中 1', '布局未验收 1', '达到上限 1', '对象前后矛盾 3', '其他 1'],
  );
  const body = diagnosticsText(results({ complete: false, diagnostics: WINDOWS }));
  assert.match(body, /^7 条诊断。/u);
  assert.match(body, /· 页面不在镜像中 1：对象所在的页在采集时已换出/u);
  const inconsistent = body.indexOf('── 对象前后矛盾 3 ──');
  assert.ok(inconsistent > body.indexOf('── 页面不在镜像中 1 ──'));
  assert.ok(body.indexOf('无效 EPROCESS') > inconsistent);
  assert.equal(diagnosticsText(results()), '没有诊断；结果完整。');
});

test('durations read as tenths, whole seconds, then minutes', () => {
  assert.equal(formatDuration(0.04), '0.0 s');
  assert.equal(formatDuration(1.25), '1.3 s');
  assert.equal(formatDuration(18.1), '18 s');
  assert.equal(formatDuration(79.04), '1m19s');
});

test('cache-read results keep a badge in the status bar while other messages replace the text', async () => {
  const { app: instance, engine } = await app();
  instance.resize(120, 30);
  engine.analyzeReply = { result: results({ plugin: 'pslist' }), source: 'cache' };
  await instance.activatePlugin('pslist');
  instance.state.status = '点击或 Enter 运行插件';
  const footer = (frame: ReturnType<typeof renderFrame>) => text(frame).split('\n')[frame.layout.status.y] ?? '';
  assert.match(footer(renderFrame(instance, 120, 30)), /内容 │  缓存读取  点击或 Enter 运行插件/u);
  engine.analyzeReply = { result: results({ plugin: 'lsmod', columns: ['Name'], rows: [['ext4']] }), source: 'fresh' };
  await instance.activatePlugin('lsmod');
  assert.match(footer(renderFrame(instance, 120, 30)), /│  重新分析  lsmod/u);
});
