import assert from 'node:assert/strict';
import test from 'node:test';
import { app, asset, results } from './harness.js';
import { renderFrame, handleKey } from '../views/root.js';
import { cacheItems, requestKey } from '../state.js';
import { assetDetailText } from '../detail.js';

function text(frame: ReturnType<typeof renderFrame>): string {
  return frame.canvas.lines().map((line) => line.filter((cell) => !cell.continuation).map((cell) => cell.text).join('')).join('\n');
}

const DIGEST = 'ab'.repeat(32);
const OTHER = 'cd'.repeat(32);
const CACHE = '/evidence/.zero/rust';

test('choosing an image verifies it once, before matching and not in the first plugin', async () => {
  const { app: instance, engine } = await app({ launch: { image: '/evidence/memory.raw' } });
  assert.deepEqual(engine.verifyCalls, ['/evidence/memory.raw']);
  assert.ok(instance.state.logs.some((line) => line.startsWith('校验镜像 SHA256')));
  assert.equal(instance.verification('/evidence/memory.raw')?.digest, DIGEST);
  assert.match(assetDetailText(instance.state, engine.assetsList[0]!), new RegExp(`SHA256: ${DIGEST}（本次会话已校验）`, 'u'));

  // Preparing again, or asking for it, reuses the session's verification.
  await instance.prepareSelectedImage();
  await handleKey(instance, 'V', {});
  assert.equal(engine.verifyCalls.length, 1);
  assert.match(instance.state.status, /镜像已校验 SHA256 abababababababab… · 完整读取 22 s.*（本次会话已校验）/u);

  // The analysis itself does not prepare the image again.
  instance.state.preparation = 'ready';
  engine.analyzeReply = { result: results({ plugin: 'pslist' }), source: 'fresh' };
  await instance.activatePlugin('pslist');
  assert.equal(engine.verifyCalls.length, 1);

  // A rewritten file is verified again.
  engine.assetsList = [asset({ stamp: 'rewritten' })];
  await instance.refreshAssets();
  assert.equal(instance.verification('/evidence/memory.raw'), null);
  await instance.prepareSelectedImage();
  assert.equal(engine.verifyCalls.length, 2);
});

test('a recorded digest is shown as a record until this session verifies it', async () => {
  const { app: instance } = await app({ page: 'assets' });
  assert.match(assetDetailText(instance.state, asset()), /SHA256: 尚未校验（选用时校验）/u);
  assert.match(
    assetDetailText(instance.state, asset({ digest: OTHER })),
    new RegExp(`SHA256: ${OTHER}（上次校验的记录，文件未变；选用时重新校验）`, 'u'),
  );
});

test('the cache page groups analysis results under the image they came from', async () => {
  const { app: instance, engine } = await app({
    launch: { image: '/evidence/memory.raw' },
    assets: [asset({ digest: DIGEST }), asset({ path: '/evidence/win.mem', name: 'win.mem', id: 'w', digest: 'ef'.repeat(32) })],
  });
  const summary = (image: string, plugin: string, complete = true) => ({
    image, source: image === OTHER ? '/evidence/win.mem' : '/evidence/memory.raw', plugin, complete, rows: 12, diagnostics: complete ? 0 : 3,
  });
  engine.cacheEntries = [
    { path: `${CACHE}/${'1'.repeat(64)}.result.json`, scope: 'results', bytes: 2048, modified: 30, result: summary(DIGEST, 'linux.pslist') },
    { path: `${CACHE}/${'2'.repeat(64)}.partial.json`, scope: 'results', bytes: 1024, modified: 40, result: summary(OTHER, 'windows.pslist', false) },
    { path: `${CACHE}/${'3'.repeat(64)}.result.json`, scope: 'results', bytes: 512, modified: 20, result: summary(DIGEST, 'linux.lsmod') },
    // Written before the image was recorded.
    { path: `${CACHE}/${'4'.repeat(64)}.result.json`, scope: 'results', bytes: 256, modified: 50, result: null },
  ];
  instance.resize(120, 35);
  await handleKey(instance, '3', {});
  await new Promise((resolve) => setImmediate(resolve));
  const items = () => cacheItems(instance.state);
  assert.deepEqual(
    items().map((item) => item.group ? `# ${item.group.label} ${item.group.known} ${item.group.count}` : item.result?.plugin ?? item.name),
    [
      '# win.mem changed 1', 'windows.pslist',
      '# memory.raw current 2', 'linux.pslist', 'linux.lsmod',
      '# 未记录镜像（旧版缓存） unrecorded 1', `${'4'.repeat(64)}.result.json`,
    ],
  );
  instance.state.cache.pane = 'entries';
  const frame = text(renderFrame(instance, 120, 35));
  assert.match(frame, /▾ win\.mem · 文件已变化，结果属于旧内容 +1 项/u);
  assert.match(frame, /▾ memory\.raw · 当前镜像 +2 项 · 2\.5 KiB/u);
  assert.match(frame, /分析结果 · 4 项 · 3 个镜像 · 3\.8 KiB/u);
  assert.match(frame, /  pslist · 12 条 · 部分 · 3 条诊断/u);

  // Enter folds one image; Delete on its heading removes all its results.
  instance.setCacheRow('entries', 2);
  await handleKey(instance, '', { return: true });
  assert.deepEqual(items().map((item) => item.group?.collapsed ?? null), [false, null, true, false, null]);
  await handleKey(instance, '', { delete: true });
  assert.match(instance.state.status, /再按 Delete 确认删除 memory\.raw 的全部 2 个分析结果/u);
  await handleKey(instance, '', { delete: true });
  assert.deepEqual(engine.removedPaths, [`${CACHE}/${'1'.repeat(64)}.result.json`, `${CACHE}/${'3'.repeat(64)}.result.json`]);
});

test('clicking the chosen image or symbol name in the header shows its detail', async () => {
  const { app: instance } = await app({ launch: { image: '/evidence/memory.raw', symbols: '/evidence/symbols/test.json.xz' } });
  instance.resize(120, 35);
  // Read through a function: assertions narrow `instance.state.dialog` otherwise.
  const shown = () => {
    const dialog = instance.state.dialog;
    return dialog?.kind === 'assetDetail' ? dialog.asset.path : dialog?.kind ?? null;
  };
  let frame = renderFrame(instance, 120, 35);
  await instance.click(frame.layout.headerImage.x + 2, frame.layout.headerImage.y);
  assert.equal(shown(), '/evidence/memory.raw');
  instance.state.dialog = null;
  frame = renderFrame(instance, 120, 35);
  await instance.click(frame.layout.headerSymbol.x + 2, frame.layout.headerSymbol.y);
  assert.equal(shown(), '/evidence/symbols/test.json.xz');
});

test('while analysing, the running badge sits in the middle of the result area', async () => {
  const { app: instance } = await app({ launch: { image: '/evidence/memory.raw' } });
  instance.resize(120, 35);
  instance.state.busy = true;
  instance.state.startedAt = Date.now();
  const frame = renderFrame(instance, 120, 35);
  const lines = text(frame).split('\n');
  assert.doesNotMatch(lines[0] ?? '', /运行中/u, 'no longer in the top-right corner');
  const content = frame.layout.content!;
  const row = lines.findIndex((line) => /运行中 [●·]{3}/u.test(line));
  assert.ok(row > content.y && row < content.y + content.height - 1, 'inside the result area');
  assert.ok(Math.abs(row - (content.y + content.height / 2)) <= 2, 'vertically centred');
  // Shown over an existing result too.
  instance.state.results.set('pslist', results());
  instance.state.results.set(requestKey(instance.state), results());
  assert.match(text(renderFrame(instance, 120, 35)), /运行中 [●·]{3} · \d+\.\d s · Esc 取消/u);
});

test('the header detail is read-only: keys and clicks in it leave the analysis alone', async () => {
  const { app: instance } = await app({ launch: { image: '/evidence/memory.raw', symbols: '/evidence/symbols/test.json.xz' } });
  instance.resize(120, 35);
  const rows = Array.from({ length: 50 }, (_, index) => [String(index), `proc${index}`]);
  const key = requestKey(instance.state);
  instance.state.results.set(key, results({ rows }));
  instance.state.row = 7;
  const open = async () => {
    const frame = renderFrame(instance, 120, 35);
    await instance.click(frame.layout.headerImage.x + 2, frame.layout.headerImage.y);
    return renderFrame(instance, 120, 35);
  };
  const frame = await open();
  const popup = frame.layout.popup!;
  assert.ok(popup.width >= 80, `wide enough to read: ${popup.width}`);
  assert.match(text(frame), /当前分析对象 · Esc／Enter 关闭/u);
  assert.doesNotMatch(text(frame), /Space 选用/u);
  // Every cell of the popup except the close chip is inert.
  const chip = frame.layout.buttons.find((button) => button.key === 'Esc')!;
  for (let y = popup.y; y < popup.y + popup.height; y += 1) {
    for (let x = popup.x; x < popup.x + popup.width; x += 1) {
      if (y === chip.rect.y && x >= chip.rect.x && x < chip.rect.x + chip.rect.width) continue;
      await instance.click(x, y);
    }
  }
  assert.equal(instance.state.dialog?.kind, 'assetDetail');
  for (const token of [' ', 'Enter']) {
    await handleKey(instance, token === ' ' ? ' ' : '', token === 'Enter' ? { return: true } : {});
    assert.equal(instance.state.dialog, null, `${token} closes it`);
    await open();
  }
  assert.equal(instance.state.image, '/evidence/memory.raw');
  assert.equal(instance.state.page, 'analysis');
  assert.equal(instance.state.row, 7);
  assert.ok(instance.state.results.has(key), 'the shown result is kept');
});
