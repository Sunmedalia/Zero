import assert from 'node:assert/strict';
import test from 'node:test';
import {
  asset,
  asset as assetFixture,
  bannerResults,
  hello,
  MemoryEngine,
  results,
} from './harness.js';
import { app } from './harness.js';
import { assetListFor, remoteList, requestKey, viewIndex, visibleRow } from '../state.js';
import { ACTIONS, KEYS, commandApplies, commandForKey, commandMatches, toolbarCommands } from '../actions.js';
import { dumpModes, parseOptions } from '../dialogs.js';
import { keyToken } from '../keys.js';

/** Poll until `predicate` holds, so a test never depends on a microtask count. */
async function waitFor(predicate: () => boolean, timeoutMs = 1000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error('condition not met before timeout');
    }
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

test('first start opens the resource library without running a plugin', async () => {
  const { app: instance, engine } = await app({
    assets: [asset(), asset({ path: '/evidence/symbols/linux.zip', kind: 'symbols', name: 'linux.zip' })],
    page: null,
  });
  assert.equal(instance.state.page, 'assets');
  assert.equal(instance.state.focus, 'navigation');
  assert.match(instance.state.status, /选择镜像：Space 选用/u);
  assert.equal(engine.analyzeCalls.length, 0);
  assert.equal(instance.state.section, 'images');
  assert.equal(instance.state.plugin, 'pslist');
  assert.equal(assetListFor(instance.state, 'images').length, 1);
  assert.equal(assetListFor(instance.state, 'symbols').length, 1);
});

test('launch flags select the image and prepare it', async () => {
  const engine = new MemoryEngine();
  engine.matchReply = {
    banner: bannerResults(),
    matched: [{ path: '/evidence/symbols/linux.zip', labels: ['Debian 3.2'] }],
    diagnostics: [],
  };
  const { app: instance } = await app({
    engine,
    launch: { image: '/evidence/memory.raw', symbols: '/evidence/symbols/linux.zip' },
    assets: [asset(), asset({ path: '/evidence/symbols/linux.zip', kind: 'symbols', name: 'linux.zip' })],
    page: null,
  });
  // An image on the command line goes straight to the analysis console.
  assert.equal(instance.state.page, 'analysis');
  assert.equal(instance.state.image, '/evidence/memory.raw');
  assert.equal(instance.state.preparation, 'ready');
  assert.equal(instance.state.choice, 'Debian 3.2');
  assert.equal(instance.state.symbols, '/evidence/symbols/linux.zip');
  assert.equal(instance.state.results.get('banners')?.plugin, 'banners');
});

test('a single local match is selected and multiple matches ask for a choice', async () => {
  const engine = new MemoryEngine();
  engine.matchReply = {
    banner: bannerResults(),
    matched: [
      { path: '/evidence/a.json.xz', labels: ['one'] },
      { path: '/evidence/a.json.xz', labels: ['two'] },
    ],
    diagnostics: ['member broken'],
  };
  const { app: instance } = await app({
    engine,
    launch: { image: '/evidence/memory.raw' },
    assets: [asset(), asset({ path: '/evidence/a.json.xz', kind: 'symbols', name: 'a.json.xz' })],
  });
  assert.equal(instance.state.preparation, 'chooseSymbols');
  assert.equal(instance.state.dialog?.kind, 'symbols');
  assert.equal(instance.state.localMatchErrors.length, 1);
  assert.equal(instance.state.lastError, 'member broken');
});

test('no local match reports missing symbols and never pretends to be ready', async () => {
  const engine = new MemoryEngine();
  engine.matchReply = { banner: bannerResults(), matched: [], diagnostics: [] };
  const { app: instance } = await app({
    engine,
    launch: { image: '/evidence/memory.raw' },
    assets: [asset()],
  });
  assert.equal(instance.state.preparation, 'missingSymbols');
  assert.match(instance.state.status, /没有本地精确匹配/);
});

test('identification switches the plugin list and drops the parameters of the other system', async () => {
  const { app: instance } = await app();
  const windowsBanner = results({
    plugin: 'banners',
    columns: ['Offset', 'Banner'],
    rows: [['[container]', 'Windows PDB ntkrnlmp.pdb/GUID age 1']],
    system: 'windows',
  });
  instance.state.analysisOptions = {
    ...instance.state.analysisOptions,
    pid: 4,
    hive: '4096',
    key: 'Software',
  };
  instance.applyIdentification(windowsBanner);
  assert.equal(instance.state.windows, true);
  assert.equal(instance.state.plugin, 'windows.pslist');
  assert.equal(instance.state.analysisOptions.pid, null);
  assert.equal(instance.state.analysisOptions.hive, null);

  // Windows-only attachments survive a switch *to* Windows…
  instance.state.analysisOptions = {
    ...instance.state.analysisOptions,
    pagefiles: [{ index: 1, path: '/evidence/pagefile.sys' }],
  };
  const linuxBanner = results({
    plugin: 'banners',
    columns: ['Offset', 'Banner'],
    rows: [['0x1000', 'Linux version 3.2.0-4-amd64 #1 SMP']],
    system: 'linux',
  });
  instance.applyIdentification(linuxBanner);
  // …and are cleared when the image turns out to be Linux.
  assert.equal(instance.state.windows, false);
  assert.deepEqual(instance.state.analysisOptions.pagefiles, []);
  assert.equal(instance.state.analysisOptions.swapfile, null);
});

test('manual system choice survives an unrelated Linux banner', async () => {
  const { app: instance } = await app();
  await instance.selectOs('windows');
  const banner = results({
    plugin: 'banners',
    columns: ['Offset', 'Banner'],
    rows: [['0x1000', 'Linux version 6.8.0']],
    system: 'linux',
  });
  instance.applyIdentification(banner);
  assert.equal(instance.state.windows, true);
  assert.equal(instance.identificationStatus(banner), '保留手动系统选择');
});

test('cancelling a task never applies its result', async () => {
  const engine = new MemoryEngine();
  let release: (() => void) | null = null;
  engine.analyze = () =>
    new Promise((resolve) => {
      release = () => resolve({ result: results() });
    });
  const { app: instance } = await app({
    engine,
    launch: { image: '/evidence/memory.raw', symbols: '/evidence/linux.zip' },
    assets: [asset(), asset({ path: '/evidence/linux.zip', kind: 'symbols', name: 'linux.zip' })],
  });
  instance.state.preparation = 'ready';
  const run = instance.requestAnalysis(false);
  await waitFor(() => instance.state.busy);
  await instance.cancel();
  (release as unknown as () => void)();
  await run;
  assert.equal(engine.cancelled, true);
  assert.equal(instance.state.results.has('pslist'), false);
  assert.equal(instance.state.busy, false);
  assert.match(instance.state.status, /已取消/);
});

test('a new request while busy queues only the last one', async () => {
  const engine = new MemoryEngine();
  let release: (() => void) | null = null;
  let calls = 0;
  engine.analyze = () => {
    calls += 1;
    if (calls === 1) {
      return new Promise((resolve) => {
        release = () => resolve({ result: results() });
      });
    }
    return Promise.resolve({ result: results({ plugin: 'pslist', rows: [['2', 'later']] }) });
  };
  const { app: instance } = await app({
    engine,
    launch: { image: '/evidence/memory.raw' },
    assets: [asset()],
  });
  instance.state.preparation = 'ready';
  const first = instance.requestAnalysis(false);
  await waitFor(() => instance.state.busy);
  await instance.requestAnalysis(true);
  assert.equal(instance.state.pendingWork?.kind, 'analyze');
  (release as unknown as () => void)();
  await first;
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(calls, 2);
  assert.equal(instance.state.pendingWork, null);
});

test('the resource toolbar drops section-specific actions', () => {
  assert.ok(toolbarCommands('images', false).includes('enterAnalysis'));
  assert.ok(!toolbarCommands('images', false).includes('download'));
  assert.ok(toolbarCommands('remote', false).includes('download'));
  assert.ok(!toolbarCommands('symbols', false).includes('download'));
  assert.equal(toolbarCommands('images', true)[0], 'cancel');
});

test('one key resolves to the page-specific command', () => {
  assert.equal(commandForKey('assets', 'd'), 'assetDetail');
  assert.equal(commandForKey('analysis', 'd'), 'detail');
  assert.equal(commandForKey('assets', 'r'), 'refreshAssets');
  assert.equal(commandForKey('analysis', 'r'), 'rerun');
  assert.equal(commandForKey('assets', 'K'), 'generateSymbols');
  assert.equal(commandForKey('analysis', 'g'), 'generateSymbols');
  assert.equal(commandForKey('analysis', 'R'), 'run');
  assert.equal(commandForKey('assets', '2'), 'pageAnalysis');
  assert.equal(commandForKey('analysis', 'F5'), null);
});

test('section-specific commands do not apply to other sections', () => {
  assert.equal(commandApplies('download', 'images'), false);
  assert.equal(commandApplies('download', 'remote'), true);
  assert.equal(commandApplies('toggleMatchFilter', 'symbols'), true);
  assert.equal(commandApplies('toggleMatchFilter', 'remote'), false);
});

test('the palette filters by page, focus and query', () => {
  const assets = commandMatches('', 'assets', 'navigation', 'images');
  assert.ok(assets.some((entry) => entry.command === 'select'));
  assert.ok(!assets.some((entry) => entry.command === 'export'));
  const dump = commandMatches('dump', 'analysis', 'content', null);
  assert.ok(dump.some((entry) => entry.command === 'dump'));
});

test('filters and tree collapse affect only the visible rows', async () => {
  const { app: instance } = await app();
  instance.state.plugin = 'pstree';
  instance.state.results.set('pstree', {
    ...results({
      plugin: 'pstree',
      columns: ['PID', 'TGID', 'PPID', 'Name', 'Address'],
      rows: [
        ['1', '1', '0', 'init', '0x1000'],
        ['2', '2', '1', 'child', '0x2000'],
        ['3', '3', '0', 'other', '0x3000'],
      ],
    }),
  });
  instance.state.results.set(requestKey(instance.state), instance.state.results.get('pstree') as never);
  instance.state.query = 'child';
  const filtered = viewIndex(instance.state);
  assert.deepEqual(filtered.filtered, [1]);
  instance.state.query = '';
  const all = viewIndex(instance.state);
  assert.equal(all.visible.length, 3);
  instance.state.collapsed.add('1');
  const collapsed = viewIndex(instance.state);
  assert.equal(collapsed.visible.length, 2);
  assert.equal(collapsed.filtered.length, 3);
  // The collapsed root keeps its expander marker; the other root is a leaf.
  const root = visibleRow(instance.state, collapsed, 0);
  assert.match(root?.[3] ?? '', /^▸/);
  // A leaf keeps the `·` marker so depth still reads at a glance.
  const leaf = visibleRow(instance.state, collapsed, 1);
  assert.equal(leaf?.[3], '· other');
});

test('sorting uses numeric order for address and PID columns', async () => {
  const { app: instance } = await app();
  instance.state.results.set('pslist', results({ rows: [['10', 'b'], ['2', 'a'], ['1', 'c']] }));
  instance.state.results.set(requestKey(instance.state), results({ rows: [['10', 'b'], ['2', 'a'], ['1', 'c']] }));
  instance.state.sort = 0;
  instance.state.descending = false;
  const index = viewIndex(instance.state);
  assert.deepEqual(
    index.filtered.map((position) => (instance.state.results.get('pslist') as { rows: string[][] }).rows[position]?.[0]),
    ['1', '2', '10'],
  );
});

test('remote filtering matches every space-separated term', async () => {
  const { app: instance } = await app();
  instance.state.remote = [
    { banner: 'Linux version 3.2 Debian', path: 'Debian/amd64/one.json.xz', url: 'https://example/one' },
    { banner: 'Linux version 6.8 Kali', path: 'Kali/arm64/two.json.xz', url: 'https://example/two' },
  ];
  instance.state.assetQueries[2] = 'debian 3.2';
  assert.equal(remoteList(instance.state).length, 1);
  instance.state.assetQueries[2] = 'missing';
  assert.equal(remoteList(instance.state).length, 0);
});

test('parameters reject a printkey form without a hive address', async () => {
  const { app: instance } = await app();
  instance.state.plugin = 'windows.printkey';
  const missing = parseOptions(instance.state, ['', '', '', 'auto', '', '']);
  assert.equal(missing.error, 'printkey 必须填写 hive 地址');
  const invalid = parseOptions(instance.state, ['zzz', '', '', 'auto', '', '']);
  assert.match(invalid.error ?? '', /无效地址/);
  const valid = parseOptions(instance.state, ['0xffff800000001000', 'Software', '', 'x64', '1=/p.sys', '']);
  assert.equal(valid.error, undefined);
  assert.equal(valid.options?.hive, BigInt('0xffff800000001000').toString());
  assert.equal(valid.options?.arch, 'x64');
  assert.deepEqual(valid.options?.pagefiles, [{ index: 1, path: '/p.sys' }]);
});

test('pagefile parsing bounds the index and rejects an empty path', async () => {
  const { app: instance } = await app();
  assert.match(parseOptions(instance.state, ['', '', '', 'auto', '16=/p.sys', '']).error ?? '', /0\.\.15/);
  assert.match(parseOptions(instance.state, ['', '', '', 'auto', '1=', '']).error ?? '', /路径不能为空/);
  assert.match(parseOptions(instance.state, ['', '', '', 'nope', '', '']).error ?? '', /无效架构/);
});

test('keys normalise Ink events into the action tokens', () => {
  const base = {
    upArrow: false,
    downArrow: false,
    leftArrow: false,
    rightArrow: false,
    pageDown: false,
    pageUp: false,
    home: false,
    end: false,
    return: false,
    escape: false,
    ctrl: false,
    shift: false,
    tab: false,
    backspace: false,
    delete: false,
    meta: false,
  };
  assert.equal(keyToken('q', base), 'q');
  assert.equal(keyToken(' ', base), ' ');
  assert.equal(keyToken('\r', { ...base, return: true }), 'Enter');
  assert.equal(keyToken('\u001b', { ...base, escape: true }), 'Esc');
  assert.equal(keyToken('\t', { ...base, tab: true }), 'Tab');
  assert.equal(keyToken('\t', { ...base, tab: true, shift: true }), 'BackTab');
  assert.equal(keyToken('r', { ...base, ctrl: true }), 'Ctrl+r');
  assert.equal(keyToken('f2', base), 'F2');
  assert.equal(keyToken('\u001b[1;3D', { ...base, leftArrow: true, meta: true }), 'Alt+Left');
  assert.equal(keyToken('', { ...base, delete: true }), 'Delete');
  assert.equal(keyToken('hello', base), null);
});

test('asset selection imports, invalidates and prepares in one step', async () => {
  const engine = new MemoryEngine();
  engine.matchReply = { banner: bannerResults(), matched: [], diagnostics: [] };
  const { app: instance } = await app({
    engine,
    assets: [asset(), asset({ path: '/evidence/symbols/linux.zip', kind: 'symbols', name: 'linux.zip' })],
  });
  instance.state.section = 'images';
  instance.state.assetRows[0] = 0;
  await instance.selectAsset();
  assert.equal(instance.state.image, '/evidence/memory.raw');
  assert.equal(instance.state.symbols, '');
  assert.equal(instance.state.preparation, 'missingSymbols');
});

test('removing the active image invalidates every bound result', async () => {
  const { app: instance, engine } = await app({
    assets: [asset(), asset({ path: '/evidence/symbols/linux.zip', kind: 'symbols', name: 'linux.zip' })],
    launch: { image: '/evidence/memory.raw', symbols: '/evidence/symbols/linux.zip' },
  });
  instance.state.results.set('pslist', results());
  instance.state.section = 'images';
  instance.state.assetRows[0] = 0;
  await instance.deleteAsset();
  assert.equal(instance.state.image, null);
  assert.equal(instance.state.results.size, 0);
  assert.equal(engine.closed, false);
});

test('enter on an unused asset selects it and opens analysis when ready', async () => {
  const engine = new MemoryEngine();
  engine.matchReply = {
    banner: bannerResults(),
    matched: [{ path: '/evidence/symbols/linux.zip', labels: ['Debian'] }],
    diagnostics: [],
  };
  const { app: instance } = await app({
    engine,
    assets: [asset(), asset({ path: '/evidence/symbols/linux.zip', kind: 'symbols', name: 'linux.zip' })],
  });
  instance.state.section = 'images';
  instance.state.assetRows[0] = 0;
  await instance.selectAndEnter();
  assert.equal(instance.state.page, 'analysis');
  assert.equal(instance.state.preparation, 'ready');
});

test('q during a task arms the quit instead of exiting', async () => {
  const { app: instance } = await app();
  instance.state.busy = true;
  let quit = false;
  instance.onQuit(() => {
    quit = true;
  });
  assert.equal(instance.requestQuit(), false);
  assert.equal(instance.state.quitArmed, true);
  assert.equal(quit, false);
  assert.equal(instance.requestQuit(), true);
  assert.equal(quit, true);
});

test('export uses the filtered rows, not just the visible page', async () => {
  const { app: instance, engine } = await app();
  instance.state.results.set('pslist', results({ rows: [['1', 'a'], ['2', 'b'], ['3', 'c']] }));
  instance.state.results.set(requestKey(instance.state), results({ rows: [['1', 'a'], ['2', 'b'], ['3', 'c']] }));
  instance.state.query = 'b';
  instance.openInput('export');
  const dialog = instance.state.dialog;
  assert.equal(dialog?.kind, 'input');
  if (dialog?.kind === 'input') {
    instance.state.dialog = { ...dialog, text: '/evidence/exports/pslist.csv' };
  }
  await instance.dialogKey('Enter', {});
  assert.equal(engine.exported?.rows, 1);
});

test('the empty-state hint depends on whether symbols are selected', async () => {
  const { app: instance } = await app();
  assert.equal(instance.state.symbols, '');
  assert.match(instance.state.status, /选择镜像/);
  instance.state.symbols = '/evidence/linux.zip';
  assert.equal(instance.state.symbols, '/evidence/linux.zip');
});

test('an offline toggle persists through the engine', async () => {
  const { app: instance, engine } = await app();
  assert.equal(instance.state.settings.remote_symbols, false);
  await instance.toggleOnline();
  assert.equal(engine.settings.remote_symbols, true);
  assert.match(instance.state.status, /在线/);
  await instance.toggleOnline();
  assert.match(instance.state.status, /离线/);
});

test('the fixture keeps asset kinds independent', () => {
  const image = assetFixture();
  const symbols = assetFixture({ kind: 'symbols', path: '/evidence/symbols/a.json.xz' });
  assert.equal(image.kind, 'image');
  assert.equal(symbols.kind, 'symbols');
  assert.equal(hello().plugins.length, 6);
});

test('no binding or label asks for a function key', () => {
  const functionKey = /\bF\d/u;
  for (const key of Object.values(KEYS)) {
    assert.doesNotMatch(key, functionKey);
  }
  for (const entry of ACTIONS) {
    assert.doesNotMatch(entry.label, functionKey);
  }
  for (const windows of [false, true]) {
    for (const mode of dumpModes(windows)) {
      assert.doesNotMatch(mode.label, functionKey);
    }
  }
});

test('scan plugins require a pattern and other plugins never send one', async () => {
  const { app: instance } = await app();
  instance.state.hello = {
    ...instance.state.hello!,
    plugins: [
      ...instance.state.hello!.plugins,
      { name: 'vmayarascan', label: 'vmayarascan', category: 'Memory', columns: ['PID', 'Name', 'Address', 'Start', 'Permissions', 'Path', 'Context'], widths: [6, 14, 18, 18, 5, 0, 0], description: 'scan' } as never,
    ],
  };
  instance.state.plugin = 'vmayarascan';
  const fields = ['', '', '', 'auto', '', '', '', ''];
  assert.equal(parseOptions(instance.state, fields).error, '扫描插件需要填写搜索模式');
  fields[7] = 'hex:4d5a??00';
  assert.equal(parseOptions(instance.state, fields).options?.pattern, 'hex:4d5a??00');
  instance.state.plugin = 'pslist';
  assert.equal(parseOptions(instance.state, fields).options?.pattern, null);
});
