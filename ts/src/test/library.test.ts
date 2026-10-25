import assert from 'node:assert/strict';
import test from 'node:test';
import { app, asset } from './harness.js';
import { handleKey, renderFrame } from '../views/root.js';
import { remoteList, settingsLabels } from '../state.js';
import { identityLabel, imageLines } from '../assetView.js';
import { assetDetailText, remoteDetailText, remoteFields } from '../detail.js';
import type { RemoteMatch, RemoteReply } from '../types.js';

function text(frame: ReturnType<typeof renderFrame>): string {
  return frame.canvas.lines().map((line) => line.filter((cell) => !cell.continuation).map((cell) => cell.text).join('')).join('\n');
}

const UBUNTU: RemoteMatch = {
  banner:
    'Linux version 5.4.0-1098-kvm (buildd@lcy02-amd64-114) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #104-Ubuntu SMP Fri Aug 18 09:21:53 UTC 2023 (Ubuntu 5.4.0-1098.104-kvm 5.4.246)',
  path: 'releases/download/isf-Ubuntu-amd64-5.4.0/Ubuntu_5.4.0-1098-kvm_5.4.0-1098.104_amd64.json.xz',
  url: 'https://github.com/Abyss-W4tcher/volatility3-symbols/releases/download/isf-Ubuntu-amd64-5.4.0/Ubuntu_5.4.0-1098-kvm_5.4.0-1098.104_amd64.json.xz',
};

const SAVED: RemoteReply = {
  matches: [UBUNTU],
  catalog: true,
  total: 1,
  index: { banners: 11683, entries: 9000, bytes: 4354630, age_seconds: 7200 },
};

test('opening the remote list shows the index saved earlier without any download', async () => {
  const { app: instance, engine } = await app({ page: 'assets' });
  engine.remoteReply = SAVED;
  await instance.switchSection('remote');
  assert.deepEqual(engine.remoteCalls.at(-1), {
    image: null, catalog: true, query: '', refresh: false, limit: 500, local_only: true,
  });
  assert.deepEqual(instance.state.remote, [UBUNTU]);
  assert.match(instance.state.status, /本地已保存索引 9000 条.*（r 重新获取）/u);
  // Switching away and back does not ask again.
  await instance.switchSection('symbols');
  await instance.switchSection('remote');
  assert.equal(engine.remoteCalls.length, 1);
  // `g` reuses the saved index too: only `r` asks for a refresh.
  await instance.fetchIndex();
  assert.equal(engine.remoteCalls.at(-1)?.refresh, false);
  assert.equal(engine.remoteCalls.at(-1)?.local_only, undefined);
});

test('without a saved index the remote list says how to get one', async () => {
  const { app: instance, engine } = await app({ page: 'assets' });
  engine.remoteReply = { matches: [], catalog: true, total: 0, index: null };
  await instance.switchSection('remote');
  assert.match(instance.state.status, /尚未获取远程索引；g 获取/u);
});

test('the remote detail lists the entry fields and offers download chips', async () => {
  const { app: instance, engine } = await app({ page: 'assets', launch: { image: '/evidence/memory.raw' } });
  engine.remoteReply = SAVED;
  instance.resize(120, 32);
  await instance.switchSection('remote');
  assert.deepEqual(remoteFields(UBUNTU), [
    ['发行版', 'Ubuntu'],
    ['内核版本', '5.4.0-1098-kvm'],
    ['架构', 'amd64'],
    ['编译器', 'gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)'],
    ['构建', '#104-Ubuntu SMP Fri Aug 18 09:21:53 UTC 2023 (Ubuntu 5.4.0-1098.104-kvm 5.4.246)'],
  ]);
  assert.match(remoteDetailText(instance.state, UBUNTU), /^发行版    Ubuntu\n内核版本  5\.4\.0-1098-kvm/u);
  assert.deepEqual(remoteFields({ ...UBUNTU, banner: 'Windows PDB ntkrnlmp.pdb/ABC1' }), []);

  instance.openAssetDetail();
  const frame = renderFrame(instance, 120, 32);
  const popup = frame.layout.popup!;
  const chips = frame.layout.buttons.filter((button) => button.rect.y === popup.y + popup.height - 2);
  assert.deepEqual(chips.map((chip) => chip.action), ['下载并选用 Space', '仅下载 w', '取消']);
  assert.match(text(frame), /\[下载并选用 Space\] \[仅下载 w\]/u);
  const only = chips.find((chip) => chip.key === 'w')!;
  await instance.click(only.rect.x, only.rect.y);
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(instance.state.dialog, null);
  assert.match(instance.state.status, /已保存到 \/evidence\/symbols\/downloaded\.json\.xz/u);
});

test('an identified image shows the kernel bound to it in the list and detail', () => {
  const linux = asset({
    identity: { system: 'linux', kernels: ['Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) #1 SMP'] },
  });
  assert.equal(identityLabel(linux), 'Linux 3.2.0-4-amd64');
  assert.deepEqual(
    imageLines(linux, 60).map((line) => line.kind),
    ['name', 'metadata', 'identity', 'directory', 'gap'],
  );
  const windows = asset({
    identity: { system: 'windows', kernels: ['Windows PDB ntkrnlmp.pdb/AAAA1', 'Windows PDB ntkrnlmp.pdb/BBBB1'] },
  });
  assert.equal(identityLabel(windows), 'Windows ntkrnlmp.pdb 等 2 个');
  assert.equal(identityLabel(asset()), null);
  assert.equal(imageLines(asset(), 60).some((line) => line.kind === 'identity'), false);
});

test('the image detail says whether identification is bound to the file', async () => {
  const { app: instance } = await app({ page: 'assets' });
  assert.match(assetDetailText(instance.state, asset()), /尚未识别：首次选用时扫描/u);
  const bound = asset({ identity: { system: 'windows', kernels: ['Windows PDB ntkrnlmp.pdb/AAAA1'] } });
  assert.match(assetDetailText(instance.state, bound), /已识别 Windows 内核（与此镜像绑定.*\nWindows PDB ntkrnlmp\.pdb\/AAAA1/u);
});

const MATCHED: RemoteMatch = {
  banner: 'Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 4.6.3) #1 SMP Debian 3.2.57-3+deb7u2',
  path: 'Debian/amd64/3.2.0/4/Debian_3.2.0-4-amd64_3.2.57-3+deb7u2_amd64.json.xz',
  url: 'https://raw.githubusercontent.com/Abyss-W4tcher/volatility3-symbols/master/Debian/amd64/3.2.0/4/Debian_3.2.0-4-amd64_3.2.57-3%2Bdeb7u2_amd64.json.xz',
};

test('an exact lookup for the image no longer hides the whole index', async () => {
  const { app: instance, engine } = await app({ page: 'assets', launch: { image: '/evidence/memory.raw' } });
  instance.resize(120, 32);
  engine.remoteReply = SAVED;
  engine.lookupReply = { matches: [MATCHED], catalog: false };
  await instance.switchSection('remote');
  assert.deepEqual(remoteList(instance.state), [UBUNTU]);
  // The lookup that used to replace the list now fills its own view.
  await instance.runWork({ kind: 'refreshLookup' });
  assert.equal(instance.state.remoteCatalog, false);
  assert.deepEqual(remoteList(instance.state), [MATCHED]);
  let frame = renderFrame(instance, 120, 32);
  assert.match(text(frame).split('\n')[2] ?? '', /远程索引 +│ +全部索引 1 +镜像匹配 1/u);
  // The index is still there: click its view, or press z.
  const all = frame.layout.remoteViewHits.find((view) => view.catalog)!;
  await instance.click(all.rect.x, all.rect.y);
  assert.deepEqual(remoteList(instance.state), [UBUNTU]);
  await handleKey(instance, 'z', {});
  assert.deepEqual(remoteList(instance.state), [MATCHED]);
  frame = renderFrame(instance, 120, 32);
  assert.ok(frame.layout.remoteViewHits.some((view) => !view.catalog && view.label.includes('镜像匹配 1')));
  // Looking up again leaves the index list untouched.
  assert.deepEqual(instance.state.remote, [UBUNTU]);
});

test('the matches view asks for an image first and looks up only once', async () => {
  const { app: instance, engine } = await app({ page: 'assets' });
  engine.remoteReply = SAVED;
  await instance.switchSection('remote');
  await instance.showRemoteView(false);
  assert.match(instance.state.status, /镜像匹配需要先选用镜像/u);
  assert.deepEqual(remoteList(instance.state), []);
});

test('the symbol repository and digest reuse are edited from settings', async () => {
  const { app: instance, engine } = await app({ page: 'assets' });
  instance.resize(120, 35);
  await handleKey(instance, ',', {});
  const rows = settingsLabels(instance.state);
  assert.match(rows[6] ?? '', /^远程符号仓库: https:\/\/github\.com\/Abyss-W4tcher\/volatility3-symbols/u);
  assert.match(rows[7] ?? '', /^镜像摘要: 每个新会话完整校验/u);
  for (let index = 0; index < 7; index += 1) {
    await handleKey(instance, '', { downArrow: true });
  }
  await handleKey(instance, '', { return: true });
  assert.equal(engine.settings.reuse_recorded_digest, true);
  assert.equal(instance.state.dialog?.kind, 'settings', 'the dialog stays open');
  assert.match(settingsLabels(instance.state)[7] ?? '', /文件未变时复用上次摘要/u);
  await handleKey(instance, '', { upArrow: true });
  await handleKey(instance, '', { return: true });
  assert.equal(instance.state.dialog?.kind, 'input');
  // Read through a function: assertions narrow `instance.state.dialog` otherwise.
  const dialogKind = () => instance.state.dialog?.kind;
  const typeInto = (value: string) => {
    const dialog = instance.state.dialog;
    assert.ok(dialog?.kind === 'input');
    instance.state.dialog = { ...dialog, text: value };
  };
  // An unaccepted address keeps the dialog and the old repository.
  typeInto('https://gitlab.com/me/r');
  await handleKey(instance, '', { return: true });
  assert.equal(engine.settings.symbol_repository, 'https://github.com/Abyss-W4tcher/volatility3-symbols');
  assert.equal(dialogKind(), 'input');
  // A new repository drops the index and matches of the previous one.
  instance.state.remote = [UBUNTU];
  typeInto('https://github.com/me/my-symbols');
  await handleKey(instance, '', { return: true });
  assert.equal(engine.settings.symbol_repository, 'https://github.com/me/my-symbols');
  assert.equal(instance.state.dialog, null);
  assert.deepEqual(instance.state.remote, []);
  assert.equal(instance.state.remoteLoaded, false);
  assert.match(instance.state.status, /远程符号仓库：https:\/\/github\.com\/me\/my-symbols/u);
});
