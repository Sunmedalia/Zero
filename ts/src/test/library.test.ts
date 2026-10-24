import assert from 'node:assert/strict';
import test from 'node:test';
import { app, asset } from './harness.js';
import { renderFrame } from '../views/root.js';
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
