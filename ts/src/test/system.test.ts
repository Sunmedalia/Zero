import assert from 'node:assert/strict';
import test from 'node:test';
import { app, results } from './harness.js';
import { renderFrame } from '../views/root.js';
import { shownSystem } from '../state.js';

function text(frame: ReturnType<typeof renderFrame>): string {
  return frame.canvas.lines().map((line) => line.filter((cell) => !cell.continuation).map((cell) => cell.text).join('')).join('\n');
}

const WINDOWS_BANNER = results({
  plugin: 'banners',
  system: 'windows',
  columns: ['Offset', 'Banner'],
  rows: [['0x1000', 'Windows PDB ntkrnlmp.pdb 0123456789ABCDEF0123456789ABCDEF1']],
});

test('automatic detection shows the detected system chip as the active one', async () => {
  const { app: instance } = await app({ page: 'assets' });
  instance.resize(120, 30);
  assert.equal(instance.state.analysisOptions.os, 'auto');
  assert.equal(shownSystem(instance.state), null);
  let frame = text(renderFrame(instance, 120, 30));
  assert.doesNotMatch(frame.split('\n')[0] ?? '', /自动/u);
  assert.match(frame.split('\n')[1] ?? '', /系统未识别 · 镜像/u);

  instance.applyIdentification(WINDOWS_BANNER);
  instance.state.results.set('banners', WINDOWS_BANNER);
  assert.equal(shownSystem(instance.state), 'windows');
  assert.equal(instance.state.plugin, 'windows.pslist');
  frame = text(renderFrame(instance, 120, 30));
  assert.match(frame.split('\n')[1] ?? '', /Windows（自动识别） · 镜像/u);
});

test('clicking the chip of the detected system keeps the session; the other switches', async () => {
  const { app: instance } = await app({ page: 'analysis' });
  instance.resize(120, 30);
  instance.applyIdentification(WINDOWS_BANNER);
  instance.state.results.set('banners', WINDOWS_BANNER);
  instance.state.results.set('windows.pslist', results({ plugin: 'windows.pslist', system: 'windows' }));
  const layout = renderFrame(instance, 120, 30).layout;
  const windows = layout.systemHits.find((hit) => hit.os === 'windows')!;
  await instance.click(windows.rect.x, windows.rect.y);
  assert.equal(instance.state.page, 'analysis');
  assert.equal(instance.state.analysisOptions.os, 'auto');
  assert.ok(instance.state.results.has('windows.pslist'));
  const linux = layout.systemHits.find((hit) => hit.os === 'linux')!;
  await instance.click(linux.rect.x, linux.rect.y);
  assert.equal(instance.state.analysisOptions.os, 'linux');
  assert.equal(shownSystem(instance.state), 'linux');
});
