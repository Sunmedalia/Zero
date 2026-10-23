import assert from 'node:assert/strict';
import test from 'node:test';
import { app, asset } from './harness.js';
import { imageLines } from '../assetView.js';
import { renderFrame, handleKey } from '../views/root.js';
import { width } from '../text.js';

test('image names and directories wrap in full without digest or ellipsis', async () => {
  const name = '内存镜像-'.repeat(25) + 'capture.raw';
  const directory = '/evidence/' + 'very-long-capture-directory/'.repeat(8);
  const image = asset({ name, path: directory + name, id: 'abcdef'.repeat(11) });
  const lines = imageLines(image, 76);
  assert.equal(lines.filter((line) => line.kind === 'name').map((line) => line.text).join(''), name);
  assert.equal(lines.filter((line) => line.kind === 'directory').map((line) => line.text).join(''), '目录 ' + directory.slice(0, -1));
  assert.ok(lines.every((line) => width(line.text) <= 76));
  assert.ok(!lines.some((line) => line.text.includes('…') || line.text.includes(image.id)));
  const { app: instance } = await app({ assets: [image] });
  instance.switchPage('assets');
  instance.resize(80, 24);
  const frame = renderFrame(instance, 80, 24);
  const pane = frame.layout.panes[0]!;
  assert.equal(pane.entries.length, 1);
  const entry = pane.entries[0]!;
  assert.equal(entry.rect.height, lines.length);
  const drawn = frame.canvas.lines();
  for (let i = 0; i < lines.length; i += 1) {
    const actual = drawn[entry.rect.y + i]!.slice(entry.rect.x + 2, entry.rect.x + entry.rect.width)
      .filter((cell) => !cell.continuation).map((cell) => cell.text).join('');
    assert.equal(actual.trimEnd(), lines[i]!.text.trimEnd());
  }
});

test('source tabs and keyboard cycle all pages while preserving per-source selection and query', async () => {
  const { app: instance } = await app();
  instance.switchPage('assets');
  instance.resize(120, 35);
  instance.state.assetQueries[0] = 'memory';
  let frame = renderFrame(instance, 120, 35);
  const symbols = frame.layout.sourceHits.find((hit) => hit.section === 'symbols')!;
  await instance.click(symbols.rect.x, symbols.rect.y);
  assert.equal(instance.state.section, 'symbols');
  frame = renderFrame(instance, 120, 35);
  assert.equal(frame.layout.panes[0]?.section, 'symbols');
  await handleKey(instance, '', { tab: true });
  assert.equal(instance.state.section, 'remote');
  await handleKey(instance, '', { tab: true });
  assert.equal(instance.state.section, 'images');
  assert.equal(instance.state.assetQueries[0], 'memory');
  await handleKey(instance, '', { tab: true, shift: true });
  assert.equal(instance.state.section, 'remote');
});

test('scrolling wrapped image entries keeps the chosen item visible and all entry lines clickable', async () => {
  const images = Array.from({ length: 20 }, (_, index) => asset({
    id: String(index), name: `capture-${index}.raw`, path: `/evidence/long-directory-for-capture-${index}/capture-${index}.raw`,
  }));
  const { app: instance } = await app({ assets: images });
  instance.switchPage('assets');
  instance.resize(80, 24);
  instance.state.assetRows[0] = 19;
  let frame = renderFrame(instance, 80, 24);
  const pane = frame.layout.panes[0]!;
  assert.ok(pane.offset > 0);
  assert.ok(pane.entries.some((entry) => entry.index === 19));
  const previous = pane.entries.find((entry) => entry.index === 18)!;
  await instance.click(previous.rect.x + 3, previous.rect.y + 2);
  assert.equal(instance.state.assetRows[0], 18);
  instance.resize(120, 35);
  frame = renderFrame(instance, 120, 35);
  assert.ok(frame.layout.panes[0]!.entries.some((entry) => entry.index === 18));
  assert.equal(instance.state.image, null, 'browsing must not select evidence');
});

test('same-named images retain distinct full directory paths', () => {
  const first = imageLines(asset({ name: 'memory.raw', path: '/cases/one/memory.raw' }), 76);
  const second = imageLines(asset({ name: 'memory.raw', path: '/cases/two/memory.raw' }), 76);
  assert.notDeepEqual(first, second);
  assert.ok(first.some((line) => line.text === '目录 /cases/one'));
  assert.ok(second.some((line) => line.text === '目录 /cases/two'));
});
