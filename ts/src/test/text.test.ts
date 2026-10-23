import assert from 'node:assert/strict';
import test from 'node:test';
import {
  charWidth,
  compactRemotePath,
  escaped,
  summariseBanner,
  truncate,
  truncatePath,
  width,
  wrapLines,
} from '../text.js';
import { compareValues } from '../resultView.js';
import { actionRows, assetDetail, fullDigest, inspector, menuWidth, space, twoPanes } from '../layout.js';

test('display width counts CJK and emoji as two cells', () => {
  assert.equal(width('abc'), 3);
  assert.equal(width('镜像'), 4);
  assert.equal(width('a镜b'), 4);
  assert.equal(charWidth('…'), 1);
  assert.equal(charWidth('😀'), 2);
});

test('control characters are escaped instead of reaching the terminal', () => {
  assert.equal(escaped('plain'), 'plain');
  assert.equal(escaped('a\u0007b'), 'a\\u{7}b');
  assert.equal(escaped('line\nbreak'), 'line\\u{a}break');
});

test('truncation keeps the informative end of a path', () => {
  assert.equal(truncate('abcdef', 10), 'abcdef');
  assert.equal(truncate('abcdef', 4), 'abc…');
  assert.equal(truncatePath('/evidence/case-1/memory.raw', 12), '…/memory.raw');
  assert.equal(truncatePath('short', 12), 'short');
});

test('repository paths drop the shared content hash', () => {
  const path = `Debian/amd64/Debian_3.2.0-4-amd64_3.2.57-3+deb7u2_amd64-${'a'.repeat(64)}.json.xz`;
  const compact = compactRemotePath(path, 60);
  assert.ok(!compact.includes('a'.repeat(32)), compact);
  assert.ok(compact.includes('Debian_3.2.0-4-amd64'), compact);
  assert.ok(compact.endsWith('.json.xz'), compact);
});

test('kernel banners keep the identifying head', () => {
  const banner =
    'Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) (gcc version 4.6.3) #1 SMP Debian 3.2.57-3+deb7u2';
  const short = summariseBanner(banner);
  assert.ok(short.startsWith('Linux version 3.2.0-4-amd64'), short);
  assert.ok(short.endsWith('…'), short);
  assert.ok(short.length < banner.length);
});

test('prose wraps at cell boundaries and preserves blank lines', () => {
  assert.deepEqual(wrapLines('ab\ncd', 10), ['ab', 'cd']);
  assert.deepEqual(wrapLines('abcd', 2), ['ab', 'cd']);
  assert.deepEqual(wrapLines('a\n\nb', 5), ['a', '', 'b']);
});

test('numeric columns sort numerically and hex columns by value', () => {
  assert.equal(compareValues('2', '10'), -1);
  assert.equal(compareValues('0x10', '0x9'), 1);
  assert.equal(compareValues('10', 'abc'), -1);
  assert.equal(compareValues('abc', 'abd'), -1);
  assert.equal(compareValues('', ''), 0);
});

test('layout thresholds answer each question once', () => {
  assert.equal(twoPanes(space(99, 30)), false);
  assert.equal(twoPanes(space(100, 30)), true);
  assert.equal(twoPanes(space(120, 23)), false);
  assert.equal(menuWidth(space(99, 30)), 22);
  assert.equal(menuWidth(space(100, 30)), 24);
  assert.equal(inspector(space(159, 40)), false);
  assert.equal(inspector(space(160, 40)), true);
  assert.equal(assetDetail(space(100, 28)), true);
  assert.equal(assetDetail(space(99, 40)), false);
  assert.equal(fullDigest(space(60, 20)), true);
  assert.equal(fullDigest(space(59, 20)), false);
});

test('action rows reserve room for the overflow chip on every row', () => {
  assert.equal(actionRows(['退出 q', '帮助 F1'], 80, 3), 1);
  assert.ok(actionRows(['一个很长的操作标签 x', '另一个很长的操作标签 y'], 24, 3) >= 2);
  assert.equal(actionRows(['短 a'], 20, 3), 1);
  // A label wider than the strip is skipped rather than counted as a row.
  assert.equal(actionRows(['超出宽度的操作 a'], 5, 3), 1);
});
