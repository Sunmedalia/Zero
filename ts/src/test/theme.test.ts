import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { TERMINAL_REPLY, backgroundFromEnv, parseBackground, queryBackground } from '../terminalTheme.js';
import { AUTO_THEME, SURFACE, THEMES, THEME_CHOICES, applyTheme, setTerminalBackground, themeOf } from '../text.js';

test('OSC 11 replies resolve to light or dark by luminance, at any channel width', () => {
  assert.equal(parseBackground('\u001b]11;rgb:ffff/fdfd/f6f6\u0007'), 'light');
  assert.equal(parseBackground('\u001b]11;rgb:1e1e/1e1e/2e2e\u001b\\'), 'dark');
  assert.equal(parseBackground('\u001b]11;rgb:f/f/f\u0007'), 'light');
  assert.equal(parseBackground('\u001b]11;rgba:0000/0000/0000/ffff\u0007'), 'dark');
  assert.equal(parseBackground('garbage'), null);
});

test('COLORFGBG names the background colour last', () => {
  assert.equal(backgroundFromEnv('15;0'), 'dark');
  assert.equal(backgroundFromEnv('0;15'), 'light');
  assert.equal(backgroundFromEnv('0;default;7'), 'light');
  assert.equal(backgroundFromEnv('7;8'), 'dark');
  assert.equal(backgroundFromEnv(undefined), null);
  assert.equal(backgroundFromEnv('x'), null);
});

class FakeTty extends EventEmitter {
  isTTY = true;
  isRaw = false;
  modes: boolean[] = [];
  written: string[] = [];
  constructor(private readonly reply: string | null) {
    super();
  }
  setRawMode(mode: boolean): void {
    this.isRaw = mode;
    this.modes.push(mode);
  }
  paused = false;
  pause(): void {
    this.paused = true;
  }
  resume(): void {}
  write(text: string): void {
    this.written.push(text);
    if (this.reply !== null) {
      setImmediate(() => this.emit('data', Buffer.from(this.reply as string, 'latin1')));
    }
  }
}

test('the startup query waits for the DA1 reply, restores the mode and never pauses stdin', async () => {
  const tty = new FakeTty('\u001b]11;rgb:fafa/fafa/fafa\u001b\\\u001b[?62;22c');
  assert.equal(await queryBackground(tty, tty), 'light');
  assert.deepEqual(tty.written, ['\u001b]11;?\u001b\\\u001b[c']);
  assert.deepEqual(tty.modes, [true, false]);
  assert.equal(tty.listenerCount('data'), 0);
  // Pausing would leave Ink's `readable` reader without input: keys and mouse dead.
  assert.equal(tty.paused, false);
  // A terminal without OSC 11 answers only DA1: no background, and no waiting.
  const plain = new FakeTty('\u001b[?1;2c');
  const started = Date.now();
  assert.equal(await queryBackground(plain, plain, 5000), null);
  assert.ok(Date.now() - started < 1000);
  // A terminal that answers neither costs only the timeout.
  const silent = new FakeTty(null);
  assert.equal(await queryBackground(silent, silent, 20), null);
  assert.equal(await queryBackground({ ...silent, isTTY: false, on: () => 0, off: () => 0, resume: () => 0 }, silent), null);
});

test('late terminal replies are recognised so they are not read as keys', () => {
  assert.ok(TERMINAL_REPLY.test('\u001b]11;rgb:1e1e/1e1e/1e1e\u001b\\'));
  assert.ok(TERMINAL_REPLY.test('\u001b[?62;22c'));
  assert.ok(!TERMINAL_REPLY.test('2'));
  assert.ok(!TERMINAL_REPLY.test('\u001b[A'));
  assert.ok(!TERMINAL_REPLY.test('\u001b[<0;5;9M'));
});

test('the auto theme follows the detected background and is first in the cycle', () => {
  assert.equal(THEME_CHOICES[0], AUTO_THEME);
  setTerminalBackground('light');
  assert.equal(themeOf(AUTO_THEME).palette, THEMES[1]!.palette);
  assert.match(themeOf(AUTO_THEME).label, /自动（终端浅色 → 纸白/u);
  applyTheme(AUTO_THEME);
  assert.equal(SURFACE, THEMES[1]!.palette.surface);
  setTerminalBackground('dark');
  assert.equal(themeOf(AUTO_THEME).palette, THEMES[0]!.palette);
  setTerminalBackground(null);
  assert.match(themeOf(AUTO_THEME).label, /未检测到终端背景，使用深色/u);
  applyTheme('slate');
});
