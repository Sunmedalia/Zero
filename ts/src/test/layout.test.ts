import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeMouse, listenMouse, type MouseEvent } from '../mouse.js';
import { Canvas, toRuns } from '../canvas.js';
import { computeLayout, frameInner, hitMap, inside, type Rect } from '../layoutTree.js';
import { app, results } from './harness.js';
import { requestKey } from '../state.js';

/* ------------------------------------------------------------------ */
/* Mouse decoding                                                       */
/* ------------------------------------------------------------------ */

test('SGR press and release decode to one-based cells converted to zero-based', () => {
  const { events } = decodeMouse('\u001b[<0;15;1M\u001b[<0;15;1m');
  assert.equal(events.length, 2);
  assert.deepEqual(
    events.map((event) => ({ kind: event.kind, button: event.button, x: event.x, y: event.y })),
    [
      { kind: 'press', button: 0, x: 14, y: 0 },
      { kind: 'release', button: 0, x: 14, y: 0 },
    ],
  );
});

test('wheel reports map to the wheel kind with the direction kept in the button', () => {
  const up = decodeMouse('\u001b[<64;5;9M').events[0] as MouseEvent;
  const down = decodeMouse('\u001b[<65;5;9M').events[0] as MouseEvent;
  assert.equal(up.kind, 'wheel');
  assert.equal(up.button, 64);
  assert.equal(down.kind, 'wheel');
  assert.equal(down.button, 65);
  assert.equal(up.x, 4);
  assert.equal(up.y, 8);
});

test('modifier bits are decoded from the button field', () => {
  // 0 + shift(4) + ctrl(16) on button 0, middle button (1) with alt(8).
  const shiftCtrl = decodeMouse('\u001b[<20;2;3M').events[0] as MouseEvent;
  assert.equal(shiftCtrl.shift, true);
  assert.equal(shiftCtrl.ctrl, true);
  assert.equal(shiftCtrl.alt, false);
  const middleAlt = decodeMouse('\u001b[<9;2;3M').events[0] as MouseEvent;
  assert.equal(middleAlt.button, 1);
  assert.equal(middleAlt.alt, true);
});

test('a report split across reads is completed by the next chunk', () => {
  let pending = '';
  const seen: MouseEvent[] = [];
  const source = {
    listeners: [] as ((chunk: string) => void)[],
    on(_event: string, listener: (chunk: string) => void) {
      this.listeners.push(listener);
    },
    off(_event: string, listener: (chunk: string) => void) {
      this.listeners = this.listeners.filter((entry) => entry !== listener);
    },
    emit(chunk: string) {
      for (const listener of this.listeners) {
        listener(chunk);
      }
    },
  };
  const detach = listenMouse(source, (event) => seen.push(event));
  source.emit('\u001b[<0;10');
  assert.equal(seen.length, 0);
  source.emit(';4M');
  assert.equal(seen.length, 1);
  assert.equal(seen[0]?.x, 9);
  assert.equal(seen[0]?.y, 3);
  detach();
  source.emit('\u001b[<0;1;1M');
  assert.equal(seen.length, 1);
  void pending;
});

test('ordinary keystrokes and unrelated escape sequences are ignored', () => {
  const { events, rest } = decodeMouse('hello\u001b[Aq');
  assert.equal(events.length, 0);
  assert.equal(rest, '');
});

/* ------------------------------------------------------------------ */
/* Canvas                                                              */
/* ------------------------------------------------------------------ */

test('canvas keeps every row exactly the terminal width', () => {
  const canvas = new Canvas(20, 3);
  canvas.write(0, 0, 'hello', { color: 'red' });
  canvas.write(0, 1, '镜像', { color: 'blue' });
  for (const line of canvas.lines()) {
    // One grid cell per terminal column; a wide glyph's second column is a
    // continuation cell, so the array length is the width.
    assert.equal(line.length, 20);
  }
});

test('wide characters occupy two cells and never split', () => {
  const canvas = new Canvas(6, 1);
  // Two cells for the wide glyph, then only one column left: the next wide
  // glyph must be dropped rather than half-written.
  canvas.write(0, 0, '镜镜', { color: 'red' }, 3);
  const line = canvas.lines()[0] ?? [];
  assert.equal(line[0]?.text, '镜');
  assert.equal(line[1]?.continuation, true);
  assert.equal(line[2]?.text, ' ');
});

test('canvas clips text at the right edge instead of overflowing', () => {
  const canvas = new Canvas(5, 1);
  canvas.write(3, 0, 'abcdef', {});
  const runs = toRuns(canvas.lines()[0] ?? []);
  const text = runs.map((run) => run.text).join('');
  assert.equal(text.length, 5);
  assert.ok(text.endsWith('ab'));
});

test('frames draw all four corners and both edges', () => {
  const canvas = new Canvas(10, 4);
  canvas.frame(0, 0, 10, 4, { color: 'grey' });
  const rows = canvas.lines().map((line) => line.map((cell) => cell.text).join(''));
  assert.equal(rows[0], '╭────────╮');
  assert.equal(rows[3], '╰────────╯');
  assert.ok(rows[1]?.startsWith('│') && rows[1]?.endsWith('│'));
});

test('adjacent cells with the same style collapse into one run', () => {
  const canvas = new Canvas(6, 1);
  canvas.write(0, 0, 'abc', { color: 'red' });
  canvas.write(3, 0, 'de', { color: 'red' });
  const runs = toRuns(canvas.lines()[0] ?? []);
  // Five red cells collapse; the untouched trailing cell keeps its own style.
  assert.equal(runs.length, 2);
  assert.equal(runs[0]?.text, 'abcde');
  assert.equal(runs[0]?.color, 'red');
  assert.equal(runs[1]?.text, ' ');
  assert.equal(runs[1]?.color, undefined);
});

/* ------------------------------------------------------------------ */
/* Layout and hit testing                                               */
/* ------------------------------------------------------------------ */

function covers(region: Rect, x: number, y: number): boolean {
  return inside(region, x, y);
}

test('layout regions never overlap the chrome', async () => {
  const { app: instance } = await app();
  const layout = computeLayout(instance.state, 100, 30);
  assert.equal(layout.tabs.y, 0);
  assert.equal(layout.systems.y, 0);
  assert.equal(layout.header.y, 1);
  assert.equal(layout.body.y, 2);
  assert.equal(layout.status.y, layout.body.y + layout.body.height);
  assert.ok(layout.actions.y >= layout.status.y);
  assert.equal(layout.actions.y + layout.actions.height, 30);
});

test('a click on a tab hits exactly one tab', async () => {
  const { app: instance } = await app();
  const layout = computeLayout(instance.state, 100, 30);
  const hits = layout.tabsHits.filter((tab) => covers(tab.rect, 15, 0));
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.page, 'analysis');
  const left = layout.tabsHits.filter((tab) => covers(tab.rect, 4, 0));
  assert.equal(left.length, 1);
  assert.equal(left[0]?.page, 'assets');
});

test('system chips are placed by display width, not string length', async () => {
  const { app: instance } = await app();
  instance.switchPage('assets');
  const layout = computeLayout(instance.state, 80, 24);
  const auto = layout.systemHits.find((hit) => hit.os === 'auto');
  assert.ok(auto, 'auto chip must fit at 80 columns');
  // " 自动 " is two wide characters (four cells) plus two spaces: six cells,
  // while `String.length` would report four.
  assert.equal(auto.rect.width, 6);
  assert.equal(' 自动 '.length, 4);
  // Every chip starts where the previous one ended.
  for (let index = 1; index < layout.systemHits.length; index += 1) {
    const previous = layout.systemHits[index - 1] as { rect: Rect };
    const current = layout.systemHits[index] as { rect: Rect };
    assert.equal(current.rect.x, previous.rect.x + previous.rect.width);
  }
});

test('list rows are individually clickable and map to absolute indices', async () => {
  const { app: instance } = await app({
    assets: Array.from({ length: 6 }, (_, index) => ({
      id: `id${index}`,
      path: `/evidence/image-${index}.raw`,
      name: `image-${index}.raw`,
      kind: 'image' as const,
      bytes: 1024,
      available: true,
      directory: false,
      format: 'RAW/LiME',
      origin: '项目',
      stamp: 'stamp',
      source_url: null,
    })),
  });
  instance.switchPage('assets');
  const layout = computeLayout(instance.state, 100, 30);
  const pane = layout.panes.find((entry) => entry.section === 'images');
  assert.ok(pane);
  const hits = layout.rowHits.filter((hit) => hit.section === 'images');
  assert.equal(hits.length, Math.min(pane.visible, 6));
  for (const [position, hit] of hits.entries()) {
    assert.equal(hit.index, pane.offset + position);
    assert.ok(covers(hit.rect, hit.rect.x, hit.rect.y));
    // A click one row lower must not hit the same row.
    assert.equal(covers(hit.rect, hit.rect.x, hit.rect.y + 1), false);
  }
});

test('the footer chips are inside the action strip and never overlap', async () => {
  const { app: instance } = await app();
  const layout = computeLayout(instance.state, 80, 24);
  const chips = layout.buttons.filter((button) => button.rect.y >= layout.actions.y);
  assert.ok(chips.length >= 4);
  for (const chip of chips) {
    assert.ok(chip.rect.y >= layout.actions.y && chip.rect.y < layout.actions.y + layout.actions.height);
  }
  for (let a = 0; a < chips.length; a += 1) {
    for (let b = a + 1; b < chips.length; b += 1) {
      const left = chips[a] as { rect: Rect };
      const right = chips[b] as { rect: Rect };
      const overlap =
        left.rect.y === right.rect.y &&
        left.rect.x < right.rect.x + right.rect.width &&
        right.rect.x < left.rect.x + left.rect.width;
      assert.equal(overlap, false, `chips overlap: ${JSON.stringify([left, right])}`);
    }
  }
});

test('the content table rows line up with the framed interior', async () => {
  const { app: instance } = await app();
  instance.state.page = 'analysis';
  const current = results({ columns: ['PID', 'Name'], rows: [['1', 'a'], ['2', 'b']] });
  instance.state.results.set('pslist', current);
  instance.state.results.set(requestKey(instance.state), current);
  const layout = computeLayout(instance.state, 100, 30);
  assert.ok(layout.content);
  const inner = frameInner(layout.content);
  const rows = layout.rowHits.filter(
    (hit) => hit.section === null && hit.rect.y >= inner.y && hit.rect.x >= inner.x,
  );
  assert.ok(rows.length > 0);
  assert.equal(rows[0]?.rect.y, inner.y + 1, 'first data row is below the header row');
  assert.equal(rows[0]?.rect.x, inner.x);
});

test('a modal owns the whole screen for clicks', async () => {
  const { app: instance } = await app();
  instance.state.dialog = { kind: 'system', selected: 0 };
  const layout = computeLayout(instance.state, 100, 30);
  assert.ok(layout.popup);
  const hits = hitMap(layout, instance.state);
  assert.deepEqual(hits.popup, layout.popup);
  // Row buttons exist for the three systems and Esc.
  const rows = layout.buttons.filter((button) => button.key.startsWith('row:'));
  assert.equal(rows.length, 3);
  assert.ok(layout.buttons.some((button) => button.key === 'Esc'));
});

test('search fields are drawn inline and are not treated as modals', async () => {
  const { app: instance } = await app();
  instance.state.page = 'analysis';
  instance.state.query = 'abc';
  const layout = computeLayout(instance.state, 100, 30);
  assert.ok(layout.contentSearch);
  assert.equal(layout.popup, null);
});

test('narrow layouts stack the panes, short ones show only the active pane', async () => {
  const { app: instance } = await app();
  instance.switchPage('assets');
  const wide = computeLayout(instance.state, 100, 24);
  assert.equal(wide.panes.length, 2);
  assert.equal(wide.panes[0]?.frame.x, 0);
  assert.ok((wide.panes[1]?.frame.x ?? 0) > 0, 'wide layout is side by side');

  const narrow = computeLayout(instance.state, 50, 24);
  assert.equal(narrow.panes.length, 2);
  assert.equal(narrow.panes[0]?.frame.x, 0);
  assert.equal(narrow.panes[1]?.frame.x, 0, 'narrow layout stacks vertically');
  assert.ok((narrow.panes[1]?.frame.y ?? 0) > (narrow.panes[0]?.frame.y ?? 0));

  // Below MIN_ASSET_TWO_PANES only the active pane is drawn.
  const short = computeLayout(instance.state, 50, 16);
  assert.equal(short.panes.length, 1);
});

test('the analysis menu disappears when content has focus on a narrow screen', async () => {
  const { app: instance } = await app();
  instance.state.page = 'analysis';
  instance.state.focus = 'content';
  const layout = computeLayout(instance.state, 60, 24);
  assert.equal(layout.menu, null);
  instance.state.focus = 'navigation';
  const withMenu = computeLayout(instance.state, 60, 24);
  assert.ok(withMenu.menu);
});
