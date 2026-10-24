/**
 * The Ink application.
 *
 * One frame is: the layout tree for the current size, then each region rendered
 * absolutely into its rectangle. Input is routed once here — Ctrl+C, then any
 * modal, then page handlers — and mouse reports come from the raw stdin stream
 * because Ink's parser discards them.
 */
import React, { useEffect, useRef, useState } from 'react';
import { Box, Text, useInput, usePaste, useStdin, useWindowSize } from 'ink';
import type { App } from '../app.js';
import { computeLayout, hitMap, inside } from '../layoutTree.js';
import { keyToken } from '../keys.js';
import { disableMouse, enableMouse, listenMouse } from '../mouse.js';
import { Canvas, toRuns } from '../canvas.js';
import * as paint from './paint.js';

export function Root({
  app,
  size,
}: {
  app: App;
  /** Fixed size for screenshots and tests; the live terminal size otherwise. */
  size?: { columns: number; rows: number };
}): React.ReactElement {
  const window = useWindowSize();
  const columns = size?.columns ?? window.columns;
  const rows = size?.rows ?? window.rows;
  const { stdin } = useStdin();
  const [, force] = useState(0);
  const mounted = useRef(true);
  const sizeRef = useRef({ columns, rows });
  sizeRef.current = { columns, rows };

  useEffect(() => {
    mounted.current = true;
    return app.subscribe(() => {
      if (mounted.current) {
        force((value) => value + 1);
      }
    });
  }, [app]);

  // The running indicator and the elapsed seconds tick without any state change.
  useEffect(() => {
    if (!app.state.busy) {
      return undefined;
    }
    const timer = setInterval(() => force((value) => value + 1), 250);
    return () => clearInterval(timer);
  }, [app, app.state.busy]);

  useEffect(() => {
    app.resize(columns, rows);
  }, [app, columns, rows]);

  useInput((input, key) => {
    void handleKey(app, input, key);
  });

  usePaste((text) => {
    app.paste(text);
  });

  // Mouse reports never reach `useInput`: Ink drops CSI sequences it cannot map
  // to a key. Listen on the raw stream instead, and enable SGR reporting.
  useEffect(() => {
    enableMouse();
    const detach = listenMouse(stdin, (event) => {
      if (event.kind === 'wheel') {
        void app.wheel(event.button === 64 ? -1 : 1, event.x, event.y);
        return;
      }
      if (event.kind === 'press' && event.button === 0) {
        void app.click(event.x, event.y);
      } else if (event.kind === 'press' && event.button === 1) {
        void app.middleClick(event.x, event.y);
      } else if (event.kind === 'drag' && event.button === 0) {
        app.drag(event.x, event.y);
      } else if (event.kind === 'release') {
        app.release();
      }
    });
    return () => {
      detach();
      disableMouse();
    };
  }, [app, stdin]);

  const { canvas } = renderFrame(app, columns, rows);
  return <Frame lines={canvas.lines()} />;
}

/** Compose the same deterministic frame for Ink and render-level regression tests. */
export function renderFrame(app: App, columns: number, rows: number) {
  const layout = computeLayout(app.state, columns, rows);
  const canvas = new Canvas(columns, rows);
  paint.paintBackground(canvas);
  if (columns < 60 || rows < 16) {
    paint.paintEmpty(canvas, { x: 0, y: 0, width: columns, height: rows },
      '终端过小 · 至少 60×16', '调整窗口大小 · q / Ctrl+C 退出');
    return { canvas, layout };
  }
  paint.paintTabs(canvas, app, layout);
  paint.paintSystems(canvas, app, layout);
  if (app.state.page === 'analysis') {
    paint.paintAnalysisHeader(canvas, app, layout);
  } else {
    paint.paintResourceHeader(canvas, app, layout);
  }
  paint.paintSources(canvas, app, layout);
  for (const pane of layout.panes) {
    paint.paintPane(canvas, app, pane);
  }
  paint.paintAssetDetail(canvas, app, layout);
  paint.paintMenu(canvas, app, layout);
  paint.paintContent(canvas, app, layout);
  paint.paintCache(canvas, app, layout);
  paint.paintFooter(canvas, app, layout);
  paint.paintInspector(canvas, app, layout);
  paint.paintScrollbars(canvas, layout);
  paint.paintDialog(canvas, app, layout);
  app.setHits(hitMap(layout, app.state));
  return { canvas, layout };
}

/**
 * Emit the composed grid.
 *
 * Exactly one `<Text>` per row keeps every line the full terminal width, so Ink's
 * line diff can never leave a stale row behind. The whole frame is one node, so
 * there is no flex layout to disagree with the canvas.
 */
function Frame({ lines }: { lines: ReturnType<Canvas['lines']> }): React.ReactElement {
  return (
    <Box flexDirection="column">
      {lines.map((cells, index) => (
        <Text key={index}>
          {toRuns(cells).map((run, position) => (
            <Text
              key={position}
              color={run.color}
              backgroundColor={run.background}
              bold={run.bold}
              dimColor={run.dim}
            >
              {run.text}
            </Text>
          ))}
        </Text>
      ))}
    </Box>
  );
}

/**
 * Split a chunk that carries several printable characters.
 *
 * A terminal normally delivers one key per read, but a fast paste or a busy
 * event loop can hand Ink a whole word (or a word plus Enter) at once. Ink
 * passes that chunk through as one `input` string, so treating it as a single
 * key silently dropped the search text and left a dialog empty.
 */
function batchedKeys(
  input: string,
  key: Parameters<typeof keyToken>[1],
): { input: string; key: Parameters<typeof keyToken>[1] }[] | null {
  if (input.length <= 1) {
    return null;
  }
  if (
    key.ctrl ||
    key.meta ||
    key.escape ||
    key.return ||
    key.tab ||
    key.backspace ||
    key.delete ||
    key.upArrow ||
    key.downArrow ||
    key.leftArrow ||
    key.rightArrow ||
    key.pageUp ||
    key.pageDown ||
    key.home ||
    key.end
  ) {
    return null;
  }
  if (!/^[\x20-\x7e\u00a0-\uffff\r\n]+$/u.test(input)) {
    return null;
  }
  const events: { input: string; key: Parameters<typeof keyToken>[1] }[] = [];
  let newline = false;
  for (const character of input) {
    if (character === '\r' || character === '\n') {
      // `\r\n` is one Enter; a run of newlines must not confirm twice.
      if (!newline) {
        events.push({ input: '', key: { return: true } });
      }
      newline = true;
      continue;
    }
    newline = false;
    events.push({ input: character, key: {} });
  }
  return events;
}

/** Route one key press; dialogs first, then page handlers. */
export async function handleKey(
  app: App,
  input: string,
  key: Parameters<typeof keyToken>[1],
): Promise<void> {
  const batched = batchedKeys(input, key);
  if (batched) {
    for (const event of batched) {
      await routeKey(app, event.input, event.key);
    }
    return;
  }
  await routeKey(app, input, key);
}

async function routeKey(
  app: App,
  input: string,
  key: Parameters<typeof keyToken>[1],
): Promise<void> {
  // Ctrl+C is the unconditional way out, even with a modal open.
  if (key.ctrl && input === 'c') {
    await app.quitNow();
    return;
  }
  const token = keyToken(input, key);
  if (!token) {
    return;
  }
  if (app.state.columns < 60 || app.state.rows < 16) {
    if (token === 'q') await app.quitNow();
    return;
  }
  if (app.state.dialog) {
    await app.dialogKey(token, key, input);
    return;
  }
  if (key.ctrl && input === 'p') {
    app.state.dialog = { kind: 'commands', query: '', selected: 0 };
    app.emitChange();
    return;
  }
  if (key.ctrl && input === 'r') {
    await app.requestAnalysis(false);
    return;
  }
  // Browser-style page tabs: Ctrl+PgUp / Ctrl+PgDn switch, Ctrl+W closes.
  if (key.ctrl && (key.pageUp || key.pageDown)) {
    await app.cycleTab(key.pageUp ? -1 : 1);
    return;
  }
  if (key.ctrl && input === 'w') {
    await app.closeActiveTab();
    return;
  }
  if (key.ctrl && (key.leftArrow || key.rightArrow || key.tab)) {
    const pages = ['assets', 'analysis', 'cache'] as const;
    const step = key.leftArrow ? pages.length - 1 : 1;
    app.switchPage(pages[(pages.indexOf(app.state.page) + step) % pages.length]!);
    return;
  }
  if (key.meta && (key.leftArrow || key.rightArrow)) {
    app.horizontalScroll(key.leftArrow ? -12 : 12);
    return;
  }
  if (app.state.page === 'assets') {
    await assetKey(app, token);
    return;
  }
  if (app.state.page === 'cache') {
    await cacheKey(app, token);
    return;
  }
  await analysisKey(app, token);
}

async function cacheKey(app: App, token: string): Promise<void> {
  app.state.focus = 'navigation';
  if (app.cacheNavigate(token)) {
    return;
  }
  const command = app.resolveKey(token);
  if (command) {
    await app.runCommand(command);
  }
}

async function assetKey(app: App, token: string): Promise<void> {
  const state = app.state;
  state.focus = 'navigation';
  const slot = state.section === 'images' ? 0 : state.section === 'symbols' ? 1 : 2;
  const command = app.resolveKey(token);
  if (command) {
    await app.runCommand(command);
    return;
  }
  switch (token) {
    case 'Tab':
    case 'BackTab': {
      const sections = ['images', 'symbols', 'remote'] as const;
      const current = sections.indexOf(state.section);
      const step = token === 'BackTab' ? 2 : 1;
      await app.switchSection(sections[(current + step) % sections.length]!);
      app.emitChange();
      return;
    }
    case 'Up':
    case 'k':
      state.assetRows[slot] = Math.max(state.assetRows[slot] - 1, 0);
      app.emitChange();
      return;
    case 'Down':
    case 'j':
      state.assetRows[slot] = Math.min(
        state.assetRows[slot] + 1,
        Math.max(app.assetCountFor(state.section) - 1, 0),
      );
      app.emitChange();
      return;
    case 'PageUp':
    case 'PageDown': {
      const visible = Math.max(app.layout().panes[0]?.entries.length ?? 1, 1);
      const delta = token === 'PageUp' ? -visible : visible;
      state.assetRows[slot] = Math.max(0, Math.min(
        state.assetRows[slot] + delta,
        Math.max(app.assetCountFor(state.section) - 1, 0),
      ));
      app.emitChange();
      return;
    }
    case 'Home':
      state.assetRows[slot] = 0;
      app.emitChange();
      return;
    case 'End':
      state.assetRows[slot] = Math.max(app.assetCountFor(state.section) - 1, 0);
      app.emitChange();
      return;
    default:
      return;
  }
}

async function analysisKey(app: App, token: string): Promise<void> {
  const state = app.state;
  if (state.focus === 'detail' && ['Up', 'Down', 'j', 'k', 'PageUp', 'PageDown', 'Home', 'End'].includes(token)) {
    app.scrollDetail(token === 'j' ? 'Down' : token === 'k' ? 'Up' : token);
    return;
  }
  const command = app.resolveKey(token);
  if (command) {
    await app.runCommand(command);
    return;
  }
  const visibleRows = app.visibleCount();
  switch (token) {
    case 'Tab':
      state.focus = app.nextFocus(false);
      app.emitChange();
      return;
    case 'BackTab':
      state.focus = app.nextFocus(true);
      app.emitChange();
      return;
    case 'Up':
    case 'k':
      if (state.focus === 'navigation') {
        state.menu = Math.max(state.menu - 1, 0);
      } else if (state.focus === 'content') {
        state.row = Math.max(state.row - 1, 0);
      }
      app.emitChange();
      return;
    case 'Down':
    case 'j':
      if (state.focus === 'navigation') {
        state.menu = Math.min(state.menu + 1, app.menuLength() - 1);
      } else if (state.focus === 'content') {
        state.row = Math.min(state.row + 1, Math.max(visibleRows - 1, 0));
      }
      app.emitChange();
      return;
    case 'PageUp':
      if (state.focus === 'navigation') {
        state.menu = Math.max(state.menu - 10, 0);
        app.emitChange();
      } else {
        app.moveResultPage(false);
      }
      return;
    case 'PageDown':
      if (state.focus === 'navigation') {
        state.menu = Math.min(state.menu + 10, app.menuLength() - 1);
        app.emitChange();
      } else {
        app.moveResultPage(true);
      }
      return;
    case 'Home':
      if (state.focus === 'navigation') {
        state.menu = 0;
      } else {
        state.row = 0;
      }
      app.emitChange();
      return;
    case 'End':
      if (state.focus === 'navigation') {
        state.menu = app.menuLength() - 1;
      } else {
        state.row = Math.max(visibleRows - 1, 0);
      }
      app.emitChange();
      return;
    case 'Left':
    case 'Right':
      if (state.focus === 'content' && app.treeVisible()) {
        const row = app.currentRowValue();
        if (row) {
          const pid = row[0] as string;
          if (token === 'Left') {
            state.collapsed.add(pid);
          } else {
            state.collapsed.delete(pid);
          }
          app.emitChange();
        }
      }
      return;
    case 'Enter':
      await app.enterFocused();
      return;
    default:
      return;
  }
}

export { inside };
