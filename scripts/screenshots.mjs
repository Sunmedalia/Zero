#!/usr/bin/env node
/**
 * Render README screenshots from the real interface and engine.
 *
 * Drives `zero tui-backend` through the same RpcEngine and App the terminal
 * uses, on a local public sample, then converts the composed canvas into SVG.
 * Nothing here is mocked: the frames are exactly what a terminal would show.
 *
 *   make ui-build build
 *   node scripts/screenshots.mjs IMAGE SYMBOLS [OUTPUT_DIR]
 *
 * IMAGE and SYMBOLS are copied into a fixed temporary project (`$TMPDIR/zero-demo`)
 * so local paths and runtime data never appear in the pictures. Offline only.
 */
import { copyFileSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';

const repo = resolve(new URL('..', import.meta.url).pathname);
const dist = join(repo, 'ts/dist');
const [imageArg, symbolsArg, outArg] = process.argv.slice(2);
if (!imageArg || !symbolsArg) {
  process.stderr.write('usage: node scripts/screenshots.mjs IMAGE SYMBOLS [OUTPUT_DIR]\n');
  process.exit(2);
}
const output = resolve(outArg ?? join(repo, 'docs/assets'));
const { RpcEngine } = await import(join(dist, 'rpc.js'));
const { App } = await import(join(dist, 'app.js'));
const { renderFrame } = await import(join(dist, 'views/root.js'));
const { toRuns } = await import(join(dist, 'canvas.js'));
const { applyTheme, cellWidth } = await import(join(dist, 'text.js'));

const COLUMNS = 128;
const ROWS = 34;
const CELL = 8.4;
const LINE = 18;
const FONT = "ui-monospace, 'SFMono-Regular', 'JetBrains Mono', Menlo, Consolas, 'Noto Sans Mono CJK SC', 'Sarasa Mono SC', monospace";

const escape = (text) => text.replace(/[&<>"]/gu, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

/** One canvas frame as a self-contained SVG with a window chrome. */
function svg(canvas, title) {
  const pad = 14;
  const bar = 30;
  const width = Math.ceil(COLUMNS * CELL + pad * 2);
  const height = Math.ceil(ROWS * LINE + pad * 2 + bar);
  const surface = canvas.lines()[ROWS - 1]?.[COLUMNS - 1]?.style.background ?? '#151b24';
  const parts = [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="${escape(title)}">`,
    `<title>${escape(title)}</title>`,
    `<rect width="${width}" height="${height}" rx="10" fill="${surface}"/>`,
    `<rect width="${width}" height="${bar}" rx="10" fill="#000" fill-opacity="0.28"/>`,
    `<rect y="${bar - 10}" width="${width}" height="10" fill="#000" fill-opacity="0.28"/>`,
    ...['#ff5f57', '#febc2e', '#28c840'].map((fill, index) => `<circle cx="${pad + 6 + index * 20}" cy="${bar / 2}" r="6" fill="${fill}"/>`),
    `<text x="${width / 2}" y="${bar / 2 + 4}" text-anchor="middle" font-family="${FONT}" font-size="12" fill="#9aa5b4">${escape(title)}</text>`,
    `<g font-family="${FONT}" font-size="14" xml:space="preserve">`,
  ];
  canvas.lines().forEach((cells, row) => {
    const y = pad + bar + row * LINE;
    let column = 0;
    for (const run of toRuns(cells)) {
      const cells = cellWidth(run.text);
      const x = pad + column * CELL;
      if (run.background && run.background !== surface) {
        parts.push(`<rect x="${x.toFixed(1)}" y="${y}" width="${(cells * CELL).toFixed(1)}" height="${LINE}" fill="${run.background}"/>`);
      }
      if (run.text.trim() !== '') {
        const weight = run.bold ? ' font-weight="700"' : '';
        parts.push(`<text x="${x.toFixed(1)}" y="${y + 13.5}" fill="${run.color ?? '#dce3ed'}"${weight} textLength="${(cells * CELL).toFixed(1)}" lengthAdjust="spacingAndGlyphs">${escape(run.text)}</text>`);
      }
      column += cells;
    }
  });
  parts.push('</g></svg>');
  return `${parts.join('\n')}\n`;
}

async function settle(app) {
  for (let waited = 0; app.state.busy && waited < 600_000; waited += 50) {
    await new Promise((done) => setTimeout(done, 50));
  }
  await new Promise((done) => setTimeout(done, 50));
}

const project = join(tmpdir(), 'zero-demo');
rmSync(project, { recursive: true, force: true });
const root = project;
mkdirSync(join(root, 'images'), { recursive: true });
mkdirSync(join(root, 'symbols'), { recursive: true });
const image = join('images', basename(imageArg));
const symbols = join('symbols', basename(symbolsArg));
copyFileSync(imageArg, join(root, image));
copyFileSync(symbolsArg, join(root, symbols));

const engine = new RpcEngine(join(repo, 'target/release/zero'), root);
try {
  const hello = await engine.hello();
  hello.settings = { ...hello.settings, remote_symbols: false };
  // Show project-relative paths, as a user who launched from the case directory sees them.
  const app = new App(engine, hello, {
    image, symbols, offline: true, os: 'auto', arch: 'auto',
    pagefiles: [], swapfile: null, hive: null, key: '', pattern: null,
  });
  await app.initialize();
  await settle(app);
  app.resize(COLUMNS, ROWS);
  for (const plugin of ['pslist', 'lsmod', 'sockstat', 'pstree']) {
    await app.activatePlugin(plugin);
    await settle(app);
  }
  mkdirSync(output, { recursive: true });
  const shots = [];
  // The engine reports absolute paths inside the temporary project; show them
  // relative to it, as they read from the case directory.
  const relative = (path) => (path.startsWith(`${root}/`) ? path.slice(root.length + 1) : path);
  const shot = (name, title) => {
    app.state.symbols = relative(app.state.symbols);
    app.state.assets = app.state.assets.map((asset) => ({ ...asset, path: relative(asset.path) }));
    const { canvas } = renderFrame(app, COLUMNS, ROWS);
    writeFileSync(join(output, name), svg(canvas, title));
    if (process.env.ZERO_SHOTS_TEXT) {
      // Plain-text twin for reviewing a frame without an SVG viewer.
      const text = canvas.lines().map((cells) => cells.filter((cell) => !cell.continuation).map((cell) => cell.text || ' ').join(''));
      writeFileSync(join(output, name.replace(/\.svg$/u, '.txt')), `${text.join('\n')}\n`);
    }
    shots.push(name);
  };
  app.state.row = 2;
  app.state.focus = 'content';
  shot('analysis.svg', 'zero — pstree · Debian 3.2 sample');
  await app.activateTab(2);
  shot('sockstat.svg', 'zero — sockstat · process sockets');
  applyTheme('light');
  await app.activateTab(1);
  shot('theme-light.svg', 'zero — lsmod · 纸白 theme');
  applyTheme('slate');
  app.switchPage('assets');
  await settle(app);
  shot('assets.svg', 'zero — resource library');
  app.switchPage('cache');
  await settle(app);
  shot('cache.svg', 'zero — cache management');
  process.stdout.write(`${shots.map((name) => join(output, name)).join('\n')}\n`);
} finally {
  await engine.close();
  rmSync(project, { recursive: true, force: true });
}
