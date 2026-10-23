/**
 * Palette and shared style tokens.
 *
 * The colours match the previous Ratatui interface exactly, so screenshots,
 * muscle memory and documentation stay valid across the rewrite.
 */
export const ACCENT = '#48c9b8';
export const FOCUS = '#f3b25c';
export const SELECTED_BG = '#1f363d';
export const SURFACE = '#11191f';
/** Raised surface for chips, buttons and alternating table rows. */
export const RAISED = '#1b2a30';
export const STRIPE = '#151f26';
export const BORDER = '#34464e';
export const TEXT = '#d6dee0';
export const MUTED = '#708289';
export const SUCCESS = '#7ed387';
export const WARN = '#f0c466';
export const DANGER = '#ec7063';
export const SHADOW = '#080c0f';

/** One cell of terminal output, measured in display columns. */
export interface Run {
  text: string;
  color?: string;
  background?: string;
  bold?: boolean;
  dim?: boolean;
}

/** Width of a string in terminal cells (CJK and emoji take two). */
export { width as cellWidth };

export function width(text: string): number {
  let cells = 0;
  for (const character of text) {
    cells += charWidth(character);
  }
  return cells;
}

/** East Asian wide/fullwidth and combining marks, matching `string-width`. */
export function charWidth(character: string): number {
  const code = character.codePointAt(0) ?? 0;
  if (code === 0) {
    return 0;
  }
  if (code < 32 || (code >= 0x7f && code < 0xa0)) {
    return 0;
  }
  if (isCombining(code)) {
    return 0;
  }
  if (isFullwidth(code)) {
    return 2;
  }
  return 1;
}

function isCombining(code: number): boolean {
  return (
    (code >= 0x0300 && code <= 0x036f) ||
    (code >= 0x1ab0 && code <= 0x1aff) ||
    (code >= 0x1dc0 && code <= 0x1dff) ||
    (code >= 0x20d0 && code <= 0x20ff) ||
    (code >= 0xfe20 && code <= 0xfe2f) ||
    (code >= 0xfe00 && code <= 0xfe0f) ||
    (code >= 0xe0100 && code <= 0xe01ef)
  );
}

function isFullwidth(code: number): boolean {
  return (
    code >= 0x1100 &&
    (code <= 0x115f ||
      code === 0x2329 ||
      code === 0x232a ||
      (code >= 0x2e80 && code <= 0xa4cf && code !== 0x303f) ||
      (code >= 0xac00 && code <= 0xd7a3) ||
      (code >= 0xf900 && code <= 0xfaff) ||
      (code >= 0xfe10 && code <= 0xfe19) ||
      (code >= 0xfe30 && code <= 0xfe6f) ||
      (code >= 0xff00 && code <= 0xff60) ||
      (code >= 0xffe0 && code <= 0xffe6) ||
      (code >= 0x1f300 && code <= 0x1f64f) ||
      (code >= 0x1f900 && code <= 0x1f9ff) ||
      (code >= 0x20000 && code <= 0x3fffd))
  );
}

/** Render control characters as visible escapes so cells cannot corrupt the screen. */
export function escaped(value: string): string {
  // eslint-disable-next-line no-control-regex
  if (!/[\u0000-\u001f\u007f-\u009f]/.test(value)) {
    return value;
  }
  let out = '';
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) {
      out += `\\u{${code.toString(16)}}`;
    } else {
      out += character;
    }
  }
  return out;
}

/** Shorten `text` to `budget` cells, marking the cut with `…`. */
export function truncate(text: string, budget: number): string {
  if (budget <= 0) {
    return '';
  }
  if (width(text) <= budget) {
    return text;
  }
  if (budget === 1) {
    return '…';
  }
  let out = '';
  let used = 0;
  for (const character of text) {
    const cells = charWidth(character);
    if (used + cells > budget - 1) {
      break;
    }
    out += character;
    used += cells;
  }
  return `${out}…`;
}

/**
 * Shorten a path to `budget` cells, keeping the end.
 *
 * The tail of a path distinguishes files: six captures in the same directory all
 * truncate to the same prefix, so a front-truncated list is unreadable.
 */
export function truncatePath(path: string, budget: number): string {
  if (width(path) <= budget) {
    return path;
  }
  if (budget <= 2) {
    return '…';
  }
  const characters = [...path];
  let used = 1;
  const kept: string[] = [];
  for (let index = characters.length - 1; index >= 0; index -= 1) {
    const character = characters[index] as string;
    const cells = charWidth(character);
    if (used + cells > budget) {
      break;
    }
    used += cells;
    kept.push(character);
  }
  return `…${kept.reverse().join('')}`;
}

/**
 * Shorten a repository path for display.
 *
 * These paths end in a long content hash that is identical for every candidate
 * of one kernel, so the tail is the least informative part. The directory and
 * the file name are kept and the hash is elided in the middle.
 */
export function compactRemotePath(path: string, columns: number): string {
  const budget = Math.max(columns - 12, 16);
  if (width(path) <= budget) {
    return path;
  }
  const slash = path.lastIndexOf('/');
  if (slash === -1) {
    return truncate(path, budget);
  }
  const directory = path.slice(0, slash);
  const file = path.slice(slash + 1);
  const extensionAt = file.indexOf('.json');
  const stem = extensionAt === -1 ? file : file.slice(0, extensionAt);
  const extension = extensionAt === -1 ? '' : file.slice(extensionAt);
  const dash = stem.lastIndexOf('-');
  const tail = dash === -1 ? '' : stem.slice(dash + 1);
  const informative =
    tail.length >= 32 && /^[0-9a-f]+$/i.test(tail) ? stem.slice(0, dash) : stem;
  const compact = `${directory}/${informative}${extension}`;
  if (width(compact) <= budget) {
    return compact;
  }
  // Still too wide: shorten the directory part, which repeats across candidates,
  // and keep the informative file name intact where it fits.
  const nameRoom = Math.max(budget - 2, 8);
  const name = `${informative}${extension}`;
  if (width(name) <= nameRoom) {
    return `…/${name}`;
  }
  const room = Math.max(nameRoom - extension.length, 4);
  return `…/${truncate(informative, room)}${extension}`;
}

/**
 * Trim a kernel banner to its identifying head.
 *
 * A full Linux banner is ~150 characters of build metadata; the version and the
 * distribution build are what identify it, and the whole string is available in
 * the detail panel and the identification result.
 */
export function summariseBanner(banner: string): string {
  const trimmed = banner.replace(/[\n\0 ]+$/u, '');
  const words = trimmed.split(/\s+/u).filter(Boolean);
  if (words.length <= 6) {
    return words.join(' ');
  }
  return `${words.slice(0, 6).join(' ')} …`;
}

/** Wrap prose to `columns` cells, preserving explicit line breaks. */
export function wrapLines(text: string, columns: number): string[] {
  const budget = Math.max(columns, 1);
  const lines: string[] = [];
  for (const paragraph of text.split('\n')) {
    let line = '';
    let used = 0;
    for (const character of paragraph) {
      const cells = charWidth(character);
      if (used + cells > budget && line.length > 0) {
        lines.push(line);
        line = '';
        used = 0;
      }
      line += character;
      used += cells;
    }
    lines.push(line);
  }
  return lines;
}

/** Format a byte count the way every panel does. */
export function mib(bytes: number): string {
  return (bytes / 1048576).toFixed(1);
}

/** Kernel address with a fixed width, matching result columns. */
export function hex(value: number): string {
  return `0x${value.toString(16).padStart(16, '0')}`;
}
