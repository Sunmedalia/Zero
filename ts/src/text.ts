/**
 * Palette and shared style tokens.
 *
 * Quiet surfaces keep evidence readable; the accent marks focus and amber
 * marks preparation or incomplete evidence. Status also always has a text label.
 *
 * The tokens are live bindings: `applyTheme` reassigns them, and every painter
 * reads them at draw time, so a theme switch takes effect on the next frame.
 */
export interface Palette {
  accent: string;
  focus: string;
  selected: string;
  surface: string;
  /** Raised surface for chips, buttons and alternating table rows. */
  raised: string;
  stripe: string;
  border: string;
  text: string;
  muted: string;
  success: string;
  warn: string;
  danger: string;
  shadow: string;
}

export interface Theme {
  id: string;
  label: string;
  palette: Palette;
}

/** Selectable themes; the first is the default and the fallback for unknown ids. */
export const THEMES: readonly Theme[] = [
  {
    id: 'slate',
    label: '石板（深色）',
    palette: {
      accent: '#82b4e8', focus: '#b8d8fa', selected: '#263b52', surface: '#151b24',
      raised: '#202a37', stripe: '#19222e', border: '#364354', text: '#dce3ed',
      muted: '#97a6b8', success: '#8bc7a3', warn: '#dfb974', danger: '#ed938c', shadow: '#080c0f',
    },
  },
  {
    id: 'light',
    label: '纸白（浅色）',
    palette: {
      accent: '#1f5f9e', focus: '#0b3d6e', selected: '#cfe0f3', surface: '#f7f8fa',
      raised: '#e6e9ee', stripe: '#eef0f3', border: '#b4bcc8', text: '#1c2430',
      muted: '#5b6676', success: '#1d7a46', warn: '#8a5a00', danger: '#b3261e', shadow: '#c3c8d0',
    },
  },
  {
    id: 'solarized',
    label: 'Solarized（深色）',
    palette: {
      accent: '#268bd2', focus: '#93d4ff', selected: '#0d3d4d', surface: '#002b36',
      raised: '#073642', stripe: '#04313c', border: '#2a525c', text: '#d5dcd7',
      muted: '#93a1a1', success: '#9fbf3b', warn: '#d9a62e', danger: '#ef6b62', shadow: '#001b22',
    },
  },
  {
    id: 'phosphor',
    label: '荧光绿（终端）',
    palette: {
      accent: '#5fd787', focus: '#afffcf', selected: '#16402a', surface: '#0b120d',
      raised: '#132019', stripe: '#0f1912', border: '#2b4a35', text: '#c9f2d5',
      muted: '#7fa98c', success: '#87e7a8', warn: '#e5c76b', danger: '#ff8c7a', shadow: '#030604',
    },
  },
  {
    id: 'contrast',
    label: '高对比',
    palette: {
      accent: '#5cc8ff', focus: '#ffffff', selected: '#003a75', surface: '#000000',
      raised: '#1a1a1a', stripe: '#0d0d0d', border: '#8c8c8c', text: '#ffffff',
      muted: '#c8c8c8', success: '#5df58a', warn: '#ffd75f', danger: '#ff6b6b', shadow: '#000000',
    },
  },
];

/** Theme id that follows the terminal's own background. */
export const AUTO_THEME = 'auto';

/** Background the terminal reported at startup; `null` when it did not say. */
let terminalBackground: 'dark' | 'light' | null = null;

export function setTerminalBackground(background: 'dark' | 'light' | null): void {
  terminalBackground = background;
}

/** Every choice in the settings cycle: `auto` first, then the fixed themes. */
export const THEME_CHOICES: readonly string[] = [AUTO_THEME, ...THEMES.map((theme) => theme.id)];

/**
 * The theme for a settings id. `auto` resolves to the light theme on a light
 * terminal and to the default dark theme otherwise, keeping the `auto` id.
 */
export function themeOf(id: string): Theme {
  if (id === AUTO_THEME) {
    const resolved = terminalBackground === 'light' ? THEMES[1]! : THEMES[0]!;
    const detected =
      terminalBackground === null ? '未检测到终端背景，使用深色' : `终端${terminalBackground === 'light' ? '浅色' : '深色'}`;
    return { id: AUTO_THEME, label: `自动（${detected} → ${resolved.label}）`, palette: resolved.palette };
  }
  return THEMES.find((theme) => theme.id === id) ?? THEMES[0]!;
}

export let ACCENT = '';
export let FOCUS = '';
export let SELECTED_BG = '';
export let SURFACE = '';
/** Raised surface for chips, buttons and alternating table rows. */
export let RAISED = '';
export let STRIPE = '';
export let BORDER = '';
export let TEXT = '';
export let MUTED = '';
export let SUCCESS = '';
export let WARN = '';
export let DANGER = '';
export let SHADOW = '';

/** Make `id` the active palette; unknown ids fall back to the default theme. */
export function applyTheme(id: string): Theme {
  const theme = themeOf(id);
  const palette = theme.palette;
  ACCENT = palette.accent;
  FOCUS = palette.focus;
  SELECTED_BG = palette.selected;
  SURFACE = palette.surface;
  RAISED = palette.raised;
  STRIPE = palette.stripe;
  BORDER = palette.border;
  TEXT = palette.text;
  MUTED = palette.muted;
  SUCCESS = palette.success;
  WARN = palette.warn;
  DANGER = palette.danger;
  SHADOW = palette.shadow;
  return theme;
}

applyTheme(THEMES[0]!.id);

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
export function compactRemotePath(full: string, columns: number): string {
  // Release assets share one prefix; the release tag and file name carry the identity.
  const path = full.startsWith('releases/download/') ? full.slice('releases/download/'.length) : full;
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
