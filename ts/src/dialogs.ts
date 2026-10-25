/**
 * Dialog geometry, editing and field parsing.
 *
 * Kept apart from the state machine so the parameter parsers — which decide
 * whether a typed hive address, PID or pagefile attachment is accepted — can be
 * unit-tested without any UI state.
 */
import type { AppState, Dialog, InputKind } from './state.js';
import type { Options } from './types.js';
import { parseAddress } from './format.js';

export interface KeyLike {
  upArrow?: boolean;
  downArrow?: boolean;
  leftArrow?: boolean;
  rightArrow?: boolean;
  pageDown?: boolean;
  pageUp?: boolean;
  home?: boolean;
  end?: boolean;
  return?: boolean;
  escape?: boolean;
  ctrl?: boolean;
  shift?: boolean;
  tab?: boolean;
  backspace?: boolean;
  delete?: boolean;
  meta?: boolean;
}

/** Columns a dialog needs for its own content, up to a readable maximum. */
export function dialogWidth(state: AppState, dialog: Dialog, columns: number): number {
  const CHROME = 4;
  const MAX = 90;
  let longest = 0;
  const longestOf = (values: string[]) =>
    values.reduce((best, value) => Math.max(best, [...value].length), 0);
  switch (dialog.kind) {
    case 'system':
      longest = 12;
      break;
    case 'sort':
      longest = longestOf(state.results.get(state.plugin)?.columns ?? []);
      break;
    case 'symbols':
      longest = longestOf(dialog.labels);
      break;
    case 'links':
      longest = longestOf(dialog.matches.map((match) => match.path));
      break;
    case 'commands':
      longest = longestOf(dialog.query === '' ? [] : [dialog.query]);
      break;
    case 'plugins':
      longest = longestOf([dialog.query]);
      break;
    case 'settings':
      longest = 40;
      break;
    case 'input':
      longest = Math.max([...dialog.text].length, 40);
      break;
    case 'detail':
    case 'remoteDetail':
    case 'assetDetail':
      longest = Math.min(Math.max(columns - 6, 30), 90);
      break;
    default:
      longest = 0;
  }
  const estimate = Math.trunc((longest * 3) / 2) + CHROME + 20;
  const max = Math.max(Math.min(columns - 6, MAX), 30);
  return Math.min(Math.max(estimate, 30), max);
}

/** Rows a dialog needs for its own content, including frame and hint row. */
export function dialogHeight(state: AppState, dialog: Dialog, rows: number): number {
  const CHROME = 2;
  let wanted: number;
  switch (dialog.kind) {
    case 'system':
      wanted = 3;
      break;
    case 'sort':
      wanted = state.results.get(state.plugin)?.columns.length ?? 4;
      break;
    case 'symbols':
      wanted = dialog.labels.length;
      break;
    case 'links':
      wanted = dialog.matches.length;
      break;
    case 'commands':
      wanted = 12;
      break;
    case 'plugins':
      wanted = 12;
      break;
    case 'settings':
      wanted = 8;
      break;
    case 'input':
      wanted = 4;
      break;
    case 'detail':
      wanted = 12;
      break;
    case 'remoteDetail':
      // Fields, banner, file and link, then a gap and the download chips.
      wanted = 18;
      break;
    case 'assetDetail':
      // File fields, SHA256 and the identified kernels, then the close chip.
      wanted = 20;
      break;
    case 'dump':
      wanted = 12;
      break;
    case 'windowsParameters':
      wanted = 18;
      break;
    case 'generateSymbols':
      wanted = 15;
      break;
    default:
      wanted = 10;
  }
  const cap = Math.max(Math.trunc((rows * 3) / 4), 8);
  return Math.min(Math.max(wanted + CHROME, 4), cap);
}

/* ------------------------------------------------------------------ */
/* Text editing                                                         */
/* ------------------------------------------------------------------ */

export interface Editor {
  text: string;
  cursor: number;
  selected: boolean;
}

function previousBoundary(text: string, cursor: number): number {
  if (cursor <= 0) {
    return 0;
  }
  const before = [...text.slice(0, cursor)];
  const last = before[before.length - 1] ?? '';
  return cursor - last.length;
}

function nextBoundary(text: string, cursor: number): number {
  const after = [...text.slice(cursor)];
  const first = after[0] ?? '';
  return cursor + first.length;
}

/**
 * Apply one editing key. Mirrors the Rust `edit_input`, including select-all and
 * the rule that typing replaces a selection.
 */
export function editInput(editor: Editor, token: string, input: string): Editor {
  const { text, cursor } = editor;
  switch (token) {
    case 'Ctrl+a':
      return { text, cursor: text.length, selected: true };
    case 'Ctrl+u':
      return { text: '', cursor: 0, selected: false };
    case 'Left':
      return { text, cursor: previousBoundary(text, cursor), selected: false };
    case 'Right':
      return { text, cursor: nextBoundary(text, cursor), selected: false };
    case 'Home':
      return { text, cursor: 0, selected: false };
    case 'End':
      return { text, cursor: text.length, selected: false };
    case 'Backspace':
    case 'Delete':
      if (editor.selected) {
        return { text: '', cursor: 0, selected: false };
      }
      if (token === 'Backspace' && cursor > 0) {
        const start = previousBoundary(text, cursor);
        return { text: text.slice(0, start) + text.slice(cursor), cursor: start, selected: false };
      }
      if (token === 'Delete' && cursor < text.length) {
        return {
          text: text.slice(0, cursor) + text.slice(nextBoundary(text, cursor)),
          cursor,
          selected: false,
        };
      }
      return editor;
    default: {
      if (!/^.$/u.test(input) || token.startsWith('Ctrl+') || token.startsWith('Alt+')) {
        return editor;
      }
      const base = editor.selected ? '' : text;
      const at = editor.selected ? 0 : cursor;
      return {
        text: base.slice(0, at) + input + base.slice(at),
        cursor: at + input.length,
        selected: false,
      };
    }
  }
}

/* ------------------------------------------------------------------ */
/* Paste                                                                */
/* ------------------------------------------------------------------ */

/** Insert pasted text into the active editable dialog, replacing a selection. */
export function pasteInto(dialog: Dialog, value: string): Dialog | null {
  const insert = (field: string, cursor: number, selected: boolean) => {
    const base = selected ? '' : field;
    const at = selected ? 0 : cursor;
    return { text: base.slice(0, at) + value + base.slice(at), cursor: at + value.length };
  };
  switch (dialog.kind) {
    case 'windowsParameters':
    case 'generateSymbols':
    case 'dump': {
      const current = dialog.fields[dialog.field];
      if (current === undefined) {
        return null;
      }
      const next = insert(current, dialog.cursor, dialog.selected);
      const fields = [...dialog.fields];
      fields[dialog.field] = next.text;
      return { ...dialog, fields, cursor: next.cursor, selected: false };
    }
    case 'input': {
      const next = insert(dialog.text, dialog.cursor, dialog.selected);
      return { ...dialog, text: next.text, cursor: next.cursor, selected: false };
    }
    case 'plugins':
    case 'commands':
      return { ...dialog, query: dialog.query + value, selected: 0 };
    default:
      return null;
  }
}

/* ------------------------------------------------------------------ */
/* Input dialog helpers                                                 */
/* ------------------------------------------------------------------ */

export function inputText(state: AppState, input: InputKind): string {
  switch (input) {
    case 'image':
      return state.image ?? '';
    case 'symbols':
      return state.symbols;
    case 'search':
      return state.query;
    case 'assetsSearch':
      return state.assetQueries[sectionSlot(state.section)];
    case 'export':
      return `${state.settings.export_dir}/${state.plugin}.csv`;
    case 'pageSize':
      return state.settings.page_size === 0 ? 'auto' : String(state.settings.page_size);
    case 'symbolRepository':
      return state.settings.symbol_repository;
    case 'imageDirectory':
      return state.settings.image_dir;
    case 'symbolsDirectory':
      return state.settings.symbols;
    case 'exportDirectory':
      return state.settings.export_dir;
    case 'history':
      return state.settings.history_dir;
  }
}

export function pickerFilter(input: InputKind): string {
  switch (input) {
    case 'image':
    case 'symbols':
      return 'files';
    case 'history':
      return 'exports';
    default:
      return 'directories';
  }
}

export function inputTitle(input: InputKind): string {
  switch (input) {
    case 'image':
      return '镜像路径 · RAW / LiME / gzip';
    case 'symbols':
      return '符号路径 · JSON / JSON.XZ / ZIP / 目录';
    case 'search':
      return '全文搜索';
    case 'assetsSearch':
      return '资产筛选 · Enter 确认 / Esc 撤销';
    case 'export':
      return '导出当前筛选 · .csv / .json';
    case 'history':
      return '导出记录 · CSV / JSON 路径';
    case 'imageDirectory':
      return '镜像存放目录';
    case 'symbolsDirectory':
      return '符号存放目录';
    case 'exportDirectory':
      return '导出存放目录';
    case 'pageSize':
      return '每页行数 · auto 自动填满 / 0 / 1–10000';
    case 'symbolRepository':
      return '远程符号仓库 · https://github.com/<所有者>/<仓库>[/tree/<分支>]';
  }
}

export function filesTitle(input: InputKind): string {
  switch (input) {
    case 'image':
      return '选择镜像';
    case 'symbols':
      return '选择符号';
    case 'history':
      return '导出记录';
    default:
      return '选择目录';
  }
}

/* ------------------------------------------------------------------ */
/* Parameters dialog                                                    */
/* ------------------------------------------------------------------ */

/** Plugins that search memory for the `pattern` parameter. */
export function isPatternScan(plugin: string | null): boolean {
  return plugin === 'windows.vadyarascan' || plugin === 'vmayarascan';
}

export function parameterFields(state: AppState, advanced: boolean): number[] {
  const fields: number[] = [];
  const descriptor = state.hello?.plugins.find((plugin) => plugin.name === state.plugin);
  if (state.plugin === 'windows.printkey') {
    fields.push(0, 1);
  }
  if (isPatternScan(state.plugin)) {
    fields.push(7);
  }
  if (descriptor?.columns.includes('PID')) {
    fields.push(2);
  }
  if (state.windows && advanced) {
    fields.push(3, 4, 5);
  }
  fields.push(6);
  return fields;
}

/**
 * Parse the parameters form. Returns the validated options or the first error,
 * never both; the dialog keeps the fields so the user can correct them.
 */
export function parseOptions(
  state: AppState,
  fields: string[],
): { options?: Options; error?: string } {
  const descriptor = state.hello?.plugins.find((plugin) => plugin.name === state.plugin);
  const printkey = state.plugin === 'windows.printkey';
  let hive: string | null = null;
  if (printkey && (fields[0] ?? '').trim() !== '') {
    try {
      hive = parseAddress(fields[0] ?? '');
    } catch (error) {
      return { error: (error as Error).message };
    }
  }
  if (printkey && hive === null) {
    return { error: 'printkey 必须填写 hive 地址' };
  }
  let pid: number | null = null;
  if (descriptor?.columns.includes('PID') && (fields[2] ?? '').trim() !== '') {
    const parsed = Number((fields[2] ?? '').trim());
    if (!Number.isInteger(parsed) || parsed < 0) {
      return { error: 'PID 无效' };
    }
    pid = parsed;
  }
  let pattern: string | null = null;
  if (isPatternScan(state.plugin)) {
    pattern = (fields[7] ?? '').trim();
    if (pattern === '') {
      return { error: '扫描插件需要填写搜索模式' };
    }
  }
  const arch = (fields[3] ?? 'auto').trim();
  if (!['auto', 'x86', 'x64', 'arm64'].includes(arch)) {
    return { error: `无效架构 ${arch}；使用 auto / x86 / x64 / arm64` };
  }
  const pagefiles: { index: number; path: string }[] = [];
  for (const part of (fields[4] ?? '').split(/[;\n]/u)) {
    const value = part.trim();
    if (value === '') {
      continue;
    }
    const at = value.indexOf('=');
    if (at === -1) {
      return { error: '使用 INDEX=PATH 指定同次采集的分页文件' };
    }
    const index = Number(value.slice(0, at));
    const path = value.slice(at + 1);
    if (!Number.isInteger(index) || index < 0 || index > 15 || path === '') {
      return { error: '分页文件索引必须为 0..15，路径不能为空' };
    }
    pagefiles.push({ index, path });
  }
  return {
    options: {
      os: state.analysisOptions.os,
      arch: arch as Options['arch'],
      pid,
      hive,
      key: printkey ? (fields[1] ?? '') : '',
      pattern,
      pagefiles,
      swapfile: (fields[5] ?? '').trim() === '' ? null : (fields[5] ?? '').trim(),
    },
  };
}

/** Dump mode chips: Linux gets ELF, Windows gets PE. */
export function dumpModes(windows: boolean): { label: string; plugin: string }[] {
  return windows
    ? [
        { label: 'Alt+1 Process', plugin: 'windows.procdump' },
        { label: 'Alt+2 Range', plugin: 'windows.memdump' },
        { label: 'Alt+3 PE', plugin: 'windows.pedump' },
      ]
    : [
        { label: 'Alt+1 Process', plugin: 'procdump' },
        { label: 'Alt+2 Range', plugin: 'memdump' },
        { label: 'Alt+3 ELF', plugin: 'elfdump' },
      ];
}

export function sectionSlot(section: 'images' | 'symbols' | 'remote'): 0 | 1 | 2 {
  return section === 'images' ? 0 : section === 'symbols' ? 1 : 2;
}
