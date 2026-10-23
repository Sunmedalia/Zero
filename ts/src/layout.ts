import { width } from './text.js';

/**
 * One place that decides what the current terminal can show.
 *
 * Layout thresholds used to be scattered across renderers and focus logic, with
 * several different numbers for the same question. Every such question is
 * answered here from one description of the space, so the renderers, the focus
 * cycle and the resize handler cannot disagree.
 */
export interface Space {
  columns: number;
  rows: number;
}

/** Narrowest terminal the two-pane layouts are drawn in. */
export const MIN_TWO_PANE = 100;
/** Below this height analysis shows only the focused region. */
export const MIN_TWO_PANE_HEIGHT = 24;
/** Menu column widths; the longest plugin label is 18 cells plus two for `› `. */
export const WIDE_MENU = 24;
export const NARROW_MENU = 22;
/** Width at which the analysis page can afford the inspector column. */
export const MIN_INSPECTOR = 160;
/** Width and height at which the resource page can afford inline detail. */
export const MIN_ASSET_DETAIL_WIDTH = 100;
export const MIN_ASSET_DETAIL_HEIGHT = 28;
/** Height at which the resource page shows both lists; below it, one list. */
export const MIN_ASSET_TWO_PANES = 20;
/** Width below which a list pane cannot also show a full digest. */
export const MIN_FULL_DIGEST_PANE = 60;

export function space(columns: number, rows: number): Space {
  return { columns, rows };
}

/** Two panes side by side, rather than one pane at a time. */
export function twoPanes(value: Space): boolean {
  return value.columns >= MIN_TWO_PANE && value.rows >= MIN_TWO_PANE_HEIGHT;
}

export function menuWidth(value: Space): number {
  return value.columns >= 100 ? WIDE_MENU : NARROW_MENU;
}

/** The analysis inspector column beside the workbench. */
export function inspector(value: Space): boolean {
  return value.columns >= MIN_INSPECTOR && value.rows >= 28;
}

/** The resource page's inline detail panel. */
export function assetDetail(value: Space): boolean {
  return (
    value.columns >= MIN_ASSET_DETAIL_WIDTH && value.rows >= MIN_ASSET_DETAIL_HEIGHT
  );
}

/** The resource page's two lists; only a short terminal drops to one. */
export function assetTwoPanes(value: Space): boolean {
  return value.rows >= MIN_ASSET_TWO_PANES;
}

/** Whether those two lists sit side by side rather than stacked. */
export function assetPanesSideBySide(value: Space): boolean {
  return value.columns >= MIN_ASSET_DETAIL_WIDTH;
}

/** Whether a pane this wide can keep the digest beside the path. */
export function fullDigest(value: Space): boolean {
  return value.columns >= MIN_FULL_DIGEST_PANE;
}

/** The analysis page's system picker row, replaced by region tabs when narrow. */
export function systemRow(value: Space): boolean {
  return value.columns >= MIN_ASSET_DETAIL_WIDTH && value.rows >= 20;
}

/**
 * Rows a wrapped action strip needs at `columns`, so the layout can reserve the
 * exact footer height before drawing. Mirrors the renderer: every row keeps
 * room for `更多 ?`.
 */
export function actionRows(labels: string[], columns: number, cap: number): number {
  const more = 7;
  let rows = 1;
  let x = 0;
  for (const label of labels) {
    const length = 2 + width(label);
    if (length > columns) {
      continue;
    }
    if (x + length + more > columns) {
      rows += 1;
      x = 0;
    }
    x += length + 1;
  }
  return Math.min(rows, cap);
}
