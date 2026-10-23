/**
 * A terminal canvas: a grid of styled cells that is composed once per frame and
 * then emitted as exactly `rows` lines of `columns` cells.
 *
 * Why not nest Ink boxes? Ink's incremental renderer diffs lines and assumes a
 * flow layout; absolutely positioned regions leave stale rows behind and can
 * shift content by a cell. Composing the grid ourselves makes the frame
 * deterministic, keeps every row the same width, and means the mouse can hit-test
 * the same rectangles that were painted.
 */
import { charWidth, type Run } from './text.js';

export interface Style {
  color?: string;
  background?: string;
  bold?: boolean;
  dim?: boolean;
}

/** One cell: a single grapheme plus its style. */
export interface Cell {
  text: string;
  style: Style;
  /** True for the trailing half of a wide character; never written directly. */
  continuation: boolean;
}

export class Canvas {
  readonly columns: number;
  readonly rows: number;
  private readonly cells: Cell[][];

  constructor(columns: number, rows: number, background?: string) {
    this.columns = Math.max(columns, 0);
    this.rows = Math.max(rows, 0);
    this.cells = Array.from({ length: this.rows }, () =>
      Array.from({ length: this.columns }, () => ({
        text: ' ',
        style: background === undefined ? {} : { background },
        continuation: false,
      })),
    );
  }

  /** Fill a rectangle with a style, leaving the text blank. */
  fill(
    x: number,
    y: number,
    width: number,
    height: number,
    style: Style,
  ): void {
    for (let row = y; row < y + height; row += 1) {
      for (let column = x; column < x + width; column += 1) {
        const cell = this.at(column, row);
        if (cell) {
          cell.text = ' ';
          cell.style = { ...style };
          cell.continuation = false;
        }
      }
    }
  }

  private at(x: number, y: number): Cell | null {
    if (x < 0 || y < 0 || x >= this.columns || y >= this.rows) {
      return null;
    }
    return this.cells[y]?.[x] ?? null;
  }

  /**
   * Write text at `(x, y)`, clipped to `maxWidth` cells.
   *
   * Wide characters occupy two cells: the glyph goes in the first and the second
   * is marked as a continuation so a later write cannot split it. Returns the
   * number of cells consumed.
   */
  write(x: number, y: number, text: string, style: Style, maxWidth = this.columns - x): number {
    let cursor = x;
    const limit = Math.min(x + maxWidth, this.columns);
    for (const character of text) {
      const cells = charWidth(character);
      if (cells === 0) {
        // Combining marks attach to the previous cell.
        const previous = this.at(cursor - 1, y);
        if (previous && !previous.continuation) {
          previous.text += character;
        }
        continue;
      }
      if (cursor + cells > limit) {
        break;
      }
      const first = this.at(cursor, y);
      if (!first) {
        break;
      }
      first.text = character;
      first.style = { ...style };
      first.continuation = false;
      if (cells === 2) {
        const second = this.at(cursor + 1, y);
        if (second) {
          second.text = '';
          second.style = { ...style };
          second.continuation = true;
        }
      }
      cursor += cells;
    }
    return cursor - x;
  }

  /** Draw a single-line box border with rounded corners. */
  frame(x: number, y: number, width: number, height: number, style: Style): void {
    if (width < 2 || height < 2) {
      return;
    }
    const right = x + width - 1;
    const bottom = y + height - 1;
    this.write(x, y, '╭', style, 1);
    this.write(right, y, '╮', style, 1);
    this.write(x, bottom, '╰', style, 1);
    this.write(right, bottom, '╯', style, 1);
    for (let column = x + 1; column < right; column += 1) {
      this.write(column, y, '─', style, 1);
      this.write(column, bottom, '─', style, 1);
    }
    for (let row = y + 1; row < bottom; row += 1) {
      this.write(x, row, '│', style, 1);
      this.write(right, row, '│', style, 1);
    }
  }

  /** Text already clipped to `width` cells, starting at `x`. */
  text(x: number, y: number, text: string, style: Style, width?: number): void {
    this.write(x, y, text, style, width);
  }

  /** Horizontal rule of `─` characters. */
  rule(x: number, y: number, width: number, style: Style): void {
    for (let column = x; column < x + width; column += 1) {
      this.write(column, y, '─', style, 1);
    }
  }

  /** The grid as rows of cells; the renderer turns each row into one Text. */
  lines(): Cell[][] {
    return this.cells;
  }
}

/** Collapse a cell row into styled runs, so a line emits a few Text nodes. */
export function toRuns(cells: Cell[]): Run[] {
  const runs: Run[] = [];
  for (const cell of cells) {
    if (cell.continuation) {
      continue;
    }
    const text = cell.text === '' ? ' ' : cell.text;
    const last = runs[runs.length - 1];
    if (
      last &&
      last.color === cell.style.color &&
      last.background === cell.style.background &&
      last.bold === cell.style.bold &&
      last.dim === cell.style.dim
    ) {
      last.text += text;
    } else {
      runs.push({
        text,
        color: cell.style.color,
        background: cell.style.background,
        bold: cell.style.bold,
        dim: cell.style.dim,
      });
    }
  }
  return runs;
}
