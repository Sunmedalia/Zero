/** Shared image row content: layout and painting must wrap identical text. */
import { basename, dirname } from 'node:path';
import type { Asset } from './types.js';
import { escaped, mib, wrapLines } from './text.js';

export interface ImageLine {
  text: string;
  kind: 'name' | 'directory' | 'metadata' | 'gap';
}

export function imageLines(asset: Asset, columns: number): ImageLine[] {
  const room = Math.max(columns, 1);
  return [
    ...wrapLines(escaped(asset.name || basename(asset.path)), room).map((text) => ({ text, kind: 'name' as const })),
    { text: `${escaped(asset.format)} · ${mib(asset.bytes)} MiB`, kind: 'metadata' },
    ...wrapLines(`目录 ${escaped(dirname(asset.path))}`, room).map((text) => ({ text, kind: 'directory' as const })),
    { text: '', kind: 'gap' },
  ];
}
