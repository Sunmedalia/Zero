/** Shared image row content: layout and painting must wrap identical text. */
import { basename, dirname } from 'node:path';
import type { Asset } from './types.js';
import { escaped, mib, wrapLines } from './text.js';

export interface ImageLine {
  text: string;
  kind: 'name' | 'directory' | 'metadata' | 'identity' | 'gap';
}

/** `Linux 3.2.0-4-amd64` / `Windows ntkrnlmp.pdb`, or null before identification. */
export function identityLabel(asset: Asset): string | null {
  const identity = asset.identity;
  const first = identity?.kernels[0];
  if (!identity || first === undefined) {
    return null;
  }
  const kernel =
    identity.system === 'linux'
      ? (first.split(/\s+/u)[2] ?? first)
      : (first.replace(/^Windows PDB /u, '').split('/')[0] ?? first);
  const more = identity.kernels.length > 1 ? ` 等 ${identity.kernels.length} 个` : '';
  return `${identity.system === 'linux' ? 'Linux' : 'Windows'} ${kernel}${more}`;
}

export function imageLines(asset: Asset, columns: number): ImageLine[] {
  const room = Math.max(columns, 1);
  return [
    ...wrapLines(escaped(asset.name || basename(asset.path)), room).map((text) => ({ text, kind: 'name' as const })),
    { text: `${escaped(asset.format)} · ${mib(asset.bytes)} MiB`, kind: 'metadata' },
    ...(identityLabel(asset) === null
      ? []
      : [{ text: `已识别 ${escaped(identityLabel(asset) as string)}`, kind: 'identity' as const }]),
    ...wrapLines(`目录 ${escaped(dirname(asset.path))}`, room).map((text) => ({ text, kind: 'directory' as const })),
    { text: '', kind: 'gap' },
  ];
}
