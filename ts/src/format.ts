/**
 * Value formatting shared by the interface: addresses, byte counts, durations
 * and the plugin status vocabulary.
 */

/**
 * Parse a user-typed 64-bit address: decimal or `0x` hexadecimal.
 *
 * Returns the canonical decimal string. Kernel addresses routinely exceed
 * `Number.MAX_SAFE_INTEGER`, so no step of this goes through a JS number.
 */
export function parseAddress(text: string): string {
  const value = text.trim();
  const hex = value.startsWith('0x') || value.startsWith('0X');
  const digits = hex ? value.slice(2) : value;
  if (digits === '' || !(hex ? /^[0-9a-fA-F]+$/u : /^[0-9]+$/u).test(digits)) {
    throw new Error(`无效地址 ${text}；使用十进制或 0x 十六进制`);
  }
  const parsed = hex ? BigInt(`0x${digits}`) : BigInt(digits);
  if (parsed > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`地址超出 64 位范围 ${text}`);
  }
  return parsed.toString();
}

/** Format a decimal address string as `0x…` for display. */
export function formatAddress(value: string | null): string {
  if (value === null) {
    return '';
  }
  try {
    return `0x${BigInt(value).toString(16)}`;
  } catch {
    return value;
  }
}

/** Format a byte count as MiB with one decimal, the unit every panel uses. */
export function mib(bytes: number): string {
  return (bytes / 1048576).toFixed(1);
}

/** Elapsed seconds since `startedAt`, or `null` when no task is running. */
export function elapsedSeconds(startedAt: number | null): number | null {
  return startedAt === null ? null : Math.floor((Date.now() - startedAt) / 1000);
}

/** Percentage embedded in a progress message, when the engine reports one. */
export function progressPercent(message: string): number | null {
  for (const word of message.split(/\s+/u)) {
    const match = /^(\d{1,3})%$/u.exec(word);
    if (match) {
      return Math.min(Number(match[1]), 100);
    }
  }
  return null;
}

/** Complete / partial / historical label for a result. */
export function resultState(result: { historical: boolean; complete: boolean }): string {
  if (result.historical) {
    return '历史';
  }
  return result.complete ? '完整' : '部分';
}

/** Display name of a plugin in a result title. */
export function shortPlugin(name: string): string {
  return name.startsWith('windows.') ? name.slice('windows.'.length) : name;
}

/** File-kind badge used by the file picker. */
export function entryBadge(entry: { directory: boolean; kind: string }): string {
  if (entry.directory) {
    return 'DIR';
  }
  if (entry.kind === 'image') {
    return 'IMG';
  }
  if (entry.kind === 'symbols') {
    return 'ISF';
  }
  return 'FILE';
}

/** Human-readable failure hint, matching the engine's vocabulary. */
export function failureStatus(error: string): string {
  const needsSymbols =
    error.includes('HTTP 404') || error.includes('官方符号包未包含精确 ISF');
  const message = error.split(/\s+/u).join(' ');
  if (message.includes('需导入精确符号') || message.includes('需手动选择本地 ISF')) {
    return `失败：${message}`;
  }
  return `失败：${message} · ${needsSymbols ? '需导入精确符号' : '可重试'}`;
}
