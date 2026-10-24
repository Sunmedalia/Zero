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

/** Human-sized byte count for listings where files range from bytes to GiB. */
export function formatBytes(bytes: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return unit === 0 ? `${bytes} B` : `${value.toFixed(1)} ${units[unit]}`;
}

/** Local `YYYY-MM-DD HH:MM` for a Unix timestamp in seconds; `—` when unknown. */
export function formatTime(seconds: number | null): string {
  if (seconds === null || !Number.isFinite(seconds)) {
    return '—';
  }
  const date = new Date(seconds * 1000);
  const two = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${two(date.getMonth() + 1)}-${two(date.getDate())} ${two(date.getHours())}:${two(date.getMinutes())}`;
}

/** Index age in words, for the remote catalog status. */
export function formatAge(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) {
    return '未知';
  }
  if (seconds < 60) return '刚刚';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
  return `${Math.floor(seconds / 86400)} 天前`;
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

/** Request wall time: tenths below a minute, `1m19s` above. */
export function formatDuration(seconds: number): string {
  if (seconds < 60) {
    return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)} s`;
  }
  const whole = Math.round(seconds);
  return `${Math.floor(whole / 60)}m${String(whole % 60).padStart(2, '0')}s`;
}

/** How a result was obtained, for the result frame and status line. */
export function originLabel(origin: { source: 'fresh' | 'cache'; seconds: number; prepared: boolean }): string {
  const time = `${formatDuration(origin.seconds)}${origin.prepared ? '（含镜像校验）' : ''}`;
  return origin.source === 'cache' ? `读取缓存 · ${time}` : `重新分析 · ${time}`;
}

/**
 * Diagnostic families, in the order they are shown. Each diagnostic is counted
 * once, under the first family whose pattern it matches.
 */
export const DIAGNOSTIC_KINDS = [
  {
    id: 'page',
    label: '页面不在镜像中',
    pattern: /缺页|不驻留|PEB 不存在|越界|空洞/u,
    explanation: '对象所在的页在采集时已换出到 pagefile、未提交或不在镜像范围内；附加 pagefile／swapfile 后可读到更多。',
  },
  {
    id: 'layout',
    label: '布局未验收',
    pattern: /布局|验收|尚未验证/u,
    explanation: '这些结构的布局来自声明来源，尚未与此精确符号身份的真实样本对照；结果可用，但需要核查。',
  },
  {
    id: 'limit',
    label: '达到上限',
    pattern: /上限|超限/u,
    explanation: '读取到的计数超过安全上限，按无效数据处理并停止该对象。',
  },
  {
    id: 'inconsistent',
    label: '对象前后矛盾',
    pattern: /不一致|无效链表|无效 EPROCESS|无效对象|未闭合|循环|NUL|无效 UNICODE_STRING|签名无效|非 canonical|未分配|无效/u,
    explanation: '链表指针、父指针或对象头与相邻对象矛盾。运行中采集的镜像常见：采集过程中进程、线程或对象正在创建或释放。',
  },
] as const;

export type DiagnosticKind = (typeof DIAGNOSTIC_KINDS)[number]['id'] | 'other';

export function diagnosticKind(diagnostic: string): DiagnosticKind {
  return DIAGNOSTIC_KINDS.find((kind) => kind.pattern.test(diagnostic))?.id ?? 'other';
}

/** Diagnostic counts per family, in display order, omitting empty families. */
export function diagnosticCounts(diagnostics: string[]): { id: DiagnosticKind; label: string; count: number }[] {
  const counts = new Map<DiagnosticKind, number>();
  for (const diagnostic of diagnostics) {
    const kind = diagnosticKind(diagnostic);
    counts.set(kind, (counts.get(kind) ?? 0) + 1);
  }
  return [...DIAGNOSTIC_KINDS.map((kind) => ({ id: kind.id as DiagnosticKind, label: kind.label })), { id: 'other' as const, label: '其他' }]
    .map((kind) => ({ ...kind, count: counts.get(kind.id) ?? 0 }))
    .filter((kind) => kind.count > 0);
}

/** `对象前后矛盾 3 · 页面不在镜像中 1` */
export function diagnosticSummary(diagnostics: string[]): string {
  return diagnosticCounts(diagnostics)
    .map((kind) => `${kind.label} ${kind.count}`)
    .join(' · ');
}

/** ` · 4 条诊断：对象前后矛盾 4（v 查看）`, or nothing without diagnostics. */
export function diagnosticStatus(diagnostics: string[]): string {
  return diagnostics.length > 0
    ? ` · ${diagnostics.length} 条诊断：${diagnosticSummary(diagnostics)}（v 查看）`
    : '';
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
