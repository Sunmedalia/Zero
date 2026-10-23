/**
 * Mouse reporting.
 *
 * Ink's input parser discards complete CSI sequences it cannot map to a key,
 * which is exactly what an SGR mouse report is — so `useInput` and Ink's own
 * event emitter never see them. This module listens on the raw stdin stream
 * instead, keeps a small rolling buffer, and decodes the reports itself.
 *
 * Only the SGR encoding (`CSI < b ; x ; y M|m`) is used, because it is the only
 * one that reports columns beyond 223 and unambiguous release events. The
 * terminal is put into that mode explicitly; X10 encoding is never enabled.
 */
/** The subset of `stdin` the listener needs. */
export interface MouseSource {
  on(event: 'data', listener: (chunk: string | Buffer) => void): unknown;
  off(event: 'data', listener: (chunk: string | Buffer) => void): unknown;
}

/** A decoded mouse event in zero-based terminal cells. */
export interface MouseEvent {
  kind: 'press' | 'release' | 'wheel';
  /** 0 = left, 1 = middle, 2 = right, 3 = release (legacy), 64/65 = wheel. */
  button: number;
  x: number;
  y: number;
  shift: boolean;
  alt: boolean;
  ctrl: boolean;
}

const ENABLE = '\u001b[?1000h\u001b[?1006h';
const DISABLE = '\u001b[?1006l\u001b[?1000l';
/** Anything longer than this cannot be a mouse report; drop it. */
const MAX_PENDING = 64;

export function enableMouse(stream: NodeJS.WriteStream = process.stdout): void {
  stream.write(ENABLE);
}

export function disableMouse(stream: NodeJS.WriteStream = process.stdout): void {
  stream.write(DISABLE);
}

/**
 * Decode every complete SGR mouse report in `text`.
 *
 * Returns the events plus the unconsumed tail, so a report split across two
 * reads is completed by the next chunk instead of being dropped.
 */
export function decodeMouse(text: string): { events: MouseEvent[]; rest: string } {
  const events: MouseEvent[] = [];
  let rest = text;
  for (;;) {
    const start = rest.indexOf('\u001b[<');
    if (start === -1) {
      // No report begins here. Keep a trailing partial prefix ("\u001b[", "\u001b[<") so
      // it can be joined with the next chunk; everything else is discarded.
      const partial = partialPrefix(rest);
      rest = partial;
      break;
    }
    const match = /^\u001b\[<(\d+);(\d+);(\d+)([Mm])/u.exec(rest.slice(start));
    if (!match) {
      rest = rest.slice(start);
      if (rest.length > MAX_PENDING) {
        rest = '';
      }
      break;
    }
    const button = Number(match[1]);
    const x = Number(match[2]) - 1;
    const y = Number(match[3]) - 1;
    const pressed = match[4] === 'M';
    const base = button & 0b1100_0011;
    if (button & 0b0100_0000) {
      events.push({
        kind: 'wheel',
        button,
        x,
        y,
        shift: (button & 0b0000_0100) !== 0,
        alt: (button & 0b0000_1000) !== 0,
        ctrl: (button & 0b0001_0000) !== 0,
      });
    } else if (base === 3) {
      // SGR reports releases with the same button bits as the press, so this
      // branch is only reached by terminals that still send the legacy code.
      events.push({ kind: 'release', button: 0, x, y, shift: false, alt: false, ctrl: false });
    } else {
      events.push({
        kind: pressed ? 'press' : 'release',
        button: base,
        x,
        y,
        shift: (button & 0b0000_0100) !== 0,
        alt: (button & 0b0000_1000) !== 0,
        ctrl: (button & 0b0001_0000) !== 0,
      });
    }
    rest = rest.slice(start + match[0].length);
  }
  return { events, rest };
}

/** Length of a trailing incomplete mouse prefix, or 0. */
function partialPrefix(text: string): string {
  for (const candidate of ['\u001b[<', '\u001b[']) {
    if (text.endsWith(candidate)) {
      return candidate;
    }
  }
  const open = text.lastIndexOf('\u001b[<');
  if (open !== -1 && text.length - open <= MAX_PENDING && !text.slice(open).includes('M')) {
    return text.slice(open);
  }
  return '';
}

/**
 * Attach a mouse listener to `stdin`.
 *
 * The listener runs on the raw stream alongside Ink's parser, so it sees reports
 * before they are filtered out. It never consumes the data: Ink still receives
 * everything and continues to handle keys and paste.
 */
export function listenMouse(
  stdin: MouseSource,
  handler: (event: MouseEvent) => void,
): () => void {
  let pending = '';
  const onData = (chunk: string | Buffer) => {
    const text = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    if (!text.includes('\u001b[<') && pending === '') {
      return;
    }
    const decoded = decodeMouse(pending + text);
    pending = decoded.rest;
    for (const event of decoded.events) {
      handler(event);
    }
  };
  stdin.on('data', onData);
  return () => {
    stdin.off('data', onData);
  };
}
