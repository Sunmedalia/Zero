/**
 * Terminal background detection for the `auto` theme.
 *
 * The terminal is asked for its background colour with OSC 11 before Ink takes
 * over stdin. A DA1 query follows it: terminals answer in order and practically
 * all answer DA1, so its reply means the OSC 11 reply has either arrived or will
 * never come — no guessing with a short timeout, after which a late reply would
 * be read as key presses. Terminals that do not answer fall back to
 * `COLORFGBG`, and without either the theme stays dark.
 */
export type Background = 'dark' | 'light';

/** Background from an OSC 11 reply such as `\x1b]11;rgb:ffff/fdfd/f6f6\x07`. */
export function parseBackground(reply: string): Background | null {
  const match = /\u001b\]11;rgba?:([0-9a-f]{1,4})\/([0-9a-f]{1,4})\/([0-9a-f]{1,4})/iu.exec(reply);
  if (!match) {
    return null;
  }
  // Each channel has 1–4 hex digits; scale it to 0..1 by its own width.
  const [red, green, blue] = match.slice(1, 4).map((hex) => parseInt(hex, 16) / (16 ** hex.length - 1)) as [
    number,
    number,
    number,
  ];
  const luminance = 0.2126 * red + 0.7152 * green + 0.0722 * blue;
  return luminance > 0.5 ? 'light' : 'dark';
}

/** Background from `COLORFGBG` (`fg;bg` or `fg;default;bg`, ANSI colour numbers). */
export function backgroundFromEnv(value: string | undefined): Background | null {
  const last = value?.split(';').at(-1);
  if (last === undefined || !/^\d+$/u.test(last)) {
    return null;
  }
  const colour = Number(last);
  // 7 (white) and the bright colours other than 8 (bright black) are light.
  return colour === 7 || (colour >= 9 && colour <= 15) ? 'light' : 'dark';
}

interface Input {
  isTTY?: boolean;
  isRaw?: boolean;
  setRawMode?: (mode: boolean) => unknown;
  on(event: 'data', listener: (chunk: Buffer | string) => void): unknown;
  off(event: 'data', listener: (chunk: Buffer | string) => void): unknown;
  resume(): unknown;
}

interface Output {
  isTTY?: boolean;
  write(text: string): unknown;
}

/** A terminal reply rather than typed input: OSC 10/11 colours or a DA1 report. */
export const TERMINAL_REPLY = /\u001b\](?:10|11);|\u001b\[\?[\d;]*c/u;

/** Primary device attributes reply, e.g. `\x1b[?62;22c`. */
const DA1_REPLY = /\u001b\[\?[\d;]*c/u;

/**
 * Ask the terminal for its background. Resolves when the DA1 reply arrives,
 * or after `timeoutMs` for a terminal that answers neither query.
 */
export async function queryBackground(input: Input, output: Output, timeoutMs = 1000): Promise<Background | null> {
  if (!input.isTTY || !output.isTTY || !input.setRawMode) {
    return null;
  }
  const wasRaw = input.isRaw === true;
  input.setRawMode(true);
  input.resume();
  let received = '';
  let listener: ((chunk: Buffer | string) => void) | undefined;
  const reply = await new Promise<Background | null>((resolve) => {
    const timer = setTimeout(() => resolve(parseBackground(received)), timeoutMs);
    listener = (chunk) => {
      received += typeof chunk === 'string' ? chunk : chunk.toString('latin1');
      if (DA1_REPLY.test(received)) {
        clearTimeout(timer);
        resolve(parseBackground(received));
      }
    };
    input.on('data', listener);
    output.write('\u001b]11;?\u001b\\\u001b[c');
  });
  if (listener) {
    input.off('data', listener);
  }
  input.setRawMode(wasRaw);
  // Do not pause: a paused stdin never reaches Ink's `readable` reader, which
  // would leave the interface deaf to keys and the mouse.
  return reply;
}
