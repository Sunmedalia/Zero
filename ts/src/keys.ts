/**
 * Key normalisation: Ink gives a character plus modifier booleans; the action
 * table compares stable tokens such as `F2`, `Alt+Left`, `Ctrl+r` and `Esc`.
 */
import type { KeyLike } from './dialogs.js';

export function keyToken(input: string, key: KeyLike): string | null {
  if (key.escape) {
    return 'Esc';
  }
  if (key.return) {
    return key.meta ? 'Alt+Enter' : 'Enter';
  }
  if (key.tab) {
    return key.shift ? 'BackTab' : 'Tab';
  }
  if (key.backspace) {
    return 'Backspace';
  }
  if (key.delete) {
    return 'Delete';
  }
  if (key.upArrow) {
    return key.meta ? 'Alt+Up' : 'Up';
  }
  if (key.downArrow) {
    return key.meta ? 'Alt+Down' : 'Down';
  }
  if (key.leftArrow) {
    return key.meta ? 'Alt+Left' : 'Left';
  }
  if (key.rightArrow) {
    return key.meta ? 'Alt+Right' : 'Right';
  }
  if (key.pageUp) {
    return 'PageUp';
  }
  if (key.pageDown) {
    return 'PageDown';
  }
  if (key.home) {
    return 'Home';
  }
  if (key.end) {
    return 'End';
  }
  const functionKey = /^f([1-9]|1[0-2])$/u.exec(input);
  if (functionKey) {
    return `F${functionKey[1]}`;
  }
  if (key.ctrl && input.length === 1) {
    return `Ctrl+${input.toLowerCase()}`;
  }
  if (key.meta && input.length === 1) {
    return `Alt+${input}`;
  }
  if (input === ' ') {
    return ' ';
  }
  return input.length === 1 ? input : null;
}
