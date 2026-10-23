/**
 * Result indexing: filtering, sorting and tree traversal over a snapshot.
 *
 * Ported from `src/result_view.rs`. Numbers compare numerically, `0x` values as
 * hex, everything else as text; a mixed pair sorts numbers first so a column of
 * addresses never interleaves with labels.
 */

/** Comparator shared by sorting and the tests that pin its behaviour. */
export function compareValues(left: string, right: string): number {
  const number = (value: string): number | null => {
    if (value.startsWith('0x')) {
      const parsed = Number.parseInt(value.slice(2), 16);
      return Number.isNaN(parsed) ? null : parsed;
    }
    if (value === '' || !/^-?\d+$/u.test(value)) {
      return null;
    }
    const parsed = Number(value);
    return Number.isNaN(parsed) ? null : parsed;
  };
  const a = number(left);
  const b = number(right);
  if (a !== null && b !== null) {
    return a === b ? 0 : a < b ? -1 : 1;
  }
  if (a !== null) {
    return -1;
  }
  if (b !== null) {
    return 1;
  }
  return left === right ? 0 : left < right ? -1 : 1;
}
