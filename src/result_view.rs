//! Indexed result views: no cell copies during filtering, sorting or tree traversal.
use crate::bytes::Row as _;
use crate::store::Results;
use std::collections::{HashMap, HashSet};

#[derive(Default, Debug)]
pub struct Index {
    pub filtered: Vec<usize>,
    pub visible: Vec<Line>,
    /// Lowercased query that produced `filtered`; a longer query containing
    /// it only has to re-check these rows.
    pub query: String,
}
#[derive(Debug)]
pub struct Line {
    pub row: usize,
    pub decoration: Option<(usize, usize, char)>,
}
/// A borrowed table row: the stored cells plus the single cell a tree
/// decoration replaces.
pub type Cells<'a> = (&'a [String], Option<(usize, String)>);
/// Rows between two cancellation checks.
const CANCEL_STRIDE: usize = 4096;
impl Index {
    pub fn build(
        result: &Results,
        query: &str,
        sort: Option<usize>,
        descending: bool,
        tree: Option<(usize, usize)>,
        collapsed: &HashSet<String>,
    ) -> Self {
        Self::build_from(
            result,
            query,
            sort,
            descending,
            tree,
            collapsed,
            None,
            &|| false,
        )
        .unwrap_or_default()
    }
    /// The lowercased form `build` matches against and stores in `query`.
    pub fn fold(query: &str) -> String {
        query.to_lowercase()
    }
    /// Whether rows matching `previous` are a superset of rows matching
    /// `next`, so `next` may be filtered from `previous`'s rows alone.
    pub fn narrows(previous: &str, next: &str) -> bool {
        Self::fold(next).contains(&Self::fold(previous))
    }
    /// Build the index, optionally restricted to `base` (rows already known to
    /// contain a substring of `query`, in any order). Returns `None` once
    /// `cancel` reports that the caller no longer wants this view.
    #[allow(clippy::too_many_arguments)]
    pub fn build_from(
        result: &Results,
        query: &str,
        sort: Option<usize>,
        descending: bool,
        tree: Option<(usize, usize)>,
        collapsed: &HashSet<String>,
        base: Option<&[usize]>,
        cancel: &dyn Fn() -> bool,
    ) -> Option<Self> {
        let query = Self::fold(query);
        let filtered = Self::filtered_rows(result, &query, sort, descending, base, cancel)?;
        let Some((parent, name)) = tree else {
            let visible = filtered
                .iter()
                .map(|&row| Line {
                    row,
                    decoration: None,
                })
                .collect();
            return Some(Self {
                filtered,
                visible,
                query,
            });
        };
        let ids: HashSet<_> = filtered
            .iter()
            .filter_map(|&i| result.rows.get(i)?.first().map(String::as_str))
            .collect();
        let mut children: HashMap<&str, Vec<usize>> = HashMap::new();
        let mut roots = Vec::new();
        for &i in &filtered {
            let Some(row) = result.rows.get(i) else {
                continue;
            };
            let id = row.first().map(String::as_str).unwrap_or("");
            let pid = row.get(parent).map(String::as_str).unwrap_or("0");
            if pid == "0" || pid == id || !ids.contains(pid) {
                roots.push(i);
            } else {
                children.entry(pid).or_default().push(i);
            }
        }
        let mut visited = HashSet::new();
        let mut visible = Vec::new();
        for root in roots.into_iter().chain(filtered.iter().copied()) {
            let mut stack = vec![(root, 0usize, false)];
            while let Some((row, depth, hidden)) = stack.pop() {
                if !visited.insert(row) {
                    continue;
                }
                let id = result.rows.get(row).map_or("", |row| row.cell(0));
                let kids = children.get(id);
                let closed = collapsed.contains(id);
                if !hidden {
                    visible.push(Line {
                        row,
                        decoration: Some((
                            name,
                            depth.min(64),
                            if kids.is_none() {
                                '·'
                            } else if closed {
                                '▸'
                            } else {
                                '▾'
                            },
                        )),
                    });
                }
                if let Some(kids) = kids {
                    for &child in kids.iter().rev() {
                        stack.push((child, depth + 1, hidden || closed));
                    }
                }
            }
        }
        Some(Self {
            filtered,
            visible,
            query,
        })
    }
    /// Filter and sort source rows using an already folded query.
    pub(crate) fn filtered_rows(
        result: &Results,
        query: &str,
        sort: Option<usize>,
        descending: bool,
        base: Option<&[usize]>,
        cancel: &dyn Fn() -> bool,
    ) -> Option<Vec<usize>> {
        let keep = |i: usize| {
            query.is_empty()
                || result
                    .rows
                    .get(i)
                    .is_some_and(|row| row.iter().any(|cell| contains_folded(cell, query)))
        };
        let mut filtered = Vec::new();
        match base {
            Some(base) => {
                for (n, &i) in base.iter().enumerate() {
                    if n % CANCEL_STRIDE == 0 && cancel() {
                        return None;
                    }
                    if keep(i) {
                        filtered.push(i);
                    }
                }
                // Restore row order so equal sort keys stay stable.
                filtered.sort_unstable();
            }
            None => {
                for i in 0..result.rows.len() {
                    if i % CANCEL_STRIDE == 0 && cancel() {
                        return None;
                    }
                    if keep(i) {
                        filtered.push(i);
                    }
                }
            }
        }
        if let Some(column) = sort {
            // Parse each key once instead of twice per comparison.
            let mut keyed: Vec<_> = filtered
                .iter()
                .map(|&i| {
                    let cell = result.rows.get(i).map_or("", |row| row.cell(column));
                    (i, sort_key(cell))
                })
                .collect();
            if cancel() {
                return None;
            }
            keyed.sort_by(|(_, a), (_, b)| {
                let order = compare_keys(a, b);
                if descending { order.reverse() } else { order }
            });
            filtered = keyed.into_iter().map(|(i, _)| i).collect();
        }
        if cancel() {
            return None;
        }
        Some(filtered)
    }
    pub fn row(&self, result: &Results, position: usize) -> Option<Vec<String>> {
        let line = self.visible.get(position)?;
        let mut row = result.rows.get(line.row)?.clone();
        if let Some((column, depth, marker)) = line.decoration
            && let Some(value) = row.get_mut(column)
        {
            *value = format!("{}{marker} {value}", "  ".repeat(depth));
        }
        Some(row)
    }
    /// Borrowed cell access for rendering. A tree row carries one decorated
    /// cell, returned separately so the caller can draw it without cloning the
    /// whole row on every frame.
    pub fn cells<'a>(&'a self, result: &'a Results, position: usize) -> Option<Cells<'a>> {
        let line = self.visible.get(position)?;
        let row = result.rows.get(line.row)?;
        let decoration = line.decoration.and_then(|(column, depth, marker)| {
            row.get(column)
                .map(|value| (column, format!("{}{marker} {value}", "  ".repeat(depth))))
        });
        Some((row.as_slice(), decoration))
    }
}
/// Case-insensitive substring test against an already folded needle, without
/// allocating for ASCII cells (the common case for addresses, PIDs and names).
fn contains_folded(cell: &str, needle: &str) -> bool {
    if needle.is_ascii() && cell.is_ascii() {
        let (hay, needle) = (cell.as_bytes(), needle.as_bytes());
        let Some((&first, rest)) = needle.split_first() else {
            return true;
        };
        if hay.len() < needle.len() {
            return false;
        }
        let last = hay.len() - needle.len();
        let mut from = 0;
        while from <= last {
            let window = hay.get(from..=last).unwrap_or_default();
            let Some(offset) = memchr::memchr2(first, first.to_ascii_uppercase(), window) else {
                return false;
            };
            let at = from + offset;
            if hay
                .get(at + 1..at + needle.len())
                .is_some_and(|tail| tail.eq_ignore_ascii_case(rest))
            {
                return true;
            }
            from = at + 1;
        }
        return false;
    }
    cell.to_lowercase().contains(needle)
}
type SortKey<'a> = (Option<u64>, &'a str);
fn sort_key(v: &str) -> SortKey<'_> {
    let number = v.strip_prefix("0x").map_or_else(
        || v.parse::<u64>().ok(),
        |v| u64::from_str_radix(v, 16).ok(),
    );
    (number, v)
}
fn compare_keys(a: &SortKey<'_>, b: &SortKey<'_>) -> std::cmp::Ordering {
    match (a.0, b.0) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        _ => a.1.cmp(b.1),
    }
}
pub fn compare(a: &str, b: &str) -> std::cmp::Ordering {
    compare_keys(&sort_key(a), &sort_key(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn results(rows: &[[&str; 3]]) -> Results {
        Results {
            plugin: "test".into(),
            columns: vec!["PID".into(), "PPID".into(), "Name".into()],
            rows: rows
                .iter()
                .map(|row| row.iter().map(|cell| (*cell).to_owned()).collect())
                .collect(),
            complete: true,
            diagnostics: vec![],
            banner: String::new(),
            symbol: String::new(),
            page_table: 0,
            historical: false,
            system: String::new(),
            kernel_identity: serde_json::Value::Null,
        }
    }
    fn names(index: &Index, result: &Results) -> Vec<String> {
        (0..index.visible.len())
            .filter_map(|i| index.row(result, i)?.get(2).cloned())
            .collect()
    }

    #[test]
    fn numbers_sort_by_value_hex_or_decimal_and_before_text() {
        use std::cmp::Ordering::*;
        assert_eq!(compare("9", "10"), Less);
        assert_eq!(compare("0x10", "15"), Greater);
        assert_eq!(compare("0xff", "255"), Equal);
        assert_eq!(compare("7", "seven"), Less);
        assert_eq!(compare("b", "a"), Greater);
        // A bare `0x` is not a number and sorts as text.
        assert_eq!(compare("0x", "1"), Greater);
    }

    #[test]
    fn filter_is_case_insensitive_over_every_cell_and_sort_is_stable() {
        let result = results(&[
            ["10", "1", "Bash"],
            ["2", "1", "sshd"],
            ["0x9", "1", "BASH"],
        ]);
        let none = HashSet::new();
        let index = Index::build(&result, "bash", None, false, None, &none);
        assert_eq!(index.filtered, vec![0, 2]);
        let index = Index::build(&result, "", Some(0), false, None, &none);
        assert_eq!(names(&index, &result), ["sshd", "BASH", "Bash"]);
        let index = Index::build(&result, "", Some(0), true, None, &none);
        assert_eq!(names(&index, &result), ["Bash", "BASH", "sshd"]);
        // Equal keys keep their original order in both directions.
        let tied = results(&[["1", "0", "a"], ["1", "0", "b"]]);
        for descending in [false, true] {
            let index = Index::build(&tied, "", Some(0), descending, None, &none);
            assert_eq!(names(&index, &tied), ["a", "b"]);
        }
    }

    #[test]
    fn folded_match_agrees_with_lowercase_contains() {
        let cells = [
            "Bash",
            "sSHd",
            "0xFFFF8880",
            "ĞÜÇ-bash",
            "",
            "ab",
            "aab",
            "K",
        ];
        let needles = ["", "bash", "ssh", "ff88", "ğü", "aab", "ab", "b", "x", "k"];
        for cell in cells {
            for needle in needles {
                assert_eq!(
                    contains_folded(cell, needle),
                    cell.to_lowercase().contains(needle),
                    "{cell:?} / {needle:?}"
                );
            }
        }
    }

    #[test]
    fn narrowing_and_cancellation_match_a_full_build() {
        let result = results(&[
            ["10", "1", "Bash"],
            ["2", "1", "sshd"],
            ["0x9", "1", "BASH"],
            ["3", "1", "bashd"],
        ]);
        let none = HashSet::new();
        let wide = Index::build(&result, "BA", Some(0), true, None, &none);
        assert!(Index::narrows(&wide.query, "bash"));
        assert!(!Index::narrows("bash", "ba"));
        let narrowed = Index::build_from(
            &result,
            "bash",
            Some(0),
            true,
            None,
            &none,
            Some(&wide.filtered),
            &|| false,
        )
        .unwrap();
        let full = Index::build(&result, "bash", Some(0), true, None, &none);
        assert_eq!(narrowed.filtered, full.filtered);
        assert_eq!(narrowed.query, "bash");
        assert!(Index::build_from(&result, "", None, false, None, &none, None, &|| true).is_none());
    }

    #[test]
    fn tree_nests_children_marks_collapse_and_keeps_orphans_and_cycles() {
        let result = results(&[
            ["1", "0", "init"],
            ["2", "1", "child"],
            ["3", "2", "grandchild"],
            ["4", "99", "orphan"],
            ["5", "6", "loop-a"],
            ["6", "5", "loop-b"],
        ]);
        let none = HashSet::new();
        let index = Index::build(&result, "", None, false, Some((1, 2)), &none);
        assert_eq!(
            names(&index, &result),
            [
                "▾ init",
                "  ▾ child",
                "    · grandchild",
                "· orphan",
                "▾ loop-a",
                // Its child `loop-a` is already shown, so the cycle ends here
                // with an expandable marker and no repeated row.
                "  ▾ loop-b"
            ]
        );
        // Collapsing hides descendants but keeps the collapsed row.
        let collapsed = HashSet::from(["2".to_owned()]);
        let index = Index::build(&result, "", None, false, Some((1, 2)), &collapsed);
        assert_eq!(
            names(&index, &result).get(..3),
            Some(
                &[
                    "▾ init".to_owned(),
                    "  ▸ child".to_owned(),
                    "· orphan".to_owned()
                ][..]
            )
        );
        // Borrowed cells carry the same decoration as the cloned row.
        let (cells, decoration) = index.cells(&result, 1).unwrap();
        assert_eq!(cells.get(2).map(String::as_str), Some("child"));
        assert_eq!(decoration, Some((2, "  ▸ child".to_owned())));
        // A filtered-out parent turns its child into a root.
        let index = Index::build(&result, "grand", None, false, Some((1, 2)), &none);
        assert_eq!(names(&index, &result), ["· grandchild"]);
    }
}
