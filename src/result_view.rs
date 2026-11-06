//! Indexed result views: no cell copies during filtering, sorting or tree traversal.
use crate::bytes::Row as _;
use crate::store::Results;
use std::collections::{HashMap, HashSet};

#[derive(Default, Debug)]
pub struct Index {
    pub filtered: Vec<usize>,
    pub visible: Vec<Line>,
}
#[derive(Debug)]
pub struct Line {
    pub row: usize,
    pub decoration: Option<(usize, usize, char)>,
}
/// A borrowed table row: the stored cells plus the single cell a tree
/// decoration replaces.
pub type Cells<'a> = (&'a [String], Option<(usize, String)>);
impl Index {
    pub fn build(
        result: &Results,
        query: &str,
        sort: Option<usize>,
        descending: bool,
        tree: Option<(usize, usize)>,
        collapsed: &HashSet<String>,
    ) -> Self {
        let query = query.to_lowercase();
        let mut filtered: Vec<_> = result
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                query.is_empty() || row.iter().any(|cell| cell.to_lowercase().contains(&query))
            })
            .map(|(i, _)| i)
            .collect();
        if let Some(column) = sort {
            filtered.sort_by(|&a, &b| {
                let a = result.rows.get(a).map_or("", |row| row.cell(column));
                let b = result.rows.get(b).map_or("", |row| row.cell(column));
                let order = compare(a, b);
                if descending { order.reverse() } else { order }
            });
        }
        let Some((parent, name)) = tree else {
            let visible = filtered
                .iter()
                .map(|&row| Line {
                    row,
                    decoration: None,
                })
                .collect();
            return Self { filtered, visible };
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
        Self { filtered, visible }
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
pub fn compare(a: &str, b: &str) -> std::cmp::Ordering {
    let number = |v: &str| {
        v.strip_prefix("0x").map_or_else(
            || v.parse::<u64>().ok(),
            |v| u64::from_str_radix(v, 16).ok(),
        )
    };
    match (number(a), number(b)) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        _ => a.cmp(b),
    }
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
