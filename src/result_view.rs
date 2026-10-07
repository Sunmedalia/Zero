//! Indexed result views: no cell copies during filtering, sorting or tree traversal.
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
                let a = result.rows[a].get(column).map(String::as_str).unwrap_or("");
                let b = result.rows[b].get(column).map(String::as_str).unwrap_or("");
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
            .filter_map(|&i| result.rows[i].first().map(String::as_str))
            .collect();
        let mut children: HashMap<&str, Vec<usize>> = HashMap::new();
        let mut roots = Vec::new();
        for &i in &filtered {
            let row = &result.rows[i];
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
                let id = result.rows[row].first().map(String::as_str).unwrap_or("");
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
