//! Immutable interval lookup with explicit source and alias precedence. Built by
//! a sweep rather than a backward linear search, even for nested/overlapping ELF symbols.
use crate::Job;
use anyhow::{Result, ensure};
use std::collections::BTreeSet;
pub(crate) struct Entry {
    pub start: u64,
    pub end: u64,
    pub priority: u8,
    pub ordinal: usize,
    pub name: String,
    pub kind: String,
    pub module: String,
}
struct Span {
    start: u64,
    end: u64,
    entry: usize,
}
pub(crate) struct SymbolIndex {
    entries: Vec<Entry>,
    spans: Vec<Span>,
}
impl SymbolIndex {
    pub fn build(entries: Vec<Entry>, job: &Job) -> Result<Self> {
        ensure!(entries.len() <= 1_000_000, "符号查询索引超过 100 万项上限");
        let mut events = Vec::with_capacity(entries.len() * 2);
        for (i, e) in entries.iter().enumerate() {
            job.check()?;
            ensure!(e.start < e.end, "符号查询范围无效");
            events.push((e.start, true, i));
            events.push((e.end, false, i));
        }
        events.sort_unstable();
        let mut active = BTreeSet::new();
        let mut spans: Vec<Span> = Vec::new();
        let mut previous = 0;
        for (address, start, index) in events {
            job.check()?;
            if previous < address
                && let Some(&(_, _, selected)) = active.first()
            {
                if let Some(last) = spans.last_mut()
                    && last.entry == selected
                    && last.end == previous
                {
                    last.end = address;
                } else {
                    spans.push(Span {
                        start: previous,
                        end: address,
                        entry: selected,
                    });
                }
            }
            let e = &entries[index];
            let key = (e.priority, e.ordinal, index);
            if start {
                active.insert(key);
            } else {
                active.remove(&key);
            }
            previous = address;
        }
        Ok(Self { entries, spans })
    }
    pub fn lookup(&self, address: u64) -> Option<&Entry> {
        let i = self
            .spans
            .partition_point(|s| s.start <= address)
            .checked_sub(1)?;
        let span = &self.spans[i];
        (address < span.end).then(|| &self.entries[span.entry])
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn e(start: u64, end: u64, priority: u8, ordinal: usize, name: &str) -> Entry {
        Entry {
            start,
            end,
            priority,
            ordinal,
            name: name.into(),
            kind: "t".into(),
            module: "test".into(),
        }
    }
    #[test]
    fn first_alias_source_priority_and_elf_order_are_stable_with_overlaps() {
        let index = SymbolIndex::build(
            vec![
                e(100, 120, 0, 0, "first"),
                e(100, 120, 0, 1, "alias"),
                e(110, 140, 1, 0, "module"),
                e(115, 125, 1, 1, "nested"),
                e(130, 150, 2, 0, "bpf"),
                e(140, 160, 3, 0, "ftrace"),
            ],
            &Job::default(),
        )
        .unwrap();
        for (at, want) in [
            (99, None),
            (100, Some("first")),
            (119, Some("first")),
            (120, Some("module")),
            (139, Some("module")),
            (140, Some("bpf")),
            (149, Some("bpf")),
            (150, Some("ftrace")),
            (160, None),
        ] {
            assert_eq!(index.lookup(at).map(|e| e.name.as_str()), want);
        }
    }
    #[test]
    fn gaps_invalid_ranges_and_cancel_are_not_filled_or_ignored() {
        let index = SymbolIndex::build(
            vec![e(10, 20, 0, 0, "a"), e(30, 40, 0, 1, "b")],
            &Job::default(),
        )
        .unwrap();
        assert!(index.lookup(25).is_none());
        assert!(SymbolIndex::build(vec![e(20, 20, 0, 0, "bad")], &Job::default()).is_err());
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(SymbolIndex::build(vec![e(10, 20, 0, 0, "a")], &job).is_err());
    }
}
