//! Bounded, weighted LRU caches. Eviction only affects performance, never evidence.
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hash};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub page_cache_entries: usize,
    pub scan_cache_bytes: usize,
    pub snapshot_memory_bytes: usize,
    pub snapshot_count: usize,
    pub snapshot_idle_seconds: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            page_cache_entries: 65_536,
            scan_cache_bytes: 64 * 1024 * 1024,
            snapshot_memory_bytes: 128 * 1024 * 1024,
            snapshot_count: 8,
            snapshot_idle_seconds: 1800,
        }
    }
}
struct Entry<K, V> {
    key: K,
    value: V,
    weight: usize,
    prev: Option<usize>,
    next: Option<usize>,
}
/// O(1) weighted LRU backed by an index-linked arena and FxHash.
pub(crate) struct Lru<K, V> {
    index: HashMap<K, usize, BuildHasherDefault<crate::symbols::FastHasher>>,
    entries: Vec<Option<Entry<K, V>>>,
    free: Vec<usize>,
    head: Option<usize>,
    tail: Option<usize>,
    used: usize,
    budget: usize,
}
impl<K: Clone + Hash + Eq, V> Lru<K, V> {
    pub fn new(budget: usize) -> Self {
        Self {
            index: HashMap::default(),
            entries: Vec::new(),
            free: Vec::new(),
            head: None,
            tail: None,
            used: 0,
            budget,
        }
    }
    pub fn get<Q>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let &slot = self.index.get(key)?;
        self.move_to_front(slot);
        self.entries.get(slot)?.as_ref().map(|entry| &entry.value)
    }
    pub fn insert(&mut self, key: K, value: V, weight: usize) {
        if let Some(slot) = self.index.remove(&key) {
            self.remove_slot(slot);
        }
        if weight > self.budget || self.budget == 0 {
            return;
        }
        while self.used > self.budget - weight {
            if !self.evict_tail() {
                break;
            }
        }
        let slot = if let Some(slot) = self.free.pop() {
            slot
        } else {
            let slot = self.entries.len();
            self.entries.push(None);
            slot
        };
        let old_head = self.head;
        if let Some(head_slot) = old_head
            && let Some(Some(head)) = self.entries.get_mut(head_slot)
        {
            head.prev = Some(slot);
        }
        if let Some(cell) = self.entries.get_mut(slot) {
            *cell = Some(Entry {
                key: key.clone(),
                value,
                weight,
                prev: None,
                next: old_head,
            });
        }
        self.head = Some(slot);
        if self.tail.is_none() {
            self.tail = Some(slot);
        }
        self.index.insert(key, slot);
        self.used += weight;
    }
    /// Change the budget, evicting least recently used entries until the
    /// remaining ones fit.
    pub fn set_budget(&mut self, budget: usize) {
        self.budget = budget;
        while self.used > budget {
            if !self.evict_tail() {
                break;
            }
        }
    }
    pub fn clear(&mut self) {
        self.index.clear();
        self.entries.clear();
        self.free.clear();
        self.head = None;
        self.tail = None;
        self.used = 0;
    }
    fn move_to_front(&mut self, slot: usize) {
        if self.head == Some(slot) {
            return;
        }
        let (prev, next) = match self.entries.get(slot).and_then(Option::as_ref) {
            Some(entry) => (entry.prev, entry.next),
            None => return,
        };
        if let Some(prev_slot) = prev
            && let Some(Some(prev_entry)) = self.entries.get_mut(prev_slot)
        {
            prev_entry.next = next;
        }
        if let Some(next_slot) = next
            && let Some(Some(next_entry)) = self.entries.get_mut(next_slot)
        {
            next_entry.prev = prev;
        } else {
            self.tail = prev;
        }
        let old_head = self.head;
        if let Some(head_slot) = old_head
            && let Some(Some(head_entry)) = self.entries.get_mut(head_slot)
        {
            head_entry.prev = Some(slot);
        }
        if let Some(Some(entry)) = self.entries.get_mut(slot) {
            entry.prev = None;
            entry.next = old_head;
        }
        self.head = Some(slot);
        if self.tail.is_none() {
            self.tail = Some(slot);
        }
    }
    fn remove_slot(&mut self, slot: usize) {
        let Some(entry) = self.entries.get_mut(slot).and_then(Option::take) else {
            return;
        };
        if let Some(prev_slot) = entry.prev
            && let Some(Some(prev_entry)) = self.entries.get_mut(prev_slot)
        {
            prev_entry.next = entry.next;
        } else {
            self.head = entry.next;
        }
        if let Some(next_slot) = entry.next
            && let Some(Some(next_entry)) = self.entries.get_mut(next_slot)
        {
            next_entry.prev = entry.prev;
        } else {
            self.tail = entry.prev;
        }
        self.used = self.used.saturating_sub(entry.weight);
        self.free.push(slot);
    }
    fn evict_tail(&mut self) -> bool {
        let Some(slot) = self.tail else {
            return false;
        };
        let Some(entry) = self.entries.get_mut(slot).and_then(Option::take) else {
            self.tail = None;
            return false;
        };
        if let Some(prev_slot) = entry.prev
            && let Some(Some(prev_entry)) = self.entries.get_mut(prev_slot)
        {
            prev_entry.next = None;
        } else {
            self.head = None;
        }
        self.tail = entry.prev;
        self.index.remove(&entry.key);
        self.used = self.used.saturating_sub(entry.weight);
        self.free.push(slot);
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn weighted_eviction_respects_recency_and_oversized_entries() {
        let mut c = Lru::new(4);
        c.insert(1, "one", 2);
        c.insert(2, "two", 2);
        assert_eq!(c.get(&1), Some(&"one"));
        c.insert(3, "three", 2);
        assert!(c.get(&2).is_none());
        c.insert(4, "large", 5);
        assert!(c.get(&4).is_none());
        assert_eq!(c.used, 4);
        c.set_budget(2);
        assert_eq!(c.used, 2);
        assert!(c.get(&3).is_some() && c.get(&1).is_none());
        c.set_budget(0);
        assert_eq!(c.used, 0);
        c.clear();
        assert_eq!(c.used, 0);
    }
    #[test]
    fn arena_lru_supports_borrowed_lookups_overwrites_and_slot_reuse() {
        let mut c: Lru<Vec<u8>, usize> = Lru::new(6);
        c.insert(b"aa".to_vec(), 1, 2);
        c.insert(b"bb".to_vec(), 2, 2);
        c.insert(b"cc".to_vec(), 3, 2);
        // Borrowed &[u8] lookup promotes "aa" to MRU without allocating a Vec.
        assert_eq!(c.get(b"aa".as_slice()), Some(&1));
        // Overwriting "bb" updates its weight and moves it to MRU.
        c.insert(b"bb".to_vec(), 20, 3);
        // "cc" (weight 2) had to be evicted to fit (used: aa=2 + bb=3 = 5 <= 6).
        assert_eq!(c.get(b"cc".as_slice()), None);
        assert_eq!(c.get(b"aa".as_slice()), Some(&1));
        assert_eq!(c.get(b"bb".as_slice()), Some(&20));
        assert_eq!(c.used, 5);
        // Repeated churn reuses freed arena slots rather than growing unbounded.
        for i in 0..100usize {
            c.insert(i.to_le_bytes().to_vec(), i, 2);
        }
        assert!(c.entries.len() <= 4);
        assert_eq!(c.used, 6);
    }
}
