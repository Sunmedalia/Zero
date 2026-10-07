//! Bounded, weighted LRU caches. Eviction only affects performance, never evidence.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::hash::Hash;

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
pub(crate) struct Lru<K, V> {
    values: HashMap<K, (V, u64, usize)>,
    order: BTreeSet<(u64, K)>,
    clock: u64,
    used: usize,
    budget: usize,
}
impl<K: Clone + Hash + Eq + Ord, V> Lru<K, V> {
    pub fn new(budget: usize) -> Self {
        Self {
            values: HashMap::new(),
            order: BTreeSet::new(),
            clock: 0,
            used: 0,
            budget,
        }
    }
    pub fn get(&mut self, key: &K) -> Option<&V> {
        let (value, stamp, _) = self.values.get_mut(key)?;
        self.order.remove(&(*stamp, key.clone()));
        self.clock += 1;
        *stamp = self.clock;
        self.order.insert((*stamp, key.clone()));
        Some(value)
    }
    pub fn insert(&mut self, key: K, value: V, weight: usize) {
        if let Some((_, stamp, old)) = self.values.remove(&key) {
            self.order.remove(&(stamp, key.clone()));
            self.used -= old;
        }
        if weight > self.budget || self.budget == 0 {
            return;
        }
        while self.used > self.budget - weight {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            if let Some((_, _, size)) = self.values.remove(&oldest) {
                self.used -= size;
            }
        }
        self.clock += 1;
        self.order.insert((self.clock, key.clone()));
        self.values.insert(key, (value, self.clock, weight));
        self.used += weight;
    }
    pub fn clear(&mut self) {
        self.values.clear();
        self.order.clear();
        self.used = 0;
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
        c.clear();
        assert_eq!(c.used, 0);
    }
}
