//! In-memory LRU store of the last bookmark acknowledged per (machine, subscription).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use uuid::Uuid;

type Key = (String, Uuid);

#[derive(Debug, Default)]
struct Inner {
    map: HashMap<Key, String>,
    /// Least recently used at the front.
    order: VecDeque<Key>,
}

impl Inner {
    fn touch(&mut self, key: &Key) {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key.clone());
    }
}

/// Bounded bookmark store; evicts the least recently used entry at capacity.
#[derive(Debug)]
pub struct BookmarkStore {
    capacity: usize,
    inner: Mutex<Inner>,
}

impl BookmarkStore {
    /// Creates a store holding at most `capacity` bookmarks (minimum 1).
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Returns the bookmark for `(machine_id, sub)` and marks it most recently used.
    pub fn get(&self, machine_id: &str, sub: Uuid) -> Option<String> {
        let key = (machine_id.to_string(), sub);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let value = inner.map.get(&key).cloned()?;
        inner.touch(&key);
        Some(value)
    }

    /// Stores a bookmark, evicting the least recently used entry when full.
    pub fn put(&self, machine_id: &str, sub: Uuid, bookmark: String) {
        let key = (machine_id.to_string(), sub);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !inner.map.contains_key(&key)
            && inner.map.len() >= self.capacity
            && let Some(oldest) = inner.order.pop_front()
        {
            inner.map.remove(&oldest);
        }
        inner.touch(&key);
        inner.map.insert(key, bookmark);
    }

    /// Number of stored bookmarks.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .len()
    }

    /// True when no bookmarks are stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bookmark_store_lru_evicts_oldest() {
        let s = BookmarkStore::new(2);
        let u = Uuid::nil();
        s.put("a", u, "1".into());
        s.put("b", u, "2".into());
        s.put("c", u, "3".into());
        assert_eq!(s.len(), 2);
        assert_eq!(s.get("a", u), None);
        assert_eq!(s.get("b", u).as_deref(), Some("2"));
        assert_eq!(s.get("c", u).as_deref(), Some("3"));
    }

    #[test]
    fn test_bookmark_store_get_refreshes_recency() {
        let s = BookmarkStore::new(2);
        let u = Uuid::nil();
        s.put("a", u, "1".into());
        s.put("b", u, "2".into());
        assert!(s.get("a", u).is_some());
        s.put("c", u, "3".into());
        assert!(s.get("a", u).is_some());
        assert_eq!(s.get("b", u), None);
    }

    #[test]
    fn test_bookmark_store_put_existing_updates_without_eviction() {
        let s = BookmarkStore::new(2);
        let u = Uuid::nil();
        s.put("a", u, "1".into());
        s.put("b", u, "2".into());
        s.put("a", u, "9".into());
        assert_eq!(s.len(), 2);
        assert_eq!(s.get("a", u).as_deref(), Some("9"));
        assert_eq!(s.get("b", u).as_deref(), Some("2"));
    }
}
