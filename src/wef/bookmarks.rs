//! In-memory LRU store of the last bookmark acknowledged per (client key,
//! subscription).

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use uuid::Uuid;

use crate::wef::subscription::validate_xml_fragment;

/// Largest bookmark accepted by [`BookmarkStore::put`].
pub const MAX_BOOKMARK_BYTES: usize = 8 * 1024;
/// Largest store key accepted by [`BookmarkStore::put`] (an identity key such as
/// `krb:<principal>`, or `machine:<MachineID>` on the unauthenticated topology).
pub const MAX_KEY_BYTES: usize = 1024;

type Key = (String, Uuid);

#[derive(Debug, Default)]
struct Inner {
    /// key -> (bookmark, recency generation)
    map: HashMap<Key, (String, u64)>,
    /// generation -> key; the smallest generation is the least recently used.
    order: BTreeMap<u64, Key>,
    next_gen: u64,
}

impl Inner {
    fn bump(&mut self, key: &Key, old_gen: Option<u64>) -> u64 {
        if let Some(g) = old_gen {
            self.order.remove(&g);
        }
        let g = self.next_gen;
        self.next_gen += 1;
        self.order.insert(g, key.clone());
        g
    }
}

/// Bounded bookmark store; evicts the least recently used entry at capacity.
///
/// Both lookups and inserts are O(log n). Bookmarks are replayed verbatim into outgoing
/// subscription XML and arrive from clients, so [`put`](Self::put) validates them; callers
/// rely on that and must not bypass it.
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

    /// Returns the bookmark for `(key, sub)` and marks it most recently used.
    pub fn get(&self, key: &str, sub: Uuid) -> Option<String> {
        let lookup_key = (key.to_string(), sub);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (value, old) = inner.map.get(&lookup_key).cloned()?;
        let g = inner.bump(&lookup_key, Some(old));
        inner.map.insert(lookup_key, (value.clone(), g));
        Some(value)
    }

    /// Stores a bookmark, evicting the least recently used entry when full.
    ///
    /// Returns `false` (and stores nothing) when `key` is not 1..=1024 bytes or the
    /// bookmark exceeds 8 KiB or is not a complete, well-formed XML fragment with a single
    /// `BookmarkList` root.
    #[must_use]
    pub fn put(&self, key: &str, sub: Uuid, bookmark: String) -> bool {
        if key.is_empty()
            || key.len() > MAX_KEY_BYTES
            || bookmark.len() > MAX_BOOKMARK_BYTES
            || validate_xml_fragment(&bookmark, "BookmarkList").is_err()
        {
            return false;
        }
        let lookup_key = (key.to_string(), sub);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let old = inner.map.get(&lookup_key).map(|(_, g)| *g);
        if old.is_none()
            && inner.map.len() >= self.capacity
            && let Some((_, oldest)) = inner.order.pop_first()
        {
            inner.map.remove(&oldest);
        }
        let g = inner.bump(&lookup_key, old);
        inner.map.insert(lookup_key, (bookmark, g));
        true
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

    fn bm(n: u32) -> String {
        format!("<BookmarkList><Bookmark Channel=\"Security\" RecordId=\"{n}\"/></BookmarkList>")
    }

    fn put(s: &BookmarkStore, m: &str, u: Uuid, n: u32) {
        assert!(s.put(m, u, bm(n)));
    }

    #[test]
    fn test_bookmark_store_lru_evicts_oldest() {
        let s = BookmarkStore::new(2);
        let u = Uuid::nil();
        put(&s, "a", u, 1);
        put(&s, "b", u, 2);
        put(&s, "c", u, 3);
        assert_eq!(s.len(), 2);
        assert_eq!(s.get("a", u), None);
        assert_eq!(s.get("b", u), Some(bm(2)));
        assert_eq!(s.get("c", u), Some(bm(3)));
    }

    #[test]
    fn test_bookmark_store_get_refreshes_recency() {
        let s = BookmarkStore::new(2);
        let u = Uuid::nil();
        put(&s, "a", u, 1);
        put(&s, "b", u, 2);
        assert!(s.get("a", u).is_some());
        put(&s, "c", u, 3);
        assert!(s.get("a", u).is_some());
        assert_eq!(s.get("b", u), None);
    }

    #[test]
    fn test_bookmark_store_put_existing_updates_without_eviction() {
        let s = BookmarkStore::new(2);
        let u = Uuid::nil();
        put(&s, "a", u, 1);
        put(&s, "b", u, 2);
        put(&s, "a", u, 9);
        assert_eq!(s.len(), 2);
        assert_eq!(s.get("a", u), Some(bm(9)));
        assert_eq!(s.get("b", u), Some(bm(2)));
    }

    #[test]
    fn test_bookmark_store_eviction_order_after_interleaved_gets() {
        let s = BookmarkStore::new(4);
        let u = Uuid::nil();
        for m in ["a", "b", "c", "d"] {
            put(&s, m, u, 1);
        }
        // recency, oldest first: a b c d -> after gets: c d b a
        s.get("a", u);
        s.get("b", u);
        s.get("a", u);
        s.get("b", u);
        put(&s, "e", u, 1); // evicts c
        put(&s, "f", u, 1); // evicts d
        assert_eq!(s.get("c", u), None);
        assert_eq!(s.get("d", u), None);
        put(&s, "g", u, 1); // evicts a (oldest of a,b,e,f after the gets above)
        assert_eq!(s.get("a", u), None);
        assert!(s.get("b", u).is_some());
        assert_eq!(s.len(), 4);
    }

    #[test]
    fn test_bookmark_store_size_boundary_8192_accepted_8193_rejected() {
        assert_eq!(MAX_BOOKMARK_BYTES, 8192);
        let s = BookmarkStore::new(4);
        let u = Uuid::nil();
        let wrap = "<BookmarkList></BookmarkList>".len();
        let at_limit = format!(
            "<BookmarkList>{}</BookmarkList>",
            " ".repeat(MAX_BOOKMARK_BYTES - wrap)
        );
        assert_eq!(at_limit.len(), 8192);
        assert!(s.put("a", u, at_limit));
        let over = format!(
            "<BookmarkList>{}</BookmarkList>",
            " ".repeat(MAX_BOOKMARK_BYTES - wrap + 1)
        );
        assert_eq!(over.len(), 8193);
        assert!(!s.put("b", u, over));
    }

    #[test]
    fn test_put_key_length_boundaries() {
        let s = BookmarkStore::new(4);
        let u = Uuid::nil();
        let bm_str = "<BookmarkList><Bookmark Channel=\"Security\" RecordId=\"1\"/></BookmarkList>";
        assert!(!s.put("", u, bm_str.into()));
        assert!(s.put(&"k".repeat(MAX_KEY_BYTES), u, bm_str.into()));
        assert!(!s.put(&"k".repeat(MAX_KEY_BYTES + 1), u, bm_str.into()));
        assert_eq!(MAX_KEY_BYTES, 1024);
    }

    #[test]
    fn test_keys_are_isolated_per_identity() {
        let s = BookmarkStore::new(4);
        let u = Uuid::nil();
        let a = "<BookmarkList><Bookmark Channel=\"Security\" RecordId=\"1\"/></BookmarkList>";
        let b = "<BookmarkList><Bookmark Channel=\"Security\" RecordId=\"2\"/></BookmarkList>";
        assert!(s.put("krb:WIN10$@EXAMPLE.COM", u, a.into()));
        assert!(s.put("krb:WIN11$@EXAMPLE.COM", u, b.into()));
        assert_eq!(s.get("krb:WIN10$@EXAMPLE.COM", u).as_deref(), Some(a));
        assert_eq!(s.get("machine:win10.example.com", u), None);
    }

    #[test]
    fn test_bookmark_store_rejects_invalid_input() {
        let s = BookmarkStore::new(4);
        let u = Uuid::nil();
        assert!(!s.put("", u, bm(1)));
        assert!(!s.put(&"m".repeat(MAX_KEY_BYTES + 1), u, bm(1)));
        assert!(s.put(&"m".repeat(MAX_KEY_BYTES), u, bm(1)));
        let big = format!(
            "<BookmarkList>{}</BookmarkList>",
            " ".repeat(MAX_BOOKMARK_BYTES)
        );
        assert!(!s.put("a", u, big));
        for bad in [
            "<BookmarkList>",
            "<BookmarkList><Bookmark>",
            "<Other/>",
            "<BookmarkList/><BookmarkList/>",
            "</BookmarkList><x>",
            "<!-- c --><BookmarkList/>",
            "<BookmarkList>&foo;</BookmarkList>",
            "",
        ] {
            assert!(!s.put("a", u, bad.to_string()), "{bad}");
        }
        assert_eq!(s.len(), 1);
        assert!(s.put("b", u, "<b:BookmarkList xmlns:b=\"urn:x\"/>".into()));
    }

    #[test]
    fn test_bookmark_store_is_empty_tracks_contents() {
        let s = BookmarkStore::new(2);
        assert!(s.is_empty());
        put(&s, "a", Uuid::nil(), 1);
        assert!(!s.is_empty());
    }
}
