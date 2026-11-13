//! Secondary indexes (#210): for the keys under a prefix, a value extracted from the stored
//! bytes (e.g. a pod's `spec.nodeName`) maps to the keys that have it, in key order. A list
//! selected by that value then visits its matches only instead of every key under the prefix.
//! Kept in step with every change of the live data (writes, replicated records, log replay,
//! restore), so a lookup is always exact for the current revision.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

/// Extracts the indexed values from a stored (plaintext) value (several for e.g. labels;
/// none: the key is not indexed).
pub type Extract = fn(&[u8]) -> Vec<String>;

pub(crate) struct Index {
    pub(crate) name: &'static str,
    prefix: String,
    extract: Extract,
    /// (value, key), so the keys of one value come in key order.
    entries: BTreeSet<(String, Rc<str>)>,
    by_key: BTreeMap<Rc<str>, Vec<String>>,
}

impl Index {
    pub(crate) fn new(name: &'static str, prefix: &str, extract: Extract) -> Index {
        Index { name, prefix: String::from(prefix), extract, entries: BTreeSet::new(), by_key: BTreeMap::new() }
    }

    pub(crate) fn put(&mut self, key: &Rc<str>, value: &[u8]) {
        if !key.starts_with(self.prefix.as_str()) {
            return;
        }
        let mut new = (self.extract)(value);
        new.sort();
        new.dedup();
        if self.by_key.get(key).map_or(new.is_empty(), |old| *old == new) {
            return;
        }
        self.remove(key);
        if !new.is_empty() {
            for v in &new {
                self.entries.insert((v.clone(), key.clone()));
            }
            self.by_key.insert(key.clone(), new);
        }
    }

    pub(crate) fn remove(&mut self, key: &str) {
        if let Some((k, vs)) = self.by_key.remove_entry(key) {
            for v in vs {
                self.entries.remove(&(v, k.clone()));
            }
        }
    }

    /// How many keys have `value` (to pick the most selective of several terms).
    pub(crate) fn count(&self, value: &str) -> usize {
        self.entries.range((String::from(value), Rc::from(""))..).take_while(|(v, _)| v == value).count()
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.by_key.clear();
    }

    pub(crate) fn covers(&self, prefix: &str) -> bool {
        prefix.starts_with(self.prefix.as_str())
    }

    /// Keys with `value` under `prefix`, after `start_after`, in key order.
    pub(crate) fn keys<'a>(&'a self, value: &'a str, prefix: &'a str, start_after: Option<&'a str>) -> impl Iterator<Item = &'a Rc<str>> + 'a {
        let from: Rc<str> = Rc::from(start_after.unwrap_or(prefix));
        let incl = start_after.is_none();
        self.entries
            .range((core::ops::Bound::Included((String::from(value), from.clone())), core::ops::Bound::Unbounded))
            .take_while(move |(v, k)| v == value && (k.starts_with(prefix) || **k < *prefix))
            .map(|(_, k)| k)
            .filter(move |k| k.starts_with(prefix) && (incl || &***k != &*from))
    }
}
