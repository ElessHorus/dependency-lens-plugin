//! Key-value storage behind the disk cache: the host storage in production, memory in tests.

use crate::model::Ecosystem;
use openidea_plugin::host;

/// A persistent key-value store with string keys and values.
///
/// Errors are plain messages: the caller logs them and goes on as if the store were empty.
pub trait Store {
    /// Returns the value of `key`, or `None` when the key does not exist.
    fn get(&self, key: &str) -> Result<Option<String>, String>;
    /// Stores `value` under `key`, replacing any previous value.
    fn set(&self, key: &str, value: &str) -> Result<(), String>;
    /// Removes `key`. A missing key is not an error.
    fn delete(&self, key: &str) -> Result<(), String>;
}

/// The plugin storage of the IDE host. It needs the `storage` capability.
pub struct HostStore;

impl Store for HostStore {
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        host::storage::get(key).map_err(|error| error.to_string())
    }

    fn set(&self, key: &str, value: &str) -> Result<(), String> {
        host::storage::set(key, value).map_err(|error| error.to_string())
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        host::storage::delete(key).map_err(|error| error.to_string())
    }
}

/// The storage key of the cache block of `ecosystem`, such as `cache/PyPI` or `cache/crates.io`.
pub fn block_key(ecosystem: Ecosystem) -> String {
    format!("cache/{}", ecosystem.osv_name())
}

/// An in-memory store for tests. A failing one rejects every call.
#[cfg(test)]
#[derive(Default)]
pub struct MemoryStore {
    entries: std::cell::RefCell<std::collections::BTreeMap<String, String>>,
    is_failing: bool,
}

#[cfg(test)]
impl MemoryStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a store whose every call returns `Err("store unavailable")`.
    pub fn failing() -> Self {
        Self {
            is_failing: true,
            ..Self::new()
        }
    }

    /// Returns the stored keys, sorted.
    pub fn keys(&self) -> Vec<String> {
        self.entries.borrow().keys().cloned().collect()
    }

    fn check(&self) -> Result<(), String> {
        if self.is_failing {
            Err("store unavailable".to_owned())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
impl Store for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        self.check()?;
        Ok(self.entries.borrow().get(key).cloned())
    }

    fn set(&self, key: &str, value: &str) -> Result<(), String> {
        self.check()?;
        self.entries
            .borrow_mut()
            .insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        self.check()?;
        self.entries.borrow_mut().remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Ecosystem;

    #[test]
    fn memory_store_round_trips_a_value() {
        let store = MemoryStore::new();
        store.set("cache/PyPI", "{}").unwrap();
        assert_eq!(store.get("cache/PyPI").unwrap().as_deref(), Some("{}"));
    }

    #[test]
    fn memory_store_get_of_a_missing_key_is_none() {
        let store = MemoryStore::new();
        assert_eq!(store.get("cache/PyPI").unwrap(), None);
    }

    #[test]
    fn memory_store_delete_removes_the_key() {
        let store = MemoryStore::new();
        store.set("cache/PyPI", "{}").unwrap();
        store.delete("cache/PyPI").unwrap();
        assert_eq!(store.get("cache/PyPI").unwrap(), None);
        assert!(store.keys().is_empty());
    }

    #[test]
    fn failing_store_returns_an_error_on_every_call() {
        let store = MemoryStore::failing();
        assert_eq!(store.get("k"), Err("store unavailable".to_owned()));
        assert_eq!(store.set("k", "v"), Err("store unavailable".to_owned()));
        assert_eq!(store.delete("k"), Err("store unavailable".to_owned()));
    }

    #[test]
    fn block_key_uses_the_osv_name() {
        assert_eq!(block_key(Ecosystem::Cargo), "cache/crates.io");
        assert_eq!(block_key(Ecosystem::PyPI), "cache/PyPI");
    }
}
