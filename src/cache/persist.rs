//! Disk blocks of the cache: one JSON block per ecosystem, built from and loaded into [`Cache`].
//!
//! A block keeps each fact once. A vulnerability list holds only advisory ids and a total, the
//! advisory records hold the details, and the advisory link is rebuilt from the id.

use super::{Cache, Entry};
use crate::model::{AdvisorySeverity, Affected, Ecosystem, RangeEvent, VersionInfo, Vulnerability};
use crate::osv::{
    DEFAULT_DETAILS_PER_QUERY, advisory_url, anonymous_deferred, deferred, is_deferred,
    is_placeholder, is_valid_advisory_id,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::hash_map::Entry as MapEntry;

/// The format version of a block. A block with another version is dropped.
pub const BLOCK_VERSION: u32 = 1;

/// The oldest record that a block load keeps, in seconds (7 days).
pub const STALE_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// The largest record that a block keeps, in serialized bytes. A longer one stays out of the block.
pub const MAX_ENTRY_BYTES: usize = 256 * 1024;

/// The largest block, in serialized bytes. The oldest records leave a block that grows past it.
pub const MAX_BLOCK_BYTES: usize = 2 * 1024 * 1024;

/// The longest vulnerability list that a block load rebuilds. A real list has a few thousand
/// advisories at most, so a larger total can only come from a damaged block.
const MAX_LIST_LEN: usize = 10_000;

/// The cache of one ecosystem, as written to the disk.
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Block {
    /// The format version.
    pub v: u32,
    /// Registry answers, by normalized package name.
    #[serde(default)]
    pub registry: HashMap<String, RegistryRecord>,
    /// Vulnerability lists, by package name and then by declared version.
    #[serde(default)]
    pub lists: HashMap<String, HashMap<String, ListRecord>>,
    /// Advisory records, by advisory id.
    #[serde(default)]
    pub advisories: HashMap<String, AdvisoryRecord>,
}

/// The registry answer for one package.
#[derive(Serialize, Deserialize, Debug)]
pub struct RegistryRecord {
    /// When the answer was stored, in seconds since the UNIX epoch.
    pub at: u64,
    /// The newest stable release, if there is one.
    pub latest: Option<String>,
    /// Every known release, newest first, pre-releases included.
    pub all: Vec<String>,
}

/// The vulnerability list of one package version.
#[derive(Serialize, Deserialize, Debug)]
pub struct ListRecord {
    /// When the list was stored.
    pub at: u64,
    /// The real number of advisories of the list.
    pub total: usize,
    /// The ids of the first advisories of the list, in order.
    pub ids: Vec<String>,
}

/// One advisory whose details are loaded.
#[derive(Serialize, Deserialize, Debug)]
pub struct AdvisoryRecord {
    /// When the record was stored.
    pub at: u64,
    /// The OSV revision of the record, which confirms it after its lifetime.
    pub revision: Option<String>,
    /// The severity of the advisory.
    pub severity: AdvisorySeverity,
    /// The one-line description of the advisory.
    pub summary: String,
    /// The affected ranges of the packages of this block's ecosystem.
    pub affected: Vec<AffectedRecord>,
}

/// The affected ranges of one package. The ecosystem is the one of the block.
#[derive(Serialize, Deserialize, Debug)]
pub struct AffectedRecord {
    /// The package name.
    pub name: String,
    /// Each range is its events in order.
    pub ranges: Vec<Vec<RangeEvent>>,
    /// The versions that the advisory lists as affected, besides its ranges.
    pub versions: Vec<String>,
}

/// Reads a block from its text. Returns `None` for invalid JSON or another format version.
pub fn decode_block(text: &str) -> Option<Block> {
    serde_json::from_str::<Block>(text)
        .ok()
        .filter(|block| block.v == BLOCK_VERSION)
}

/// Writes a block as compact JSON.
pub fn encode_block(block: &Block) -> String {
    // Every key is a string, so serialization cannot fail. An empty text would read back as invalid.
    serde_json::to_string(block).unwrap_or_default()
}

impl Cache {
    /// Builds the block of `ecosystem` from what the cache holds.
    ///
    /// A list keeps `total` and the ids of its first [`DEFAULT_DETAILS_PER_QUERY`] entries. An
    /// advisory record is written only for an id whose details and affected ranges are cached.
    pub fn export_block(&self, ecosystem: Ecosystem) -> Block {
        let registry = self
            .version_info
            .get(&ecosystem)
            .into_iter()
            .flatten()
            .map(|(name, entry)| {
                let record = RegistryRecord {
                    at: entry.stored_at,
                    latest: entry.value.latest.clone(),
                    all: entry.value.versions.clone(),
                };
                (name.clone(), record)
            })
            .collect();
        let mut lists: HashMap<String, HashMap<String, ListRecord>> = HashMap::new();
        let mut advisories: HashMap<String, AdvisoryRecord> = HashMap::new();
        for (package, versions) in self.vulnerabilities.get(&ecosystem).into_iter().flatten() {
            for (version, entry) in versions {
                // An entry without an id comes from a restored list. It names nothing to keep.
                let first: Vec<&Vulnerability> = entry
                    .value
                    .iter()
                    .take(DEFAULT_DETAILS_PER_QUERY)
                    .filter(|listed| !listed.id.is_empty())
                    .collect();
                for listed in &first {
                    if advisories.contains_key(&listed.id) {
                        continue;
                    }
                    if let Some(record) = self.advisory_record(ecosystem, listed, entry.stored_at) {
                        advisories.insert(listed.id.clone(), record);
                    }
                }
                let record = ListRecord {
                    at: entry.stored_at,
                    total: entry.value.len(),
                    ids: first.iter().map(|listed| listed.id.clone()).collect(),
                };
                lists
                    .entry(package.clone())
                    .or_default()
                    .insert(version.clone(), record);
            }
        }
        let mut block = Block {
            v: BLOCK_VERSION,
            registry,
            lists,
            advisories,
        };
        apply_limits(&mut block);
        block
    }

    /// Builds the record of the advisory named by `listed`, when its details and ranges are cached.
    ///
    /// The details come from the advisory table, or from `listed` itself when it is a full record.
    fn advisory_record(
        &self,
        ecosystem: Ecosystem,
        listed: &Vulnerability,
        list_stored_at: u64,
    ) -> Option<AdvisoryRecord> {
        let affected = self.affected.get(&listed.id)?;
        let (details, at) = match self.advisories.get(&listed.id) {
            Some(entry) => (&entry.value, entry.stored_at),
            None if !is_placeholder(listed) && !is_deferred(listed) => (listed, list_stored_at),
            None => return None,
        };
        let ecosystem_name = ecosystem.osv_name();
        Some(AdvisoryRecord {
            at,
            revision: self.revisions.get(&listed.id).cloned(),
            severity: details.severity,
            summary: details.summary.clone(),
            // `fixes` reads only the entries of the ecosystem of the queried package.
            affected: affected
                .value
                .iter()
                .filter(|entry| entry.ecosystem.eq_ignore_ascii_case(ecosystem_name))
                .map(|entry| AffectedRecord {
                    name: entry.name.clone(),
                    ranges: entry.ranges.clone(),
                    versions: entry.versions.clone(),
                })
                .collect(),
        })
    }

    /// Loads a block of `ecosystem` into the cache, keeping the stored times of its records.
    ///
    /// A record older than [`STALE_MAX_AGE_SECS`] at `now` is skipped. An entry that the cache
    /// already holds is kept. The TTL still decides later whether a loaded record is fresh.
    pub fn import_block(&mut self, ecosystem: Ecosystem, block: Block, now: u64) {
        // A record dated after `now` (the clock moved back) counts as age zero.
        let is_recent = |at: u64| now.saturating_sub(at) <= STALE_MAX_AGE_SECS;
        for (name, record) in block.registry {
            if !is_recent(record.at) {
                continue;
            }
            self.version_info
                .entry(ecosystem)
                .or_default()
                .entry(name)
                .or_insert(Entry {
                    value: VersionInfo {
                        latest: record.latest,
                        versions: record.all,
                    },
                    stored_at: record.at,
                });
        }
        // Advisories first, so that the lists can name their records.
        let mut loaded: HashMap<String, Vulnerability> = HashMap::new();
        for (id, record) in block.advisories {
            // The id goes into links and requests, so a damaged one is not trusted.
            if !is_recent(record.at) || !is_valid_advisory_id(&id) {
                continue;
            }
            let advisory = Vulnerability {
                id: id.clone(),
                severity: record.severity,
                summary: record.summary,
                url: Some(advisory_url(&id)),
            };
            let affected: Vec<Affected> = record
                .affected
                .into_iter()
                .map(|entry| Affected {
                    ecosystem: ecosystem.osv_name().to_owned(),
                    name: entry.name,
                    ranges: entry.ranges,
                    versions: entry.versions,
                })
                .collect();
            self.advisories.entry(id.clone()).or_insert(Entry {
                value: advisory.clone(),
                stored_at: record.at,
            });
            // An advisory can name packages of several ecosystems, one block each: merge them.
            match self.affected.entry(id.clone()) {
                MapEntry::Occupied(mut known) => {
                    for entry in affected {
                        if !known.get().value.contains(&entry) {
                            known.get_mut().value.push(entry);
                        }
                    }
                }
                MapEntry::Vacant(slot) => {
                    slot.insert(Entry {
                        value: affected,
                        stored_at: record.at,
                    });
                }
            }
            if let Some(revision) = record.revision {
                self.revisions.entry(id.clone()).or_insert(revision);
            }
            loaded.insert(id, advisory);
        }
        for (package, versions) in block.lists {
            for (version, record) in versions {
                if !is_recent(record.at) {
                    continue;
                }
                let list = rebuild_list(&record, &loaded);
                self.vulnerabilities
                    .entry(ecosystem)
                    .or_default()
                    .entry(package.clone())
                    .or_default()
                    .entry(version)
                    .or_insert(Entry {
                        value: list,
                        stored_at: record.at,
                    });
            }
        }
    }
}

/// The serialized size of a record under `key`, with a few bytes for the quotes and separators.
fn record_size<T: Serialize>(key: &str, record: &T) -> usize {
    key.len() + serde_json::to_string(record).map_or(usize::MAX / 4, |text| text.len()) + 4
}

/// A record that can leave a block to make it fit: the oldest go first.
struct Removable {
    at: u64,
    size: usize,
    place: Place,
}

/// Where a [`Removable`] sits in the block.
enum Place {
    Registry(String),
    List(String, String),
}

/// Keeps a block within [`MAX_ENTRY_BYTES`] per record and [`MAX_BLOCK_BYTES`] in all.
///
/// A record over the entry limit is dropped. Past the block limit, the registry answers and lists
/// leave oldest first, and an advisory leaves with the last list that names it.
/// A list holds at most ten ids, so only the other records can exceed the entry limit.
fn apply_limits(block: &mut Block) {
    // Each record is measured once here and its size is kept, so no removal serializes it again.
    let mut total = 0;
    let mut removable: Vec<Removable> = Vec::new();
    block.registry.retain(|name, record| {
        let size = record_size(name, record);
        if size > MAX_ENTRY_BYTES {
            return false;
        }
        total += size;
        removable.push(Removable {
            at: record.at,
            size,
            place: Place::Registry(name.clone()),
        });
        true
    });
    let mut advisory_sizes: HashMap<String, usize> = HashMap::new();
    block.advisories.retain(|id, record| {
        let size = record_size(id, record);
        if size > MAX_ENTRY_BYTES {
            return false;
        }
        total += size;
        advisory_sizes.insert(id.clone(), size);
        true
    });
    // How many lists name each advisory: an advisory leaves with its last list.
    let mut references: HashMap<String, usize> = HashMap::new();
    for (package, versions) in &block.lists {
        for (version, record) in versions {
            let size = record_size(&format!("{package}/{version}"), record);
            total += size;
            removable.push(Removable {
                at: record.at,
                size,
                place: Place::List(package.clone(), version.clone()),
            });
            for id in &record.ids {
                *references.entry(id.clone()).or_default() += 1;
            }
        }
    }
    removable.sort_unstable_by_key(|record| record.at);
    for record in removable {
        if total <= MAX_BLOCK_BYTES {
            break;
        }
        total -= record.size;
        match record.place {
            Place::Registry(name) => {
                block.registry.remove(&name);
            }
            Place::List(package, version) => {
                let versions = block.lists.entry(package.clone()).or_default();
                let Some(removed) = versions.remove(&version) else {
                    continue;
                };
                if versions.is_empty() {
                    block.lists.remove(&package);
                }
                for id in &removed.ids {
                    let Some(count) = references.get_mut(id) else {
                        continue;
                    };
                    *count -= 1;
                    if *count == 0 {
                        block.advisories.remove(id);
                        total -= advisory_sizes.get(id).copied().unwrap_or(0);
                    }
                }
            }
        }
    }
}

/// Rebuilds a vulnerability list: the advisory of each stored id when its record is `loaded`, else
/// a deferred entry that keeps the id, then anonymous deferred entries up to the stored total.
fn rebuild_list(
    record: &ListRecord,
    loaded: &HashMap<String, Vulnerability>,
) -> Vec<Vulnerability> {
    let total = record.total.min(MAX_LIST_LEN);
    let named = record
        .ids
        .iter()
        .take(total)
        .map(|id| match loaded.get(id) {
            Some(advisory) => advisory.clone(),
            None if is_valid_advisory_id(id) => deferred(id),
            None => anonymous_deferred(),
        });
    let anonymous_count = total.saturating_sub(record.ids.len());
    named
        .chain(std::iter::repeat_with(anonymous_deferred).take(anonymous_count))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AdvisorySeverity, Affected, Ecosystem, RangeEvent, VersionInfo, Vulnerability,
    };
    use crate::osv::{advisory_url, anonymous_deferred, deferred, is_deferred};

    const NOW: u64 = 1_763_300_000;
    /// A lifetime longer than the maximum age, so a read never hides a record that was imported.
    const LONG_TTL_SECS: u64 = 100 * STALE_MAX_AGE_SECS;
    const PACKAGE: &str = "requests";
    const VERSION: &str = "1.0.0";

    fn known(id: &str) -> Vulnerability {
        Vulnerability {
            id: id.to_owned(),
            severity: AdvisorySeverity::High,
            summary: format!("summary of {id}"),
            url: Some(advisory_url(id)),
        }
    }

    fn affected(ecosystem: &str, name: &str) -> Affected {
        Affected {
            ecosystem: ecosystem.to_owned(),
            name: name.to_owned(),
            ranges: vec![vec![
                RangeEvent::Introduced("0".to_owned()),
                RangeEvent::Fixed("2.0.0".to_owned()),
            ]],
            versions: vec!["1.5.0".to_owned()],
        }
    }

    /// Caches the details of `id`: its advisory, its affected entry and its revision.
    fn store_details(cache: &mut Cache, id: &str, at: u64) {
        cache.put_advisory(known(id), at);
        cache.put_affected(id, vec![affected("PyPI", PACKAGE)], at);
        cache.put_revision(id, &format!("rev-{id}"));
    }

    fn ids(count: usize) -> Vec<String> {
        (0..count).map(|number| format!("GHSA-{number}")).collect()
    }

    /// Writes the block of `ecosystem` to text, reads it back, and loads it in a new cache.
    fn round_trip(cache: &Cache, ecosystem: Ecosystem) -> Cache {
        let text = encode_block(&cache.export_block(ecosystem));
        let block = decode_block(&text).expect("a written block reads back");
        let mut restored = Cache::new(LONG_TTL_SECS);
        restored.import_block(ecosystem, block, NOW);
        restored
    }

    fn version_info() -> VersionInfo {
        VersionInfo {
            latest: Some("2.0.0".to_owned()),
            versions: vec![
                "3.0.0rc1".to_owned(),
                "2.0.0".to_owned(),
                "1.0.0".to_owned(),
            ],
        }
    }

    #[test]
    fn a_block_round_trips_registry_lists_and_advisories() {
        let mut cache = Cache::new(LONG_TTL_SECS);
        cache.put_version_info(Ecosystem::PyPI, PACKAGE, version_info(), NOW);
        let list_ids = ids(4);
        for id in &list_ids {
            store_details(&mut cache, id, NOW);
        }
        let list: Vec<Vulnerability> = list_ids.iter().map(|id| known(id)).collect();
        cache.put_vulnerabilities(Ecosystem::PyPI, PACKAGE, VERSION, list.clone(), NOW);

        let mut restored = round_trip(&cache, Ecosystem::PyPI);

        assert_eq!(
            restored.version_info(Ecosystem::PyPI, PACKAGE, NOW),
            Some(&version_info())
        );
        assert_eq!(
            restored.vulnerabilities(Ecosystem::PyPI, PACKAGE, VERSION, NOW),
            Some(list.as_slice())
        );
        for id in &list_ids {
            assert_eq!(restored.advisory(id, NOW), cache.advisory(id, NOW));
            assert_eq!(restored.affected(id, NOW), cache.affected(id, NOW));
            assert!(restored.confirm_advisory(id, Some(&format!("rev-{id}")), NOW));
        }
    }

    #[test]
    fn a_registry_answer_without_a_stable_release_round_trips() {
        let only_prereleases = VersionInfo {
            latest: None,
            versions: vec!["2.0.0rc2".to_owned(), "2.0.0rc1".to_owned()],
        };
        let mut cache = Cache::new(LONG_TTL_SECS);
        cache.put_version_info(Ecosystem::PyPI, PACKAGE, only_prereleases.clone(), NOW);

        let restored = round_trip(&cache, Ecosystem::PyPI);

        assert_eq!(
            restored.version_info(Ecosystem::PyPI, PACKAGE, NOW),
            Some(&only_prereleases)
        );
    }

    /// A list of `count` deferred advisories, whose first `loaded` have their details cached.
    fn deferred_list(cache: &mut Cache, count: usize, loaded: usize) -> Vec<String> {
        let list_ids = ids(count);
        for id in &list_ids[..loaded] {
            store_details(cache, id, NOW);
        }
        let list: Vec<Vulnerability> = list_ids.iter().map(|id| deferred(id)).collect();
        cache.put_vulnerabilities(Ecosystem::PyPI, PACKAGE, VERSION, list, NOW);
        list_ids
    }

    #[test]
    fn a_list_of_758_exports_ten_ids_and_the_total() {
        let mut cache = Cache::new(LONG_TTL_SECS);
        let list_ids = deferred_list(&mut cache, 758, 20);

        let block = cache.export_block(Ecosystem::PyPI);

        let record = &block.lists[PACKAGE][VERSION];
        assert_eq!(record.total, 758);
        assert_eq!(record.ids, list_ids[..10]);
        let mut exported: Vec<&String> = block.advisories.keys().collect();
        exported.sort();
        let mut expected: Vec<&String> = list_ids[..10].iter().collect();
        expected.sort();
        assert_eq!(exported, expected);
    }

    #[test]
    fn an_imported_trimmed_list_gets_deferred_and_anonymous_entries() {
        let mut cache = Cache::new(LONG_TTL_SECS);
        // Only the first 5 of the 10 exported ids have a record.
        let list_ids = deferred_list(&mut cache, 758, 5);

        let restored = round_trip(&cache, Ecosystem::PyPI);

        let list = restored
            .vulnerabilities(Ecosystem::PyPI, PACKAGE, VERSION, NOW)
            .unwrap();
        assert_eq!(list.len(), 758);
        for (entry, id) in list[..5].iter().zip(&list_ids) {
            assert_eq!(entry, &known(id));
        }
        for (entry, id) in list[5..10].iter().zip(&list_ids[5..10]) {
            assert!(is_deferred(entry));
            assert_eq!(&entry.id, id);
            assert_eq!(entry.url, Some(advisory_url(id)));
        }
        let anonymous = &list[10..];
        assert_eq!(anonymous.len(), 748);
        assert!(
            anonymous
                .iter()
                .all(|entry| is_deferred(entry) && entry.id.is_empty() && entry.url.is_none())
        );
    }

    #[test]
    fn details_loaded_beyond_the_first_ten_are_not_exported() {
        let mut cache = Cache::new(LONG_TTL_SECS);
        let list_ids = deferred_list(&mut cache, 30, 0);
        store_details(&mut cache, &list_ids[15], NOW);

        let block = cache.export_block(Ecosystem::PyPI);

        assert!(!block.advisories.contains_key(&list_ids[15]));
    }

    #[test]
    fn failures_are_not_exported() {
        use crate::cache::FailureKind;
        let mut cache = Cache::new(LONG_TTL_SECS);
        cache.put_failure(
            FailureKind::Registry,
            Ecosystem::PyPI,
            PACKAGE,
            "registry-boom".to_owned(),
            NOW,
        );
        cache.put_failure(
            FailureKind::Osv,
            Ecosystem::PyPI,
            "requests@1.0.0",
            "osv-boom".to_owned(),
            NOW,
        );

        let block = cache.export_block(Ecosystem::PyPI);
        let text = encode_block(&block);

        assert!(block.registry.is_empty() && block.lists.is_empty());
        assert!(!text.contains("boom"), "{text}");
    }

    #[test]
    fn an_advisory_named_by_two_lists_is_stored_once() {
        let mut cache = Cache::new(LONG_TTL_SECS);
        store_details(&mut cache, "GHSA-shared", NOW);
        for version in ["1.0.0", "2.0.0"] {
            cache.put_vulnerabilities(
                Ecosystem::PyPI,
                PACKAGE,
                version,
                vec![known("GHSA-shared")],
                NOW,
            );
        }

        let block = cache.export_block(Ecosystem::PyPI);
        assert_eq!(block.advisories.len(), 1);

        let restored = round_trip(&cache, Ecosystem::PyPI);
        for version in ["1.0.0", "2.0.0"] {
            assert_eq!(
                restored.vulnerabilities(Ecosystem::PyPI, PACKAGE, version, NOW),
                Some(&[known("GHSA-shared")][..])
            );
        }
    }

    #[test]
    fn the_link_is_rebuilt_and_other_ecosystems_are_left_out() {
        let mut cache = Cache::new(LONG_TTL_SECS);
        cache.put_advisory(known("GHSA-two"), NOW);
        cache.put_affected(
            "GHSA-two",
            vec![affected("PyPI", PACKAGE), affected("npm", "left-pad")],
            NOW,
        );
        cache.put_vulnerabilities(
            Ecosystem::PyPI,
            PACKAGE,
            VERSION,
            vec![known("GHSA-two")],
            NOW,
        );

        let text = encode_block(&cache.export_block(Ecosystem::PyPI));
        assert!(!text.contains("osv.dev"), "{text}");
        assert!(!text.contains("left-pad"), "{text}");
        assert!(!text.contains("ecosystem"), "{text}");

        let restored = round_trip(&cache, Ecosystem::PyPI);
        assert_eq!(
            restored.affected("GHSA-two", NOW),
            Some(&[affected("PyPI", PACKAGE)][..])
        );
        assert_eq!(
            restored.advisory("GHSA-two", NOW).unwrap().url,
            Some(advisory_url("GHSA-two"))
        );
    }

    #[test]
    fn records_older_than_the_maximum_age_are_dropped_on_import() {
        let mut cache = Cache::new(LONG_TTL_SECS);
        cache.put_version_info(
            Ecosystem::PyPI,
            "too-old",
            version_info(),
            NOW - STALE_MAX_AGE_SECS - 1,
        );
        cache.put_version_info(
            Ecosystem::PyPI,
            "edge",
            version_info(),
            NOW - STALE_MAX_AGE_SECS,
        );
        cache.put_vulnerabilities(
            Ecosystem::PyPI,
            "too-old",
            VERSION,
            vec![anonymous_deferred()],
            NOW - STALE_MAX_AGE_SECS - 1,
        );
        cache.put_vulnerabilities(
            Ecosystem::PyPI,
            "edge",
            VERSION,
            vec![anonymous_deferred()],
            NOW - STALE_MAX_AGE_SECS,
        );
        store_details(&mut cache, "GHSA-old", NOW - STALE_MAX_AGE_SECS - 1);
        cache.put_vulnerabilities(
            Ecosystem::PyPI,
            "has-old-advisory",
            VERSION,
            vec![known("GHSA-old")],
            NOW,
        );

        let restored = round_trip(&cache, Ecosystem::PyPI);

        assert!(
            restored
                .version_info(Ecosystem::PyPI, "too-old", NOW)
                .is_none()
        );
        assert!(
            restored
                .version_info(Ecosystem::PyPI, "edge", NOW)
                .is_some()
        );
        assert!(
            restored
                .vulnerabilities(Ecosystem::PyPI, "too-old", VERSION, NOW)
                .is_none()
        );
        assert!(
            restored
                .vulnerabilities(Ecosystem::PyPI, "edge", VERSION, NOW)
                .is_some()
        );
        // An advisory record that is too old is gone, so its id comes back deferred.
        assert!(restored.advisory("GHSA-old", NOW).is_none());
        let list = restored
            .vulnerabilities(Ecosystem::PyPI, "has-old-advisory", VERSION, NOW)
            .unwrap();
        assert!(is_deferred(&list[0]) && list[0].id == "GHSA-old");
    }

    #[test]
    fn a_record_from_the_future_is_kept() {
        // The clock moved back: a record dated after `now` is not dropped.
        let mut cache = Cache::new(LONG_TTL_SECS);
        cache.put_version_info(Ecosystem::PyPI, PACKAGE, version_info(), NOW + 100);

        let restored = round_trip(&cache, Ecosystem::PyPI);

        assert!(
            restored
                .version_info(Ecosystem::PyPI, PACKAGE, NOW)
                .is_some()
        );
    }

    #[test]
    fn an_advisory_shared_by_two_ecosystems_keeps_the_entries_of_both() {
        let mut cache = Cache::new(LONG_TTL_SECS);
        cache.put_advisory(known("GHSA-both"), NOW);
        cache.put_affected(
            "GHSA-both",
            vec![affected("PyPI", PACKAGE), affected("npm", "left-pad")],
            NOW,
        );
        cache.put_vulnerabilities(
            Ecosystem::PyPI,
            PACKAGE,
            VERSION,
            vec![known("GHSA-both")],
            NOW,
        );
        cache.put_vulnerabilities(
            Ecosystem::Npm,
            "left-pad",
            VERSION,
            vec![known("GHSA-both")],
            NOW,
        );
        let python_block = encode_block(&cache.export_block(Ecosystem::PyPI));
        let npm_block = encode_block(&cache.export_block(Ecosystem::Npm));

        // The blocks load one after the other, as two manifests of different ecosystems open.
        let mut restored = Cache::new(LONG_TTL_SECS);
        restored.import_block(Ecosystem::PyPI, decode_block(&python_block).unwrap(), NOW);
        restored.import_block(Ecosystem::Npm, decode_block(&npm_block).unwrap(), NOW);

        let entries = restored.affected("GHSA-both", NOW).unwrap();
        assert!(entries.contains(&affected("PyPI", PACKAGE)));
        assert!(entries.contains(&affected("npm", "left-pad")));
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn a_damaged_id_is_not_trusted_on_import() {
        let text = r#"{"v":1,"registry":{},
            "lists":{"requests":{"1.0.0":{"at":1763300000,"total":2,"ids":["a/b","GHSA-ok"]}}},
            "advisories":{"../x":{"at":1763300000,"revision":null,"severity":"high","summary":"s","affected":[]}}}"#;
        let mut cache = Cache::new(LONG_TTL_SECS);
        cache.import_block(Ecosystem::PyPI, decode_block(text).unwrap(), NOW);

        assert!(cache.advisory("../x", NOW).is_none());
        let list = cache
            .vulnerabilities(Ecosystem::PyPI, PACKAGE, VERSION, NOW)
            .unwrap();
        // The damaged id becomes an anonymous entry. The valid one keeps its id and its link.
        assert_eq!(list[0], anonymous_deferred());
        assert_eq!(list[1], deferred("GHSA-ok"));
    }

    #[test]
    fn a_huge_total_does_not_build_a_huge_list() {
        let text = format!(
            r#"{{"v":1,"lists":{{"requests":{{"1.0.0":{{"at":{NOW},"total":{},"ids":[]}}}}}}}}"#,
            usize::MAX
        );
        let mut cache = Cache::new(LONG_TTL_SECS);
        cache.import_block(Ecosystem::PyPI, decode_block(&text).unwrap(), NOW);

        let list = cache
            .vulnerabilities(Ecosystem::PyPI, PACKAGE, VERSION, NOW)
            .unwrap();
        assert_eq!(list.len(), MAX_LIST_LEN);
    }

    #[test]
    fn a_put_marks_the_ecosystem_dirty_and_an_import_does_not() {
        let mut cache = Cache::new(LONG_TTL_SECS);
        assert!(!cache.is_dirty(Ecosystem::PyPI));

        cache.put_version_info(Ecosystem::PyPI, PACKAGE, version_info(), NOW);
        assert!(cache.is_dirty(Ecosystem::PyPI));
        assert!(!cache.is_dirty(Ecosystem::Npm));
        assert_eq!(cache.take_dirty(), [Ecosystem::PyPI]);
        assert!(!cache.is_dirty(Ecosystem::PyPI));

        cache.put_vulnerabilities(
            Ecosystem::Npm,
            "left-pad",
            VERSION,
            vec![known("GHSA-1")],
            NOW,
        );
        assert!(cache.is_dirty(Ecosystem::Npm));
        cache.mark_clean(Ecosystem::Npm);
        assert!(cache.take_dirty().is_empty());

        let mut source = Cache::new(LONG_TTL_SECS);
        source.put_version_info(Ecosystem::PyPI, PACKAGE, version_info(), NOW);
        let block = decode_block(&encode_block(&source.export_block(Ecosystem::PyPI))).unwrap();
        cache.import_block(Ecosystem::PyPI, block, NOW);
        assert!(!cache.is_dirty(Ecosystem::PyPI));

        // A save that the store rejects marks the ecosystem again, so the next chunk retries it.
        cache.mark_dirty(Ecosystem::PyPI);
        assert_eq!(cache.take_dirty(), [Ecosystem::PyPI]);
    }

    #[test]
    fn a_failure_does_not_mark_dirty() {
        use crate::cache::FailureKind;
        let mut cache = Cache::new(LONG_TTL_SECS);
        cache.put_failure(
            FailureKind::Registry,
            Ecosystem::PyPI,
            PACKAGE,
            "boom".to_owned(),
            NOW,
        );
        assert!(!cache.is_dirty(Ecosystem::PyPI));
    }

    /// A version list of `count` releases: about 12 bytes each once written.
    fn long_version_list(count: usize) -> VersionInfo {
        VersionInfo {
            latest: None,
            versions: (0..count).map(|number| format!("1.{number}.0")).collect(),
        }
    }

    #[test]
    fn an_entry_over_the_entry_limit_is_not_exported_and_the_others_are() {
        let mut cache = Cache::new(LONG_TTL_SECS);
        // About 440 KB: over the 256 KiB entry limit.
        cache.put_version_info(Ecosystem::PyPI, "huge", long_version_list(40_000), NOW);
        cache.put_version_info(Ecosystem::PyPI, "small", version_info(), NOW);

        let block = cache.export_block(Ecosystem::PyPI);

        assert!(!block.registry.contains_key("huge"));
        assert!(block.registry.contains_key("small"));
    }

    #[test]
    fn a_block_over_the_block_limit_drops_the_oldest_records_first() {
        let mut cache = Cache::new(LONG_TTL_SECS);
        // Each answer is about 240 KB, under the entry limit. Thirty of them are far over 2 MiB.
        for number in 0..30u64 {
            cache.put_version_info(
                Ecosystem::PyPI,
                &format!("pkg-{number}"),
                long_version_list(20_000),
                NOW + number,
            );
        }
        // The oldest list names an advisory that no other list names.
        store_details(&mut cache, "GHSA-old", NOW - 10);
        cache.put_vulnerabilities(
            Ecosystem::PyPI,
            "old-list",
            VERSION,
            vec![known("GHSA-old")],
            NOW - 10,
        );
        store_details(&mut cache, "GHSA-new", NOW + 100);
        cache.put_vulnerabilities(
            Ecosystem::PyPI,
            "new-list",
            VERSION,
            vec![known("GHSA-new")],
            NOW + 100,
        );

        let block = cache.export_block(Ecosystem::PyPI);

        assert!(encode_block(&block).len() <= MAX_BLOCK_BYTES);
        let mut kept: Vec<u64> = block
            .registry
            .keys()
            .map(|name| name.strip_prefix("pkg-").unwrap().parse().unwrap())
            .collect();
        kept.sort_unstable();
        assert!(!kept.is_empty() && kept.len() < 30);
        // Only the newest answers stay: the kept numbers are the last ones.
        let first_kept = 30 - kept.len() as u64;
        assert_eq!(kept, (first_kept..30).collect::<Vec<_>>());
        // The oldest list went first, and its advisory with it. The newest list stays.
        assert!(!block.lists.contains_key("old-list"));
        assert!(!block.advisories.contains_key("GHSA-old"));
        assert!(block.lists.contains_key("new-list"));
        assert!(block.advisories.contains_key("GHSA-new"));
    }

    #[test]
    fn decode_block_rejects_invalid_json_and_other_versions() {
        assert!(decode_block("{").is_none());
        assert!(decode_block("").is_none());
        assert!(decode_block(r#"{"v":2,"registry":{},"lists":{},"advisories":{}}"#).is_none());
        assert!(decode_block(r#"{"registry":{}}"#).is_none());
        assert!(decode_block(r#"{"v":1,"registry":{},"lists":{},"advisories":{}}"#).is_some());
    }
}
