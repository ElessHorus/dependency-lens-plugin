//! In-memory TTL cache for registry versions, OSV results and advisories.

use crate::model::{Affected, Ecosystem, VersionInfo, Vulnerability};
use std::collections::{HashMap, HashSet};

pub mod persist;

/// Lifetime of a cached failure, in seconds. Independent of the cache TTL.
const FAILURE_TTL_SECS: u64 = 60;

/// Which upstream service reported a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailureKind {
    /// A package registry lookup failed.
    Registry,
    /// An OSV.dev query failed.
    Osv,
}

/// A cached value and the time it was stored.
struct Entry<T> {
    value: T,
    stored_at: u64,
}

/// Vulnerability entries of one ecosystem, keyed by package name and then by version.
type VulnerabilityIndex = HashMap<String, HashMap<String, Entry<Vec<Vulnerability>>>>;

/// In-memory cache with a time-to-live per entry.
pub struct Cache {
    ttl_secs: u64,
    version_info: HashMap<Ecosystem, HashMap<String, Entry<VersionInfo>>>,
    vulnerabilities: HashMap<Ecosystem, VulnerabilityIndex>,
    failures: HashMap<(FailureKind, Ecosystem), HashMap<String, Entry<String>>>,
    advisories: HashMap<String, Entry<Vulnerability>>,
    /// The affected ranges of each advisory, which the fix quick fix reads.
    affected: HashMap<String, Entry<Vec<Affected>>>,
    /// The revision (`modified` time) of each stored advisory record. It outlives the TTL, so that
    /// an expired record whose revision did not change is confirmed without a new download.
    revisions: HashMap<String, String>,
    /// Ecosystems whose disk block is out of date: a registry answer or a list was stored since the last save.
    dirty: HashSet<Ecosystem>,
}

/// Returns the value of an entry that is still valid at `now`.
///
/// `saturating_sub` treats a `now` earlier than `stored_at` as age zero, so such an entry stays fresh.
fn fresh_value<T>(entry: Option<&Entry<T>>, now: u64, ttl_secs: u64) -> Option<&T> {
    entry
        .filter(|fresh| now.saturating_sub(fresh.stored_at) < ttl_secs)
        .map(|fresh| &fresh.value)
}

impl Cache {
    /// Creates a cache whose entries live `ttl_secs` seconds. Zero stores nothing.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl_secs,
            version_info: HashMap::new(),
            vulnerabilities: HashMap::new(),
            failures: HashMap::new(),
            advisories: HashMap::new(),
            affected: HashMap::new(),
            revisions: HashMap::new(),
            dirty: HashSet::new(),
        }
    }

    /// Returns `false` when the cache must not store anything.
    fn stores_entries(&self) -> bool {
        self.ttl_secs > 0
    }

    /// Returns `true` when the disk block of `ecosystem` is out of date.
    pub fn is_dirty(&self, ecosystem: Ecosystem) -> bool {
        self.dirty.contains(&ecosystem)
    }

    /// Returns the ecosystems whose disk block is out of date, in order, and marks them all clean.
    pub fn take_dirty(&mut self) -> Vec<Ecosystem> {
        let mut ecosystems: Vec<Ecosystem> = self.dirty.drain().collect();
        ecosystems.sort_unstable();
        ecosystems
    }

    /// Marks the disk block of `ecosystem` as up to date.
    pub fn mark_clean(&mut self, ecosystem: Ecosystem) {
        self.dirty.remove(&ecosystem);
    }

    /// Marks the disk block of `ecosystem` as out of date, for a save that did not succeed.
    pub fn mark_dirty(&mut self, ecosystem: Ecosystem) {
        self.dirty.insert(ecosystem);
    }

    /// Returns the cached version data for a package, if still valid.
    pub fn version_info(&self, eco: Ecosystem, package: &str, now: u64) -> Option<&VersionInfo> {
        // Nested maps let a `&str` key the lookup, so no `String` is built.
        let entry = self.version_info.get(&eco)?.get(package);
        fresh_value(entry, now, self.ttl_secs)
    }

    /// Stores version data for a package, replacing any previous value.
    pub fn put_version_info(&mut self, eco: Ecosystem, package: &str, info: VersionInfo, now: u64) {
        if !self.stores_entries() {
            return;
        }
        self.dirty.insert(eco);
        self.version_info.entry(eco).or_default().insert(
            package.to_owned(),
            Entry {
                value: info,
                stored_at: now,
            },
        );
    }

    /// Returns the cached vulnerabilities of one package version, if still valid.
    pub fn vulnerabilities(
        &self,
        eco: Ecosystem,
        package: &str,
        version: &str,
        now: u64,
    ) -> Option<&[Vulnerability]> {
        let entry = self.vulnerabilities.get(&eco)?.get(package)?.get(version);
        fresh_value(entry, now, self.ttl_secs).map(Vec::as_slice)
    }

    /// Stores the vulnerabilities of one package version, replacing any previous value.
    pub fn put_vulnerabilities(
        &mut self,
        eco: Ecosystem,
        package: &str,
        version: &str,
        vulns: Vec<Vulnerability>,
        now: u64,
    ) {
        if !self.stores_entries() {
            return;
        }
        self.dirty.insert(eco);
        self.vulnerabilities
            .entry(eco)
            .or_default()
            .entry(package.to_owned())
            .or_default()
            .insert(
                version.to_owned(),
                Entry {
                    value: vulns,
                    stored_at: now,
                },
            );
    }

    /// Stores a failure for 60 seconds, whatever the cache TTL.
    pub fn put_failure(
        &mut self,
        kind: FailureKind,
        eco: Ecosystem,
        package: &str,
        reason: String,
        now: u64,
    ) {
        if !self.stores_entries() {
            return;
        }
        self.failures.entry((kind, eco)).or_default().insert(
            package.to_owned(),
            Entry {
                value: reason,
                stored_at: now,
            },
        );
    }

    /// Returns the reason of a recent failure, if it is still within 60 seconds.
    pub fn failure(
        &self,
        kind: FailureKind,
        eco: Ecosystem,
        package: &str,
        now: u64,
    ) -> Option<&str> {
        let entry = self.failures.get(&(kind, eco))?.get(package);
        fresh_value(entry, now, FAILURE_TTL_SECS).map(String::as_str)
    }

    /// Returns a cached advisory by its identifier, if still valid.
    pub fn advisory(&self, id: &str, now: u64) -> Option<&Vulnerability> {
        fresh_value(self.advisories.get(id), now, self.ttl_secs)
    }

    /// Returns the cached affected ranges of an advisory, if still valid.
    pub fn affected(&self, id: &str, now: u64) -> Option<&[Affected]> {
        fresh_value(self.affected.get(id), now, self.ttl_secs).map(Vec::as_slice)
    }

    /// Stores the affected ranges of the advisory `id`, replacing any previous value.
    pub fn put_affected(&mut self, id: &str, affected: Vec<Affected>, now: u64) {
        if !self.stores_entries() {
            return;
        }
        self.affected.insert(
            id.to_owned(),
            Entry {
                value: affected,
                stored_at: now,
            },
        );
    }

    /// Stores the revision of the record of the advisory `id`, as a comparable key.
    pub fn put_revision(&mut self, id: &str, revision: &str) {
        if self.stores_entries() {
            self.revisions.insert(id.to_owned(), revision.to_owned());
        }
    }

    /// Returns `true` when the stored record of the advisory `id` is the one to use.
    ///
    /// A stored revision that equals `revision` confirms the record, even after its TTL, and
    /// restarts its lifetime. A different revision rejects it, even inside its TTL. When one side
    /// has no revision, the TTL decides. The record needs both its advisory and its affected ranges.
    pub fn confirm_advisory(&mut self, id: &str, revision: Option<&str>, now: u64) -> bool {
        let (Some(advisory), Some(affected)) =
            (self.advisories.get_mut(id), self.affected.get_mut(id))
        else {
            return false;
        };
        match (self.revisions.get(id).map(String::as_str), revision) {
            (Some(stored), Some(wanted)) if stored == wanted => {
                advisory.stored_at = now;
                affected.stored_at = now;
                true
            }
            (Some(_), Some(_)) => false,
            _ => {
                fresh_value(Some(&*advisory), now, self.ttl_secs).is_some()
                    && fresh_value(Some(&*affected), now, self.ttl_secs).is_some()
            }
        }
    }

    /// Stores an advisory under its `id`, replacing any previous value.
    pub fn put_advisory(&mut self, advisory: Vulnerability, now: u64) {
        if !self.stores_entries() {
            return;
        }
        let id = advisory.id.clone();
        self.advisories.insert(
            id,
            Entry {
                value: advisory,
                stored_at: now,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AdvisorySeverity;

    const TTL_SECS: u64 = 3600;
    const START_SECS: u64 = 1_000;

    fn sample_info() -> VersionInfo {
        VersionInfo {
            latest: Some("1.2.0".to_owned()),
            versions: vec!["1.1.0".to_owned(), "1.2.0".to_owned()],
        }
    }

    fn sample_vulnerability(id: &str) -> Vulnerability {
        Vulnerability {
            id: id.to_owned(),
            severity: AdvisorySeverity::High,
            summary: "summary".to_owned(),
            url: None,
        }
    }

    #[test]
    fn version_info_is_returned_until_ttl_ends() {
        let mut cache = Cache::new(TTL_SECS);
        cache.put_version_info(Ecosystem::Cargo, "serde", sample_info(), START_SECS);
        let expected = sample_info();
        assert_eq!(
            cache.version_info(Ecosystem::Cargo, "serde", START_SECS + TTL_SECS - 1),
            Some(&expected)
        );
        assert_eq!(
            cache.version_info(Ecosystem::Cargo, "serde", START_SECS + TTL_SECS),
            None
        );
    }

    #[test]
    fn earlier_now_than_stored_time_counts_as_fresh() {
        let mut cache = Cache::new(TTL_SECS);
        cache.put_version_info(Ecosystem::Cargo, "serde", sample_info(), START_SECS);
        assert!(cache.version_info(Ecosystem::Cargo, "serde", 0).is_some());
    }

    #[test]
    fn put_replaces_the_previous_value() {
        let mut cache = Cache::new(TTL_SECS);
        cache.put_version_info(Ecosystem::Cargo, "serde", sample_info(), START_SECS);
        let newer = VersionInfo {
            latest: Some("2.0.0".to_owned()),
            versions: vec!["2.0.0".to_owned()],
        };
        cache.put_version_info(Ecosystem::Cargo, "serde", newer.clone(), START_SECS + 10);
        assert_eq!(
            cache.version_info(Ecosystem::Cargo, "serde", START_SECS + 10),
            Some(&newer)
        );
    }

    #[test]
    fn vulnerabilities_are_keyed_by_version() {
        let mut cache = Cache::new(TTL_SECS);
        let vulns = vec![sample_vulnerability("GHSA-1")];
        cache.put_vulnerabilities(
            Ecosystem::Cargo,
            "serde",
            "1.0.0",
            vulns.clone(),
            START_SECS,
        );
        assert_eq!(
            cache.vulnerabilities(Ecosystem::Cargo, "serde", "1.0.0", START_SECS),
            Some(vulns.as_slice())
        );
        assert_eq!(
            cache.vulnerabilities(Ecosystem::Cargo, "serde", "1.0.1", START_SECS),
            None
        );
    }

    #[test]
    fn failure_expires_after_60_seconds_regardless_of_ttl() {
        let mut cache = Cache::new(TTL_SECS);
        cache.put_failure(
            FailureKind::Registry,
            Ecosystem::Cargo,
            "serde",
            "timeout".to_owned(),
            START_SECS,
        );
        assert_eq!(
            cache.failure(
                FailureKind::Registry,
                Ecosystem::Cargo,
                "serde",
                START_SECS + 59
            ),
            Some("timeout")
        );
        assert_eq!(
            cache.failure(
                FailureKind::Registry,
                Ecosystem::Cargo,
                "serde",
                START_SECS + 60
            ),
            None
        );
    }

    #[test]
    fn failure_does_not_block_a_later_success() {
        let mut cache = Cache::new(TTL_SECS);
        cache.put_failure(
            FailureKind::Registry,
            Ecosystem::Cargo,
            "serde",
            "timeout".to_owned(),
            START_SECS,
        );
        cache.put_version_info(Ecosystem::Cargo, "serde", sample_info(), START_SECS + 60);
        assert!(
            cache
                .version_info(Ecosystem::Cargo, "serde", START_SECS + 60)
                .is_some()
        );
    }

    #[test]
    fn failures_are_keyed_by_kind() {
        let mut cache = Cache::new(TTL_SECS);
        cache.put_failure(
            FailureKind::Osv,
            Ecosystem::Cargo,
            "serde",
            "503".to_owned(),
            START_SECS,
        );
        assert_eq!(
            cache.failure(FailureKind::Registry, Ecosystem::Cargo, "serde", START_SECS),
            None
        );
    }

    #[test]
    fn advisory_is_found_by_id_until_ttl_ends() {
        let mut cache = Cache::new(TTL_SECS);
        let advisory = sample_vulnerability("GHSA-1");
        cache.put_advisory(advisory.clone(), START_SECS);
        assert_eq!(
            cache.advisory("GHSA-1", START_SECS + TTL_SECS - 1),
            Some(&advisory)
        );
        assert_eq!(cache.advisory("GHSA-1", START_SECS + TTL_SECS), None);
        assert_eq!(cache.advisory("GHSA-2", START_SECS), None);
    }

    #[test]
    fn zero_ttl_stores_nothing() {
        let mut cache = Cache::new(0);
        cache.put_version_info(Ecosystem::Cargo, "serde", sample_info(), START_SECS);
        cache.put_vulnerabilities(Ecosystem::Cargo, "serde", "1.0.0", Vec::new(), START_SECS);
        cache.put_failure(
            FailureKind::Osv,
            Ecosystem::Cargo,
            "serde",
            "503".to_owned(),
            START_SECS,
        );
        cache.put_advisory(sample_vulnerability("GHSA-1"), START_SECS);
        assert_eq!(
            cache.version_info(Ecosystem::Cargo, "serde", START_SECS),
            None
        );
        assert_eq!(
            cache.vulnerabilities(Ecosystem::Cargo, "serde", "1.0.0", START_SECS),
            None
        );
        assert_eq!(
            cache.failure(FailureKind::Osv, Ecosystem::Cargo, "serde", START_SECS),
            None
        );
        assert_eq!(cache.advisory("GHSA-1", START_SECS), None);
    }

    #[test]
    fn an_advisory_with_an_unchanged_revision_stays_valid_after_the_ttl() {
        let mut cache = Cache::new(TTL_SECS);
        cache.put_advisory(sample_vulnerability("GHSA-1"), START_SECS);
        cache.put_affected("GHSA-1", Vec::new(), START_SECS);
        cache.put_revision("GHSA-1", "2025-01-01T00:00:00.000001Z");
        let later = START_SECS + TTL_SECS + 5;
        assert!(cache.advisory("GHSA-1", later).is_none());
        // The same revision confirms the record and restarts its lifetime.
        assert!(cache.confirm_advisory("GHSA-1", Some("2025-01-01T00:00:00.000001Z"), later));
        assert!(cache.advisory("GHSA-1", later).is_some());
        assert!(cache.affected("GHSA-1", later).is_some());
        assert!(cache.advisory("GHSA-1", later + TTL_SECS - 1).is_some());
    }

    #[test]
    fn a_new_revision_does_not_confirm_the_advisory() {
        let mut cache = Cache::new(TTL_SECS);
        cache.put_advisory(sample_vulnerability("GHSA-1"), START_SECS);
        cache.put_affected("GHSA-1", Vec::new(), START_SECS);
        cache.put_revision("GHSA-1", "2025-01-01T00:00:00.000001Z");
        // Even inside the lifetime, a newer revision means the record is out of date.
        assert!(!cache.confirm_advisory(
            "GHSA-1",
            Some("2025-02-01T00:00:00.000001Z"),
            START_SECS + 1
        ));
    }

    #[test]
    fn without_a_revision_the_ttl_decides() {
        let mut cache = Cache::new(TTL_SECS);
        cache.put_advisory(sample_vulnerability("GHSA-1"), START_SECS);
        cache.put_affected("GHSA-1", Vec::new(), START_SECS);
        assert!(cache.confirm_advisory(
            "GHSA-1",
            Some("2025-01-01T00:00:00.000001Z"),
            START_SECS + 1
        ));
        assert!(cache.confirm_advisory("GHSA-1", None, START_SECS + 1));
        assert!(!cache.confirm_advisory("GHSA-1", None, START_SECS + TTL_SECS));
        // An advisory that was never stored is never confirmed.
        assert!(!cache.confirm_advisory("GHSA-2", None, START_SECS));
    }

    #[test]
    fn a_cache_that_stores_nothing_confirms_nothing() {
        let mut cache = Cache::new(0);
        cache.put_advisory(sample_vulnerability("GHSA-1"), START_SECS);
        cache.put_affected("GHSA-1", Vec::new(), START_SECS);
        cache.put_revision("GHSA-1", "r1");
        assert!(!cache.confirm_advisory("GHSA-1", Some("r1"), START_SECS));
    }
}
