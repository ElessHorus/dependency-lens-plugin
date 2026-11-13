//! Analysis pipeline: turns parsed dependencies into entries with status and advisories.

use crate::cache::{Cache, FailureKind};
use crate::http::Http;
use crate::model::{Dependency, Ecosystem, Vulnerability};
use crate::osv::{OsvQuery, declared_version_for_osv, query_batch};
use crate::settings::Settings;
use std::collections::HashSet;
use std::time::Instant;

/// Result of checking one dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// The registry lookup is still running.
    Pending,
    /// The declared version is the newest release.
    UpToDate,
    /// A newer release exists.
    Outdated {
        /// Newest release reported by the registry.
        latest: String,
    },
    /// The check failed, with the reason.
    Unknown(String),
    /// The check did not run.
    NotChecked,
}

/// One analyzed dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The dependency as declared in the manifest.
    pub dependency: Dependency,
    /// Result of the check.
    pub status: Status,
    /// Advisories that affect the checked version, at or above the minimum severity.
    pub vulnerabilities: Vec<Vulnerability>,
    /// Version that was checked, or `None` when the requirement names no registry version.
    pub checked_version: Option<String>,
}

/// Analysis result for one manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Analysis {
    /// One entry per analyzed dependency, in manifest order.
    pub entries: Vec<Entry>,
    /// Number of entries whose check is still running.
    pub pending: usize,
}

/// Limits the registry lookups of one run, by count and by deadline.
pub struct Budget {
    lookups_left: usize,
    deadline: Option<Instant>,
}

impl Budget {
    /// Creates a budget for `max_lookups` lookups that ends at `deadline`, when one is set.
    pub fn new(max_lookups: usize, deadline: Option<Instant>) -> Self {
        Self {
            lookups_left: max_lookups,
            deadline,
        }
    }

    /// Consumes one registry lookup; false when none is left or the deadline passed.
    pub fn take(&mut self) -> bool {
        // Count first: a spent budget never reads the clock.
        if self.lookups_left == 0 {
            return false;
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return false;
        }
        self.lookups_left -= 1;
        true
    }
}

/// Analyzes the dependencies of one manifest of ecosystem `eco`.
///
/// Queries OSV.dev once for every uncached `(name, version)` pair and stores the
/// answers and failures in `cache`. `_budget` is not used yet: Task 8 starts
/// consuming it for registry lookups.
pub fn analyze(
    eco: Ecosystem,
    deps: Vec<Dependency>,
    cache: &mut Cache,
    http: &dyn Http,
    settings: &Settings,
    now: u64,
    _budget: &mut Budget,
) -> Analysis {
    if !settings.is_enabled(eco) {
        return Analysis {
            entries: Vec::new(),
            pending: 0,
        };
    }
    let ignored: HashSet<&str> = settings.ignore.iter().map(String::as_str).collect();
    let kept: Vec<Dependency> = deps
        .into_iter()
        .filter(|dependency| !ignored.contains(dependency.name.as_str()))
        .collect();
    // Each declared version is parsed once; the query and the entry both reuse it.
    let checked_versions: Vec<Option<String>> = kept
        .iter()
        .map(|dependency| declared_version_for_osv(&dependency.version))
        .collect();
    if settings.vulnerabilities {
        query_missing_vulnerabilities(eco, &kept, &checked_versions, cache, http, now);
    }
    let cache: &Cache = cache;
    let entries = kept
        .into_iter()
        .zip(checked_versions)
        .map(|(dependency, checked_version)| {
            build_entry(eco, dependency, checked_version, cache, settings, now)
        })
        .collect();
    Analysis {
        entries,
        pending: 0,
    }
}

/// Sends one OSV batch for the checked pairs that have neither a cached answer nor a recent failure.
///
/// Stores each answer, or the failure reason for every queried package.
fn query_missing_vulnerabilities(
    eco: Ecosystem,
    deps: &[Dependency],
    checked_versions: &[Option<String>],
    cache: &mut Cache,
    http: &dyn Http,
    now: u64,
) {
    // Borrowed pairs: duplicates are found without copying the names.
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    let mut queries: Vec<OsvQuery> = Vec::new();
    for (dependency, checked_version) in deps.iter().zip(checked_versions) {
        let Some(version) = checked_version.as_deref() else {
            continue;
        };
        if cache
            .vulnerabilities(eco, &dependency.name, version, now)
            .is_some()
            || cache
                .failure(FailureKind::Osv, eco, &dependency.name, now)
                .is_some()
            || !seen.insert((dependency.name.as_str(), version))
        {
            continue;
        }
        queries.push(OsvQuery {
            ecosystem: eco,
            name: dependency.name.clone(),
            version: version.to_owned(),
        });
    }
    if queries.is_empty() {
        return;
    }
    match query_batch(http, cache, &queries, now) {
        Ok(results) => {
            for (query, vulnerabilities) in queries.iter().zip(results) {
                cache.put_vulnerabilities(eco, &query.name, &query.version, vulnerabilities, now);
            }
        }
        Err(reason) => {
            for query in &queries {
                cache.put_failure(FailureKind::Osv, eco, &query.name, reason.clone(), now);
            }
        }
    }
}

/// Builds the entry of one dependency from cached data.
///
/// Advisories below `minimum_severity` are filtered here, at read time, so a
/// change of the setting applies to answers that are already cached.
fn build_entry(
    eco: Ecosystem,
    dependency: Dependency,
    checked_version: Option<String>,
    cache: &Cache,
    settings: &Settings,
    now: u64,
) -> Entry {
    if !settings.vulnerabilities {
        return Entry {
            dependency,
            status: Status::NotChecked,
            vulnerabilities: Vec::new(),
            checked_version,
        };
    }
    let vulnerabilities = checked_version
        .as_deref()
        .and_then(|version| cache.vulnerabilities(eco, &dependency.name, version, now))
        .unwrap_or_default()
        .iter()
        .filter(|vulnerability| vulnerability.severity >= settings.minimum_severity)
        .cloned()
        .collect();
    let status = match cache.failure(FailureKind::Osv, eco, &dependency.name, now) {
        Some(reason) => Status::Unknown(reason.to_owned()),
        None => Status::NotChecked,
    };
    Entry {
        dependency,
        status,
        vulnerabilities,
        checked_version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::FakeHttp;
    use crate::model::AdvisorySeverity;
    use crate::parsers;
    use std::collections::BTreeSet;
    use std::time::Duration;

    const NOW: u64 = 1_000;
    const TTL_SECS: u64 = 3600;
    const BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
    const DETAIL_PREFIX: &str = "https://api.osv.dev/v1/vulns/";
    const MANIFEST: &str =
        "[dependencies]\nserde = \"1.0.0\"\nanyhow = \"1.0.80\"\ntokio = \"1.37.0\"\n";

    /// Builds an OSV detail record with a `database_specific.severity` label.
    fn detail_body(id: &str, severity_label: &str) -> String {
        format!(
            r#"{{"id":"{id}","summary":"Summary of {id}","database_specific":{{"severity":"{severity_label}"}}}}"#
        )
    }

    /// Parses `manifest` and runs `analyze` for Cargo with an unlimited budget.
    fn run(
        cache: &mut Cache,
        http: &dyn Http,
        settings: &Settings,
        now: u64,
        manifest: &str,
    ) -> Analysis {
        let mut budget = Budget::new(usize::MAX, None);
        analyze(
            Ecosystem::Cargo,
            parsers::cargo::parse(manifest),
            cache,
            http,
            settings,
            now,
            &mut budget,
        )
    }

    /// Returns the entry of the dependency named `name`.
    fn entry<'a>(analysis: &'a Analysis, name: &str) -> &'a Entry {
        analysis
            .entries
            .iter()
            .find(|entry| entry.dependency.name == name)
            .unwrap_or_else(|| panic!("missing entry {name}"))
    }

    /// Answers the batch for three queries, where only the first (serde) has one advisory.
    fn serde_high_http() -> FakeHttp {
        FakeHttp::new()
            .route(
                "POST",
                BATCH_URL,
                200,
                r#"{"results":[{"vulns":[{"id":"GHSA-high-0001"}]},{"vulns":[]},{"vulns":[]}]}"#,
            )
            .route(
                "GET",
                &format!("{DETAIL_PREFIX}GHSA-high-0001"),
                200,
                &detail_body("GHSA-high-0001", "HIGH"),
            )
    }

    #[test]
    fn attaches_high_advisory_to_serde_with_one_batch_request() {
        let mut cache = Cache::new(TTL_SECS);
        let http = serde_high_http();
        let analysis = run(&mut cache, &http, &Settings::default(), NOW, MANIFEST);
        assert_eq!(analysis.pending, 0);
        assert_eq!(http.count(BATCH_URL), 1);
        let serde = entry(&analysis, "serde");
        assert_eq!(serde.status, Status::NotChecked);
        assert_eq!(serde.checked_version.as_deref(), Some("1.0.0"));
        assert_eq!(serde.vulnerabilities.len(), 1);
        assert_eq!(serde.vulnerabilities[0].id, "GHSA-high-0001");
        assert_eq!(serde.vulnerabilities[0].severity, AdvisorySeverity::High);
        assert!(entry(&analysis, "anyhow").vulnerabilities.is_empty());
        assert!(entry(&analysis, "tokio").vulnerabilities.is_empty());
    }

    #[test]
    fn keeps_manifest_order() {
        let mut cache = Cache::new(TTL_SECS);
        let analysis = run(
            &mut cache,
            &serde_high_http(),
            &Settings::default(),
            NOW,
            MANIFEST,
        );
        let names: Vec<&str> = analysis
            .entries
            .iter()
            .map(|entry| entry.dependency.name.as_str())
            .collect();
        assert_eq!(names, ["serde", "anyhow", "tokio"]);
    }

    #[test]
    fn second_run_with_same_cache_makes_no_request() {
        let mut cache = Cache::new(TTL_SECS);
        let http = serde_high_http();
        let first = run(&mut cache, &http, &Settings::default(), NOW, MANIFEST);
        let requests_after_first = http.requests().len();
        let second = run(&mut cache, &http, &Settings::default(), NOW, MANIFEST);
        assert_eq!(http.requests().len(), requests_after_first);
        assert_eq!(second, first);
    }

    #[test]
    fn wildcard_version_is_never_queried() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new().route("POST", BATCH_URL, 200, r#"{"results":[{"vulns":[]}]}"#);
        let manifest = "[dependencies]\nserde = \"*\"\nanyhow = \"1.0.80\"\n";
        let analysis = run(&mut cache, &http, &Settings::default(), NOW, manifest);
        let bodies = http.request_bodies();
        assert_eq!(bodies.len(), 1);
        assert!(!bodies[0].contains("\"serde\""));
        assert!(bodies[0].contains("\"anyhow\""));
        let serde = entry(&analysis, "serde");
        assert_eq!(serde.checked_version, None);
        assert!(serde.vulnerabilities.is_empty());
    }

    #[test]
    fn manifest_of_only_wildcards_sends_no_batch() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new();
        let manifest = "[dependencies]\nserde = \"*\"\n";
        run(&mut cache, &http, &Settings::default(), NOW, manifest);
        assert_eq!(http.count(BATCH_URL), 0);
    }

    #[test]
    fn duplicate_name_and_version_is_queried_once() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new().route("POST", BATCH_URL, 200, r#"{"results":[{"vulns":[]}]}"#);
        let manifest = "[dependencies]\nserde = \"1.0.0\"\n[dev-dependencies]\nserde = \"1.0.0\"\n";
        let analysis = run(&mut cache, &http, &Settings::default(), NOW, manifest);
        assert_eq!(analysis.entries.len(), 2);
        let bodies = http.request_bodies();
        assert_eq!(bodies[0].matches("\"name\":\"serde\"").count(), 1);
    }

    #[test]
    fn osv_error_marks_queried_packages_unknown_and_retries_after_60_seconds() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new().route("POST", BATCH_URL, 500, "{}");
        let settings = Settings::default();
        let first = run(&mut cache, &http, &settings, NOW, MANIFEST);
        for name in ["serde", "anyhow", "tokio"] {
            let found = entry(&first, name);
            assert_eq!(found.status, Status::Unknown("OSV: HTTP 500".to_string()));
            assert!(found.vulnerabilities.is_empty());
        }
        assert_eq!(http.count(BATCH_URL), 1);

        // Within 60 seconds the failure is served from the cache.
        let within_window = run(&mut cache, &http, &settings, NOW + 59, MANIFEST);
        assert_eq!(http.count(BATCH_URL), 1);
        assert_eq!(
            entry(&within_window, "serde").status,
            Status::Unknown("OSV: HTTP 500".to_string())
        );

        // After 60 seconds the query runs again.
        let after_window = run(&mut cache, &http, &settings, NOW + 60, MANIFEST);
        assert_eq!(http.count(BATCH_URL), 2);
        assert_eq!(
            entry(&after_window, "serde").status,
            Status::Unknown("OSV: HTTP 500".to_string())
        );
    }

    #[test]
    fn ignored_name_is_removed_and_not_queried() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new().route(
            "POST",
            BATCH_URL,
            200,
            r#"{"results":[{"vulns":[]},{"vulns":[]}]}"#,
        );
        let settings = Settings {
            ignore: vec!["serde".to_owned()],
            ..Settings::default()
        };
        let analysis = run(&mut cache, &http, &settings, NOW, MANIFEST);
        let names: Vec<&str> = analysis
            .entries
            .iter()
            .map(|entry| entry.dependency.name.as_str())
            .collect();
        assert_eq!(names, ["anyhow", "tokio"]);
        assert!(!http.request_bodies()[0].contains("\"serde\""));
    }

    #[test]
    fn minimum_severity_filters_at_read_time_on_cached_answers() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route(
                "POST",
                BATCH_URL,
                200,
                r#"{"results":[{"vulns":[{"id":"GHSA-medium-0001"}]},{"vulns":[{"id":"GHSA-high-0001"}]},{"vulns":[]}]}"#,
            )
            .route(
                "GET",
                &format!("{DETAIL_PREFIX}GHSA-medium-0001"),
                200,
                &detail_body("GHSA-medium-0001", "MEDIUM"),
            )
            .route(
                "GET",
                &format!("{DETAIL_PREFIX}GHSA-high-0001"),
                200,
                &detail_body("GHSA-high-0001", "HIGH"),
            );
        let low = run(&mut cache, &http, &Settings::default(), NOW, MANIFEST);
        assert_eq!(entry(&low, "serde").vulnerabilities.len(), 1);
        assert_eq!(entry(&low, "anyhow").vulnerabilities.len(), 1);

        let high_only = Settings {
            minimum_severity: AdvisorySeverity::High,
            ..Settings::default()
        };
        let high = run(&mut cache, &http, &high_only, NOW, MANIFEST);
        assert!(entry(&high, "serde").vulnerabilities.is_empty());
        assert_eq!(
            entry(&high, "anyhow").vulnerabilities[0].severity,
            AdvisorySeverity::High
        );
        assert_eq!(http.count(BATCH_URL), 1);
    }

    #[test]
    fn disabled_vulnerability_checks_send_no_request() {
        let mut cache = Cache::new(TTL_SECS);
        let http = serde_high_http();
        let settings = Settings {
            vulnerabilities: false,
            ..Settings::default()
        };
        let analysis = run(&mut cache, &http, &settings, NOW, MANIFEST);
        assert!(http.requests().is_empty());
        assert!(analysis.entries.iter().all(|entry| {
            entry.status == Status::NotChecked && entry.vulnerabilities.is_empty()
        }));
    }

    #[test]
    fn disabled_ecosystem_returns_empty_analysis_without_request() {
        let mut cache = Cache::new(TTL_SECS);
        let http = serde_high_http();
        let settings = Settings {
            enabled: BTreeSet::new(),
            ..Settings::default()
        };
        let analysis = run(&mut cache, &http, &settings, NOW, MANIFEST);
        assert_eq!(
            analysis,
            Analysis {
                entries: Vec::new(),
                pending: 0,
            }
        );
        assert!(http.requests().is_empty());
    }

    #[test]
    fn budget_allows_exactly_the_given_number_of_lookups() {
        let mut budget = Budget::new(2, None);
        assert!(budget.take());
        assert!(budget.take());
        assert!(!budget.take());
    }

    #[test]
    fn budget_refuses_lookups_after_a_past_deadline() {
        let past = Instant::now() - Duration::from_secs(1);
        let mut budget = Budget::new(5, Some(past));
        assert!(!budget.take());
    }

    #[test]
    fn budget_allows_lookups_before_a_future_deadline() {
        let future = Instant::now() + Duration::from_secs(3600);
        let mut budget = Budget::new(1, Some(future));
        assert!(budget.take());
        assert!(!budget.take());
    }
}
