//! Analysis pipeline: turns parsed dependencies into entries with status and advisories.

use crate::cache::{Cache, FailureKind};
use crate::http::Http;
use crate::model::{Dependency, Ecosystem, VersionInfo, Vulnerability};
use crate::osv::{OsvQuery, declared_version_for_osv, query_batch};
use crate::settings::Settings;
use crate::update::is_outdated;
use std::collections::{HashMap, HashSet};
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
/// answers and failures in `cache`. For ecosystems that offer updates, looks up
/// the registry for every checked dependency. Each registry lookup takes one unit
/// of `budget`; entries past the budget stay [`Status::Pending`].
pub fn analyze(
    eco: Ecosystem,
    deps: Vec<Dependency>,
    cache: &mut Cache,
    http: &dyn Http,
    settings: &Settings,
    now: u64,
    budget: &mut Budget,
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
    let mut entries: Vec<Entry> = {
        let cache_view: &Cache = cache;
        kept.into_iter()
            .zip(checked_versions)
            .map(|(dependency, checked_version)| {
                build_entry(eco, dependency, checked_version, cache_view, settings, now)
            })
            .collect()
    };
    let pending = if eco.offers_updates() {
        resolve_registry(eco, &mut entries, cache, http, budget, now)
    } else {
        0
    };
    Analysis { entries, pending }
}

/// Registry outcome of one package name: the newest release, or the failure reason.
type Lookup = Result<Option<String>, String>;

/// Sets the registry status of every entry with a checked version. Returns how many stay pending.
///
/// Each entry reads the cache first. A name that is missing from the cache gets one request
/// per call, and the call-local map answers its duplicates even when the cache keeps nothing.
fn resolve_registry(
    eco: Ecosystem,
    entries: &mut [Entry],
    cache: &mut Cache,
    http: &dyn Http,
    budget: &mut Budget,
    now: u64,
) -> usize {
    let mut fresh: HashMap<String, Lookup> = HashMap::new();
    let mut pending_count = 0;
    for entry in entries
        .iter_mut()
        .filter(|entry| entry.checked_version.is_some())
    {
        let name = eco.normalize_package(&entry.dependency.name);
        let declared = entry.dependency.version.as_str();
        let status = if let Some(info) = cache.version_info(eco, &name, now) {
            status_from_lookup(eco, declared, Ok(info.latest.as_deref()))
        } else if let Some(reason) = cache.failure(FailureKind::Registry, eco, &name, now) {
            status_from_lookup(eco, declared, Err(reason))
        } else if let Some(lookup) = fresh.get(&*name) {
            status_from_lookup(eco, declared, lookup_view(lookup))
        } else if budget.take() {
            let lookup = lookup_registry(eco, &entry.dependency.name, &name, http, cache, now);
            let status = status_from_lookup(eco, declared, lookup_view(&lookup));
            fresh.insert(name.into_owned(), lookup);
            status
        } else {
            pending_count += 1;
            Status::Pending
        };
        entry.status = status;
    }
    pending_count
}

/// Borrows the parts of a lookup that the status needs.
fn lookup_view(lookup: &Lookup) -> Result<Option<&str>, &str> {
    lookup
        .as_ref()
        .map(|latest| latest.as_deref())
        .map_err(String::as_str)
}

/// Builds the registry status of one entry from its lookup outcome.
fn status_from_lookup(
    eco: Ecosystem,
    declared: &str,
    lookup: Result<Option<&str>, &str>,
) -> Status {
    match lookup {
        Err(reason) => Status::Unknown(reason.to_owned()),
        Ok(None) => Status::Unknown("registry: no version found".to_owned()),
        Ok(Some(latest)) if is_outdated(eco, declared, latest) => Status::Outdated {
            latest: latest.to_owned(),
        },
        Ok(Some(_)) => Status::UpToDate,
    }
}

/// Asks the registry for `package`, stores the answer or the failure under `name`, and returns the outcome.
fn lookup_registry(
    eco: Ecosystem,
    package: &str,
    name: &str,
    http: &dyn Http,
    cache: &mut Cache,
    now: u64,
) -> Lookup {
    match request_version_info(eco, package, http) {
        Ok(info) => {
            let latest = info.latest.clone();
            cache.put_version_info(eco, name, info, now);
            Ok(latest)
        }
        Err(reason) => {
            cache.put_failure(FailureKind::Registry, eco, name, reason.clone(), now);
            Err(reason)
        }
    }
}

/// Sends the registry request for `package` and reads the answer. Errors carry the `registry:` prefix.
fn request_version_info(
    eco: Ecosystem,
    package: &str,
    http: &dyn Http,
) -> Result<VersionInfo, String> {
    let Some(request) = eco.registry_request(package) else {
        return Err("registry: no request".to_owned());
    };
    let response = http
        .send(&request)
        .map_err(|message| format!("registry: {message}"))?;
    if !(200..=299).contains(&response.status) {
        return Err(format!("registry: HTTP {}", response.status));
    }
    eco.parse_registry(&String::from_utf8_lossy(&response.body))
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

    const MONOLOG_URL: &str = "https://repo.packagist.org/p2/monolog/monolog.json";
    const CURRENT_URL: &str = "https://repo.packagist.org/p2/acme/current.json";
    const MONOLOG_BODY: &str = r#"{"minified":"composer/2.0","packages":{"monolog/monolog":[{"version":"3.12.1"},{"version":"3.0.0-RC1"}]}}"#;
    const CURRENT_BODY: &str =
        r#"{"minified":"composer/2.0","packages":{"acme/current":[{"version":"3.12.1"}]}}"#;

    /// Parses a `composer.json` text and runs `analyze` for Packagist.
    fn analyze_composer(
        cache: &mut Cache,
        http: &dyn Http,
        text: &str,
        budget: &mut Budget,
    ) -> Analysis {
        analyze(
            Ecosystem::Packagist,
            parsers::php::parse(text),
            cache,
            http,
            &Settings::default(),
            NOW,
            budget,
        )
    }

    #[test]
    fn packagist_requirements_are_outdated_or_up_to_date_from_the_registry() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(2))
            .route("GET", MONOLOG_URL, 200, MONOLOG_BODY)
            .route("GET", CURRENT_URL, 200, CURRENT_BODY);
        let analysis = analyze_composer(
            &mut cache,
            &http,
            r#"{"require":{"monolog/monolog":"^3.0","acme/current":"^3.12.1"}}"#,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(analysis.pending, 0);
        assert_eq!(
            entry(&analysis, "monolog/monolog").status,
            Status::Outdated {
                latest: "3.12.1".to_owned()
            }
        );
        assert_eq!(entry(&analysis, "acme/current").status, Status::UpToDate);
    }

    #[test]
    fn packagist_http_404_is_reported_as_unknown() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", MONOLOG_URL, 404, "");
        let analysis = analyze_composer(
            &mut cache,
            &http,
            r#"{"require":{"monolog/monolog":"^3.0"}}"#,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(
            entry(&analysis, "monolog/monolog").status,
            Status::Unknown("registry: HTTP 404".to_owned())
        );
    }

    #[test]
    fn packagist_names_are_lowercased_and_looked_up_once_per_call() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(2))
            .route("GET", MONOLOG_URL, 200, MONOLOG_BODY);
        let analysis = analyze_composer(
            &mut cache,
            &http,
            r#"{"require":{"Monolog/Monolog":"^3.0","monolog/monolog":"^3.0"}}"#,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(http.count(MONOLOG_URL), 1);
        assert!(matches!(
            entry(&analysis, "Monolog/Monolog").status,
            Status::Outdated { .. }
        ));
        assert!(matches!(
            entry(&analysis, "monolog/monolog").status,
            Status::Outdated { .. }
        ));
    }

    const PUB_HTTP_URL: &str = "https://pub.dev/api/packages/http";
    const PUB_CURRENT_URL: &str = "https://pub.dev/api/packages/current";
    const PUB_INTL_PREFIX: &str = "https://pub.dev/api/packages/intl";
    const PUB_HTTP_BODY: &str = r#"{"name":"http","latest":{"version":"1.2.0"},"versions":[{"version":"1.0.0"},{"version":"1.2.0"}]}"#;
    const PUB_CURRENT_BODY: &str =
        r#"{"name":"current","latest":{"version":"1.2.0"},"versions":[{"version":"1.2.0"}]}"#;

    /// Parses a `pubspec.yaml` text and runs `analyze` for Pub.
    fn analyze_pubspec(
        cache: &mut Cache,
        http: &dyn Http,
        text: &str,
        budget: &mut Budget,
    ) -> Analysis {
        analyze(
            Ecosystem::Pub,
            parsers::dart::parse(text),
            cache,
            http,
            &Settings::default(),
            NOW,
            budget,
        )
    }

    #[test]
    fn pub_requirements_are_outdated_or_up_to_date_from_the_registry() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(2))
            .route("GET", PUB_HTTP_URL, 200, PUB_HTTP_BODY)
            .route("GET", PUB_CURRENT_URL, 200, PUB_CURRENT_BODY);
        let analysis = analyze_pubspec(
            &mut cache,
            &http,
            "dependencies:\n  http: ^1.0.0\n  current: ^1.2.0\n",
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(analysis.pending, 0);
        assert_eq!(
            entry(&analysis, "http").status,
            Status::Outdated {
                latest: "1.2.0".to_owned()
            }
        );
        assert_eq!(entry(&analysis, "current").status, Status::UpToDate);
    }

    #[test]
    fn pub_http_404_is_reported_as_unknown() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", PUB_HTTP_URL, 404, "");
        let analysis = analyze_pubspec(
            &mut cache,
            &http,
            "dependencies:\n  http: ^1.0.0\n",
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(
            entry(&analysis, "http").status,
            Status::Unknown("registry: HTTP 404".to_owned())
        );
    }

    #[test]
    fn pub_any_requirement_is_not_checked_and_makes_no_registry_request() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", PUB_HTTP_URL, 200, PUB_HTTP_BODY);
        let analysis = analyze_pubspec(
            &mut cache,
            &http,
            "dependencies:\n  http: ^1.0.0\n  intl: any\n",
            &mut Budget::new(usize::MAX, None),
        );
        let intl = entry(&analysis, "intl");
        assert_eq!(intl.status, Status::NotChecked);
        assert_eq!(intl.checked_version, None);
        assert_eq!(http.count(PUB_INTL_PREFIX), 0);
    }

    const NUGET_PREFIX: &str = "https://api.nuget.org/v3-flatcontainer/";
    const NEWTONSOFT_URL: &str =
        "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json";
    const SERILOG_URL: &str = "https://api.nuget.org/v3-flatcontainer/serilog/index.json";
    const NEWTONSOFT_BODY: &str = r#"{"versions":["13.0.3","13.0.4"]}"#;
    const SERILOG_BODY: &str = r#"{"versions":["3.1.1"]}"#;

    /// Parses a `.csproj` text and runs `analyze` for NuGet.
    fn analyze_csproj(
        cache: &mut Cache,
        http: &dyn Http,
        text: &str,
        budget: &mut Budget,
    ) -> Analysis {
        analyze(
            Ecosystem::NuGet,
            parsers::csharp::parse(text),
            cache,
            http,
            &Settings::default(),
            NOW,
            budget,
        )
    }

    /// Builds a `.csproj` text with one `PackageReference` per `(name, version)` pair.
    fn csproj_with(references: &[(&str, &str)]) -> String {
        let items: String = references
            .iter()
            .map(|(name, version)| {
                format!(r#"<PackageReference Include="{name}" Version="{version}" />"#)
            })
            .collect();
        format!("<Project><ItemGroup>{items}</ItemGroup></Project>")
    }

    #[test]
    fn nuget_packages_are_outdated_or_up_to_date_from_the_registry() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(2))
            .route("GET", NEWTONSOFT_URL, 200, NEWTONSOFT_BODY)
            .route("GET", SERILOG_URL, 200, SERILOG_BODY);
        let analysis = analyze_csproj(
            &mut cache,
            &http,
            &csproj_with(&[("Newtonsoft.Json", "13.0.3"), ("Serilog", "3.1.1")]),
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(analysis.pending, 0);
        assert_eq!(
            entry(&analysis, "Newtonsoft.Json").status,
            Status::Outdated {
                latest: "13.0.4".to_owned()
            }
        );
        assert_eq!(entry(&analysis, "Serilog").status, Status::UpToDate);
    }

    #[test]
    fn nuget_http_404_is_reported_as_unknown() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", NEWTONSOFT_URL, 404, "");
        let analysis = analyze_csproj(
            &mut cache,
            &http,
            &csproj_with(&[("Newtonsoft.Json", "13.0.3")]),
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(
            entry(&analysis, "Newtonsoft.Json").status,
            Status::Unknown("registry: HTTP 404".to_owned())
        );
    }

    #[test]
    fn nuget_names_are_lowercased_and_looked_up_once_per_call() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(2))
            .route("GET", NEWTONSOFT_URL, 200, NEWTONSOFT_BODY);
        let analysis = analyze_csproj(
            &mut cache,
            &http,
            &csproj_with(&[("Newtonsoft.Json", "13.0.3"), ("newtonsoft.json", "13.0.3")]),
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(http.count(NEWTONSOFT_URL), 1);
        assert!(matches!(
            entry(&analysis, "Newtonsoft.Json").status,
            Status::Outdated { .. }
        ));
        assert!(matches!(
            entry(&analysis, "newtonsoft.json").status,
            Status::Outdated { .. }
        ));
    }

    #[test]
    fn nuget_floating_version_is_not_checked_and_makes_no_registry_request() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", NEWTONSOFT_URL, 200, NEWTONSOFT_BODY);
        let analysis = analyze_csproj(
            &mut cache,
            &http,
            &csproj_with(&[("Floating", "1.*")]),
            &mut Budget::new(usize::MAX, None),
        );
        let floating = entry(&analysis, "Floating");
        assert_eq!(floating.status, Status::NotChecked);
        assert_eq!(floating.checked_version, None);
        assert_eq!(http.count(NUGET_PREFIX), 0);
    }

    const PYPI_PREFIX: &str = "https://pypi.org/pypi/";
    const REQUESTS_URL: &str = "https://pypi.org/pypi/requests/json";
    const FLASK_URL: &str = "https://pypi.org/pypi/flask/json";
    const FLASK_LOGIN_URL: &str = "https://pypi.org/pypi/flask-login/json";
    const REQUESTS_BODY: &str = r#"{"info":{"version":"2.31.0"},"releases":{"2.28.0":[{"yanked":false}],"2.31.0":[{"yanked":false}]}}"#;
    const FLASK_BODY: &str =
        r#"{"info":{"version":"2.31.0"},"releases":{"2.31.0":[{"yanked":false}]}}"#;
    const LOGIN_BODY: &str =
        r#"{"info":{"version":"0.6.0"},"releases":{"0.6.0":[{"yanked":false}]}}"#;
    const PACKAGE_BODY: &str = r#"{"info":{"version":"2.0"},"releases":{"1.0":[{"yanked":false}],"2.0":[{"yanked":false}]}}"#;

    /// Builds an OSV batch answer with `query_count` empty results.
    fn batch_body(query_count: usize) -> String {
        let results = vec!["{}"; query_count].join(",");
        format!(r#"{{"results":[{results}]}}"#)
    }

    /// Parses a requirements text and runs `analyze` for PyPI.
    fn analyze_python(
        cache: &mut Cache,
        http: &dyn Http,
        now: u64,
        text: &str,
        budget: &mut Budget,
    ) -> Analysis {
        analyze(
            Ecosystem::PyPI,
            parsers::python::parse(text),
            cache,
            http,
            &Settings::default(),
            now,
            budget,
        )
    }

    #[test]
    fn pypi_pins_are_outdated_or_up_to_date_from_the_registry() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(2))
            .route("GET", REQUESTS_URL, 200, REQUESTS_BODY)
            .route("GET", FLASK_URL, 200, FLASK_BODY);
        let analysis = analyze_python(
            &mut cache,
            &http,
            NOW,
            "requests==2.28.0\nflask==2.31.0\n",
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(analysis.pending, 0);
        assert_eq!(
            entry(&analysis, "requests").status,
            Status::Outdated {
                latest: "2.31.0".to_owned()
            }
        );
        assert_eq!(entry(&analysis, "flask").status, Status::UpToDate);
    }

    #[test]
    fn registry_http_error_is_cached_for_60_seconds() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", REQUESTS_URL, 404, "");
        let text = "requests==2.28.0\n";
        let first = analyze_python(
            &mut cache,
            &http,
            NOW,
            text,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(
            entry(&first, "requests").status,
            Status::Unknown("registry: HTTP 404".to_owned())
        );

        analyze_python(
            &mut cache,
            &http,
            NOW + 59,
            text,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(http.count(REQUESTS_URL), 1);

        let after = analyze_python(
            &mut cache,
            &http,
            NOW + 60,
            text,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(http.count(REQUESTS_URL), 2);
        assert_eq!(
            entry(&after, "requests").status,
            Status::Unknown("registry: HTTP 404".to_owned())
        );
    }

    #[test]
    fn registry_body_that_is_not_json_is_an_invalid_response() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", REQUESTS_URL, 200, "not json");
        let analysis = analyze_python(
            &mut cache,
            &http,
            NOW,
            "requests==2.28.0\n",
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(
            entry(&analysis, "requests").status,
            Status::Unknown("registry: invalid response".to_owned())
        );
    }

    #[test]
    fn registry_transport_error_is_reported_with_its_message() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .transport_error("GET", REQUESTS_URL, "connection refused");
        let analysis = analyze_python(
            &mut cache,
            &http,
            NOW,
            "requests==2.28.0\n",
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(
            entry(&analysis, "requests").status,
            Status::Unknown("registry: connection refused".to_owned())
        );
    }

    #[test]
    fn package_names_are_normalised_and_looked_up_once_per_call() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(2))
            .route("GET", FLASK_LOGIN_URL, 200, LOGIN_BODY);
        let analysis = analyze_python(
            &mut cache,
            &http,
            NOW,
            "Flask_Login==0.6.0\nflask-login==0.6.0\n",
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(http.count(FLASK_LOGIN_URL), 1);
        assert_eq!(entry(&analysis, "Flask_Login").status, Status::UpToDate);
        assert_eq!(entry(&analysis, "flask-login").status, Status::UpToDate);
    }

    #[test]
    fn duplicate_lookups_stay_once_per_call_even_without_cache_storage() {
        let mut cache = Cache::new(0);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(2))
            .route("GET", FLASK_LOGIN_URL, 200, LOGIN_BODY);
        analyze_python(
            &mut cache,
            &http,
            NOW,
            "Flask_Login==0.6.0\nflask-login==0.6.0\n",
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(http.count(FLASK_LOGIN_URL), 1);
    }

    #[test]
    fn dependency_without_a_checked_version_makes_no_registry_request() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new();
        let analysis = analyze_python(
            &mut cache,
            &http,
            NOW,
            "[tool.poetry.dependencies]\nrequests = \"*\"\n",
            &mut Budget::new(usize::MAX, None),
        );
        assert!(http.requests().is_empty());
        let requests = entry(&analysis, "requests");
        assert_eq!(requests.checked_version, None);
        assert_eq!(requests.status, Status::NotChecked);
    }

    #[test]
    fn budget_caps_registry_lookups_and_leaves_the_rest_pending() {
        let text: String = (0..300).map(|index| format!("pkg{index}==1.0\n")).collect();
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(300))
            .route("GET", PYPI_PREFIX, 200, PACKAGE_BODY);

        let first = analyze_python(&mut cache, &http, NOW, &text, &mut Budget::new(2, None));
        assert_eq!(http.count(PYPI_PREFIX), 2);
        assert_eq!(first.pending, 298);
        let outdated_count = first
            .entries
            .iter()
            .filter(|entry| {
                entry.status
                    == Status::Outdated {
                        latest: "2.0".to_owned(),
                    }
            })
            .count();
        let pending_count = first
            .entries
            .iter()
            .filter(|entry| entry.status == Status::Pending)
            .count();
        assert_eq!(outdated_count, 2);
        assert_eq!(pending_count, 298);
        assert_eq!(http.count(BATCH_URL), 1);

        let second = analyze_python(&mut cache, &http, NOW, &text, &mut Budget::new(2, None));
        assert_eq!(http.count(PYPI_PREFIX), 4);
        assert_eq!(http.count(BATCH_URL), 1);
        assert_eq!(second.pending, 296);
    }

    #[test]
    fn unlimited_budget_completes_every_registry_lookup() {
        let text: String = (0..300).map(|index| format!("pkg{index}==1.0\n")).collect();
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(300))
            .route("GET", PYPI_PREFIX, 200, PACKAGE_BODY);
        let analysis = analyze_python(
            &mut cache,
            &http,
            NOW,
            &text,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(analysis.pending, 0);
        assert_eq!(http.count(PYPI_PREFIX), 300);
    }
}
