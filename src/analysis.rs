//! Analysis pipeline: turns parsed dependencies into entries with status and advisories.

use crate::cache::{Cache, FailureKind};
use crate::http::{Http, is_cancelled_message, is_success};
use crate::model::{Dependency, Ecosystem, VersionInfo, Vulnerability};
use crate::osv::{
    DEFAULT_DETAILS_PER_QUERY, OsvQuery, is_deferred, is_placeholder, query_batch_limited,
};
use crate::requirement::{checked_version_of, needs_list};
use crate::settings::Settings;
use crate::update::is_outdated;
use openidea_plugin::HttpRequest;
use std::borrow::Cow;
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
    /// Number of entries whose checked version still waits for a registry list. They are pending
    /// too. A chunk that resolves one lowers this count, so the chunk loop knows it made progress.
    pub lists_waiting: usize,
}

impl Analysis {
    /// Number of advisories whose details are not loaded: deferred ones and ones still waiting.
    pub fn unloaded_advisory_count(&self) -> usize {
        self.entries
            .iter()
            .flat_map(|entry| &entry.vulnerabilities)
            .filter(|vulnerability| is_deferred(vulnerability) || is_placeholder(vulnerability))
            .count()
    }
}

/// Limits the work of one run: registry lookups by count and by deadline, and the advisory
/// details that load for each package version.
pub struct Budget {
    lookups_left: usize,
    deadline: Option<Instant>,
    /// Advisories per package version whose details load. The others are deferred.
    details_per_query: usize,
    /// The host cancelled a request of this run, because a newer call supersedes it.
    is_cancelled: bool,
    /// How many package versions that were never queried may go to OSV in one call, at the least.
    /// The share doubles with the answers that the cache holds. `None` queries all of them.
    first_osv_slice: Option<usize>,
    /// No request leaves in this run: it only reads what the cache holds.
    is_offline: bool,
}

impl Budget {
    /// Creates a budget for `max_lookups` lookups that ends at `deadline`, when one is set.
    pub fn new(max_lookups: usize, deadline: Option<Instant>) -> Self {
        Self {
            lookups_left: max_lookups,
            deadline,
            details_per_query: DEFAULT_DETAILS_PER_QUERY,
            is_cancelled: false,
            first_osv_slice: None,
            is_offline: false,
        }
    }

    /// Creates a budget for a run that sends no request at all, to show what the cache holds.
    ///
    /// No registry lookup and no OSV query run, so nothing is stored and no failure is recorded.
    /// An entry that needs a request stays [`Status::Pending`].
    pub fn offline() -> Self {
        Self {
            is_offline: true,
            ..Self::new(0, None)
        }
    }

    /// Sends a first slice of the package versions that were never queried to OSV, and leaves the
    /// others pending. A manifest then shows its first dependencies as soon as OSV answers for
    /// them, and a slow package delays only its own slice. The next calls double the slice.
    pub fn with_first_osv_slice(mut self, queries: usize) -> Self {
        self.first_osv_slice = Some(queries);
        self
    }

    /// The slice of never-queried package versions that one call sends to OSV, if it is limited.
    pub(crate) fn first_osv_slice(&self) -> Option<usize> {
        self.first_osv_slice
    }

    /// Records that the host cancelled a request. No lookup starts afterwards.
    pub(crate) fn cancel(&mut self) {
        self.is_cancelled = true;
        self.lookups_left = 0;
    }

    /// Whether the host cancelled a request of this run. Its results are then incomplete.
    pub fn is_cancelled(&self) -> bool {
        self.is_cancelled
    }

    /// Sets how many advisories per package version load their details. `usize::MAX` loads all.
    pub fn with_detail_limit(mut self, details_per_query: usize) -> Self {
        self.details_per_query = details_per_query;
        self
    }

    /// Advisories per package version whose details load in this run.
    pub(crate) fn details_per_query(&self) -> usize {
        self.details_per_query
    }

    /// The instant at which the run must stop starting slow work, when one is set.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
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
            lists_waiting: 0,
        };
    }
    // The ignore list is normalised once per call, so each dependency name is the only per-item work.
    let ignored = settings.ignored_packages(eco);
    let kept: Vec<Dependency> = deps
        .into_iter()
        .filter(|dependency| !ignored.contains(&eco.normalize_package(&dependency.name)))
        .collect();
    // Registry answers of this call, with their full lists. They serve the checked versions and the
    // registry status alike, so a package is requested once even when the cache keeps nothing.
    let mut registry_answers: HashMap<String, Lookup> = HashMap::new();
    // Each checked version is resolved once; the query and the entry both reuse it.
    let resolved_versions = if settings.vulnerabilities {
        resolve_checked_versions(eco, &kept, cache, http, budget, now, &mut registry_answers)
    } else {
        kept.iter()
            .map(|dependency| checked_with_list(eco, dependency, None))
            .collect()
    };
    let lists_waiting = resolved_versions
        .iter()
        .filter(|resolved| matches!(resolved, CheckedVersion::WaitingForList))
        .count();
    // An entry that waits for its list sends nothing to OSV yet.
    let checked_versions: Vec<Option<String>> = resolved_versions
        .iter()
        .map(|resolved| match resolved {
            CheckedVersion::Known(version) => version.clone(),
            CheckedVersion::WaitingForList => None,
        })
        .collect();
    let fresh_osv = if settings.vulnerabilities {
        query_missing_vulnerabilities(eco, &kept, &checked_versions, cache, http, now, budget)
    } else {
        FreshOsv::default()
    };
    let mut entries: Vec<Entry> = {
        let cache_view: &Cache = cache;
        kept.into_iter()
            .zip(resolved_versions)
            .map(|(dependency, resolved)| {
                build_entry(
                    eco, dependency, resolved, cache_view, &fresh_osv, settings, now,
                )
            })
            .collect()
    };
    // An entry that waits for OSV stays pending, and its registry lookup comes with its slice.
    let waiting_for_osv = entries
        .iter()
        .filter(|entry| entry.status == Status::Pending)
        .count();
    let pending = waiting_for_osv
        + if eco.offers_updates() {
            resolve_registry(
                eco,
                &mut entries,
                cache,
                http,
                budget,
                now,
                &mut registry_answers,
            )
        } else {
            0
        };
    Analysis {
        entries,
        pending,
        lists_waiting,
    }
}

/// Whether the cache holds an OSV answer or an OSV failure for one version of `dependency`.
fn is_osv_answered(
    cache: &Cache,
    eco: Ecosystem,
    dependency: &Dependency,
    version: &str,
    now: u64,
) -> bool {
    cache
        .vulnerabilities(eco, &dependency.name, version, now)
        .is_some()
        || cache
            .failure(
                FailureKind::Osv,
                eco,
                &osv_failure_key(&dependency.name, version),
                now,
            )
            .is_some()
}

/// How the checked version of one dependency stands before the OSV query.
enum CheckedVersion {
    /// The version to send to OSV, or `None` when the requirement is not audited.
    Known(Option<String>),
    /// The registry list that names the version is not known yet. The entry stays pending.
    WaitingForList,
}

/// Names the checked version of every dependency, and looks up the registry lists that it needs.
///
/// A dependency whose requirement is not an exact pin needs the registry list of its package. The
/// list comes from the answers of this call, then from the cache. A package that is in neither is
/// looked up here, before its OSV query. The lookups of one call follow the first slice of the
/// budget, as the OSV pairs do, so the first dependencies show at once. A lookup that fails sends
/// the text of the lower bound to OSV, and the registry step reports the failure.
fn resolve_checked_versions(
    eco: Ecosystem,
    deps: &[Dependency],
    cache: &mut Cache,
    http: &dyn Http,
    budget: &mut Budget,
    now: u64,
    answers: &mut HashMap<String, Lookup>,
) -> Vec<CheckedVersion> {
    // The normalized name of each dependency that needs a list, computed once for both passes.
    let names: Vec<Option<Cow<'_, str>>> = deps
        .iter()
        .map(|dependency| {
            needs_list(eco, &dependency.version, dependency.requirement.as_ref())
                .then(|| eco.normalize_package(&dependency.name))
        })
        .collect();
    // Pass 1 makes no request: it settles every dependency that the cache or the call already answers.
    let mut resolved: Vec<Option<CheckedVersion>> = deps
        .iter()
        .zip(&names)
        .map(|(dependency, name)| match name {
            None => Some(checked_with_list(eco, dependency, None)),
            Some(name) => checked_from_known_list(eco, dependency, name, cache, answers, now),
        })
        .collect();
    let answered = deps
        .iter()
        .zip(&resolved)
        .filter(|(dependency, state)| {
            matches!(state, Some(CheckedVersion::Known(Some(version)))
                if is_osv_answered(cache, eco, dependency, version, now))
        })
        .count();
    let list_limit = budget
        .first_osv_slice()
        .map_or(usize::MAX, |slice| slice.max(answered));
    // Pass 2 looks up the lists that are still missing, in manifest order.
    let mut lookups_done = 0;
    for ((dependency, name), state) in deps.iter().zip(&names).zip(resolved.iter_mut()) {
        // A dependency without a name here needs no list, so pass 1 settled it.
        let (None, Some(name)) = (&*state, name) else {
            continue;
        };
        // A name that an earlier dependency of this call looked up answers its duplicates.
        if let Some(known) = checked_from_known_list(eco, dependency, name, cache, answers, now) {
            *state = Some(known);
            continue;
        }
        // An invalid name costs no lookup. The registry step reports it.
        let Some(request) = eco.registry_request(&dependency.name) else {
            *state = Some(checked_with_list(eco, dependency, None));
            continue;
        };
        if lookups_done >= list_limit || !budget.take() {
            *state = Some(CheckedVersion::WaitingForList);
            continue;
        }
        lookups_done += 1;
        let lookup = lookup_registry(eco, request, name, http, cache, now);
        if note_cancellation(&lookup, budget) {
            // The entry stays pending, and no lookup follows.
            *state = Some(CheckedVersion::WaitingForList);
            continue;
        }
        answers.insert(name.to_string(), lookup);
        *state = checked_from_known_list(eco, dependency, name, cache, answers, now);
    }
    resolved
        .into_iter()
        .map(|state| state.unwrap_or(CheckedVersion::WaitingForList))
        .collect()
}

/// The checked version of `dependency` when its registry list is known, or its failure is.
///
/// Returns `None` when the package was not looked up yet. A failed lookup gives the text of the
/// lower bound, because no list names a version.
fn checked_from_known_list(
    eco: Ecosystem,
    dependency: &Dependency,
    name: &str,
    cache: &Cache,
    answers: &HashMap<String, Lookup>,
    now: u64,
) -> Option<CheckedVersion> {
    let list: Option<&[String]> = match answers.get(name) {
        Some(Ok(info)) => Some(info.versions.as_slice()),
        Some(Err(_)) => None,
        None => match cache.version_info(eco, name, now) {
            Some(info) => Some(info.versions.as_slice()),
            None if cache
                .failure(FailureKind::Registry, eco, name, now)
                .is_some() =>
            {
                None
            }
            None => return None,
        },
    };
    Some(checked_with_list(eco, dependency, list))
}

/// The checked version of `dependency` read with `list`, the registry list newest first.
///
/// Without a list, the text of the lower bound is the checked version.
fn checked_with_list(
    eco: Ecosystem,
    dependency: &Dependency,
    list: Option<&[String]>,
) -> CheckedVersion {
    CheckedVersion::Known(checked_version_of(
        eco,
        &dependency.version,
        dependency.requirement.as_ref(),
        list,
    ))
}

/// Registry outcome of one package name: its versions, or the failure reason.
type Lookup = Result<VersionInfo, String>;

/// Sets the registry status of every entry with a checked version. Returns how many stay pending.
///
/// An entry that already is [`Status::Unknown`] (an OSV failure) keeps that status and costs no request.
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
    fresh: &mut HashMap<String, Lookup>,
) -> usize {
    let mut pending_count = 0;
    for entry in entries.iter_mut().filter(|entry| {
        entry.checked_version.is_some()
            && !matches!(entry.status, Status::Unknown(_) | Status::Pending)
    }) {
        let name = eco.normalize_package(&entry.dependency.name);
        let declared = entry.dependency.version.as_str();
        let status = if let Some(info) = cache.version_info(eco, &name, now) {
            status_from_lookup(eco, declared, Ok(info.latest.as_deref()))
        } else if let Some(reason) = cache.failure(FailureKind::Registry, eco, &name, now) {
            status_from_lookup(eco, declared, Err(reason))
        } else if let Some(lookup) = fresh.get(&*name) {
            status_from_lookup(eco, declared, lookup_view(lookup))
        } else {
            // The request is built before the budget is spent, so an invalid name costs no lookup.
            // Its status is not cached, so a later fix of the manifest takes effect at once.
            let Some(request) = eco.registry_request(&entry.dependency.name) else {
                entry.status = Status::Unknown("registry: invalid package name".to_owned());
                continue;
            };
            if budget.take() {
                let lookup = lookup_registry(eco, request, &name, http, cache, now);
                if note_cancellation(&lookup, budget) {
                    // The entry stays pending, and no lookup follows.
                    pending_count += 1;
                    entry.status = Status::Pending;
                    continue;
                }
                let status = status_from_lookup(eco, declared, lookup_view(&lookup));
                fresh.insert(name.into_owned(), lookup);
                status
            } else {
                pending_count += 1;
                Status::Pending
            }
        };
        entry.status = status;
    }
    pending_count
}

/// Whether `lookup` failed because the host cancelled it, which also cancels the budget.
///
/// The host cancels a request when a newer call supersedes this one, so no lookup follows.
fn note_cancellation<T>(lookup: &Result<T, String>, budget: &mut Budget) -> bool {
    let is_cancelled = lookup
        .as_ref()
        .is_err_and(|reason| is_cancelled_message(reason));
    if is_cancelled {
        budget.cancel();
    }
    is_cancelled
}

/// Borrows the parts of a lookup that the status needs.
fn lookup_view(lookup: &Lookup) -> Result<Option<&str>, &str> {
    lookup
        .as_ref()
        .map(|info| info.latest.as_deref())
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

/// Sends `request` to the registry, stores the answer or the failure under `name`, and returns the outcome.
fn lookup_registry(
    eco: Ecosystem,
    request: HttpRequest,
    name: &str,
    http: &dyn Http,
    cache: &mut Cache,
    now: u64,
) -> Lookup {
    match request_version_info(eco, &request, http) {
        Ok(info) => {
            // The call keeps its own copy of the list: the cache may store nothing.
            cache.put_version_info(eco, name, info.clone(), now);
            Ok(info)
        }
        Err(reason) => {
            // A cancelled request is not a registry failure: the newer call asks the registry again.
            if !is_cancelled_message(&reason) {
                cache.put_failure(FailureKind::Registry, eco, name, reason.clone(), now);
            }
            Err(reason)
        }
    }
}

/// Sends the registry `request` and reads the answer. Errors carry the `registry:` prefix.
fn request_version_info(
    eco: Ecosystem,
    request: &HttpRequest,
    http: &dyn Http,
) -> Result<VersionInfo, String> {
    let response = http
        .send(request)
        .map_err(|message| format!("registry: {message}"))?;
    if !is_success(response.status) {
        return Err(format!("registry: HTTP {}", response.status));
    }
    eco.parse_registry(&String::from_utf8_lossy(&response.body))
}

/// Keeps the OSV failure of one queried package version, in this run and in the cache.
fn record_osv_failure(
    fresh: &mut FreshOsv,
    cache: &mut Cache,
    eco: Ecosystem,
    query: &OsvQuery,
    reason: &str,
    now: u64,
) {
    fresh
        .failed
        .entry(query.name.clone())
        .or_default()
        .insert(query.version.clone(), reason.to_owned());
    cache.put_failure(
        FailureKind::Osv,
        eco,
        &osv_failure_key(&query.name, &query.version),
        reason.to_owned(),
        now,
    );
}

/// The failure-cache key of one package version, so a failure of one version leaves the others alone.
fn osv_failure_key(name: &str, version: &str) -> String {
    format!("{name}@{version}")
}

/// Reason stored when an OSV re-query loads no advisory detail.
const DETAILS_NOT_LOADED: &str = "OSV: advisory details not loaded";

/// Counts the placeholders of `list` whose real record is not in the advisory cache.
///
/// A deferred advisory counts only when its position in `list` is inside the window of
/// `details_per_query`: this run would load it, so it still waits.
fn unresolved_count(
    list: &[Vulnerability],
    cache: &Cache,
    now: u64,
    details_per_query: usize,
) -> usize {
    list.iter()
        .enumerate()
        .filter(|(position, vulnerability)| {
            let waits_for_details = is_placeholder(vulnerability)
                || (*position < details_per_query && is_deferred(vulnerability));
            waits_for_details && cache.advisory(&vulnerability.id, now).is_none()
        })
        .count()
}

/// Sends one OSV batch for the checked pairs that have no usable cached answer and no recent failure.
///
/// A cached answer is not usable while it holds a placeholder without a cached advisory (ruling
/// R35): the pair is queried again, and `fetch_missing_details` loads the details within its cap.
/// A query that leaves as many unresolved placeholders as it started with stores a 60 s failure,
/// so the package is not queried again at once. A query that makes progress stores none, so the
/// next chunk continues at once. Stores each answer, or the failure reason for every queried package,
/// in the cache and in the returned [`FreshOsv`].
fn query_missing_vulnerabilities(
    eco: Ecosystem,
    deps: &[Dependency],
    checked_versions: &[Option<String>],
    cache: &mut Cache,
    http: &dyn Http,
    now: u64,
    budget: &mut Budget,
) -> FreshOsv {
    let mut fresh = FreshOsv::default();
    // A cancelled run is superseded by a newer call, which would throw this answer away.
    if budget.is_offline || budget.is_cancelled() {
        return fresh;
    }
    let details_per_query = budget.details_per_query();
    // How many package versions that OSV never answered for may be sent in this call: the slice
    // of the budget, or as many as the cache already answered, so the slice doubles at each call.
    let new_pair_limit = budget.first_osv_slice().map(|slice| {
        let answered: HashSet<(&str, &str)> = deps
            .iter()
            .zip(checked_versions)
            .filter_map(|(dependency, checked_version)| {
                let version = checked_version.as_deref()?;
                is_osv_answered(cache, eco, dependency, version, now)
                    .then_some((dependency.name.as_str(), version))
            })
            .collect();
        slice.max(answered.len())
    });
    let mut new_pairs_taken = 0;
    // Borrowed pairs: duplicates are found without copying the names.
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    let mut queries: Vec<OsvQuery> = Vec::new();
    // Unresolved placeholders of a cached pair before its re-query; `None` for a pair never queried.
    let mut unresolved_before: Vec<Option<usize>> = Vec::new();
    for (dependency, checked_version) in deps.iter().zip(checked_versions) {
        let Some(version) = checked_version.as_deref() else {
            continue;
        };
        let unresolved = match cache.vulnerabilities(eco, &dependency.name, version, now) {
            Some(list) => match unresolved_count(list, cache, now, details_per_query) {
                0 => continue,
                count => Some(count),
            },
            None => None,
        };
        if cache
            .failure(
                FailureKind::Osv,
                eco,
                &osv_failure_key(&dependency.name, version),
                now,
            )
            .is_some()
            || !seen.insert((dependency.name.as_str(), version))
        {
            continue;
        }
        // A pair that OSV never answered for waits for a later call once the slice is full. A
        // pair that is queried again for its details is not limited: the user asked for them.
        if unresolved.is_none()
            && let Some(limit) = new_pair_limit
        {
            if new_pairs_taken >= limit {
                continue;
            }
            new_pairs_taken += 1;
        }
        queries.push(OsvQuery {
            ecosystem: eco,
            name: dependency.name.clone(),
            version: version.to_owned(),
        });
        unresolved_before.push(unresolved);
    }
    if queries.is_empty() {
        return fresh;
    }
    match query_batch_limited(
        http,
        cache,
        &queries,
        now,
        budget.deadline(),
        details_per_query,
    ) {
        Ok(results) => {
            for ((query, before), vulnerabilities) in
                queries.iter().zip(unresolved_before).zip(results)
            {
                let unresolved_after =
                    unresolved_count(&vulnerabilities, cache, now, details_per_query);
                // A pair never queried starts with every advisory unresolved.
                let made_no_progress = unresolved_after > 0
                    && unresolved_after >= before.unwrap_or(vulnerabilities.len());
                fresh
                    .found
                    .entry(query.name.clone())
                    .or_default()
                    .insert(query.version.clone(), vulnerabilities.clone());
                cache.put_vulnerabilities(eco, &query.name, &query.version, vulnerabilities, now);
                if made_no_progress {
                    record_osv_failure(&mut fresh, cache, eco, query, DETAILS_NOT_LOADED, now);
                }
            }
        }
        // A cancelled request is not an OSV failure: the newer call queries OSV again.
        Err(reason) if is_cancelled_message(&reason) => budget.cancel(),
        Err(reason) => {
            for query in &queries {
                record_osv_failure(&mut fresh, cache, eco, query, &reason, now);
            }
        }
    }
    fresh
}

/// What the OSV phase of one `analyze` call learned, kept for that call.
///
/// The cache stores nothing when `cacheTtlSeconds` is zero, so reading the answers back from the
/// cache alone would hide every advisory and every OSV failure. Entries are built from this first.
/// The maps are nested so a lookup borrows the name and the version instead of building a key.
#[derive(Default)]
struct FreshOsv {
    /// Package name, then declared version, to the advisories OSV returned.
    found: HashMap<String, HashMap<String, Vec<Vulnerability>>>,
    /// Package name, then declared version, to the reason its OSV answer is missing or incomplete.
    failed: HashMap<String, HashMap<String, String>>,
}

impl FreshOsv {
    fn vulnerabilities(&self, name: &str, version: &str) -> Option<&[Vulnerability]> {
        self.found.get(name)?.get(version).map(Vec::as_slice)
    }

    fn failure(&self, name: &str, version: &str) -> Option<&str> {
        self.failed.get(name)?.get(version).map(String::as_str)
    }
}

/// Builds the entry of one dependency from cached data.
///
/// Advisories below `minimum_severity` are filtered here, at read time, so a
/// change of the setting applies to answers that are already cached. A placeholder
/// is replaced by its advisory once that is cached. A placeholder and a deferred advisory
/// are never filtered: their severity is unknown, so they must stay visible.
fn build_entry(
    eco: Ecosystem,
    dependency: Dependency,
    resolved: CheckedVersion,
    cache: &Cache,
    fresh: &FreshOsv,
    settings: &Settings,
    now: u64,
) -> Entry {
    let (checked_version, waits_for_list) = match resolved {
        CheckedVersion::Known(version) => (version, false),
        CheckedVersion::WaitingForList => (None, true),
    };
    if !settings.vulnerabilities {
        return Entry {
            dependency,
            status: Status::NotChecked,
            vulnerabilities: Vec::new(),
            checked_version,
        };
    }
    let answer = checked_version.as_deref().and_then(|version| {
        fresh
            .vulnerabilities(&dependency.name, version)
            .or_else(|| cache.vulnerabilities(eco, &dependency.name, version, now))
    });
    let has_answer = answer.is_some();
    let vulnerabilities = answer
        .unwrap_or_default()
        .iter()
        .filter_map(|cached| {
            let current = if is_placeholder(cached) || is_deferred(cached) {
                cache.advisory(&cached.id, now).unwrap_or(cached)
            } else {
                cached
            };
            (is_placeholder(current)
                || is_deferred(current)
                || current.severity >= settings.minimum_severity)
                .then(|| current.clone())
        })
        .collect();
    // An OSV failure belongs to one package version, so an entry without a checked version has none.
    let failure = checked_version.as_deref().and_then(|version| {
        fresh.failure(&dependency.name, version).or_else(|| {
            cache.failure(
                FailureKind::Osv,
                eco,
                &osv_failure_key(&dependency.name, version),
                now,
            )
        })
    });
    // A checked version with neither an answer nor a failure was left for a later call.
    let waits_for_osv = checked_version.is_some() && !has_answer && failure.is_none();
    let status = match failure {
        Some(reason) => Status::Unknown(reason.to_owned()),
        None if waits_for_osv || waits_for_list => Status::Pending,
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
    use crate::model::{AdvisorySeverity, Span};
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
    fn reports_advisories_when_the_cache_stores_nothing() {
        // A cache lifetime of zero keeps nothing between calls, but one call must still show its answers.
        let mut cache = Cache::new(0);
        let http = serde_high_http();
        let analysis = run(&mut cache, &http, &Settings::default(), NOW, MANIFEST);
        let serde = entry(&analysis, "serde");
        assert_eq!(serde.status, Status::NotChecked);
        assert_eq!(serde.vulnerabilities.len(), 1);
        assert_eq!(serde.vulnerabilities[0].id, "GHSA-high-0001");
        assert_eq!(serde.vulnerabilities[0].severity, AdvisorySeverity::High);
        assert!(entry(&analysis, "anyhow").vulnerabilities.is_empty());
        assert_eq!(http.count(BATCH_URL), 1);
    }

    #[test]
    fn reports_an_osv_failure_when_the_cache_stores_nothing() {
        let mut cache = Cache::new(0);
        let http = FakeHttp::new().route("POST", BATCH_URL, 500, "");
        let analysis = run(&mut cache, &http, &Settings::default(), NOW, MANIFEST);
        for name in ["serde", "anyhow", "tokio"] {
            assert_eq!(
                entry(&analysis, name).status,
                Status::Unknown("OSV: HTTP 500".to_owned()),
                "{name}"
            );
        }
    }

    #[test]
    fn minimum_severity_still_filters_when_the_cache_stores_nothing() {
        let mut cache = Cache::new(0);
        let settings = Settings {
            minimum_severity: AdvisorySeverity::Critical,
            ..Settings::default()
        };
        let analysis = run(&mut cache, &serde_high_http(), &settings, NOW, MANIFEST);
        assert!(entry(&analysis, "serde").vulnerabilities.is_empty());
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

    /// Runs `analyze` for `eco` on `text` with `ignore` and no advisory checks, and returns the kept names.
    fn kept_names(eco: Ecosystem, text: &str, ignore: &[&str]) -> Vec<String> {
        let settings = Settings {
            vulnerabilities: false,
            ignore: ignore.iter().map(|name| (*name).to_owned()).collect(),
            ..Settings::default()
        };
        let mut cache = Cache::new(TTL_SECS);
        let analysis = analyze(
            eco,
            eco.parse(text),
            &mut cache,
            &FakeHttp::new(),
            &settings,
            NOW,
            &mut Budget::new(usize::MAX, None),
        );
        analysis
            .entries
            .into_iter()
            .map(|entry| entry.dependency.name)
            .collect()
    }

    #[test]
    fn ignore_entry_matches_a_pypi_name_after_normalisation() {
        let text = "flask-login==0.6.0\nrequests==2.28.0\n";
        assert_eq!(
            kept_names(Ecosystem::PyPI, text, &["Flask_Login"]),
            ["requests"]
        );
    }

    #[test]
    fn ignore_entry_matches_a_packagist_name_case_insensitively() {
        let text = r#"{"require":{"monolog/monolog":"^3.0","psr/log":"^3.0"}}"#;
        assert_eq!(
            kept_names(Ecosystem::Packagist, text, &["Monolog/Monolog"]),
            ["psr/log"]
        );
    }

    #[test]
    fn ignore_entry_that_differs_after_normalisation_keeps_the_dependency() {
        let text = "flask-login==0.6.0\n";
        assert_eq!(
            kept_names(Ecosystem::PyPI, text, &["flask-logins"]),
            ["flask-login"]
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
                lists_waiting: 0,
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

    /// Parses a `Gemfile` text and runs `analyze` for RubyGems.
    fn analyze_gemfile(
        cache: &mut Cache,
        http: &dyn Http,
        text: &str,
        budget: &mut Budget,
    ) -> Analysis {
        analyze(
            Ecosystem::RubyGems,
            parsers::ruby::parse(text),
            cache,
            http,
            &Settings::default(),
            NOW,
            budget,
        )
    }

    #[test]
    fn rubygems_gems_are_checked_from_the_registry_including_development_gems() {
        const GEMFILE: &str = "gem 'rails', '~> 7.0.4'\ngem 'rack', '2.2.4'\ngroup :development do\n  gem 'rspec-rails', '~> 6.0'\nend\n";
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(3))
            .route(
                "GET",
                "https://rubygems.org/api/v1/versions/rails.json",
                200,
                r#"[{"number":"8.1.4.1","prerelease":false},{"number":"7.0.4","prerelease":false}]"#,
            )
            .route(
                "GET",
                "https://rubygems.org/api/v1/versions/rack.json",
                404,
                "",
            )
            .route(
                "GET",
                "https://rubygems.org/api/v1/versions/rspec-rails.json",
                200,
                r#"[{"number":"6.0.4","prerelease":false},{"number":"6.0.3","prerelease":false}]"#,
            );
        let analysis = analyze_gemfile(
            &mut cache,
            &http,
            GEMFILE,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(analysis.pending, 0);
        assert_eq!(
            entry(&analysis, "rails").status,
            Status::Outdated {
                latest: "8.1.4.1".to_owned()
            }
        );
        assert_eq!(
            entry(&analysis, "rack").status,
            Status::Unknown("registry: HTTP 404".to_owned())
        );
        assert_eq!(
            entry(&analysis, "rspec-rails").status,
            Status::Outdated {
                latest: "6.0.4".to_owned()
            }
        );
    }

    #[test]
    fn rubygems_pinned_at_the_latest_release_is_up_to_date() {
        const GEMFILE: &str = "gem 'rails', '8.1.4.1'\n";
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route(
                "GET",
                "https://rubygems.org/api/v1/versions/rails.json",
                200,
                r#"[{"number":"8.1.4.1","prerelease":false}]"#,
            );
        let analysis = analyze_gemfile(
            &mut cache,
            &http,
            GEMFILE,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(entry(&analysis, "rails").status, Status::UpToDate);
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

    /// Builds a PyPI dependency literal. The parser would cut names such as `bad?name` short, so the tests skip it.
    fn pypi_dependency(name: &str, version: &str) -> Dependency {
        let span = Span {
            line: 0,
            line_start: 0,
            line_end: 0,
        };
        Dependency {
            name: name.to_owned(),
            version: version.to_owned(),
            name_span: span,
            version_span: span,
            dev: false,
            optional: false,
            has_additional_version_constraints: false,
            requirement: None,
        }
    }

    #[test]
    fn invalid_package_name_is_unknown_without_registry_request_or_cache_entry() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new().route("POST", BATCH_URL, 200, &batch_body(1));
        let first = analyze(
            Ecosystem::PyPI,
            vec![pypi_dependency("bad?name", "1.0")],
            &mut cache,
            &http,
            &Settings::default(),
            NOW,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(
            entry(&first, "bad?name").status,
            Status::Unknown("registry: invalid package name".to_string())
        );
        assert_eq!(http.count(PYPI_PREFIX), 0);
        assert!(
            cache
                .version_info(Ecosystem::PyPI, "bad?name", NOW)
                .is_none()
        );
        assert!(
            cache
                .failure(FailureKind::Registry, Ecosystem::PyPI, "bad?name", NOW)
                .is_none()
        );

        let second = analyze(
            Ecosystem::PyPI,
            vec![pypi_dependency("bad?name", "1.0")],
            &mut cache,
            &http,
            &Settings::default(),
            NOW,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(entry(&second, "bad?name").status, first.entries[0].status);
        assert_eq!(http.count(PYPI_PREFIX), 0);
    }

    #[test]
    fn invalid_package_name_consumes_no_budget() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(2))
            .route("GET", REQUESTS_URL, 200, REQUESTS_BODY);
        let analysis = analyze(
            Ecosystem::PyPI,
            vec![
                pypi_dependency("bad?name", "1.0"),
                pypi_dependency("requests", "2.28.0"),
            ],
            &mut cache,
            &http,
            &Settings::default(),
            NOW,
            &mut Budget::new(1, None),
        );
        assert_eq!(analysis.pending, 0);
        assert_eq!(
            entry(&analysis, "requests").status,
            Status::Outdated {
                latest: "2.31.0".to_owned()
            }
        );
        assert_eq!(http.count(REQUESTS_URL), 1);
    }

    // OSV failure and advisory placeholders

    const SINGLE_SERDE: &str = "[dependencies]\nserde = \"1.0.0\"\n";
    const CRIT_DETAIL_URL: &str = "https://api.osv.dev/v1/vulns/GHSA-crit";

    /// Settings that keep only advisories of High severity or above.
    fn high_only() -> Settings {
        Settings {
            minimum_severity: AdvisorySeverity::High,
            ..Settings::default()
        }
    }

    /// Answers the batch with one advisory id for the only query.
    fn one_advisory_batch(id: &str) -> String {
        format!(r#"{{"results":[{{"vulns":[{{"id":"{id}"}}]}}]}}"#)
    }

    #[test]
    fn osv_failure_keeps_a_packagist_dependency_unknown_without_registry_request() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new().route("POST", BATCH_URL, 500, "{}").route(
            "GET",
            CURRENT_URL,
            200,
            CURRENT_BODY,
        );
        let analysis = analyze_composer(
            &mut cache,
            &http,
            r#"{"require":{"acme/current":"3.12.1"}}"#,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(
            entry(&analysis, "acme/current").status,
            Status::Unknown("OSV: HTTP 500".to_string())
        );
        assert_eq!(analysis.pending, 0);
        assert_eq!(http.count("https://repo.packagist.org/"), 0);
    }

    #[test]
    fn osv_failure_keeps_a_pypi_dependency_unknown_without_registry_request() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 500, "{}")
            .route("GET", FLASK_URL, 200, FLASK_BODY);
        let analysis = analyze_python(
            &mut cache,
            &http,
            NOW,
            "flask==2.31.0\n",
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(
            entry(&analysis, "flask").status,
            Status::Unknown("OSV: HTTP 500".to_string())
        );
        assert_eq!(analysis.pending, 0);
        assert_eq!(http.count(PYPI_PREFIX), 0);
    }

    #[test]
    fn failed_detail_fetch_keeps_the_placeholder_despite_the_minimum_severity() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &one_advisory_batch("GHSA-crit"))
            .route("GET", CRIT_DETAIL_URL, 503, "");
        let analysis = run(&mut cache, &http, &high_only(), NOW, SINGLE_SERDE);
        let vulnerabilities = &entry(&analysis, "serde").vulnerabilities;
        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(vulnerabilities[0].id, "GHSA-crit");
        assert!(crate::osv::is_placeholder(&vulnerabilities[0]));
    }

    #[test]
    fn placeholder_is_queried_again_after_the_failure_window() {
        let mut cache = Cache::new(TTL_SECS);
        let failing = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &one_advisory_batch("GHSA-crit"))
            .route("GET", CRIT_DETAIL_URL, 503, "");
        run(&mut cache, &failing, &high_only(), NOW, SINGLE_SERDE);
        assert_eq!(failing.count(CRIT_DETAIL_URL), 1);

        let working = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &one_advisory_batch("GHSA-crit"))
            .route(
                "GET",
                CRIT_DETAIL_URL,
                200,
                &detail_body("GHSA-crit", "CRITICAL"),
            );
        let second = run(&mut cache, &working, &high_only(), NOW + 61, SINGLE_SERDE);
        let vulnerabilities = &entry(&second, "serde").vulnerabilities;
        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(vulnerabilities[0].severity, AdvisorySeverity::Critical);
        assert!(!crate::osv::is_placeholder(&vulnerabilities[0]));
        assert_eq!(working.count(CRIT_DETAIL_URL), 1);
        assert_eq!(working.count(BATCH_URL), 1);
        assert_eq!(entry(&second, "serde").status, Status::NotChecked);
    }

    #[test]
    fn placeholder_is_not_queried_again_inside_the_failure_window() {
        let mut cache = Cache::new(TTL_SECS);
        let failing = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &one_advisory_batch("GHSA-crit"))
            .route("GET", CRIT_DETAIL_URL, 503, "");
        run(&mut cache, &failing, &high_only(), NOW, SINGLE_SERDE);

        let working = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &one_advisory_batch("GHSA-crit"))
            .route(
                "GET",
                CRIT_DETAIL_URL,
                200,
                &detail_body("GHSA-crit", "CRITICAL"),
            );
        let second = run(&mut cache, &working, &high_only(), NOW + 5, SINGLE_SERDE);
        assert!(working.requests().is_empty());
        assert_eq!(entry(&second, "serde").vulnerabilities.len(), 1);
    }

    #[test]
    fn more_advisories_than_the_detail_cap_complete_on_the_next_call_without_delay() {
        let ids: Vec<String> = (0..120).map(|index| format!("TEST-{index:03}")).collect();
        let list: Vec<String> = ids.iter().map(|id| format!(r#"{{"id":"{id}"}}"#)).collect();
        let batch = format!(r#"{{"results":[{{"vulns":[{}]}}]}}"#, list.join(","));
        let mut http = FakeHttp::new().route("POST", BATCH_URL, 200, &batch);
        for id in &ids {
            http = http.route(
                "GET",
                &format!("{DETAIL_PREFIX}{id}"),
                200,
                &detail_body(id, "LOW"),
            );
        }
        let mut cache = Cache::new(TTL_SECS);
        let count_placeholders = |analysis: &Analysis| {
            entry(analysis, "serde")
                .vulnerabilities
                .iter()
                .filter(|vulnerability| crate::osv::is_placeholder(vulnerability))
                .count()
        };

        // The run loads every advisory, so the cap of 100 details per run is what limits it.
        let run_unlimited = |cache: &mut Cache| {
            analyze(
                Ecosystem::Cargo,
                parsers::cargo::parse(SINGLE_SERDE),
                cache,
                &http,
                &Settings::default(),
                NOW,
                &mut Budget::new(usize::MAX, None).with_detail_limit(usize::MAX),
            )
        };
        let first = run_unlimited(&mut cache);
        assert_eq!(http.count(DETAIL_PREFIX), 100);
        assert_eq!(count_placeholders(&first), 20);

        let second = run_unlimited(&mut cache);
        assert_eq!(http.count(DETAIL_PREFIX), 120);
        assert_eq!(count_placeholders(&second), 0);
        assert_eq!(entry(&second, "serde").vulnerabilities.len(), 120);
    }

    /// Runs `chunk_count` chunks of two registry lookups each over four gems and returns the pending count after each.
    ///
    /// `clock_step_secs` moves the clock between chunks, like a slow chunk does.
    fn pending_after_each_chunk(
        ttl_secs: u64,
        clock_step_secs: u64,
        chunk_count: usize,
    ) -> Vec<usize> {
        const GEMFILE: &str = "gem 'a', '1.0'\ngem 'b', '1.0'\ngem 'c', '1.0'\ngem 'd', '1.0'\n";
        let mut http = FakeHttp::new().route("POST", BATCH_URL, 200, &batch_body(4));
        for name in ["a", "b", "c", "d"] {
            http = http.route(
                "GET",
                &format!("https://rubygems.org/api/v1/versions/{name}.json"),
                200,
                r#"[{"number":"2.0","prerelease":false}]"#,
            );
        }
        let mut cache = Cache::new(ttl_secs);
        (0..chunk_count)
            .map(|chunk_index| {
                let mut budget = Budget::new(2, None);
                let now = NOW + clock_step_secs * chunk_index as u64;
                let analysis = analyze(
                    Ecosystem::RubyGems,
                    parsers::ruby::parse(GEMFILE),
                    &mut cache,
                    &http,
                    &Settings::default(),
                    now,
                    &mut budget,
                );
                analysis.pending
            })
            .collect()
    }

    #[test]
    fn chunks_that_share_one_clock_reading_resolve_every_gem_with_a_short_ttl() {
        // The plugin reads the clock once per run, so entries of an earlier chunk stay fresh.
        assert_eq!(pending_after_each_chunk(5, 0, 3), [2, 0, 0]);
    }

    #[test]
    fn a_clock_that_passes_the_ttl_between_chunks_makes_no_progress() {
        // This is why the run must not read the clock again per chunk: the first two answers
        // expire, the second chunk refetches them, and the pending count stays the same.
        let pending = pending_after_each_chunk(5, 10, 3);
        assert_eq!(pending[0], pending[1]);
    }

    /// A manifest with one crate whose OSV answer lists `count` advisories, each with a detail route.
    fn http_with_many_advisories(count: usize) -> FakeHttp {
        let ids: Vec<String> = (0..count)
            .map(|number| format!("GHSA-{number:04}"))
            .collect();
        let vulns: Vec<String> = ids.iter().map(|id| format!(r#"{{"id":"{id}"}}"#)).collect();
        let mut http = FakeHttp::new().route(
            "POST",
            BATCH_URL,
            200,
            &format!(r#"{{"results":[{{"vulns":[{}]}}]}}"#, vulns.join(",")),
        );
        for id in &ids {
            http = http.route(
                "GET",
                &format!("{DETAIL_PREFIX}{id}"),
                200,
                &detail_body(id, "HIGH"),
            );
        }
        http
    }

    const OLD_CRATE: &str = "[dependencies]\nold = \"1.0.0\"\n";

    #[test]
    fn only_ten_advisories_load_their_details_and_the_rest_wait_for_a_request() {
        let mut cache = Cache::new(TTL_SECS);
        let http = http_with_many_advisories(15);
        let analysis = run(&mut cache, &http, &Settings::default(), NOW, OLD_CRATE);
        let old = entry(&analysis, "old");
        assert_eq!(old.vulnerabilities.len(), 15);
        let deferred = old
            .vulnerabilities
            .iter()
            .filter(|v| crate::osv::is_deferred(v))
            .count();
        assert_eq!(deferred, 5);
        assert_eq!(http.count(DETAIL_PREFIX), 10);
        // Deferred advisories are not a failure, so the status stays clean.
        assert_eq!(old.status, Status::NotChecked);

        // A second run reads the cache: no new OSV request, and no retry of the deferred ones.
        let again = run(&mut cache, &http, &Settings::default(), NOW + 1, OLD_CRATE);
        assert_eq!(entry(&again, "old").vulnerabilities.len(), 15);
        assert_eq!(http.count(BATCH_URL), 1);
        assert_eq!(http.count(DETAIL_PREFIX), 10);
    }

    /// Answers every OSV batch with one empty result per query and records the batch sizes. Any
    /// other request gets a 404.
    #[derive(Default)]
    struct SliceHttp {
        batch_sizes: std::cell::RefCell<Vec<usize>>,
        registry_requests: std::cell::Cell<usize>,
    }

    impl Http for SliceHttp {
        fn send(
            &self,
            request: &openidea_plugin::HttpRequest,
        ) -> Result<openidea_plugin::HttpResponse, String> {
            let (status, body) = if request.url == BATCH_URL {
                let sent: serde_json::Value =
                    serde_json::from_slice(request.body.as_deref().unwrap_or_default())
                        .map_err(|error| error.to_string())?;
                let size = sent["queries"].as_array().map_or(0, Vec::len);
                self.batch_sizes.borrow_mut().push(size);
                (200, batch_body(size))
            } else {
                self.registry_requests.set(self.registry_requests.get() + 1);
                (404, String::new())
            };
            Ok(openidea_plugin::HttpResponse {
                status,
                headers: Vec::new(),
                body: body.into_bytes(),
            })
        }
    }

    const FIVE_CRATES: &str = "[dependencies]\na = \"1.0.0\"\nb = \"1.0.0\"\nc = \"1.0.0\"\nd = \"1.0.0\"\ne = \"1.0.0\"\n";

    fn analyze_five_crates(cache: &mut Cache, http: &SliceHttp, first_slice: usize) -> Analysis {
        analyze(
            Ecosystem::Cargo,
            parsers::cargo::parse(FIVE_CRATES),
            cache,
            http,
            &Settings::default(),
            NOW,
            &mut Budget::new(usize::MAX, None).with_first_osv_slice(first_slice),
        )
    }

    fn pending_names(analysis: &Analysis) -> Vec<&str> {
        analysis
            .entries
            .iter()
            .filter(|entry| entry.status == Status::Pending)
            .map(|entry| entry.dependency.name.as_str())
            .collect()
    }

    #[test]
    fn a_cold_analysis_queries_only_a_first_slice_and_leaves_the_others_pending() {
        let mut cache = Cache::new(TTL_SECS);
        let http = SliceHttp::default();
        let analysis = analyze_five_crates(&mut cache, &http, 2);
        assert_eq!(*http.batch_sizes.borrow(), [2]);
        assert_eq!(pending_names(&analysis), ["c", "d", "e"]);
        assert_eq!(analysis.pending, 3);
        // The two that were queried are settled.
        assert_eq!(entry(&analysis, "a").status, Status::NotChecked);
        assert_eq!(entry(&analysis, "b").status, Status::NotChecked);
    }

    #[test]
    fn the_slice_doubles_as_the_answers_accumulate() {
        let mut cache = Cache::new(TTL_SECS);
        let http = SliceHttp::default();
        let sizes_after_each_call: Vec<usize> = (0..3)
            .map(|_| analyze_five_crates(&mut cache, &http, 2).pending)
            .collect();
        // 2 answered after the first call, then 2 more (4 answered), then the last one.
        assert_eq!(*http.batch_sizes.borrow(), [2, 2, 1]);
        assert_eq!(sizes_after_each_call, [3, 1, 0]);
    }

    #[test]
    fn without_a_slice_every_dependency_is_queried_at_once() {
        let mut cache = Cache::new(TTL_SECS);
        let http = SliceHttp::default();
        let analysis = analyze(
            Ecosystem::Cargo,
            parsers::cargo::parse(FIVE_CRATES),
            &mut cache,
            &http,
            &Settings::default(),
            NOW,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(*http.batch_sizes.borrow(), [5]);
        assert_eq!(analysis.pending, 0);
    }

    #[test]
    fn a_dependency_that_waits_for_osv_makes_no_registry_request_yet() {
        let mut cache = Cache::new(TTL_SECS);
        let http = SliceHttp::default();
        let manifest = "a==1.0.0\nb==1.0.0\nc==1.0.0\nd==1.0.0\ne==1.0.0\n";
        let analysis = analyze_python(
            &mut cache,
            &http,
            NOW,
            manifest,
            &mut Budget::new(usize::MAX, None).with_first_osv_slice(2),
        );
        // Only the two queried dependencies look up the registry, and they fail with a 404 here.
        assert_eq!(http.registry_requests.get(), 2);
        assert_eq!(pending_names(&analysis), ["c", "d", "e"]);
        assert_eq!(analysis.pending, 3);
    }

    #[test]
    fn a_requery_for_unloaded_details_is_not_sliced() {
        // A cached answer with a deferred advisory is queried again whatever the slice, because the
        // user asked for its details. Only a pair that was never queried waits for its turn.
        let mut cache = Cache::new(TTL_SECS);
        let http = http_with_many_advisories(15);
        let first = analyze(
            Ecosystem::Cargo,
            parsers::cargo::parse(SINGLE_SERDE),
            &mut cache,
            &http,
            &Settings::default(),
            NOW,
            &mut Budget::new(usize::MAX, None).with_first_osv_slice(1),
        );
        assert!(first.unloaded_advisory_count() > 0);
        let second = analyze(
            Ecosystem::Cargo,
            parsers::cargo::parse(SINGLE_SERDE),
            &mut cache,
            &http,
            &Settings::default(),
            NOW,
            &mut Budget::new(usize::MAX, None)
                .with_first_osv_slice(1)
                .with_detail_limit(usize::MAX),
        );
        assert_eq!(second.unloaded_advisory_count(), 0);
    }

    #[test]
    fn a_larger_detail_limit_loads_the_deferred_advisories() {
        let mut cache = Cache::new(TTL_SECS);
        let http = http_with_many_advisories(15);
        run(&mut cache, &http, &Settings::default(), NOW, OLD_CRATE);

        let mut budget = Budget::new(usize::MAX, None).with_detail_limit(usize::MAX);
        let analysis = analyze(
            Ecosystem::Cargo,
            parsers::cargo::parse(OLD_CRATE),
            &mut cache,
            &http,
            &Settings::default(),
            NOW + 1,
            &mut budget,
        );
        let old = entry(&analysis, "old");
        assert!(
            old.vulnerabilities
                .iter()
                .all(|v| !crate::osv::is_deferred(v))
        );
        assert_eq!(old.vulnerabilities.len(), 15);
        assert_eq!(http.count(DETAIL_PREFIX), 15);

        // The complete list is cached, so a default run keeps it.
        let after = run(&mut cache, &http, &Settings::default(), NOW + 2, OLD_CRATE);
        assert!(
            entry(&after, "old")
                .vulnerabilities
                .iter()
                .all(|v| !crate::osv::is_deferred(v))
        );
        assert_eq!(http.count(BATCH_URL), 2);
    }

    #[test]
    fn deferred_advisories_stay_visible_under_a_high_minimum_severity() {
        // Their severity is unknown until they load, so the filter cannot hide them.
        let mut cache = Cache::new(TTL_SECS);
        let http = http_with_many_advisories(15);
        let settings = Settings {
            minimum_severity: AdvisorySeverity::Critical,
            ..Settings::default()
        };
        let analysis = run(&mut cache, &http, &settings, NOW, OLD_CRATE);
        let old = entry(&analysis, "old");
        // The ten loaded advisories are High, so only the five deferred ones remain.
        assert_eq!(old.vulnerabilities.len(), 5);
        assert!(old.vulnerabilities.iter().all(crate::osv::is_deferred));
    }

    #[test]
    fn an_osv_failure_of_one_version_does_not_mark_another_version_of_the_package() {
        let http = FakeHttp::new()
            .route(
                "POST",
                BATCH_URL,
                200,
                r#"{"results":[{"vulns":[{"id":"GHSA-0001"}]},{}]}"#,
            )
            .route("GET", &format!("{DETAIL_PREFIX}GHSA-0001"), 500, "");
        let manifest =
            "[dependencies]\nserde = \"1.0.0\"\n\n[dev-dependencies]\nserde = \"1.0.200\"\n";
        let mut cache = Cache::new(TTL_SECS);
        let analysis = run(&mut cache, &http, &Settings::default(), NOW, manifest);
        let status_of = |version: &str| {
            analysis
                .entries
                .iter()
                .find(|entry| entry.dependency.version == version)
                .map(|entry| entry.status.clone())
                .unwrap_or_else(|| panic!("missing entry {version}"))
        };
        assert_eq!(
            status_of("1.0.0"),
            Status::Unknown(DETAILS_NOT_LOADED.to_owned())
        );
        assert_eq!(status_of("1.0.200"), Status::NotChecked);
    }

    #[test]
    fn a_deferred_advisory_is_replaced_once_its_details_are_cached() {
        let mut cache = Cache::new(TTL_SECS);
        let http = http_with_many_advisories(15);
        run(&mut cache, &http, &Settings::default(), NOW, OLD_CRATE);
        // Another package loads the advisory that sat at position 12.
        cache.put_advisory(
            Vulnerability {
                id: "GHSA-0012".to_owned(),
                severity: AdvisorySeverity::Low,
                summary: "Loaded later".to_owned(),
                url: None,
            },
            NOW,
        );
        let analysis = run(&mut cache, &http, &Settings::default(), NOW + 1, OLD_CRATE);
        let old = entry(&analysis, "old");
        assert_eq!(old.vulnerabilities.len(), 15);
        assert_eq!(
            old.vulnerabilities
                .iter()
                .filter(|v| crate::osv::is_deferred(v))
                .count(),
            4
        );
        assert!(
            old.vulnerabilities
                .iter()
                .any(|v| v.summary == "Loaded later")
        );

        // A loaded advisory below the minimum severity is hidden, like any other.
        let settings = Settings {
            minimum_severity: AdvisorySeverity::Critical,
            ..Settings::default()
        };
        let filtered = run(&mut cache, &http, &settings, NOW + 2, OLD_CRATE);
        assert!(
            !entry(&filtered, "old")
                .vulnerabilities
                .iter()
                .any(|v| v.summary == "Loaded later")
        );
    }

    #[test]
    fn a_limit_between_the_default_and_the_list_length_leaves_no_false_failure() {
        let mut cache = Cache::new(TTL_SECS);
        let http = http_with_many_advisories(30);
        let analyze_with_limit = |cache: &mut Cache, now: u64| {
            analyze(
                Ecosystem::Cargo,
                parsers::cargo::parse(OLD_CRATE),
                cache,
                &http,
                &Settings::default(),
                now,
                &mut Budget::new(usize::MAX, None).with_detail_limit(15),
            )
        };
        let first = analyze_with_limit(&mut cache, NOW);
        assert_eq!(http.count(DETAIL_PREFIX), 15);
        assert_eq!(entry(&first, "old").status, Status::NotChecked);
        // The 15 advisories past the limit are not waiting for this run, so a second run asks for nothing.
        let second = analyze_with_limit(&mut cache, NOW + 1);
        assert_eq!(entry(&second, "old").status, Status::NotChecked);
        assert_eq!(http.count(BATCH_URL), 1);
        assert_eq!(http.count(DETAIL_PREFIX), 15);
    }

    #[test]
    fn a_cancelled_osv_request_is_not_cached_as_a_failure() {
        // The host cancels the call when a newer batch of the same kind arrives. The newer call
        // must still query OSV, so the cancellation leaves no failure behind.
        let mut cache = Cache::new(TTL_SECS);
        let cancelled_http = FakeHttp::new().transport_error("POST", BATCH_URL, "cancelled");
        let mut budget = Budget::new(usize::MAX, None);
        let analysis = analyze(
            Ecosystem::Cargo,
            parsers::cargo::parse(MANIFEST),
            &mut cache,
            &cancelled_http,
            &Settings::default(),
            NOW,
            &mut budget,
        );
        assert!(budget.is_cancelled());
        // The run learned nothing about the dependencies, so they still wait for OSV. A cancelled
        // run is not published, so nobody sees this state.
        assert!(
            analysis
                .entries
                .iter()
                .all(|entry| entry.status == Status::Pending)
        );
        assert!(
            cache
                .failure(
                    FailureKind::Osv,
                    Ecosystem::Cargo,
                    &osv_failure_key("serde", "1.0.0"),
                    NOW
                )
                .is_none()
        );

        // The next call, a moment later, asks OSV again and shows the advisory.
        let next = run(
            &mut cache,
            &serde_high_http(),
            &Settings::default(),
            NOW + 1,
            MANIFEST,
        );
        assert_eq!(entry(&next, "serde").vulnerabilities.len(), 1);
        assert_eq!(entry(&next, "serde").status, Status::NotChecked);
    }

    #[test]
    fn a_cancelled_registry_lookup_stays_pending_and_is_not_cached() {
        const GEMFILE: &str = "gem 'rails', '7.0.4'\n";
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .transport_error(
                "GET",
                "https://rubygems.org/api/v1/versions/rails.json",
                "cancelled",
            );
        let mut budget = Budget::new(usize::MAX, None);
        let analysis = analyze_gemfile(&mut cache, &http, GEMFILE, &mut budget);
        assert!(budget.is_cancelled());
        assert_eq!(entry(&analysis, "rails").status, Status::Pending);
        assert_eq!(analysis.pending, 1);
        assert!(
            cache
                .failure(FailureKind::Registry, Ecosystem::RubyGems, "rails", NOW)
                .is_none()
        );
    }

    #[test]
    fn an_ordinary_transport_error_is_still_cached_as_a_failure() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new().transport_error("POST", BATCH_URL, "timeout");
        let mut budget = Budget::new(usize::MAX, None);
        analyze(
            Ecosystem::Cargo,
            parsers::cargo::parse(MANIFEST),
            &mut cache,
            &http,
            &Settings::default(),
            NOW,
            &mut budget,
        );
        assert!(!budget.is_cancelled());
        assert!(
            cache
                .failure(
                    FailureKind::Osv,
                    Ecosystem::Cargo,
                    &osv_failure_key("serde", "1.0.0"),
                    NOW
                )
                .is_some()
        );
    }

    /// A time far from zero, so that entries can be stored in the past.
    const LATER_SECS: u64 = 30 * 24 * 60 * 60;

    #[test]
    fn an_offline_analysis_sends_no_request_and_records_no_failure() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new();

        let analysis = analyze_python(
            &mut cache,
            &http,
            LATER_SECS,
            "requests==1.0.0\n",
            &mut Budget::offline(),
        );

        assert!(http.requests().is_empty());
        assert_eq!(analysis.entries[0].status, Status::Pending);
        assert_eq!(analysis.pending, 1);
        for kind in [FailureKind::Registry, FailureKind::Osv] {
            for key in ["requests", "requests@1.0.0"] {
                assert!(
                    cache
                        .failure(kind, Ecosystem::PyPI, key, LATER_SECS)
                        .is_none()
                );
            }
        }
    }

    #[test]
    fn an_offline_analysis_of_a_cargo_manifest_sends_nothing() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new();

        let analysis = analyze(
            Ecosystem::Cargo,
            parsers::cargo::parse(MANIFEST),
            &mut cache,
            &http,
            &Settings::default(),
            NOW,
            &mut Budget::offline(),
        );

        assert!(http.requests().is_empty());
        assert_eq!(analysis.pending, 3);
        assert!(
            analysis
                .entries
                .iter()
                .all(|entry| entry.status == Status::Pending)
        );
    }

    /// Caches an old registry answer and an old vulnerability list of `requests 1.0.0`.
    fn cache_with_old_requests(stored_at: u64) -> Cache {
        let mut cache = Cache::new(TTL_SECS);
        cache.put_version_info(
            Ecosystem::PyPI,
            "requests",
            VersionInfo {
                latest: Some("2.0".to_owned()),
                versions: vec!["2.0".to_owned(), "1.0".to_owned()],
            },
            stored_at,
        );
        cache.put_vulnerabilities(
            Ecosystem::PyPI,
            "requests",
            "1.0.0",
            vec![Vulnerability {
                id: "GHSA-stale".to_owned(),
                severity: AdvisorySeverity::High,
                summary: "stale advisory".to_owned(),
                url: None,
            }],
            stored_at,
        );
        cache
    }

    #[test]
    fn a_stale_offline_analysis_builds_entries_from_old_data() {
        use crate::cache::persist::STALE_MAX_AGE_SECS;
        let mut cache = cache_with_old_requests(LATER_SECS - 7200);
        let http = FakeHttp::new();

        // With the normal lifetime, nothing is fresh: the entry waits.
        let fresh = analyze_python(
            &mut cache,
            &http,
            LATER_SECS,
            "requests==1.0.0\n",
            &mut Budget::offline(),
        );
        assert_eq!(fresh.pending, 1);

        let stale = cache.with_stale_reads(STALE_MAX_AGE_SECS, |cache| {
            analyze_python(
                cache,
                &http,
                LATER_SECS,
                "requests==1.0.0\n",
                &mut Budget::offline(),
            )
        });

        assert_eq!(stale.pending, 0);
        let requests = &stale.entries[0];
        assert_eq!(
            requests.status,
            Status::Outdated {
                latest: "2.0".to_owned()
            }
        );
        assert_eq!(requests.vulnerabilities[0].id, "GHSA-stale");
        assert!(http.requests().is_empty());
    }

    #[test]
    fn a_stale_offline_analysis_ignores_data_older_than_the_maximum_age() {
        use crate::cache::persist::STALE_MAX_AGE_SECS;
        let mut cache = cache_with_old_requests(LATER_SECS - STALE_MAX_AGE_SECS - 1);
        let http = FakeHttp::new();

        let stale = cache.with_stale_reads(STALE_MAX_AGE_SECS, |cache| {
            analyze_python(
                cache,
                &http,
                LATER_SECS,
                "requests==1.0.0\n",
                &mut Budget::offline(),
            )
        });

        assert_eq!(stale.pending, 1);
        assert_eq!(stale.entries[0].status, Status::Pending);
    }

    /// A PyPI answer that has the 1.x line up to 1.2.3 and the 2.x line up to 2.34.2.
    const RANGE_BODY: &str = r#"{"info":{"version":"2.34.2"},"releases":{"1.2.3":[{"yanked":false}],"2.0.0":[{"yanked":false}],"2.9.2":[{"yanked":false}],"2.10.0":[{"yanked":false}],"2.34.2":[{"yanked":false}]}}"#;
    const RANGE_TEXT: &str = "requests>1.12,<2.10\n";

    /// The OSV batch bodies that the fake received, in order.
    fn batch_bodies(http: &FakeHttp) -> Vec<String> {
        http.requests()
            .into_iter()
            .zip(http.request_bodies())
            .filter(|((method, url), _)| method == "POST" && url == BATCH_URL)
            .map(|(_, body)| body)
            .collect()
    }

    #[test]
    fn a_range_is_queried_with_the_lowest_allowed_version() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", REQUESTS_URL, 200, RANGE_BODY);
        let analysis = analyze_python(
            &mut cache,
            &http,
            NOW,
            RANGE_TEXT,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(
            entry(&analysis, "requests").checked_version.as_deref(),
            Some("2.0.0")
        );
        let bodies = batch_bodies(&http);
        assert_eq!(bodies.len(), 1);
        assert!(bodies[0].contains("\"2.0.0\""), "{}", bodies[0]);
        assert!(!bodies[0].contains("1.12"), "{}", bodies[0]);
    }

    #[test]
    fn an_exact_pin_is_queried_without_waiting_for_the_registry() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", REQUESTS_URL, 200, RANGE_BODY);
        analyze_python(
            &mut cache,
            &http,
            NOW,
            "requests==2.0.0\n",
            &mut Budget::new(usize::MAX, None),
        );
        let methods: Vec<String> = http
            .requests()
            .into_iter()
            .map(|(method, _)| method)
            .collect();
        assert_eq!(methods, ["POST", "GET"]);
    }

    #[test]
    fn a_registry_failure_queries_the_bound_text_and_keeps_the_failure() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", REQUESTS_URL, 500, "");
        let analysis = analyze_python(
            &mut cache,
            &http,
            NOW,
            RANGE_TEXT,
            &mut Budget::new(usize::MAX, None),
        );
        let requests = entry(&analysis, "requests");
        assert_eq!(requests.checked_version.as_deref(), Some("1.12"));
        assert!(
            matches!(&requests.status, Status::Unknown(reason) if reason.starts_with("registry:")),
            "{:?}",
            requests.status
        );
        assert!(batch_bodies(&http)[0].contains("\"1.12\""));
    }

    #[test]
    fn an_ignored_package_with_a_range_makes_no_request() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new();
        let settings = Settings {
            ignore: vec!["requests".to_owned()],
            ..Settings::default()
        };
        let analysis = analyze(
            Ecosystem::PyPI,
            parsers::python::parse(RANGE_TEXT),
            &mut cache,
            &http,
            &settings,
            NOW,
            &mut Budget::new(usize::MAX, None),
        );
        assert!(analysis.entries.is_empty());
        assert!(http.requests().is_empty());
    }

    #[test]
    fn a_cancelled_registry_lookup_sends_no_osv_batch() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .transport_error("GET", "https://pypi.org/pypi/aaa/json", "cancelled");
        let mut budget = Budget::new(usize::MAX, None);
        let analysis = analyze_python(
            &mut cache,
            &http,
            NOW,
            "aaa>=1.0\nbbb==2.0.0\n",
            &mut budget,
        );
        assert!(budget.is_cancelled());
        // The answer of OSV would be thrown away, so the request is not sent.
        assert!(
            http.requests().iter().all(|(method, _)| method != "POST"),
            "{:?}",
            http.requests()
        );
        assert_eq!(analysis.pending, 2);
        assert!(
            cache
                .failure(FailureKind::Registry, Ecosystem::PyPI, "aaa", NOW)
                .is_none()
        );
    }

    #[test]
    fn a_cancelled_list_lookup_keeps_a_range_waiting_for_its_list() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .transport_error("GET", "https://pypi.org/pypi/aaa/json", "cancelled");
        let mut budget = Budget::new(usize::MAX, None);
        let analysis = analyze_python(&mut cache, &http, NOW, "aaa>=1.0\n", &mut budget);
        assert!(budget.is_cancelled());
        assert_eq!(entry(&analysis, "aaa").status, Status::Pending);
        assert_eq!(entry(&analysis, "aaa").checked_version, None);
    }

    #[test]
    fn a_chunk_with_one_lookup_reports_the_lists_still_waiting() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", PYPI_PREFIX, 200, RANGE_BODY);
        let analysis = analyze_python(
            &mut cache,
            &http,
            NOW,
            "aaa>1.12,<2.10\nbbb==2.0.0\nccc>1.12,<2.10\n",
            &mut Budget::new(1, None).with_first_osv_slice(1),
        );
        assert_eq!(analysis.lists_waiting, 1);
        assert_eq!(analysis.pending, 2);
    }

    #[test]
    fn a_budget_of_one_lookup_resolves_the_missing_list_of_one_package() {
        let run = |budget: &mut Budget| {
            let mut cache = Cache::new(TTL_SECS);
            let http = FakeHttp::new()
                .route("POST", BATCH_URL, 200, &batch_body(1))
                .route("GET", REQUESTS_URL, 200, RANGE_BODY);
            let analysis = analyze_python(&mut cache, &http, NOW, RANGE_TEXT, budget);
            (analysis, http)
        };
        // Without a lookup the range waits for its list: no request leaves, and the entry is pending.
        let (waiting, http) = run(&mut Budget::new(0, None));
        assert_eq!(entry(&waiting, "requests").status, Status::Pending);
        assert_eq!(waiting.lists_waiting, 1);
        assert!(http.requests().is_empty());
        // One lookup reads the list, and OSV is asked about the lowest allowed version.
        let (resolved, http) = run(&mut Budget::new(1, None));
        assert_eq!(resolved.lists_waiting, 0);
        assert_eq!(
            entry(&resolved, "requests").checked_version.as_deref(),
            Some("2.0.0")
        );
        assert!(batch_bodies(&http)[0].contains("\"2.0.0\""));
    }

    #[test]
    fn an_ignored_package_costs_no_lookup_with_a_budget_of_one() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new();
        let settings = Settings {
            ignore: vec!["requests".to_owned()],
            ..Settings::default()
        };
        analyze(
            Ecosystem::PyPI,
            parsers::python::parse(RANGE_TEXT),
            &mut cache,
            &http,
            &settings,
            NOW,
            &mut Budget::new(1, None),
        );
        assert!(http.requests().is_empty());
    }

    #[test]
    fn a_cache_that_stores_nothing_still_gives_the_list() {
        let mut cache = Cache::new(0);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", REQUESTS_URL, 200, RANGE_BODY);
        let analysis = analyze_python(
            &mut cache,
            &http,
            NOW,
            RANGE_TEXT,
            &mut Budget::new(usize::MAX, None),
        );
        assert_eq!(
            entry(&analysis, "requests").checked_version.as_deref(),
            Some("2.0.0")
        );
        assert_eq!(http.count(PYPI_PREFIX), 1);
    }

    #[test]
    fn the_first_slice_limits_the_list_lookups_and_the_pending_count_falls() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", PYPI_PREFIX, 200, RANGE_BODY);
        let text = "a>1.12,<2.10\nb>1.12,<2.10\nc>1.12,<2.10\nd>1.12,<2.10\ne>1.12,<2.10\n";
        let run = |cache: &mut Cache| {
            analyze_python(
                cache,
                &http,
                NOW,
                text,
                &mut Budget::new(20, None).with_first_osv_slice(1),
            )
        };
        let first = run(&mut cache);
        assert_eq!(http.count(PYPI_PREFIX), 1);
        assert_eq!(first.pending, 4);
        let second = run(&mut cache);
        assert_eq!(http.count(PYPI_PREFIX), 2);
        assert_eq!(second.pending, 3);
    }

    #[test]
    fn an_offline_run_uses_a_cached_list_and_leaves_an_unknown_one_pending() {
        let mut cache = Cache::new(TTL_SECS);
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(1))
            .route("GET", REQUESTS_URL, 200, RANGE_BODY);
        let cold = analyze_python(&mut cache, &http, NOW, RANGE_TEXT, &mut Budget::offline());
        assert_eq!(cold.pending, 1);
        assert_eq!(entry(&cold, "requests").checked_version, None);
        assert!(http.requests().is_empty());

        analyze_python(
            &mut cache,
            &http,
            NOW,
            RANGE_TEXT,
            &mut Budget::new(usize::MAX, None),
        );
        let warm = analyze_python(&mut cache, &http, NOW, RANGE_TEXT, &mut Budget::offline());
        assert_eq!(warm.pending, 0);
        assert_eq!(
            entry(&warm, "requests").checked_version.as_deref(),
            Some("2.0.0")
        );
    }
}
