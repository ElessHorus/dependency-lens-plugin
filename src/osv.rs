//! OSV.dev client: batch queries for advisory ids, then advisory details, cached in [`Cache`].

use crate::cache::Cache;
use crate::http::{Http, is_success};
use crate::model::{AdvisorySeverity, Affected, Ecosystem, RangeEvent, Vulnerability};
use crate::registries::dotted::is_dev_branch;
use openidea_plugin::{HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// Most advisory details fetched during one call to [`query_batch`].
pub const MAX_DETAIL_FETCHES_PER_RUN: usize = 100;

/// Advisories per queried package version whose details load without a request from the user.
/// The others are deferred (see [`is_deferred`]) and load on demand.
pub const DEFAULT_DETAILS_PER_QUERY: usize = 10;

/// Most queries that OSV accepts in one `querybatch` request.
const MAX_BATCH_QUERIES: usize = 1000;

/// A full query costs one request plus the transfer of every record, which is about as long as
/// one request by id for this many advisories (measured on OSV: 170 ms a request, 4 to 8 ms a record).
/// The query is used when it replaces enough requests by id: at most this many advisories for
/// each request that it saves.
const FULL_QUERY_IDS_PER_SAVED_REQUEST: usize = 25;

/// Most advisories of one package version that a full query reads. A larger answer would hold
/// too much in memory, so such a package is read by id.
const FULL_QUERY_MAX_IDS: usize = 1500;

/// Time allowed to a full query, in milliseconds.
const FULL_QUERY_TIMEOUT_MS: u32 = 30_000;

/// Longest advisory id that is used in a URL.
const MAX_ADVISORY_ID_LEN: usize = 64;

const BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
/// Returns the full records of every advisory of one package version in a single request.
const QUERY_URL: &str = "https://api.osv.dev/v1/query";
const DETAIL_URL_PREFIX: &str = "https://api.osv.dev/v1/vulns/";
const ADVISORY_URL_PREFIX: &str = "https://osv.dev/vulnerability/";
/// Summary of the placeholder shown while the details of an advisory are not loaded.
pub const PLACEHOLDER_SUMMARY: &str = "Details not loaded yet";
/// Summary of an advisory whose details are left unloaded until the user asks for them.
pub const DEFERRED_SUMMARY: &str = "Details load on request";
/// Longest advisory summary kept, in characters.
const SUMMARY_MAX_CHARS: usize = 200;
const INVALID_RESPONSE: &str = "OSV: invalid response";

/// Operators that may prefix a version requirement, longest first.
const VERSION_OPERATORS: [&str; 12] = [
    "===", "==", ">=", "<=", "!=", "~=", "~>", "^", "~", ">", "<", "=",
];

/// CVSS v3 base metrics, in the slot order used by [`cvss3_base_score`].
const BASE_METRICS: [&str; 8] = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

/// Weights of the confidentiality, integrity and availability metrics.
const IMPACT_WEIGHTS: [(&str, f64); 3] = [("H", 0.56), ("L", 0.22), ("N", 0.0)];

/// Maps `database_specific.severity` labels (upper case) to severities.
const SEVERITY_LABELS: [(&str, AdvisorySeverity); 5] = [
    ("CRITICAL", AdvisorySeverity::Critical),
    ("HIGH", AdvisorySeverity::High),
    ("MODERATE", AdvisorySeverity::Medium),
    ("MEDIUM", AdvisorySeverity::Medium),
    ("LOW", AdvisorySeverity::Low),
];

/// A package version to check against OSV.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsvQuery {
    /// Registry that holds the package.
    pub ecosystem: Ecosystem,
    /// Package name as the registry knows it.
    pub name: String,
    /// Version to check, as produced by [`declared_version_for_osv`].
    pub version: String,
}

/// Turns a manifest version requirement into a version that OSV can check.
///
/// Returns `None` when the requirement names no registry version, such as `*`,
/// a workspace, file or git source, or an unresolved `${...}` property.
pub fn declared_version_for_osv(spec: &str) -> Option<String> {
    // Only the first alternative of the first comma-separated requirement names one version.
    // A single `|` separates alternatives as well as `||` does.
    let first_requirement = spec.split([',', '|']).next()?.trim();
    // An exclusion or an upper bound names a version that the manifest rules out (ruling R17).
    if first_requirement.starts_with('<') || first_requirement.starts_with("!=") {
        return None;
    }
    let without_operator = VERSION_OPERATORS
        .iter()
        .find_map(|operator| first_requirement.strip_prefix(*operator))
        .unwrap_or(first_requirement)
        .trim_start();
    // A `v` marks a Go-style version only when a digit follows it.
    let without_v = match without_operator.strip_prefix(['v', 'V']) {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
        _ => without_operator,
    };
    // A range such as `>=1.0 <2.0` names its first version only, so the text stops at a space.
    let first_word = without_v.split_whitespace().next()?;
    // Composer stability flags such as `^1.0@dev` follow the version and are cut here.
    let without_flag = first_word
        .split_once('@')
        .map_or(first_word, |(version_part, _)| version_part);
    // Maven ranges keep one bracket per side after the comma cut, e.g. `[1.0` or `2.0)`.
    let without_open = without_flag
        .strip_prefix(['[', '('])
        .unwrap_or(without_flag);
    let version = without_open
        .strip_suffix([']', ')'])
        .unwrap_or(without_open);
    if version.is_empty() || is_dev_branch(version) {
        return None;
    }
    let has_digit = version.bytes().any(|byte| byte.is_ascii_digit());
    // `:` marks URLs and `workspace:`/`file:` sources, `$` marks unresolved properties.
    // `/` marks a GitHub shorthand such as `user/repo`.
    let names_source = version.contains([':', '$', '/'])
        || version.starts_with("git")
        || version.starts_with("path");
    // `*` and an `x` component mark a wildcard, which names no single version.
    let has_wildcard = version.contains('*')
        || version
            .split('.')
            .any(|component| component == "x" || component == "X");
    (has_digit && !names_source && !has_wildcard).then(|| version.to_owned())
}

/// Returns the CVSS v3.x base score of `vector`, or `None` for other versions or invalid vectors.
///
/// Temporal and environmental metrics are ignored. Metrics may appear in any order.
pub fn cvss3_base_score(vector: &str) -> Option<f64> {
    let mut parts = vector.split('/');
    let (prefix, version) = parts.next()?.split_once(':')?;
    if prefix != "CVSS" || !version.starts_with("3.") {
        return None;
    }
    // Slot per base metric, in `BASE_METRICS` order.
    let mut values: [Option<&str>; BASE_METRICS.len()] = [None; BASE_METRICS.len()];
    for part in parts {
        let (metric, value) = part.split_once(':')?;
        if let Some(index) = BASE_METRICS.iter().position(|name| *name == metric) {
            values[index] = Some(value);
        }
    }
    let [av, ac, pr, ui, scope, c, i, a] = values;
    let changed = match scope? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let attack_vector = metric_weight(av, &[("N", 0.85), ("A", 0.62), ("L", 0.55), ("P", 0.2)])?;
    let attack_complexity = metric_weight(ac, &[("L", 0.77), ("H", 0.44)])?;
    // The privileges weight depends on the scope.
    let privileges_required = if changed {
        metric_weight(pr, &[("N", 0.85), ("L", 0.68), ("H", 0.5)])?
    } else {
        metric_weight(pr, &[("N", 0.85), ("L", 0.62), ("H", 0.27)])?
    };
    let user_interaction = metric_weight(ui, &[("N", 0.85), ("R", 0.62)])?;
    let confidentiality = metric_weight(c, &IMPACT_WEIGHTS)?;
    let integrity = metric_weight(i, &IMPACT_WEIGHTS)?;
    let availability = metric_weight(a, &IMPACT_WEIGHTS)?;

    // Impact sub score (ISS): combined loss of confidentiality, integrity and availability.
    let impact_subscore = 1.0 - (1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability);
    let impact = if changed {
        7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02).powi(15)
    } else {
        6.42 * impact_subscore
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability =
        8.22 * attack_vector * attack_complexity * privileges_required * user_interaction;
    let combined = impact + exploitability;
    // A changed scope multiplies the sum by 1.08 before the cap at 10.
    let capped = if changed {
        (1.08 * combined).min(10.0)
    } else {
        combined.min(10.0)
    };
    Some(roundup(capped))
}

/// Looks up the weight of a metric value. Returns `None` when the metric is missing or unknown.
fn metric_weight(value: Option<&str>, weights: &[(&str, f64)]) -> Option<f64> {
    let value = value?;
    weights
        .iter()
        .find(|(name, _)| *name == value)
        .map(|(_, weight)| *weight)
}

/// Rounds up to one decimal, as CVSS v3.1 `Roundup` does.
///
/// Works on integers in units of 1e-5, so float noise such as 4.0000000001 does not round to 4.1.
fn roundup(value: f64) -> f64 {
    let scaled = (value * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        ((scaled / 10_000 + 1) as f64) / 10.0
    }
}

/// Checks `queries` against OSV and returns the advisories of each query, in input order.
///
/// Advisory ids come from `querybatch`. Their details come from `cache` or from
/// `GET /v1/vulns/{id}`, at most [`MAX_DETAIL_FETCHES_PER_RUN`] per call, and none once
/// `deadline` has passed. Ids beyond that cap or limit, and ids whose detail fetch fails,
/// get a placeholder (see [`is_placeholder`]). The advisory cache never holds a placeholder,
/// but the returned lists do: a caller that stores them must treat a placeholder as unresolved
/// and query again later.
///
/// # Errors
///
/// Returns an error when a `querybatch` request fails or its answer is malformed.
pub fn query_batch(
    http: &dyn Http,
    cache: &mut Cache,
    queries: &[OsvQuery],
    now: u64,
    deadline: Option<Instant>,
) -> Result<Vec<Vec<Vulnerability>>, String> {
    query_batch_limited(http, cache, queries, now, deadline, usize::MAX)
}

/// Like [`query_batch`], but only the first `details_per_query` advisories of each query load
/// their details. The others come back as deferred advisories and cost no request.
///
/// # Errors
///
/// Returns an error when a `querybatch` request fails or its answer is malformed.
pub fn query_batch_limited(
    http: &dyn Http,
    cache: &mut Cache,
    queries: &[OsvQuery],
    now: u64,
    deadline: Option<Instant>,
    details_per_query: usize,
) -> Result<Vec<Vec<Vulnerability>>, String> {
    let mut advisories_per_query: Vec<Vec<AdvisoryRef>> = Vec::with_capacity(queries.len());
    for chunk in queries.chunks(MAX_BATCH_QUERIES) {
        advisories_per_query.extend(query_chunk(http, chunk)?);
    }
    let fetched = fetch_missing_details(
        http,
        cache,
        queries,
        &advisories_per_query,
        now,
        deadline,
        details_per_query,
    );
    let cache: &Cache = cache;
    Ok(advisories_per_query
        .iter()
        .map(|advisories| {
            advisories
                .iter()
                .enumerate()
                .map(|(position, reference)| {
                    let id = &reference.id;
                    let advisory = resolve_advisory(id, &fetched, cache, now);
                    // Past the window, an advisory stays deferred unless its details are known already.
                    if position >= details_per_query && is_placeholder(&advisory) {
                        deferred(id)
                    } else {
                        advisory
                    }
                })
                .collect()
        })
        .collect())
}

/// Sends one `querybatch` request and returns the advisory ids of each query.
fn query_chunk(http: &dyn Http, chunk: &[OsvQuery]) -> Result<Vec<Vec<AdvisoryRef>>, String> {
    // Borrowed fields: the request body is built without copying the queries.
    let body = BatchRequest {
        queries: chunk
            .iter()
            .map(|query| BatchQuery {
                package: BatchPackage {
                    name: &query.name,
                    ecosystem: query.ecosystem.osv_name(),
                },
                version: &query.version,
            })
            .collect(),
    };
    let payload = serde_json::to_vec(&body).map_err(|error| format!("OSV: {error}"))?;
    let request = HttpRequest::post(BATCH_URL, payload).header("Content-Type", "application/json");
    let response = http
        .send(&request)
        .map_err(|message| format!("OSV: {message}"))?;
    ensure_success(&response)?;
    let batch: BatchResponse =
        serde_json::from_slice(&response.body).map_err(|_| INVALID_RESPONSE.to_owned())?;
    // Results align with queries by index, so a count mismatch makes the answer unusable.
    if batch.results.len() != chunk.len() {
        return Err(INVALID_RESPONSE.to_owned());
    }
    Ok(batch
        .results
        .into_iter()
        .map(|result| {
            result
                .vulns
                .unwrap_or_default()
                .into_iter()
                .filter(|vulnerability| is_valid_advisory_id(&vulnerability.id))
                .map(|vulnerability| AdvisoryRef {
                    revision: vulnerability.modified.as_deref().map(revision_key),
                    id: vulnerability.id,
                })
                .collect()
        })
        .collect())
}

/// What the record of one advisory gives: the advisory, its affected ranges and its revision.
struct AdvisoryRecord {
    advisory: Vulnerability,
    affected: Vec<Affected>,
    /// The comparable key of the `modified` time (see [`revision_key`]).
    revision: Option<String>,
}

/// Reads the record of `detail`, which the caller has checked to be valid.
fn record_of(detail: &AdvisoryDetail) -> AdvisoryRecord {
    AdvisoryRecord {
        advisory: advisory_from_detail(&detail.id, detail),
        affected: affected_from_detail(detail).collect(),
        revision: detail.modified.as_deref().map(revision_key),
    }
}

/// Stores a record in `cache` and returns its advisory.
fn store_record(cache: &mut Cache, record: AdvisoryRecord, now: u64) -> Vulnerability {
    let id = record.advisory.id.clone();
    cache.put_advisory(record.advisory.clone(), now);
    cache.put_affected(&id, record.affected, now);
    if let Some(revision) = &record.revision {
        cache.put_revision(&id, revision);
    }
    record.advisory
}

/// Returns `true` when a full query is the cheaper way to read `missing` advisories of a package
/// version that has `total` advisories (see [`FULL_QUERY_IDS_PER_SAVED_REQUEST`]).
fn is_full_query_worth_it(missing: usize, total: usize) -> bool {
    missing >= 2
        && total <= FULL_QUERY_MAX_IDS
        && total <= FULL_QUERY_IDS_PER_SAVED_REQUEST * (missing - 1)
}

/// Loads the details of the advisories that the queries matched and that `cache` does not hold.
///
/// Only the first `details_per_query` advisories of each query count. A record that the cache
/// holds with the revision that the batch names is kept, whatever its age. For the others, a
/// package version with enough missing records is read by one full query, which also stores the
/// records beyond the window. The rest are read by id, at most [`MAX_DETAIL_FETCHES_PER_RUN`]
/// of them. No request starts at or after `deadline`.
/// Stores each fetched advisory in `cache` and returns the fetched advisories by id.
fn fetch_missing_details<'a>(
    http: &dyn Http,
    cache: &mut Cache,
    queries: &[OsvQuery],
    advisories_per_query: &'a [Vec<AdvisoryRef>],
    now: u64,
    deadline: Option<Instant>,
    details_per_query: usize,
) -> HashMap<&'a str, Vulnerability> {
    // The caller's deadline bounds the requests: a sequence of them would outlast the host's limit.
    let is_past_deadline = || deadline.is_some_and(|limit| Instant::now() >= limit);
    let mut fetched: HashMap<&'a str, Vulnerability> = HashMap::new();
    // One pass: `seen` drops repeats across queries.
    let mut seen: HashSet<&str> = HashSet::new();
    // The ids that no full query settled, to read one by one.
    let mut by_id: Vec<&'a str> = Vec::new();
    for (query, advisories) in queries.iter().zip(advisories_per_query) {
        let missing: Vec<&'a str> = advisories
            .iter()
            .enumerate()
            .filter(|(_, reference)| {
                !cache.confirm_advisory(&reference.id, reference.revision.as_deref(), now)
            })
            .filter(|(position, reference)| {
                *position < details_per_query && seen.insert(reference.id.as_str())
            })
            .map(|(_, reference)| reference.id.as_str())
            .collect();
        if missing.is_empty() {
            continue;
        }
        // A full query does not use the budget of requests by id: it replaces many of them, and the
        // deadline bounds the time of the run.
        if is_full_query_worth_it(missing.len(), advisories.len()) && !is_past_deadline() {
            let wanted: HashSet<&'a str> = advisories
                .iter()
                .map(|reference| reference.id.as_str())
                .collect();
            for record in fetch_full_query(http, query).into_iter().flatten() {
                // A record that the batch did not name is not stored under a key that nobody asked for.
                if let Some(id) = wanted.get(record.advisory.id.as_str()).copied() {
                    fetched.insert(id, store_record(cache, record, now));
                }
            }
        }
        by_id.extend(missing.into_iter().filter(|id| !fetched.contains_key(id)));
    }
    for id in by_id.into_iter().take(MAX_DETAIL_FETCHES_PER_RUN) {
        if is_past_deadline() {
            break;
        }
        if let Some(record) = fetch_detail(http, id) {
            fetched.insert(id, store_record(cache, record, now));
        }
    }
    fetched
}

/// Fetches and parses one advisory with its affected ranges. Returns `None` on any failure.
fn fetch_detail(http: &dyn Http, id: &str) -> Option<AdvisoryRecord> {
    let url = format!("{DETAIL_URL_PREFIX}{id}");
    let response = http.send(&HttpRequest::get(&url)).ok()?;
    if !is_success(response.status) {
        return None;
    }
    let detail: AdvisoryDetail = serde_json::from_slice(&response.body).ok()?;
    // A record for another id would be cached under the wrong key, so it is rejected.
    (detail.id == id).then(|| record_of(&detail))
}

/// Fetches the full records of every advisory of the package version of `query`.
///
/// Returns `None` when the request or its answer fails. A record that does not parse, or whose
/// id is not valid, is left out. An answer in several pages gives its first page only: the
/// advisories of the other pages are read by id.
fn fetch_full_query(http: &dyn Http, query: &OsvQuery) -> Option<Vec<AdvisoryRecord>> {
    let body = BatchQuery {
        package: BatchPackage {
            name: &query.name,
            ecosystem: query.ecosystem.osv_name(),
        },
        version: &query.version,
    };
    let payload = serde_json::to_vec(&body).ok()?;
    let request = HttpRequest {
        // A package with hundreds of advisories answers with megabytes.
        timeout_ms: Some(FULL_QUERY_TIMEOUT_MS),
        ..HttpRequest::post(QUERY_URL, payload).header("Content-Type", "application/json")
    };
    let response = http.send(&request).ok()?;
    if !is_success(response.status) {
        return None;
    }
    let answer: FullQueryResponse = serde_json::from_slice(&response.body).ok()?;
    Some(
        answer
            .vulns
            .into_iter()
            .flatten()
            .filter_map(|raw| serde_json::from_str::<AdvisoryDetail>(raw.get()).ok())
            .filter(|detail| is_valid_advisory_id(&detail.id))
            .map(|detail| record_of(&detail))
            .collect(),
    )
}

/// Reads the affected ranges of an advisory.
///
/// An entry that is malformed, that has no package name, or whose ecosystem the plugin does not read, is
/// left out, and so is a range of another kind than `SEMVER` or `ECOSYSTEM`. Some advisories list
/// thousands of packages, and only the ones of the nine ecosystems can be a dependency here.
fn affected_from_detail(detail: &AdvisoryDetail) -> impl Iterator<Item = Affected> + '_ {
    detail
        .affected
        .iter()
        .flatten()
        .filter_map(|raw| serde_json::from_str::<AffectedDetail>(raw.get()).ok())
        .filter_map(|entry| {
            let package = entry.package?;
            let (name, ecosystem) = (package.name?, package.ecosystem?);
            if !Ecosystem::ALL
                .iter()
                .any(|known| known.osv_name().eq_ignore_ascii_case(&ecosystem))
            {
                return None;
            }
            let ranges = entry
                .ranges
                .into_iter()
                .flatten()
                .filter(|range| matches!(range.kind.as_deref(), Some("SEMVER" | "ECOSYSTEM")))
                .map(|range| range.events.iter().filter_map(range_event_of).collect())
                .collect();
            let versions = entry
                .versions
                .into_iter()
                .flatten()
                .filter_map(|version| match version {
                    serde_json::Value::String(text) => Some(text),
                    _ => None,
                })
                .collect();
            Some(Affected {
                ecosystem,
                name,
                ranges,
                versions,
            })
        })
}

/// Reads one range event: the one key that an OSV event object holds.
fn range_event_of(event: &RangeEventDetail) -> Option<RangeEvent> {
    event
        .introduced
        .clone()
        .map(RangeEvent::Introduced)
        .or_else(|| event.fixed.clone().map(RangeEvent::Fixed))
        .or_else(|| event.last_affected.clone().map(RangeEvent::LastAffected))
}

/// Returns the advisory for `id` from this run's fetches or from `cache`, else a placeholder.
fn resolve_advisory(
    id: &str,
    fetched: &HashMap<&str, Vulnerability>,
    cache: &Cache,
    now: u64,
) -> Vulnerability {
    fetched
        .get(id)
        .or_else(|| cache.advisory(id, now))
        .cloned()
        .unwrap_or_else(|| placeholder(id))
}

/// Returns the advisory shown when its details are not available yet.
fn placeholder(id: &str) -> Vulnerability {
    Vulnerability {
        id: id.to_owned(),
        severity: AdvisorySeverity::Medium,
        summary: PLACEHOLDER_SUMMARY.to_owned(),
        url: Some(advisory_url(id)),
    }
}

/// Returns the advisory shown for an id whose details wait for a request from the user.
pub fn deferred(id: &str) -> Vulnerability {
    Vulnerability {
        summary: DEFERRED_SUMMARY.to_owned(),
        ..placeholder(id)
    }
}

/// Returns the deferred entry that stands for an advisory whose id is not known.
///
/// The disk cache keeps the ids of the first advisories of a list and only the count of the
/// others. This entry fills the rest of the list: it has no id and no link, so nothing can name it.
pub fn anonymous_deferred() -> Vulnerability {
    Vulnerability {
        id: String::new(),
        severity: AdvisorySeverity::Medium,
        summary: DEFERRED_SUMMARY.to_owned(),
        url: None,
    }
}

/// Returns `true` when `vulnerability` is a deferred advisory: its details load on request.
pub fn is_deferred(vulnerability: &Vulnerability) -> bool {
    vulnerability.summary == DEFERRED_SUMMARY
}

/// Returns `true` when `vulnerability` is the placeholder of an advisory whose details are not loaded.
pub fn is_placeholder(vulnerability: &Vulnerability) -> bool {
    vulnerability.summary == PLACEHOLDER_SUMMARY
}

/// Returns the OSV page of the advisory `id`.
pub fn advisory_url(id: &str) -> String {
    format!("{ADVISORY_URL_PREFIX}{id}")
}

fn ensure_success(response: &HttpResponse) -> Result<(), String> {
    if is_success(response.status) {
        Ok(())
    } else {
        Err(format!("OSV: HTTP {}", response.status))
    }
}

/// Returns the key that compares two spellings of the `modified` time of an advisory.
///
/// `querybatch` cuts the time at the microsecond, while a full record keeps the nanoseconds.
/// The key keeps at most six digits of the fraction.
fn revision_key(modified: &str) -> String {
    let Some((seconds, after_point)) = modified.split_once('.') else {
        return modified.to_owned();
    };
    let digits = after_point
        .bytes()
        .take_while(u8::is_ascii_digit)
        .count()
        .min(6);
    let rest = after_point.trim_start_matches(|c: char| c.is_ascii_digit());
    format!("{seconds}.{}{rest}", &after_point[..digits])
}

/// Returns `true` when `id` matches `[A-Za-z0-9-]{1,64}`.
///
/// Checks bytes: only ASCII passes, so the byte length is the character count.
pub(crate) fn is_valid_advisory_id(id: &str) -> bool {
    (1..=MAX_ADVISORY_ID_LEN).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Builds the advisory of a parsed detail record, keyed by the requested `id`.
fn advisory_from_detail(id: &str, detail: &AdvisoryDetail) -> Vulnerability {
    Vulnerability {
        id: id.to_owned(),
        severity: severity_of(detail),
        summary: summary_of(id, detail),
        url: Some(advisory_url(id)),
    }
}

/// Returns the summary: the OSV summary, else the first details line, else the id.
fn summary_of(id: &str, detail: &AdvisoryDetail) -> String {
    let first_details_line = detail
        .details
        .as_deref()
        .and_then(|details| details.lines().next());
    [detail.summary.as_deref(), first_details_line]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|text| !text.is_empty())
        .map_or_else(
            || id.to_owned(),
            |text| truncate_chars(text, SUMMARY_MAX_CHARS).to_owned(),
        )
}

/// Cuts `text` after `max_chars` characters, always on a char boundary.
fn truncate_chars(text: &str, max_chars: usize) -> &str {
    match text.char_indices().nth(max_chars) {
        Some((byte_index, _)) => &text[..byte_index],
        None => text,
    }
}

/// Returns the severity of an advisory (ruling R9).
///
/// Order: `database_specific.severity`, then the CVSS v3 base score of the first
/// `CVSS:3.` vector, then the first numeric score. Otherwise Medium.
fn severity_of(detail: &AdvisoryDetail) -> AdvisorySeverity {
    let entries: &[SeverityEntry] = detail.severity.as_deref().unwrap_or_default();
    let database_label = detail
        .database_specific
        .as_ref()
        .and_then(|specific| specific.severity.as_deref());
    if let Some(severity) = database_label.and_then(severity_from_label) {
        return severity;
    }
    // A CVSS vector that does not score falls through to the numeric scores.
    let cvss_score = entries
        .iter()
        .find(|entry| entry.score.starts_with("CVSS:3."))
        .and_then(|entry| cvss3_base_score(&entry.score));
    let numeric_score = || {
        entries.iter().find_map(|entry| {
            entry
                .score
                .parse::<f64>()
                .ok()
                .filter(|score| score.is_finite())
        })
    };
    match cvss_score.or_else(numeric_score) {
        Some(score) => severity_from_score(score),
        None => AdvisorySeverity::Medium,
    }
}

/// Maps a `database_specific.severity` label to a severity, ignoring case.
fn severity_from_label(label: &str) -> Option<AdvisorySeverity> {
    SEVERITY_LABELS
        .iter()
        .find(|(name, _)| label.eq_ignore_ascii_case(name))
        .map(|(_, severity)| *severity)
}

/// Maps a CVSS or numeric score to a severity band.
fn severity_from_score(score: f64) -> AdvisorySeverity {
    if score >= 9.0 {
        AdvisorySeverity::Critical
    } else if score >= 7.0 {
        AdvisorySeverity::High
    } else if score >= 4.0 {
        AdvisorySeverity::Medium
    } else {
        AdvisorySeverity::Low
    }
}

/// One advisory record from `GET /v1/vulns/{id}`. Unknown fields are ignored.
#[derive(Debug, Deserialize)]
struct AdvisoryDetail {
    id: String,
    /// The revision of the record, with its nanoseconds.
    modified: Option<String>,
    summary: Option<String>,
    details: Option<String>,
    severity: Option<Vec<SeverityEntry>>,
    database_specific: Option<DatabaseSpecific>,
    /// Read entry by entry, so a malformed entry never hides the advisory itself. Each entry stays
    /// raw text until it is read, because an advisory can list thousands of packages and versions.
    affected: Option<Vec<Box<serde_json::value::RawValue>>>,
}

/// One `affected[]` entry of an advisory record.
#[derive(Debug, Deserialize)]
struct AffectedDetail {
    package: Option<PackageDetail>,
    ranges: Option<Vec<RangeDetail>>,
    /// Kept as raw values: an item that is not a string is skipped, and the entry stays.
    versions: Option<Vec<serde_json::Value>>,
}

/// The `package` of an `affected[]` entry.
#[derive(Debug, Deserialize)]
struct PackageDetail {
    name: Option<String>,
    ecosystem: Option<String>,
}

/// One `ranges[]` entry: its kind and its events.
#[derive(Debug, Deserialize)]
struct RangeDetail {
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    events: Vec<RangeEventDetail>,
}

/// One event of a range. Each object holds a single one of these keys.
#[derive(Debug, Deserialize)]
struct RangeEventDetail {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

/// One `severity[]` entry: a CVSS vector or a plain numeric score.
#[derive(Debug, Deserialize)]
struct SeverityEntry {
    score: String,
}

/// The `database_specific` block of an advisory record.
#[derive(Debug, Deserialize)]
struct DatabaseSpecific {
    severity: Option<String>,
}

/// Body of a `querybatch` request. Borrows the query fields to avoid copies.
#[derive(Serialize)]
struct BatchRequest<'a> {
    queries: Vec<BatchQuery<'a>>,
}

#[derive(Serialize)]
struct BatchQuery<'a> {
    package: BatchPackage<'a>,
    version: &'a str,
}

#[derive(Serialize)]
struct BatchPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

/// Body of a `querybatch` answer. Each result aligns with one query by index.
#[derive(Debug, Deserialize)]
struct BatchResponse {
    results: Vec<BatchResult>,
}

/// One query result. A result without `vulns` means no advisories.
#[derive(Debug, Deserialize)]
struct BatchResult {
    vulns: Option<Vec<BatchVulnerability>>,
}

#[derive(Debug, Deserialize)]
struct BatchVulnerability {
    id: String,
    /// The revision of the record, cut at the microsecond.
    modified: Option<String>,
}

/// An advisory that a query matched: its id and the revision of its record.
struct AdvisoryRef {
    id: String,
    /// The comparable key of the `modified` time (see [`revision_key`]).
    revision: Option<String>,
}

/// Body of a `POST /v1/query`. Each record is read on its own, so a malformed one costs only itself.
#[derive(Debug, Deserialize)]
struct FullQueryResponse {
    vulns: Option<Vec<Box<serde_json::value::RawValue>>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::FakeHttp;
    use openidea_plugin::HttpResponse;
    use serde_json::{Value, json};
    use std::cell::RefCell;
    use std::time::Duration;

    const NOW: u64 = 1_000;
    const TTL_SECS: u64 = 3600;
    const BATCH_RESPONSE: &str = include_str!("../tests/fixtures/osv/batch_response.json");
    const RUSTSEC_DETAIL: &str = include_str!("../tests/fixtures/osv/vuln_RUSTSEC-2021-0003.json");
    const GHSA_SMALLVEC_DETAIL: &str =
        include_str!("../tests/fixtures/osv/vuln_GHSA-43w2-9j62-hq99.json");
    const GHSA_GO_DETAIL: &str =
        include_str!("../tests/fixtures/osv/vuln_GHSA-5rcv-m4m3-hfh7.json");
    const CVSS_CRITICAL: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    fn query(name: &str, version: &str) -> OsvQuery {
        OsvQuery {
            ecosystem: Ecosystem::Cargo,
            name: name.to_owned(),
            version: version.to_owned(),
        }
    }

    fn detail_url(id: &str) -> String {
        format!("{DETAIL_URL_PREFIX}{id}")
    }

    /// Builds a `querybatch` body with one `results` entry per id list.
    fn batch_body(results: &[&[&str]]) -> String {
        let entries: Vec<Value> = results
            .iter()
            .map(|ids| {
                let vulns: Vec<Value> = ids.iter().map(|id| json!({ "id": id })).collect();
                json!({ "vulns": vulns })
            })
            .collect();
        json!({ "results": entries }).to_string()
    }

    /// Builds a minimal detail record whose summary names its own id.
    fn detail_body(id: &str) -> String {
        json!({ "id": id, "summary": format!("Summary of {id}") }).to_string()
    }

    fn placeholder(id: &str) -> Vulnerability {
        Vulnerability {
            id: id.to_owned(),
            severity: AdvisorySeverity::Medium,
            summary: PLACEHOLDER_SUMMARY.to_owned(),
            url: Some(format!("{ADVISORY_URL_PREFIX}{id}")),
        }
    }

    fn fixture_http() -> FakeHttp {
        FakeHttp::new()
            .route("POST", BATCH_URL, 200, BATCH_RESPONSE)
            .route("GET", &detail_url("RUSTSEC-2021-0003"), 200, RUSTSEC_DETAIL)
            .route(
                "GET",
                &detail_url("GHSA-43w2-9j62-hq99"),
                200,
                GHSA_SMALLVEC_DETAIL,
            )
            .route(
                "GET",
                &detail_url("GHSA-5rcv-m4m3-hfh7"),
                200,
                GHSA_GO_DETAIL,
            )
    }

    fn fixture_queries() -> Vec<OsvQuery> {
        vec![
            query("smallvec", "1.6.0"),
            query("serde", "1.0.0"),
            query("golang.org/x/text", "0.3.0"),
        ]
    }

    /// Answers every `querybatch` with one empty result per query and records the batch sizes.
    #[derive(Default)]
    struct EchoBatchHttp {
        batch_sizes: RefCell<Vec<usize>>,
    }

    impl Http for EchoBatchHttp {
        fn send(&self, request: &HttpRequest) -> Result<HttpResponse, String> {
            let body: Value = serde_json::from_slice(request.body.as_deref().unwrap_or_default())
                .map_err(|error| error.to_string())?;
            let size = body["queries"].as_array().map_or(0, Vec::len);
            self.batch_sizes.borrow_mut().push(size);
            let results = vec![json!({}); size];
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: json!({ "results": results }).to_string().into_bytes(),
            })
        }
    }

    // declared_version_for_osv

    #[test]
    fn strips_operators_and_keeps_partial_versions() {
        assert_eq!(declared_version_for_osv("^1.2").as_deref(), Some("1.2"));
        assert_eq!(declared_version_for_osv("~1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(
            declared_version_for_osv("==1.2.3").as_deref(),
            Some("1.2.3")
        );
        assert_eq!(declared_version_for_osv("v0.9.1").as_deref(), Some("0.9.1"));
        assert_eq!(
            declared_version_for_osv("v2.0.0+incompatible").as_deref(),
            Some("2.0.0+incompatible")
        );
        assert_eq!(declared_version_for_osv("1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(
            declared_version_for_osv(">=2.0, <3").as_deref(),
            Some("2.0")
        );
    }

    #[test]
    fn keeps_caret_tilde_prerelease_and_range_forms() {
        assert_eq!(declared_version_for_osv("^1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(declared_version_for_osv("~0.9.0").as_deref(), Some("0.9.0"));
        assert_eq!(
            declared_version_for_osv("1.2.3-beta.1").as_deref(),
            Some("1.2.3-beta.1")
        );
        assert_eq!(
            declared_version_for_osv(">=1.0.0 <2.0.0").as_deref(),
            Some("1.0.0")
        );
        assert_eq!(
            declared_version_for_osv("^1.0.0 || ^2.0.0").as_deref(),
            Some("1.0.0")
        );
        assert_eq!(
            declared_version_for_osv("1.0.0 - 2.0.0").as_deref(),
            Some("1.0.0")
        );
    }

    #[test]
    fn skips_specs_without_a_single_version() {
        assert_eq!(declared_version_for_osv("user/repo2"), None);
        assert_eq!(declared_version_for_osv("github:user/repo"), None);
        assert_eq!(declared_version_for_osv("1.x"), None);
        assert_eq!(declared_version_for_osv("1.2.X"), None);
        assert_eq!(declared_version_for_osv("1.2.x"), None);
        assert_eq!(declared_version_for_osv("x"), None);
        assert_eq!(declared_version_for_osv("beta"), None);
        assert_eq!(declared_version_for_osv("next"), None);
    }

    #[test]
    fn keeps_first_alternative_and_first_word_of_a_range() {
        assert_eq!(
            declared_version_for_osv("^1.0 || ^2.0").as_deref(),
            Some("1.0")
        );
        assert_eq!(
            declared_version_for_osv(">=1.0 <2.0").as_deref(),
            Some("1.0")
        );
    }

    #[test]
    fn a_single_bar_cuts_the_alternatives() {
        assert_eq!(
            declared_version_for_osv("^1.0|^2.0").as_deref(),
            Some("1.0")
        );
        assert_eq!(
            declared_version_for_osv("^1.0 || ^2.0").as_deref(),
            Some("1.0")
        );
    }

    #[test]
    fn exclusions_and_upper_bounds_name_no_declared_version() {
        assert_eq!(declared_version_for_osv("<2.0.0"), None);
        assert_eq!(declared_version_for_osv("<=1.5"), None);
        assert_eq!(declared_version_for_osv("!=1.0"), None);
        assert_eq!(
            declared_version_for_osv(">=1.0, <2.0").as_deref(),
            Some("1.0")
        );
        assert_eq!(declared_version_for_osv("~1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(declared_version_for_osv("^1.0").as_deref(), Some("1.0"));
        assert_eq!(
            declared_version_for_osv("==1.2.3").as_deref(),
            Some("1.2.3")
        );
        assert_eq!(declared_version_for_osv("v1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(
            declared_version_for_osv("[1.0,2.0)").as_deref(),
            Some("1.0")
        );
    }

    #[test]
    fn nuget_wildcards_properties_and_ranges_follow_the_osv_rules() {
        assert_eq!(declared_version_for_osv("1.*"), None);
        assert_eq!(declared_version_for_osv("$(Missing)"), None);
        assert_eq!(
            declared_version_for_osv("[1.0,2.0)").as_deref(),
            Some("1.0")
        );
    }

    #[test]
    fn rejects_wildcard_versions() {
        assert_eq!(declared_version_for_osv("2.*"), None);
        assert_eq!(declared_version_for_osv("==2.*"), None);
    }

    #[test]
    fn keeps_the_first_bound_of_maven_ranges() {
        assert_eq!(
            declared_version_for_osv("[1.0,2.0)").as_deref(),
            Some("1.0")
        );
        assert_eq!(declared_version_for_osv("[1.5]").as_deref(), Some("1.5"));
        assert_eq!(
            declared_version_for_osv("(1.0,2.0]").as_deref(),
            Some("1.0")
        );
        assert_eq!(declared_version_for_osv("(,1.0]"), None);
    }

    #[test]
    fn skips_maven_keywords_and_keeps_release_suffixes() {
        assert_eq!(declared_version_for_osv("LATEST"), None);
        assert_eq!(declared_version_for_osv("RELEASE"), None);
        assert_eq!(
            declared_version_for_osv("1.2.3.RELEASE").as_deref(),
            Some("1.2.3.RELEASE")
        );
        assert_eq!(declared_version_for_osv("5.9.2").as_deref(), Some("5.9.2"));
    }

    #[test]
    fn rejects_specs_that_name_no_registry_version() {
        for spec in [
            "*",
            "latest",
            "",
            "workspace:*",
            "git+https://x",
            "file:../x",
            "${spring.version}",
        ] {
            assert_eq!(declared_version_for_osv(spec), None, "spec {spec:?}");
        }
    }

    #[test]
    fn composer_stability_flags_and_dev_branches() {
        assert_eq!(declared_version_for_osv("^1.0@dev").as_deref(), Some("1.0"));
        assert_eq!(declared_version_for_osv("dev-main"), None);
        assert_eq!(declared_version_for_osv("dev-main as 1.0.x-dev"), None);
        assert_eq!(declared_version_for_osv("1.0.x-dev"), None);
        assert_eq!(declared_version_for_osv("1.2.*"), None);
        assert_eq!(declared_version_for_osv("~6.2").as_deref(), Some("6.2"));
        assert_eq!(declared_version_for_osv("^3.0").as_deref(), Some("3.0"));
        assert_eq!(
            declared_version_for_osv(">=1.2 <2.0").as_deref(),
            Some("1.2")
        );
        assert_eq!(
            declared_version_for_osv("^1.0 || ^2.0").as_deref(),
            Some("1.0")
        );
        assert_eq!(
            declared_version_for_osv("3.0.0-RC1").as_deref(),
            Some("3.0.0-RC1")
        );
    }

    // cvss3_base_score

    #[test]
    fn cvss3_base_score_matches_reference_vectors() {
        assert_eq!(cvss3_base_score(CVSS_CRITICAL), Some(9.8));
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            Some(10.0)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"),
            Some(7.8)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            Some(5.3)
        );
        // Temporal metrics do not change the base score.
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:O/RC:C"),
            Some(7.5)
        );
        // Metric order does not matter.
        assert_eq!(
            cvss3_base_score("CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N"),
            Some(9.8)
        );
    }

    #[test]
    fn cvss3_base_score_rejects_other_versions_and_incomplete_vectors() {
        assert_eq!(cvss3_base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P"), None);
        assert_eq!(
            cvss3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
            None
        );
        assert_eq!(cvss3_base_score("not a vector"), None);
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"),
            None
        );
    }

    // severity (ruling R9)

    fn severity_of(label: Option<&str>, scores: &[&str]) -> AdvisorySeverity {
        let severity: Vec<Value> = scores
            .iter()
            .map(|score| json!({ "type": "CVSS_V3", "score": score }))
            .collect();
        let detail = json!({
            "id": "GHSA-sev-0001",
            "severity": severity,
            "database_specific": { "severity": label },
        });
        let parsed: AdvisoryDetail = serde_json::from_value(detail).expect("valid detail");
        advisory_from_detail(&parsed.id, &parsed).severity
    }

    #[test]
    fn database_label_wins_over_cvss_and_ignores_case() {
        assert_eq!(
            severity_of(
                Some("CRITICAL"),
                &["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"]
            ),
            AdvisorySeverity::Critical
        );
        assert_eq!(severity_of(Some("high"), &[]), AdvisorySeverity::High);
        assert_eq!(severity_of(Some("MODERATE"), &[]), AdvisorySeverity::Medium);
        assert_eq!(severity_of(Some("Medium"), &[]), AdvisorySeverity::Medium);
        assert_eq!(severity_of(Some("low"), &[]), AdvisorySeverity::Low);
    }

    #[test]
    fn cvss_base_score_maps_to_severity_bands() {
        assert_eq!(
            severity_of(None, &[CVSS_CRITICAL]),
            AdvisorySeverity::Critical
        );
        assert_eq!(
            severity_of(
                None,
                &["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:O/RC:C"]
            ),
            AdvisorySeverity::High
        );
        assert_eq!(
            severity_of(None, &["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"]),
            AdvisorySeverity::Medium
        );
    }

    #[test]
    fn unknown_label_falls_back_to_cvss_then_numeric_score() {
        assert_eq!(
            severity_of(Some("UNKNOWN"), &[CVSS_CRITICAL]),
            AdvisorySeverity::Critical
        );
        assert_eq!(
            severity_of(Some("UNKNOWN"), &["9.5"]),
            AdvisorySeverity::Critical
        );
    }

    #[test]
    fn numeric_score_is_used_without_a_cvss_v3_vector() {
        assert_eq!(severity_of(None, &["7.5"]), AdvisorySeverity::High);
        assert_eq!(severity_of(None, &["2.5"]), AdvisorySeverity::Low);
        assert_eq!(
            severity_of(None, &["2.0", CVSS_CRITICAL]),
            AdvisorySeverity::Critical
        );
    }

    #[test]
    fn missing_severity_information_defaults_to_medium() {
        assert_eq!(severity_of(None, &[]), AdvisorySeverity::Medium);
        assert_eq!(
            severity_of(None, &["not a score"]),
            AdvisorySeverity::Medium
        );
    }

    // summary and id checks

    #[test]
    fn summary_falls_back_to_first_details_line_then_id() {
        let with_details: AdvisoryDetail = serde_json::from_str(
            r#"{"id":"GHSA-aaaa-bbbb-cccc","details":"First line\nSecond line"}"#,
        )
        .expect("valid detail");
        assert_eq!(
            advisory_from_detail(&with_details.id, &with_details).summary,
            "First line"
        );
        let bare: AdvisoryDetail =
            serde_json::from_str(r#"{"id":"GHSA-aaaa-bbbb-cccc"}"#).expect("valid detail");
        assert_eq!(
            advisory_from_detail(&bare.id, &bare).summary,
            "GHSA-aaaa-bbbb-cccc"
        );
    }

    #[test]
    fn long_summary_is_truncated_on_a_char_boundary() {
        let long_summary = "é".repeat(250);
        let detail: AdvisoryDetail = serde_json::from_value(json!({
            "id": "GHSA-aaaa-bbbb-cccc",
            "summary": long_summary,
        }))
        .expect("valid detail");
        let summary = advisory_from_detail(&detail.id, &detail).summary;
        assert_eq!(summary.chars().count(), SUMMARY_MAX_CHARS);
    }

    #[test]
    fn advisory_ids_must_match_the_safe_alphabet_and_length() {
        assert!(is_valid_advisory_id("RUSTSEC-2021-0003"));
        assert!(is_valid_advisory_id("GHSA-43w2-9j62-hq99"));
        assert!(is_valid_advisory_id(&"a".repeat(64)));
        assert!(!is_valid_advisory_id(""));
        assert!(!is_valid_advisory_id("a/b"));
        assert!(!is_valid_advisory_id("a b"));
        assert!(!is_valid_advisory_id("a.b"));
        assert!(!is_valid_advisory_id(&"a".repeat(65)));
    }

    // query_batch

    #[test]
    fn anonymous_deferred_has_no_id_and_no_link() {
        let entry = anonymous_deferred();
        assert!(is_deferred(&entry));
        assert_eq!(entry.id, "");
        assert_eq!(entry.url, None);
    }

    #[test]
    fn results_align_with_queries_and_details_are_cached() {
        let http = fixture_http();
        let mut cache = Cache::new(TTL_SECS);
        let results = query_batch(&http, &mut cache, &fixture_queries(), NOW, None).unwrap();

        let smallvec_summary = "Buffer overflow in SmallVec::insert_many";
        let rustsec = Vulnerability {
            id: "RUSTSEC-2021-0003".to_owned(),
            severity: AdvisorySeverity::Critical,
            summary: smallvec_summary.to_owned(),
            url: Some("https://osv.dev/vulnerability/RUSTSEC-2021-0003".to_owned()),
        };
        let ghsa_smallvec = Vulnerability {
            id: "GHSA-43w2-9j62-hq99".to_owned(),
            severity: AdvisorySeverity::Critical,
            summary: smallvec_summary.to_owned(),
            url: Some("https://osv.dev/vulnerability/GHSA-43w2-9j62-hq99".to_owned()),
        };
        let ghsa_go = Vulnerability {
            id: "GHSA-5rcv-m4m3-hfh7".to_owned(),
            severity: AdvisorySeverity::Medium,
            summary: "golang.org/x/text Infinite loop".to_owned(),
            url: Some("https://osv.dev/vulnerability/GHSA-5rcv-m4m3-hfh7".to_owned()),
        };
        assert_eq!(
            results,
            vec![vec![rustsec, ghsa_smallvec], vec![], vec![ghsa_go]]
        );

        assert_eq!(
            http.requests(),
            vec![
                ("POST".to_owned(), BATCH_URL.to_owned()),
                // This fake has no route for the full query of the two advisories of smallvec, so
                // it fails and they are read by id.
                ("POST".to_owned(), QUERY_URL.to_owned()),
                ("GET".to_owned(), detail_url("RUSTSEC-2021-0003")),
                ("GET".to_owned(), detail_url("GHSA-43w2-9j62-hq99")),
                ("GET".to_owned(), detail_url("GHSA-5rcv-m4m3-hfh7")),
            ]
        );
    }

    #[test]
    fn batch_body_lists_one_entry_per_query() {
        let http = fixture_http();
        let mut cache = Cache::new(TTL_SECS);
        query_batch(&http, &mut cache, &fixture_queries(), NOW, None).unwrap();
        let sent: Value = serde_json::from_str(&http.request_bodies()[0]).unwrap();
        assert_eq!(
            sent,
            json!({
                "queries": [
                    { "package": { "name": "smallvec", "ecosystem": "crates.io" }, "version": "1.6.0" },
                    { "package": { "name": "serde", "ecosystem": "crates.io" }, "version": "1.0.0" },
                    { "package": { "name": "golang.org/x/text", "ecosystem": "crates.io" }, "version": "0.3.0" },
                ]
            })
        );
    }

    #[test]
    fn second_call_is_served_from_the_cache_without_detail_requests() {
        let http = fixture_http();
        let mut cache = Cache::new(TTL_SECS);
        let first = query_batch(&http, &mut cache, &fixture_queries(), NOW, None).unwrap();
        let details_after_first = http.count(DETAIL_URL_PREFIX);
        let second = query_batch(&http, &mut cache, &fixture_queries(), NOW + 1, None).unwrap();
        assert_eq!(first, second);
        assert_eq!(details_after_first, 3);
        assert_eq!(http.count(DETAIL_URL_PREFIX), 3);
        assert_eq!(http.count(BATCH_URL), 2);
    }

    #[test]
    fn empty_query_list_sends_nothing() {
        let http = FakeHttp::new();
        let mut cache = Cache::new(TTL_SECS);
        assert_eq!(
            query_batch(&http, &mut cache, &[], NOW, None),
            Ok(Vec::new())
        );
        assert!(http.requests().is_empty());
    }

    #[test]
    fn caps_detail_fetches_per_run_and_leaves_the_overflow_uncached() {
        let ids: Vec<String> = (0..=MAX_DETAIL_FETCHES_PER_RUN)
            .map(|index| format!("TEST-{index:03}"))
            .collect();
        let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let mut http =
            FakeHttp::new().route("POST", BATCH_URL, 200, &batch_body(&[id_refs.as_slice()]));
        for id in &ids {
            http = http.route("GET", &detail_url(id), 200, &detail_body(id));
        }
        let mut cache = Cache::new(TTL_SECS);
        let overflow_id = &ids[MAX_DETAIL_FETCHES_PER_RUN];

        let results =
            query_batch(&http, &mut cache, &[query("serde", "1.0.0")], NOW, None).unwrap();

        assert_eq!(http.count(DETAIL_URL_PREFIX), MAX_DETAIL_FETCHES_PER_RUN);
        assert_eq!(results[0].len(), ids.len());
        assert_eq!(
            results[0][MAX_DETAIL_FETCHES_PER_RUN],
            placeholder(overflow_id)
        );
        assert!(cache.advisory(overflow_id, NOW).is_none());
        assert!(cache.advisory(&ids[0], NOW).is_some());

        // A later run completes the overflow id: only that one detail is fetched.
        query_batch(&http, &mut cache, &[query("serde", "1.0.0")], NOW, None).unwrap();
        assert_eq!(
            http.count(DETAIL_URL_PREFIX),
            MAX_DETAIL_FETCHES_PER_RUN + 1
        );
        assert!(cache.advisory(overflow_id, NOW).is_some());
    }

    #[test]
    fn passed_deadline_sends_the_batch_but_no_detail_requests() {
        let http = fixture_http();
        let mut cache = Cache::new(TTL_SECS);
        // Any instant that already passed ends the detail phase before its first request.
        let passed = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);

        let results =
            query_batch(&http, &mut cache, &fixture_queries(), NOW, Some(passed)).unwrap();

        assert_eq!(http.count(BATCH_URL), 1);
        assert_eq!(http.count(DETAIL_URL_PREFIX), 0);
        assert_eq!(
            results,
            vec![
                vec![
                    placeholder("RUSTSEC-2021-0003"),
                    placeholder("GHSA-43w2-9j62-hq99")
                ],
                vec![],
                vec![placeholder("GHSA-5rcv-m4m3-hfh7")]
            ]
        );
        assert!(results.iter().flatten().all(is_placeholder));
    }

    #[test]
    fn future_deadline_fetches_details_as_without_a_deadline() {
        let http = fixture_http();
        let mut cache = Cache::new(TTL_SECS);
        let future = Instant::now() + Duration::from_secs(3600);
        query_batch(&http, &mut cache, &fixture_queries(), NOW, Some(future)).unwrap();
        assert_eq!(http.count(DETAIL_URL_PREFIX), 3);
    }

    #[test]
    fn invalid_advisory_ids_are_dropped_silently() {
        let long_id = "a".repeat(65);
        let ids = ["bad/../x", "GHSA-ok-1234", long_id.as_str()];
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(&[&ids]))
            .route(
                "GET",
                &detail_url("GHSA-ok-1234"),
                200,
                &detail_body("GHSA-ok-1234"),
            );
        let mut cache = Cache::new(TTL_SECS);

        let results =
            query_batch(&http, &mut cache, &[query("serde", "1.0.0")], NOW, None).unwrap();

        assert_eq!(results[0].len(), 1);
        assert_eq!(results[0][0].id, "GHSA-ok-1234");
        assert_eq!(http.count(DETAIL_URL_PREFIX), 1);
    }

    #[test]
    fn failed_detail_fetches_get_a_placeholder_and_are_not_cached() {
        let ids = [
            "GHSA-500-0000",
            "GHSA-net-0000",
            "GHSA-json-0000",
            "GHSA-other-0000",
        ];
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(&[&ids]))
            .route("GET", &detail_url(ids[0]), 500, "")
            .transport_error("GET", &detail_url(ids[1]), "network down")
            .route("GET", &detail_url(ids[2]), 200, "not json")
            .route("GET", &detail_url(ids[3]), 200, RUSTSEC_DETAIL);
        let mut cache = Cache::new(TTL_SECS);

        let results =
            query_batch(&http, &mut cache, &[query("serde", "1.0.0")], NOW, None).unwrap();

        let expected: Vec<Vulnerability> = ids.iter().map(|id| placeholder(id)).collect();
        assert_eq!(results, vec![expected]);
        for id in ids {
            assert!(cache.advisory(id, NOW).is_none(), "{id} must not be cached");
        }
    }

    #[test]
    fn batch_http_errors_return_the_status_or_cause() {
        let mut cache = Cache::new(TTL_SECS);
        let queries = [query("serde", "1.0.0")];

        let too_many = FakeHttp::new().route("POST", BATCH_URL, 429, "{}");
        assert_eq!(
            query_batch(&too_many, &mut cache, &queries, NOW, None),
            Err("OSV: HTTP 429".to_owned())
        );

        let server_error = FakeHttp::new().route("POST", BATCH_URL, 500, "{}");
        assert_eq!(
            query_batch(&server_error, &mut cache, &queries, NOW, None),
            Err("OSV: HTTP 500".to_owned())
        );

        let invalid_json = FakeHttp::new().route("POST", BATCH_URL, 200, "not json");
        assert_eq!(
            query_batch(&invalid_json, &mut cache, &queries, NOW, None),
            Err(INVALID_RESPONSE.to_owned())
        );

        let missing_result = FakeHttp::new().route("POST", BATCH_URL, 200, r#"{"results":[]}"#);
        assert_eq!(
            query_batch(&missing_result, &mut cache, &queries, NOW, None),
            Err(INVALID_RESPONSE.to_owned())
        );

        let offline = FakeHttp::new().transport_error("POST", BATCH_URL, "network down");
        assert_eq!(
            query_batch(&offline, &mut cache, &queries, NOW, None),
            Err("OSV: network down".to_owned())
        );
    }

    #[test]
    fn splits_batch_requests_at_one_thousand_queries() {
        let names: Vec<String> = (0..=MAX_BATCH_QUERIES)
            .map(|index| format!("crate-{index}"))
            .collect();
        let queries: Vec<OsvQuery> = names.iter().map(|name| query(name, "1.0.0")).collect();
        let http = EchoBatchHttp::default();
        let mut cache = Cache::new(TTL_SECS);

        let results = query_batch(&http, &mut cache, &queries, NOW, None).unwrap();

        assert_eq!(results.len(), queries.len());
        assert_eq!(*http.batch_sizes.borrow(), vec![MAX_BATCH_QUERIES, 1]);
    }

    // details_per_query

    /// `count` advisory ids, in the order OSV would return them.
    fn advisory_ids(count: usize) -> Vec<String> {
        (0..count)
            .map(|number| format!("GHSA-{number:04}"))
            .collect()
    }

    /// Answers one query with all of `ids`, and every detail request with a minimal record.
    fn http_with_advisories(ids: &[String]) -> FakeHttp {
        let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let mut http = FakeHttp::new().route("POST", BATCH_URL, 200, &batch_body(&[&id_refs]));
        for id in ids {
            http = http.route("GET", &detail_url(id), 200, &detail_body(id));
        }
        http
    }

    #[test]
    fn only_the_first_advisories_of_a_query_load_their_details() {
        let ids = advisory_ids(15);
        let http = http_with_advisories(&ids);
        let mut cache = Cache::new(TTL_SECS);
        let queries = [query("nokogiri", "1.10.0")];
        let results = query_batch_limited(
            &http,
            &mut cache,
            &queries,
            NOW,
            None,
            DEFAULT_DETAILS_PER_QUERY,
        )
        .unwrap();

        let list = &results[0];
        assert_eq!(list.len(), 15);
        assert!(
            list[..10]
                .iter()
                .all(|advisory| !is_placeholder(advisory) && !is_deferred(advisory))
        );
        assert!(list[10..].iter().all(is_deferred));
        // A deferred advisory is not a retry placeholder: nothing is waiting to be fetched for it.
        assert!(list[10..].iter().all(|advisory| !is_placeholder(advisory)));
        assert_eq!(http.count(DETAIL_URL_PREFIX), 10);
    }

    #[test]
    fn a_larger_limit_loads_the_deferred_advisories_and_keeps_the_cached_ones() {
        let ids = advisory_ids(15);
        let http = http_with_advisories(&ids);
        let mut cache = Cache::new(TTL_SECS);
        let queries = [query("nokogiri", "1.10.0")];
        query_batch_limited(
            &http,
            &mut cache,
            &queries,
            NOW,
            None,
            DEFAULT_DETAILS_PER_QUERY,
        )
        .unwrap();
        let results =
            query_batch_limited(&http, &mut cache, &queries, NOW, None, usize::MAX).unwrap();
        assert!(
            results[0]
                .iter()
                .all(|advisory| !is_placeholder(advisory) && !is_deferred(advisory))
        );
        // The ten loaded advisories are read from the cache, so only five more requests go out.
        assert_eq!(http.count(DETAIL_URL_PREFIX), 15);
    }

    #[test]
    fn the_unlimited_query_batch_loads_every_advisory() {
        let ids = advisory_ids(15);
        let http = http_with_advisories(&ids);
        let mut cache = Cache::new(TTL_SECS);
        let results =
            query_batch(&http, &mut cache, &[query("nokogiri", "1.10.0")], NOW, None).unwrap();
        assert!(results[0].iter().all(|advisory| !is_deferred(advisory)));
        assert_eq!(http.count(DETAIL_URL_PREFIX), 15);
    }

    #[test]
    fn an_advisory_beyond_the_window_is_resolved_when_its_details_are_cached() {
        let ids = advisory_ids(15);
        let http = http_with_advisories(&ids);
        let mut cache = Cache::new(TTL_SECS);
        // Another package already loaded the advisory at position 12.
        let cached = Vulnerability {
            id: ids[12].clone(),
            severity: AdvisorySeverity::Low,
            summary: "Cached by another package".to_owned(),
            url: None,
        };
        cache.put_advisory(cached.clone(), NOW);
        let results = query_batch_limited(
            &http,
            &mut cache,
            &[query("nokogiri", "1.10.0")],
            NOW,
            None,
            DEFAULT_DETAILS_PER_QUERY,
        )
        .unwrap();
        assert_eq!(results[0][12], cached);
        assert!(results[0][10..12].iter().all(is_deferred));
        assert!(results[0][13..].iter().all(is_deferred));
    }

    // affected ranges

    /// A real-shaped advisory record: one Go package with an open range closed by a fix.
    const DETAIL_WITH_RANGES: &str = r#"{
        "id": "GHSA-5rcv-m4m3-hfh7",
        "summary": "golang.org/x/text Infinite loop",
        "affected": [
            {
                "package": {"name": "golang.org/x/text", "ecosystem": "Go"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.3.3"}]},
                    {"type": "GIT", "repo": "https://example.com/x.git", "events": [{"introduced": "0"}, {"fixed": "abc123"}]}
                ],
                "versions": ["0.1.0", "0.3.0"]
            },
            {
                "package": {"name": "other", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"last_affected": "1.4"}]}]
            }
        ]
    }"#;

    #[test]
    fn the_affected_ranges_and_versions_of_a_fetched_advisory_are_cached_without_git_ranges() {
        let http = FakeHttp::new()
            .route(
                "POST",
                BATCH_URL,
                200,
                &batch_body(&[&["GHSA-5rcv-m4m3-hfh7"]]),
            )
            .route(
                "GET",
                &detail_url("GHSA-5rcv-m4m3-hfh7"),
                200,
                DETAIL_WITH_RANGES,
            );
        let mut cache = Cache::new(TTL_SECS);
        query_batch(
            &http,
            &mut cache,
            &[query("golang.org/x/text", "0.3.0")],
            NOW,
            None,
        )
        .unwrap();

        let affected = cache
            .affected("GHSA-5rcv-m4m3-hfh7", NOW)
            .expect("affected is cached");
        assert_eq!(
            affected,
            [
                Affected {
                    ecosystem: "Go".to_owned(),
                    name: "golang.org/x/text".to_owned(),
                    ranges: vec![vec![
                        RangeEvent::Introduced("0".to_owned()),
                        RangeEvent::Fixed("0.3.3".to_owned()),
                    ]],
                    versions: vec!["0.1.0".to_owned(), "0.3.0".to_owned()],
                },
                Affected {
                    ecosystem: "npm".to_owned(),
                    name: "other".to_owned(),
                    ranges: vec![vec![
                        RangeEvent::Introduced("1.0".to_owned()),
                        RangeEvent::LastAffected("1.4".to_owned()),
                    ]],
                    versions: Vec::new(),
                },
            ]
        );
    }

    #[test]
    fn an_advisory_without_affected_ranges_caches_an_empty_list() {
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(&[&["GHSA-0001"]]))
            .route(
                "GET",
                &detail_url("GHSA-0001"),
                200,
                &detail_body("GHSA-0001"),
            );
        let mut cache = Cache::new(TTL_SECS);
        query_batch(&http, &mut cache, &[query("serde", "1.0.0")], NOW, None).unwrap();
        assert_eq!(cache.affected("GHSA-0001", NOW), Some(&[][..]));
    }

    #[test]
    fn a_malformed_affected_entry_does_not_hide_the_advisory() {
        let body = r#"{
            "id": "GHSA-0002",
            "summary": "Still shown",
            "affected": [
                {"package": {"ecosystem": "npm"}, "ranges": [{"events": [{"introduced": "0"}]}]},
                {"package": {"name": "ok", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]},
                {"package": {"name": "other", "ecosystem": "Alpine:v3.5"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9"}]}]}
            ]
        }"#;
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(&[&["GHSA-0002"]]))
            .route("GET", &detail_url("GHSA-0002"), 200, body);
        let mut cache = Cache::new(TTL_SECS);
        let results = query_batch(&http, &mut cache, &[query("ok", "1.0.0")], NOW, None).unwrap();
        assert_eq!(results[0][0].summary, "Still shown");
        // Only the well-formed entry of a known ecosystem is kept.
        let affected = cache
            .affected("GHSA-0002", NOW)
            .expect("affected is cached");
        assert_eq!(affected.len(), 1);
        assert_eq!(affected[0].name, "ok");
    }

    /// Builds a `querybatch` body for one query, with a revision per advisory.
    fn batch_body_with_revisions(entries: &[(&str, &str)]) -> String {
        let vulns: Vec<Value> = entries
            .iter()
            .map(|(id, modified)| json!({ "id": id, "modified": modified }))
            .collect();
        json!({ "results": [{ "vulns": vulns }] }).to_string()
    }

    /// Builds the body of a `POST /v1/query`: the full records of the advisories.
    fn full_query_body(records: &[(&str, &str)]) -> String {
        let vulns: Vec<Value> = records
            .iter()
            .map(|(id, modified)| {
                json!({ "id": id, "summary": format!("Summary of {id}"), "modified": modified })
            })
            .collect();
        json!({ "vulns": vulns }).to_string()
    }

    /// Returns `count` advisory ids such as `GHSA-0001`.
    fn numbered_advisory_ids(count: usize) -> Vec<String> {
        (1..=count)
            .map(|number| format!("GHSA-{number:04}"))
            .collect()
    }

    /// The requests that were not the `querybatch`, as `(method, url)`.
    fn detail_requests(http: &FakeHttp) -> Vec<(String, String)> {
        http.requests()
            .into_iter()
            .filter(|(_, url)| url != BATCH_URL)
            .collect()
    }

    const REVISION: &str = "2025-01-01T00:00:00.000001Z";

    #[test]
    fn several_missing_advisories_of_a_package_come_from_one_full_query() {
        let ids = numbered_advisory_ids(5);
        let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let records: Vec<(&str, &str)> = id_refs.iter().map(|id| (*id, REVISION)).collect();
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(&[&id_refs]))
            .route("POST", QUERY_URL, 200, &full_query_body(&records));
        let mut cache = Cache::new(TTL_SECS);
        let results = query_batch(&http, &mut cache, &[query("pkg", "1.0.0")], NOW, None).unwrap();
        assert_eq!(
            detail_requests(&http),
            [("POST".to_owned(), QUERY_URL.to_owned())]
        );
        assert_eq!(results[0].len(), 5);
        for id in &ids {
            assert!(cache.advisory(id, NOW).is_some(), "{id}");
            assert!(cache.affected(id, NOW).is_some(), "{id}");
        }
        assert_eq!(results[0][0].summary, "Summary of GHSA-0001");
        // The request names the package and the version of the query.
        let sent: Value = serde_json::from_str(&http.request_bodies()[1]).unwrap();
        assert_eq!(sent["package"]["name"], "pkg");
        assert_eq!(sent["version"], "1.0.0");
    }

    #[test]
    fn a_single_missing_advisory_is_fetched_by_id() {
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(&[&["GHSA-0001"]]))
            .route(
                "GET",
                &detail_url("GHSA-0001"),
                200,
                &detail_body("GHSA-0001"),
            );
        let mut cache = Cache::new(TTL_SECS);
        query_batch(&http, &mut cache, &[query("pkg", "1.0.0")], NOW, None).unwrap();
        assert_eq!(
            detail_requests(&http),
            [("GET".to_owned(), detail_url("GHSA-0001"))]
        );
    }

    #[test]
    fn a_big_package_with_a_small_window_is_fetched_by_id() {
        // 300 advisories and a window of 10: ten requests by id are cheaper than a 300-record answer.
        let ids = numbered_advisory_ids(300);
        let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let mut http = FakeHttp::new().route("POST", BATCH_URL, 200, &batch_body(&[&id_refs]));
        for id in &ids[..10] {
            http = http.route("GET", &detail_url(id), 200, &detail_body(id));
        }
        let mut cache = Cache::new(TTL_SECS);
        query_batch_limited(&http, &mut cache, &[query("pkg", "1.0.0")], NOW, None, 10).unwrap();
        let requests = detail_requests(&http);
        assert_eq!(requests.len(), 10);
        assert!(requests.iter().all(|(method, _)| method == "GET"));
    }

    #[test]
    fn loading_everything_reads_a_big_package_in_one_full_query() {
        let ids = numbered_advisory_ids(300);
        let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let records: Vec<(&str, &str)> = id_refs.iter().map(|id| (*id, REVISION)).collect();
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(&[&id_refs]))
            .route("POST", QUERY_URL, 200, &full_query_body(&records));
        let mut cache = Cache::new(TTL_SECS);
        query_batch(&http, &mut cache, &[query("pkg", "1.0.0")], NOW, None).unwrap();
        assert_eq!(
            detail_requests(&http),
            [("POST".to_owned(), QUERY_URL.to_owned())]
        );
        assert!(ids.iter().all(|id| cache.advisory(id, NOW).is_some()));
    }

    #[test]
    fn the_records_beyond_the_window_are_kept_and_not_deferred() {
        let ids = numbered_advisory_ids(5);
        let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let records: Vec<(&str, &str)> = id_refs.iter().map(|id| (*id, REVISION)).collect();
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(&[&id_refs]))
            .route("POST", QUERY_URL, 200, &full_query_body(&records));
        let mut cache = Cache::new(TTL_SECS);
        let results =
            query_batch_limited(&http, &mut cache, &[query("pkg", "1.0.0")], NOW, None, 3).unwrap();
        // The query answered for all five, so none waits for a later request.
        assert!(
            results[0]
                .iter()
                .all(|advisory| !is_deferred(advisory) && !is_placeholder(advisory))
        );
    }

    #[test]
    fn a_failed_full_query_falls_back_to_fetching_by_id() {
        let ids = numbered_advisory_ids(3);
        let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let mut http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(&[&id_refs]))
            .route("POST", QUERY_URL, 500, "{}");
        for id in &ids {
            http = http.route("GET", &detail_url(id), 200, &detail_body(id));
        }
        let mut cache = Cache::new(TTL_SECS);
        let results = query_batch(&http, &mut cache, &[query("pkg", "1.0.0")], NOW, None).unwrap();
        let requests = detail_requests(&http);
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0], ("POST".to_owned(), QUERY_URL.to_owned()));
        assert!(results[0].iter().all(|advisory| !is_placeholder(advisory)));
    }

    #[test]
    fn a_full_query_record_for_another_id_is_ignored_and_the_gap_is_fetched_by_id() {
        let http = FakeHttp::new()
            .route(
                "POST",
                BATCH_URL,
                200,
                &batch_body(&[&["GHSA-0001", "GHSA-0002"]]),
            )
            // The answer holds GHSA-0001 and a record that the batch never named.
            .route(
                "POST",
                QUERY_URL,
                200,
                &full_query_body(&[("GHSA-0001", REVISION), ("GHSA-9999", REVISION)]),
            )
            .route(
                "GET",
                &detail_url("GHSA-0002"),
                200,
                &detail_body("GHSA-0002"),
            );
        let mut cache = Cache::new(TTL_SECS);
        query_batch(&http, &mut cache, &[query("pkg", "1.0.0")], NOW, None).unwrap();
        assert!(cache.advisory("GHSA-0001", NOW).is_some());
        assert!(cache.advisory("GHSA-9999", NOW).is_none());
        assert!(cache.advisory("GHSA-0002", NOW).is_some());
        assert_eq!(
            detail_requests(&http),
            [
                ("POST".to_owned(), QUERY_URL.to_owned()),
                ("GET".to_owned(), detail_url("GHSA-0002"))
            ]
        );
    }

    #[test]
    fn an_advisory_with_an_unchanged_revision_needs_no_request_after_the_ttl() {
        let http = FakeHttp::new()
            .route(
                "POST",
                BATCH_URL,
                200,
                &batch_body_with_revisions(&[("GHSA-0001", REVISION)]),
            )
            .route(
                "GET",
                &detail_url("GHSA-0001"),
                200,
                &json!({ "id": "GHSA-0001", "summary": "S", "modified": REVISION }).to_string(),
            );
        let mut cache = Cache::new(TTL_SECS);
        query_batch(&http, &mut cache, &[query("pkg", "1.0.0")], NOW, None).unwrap();
        assert_eq!(detail_requests(&http).len(), 1);
        // After the lifetime, the batch repeats the same revision: no detail request follows.
        let later = NOW + TTL_SECS + 10;
        let results =
            query_batch(&http, &mut cache, &[query("pkg", "1.0.0")], later, None).unwrap();
        assert_eq!(detail_requests(&http).len(), 1);
        assert_eq!(results[0][0].summary, "S");
    }

    #[test]
    fn a_new_revision_of_an_advisory_is_fetched_again() {
        let detail = |revision: &str| {
            json!({ "id": "GHSA-0001", "summary": "S", "modified": revision }).to_string()
        };
        let first = FakeHttp::new()
            .route(
                "POST",
                BATCH_URL,
                200,
                &batch_body_with_revisions(&[("GHSA-0001", REVISION)]),
            )
            .route("GET", &detail_url("GHSA-0001"), 200, &detail(REVISION));
        let mut cache = Cache::new(TTL_SECS);
        query_batch(&first, &mut cache, &[query("pkg", "1.0.0")], NOW, None).unwrap();
        let newer = "2025-03-01T00:00:00.000001Z";
        let second = FakeHttp::new()
            .route(
                "POST",
                BATCH_URL,
                200,
                &batch_body_with_revisions(&[("GHSA-0001", newer)]),
            )
            .route("GET", &detail_url("GHSA-0001"), 200, &detail(newer));
        // Still inside the lifetime, yet the revision changed.
        query_batch(&second, &mut cache, &[query("pkg", "1.0.0")], NOW + 5, None).unwrap();
        assert_eq!(detail_requests(&second).len(), 1);
    }

    #[test]
    fn revisions_compare_at_the_microsecond() {
        // `querybatch` cuts the time at the microsecond. A full record keeps the nanoseconds.
        assert_eq!(
            revision_key("2026-09-10T03:51:10.140141450Z"),
            revision_key("2026-09-10T03:51:10.140141Z")
        );
        assert_ne!(
            revision_key("2026-09-10T03:51:10.140141Z"),
            revision_key("2026-09-10T03:51:10.140142Z")
        );
        // A time with fewer digits, or none, is kept as it is.
        assert_eq!(revision_key("2026-09-10T03:51:10Z"), "2026-09-10T03:51:10Z");
        assert_eq!(
            revision_key("2026-09-10T03:51:10.5Z"),
            "2026-09-10T03:51:10.5Z"
        );
    }

    #[test]
    fn a_listed_version_that_is_not_text_is_skipped_and_the_entry_stays() {
        let body = r#"{
            "id": "GHSA-0003",
            "affected": [{
                "package": {"name": "ok", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
                "versions": ["1.0.0", 5, null, ["x"], {"a": 1}, "1.1.0"]
            }]
        }"#;
        let http = FakeHttp::new()
            .route("POST", BATCH_URL, 200, &batch_body(&[&["GHSA-0003"]]))
            .route("GET", &detail_url("GHSA-0003"), 200, body);
        let mut cache = Cache::new(TTL_SECS);
        query_batch(&http, &mut cache, &[query("ok", "1.0.0")], NOW, None).unwrap();
        let affected = cache
            .affected("GHSA-0003", NOW)
            .expect("affected is cached");
        assert_eq!(affected[0].versions, ["1.0.0", "1.1.0"]);
        assert_eq!(affected[0].ranges.len(), 1);
    }
}
