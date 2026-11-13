//! OSV.dev client: batch queries for advisory ids, then advisory details, cached in [`Cache`].

use crate::cache::Cache;
use crate::http::Http;
use crate::model::{AdvisorySeverity, Ecosystem, Vulnerability};
use openidea_plugin::{HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Most advisory details fetched during one call to [`query_batch`].
pub const MAX_DETAIL_FETCHES_PER_RUN: usize = 100;

/// Most queries that OSV accepts in one `querybatch` request.
const MAX_BATCH_QUERIES: usize = 1000;

/// Longest advisory id that is used in a URL.
const MAX_ADVISORY_ID_LEN: usize = 64;

const BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const DETAIL_URL_PREFIX: &str = "https://api.osv.dev/v1/vulns/";
const ADVISORY_URL_PREFIX: &str = "https://osv.dev/vulnerability/";
const PLACEHOLDER_SUMMARY: &str = "Details not loaded yet";
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
    // Only the first comma-separated requirement names one version.
    let first_requirement = spec.trim_start().split(',').next()?.trim();
    let without_operator = VERSION_OPERATORS
        .iter()
        .find_map(|operator| first_requirement.strip_prefix(*operator))
        .unwrap_or(first_requirement);
    // A `v` marks a Go-style version only when a digit follows it.
    let without_v = match without_operator.strip_prefix(['v', 'V']) {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
        _ => without_operator,
    };
    let version = without_v.trim();
    let has_digit = version.bytes().any(|byte| byte.is_ascii_digit());
    // `:` marks URLs and `workspace:`/`file:` sources, `$` marks unresolved properties.
    let names_source =
        version.contains([':', '$']) || version.starts_with("git") || version.starts_with("path");
    (has_digit && !names_source).then(|| version.to_owned())
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
/// `GET /v1/vulns/{id}`, at most [`MAX_DETAIL_FETCHES_PER_RUN`] per call. Ids beyond that
/// cap, and ids whose detail fetch fails, get a placeholder that is not cached.
///
/// # Errors
///
/// Returns an error when a `querybatch` request fails or its answer is malformed.
pub fn query_batch(
    http: &dyn Http,
    cache: &mut Cache,
    queries: &[OsvQuery],
    now: u64,
) -> Result<Vec<Vec<Vulnerability>>, String> {
    let mut advisory_ids_per_query: Vec<Vec<String>> = Vec::with_capacity(queries.len());
    for chunk in queries.chunks(MAX_BATCH_QUERIES) {
        advisory_ids_per_query.extend(query_chunk(http, chunk)?);
    }
    let fetched = fetch_missing_details(http, cache, &advisory_ids_per_query, now);
    let cache: &Cache = cache;
    Ok(advisory_ids_per_query
        .iter()
        .map(|advisory_ids| {
            advisory_ids
                .iter()
                .map(|id| resolve_advisory(id, &fetched, cache, now))
                .collect()
        })
        .collect())
}

/// Sends one `querybatch` request and returns the advisory ids of each query.
fn query_chunk(http: &dyn Http, chunk: &[OsvQuery]) -> Result<Vec<Vec<String>>, String> {
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
                .filter_map(|vulnerability| {
                    is_valid_advisory_id(&vulnerability.id).then_some(vulnerability.id)
                })
                .collect()
        })
        .collect())
}

/// Fetches the details of uncached advisory ids, at most [`MAX_DETAIL_FETCHES_PER_RUN`].
///
/// Stores each fetched advisory in `cache` and returns the fetched advisories by id.
fn fetch_missing_details<'a>(
    http: &dyn Http,
    cache: &mut Cache,
    advisory_ids_per_query: &'a [Vec<String>],
    now: u64,
) -> HashMap<&'a str, Vulnerability> {
    // One pass: `seen` drops repeats, and `take` stops the scan at the cap.
    let mut seen: HashSet<&str> = HashSet::new();
    let missing_ids: Vec<&str> = advisory_ids_per_query
        .iter()
        .flatten()
        .map(String::as_str)
        .filter(|id| cache.advisory(id, now).is_none() && seen.insert(*id))
        .take(MAX_DETAIL_FETCHES_PER_RUN)
        .collect();

    let mut fetched = HashMap::with_capacity(missing_ids.len());
    for id in missing_ids {
        if let Some(advisory) = fetch_detail(http, id) {
            cache.put_advisory(advisory.clone(), now);
            fetched.insert(id, advisory);
        }
    }
    fetched
}

/// Fetches and parses one advisory. Returns `None` on any failure.
fn fetch_detail(http: &dyn Http, id: &str) -> Option<Vulnerability> {
    let url = format!("{DETAIL_URL_PREFIX}{id}");
    let response = http.send(&HttpRequest::get(&url)).ok()?;
    if !is_success(response.status) {
        return None;
    }
    let detail: AdvisoryDetail = serde_json::from_slice(&response.body).ok()?;
    // A record for another id would be cached under the wrong key, so it is rejected.
    (detail.id == id).then(|| advisory_from_detail(id, &detail))
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

fn advisory_url(id: &str) -> String {
    format!("{ADVISORY_URL_PREFIX}{id}")
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn ensure_success(response: &HttpResponse) -> Result<(), String> {
    if is_success(response.status) {
        Ok(())
    } else {
        Err(format!("OSV: HTTP {}", response.status))
    }
}

/// Returns `true` when `id` matches `[A-Za-z0-9-]{1,64}`.
///
/// Checks bytes: only ASCII passes, so the byte length is the character count.
fn is_valid_advisory_id(id: &str) -> bool {
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
    summary: Option<String>,
    details: Option<String>,
    severity: Option<Vec<SeverityEntry>>,
    database_specific: Option<DatabaseSpecific>,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::FakeHttp;
    use openidea_plugin::HttpResponse;
    use serde_json::{Value, json};
    use std::cell::RefCell;

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
        assert_eq!(declared_version_for_osv("1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(
            declared_version_for_osv(">=2.0, <3").as_deref(),
            Some("2.0")
        );
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
    fn results_align_with_queries_and_details_are_cached() {
        let http = fixture_http();
        let mut cache = Cache::new(TTL_SECS);
        let results = query_batch(&http, &mut cache, &fixture_queries(), NOW).unwrap();

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
        query_batch(&http, &mut cache, &fixture_queries(), NOW).unwrap();
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
        let first = query_batch(&http, &mut cache, &fixture_queries(), NOW).unwrap();
        let details_after_first = http.count(DETAIL_URL_PREFIX);
        let second = query_batch(&http, &mut cache, &fixture_queries(), NOW + 1).unwrap();
        assert_eq!(first, second);
        assert_eq!(details_after_first, 3);
        assert_eq!(http.count(DETAIL_URL_PREFIX), 3);
        assert_eq!(http.count(BATCH_URL), 2);
    }

    #[test]
    fn empty_query_list_sends_nothing() {
        let http = FakeHttp::new();
        let mut cache = Cache::new(TTL_SECS);
        assert_eq!(query_batch(&http, &mut cache, &[], NOW), Ok(Vec::new()));
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

        let results = query_batch(&http, &mut cache, &[query("serde", "1.0.0")], NOW).unwrap();

        assert_eq!(http.count(DETAIL_URL_PREFIX), MAX_DETAIL_FETCHES_PER_RUN);
        assert_eq!(results[0].len(), ids.len());
        assert_eq!(
            results[0][MAX_DETAIL_FETCHES_PER_RUN],
            placeholder(overflow_id)
        );
        assert!(cache.advisory(overflow_id, NOW).is_none());
        assert!(cache.advisory(&ids[0], NOW).is_some());

        // A later run completes the overflow id: only that one detail is fetched.
        query_batch(&http, &mut cache, &[query("serde", "1.0.0")], NOW).unwrap();
        assert_eq!(
            http.count(DETAIL_URL_PREFIX),
            MAX_DETAIL_FETCHES_PER_RUN + 1
        );
        assert!(cache.advisory(overflow_id, NOW).is_some());
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

        let results = query_batch(&http, &mut cache, &[query("serde", "1.0.0")], NOW).unwrap();

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

        let results = query_batch(&http, &mut cache, &[query("serde", "1.0.0")], NOW).unwrap();

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
            query_batch(&too_many, &mut cache, &queries, NOW),
            Err("OSV: HTTP 429".to_owned())
        );

        let server_error = FakeHttp::new().route("POST", BATCH_URL, 500, "{}");
        assert_eq!(
            query_batch(&server_error, &mut cache, &queries, NOW),
            Err("OSV: HTTP 500".to_owned())
        );

        let invalid_json = FakeHttp::new().route("POST", BATCH_URL, 200, "not json");
        assert_eq!(
            query_batch(&invalid_json, &mut cache, &queries, NOW),
            Err(INVALID_RESPONSE.to_owned())
        );

        let missing_result = FakeHttp::new().route("POST", BATCH_URL, 200, r#"{"results":[]}"#);
        assert_eq!(
            query_batch(&missing_result, &mut cache, &queries, NOW),
            Err(INVALID_RESPONSE.to_owned())
        );

        let offline = FakeHttp::new().transport_error("POST", BATCH_URL, "network down");
        assert_eq!(
            query_batch(&offline, &mut cache, &queries, NOW),
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

        let results = query_batch(&http, &mut cache, &queries, NOW).unwrap();

        assert_eq!(results.len(), queries.len());
        assert_eq!(*http.batch_sizes.borrow(), vec![MAX_BATCH_QUERIES, 1]);
    }
}
