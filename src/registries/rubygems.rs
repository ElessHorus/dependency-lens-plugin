//! RubyGems registry client: request building and response parsing (`/api/v1/versions/{gem}.json`).

use super::gem_version::GemVersion;
use super::rank_with;
use crate::model::VersionInfo;
use openidea_plugin::HttpRequest;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashSet;

/// Error text for any body that is not an array of release objects.
const INVALID_RESPONSE: &str = "registry: invalid response";

/// The two fields of a release entry that the plugin reads. Other fields are skipped without allocation.
#[derive(Deserialize)]
struct Release<'a> {
    #[serde(borrow)]
    number: Cow<'a, str>,
    prerelease: Option<bool>,
}

/// A unique version number and whether the API marks it as a prerelease.
///
/// The order depends on the version only, so equal numbers keep the input order.
struct ReleaseVersion {
    version: GemVersion,
    is_api_prerelease: bool,
}

impl ReleaseVersion {
    /// Returns `true` for a prerelease by its text or by the API flag.
    fn is_prerelease(&self) -> bool {
        self.is_api_prerelease || self.version.is_prerelease()
    }
}

impl Ord for ReleaseVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.version.cmp(&other.version)
    }
}

impl PartialOrd for ReleaseVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ReleaseVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ReleaseVersion {}

/// Builds the GET request for the version list of `package`.
pub fn request(package: &str) -> HttpRequest {
    HttpRequest::get(&format!(
        "https://rubygems.org/api/v1/versions/{package}.json"
    ))
}

/// Reads a versions response into the versions of the gem.
///
/// The response holds one entry per platform, so a version number can repeat many times.
/// Each number is kept once, at its first position in the response.
pub fn parse(body: &str) -> Result<VersionInfo, String> {
    // Entries stay raw until read, so each one is validated and read without building a value tree.
    let entries: Vec<&RawValue> =
        serde_json::from_str(body).map_err(|_| INVALID_RESPONSE.to_string())?;
    let mut seen: HashSet<Cow<'_, str>> = HashSet::with_capacity(entries.len());
    let mut api_prereleases: HashSet<Cow<'_, str>> = HashSet::new();
    let mut texts: Vec<String> = Vec::new();
    for entry in entries {
        // Entries that are not release objects, or lack a string number, are skipped.
        let Ok(release) = serde_json::from_str::<Release>(entry.get()) else {
            continue;
        };
        if release.prerelease == Some(true) {
            api_prereleases.insert(release.number.clone());
        }
        if seen.insert(release.number.clone()) {
            texts.push(release.number.into_owned());
        }
    }
    Ok(rank_with(
        texts,
        |text| {
            GemVersion::parse(text).map(|version| ReleaseVersion {
                is_api_prerelease: api_prereleases.contains(text),
                version,
            })
        },
        ReleaseVersion::is_prerelease,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/ruby/registry.json");

    #[test]
    fn reads_the_newest_stable_version_as_latest() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert_eq!(info.latest.as_deref(), Some("8.1.4.1"));
    }

    #[test]
    fn lists_each_version_once_newest_first_and_drops_unparsable_numbers() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert_eq!(
            info.versions,
            [
                "8.1.4.1",
                "8.1.4",
                "8.1.3.1",
                "8.1.3",
                "8.1.2.1",
                "8.1.2",
                "8.1.1",
                "8.1.0",
                "8.1.0.rc1",
                "8.1.0.beta1",
                "8.0.5.2",
                "8.0.5.1",
                "8.0.5",
                "8.0.4.1",
                "8.0.4",
            ]
        );
    }

    #[test]
    fn keeps_prereleases_listed_but_never_latest() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert!(info.versions.iter().any(|version| version == "8.1.0.rc1"));
        assert_ne!(info.latest.as_deref(), Some("8.1.0.rc1"));
    }

    #[test]
    fn an_api_prerelease_with_a_stable_looking_number_is_not_latest() {
        let body = r#"[{"number":"2.0","prerelease":true},{"number":"1.0","prerelease":false}]"#;
        let info = parse(body).expect("body must parse");
        assert_eq!(info.latest.as_deref(), Some("1.0"));
        assert_eq!(info.versions, ["2.0", "1.0"]);
    }

    #[test]
    fn has_no_latest_when_only_prereleases_are_listed() {
        let body = r#"[{"number":"8.1.0.rc1","prerelease":true}]"#;
        let info = parse(body).expect("body must parse");
        assert_eq!(info.latest, None);
        assert_eq!(info.versions, ["8.1.0.rc1"]);
    }

    #[test]
    fn rejects_bodies_that_are_not_arrays_of_objects() {
        for body in ["not json", "{}", "1"] {
            assert_eq!(
                parse(body),
                Err("registry: invalid response".to_string()),
                "{body}"
            );
        }
    }

    #[test]
    fn skips_elements_that_are_not_release_objects() {
        let info = parse(r#"[1, {"x":1}, {"number":"1.0"}]"#).expect("body must parse");
        assert_eq!(info.versions, ["1.0"]);
    }

    #[test]
    fn requests_the_versions_json_of_the_gem() {
        let request = request("rails");
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.url,
            "https://rubygems.org/api/v1/versions/rails.json"
        );
    }
}
