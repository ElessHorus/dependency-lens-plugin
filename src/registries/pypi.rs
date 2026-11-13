//! PyPI registry client: request building and response parsing.

use super::pep440::Pep440;
use crate::model::VersionInfo;
use openidea_plugin::HttpRequest;
use serde::Deserialize;
use std::collections::HashMap;

/// Error text for any body that is not a PyPI JSON response.
const INVALID_RESPONSE: &str = "registry: invalid response";

/// The parts of a PyPI JSON response that the plugin reads. Other fields are ignored.
#[derive(Deserialize)]
struct RegistryResponse {
    info: ProjectInfo,
    #[serde(default)]
    releases: HashMap<String, Vec<ReleaseFile>>,
}

/// The project metadata block.
#[derive(Deserialize)]
struct ProjectInfo {
    #[serde(default)]
    version: Option<String>,
}

/// One uploaded file of a release. Only the yanked flag matters here.
#[derive(Deserialize)]
struct ReleaseFile {
    yanked: Option<bool>,
}

/// Returns the PEP 503 normalised form of a project name: lowercase, with each run of `-`, `_` or `.` replaced by one `-`.
pub fn normalize_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut is_in_separator_run = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !is_in_separator_run {
                normalized.push('-');
            }
            is_in_separator_run = true;
        } else {
            normalized.extend(character.to_lowercase());
            is_in_separator_run = false;
        }
    }
    normalized
}

/// Builds the GET request for the JSON API of a project.
pub fn request(package: &str) -> HttpRequest {
    HttpRequest::get(&format!(
        "https://pypi.org/pypi/{}/json",
        normalize_name(package)
    ))
}

/// Reads a PyPI JSON response into the versions of the project.
pub fn parse(body: &str) -> Result<VersionInfo, String> {
    let response: RegistryResponse =
        serde_json::from_str(body).map_err(|_| INVALID_RESPONSE.to_string())?;
    let RegistryResponse { info, releases } = response;
    // Parse only the keys that can be listed. Each key is parsed once and kept beside its version.
    let mut ranked: Vec<(Pep440, String)> = releases
        .into_iter()
        .filter(|(_, files)| is_listable(files))
        .filter_map(|(text, _)| Pep440::parse(&text).map(|version| (version, text)))
        .collect();
    // Newest first. The text breaks ties, such as `1.0` and `1.0.0`, so the order does not depend on HashMap order.
    ranked.sort_by(|(left_version, left_text), (right_version, right_text)| {
        right_version
            .cmp(left_version)
            .then_with(|| left_text.cmp(right_text))
    });
    let latest = ranked
        .iter()
        .find(|(version, _)| !version.is_prerelease())
        .map(|(_, text)| text.clone())
        .or_else(|| info.version.filter(|version_text| !version_text.is_empty()));
    Ok(VersionInfo {
        latest,
        versions: ranked.into_iter().map(|(_, text)| text).collect(),
    })
}

/// Returns `true` when a release has files and at least one file is not yanked.
fn is_listable(files: &[ReleaseFile]) -> bool {
    // `all` on an empty slice is true, so the emptiness check must come first.
    !files.is_empty() && !files.iter().all(|file| file.yanked == Some(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/python/registry.json");

    #[test]
    fn normalizes_names_per_pep_503() {
        assert_eq!(normalize_name("Flask"), "flask");
        assert_eq!(normalize_name("ruamel.yaml"), "ruamel-yaml");
        assert_eq!(normalize_name("Foo__Bar-baz"), "foo-bar-baz");
    }

    #[test]
    fn requests_the_normalised_json_url() {
        let request = request("Foo_Bar");
        assert_eq!(request.method, "GET");
        assert_eq!(request.url, "https://pypi.org/pypi/foo-bar/json");
    }

    #[test]
    fn picks_the_newest_non_prerelease_as_latest() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert_eq!(info.latest.as_deref(), Some("2.34.2"));
    }

    #[test]
    fn lists_newest_first_and_drops_unusable_releases() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert_eq!(
            info.versions,
            [
                "2.34.2",
                "2.34.1",
                "2.34.0",
                "2.34.0.dev1",
                "2.33.1",
                "2.32.2",
                "2.31.0",
                "2.9.2",
            ]
        );
    }

    #[test]
    fn keeps_prereleases_listed_but_never_latest() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert!(info.versions.iter().any(|version| version == "2.34.0.dev1"));
        assert_ne!(info.latest.as_deref(), Some("2.34.0.dev1"));
    }

    #[test]
    fn falls_back_to_info_version_when_only_prereleases_exist() {
        let body =
            r#"{"info":{"version":"2.0.0"},"releases":{"1.0a1":[{"yanked":false}],"1.0rc1":[{}]}}"#;
        let info = parse(body).expect("body must parse");
        assert_eq!(info.latest.as_deref(), Some("2.0.0"));
        assert_eq!(info.versions, ["1.0rc1", "1.0a1"]);
    }

    #[test]
    fn has_no_latest_when_nothing_is_known() {
        let body = r#"{"info":{"version":""},"releases":{}}"#;
        let info = parse(body).expect("body must parse");
        assert_eq!(info.latest, None);
        assert!(info.versions.is_empty());
    }

    #[test]
    fn rejects_bodies_that_are_not_registry_responses() {
        assert_eq!(
            parse("not json"),
            Err("registry: invalid response".to_string())
        );
        assert_eq!(parse("{}"), Err("registry: invalid response".to_string()));
    }
}
