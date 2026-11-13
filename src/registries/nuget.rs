//! NuGet registry client: request building and response parsing (NuGet v3 flat container).

use super::dotted::DottedVersion;
use crate::model::VersionInfo;
use openidea_plugin::HttpRequest;
use serde::Deserialize;
use serde_json::Value;

/// Error text for any body that is not a flat container version index.
const INVALID_RESPONSE: &str = "registry: invalid response";

/// The part of a flat container index that the plugin reads. Other fields are ignored.
///
/// Entries are read as raw values so that one non-string entry skips only itself.
#[derive(Deserialize)]
struct RegistryResponse {
    versions: Vec<Value>,
}

/// Builds the GET request for the version index of `package`. The id is lowercased, as the flat container stores it.
pub fn request(package: &str) -> HttpRequest {
    HttpRequest::get(&format!(
        "https://api.nuget.org/v3-flatcontainer/{}/index.json",
        package.to_lowercase()
    ))
}

/// Reads a version index into the versions of the package.
///
/// Texts that are not dotted versions are dropped. The list is newest first.
/// `latest` is the newest stable release, or `None` when only prereleases exist.
pub fn parse(body: &str) -> Result<VersionInfo, String> {
    let response: RegistryResponse =
        serde_json::from_str(body).map_err(|_| INVALID_RESPONSE.to_string())?;
    // Each version is parsed once and kept beside its text.
    let mut ranked: Vec<(DottedVersion, String)> = response
        .versions
        .into_iter()
        .filter_map(|entry| match entry {
            Value::String(text) => DottedVersion::parse(&text).map(|version| (version, text)),
            _ => None,
        })
        .collect();
    // Newest first. The sort is stable, so equal versions keep the registry order.
    ranked.sort_by(|(left_version, _), (right_version, _)| right_version.cmp(left_version));
    let latest = ranked
        .iter()
        .find(|(version, _)| !version.is_prerelease())
        .map(|(_, text)| text.clone());
    Ok(VersionInfo {
        latest,
        versions: ranked.into_iter().map(|(_, text)| text).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/csharp/registry.json");

    #[test]
    fn reads_the_latest_stable_version() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert_eq!(info.latest.as_deref(), Some("13.0.4"));
    }

    #[test]
    fn lists_newest_first_without_unparsable_versions() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert_eq!(
            info.versions,
            [
                "14.0.1-beta2",
                "14.0.1-beta1",
                "13.0.5-beta1",
                "13.0.4",
                "13.0.4-beta1",
                "13.0.3",
                "13.0.3-beta1",
                "13.0.2",
                "13.0.2-beta1",
                "13.0.1",
                "13.0.1-beta1",
                "12.0.3",
                "12.0.3-beta1",
                "12.0.2",
                "12.0.2-beta3",
            ]
        );
    }

    #[test]
    fn keeps_prereleases_listed_but_never_latest() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert!(
            info.versions
                .iter()
                .any(|version| version == "13.0.4-beta1")
        );
        assert_ne!(info.latest.as_deref(), Some("14.0.1-beta2"));
    }

    #[test]
    fn has_no_latest_when_only_prereleases_are_listed() {
        let body = r#"{"versions":["2.0.0-beta1","2.0.0-rc1"]}"#;
        let info = parse(body).expect("body must parse");
        assert_eq!(info.latest, None);
        assert_eq!(info.versions, ["2.0.0-rc1", "2.0.0-beta1"]);
    }

    #[test]
    fn skips_non_string_entries() {
        let info = parse(r#"{"versions":[1,"1.0.0",null]}"#).expect("body must parse");
        assert_eq!(info.versions, ["1.0.0"]);
    }

    #[test]
    fn rejects_bodies_that_are_not_version_indexes() {
        for body in ["not json", "{}", "[]", r#"{"versions": 1}"#] {
            assert_eq!(
                parse(body),
                Err("registry: invalid response".to_string()),
                "{body}"
            );
        }
    }

    #[test]
    fn requests_the_lowercased_flat_container_url() {
        let request = request("Newtonsoft.Json");
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.url,
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json"
        );
    }
}
