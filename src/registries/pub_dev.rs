//! pub.dev registry client: request building and response parsing (pub.dev package API).

use super::dotted::{PubVersion, rank_pub_versions};
use crate::model::VersionInfo;
use openidea_plugin::HttpRequest;
use serde::Deserialize;

/// Error text for any body that is not a pub.dev package response.
const INVALID_RESPONSE: &str = "registry: invalid response";

/// The parts of a package response that the plugin reads. Other fields are ignored.
///
/// Each version entry also carries a large `pubspec`. Serde skips it without building a value.
#[derive(Deserialize)]
struct RegistryResponse {
    latest: Option<LatestEntry>,
    versions: Vec<VersionEntry>,
}

/// The reported latest release, used only when no stable version is listed.
#[derive(Deserialize)]
struct LatestEntry {
    version: String,
}

/// One release. `retracted` is absent for most releases.
#[derive(Deserialize)]
struct VersionEntry {
    version: String,
    retracted: Option<bool>,
}

/// Builds the GET request for the package API of `package`.
pub fn request(package: &str) -> HttpRequest {
    HttpRequest::get(&format!("https://pub.dev/api/packages/{package}"))
}

/// Reads a package API response into the versions of the package.
///
/// Retracted releases and texts that are not dotted versions are dropped. The
/// list is newest first. `latest` is the newest stable release listed, or the
/// reported latest when only prereleases are listed.
pub fn parse(body: &str) -> Result<VersionInfo, String> {
    let response: RegistryResponse =
        serde_json::from_str(body).map_err(|_| INVALID_RESPONSE.to_string())?;
    let reported_latest = response.latest;
    let mut info = rank_pub_versions(
        response
            .versions
            .into_iter()
            .filter(|entry| entry.retracted != Some(true))
            .map(|entry| entry.version),
    );
    // The reported latest is used only when no stable release is listed.
    info.latest = info.latest.or_else(|| {
        reported_latest
            .map(|entry| entry.version)
            .filter(|text| PubVersion::parse(text).is_some())
    });
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/dart/registry.json");

    #[test]
    fn reads_the_latest_stable_version() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert_eq!(info.latest.as_deref(), Some("1.6.0"));
    }

    #[test]
    fn lists_newest_first_without_retracted_or_unparsable_versions() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert_eq!(
            info.versions,
            [
                "1.6.0",
                "1.5.0",
                "1.5.0-beta.2",
                "1.5.0-beta",
                "1.4.0",
                "1.3.0",
                "1.2.2",
                "1.2.0",
                "1.0.0",
                "0.13.6",
            ]
        );
    }

    #[test]
    fn keeps_prereleases_listed_but_never_latest() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert!(info.versions.iter().any(|version| version == "1.5.0-beta"));
        assert_ne!(info.latest.as_deref(), Some("1.5.0-beta.2"));
    }

    #[test]
    fn falls_back_to_the_reported_latest_when_only_prereleases_are_listed() {
        let body = r#"{"name":"demo","latest":{"version":"2.0.0"},"versions":[{"version":"2.0.0-dev.1"},{"version":"2.0.0-dev.2"}]}"#;
        let info = parse(body).expect("body must parse");
        assert_eq!(info.latest.as_deref(), Some("2.0.0"));
        assert_eq!(info.versions, ["2.0.0-dev.2", "2.0.0-dev.1"]);
    }

    #[test]
    fn rejects_bodies_that_are_not_package_responses() {
        for body in ["not json", "{}"] {
            assert_eq!(
                parse(body),
                Err("registry: invalid response".to_string()),
                "{body}"
            );
        }
    }

    #[test]
    fn requests_the_package_api_url() {
        let request = request("http");
        assert_eq!(request.method, "GET");
        assert_eq!(request.url, "https://pub.dev/api/packages/http");
    }

    #[test]
    fn build_numbers_rank_a_version_above_the_same_version_without_one() {
        // pub.dev lists the oldest first, so the plain version comes before its builds.
        let body = r#"{"latest":{"version":"0.4.0+9"},"versions":[{"version":"0.3.0"},{"version":"0.4.0"},{"version":"0.4.0+1"},{"version":"0.4.0+9"},{"version":"0.4.0+10"}]}"#;
        let info = parse(body).expect("body must parse");
        assert_eq!(info.latest.as_deref(), Some("0.4.0+10"));
        assert_eq!(
            info.versions,
            ["0.4.0+10", "0.4.0+9", "0.4.0+1", "0.4.0", "0.3.0"]
        );
    }
}
