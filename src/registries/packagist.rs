//! Packagist registry client: request building and response parsing (Composer p2 API).

use super::dotted::{is_dev_branch, rank_versions};
use crate::model::VersionInfo;
use openidea_plugin::HttpRequest;
use serde::Deserialize;
use std::collections::HashMap;

/// Error text for any body that is not a Packagist p2 response.
const INVALID_RESPONSE: &str = "registry: invalid response";

/// The parts of a p2 response that the plugin reads. Other fields are ignored.
#[derive(Deserialize)]
struct RegistryResponse {
    packages: HashMap<String, Vec<VersionEntry>>,
}

/// One version entry. Minified entries omit most fields, so only `version` is read.
#[derive(Deserialize)]
struct VersionEntry {
    version: String,
}

/// Builds the GET request for the p2 metadata of a package. The name is lowercased, as Packagist stores it.
pub fn request(package: &str) -> HttpRequest {
    HttpRequest::get(&format!(
        "https://repo.packagist.org/p2/{}.json",
        package.to_lowercase()
    ))
}

/// Reads a p2 response into the versions of the package.
///
/// Only the first package list is read, because a p2 response for one package holds one list.
pub fn parse(body: &str) -> Result<VersionInfo, String> {
    let response: RegistryResponse =
        serde_json::from_str(body).map_err(|_| INVALID_RESPONSE.to_string())?;
    let entries = response
        .packages
        .into_values()
        .next()
        .ok_or_else(|| INVALID_RESPONSE.to_string())?;
    // Dev branches never reach the list.
    Ok(rank_versions(
        entries
            .into_iter()
            .map(|entry| entry.version)
            .filter(|version| !is_dev_branch(version)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/php/registry.json");

    #[test]
    fn picks_the_newest_stable_version_as_latest() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert_eq!(info.latest.as_deref(), Some("3.12.1"));
    }

    #[test]
    fn lists_newest_first_without_dev_branches() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert_eq!(
            info.versions,
            [
                "3.12.1",
                "3.12.0",
                "3.0.0",
                "3.0.0-RC1",
                "2.11.1",
                "2.0.0",
                "2.0.0-beta2",
                "1.27.1",
                "1.0.0",
                "1.0.0-RC1",
            ]
        );
    }

    #[test]
    fn keeps_prereleases_listed_but_never_latest() {
        let info = parse(FIXTURE).expect("fixture must parse");
        assert!(info.versions.iter().any(|version| version == "3.0.0-RC1"));
        assert_ne!(info.latest.as_deref(), Some("3.0.0-RC1"));
    }

    #[test]
    fn has_no_latest_when_only_prereleases_exist() {
        let body = r#"{"minified":"composer/2.0","packages":{"vendor/pre":[{"version":"2.0.0-beta1"},{"version":"2.0.0-RC1"}]}}"#;
        let info = parse(body).expect("body must parse");
        assert_eq!(info.latest, None);
        assert_eq!(info.versions, ["2.0.0-RC1", "2.0.0-beta1"]);
    }

    #[test]
    fn rejects_bodies_that_are_not_p2_responses() {
        for body in ["not json", "{}", r#"{"packages":{}}"#] {
            assert_eq!(
                parse(body),
                Err("registry: invalid response".to_string()),
                "{body}"
            );
        }
    }

    #[test]
    fn requests_the_lowercased_p2_url() {
        let request = request("Monolog/Monolog");
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.url,
            "https://repo.packagist.org/p2/monolog/monolog.json"
        );
    }
}
