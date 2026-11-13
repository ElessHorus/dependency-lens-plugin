//! Registry clients: one module per ecosystem, reached through `Ecosystem` hooks.

pub mod dotted;
pub mod packagist;
pub mod pep440;
pub mod pypi;

use crate::model::{Ecosystem, VersionInfo};
use openidea_plugin::HttpRequest;
use std::borrow::Cow;

impl Ecosystem {
    /// Returns the registry spelling of `name`. Borrows when nothing changes.
    pub fn normalize_package(self, name: &str) -> Cow<'_, str> {
        match self {
            Ecosystem::PyPI => {
                let normalized = pypi::normalize_name(name);
                if normalized == name {
                    Cow::Borrowed(name)
                } else {
                    Cow::Owned(normalized)
                }
            }
            // Packagist stores names in lowercase. Only names with an uppercase letter need a copy.
            Ecosystem::Packagist if name.chars().any(char::is_uppercase) => {
                Cow::Owned(name.to_lowercase())
            }
            _ => Cow::Borrowed(name),
        }
    }

    /// Builds the request for the version list of `package`, or `None` without a registry client.
    pub fn registry_request(self, package: &str) -> Option<HttpRequest> {
        match self {
            Ecosystem::PyPI => Some(pypi::request(package)),
            Ecosystem::Packagist => Some(packagist::request(package)),
            _ => None,
        }
    }

    /// Reads a registry response of this ecosystem into its version list.
    pub fn parse_registry(self, body: &str) -> Result<VersionInfo, String> {
        match self {
            Ecosystem::PyPI => pypi::parse(body),
            Ecosystem::Packagist => packagist::parse(body),
            _ => Err("no registry for this ecosystem".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PYPI_FIXTURE: &str = include_str!("../../tests/fixtures/python/registry.json");

    #[test]
    fn pypi_normalizes_package_names() {
        assert_eq!(Ecosystem::PyPI.normalize_package("Flask"), "flask");
        assert!(matches!(
            Ecosystem::PyPI.normalize_package("flask"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn other_ecosystems_keep_package_names() {
        assert!(matches!(
            Ecosystem::Cargo.normalize_package("Serde"),
            Cow::Borrowed("Serde")
        ));
    }

    #[test]
    fn only_pypi_has_a_registry_request() {
        let request = Ecosystem::PyPI
            .registry_request("requests")
            .expect("PyPI has a registry");
        assert_eq!(request.url, "https://pypi.org/pypi/requests/json");
        assert!(Ecosystem::Cargo.registry_request("serde").is_none());
    }

    #[test]
    fn pypi_parses_registry_bodies_like_the_pypi_module() {
        assert_eq!(
            Ecosystem::PyPI.parse_registry(PYPI_FIXTURE),
            pypi::parse(PYPI_FIXTURE)
        );
    }

    #[test]
    fn packagist_lowercases_names_and_has_a_registry() {
        assert_eq!(
            Ecosystem::Packagist.normalize_package("Monolog/Monolog"),
            "monolog/monolog"
        );
        assert!(matches!(
            Ecosystem::Packagist.normalize_package("monolog/monolog"),
            Cow::Borrowed(_)
        ));
        assert!(
            Ecosystem::Packagist
                .registry_request("monolog/monolog")
                .is_some()
        );
    }

    #[test]
    fn packagist_parses_registry_bodies_like_the_packagist_module() {
        let fixture = include_str!("../../tests/fixtures/php/registry.json");
        assert_eq!(
            Ecosystem::Packagist.parse_registry(fixture),
            packagist::parse(fixture)
        );
    }

    #[test]
    fn other_ecosystems_reject_registry_bodies() {
        assert_eq!(
            Ecosystem::Cargo.parse_registry("{}"),
            Err("no registry for this ecosystem".to_string())
        );
    }
}
