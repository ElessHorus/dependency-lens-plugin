//! Registry clients: one module per ecosystem, reached through `Ecosystem` hooks.

pub mod dotted;
pub mod gem_version;
pub mod maven_version;
pub mod nuget;
pub mod packagist;
pub mod pep440;
pub mod pub_dev;
pub mod pypi;
pub mod rubygems;

use crate::model::{Ecosystem, VersionInfo};
use openidea_plugin::HttpRequest;
use std::borrow::Cow;

/// Ranks version texts newest first, with `parse` and `is_prerelease` supplied by the ecosystem.
///
/// Each text is parsed once and kept beside its parsed version, so the sort compares
/// stored values. Texts that do not parse are dropped. The sort is stable, so equal
/// versions keep the input order. `latest` is the first non-prerelease in that order.
pub fn rank_with<V: Ord>(
    texts: impl IntoIterator<Item = String>,
    parse: impl Fn(&str) -> Option<V>,
    is_prerelease: impl Fn(&V) -> bool,
) -> VersionInfo {
    let mut ranked: Vec<(V, String)> = texts
        .into_iter()
        .filter_map(|text| parse(&text).map(|version| (version, text)))
        .collect();
    ranked.sort_by(|(left_version, _), (right_version, _)| right_version.cmp(left_version));
    let latest = ranked
        .iter()
        .find(|(version, _)| !is_prerelease(version))
        .map(|(_, text)| text.clone());
    VersionInfo {
        latest,
        versions: ranked.into_iter().map(|(_, text)| text).collect(),
    }
}

/// True when `name` is a plausible package name for `eco`'s registry (ASCII only, no path or query characters).
///
/// Names come from manifest text and go into URL paths unencoded, so each grammar
/// is strict. Every check works on bytes: a non-ASCII byte never matches a class.
pub fn is_valid_package_name(eco: Ecosystem, name: &str) -> bool {
    match eco {
        Ecosystem::PyPI => is_bounded_run(name, 128, is_dotted_byte) && has_alphanumeric_ends(name),
        Ecosystem::Packagist => match name.split_once('/') {
            Some((vendor, package)) => {
                is_packagist_segment(vendor) && is_packagist_segment(package)
            }
            None => false,
        },
        Ecosystem::Pub => is_bounded_run(name, 128, is_word_byte),
        Ecosystem::NuGet | Ecosystem::RubyGems => {
            is_bounded_run(name, 128, is_dotted_byte) && starts_alphanumeric(name)
        }
        Ecosystem::Cargo | Ecosystem::Npm | Ecosystem::Go | Ecosystem::Maven => false,
    }
}

/// Letters, digits, `_`, `.` and `-`: the class of PyPI, Packagist, NuGet and RubyGems names.
fn is_dotted_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

/// Letters, digits and `_`: the class of Pub package names.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// True when `segment` has 1 to `max_length` bytes and every byte passes `is_allowed`.
fn is_bounded_run(segment: &str, max_length: usize, is_allowed: fn(u8) -> bool) -> bool {
    (1..=max_length).contains(&segment.len()) && segment.bytes().all(is_allowed)
}

/// True when the first byte is a letter or digit.
fn starts_alphanumeric(segment: &str) -> bool {
    segment
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
}

/// True when the first and the last byte are letters or digits.
fn has_alphanumeric_ends(segment: &str) -> bool {
    starts_alphanumeric(segment)
        && segment
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

/// One side of a Packagist name: a dotted run of up to 100 bytes that is not `.` or `..`.
fn is_packagist_segment(segment: &str) -> bool {
    is_bounded_run(segment, 100, is_dotted_byte) && segment != "." && segment != ".."
}

/// True when `name` is safe to put in the URL of a package page and in a Markdown link.
///
/// The five ecosystems with a registry client reuse `is_valid_package_name`. The others
/// follow the name grammar of their registry, in ASCII only. The name is never encoded:
/// the allow-list keeps it inside the URL path and cannot break the Markdown link.
fn is_linkable_name(eco: Ecosystem, name: &str) -> bool {
    match eco {
        Ecosystem::PyPI
        | Ecosystem::Packagist
        | Ecosystem::Pub
        | Ecosystem::NuGet
        | Ecosystem::RubyGems => is_valid_package_name(eco, name),
        Ecosystem::Cargo => {
            is_bounded_run(name, 64, is_word_or_hyphen_byte)
                && name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        }
        Ecosystem::Npm => is_npm_name(name),
        Ecosystem::Go => {
            name.len() <= 256
                && name
                    .split('/')
                    .all(|segment| is_path_segment(segment, is_tilde_dotted_byte))
        }
        Ecosystem::Maven => name
            .split_once(':')
            .is_some_and(|(group, artifact)| is_maven_part(group) && is_maven_part(artifact)),
    }
}

/// Letters, digits, `_` and `-`: the class of Cargo crate names.
fn is_word_or_hyphen_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

/// Letters, digits and `-._~`: the class of Go path segments.
fn is_tilde_dotted_byte(byte: u8) -> bool {
    is_dotted_byte(byte) || byte == b'~'
}

/// Letters, digits and `-._~`: the class of npm name parts. Old packages have uppercase letters.
fn is_npm_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// True when `segment` is a non-empty path segment, is not `.` or `..`, and passes `is_allowed`.
fn is_path_segment(segment: &str, is_allowed: fn(u8) -> bool) -> bool {
    !segment.is_empty() && segment != "." && segment != ".." && segment.bytes().all(is_allowed)
}

/// True for `name` or `@scope/name`, at most 214 bytes, where no part starts with `.` or `_`.
fn is_npm_name(name: &str) -> bool {
    let is_npm_part =
        |part: &str| is_bounded_run(part, 214, is_npm_byte) && !part.starts_with(['.', '_']);
    if name.len() > 214 {
        return false;
    }
    match name.strip_prefix('@') {
        Some(scoped) => scoped
            .split_once('/')
            .is_some_and(|(scope, package)| is_npm_part(scope) && is_npm_part(package)),
        None => is_npm_part(name),
    }
}

/// One side of a Maven `group:artifact` name: letters, digits and `-._`, starting with a letter or a digit.
fn is_maven_part(part: &str) -> bool {
    is_bounded_run(part, 128, is_dotted_byte) && starts_alphanumeric(part)
}

impl Ecosystem {
    /// Returns the URL of the package page on the public registry, or `None` for an unsafe name.
    ///
    /// The URL needs no request. The name is normalized first, so it matches the registry spelling.
    pub fn package_page_url(self, name: &str) -> Option<String> {
        let package = self.normalize_package(name);
        if !is_linkable_name(self, &package) {
            return None;
        }
        let url = match self {
            Ecosystem::PyPI => format!("https://pypi.org/project/{package}"),
            Ecosystem::Packagist => format!("https://packagist.org/packages/{package}"),
            Ecosystem::Pub => format!("https://pub.dev/packages/{package}"),
            Ecosystem::NuGet => format!("https://www.nuget.org/packages/{package}"),
            Ecosystem::RubyGems => format!("https://rubygems.org/gems/{package}"),
            Ecosystem::Cargo => format!("https://crates.io/crates/{package}"),
            Ecosystem::Npm => format!("https://www.npmjs.com/package/{package}"),
            Ecosystem::Go => format!("https://pkg.go.dev/{package}"),
            // `is_linkable_name` guarantees one `:`, which becomes the path separator.
            Ecosystem::Maven => format!(
                "https://central.sonatype.com/artifact/{}",
                package.replacen(':', "/", 1)
            ),
        };
        Some(url)
    }

    /// The name of the public registry, as shown in the text of the package page link.
    pub fn registry_label(self) -> &'static str {
        match self {
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Packagist => "Packagist",
            Ecosystem::Pub => "pub.dev",
            Ecosystem::NuGet => "NuGet",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::Cargo => "crates.io",
            Ecosystem::Npm => "npm",
            Ecosystem::Go => "pkg.go.dev",
            Ecosystem::Maven => "Maven Central",
        }
    }

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
            // Packagist and the NuGet flat container store names in lowercase. Only names with an uppercase letter need a copy.
            Ecosystem::Packagist | Ecosystem::NuGet if name.chars().any(char::is_uppercase) => {
                Cow::Owned(name.to_lowercase())
            }
            _ => Cow::Borrowed(name),
        }
    }

    /// Builds the request for the version list of `package`, or `None` without a registry client or for an invalid name.
    pub fn registry_request(self, package: &str) -> Option<HttpRequest> {
        if !is_valid_package_name(self, package) {
            return None;
        }
        match self {
            Ecosystem::PyPI => Some(pypi::request(package)),
            Ecosystem::Packagist => Some(packagist::request(package)),
            Ecosystem::Pub => Some(pub_dev::request(package)),
            Ecosystem::NuGet => Some(nuget::request(package)),
            Ecosystem::RubyGems => Some(rubygems::request(package)),
            _ => None,
        }
    }

    /// Reads a registry response of this ecosystem into its version list.
    pub fn parse_registry(self, body: &str) -> Result<VersionInfo, String> {
        match self {
            Ecosystem::PyPI => pypi::parse(body),
            Ecosystem::Packagist => packagist::parse(body),
            Ecosystem::Pub => pub_dev::parse(body),
            Ecosystem::NuGet => nuget::parse(body),
            Ecosystem::RubyGems => rubygems::parse(body),
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
    fn pub_has_a_registry_and_keeps_package_names() {
        let fixture = include_str!("../../tests/fixtures/dart/registry.json");
        assert_eq!(
            Ecosystem::Pub.parse_registry(fixture),
            pub_dev::parse(fixture)
        );
        assert!(matches!(
            Ecosystem::Pub.normalize_package("http"),
            Cow::Borrowed("http")
        ));
        assert_eq!(
            Ecosystem::Pub
                .registry_request("http")
                .map(|request| request.url),
            Some("https://pub.dev/api/packages/http".to_owned())
        );
    }

    #[test]
    fn nuget_lowercases_ids_and_has_a_registry() {
        assert_eq!(
            Ecosystem::NuGet.normalize_package("Newtonsoft.Json"),
            "newtonsoft.json"
        );
        assert!(matches!(
            Ecosystem::NuGet.normalize_package("newtonsoft.json"),
            Cow::Borrowed(_)
        ));
        let fixture = include_str!("../../tests/fixtures/csharp/registry.json");
        assert_eq!(
            Ecosystem::NuGet.parse_registry(fixture),
            nuget::parse(fixture)
        );
        assert!(
            Ecosystem::NuGet
                .registry_request("Newtonsoft.Json")
                .is_some()
        );
    }

    /// Ranks plain `u32` versions, where a version is a prerelease when it is odd.
    fn rank_numbers(texts: &[&str]) -> VersionInfo {
        rank_with(
            texts.iter().map(|text| (*text).to_owned()),
            |text| text.parse::<u32>().ok(),
            |version| version % 2 == 1,
        )
    }

    #[test]
    fn rank_with_drops_texts_that_do_not_parse() {
        let info = rank_numbers(&["4", "x", "2", ""]);
        assert_eq!(info.versions, ["4", "2"]);
    }

    #[test]
    fn rank_with_sorts_newest_first_and_picks_the_first_non_prerelease() {
        // 9 is an odd prerelease, so it is listed but skipped as `latest`.
        let info = rank_numbers(&["2", "9", "3", "8"]);
        assert_eq!(info.versions, ["9", "8", "3", "2"]);
        assert_eq!(info.latest.as_deref(), Some("8"));
    }

    #[test]
    fn rank_with_has_no_latest_when_only_prereleases_exist() {
        let info = rank_numbers(&["1", "3"]);
        assert_eq!(info.latest, None);
        assert_eq!(info.versions, ["3", "1"]);
    }

    #[test]
    fn rank_with_of_nothing_is_empty() {
        let info = rank_numbers(&[]);
        assert_eq!(info, VersionInfo::default());
    }

    #[test]
    fn rank_with_keeps_the_input_order_of_equal_versions() {
        let info = rank_with(
            ["b", "a", "c"].map(str::to_owned),
            |text| Some(text.len()),
            |_| false,
        );
        assert_eq!(info.versions, ["b", "a", "c"]);
    }

    #[test]
    fn rubygems_has_a_registry_and_keeps_gem_names() {
        let fixture = include_str!("../../tests/fixtures/ruby/registry.json");
        assert_eq!(
            Ecosystem::RubyGems.parse_registry(fixture),
            rubygems::parse(fixture)
        );
        assert!(matches!(
            Ecosystem::RubyGems.normalize_package("Rails"),
            Cow::Borrowed("Rails")
        ));
        assert_eq!(
            Ecosystem::RubyGems
                .registry_request("rails")
                .map(|request| request.url),
            Some("https://rubygems.org/api/v1/versions/rails.json".to_owned())
        );
    }

    /// Registry ecosystems that have a client, with one valid name each.
    const REGISTRY_ECOSYSTEMS: [Ecosystem; 5] = [
        Ecosystem::PyPI,
        Ecosystem::Packagist,
        Ecosystem::Pub,
        Ecosystem::NuGet,
        Ecosystem::RubyGems,
    ];

    #[test]
    fn valid_package_names_are_accepted_per_registry() {
        let valid_names = [
            (Ecosystem::PyPI, "requests"),
            (Ecosystem::PyPI, "Flask-Login"),
            (Ecosystem::PyPI, "ruamel.yaml"),
            (Ecosystem::PyPI, "a"),
            (Ecosystem::PyPI, "zope.interface_2"),
            (Ecosystem::Packagist, "monolog/monolog"),
            (Ecosystem::Packagist, "Symfony/Console"),
            (Ecosystem::Packagist, "a-b/c.d_e"),
            (Ecosystem::Pub, "http"),
            (Ecosystem::Pub, "flutter_bloc"),
            (Ecosystem::Pub, "Provider2"),
            (Ecosystem::NuGet, "Newtonsoft.Json"),
            (Ecosystem::NuGet, "Serilog.Sinks.File"),
            (Ecosystem::NuGet, "a-b_c"),
            (Ecosystem::RubyGems, "rails"),
            (Ecosystem::RubyGems, "aws-sdk-s3"),
            (Ecosystem::RubyGems, "net-http_2.0"),
        ];
        for (eco, name) in valid_names {
            assert!(is_valid_package_name(eco, name), "{eco:?} {name:?}");
        }
    }

    #[test]
    fn unsafe_package_names_are_rejected_by_every_registry() {
        let unsafe_names = [
            "", " ", "a b", "a\n", "é", "a?x=1", "a#frag", "a%2f", "a\\b", "..", "../x", "a/../b",
            "a:b", "a@b", "a\0b",
        ];
        for eco in REGISTRY_ECOSYSTEMS {
            for name in unsafe_names {
                assert!(!is_valid_package_name(eco, name), "{eco:?} {name:?}");
            }
            let too_long = "a".repeat(300);
            assert!(!is_valid_package_name(eco, &too_long), "{eco:?} long");
        }
    }

    #[test]
    fn registry_specific_package_name_rules_are_enforced() {
        let rejected = [
            (Ecosystem::PyPI, "-a"),
            (Ecosystem::PyPI, "a-"),
            (Ecosystem::Packagist, "monolog"),
            (Ecosystem::Packagist, "a/b/c"),
            (Ecosystem::Packagist, "/b"),
            (Ecosystem::Packagist, "a/"),
            (Ecosystem::Packagist, "./x"),
            (Ecosystem::Packagist, "a/.."),
            (Ecosystem::Pub, "a-b"),
            (Ecosystem::Pub, "a.b"),
            (Ecosystem::NuGet, ".hidden"),
            (Ecosystem::NuGet, "-x"),
            (Ecosystem::RubyGems, ".hidden"),
            (Ecosystem::RubyGems, "-x"),
        ];
        for (eco, name) in rejected {
            assert!(!is_valid_package_name(eco, name), "{eco:?} {name:?}");
        }
    }

    #[test]
    fn ecosystems_without_a_registry_client_reject_every_name() {
        assert!(!is_valid_package_name(Ecosystem::Cargo, "serde"));
    }

    #[test]
    fn registry_request_is_none_for_invalid_package_names() {
        assert!(Ecosystem::PyPI.registry_request("a/../b").is_none());
        assert!(Ecosystem::Packagist.registry_request("monolog").is_none());
        assert!(Ecosystem::Pub.registry_request("a-b").is_none());
        assert!(Ecosystem::NuGet.registry_request("x?y").is_none());
        assert!(Ecosystem::RubyGems.registry_request("x#y").is_none());
    }

    #[test]
    fn package_page_url_table() {
        let cases = [
            (
                Ecosystem::PyPI,
                "Flask_Login",
                "https://pypi.org/project/flask-login",
            ),
            (
                Ecosystem::Packagist,
                "Monolog/Monolog",
                "https://packagist.org/packages/monolog/monolog",
            ),
            (Ecosystem::Pub, "http", "https://pub.dev/packages/http"),
            (
                Ecosystem::NuGet,
                "Newtonsoft.Json",
                "https://www.nuget.org/packages/newtonsoft.json",
            ),
            (
                Ecosystem::RubyGems,
                "rails",
                "https://rubygems.org/gems/rails",
            ),
            (Ecosystem::Cargo, "serde", "https://crates.io/crates/serde"),
            (
                Ecosystem::Npm,
                "left-pad",
                "https://www.npmjs.com/package/left-pad",
            ),
            // Old npm packages can have uppercase letters in their name.
            (
                Ecosystem::Npm,
                "JSONStream",
                "https://www.npmjs.com/package/JSONStream",
            ),
            (
                Ecosystem::Npm,
                "@types/node",
                "https://www.npmjs.com/package/@types/node",
            ),
            (
                Ecosystem::Go,
                "github.com/Masterminds/semver/v3",
                "https://pkg.go.dev/github.com/Masterminds/semver/v3",
            ),
            (
                Ecosystem::Maven,
                "org.apache.commons:commons-lang3",
                "https://central.sonatype.com/artifact/org.apache.commons/commons-lang3",
            ),
        ];
        for (eco, name, expected) in cases {
            assert_eq!(
                eco.package_page_url(name).as_deref(),
                Some(expected),
                "{eco:?} {name:?}"
            );
        }
    }

    #[test]
    fn package_page_url_refuses_unsafe_names() {
        let too_long = "a".repeat(300);
        let unsafe_names = [
            "",
            "a b",
            "a)",
            "a]",
            "a?x",
            "a#x",
            "café",
            too_long.as_str(),
        ];
        for eco in Ecosystem::ALL {
            for name in unsafe_names {
                assert_eq!(eco.package_page_url(name), None, "{eco:?} {name:?}");
            }
        }
        let refused = [
            (Ecosystem::Npm, "@scope"),
            (Ecosystem::Npm, "@/x"),
            (Ecosystem::Go, "a//b"),
            (Ecosystem::Go, "a/"),
            (Ecosystem::Go, "a/../b"),
            (Ecosystem::Maven, "nocolon"),
            (Ecosystem::Maven, "a:b:c"),
            (Ecosystem::Maven, "group:"),
            (Ecosystem::Packagist, "novendor"),
        ];
        for (eco, name) in refused {
            assert_eq!(eco.package_page_url(name), None, "{eco:?} {name:?}");
        }
    }

    #[test]
    fn registry_label_table() {
        let labels = [
            (Ecosystem::PyPI, "PyPI"),
            (Ecosystem::Packagist, "Packagist"),
            (Ecosystem::Pub, "pub.dev"),
            (Ecosystem::NuGet, "NuGet"),
            (Ecosystem::RubyGems, "RubyGems"),
            (Ecosystem::Cargo, "crates.io"),
            (Ecosystem::Npm, "npm"),
            (Ecosystem::Go, "pkg.go.dev"),
            (Ecosystem::Maven, "Maven Central"),
        ];
        for (eco, label) in labels {
            assert_eq!(eco.registry_label(), label, "{eco:?}");
        }
    }

    #[test]
    fn other_ecosystems_reject_registry_bodies() {
        assert_eq!(
            Ecosystem::Cargo.parse_registry("{}"),
            Err("no registry for this ecosystem".to_string())
        );
    }
}
