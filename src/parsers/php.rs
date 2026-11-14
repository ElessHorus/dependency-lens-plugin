//! Parser for Composer `composer.json` dependency sections.
//!
//! Platform requirements such as `php`, `ext-json` and `lib-curl` name no Packagist
//! package. They contain no `/`, so they are skipped. Dev branches, wildcards, stability
//! flags and ranges are kept. `declared_version_for_osv` filters them before any lookup.

use serde::Deserialize;
use serde_json::Value;

use super::json_spans::{JsonSection, parse_sections};
use crate::model::Dependency;

/// URLs that name the public Packagist repository.
const PUBLIC_REPOSITORY_URLS: [&str; 2] = ["https://repo.packagist.org", "https://packagist.org"];

/// The part of `composer.json` that decides whether the packages are public.
#[derive(Deserialize)]
struct Manifest {
    repositories: Option<Value>,
}

/// Dependency sections that Composer reads, with their dev flags.
const SECTIONS: [JsonSection; 2] = [
    JsonSection {
        key: "require",
        dev: false,
        optional: false,
    },
    JsonSection {
        key: "require-dev",
        dev: true,
        optional: false,
    },
];

/// Returns `true` when a `repositories` entry cannot serve a private package.
///
/// An entry such as `{"packagist.org": false}` only turns a repository off. A
/// `composer` repository counts when its URL is the public Packagist one.
fn is_public_repository(repository: &Value) -> bool {
    match repository {
        Value::Bool(false) => true,
        Value::Object(fields) if fields.contains_key("type") => {
            fields.get("type").and_then(Value::as_str) == Some("composer")
                && fields
                    .get("url")
                    .and_then(Value::as_str)
                    .is_some_and(|url| PUBLIC_REPOSITORY_URLS.contains(&url.trim_end_matches('/')))
        }
        Value::Object(fields) => fields.values().all(|value| *value == Value::Bool(false)),
        _ => false,
    }
}

/// Returns `true` when the manifest lists a repository that may hold private packages.
///
/// The `repositories` key is an array or an object of named repositories. Composer
/// searches them before Packagist, so any package name may come from one of them.
fn has_private_repository(text: &str) -> bool {
    // Most manifests have no `repositories` key, so the extra parse is skipped for them.
    if !text.contains("\"repositories\"") {
        return false;
    }
    let Ok(Manifest {
        repositories: Some(repositories),
    }) = serde_json::from_str(text)
    else {
        return false;
    };
    match &repositories {
        Value::Array(entries) => !entries.iter().all(is_public_repository),
        Value::Object(named_entries) => !named_entries.values().all(is_public_repository),
        _ => false,
    }
}

/// Parses the dependencies of a `composer.json` manifest.
///
/// A manifest with a repository other than Packagist returns nothing, because any
/// of its packages may be private.
pub fn parse(text: &str) -> Vec<Dependency> {
    if has_private_repository(text) {
        return Vec::new();
    }
    parse_sections(text, &SECTIONS, |name, _version| !name.contains('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::text_of_span;

    const FIXTURE: &str = include_str!("../../tests/fixtures/php/composer.json");

    #[test]
    fn returns_exact_entries_in_section_then_document_order() {
        let dependencies = parse(FIXTURE);
        let entries: Vec<(&str, &str, bool)> = dependencies
            .iter()
            .map(|dependency| {
                (
                    dependency.name.as_str(),
                    dependency.version.as_str(),
                    dependency.dev,
                )
            })
            .collect();
        assert_eq!(
            entries,
            [
                ("monolog/monolog", "^3.0", false),
                ("symfony/console", "~6.2", false),
                ("foo/dev", "dev-main", false),
                ("bar/alias", "dev-main as 1.0.x-dev", false),
                ("baz/stable", "1.2.*", false),
                ("qux/flag", "^1.0@dev", false),
                ("phpunit/phpunit", "^10.0", true),
            ]
        );
    }

    #[test]
    fn skips_platform_requirements_and_other_sections() {
        let dependencies = parse(FIXTURE);
        for omitted in [
            "php",
            "ext-json",
            "lib-curl",
            "composer-plugin-api",
            "acme/old",
            "ext-redis",
            "Acme\\Demo\\",
        ] {
            assert!(
                dependencies
                    .iter()
                    .all(|dependency| dependency.name != omitted),
                "{omitted} must not be returned"
            );
        }
    }

    #[test]
    fn name_and_version_spans_point_at_inner_text() {
        let dependencies = parse(FIXTURE);
        let monolog = dependencies
            .iter()
            .find(|dependency| dependency.name == "monolog/monolog")
            .expect("monolog dependency");
        assert_eq!(
            text_of_span(FIXTURE, monolog.version_span).as_deref(),
            Some("^3.0")
        );
        assert_eq!(
            text_of_span(FIXTURE, monolog.name_span).as_deref(),
            Some("monolog/monolog")
        );
    }

    #[test]
    fn spans_are_correct_with_crlf_line_endings() {
        let crlf_text = FIXTURE.replace('\n', "\r\n");
        let dependencies = parse(&crlf_text);
        assert_eq!(dependencies, parse(FIXTURE));
        let phpunit = dependencies
            .iter()
            .find(|dependency| dependency.name == "phpunit/phpunit")
            .expect("phpunit dependency");
        assert_eq!(
            text_of_span(&crlf_text, phpunit.version_span).as_deref(),
            Some("^10.0")
        );
    }

    #[test]
    fn a_private_repository_hides_every_package() {
        for repositories in [
            r#"[{"type": "path", "url": "../internal"}]"#,
            r#"[{"type": "vcs", "url": "https://git.example.com/acme/internal.git"}]"#,
            r#"[{"type": "composer", "url": "https://packages.example.com"}]"#,
            r#"{"private": {"type": "composer", "url": "https://packages.example.com"}}"#,
            r#"[{"type": "artifact", "url": "artifacts"}]"#,
            r#"["not-a-repository"]"#,
        ] {
            let manifest = format!(
                r#"{{"repositories": {repositories}, "require": {{"acme/internal": "^1.0"}}}}"#
            );
            assert!(
                parse(&manifest).is_empty(),
                "{repositories} must hide the file"
            );
        }
    }

    #[test]
    fn public_packagist_repositories_do_not_hide_the_packages() {
        for repositories in [
            r#"[{"packagist.org": false}]"#,
            r#"{"packagist.org": false}"#,
            r#"[{"type": "composer", "url": "https://repo.packagist.org/"}]"#,
            r#"[]"#,
        ] {
            let manifest = format!(
                r#"{{"repositories": {repositories}, "require": {{"monolog/monolog": "^3.0"}}}}"#
            );
            assert_eq!(
                parse(&manifest).len(),
                1,
                "{repositories} must keep the file"
            );
        }
    }

    #[test]
    fn invalid_manifest_returns_empty() {
        assert!(parse("{\"require\": {").is_empty());
    }
}
