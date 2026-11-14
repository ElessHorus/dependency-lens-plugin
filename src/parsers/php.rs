//! Parser for Composer `composer.json` dependency sections.
//!
//! Platform requirements such as `php`, `ext-json` and `lib-curl` name no Packagist
//! package. They contain no `/`, so they are skipped. Dev branches, wildcards, stability
//! flags and ranges are kept. `declared_version_for_osv` filters them before any lookup.

use super::json_spans::{JsonSection, parse_sections};
use crate::model::Dependency;

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

/// Parses the dependencies of a `composer.json` manifest.
pub fn parse(text: &str) -> Vec<Dependency> {
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
    fn invalid_manifest_returns_empty() {
        assert!(parse("{\"require\": {").is_empty());
    }
}
