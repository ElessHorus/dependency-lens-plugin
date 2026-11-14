//! Parser for npm `package.json` dependency sections.
//!
//! npm aliases (`npm:` prefix) are skipped because they name another package.
//! Other specs, such as `file:`, `workspace:` and URLs, are kept. They have no
//! registry version, so `declared_version_for_osv` filters them out before any lookup.

use super::json_spans::{JsonSection, parse_sections};
use crate::model::Dependency;

/// Dependency sections that npm reads, with their dev and optional flags.
const SECTIONS: [JsonSection; 4] = [
    JsonSection {
        key: "dependencies",
        dev: false,
        optional: false,
    },
    JsonSection {
        key: "devDependencies",
        dev: true,
        optional: false,
    },
    JsonSection {
        key: "peerDependencies",
        dev: false,
        optional: true,
    },
    JsonSection {
        key: "optionalDependencies",
        dev: false,
        optional: true,
    },
];

/// Parses the dependencies of a `package.json` manifest.
pub fn parse(text: &str) -> Vec<Dependency> {
    parse_sections(text, &SECTIONS, |_name, version| {
        version.starts_with("npm:")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::text_of_span;

    const FIXTURE: &str = include_str!("../../tests/fixtures/npm/package.json");

    fn find<'a>(dependencies: &'a [Dependency], name: &str) -> &'a Dependency {
        dependencies
            .iter()
            .find(|dependency| dependency.name == name)
            .unwrap_or_else(|| panic!("missing dependency {name}"))
    }

    #[test]
    fn returns_exact_entries_in_section_then_document_order() {
        let dependencies = parse(FIXTURE);
        let entries: Vec<(&str, &str, bool, bool)> = dependencies
            .iter()
            .map(|dependency| {
                (
                    dependency.name.as_str(),
                    dependency.version.as_str(),
                    dependency.dev,
                    dependency.optional,
                )
            })
            .collect();
        assert_eq!(
            entries,
            [
                ("left-pad", "^1.3.0", false, false),
                ("@scope/pkg", "~2.1.0", false, false),
                ("ünï", "1.0.0", false, false),
                ("local", "file:../local", false, false),
                ("mono", "workspace:*", false, false),
                ("gh", "user/repo", false, false),
                ("git", "git+https://github.com/x/y.git", false, false),
                ("jest", "29.7.0", true, false),
                ("react", ">=17 <19", false, true),
                ("fsevents", "2.3.3", false, true),
            ]
        );
    }

    #[test]
    fn omits_aliases_escaped_keys_and_overrides() {
        let dependencies = parse(FIXTURE);
        for omitted in ["my-alias", "café", "caf\\u00e9", "minimist"] {
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
        let left_pad = find(&dependencies, "left-pad");
        assert_eq!(
            text_of_span(FIXTURE, left_pad.version_span).as_deref(),
            Some("^1.3.0")
        );
        assert_eq!(
            text_of_span(FIXTURE, left_pad.name_span).as_deref(),
            Some("left-pad")
        );
    }

    #[test]
    fn span_after_non_ascii_key_is_utf16_correct() {
        let dependencies = parse(FIXTURE);
        let unicode = find(&dependencies, "ünï");
        assert_eq!(
            text_of_span(FIXTURE, unicode.version_span).as_deref(),
            Some("1.0.0")
        );
    }

    #[test]
    fn spans_are_correct_with_crlf_line_endings() {
        let crlf_text = FIXTURE.replace('\n', "\r\n");
        let dependencies = parse(&crlf_text);
        let left_pad = find(&dependencies, "left-pad");
        assert_eq!(
            text_of_span(&crlf_text, left_pad.version_span).as_deref(),
            Some("^1.3.0")
        );
        assert_eq!(
            text_of_span(&crlf_text, left_pad.name_span).as_deref(),
            Some("left-pad")
        );
        let unicode = find(&dependencies, "ünï");
        assert_eq!(
            text_of_span(&crlf_text, unicode.version_span).as_deref(),
            Some("1.0.0")
        );
    }

    #[test]
    fn invalid_manifest_returns_empty() {
        assert!(parse("{\"dependencies\": {").is_empty());
    }
}
