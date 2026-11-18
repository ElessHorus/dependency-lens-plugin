//! Reads top-level JSON sections of `name: version` pairs with source spans.
//!
//! Shared by npm and Composer. The module holds no ecosystem rules:
//! the caller chooses the sections and the entries to skip.

use json_spanned_value::spanned;
use json_spanned_value::{Settings, Spanned, Value, from_str_with_settings};

use super::spans::LineIndex;
use crate::model::{Dependency, Span};

/// A top-level JSON object that maps package names to version strings.
pub struct JsonSection {
    /// Key of the object in the document root.
    pub key: &'static str,
    /// Whether the dependencies of this section are only used in development.
    pub dev: bool,
    /// Whether the dependencies of this section are optional.
    pub optional: bool,
}

/// Reads every section of `sections` found at the top level of the JSON document `text`.
///
/// `skip(name, version)` lets an ecosystem drop entries (aliases, platform packages)
/// before they become dependencies. Never panics; invalid JSON, a non-object root,
/// a missing or non-object section, or non-string values give no dependencies for that part.
pub fn parse_sections(
    text: &str,
    sections: &[JsonSection],
    skip: impl Fn(&str, &str) -> bool,
) -> Vec<Dependency> {
    // Duplicate keys keep the last value, as package managers do; the crate rejects them by default.
    let settings = Settings {
        allow_duplicate_keys: true,
        ..Settings::default()
    };
    let Ok(root) = from_str_with_settings::<spanned::Object>(text, &settings) else {
        return Vec::new();
    };
    let index = LineIndex::new(text);
    let mut dependencies = Vec::new();
    for section in sections {
        let Some(section_object) = root
            .get_ref()
            .get(section.key)
            .and_then(Spanned::<Value>::as_span_object)
        else {
            continue;
        };
        // The crate's map is sorted by key, so sort the entries back into document order.
        let mut entries: Vec<_> = section_object.get_ref().iter().collect();
        entries.sort_unstable_by_key(|(name, _)| name.start());
        dependencies.extend(
            entries
                .into_iter()
                .filter_map(|(name, value)| read_entry(text, &index, section, name, value, &skip)),
        );
    }
    dependencies
}

/// Builds one dependency from a `name: value` pair. Returns `None` for non-string
/// values, for skipped entries and for entries whose spans cannot be published.
fn read_entry(
    text: &str,
    index: &LineIndex<'_>,
    section: &JsonSection,
    name: &Spanned<String>,
    value: &Spanned<Value>,
    skip: &impl Fn(&str, &str) -> bool,
) -> Option<Dependency> {
    let version = value.as_span_string()?;
    let name_span = string_content_span(text, index, name.start(), name.end(), name.get_ref())?;
    let version_span =
        string_content_span(text, index, value.start(), value.end(), version.get_ref())?;
    if skip(name.get_ref(), version.get_ref()) {
        return None;
    }
    Some(Dependency {
        name: name.get_ref().clone(),
        version: version.get_ref().to_string(),
        name_span,
        version_span,
        dev: section.dev,
        optional: section.optional,
        has_additional_version_constraints: false,
        requirement: None,
    })
}

/// Returns the span of the text between the quotes of the JSON string at `start..end`.
///
/// Returns `None` when the raw text differs from `decoded`, because a JSON escape
/// makes the raw bytes differ from the value. Such a span would point at the wrong text.
fn string_content_span(
    text: &str,
    index: &LineIndex<'_>,
    start: usize,
    end: usize,
    decoded: &str,
) -> Option<Span> {
    let raw = text.get(start..end)?;
    let content = raw.strip_prefix('"')?.strip_suffix('"')?;
    if content != decoded {
        return None;
    }
    let content_start = start + 1;
    index.span(content_start, content_start + content.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::text_of_span;

    const SECTIONS: [JsonSection; 2] = [
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
    ];

    fn keep_all(_name: &str, _version: &str) -> bool {
        false
    }

    fn names_and_versions(dependencies: &[Dependency]) -> Vec<(&str, &str)> {
        dependencies
            .iter()
            .map(|dependency| (dependency.name.as_str(), dependency.version.as_str()))
            .collect()
    }

    #[test]
    fn duplicate_key_keeps_last_value_and_its_span() {
        let text = "{\"dependencies\": {\"a\": \"1.0.0\",\n\"a\": \"2.0.0\"}}";
        let dependencies = parse_sections(text, &SECTIONS, keep_all);
        assert_eq!(names_and_versions(&dependencies), [("a", "2.0.0")]);
        let version_span = dependencies[0].version_span;
        assert_eq!(version_span.line, 1);
        assert_eq!(text_of_span(text, version_span).as_deref(), Some("2.0.0"));
    }

    #[test]
    fn non_object_roots_and_empty_objects_give_nothing() {
        for text in ["[]", "\"x\"", "{}", "{\"dependencies\": []}", ""] {
            assert!(
                parse_sections(text, &SECTIONS, keep_all).is_empty(),
                "{text}"
            );
        }
    }

    #[test]
    fn invalid_json_gives_nothing() {
        assert!(parse_sections("{\"dependencies\": {", &SECTIONS, keep_all).is_empty());
    }

    #[test]
    fn non_string_values_are_skipped_without_affecting_neighbours() {
        let text = "{\"dependencies\": {\"a\": 1, \"b\": {\"version\": \"1\"}, \"c\": \"2.0.0\"}}";
        let dependencies = parse_sections(text, &SECTIONS, keep_all);
        assert_eq!(names_and_versions(&dependencies), [("c", "2.0.0")]);
    }

    #[test]
    fn skip_closure_is_honoured() {
        let text = "{\"dependencies\": {\"a\": \"1\", \"b\": \"2\"}}";
        let dependencies = parse_sections(text, &SECTIONS, |name, _version| name == "a");
        assert_eq!(names_and_versions(&dependencies), [("b", "2")]);
    }

    #[test]
    fn escaped_key_or_value_is_skipped() {
        let text =
            "{\"dependencies\": {\"caf\\u00e9\": \"1\", \"b\": \"1\\u002e0\", \"c\": \"3\"}}";
        let dependencies = parse_sections(text, &SECTIONS, keep_all);
        assert_eq!(names_and_versions(&dependencies), [("c", "3")]);
    }

    #[test]
    fn sections_follow_the_slice_order_and_entries_follow_document_order() {
        let text =
            "{\"devDependencies\": {\"b\": \"1\"}, \"dependencies\": {\"z\": \"1\", \"a\": \"2\"}}";
        let dependencies = parse_sections(text, &SECTIONS, keep_all);
        assert_eq!(
            names_and_versions(&dependencies),
            [("z", "1"), ("a", "2"), ("b", "1")]
        );
        assert!(!dependencies[0].dev);
        assert!(dependencies[2].dev);
    }

    #[test]
    fn missing_section_gives_nothing_for_that_section() {
        let text = "{\"devDependencies\": {\"b\": \"1\"}}";
        let dependencies = parse_sections(text, &SECTIONS, keep_all);
        assert_eq!(names_and_versions(&dependencies), [("b", "1")]);
    }

    #[test]
    fn spans_of_a_key_with_non_ascii_text_are_utf16_correct() {
        let text = "{\"dependencies\": {\"ü\": \"1.0.0\"}}";
        let dependencies = parse_sections(text, &SECTIONS, keep_all);
        let dependency = &dependencies[0];
        assert_eq!(
            text_of_span(text, dependency.name_span).as_deref(),
            Some("ü")
        );
        assert_eq!(
            text_of_span(text, dependency.version_span).as_deref(),
            Some("1.0.0")
        );
    }
}
