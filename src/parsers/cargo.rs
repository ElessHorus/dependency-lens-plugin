//! Parser for `Cargo.toml` dependency tables.
//!
//! Reads `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, the
//! same tables under `[target.<cfg>]`, and `[workspace.dependencies]`. Entries
//! without a registry version (`path`, `git`, `workspace = true`) are skipped.

use taplo::dom::Node;
use taplo::dom::node::{Bool, DomNode, Key, Str};
use taplo::rowan::{TextRange, TextSize};
use taplo::syntax::SyntaxElement;

use crate::model::{Dependency, Span};

/// Dependency tables that Cargo reads under the root or under a `[target.<cfg>]`, with a dev flag.
const DEPENDENCY_SECTIONS: [(&str, bool); 3] = [
    ("dependencies", false),
    ("dev-dependencies", true),
    ("build-dependencies", false),
];

/// Parses the dependencies of a `Cargo.toml` manifest.
///
/// Returns an empty vector when the manifest has any syntax error. A
/// half-typed manifest would otherwise yield a misleading partial DOM.
pub fn parse(text: &str) -> Vec<Dependency> {
    let parsed = taplo::parser::parse(text);
    if !parsed.errors.is_empty() {
        return Vec::new();
    }
    let line_ranges = line_ranges(text);
    let dom = parsed.into_dom();
    let mut dependencies = Vec::new();

    collect_section_deps(&dom, &line_ranges, &mut dependencies);

    let target_node = dom.get("target");
    if let Some(target_table) = target_node.as_table() {
        let targets = target_table.entries().read();
        for (_, cfg_node) in targets.iter() {
            collect_section_deps(cfg_node, &line_ranges, &mut dependencies);
        }
    }

    let workspace_node = dom.get("workspace");
    collect_table_deps(
        &workspace_node.get("dependencies"),
        false,
        &line_ranges,
        &mut dependencies,
    );

    dependencies
}

/// Returns the byte range of each line, excluding its `\n` or `\r\n` terminator.
///
/// Built once per parse so that every span lookup is a binary search.
fn line_ranges(text: &str) -> Box<[TextRange]> {
    let mut line_start: usize = 0;
    text.split_inclusive('\n')
        .map(|line| {
            let content_len = line.trim_end_matches(['\r', '\n']).len();
            let range = TextRange::at(
                TextSize::from(line_start as u32),
                TextSize::from(content_len as u32),
            );
            line_start += line.len();
            range
        })
        .collect()
}

/// Parses every [`DEPENDENCY_SECTIONS`] table that sits directly under `container`.
fn collect_section_deps(container: &Node, line_ranges: &[TextRange], out: &mut Vec<Dependency>) {
    for (section_name, is_dev) in DEPENDENCY_SECTIONS {
        collect_table_deps(&container.get(section_name), is_dev, line_ranges, out);
    }
}

/// Appends the dependencies of one table node. Ignores nodes that are not tables.
fn collect_table_deps(
    section: &Node,
    is_dev: bool,
    line_ranges: &[TextRange],
    out: &mut Vec<Dependency>,
) {
    let Some(table) = section.as_table() else {
        return;
    };
    let entries = table.entries().read();
    out.extend(
        entries
            .iter()
            .filter_map(|(key, value)| parse_dependency(key, value, line_ranges, is_dev)),
    );
}

/// Parses one entry, in the simple form or in the inline or sub-table form.
fn parse_dependency(
    key: &Key,
    node: &Node,
    line_ranges: &[TextRange],
    is_dev: bool,
) -> Option<Dependency> {
    match node {
        // Simple form: `name = "1.0"`.
        Node::Str(version) => build_dependency(key, None, version, false, line_ranges, is_dev),
        // Inline table `name = { version = "1.0" }` or sub-table `[dependencies.name]`.
        Node::Table(table) => {
            // A path or git source has no registry version to check.
            if table.get("path").is_some() || table.get("git").is_some() {
                return None;
            }
            let version_node = table.get("version")?;
            let version = version_node.as_str()?;
            let package_node = table.get("package");
            let package = package_node.as_ref().and_then(Node::as_str);
            let optional_node = table.get("optional");
            let optional = optional_node
                .as_ref()
                .and_then(Node::as_bool)
                .is_some_and(Bool::value);
            build_dependency(key, package, version, optional, line_ranges, is_dev)
        }
        _ => None,
    }
}

/// Builds a [`Dependency`] and resolves the spans of its name and version.
///
/// A `package = "..."` alias replaces the key as the registry name.
fn build_dependency(
    key: &Key,
    package: Option<&Str>,
    version: &Str,
    optional: bool,
    line_ranges: &[TextRange],
    is_dev: bool,
) -> Option<Dependency> {
    let name_range = match package {
        Some(package) => quoted_content_range(package.syntax()?)?,
        None => key_content_range(key)?,
    };
    let version_range = quoted_content_range(version.syntax()?)?;
    Some(Dependency {
        name: package.map_or_else(|| key.value(), Str::value).to_owned(),
        version: version.value().to_owned(),
        name_span: find_span(line_ranges, name_range)?,
        version_span: find_span(line_ranges, version_range)?,
        dev: is_dev,
        optional,
        has_additional_version_constraints: false,
    })
}

/// Returns the range of a key, without its quotes when the key is quoted.
fn key_content_range(key: &Key) -> Option<TextRange> {
    let element = key.syntax()?;
    let token = element.as_token()?;
    let range = token.text_range();
    if token.text().starts_with(['"', '\'']) {
        strip_one_byte_each_side(range)
    } else {
        Some(range)
    }
}

/// Returns the range of a quoted string token, without its quote characters.
fn quoted_content_range(element: &SyntaxElement) -> Option<TextRange> {
    strip_one_byte_each_side(element.text_range())
}

/// Shrinks a range by one byte at each end. Returns `None` if the range is too short.
fn strip_one_byte_each_side(range: TextRange) -> Option<TextRange> {
    let one = TextSize::from(1);
    let inner_start = range.start().checked_add(one)?;
    let inner_end = range.end().checked_sub(one)?;
    (inner_start <= inner_end).then(|| TextRange::new(inner_start, inner_end))
}

/// Finds the line that holds `needle` and returns its span.
///
/// Returns `None` when `needle` crosses a line break.
fn find_span(line_ranges: &[TextRange], needle: TextRange) -> Option<Span> {
    let line_index = line_ranges
        .binary_search_by(|line_range| line_range.ordering(needle))
        .ok()?;
    let line_range = line_ranges[line_index];
    if needle.start() < line_range.start() || needle.end() > line_range.end() {
        return None;
    }
    let base = line_range.start();
    Some(Span {
        line: u32::try_from(line_index).ok()?,
        line_start: (needle.start() - base).into(),
        line_end: (needle.end() - base).into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::to_range;
    use openidea_plugin::Document;

    const FIXTURE: &str = include_str!("../../tests/fixtures/cargo/Cargo.toml");

    fn find<'a>(dependencies: &'a [Dependency], name: &str) -> &'a Dependency {
        dependencies
            .iter()
            .find(|dependency| dependency.name == name)
            .unwrap_or_else(|| panic!("missing dependency {name}"))
    }

    #[test]
    fn parses_string_dependency() {
        let dependencies = parse(FIXTURE);
        let serde = find(&dependencies, "serde");
        assert_eq!(serde.version, "1.0");
        assert!(!serde.dev);
    }

    #[test]
    fn parses_inline_table_version() {
        let dependencies = parse(FIXTURE);
        assert_eq!(find(&dependencies, "tokio").version, "1");
    }

    #[test]
    fn marks_dev_dependencies() {
        let dependencies = parse(FIXTURE);
        assert!(find(&dependencies, "tempfile").dev);
    }

    #[test]
    fn keeps_build_dependencies_as_normal() {
        let dependencies = parse(FIXTURE);
        assert!(!find(&dependencies, "cc").dev);
    }

    #[test]
    fn finds_target_specific_dependencies() {
        let dependencies = parse(FIXTURE);
        assert_eq!(find(&dependencies, "libc").version, "0.2");
    }

    #[test]
    fn finds_workspace_dependencies() {
        let dependencies = parse(FIXTURE);
        assert_eq!(find(&dependencies, "anyhow").version, "1.0");
    }

    #[test]
    fn finds_sub_table_dependencies() {
        let dependencies = parse(FIXTURE);
        assert_eq!(find(&dependencies, "reqwest").version, "0.12");
    }

    #[test]
    fn sets_optional_flag() {
        let dependencies = parse(FIXTURE);
        assert!(find(&dependencies, "optional-dep").optional);
        assert!(!find(&dependencies, "serde").optional);
    }

    #[test]
    fn skips_path_git_and_workspace_inherited_dependencies() {
        let dependencies = parse(FIXTURE);
        for skipped in ["local", "g", "serde-workspace"] {
            assert!(
                dependencies
                    .iter()
                    .all(|dependency| dependency.name != skipped),
                "{skipped} must not be returned"
            );
        }
    }

    #[test]
    fn version_span_points_at_inner_text_after_non_ascii_key() {
        let dependencies = parse(FIXTURE);
        let unicode = find(&dependencies, "ünï");
        let document = Document {
            version: 1,
            text: FIXTURE.to_owned(),
        };
        let range = to_range(FIXTURE, unicode.version_span).unwrap();
        assert_eq!(document.text_in(range), Some("1.0"));
    }

    #[test]
    fn name_span_points_at_inner_text_of_quoted_key() {
        let dependencies = parse(FIXTURE);
        let unicode = find(&dependencies, "ünï");
        let document = Document {
            version: 1,
            text: FIXTURE.to_owned(),
        };
        let range = to_range(FIXTURE, unicode.name_span).unwrap();
        assert_eq!(document.text_in(range), Some("ünï"));
    }

    #[test]
    fn malformed_toml_returns_empty() {
        assert!(parse("[dependencies\nserde = \"1.0\"\n").is_empty());
        assert!(parse("\u{0}= \"").is_empty());
        assert!(parse("").is_empty());
    }
}
