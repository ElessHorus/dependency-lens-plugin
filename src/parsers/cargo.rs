//! Parser for `Cargo.toml` dependency tables.
//!
//! Reads `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, the
//! same tables under `[target.<cfg>]`, and `[workspace.dependencies]`. Entries
//! without a crates.io version (`path`, `git`, `registry`, `workspace = true`) are skipped.

use taplo::dom::Node;
use taplo::dom::node::{Bool, DomNode, Key, Str};
use taplo::rowan::{TextRange, TextSize};
use taplo::syntax::SyntaxElement;

use super::spans::LineIndex;
use crate::model::Dependency;

/// Dependency tables that Cargo reads under the root or under a `[target.<cfg>]`, with a dev flag.
const DEPENDENCY_SECTIONS: [(&str, bool); 3] = [
    ("dependencies", false),
    ("dev-dependencies", true),
    ("build-dependencies", false),
];

/// Keys that make an entry come from a source other than crates.io.
const NON_REGISTRY_KEYS: [&str; 4] = ["path", "git", "registry", "registry-index"];

/// Parses the dependencies of a `Cargo.toml` manifest.
///
/// Returns an empty vector when the manifest has any syntax error. A
/// half-typed manifest would otherwise yield a misleading partial DOM.
pub fn parse(text: &str) -> Vec<Dependency> {
    let parsed = taplo::parser::parse(text);
    if !parsed.errors.is_empty() {
        return Vec::new();
    }
    let index = LineIndex::new(text);
    let dom = parsed.into_dom();
    let mut dependencies = Vec::new();

    collect_section_deps(&dom, &index, &mut dependencies);

    let target_node = dom.get("target");
    if let Some(target_table) = target_node.as_table() {
        let targets = target_table.entries().read();
        for (_, cfg_node) in targets.iter() {
            collect_section_deps(cfg_node, &index, &mut dependencies);
        }
    }

    let workspace_node = dom.get("workspace");
    collect_table_deps(
        &workspace_node.get("dependencies"),
        false,
        &index,
        &mut dependencies,
    );

    dependencies
}

/// Parses every [`DEPENDENCY_SECTIONS`] table that sits directly under `container`.
fn collect_section_deps(container: &Node, index: &LineIndex<'_>, out: &mut Vec<Dependency>) {
    for (section_name, is_dev) in DEPENDENCY_SECTIONS {
        collect_table_deps(&container.get(section_name), is_dev, index, out);
    }
}

/// Appends the dependencies of one table node. Ignores nodes that are not tables.
fn collect_table_deps(
    section: &Node,
    is_dev: bool,
    index: &LineIndex<'_>,
    out: &mut Vec<Dependency>,
) {
    let Some(table) = section.as_table() else {
        return;
    };
    let entries = table.entries().read();
    out.extend(
        entries
            .iter()
            .filter_map(|(key, value)| parse_dependency(key, value, index, is_dev)),
    );
}

/// Parses one entry, in the simple form or in the inline or sub-table form.
fn parse_dependency(
    key: &Key,
    node: &Node,
    index: &LineIndex<'_>,
    is_dev: bool,
) -> Option<Dependency> {
    match node {
        // Simple form: `name = "1.0"`.
        Node::Str(version) => build_dependency(key, None, version, false, index, is_dev),
        // Inline table `name = { version = "1.0" }` or sub-table `[dependencies.name]`.
        Node::Table(table) => {
            // A path, git or alternative registry source has no crates.io version to check.
            if NON_REGISTRY_KEYS
                .iter()
                .any(|source_key| table.get(*source_key).is_some())
            {
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
            build_dependency(key, package, version, optional, index, is_dev)
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
    index: &LineIndex<'_>,
    is_dev: bool,
) -> Option<Dependency> {
    let name_range = match package {
        Some(package) => quoted_content_range(package.syntax()?)?,
        None => key_content_range(key)?,
    };
    let version_range = quoted_content_range(version.syntax()?)?;
    // A span must cover the value itself. An escape sequence or a multi-line quote makes the
    // source text differ from the value, so such an entry is not returned.
    let source_text = index.text();
    let name_value = package.map_or_else(|| key.value(), Str::value);
    if source_text.get(usize::from(name_range.start())..usize::from(name_range.end()))
        != Some(name_value)
        || source_text.get(usize::from(version_range.start())..usize::from(version_range.end()))
            != Some(version.value())
    {
        return None;
    }
    Some(Dependency {
        name: package.map_or_else(|| key.value(), Str::value).to_owned(),
        version: version.value().to_owned(),
        name_span: index.span(
            usize::from(name_range.start()),
            usize::from(name_range.end()),
        )?,
        version_span: index.span(
            usize::from(version_range.start()),
            usize::from(version_range.end()),
        )?,
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

    #[test]
    fn skips_dependencies_from_an_alternative_registry() {
        let manifest = "\
[dependencies]
by_name = { version = \"1.0\", registry = \"corp\" }
by_index = { version = \"1.0\", registry-index = \"sparse+https://cargo.example.com/\" }
serde = \"1.0\"

[dependencies.sub_table]
version = \"2.0\"
registry = \"corp\"
";
        let dependencies = parse(manifest);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name, "serde");
    }

    #[test]
    fn strings_whose_source_text_differs_from_their_value_are_not_returned() {
        // An escape or a multi-line quote would make the span point at text that is not the value.
        let manifest = "[dependencies]\n\"caf\\u00e9\" = \"1.0\"\nescaped = \"1\\u002e0\"\nliteral = '''2.0'''\nplain = \"3.0\"\n";
        let dependencies = parse(manifest);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name, "plain");
        assert_eq!(
            to_range(manifest, dependencies[0].version_span).map(|range| range.start.character),
            Some(9)
        );
    }
}
