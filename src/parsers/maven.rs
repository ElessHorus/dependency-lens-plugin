//! Parser for Maven `pom.xml` dependency declarations.
//!
//! Reads `<dependency>` entries under `<dependencies>` in one streaming pass.
//! Plugin dependencies, reporting sections, `system` scope entries (local JARs)
//! and entries without a literal or resolvable version are not returned. Parent POMs, profiles and BOM imports
//! are not resolved.

use std::collections::HashMap;

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use super::spans::LineIndex;
use super::xml_text::{Field, byte_offset, element_name, read_field};
use crate::model::Dependency;

/// Elements whose `<dependency>` children belong to build tools, not to the project.
const EXCLUDED_SECTIONS: [&str; 3] = ["plugin", "plugins", "reporting"];

/// A child of `<dependency>` whose text the parser reads.
#[derive(Clone, Copy)]
enum FieldKind {
    GroupId,
    ArtifactId,
    Version,
    Scope,
    Optional,
}

/// What the text of the currently open element is used for.
#[derive(Clone, Copy)]
enum Capture<'a> {
    Field(FieldKind),
    Property(&'a str),
}

/// An element whose text is read when its end tag arrives.
#[derive(Clone, Copy)]
struct OpenCapture<'a> {
    target: Capture<'a>,
    /// Length of the element stack while the element is open.
    depth: usize,
    /// Byte offset just after the start tag.
    content_start: usize,
}

/// The fields of a `<dependency>` read so far. Invalid fields stay `None`.
#[derive(Default)]
struct PendingDependency<'a> {
    group_id: Option<Field<'a>>,
    artifact_id: Option<Field<'a>>,
    version: Option<Field<'a>>,
    scope: Option<Field<'a>>,
    optional: Option<Field<'a>>,
}

/// Parses the dependencies of a `pom.xml` manifest. Never panics.
///
/// Reads the document once. Each `<version>` placeholder that names a property
/// is resolved after the pass, so a property may be declared after its use.
pub fn parse(text: &str) -> Vec<Dependency> {
    let index = LineIndex::new(text);
    let mut reader = Reader::from_str(text);
    // Names of the open elements, sliced from `text` so they live as long as the input.
    let mut stack: Vec<&str> = Vec::new();
    let mut excluded_depth = 0_usize;
    let mut open_capture: Option<OpenCapture> = None;
    // Stack length while the dependency is open, with its fields read so far.
    let mut dependency: Option<(usize, PendingDependency)> = None;
    let mut dependencies: Vec<Dependency> = Vec::new();
    let mut properties: HashMap<&str, &str> = HashMap::new();
    // Dependencies whose version is a `${name}` placeholder, with the property name.
    let mut placeholders: Vec<(usize, &str)> = Vec::new();

    // Events are contiguous, so the reader position before a read is where that event starts.
    while let Some(event_start) = byte_offset(reader.buffer_position()) {
        let Ok(event) = reader.read_event() else {
            break;
        };
        match event {
            Event::Start(start) => {
                let Some(name) = element_name(text, event_start + 1, start.name()) else {
                    break;
                };
                let Some(content_start) = byte_offset(reader.buffer_position()) else {
                    break;
                };
                let depth_before = stack.len();
                if open_capture.is_none() {
                    if let Some((dependency_depth, _)) = &dependency
                        && depth_before == *dependency_depth
                        && let Some(kind) = field_kind(name)
                    {
                        open_capture = Some(OpenCapture {
                            target: Capture::Field(kind),
                            depth: depth_before + 1,
                            content_start,
                        });
                    } else if dependency.is_none() && stack.as_slice() == ["project", "properties"]
                    {
                        open_capture = Some(OpenCapture {
                            target: Capture::Property(name),
                            depth: depth_before + 1,
                            content_start,
                        });
                    }
                }
                if name == "dependency"
                    && dependency.is_none()
                    && excluded_depth == 0
                    && stack.last() == Some(&"dependencies")
                {
                    dependency = Some((depth_before + 1, PendingDependency::default()));
                }
                if EXCLUDED_SECTIONS.contains(&name) {
                    excluded_depth += 1;
                }
                stack.push(name);
            }
            Event::End(end) => {
                let depth = stack.len();
                if let Some(capture) = open_capture.filter(|capture| capture.depth == depth) {
                    open_capture = None;
                    let value = read_field(text, &index, capture.content_start, event_start);
                    match capture.target {
                        Capture::Field(kind) => {
                            if let Some((_, pending)) = dependency.as_mut() {
                                *field_slot(pending, kind) = value;
                            }
                        }
                        Capture::Property(property_name) => {
                            if let Some(field) = value {
                                properties.insert(property_name, field.text);
                            }
                        }
                    }
                }
                let closes_dependency = end.name().0 == "dependency"
                    && dependency
                        .as_ref()
                        .is_some_and(|(dependency_depth, _)| *dependency_depth == depth);
                if closes_dependency
                    && let Some((_, pending)) = dependency.take()
                    && let Some((entry, property)) = build_dependency(pending)
                {
                    if let Some(property_name) = property {
                        placeholders.push((dependencies.len(), property_name));
                    }
                    dependencies.push(entry);
                }
                if let Some(popped) = stack.pop()
                    && EXCLUDED_SECTIONS.contains(&popped)
                {
                    excluded_depth -= 1;
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    // Resolve placeholders last so that properties declared after a dependency still apply.
    for (dependency_index, property) in placeholders {
        let Some(value) = properties.get(property) else {
            continue;
        };
        if value.starts_with("${") {
            continue;
        }
        if let Some(entry) = dependencies.get_mut(dependency_index) {
            entry.version = (*value).to_owned();
        }
    }
    dependencies
}

/// Builds a dependency from its fields. Returns the property name as well when the
/// version is a `${name}` placeholder, so the caller can resolve it after the pass.
///
/// Returns `None` when a coordinate or the version is missing or invalid, or when
/// a coordinate holds a placeholder such as `${project.groupId}`.
fn build_dependency(pending: PendingDependency<'_>) -> Option<(Dependency, Option<&'_ str>)> {
    let group = pending.group_id?;
    let artifact = pending.artifact_id?;
    let version = pending.version?;
    if group.text.contains("${") || artifact.text.contains("${") {
        return None;
    }
    // A system-scope dependency is a local JAR, so no registry holds it.
    if pending.scope.is_some_and(|scope| scope.text == "system") {
        return None;
    }
    let dependency = Dependency {
        name: format!("{}:{}", group.text, artifact.text),
        version: version.text.to_owned(),
        name_span: artifact.span,
        version_span: version.span,
        dev: pending.scope.is_some_and(|scope| scope.text == "test"),
        optional: pending.optional.is_some_and(|flag| flag.text == "true"),
        has_additional_version_constraints: version.text.contains("${"),
    };
    Some((dependency, placeholder_property(version.text)))
}

/// Maps a `<dependency>` child name to the field it fills.
fn field_kind(name: &str) -> Option<FieldKind> {
    match name {
        "groupId" => Some(FieldKind::GroupId),
        "artifactId" => Some(FieldKind::ArtifactId),
        "version" => Some(FieldKind::Version),
        "scope" => Some(FieldKind::Scope),
        "optional" => Some(FieldKind::Optional),
        _ => None,
    }
}

/// Returns the slot of `pending` that `kind` fills.
fn field_slot<'p, 'a>(
    pending: &'p mut PendingDependency<'a>,
    kind: FieldKind,
) -> &'p mut Option<Field<'a>> {
    match kind {
        FieldKind::GroupId => &mut pending.group_id,
        FieldKind::ArtifactId => &mut pending.artifact_id,
        FieldKind::Version => &mut pending.version,
        FieldKind::Scope => &mut pending.scope,
        FieldKind::Optional => &mut pending.optional,
    }
}

/// Returns the property name of a `${name}` version, or `None` for any other text.
fn placeholder_property(version: &str) -> Option<&str> {
    let property = version.strip_prefix("${")?.strip_suffix('}')?;
    (!property.is_empty() && !property.contains(['$', '{', '}'])).then_some(property)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::text_of_span;

    const FIXTURE: &str = include_str!("../../tests/fixtures/maven/pom.xml");

    fn find<'a>(dependencies: &'a [Dependency], name: &str) -> &'a Dependency {
        dependencies
            .iter()
            .find(|dependency| dependency.name == name)
            .unwrap_or_else(|| panic!("missing dependency {name}"))
    }

    #[test]
    fn returns_exact_entries_in_document_order() {
        let dependencies = parse(FIXTURE);
        let entries: Vec<(&str, &str, bool, bool, bool)> = dependencies
            .iter()
            .map(|dependency| {
                (
                    dependency.name.as_str(),
                    dependency.version.as_str(),
                    dependency.dev,
                    dependency.optional,
                    dependency.has_additional_version_constraints,
                )
            })
            .collect();
        assert_eq!(
            entries,
            [
                (
                    "org.apache.commons:commons-lang3",
                    "3.12.0",
                    false,
                    false,
                    false
                ),
                (
                    "org.junit.jupiter:junit-jupiter",
                    "5.9.2",
                    true,
                    false,
                    true
                ),
                (
                    "org.springframework:spring-core",
                    "6.0.0",
                    false,
                    false,
                    true
                ),
                (
                    "com.example:undefined-prop",
                    "${missing.version}",
                    false,
                    false,
                    true
                ),
                ("org.slf4j:slf4j-api", "[1.7,2.0)", false, true, false),
                ("com.example:non-ascii", "2.0.1", false, false, false),
                ("com.example:bom-managed", "4.5.6", false, false, false),
            ]
        );
    }

    #[test]
    fn omits_managed_internal_plugin_and_commented_or_cdata_entries() {
        let dependencies = parse(FIXTURE);
        for omitted in [
            "com.example:managed",
            "${project.groupId}:sibling",
            "com.example:plugin-dep",
            "com.example:in-comment",
            "com.example:cdata",
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
        let commons = find(&dependencies, "org.apache.commons:commons-lang3");
        assert_eq!(
            text_of_span(FIXTURE, commons.version_span).as_deref(),
            Some("3.12.0")
        );
        assert_eq!(
            text_of_span(FIXTURE, commons.name_span).as_deref(),
            Some("commons-lang3")
        );
    }

    #[test]
    fn placeholder_version_span_covers_the_placeholder_text() {
        let dependencies = parse(FIXTURE);
        let junit = find(&dependencies, "org.junit.jupiter:junit-jupiter");
        assert_eq!(junit.version, "5.9.2");
        assert_eq!(
            text_of_span(FIXTURE, junit.version_span).as_deref(),
            Some("${junit.version}")
        );
    }

    #[test]
    fn version_span_is_correct_after_a_comment_with_non_ascii_text() {
        let dependencies = parse(FIXTURE);
        let non_ascii = find(&dependencies, "com.example:non-ascii");
        assert_eq!(
            text_of_span(FIXTURE, non_ascii.version_span).as_deref(),
            Some("2.0.1")
        );
    }

    #[test]
    fn crlf_text_gives_the_same_dependencies() {
        let crlf_text = FIXTURE.replace('\n', "\r\n");
        let dependencies = parse(&crlf_text);
        assert_eq!(dependencies, parse(FIXTURE));
        let commons = find(&dependencies, "org.apache.commons:commons-lang3");
        assert_eq!(
            text_of_span(&crlf_text, commons.version_span).as_deref(),
            Some("3.12.0")
        );
        let non_ascii = find(&dependencies, "com.example:non-ascii");
        assert_eq!(
            text_of_span(&crlf_text, non_ascii.version_span).as_deref(),
            Some("2.0.1")
        );
    }

    #[test]
    fn malformed_xml_returns_the_dependencies_read_so_far() {
        let text = "<project><dependencies><dependency><groupId>a</groupId>\
                    <artifactId>b</artifactId><version>1.0</version></dependency>\
                    <dependency><groupId>";
        let dependencies = parse(text);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name, "a:b");
    }

    #[test]
    fn empty_and_non_xml_text_return_nothing() {
        assert!(parse("").is_empty());
        assert!(parse("not xml").is_empty());
    }

    #[test]
    fn entity_in_a_used_element_skips_the_dependency() {
        let text = "<project><dependencies>\
                    <dependency><groupId>a</groupId><artifactId>b</artifactId>\
                    <version>1.&amp;0</version></dependency>\
                    <dependency><groupId>c</groupId><artifactId>d</artifactId>\
                    <version>2.0</version></dependency>\
                    </dependencies></project>";
        let dependencies = parse(text);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name, "c:d");
    }

    // Changed from `<version>\n1.0\n</version>` (expected dropped) to a value whose
    // trimmed text really spans two lines: R24 keeps pretty-printed values.
    #[test]
    fn value_whose_trimmed_text_spans_two_lines_is_dropped() {
        let text = "<project><dependencies><dependency>\
                    <groupId>a</groupId><artifactId>b</artifactId>\
                    <version>1.0\n2.0</version></dependency></dependencies></project>";
        assert!(parse(text).is_empty());
    }

    #[test]
    fn pretty_printed_value_is_trimmed_and_kept() {
        let text = "<project><dependencies><dependency>\n  <groupId>a</groupId>\n  \
                    <artifactId>b</artifactId>\n  <version>\n    1.0\n  </version>\n\
                    </dependency></dependencies></project>";
        let dependencies = parse(text);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].version, "1.0");
        assert_eq!(
            text_of_span(text, dependencies[0].version_span).as_deref(),
            Some("1.0")
        );
    }

    #[test]
    fn property_declared_after_its_use_resolves() {
        let text = "<project><dependencies><dependency><groupId>a</groupId>\
                    <artifactId>b</artifactId><version>${p}</version></dependency>\
                    </dependencies><properties><p>2</p></properties></project>";
        let dependencies = parse(text);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].version, "2");
        assert_eq!(
            text_of_span(text, dependencies[0].version_span).as_deref(),
            Some("${p}")
        );
        assert!(dependencies[0].has_additional_version_constraints);
    }

    #[test]
    fn system_scope_dependencies_are_local_jars_and_are_skipped() {
        let manifest = "\
<project>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>local-jar</artifactId>
      <version>1.0</version>
      <scope>system</scope>
      <systemPath>${project.basedir}/lib/local.jar</systemPath>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.9</version>
    </dependency>
  </dependencies>
</project>
";
        let names: Vec<_> = parse(manifest)
            .into_iter()
            .map(|dependency| dependency.name)
            .collect();
        assert_eq!(names, ["org.slf4j:slf4j-api"]);
    }
}
