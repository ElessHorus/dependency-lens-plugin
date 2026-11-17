//! Parser for NuGet package declarations in MSBuild project and props files.
//!
//! Reads `PackageReference`, `PackageVersion` and `GlobalPackageReference` items
//! under `Project` in one streaming pass. Attribute values are read from the raw
//! start tag, so their spans are exact. A version written as `$(Name)` is resolved
//! from a property of the same file after the pass.

use std::collections::HashMap;

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use super::spans::LineIndex;
use super::xml_text::{Field, byte_offset, element_name, read_field, trimmed_field};
use crate::model::Dependency;

/// Root element of an MSBuild project or props file.
const ROOT_ELEMENT: &str = "Project";
/// Element that groups property definitions.
const PROPERTY_GROUP_ELEMENT: &str = "PropertyGroup";

/// The item element that declares a package.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ItemKind {
    #[default]
    PackageReference,
    PackageVersion,
    GlobalPackageReference,
}

/// Maps an element name to the item kind it declares.
fn item_kind(name: &str) -> Option<ItemKind> {
    match name {
        "PackageReference" => Some(ItemKind::PackageReference),
        "PackageVersion" => Some(ItemKind::PackageVersion),
        "GlobalPackageReference" => Some(ItemKind::GlobalPackageReference),
        _ => None,
    }
}

/// A child element of an item whose text the parser reads.
#[derive(Clone, Copy)]
enum ItemChild {
    Version,
    VersionOverride,
    PrivateAssets,
}

/// What the text of the currently open element is used for.
#[derive(Clone, Copy)]
enum Capture<'a> {
    Item(ItemChild),
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

/// The fields of an item read so far. Invalid values stay `None`.
#[derive(Default)]
struct PendingItem<'a> {
    kind: ItemKind,
    include: Option<Field<'a>>,
    update: Option<Field<'a>>,
    version: Option<Field<'a>>,
    version_override: Option<Field<'a>>,
    child_version: Option<Field<'a>>,
    child_version_override: Option<Field<'a>>,
    is_private_assets_all: bool,
}

/// One attribute of a start tag, with its raw value between the quotes.
struct RawAttribute<'a> {
    name: &'a str,
    value: &'a str,
    /// Byte offset of the first byte of `value`.
    value_start: usize,
}

/// Iterates over the attributes of the start tag `text[tag_start..tag_end]`.
///
/// Stops at the first malformed attribute. Names end at the `=`, so `Version`
/// never matches inside `VersionOverride` or `AssemblyVersion`.
struct AttributeScanner<'a> {
    text: &'a str,
    position: usize,
    tag_end: usize,
}

impl<'a> AttributeScanner<'a> {
    fn new(text: &'a str, tag_start: usize, tag_end: usize) -> Self {
        Self {
            text,
            position: tag_start,
            tag_end,
        }
    }

    /// Advances past ASCII whitespace.
    fn skip_whitespace(&mut self) {
        let bytes = self.text.as_bytes();
        while self.position < self.tag_end && bytes[self.position].is_ascii_whitespace() {
            self.position += 1;
        }
    }
}

impl<'a> Iterator for AttributeScanner<'a> {
    type Item = RawAttribute<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.skip_whitespace();
        let name_start = self.position;
        let bytes = self.text.as_bytes();
        while self.position < self.tag_end
            && !matches!(bytes[self.position], b'=' | b'/' | b'>')
            && !bytes[self.position].is_ascii_whitespace()
        {
            self.position += 1;
        }
        if self.position == name_start {
            return None;
        }
        let name = self.text.get(name_start..self.position)?;
        self.skip_whitespace();
        if self.position >= self.tag_end || bytes[self.position] != b'=' {
            return None;
        }
        self.position += 1;
        self.skip_whitespace();
        let quote = match bytes.get(self.position) {
            Some(&byte @ (b'"' | b'\'')) if self.position < self.tag_end => byte,
            _ => return None,
        };
        let value_start = self.position + 1;
        let value_end = value_start
            + self
                .text
                .get(value_start..self.tag_end)?
                .find(char::from(quote))?;
        self.position = value_end + 1;
        Some(RawAttribute {
            name,
            value: self.text.get(value_start..value_end)?,
            value_start,
        })
    }
}

/// Reads the value of one attribute as a plain field.
///
/// Returns `None` when the value holds an entity or its trimmed text is empty or spans
/// lines. Such a value counts as absent.
fn attribute_field<'a>(attribute: &RawAttribute<'a>, index: &LineIndex<'_>) -> Option<Field<'a>> {
    if attribute.value.contains('&') {
        return None;
    }
    trimmed_field(attribute.value, attribute.value_start, index)
}

/// Stores the attributes of an item start tag in `item`.
fn read_attributes<'a>(
    text: &'a str,
    index: &LineIndex<'_>,
    tag_start: usize,
    tag_end: usize,
    item: &mut PendingItem<'a>,
) {
    for attribute in AttributeScanner::new(text, tag_start, tag_end) {
        match attribute.name {
            "Include" => item.include = attribute_field(&attribute, index),
            "Update" => item.update = attribute_field(&attribute, index),
            "Version" => item.version = attribute_field(&attribute, index),
            "VersionOverride" => item.version_override = attribute_field(&attribute, index),
            "PrivateAssets" => {
                if let Some(field) = attribute_field(&attribute, index) {
                    item.is_private_assets_all |= field.text.eq_ignore_ascii_case("all");
                }
            }
            _ => {}
        }
    }
}

/// Stores the text of an item child element in `item`.
fn record_child<'a>(item: &mut PendingItem<'a>, child: ItemChild, value: Option<Field<'a>>) {
    match child {
        ItemChild::Version => item.child_version = value,
        ItemChild::VersionOverride => item.child_version_override = value,
        ItemChild::PrivateAssets => {
            if let Some(field) = value {
                item.is_private_assets_all |= field.text.eq_ignore_ascii_case("all");
            }
        }
    }
}

/// Maps an item child element name to the child it fills.
fn item_child(name: &str) -> Option<ItemChild> {
    match name {
        "Version" => Some(ItemChild::Version),
        "VersionOverride" => Some(ItemChild::VersionOverride),
        "PrivateAssets" => Some(ItemChild::PrivateAssets),
        _ => None,
    }
}

/// Builds a dependency from an item. Returns the property name as well when the version
/// is a `$(Name)` placeholder, so the caller can resolve it after the pass.
///
/// The version keeps the first source in this order: attribute `Version`, attribute
/// `VersionOverride`, child `Version`, child `VersionOverride`. `Update` names a package
/// only on `PackageReference`. Returns `None` when the name or every version source is missing.
fn build_dependency<'a>(item: PendingItem<'a>) -> Option<(Dependency, Option<&'a str>)> {
    let name = item.include.or(match item.kind {
        ItemKind::PackageReference => item.update,
        ItemKind::PackageVersion | ItemKind::GlobalPackageReference => None,
    })?;
    let version = item
        .version
        .or(item.version_override)
        .or(item.child_version)
        .or(item.child_version_override)?;
    let property_name = placeholder_property(version.text);
    let dependency = Dependency {
        name: name.text.to_owned(),
        version: version.text.to_owned(),
        name_span: name.span,
        version_span: version.span,
        dev: item.kind == ItemKind::GlobalPackageReference || item.is_private_assets_all,
        optional: false,
        has_additional_version_constraints: property_name.is_some(),
        requirement: None,
    };
    Some((dependency, property_name))
}

/// Reads an item whose start tag begins at `event_start` and whose name is `name`.
///
/// `content_start` is the byte offset after the `>` that ends the start tag.
fn read_item<'a>(
    text: &'a str,
    index: &LineIndex<'_>,
    event_start: usize,
    name: &str,
    content_start: usize,
    kind: ItemKind,
) -> PendingItem<'a> {
    let mut item = PendingItem {
        kind,
        ..PendingItem::default()
    };
    let attributes_start = event_start + 1 + name.len();
    // `content_start - 1` is the `>`, which the attribute scanner must not read.
    read_attributes(
        text,
        index,
        attributes_start,
        content_start.saturating_sub(1),
        &mut item,
    );
    item
}

/// Adds a built item to `dependencies`, and queues its property placeholder if it has one.
fn push_item<'a>(
    item: PendingItem<'a>,
    dependencies: &mut Vec<Dependency>,
    placeholders: &mut Vec<(usize, &'a str)>,
) {
    let Some((dependency, property_name)) = build_dependency(item) else {
        return;
    };
    if let Some(property_name) = property_name {
        placeholders.push((dependencies.len(), property_name));
    }
    dependencies.push(dependency);
}

/// Returns the property name of an exact `$(Name)` version, or `None` for other text.
fn placeholder_property(version: &str) -> Option<&str> {
    let property = version.strip_prefix("$(")?.strip_suffix(')')?;
    (!property.is_empty() && !property.contains(['$', '(', ')'])).then_some(property)
}

/// Parses the NuGet packages of an MSBuild manifest. Never panics.
///
/// Reads the document once and builds the line index once. Malformed XML returns the
/// items read before the error.
pub fn parse(text: &str) -> Vec<Dependency> {
    let index = LineIndex::new(text);
    let mut reader = Reader::from_str(text);
    // Names of the open elements, sliced from `text` so they live as long as the input.
    let mut stack: Vec<&str> = Vec::new();
    let mut open_capture: Option<OpenCapture> = None;
    // Stack length while the item is open, with its fields read so far.
    let mut open_item: Option<(usize, PendingItem)> = None;
    let mut dependencies: Vec<Dependency> = Vec::new();
    let mut properties: HashMap<&str, &str> = HashMap::new();
    // Dependencies whose version is a `$(Name)` placeholder, with the property name.
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
                let is_under_project = stack.first() == Some(&ROOT_ELEMENT);
                if open_capture.is_none() {
                    if let Some((item_depth, _)) = &open_item {
                        if depth_before == *item_depth
                            && let Some(child) = item_child(name)
                        {
                            open_capture = Some(OpenCapture {
                                target: Capture::Item(child),
                                depth: depth_before + 1,
                                content_start,
                            });
                        }
                    } else if stack.last() == Some(&PROPERTY_GROUP_ELEMENT) {
                        open_capture = Some(OpenCapture {
                            target: Capture::Property(name),
                            depth: depth_before + 1,
                            content_start,
                        });
                    }
                }
                if open_item.is_none()
                    && is_under_project
                    && let Some(kind) = item_kind(name)
                {
                    let item = read_item(text, &index, event_start, name, content_start, kind);
                    open_item = Some((depth_before + 1, item));
                }
                stack.push(name);
            }
            Event::Empty(start) => {
                let Some(name) = element_name(text, event_start + 1, start.name()) else {
                    break;
                };
                let Some(content_start) = byte_offset(reader.buffer_position()) else {
                    break;
                };
                if open_item.is_none()
                    && stack.first() == Some(&ROOT_ELEMENT)
                    && let Some(kind) = item_kind(name)
                {
                    let item = read_item(text, &index, event_start, name, content_start, kind);
                    push_item(item, &mut dependencies, &mut placeholders);
                }
            }
            Event::End(_) => {
                let depth = stack.len();
                if let Some(capture) = open_capture.filter(|capture| capture.depth == depth) {
                    open_capture = None;
                    let value = read_field(text, &index, capture.content_start, event_start);
                    match capture.target {
                        Capture::Item(child) => {
                            if let Some((_, item)) = open_item.as_mut() {
                                record_child(item, child, value);
                            }
                        }
                        Capture::Property(property_name) => {
                            if let Some(field) = value {
                                properties.insert(property_name, field.text);
                            }
                        }
                    }
                }
                if open_item
                    .as_ref()
                    .is_some_and(|(item_depth, _)| *item_depth == depth)
                    && let Some((_, item)) = open_item.take()
                {
                    push_item(item, &mut dependencies, &mut placeholders);
                }
                stack.pop();
            }
            Event::Eof => break,
            _ => {}
        }
    }

    // Resolve placeholders last so that properties declared after an item still apply.
    // A property whose value is itself a `$(...)` reference stays unresolved.
    for (dependency_index, property_name) in placeholders {
        let Some(value) = properties.get(property_name) else {
            continue;
        };
        if value.starts_with("$(") {
            continue;
        }
        if let Some(dependency) = dependencies.get_mut(dependency_index) {
            dependency.version = (*value).to_owned();
        }
    }
    dependencies
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::text_of_span;

    const APP: &str = include_str!("../../tests/fixtures/csharp/app.csproj");
    const PROPS: &str = include_str!("../../tests/fixtures/csharp/Directory.Packages.props");

    /// Returns the fields that the exact-list test compares.
    fn summary(dependencies: &[Dependency]) -> Vec<(&str, &str, bool, bool)> {
        dependencies
            .iter()
            .map(|dependency| {
                (
                    dependency.name.as_str(),
                    dependency.version.as_str(),
                    dependency.dev,
                    dependency.has_additional_version_constraints,
                )
            })
            .collect()
    }

    fn find<'a>(dependencies: &'a [Dependency], name: &str) -> &'a Dependency {
        dependencies
            .iter()
            .find(|dependency| dependency.name == name)
            .unwrap_or_else(|| panic!("missing dependency {name}"))
    }

    #[test]
    fn returns_exact_entries_of_app_csproj_in_document_order() {
        assert_eq!(
            summary(&parse(APP)),
            [
                ("Newtonsoft.Json", "13.0.3", false, false),
                ("Serilog", "3.1.1", false, true),
                ("Undefined.Prop", "$(Missing)", false, true),
                ("Child.Version", "2.0.1", false, false),
                ("Floating", "1.*", false, false),
                ("Ranged", "[1.0,2.0)", false, false),
                ("Analyzer", "4.5.6", true, false),
                ("Override", "7.0.0", false, false),
                ("Updated", "8.8.8", false, false),
                ("Cafe", "9.9.9", false, false),
            ]
        );
    }

    #[test]
    fn returns_moq_and_global_reference_from_directory_packages_props() {
        assert_eq!(
            summary(&parse(PROPS)),
            [
                ("Moq", "4.20.70", false, false),
                ("StyleCop.Analyzers", "1.2.0-beta.556", true, false),
            ]
        );
    }

    #[test]
    fn name_and_version_spans_point_at_the_values() {
        let dependencies = parse(APP);
        let newtonsoft = find(&dependencies, "Newtonsoft.Json");
        assert_eq!(
            text_of_span(APP, newtonsoft.version_span).as_deref(),
            Some("13.0.3")
        );
        assert_eq!(
            text_of_span(APP, newtonsoft.name_span).as_deref(),
            Some("Newtonsoft.Json")
        );
        let serilog = find(&dependencies, "Serilog");
        assert_eq!(
            text_of_span(APP, serilog.version_span).as_deref(),
            Some("$(SerilogVersion)")
        );
        let child = find(&dependencies, "Child.Version");
        assert_eq!(
            text_of_span(APP, child.version_span).as_deref(),
            Some("2.0.1")
        );
    }

    #[test]
    fn version_override_span_is_not_matched_by_the_version_attribute() {
        let dependencies = parse(APP);
        let override_dependency = find(&dependencies, "Override");
        assert_eq!(
            text_of_span(APP, override_dependency.version_span).as_deref(),
            Some("7.0.0")
        );
    }

    #[test]
    fn version_attribute_is_not_matched_inside_assembly_version() {
        let text = r#"<Project><ItemGroup><PackageReference Include="X" AssemblyVersion="1.0" Version="2.0" /></ItemGroup></Project>"#;
        let dependencies = parse(text);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].version, "2.0");
        assert_eq!(
            text_of_span(text, dependencies[0].version_span).as_deref(),
            Some("2.0")
        );
    }

    #[test]
    fn span_is_exact_after_a_comment_with_non_ascii_text() {
        let dependencies = parse(APP);
        let cafe = find(&dependencies, "Cafe");
        assert_eq!(
            text_of_span(APP, cafe.version_span).as_deref(),
            Some("9.9.9")
        );
    }

    #[test]
    fn crlf_text_gives_the_same_dependencies() {
        let crlf_text = APP.replace('\n', "\r\n");
        let dependencies = parse(&crlf_text);
        assert_eq!(dependencies, parse(APP));
        let cafe = find(&dependencies, "Cafe");
        assert_eq!(
            text_of_span(&crlf_text, cafe.version_span).as_deref(),
            Some("9.9.9")
        );
    }

    #[test]
    fn single_quotes_and_spaces_around_equals_are_accepted() {
        let text = "<Project><ItemGroup>\
                    <PackageReference Include = 'A' Version = '1.0.0' />\
                    </ItemGroup></Project>";
        let dependencies = parse(text);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name, "A");
        assert_eq!(dependencies[0].version, "1.0.0");
        assert_eq!(
            text_of_span(text, dependencies[0].version_span).as_deref(),
            Some("1.0.0")
        );
    }

    #[test]
    fn version_with_an_entity_is_skipped() {
        let text = r#"<Project><ItemGroup><PackageReference Include="A" Version="1&amp;0" /><PackageReference Include="B" Version="2.0" /></ItemGroup></Project>"#;
        assert_eq!(summary(&parse(text)), [("B", "2.0", false, false)]);
    }

    #[test]
    fn version_spanning_two_lines_is_skipped() {
        let text = "<Project><ItemGroup>\n<PackageReference Include=\"A\" Version=\"1.0\n2.0\" />\n</ItemGroup></Project>";
        assert!(parse(text).is_empty());
    }

    #[test]
    fn item_without_an_include_value_is_skipped() {
        let text = r#"<Project><ItemGroup><PackageReference Include="" Version="1.0" /><PackageReference Version="2.0" /></ItemGroup></Project>"#;
        assert!(parse(text).is_empty());
    }

    #[test]
    fn malformed_xml_returns_the_items_read_so_far() {
        let text = r#"<Project><ItemGroup><PackageReference Include="A" Version="1.0"/><PackageReference Inc"#;
        let dependencies = parse(text);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name, "A");
    }

    #[test]
    fn empty_and_non_xml_text_return_nothing() {
        assert!(parse("").is_empty());
        assert!(parse("not xml").is_empty());
    }

    #[test]
    fn private_assets_child_element_marks_a_development_dependency() {
        let text = "<Project><ItemGroup><PackageReference Include=\"A\" Version=\"1.0\">\
                    <PrivateAssets>ALL</PrivateAssets></PackageReference></ItemGroup></Project>";
        assert_eq!(summary(&parse(text)), [("A", "1.0", true, false)]);
    }

    #[test]
    fn property_declared_after_its_use_resolves() {
        let text = "<Project><ItemGroup><PackageReference Include=\"A\" Version=\"$(V)\" />\
                    </ItemGroup><PropertyGroup><V>2.1.0</V></PropertyGroup></Project>";
        let dependencies = parse(text);
        assert_eq!(summary(&dependencies), [("A", "2.1.0", false, true)]);
        assert_eq!(
            text_of_span(text, dependencies[0].version_span).as_deref(),
            Some("$(V)")
        );
    }

    #[test]
    fn property_that_refers_to_another_property_stays_unresolved() {
        let text = "<Project><ItemGroup><PackageReference Include=\"A\" Version=\"$(V)\" />\
                    </ItemGroup><PropertyGroup><V>$(W)</V><W>3.0</W></PropertyGroup></Project>";
        assert_eq!(summary(&parse(text)), [("A", "$(V)", false, true)]);
    }
}
