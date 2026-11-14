//! Parser for Python manifests: requirements files and TOML manifests.
//!
//! One entry point reads every PyPI manifest. The format comes from the
//! text, because the model passes only the text. Text that parses as TOML
//! with a handled key is a TOML manifest. Anything else is a requirements file.

use std::collections::HashSet;
use std::ops::Range;

use taplo::dom::Node;
use taplo::dom::node::{Bool, DomNode, Key, Str};
use taplo::syntax::SyntaxElement;

use super::spans::LineIndex;
use crate::model::{Dependency, Span};
use crate::registries::pypi::normalize_name;

/// PEP 440 operators that may start a version constraint.
const OPERATORS: [&str; 8] = ["===", "==", ">=", "<=", "!=", "~=", ">", "<"];

/// Operators whose version is the declared version of a requirement. `!=`, `<` and `<=` never pin a version.
const PIN_OPERATORS: [&str; 5] = ["===", "==", "~=", ">=", ">"];

/// Source names that a Poetry dependency table can use instead of a registry version.
///
/// `source = "name"` is not in this list. It names a private Poetry source, except
/// for the reserved name `pypi`, so it needs its own check.
const POETRY_SOURCE_KEYS: [&str; 3] = ["path", "git", "url"];

/// The reserved name of the public index in a Poetry `source` key.
const POETRY_PUBLIC_SOURCE: &str = "pypi";

/// Parses the dependencies of a PyPI manifest.
///
/// The format comes from the text. Text that parses as TOML with a handled key is
/// read as a TOML manifest. Anything else is read as a requirements file.
pub fn parse(text: &str) -> Vec<Dependency> {
    let parsed = taplo::parser::parse(text);
    if parsed.errors.is_empty() {
        let dom = parsed.into_dom();
        if has_handled_key(&dom) {
            return parse_toml(text, &dom);
        }
    }
    parse_requirements(text)
}

/// Returns `true` when the TOML document holds a table or array that this parser reads.
fn has_handled_key(dom: &Node) -> bool {
    let project = dom.get("project");
    let poetry = dom.get("tool").get("poetry");
    project.get("dependencies").as_array().is_some()
        || project.get("optional-dependencies").as_table().is_some()
        || dom.get("dependency-groups").as_table().is_some()
        || poetry.get("dependencies").as_table().is_some()
        || poetry.get("dev-dependencies").as_table().is_some()
        || poetry.get("group").as_table().is_some()
        || dom.get("envs").as_table().is_some()
}

/// Option names whose value is a package source. `-i` and `-f` are the short forms.
const SOURCE_OPTIONS: [&str; 6] = [
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "--no-index",
];

/// Index URLs that name the public PyPI index.
const PUBLIC_INDEX_URLS: [&str; 2] = ["https://pypi.org/simple", "https://pypi.python.org/simple"];

/// Returns `true` when a requirements line sets a package source other than the public PyPI index.
///
/// A pip option applies to the whole file, so such a line makes every package of the
/// file a possible private package.
fn sets_private_source(line: &str) -> bool {
    // A comment starts at `#` after whitespace. A final `\` joins the value of the next line.
    let option_text = line
        .split_once(" #")
        .map_or(line, |(before_comment, _)| before_comment)
        .trim()
        .trim_end_matches('\\')
        .trim_end();
    // A short option may hold its value, as in `-ihttps://host/simple` or `-fwheels`.
    let (option, value) = if option_text.starts_with(['-']) && !option_text.starts_with("--") {
        option_text.split_at_checked(2).unwrap_or((option_text, ""))
    } else {
        // The value follows a space (`--index-url URL`) or an equals sign (`--index-url=URL`).
        option_text
            .split_once([' ', '\t', '='])
            .unwrap_or((option_text, ""))
    };
    SOURCE_OPTIONS.contains(&option) && !is_public_index_url(value.trim_start_matches('=').trim())
}

/// Returns `true` when `url` is the public PyPI index, with or without a final `/`.
fn is_public_index_url(url: &str) -> bool {
    PUBLIC_INDEX_URLS
        .iter()
        .any(|public_url| url.trim_end_matches('/').eq_ignore_ascii_case(public_url))
}

/// Parses a requirements file, one requirement per line.
///
/// Lines that are not requirements (options, comments, URLs, paths) fail
/// [`parse_pep508`] and are skipped. Offsets are relative to each line, so no line table is needed.
/// A line that sets a non-public index or a link source hides the whole file.
fn parse_requirements(text: &str) -> Vec<Dependency> {
    if text.lines().any(sets_private_source) {
        return Vec::new();
    }
    text.lines()
        .enumerate()
        .filter_map(|(line_index, line)| {
            let line_number = u32::try_from(line_index).ok()?;
            let anchor = Anchor {
                line: line_number,
                column: 0,
            };
            dependency_from_pep508(line, line, anchor, false, false)
        })
        .collect()
}

/// The 0-based line and the byte column where a text starts.
///
/// Ranges that are relative to that text become spans with [`Anchor::span`].
#[derive(Clone, Copy)]
struct Anchor {
    line: u32,
    column: usize,
}

impl Anchor {
    /// Anchors the text that starts at `offset` of the indexed source.
    fn at(index: &LineIndex<'_>, offset: usize) -> Option<Self> {
        let (line, column) = index.locate(offset)?;
        Some(Self { line, column })
    }

    /// Converts a range relative to the anchored text into a span on its line.
    fn span(self, range: Range<usize>) -> Option<Span> {
        Some(Span {
            line: self.line,
            line_start: u32::try_from(self.column.checked_add(range.start)?).ok()?,
            line_end: u32::try_from(self.column.checked_add(range.end)?).ok()?,
        })
    }
}

/// Byte ranges of a PEP 508 requirement, relative to the parsed text.
struct Pep508 {
    name: Range<usize>,
    /// Version of the first pin constraint.
    version: Range<usize>,
    /// Whether the requirement has more than one constraint.
    has_additional_version_constraints: bool,
}

/// One `operator version` pair of a requirement.
struct Constraint<'a> {
    operator: &'a str,
    version: Range<usize>,
}

/// Reads the name and the declared version of a PEP 508 requirement.
///
/// The declared version is the version of the first pin constraint. Exclusions
/// and upper bounds never pin one, so a requirement without a pin returns `None`.
/// Extras, markers and comments are skipped, not validated. This also rejects
/// URL, path and option lines.
fn parse_pep508(input: &str) -> Option<Pep508> {
    let bytes = input.as_bytes();
    let name_start = scan_while(bytes, 0, |byte| byte.is_ascii_whitespace());
    if !bytes.get(name_start)?.is_ascii_alphanumeric() {
        return None;
    }
    let name_end = scan_while(bytes, name_start, is_name_byte);
    let mut cursor = scan_while(bytes, name_end, |byte| byte.is_ascii_whitespace());
    if bytes.get(cursor) == Some(&b'[') {
        let closing = bytes[cursor..].iter().position(|&byte| byte == b']')?;
        cursor = scan_while(bytes, cursor + closing + 1, |byte| {
            byte.is_ascii_whitespace()
        });
    }
    // PEP 508 allows the constraints inside one pair of parentheses: `requests (==2.28.0)`.
    let is_wrapped = bytes.get(cursor) == Some(&b'(');
    if is_wrapped {
        cursor += 1;
    }
    let mut constraints = Vec::new();
    let mut next_from = Some(cursor);
    // A malformed constraint after the first ends the list. The ones read so far still count.
    while let Some(from) = next_from {
        let Some((constraint, next)) = parse_constraint(input, from, is_wrapped) else {
            break;
        };
        constraints.push(constraint);
        next_from = next;
    }
    let pin = constraints
        .iter()
        .find(|constraint| PIN_OPERATORS.contains(&constraint.operator))?;
    Some(Pep508 {
        name: name_start..name_end,
        version: pin.version.clone(),
        has_additional_version_constraints: constraints.len() > 1,
    })
}

/// Reads one `operator version` pair that starts at `from`.
///
/// Returns the pair and the offset of the next pair after a comma, if one follows.
/// In a wrapped list, the closing parenthesis ends the last version.
fn parse_constraint(
    input: &str,
    from: usize,
    is_wrapped: bool,
) -> Option<(Constraint<'_>, Option<usize>)> {
    let bytes = input.as_bytes();
    let operator_start = scan_while(bytes, from, |byte| byte.is_ascii_whitespace());
    let operator_end = scan_while(bytes, operator_start, is_operator_byte);
    let operator = input
        .get(operator_start..operator_end)
        .filter(|operator| OPERATORS.contains(operator))?;
    let version_start = scan_while(bytes, operator_end, |byte| byte.is_ascii_whitespace());
    // A version stops at a space, a constraint or marker separator, a comment or a line continuation.
    let version_end = scan_while(bytes, version_start, |byte| {
        !ends_version(byte) && !(is_wrapped && byte == b')')
    });
    if version_end == version_start {
        return None;
    }
    let after_version = scan_while(bytes, version_end, |byte| byte.is_ascii_whitespace());
    let next = (bytes.get(after_version) == Some(&b',')).then_some(after_version + 1);
    Some((
        Constraint {
            operator,
            version: version_start..version_end,
        },
        next,
    ))
}

/// Returns the index of the first byte from `from` that fails `keep`, or the length of `bytes`.
fn scan_while(bytes: &[u8], from: usize, keep: impl Fn(u8) -> bool) -> usize {
    from + bytes[from..].iter().take_while(|&&byte| keep(byte)).count()
}

/// Returns `true` for bytes that may appear in a distribution name.
fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

/// Returns `true` for bytes that may appear in an operator.
fn is_operator_byte(byte: u8) -> bool {
    matches!(byte, b'=' | b'<' | b'>' | b'!' | b'~')
}

/// Returns `true` for bytes that end a version.
fn ends_version(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b',' | b';' | b'#' | b'\\')
}

/// Builds a dependency from one PEP 508 requirement.
///
/// `value` is the decoded text. `raw` is the source text it came from, which
/// keeps any escapes of a TOML string. Offsets map onto the source only while
/// the raw text matches the value. An escape before the version breaks that match.
fn dependency_from_pep508(
    value: &str,
    raw: &str,
    anchor: Anchor,
    is_dev: bool,
    is_optional: bool,
) -> Option<Dependency> {
    let requirement = parse_pep508(value)?;
    if raw.get(..requirement.version.end)? != value.get(..requirement.version.end)? {
        return None;
    }
    Some(Dependency {
        name: value.get(requirement.name.clone())?.to_owned(),
        version: value.get(requirement.version.clone())?.to_owned(),
        name_span: anchor.span(requirement.name)?,
        version_span: anchor.span(requirement.version)?,
        dev: is_dev,
        optional: is_optional,
        has_additional_version_constraints: requirement.has_additional_version_constraints,
    })
}

/// Parses a TOML manifest: PEP 621, PEP 735, Poetry and Hatch environments.
fn parse_toml(text: &str, dom: &Node) -> Vec<Dependency> {
    if has_private_index(dom) {
        return Vec::new();
    }
    let index = LineIndex::new(text);
    let mut dependencies = Vec::new();
    let project = dom.get("project");
    collect_requirement_array(
        &index,
        &project.get("dependencies"),
        false,
        false,
        &mut dependencies,
    );
    collect_requirement_tables(
        &index,
        &project.get("optional-dependencies"),
        false,
        true,
        &mut dependencies,
    );
    collect_requirement_tables(
        &index,
        &dom.get("dependency-groups"),
        true,
        false,
        &mut dependencies,
    );
    let poetry = dom.get("tool").get("poetry");
    collect_poetry_table(
        &index,
        &poetry.get("dependencies"),
        false,
        &mut dependencies,
    );
    collect_poetry_table(
        &index,
        &poetry.get("dev-dependencies"),
        true,
        &mut dependencies,
    );
    collect_poetry_groups(&index, &poetry.get("group"), &mut dependencies);
    collect_hatch_envs(&index, &dom.get("envs"), &mut dependencies);
    exclude_uv_sources(dom, &mut dependencies);
    dependencies
}

/// Removes the packages that `[tool.uv.sources]` takes from a path, a git URL, a workspace or an index.
///
/// Names are compared in the PEP 503 normal form, so `Internal_Two` matches `internal-two`.
fn exclude_uv_sources(dom: &Node, dependencies: &mut Vec<Dependency>) {
    let sources = dom.get("tool").get("uv").get("sources");
    let Some(table) = sources.as_table() else {
        return;
    };
    let source_names: HashSet<String> = table
        .entries()
        .read()
        .iter()
        .map(|(key, _)| normalize_name(key.value()))
        .collect();
    dependencies.retain(|dependency| !source_names.contains(&normalize_name(&dependency.name)));
}

/// Returns `true` when a uv or Poetry setting adds a package index other than the public PyPI one.
///
/// Such an index may serve any package of the manifest, like a pip `--index-url`. An
/// `explicit` uv index and an `explicit` Poetry source serve only the packages that name them,
/// and those are already skipped.
fn has_private_index(dom: &Node) -> bool {
    let tool = dom.get("tool");
    let uv = tool.get("uv");
    holds_private_url(&uv.get("index-url"))
        || holds_private_url(&uv.get("extra-index-url"))
        || holds_private_url(&uv.get("find-links"))
        || holds_private_index_table(&uv.get("index"), |table| {
            table.get("explicit").as_bool().is_some_and(Bool::value)
        })
        || holds_private_index_table(&tool.get("poetry").get("source"), |table| {
            table
                .get("priority")
                .as_str()
                .is_some_and(|priority| priority.value() == "explicit")
        })
}

/// Returns `true` when a string node, or an array of string nodes, holds a URL that is not public PyPI.
fn holds_private_url(node: &Node) -> bool {
    if let Some(url) = node.as_str() {
        return !is_public_index_url(url.value());
    }
    node.as_array().is_some_and(|array| {
        array.items().read().iter().any(|item| {
            item.as_str()
                .is_some_and(|url| !is_public_index_url(url.value()))
        })
    })
}

/// Returns `true` when an array of index tables holds a table that is not explicit and has a non-public `url`.
fn holds_private_index_table(node: &Node, is_explicit: impl Fn(&Node) -> bool) -> bool {
    node.as_array().is_some_and(|array| {
        array.items().read().iter().any(|table| {
            !is_explicit(table)
                && table
                    .get("url")
                    .as_str()
                    .is_some_and(|url| !is_public_index_url(url.value()))
        })
    })
}

/// Appends the dependencies of a PEP 508 string array. Ignores other nodes.
fn collect_requirement_array(
    index: &LineIndex<'_>,
    node: &Node,
    is_dev: bool,
    is_optional: bool,
    out: &mut Vec<Dependency>,
) {
    let Some(array) = node.as_array() else {
        return;
    };
    let items = array.items().read();
    for item in items.iter() {
        let Some(string) = item.as_str() else {
            continue;
        };
        let Some((content_start, raw)) = raw_content(index, string.syntax()) else {
            continue;
        };
        let Some(anchor) = Anchor::at(index, content_start) else {
            continue;
        };
        if let Some(dependency) =
            dependency_from_pep508(string.value(), raw, anchor, is_dev, is_optional)
        {
            out.push(dependency);
        }
    }
}

/// Appends the dependencies of every group array in a table of groups.
fn collect_requirement_tables(
    index: &LineIndex<'_>,
    node: &Node,
    is_dev: bool,
    is_optional: bool,
    out: &mut Vec<Dependency>,
) {
    let Some(table) = node.as_table() else {
        return;
    };
    let entries = table.entries().read();
    for (_, group) in entries.iter() {
        collect_requirement_array(index, group, is_dev, is_optional, out);
    }
}

/// Appends the dependencies of a Poetry dependency table. Every entry is dev when `is_dev` is set.
///
/// The `python` key is the interpreter constraint, so it is skipped.
fn collect_poetry_table(
    index: &LineIndex<'_>,
    node: &Node,
    is_dev: bool,
    out: &mut Vec<Dependency>,
) {
    let Some(table) = node.as_table() else {
        return;
    };
    let entries = table.entries().read();
    for (key, value) in entries.iter() {
        if key.value() == "python" {
            continue;
        }
        if let Some(dependency) = poetry_dependency(index, key, value, is_dev) {
            out.push(dependency);
        }
    }
}

/// Appends the dependencies of every `[tool.poetry.group.<name>]` table. All groups are dev.
fn collect_poetry_groups(index: &LineIndex<'_>, node: &Node, out: &mut Vec<Dependency>) {
    let Some(groups) = node.as_table() else {
        return;
    };
    let entries = groups.entries().read();
    for (_, group) in entries.iter() {
        collect_poetry_table(index, &group.get("dependencies"), true, out);
    }
}

/// Appends the `dependencies` and `extra-dependencies` of every `[envs.<name>]` table. All are dev.
fn collect_hatch_envs(index: &LineIndex<'_>, node: &Node, out: &mut Vec<Dependency>) {
    let Some(envs) = node.as_table() else {
        return;
    };
    let entries = envs.entries().read();
    for (_, env) in entries.iter() {
        for key in ["dependencies", "extra-dependencies"] {
            collect_requirement_array(index, &env.get(key), true, false, out);
        }
    }
}

/// Reads one Poetry entry: `name = "^1.0"` or an inline table with `version`.
///
/// Entries with a `path`, `git` or `url` source have no registry version and yield `None`.
fn poetry_dependency(
    index: &LineIndex<'_>,
    key: &Key,
    value: &Node,
    is_dev: bool,
) -> Option<Dependency> {
    match value {
        Node::Str(version) => build_poetry_dependency(index, key, version, false, is_dev),
        Node::Table(table) => {
            let names_private_source = table.get("source").is_some_and(|source_node| {
                !source_node
                    .as_str()
                    .is_some_and(|name| name.value().eq_ignore_ascii_case(POETRY_PUBLIC_SOURCE))
            });
            if names_private_source
                || POETRY_SOURCE_KEYS
                    .iter()
                    .any(|source_key| table.get(*source_key).is_some())
            {
                return None;
            }
            let version_node = table.get("version")?;
            let version = version_node.as_str()?;
            let is_optional = table
                .get("optional")
                .as_ref()
                .and_then(Node::as_bool)
                .is_some_and(Bool::value);
            build_poetry_dependency(index, key, version, is_optional, is_dev)
        }
        _ => None,
    }
}

/// Builds a Poetry dependency. Its name span is the key, and its version span is the whole string content.
fn build_poetry_dependency(
    index: &LineIndex<'_>,
    key: &Key,
    version: &Str,
    is_optional: bool,
    is_dev: bool,
) -> Option<Dependency> {
    let name = key.value();
    let name_anchor = exact_anchor(index, key.syntax(), name)?;
    let version_text = version.value();
    let version_anchor = exact_anchor(index, version.syntax(), version_text)?;
    Some(Dependency {
        name: name.to_owned(),
        version: version_text.to_owned(),
        name_span: name_anchor.span(0..name.len())?,
        version_span: version_anchor.span(0..version_text.len())?,
        dev: is_dev,
        optional: is_optional,
        has_additional_version_constraints: false,
    })
}

/// Returns the anchor of a key or string whose raw text equals its decoded value.
///
/// Escaped text has a different raw form, so its offsets would not map onto the source.
fn exact_anchor(
    index: &LineIndex<'_>,
    element: Option<&SyntaxElement>,
    value: &str,
) -> Option<Anchor> {
    let (content_start, raw) = raw_content(index, element)?;
    if raw != value {
        return None;
    }
    Anchor::at(index, content_start)
}

/// Returns the start offset and raw text of a single-line TOML string or key, without its quotes.
///
/// The raw text keeps escapes, so it can differ from the decoded value.
fn raw_content<'a>(
    index: &LineIndex<'a>,
    element: Option<&SyntaxElement>,
) -> Option<(usize, &'a str)> {
    let range = element?.text_range();
    let (start, end) = (usize::from(range.start()), usize::from(range.end()));
    let raw = index.text().get(start..end)?;
    if raw.contains('\n') {
        return None;
    }
    let is_quoted = match raw.as_bytes() {
        [first, .., last] => first == last && matches!(first, b'"' | b'\''),
        _ => false,
    };
    let (content_start, content_end) = if is_quoted {
        (start + 1, end - 1)
    } else {
        (start, end)
    };
    Some((content_start, index.text().get(content_start..content_end)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Ecosystem;
    use crate::text::to_range;
    use openidea_plugin::Document;

    const REQUIREMENTS: &str = include_str!("../../tests/fixtures/python/requirements.txt");
    const PYPROJECT: &str = include_str!("../../tests/fixtures/python/pyproject.toml");
    const HATCH: &str = include_str!("../../tests/fixtures/python/hatch.toml");

    fn find<'a>(dependencies: &'a [Dependency], name: &str) -> &'a Dependency {
        dependencies
            .iter()
            .find(|dependency| dependency.name == name)
            .unwrap_or_else(|| panic!("missing dependency {name}"))
    }

    fn version_text(text: &str, dependency: &Dependency) -> Option<String> {
        let document = Document {
            version: 1,
            text: text.to_owned(),
        };
        let range = to_range(text, dependency.version_span)?;
        document.text_in(range).map(str::to_owned)
    }

    #[test]
    fn requirements_return_pinned_names_in_order() {
        let names: Vec<String> = parse(REQUIREMENTS)
            .into_iter()
            .map(|dependency| dependency.name)
            .collect();
        assert_eq!(names, ["requests", "flask", "numpy", "pandas", "django"]);
    }

    #[test]
    fn single_constraint_has_no_additional_constraints() {
        let dependencies = parse(REQUIREMENTS);
        let requests = find(&dependencies, "requests");
        assert_eq!(requests.version, "2.28.0");
        assert!(!requests.has_additional_version_constraints);
        assert_eq!(
            requests.name_span,
            Span {
                line: 1,
                line_start: 0,
                line_end: 8
            }
        );
        assert_eq!(
            requests.version_span,
            Span {
                line: 1,
                line_start: 10,
                line_end: 16
            }
        );
    }

    #[test]
    fn first_of_several_constraints_is_the_version() {
        let dependencies = parse(REQUIREMENTS);
        let flask = find(&dependencies, "flask");
        assert_eq!(flask.version, "2.0");
        assert!(flask.has_additional_version_constraints);
    }

    #[test]
    fn inline_comment_does_not_change_version() {
        let dependencies = parse(REQUIREMENTS);
        assert_eq!(find(&dependencies, "numpy").version, "1.24.1");
    }

    #[test]
    fn extras_and_markers_do_not_change_name_or_version() {
        let dependencies = parse(REQUIREMENTS);
        let pandas = find(&dependencies, "pandas");
        assert_eq!(pandas.version, "2.0.0");
    }

    #[test]
    fn hash_continuation_keeps_the_requirement() {
        let dependencies = parse(REQUIREMENTS);
        assert_eq!(find(&dependencies, "django").version, "4.2");
    }

    #[test]
    fn skips_options_urls_paths_and_bare_names() {
        let dependencies = parse(REQUIREMENTS);
        for skipped in ["other.txt", "git", "y", ".", "local", "six", "https"] {
            assert!(
                dependencies
                    .iter()
                    .all(|dependency| dependency.name != skipped),
                "{skipped} must not be returned"
            );
        }
    }

    #[test]
    fn crlf_line_endings_give_the_same_dependencies() {
        let lf = "requests==2.28.0\nflask>=2.0,<3\n";
        let crlf = "requests==2.28.0\r\nflask>=2.0,<3\r\n";
        assert_eq!(parse(crlf), parse(lf));
    }

    #[test]
    fn tab_indented_requirement_keeps_byte_spans() {
        let dependencies = parse("\trequests==2.28.0\n");
        let requests = find(&dependencies, "requests");
        assert_eq!(
            requests.name_span,
            Span {
                line: 0,
                line_start: 1,
                line_end: 9
            }
        );
        assert_eq!(
            requests.version_span,
            Span {
                line: 0,
                line_start: 11,
                line_end: 17
            }
        );
    }

    #[test]
    fn non_ascii_comment_keeps_version_span_exact() {
        let text = "# ünïcode header\nrequests==2.28.0\n";
        let dependencies = parse(text);
        let requests = find(&dependencies, "requests");
        assert_eq!(version_text(text, requests).as_deref(), Some("2.28.0"));
    }

    #[test]
    fn non_ascii_inline_comment_keeps_version_span_exact() {
        let text = "requests==2.28.0  # café\n";
        let dependencies = parse(text);
        let requests = find(&dependencies, "requests");
        assert_eq!(
            requests.version_span,
            Span {
                line: 0,
                line_start: 10,
                line_end: 16
            }
        );
    }

    #[test]
    fn pyproject_reads_pep621_dependencies_with_flags() {
        let dependencies = parse(PYPROJECT);
        let requests = find(&dependencies, "requests");
        assert_eq!(requests.version, "2.28.0");
        assert!(!requests.dev && !requests.optional);
        let click = find(&dependencies, "click");
        assert_eq!(click.version, "8.1.7");
        assert!(!click.dev && !click.optional);
    }

    #[test]
    fn pyproject_optional_dependencies_are_optional() {
        let dependencies = parse(PYPROJECT);
        let sphinx = find(&dependencies, "sphinx");
        assert_eq!(sphinx.version, "7.2.6");
        assert!(sphinx.optional);
    }

    #[test]
    fn pyproject_dependency_groups_are_dev_and_skip_includes() {
        let dependencies = parse(PYPROJECT);
        let pytest = find(&dependencies, "pytest");
        assert_eq!(pytest.version, "7.4.0");
        assert!(pytest.dev);
        assert!(find(&dependencies, "ruff").dev);
    }

    #[test]
    fn poetry_string_and_table_values_keep_their_text() {
        let dependencies = parse(PYPROJECT);
        let httpx = find(&dependencies, "httpx");
        assert_eq!(httpx.version, "^0.27");
        assert!(!httpx.dev);
        let attrs = find(&dependencies, "attrs");
        assert_eq!(attrs.version, "^23.1");
        assert!(attrs.optional);
    }

    #[test]
    fn poetry_dev_and_group_dependencies_are_dev() {
        let dependencies = parse(PYPROJECT);
        assert!(find(&dependencies, "mypy").dev);
        assert!(find(&dependencies, "black").dev);
    }

    #[test]
    fn poetry_python_key_and_path_sources_are_skipped() {
        let dependencies = parse(PYPROJECT);
        for skipped in ["python", "local"] {
            assert!(
                dependencies
                    .iter()
                    .all(|dependency| dependency.name != skipped),
                "{skipped} must not be returned"
            );
        }
    }

    #[test]
    fn multi_line_array_spans_point_at_each_line() {
        let dependencies = parse(PYPROJECT);
        let requests = find(&dependencies, "requests");
        assert_eq!(requests.version_span.line, 5);
        assert_eq!(version_text(PYPROJECT, requests).as_deref(), Some("2.28.0"));
        let click = find(&dependencies, "click");
        assert_eq!(click.version_span.line, 6);
        assert_eq!(version_text(PYPROJECT, click).as_deref(), Some("8.1.7"));
    }

    #[test]
    fn pyproject_non_ascii_line_keeps_version_span_exact() {
        let dependencies = parse(PYPROJECT);
        let requests = find(&dependencies, "requests");
        assert_eq!(version_text(PYPROJECT, requests).as_deref(), Some("2.28.0"));
    }

    #[test]
    fn hatch_envs_are_dev_dependencies() {
        let dependencies = parse(HATCH);
        let pytest = find(&dependencies, "pytest");
        assert_eq!(pytest.version, "7.4.0");
        assert!(pytest.dev);
        assert_eq!(find(&dependencies, "ruff").version, "0.4.1");
        assert_eq!(find(&dependencies, "mypy").version, "1.5");
    }

    /// Returns `(name, version, has_additional_version_constraints)` of each dependency.
    fn summary(text: &str) -> Vec<(String, String, bool)> {
        parse(text)
            .into_iter()
            .map(|dependency| {
                (
                    dependency.name,
                    dependency.version,
                    dependency.has_additional_version_constraints,
                )
            })
            .collect()
    }

    fn one(name: &str, version: &str, has_additional: bool) -> Vec<(String, String, bool)> {
        vec![(name.to_owned(), version.to_owned(), has_additional)]
    }

    #[test]
    fn exclusion_and_upper_bound_alone_are_not_pins() {
        for line in ["foo!=1.0\n", "flask<3\n", "bar<=2,!=1.5\n"] {
            assert!(summary(line).is_empty(), "{line:?} must not be returned");
        }
    }

    #[test]
    fn exclusion_before_a_pin_is_not_the_version() {
        assert_eq!(summary("foo!=1.5,>=1.0\n"), one("foo", "1.0", true));
        assert_eq!(
            summary("urllib3!=1.25.0,>=1.21\n"),
            one("urllib3", "1.21", true)
        );
    }

    #[test]
    fn exclusion_after_a_pin_keeps_the_pin() {
        assert_eq!(summary("foo>=1.0,!=1.5\n"), one("foo", "1.0", true));
    }

    #[test]
    fn upper_bound_before_a_pin_is_not_the_version() {
        assert_eq!(summary("flask<3,>=2\n"), one("flask", "2", true));
    }

    #[test]
    fn single_pin_has_no_additional_constraints() {
        assert_eq!(summary("baz>2.0\n"), one("baz", "2.0", false));
    }

    #[test]
    fn pin_span_points_at_the_pinned_version() {
        let text = "urllib3!=1.25.0,>=1.21\n";
        let dependencies = parse(text);
        let urllib3 = find(&dependencies, "urllib3");
        assert_eq!(version_text(text, urllib3).as_deref(), Some("1.21"));
    }

    #[test]
    fn pyproject_uses_the_same_pin_rule() {
        let text = "[project]\ndependencies = [\"urllib3!=1.25.0,>=1.21\", \"foo!=1.0\"]\n";
        let dependencies = parse(text);
        assert_eq!(summary(text), one("urllib3", "1.21", true));
        assert_eq!(
            version_text(text, find(&dependencies, "urllib3")).as_deref(),
            Some("1.21")
        );
    }

    #[test]
    fn escape_before_the_version_skips_the_string() {
        // `\u0072` decodes to `r`, so the raw text no longer matches the name offsets.
        let text = r#"[project]
dependencies = ["\u0072equests==2.28.0"]
"#;
        assert!(parse(text).is_empty());
    }

    #[test]
    fn malformed_input_returns_no_dependencies_without_panic() {
        assert!(parse("[project\ndependencies = [").is_empty());
        assert!(parse("\u{0}\u{1}==").is_empty());
        assert!(parse("").is_empty());
    }

    #[test]
    fn ecosystem_dispatches_requirements_text() {
        let names: Vec<String> = Ecosystem::PyPI
            .parse(REQUIREMENTS)
            .into_iter()
            .map(|dependency| dependency.name)
            .collect();
        assert!(names.contains(&"requests".to_owned()));
    }

    #[test]
    fn ecosystem_dispatches_pyproject_text() {
        let dependencies = Ecosystem::PyPI.parse(PYPROJECT);
        assert!(
            dependencies
                .iter()
                .any(|dependency| dependency.name == "requests")
        );
        assert!(
            dependencies
                .iter()
                .any(|dependency| dependency.name == "mypy")
        );
    }

    #[test]
    fn parenthesized_constraint_gives_the_bare_version() {
        let text = "requests (==2.28.0)\n";
        let dependencies = parse(text);
        let requests = find(&dependencies, "requests");
        assert_eq!(requests.version, "2.28.0");
        assert_eq!(version_text(text, requests).as_deref(), Some("2.28.0"));
        assert!(!requests.has_additional_version_constraints);
    }

    #[test]
    fn parenthesized_constraint_after_extras_and_before_markers() {
        let text = "requests[socks] ( >= 2.28.0 ) ; python_version < \"3.12\"\n";
        let dependencies = parse(text);
        let requests = find(&dependencies, "requests");
        assert_eq!(requests.version, "2.28.0");
        assert_eq!(version_text(text, requests).as_deref(), Some("2.28.0"));
    }

    #[test]
    fn parenthesized_constraints_keep_the_additional_constraint_flag() {
        let dependencies = parse("flask (>=2.0, <3)\n");
        let flask = find(&dependencies, "flask");
        assert_eq!(flask.version, "2.0");
        assert!(flask.has_additional_version_constraints);
    }

    #[test]
    fn parenthesized_constraint_in_pyproject() {
        let text = "[project]\nname = \"x\"\ndependencies = [\"requests (==2.28.0)\"]\n";
        let dependencies = parse(text);
        let requests = find(&dependencies, "requests");
        assert_eq!(requests.version, "2.28.0");
        assert_eq!(version_text(text, requests).as_deref(), Some("2.28.0"));
    }

    #[test]
    fn closing_parenthesis_without_opening_one_stays_part_of_the_version() {
        // Only a wrapped constraint list may end at `)`.
        let dependencies = parse("requests==2.28.0)\n");
        assert_eq!(find(&dependencies, "requests").version, "2.28.0)");
    }

    #[test]
    fn poetry_dependency_with_a_named_source_is_skipped() {
        let manifest = "\
[tool.poetry.dependencies]
python = \"^3.11\"
internal = { version = \"^1.0\", source = \"private\" }
requests = \"^2.28.0\"
";
        let dependencies = parse(manifest);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name, "requests");
    }

    #[test]
    fn poetry_dependency_with_the_pypi_source_is_kept() {
        let manifest = "\
[tool.poetry.dependencies]
python = \"^3.11\"
requests = { version = \"^2.28.0\", source = \"pypi\" }
internal = { version = \"^1.0\", source = \"private\" }
";
        let dependencies = parse(manifest);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name, "requests");
    }

    #[test]
    fn requirements_with_a_non_public_index_or_link_source_return_nothing() {
        for option in [
            "-i https://pypi.acme.internal/simple",
            "--index-url https://pypi.acme.internal/simple",
            "--index-url=https://pypi.acme.internal/simple",
            "--extra-index-url https://pypi.acme.internal/simple",
            "--extra-index-url=https://pypi.acme.internal/simple  # private",
            "-f ./wheels",
            "--find-links=https://example.com/wheels",
        ] {
            let manifest = format!("{option}\ninternal-lib==1.0\nrequests==2.0\n");
            assert!(parse(&manifest).is_empty(), "{option} must hide the file");
        }
    }

    #[test]
    fn requirements_with_the_public_index_or_unrelated_options_are_kept() {
        let manifest = "\
--index-url https://pypi.org/simple
--extra-index-url=https://pypi.org/simple/
# --index-url https://pypi.acme.internal/simple
-r other.txt
--no-binary :all:
requests==2.0
";
        let dependencies = parse(manifest);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name, "requests");
    }

    #[test]
    fn uv_sources_exclude_the_packages_they_name() {
        let manifest = "\
[project]
dependencies = [\"internal>=1.0\", \"Internal_Two==1.0\", \"third.party==1.0\", \"requests==2.28.0\"]

[dependency-groups]
dev = [\"internal-dev==1.0\"]

[tool.uv.sources]
internal = { path = \"../internal\" }
internal-two = { index = \"acme\" }
third-party = [{ git = \"https://example.com/x.git\", marker = \"sys_platform == 'linux'\" }]
internal-dev = { workspace = true }
";
        let dependencies = parse(manifest);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].name, "requests");
    }

    #[test]
    fn attached_short_options_and_continuations_are_private_sources() {
        for option in [
            "-ihttps://pypi.acme.internal/simple",
            "-fwheels",
            "--index-url\\",
            "--extra-index-url=https://pypi.acme.internal/simple\\",
        ] {
            let manifest = format!("{option}\ninternal-lib==1.0\n");
            assert!(parse(&manifest).is_empty(), "{option} must hide the file");
        }
        assert_eq!(parse("-ihttps://pypi.org/simple\nrequests==2.0\n").len(), 1);
    }

    #[test]
    fn a_private_uv_or_poetry_index_hides_the_manifest() {
        for index_setting in [
            "[tool.uv]\nindex-url = \"https://pypi.acme.internal/simple\"",
            "[tool.uv]\nextra-index-url = [\"https://pypi.acme.internal/simple\"]",
            "[tool.uv]\nfind-links = [\"./wheels\"]",
            "[[tool.uv.index]]\nname = \"acme\"\nurl = \"https://pypi.acme.internal/simple\"",
            "[[tool.poetry.source]]\nname = \"acme\"\nurl = \"https://pypi.acme.internal/simple\"",
        ] {
            let manifest =
                format!("[project]\ndependencies = [\"internal==1.0\"]\n\n{index_setting}\n");
            assert!(
                parse(&manifest).is_empty(),
                "{index_setting} must hide the file"
            );
        }
    }

    #[test]
    fn public_or_explicit_indexes_do_not_hide_the_manifest() {
        for index_setting in [
            "[tool.uv]\nindex-url = \"https://pypi.org/simple/\"",
            "[[tool.uv.index]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"",
            "[[tool.uv.index]]\nname = \"acme\"\nurl = \"https://pypi.acme.internal/simple\"\nexplicit = true",
            "[[tool.poetry.source]]\nname = \"acme\"\nurl = \"https://pypi.acme.internal/simple\"\npriority = \"explicit\"",
        ] {
            let manifest =
                format!("[project]\ndependencies = [\"requests==2.28.0\"]\n\n{index_setting}\n");
            assert_eq!(
                parse(&manifest).len(),
                1,
                "{index_setting} must keep the file"
            );
        }
    }
}
