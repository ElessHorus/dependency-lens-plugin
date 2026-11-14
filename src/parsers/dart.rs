//! Parser for Dart and Flutter `pubspec.yaml` files.
//!
//! Reads the `dependencies` and `dev_dependencies` blocks only. Entries with a
//! `sdk`, `path`, `git` or `url` key, or with a `hosted` key that is not pub.dev, come from a source other than the registry,
//! so they are skipped. The parser is line based and reads each line once. It
//! does not use a YAML library, so quoted keys are not read.

use crate::model::{Dependency, Span};

/// Keys that make a map-form entry a non-registry source.
const SOURCE_KEYS: [&str; 4] = ["sdk", "path", "git", "url"];

/// URLs of the public pub.dev registry. A `hosted` entry with one of them is a registry entry.
const PUBLIC_REGISTRY_URLS: [&str; 2] = ["https://pub.dev", "https://pub.dartlang.org"];

/// One `key: value` line. Offsets are byte columns inside the line.
struct Field<'a> {
    key: &'a str,
    /// Byte offset of the key. The key starts after the indentation.
    key_start: usize,
    /// `None` when the value is malformed, such as an unterminated quote.
    value: Option<Value<'a>>,
}

/// The text of a value and the byte offset where it starts inside the line.
///
/// An empty text after a key means that a map follows.
struct Value<'a> {
    text: &'a str,
    start: usize,
}

/// An entry whose nested lines may still change its version or skip it.
struct PendingEntry<'a> {
    /// 0-based line of the entry key.
    line: u32,
    name: &'a str,
    name_start: usize,
    /// Non-empty version text, taken from the scalar value or a direct `version:` child.
    version: Option<Value<'a>>,
    /// 0-based line of `version`, which differs from `line` for a direct `version:` child.
    version_line: u32,
    /// `true` for the map form, where nested lines may hold the version.
    is_map: bool,
    /// Indentation of the direct children of a map-form entry, set by its first child.
    child_indent: Option<usize>,
    /// `true` once a direct key names a non-registry source.
    is_skipped: bool,
    dev: bool,
}

/// Parses the registry dependencies of a `pubspec.yaml` file.
///
/// Entries keep document order. Malformed lines are skipped, and an unterminated
/// block keeps the entries read so far.
pub fn parse(text: &str) -> Vec<Dependency> {
    let mut dependencies = Vec::new();
    // `Some(dev)` inside a block that this parser reads, `None` in every other block.
    let mut block_dev: Option<bool> = None;
    // Indentation of the entries of the open block, set by its first indented line.
    let mut entry_indent: Option<usize> = None;
    let mut entry: Option<PendingEntry<'_>> = None;
    for (index, raw_line) in text.split_inclusive('\n').enumerate() {
        let Ok(line_number) = u32::try_from(index) else {
            break;
        };
        let line = raw_line.trim_end_matches(['\r', '\n']);
        // Blank and comment lines never change the state. Tab indentation is not valid YAML.
        let body = line.trim_start_matches([' ', '\t']);
        let indent = line.len() - body.len();
        let leading = line.get(..indent).unwrap_or_default();
        if body.is_empty() || body.starts_with('#') || leading.contains('\t') {
            continue;
        }
        let field = read_field(line, indent);

        // A line without indentation ends the open entry and selects the next block.
        if indent == 0 {
            finish_entry(entry.take(), &mut dependencies);
            entry_indent = None;
            block_dev = match field.as_ref().map(|field| field.key) {
                Some("dependencies") => Some(false),
                Some("dev_dependencies") => Some(true),
                _ => None,
            };
            continue;
        }
        let Some(dev) = block_dev else {
            continue;
        };

        let block_indent = *entry_indent.get_or_insert(indent);
        if indent == block_indent {
            finish_entry(entry.take(), &mut dependencies);
            entry = field.map(|field| PendingEntry::start(field, line_number, dev));
        } else if indent < block_indent {
            finish_entry(entry.take(), &mut dependencies);
        } else if let Some(pending) = entry.as_mut() {
            pending.apply_nested(line_number, indent, field);
        }
    }
    finish_entry(entry, &mut dependencies);
    dependencies
}

impl<'a> PendingEntry<'a> {
    /// Opens an entry from its key line. A scalar value is the version, and an empty value opens a map.
    fn start(field: Field<'a>, line: u32, dev: bool) -> Self {
        let is_map = field
            .value
            .as_ref()
            .is_some_and(|value| value.text.is_empty());
        let version = field.value.filter(|value| !value.text.is_empty());
        Self {
            line,
            name: field.key,
            name_start: field.key_start,
            version,
            version_line: line,
            is_map,
            child_indent: None,
            is_skipped: false,
            dev,
        }
    }

    /// Applies a line nested under this entry. Only the direct keys count, so deeper lines are ignored.
    fn apply_nested(&mut self, line: u32, indent: usize, field: Option<Field<'a>>) {
        if !self.is_map {
            return;
        }
        let direct_indent = *self.child_indent.get_or_insert(indent);
        if indent != direct_indent {
            return;
        }
        let Some(field) = field else {
            return;
        };
        if SOURCE_KEYS.contains(&field.key) || names_custom_server(&field) {
            self.is_skipped = true;
        } else if field.key == "version"
            && let Some(value) = field.value.filter(|value| !value.text.is_empty())
        {
            self.version = Some(value);
            self.version_line = line;
        }
    }
}

/// Returns `true` for a `hosted` key that does not name pub.dev.
///
/// The map form (`hosted:` with nested `name` and `url`) is not read, so it counts
/// as a custom server. The scalar form counts only when its URL is not pub.dev.
fn names_custom_server(field: &Field<'_>) -> bool {
    field.key == "hosted"
        && !field
            .value
            .as_ref()
            .is_some_and(|value| PUBLIC_REGISTRY_URLS.contains(&value.text.trim_end_matches('/')))
}

/// Reads `key: value` from `line`, whose key starts at byte `indent`.
///
/// Returns `None` for a line without a key, for a quoted key, and for a colon
/// that is not followed by a space, a tab or the end of the line.
fn read_field(line: &str, indent: usize) -> Option<Field<'_>> {
    let body = line.get(indent..)?;
    let colon = body.find(':')?;
    let key = body.get(..colon)?.trim_end_matches([' ', '\t']);
    let after_colon = body.get(colon + 1..)?;
    let key_is_plain = !key.is_empty() && !key.starts_with(['\'', '"']);
    let colon_is_separator = after_colon.is_empty() || after_colon.starts_with([' ', '\t']);
    if !key_is_plain || !colon_is_separator {
        return None;
    }
    Some(Field {
        key,
        key_start: indent,
        value: read_value(line, indent + colon + 1),
    })
}

/// Reads the value that follows the colon at byte `from` of `line`.
///
/// A quoted value keeps the text between its quotes. A plain value stops before
/// a comment, which starts at `#` after a space or a tab. Returns `None` for an
/// unterminated quote or for text after the closing quote other than a comment.
fn read_value(line: &str, from: usize) -> Option<Value<'_>> {
    let rest = line.get(from..)?;
    let start = from + (rest.len() - rest.trim_start_matches([' ', '\t']).len());
    let value_text = line.get(start..)?;
    if let Some(quote) = value_text
        .chars()
        .next()
        .filter(|character| matches!(character, '\'' | '"'))
    {
        // A quote is one byte, so the quoted text starts one byte after the opening quote.
        let inner_start = start + 1;
        let inner = line.get(inner_start..)?;
        let inner_len = inner.find(quote)?;
        let after_quote = inner.get(inner_len + 1..)?.trim_start_matches([' ', '\t']);
        if !after_quote.is_empty() && !after_quote.starts_with('#') {
            return None;
        }
        return Some(Value {
            text: inner.get(..inner_len)?,
            start: inner_start,
        });
    }
    // A `#` at the start of the value is a comment too. Index 0 has no byte before it.
    let comment_at = value_text
        .match_indices('#')
        .find(|&(index, _)| {
            index == 0
                || value_text
                    .as_bytes()
                    .get(index - 1)
                    .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        })
        .map_or(value_text.len(), |(index, _)| index);
    let text = value_text.get(..comment_at)?.trim_end_matches([' ', '\t']);
    Some(Value { text, start })
}

/// Pushes the finished entry when it names a registry version.
fn finish_entry(entry: Option<PendingEntry<'_>>, dependencies: &mut Vec<Dependency>) {
    let Some(entry) = entry else {
        return;
    };
    if entry.is_skipped {
        return;
    }
    let Some(version) = entry.version else {
        return;
    };
    let (Some(name_span), Some(version_span)) = (
        span_at(entry.line, entry.name_start, entry.name.len()),
        span_at(entry.version_line, version.start, version.text.len()),
    ) else {
        return;
    };
    dependencies.push(Dependency {
        name: entry.name.to_owned(),
        version: version.text.to_owned(),
        name_span,
        version_span,
        dev: entry.dev,
        optional: false,
        has_additional_version_constraints: false,
    });
}

/// Builds the span of `length` bytes that start at byte `start` of `line`.
fn span_at(line: u32, start: usize, length: usize) -> Option<Span> {
    Some(Span {
        line,
        line_start: u32::try_from(start).ok()?,
        line_end: u32::try_from(start + length).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::text_of_span;

    const FIXTURE: &str = include_str!("../../tests/fixtures/dart/pubspec.yaml");

    /// Returns `(name, version, dev)` for each dependency, in order.
    fn summary(dependencies: &[Dependency]) -> Vec<(&str, &str, bool)> {
        dependencies
            .iter()
            .map(|dependency| {
                (
                    dependency.name.as_str(),
                    dependency.version.as_str(),
                    dependency.dev,
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
    fn returns_exact_registry_entries_in_document_order() {
        assert_eq!(
            summary(&parse(FIXTURE)),
            [
                ("http", "^1.0.0", false),
                ("provider", "^6.1.0", false),
                ("intl", "any", false),
                ("versioned_pkg", "^2.3.4", false),
                ("old", ">=1.0.0 <2.0.0", false),
                ("lints", "^3.0.0", true),
            ]
        );
    }

    #[test]
    fn version_spans_read_back_the_bare_requirement() {
        let dependencies = parse(FIXTURE);
        let text_of = |name: &str| {
            let dependency = find(&dependencies, name);
            text_of_span(FIXTURE, dependency.version_span)
        };
        assert_eq!(text_of("http").as_deref(), Some("^1.0.0"));
        assert_eq!(text_of("provider").as_deref(), Some("^6.1.0"));
        assert_eq!(text_of("versioned_pkg").as_deref(), Some("^2.3.4"));
    }

    #[test]
    fn name_span_reads_back_the_key() {
        let dependencies = parse(FIXTURE);
        let http = find(&dependencies, "http");
        assert_eq!(
            text_of_span(FIXTURE, http.name_span).as_deref(),
            Some("http")
        );
    }

    #[test]
    fn crlf_line_endings_give_identical_dependencies() {
        let crlf_text = FIXTURE.replace('\n', "\r\n");
        assert_eq!(parse(&crlf_text), parse(FIXTURE));
    }

    #[test]
    fn non_ascii_trailing_comment_does_not_shift_spans() {
        let manifest = "dependencies:\n  http: ^1.0.0 # café\n  provider: '^6.1.0' # é\n";
        let dependencies = parse(manifest);
        assert_eq!(
            text_of_span(manifest, find(&dependencies, "http").version_span).as_deref(),
            Some("^1.0.0")
        );
        assert_eq!(
            text_of_span(manifest, find(&dependencies, "provider").version_span).as_deref(),
            Some("^6.1.0")
        );
    }

    #[test]
    fn tab_indented_entries_are_skipped() {
        let manifest = "dependencies:\n\thttp: ^1.0.0\n  provider: ^6.0.0\n";
        assert_eq!(summary(&parse(manifest)), [("provider", "^6.0.0", false)]);
    }

    #[test]
    fn empty_and_garbage_input_give_no_dependencies() {
        assert!(parse("").is_empty());
        assert!(parse("dependencies:\n  ::::\n  'unterminated: x\n\u{0}\n").is_empty());
        assert!(parse("\u{feff}\u{ffff}: ?").is_empty());
    }

    #[test]
    fn unterminated_block_keeps_entries_read_so_far() {
        let manifest = "dependencies:\n  http: ^1.0.0\n  provider: ^6.0.0\n";
        assert_eq!(parse(manifest).len(), 2);
    }

    #[test]
    fn hosted_entries_come_from_a_custom_server_and_are_skipped() {
        let manifest = "\
dependencies:
  scalar_form:
    hosted: https://pub.example.com
    version: ^1.0.0
  map_form:
    hosted:
      name: map_form
      url: https://pub.example.com
    version: ^1.0.0
  http: ^1.0.0
";
        assert_eq!(summary(&parse(manifest)), [("http", "^1.0.0", false)]);
    }

    #[test]
    fn hosted_entry_with_the_public_pub_dev_url_is_kept() {
        let manifest = "\
dependencies:
  plain:
    hosted: https://pub.dev
    version: ^1.0.0
  slash:
    hosted: \"https://pub.dev/\"
    version: ^2.0.0
  lookalike:
    hosted: https://pub.dev.evil.example
    version: ^3.0.0
";
        assert_eq!(
            summary(&parse(manifest)),
            [("plain", "^1.0.0", false), ("slash", "^2.0.0", false)]
        );
    }
}
