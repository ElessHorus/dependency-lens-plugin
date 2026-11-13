//! Parser for Go module files (`go.mod`).
//!
//! Reads the `require` directives only, in the single-line form and in the
//! block form. Other directives, such as `replace`, `exclude` and `retract`,
//! are skipped together with their blocks. Go modules have no registry
//! version hint, so every entry has `dev = false` and no extra constraints.

use crate::model::{Dependency, Span};

/// Directive whose block is open at the current line.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenBlock {
    None,
    Require,
    /// A block of any other directive. Its lines are skipped until `)`.
    Other,
}

/// Parses the `require` entries of a `go.mod` file.
///
/// One pass over the lines. Spans use byte columns within the line, so no
/// line index is needed. Entries keep document order.
pub fn parse(text: &str) -> Vec<Dependency> {
    let mut dependencies = Vec::new();
    let mut open_block = OpenBlock::None;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        let Ok(line_number) = u32::try_from(index) else {
            break;
        };
        let content = line.trim_end_matches(['\r', '\n']);
        let (code, comment) = content.split_once("//").unwrap_or((content, ""));
        // Blank and comment-only lines have no field, so they never change the block state.
        let Some((keyword_start, keyword)) = next_field(code, 0) else {
            continue;
        };

        match open_block {
            OpenBlock::Other if keyword == ")" => open_block = OpenBlock::None,
            OpenBlock::Other => {}
            OpenBlock::Require if keyword == ")" => open_block = OpenBlock::None,
            // Inside a require block the first field is the module path.
            OpenBlock::Require => {
                dependencies.extend(parse_entry(code, comment, 0, line_number));
            }
            OpenBlock::None => {
                let keyword_end = keyword_start + keyword.len();
                let opens_block =
                    next_field(code, keyword_end).is_some_and(|(_, field)| field.starts_with('('));
                if keyword == "require" {
                    if opens_block {
                        open_block = OpenBlock::Require;
                    } else {
                        dependencies.extend(parse_entry(code, comment, keyword_end, line_number));
                    }
                } else if opens_block {
                    open_block = OpenBlock::Other;
                }
            }
        }
    }
    dependencies
}

/// Returns `true` for a separator of go.mod fields.
fn is_separator(character: char) -> bool {
    matches!(character, ' ' | '\t')
}

/// Returns the next field at or after `from`, with its byte offset in `code`.
///
/// Returns `None` when no field is left. `from` must be a field boundary.
fn next_field(code: &str, from: usize) -> Option<(usize, &str)> {
    let rest = code.get(from..)?;
    let trimmed = rest.trim_start_matches(is_separator);
    let start = code.len() - trimmed.len();
    // `trimmed` starts with a non-separator, so the first split piece is the field.
    let field = trimmed
        .split(is_separator)
        .next()
        .filter(|field| !field.is_empty())?;
    Some((start, field))
}

/// Reads `module version` from `code` starting at `from`.
///
/// `comment` is the text after `//`. An `indirect` comment marks the entry as
/// optional. Returns `None` for a quoted path, a missing field or a version
/// that does not start with `v` and a digit.
fn parse_entry(code: &str, comment: &str, from: usize, line_number: u32) -> Option<Dependency> {
    let (name_start, name) = next_field(code, from)?;
    let (version_start, version) = next_field(code, name_start + name.len())?;
    if name.starts_with(['"', '`']) || !is_go_version(version) {
        return None;
    }
    Some(Dependency {
        name: name.to_owned(),
        version: version.to_owned(),
        name_span: field_span(line_number, name_start, name)?,
        version_span: field_span(line_number, version_start, version)?,
        dev: false,
        optional: comment.trim_start().starts_with("indirect"),
        has_additional_version_constraints: false,
    })
}

/// Returns `true` when `field` starts with `v` followed by a digit, as Go versions do.
fn is_go_version(field: &str) -> bool {
    field
        .strip_prefix('v')
        .is_some_and(|rest| rest.starts_with(|character: char| character.is_ascii_digit()))
}

/// Builds the span of `field`, which starts at byte `start` of its line.
fn field_span(line_number: u32, start: usize, field: &str) -> Option<Span> {
    let line_start = u32::try_from(start).ok()?;
    let line_end = u32::try_from(start + field.len()).ok()?;
    Some(Span {
        line: line_number,
        line_start,
        line_end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::text_of_span;

    const FIXTURE: &str = include_str!("../../tests/fixtures/go/go.mod");

    fn find<'a>(dependencies: &'a [Dependency], name: &str) -> &'a Dependency {
        dependencies
            .iter()
            .find(|dependency| dependency.name == name)
            .unwrap_or_else(|| panic!("missing dependency {name}"))
    }

    #[test]
    fn returns_exact_require_entries_in_document_order() {
        let dependencies = parse(FIXTURE);
        let entries: Vec<(&str, &str, bool)> = dependencies
            .iter()
            .map(|dependency| {
                (
                    dependency.name.as_str(),
                    dependency.version.as_str(),
                    dependency.optional,
                )
            })
            .collect();
        assert_eq!(
            entries,
            [
                ("github.com/pkg/errors", "v0.9.1", false),
                ("golang.org/x/text", "v0.3.0", true),
                (
                    "example.com/pseudo",
                    "v0.0.0-20200101120000-abcdefabcdef",
                    false
                ),
                ("gopkg.in/yaml.v3", "v3.0.1", false),
                ("github.com/old/lib", "v2.0.0+incompatible", false),
                ("github.com/single/dep", "v1.2.3", false),
            ]
        );
    }

    #[test]
    fn every_entry_is_a_runtime_dependency_without_extra_constraints() {
        let dependencies = parse(FIXTURE);
        assert!(dependencies.iter().all(|dependency| !dependency.dev
            && !dependency.has_additional_version_constraints));
    }

    #[test]
    fn spans_point_at_name_and_version_text() {
        let dependencies = parse(FIXTURE);
        let text_entry = find(&dependencies, "golang.org/x/text");
        assert_eq!(
            text_of_span(FIXTURE, text_entry.version_span).as_deref(),
            Some("v0.3.0")
        );
        assert_eq!(
            text_of_span(FIXTURE, text_entry.name_span).as_deref(),
            Some("golang.org/x/text")
        );
    }

    #[test]
    fn crlf_line_endings_give_identical_dependencies() {
        let crlf_text = FIXTURE.replace('\n', "\r\n");
        assert_eq!(parse(&crlf_text), parse(FIXTURE));
    }

    #[test]
    fn tab_and_space_indented_entries_have_exact_spans() {
        let spaced = "require (\n    github.com/a/b v1.0.0\n)\n";
        let tabbed = "require (\n\tgithub.com/a/b v1.0.0\n)\n";
        for manifest in [spaced, tabbed] {
            let dependencies = parse(manifest);
            let entry = find(&dependencies, "github.com/a/b");
            assert_eq!(
                text_of_span(manifest, entry.version_span).as_deref(),
                Some("v1.0.0")
            );
            assert_eq!(
                text_of_span(manifest, entry.name_span).as_deref(),
                Some("github.com/a/b")
            );
        }
    }

    #[test]
    fn non_ascii_comment_does_not_shift_spans() {
        let manifest = "require github.com/a/b v1.0.0 // café\n";
        let dependencies = parse(manifest);
        let entry = find(&dependencies, "github.com/a/b");
        assert_eq!(
            text_of_span(manifest, entry.version_span).as_deref(),
            Some("v1.0.0")
        );
        assert_eq!(
            text_of_span(manifest, entry.name_span).as_deref(),
            Some("github.com/a/b")
        );
    }

    #[test]
    fn skips_malformed_and_quoted_require_entries() {
        for manifest in [
            "require github.com/lonely\n",
            "require github.com/x/y notaversion\n",
            "require \"github.com/q/r\" v1.0.0\n",
        ] {
            assert!(
                parse(manifest).is_empty(),
                "{manifest:?} must yield nothing"
            );
        }
    }

    #[test]
    fn unterminated_block_keeps_entries_read_so_far() {
        let dependencies = parse("require (\n\tgithub.com/a/b v1.0.0\n\tgithub.com/c/d v2.0.0\n");
        assert_eq!(dependencies.len(), 2);
    }

    #[test]
    fn empty_text_returns_nothing() {
        assert!(parse("").is_empty());
    }
}
