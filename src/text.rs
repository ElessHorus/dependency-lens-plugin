//! Conversion from depsy-style byte spans to LSP UTF-16 positions.

use openidea_plugin::{Position, Range};

use crate::model::Span;

/// Converts a byte span on one line into an LSP range with UTF-16 columns.
///
/// Returns `None` when the line does not exist, when the span leaves the line,
/// or when a span edge is not on a UTF-8 character boundary.
pub fn to_range(text: &str, span: Span) -> Option<Range> {
    // `lines` already drops the `\r` of a `\r\n` terminator.
    to_range_in_line(text.lines().nth(span.line as usize)?, span)
}

/// Converts a byte span into an LSP range, given the text of its line.
///
/// A caller that converts many spans of one text collects `text.lines()` once and passes
/// each line here. [`to_range`] would walk the text from its start for every span.
pub fn to_range_in_line(line: &str, span: Span) -> Option<Range> {
    let start = span.line_start as usize;
    let end = span.line_end as usize;
    if start > end
        || end > line.len()
        || !line.is_char_boundary(start)
        || !line.is_char_boundary(end)
    {
        return None;
    }
    // LSP columns count UTF-16 units, so each edge is converted from its byte prefix.
    let start_character = utf16_units(&line[..start])?;
    let end_character = utf16_units(&line[..end])?;
    Some(Range::new(
        Position::new(span.line, start_character),
        Position::new(span.line, end_character),
    ))
}

/// Counts the UTF-16 code units of `segment`, or `None` on `u32` overflow.
fn utf16_units(segment: &str) -> Option<u32> {
    u32::try_from(segment.encode_utf16().count()).ok()
}

/// Returns the text that `span` covers in `text`, read through the same UTF-16 conversion.
#[cfg(test)]
pub fn text_of_span(text: &str, span: Span) -> Option<String> {
    use openidea_plugin::Document;
    let document = Document {
        version: 1,
        text: text.to_owned(),
    };
    document.text_in(to_range(text, span)?).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_bytes_to_utf16_columns() {
        // "é" is 2 bytes in UTF-8 but 1 UTF-16 unit.
        let text = "é = \"1.0\"\n";
        let span = Span {
            line: 0,
            line_start: 6,
            line_end: 9,
        };
        let range = to_range(text, span).unwrap();
        assert_eq!(range, Range::new(Position::new(0, 5), Position::new(0, 8)));
    }

    #[test]
    fn rejects_span_outside_line() {
        let text = "a = 1\n";
        let span = Span {
            line: 0,
            line_start: 4,
            line_end: 40,
        };
        assert_eq!(to_range(text, span), None);
    }

    #[test]
    fn rejects_missing_line() {
        let text = "a = 1\n";
        let span = Span {
            line: 5,
            line_start: 0,
            line_end: 1,
        };
        assert_eq!(to_range(text, span), None);
    }

    #[test]
    fn rejects_span_inside_multibyte_char() {
        let text = "é = 1\n";
        let span = Span {
            line: 0,
            line_start: 1,
            line_end: 3,
        };
        assert_eq!(to_range(text, span), None);
    }

    #[test]
    fn maps_crlf_line_without_carriage_return() {
        // Line 1 is `b = "1"`; the value `"1"` sits at bytes 4..7.
        let text = "a\r\nb = \"1\"\r\n";
        let span = Span {
            line: 1,
            line_start: 4,
            line_end: 7,
        };
        let range = to_range(text, span).unwrap();
        assert_eq!(range, Range::new(Position::new(1, 4), Position::new(1, 7)));
    }

    #[test]
    fn a_range_from_a_split_line_table_equals_the_range_from_the_text() {
        let text = "é = 1\r\n[a]\nname = \"é1\"\n";
        let lines: Vec<&str> = text.lines().collect();
        for span in [
            Span {
                line: 0,
                line_start: 5,
                line_end: 6,
            },
            Span {
                line: 2,
                line_start: 8,
                line_end: 11,
            },
            Span {
                line: 3,
                line_start: 0,
                line_end: 1,
            },
            Span {
                line: 1,
                line_start: 9,
                line_end: 10,
            },
        ] {
            assert_eq!(
                lines
                    .get(span.line as usize)
                    .and_then(|line| to_range_in_line(line, span)),
                to_range(text, span)
            );
        }
    }
}
