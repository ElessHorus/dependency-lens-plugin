//! Byte-offset to line-and-column conversion shared by every parser.

use std::iter::once;

use crate::model::Span;

/// Byte offsets of the start of every line of one text, built once per parse.
pub struct LineIndex<'a> {
    text: &'a str,
    line_starts: Box<[usize]>,
}

impl<'a> LineIndex<'a> {
    /// Builds the line table of `text`. Lines split on `\n` only.
    pub fn new(text: &'a str) -> Self {
        let line_starts = once(0)
            .chain(text.match_indices('\n').map(|(index, _)| index + 1))
            .collect();
        Self { text, line_starts }
    }

    /// Returns the text this index was built from.
    pub fn text(&self) -> &'a str {
        self.text
    }

    /// Returns the 0-based line and the byte column of `offset`.
    ///
    /// Returns `None` when `offset` is past the end of the text or when the line
    /// number does not fit a `u32`. `offset == text.len()` is valid.
    pub fn locate(&self, offset: usize) -> Option<(u32, usize)> {
        if offset > self.text.len() {
            return None;
        }
        let line_index = self.line_index_of(offset);
        let line = u32::try_from(line_index).ok()?;
        Some((line, offset - self.line_starts[line_index]))
    }

    /// Returns the span of `text[start..end]` when the range lies on one line.
    ///
    /// The `\n` and the `\r` before it are not part of a line's content. Returns
    /// `None` when `start > end`, when `end` is past the text, or when the range
    /// includes a line break.
    pub fn span(&self, start: usize, end: usize) -> Option<Span> {
        if start > end || end > self.text.len() {
            return None;
        }
        let line_index = self.line_index_of(start);
        let line_start = self.line_starts[line_index];
        if end > self.content_end(line_index) {
            return None;
        }
        Some(Span {
            line: u32::try_from(line_index).ok()?,
            line_start: u32::try_from(start - line_start).ok()?,
            line_end: u32::try_from(end - line_start).ok()?,
        })
    }

    /// Returns the index of the line that holds `offset`. `offset` must be within the text.
    fn line_index_of(&self, offset: usize) -> usize {
        // Line 0 starts at 0, so the count of starts at or before `offset` is at least 1.
        self.line_starts.partition_point(|&start| start <= offset) - 1
    }

    /// Returns the byte offset past the last content byte of a line, without its `\n` or `\r\n`.
    fn content_end(&self, line_index: usize) -> usize {
        let line_start = self.line_starts[line_index];
        let mut end = self
            .line_starts
            .get(line_index + 1)
            .map_or(self.text.len(), |next_start| next_start - 1);
        if end > line_start && self.text.as_bytes()[end - 1] == b'\r' {
            end -= 1;
        }
        end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_text_has_one_empty_line() {
        let index = LineIndex::new("");
        assert_eq!(index.locate(0), Some((0, 0)));
        assert_eq!(index.locate(1), None);
        assert_eq!(
            index.span(0, 0),
            Some(Span {
                line: 0,
                line_start: 0,
                line_end: 0
            })
        );
    }

    #[test]
    fn locates_offsets_on_each_line() {
        let index = LineIndex::new("ab\ncd\n");
        assert_eq!(index.locate(0), Some((0, 0)));
        // The `\n` byte belongs to line 0.
        assert_eq!(index.locate(2), Some((0, 2)));
        assert_eq!(index.locate(3), Some((1, 0)));
        // End of text is the empty last line.
        assert_eq!(index.locate(6), Some((2, 0)));
        assert_eq!(index.locate(7), None);
    }

    #[test]
    fn span_stops_before_the_line_break() {
        let index = LineIndex::new("ab\ncd\n");
        assert_eq!(
            index.span(3, 5),
            Some(Span {
                line: 1,
                line_start: 0,
                line_end: 2
            })
        );
        assert!(index.span(0, 2).is_some());
        assert_eq!(index.span(0, 3), None);
        assert_eq!(index.span(1, 4), None);
        assert_eq!(index.span(4, 3), None);
        assert_eq!(index.span(0, 99), None);
    }

    #[test]
    fn crlf_carriage_return_does_not_shift_the_next_line() {
        let index = LineIndex::new("a\r\nb = \"1\"\r\n");
        assert_eq!(
            index.span(8, 9),
            Some(Span {
                line: 1,
                line_start: 5,
                line_end: 6
            })
        );
    }

    #[test]
    fn columns_are_byte_offsets_not_utf16() {
        let index = LineIndex::new("é = \"1.0\"\n");
        assert_eq!(
            index.span(6, 9),
            Some(Span {
                line: 0,
                line_start: 6,
                line_end: 9
            })
        );
    }

    #[test]
    fn last_line_without_trailing_newline_is_spanned() {
        let index = LineIndex::new("a\nb");
        assert_eq!(
            index.span(2, 3),
            Some(Span {
                line: 1,
                line_start: 0,
                line_end: 1
            })
        );
    }

    #[test]
    fn text_returns_the_source_slice() {
        let text = "a\nb";
        assert_eq!(LineIndex::new(text).text(), text);
    }
}
