//! Helpers shared by the XML manifest parsers: element names and element text spans.

use std::borrow::Cow;

use quick_xml::escape::unescape;
use quick_xml::name::QName;

use super::spans::LineIndex;
use crate::model::Span;

/// Text of one element, with the span of its trimmed content.
#[derive(Clone, Copy)]
pub struct Field<'a> {
    pub text: &'a str,
    pub span: Span,
}

/// Returns the byte offset of a reader position, or `None` when it does not fit `usize`.
pub fn byte_offset(position: u64) -> Option<usize> {
    usize::try_from(position).ok()
}

/// Returns the element name that starts at `name_start` in `text`.
pub fn element_name<'a>(text: &'a str, name_start: usize, name: QName<'_>) -> Option<&'a str> {
    text.get(name_start..)?.get(..name.0.len())
}

/// Reads the trimmed text of `text[content_start..content_end]` as a plain value.
///
/// Returns `None` when the content holds child markup, an entity, or when the trimmed
/// text spans lines. Whitespace around the value, such as a pretty-printed line break,
/// is allowed: the span covers only the trimmed text.
/// An entity would make the raw span differ from the value, so the value is dropped.
pub fn read_field<'a>(
    text: &'a str,
    index: &LineIndex<'_>,
    content_start: usize,
    content_end: usize,
) -> Option<Field<'a>> {
    let raw = text.get(content_start..content_end)?;
    if raw.contains('<') {
        return None;
    }
    if !matches!(unescape(raw), Ok(Cow::Borrowed(_))) {
        return None;
    }
    trimmed_field(raw, content_start, index)
}

/// Returns the trimmed text of `raw`, which starts at byte `raw_start` of the source.
///
/// Returns `None` when the trimmed text is empty or spans lines.
pub fn trimmed_field<'a>(
    raw: &'a str,
    raw_start: usize,
    index: &LineIndex<'_>,
) -> Option<Field<'a>> {
    let value = raw.trim_ascii();
    if value.is_empty() {
        return None;
    }
    let value_start = raw_start + (raw.len() - raw.trim_ascii_start().len());
    // `span` returns `None` when the trimmed text contains a line break.
    let span = index.span(value_start, value_start + value.len())?;
    Some(Field { text: value, span })
}
