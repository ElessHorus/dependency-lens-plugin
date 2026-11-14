//! RubyGems version numbers, compared like Ruby's `Gem::Version`.

use std::cmp::Ordering;

/// One run of a version, such as `1` or `rc` in `1.0.rc1`.
///
/// `Str` comes first, so the derived order puts letter runs below numbers. That is the rule for `1.0.rc1 < 1.0`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Segment {
    /// Lowercased letters. Any letter segment makes the version a prerelease.
    Str(String),
    /// Decimal digits.
    Num(u64),
}

/// The segment that a missing position counts as, so `1.0` equals `1.0.0`.
static MISSING_SEGMENT: Segment = Segment::Num(0);

/// A parsed RubyGems version such as `8.1.4.1` or `8.1.0.rc1`.
#[derive(Clone, Debug)]
pub struct GemVersion {
    segments: Vec<Segment>,
}

impl GemVersion {
    /// Parses `text`. Returns `None` for empty, malformed or overflowing input.
    pub fn parse(text: &str) -> Option<GemVersion> {
        // A dash starts a prerelease, so `1.0.0-beta` reads as `1.0.0.pre.beta`.
        let normalized = text.trim().replace('-', ".pre.");
        let mut components = normalized.split('.');
        let first_component = components.next()?;
        if first_component.is_empty() || !first_component.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let mut segments = Vec::new();
        push_runs(first_component, &mut segments)?;
        for component in components {
            if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                return None;
            }
            push_runs(component, &mut segments)?;
        }
        Some(GemVersion { segments })
    }

    /// Returns `true` when the version has a letter segment, such as `rc1` or `beta`.
    pub fn is_prerelease(&self) -> bool {
        self.segments
            .iter()
            .any(|segment| matches!(segment, Segment::Str(_)))
    }

    /// Returns the leading numeric segments, such as `[8, 1, 4, 1]` for `8.1.4.1`.
    pub fn release(&self) -> Vec<u64> {
        self.segments
            .iter()
            .map_while(|segment| match segment {
                Segment::Num(number) => Some(*number),
                Segment::Str(_) => None,
            })
            .collect()
    }
}

/// Appends the digit runs and letter runs of one alphanumeric component. `rc1` becomes `rc` and `1`.
///
/// `chunk_by` splits the bytes in one pass, so no run is copied before it is parsed.
fn push_runs(component: &str, segments: &mut Vec<Segment>) -> Option<()> {
    for run in component
        .as_bytes()
        .chunk_by(|left, right| left.is_ascii_digit() == right.is_ascii_digit())
    {
        let run_text = std::str::from_utf8(run).ok()?;
        let segment = if run_text.starts_with(|character: char| character.is_ascii_digit()) {
            Segment::Num(run_text.parse().ok()?)
        } else {
            Segment::Str(run_text.to_ascii_lowercase())
        };
        segments.push(segment);
    }
    Some(())
}

impl Ord for GemVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // Lazy iterators compare the padded segments without building padded copies.
        let segment_count = self.segments.len().max(other.segments.len());
        (0..segment_count)
            .map(|index| segment_at(&self.segments, index))
            .cmp((0..segment_count).map(|index| segment_at(&other.segments, index)))
    }
}

/// Returns the segment at `index`, or the zero segment past the end.
fn segment_at(segments: &[Segment], index: usize) -> &Segment {
    segments.get(index).unwrap_or(&MISSING_SEGMENT)
}

impl PartialOrd for GemVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for GemVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for GemVersion {}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(text: &str) -> GemVersion {
        GemVersion::parse(text).unwrap_or_else(|| panic!("{text} must parse"))
    }

    #[test]
    fn orders_prereleases_before_their_release_and_numbers_numerically() {
        let chain = [
            "1.0.0.a",
            "1.0.0.rc1",
            "1.0.0.rc2",
            "1.0.0",
            "1.0.0.1",
            "1.0.1",
            "1.1",
            "2.0",
        ];
        for pair in chain.windows(2) {
            assert!(
                version(pair[0]) < version(pair[1]),
                "{} < {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn pads_missing_segments_with_zeros() {
        assert_eq!(version("1.0"), version("1.0.0"));
        assert_eq!(version("1.0.0"), version("1.0.0.0"));
    }

    #[test]
    fn reads_a_dash_as_a_pre_segment() {
        assert_eq!(version("1.0.0-beta"), version("1.0.0.pre.beta"));
        assert!(version("1.0.0-beta").is_prerelease());
    }

    #[test]
    fn a_fourth_segment_is_newer_than_its_release() {
        assert!(version("8.1.4.1") > version("8.1.4"));
    }

    #[test]
    fn detects_prereleases_by_any_letter_segment() {
        assert!(version("8.1.0.rc1").is_prerelease());
        assert!(version("1.0.0.pre").is_prerelease());
        assert!(version("2.0.0.beta1").is_prerelease());
        assert!(!version("8.1.4.1").is_prerelease());
    }

    #[test]
    fn exposes_the_leading_numeric_segments_as_the_release() {
        assert_eq!(version("8.1.4.1").release(), [8, 1, 4, 1]);
        assert_eq!(version("1.0.0.rc1").release(), [1, 0, 0]);
    }

    #[test]
    fn rejects_empty_garbage_and_overflowing_versions() {
        for text in ["", "abc", "1..2", "1.0.", ".1", "99999999999999999999"] {
            assert!(GemVersion::parse(text).is_none(), "{text}");
        }
    }
}
