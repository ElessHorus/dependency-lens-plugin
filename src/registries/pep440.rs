//! PEP 440 version parsing and ordering for PyPI release keys.

use std::cmp::Ordering;

/// Kind of a pre-release segment. The declaration order is the ordering: `a < b < rc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PreKind {
    A,
    B,
    Rc,
}

/// A parsed PEP 440 version.
#[derive(Clone, Debug)]
pub struct Pep440 {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<(PreKind, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
    local: Option<String>,
}

impl Pep440 {
    /// Parses a PEP 440 version. Returns `None` when `text` is not a version.
    pub fn parse(text: &str) -> Option<Pep440> {
        // Lowercasing once lets the rest of the parser match ASCII spellings only.
        let lowered = text.trim().to_ascii_lowercase();
        let body = lowered.strip_prefix('v').unwrap_or(lowered.as_str());
        // Split off the local label first: its `.` separators would look like release separators.
        let (body, local) = match body.split_once('+') {
            Some((head, local_text)) => (head, Some(parse_local(local_text)?)),
            None => (body, None),
        };
        let (epoch, body) = match body.split_once('!') {
            Some((epoch_text, after_epoch)) => (parse_digits(epoch_text)?, after_epoch),
            None => (0, body),
        };
        let (release, body) = take_release(body)?;
        let (pre, body) = take_optional(take_pre, body);
        let (post, body) = take_optional(take_post, body);
        let (dev, body) = take_optional(take_dev, body);
        if !body.is_empty() {
            return None;
        }
        Some(Pep440 {
            epoch,
            release,
            pre,
            post,
            dev,
            local,
        })
    }

    /// Returns `true` for a pre-release or a dev release. A post release alone is not one.
    pub fn is_prerelease(&self) -> bool {
        self.pre.is_some() || self.dev.is_some()
    }

    /// Whether `self` is a post-release of `bound`: the same version once the post part is removed.
    ///
    /// A bound that is itself a post-release has no post-releases of its own in this sense, so
    /// `1.0.post2` is not a post-release of `1.0.post1`. Dev and local parts are ignored.
    pub fn is_post_release_of(&self, bound: &Pep440) -> bool {
        self.post.is_some()
            && bound.post.is_none()
            && self.epoch == bound.epoch
            && cmp_release(&self.release, &bound.release) == Ordering::Equal
            && self.pre == bound.pre
    }

    /// Whether `self` is a pre-release or dev release of the final release `bound` names.
    ///
    /// Only the epoch and the release segments are compared: `2.0rc1` and `2.0.dev1` are
    /// pre-releases of `2.0`.
    pub fn is_pre_release_of(&self, bound: &Pep440) -> bool {
        self.is_prerelease()
            && self.epoch == bound.epoch
            && cmp_release(&self.release, &bound.release) == Ordering::Equal
    }

    /// Returns the release segments as written, so `1.2.3` gives `[1, 2, 3]`.
    pub fn release(&self) -> &[u64] {
        &self.release
    }
}

impl PartialEq for Pep440 {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Pep440 {}

impl PartialOrd for Pep440 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Pep440 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| cmp_release(&self.release, &other.release))
            .then_with(|| stage_of(self).cmp(&stage_of(other)))
            .then_with(|| self.pre.cmp(&other.pre))
            .then_with(|| self.post.cmp(&other.post))
            .then_with(|| dev_rank(self.dev).cmp(&dev_rank(other.dev)))
            .then_with(|| self.local.cmp(&other.local))
    }
}

/// Spellings of pre-release kinds. Longer spellings come first, so `alpha` wins over `a` and `preview` over `pre`.
const PRE_SPELLINGS: [(&str, PreKind); 8] = [
    ("alpha", PreKind::A),
    ("a", PreKind::A),
    ("beta", PreKind::B),
    ("b", PreKind::B),
    ("preview", PreKind::Rc),
    ("pre", PreKind::Rc),
    ("rc", PreKind::Rc),
    ("c", PreKind::Rc),
];

/// Spellings of the post-release keyword. Longer spellings come first.
const POST_SPELLINGS: [&str; 3] = ["post", "rev", "r"];

/// Returns `text` without one leading `.`, `-` or `_`.
fn strip_separator(text: &str) -> &str {
    text.strip_prefix(['.', '-', '_']).unwrap_or(text)
}

/// Splits the leading ASCII digits off `text`. A missing number reads as 0, so `a` means `a0`.
///
/// Returns `None` only when the digits overflow `u64`.
fn take_number(text: &str) -> Option<(u64, &str)> {
    let digit_count = text.bytes().take_while(u8::is_ascii_digit).count();
    let (digits, rest) = text.split_at(digit_count);
    let value = if digits.is_empty() {
        0
    } else {
        digits.parse().ok()?
    };
    Some((value, rest))
}

/// Parses text that must be only ASCII digits.
fn parse_digits(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Checks a local version label: dot, dash or underscore separated alphanumeric segments.
fn parse_local(text: &str) -> Option<String> {
    let is_valid = !text.is_empty()
        && text.split(['.', '-', '_']).all(|segment| {
            !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_alphanumeric())
        });
    is_valid.then(|| text.to_owned())
}

/// Reads the release segments `N(.N)*`. A `.` that does not start another number stays unread.
fn take_release(text: &str) -> Option<(Vec<u64>, &str)> {
    let mut release = Vec::new();
    let mut rest = text;
    loop {
        if !rest.starts_with(|character: char| character.is_ascii_digit()) {
            return None;
        }
        let (segment, after_segment) = take_number(rest)?;
        release.push(segment);
        match after_segment.strip_prefix('.') {
            Some(next) if next.starts_with(|character: char| character.is_ascii_digit()) => {
                rest = next;
            }
            _ => return Some((release, after_segment)),
        }
    }
}

/// Reads an optional pre-release segment such as `.rc2`, `b1` or `-alpha`.
fn take_pre(text: &str) -> Option<((PreKind, u64), &str)> {
    let after_separator = strip_separator(text);
    let (kind, after_kind) = PRE_SPELLINGS
        .iter()
        .find_map(|(spelling, kind)| Some((*kind, after_separator.strip_prefix(*spelling)?)))?;
    let (number, rest) = take_number(strip_separator(after_kind))?;
    Some(((kind, number), rest))
}

/// Reads an optional post-release segment: `.post1`, `-1`, `rev2` or `r3`.
fn take_post(text: &str) -> Option<(u64, &str)> {
    // The implicit form `-N` needs digits after the dash. Otherwise the dash may start a pre-release.
    if let Some(after_dash) = text
        .strip_prefix('-')
        .filter(|after| after.starts_with(|character: char| character.is_ascii_digit()))
    {
        return take_number(after_dash);
    }
    let after_separator = strip_separator(text);
    let after_keyword = POST_SPELLINGS
        .iter()
        .find_map(|spelling| after_separator.strip_prefix(*spelling))?;
    take_number(strip_separator(after_keyword))
}

/// Reads an optional dev-release segment such as `.dev3`.
fn take_dev(text: &str) -> Option<(u64, &str)> {
    let after_keyword = strip_separator(text).strip_prefix("dev")?;
    take_number(strip_separator(after_keyword))
}

/// Runs an optional segment parser. A failed parse consumes nothing.
fn take_optional<'a, Value>(
    take: fn(&'a str) -> Option<(Value, &'a str)>,
    text: &'a str,
) -> (Option<Value>, &'a str) {
    match take(text) {
        Some((value, rest)) => (Some(value), rest),
        None => (None, text),
    }
}

/// Compares release segments, reading missing trailing segments as zero. Allocates nothing.
fn cmp_release(left: &[u64], right: &[u64]) -> Ordering {
    // Zero padding is endless, so `take` bounds the zip to the longer release.
    let length = left.len().max(right.len());
    left.iter()
        .chain(std::iter::repeat(&0))
        .zip(right.iter().chain(std::iter::repeat(&0)))
        .take(length)
        .map(|(left_segment, right_segment)| left_segment.cmp(right_segment))
        .find(|ordering| ordering.is_ne())
        .unwrap_or(Ordering::Equal)
}

/// Groups versions that share a release: dev-only (0), pre-release (1), final (2), post release (3).
fn stage_of(version: &Pep440) -> u8 {
    match (&version.pre, version.post, version.dev) {
        (Some(_), _, _) => 1,
        (None, Some(_), _) => 3,
        (None, None, Some(_)) => 0,
        (None, None, None) => 2,
    }
}

/// Ranks a dev number so that a dev release sorts before the same version without one.
fn dev_rank(dev: Option<u64>) -> (bool, Option<u64>) {
    // `None` gets `true` and so sorts after every `Some`.
    (dev.is_none(), dev)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a version that the test expects to be valid.
    fn version(text: &str) -> Pep440 {
        Pep440::parse(text).expect("test version must be valid PEP 440")
    }

    #[test]
    fn a_post_release_is_found_by_its_base_version() {
        let cases = [
            ("1.0.post1", "1.0", true),
            ("1.0.0.post1", "1.0", true),
            ("1.0rc1.post1", "1.0rc1", true),
            ("1.0.post1", "1.0.post1", false),
            ("1.0.post2", "1.0.post1", false),
            ("1.0", "1.0", false),
            ("1.1.post1", "1.0", false),
            ("1.0rc1.post1", "1.0", false),
        ];
        for (target, bound, expected) in cases {
            assert_eq!(
                version(target).is_post_release_of(&version(bound)),
                expected,
                "{target} of {bound}"
            );
        }
    }

    #[test]
    fn a_pre_release_is_found_by_its_final_release() {
        let cases = [
            ("2.0rc1", "2.0", true),
            ("2.0.dev1", "2.0", true),
            ("2.0.0a1", "2.0", true),
            ("1.9rc1", "2.0", false),
            ("2.0", "2.0", false),
            ("2.1rc1", "2.0", false),
        ];
        for (target, bound, expected) in cases {
            assert_eq!(
                version(target).is_pre_release_of(&version(bound)),
                expected,
                "{target} of {bound}"
            );
        }
    }

    #[test]
    fn orders_the_standard_chain() {
        let chain = [
            "1.0.dev1",
            "1.0a1",
            "1.0a2",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0.post1",
            "1.0.1",
            "1.1",
            "2.0",
        ];
        let versions: Vec<Pep440> = chain.iter().map(|text| version(text)).collect();
        for pair in versions.windows(2) {
            assert!(
                pair[0] < pair[1],
                "{:?} must sort before {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn pads_release_segments_with_zeros() {
        assert_eq!(version("1.0").cmp(&version("1.0.0")), Ordering::Equal);
        assert_eq!(version("1.0"), version("1.0.0.0"));
    }

    #[test]
    fn compares_release_segments_numerically() {
        assert!(version("2.0") > version("1.99.99"));
    }

    #[test]
    fn epoch_dominates_release() {
        assert!(version("1!0.5") > version("2.0"));
    }

    #[test]
    fn local_part_breaks_ties_after_the_plain_version() {
        assert!(version("1.0+local") > version("1.0"));
    }

    #[test]
    fn implicit_post_release_spelling_is_equal() {
        assert_eq!(version("1.0-1"), version("1.0.post1"));
    }

    #[test]
    fn alternative_spellings_are_equal() {
        assert_eq!(version("1.0alpha1"), version("1.0a1"));
        assert_eq!(version("1.0c1"), version("1.0rc1"));
    }

    #[test]
    fn accepts_leading_v_and_uppercase() {
        assert!(Pep440::parse("V1.0").is_some());
    }

    #[test]
    fn detects_prereleases() {
        assert!(version("1.0a1").is_prerelease());
        assert!(version("1.0rc2").is_prerelease());
        assert!(version("1.0.dev3").is_prerelease());
        assert!(version("1.0b1.post2").is_prerelease());
    }

    #[test]
    fn final_and_post_releases_are_not_prereleases() {
        assert!(!version("1.0").is_prerelease());
        assert!(!version("1.0.post1").is_prerelease());
        assert!(!version("2024.1").is_prerelease());
    }

    #[test]
    fn release_segments_are_kept_as_written() {
        assert_eq!(version("1.2.3").release(), &[1, 2, 3]);
    }

    #[test]
    fn rejects_text_that_is_not_a_version() {
        assert!(Pep440::parse("abc").is_none());
        assert!(Pep440::parse("").is_none());
        assert!(Pep440::parse("1.x").is_none());
    }
}
