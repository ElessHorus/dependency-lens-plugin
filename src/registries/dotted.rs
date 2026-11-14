//! Dotted version numbers of Composer, pub.dev and NuGet, compared per semver 2.0 precedence.
//!
//! Composer-style stability names such as `RC1` or `beta2` (no dot) are single
//! alphanumeric identifiers. They compare lexically, so `alpha1 < beta1 < rc1`.
//! Composer's `-p1` and `-patch` stability is treated as a prerelease.

use super::rank_with;
use crate::model::VersionInfo;
use std::cmp::Ordering;

/// The most release segments that one version may have, such as `1.2.3.4`.
const MAX_RELEASE_SEGMENTS: usize = 6;

/// One dot-separated part of a prerelease, such as `alpha` or `11` in `1.0.0-alpha.11`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PreId {
    /// Numeric parts sort before alphanumeric parts, so the variant order is the rule.
    Numeric(u64),
    /// Lowercased text, compared lexically.
    Alphanumeric(String),
}

/// A parsed version such as `1.2.3`, `v2.0`, or `3.0.0-RC1`.
///
/// Build metadata (`+7`) is kept but never changes the ordering, as semver says. Only
/// [`PubVersion`] reads it.
#[derive(Clone, Debug)]
pub struct DottedVersion {
    release: Vec<u64>,
    pre: Option<Vec<PreId>>,
    /// The identifiers after `+`. Empty when the version has none, or when they are malformed.
    build: Vec<PreId>,
}

impl DottedVersion {
    /// Parses `text`. Returns `None` for empty, malformed or overflowing input.
    pub fn parse(text: &str) -> Option<DottedVersion> {
        let trimmed = text.trim();
        let without_v = trimmed.strip_prefix(['v', 'V']).unwrap_or(trimmed);
        // The build part is cut before the release and prerelease split.
        let (without_build, build_text) = match without_v.split_once('+') {
            Some((head, build_text)) => (head, Some(build_text)),
            None => (without_v, None),
        };
        let (release_text, pre_text) = match without_build.split_once('-') {
            Some((release_text, pre_text)) => (release_text, Some(pre_text)),
            None => (without_build, None),
        };
        Some(DottedVersion {
            release: parse_release(release_text)?,
            pre: match pre_text {
                Some(text) => Some(parse_prerelease(text)?),
                None => None,
            },
            // A malformed build never rejects the version: it only loses its tie-break.
            build: build_text.and_then(parse_prerelease).unwrap_or_default(),
        })
    }

    /// Returns `true` when the version has a `-prerelease` part.
    pub fn is_prerelease(&self) -> bool {
        self.pre.is_some()
    }

    /// Returns the release segments, such as `[1, 2, 3]` for `1.2.3`.
    pub fn release(&self) -> &[u64] {
        &self.release
    }
}

/// Returns `true` for a Composer development branch: a `dev-` prefix or a `-dev` suffix, in any case.
///
/// A `1.0.x-dev` suffix matches `-dev` too, so `.x-dev` needs no separate check.
pub fn is_dev_branch(version: &str) -> bool {
    let has_dev_prefix = version
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("dev-"));
    let has_dev_suffix = version
        .len()
        .checked_sub(4)
        .and_then(|start| version.get(start..))
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case("-dev"));
    has_dev_prefix || has_dev_suffix
}

/// Ranks version texts newest first. `latest` is the newest non-prerelease.
///
/// Texts that do not parse are dropped. Each text is parsed once and kept beside
/// its parsed version, so the sort compares stored values without parsing again.
pub fn rank_versions(texts: impl IntoIterator<Item = String>) -> VersionInfo {
    rank_with(texts, DottedVersion::parse, DottedVersion::is_prerelease)
}

/// A pub.dev version. It orders like [`DottedVersion`], and a build number breaks a tie:
/// `0.4.0+2` is newer than `0.4.0+1`, and both are newer than `0.4.0`.
#[derive(Clone, Debug)]
pub struct PubVersion(DottedVersion);

impl PubVersion {
    /// Parses `text`. Returns `None` when [`DottedVersion::parse`] does.
    pub fn parse(text: &str) -> Option<PubVersion> {
        DottedVersion::parse(text).map(PubVersion)
    }

    /// Returns `true` when the version has a `-prerelease` part.
    pub fn is_prerelease(&self) -> bool {
        self.0.is_prerelease()
    }

    /// Returns the release segments, such as `[1, 2, 3]` for `1.2.3`.
    pub fn release(&self) -> &[u64] {
        self.0.release()
    }
}

impl Ord for PubVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // An empty build is below every build, so a plain version sorts before its builds.
        self.0
            .cmp(&other.0)
            .then_with(|| self.0.build.cmp(&other.0.build))
    }
}

impl PartialOrd for PubVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PubVersion {
    // Equality follows the ordering, so it counts the build number too.
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for PubVersion {}

/// Ranks pub.dev version texts newest first, like [`rank_versions`], with build numbers counted.
pub fn rank_pub_versions(texts: impl IntoIterator<Item = String>) -> VersionInfo {
    rank_with(texts, PubVersion::parse, PubVersion::is_prerelease)
}

impl Ord for DottedVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // Missing release segments read as 0, so `1.0` equals `1.0.0`. Lazy iterators avoid padded copies.
        let segment_count = self.release.len().max(other.release.len());
        let release_order = (0..segment_count)
            .map(|index| segment(&self.release, index))
            .cmp((0..segment_count).map(|index| segment(&other.release, index)));
        release_order.then_with(|| compare_prerelease(self.pre.as_deref(), other.pre.as_deref()))
    }
}

/// Returns the release segment at `index`, or 0 past the end.
pub(crate) fn segment(release: &[u64], index: usize) -> u64 {
    release.get(index).copied().unwrap_or(0)
}

/// Orders prereleases below the release they belong to, and compares their parts one by one.
///
/// `Option` puts `None` first, so the absent prerelease is ranked explicitly.
fn compare_prerelease(left: Option<&[PreId]>, right: Option<&[PreId]>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (Some(left_ids), Some(right_ids)) => left_ids.cmp(right_ids),
    }
}

/// Parses `1.2.3` into its release segments. Each segment is decimal digits only.
fn parse_release(text: &str) -> Option<Vec<u64>> {
    let mut release = Vec::with_capacity(MAX_RELEASE_SEGMENTS);
    for segment_text in text.split('.') {
        if release.len() == MAX_RELEASE_SEGMENTS {
            return None;
        }
        release.push(parse_number(segment_text)?);
    }
    Some(release)
}

/// Parses a non-empty run of ASCII digits. Returns `None` when the value overflows `u64`.
fn parse_number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Parses the text after `-`, such as `beta.11`, into its dot-separated identifiers.
fn parse_prerelease(text: &str) -> Option<Vec<PreId>> {
    text.split('.').map(parse_pre_id).collect()
}

/// Parses one prerelease identifier. Letters are lowercased, so the comparison ignores case.
fn parse_pre_id(text: &str) -> Option<PreId> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return None;
    }
    if text.bytes().all(|byte| byte.is_ascii_digit()) {
        return parse_number(text).map(PreId::Numeric);
    }
    Some(PreId::Alphanumeric(text.to_ascii_lowercase()))
}

impl PartialOrd for DottedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for DottedVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for DottedVersion {}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(text: &str) -> DottedVersion {
        DottedVersion::parse(text).unwrap_or_else(|| panic!("{text} must parse"))
    }

    /// Converts string literals into the owned texts that `rank_versions` takes.
    fn texts(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn rank_versions_of_nothing_has_no_latest_and_no_versions() {
        let info = rank_versions(Vec::new());
        assert_eq!(info.latest, None);
        assert!(info.versions.is_empty());
    }

    #[test]
    fn rank_versions_lists_newest_first_and_picks_the_newest_stable() {
        let info = rank_versions(texts(&["1.0.0", "2.0.0", "1.5.0"]));
        assert_eq!(info.versions, ["2.0.0", "1.5.0", "1.0.0"]);
        assert_eq!(info.latest.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn rank_versions_keeps_prereleases_listed_but_never_latest() {
        let info = rank_versions(texts(&["1.0.0", "2.0.0-beta"]));
        assert_eq!(info.versions, ["2.0.0-beta", "1.0.0"]);
        assert_eq!(info.latest.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn rank_versions_has_no_latest_when_only_prereleases_exist() {
        let info = rank_versions(texts(&["2.0.0-beta1", "2.0.0-rc1"]));
        assert_eq!(info.latest, None);
        assert_eq!(info.versions, ["2.0.0-rc1", "2.0.0-beta1"]);
    }

    #[test]
    fn rank_versions_drops_texts_that_do_not_parse() {
        let info = rank_versions(texts(&["not-a-version", "1.0.0", ""]));
        assert_eq!(info.versions, ["1.0.0"]);
    }

    #[test]
    fn rank_versions_keeps_the_input_order_of_equal_versions() {
        let info = rank_versions(texts(&["1.0", "1.0.0"]));
        assert_eq!(info.versions, ["1.0", "1.0.0"]);
        let reversed = rank_versions(texts(&["1.0.0", "1.0"]));
        assert_eq!(reversed.versions, ["1.0.0", "1.0"]);
    }

    #[test]
    fn orders_prereleases_before_their_release_per_semver() {
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
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
    fn pads_missing_release_segments_with_zeros() {
        assert_eq!(version("1.0"), version("1.0.0"));
        assert_eq!(version("1.0.0"), version("1.0.0.0"));
    }

    #[test]
    fn accepts_a_leading_v_and_ignores_build_metadata() {
        assert_eq!(version("v1.2"), version("1.2.0"));
        assert_eq!(version("1.2.3+build5"), version("1.2.3"));
    }

    #[test]
    fn compares_composer_stability_names_lexically() {
        assert!(version("3.0.0-RC1") > version("3.0.0-beta2"));
        assert!(version("3.0.0-RC1") < version("3.0.0"));
        assert!(version("1.0.0-alpha1") < version("1.0.0-beta1"));
        assert!(version("1.0.0-beta1") < version("1.0.0-rc1"));
    }

    #[test]
    fn detects_prereleases_and_ignores_build_metadata_for_them() {
        assert!(version("1.0.0-RC1").is_prerelease());
        assert!(!version("1.0.0").is_prerelease());
        assert!(!version("1.0.0+b").is_prerelease());
    }

    #[test]
    fn exposes_release_segments() {
        assert_eq!(version("1.2.3").release(), [1, 2, 3]);
    }

    #[test]
    fn rejects_empty_garbage_overflowing_and_too_long_versions() {
        for text in [
            "",
            "abc",
            "1..2",
            "1.2.x",
            "99999999999999999999.1",
            "1.2.3.4.5.6.7",
        ] {
            assert!(DottedVersion::parse(text).is_none(), "{text}");
        }
    }
}
