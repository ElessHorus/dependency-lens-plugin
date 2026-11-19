//! What a version requirement allows: constraints, alternatives and the lowest allowed version.

use crate::model::Ecosystem;
use crate::osv::declared_version_for_osv;
use crate::registries::dotted::{DottedVersion, PubVersion, is_dev_branch, segment};
use crate::registries::gem_version::GemVersion;
use crate::registries::maven_version::MavenVersion;
use crate::registries::pep440::Pep440;
use crate::update::{ExclusiveBound, UpdateVersion};

/// One constraint of a requirement, such as `<` and `1` in `flask>=0.12.2,<1`.
///
/// The operator is one of `==`, `===`, `!=`, `>`, `>=`, `<`, `<=`, `~=` and `~>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constraint {
    pub operator: String,
    pub version: String,
}

/// What a manifest allows for one dependency: alternatives (OR) of constraint lists (AND).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement {
    alternatives: Vec<Vec<Constraint>>,
}

impl Requirement {
    /// Builds a requirement. Returns `None` without any alternative, or with an empty one.
    pub fn new(alternatives: Vec<Vec<Constraint>>) -> Option<Self> {
        let is_complete = !alternatives.is_empty()
            && alternatives
                .iter()
                .all(|constraints| !constraints.is_empty());
        is_complete.then_some(Self { alternatives })
    }

    /// Builds a requirement of one alternative. Returns `None` without any constraint.
    pub fn from_constraints(constraints: Vec<Constraint>) -> Option<Self> {
        Self::new(vec![constraints])
    }

    /// Reads the requirement text of a manifest.
    ///
    /// Supports PyPI (Poetry text), Packagist, Pub and NuGet. Returns `None` for any other ecosystem and
    /// for text that names no single readable range: wildcards, hyphen ranges, branches, `any`.
    pub fn parse(eco: Ecosystem, text: &str) -> Option<Self> {
        match eco {
            Ecosystem::PyPI | Ecosystem::Packagist | Ecosystem::Pub => {
                parse_operator_text(eco, text)
            }
            Ecosystem::NuGet => parse_nuget_range(text),
            _ => None,
        }
    }

    /// Whether the requirement names one version: one alternative with one `==` or `===`.
    pub fn is_exact_pin(&self) -> bool {
        matches!(
            self.alternatives.as_slice(),
            [constraints] if matches!(
                constraints.as_slice(),
                [only] if only.operator == "==" || only.operator == "==="
            )
        )
    }

    /// Whether `version` satisfies at least one alternative.
    pub fn allows(&self, eco: Ecosystem, version: &str) -> bool {
        self.alternatives
            .iter()
            .any(|constraints| satisfies_all(eco, version, constraints))
    }

    /// The lowest version of `versions` (newest first) that the requirement allows.
    ///
    /// A pre-release counts only when a constraint of the requirement names one.
    pub fn lowest_allowed(&self, eco: Ecosystem, versions: &[String]) -> Option<String> {
        match eco {
            Ecosystem::PyPI => self.lowest_allowed_of::<Pep440>(versions),
            Ecosystem::RubyGems => self.lowest_allowed_of::<GemVersion>(versions),
            Ecosystem::Pub => self.lowest_allowed_of::<PubVersion>(versions),
            Ecosystem::Maven => self.lowest_allowed_of::<MavenVersion>(versions),
            _ => self.lowest_allowed_of::<DottedVersion>(versions),
        }
    }

    /// One pass: each bound is parsed once for the whole list, and each candidate once.
    fn lowest_allowed_of<V: UpdateVersion>(&self, versions: &[String]) -> Option<String> {
        let alternatives: Vec<Vec<TypedConstraint<'_, V>>> = self
            .alternatives
            .iter()
            .map(|constraints| typed_constraints(constraints))
            .collect();
        let names_pre_release = alternatives
            .iter()
            .flatten()
            .filter_map(|constraint| constraint.bound.as_ref())
            .any(|bound| bound.is_prerelease_version());
        // The list is newest first, so the reverse scan meets the oldest version first.
        versions
            .iter()
            .rev()
            .find(|text| {
                V::parse_version(text).is_some_and(|version| {
                    (names_pre_release || !version.is_prerelease_version())
                        && alternatives
                            .iter()
                            .any(|constraints| satisfies_typed(&version, constraints))
                })
            })
            .cloned()
    }
}

/// Builds the constraint of `operator` and `version`.
fn constraint(operator: &str, version: &str) -> Constraint {
    Constraint {
        operator: operator.to_owned(),
        version: version.to_owned(),
    }
}

/// Reads a NuGet version range: a bare version is a minimum, `[1.0]` is exact, and
/// `[1.0,2.0)` is an interval whose brackets include a bound and whose parentheses exclude it.
fn parse_nuget_range(text: &str) -> Option<Requirement> {
    let text = text.trim();
    let is_plain = |version: &str| {
        version.starts_with(|character: char| character.is_ascii_digit())
            && !version.contains(['*', '$', ',', ' '])
    };
    let (Some(opening), Some(closing)) = (text.chars().next(), text.chars().last()) else {
        return None;
    };
    if !matches!(opening, '[' | '(') {
        return is_plain(text)
            .then(|| Requirement::from_constraints(vec![constraint(">=", text)]))
            .flatten();
    }
    // An interval that is still being typed has no closing bracket: its last character would be cut.
    if !matches!(closing, ']' | ')') {
        return None;
    }
    // Both brackets are ASCII, so the slice falls on character boundaries.
    let inner = text.get(1..text.len().checked_sub(1)?)?;
    let constraints = match inner.split_once(',') {
        None if opening == '[' && closing == ']' && is_plain(inner.trim()) => {
            vec![constraint("==", inner.trim())]
        }
        None => return None,
        Some((low, high)) => {
            let (low, high) = (low.trim(), high.trim());
            let mut bounds = Vec::new();
            if !low.is_empty() {
                bounds.push(constraint(if opening == '[' { ">=" } else { ">" }, low));
            }
            if !high.is_empty() {
                bounds.push(constraint(if closing == ']' { "<=" } else { "<" }, high));
            }
            if !bounds.iter().all(|bound| is_plain(&bound.version)) {
                return None;
            }
            bounds
        }
    };
    Requirement::from_constraints(constraints)
}

/// The version to send to OSV for one dependency, or `None` when the requirement is not audited.
///
/// `declared_version` is the version text of the manifest and `versions` the registry list, newest
/// first. A requirement with a range gives the lowest version that it allows. The text of the
/// lower bound is the answer when the requirement is an exact pin, when the list is missing, and
/// when no listed version fits, so that no dependency is audited in silence.
pub fn checked_version_of(
    eco: Ecosystem,
    declared_version: &str,
    requirement: Option<&Requirement>,
    versions: Option<&[String]>,
) -> Option<String> {
    let bound_text = declared_version_for_osv(declared_version)?;
    let Some(requirement) = requirement.filter(|requirement| !requirement.is_exact_pin()) else {
        return Some(bound_text);
    };
    Some(
        versions
            .and_then(|list| requirement.lowest_allowed(eco, list))
            .unwrap_or(bound_text),
    )
}

/// Whether the checked version of a dependency needs the registry list.
pub fn needs_list(
    eco: Ecosystem,
    declared_version: &str,
    requirement: Option<&Requirement>,
) -> bool {
    eco.offers_updates()
        && requirement.is_some_and(|requirement| !requirement.is_exact_pin())
        && declared_version_for_osv(declared_version).is_some()
}

/// Operators that a word of the requirement text may start with.
const TEXT_OPERATORS: [&str; 13] = [
    "", "=", "==", "===", "!=", ">", ">=", "<", "<=", "~=", "~>", "^", "~",
];

/// Reads text in the shared grammar of Poetry, Composer and Pub: alternatives split by `|` or `||`,
/// constraints split by `,` or spaces, and an operator that may stand apart from its version.
fn parse_operator_text(eco: Ecosystem, text: &str) -> Option<Requirement> {
    if is_dev_branch(text.trim()) {
        return None;
    }
    let alternatives = text
        .split('|')
        .map(str::trim)
        .filter(|alternative| !alternative.is_empty())
        .map(|alternative| parse_alternative(eco, alternative))
        .collect::<Option<Vec<_>>>()?;
    Requirement::new(alternatives)
}

/// Reads the constraints of one alternative. Returns `None` when a word is not a constraint.
fn parse_alternative(eco: Ecosystem, alternative: &str) -> Option<Vec<Constraint>> {
    let mut words = alternative
        .split(|character: char| character == ',' || character.is_whitespace())
        .filter(|word| !word.is_empty());
    let mut constraints = Vec::new();
    while let Some(word) = words.next() {
        let is_operator_only = word.bytes().all(|byte| b"=!<>~^".contains(&byte));
        // An operator that stands apart (`>= 1.0`) takes the next word as its version.
        let joined;
        let word = if is_operator_only {
            joined = format!("{word}{}", words.next()?);
            joined.as_str()
        } else {
            word
        };
        constraints.extend(parse_word(eco, word)?);
    }
    Some(constraints)
}

/// Reads one word such as `^1.2.3` into the constraints that it stands for.
fn parse_word(eco: Ecosystem, word: &str) -> Option<Vec<Constraint>> {
    // A Composer stability flag (`@dev`) follows the version and is cut here.
    let word = word
        .split_once('@')
        .map_or(word, |(version_part, _)| version_part);
    let operator_len = word
        .bytes()
        .take_while(|byte| b"=!<>~^".contains(byte))
        .count();
    let (operator, version) = word.split_at(operator_len);
    if !TEXT_OPERATORS.contains(&operator)
        || !version.starts_with(|character: char| character.is_ascii_digit())
        || version.contains('*')
        || version
            .split('.')
            .any(|part| part.eq_ignore_ascii_case("x"))
    {
        return None;
    }
    Some(match (operator, eco) {
        ("" | "=" | "==", _) => vec![constraint("==", version)],
        ("^", Ecosystem::Pub) => {
            let mut segments = numeric_prefix(version);
            // Dart `nextBreaking` raises the minor when the major is 0 (`^0.0.3` stops at `0.1`),
            // and the major otherwise. A short version is padded so `^0` keeps a minor segment.
            let kept = if segments.first() == Some(&0) { 2 } else { 1 };
            if segments.len() < kept {
                segments.resize(kept, 0);
            }
            vec![
                constraint(">=", version),
                constraint("<", &upper_bound(&segments, kept)?),
            ]
        }
        ("^", _) => {
            let segments = numeric_prefix(version);
            // The first non-zero segment is the one that may not change (`^0.2.3` stops at `0.3`).
            let kept = segments
                .iter()
                .position(|&part| part != 0)
                .map_or(segments.len(), |index| index + 1);
            vec![
                constraint(">=", version),
                constraint("<", &upper_bound(&segments, kept)?),
            ]
        }
        ("~", Ecosystem::PyPI) => {
            // Poetry keeps the major and minor segments: `~1.2.3` and `~1.2` stop at `1.3`, `~1` at `2`.
            let segments = numeric_prefix(version);
            let kept = segments.len().min(2);
            vec![
                constraint(">=", version),
                constraint("<", &upper_bound(&segments, kept)?),
            ]
        }
        // Composer reads `~1.2` as the compatible release `~> 1.2`.
        ("~", Ecosystem::Packagist) => vec![constraint("~>", version)],
        ("~", _) => return None,
        (other, _) => vec![constraint(other, version)],
    })
}

/// The leading numeric segments of a version text: `1.2.3rc1` gives `[1, 2, 3]`.
fn numeric_prefix(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map_while(|part| {
            let digits_len = part.bytes().take_while(u8::is_ascii_digit).count();
            let digits = part.get(..digits_len).filter(|digits| !digits.is_empty())?;
            // A part with a text tail ends the prefix after its own digits.
            digits
                .parse()
                .ok()
                .map(|number| (number, digits_len == part.len()))
        })
        .scan(false, |has_ended, (number, is_whole)| {
            if *has_ended {
                return None;
            }
            *has_ended = !is_whole;
            Some(number)
        })
        .collect()
}

/// The text of the first version that a caret or tilde excludes: the first `kept` segments, with the last raised by one.
fn upper_bound(segments: &[u64], kept: usize) -> Option<String> {
    let kept = kept.min(segments.len());
    let (last, head) = segments[..kept].split_last()?;
    let raised = last.checked_add(1)?;
    Some(
        head.iter()
            .map(u64::to_string)
            .chain(std::iter::once(raised.to_string()))
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Returns `true` when `target` satisfies every constraint. A constraint that is not a version
/// cannot be checked, so it refuses the target.
pub fn satisfies_all(eco: Ecosystem, target: &str, constraints: &[Constraint]) -> bool {
    match eco {
        Ecosystem::PyPI => satisfies_all_of::<Pep440>(target, constraints),
        Ecosystem::RubyGems => satisfies_all_of::<GemVersion>(target, constraints),
        Ecosystem::Pub => satisfies_all_of::<PubVersion>(target, constraints),
        Ecosystem::Maven => satisfies_all_of::<MavenVersion>(target, constraints),
        _ => satisfies_all_of::<DottedVersion>(target, constraints),
    }
}

fn satisfies_all_of<V: UpdateVersion>(target: &str, constraints: &[Constraint]) -> bool {
    V::parse_version(target)
        .is_some_and(|target| satisfies_typed(&target, &typed_constraints(constraints)))
}

/// A constraint whose bound is parsed once. A bound that is not a version stays `None`, and
/// refuses every target, as an unreadable constraint must.
struct TypedConstraint<'a, V> {
    operator: &'a str,
    bound: Option<V>,
}

/// Parses the bound of each constraint, so that a scan over many candidates parses it only once.
fn typed_constraints<V: UpdateVersion>(constraints: &[Constraint]) -> Vec<TypedConstraint<'_, V>> {
    constraints
        .iter()
        .map(|constraint| TypedConstraint {
            operator: constraint.operator.as_str(),
            bound: V::parse_version(&constraint.version),
        })
        .collect()
}

/// Returns `true` when `target` satisfies every constraint.
fn satisfies_typed<V: UpdateVersion>(target: &V, constraints: &[TypedConstraint<'_, V>]) -> bool {
    constraints.iter().all(|constraint| {
        let Some(bound) = &constraint.bound else {
            return false;
        };
        match constraint.operator {
            "<" => target < bound && !target.is_excluded_by_bound(ExclusiveBound::LessThan, bound),
            "<=" => target <= bound,
            ">" => {
                target > bound && !target.is_excluded_by_bound(ExclusiveBound::GreaterThan, bound)
            }
            ">=" => target >= bound,
            "==" | "===" => target == bound,
            "!=" => target != bound,
            // Compatible release: at least the bound, and the same release without its last segment.
            "~=" | "~>" => {
                let (bound_segments, target_segments) =
                    (bound.release_segments(), target.release_segments());
                // `~> 2.2` keeps the major version, and so does `~> 2`: at least one segment is kept.
                let kept = bound_segments.len().saturating_sub(1).max(1);
                target >= bound
                    && (0..kept).all(|index| {
                        segment(&target_segments, index) == segment(&bound_segments, index)
                    })
            }
            _ => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a requirement from alternatives of `(operator, version)` pairs.
    fn requirement(alternatives: &[&[(&str, &str)]]) -> Requirement {
        Requirement::new(
            alternatives
                .iter()
                .map(|constraints| {
                    constraints
                        .iter()
                        .map(|(operator, version)| Constraint {
                            operator: (*operator).to_owned(),
                            version: (*version).to_owned(),
                        })
                        .collect()
                })
                .collect(),
        )
        .expect("a non-empty requirement")
    }

    fn versions(texts: &[&str]) -> Vec<String> {
        texts.iter().map(|text| (*text).to_owned()).collect()
    }

    /// Newest first, as the registry clients rank them.
    const REQUESTS: [&str; 7] = [
        "2.34.2", "2.10.0", "2.9.2", "2.9.1", "2.0.1", "2.0.0", "1.2.3",
    ];

    #[test]
    fn lowest_allowed_skips_a_bound_that_does_not_exist() {
        let allowed = requirement(&[&[(">", "1.12"), ("<", "2.10")]]);
        assert_eq!(
            allowed.lowest_allowed(Ecosystem::PyPI, &versions(&REQUESTS)),
            Some("2.0.0".to_owned())
        );
    }

    #[test]
    fn an_exclusive_bound_is_excluded_and_an_inclusive_one_is_kept() {
        let list = versions(&REQUESTS);
        let exclusive = requirement(&[&[(">", "2.0.0")]]);
        assert_eq!(
            exclusive.lowest_allowed(Ecosystem::PyPI, &list),
            Some("2.0.1".to_owned())
        );
        let inclusive = requirement(&[&[(">=", "2.0.0")]]);
        assert_eq!(
            inclusive.lowest_allowed(Ecosystem::PyPI, &list),
            Some("2.0.0".to_owned())
        );
    }

    #[test]
    fn a_bound_that_exists_is_kept() {
        let allowed = requirement(&[&[(">=", "2.9.1")]]);
        assert_eq!(
            allowed.lowest_allowed(Ecosystem::PyPI, &versions(&REQUESTS)),
            Some("2.9.1".to_owned())
        );
    }

    #[test]
    fn no_allowed_version_gives_none() {
        let allowed = requirement(&[&[(">", "2.0.0"), ("<", "2.0.1")]]);
        assert_eq!(
            allowed.lowest_allowed(Ecosystem::PyPI, &versions(&REQUESTS)),
            None
        );
    }

    #[test]
    fn the_lowest_of_all_alternatives_wins() {
        let allowed = requirement(&[&[(">=", "2.0")], &[(">=", "1.5"), ("<", "1.6")]]);
        assert_eq!(
            allowed.lowest_allowed(Ecosystem::Packagist, &versions(&["2.1", "1.5.3", "1.4"])),
            Some("1.5.3".to_owned())
        );
    }

    #[test]
    fn a_pre_release_is_skipped_unless_a_bound_names_one() {
        let named = requirement(&[&[(">=", "2.0.0rc1")]]);
        assert_eq!(
            named.lowest_allowed(Ecosystem::PyPI, &versions(&["2.0.0", "2.0.0rc1"])),
            Some("2.0.0rc1".to_owned())
        );
        let plain = requirement(&[&[(">=", "1.0")]]);
        assert_eq!(
            plain.lowest_allowed(Ecosystem::PyPI, &versions(&["2.0.0rc1", "2.0.0"])),
            Some("2.0.0".to_owned())
        );
        assert_eq!(
            plain.lowest_allowed(Ecosystem::PyPI, &versions(&["2.0.0rc1"])),
            None
        );
    }

    #[test]
    fn an_exact_pin_is_detected() {
        assert!(requirement(&[&[("==", "1.0")]]).is_exact_pin());
        assert!(requirement(&[&[("===", "1.0")]]).is_exact_pin());
        assert!(!requirement(&[&[(">=", "1.0")]]).is_exact_pin());
        assert!(!requirement(&[&[("==", "1.0")], &[("==", "2.0")]]).is_exact_pin());
        assert!(!requirement(&[&[("==", "1.0"), ("!=", "1.1")]]).is_exact_pin());
    }

    #[test]
    fn an_empty_requirement_is_refused() {
        assert!(Requirement::new(Vec::new()).is_none());
        assert!(Requirement::new(vec![Vec::new()]).is_none());
    }

    #[test]
    fn allows_follows_the_ordering_of_the_ecosystem() {
        let compatible = requirement(&[&[("~>", "2.2")]]);
        assert!(compatible.allows(Ecosystem::RubyGems, "2.9"));
        assert!(!compatible.allows(Ecosystem::RubyGems, "3.0"));
    }

    #[test]
    fn pypi_text_reads_poetry_and_pep_440_forms() {
        let cases: [(&str, Option<Requirement>); 10] = [
            (
                ">=2.0,<3.0",
                Some(requirement(&[&[(">=", "2.0"), ("<", "3.0")]])),
            ),
            (
                "^1.2.3",
                Some(requirement(&[&[(">=", "1.2.3"), ("<", "2")]])),
            ),
            (
                "^0.2.3",
                Some(requirement(&[&[(">=", "0.2.3"), ("<", "0.3")]])),
            ),
            (
                "^0.0.3",
                Some(requirement(&[&[(">=", "0.0.3"), ("<", "0.0.4")]])),
            ),
            ("~1.2", Some(requirement(&[&[(">=", "1.2"), ("<", "1.3")]]))),
            ("~1", Some(requirement(&[&[(">=", "1"), ("<", "2")]]))),
            (
                "^1.0|^2.0",
                Some(requirement(&[
                    &[(">=", "1.0"), ("<", "2")],
                    &[(">=", "2.0"), ("<", "3")],
                ])),
            ),
            ("1.2.3", Some(requirement(&[&[("==", "1.2.3")]]))),
            ("*", None),
            ("1.*", None),
        ];
        for (text, expected) in cases {
            assert_eq!(
                Requirement::parse(Ecosystem::PyPI, text),
                expected,
                "{text}"
            );
        }
    }

    #[test]
    fn composer_text_reads_carets_tildes_and_alternatives() {
        let cases: [(&str, Option<Requirement>); 9] = [
            ("^1.2", Some(requirement(&[&[(">=", "1.2"), ("<", "2")]]))),
            ("~1.2", Some(requirement(&[&[("~>", "1.2")]]))),
            (
                ">=1.0 <2.0",
                Some(requirement(&[&[(">=", "1.0"), ("<", "2.0")]])),
            ),
            (
                ">= 1.0, < 2.0",
                Some(requirement(&[&[(">=", "1.0"), ("<", "2.0")]])),
            ),
            (
                "^1.0 || ^2.0",
                Some(requirement(&[
                    &[(">=", "1.0"), ("<", "2")],
                    &[(">=", "2.0"), ("<", "3")],
                ])),
            ),
            (
                "^1.0@dev",
                Some(requirement(&[&[(">=", "1.0"), ("<", "2")]])),
            ),
            ("1.0 - 2.0", None),
            ("dev-main", None),
            ("1.2.*", None),
        ];
        for (text, expected) in cases {
            assert_eq!(
                Requirement::parse(Ecosystem::Packagist, text),
                expected,
                "{text}"
            );
        }
    }

    #[test]
    fn pub_text_reads_carets_and_space_separated_ranges() {
        let cases: [(&str, Option<Requirement>); 5] = [
            (
                "^1.2.3",
                Some(requirement(&[&[(">=", "1.2.3"), ("<", "2")]])),
            ),
            (
                ">=1.0.0 <2.0.0",
                Some(requirement(&[&[(">=", "1.0.0"), ("<", "2.0.0")]])),
            ),
            ("1.2.3", Some(requirement(&[&[("==", "1.2.3")]]))),
            ("any", None),
            ("~1.2", None),
        ];
        for (text, expected) in cases {
            assert_eq!(Requirement::parse(Ecosystem::Pub, text), expected, "{text}");
        }
    }

    #[test]
    fn a_parsed_range_gives_its_lowest_allowed_version() {
        let cases = [
            (
                Ecosystem::Packagist,
                "^1.2",
                &["2.0.0", "1.9.0", "1.2.1", "1.1.0"][..],
                "1.2.1",
            ),
            (Ecosystem::Pub, "^0.0.3", &["0.0.4", "0.0.3"][..], "0.0.3"),
            // Dart reads `^0.0.3` as `>=0.0.3 <0.1.0`, so `0.0.5` is allowed and `0.0.2` is not.
            (Ecosystem::Pub, "^0.0.3", &["0.0.5", "0.0.2"][..], "0.0.5"),
            (
                Ecosystem::PyPI,
                "^1.5",
                &["2.0.0", "1.9.0", "1.4.0"][..],
                "1.9.0",
            ),
        ];
        for (eco, text, list, expected) in cases {
            let parsed = Requirement::parse(eco, text).expect("a readable requirement");
            assert_eq!(
                parsed.lowest_allowed(eco, &versions(list)),
                Some(expected.to_owned()),
                "{text}"
            );
        }
    }

    #[test]
    fn pep440_exclusive_bounds_follow_the_standard() {
        let cases = [
            (">", "1.0", "1.0.post1", false),
            (">", "1.0", "1.1", true),
            (">", "1.0.post1", "1.0.post2", true),
            ("<", "2.0", "2.0rc1", false),
            ("<", "2.0", "2.0.dev1", false),
            ("<", "2.0", "1.9", true),
            ("<", "2.0rc2", "2.0rc1", true),
        ];
        for (operator, bound, target, expected) in cases {
            let allowed = requirement(&[&[(operator, bound)]]);
            assert_eq!(
                allowed.allows(Ecosystem::PyPI, target),
                expected,
                "{target} against {operator}{bound}"
            );
        }
        let after_one = requirement(&[&[(">", "1.0")]]);
        assert_eq!(
            after_one.lowest_allowed(Ecosystem::PyPI, &versions(&["1.1", "1.0.post1", "1.0"])),
            Some("1.1".to_owned())
        );
    }

    #[test]
    fn pub_caret_follows_dart_next_breaking() {
        let cases = [
            ("^0.0.3", "0.0.3", "0.1"),
            ("^0.2.3", "0.2.3", "0.3"),
            ("^1.2.3", "1.2.3", "2"),
            ("^0", "0", "0.1"),
        ];
        for (text, lower, upper) in cases {
            assert_eq!(
                Requirement::parse(Ecosystem::Pub, text),
                Some(requirement(&[&[(">=", lower), ("<", upper)]])),
                "{text}"
            );
        }
    }

    #[test]
    fn nuget_text_reads_minimums_and_intervals() {
        let cases: [(&str, Option<Requirement>); 13] = [
            ("1.0", Some(requirement(&[&[(">=", "1.0")]]))),
            ("[1.0]", Some(requirement(&[&[("==", "1.0")]]))),
            (
                "[1.0,2.0)",
                Some(requirement(&[&[(">=", "1.0"), ("<", "2.0")]])),
            ),
            ("(1.0,)", Some(requirement(&[&[(">", "1.0")]]))),
            ("(,2.0]", Some(requirement(&[&[("<=", "2.0")]]))),
            ("(,)", None),
            // An interval that is still being typed has no closing bracket.
            ("[1.0,2.0", None),
            ("[1.0,2.0x", None),
            ("(1.0,2.0", None),
            ("[1.0", None),
            ("1.*", None),
            ("$(Ver)", None),
            ("", None),
        ];
        for (text, expected) in cases {
            assert_eq!(
                Requirement::parse(Ecosystem::NuGet, text),
                expected,
                "{text}"
            );
        }
    }

    #[test]
    fn a_nuget_range_gives_its_lowest_allowed_version() {
        let minimum = Requirement::parse(Ecosystem::NuGet, "1.0").expect("a minimum");
        assert_eq!(
            minimum.lowest_allowed(Ecosystem::NuGet, &versions(&["2.0.0", "1.1.0"])),
            Some("1.1.0".to_owned())
        );
        let interval = Requirement::parse(Ecosystem::NuGet, "[1.0,2.0)").expect("an interval");
        assert_eq!(
            interval.lowest_allowed(Ecosystem::NuGet, &versions(&["2.0.0", "1.9.0", "1.0.0"])),
            Some("1.0.0".to_owned())
        );
    }

    #[test]
    fn the_requests_range_checks_the_lowest_allowed_version() {
        let allowed = requirement(&[&[(">", "1.12"), ("<", "2.10")]]);
        let list = versions(&REQUESTS);
        assert_eq!(
            checked_version_of(Ecosystem::PyPI, "1.12", Some(&allowed), Some(&list)),
            Some("2.0.0".to_owned())
        );
        assert!(needs_list(Ecosystem::PyPI, "1.12", Some(&allowed)));
    }

    #[test]
    fn without_a_list_or_an_allowed_version_the_bound_text_is_checked() {
        let allowed = requirement(&[&[(">", "1.12"), ("<", "2.10")]]);
        assert_eq!(
            checked_version_of(Ecosystem::PyPI, "1.12", Some(&allowed), None),
            Some("1.12".to_owned())
        );
        let none_fits = requirement(&[&[(">", "2.0.0"), ("<", "2.0.1")]]);
        assert_eq!(
            checked_version_of(
                Ecosystem::PyPI,
                "2.0.0",
                Some(&none_fits),
                Some(&versions(&REQUESTS))
            ),
            Some("2.0.0".to_owned())
        );
        assert_eq!(
            checked_version_of(Ecosystem::Cargo, "1.12", None, None),
            Some("1.12".to_owned())
        );
    }

    #[test]
    fn an_exact_pin_keeps_its_text_and_needs_no_list() {
        let pin = requirement(&[&[("==", "2.0.0")]]);
        assert_eq!(
            checked_version_of(
                Ecosystem::PyPI,
                "2.0.0",
                Some(&pin),
                Some(&versions(&["3.0.0"]))
            ),
            Some("2.0.0".to_owned())
        );
        assert!(!needs_list(Ecosystem::PyPI, "2.0.0", Some(&pin)));
        assert!(!needs_list(Ecosystem::Cargo, "1.0", None));
    }

    #[test]
    fn a_requirement_that_is_not_audited_stays_unaudited() {
        let allowed = requirement(&[&[(">=", "1.2")]]);
        let list = versions(&["1.2.5"]);
        assert_eq!(
            checked_version_of(Ecosystem::Packagist, "1.2.*", Some(&allowed), Some(&list)),
            None
        );
        assert!(!needs_list(Ecosystem::Packagist, "1.2.*", Some(&allowed)));
    }
}
