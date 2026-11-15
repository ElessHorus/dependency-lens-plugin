//! Fixes for known vulnerabilities: the version to move to, whether the declared bounds allow it,
//! and the requirement text to write.
//!
//! OSV lists for each advisory the version ranges that it affects, and the version that fixes
//! each range. The rules here pick, for one dependency, the smallest version that fixes every
//! advisory of its current version.

use crate::model::{Affected, Ecosystem, RangeEvent};
use crate::registries::dotted::{DottedVersion, PubVersion, segment};
use crate::registries::gem_version::GemVersion;
use crate::registries::pep440::Pep440;
use crate::update::{UpdateVersion, split_operator};

/// Operators that a requirement may start with and that keep the target version allowed.
///
/// `>` and `<` are left out: replacing `>1.0` by `>1.2` would exclude `1.2`, the fixed version itself.
const REWRITABLE_OPERATORS: [&str; 9] = ["", "=", "==", "===", "^", "~", "~>", "~=", ">="];

/// Constraint operators that the scanner of a line reads, longest first.
const SCANNED_OPERATORS: [&str; 9] = ["===", "==", "~=", "~>", ">=", "<=", "!=", "<", ">"];

/// What a fix does for one dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixPlan {
    /// The smallest version that fixes every advisory that has a known fix.
    pub target: String,
    /// The advisories that the target fixes.
    pub fixed_count: usize,
    /// The advisories of the current version, with or without a known fix.
    pub total_count: usize,
}

/// One constraint of a requirement line, such as `<` and `1` in `flask>=0.12.2,<1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constraint {
    pub operator: String,
    pub version: String,
}

/// The constraints that a requirement line holds.
#[derive(Debug, PartialEq, Eq)]
pub struct LineConstraints {
    /// The operator right before the pin, which the fix replaces. `None` when the pin has none.
    pub pin_operator: Option<String>,
    /// Every other constraint of the line. The fixed version must satisfy them too.
    pub others: Vec<Constraint>,
}

/// Returns the version that fixes the first range of `affected` that holds `current`, as OSV writes it.
///
/// Only the entries of the package `package` in the ecosystem `eco` count. Returns `None` when no
/// range holds `current`, or when the range that holds it names no fixed version.
pub fn fixed_version(
    eco: Ecosystem,
    package: &str,
    current: &str,
    affected: &[Affected],
) -> Option<String> {
    match eco {
        Ecosystem::PyPI => {
            fixed_version_of::<Pep440>(eco, package, current, affected).map(|(_, text)| text)
        }
        Ecosystem::RubyGems => {
            fixed_version_of::<GemVersion>(eco, package, current, affected).map(|(_, text)| text)
        }
        Ecosystem::Pub => {
            fixed_version_of::<PubVersion>(eco, package, current, affected).map(|(_, text)| text)
        }
        _ => {
            fixed_version_of::<DottedVersion>(eco, package, current, affected).map(|(_, text)| text)
        }
    }
}

fn fixed_version_of<V: UpdateVersion>(
    eco: Ecosystem,
    package: &str,
    current: &str,
    affected: &[Affected],
) -> Option<(V, String)> {
    let current = V::parse_version(current)?;
    ranges_of(eco, package, affected).find_map(|events| fix_of_range(events, &current))
}

/// Returns the event lists of the ranges of the entries of `affected` that name `package` in `eco`.
fn ranges_of<'a>(
    eco: Ecosystem,
    package: &str,
    affected: &'a [Affected],
) -> impl Iterator<Item = &'a [RangeEvent]> {
    let wanted_package = eco.normalize_package(package);
    affected
        .iter()
        .filter(move |entry| {
            entry.ecosystem.eq_ignore_ascii_case(eco.osv_name())
                && eco.normalize_package(&entry.name) == wanted_package
        })
        .flat_map(|entry| entry.ranges.iter().map(Vec::as_slice))
}

/// Returns the fix of the interval of `events` that holds `current`.
///
/// Events come in order: each `introduced` opens an interval, and the next `fixed` closes it. An
/// interval closed by `last_affected`, or never closed, holds `current` but names no fix.
fn fix_of_range<V: UpdateVersion>(events: &[RangeEvent], current: &V) -> Option<(V, String)> {
    let mut introduced: Option<V> = None;
    for event in events {
        match event {
            RangeEvent::Introduced(text) => introduced = V::parse_version(text),
            RangeEvent::Fixed(text) => {
                // A fixed version that is not a version, such as a commit, skips only its interval.
                if let Some(fixed) = V::parse_version(text)
                    && introduced.as_ref().is_some_and(|start| start <= current)
                    && *current < fixed
                {
                    return Some((fixed, text.clone()));
                }
                introduced = None;
            }
            RangeEvent::LastAffected(_) => introduced = None,
        }
    }
    None
}

/// Plans the fix of a dependency whose current version `current` the `advisories` affect.
///
/// The target is the highest of the fixes that `allows` accepts, such as the ones inside the bounds
/// of the requirement. It fixes every advisory whose fix is not above it. Returns `None` when no
/// fix is allowed, or when `current` is not a version.
pub fn plan_fix(
    eco: Ecosystem,
    package: &str,
    current: &str,
    advisories: &[&[Affected]],
    allows: impl Fn(&str) -> bool,
) -> Option<FixPlan> {
    match eco {
        Ecosystem::PyPI => plan_fix_of::<Pep440>(eco, package, current, advisories, allows),
        Ecosystem::RubyGems => plan_fix_of::<GemVersion>(eco, package, current, advisories, allows),
        Ecosystem::Pub => plan_fix_of::<PubVersion>(eco, package, current, advisories, allows),
        _ => plan_fix_of::<DottedVersion>(eco, package, current, advisories, allows),
    }
}

/// The kind of an OSV range event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EventKind {
    Introduced,
    Fixed,
    LastAffected,
}

/// A range event whose version is parsed. `text` is the version as OSV writes it.
struct ParsedEvent<'a, V> {
    version: V,
    kind: EventKind,
    text: &'a str,
}

/// Parses the events of a range and sorts them by version, as the OSV evaluation algorithm does.
///
/// An event whose version does not parse, such as a commit, is skipped. An unreadable `fixed` or
/// `last_affected` then leaves its interval open, so the range never claims a fix it cannot prove.
fn parse_range<V: UpdateVersion>(events: &[RangeEvent]) -> Vec<ParsedEvent<'_, V>> {
    let mut parsed: Vec<ParsedEvent<'_, V>> = events
        .iter()
        .filter_map(|event| {
            let (kind, text) = match event {
                RangeEvent::Introduced(text) => (EventKind::Introduced, text.as_str()),
                RangeEvent::Fixed(text) => (EventKind::Fixed, text.as_str()),
                RangeEvent::LastAffected(text) => (EventKind::LastAffected, text.as_str()),
            };
            Some(ParsedEvent {
                version: V::parse_version(text)?,
                kind,
                text,
            })
        })
        .collect();
    // Stable, so events of the same version keep the order of the advisory.
    parsed.sort_by(|left, right| left.version.cmp(&right.version));
    parsed
}

/// Returns `true` when `version` lies in the range `events`.
///
/// This is the `IncludedInRanges` algorithm of the OSV schema: `introduced` opens the range at its
/// version, `fixed` closes it at its version, and `last_affected` closes it after its version. The
/// later events win, so a range with several intervals holds a version of any of them.
fn range_holds<V: UpdateVersion>(events: &[ParsedEvent<'_, V>], version: &V) -> bool {
    let mut is_affected = false;
    for event in events {
        match event.kind {
            EventKind::Introduced if *version >= event.version => is_affected = true,
            EventKind::Fixed if *version >= event.version => is_affected = false,
            EventKind::LastAffected if *version > event.version => is_affected = false,
            _ => {}
        }
    }
    is_affected
}

/// The ranges of one advisory for the package, with their events parsed.
struct AdvisoryRanges<'a, V> {
    ranges: Vec<Vec<ParsedEvent<'a, V>>>,
}

impl<'a, V: UpdateVersion> AdvisoryRanges<'a, V> {
    /// Returns `true` when the advisory affects `version` through any of its ranges.
    fn affects(&self, version: &V) -> bool {
        self.ranges.iter().any(|range| range_holds(range, version))
    }

    /// Returns the `fixed` event that ends the intervals holding `current`, as OSV writes it.
    ///
    /// Returns `None` when an interval that holds `current` ends with `last_affected`, or does not
    /// end: the advisory has no fix for this version. Several intervals can hold `current`, and
    /// the advisory then ends with the last of them.
    fn fix_for(&self, current: &V) -> Option<&ParsedEvent<'a, V>> {
        let mut last_fix = None;
        for range in self
            .ranges
            .iter()
            .filter(|range| range_holds(range, current))
        {
            // The events are sorted, so the first event past `current` ends the interval.
            let end = range.iter().find(|event| {
                event.version > *current
                    || (event.version == *current && event.kind == EventKind::LastAffected)
            })?;
            if end.kind != EventKind::Fixed {
                return None;
            }
            if last_fix.is_none_or(|fix: &ParsedEvent<'a, V>| fix.version < end.version) {
                last_fix = Some(end);
            }
        }
        last_fix
    }
}

fn plan_fix_of<V: UpdateVersion>(
    eco: Ecosystem,
    package: &str,
    current: &str,
    advisories: &[&[Affected]],
    allows: impl Fn(&str) -> bool,
) -> Option<FixPlan> {
    let current = V::parse_version(current)?;
    // Parse each advisory once. Only an advisory that affects the current version can be fixed.
    let open_advisories: Vec<AdvisoryRanges<'_, V>> = advisories
        .iter()
        .map(|affected| AdvisoryRanges {
            ranges: ranges_of(eco, package, affected).map(parse_range).collect(),
        })
        .filter(|advisory| advisory.affects(&current))
        .collect();
    let fixes: Vec<&ParsedEvent<'_, V>> = open_advisories
        .iter()
        .filter_map(|advisory| advisory.fix_for(&current))
        .collect();
    // The least target is the highest allowed fix that OSV names for the current version.
    let least_fix = fixes
        .iter()
        .filter(|fix| allows(fix.text))
        .max_by(|left, right| left.version.cmp(&right.version))?;
    let least_target = &least_fix.version;
    // The target must fix every advisory that this least target is meant to fix. A later interval of
    // such an advisory may hold the least target, so the target then moves to a higher fix.
    let must_fix: Vec<&AdvisoryRanges<'_, V>> = open_advisories
        .iter()
        .filter(|advisory| {
            advisory
                .fix_for(&current)
                .is_some_and(|fix| fix.version <= *least_target)
        })
        .collect();
    // A candidate target is a version where an interval of an open advisory ends.
    let mut candidates: Vec<(&V, &str)> = open_advisories
        .iter()
        .flat_map(|advisory| &advisory.ranges)
        .flatten()
        .filter(|event| event.kind == EventKind::Fixed && event.version > current)
        .filter(|event| allows(event.text))
        .map(|event| (&event.version, event.text))
        .collect();
    candidates.sort_by(|left, right| left.0.cmp(right.0));
    let fixed_count_at = |version: &V| {
        open_advisories
            .iter()
            .filter(|advisory| !advisory.affects(version))
            .count()
    };
    let plan_at = |text: &str, fixed_count: usize| FixPlan {
        target: text.to_owned(),
        fixed_count,
        total_count: advisories.len(),
    };
    // The nearest candidate from the least target that fixes every advisory to fix. It does not
    // chase advisories that have no fix for the current version, so it never jumps further than needed.
    if let Some((version, text)) = candidates.iter().find(|(version, _)| {
        **version >= *least_target && must_fix.iter().all(|advisory| !advisory.affects(version))
    }) {
        return Some(plan_at(text, fixed_count_at(version)));
    }
    // No allowed candidate fixes them all. Take the one that fixes the most, the smallest on a tie.
    let mut best: Option<(usize, &str)> = None;
    for (version, text) in candidates {
        let fixed_count = fixed_count_at(version);
        if fixed_count > best.map_or(0, |(best_count, _)| best_count) {
            best = Some((fixed_count, text));
        }
    }
    let (fixed_count, text) = best?;
    Some(plan_at(text, fixed_count))
}

/// Reads the constraints of the requirement of `eco` that holds the pin at byte `pin_start` of `line`.
///
/// A constraint is an operator followed by a version that starts with a digit. This reads
/// `flask>=0.12.2,<1` and `gem 'rails', '>= 7.0', '< 8'`, and leaves out a marker such as
/// `python_version < "3.8"`, a comment, and the other requirements of the same line.
pub fn line_constraints(eco: Ecosystem, line: &str, pin_start: usize) -> LineConstraints {
    let (segment, segment_start) = requirement_segment(eco, line, pin_start);
    let pin_in_segment = pin_start.saturating_sub(segment_start);
    let bytes = segment.as_bytes();
    let mut found = LineConstraints {
        pin_operator: None,
        others: Vec::new(),
    };
    let mut index = 0;
    while index < bytes.len() {
        let follows_operator = index > 0 && b"=<>!~".contains(&bytes[index - 1]);
        // Bytes are compared, because `index` may sit inside a multi-byte character.
        let operator = SCANNED_OPERATORS.iter().find(|candidate| {
            !follows_operator && bytes[index..].starts_with(candidate.as_bytes())
        });
        let Some(operator) = operator else {
            index += 1;
            continue;
        };
        let after_operator = index + operator.len();
        let version_start = after_operator
            + bytes[after_operator..]
                .iter()
                .take_while(|byte| **byte == b' ')
                .count();
        let version_len = bytes[version_start..]
            .iter()
            .take_while(|byte| byte.is_ascii_alphanumeric() || b".+-*".contains(byte))
            .count();
        let starts_with_digit = bytes.get(version_start).is_some_and(u8::is_ascii_digit);
        if starts_with_digit {
            if version_start == pin_in_segment {
                found.pin_operator = Some((*operator).to_owned());
            } else {
                found.others.push(Constraint {
                    operator: (*operator).to_owned(),
                    // The version bytes are ASCII, so the slice is on character boundaries.
                    version: segment[version_start..version_start + version_len].to_owned(),
                });
            }
        }
        index = after_operator;
    }
    found
}

/// The part of `line` that holds the requirement of the pin, and its start.
///
/// A PyPI requirement sits in one string (`"flask>=0.12.2,<1"`) or fills a requirements line,
/// and a trailing comment is not part of it. A gem lists its constraints in several strings, so
/// its segment is the line up to a trailing comment.
fn requirement_segment(eco: Ecosystem, line: &str, pin_start: usize) -> (&str, usize) {
    let code = line.find(" #").map_or(line, |comment| &line[..comment]);
    if eco == Ecosystem::RubyGems {
        return (code, 0);
    }
    let before = code.get(..pin_start).unwrap_or(code);
    let start = before.rfind(['"', '\'']).map_or(0, |quote| quote + 1);
    let after = code.get(pin_start..).unwrap_or_default();
    let end = after
        .find(['"', '\''])
        .map_or(code.len(), |quote| pin_start + quote);
    (&code[start..end], start)
}

/// Returns `true` when `target` satisfies every constraint. A constraint that is not a version
/// cannot be checked, so it refuses the target.
pub fn satisfies_all(eco: Ecosystem, target: &str, constraints: &[Constraint]) -> bool {
    match eco {
        Ecosystem::PyPI => satisfies_all_of::<Pep440>(target, constraints),
        Ecosystem::RubyGems => satisfies_all_of::<GemVersion>(target, constraints),
        Ecosystem::Pub => satisfies_all_of::<PubVersion>(target, constraints),
        _ => satisfies_all_of::<DottedVersion>(target, constraints),
    }
}

fn satisfies_all_of<V: UpdateVersion>(target: &str, constraints: &[Constraint]) -> bool {
    let Some(target) = V::parse_version(target) else {
        return false;
    };
    constraints.iter().all(|constraint| {
        let Some(bound) = V::parse_version(&constraint.version) else {
            return false;
        };
        match constraint.operator.as_str() {
            "<" => target < bound,
            "<=" => target <= bound,
            ">" => target > bound,
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

/// The requirement text that moves `declared` to `target`, or `None` when the form cannot be rewritten.
///
/// The operator and the `v` of a Go version stay, and the full target is written. Ranges, wildcards,
/// properties and the strict `>` name no single version to replace, so they are left alone.
pub fn render_fix(eco: Ecosystem, declared: &str, target: &str) -> Option<String> {
    match eco {
        Ecosystem::PyPI => render_fix_of::<Pep440>(declared, target),
        Ecosystem::RubyGems => render_fix_of::<GemVersion>(declared, target),
        Ecosystem::Pub => render_fix_of::<PubVersion>(declared, target),
        _ => render_fix_of::<DottedVersion>(declared, target),
    }
}

fn render_fix_of<V: UpdateVersion>(declared: &str, target: &str) -> Option<String> {
    if declared.is_empty()
        || declared.contains(char::is_whitespace)
        || declared.contains(['*', '|', ',', '$', '@', '[', '(', ')'])
    {
        return None;
    }
    let (operator, rest) = split_operator(declared);
    if !REWRITABLE_OPERATORS.contains(&operator) {
        return None;
    }
    // A Go version starts with `v`, and the version OSV gives for it does not.
    let (prefix, version_text) = match rest.strip_prefix('v') {
        Some(after) if after.starts_with(|character: char| character.is_ascii_digit()) => {
            ("v", after)
        }
        _ => ("", rest),
    };
    let declared_version = V::parse_version(version_text)?;
    let target_version = V::parse_version(target)?;
    (target_version > declared_version).then(|| format!("{operator}{prefix}{target}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Affected, Ecosystem, RangeEvent};

    fn range(events: &[(&str, &str)]) -> Vec<RangeEvent> {
        events
            .iter()
            .map(|(kind, version)| match *kind {
                "introduced" => RangeEvent::Introduced((*version).to_owned()),
                "fixed" => RangeEvent::Fixed((*version).to_owned()),
                _ => RangeEvent::LastAffected((*version).to_owned()),
            })
            .collect()
    }

    fn affected(ecosystem: &str, name: &str, ranges: &[&[(&str, &str)]]) -> Vec<Affected> {
        vec![Affected {
            ecosystem: ecosystem.to_owned(),
            name: name.to_owned(),
            ranges: ranges.iter().map(|events| range(events)).collect(),
        }]
    }

    #[test]
    fn the_fixed_version_closes_the_range_that_holds_the_current_version() {
        let go = affected(
            "Go",
            "golang.org/x/text",
            &[&[("introduced", "0"), ("fixed", "0.3.3")]],
        );
        assert_eq!(
            fixed_version(Ecosystem::Go, "golang.org/x/text", "0.3.0", &go).as_deref(),
            Some("0.3.3")
        );
        // A backport: two ranges, and each version line has its own fix.
        let backport = affected(
            "npm",
            "lodash",
            &[
                &[("introduced", "0"), ("fixed", "4.17.21")],
                &[("introduced", "5.0.0"), ("fixed", "5.1.2")],
            ],
        );
        assert_eq!(
            fixed_version(Ecosystem::Npm, "lodash", "4.17.15", &backport).as_deref(),
            Some("4.17.21")
        );
        assert_eq!(
            fixed_version(Ecosystem::Npm, "lodash", "5.0.4", &backport).as_deref(),
            Some("5.1.2")
        );
    }

    #[test]
    fn a_range_that_does_not_hold_the_version_or_names_no_fix_gives_none() {
        let go = affected(
            "Go",
            "golang.org/x/text",
            &[&[("introduced", "0"), ("fixed", "0.3.3")]],
        );
        // The version is already past the fix.
        assert_eq!(
            fixed_version(Ecosystem::Go, "golang.org/x/text", "0.3.3", &go),
            None
        );
        // The range opens after the version.
        let later = affected(
            "npm",
            "x",
            &[&[("introduced", "2.0.0"), ("fixed", "2.1.0")]],
        );
        assert_eq!(fixed_version(Ecosystem::Npm, "x", "1.5.0", &later), None);
        // Only a last affected version: no fix is known.
        let unfixed = affected(
            "npm",
            "x",
            &[&[("introduced", "0"), ("last_affected", "9.9.9")]],
        );
        assert_eq!(fixed_version(Ecosystem::Npm, "x", "1.5.0", &unfixed), None);
        // An open range with no closing event is still affected and unfixed.
        let open = affected("npm", "x", &[&[("introduced", "0")]]);
        assert_eq!(fixed_version(Ecosystem::Npm, "x", "1.5.0", &open), None);
    }

    #[test]
    fn only_the_entry_of_the_same_ecosystem_and_package_counts() {
        let entries = affected(
            "Go",
            "golang.org/x/text",
            &[&[("introduced", "0"), ("fixed", "0.3.3")]],
        );
        assert_eq!(
            fixed_version(Ecosystem::Npm, "golang.org/x/text", "0.3.0", &entries),
            None
        );
        assert_eq!(
            fixed_version(Ecosystem::Go, "golang.org/x/net", "0.3.0", &entries),
            None
        );
        // PyPI names compare in their normal form.
        let pypi = affected(
            "PyPI",
            "Flask",
            &[&[("introduced", "0"), ("fixed", "0.12.3")]],
        );
        assert_eq!(
            fixed_version(Ecosystem::PyPI, "flask", "0.12.2", &pypi).as_deref(),
            Some("0.12.3")
        );
    }

    #[test]
    fn versions_compare_by_the_rules_of_their_ecosystem() {
        // PEP 440: `1.0rc1` is below `1.0`.
        let pypi = affected("PyPI", "demo", &[&[("introduced", "0"), ("fixed", "1.0")]]);
        assert_eq!(
            fixed_version(Ecosystem::PyPI, "demo", "1.0rc1", &pypi).as_deref(),
            Some("1.0")
        );
        // Maven: the log4j fix of 2.15.0.
        let maven = affected(
            "Maven",
            "org.apache.logging.log4j:log4j-core",
            &[&[("introduced", "2.0-beta9"), ("fixed", "2.15.0")]],
        );
        assert_eq!(
            fixed_version(
                Ecosystem::Maven,
                "org.apache.logging.log4j:log4j-core",
                "2.14.1",
                &maven
            )
            .as_deref(),
            Some("2.15.0")
        );
    }

    #[test]
    fn the_target_is_the_highest_fix_of_the_advisories_and_counts_them() {
        let smallvec_a = affected(
            "crates.io",
            "smallvec",
            &[&[("introduced", "0.6.5"), ("fixed", "0.6.13")]],
        );
        let smallvec_b = affected(
            "crates.io",
            "smallvec",
            &[&[("introduced", "1.0.0"), ("fixed", "1.6.1")]],
        );
        let unfixed = affected(
            "crates.io",
            "smallvec",
            &[&[("introduced", "0"), ("last_affected", "9.0.0")]],
        );
        let advisories: Vec<&[Affected]> = vec![&smallvec_b, &unfixed, &smallvec_b];
        let plan =
            plan_fix(Ecosystem::Cargo, "smallvec", "1.6.0", &advisories, |_| true).expect("a fix");
        assert_eq!(plan.target, "1.6.1");
        assert_eq!((plan.fixed_count, plan.total_count), (2, 3));
        // Another range that does not hold 1.6.0 adds nothing.
        let advisories: Vec<&[Affected]> = vec![&smallvec_a, &smallvec_b];
        assert_eq!(
            plan_fix(Ecosystem::Cargo, "smallvec", "1.6.0", &advisories, |_| true)
                .unwrap()
                .fixed_count,
            1
        );
        // No advisory has a fix.
        let advisories: Vec<&[Affected]> = vec![&unfixed];
        assert!(plan_fix(Ecosystem::Cargo, "smallvec", "1.6.0", &advisories, |_| true).is_none());
        assert!(plan_fix(Ecosystem::Cargo, "smallvec", "not a version", &[], |_| true).is_none());
    }

    #[test]
    fn a_target_that_the_bounds_refuse_gives_way_to_the_highest_allowed_fix() {
        let early = affected(
            "PyPI",
            "flask",
            &[&[("introduced", "0"), ("fixed", "0.12.3")]],
        );
        let late = affected(
            "PyPI",
            "flask",
            &[&[("introduced", "0"), ("fixed", "2.3.2")]],
        );
        let advisories: Vec<&[Affected]> = vec![&early, &late, &early];
        let below_one = [Constraint {
            operator: "<".to_owned(),
            version: "1".to_owned(),
        }];
        let allows = |target: &str| satisfies_all(Ecosystem::PyPI, target, &below_one);
        let plan =
            plan_fix(Ecosystem::PyPI, "flask", "0.12.2", &advisories, allows).expect("a fix");
        assert_eq!(plan.target, "0.12.3");
        // The two advisories fixed in 0.12.3 are fixed, and the one fixed in 2.3.2 is not.
        assert_eq!((plan.fixed_count, plan.total_count), (2, 3));
        // When every fix leaves the bounds, there is none.
        let only_late: Vec<&[Affected]> = vec![&late];
        assert!(plan_fix(Ecosystem::PyPI, "flask", "0.12.2", &only_late, allows).is_none());
    }

    /// An advisory whose single range holds several intervals, as in the OSV "multiple range" example.
    fn two_interval_advisory(second_end: (&'static str, &'static str)) -> Vec<Affected> {
        affected(
            "crates.io",
            "review_demo",
            &[&[
                ("introduced", "0"),
                ("fixed", "1.1.0"),
                ("introduced", "1.5.0"),
                second_end,
            ]],
        )
    }

    fn plan_of(advisories: &[&[Affected]], allows: impl Fn(&str) -> bool) -> Option<FixPlan> {
        plan_fix(Ecosystem::Cargo, "review_demo", "1.0.0", advisories, allows)
    }

    #[test]
    fn a_target_inside_a_later_interval_of_an_advisory_does_not_fix_it() {
        // A is affected on [0, 1.1.0) and [1.5.0, 1.8.0). B is affected on [0, 1.6.0).
        let advisory_a = two_interval_advisory(("fixed", "1.8.0"));
        let advisory_b = affected(
            "crates.io",
            "review_demo",
            &[&[("introduced", "0"), ("fixed", "1.6.0")]],
        );
        let plan = plan_of(&[&advisory_a, &advisory_b], |_| true).expect("a fix");
        // 1.6.0 is still inside the second interval of A, so the target moves on to 1.8.0.
        assert_eq!(plan.target, "1.8.0");
        assert_eq!((plan.fixed_count, plan.total_count), (2, 2));
        // Control: with only the first interval of A, 1.6.0 fixes both.
        let first_only = affected(
            "crates.io",
            "review_demo",
            &[&[("introduced", "0"), ("fixed", "1.1.0")]],
        );
        let plan = plan_of(&[&first_only, &advisory_b], |_| true).expect("a fix");
        assert_eq!(plan.target, "1.6.0");
        assert_eq!((plan.fixed_count, plan.total_count), (2, 2));
    }

    #[test]
    fn the_fixed_count_follows_the_real_status_of_the_target() {
        let advisory_a = two_interval_advisory(("fixed", "1.8.0"));
        let advisory_b = affected(
            "crates.io",
            "review_demo",
            &[&[("introduced", "0"), ("fixed", "1.6.0")]],
        );
        // The bounds refuse 1.8.0. 1.1.0 and 1.6.0 each fix one advisory, and the smaller one wins.
        let plan = plan_of(&[&advisory_a, &advisory_b], |target| target != "1.8.0").expect("a fix");
        assert_eq!(plan.target, "1.1.0");
        assert_eq!((plan.fixed_count, plan.total_count), (1, 2));
    }

    #[test]
    fn the_intervals_of_several_ranges_of_one_entry_all_count() {
        let two_ranges = affected(
            "crates.io",
            "review_demo",
            &[
                &[("introduced", "0"), ("fixed", "1.1.0")],
                &[("introduced", "1.5.0"), ("fixed", "1.8.0")],
            ],
        );
        let advisory_b = affected(
            "crates.io",
            "review_demo",
            &[&[("introduced", "0"), ("fixed", "1.6.0")]],
        );
        let plan = plan_of(&[&two_ranges, &advisory_b], |_| true).expect("a fix");
        assert_eq!(plan.target, "1.8.0");
        assert_eq!((plan.fixed_count, plan.total_count), (2, 2));
    }

    #[test]
    fn events_are_read_in_version_order() {
        // OSV recommends sorted events but does not require it: its algorithm sorts them first.
        let shuffled = affected(
            "crates.io",
            "review_demo",
            &[&[
                ("introduced", "1.5.0"),
                ("fixed", "1.8.0"),
                ("introduced", "0"),
                ("fixed", "1.1.0"),
            ]],
        );
        let advisory_b = affected(
            "crates.io",
            "review_demo",
            &[&[("introduced", "0"), ("fixed", "1.6.0")]],
        );
        let plan = plan_of(&[&shuffled, &advisory_b], |_| true).expect("a fix");
        assert_eq!(plan.target, "1.8.0");
        assert_eq!((plan.fixed_count, plan.total_count), (2, 2));
    }

    #[test]
    fn the_last_affected_version_is_still_affected() {
        let advisory_b = affected(
            "crates.io",
            "review_demo",
            &[&[("introduced", "0"), ("fixed", "1.6.0")]],
        );
        // 1.6.0 is the last affected version of A: A still affects it, so 1.1.0 stays the target.
        let inclusive = two_interval_advisory(("last_affected", "1.6.0"));
        let plan = plan_of(&[&inclusive, &advisory_b], |_| true).expect("a fix");
        assert_eq!(plan.target, "1.1.0");
        assert_eq!((plan.fixed_count, plan.total_count), (1, 2));
        // One step lower, 1.6.0 is above the last affected version, so it fixes both.
        let exclusive = two_interval_advisory(("last_affected", "1.5.9"));
        let plan = plan_of(&[&exclusive, &advisory_b], |_| true).expect("a fix");
        assert_eq!(plan.target, "1.6.0");
        assert_eq!((plan.fixed_count, plan.total_count), (2, 2));
    }

    #[test]
    fn an_interval_with_an_unparsable_end_is_never_claimed_as_fixed() {
        // The second interval ends at a commit: it cannot be compared, so it stays affected.
        let commit_end = two_interval_advisory(("fixed", "abc123"));
        let advisory_b = affected(
            "crates.io",
            "review_demo",
            &[&[("introduced", "0"), ("fixed", "1.6.0")]],
        );
        let plan = plan_of(&[&commit_end, &advisory_b], |_| true).expect("a fix");
        assert_eq!(plan.target, "1.1.0");
        assert_eq!((plan.fixed_count, plan.total_count), (1, 2));
    }

    #[test]
    fn an_advisory_without_a_fix_for_the_current_version_does_not_pull_the_target() {
        // A is fixed in 1.1.0. C holds 1.0.0 through a `last_affected` interval, so it has no fix for
        // it, but a later interval of C ends far away. That far end must not become the target.
        let advisory_a = affected(
            "crates.io",
            "review_demo",
            &[&[("introduced", "0"), ("fixed", "1.1.0")]],
        );
        for far_end in ["3.5.0", "4.0.0-beta.2"] {
            let advisory_c = affected(
                "crates.io",
                "review_demo",
                &[&[
                    ("introduced", "0"),
                    ("last_affected", "2.0.0"),
                    ("introduced", "3.0.0"),
                    ("fixed", far_end),
                ]],
            );
            let plan = plan_of(&[&advisory_a, &advisory_c], |_| true).expect("a fix");
            assert_eq!(plan.target, "1.1.0", "{far_end}");
            assert_eq!((plan.fixed_count, plan.total_count), (1, 2), "{far_end}");
        }
    }

    #[test]
    fn an_advisory_closed_by_last_affected_counts_as_fixed_by_a_higher_target() {
        // OSV: versions above `last_affected` are unaffected. 0.10.0 fixes B and ends A and C.
        let fixed = affected(
            "crates.io",
            "review_demo",
            &[&[("introduced", "0"), ("fixed", "0.10.0")]],
        );
        let last_affected = affected(
            "crates.io",
            "review_demo",
            &[&[("introduced", "0"), ("last_affected", "0.9.6")]],
        );
        let advisories: Vec<&[Affected]> = vec![&fixed, &last_affected, &last_affected];
        let plan = plan_fix(
            Ecosystem::Cargo,
            "review_demo",
            "0.9.6",
            &advisories,
            |_| true,
        )
        .expect("a fix");
        assert_eq!(plan.target, "0.10.0");
        assert_eq!((plan.fixed_count, plan.total_count), (3, 3));
    }

    #[test]
    fn a_backport_does_not_pull_the_target_to_another_major_line() {
        // One advisory, a fix on each version line: the nearest fix of the current line wins the tie.
        let backport = affected(
            "npm",
            "lodash",
            &[&[
                ("introduced", "0"),
                ("fixed", "4.17.21"),
                ("introduced", "5.0.0"),
                ("fixed", "5.1.2"),
            ]],
        );
        let advisories: Vec<&[Affected]> = vec![&backport];
        let plan =
            plan_fix(Ecosystem::Npm, "lodash", "4.17.15", &advisories, |_| true).expect("a fix");
        assert_eq!(plan.target, "4.17.21");
        assert_eq!((plan.fixed_count, plan.total_count), (1, 1));
    }

    #[test]
    fn constraints_are_read_from_the_line_except_the_pin() {
        let line = "  \"flask>=0.12.2,<1\",";
        let pin_start = line.find("0.12.2").unwrap();
        let found = line_constraints(Ecosystem::PyPI, line, pin_start);
        assert_eq!(found.pin_operator.as_deref(), Some(">="));
        assert_eq!(
            found.others,
            [Constraint {
                operator: "<".to_owned(),
                version: "1".to_owned()
            }]
        );
        // A marker with a quoted version is not a constraint.
        let marked = "\"requests==2.0; python_version < \\\"3.8\\\"\"";
        let found = line_constraints(Ecosystem::PyPI, marked, marked.find("2.0").unwrap());
        assert_eq!(found.pin_operator.as_deref(), Some("=="));
        assert!(found.others.is_empty());
        // Ruby lists each constraint in its own string.
        let gem = "gem 'rails', '>= 7.0.4', '< 8'";
        let found = line_constraints(Ecosystem::RubyGems, gem, gem.find("7.0.4").unwrap());
        assert_eq!(found.pin_operator.as_deref(), Some(">="));
        assert_eq!(found.others.len(), 1);
        assert_eq!(found.others[0].version, "8");
    }

    #[test]
    fn a_target_must_satisfy_every_other_constraint() {
        let below_one = [Constraint {
            operator: "<".to_owned(),
            version: "1".to_owned(),
        }];
        // flask: the fix in 0.12.3 fits `<1`, the fix in 2.3.2 does not.
        assert!(satisfies_all(Ecosystem::PyPI, "0.12.3", &below_one));
        assert!(!satisfies_all(Ecosystem::PyPI, "2.3.2", &below_one));
        for (operator, version, target, expected) in [
            ("<=", "2.0", "2.0", true),
            ("<=", "2.0", "2.1", false),
            (">", "1.0", "1.1", true),
            ("!=", "1.1", "1.1", false),
            ("==", "1.1", "1.1", true),
            ("~=", "2.28", "2.31.4", true),
            ("~=", "2.28", "3.0", false),
            ("~>", "7.0.4", "7.0.8", true),
            ("~>", "7.0.4", "7.1.0", false),
        ] {
            let constraint = [Constraint {
                operator: operator.to_owned(),
                version: version.to_owned(),
            }];
            let eco = if operator == "~>" {
                Ecosystem::RubyGems
            } else {
                Ecosystem::PyPI
            };
            assert_eq!(
                satisfies_all(eco, target, &constraint),
                expected,
                "{operator} {version} vs {target}"
            );
        }
        // A constraint that is not a version cannot be checked, so the target is refused.
        let wildcard = [Constraint {
            operator: "==".to_owned(),
            version: "1.*".to_owned(),
        }];
        assert!(!satisfies_all(Ecosystem::PyPI, "1.5", &wildcard));
    }

    #[test]
    fn the_requirement_keeps_its_operator_and_writes_the_full_target() {
        for (eco, declared, target, expected) in [
            (Ecosystem::Cargo, "1.6.0", "1.6.1", Some("1.6.1")),
            (Ecosystem::Cargo, "^1.6", "1.6.1", Some("^1.6.1")),
            (Ecosystem::Cargo, "=1.6.0", "1.6.1", Some("=1.6.1")),
            (Ecosystem::Npm, "4.17.15", "4.17.21", Some("4.17.21")),
            (Ecosystem::Npm, "~4.17.15", "4.17.21", Some("~4.17.21")),
            (Ecosystem::Npm, ">=4.17.15", "4.17.21", Some(">=4.17.21")),
            (Ecosystem::Maven, "2.14.1", "2.15.0", Some("2.15.0")),
            (Ecosystem::Go, "v0.3.0", "0.3.3", Some("v0.3.3")),
            (Ecosystem::PyPI, "2.19.0", "2.20.0", Some("2.20.0")),
            (Ecosystem::RubyGems, "1.10.0", "1.10.10", Some("1.10.10")),
            (Ecosystem::Packagist, "^8.1", "8.2.3", Some("^8.2.3")),
            // Forms that name no single version, or exclude the target, are left alone.
            (Ecosystem::Npm, "^1.0.0 || ^2.0.0", "2.1.0", None),
            (Ecosystem::Npm, "1.x", "1.5.0", None),
            (Ecosystem::Npm, "latest", "1.5.0", None),
            (Ecosystem::Cargo, ">=1.0, <2", "1.6.1", None),
            (Ecosystem::Cargo, ">1.6.0", "1.6.1", None),
            (Ecosystem::Maven, "[2.0,3.0)", "2.15.0", None),
            (Ecosystem::Maven, "${log4j.version}", "2.15.0", None),
            (Ecosystem::Cargo, "1.6.1", "1.6.1", None),
        ] {
            assert_eq!(
                render_fix(eco, declared, target).as_deref(),
                expected,
                "{eco:?} {declared} -> {target}"
            );
        }
    }

    #[test]
    fn real_advisory_shapes_give_the_expected_fixes() {
        // RUSTSEC-2021-0003: one range that holds two intervals.
        let smallvec = affected(
            "crates.io",
            "smallvec",
            &[&[
                ("introduced", "0.6.3"),
                ("fixed", "0.6.14"),
                ("introduced", "1.0.0"),
                ("fixed", "1.6.1"),
            ]],
        );
        assert_eq!(
            fixed_version(Ecosystem::Cargo, "smallvec", "1.6.0", &smallvec).as_deref(),
            Some("1.6.1")
        );
        assert_eq!(
            fixed_version(Ecosystem::Cargo, "smallvec", "0.6.10", &smallvec).as_deref(),
            Some("0.6.14")
        );
        assert_eq!(
            fixed_version(Ecosystem::Cargo, "smallvec", "0.6.2", &smallvec),
            None
        );
        assert_eq!(
            fixed_version(Ecosystem::Cargo, "smallvec", "0.9.0", &smallvec),
            None
        );

        // GHSA-jfh8-c2jp-5v3q (Log4Shell): one range per release line, plus other packages.
        let mut log4j = affected(
            "Maven",
            "org.apache.logging.log4j:log4j-core",
            &[
                &[("introduced", "2.13.0"), ("fixed", "2.15.0")],
                &[("introduced", "2.0-beta9"), ("fixed", "2.3.1")],
                &[("introduced", "2.4"), ("fixed", "2.12.2")],
            ],
        );
        log4j.extend(affected(
            "Maven",
            "org.ops4j.pax.logging:pax-logging-log4j2",
            &[&[("introduced", "1.8.0"), ("fixed", "1.9.2")]],
        ));
        let package = "org.apache.logging.log4j:log4j-core";
        assert_eq!(
            fixed_version(Ecosystem::Maven, package, "2.14.1", &log4j).as_deref(),
            Some("2.15.0")
        );
        assert_eq!(
            fixed_version(Ecosystem::Maven, package, "2.4.1", &log4j).as_deref(),
            Some("2.12.2")
        );
        assert_eq!(
            fixed_version(Ecosystem::Maven, package, "2.0", &log4j).as_deref(),
            Some("2.3.1")
        );
    }

    #[test]
    fn the_line_scan_survives_non_ascii_text_and_stays_inside_the_requirement() {
        // A non-ASCII character after the pin must not split the scan inside a character.
        let line = "  \"flask>=0.12.2,<1\",  # prüfen >=3.5";
        let found = line_constraints(Ecosystem::PyPI, line, line.find("0.12.2").unwrap());
        assert_eq!(found.others.len(), 1);
        assert_eq!(found.others[0].version, "1");
        // Another requirement on the same line is not a constraint of this one.
        let two = "dependencies = [\"flask>=0.12.2,<1\", \"requests==2.19.0\"]";
        let found = line_constraints(Ecosystem::PyPI, two, two.find("0.12.2").unwrap());
        assert_eq!(found.others.len(), 1);
        assert_eq!(found.others[0].operator, "<");
        // A requirements line has no quotes, and its comment is left out.
        let plain = "flask>=0.12.2,<1  # needs >=3.5";
        let found = line_constraints(Ecosystem::PyPI, plain, plain.find("0.12.2").unwrap());
        assert_eq!(found.others.len(), 1);
    }

    #[test]
    fn an_unparsable_fixed_version_skips_only_its_interval() {
        let events = affected(
            "Maven",
            "g:a",
            &[&[
                ("introduced", "0"),
                ("fixed", "not-a-version"),
                ("introduced", "2.0"),
                ("fixed", "2.4.1"),
            ]],
        );
        assert_eq!(
            fixed_version(Ecosystem::Maven, "g:a", "2.1", &events).as_deref(),
            Some("2.4.1")
        );
    }

    #[test]
    fn a_single_segment_pessimistic_bound_keeps_its_major_version() {
        let bound = [Constraint {
            operator: "~>".to_owned(),
            version: "2".to_owned(),
        }];
        assert!(!satisfies_all(Ecosystem::RubyGems, "3.0.1", &bound));
        assert!(satisfies_all(Ecosystem::RubyGems, "2.5", &bound));
    }

    #[test]
    fn pub_versions_count_their_build_number() {
        let pub_package = affected(
            "Pub",
            "demo",
            &[&[("introduced", "0"), ("fixed", "0.4.0+2")]],
        );
        assert_eq!(
            fixed_version(Ecosystem::Pub, "demo", "0.4.0+1", &pub_package).as_deref(),
            Some("0.4.0+2")
        );
        assert_eq!(
            fixed_version(Ecosystem::Pub, "demo", "0.4.0+2", &pub_package),
            None
        );
    }
}
