//! What a version requirement allows: constraints, alternatives and the lowest allowed version.

use crate::model::Ecosystem;
use crate::registries::dotted::{DottedVersion, PubVersion, segment};
use crate::registries::gem_version::GemVersion;
use crate::registries::maven_version::MavenVersion;
use crate::registries::pep440::Pep440;
use crate::update::UpdateVersion;

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
            Ecosystem::PyPI => self.lowest_allowed_of::<Pep440>(eco, versions),
            Ecosystem::RubyGems => self.lowest_allowed_of::<GemVersion>(eco, versions),
            Ecosystem::Pub => self.lowest_allowed_of::<PubVersion>(eco, versions),
            Ecosystem::Maven => self.lowest_allowed_of::<MavenVersion>(eco, versions),
            _ => self.lowest_allowed_of::<DottedVersion>(eco, versions),
        }
    }

    fn lowest_allowed_of<V: UpdateVersion>(
        &self,
        eco: Ecosystem,
        versions: &[String],
    ) -> Option<String> {
        let names_pre_release = self
            .alternatives
            .iter()
            .flatten()
            .filter_map(|constraint| V::parse_version(&constraint.version))
            .any(|bound| bound.is_prerelease_version());
        // The list is newest first, so the reverse scan meets the oldest version first.
        versions
            .iter()
            .rev()
            .find(|text| {
                (names_pre_release
                    || V::parse_version(text)
                        .is_some_and(|version| !version.is_prerelease_version()))
                    && self.allows(eco, text)
            })
            .cloned()
    }
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
}
