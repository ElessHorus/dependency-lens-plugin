//! Update rules: how far a registry release is ahead of a declared version, and how to rewrite a requirement to a newer version.

use crate::model::{Dependency, Ecosystem};
use crate::osv::declared_version_for_osv;
use crate::registries::pep440::Pep440;

/// Operator characters that may start a Poetry-style requirement such as `^2.28`.
const OPERATOR_BYTES: &[u8] = b"^~=<>!";

/// How far the latest release is ahead of the current version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateKind {
    /// The first release segment changes.
    Major,
    /// The second release segment changes.
    Minor,
    /// Only a later release segment changes.
    Patch,
    /// The latest release is a pre-release.
    Prerelease,
}

/// `None` when either version cannot be parsed for this ecosystem or `latest` is not newer than `current`.
pub fn update_kind(eco: Ecosystem, current: &str, latest: &str) -> Option<UpdateKind> {
    match eco {
        Ecosystem::PyPI => pep440_update_kind(current, latest),
        _ => None,
    }
}

/// True when `latest` is a stable version newer than the lower bound of `declared`.
pub fn is_outdated(eco: Ecosystem, declared: &str, latest: &str) -> bool {
    match eco {
        Ecosystem::PyPI => pep440_is_outdated(declared, latest),
        _ => false,
    }
}

/// The replacement text for `dep.version_span`, or None when the requirement cannot be rewritten safely.
pub fn render_update(eco: Ecosystem, dep: &Dependency, latest: &str) -> Option<String> {
    match eco {
        Ecosystem::PyPI => pep440_render_update(dep, latest),
        _ => None,
    }
}

/// Classifies the step from `current` to `latest` by the first release segment that differs.
fn pep440_update_kind(current: &str, latest: &str) -> Option<UpdateKind> {
    let current = Pep440::parse(current)?;
    let latest = Pep440::parse(latest)?;
    if latest <= current {
        return None;
    }
    if latest.is_prerelease() {
        return Some(UpdateKind::Prerelease);
    }
    // A missing segment reads as 0, so `2` and `2.0` compare equal.
    let segment = |release: &[u64], index: usize| release.get(index).copied().unwrap_or(0);
    let (current_release, latest_release) = (current.release(), latest.release());
    if segment(current_release, 0) != segment(latest_release, 0) {
        Some(UpdateKind::Major)
    } else if segment(current_release, 1) != segment(latest_release, 1) {
        Some(UpdateKind::Minor)
    } else {
        Some(UpdateKind::Patch)
    }
}

/// Compares the lower bound of the declared requirement with a stable `latest`.
fn pep440_is_outdated(declared: &str, latest: &str) -> bool {
    let Some(bound_text) = declared_version_for_osv(declared) else {
        return false;
    };
    let (Some(bound), Some(latest)) = (Pep440::parse(&bound_text), Pep440::parse(latest)) else {
        return false;
    };
    !latest.is_prerelease() && latest > bound
}

/// Keeps the operator run of the requirement and appends `latest`.
fn pep440_render_update(dep: &Dependency, latest: &str) -> Option<String> {
    if dep.has_additional_version_constraints
        || dep.version.is_empty()
        || dep.version.contains(char::is_whitespace)
    {
        return None;
    }
    // The operator bytes are ASCII, so the split always falls on a character boundary.
    let operator_len = dep
        .version
        .bytes()
        .take_while(|byte| OPERATOR_BYTES.contains(byte))
        .count();
    let (operator, _) = dep.version.split_at(operator_len);
    Some(format!("{operator}{latest}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers;

    /// Parses a requirements or pyproject text and returns its first dependency.
    fn first_dependency(text: &str) -> Dependency {
        parsers::python::parse(text)
            .into_iter()
            .next()
            .expect("one dependency")
    }

    #[test]
    fn pypi_is_outdated_compares_the_declared_lower_bound() {
        assert!(is_outdated(Ecosystem::PyPI, "2.28.0", "2.31.0"));
        assert!(!is_outdated(Ecosystem::PyPI, "2.31.0", "2.31.0"));
        assert!(!is_outdated(Ecosystem::PyPI, "2.31.0", "2.28.0"));
        assert!(!is_outdated(Ecosystem::PyPI, "2.0", "2.0b1"));
        assert!(!is_outdated(Ecosystem::PyPI, "2.0", "2.1rc1"));
        assert!(is_outdated(Ecosystem::PyPI, "^2.28", "2.31.0"));
        assert!(!is_outdated(Ecosystem::PyPI, "*", "2.31.0"));
        assert!(!is_outdated(Ecosystem::PyPI, "abc", "2.0"));
        assert!(!is_outdated(Ecosystem::PyPI, "2.0", "zzz"));
    }

    #[test]
    fn unimplemented_ecosystems_are_never_outdated() {
        assert!(!is_outdated(Ecosystem::Cargo, "1.0", "2.0"));
    }

    #[test]
    fn pypi_update_kind_names_the_first_changed_segment() {
        assert_eq!(
            update_kind(Ecosystem::PyPI, "2.28.0", "3.0.0"),
            Some(UpdateKind::Major)
        );
        assert_eq!(
            update_kind(Ecosystem::PyPI, "2.28.0", "2.31.0"),
            Some(UpdateKind::Minor)
        );
        assert_eq!(
            update_kind(Ecosystem::PyPI, "2.28.0", "2.28.4"),
            Some(UpdateKind::Patch)
        );
        assert_eq!(
            update_kind(Ecosystem::PyPI, "1.0", "2.0b1"),
            Some(UpdateKind::Prerelease)
        );
    }

    #[test]
    fn update_kind_is_none_without_a_newer_parsable_version() {
        assert_eq!(update_kind(Ecosystem::PyPI, "2.31.0", "2.31.0"), None);
        assert_eq!(update_kind(Ecosystem::PyPI, "3.0", "2.0"), None);
        assert_eq!(update_kind(Ecosystem::PyPI, "x", "2.0"), None);
        assert_eq!(update_kind(Ecosystem::Cargo, "1.0", "2.0"), None);
    }

    #[test]
    fn pep508_pin_is_rewritten_to_the_bare_version() {
        let dependency = first_dependency("requests==2.28.0\n");
        assert_eq!(
            render_update(Ecosystem::PyPI, &dependency, "2.31.0"),
            Some("2.31.0".to_owned())
        );
    }

    #[test]
    fn pep508_lower_bound_is_rewritten_to_the_bare_version() {
        let dependency = first_dependency("requests>=2.0\n");
        assert_eq!(
            render_update(Ecosystem::PyPI, &dependency, "2.31.0"),
            Some("2.31.0".to_owned())
        );
    }

    #[test]
    fn additional_constraints_are_not_rewritten() {
        let dependency = first_dependency("flask>=2.0,<3\n");
        assert_eq!(render_update(Ecosystem::PyPI, &dependency, "2.31.0"), None);
    }

    #[test]
    fn poetry_caret_keeps_its_operator() {
        let dependency = first_dependency("[tool.poetry.dependencies]\nrequests = \"^2.28\"\n");
        assert_eq!(
            render_update(Ecosystem::PyPI, &dependency, "2.31.0"),
            Some("^2.31.0".to_owned())
        );
    }

    #[test]
    fn unimplemented_ecosystems_render_nothing() {
        let dependency = first_dependency("requests==2.28.0\n");
        assert_eq!(render_update(Ecosystem::Cargo, &dependency, "2.31.0"), None);
    }
}
