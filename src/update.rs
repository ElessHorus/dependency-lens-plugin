//! Update rules: how far a registry release is ahead of a declared version, and how to rewrite a requirement to a newer version.

use crate::model::{Dependency, Ecosystem};
use crate::osv::declared_version_for_osv;
use crate::registries::dotted::{DottedVersion, PubVersion, is_dev_branch, segment};
use crate::registries::gem_version::GemVersion;
use crate::registries::maven_version::MavenVersion;
use crate::registries::pep440::Pep440;
use std::borrow::Cow;

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

/// The two operators whose bound is exclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExclusiveBound {
    /// `>V`: the versions above `V`.
    GreaterThan,
    /// `<V`: the versions below `V`.
    LessThan,
}

/// Version operations that the update rules need. PEP 440 and dotted versions implement it,
/// so each ecosystem adds one match arm and no new rule code.
pub(crate) trait UpdateVersion: Ord + Sized {
    /// Parses version text, or returns `None` when the text is not a version of this ecosystem.
    fn parse_version(text: &str) -> Option<Self>;
    /// Returns `true` for a prerelease version.
    fn is_prerelease_version(&self) -> bool;
    /// Returns the release segments, such as `[2, 31, 0]`. Borrowed when the version stores them.
    fn release_segments(&self) -> Cow<'_, [u64]>;
    /// Whether an exclusive bound (`>` or `<`) keeps `self` out although the order allows it.
    ///
    /// Only PEP 440 has such a rule, so the default is `false`.
    fn is_excluded_by_bound(&self, _kind: ExclusiveBound, _bound: &Self) -> bool {
        false
    }
}

impl UpdateVersion for Pep440 {
    fn parse_version(text: &str) -> Option<Self> {
        Pep440::parse(text)
    }

    fn is_prerelease_version(&self) -> bool {
        self.is_prerelease()
    }

    fn release_segments(&self) -> Cow<'_, [u64]> {
        Cow::Borrowed(self.release())
    }

    /// PEP 440: `>V` does not allow a post-release of `V` unless `V` is one, and `<V` does not
    /// allow a pre-release of `V` unless `V` is one.
    fn is_excluded_by_bound(&self, kind: ExclusiveBound, bound: &Self) -> bool {
        match kind {
            ExclusiveBound::GreaterThan => self.is_post_release_of(bound),
            ExclusiveBound::LessThan => !bound.is_prerelease() && self.is_pre_release_of(bound),
        }
    }
}

impl UpdateVersion for DottedVersion {
    fn parse_version(text: &str) -> Option<Self> {
        DottedVersion::parse(text)
    }

    fn is_prerelease_version(&self) -> bool {
        self.is_prerelease()
    }

    fn release_segments(&self) -> Cow<'_, [u64]> {
        Cow::Borrowed(self.release())
    }
}

impl UpdateVersion for PubVersion {
    fn parse_version(text: &str) -> Option<Self> {
        PubVersion::parse(text)
    }

    fn is_prerelease_version(&self) -> bool {
        self.is_prerelease()
    }

    fn release_segments(&self) -> Cow<'_, [u64]> {
        Cow::Borrowed(self.release())
    }
}

impl UpdateVersion for GemVersion {
    fn parse_version(text: &str) -> Option<Self> {
        GemVersion::parse(text)
    }

    fn is_prerelease_version(&self) -> bool {
        self.is_prerelease()
    }

    fn release_segments(&self) -> Cow<'_, [u64]> {
        Cow::Owned(self.release())
    }
}

impl UpdateVersion for MavenVersion {
    fn parse_version(text: &str) -> Option<Self> {
        MavenVersion::parse(text)
    }

    fn is_prerelease_version(&self) -> bool {
        self.is_prerelease()
    }

    fn release_segments(&self) -> Cow<'_, [u64]> {
        Cow::Owned(self.release())
    }
}

/// `None` when either version cannot be parsed for this ecosystem or `latest` is not newer than `current`.
pub fn update_kind(eco: Ecosystem, current: &str, latest: &str) -> Option<UpdateKind> {
    match eco {
        Ecosystem::PyPI => update_kind_of::<Pep440>(current, latest),
        Ecosystem::Packagist | Ecosystem::NuGet => update_kind_of::<DottedVersion>(current, latest),
        Ecosystem::Pub => update_kind_of::<PubVersion>(current, latest),
        Ecosystem::RubyGems => update_kind_of::<GemVersion>(current, latest),
        _ => None,
    }
}

/// True when `latest` is a stable version newer than the lower bound of `declared`.
pub fn is_outdated(eco: Ecosystem, declared: &str, latest: &str) -> bool {
    match eco {
        Ecosystem::PyPI => is_outdated_of::<Pep440>(declared, latest),
        Ecosystem::Packagist | Ecosystem::NuGet => {
            is_outdated_of::<DottedVersion>(declared, latest)
        }
        Ecosystem::Pub => is_outdated_of::<PubVersion>(declared, latest),
        Ecosystem::RubyGems => is_outdated_of::<GemVersion>(declared, latest),
        _ => false,
    }
}

/// The replacement text for `dep.version_span`, or None when the requirement cannot be rewritten safely.
pub fn render_update(eco: Ecosystem, dep: &Dependency, latest: &str) -> Option<String> {
    match eco {
        Ecosystem::PyPI => pep440_render_update(dep, latest),
        Ecosystem::Packagist => dotted_render_update(dep, latest, false),
        Ecosystem::Pub => dotted_render_update(dep, latest, true),
        Ecosystem::NuGet => full_latest_render_update::<DottedVersion>(dep, latest),
        // A second constraint stays in the line after the rewrite, so such a gem is left alone.
        Ecosystem::RubyGems if dep.has_additional_version_constraints => None,
        Ecosystem::RubyGems => full_latest_render_update::<GemVersion>(dep, latest),
        _ => None,
    }
}

/// Classifies the step from `current` to `latest` by the first release segment that differs.
fn update_kind_of<V: UpdateVersion>(current: &str, latest: &str) -> Option<UpdateKind> {
    let current = V::parse_version(current)?;
    let latest = V::parse_version(latest)?;
    if latest <= current {
        return None;
    }
    if latest.is_prerelease_version() {
        return Some(UpdateKind::Prerelease);
    }
    // A missing segment reads as 0, so `2` and `2.0` compare equal.
    let (current_release, latest_release) = (current.release_segments(), latest.release_segments());
    if segment(&current_release, 0) != segment(&latest_release, 0) {
        Some(UpdateKind::Major)
    } else if segment(&current_release, 1) != segment(&latest_release, 1) {
        Some(UpdateKind::Minor)
    } else {
        Some(UpdateKind::Patch)
    }
}

/// Compares the lower bound of the declared requirement with a stable `latest`.
fn is_outdated_of<V: UpdateVersion>(declared: &str, latest: &str) -> bool {
    let Some(bound_text) = declared_version_for_osv(declared) else {
        return false;
    };
    let (Some(bound), Some(latest)) = (V::parse_version(&bound_text), V::parse_version(latest))
    else {
        return false;
    };
    !latest.is_prerelease_version() && latest > bound
}

/// One registry release that orders after a base version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Release<'a> {
    /// The version text, as the registry writes it.
    pub text: &'a str,
    /// Whether the version is a pre-release.
    pub is_prerelease: bool,
}

/// The entries of `versions` that order after `base`, in the order of `versions`.
///
/// A text that is not a version of the ecosystem is skipped. A `base` that is not a version gives
/// no release. The list is not sorted again: the registry clients already rank it.
pub fn newer_releases<'a>(eco: Ecosystem, base: &str, versions: &'a [String]) -> Vec<Release<'a>> {
    match eco {
        Ecosystem::PyPI => newer_releases_of::<Pep440>(base, versions),
        Ecosystem::RubyGems => newer_releases_of::<GemVersion>(base, versions),
        Ecosystem::Pub => newer_releases_of::<PubVersion>(base, versions),
        Ecosystem::Maven => newer_releases_of::<MavenVersion>(base, versions),
        _ => newer_releases_of::<DottedVersion>(base, versions),
    }
}

/// One pass: `base` is parsed once and each listed text once.
fn newer_releases_of<'a, V: UpdateVersion>(base: &str, versions: &'a [String]) -> Vec<Release<'a>> {
    let Some(base) = V::parse_version(base) else {
        return Vec::new();
    };
    versions
        .iter()
        .filter_map(|text| {
            let version = V::parse_version(text)?;
            (version > base).then(|| Release {
                text,
                is_prerelease: version.is_prerelease_version(),
            })
        })
        .collect()
}

/// Splits a requirement into its leading operator run and the version text after it.
pub(crate) fn split_operator(requirement: &str) -> (&str, &str) {
    // The operator bytes are ASCII, so the split always falls on a character boundary.
    let operator_len = requirement
        .bytes()
        .take_while(|byte| OPERATOR_BYTES.contains(byte))
        .count();
    requirement.split_at(operator_len)
}

/// Keeps the operator run of the requirement and appends `latest`.
fn pep440_render_update(dep: &Dependency, latest: &str) -> Option<String> {
    if dep.has_additional_version_constraints
        || dep.version.is_empty()
        || dep.version.contains(char::is_whitespace)
        // Poetry writes `>=2.0,<3.0` and `^1.0|^2.0` without spaces; rewriting would drop a bound.
        || dep.version.contains([',', '|'])
    {
        return None;
    }
    let (operator, _) = split_operator(&dep.version);
    Some(format!("{operator}{latest}"))
}

/// Replaces a version with the full `latest`, for ecosystems whose pins are exact. The
/// declared precision and operators do not apply. Floating, range and property
/// versions name no single version to replace, so they are left alone.
fn full_latest_render_update<V: UpdateVersion>(dep: &Dependency, latest: &str) -> Option<String> {
    if dep.version.contains(char::is_whitespace)
        || dep.version.contains(['*', '$', '(', '[', ',', '|'])
        || latest.contains(char::is_whitespace)
    {
        return None;
    }
    let declared = V::parse_version(&dep.version)?;
    let latest_version = V::parse_version(latest)?;
    if latest_version.is_prerelease_version() || latest_version == declared {
        return None;
    }
    Some(latest.to_owned())
}

/// Rewrites a Composer or pub.dev requirement to `latest`. It keeps the operator and
/// writes as many release segments as the declared text has, so `^8.1` takes `8.2`
/// from `8.2.3`. With `keeps_build`, a build number of `latest` follows the release, as in pub.dev's `0.4.0+9`.
fn dotted_render_update(dep: &Dependency, latest: &str, keeps_build: bool) -> Option<String> {
    if dep.version.is_empty()
        || dep.version.contains(char::is_whitespace)
        || dep.version.contains(['*', '@', '|'])
        || is_dev_branch(&dep.version)
    {
        return None;
    }
    let (operator, declared_text) = split_operator(&dep.version);
    let declared = DottedVersion::parse(declared_text)?;
    let latest_version = DottedVersion::parse(latest)?;
    if latest_version.is_prerelease() {
        return None;
    }
    // A latest version with fewer segments than declared is written in full. A build number only
    // follows a full release, so `^0.4` and `0.4.1+2` give `^0.4.1+2`, never `^0.4+2`.
    let has_build = keeps_build && latest.contains('+');
    let precision = if has_build {
        declared.release().len().max(latest_version.release().len())
    } else {
        declared.release().len()
    };
    let rendered_release = latest_version
        .release()
        .iter()
        .take(precision)
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".");
    let build = latest
        .split_once('+')
        .filter(|_| has_build)
        .map_or(String::new(), |(_, build_text)| format!("+{build_text}"));
    let rendered = format!("{operator}{rendered_release}{build}");
    (rendered != dep.version).then_some(rendered)
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
    fn poetry_range_with_an_upper_bound_is_not_rewritten() {
        let dependency =
            first_dependency("[tool.poetry.dependencies]\nrequests = \">=2.0,<3.0\"\n");
        assert_eq!(render_update(Ecosystem::PyPI, &dependency, "2.31.0"), None);
    }

    /// Parses a `composer.json` with one `require` entry and returns that dependency.
    fn composer_dependency(requirement: &str) -> Dependency {
        let text = format!(r#"{{"require":{{"acme/lib":"{requirement}"}}}}"#);
        parsers::php::parse(&text)
            .into_iter()
            .next()
            .expect("one dependency")
    }

    #[test]
    fn packagist_is_outdated_compares_the_declared_lower_bound() {
        assert!(is_outdated(Ecosystem::Packagist, "^3.0", "3.12.1"));
        assert!(is_outdated(Ecosystem::Packagist, "^3.12", "3.12.1"));
        assert!(!is_outdated(Ecosystem::Packagist, "3.12.1", "3.12.1"));
        assert!(!is_outdated(Ecosystem::Packagist, "^3.0", "4.0.0-RC1"));
        assert!(!is_outdated(Ecosystem::Packagist, "dev-main", "3.0"));
        assert!(!is_outdated(Ecosystem::Packagist, "1.2.*", "3.0"));
        assert!(is_outdated(Ecosystem::Packagist, "^1.0@dev", "2.0.0"));
    }

    #[test]
    fn packagist_update_kind_names_the_first_changed_segment() {
        assert_eq!(
            update_kind(Ecosystem::Packagist, "1.0", "2.0"),
            Some(UpdateKind::Major)
        );
        assert_eq!(
            update_kind(Ecosystem::Packagist, "3.0", "3.12.1"),
            Some(UpdateKind::Minor)
        );
        assert_eq!(
            update_kind(Ecosystem::Packagist, "3.12.0", "3.12.1"),
            Some(UpdateKind::Patch)
        );
        assert_eq!(
            update_kind(Ecosystem::Packagist, "1.0", "2.0.0-RC1"),
            Some(UpdateKind::Prerelease)
        );
        assert_eq!(update_kind(Ecosystem::Packagist, "3.12.1", "3.12.1"), None);
    }

    #[test]
    fn packagist_render_keeps_the_operator_and_the_declared_precision() {
        let render = |requirement: &str, latest: &str| {
            render_update(
                Ecosystem::Packagist,
                &composer_dependency(requirement),
                latest,
            )
        };
        assert_eq!(render("^8.1", "8.2.3").as_deref(), Some("^8.2"));
        assert_eq!(render("~6.2.1", "6.4.1").as_deref(), Some("~6.4.1"));
        assert_eq!(render("1.0", "2.5.7").as_deref(), Some("2.5"));
        assert_eq!(render("^3.12", "3.12.1"), None);
        assert_eq!(render("1.2.*", "3.0.0"), None);
        assert_eq!(render("dev-main", "3.0.0"), None);
        assert_eq!(render("^1.0@dev", "2.0.0"), None);
        assert_eq!(render(">=1.2 <2.0", "3.0.0"), None);
        assert_eq!(render("", "3.0.0"), None);
        assert_eq!(render("^3.0", "4.0.0-RC1"), None);
    }

    /// Parses a `pubspec.yaml` with one `http` entry and returns that dependency.
    fn pubspec_dependency(requirement: &str) -> Dependency {
        let text = format!("dependencies:\n  http: {requirement}\n");
        parsers::dart::parse(&text)
            .into_iter()
            .next()
            .expect("one dependency")
    }

    #[test]
    fn pub_is_outdated_compares_the_declared_lower_bound() {
        assert!(is_outdated(Ecosystem::Pub, "^1.0.0", "1.2.0"));
        assert!(!is_outdated(Ecosystem::Pub, "^1.2.0", "1.2.0"));
        assert!(!is_outdated(Ecosystem::Pub, "any", "2.0.0"));
        // The first lower bound decides; range-awareness is deferred.
        assert!(is_outdated(Ecosystem::Pub, ">=1.0.0 <2.0.0", "3.0.0"));
        assert!(!is_outdated(Ecosystem::Pub, "^1.0.0", "2.0.0-dev.1"));
    }

    #[test]
    fn pub_update_kind_names_the_first_changed_segment() {
        assert_eq!(
            update_kind(Ecosystem::Pub, "1.0.0", "2.0.0"),
            Some(UpdateKind::Major)
        );
        assert_eq!(
            update_kind(Ecosystem::Pub, "1.0.0", "1.2.0"),
            Some(UpdateKind::Minor)
        );
        assert_eq!(
            update_kind(Ecosystem::Pub, "1.2.0", "1.2.3"),
            Some(UpdateKind::Patch)
        );
    }

    #[test]
    fn pub_render_keeps_the_operator_and_the_declared_precision() {
        let render = |requirement: &str, latest: &str| {
            render_update(Ecosystem::Pub, &pubspec_dependency(requirement), latest)
        };
        assert_eq!(render("^1.0.0", "1.2.0").as_deref(), Some("^1.2.0"));
        assert_eq!(render("^1.0", "1.2.3").as_deref(), Some("^1.2"));
        assert_eq!(render("^1.2.0", "1.2.0"), None);
        assert_eq!(render("any", "1.2.0"), None);
        assert_eq!(render(">=1.0.0 <2.0.0", "3.0.0"), None);
        assert_eq!(render("^1.0.0", "2.0.0-dev.1"), None);
    }

    /// Parses a `.csproj` with one `Newtonsoft.Json` reference and returns that dependency.
    fn nuget_dependency(requirement: &str) -> Dependency {
        let text = format!(
            r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="{requirement}" /></ItemGroup></Project>"#
        );
        parsers::csharp::parse(&text)
            .into_iter()
            .next()
            .expect("one dependency")
    }

    #[test]
    fn nuget_is_outdated_compares_the_declared_lower_bound() {
        assert!(is_outdated(Ecosystem::NuGet, "13.0.3", "13.0.4"));
        assert!(!is_outdated(Ecosystem::NuGet, "13.0.3", "13.0.3"));
        assert!(!is_outdated(Ecosystem::NuGet, "13.0.3", "14.0.0-beta1"));
        // The lower bound of a range decides, as for the other dotted ecosystems.
        assert!(is_outdated(Ecosystem::NuGet, "[1.0,2.0)", "3.0.0"));
        assert!(!is_outdated(Ecosystem::NuGet, "1.*", "3.0.0"));
        assert!(!is_outdated(Ecosystem::NuGet, "$(Missing)", "3.0.0"));
    }

    #[test]
    fn nuget_update_kind_names_the_first_changed_segment() {
        assert_eq!(
            update_kind(Ecosystem::NuGet, "13.0.3", "14.0.0"),
            Some(UpdateKind::Major)
        );
        assert_eq!(
            update_kind(Ecosystem::NuGet, "13.0.3", "13.1.0"),
            Some(UpdateKind::Minor)
        );
        assert_eq!(
            update_kind(Ecosystem::NuGet, "13.0.3", "13.0.4"),
            Some(UpdateKind::Patch)
        );
        assert_eq!(
            update_kind(Ecosystem::NuGet, "13.0.3", "14.0.0-beta1"),
            Some(UpdateKind::Prerelease)
        );
        assert_eq!(update_kind(Ecosystem::NuGet, "13.0.3", "13.0.3"), None);
    }

    #[test]
    fn nuget_render_writes_the_full_latest_version() {
        let render = |requirement: &str, latest: &str| {
            render_update(Ecosystem::NuGet, &nuget_dependency(requirement), latest)
        };
        assert_eq!(render("13.0.3", "13.0.4").as_deref(), Some("13.0.4"));
        assert_eq!(render("4.2.2", "4.2.2.1").as_deref(), Some("4.2.2.1"));
        assert_eq!(render("13.0.3", "13.0.3"), None);
        assert_eq!(render("1.*", "3.0.0"), None);
        assert_eq!(render("[1.0,2.0)", "3.0.0"), None);
        assert_eq!(render("$(SerilogVersion)", "3.1.2"), None);
        assert_eq!(render("13.0.3", "14.0.0-beta1"), None);
    }

    /// Parses a `Gemfile` line and returns its first gem.
    fn gem_dependency(line: &str) -> Dependency {
        parsers::ruby::parse(line)
            .into_iter()
            .next()
            .expect("one gem")
    }

    #[test]
    fn rubygems_is_outdated_compares_the_declared_lower_bound() {
        assert!(is_outdated(Ecosystem::RubyGems, "7.0.4", "8.1.4.1"));
        assert!(!is_outdated(Ecosystem::RubyGems, "8.1.4.1", "8.1.4.1"));
        assert!(!is_outdated(Ecosystem::RubyGems, "7.0.4", "8.0.0.rc1"));
        assert!(!is_outdated(Ecosystem::RubyGems, "abc", "8.0"));
    }

    #[test]
    fn rubygems_update_kind_names_the_first_changed_segment() {
        assert_eq!(
            update_kind(Ecosystem::RubyGems, "7.0.4", "8.1.4.1"),
            Some(UpdateKind::Major)
        );
        assert_eq!(
            update_kind(Ecosystem::RubyGems, "7.0.4", "7.1.2"),
            Some(UpdateKind::Minor)
        );
        assert_eq!(
            update_kind(Ecosystem::RubyGems, "7.0.4", "7.0.8"),
            Some(UpdateKind::Patch)
        );
        assert_eq!(
            update_kind(Ecosystem::RubyGems, "7.0.4", "8.0.0.rc1"),
            Some(UpdateKind::Prerelease)
        );
        assert_eq!(update_kind(Ecosystem::RubyGems, "7.0.4", "7.0.4"), None);
    }

    #[test]
    fn rubygems_render_writes_the_full_latest_version() {
        let render = |line: &str, latest: &str| {
            render_update(Ecosystem::RubyGems, &gem_dependency(line), latest)
        };
        assert_eq!(
            render("gem 'rails', '~> 7.0.4'", "8.1.4.1").as_deref(),
            Some("8.1.4.1")
        );
        assert_eq!(
            render("gem 'rack','2.2.4'", "2.2.5").as_deref(),
            Some("2.2.5")
        );
        assert_eq!(render("gem \"pg\", \">= 0.18\", \"< 2.0\"", "2.1.0"), None);
        assert_eq!(render("gem 'rails', '~> 7.0.4'", "7.0.4"), None);
        assert_eq!(render("gem 'rails', '~> 7.0.4'", "8.0.0.rc1"), None);
    }

    #[test]
    fn unimplemented_ecosystems_render_nothing() {
        let dependency = first_dependency("requests==2.28.0\n");
        assert_eq!(render_update(Ecosystem::Cargo, &dependency, "2.31.0"), None);
    }

    #[test]
    fn pub_build_numbers_count_but_other_ecosystems_ignore_them() {
        assert!(is_outdated(Ecosystem::Pub, "0.4.0+1", "0.4.0+9"));
        assert!(is_outdated(Ecosystem::Pub, "0.4.0", "0.4.0+1"));
        assert!(!is_outdated(Ecosystem::Pub, "0.4.0+9", "0.4.0+9"));
        assert!(!is_outdated(Ecosystem::Pub, "0.4.0+9", "0.4.0"));
        // Semver says build metadata never changes precedence, and NuGet and Composer follow it.
        assert!(!is_outdated(Ecosystem::NuGet, "1.0.0+1", "1.0.0+9"));
        assert!(!is_outdated(Ecosystem::Packagist, "1.0.0+1", "1.0.0+9"));
    }

    #[test]
    fn pub_update_keeps_the_build_number_of_the_latest_version() {
        let dependency = Dependency {
            name: "demo".to_owned(),
            version: "^0.4.0+1".to_owned(),
            name_span: crate::model::Span {
                line: 0,
                line_start: 0,
                line_end: 4,
            },
            version_span: crate::model::Span {
                line: 0,
                line_start: 6,
                line_end: 14,
            },
            dev: false,
            optional: false,
            has_additional_version_constraints: false,
            requirement: None,
        };
        assert_eq!(
            render_update(Ecosystem::Pub, &dependency, "0.4.0+9").as_deref(),
            Some("^0.4.0+9")
        );
    }

    #[test]
    fn pub_update_with_a_build_number_writes_the_full_release() {
        for (declared, latest, expected) in [
            ("^0.4", "0.4.1+2", "^0.4.1+2"),
            ("^1", "2.0.0+3", "^2.0.0+3"),
            ("^0.4.0+1", "0.4.0+9", "^0.4.0+9"),
        ] {
            let dependency = Dependency {
                name: "demo".to_owned(),
                version: declared.to_owned(),
                name_span: crate::model::Span {
                    line: 0,
                    line_start: 0,
                    line_end: 4,
                },
                version_span: crate::model::Span {
                    line: 0,
                    line_start: 6,
                    line_end: 14,
                },
                dev: false,
                optional: false,
                has_additional_version_constraints: false,
                requirement: None,
            };
            assert_eq!(
                render_update(Ecosystem::Pub, &dependency, latest).as_deref(),
                Some(expected),
                "{declared} -> {latest}"
            );
        }
    }
    #[test]
    fn newer_releases_keeps_registry_order_and_skips_junk() {
        let owned =
            |texts: &[&str]| -> Vec<String> { texts.iter().map(|t| (*t).to_owned()).collect() };
        // (ecosystem, base, registry list, expected (text, is_prerelease))
        let cases = [
            (
                Ecosystem::PyPI,
                "2.0.0",
                owned(&[
                    "3.0.0", "2.34.2", "2.9.2rc1", "2.9.2", "2.0.0", "1.9.0", "junk",
                ]),
                vec![
                    ("3.0.0", false),
                    ("2.34.2", false),
                    ("2.9.2rc1", true),
                    ("2.9.2", false),
                ],
            ),
            (
                Ecosystem::RubyGems,
                "1.0.0",
                owned(&["2.0.0.beta1", "1.0.1", "1.0.0"]),
                vec![("2.0.0.beta1", true), ("1.0.1", false)],
            ),
            (
                Ecosystem::NuGet,
                "1.0.0",
                owned(&["1.1.0-preview1", "1.0.0"]),
                vec![("1.1.0-preview1", true)],
            ),
            (Ecosystem::PyPI, "not-a-version", owned(&["1.0.0"]), vec![]),
        ];
        for (eco, base, versions, expected) in cases {
            let found: Vec<(&str, bool)> = newer_releases(eco, base, &versions)
                .into_iter()
                .map(|release| (release.text, release.is_prerelease))
                .collect();
            assert_eq!(found, expected, "{eco:?} after {base}");
        }
    }
}
