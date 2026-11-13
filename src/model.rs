//! Shared data model for manifest parsing, registry lookups and advisories.

use crate::parsers;

/// A package registry that a manifest file belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosystem {
    /// Rust crates (`Cargo.toml`).
    Cargo,
    /// npm packages (`package.json`).
    Npm,
    /// Python packages (requirements, constraints, pyproject, hatch).
    PyPI,
    /// Go modules (`go.mod`).
    Go,
    /// PHP packages (`composer.json`).
    Packagist,
    /// Dart and Flutter packages (`pubspec.yaml`).
    Pub,
    /// .NET packages (`*.csproj`, MSBuild props).
    NuGet,
    /// Ruby gems (`Gemfile`).
    RubyGems,
    /// Java packages (`pom.xml`).
    Maven,
}

impl Ecosystem {
    /// Detects the ecosystem of a manifest from its path.
    ///
    /// Accepts `/` or `\` separators and matches on the file name only.
    pub fn detect(path: &str) -> Option<Ecosystem> {
        // `rsplit` yields the file name first, so no full split is needed.
        let file_name = path.rsplit(['/', '\\']).next()?;
        match file_name {
            "Cargo.toml" => Some(Ecosystem::Cargo),
            "package.json" => Some(Ecosystem::Npm),
            "go.mod" => Some(Ecosystem::Go),
            "pom.xml" => Some(Ecosystem::Maven),
            "pyproject.toml" | "hatch.toml" | "constraints.txt" => Some(Ecosystem::PyPI),
            "composer.json" => Some(Ecosystem::Packagist),
            "pubspec.yaml" => Some(Ecosystem::Pub),
            "Gemfile" => Some(Ecosystem::RubyGems),
            "Directory.Build.props" | "Directory.Packages.props" => Some(Ecosystem::NuGet),
            _ if file_name.ends_with(".csproj") => Some(Ecosystem::NuGet),
            _ if file_name.starts_with("requirements") && file_name.ends_with(".txt") => {
                Some(Ecosystem::PyPI)
            }
            _ => None,
        }
    }

    /// Parses the dependencies declared in a manifest of this ecosystem.
    ///
    /// Ecosystems without a parser yet return an empty vector.
    pub fn parse(self, text: &str) -> Vec<Dependency> {
        match self {
            Ecosystem::Cargo => parsers::cargo::parse(text),
            Ecosystem::Npm => Vec::new(),
            Ecosystem::PyPI => parsers::python::parse(text),
            Ecosystem::Go => Vec::new(),
            Ecosystem::Packagist => Vec::new(),
            Ecosystem::Pub => Vec::new(),
            Ecosystem::NuGet => Vec::new(),
            Ecosystem::RubyGems => Vec::new(),
            Ecosystem::Maven => Vec::new(),
        }
    }

    /// Returns the ecosystem name that the OSV.dev API expects.
    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::Cargo => "crates.io",
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Go => "Go",
            Ecosystem::Packagist => "Packagist",
            Ecosystem::Pub => "Pub",
            Ecosystem::NuGet => "NuGet",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::Maven => "Maven",
        }
    }

    /// Returns `true` when the registry can report newer versions.
    pub fn offers_updates(self) -> bool {
        matches!(
            self,
            Ecosystem::PyPI
                | Ecosystem::Packagist
                | Ecosystem::Pub
                | Ecosystem::NuGet
                | Ecosystem::RubyGems
        )
    }
}

/// A byte range inside one source line.
///
/// `line` is 0-based. `line_start` and `line_end` are byte offsets within
/// that line, and the range excludes `line_end`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    /// 0-based line index.
    pub line: u32,
    /// Byte offset of the first byte, inclusive.
    pub line_start: u32,
    /// Byte offset past the last byte, exclusive.
    pub line_end: u32,
}

/// A dependency declared in a manifest file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dependency {
    /// Package name as written in the manifest.
    pub name: String,
    /// Version requirement as written in the manifest.
    pub version: String,
    /// Location of the package name.
    pub name_span: Span,
    /// Location of the version requirement.
    pub version_span: Span,
    /// Whether the dependency is only used in development.
    pub dev: bool,
    /// Whether the dependency is optional.
    pub optional: bool,
    /// Whether the source holds version constraints beyond `version`.
    pub has_additional_version_constraints: bool,
}

/// Version data fetched from a registry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionInfo {
    /// Newest release, if the registry reports one.
    pub latest: Option<String>,
    /// All known release versions.
    pub versions: Vec<String>,
}

/// How severe a security advisory is. Variants are ordered from least to most severe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvisorySeverity {
    /// Minor impact.
    Low,
    /// Moderate impact.
    Medium,
    /// Serious impact.
    High,
    /// Most severe impact.
    Critical,
}

/// A known vulnerability that affects a package version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vulnerability {
    /// Advisory identifier, such as a CVE or GHSA id.
    pub id: String,
    /// Severity of the advisory.
    pub severity: AdvisorySeverity,
    /// One-line description of the advisory.
    pub summary: String,
    /// Link to the full advisory, if known.
    pub url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_fixed_file_names() {
        assert_eq!(Ecosystem::detect("/p/Cargo.toml"), Some(Ecosystem::Cargo));
        assert_eq!(Ecosystem::detect("/p/package.json"), Some(Ecosystem::Npm));
        assert_eq!(Ecosystem::detect("/p/go.mod"), Some(Ecosystem::Go));
        assert_eq!(Ecosystem::detect("/p/pom.xml"), Some(Ecosystem::Maven));
        assert_eq!(
            Ecosystem::detect("/p/pyproject.toml"),
            Some(Ecosystem::PyPI)
        );
        assert_eq!(Ecosystem::detect("/p/hatch.toml"), Some(Ecosystem::PyPI));
        assert_eq!(
            Ecosystem::detect("/p/constraints.txt"),
            Some(Ecosystem::PyPI)
        );
        assert_eq!(
            Ecosystem::detect("/p/composer.json"),
            Some(Ecosystem::Packagist)
        );
        assert_eq!(Ecosystem::detect("/p/pubspec.yaml"), Some(Ecosystem::Pub));
        assert_eq!(Ecosystem::detect("/p/Gemfile"), Some(Ecosystem::RubyGems));
        assert_eq!(
            Ecosystem::detect("/p/Directory.Build.props"),
            Some(Ecosystem::NuGet)
        );
        assert_eq!(
            Ecosystem::detect("/p/Directory.Packages.props"),
            Some(Ecosystem::NuGet)
        );
    }

    #[test]
    fn detects_pattern_file_names() {
        assert_eq!(
            Ecosystem::detect("/p/requirements.txt"),
            Some(Ecosystem::PyPI)
        );
        assert_eq!(
            Ecosystem::detect("/p/requirements-dev.txt"),
            Some(Ecosystem::PyPI)
        );
        assert_eq!(Ecosystem::detect("/p/Foo.csproj"), Some(Ecosystem::NuGet));
    }

    #[test]
    fn accepts_windows_separators() {
        assert_eq!(
            Ecosystem::detect(r"C:\repo\app\Cargo.toml"),
            Some(Ecosystem::Cargo)
        );
    }

    #[test]
    fn ignores_unknown_and_lock_files() {
        assert_eq!(Ecosystem::detect("/p/README.md"), None);
        assert_eq!(Ecosystem::detect("/p/package-lock.json"), None);
    }

    #[test]
    fn exposes_osv_names_and_update_support() {
        assert_eq!(Ecosystem::Cargo.osv_name(), "crates.io");
        assert_eq!(Ecosystem::PyPI.osv_name(), "PyPI");
        assert_eq!(Ecosystem::RubyGems.osv_name(), "RubyGems");
        assert!(Ecosystem::PyPI.offers_updates());
        assert!(Ecosystem::Packagist.offers_updates());
        assert!(Ecosystem::Pub.offers_updates());
        assert!(Ecosystem::NuGet.offers_updates());
        assert!(Ecosystem::RubyGems.offers_updates());
        assert!(!Ecosystem::Cargo.offers_updates());
        assert!(!Ecosystem::Npm.offers_updates());
    }

    #[test]
    fn parse_dispatches_cargo_and_returns_empty_for_unported_ecosystems() {
        let manifest = "[dependencies]\nserde = \"1.0\"\n";
        assert_eq!(Ecosystem::Cargo.parse(manifest).len(), 1);
        assert!(Ecosystem::Npm.parse(manifest).is_empty());
    }

    #[test]
    fn advisory_severity_orders_from_low_to_critical() {
        assert!(AdvisorySeverity::Low < AdvisorySeverity::Medium);
        assert!(AdvisorySeverity::High < AdvisorySeverity::Critical);
    }
}
