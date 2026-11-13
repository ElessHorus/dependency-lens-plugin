//! Shared data model for manifest parsing, registry lookups and advisories.

use crate::parsers;

/// UTF-8 byte order mark that some editors write at the start of a file.
const BYTE_ORDER_MARK: char = '\u{feff}';

/// Byte length of [`BYTE_ORDER_MARK`], which shifts the spans on line 0.
const BYTE_ORDER_MARK_BYTES: u32 = BYTE_ORDER_MARK.len_utf8() as u32;

/// Moves a span on line 0 past the byte order mark. Spans on other lines are unchanged.
fn shift_first_line(span: &mut Span) {
    if span.line == 0 {
        span.line_start = span.line_start.saturating_add(BYTE_ORDER_MARK_BYTES);
        span.line_end = span.line_end.saturating_add(BYTE_ORDER_MARK_BYTES);
    }
}

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
    /// A leading byte order mark is skipped here, once for every parser. Its bytes
    /// sit on line 0, so only the line 0 spans move past it.
    pub fn parse(self, text: &str) -> Vec<Dependency> {
        let Some(body) = text.strip_prefix(BYTE_ORDER_MARK) else {
            return self.parse_body(text);
        };
        let mut dependencies = self.parse_body(body);
        for dependency in &mut dependencies {
            shift_first_line(&mut dependency.name_span);
            shift_first_line(&mut dependency.version_span);
        }
        dependencies
    }

    /// Dispatches to the parser of this ecosystem. `text` has no byte order mark.
    ///
    /// Ecosystems without a parser yet return an empty vector.
    fn parse_body(self, text: &str) -> Vec<Dependency> {
        match self {
            Ecosystem::Cargo => parsers::cargo::parse(text),
            Ecosystem::Npm => parsers::npm::parse(text),
            Ecosystem::PyPI => parsers::python::parse(text),
            Ecosystem::Go => parsers::go::parse(text),
            Ecosystem::Packagist => parsers::php::parse(text),
            Ecosystem::Pub => Vec::new(),
            Ecosystem::NuGet => Vec::new(),
            Ecosystem::RubyGems => Vec::new(),
            Ecosystem::Maven => parsers::maven::parse(text),
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
        assert!(Ecosystem::Pub.parse(manifest).is_empty());
    }

    #[test]
    fn parse_dispatches_go_to_the_go_parser() {
        let manifest = include_str!("../tests/fixtures/go/go.mod");
        let dependencies = Ecosystem::Go.parse(manifest);
        assert_eq!(dependencies.len(), 6);
        assert_eq!(dependencies, parsers::go::parse(manifest));
    }

    #[test]
    fn parse_dispatches_npm_to_the_npm_parser() {
        let manifest = include_str!("../tests/fixtures/npm/package.json");
        let dependencies = Ecosystem::Npm.parse(manifest);
        assert_eq!(dependencies.len(), 10);
        assert_eq!(dependencies, parsers::npm::parse(manifest));
    }

    #[test]
    fn parse_dispatches_packagist_to_the_php_parser() {
        let manifest = include_str!("../tests/fixtures/php/composer.json");
        let dependencies = Ecosystem::Packagist.parse(manifest);
        assert_eq!(dependencies.len(), 7);
        assert_eq!(dependencies, parsers::php::parse(manifest));
    }

    #[test]
    fn parse_dispatches_maven_to_the_maven_parser() {
        let manifest = include_str!("../tests/fixtures/maven/pom.xml");
        let dependencies = Ecosystem::Maven.parse(manifest);
        assert_eq!(dependencies.len(), 7);
        assert_eq!(dependencies, parsers::maven::parse(manifest));
    }

    #[test]
    fn advisory_severity_orders_from_low_to_critical() {
        assert!(AdvisorySeverity::Low < AdvisorySeverity::Medium);
        assert!(AdvisorySeverity::High < AdvisorySeverity::Critical);
    }
}

#[cfg(test)]
mod byte_order_mark_tests {
    use super::*;
    use crate::text::text_of_span;

    const CARGO: &str = include_str!("../tests/fixtures/cargo/Cargo.toml");
    const NPM: &str = include_str!("../tests/fixtures/npm/package.json");
    const PYPI: &str = include_str!("../tests/fixtures/python/requirements.txt");
    const GO: &str = include_str!("../tests/fixtures/go/go.mod");
    const MAVEN: &str = include_str!("../tests/fixtures/maven/pom.xml");

    /// Returns the fields that a byte order mark must not change.
    fn summary(dependencies: &[Dependency]) -> Vec<(&str, &str, bool, bool, bool)> {
        dependencies
            .iter()
            .map(|dependency| {
                (
                    dependency.name.as_str(),
                    dependency.version.as_str(),
                    dependency.dev,
                    dependency.optional,
                    dependency.has_additional_version_constraints,
                )
            })
            .collect()
    }

    /// Returns the text under each version span, read back from `text`.
    fn version_texts(text: &str, dependencies: &[Dependency]) -> Vec<Option<String>> {
        dependencies
            .iter()
            .map(|dependency| text_of_span(text, dependency.version_span))
            .collect()
    }

    fn assert_byte_order_mark_is_transparent(ecosystem: Ecosystem, plain: &str) {
        let bom_text = format!("\u{feff}{plain}");
        let plain_dependencies = ecosystem.parse(plain);
        let bom_dependencies = ecosystem.parse(&bom_text);
        assert!(
            !plain_dependencies.is_empty(),
            "{ecosystem:?} fixture is empty"
        );
        assert_eq!(summary(&bom_dependencies), summary(&plain_dependencies));
        let plain_versions = version_texts(plain, &plain_dependencies);
        assert_eq!(version_texts(&bom_text, &bom_dependencies), plain_versions);
        assert!(plain_versions.iter().all(Option::is_some));
    }

    #[test]
    fn every_ecosystem_ignores_a_leading_byte_order_mark() {
        assert_byte_order_mark_is_transparent(Ecosystem::Cargo, CARGO);
        assert_byte_order_mark_is_transparent(Ecosystem::Npm, NPM);
        assert_byte_order_mark_is_transparent(Ecosystem::PyPI, PYPI);
        assert_byte_order_mark_is_transparent(Ecosystem::Go, GO);
        assert_byte_order_mark_is_transparent(Ecosystem::Maven, MAVEN);
    }

    #[test]
    fn maven_spans_are_identical_with_a_byte_order_mark() {
        let bom_text = format!("\u{feff}{MAVEN}");
        assert_eq!(
            Ecosystem::Maven.parse(&bom_text),
            Ecosystem::Maven.parse(MAVEN)
        );
    }

    #[test]
    fn byte_order_mark_shifts_spans_on_line_zero_by_three_bytes() {
        let plain = r#"{"dependencies":{"a":"1.0.0"}}"#;
        let bom_text = format!("\u{feff}{plain}");
        let plain_dependencies = Ecosystem::Npm.parse(plain);
        let bom_dependencies = Ecosystem::Npm.parse(&bom_text);
        assert_eq!(plain_dependencies.len(), 1);
        assert_eq!(bom_dependencies.len(), 1);
        assert_eq!(
            bom_dependencies[0].version_span.line_start,
            plain_dependencies[0].version_span.line_start + 3
        );
        assert_eq!(
            text_of_span(&bom_text, bom_dependencies[0].version_span).as_deref(),
            Some("1.0.0")
        );
    }
}
