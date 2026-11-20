//! The IDE hover that links the package page of the dependency under the cursor.

use crate::model::{Dependency, Ecosystem};
use crate::settings::Settings;
use crate::text::to_range_in_line;
use openidea_plugin::hover::Hover;
use openidea_plugin::{Position, Range};

/// The hover that links the package page of the dependency under the cursor.
///
/// The cursor must lie on the name or on the version of a dependency. The answer reads no cache
/// and makes no request. It follows the path of the quick fixes: a file that is not a manifest, a
/// disabled ecosystem and an ignored package give `None`. A private or local package is not in
/// `Ecosystem::parse`, so it gets no link. The one exception is npm, whose local and URL specs
/// the parser keeps: `names_a_registry_package` refuses them. A name that is unsafe for a URL gives `None` too.
pub fn package_link_hover(
    settings: &Settings,
    doc_path: &str,
    project_root: Option<&str>,
    doc_text: &str,
    at: Position,
) -> Option<Hover> {
    if !crate::is_manifest_in(doc_path, project_root) {
        return None;
    }
    let eco = Ecosystem::detect(doc_path)?;
    if !settings.is_enabled(eco) {
        return None;
    }
    // The cursor line is read once, so no span walks the text from its start again.
    let cursor_line = doc_text.lines().nth(at.line as usize)?;
    let dependencies = eco.parse(doc_text);
    // The hover names the span under the cursor: the editor anchors the tooltip on that range.
    let (dependency, hovered_range) = dependencies.iter().find_map(|dependency| {
        range_under_cursor(cursor_line, dependency, at).map(|range| (dependency, range))
    })?;
    if !names_a_registry_package(eco, dependency) {
        return None;
    }
    // The ignore set is built only for a match, so a hover over plain text allocates nothing.
    if settings
        .ignored_packages(eco)
        .contains(&eco.normalize_package(&dependency.name))
    {
        return None;
    }
    let url = eco.package_page_url(&dependency.name)?;
    // The link text names the package as the manifest writes it. `package_page_url` already
    // checked the name against an allow-list, so the name cannot break the Markdown link.
    let text = format!(
        "[Open {} on {}]({url})",
        dependency.name,
        eco.registry_label()
    );
    Some(Hover::new(text).range(hovered_range))
}

/// Whether `dependency` is a package of the public registry of `eco`.
///
/// The npm parser keeps `file:`, `link:`, `workspace:`, git, URL and `user/repo` specs, because
/// `declared_version_for_osv` filters them later. A registry range never holds `:` or `/`, so
/// either character marks a local or URL source, which gets no link (privacy invariant).
/// The parsers of the other ecosystems already drop such sources.
fn names_a_registry_package(eco: Ecosystem, dependency: &Dependency) -> bool {
    eco != Ecosystem::Npm || !dependency.version.contains([':', '/'])
}

/// The range of the name or of the version of `dependency` that holds `at`, if any.
///
/// `cursor_line` is the text of line `at.line`. The end of a span is exclusive.
fn range_under_cursor(cursor_line: &str, dependency: &Dependency, at: Position) -> Option<Range> {
    [dependency.name_span, dependency.version_span]
        .into_iter()
        .filter(|span| span.line == at.line)
        .filter_map(|span| to_range_in_line(cursor_line, span))
        .find(|range| range.start.character <= at.character && at.character < range.end.character)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARGO: &str =
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.0\"\n";
    const CARGO_LOCAL: &str = "[dependencies]\nserde = { path = \"../serde\" }\n";
    const PIP: &str = "requests==2.0.0\n";
    const PIP_PRIVATE: &str = "--index-url https://pypi.example.com/simple\nrequests==2.0.0\n";
    const POM: &str = "<project>\n  <dependencies>\n    <dependency>\n      <groupId>org.apache.logging.log4j</groupId>\n      <artifactId>log4j-core</artifactId>\n      <version>2.14.1</version>\n    </dependency>\n  </dependencies>\n</project>\n";

    const SERDE_LINK: &str = "[Open serde on crates.io](https://crates.io/crates/serde)";
    const REQUESTS_LINK: &str = "[Open requests on PyPI](https://pypi.org/project/requests)";

    /// The markdown of the hover at `line`, `character`, with default settings.
    fn hover_at(path: &str, text: &str, line: u32, character: u32) -> Option<String> {
        hover_with(&Settings::default(), path, text, line, character)
    }

    fn hover_with(
        settings: &Settings,
        path: &str,
        text: &str,
        line: u32,
        character: u32,
    ) -> Option<String> {
        package_link_hover(settings, path, None, text, Position::new(line, character))
            .map(|hover| hover.markdown)
    }

    #[test]
    fn the_name_and_the_version_of_a_dependency_give_its_link() {
        // (path, text, line, character, expected link)
        let cases = [
            ("/p/Cargo.toml", CARGO, 5, 0, SERDE_LINK),
            ("/p/Cargo.toml", CARGO, 5, 2, SERDE_LINK),
            ("/p/Cargo.toml", CARGO, 5, 4, SERDE_LINK),
            ("/p/Cargo.toml", CARGO, 5, 9, SERDE_LINK),
            ("/p/Cargo.toml", CARGO, 5, 10, SERDE_LINK),
            ("/p/Cargo.toml", CARGO, 5, 13, SERDE_LINK),
            ("/p/requirements.txt", PIP, 0, 3, REQUESTS_LINK),
        ];
        for (path, text, line, character, expected) in cases {
            assert_eq!(
                hover_at(path, text, line, character).as_deref(),
                Some(expected),
                "{path} {line}:{character}"
            );
        }
    }

    #[test]
    fn the_hover_names_the_span_under_the_cursor() {
        // The editor anchors the tooltip on this range. A range away from the cursor would close
        // the tooltip on the next mouse move, so the link could not be clicked.
        let name = Range::new(Position::new(5, 0), Position::new(5, 5));
        let version = Range::new(Position::new(5, 9), Position::new(5, 14));
        for (character, expected) in [(0, name), (4, name), (9, version), (13, version)] {
            let hover = package_link_hover(
                &Settings::default(),
                "/p/Cargo.toml",
                None,
                CARGO,
                Position::new(5, character),
            )
            .expect("a hover");
            assert_eq!(hover.range, Some(expected), "column {character}");
        }
    }

    #[test]
    fn a_cursor_outside_every_span_gives_nothing() {
        // The end of a span is exclusive. Columns 5 to 8 lie between the name and the version.
        let cases = [
            (CARGO, 5, 5),
            (CARGO, 5, 8),
            (CARGO, 5, 14),
            (CARGO, 5, 40),
            (CARGO, 4, 3),
            (CARGO, 99, 0),
            (CARGO, 1, 2),
        ];
        for (text, line, character) in cases {
            assert_eq!(
                hover_at("/p/Cargo.toml", text, line, character),
                None,
                "{line}:{character}"
            );
        }
        assert_eq!(hover_at("/p/Cargo.toml", "", 0, 0), None);
    }

    #[test]
    fn a_private_or_local_package_has_no_link() {
        assert_eq!(hover_at("/p/Cargo.toml", CARGO_LOCAL, 1, 2), None);
        assert_eq!(hover_at("/p/requirements.txt", PIP_PRIVATE, 1, 3), None);
    }

    #[test]
    fn an_ignored_package_has_no_link() {
        let settings = Settings {
            ignore: vec!["serde".to_owned()],
            ..Settings::default()
        };
        assert_eq!(hover_with(&settings, "/p/Cargo.toml", CARGO, 5, 2), None);
    }

    #[test]
    fn a_disabled_ecosystem_has_no_link() {
        let mut settings = Settings::default();
        settings.enabled.remove(&Ecosystem::Cargo);
        assert_eq!(hover_with(&settings, "/p/Cargo.toml", CARGO, 5, 2), None);
    }

    #[test]
    fn a_file_that_is_not_a_manifest_has_no_link() {
        assert_eq!(hover_at("/p/notes.txt", CARGO, 5, 2), None);
    }

    #[test]
    fn an_npm_dependency_that_is_not_from_the_registry_has_no_link() {
        // `Ecosystem::Npm.parse` keeps these specs, so the hover itself must refuse them.
        // Line 2 holds the registry package. Each other line holds one local or URL source.
        let package_json = "{\n  \"dependencies\": {\n    \"left-pad\": \"^1.3.0\",\n    \"local\": \"file:../local\",\n    \"mono\": \"workspace:*\",\n    \"lnk\": \"link:../x\",\n    \"gh\": \"user/repo\",\n    \"git\": \"git+https://github.com/x/y.git\",\n    \"tar\": \"https://example.com/a.tgz\",\n    \"hub\": \"github:user/repo\"\n  }\n}\n";
        let path = "/p/package.json";
        assert_eq!(
            hover_at(path, package_json, 2, 6).as_deref(),
            Some("[Open left-pad on npm](https://www.npmjs.com/package/left-pad)")
        );
        for line in 3..=9 {
            // Column 6 lies inside the name, and column 20 inside the version, of every line.
            assert_eq!(
                hover_at(path, package_json, line, 6),
                None,
                "name, line {line}"
            );
            assert_eq!(
                hover_at(path, package_json, line, 20),
                None,
                "version, line {line}"
            );
        }
    }

    #[test]
    fn a_pip_dependency_from_a_path_or_a_url_has_no_link() {
        let requirements = "requests==2.0.0\n-e ./local\nlocalpkg @ file:///tmp/localpkg\nurlpkg @ https://example.com/urlpkg.zip\ngitpkg @ git+https://github.com/x/y.git\n";
        let path = "/p/requirements.txt";
        assert!(hover_at(path, requirements, 0, 3).is_some());
        for line in 1..=4 {
            assert_eq!(hover_at(path, requirements, line, 3), None, "line {line}");
        }
    }

    #[test]
    fn the_name_line_and_the_version_line_of_a_pom_dependency_both_give_the_link() {
        // The artifact and the version sit on different lines of a pom.xml.
        let link = "[Open org.apache.logging.log4j:log4j-core on Maven Central](https://central.sonatype.com/artifact/org.apache.logging.log4j/log4j-core)";
        assert_eq!(hover_at("/p/pom.xml", POM, 4, 20).as_deref(), Some(link));
        assert_eq!(hover_at("/p/pom.xml", POM, 5, 16).as_deref(), Some(link));
        assert_eq!(hover_at("/p/pom.xml", POM, 6, 8), None);
    }
}
