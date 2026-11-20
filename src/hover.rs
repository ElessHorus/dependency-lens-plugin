//! The IDE hover that links the package page of the dependency under the cursor.

use crate::cache::Cache;
use crate::history::version_history;
use crate::model::Dependency;
use crate::settings::Settings;
use crate::text::to_range_in_line;
use openidea_plugin::hover::Hover;
use openidea_plugin::{Position, Range};

/// The hover that links the package page of the dependency under the cursor.
///
/// The cursor must lie on the name or on the version of a dependency. Under the link, the answer
/// lists the releases newer than the checked version when the cache holds the registry list of the
/// package. It only reads the cache and makes no request. It follows the path of the quick fixes:
/// a file that is not a manifest, a disabled ecosystem and an ignored package give `None`. A
/// private or local package is not in `Ecosystem::parse`, so it gets no link. A name that is
/// unsafe for a URL gives `None` too.
pub fn package_link_hover(
    settings: &Settings,
    cache: &Cache,
    now: u64,
    doc_path: &str,
    project_root: Option<&str>,
    doc_text: &str,
    at: Position,
) -> Option<Hover> {
    let eco = crate::enabled_manifest_ecosystem(settings, doc_path, project_root)?;
    // The cursor line is read once, so no span walks the text from its start again.
    let cursor_line = doc_text.lines().nth(at.line as usize)?;
    let dependencies = eco.parse(doc_text);
    // The hover names the span under the cursor: the editor anchors the tooltip on that range.
    let (dependency, hovered_range) = dependencies.iter().find_map(|dependency| {
        range_under_cursor(cursor_line, dependency, at).map(|range| (dependency, range))
    })?;
    // The ignore set is built only for a match, so a hover over plain text allocates nothing.
    if settings
        .ignored_packages(eco)
        .contains(&eco.normalize_package(&dependency.name))
    {
        return None;
    }
    let url = eco.package_page_url(&dependency.name)?;
    // The link text names the package as the manifest writes it. `package_page_url` checked the
    // normalized name against an allow-list, and normalization never removes a Markdown character,
    // so the name cannot break the link. Emphasis characters are escaped, so they stay visible.
    let mut text = format!(
        "[Open {} on {}]({url})",
        escape_emphasis(&dependency.name),
        eco.registry_label()
    );
    if let Some(section) = version_history(eco, dependency, cache, settings, now) {
        text.push_str("\n\n");
        text.push_str(&section);
    }
    Some(Hover::new(text).range(hovered_range))
}

/// Escapes the characters of `name` that Markdown reads as emphasis, so a name such as `_priv_`
/// keeps its underscores in the link text.
fn escape_emphasis(name: &str) -> String {
    let mut escaped = String::with_capacity(name.len());
    for character in name.chars() {
        if matches!(character, '_' | '~' | '*') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

/// The range of the name or of the version of `dependency` that holds `at`, if any.
///
/// `cursor_line` is the text of line `at.line`. The end of a span counts, because the editor
/// rounds the mouse position to the nearest character boundary.
fn range_under_cursor(cursor_line: &str, dependency: &Dependency, at: Position) -> Option<Range> {
    [dependency.name_span, dependency.version_span]
        .into_iter()
        .filter(|span| span.line == at.line)
        .filter_map(|span| to_range_in_line(cursor_line, span))
        .find(|range| range.start.character <= at.character && at.character <= range.end.character)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Ecosystem, VersionInfo};

    const NOW: u64 = 1_000;

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
        package_link_hover(
            settings,
            &Cache::new(3_600),
            NOW,
            path,
            None,
            text,
            Position::new(line, character),
        )
        .map(|hover| hover.markdown)
    }

    /// A cache that holds the registry list of `requests`, newest first.
    fn cache_with_requests_list() -> Cache {
        let mut cache = Cache::new(3_600);
        let versions = [
            "3.0.0", "2.34.2", "2.10.0", "2.9.2", "2.9.1", "2.9.0rc1", "2.0.0",
        ];
        let info = VersionInfo {
            latest: Some("3.0.0".to_owned()),
            versions: versions.iter().map(|text| (*text).to_owned()).collect(),
        };
        cache.put_version_info(Ecosystem::PyPI, "requests", info, NOW);
        cache
    }

    const RANGE: &str = "requests>1.12,<2.10\n";
    const RANGE_SECTION: &str = "Versions after 2.0.0:\n\
- `3.0.0` — outside your bounds\n\
- `2.34.2` — outside your bounds\n\
- `2.10.0` — outside your bounds\n\
- `2.9.2` — allowed, latest allowed\n\
- `2.9.1` — allowed\n\
- `2.9.0rc1` — allowed, pre-release";

    fn hover_with_cache(settings: &Settings, text: &str, line: u32) -> Option<String> {
        package_link_hover(
            settings,
            &cache_with_requests_list(),
            NOW,
            "/p/requirements.txt",
            None,
            text,
            Position::new(line, 2),
        )
        .map(|hover| hover.markdown)
    }

    #[test]
    fn the_hover_adds_the_newer_releases_under_the_link() {
        assert_eq!(
            hover_with_cache(&Settings::default(), RANGE, 0),
            Some(format!("{REQUESTS_LINK}\n\n{RANGE_SECTION}"))
        );
    }

    #[test]
    fn an_ignored_package_has_no_section() {
        let settings = Settings {
            ignore: vec!["requests".to_owned()],
            ..Settings::default()
        };
        assert_eq!(hover_with_cache(&settings, RANGE, 0), None);
    }

    #[test]
    fn a_package_of_a_private_index_has_no_section() {
        let text = format!("--index-url https://pypi.example.com/simple\n{RANGE}");
        assert_eq!(hover_with_cache(&Settings::default(), &text, 1), None);
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
            // The editor rounds the mouse to the nearest boundary, so the end of a span counts.
            ("/p/Cargo.toml", CARGO, 5, 5, SERDE_LINK),
            ("/p/Cargo.toml", CARGO, 5, 14, SERDE_LINK),
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
                &Cache::new(3_600),
                NOW,
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
        // Columns 6 to 8 lie between the name and the version, and 15 is past the version.
        let cases = [
            (CARGO, 5, 6),
            (CARGO, 5, 8),
            (CARGO, 5, 15),
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

    /// The UTF-16 column where `needle` starts in `line`, as the editor counts columns.
    fn utf16_column_of(line: &str, needle: &str) -> u32 {
        let byte_start = line.find(needle).expect("the needle is in the line");
        u32::try_from(line[..byte_start].encode_utf16().count()).expect("a small column")
    }

    #[test]
    fn crlf_line_ends_and_a_bom_do_not_shift_the_cursor() {
        let crlf = CARGO.replace('\n', "\r\n");
        assert_eq!(
            hover_at("/p/Cargo.toml", &crlf, 5, 2).as_deref(),
            Some(SERDE_LINK)
        );
        assert_eq!(
            hover_at("/p/Cargo.toml", &crlf, 5, 10).as_deref(),
            Some(SERDE_LINK)
        );
        // A BOM is one UTF-16 unit on line 0, so the name of the first requirement starts at 1.
        let with_bom = format!("\u{feff}{PIP}");
        assert_eq!(
            hover_at("/p/requirements.txt", &with_bom, 0, 1).as_deref(),
            Some(REQUESTS_LINK)
        );
        assert_eq!(hover_at("/p/requirements.txt", &with_bom, 0, 0), None);
    }

    #[test]
    fn text_before_the_name_on_the_same_line_counts_in_utf16_units() {
        // `é` is one UTF-16 unit and the emoji is two, but they take two and four bytes.
        let line =
            "{\"note\":\"é😀\",\"dependencies\":{\"left-pad\":\"^1.3.0\",\"react\":\"^18.0.0\"}}\n";
        let path = "/p/package.json";
        let left_pad = utf16_column_of(line, "left-pad");
        let react = utf16_column_of(line, "react");
        assert_eq!(
            hover_at(path, line, 0, left_pad + 2).as_deref(),
            Some("[Open left-pad on npm](https://www.npmjs.com/package/left-pad)")
        );
        // Two dependencies share the line: each cursor gets the dependency under it.
        assert_eq!(
            hover_at(path, line, 0, react + 2).as_deref(),
            Some("[Open react on npm](https://www.npmjs.com/package/react)")
        );
        assert_eq!(hover_at(path, line, 0, left_pad - 3), None);
    }

    #[test]
    fn a_parsed_name_that_is_unsafe_for_a_url_has_no_link() {
        // The npm parser reads `ünï`, but the name is not ASCII, so `package_page_url` refuses it.
        let package_json = "{\n  \"dependencies\": {\n    \"ünï\": \"1.0.0\"\n  }\n}\n";
        assert_eq!(hover_at("/p/package.json", package_json, 2, 6), None);
    }

    #[test]
    fn a_manifest_in_a_skipped_folder_has_no_link() {
        let hover = |path: &str| {
            package_link_hover(
                &Settings::default(),
                &Cache::new(3_600),
                NOW,
                path,
                Some("/p"),
                CARGO,
                Position::new(5, 2),
            )
        };
        assert!(hover("/p/Cargo.toml").is_some());
        assert_eq!(hover("/p/node_modules/dep/Cargo.toml"), None);
    }

    #[test]
    fn emphasis_characters_of_a_name_are_escaped_in_the_link_text() {
        assert_eq!(escape_emphasis("_priv_"), "\\_priv\\_");
        assert_eq!(escape_emphasis("a~b*c"), "a\\~b\\*c");
        assert_eq!(escape_emphasis("left-pad"), "left-pad");
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
