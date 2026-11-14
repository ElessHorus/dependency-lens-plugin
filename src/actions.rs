//! Code actions: quick fixes that bump an outdated requirement to the latest registry release.

use crate::cache::Cache;
use crate::is_manifest;
use crate::model::{Dependency, Ecosystem};
use crate::osv::declared_version_for_osv;
use crate::settings::Settings;
use crate::text::to_range;
use crate::update::{UpdateKind, is_outdated, render_update, update_kind};
use openidea_plugin::providers::CodeAction;
use openidea_plugin::{Range, TextEdit};

/// Quick fixes for the outdated requirements whose version lies on a selected line.
///
/// Reads the cache only: an editor provider must never reach the network.
pub fn code_actions(
    cache: &Cache,
    settings: &Settings,
    doc_path: &str,
    doc_text: &str,
    selection: Range,
    now: u64,
) -> Vec<CodeAction> {
    if !is_manifest(doc_path) {
        return Vec::new();
    }
    let Some(eco) = Ecosystem::detect(doc_path) else {
        return Vec::new();
    };
    if !eco.offers_updates() || !settings.is_enabled(eco) {
        return Vec::new();
    }
    // One parse; the line test is a range check, so lines outside the selection build no action.
    let selected_lines = selection.start.line..=selection.end.line;
    eco.parse(doc_text)
        .iter()
        .filter(|dep| selected_lines.contains(&dep.version_span.line))
        .filter_map(|dep| action_for(cache, eco, dep, doc_path, doc_text, now))
        .collect()
}

/// The quick fix that bumps `dep` to its cached latest release, `None` when none applies.
fn action_for(
    cache: &Cache,
    eco: Ecosystem,
    dep: &Dependency,
    doc_path: &str,
    doc_text: &str,
    now: u64,
) -> Option<CodeAction> {
    let package = eco.normalize_package(&dep.name);
    let latest = cache.version_info(eco, &package, now)?.latest.as_deref()?;
    if !is_outdated(eco, &dep.version, latest) {
        return None;
    }
    let new_text = render_update(eco, dep, latest)?;
    let current = declared_version_for_osv(&dep.version)?;
    let kind = update_kind(eco, &current, latest)?;
    let range = to_range(doc_text, dep.version_span)?;
    Some(CodeAction {
        title: format!("Update {} to {latest} ({})", dep.name, kind_label(kind)),
        kind: Some("quickfix".to_string()),
        // Minor and patch steps are usually safe in one click; major and pre-release steps are not.
        preferred: matches!(kind, UpdateKind::Minor | UpdateKind::Patch),
        edits: vec![(
            doc_path.to_string(),
            vec![TextEdit {
                range,
                text: new_text,
            }],
        )],
        data: None,
    })
}

/// The word that names `kind` in an action title.
fn kind_label(kind: UpdateKind) -> &'static str {
    match kind {
        UpdateKind::Major => "major",
        UpdateKind::Minor => "minor",
        UpdateKind::Patch => "patch",
        UpdateKind::Prerelease => "prerelease",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Ecosystem, VersionInfo};
    use openidea_plugin::{Position, TextEdit};

    const DOC_PATH: &str = "/p/requirements.txt";
    const DOC_TEXT: &str = "requests==2.28.0\nflask==2.31.0\ndjango==3.2\n";
    const NOW: u64 = 1_000_000;
    const TTL_SECS: u64 = 3600;

    /// A cache holding the latest PyPI release of each package, stored at `NOW`.
    fn pypi_cache(ttl_secs: u64) -> Cache {
        let mut cache = Cache::new(ttl_secs);
        for (package, latest) in [
            ("requests", "2.31.0"),
            ("flask", "2.31.0"),
            ("django", "4.2.0"),
        ] {
            cache.put_version_info(
                Ecosystem::PyPI,
                package,
                VersionInfo {
                    latest: Some(latest.to_owned()),
                    versions: Vec::new(),
                },
                NOW,
            );
        }
        cache
    }

    fn cursor_on(line: u32) -> Range {
        Range::new(Position::new(line, 3), Position::new(line, 3))
    }

    fn actions_for(cache: &Cache, settings: &Settings, selection: Range) -> Vec<CodeAction> {
        code_actions(cache, settings, DOC_PATH, DOC_TEXT, selection, NOW)
    }

    #[test]
    fn cursor_on_outdated_line_offers_a_minor_preferred_quick_fix() {
        let cache = pypi_cache(TTL_SECS);
        let actions = actions_for(&cache, &Settings::default(), cursor_on(0));
        assert_eq!(actions.len(), 1);
        let action = &actions[0];
        assert_eq!(action.title, "Update requests to 2.31.0 (minor)");
        assert!(action.preferred);
        assert_eq!(action.kind, Some("quickfix".to_string()));
        assert_eq!(action.data, None);
        assert_eq!(
            action.edits,
            vec![(
                DOC_PATH.to_string(),
                vec![TextEdit {
                    range: Range::new(Position::new(0, 10), Position::new(0, 16)),
                    text: "2.31.0".to_string(),
                }],
            )]
        );
    }

    #[test]
    fn up_to_date_line_and_line_past_the_end_offer_nothing() {
        let cache = pypi_cache(TTL_SECS);
        assert!(actions_for(&cache, &Settings::default(), cursor_on(1)).is_empty());
        assert!(actions_for(&cache, &Settings::default(), cursor_on(9)).is_empty());
    }

    #[test]
    fn major_update_is_offered_but_not_preferred() {
        let cache = pypi_cache(TTL_SECS);
        let actions = actions_for(&cache, &Settings::default(), cursor_on(2));
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].title, "Update django to 4.2.0 (major)");
        assert!(!actions[0].preferred);
        assert_eq!(actions[0].edits[0].1[0].text, "4.2.0");
    }

    #[test]
    fn selection_over_several_lines_offers_actions_in_document_order() {
        let cache = pypi_cache(TTL_SECS);
        let selection = Range::new(Position::new(0, 0), Position::new(2, 0));
        let titles: Vec<String> = actions_for(&cache, &Settings::default(), selection)
            .into_iter()
            .map(|action| action.title)
            .collect();
        assert_eq!(
            titles,
            vec![
                "Update requests to 2.31.0 (minor)".to_string(),
                "Update django to 4.2.0 (major)".to_string(),
            ]
        );
    }

    #[test]
    fn cold_cache_offers_nothing() {
        let cache = Cache::new(TTL_SECS);
        assert!(actions_for(&cache, &Settings::default(), cursor_on(0)).is_empty());
    }

    #[test]
    fn expired_cache_entry_offers_nothing() {
        let cache = pypi_cache(60);
        // The entry is stored at NOW, so `now` at the TTL boundary expires it.
        let actions = code_actions(
            &cache,
            &Settings::default(),
            DOC_PATH,
            DOC_TEXT,
            cursor_on(0),
            NOW + 60,
        );
        assert!(actions.is_empty());
    }

    #[test]
    fn paths_that_are_not_pypi_manifests_offer_nothing() {
        let cache = pypi_cache(TTL_SECS);
        for path in [
            "/p/Cargo.toml",
            "/p/README.md",
            "/p/node_modules/x/requirements.txt",
        ] {
            let actions = code_actions(
                &cache,
                &Settings::default(),
                path,
                DOC_TEXT,
                cursor_on(0),
                NOW,
            );
            assert!(actions.is_empty(), "{path} must offer nothing");
        }
    }

    #[test]
    fn disabled_ecosystem_offers_nothing() {
        let cache = pypi_cache(TTL_SECS);
        let mut settings = Settings::default();
        settings.enabled.remove(&Ecosystem::PyPI);
        assert!(actions_for(&cache, &settings, cursor_on(0)).is_empty());
    }
}
