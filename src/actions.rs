//! Code actions: quick fixes that move a requirement to a version that fixes its known
//! vulnerabilities, or to the latest registry release.

use crate::cache::Cache;
use crate::fixes::{line_constraints, plan_fix, render_fix};
use crate::is_manifest_in;
use crate::model::{Affected, Dependency, Ecosystem};
use crate::osv::{declared_version_for_osv, is_deferred, is_placeholder};
use crate::requirement::{checked_version_of, needs_list, satisfies_all};
use crate::settings::Settings;
use crate::text::to_range;
use crate::update::{UpdateKind, is_outdated, render_update, update_kind};
use openidea_plugin::providers::CodeAction;
use openidea_plugin::{Range, TextEdit};
use std::collections::HashSet;

/// The start of the `data` of an action that loads the deferred advisories of one dependency.
/// The rest of the text is the package name.
pub const LOAD_ACTION_PREFIX: &str = "load-vulnerabilities:";

/// Quick fixes for the requirements whose version lies on a selected line.
///
/// A dependency with known vulnerabilities gets a fix to the smallest version that fixes them, in
/// every ecosystem. An outdated dependency of an ecosystem with a registry also gets an update to the
/// latest release, after the fix. A dependency whose advisories wait for their details also gets an
/// action that loads them, which runs when the user picks it. Listing the actions reads the cache
/// only: an editor provider must never reach the network.
pub fn code_actions(
    cache: &Cache,
    settings: &Settings,
    doc_path: &str,
    project_root: Option<&str>,
    doc_text: &str,
    selection: Range,
    now: u64,
) -> Vec<CodeAction> {
    if !is_manifest_in(doc_path, project_root) {
        return Vec::new();
    }
    let Some(eco) = Ecosystem::detect(doc_path) else {
        return Vec::new();
    };
    if !settings.is_enabled(eco) {
        return Vec::new();
    }
    let ignored = settings.ignored_packages(eco);
    // One parse; the line test is a range check, so lines outside the selection build no action.
    let selected_lines = selection.start.line..=selection.end.line;
    let mut actions: Vec<CodeAction> = eco
        .parse(doc_text)
        .iter()
        .filter(|dep| selected_lines.contains(&dep.version_span.line))
        .filter(|dep| !ignored.contains(&eco.normalize_package(&dep.name)))
        .flat_map(|dep| {
            let fix = settings
                .vulnerabilities
                .then(|| fix_action_for(cache, settings, eco, dep, doc_path, doc_text, now))
                .flatten();
            let mut update = eco
                .offers_updates()
                .then(|| action_for(cache, eco, dep, doc_path, doc_text, now))
                .flatten();
            // Two preferred actions on one version would leave the choice to the editor.
            if fix.is_some()
                && let Some(update) = update.as_mut()
            {
                update.preferred = false;
            }
            let load = settings
                .vulnerabilities
                .then(|| load_action_for(cache, eco, dep, now))
                .flatten();
            fix.into_iter().chain(update).chain(load)
        })
        .collect();
    // Two lines of one package give the same load action, so it is listed once.
    let mut seen_data: HashSet<String> = HashSet::new();
    actions.retain(|action| {
        action
            .data
            .as_ref()
            .is_none_or(|data| seen_data.insert(data.clone()))
    });
    actions
}

/// The version that the analysis checked for `dep`: the lowest version of the cached registry
/// list that its requirement allows, or the text of the lower bound without such a list.
fn checked_version_for(
    cache: &Cache,
    eco: Ecosystem,
    dep: &Dependency,
    now: u64,
) -> Option<String> {
    let versions = needs_list(eco, &dep.version, dep.requirement.as_ref())
        .then(|| cache.version_info(eco, &eco.normalize_package(&dep.name), now))
        .flatten()
        .map(|info| info.versions.as_slice());
    checked_version_of(eco, &dep.version, dep.requirement.as_ref(), versions)
}

/// The action that loads the deferred advisories of `dep`, `None` when none waits for its details.
///
/// The action has no edit. Its `data` names the package, and picking it resolves the action,
/// which loads the details and refreshes the manifest.
fn load_action_for(
    cache: &Cache,
    eco: Ecosystem,
    dep: &Dependency,
    now: u64,
) -> Option<CodeAction> {
    let current = checked_version_for(cache, eco, dep, now)?;
    let waiting = cache
        .vulnerabilities(eco, &dep.name, &current, now)?
        .iter()
        .filter(|vulnerability| {
            is_deferred(vulnerability) && cache.advisory(&vulnerability.id, now).is_none()
        })
        .count();
    let noun = if waiting == 1 {
        "vulnerability"
    } else {
        "vulnerabilities"
    };
    (waiting > 0).then(|| CodeAction {
        title: format!("Load {waiting} more {noun} of {}", dep.name),
        kind: Some("quickfix".to_string()),
        preferred: false,
        edits: Vec::new(),
        data: Some(format!("{LOAD_ACTION_PREFIX}{}", dep.name)),
    })
}

/// The quick fix that moves `dep` to the smallest version that fixes its cached advisories.
///
/// It counts the advisories that the user sees: their details are loaded, and their severity
/// reaches the minimum. Returns `None` when none has a known fix, when the fix leaves the bounds of
/// the requirement, or when the requirement cannot be rewritten to one version.
fn fix_action_for(
    cache: &Cache,
    settings: &Settings,
    eco: Ecosystem,
    dep: &Dependency,
    doc_path: &str,
    doc_text: &str,
    now: u64,
) -> Option<CodeAction> {
    // A Maven version that is a property has its text elsewhere, so there is nothing to replace here.
    if eco == Ecosystem::Maven && dep.has_additional_version_constraints {
        return None;
    }
    let current = checked_version_for(cache, eco, dep, now)?;
    let listed = cache.vulnerabilities(eco, &dep.name, &current, now)?;
    let affected: Vec<&[Affected]> = listed
        .iter()
        .filter_map(|vulnerability| {
            let known = if is_placeholder(vulnerability) || is_deferred(vulnerability) {
                cache.advisory(&vulnerability.id, now)?
            } else {
                vulnerability
            };
            (known.severity >= settings.minimum_severity)
                .then(|| cache.affected(&known.id, now).unwrap_or_default())
        })
        .collect();
    // For PyPI and RubyGems, the version text excludes its operator, so the operator and the other
    // constraints sit in the line. The other ecosystems write them inside the version text, and an
    // XML tag such as `<version>` would read as an operator.
    let constraints = if matches!(eco, Ecosystem::PyPI | Ecosystem::RubyGems) {
        let line = doc_text.lines().nth(dep.version_span.line as usize)?;
        Some(line_constraints(
            eco,
            line,
            dep.version_span.line_start as usize,
        ))
    } else {
        None
    };
    // Replacing the version of `>1.0` would exclude the fixed version itself.
    if constraints
        .as_ref()
        .is_some_and(|found| found.pin_operator.as_deref() == Some(">"))
    {
        return None;
    }
    // A fix must also satisfy the other constraints of the line, such as the `<1` of `>=0.12.2,<1`.
    let allows = |target: &str| match &constraints {
        Some(found) if dep.has_additional_version_constraints => {
            satisfies_all(eco, target, &found.others)
        }
        _ => true,
    };
    let plan = plan_fix(eco, &dep.name, &current, &affected, allows)?;
    let new_text = render_fix(eco, &dep.version, &plan.target)?;
    let range = to_range(doc_text, dep.version_span)?;
    let count = if plan.fixed_count == plan.total_count {
        match plan.fixed_count {
            1 => "1 vulnerability".to_owned(),
            count => format!("{count} vulnerabilities"),
        }
    } else {
        format!(
            "{} of {} vulnerabilities",
            plan.fixed_count, plan.total_count
        )
    };
    Some(CodeAction {
        title: format!("Fix {count}: update {} to {}", dep.name, plan.target),
        kind: Some("quickfix".to_string()),
        // A security fix is the one to take first.
        preferred: true,
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
    use crate::model::{
        AdvisorySeverity, Affected, Ecosystem, RangeEvent, VersionInfo, Vulnerability,
    };
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
        code_actions(
            cache,
            settings,
            DOC_PATH,
            Some("/p"),
            DOC_TEXT,
            selection,
            NOW,
        )
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
            Some("/p"),
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
                Some("/p"),
                DOC_TEXT,
                cursor_on(0),
                NOW,
            );
            assert!(actions.is_empty(), "{path} must offer nothing");
        }
    }

    #[test]
    fn ignored_packages_offer_no_quick_fix() {
        let cache = pypi_cache(TTL_SECS);
        // The ignore list is compared in the ecosystem's normal form, like the analysis does.
        let settings = Settings {
            ignore: vec!["Requests".to_owned()],
            ..Settings::default()
        };
        let titles: Vec<String> = actions_for(
            &cache,
            &settings,
            Range::new(Position::new(0, 0), Position::new(2, 0)),
        )
        .into_iter()
        .map(|action| action.title)
        .collect();
        assert_eq!(titles.len(), 1);
        assert!(titles[0].starts_with("Update django"), "{titles:?}");
    }

    #[test]
    fn disabled_ecosystem_offers_nothing() {
        let cache = pypi_cache(TTL_SECS);
        let mut settings = Settings::default();
        settings.enabled.remove(&Ecosystem::PyPI);
        assert!(actions_for(&cache, &settings, cursor_on(0)).is_empty());
    }

    // fixes for vulnerabilities

    const FIX_NOW: u64 = NOW;

    /// The `(kind, version)` events of one affected range.
    type Events<'a> = &'a [(&'a str, &'a str)];
    /// An advisory of a test cache: its id, its severity and its affected range.
    type AdvisorySpec<'a> = (&'a str, AdvisorySeverity, Events<'a>);

    /// One ecosystem of the table test: where the dependency is, and what the fix writes.
    struct FixCase {
        eco: Ecosystem,
        package: &'static str,
        current: &'static str,
        fixed: &'static str,
        path: &'static str,
        text: &'static str,
        line: u32,
        expected_text: &'static str,
    }

    /// A cache that holds the advisories of one dependency, each with one affected range for it.
    ///
    /// Each advisory is `(id, severity, events)`, where `events` are `(kind, version)` pairs.
    fn fix_cache(
        eco: Ecosystem,
        package: &str,
        version: &str,
        advisories: &[AdvisorySpec<'_>],
    ) -> Cache {
        let mut cache = Cache::new(TTL_SECS);
        let mut listed = Vec::new();
        for (id, severity, events) in advisories {
            let vulnerability = Vulnerability {
                id: (*id).to_owned(),
                severity: *severity,
                summary: format!("Summary of {id}"),
                url: None,
            };
            listed.push(vulnerability.clone());
            cache.put_advisory(vulnerability, FIX_NOW);
            let range = events
                .iter()
                .map(|(kind, text)| match *kind {
                    "introduced" => RangeEvent::Introduced((*text).to_owned()),
                    "fixed" => RangeEvent::Fixed((*text).to_owned()),
                    _ => RangeEvent::LastAffected((*text).to_owned()),
                })
                .collect();
            cache.put_affected(
                id,
                vec![Affected {
                    ecosystem: eco.osv_name().to_owned(),
                    name: package.to_owned(),
                    ranges: vec![range],
                    versions: Vec::new(),
                }],
                FIX_NOW,
            );
        }
        cache.put_vulnerabilities(eco, package, version, listed, FIX_NOW);
        cache
    }

    /// The actions for `text` at `path`, with the cursor on `line`.
    fn actions_at(
        cache: &Cache,
        settings: &Settings,
        path: &str,
        text: &str,
        line: u32,
    ) -> Vec<CodeAction> {
        code_actions(
            cache,
            settings,
            path,
            Some("/p"),
            text,
            cursor_on(line),
            FIX_NOW,
        )
    }

    /// The title and the replacement text of each action.
    fn summary_of(actions: &[CodeAction]) -> Vec<(String, String)> {
        actions
            .iter()
            .map(|action| (action.title.clone(), action.edits[0].1[0].text.clone()))
            .collect()
    }

    const HIGH: AdvisorySeverity = AdvisorySeverity::High;
    const FROM_ZERO: &[(&str, &str)] = &[("introduced", "0")];

    fn events(fixed: &str) -> Vec<(&str, &str)> {
        let mut list = FROM_ZERO.to_vec();
        list.push(("fixed", fixed));
        list
    }

    #[test]
    fn a_vulnerable_dependency_gets_a_fix_in_every_ecosystem() {
        let settings = Settings::default();
        let pom = "<project>\n<dependencies>\n<dependency>\n<groupId>org.apache.logging.log4j</groupId>\n<artifactId>log4j-core</artifactId>\n<version>2.14.1</version>\n</dependency>\n</dependencies>\n</project>\n";
        let cases = [
            FixCase {
                eco: Ecosystem::Cargo,
                package: "smallvec",
                current: "1.6.0",
                fixed: "1.6.1",
                path: "/p/Cargo.toml",
                text: "[dependencies]\nsmallvec = \"1.6.0\"\n",
                line: 1,
                expected_text: "1.6.1",
            },
            FixCase {
                eco: Ecosystem::Npm,
                package: "lodash",
                current: "4.17.15",
                fixed: "4.17.21",
                path: "/p/package.json",
                text: "{\n  \"dependencies\": {\n    \"lodash\": \"4.17.15\"\n  }\n}\n",
                line: 2,
                expected_text: "4.17.21",
            },
            FixCase {
                eco: Ecosystem::Maven,
                package: "org.apache.logging.log4j:log4j-core",
                current: "2.14.1",
                fixed: "2.15.0",
                path: "/p/pom.xml",
                text: pom,
                line: 5,
                expected_text: "2.15.0",
            },
            FixCase {
                eco: Ecosystem::Go,
                package: "golang.org/x/text",
                current: "0.3.0",
                fixed: "0.3.3",
                path: "/p/go.mod",
                text: "module m\n\nrequire golang.org/x/text v0.3.0\n",
                line: 2,
                expected_text: "v0.3.3",
            },
            FixCase {
                eco: Ecosystem::PyPI,
                package: "requests",
                current: "2.19.0",
                fixed: "2.20.0",
                path: "/p/requirements.txt",
                text: "requests==2.19.0\n",
                line: 0,
                expected_text: "2.20.0",
            },
        ];
        for case in cases {
            let eco = case.eco;
            let cache = fix_cache(
                eco,
                case.package,
                case.current,
                &[("GHSA-1", HIGH, &events(case.fixed))],
            );
            let actions = actions_at(&cache, &settings, case.path, case.text, case.line);
            let fix = actions
                .iter()
                .find(|action| action.title.starts_with("Fix "))
                .unwrap_or_else(|| panic!("no fix for {eco:?}: {actions:?}"));
            assert_eq!(
                fix.title,
                format!(
                    "Fix 1 vulnerability: update {} to {}",
                    case.package, case.fixed
                ),
                "{eco:?}"
            );
            assert_eq!(fix.edits[0].1[0].text, case.expected_text, "{eco:?}");
            assert!(fix.preferred, "{eco:?}");
            assert_eq!(fix.kind.as_deref(), Some("quickfix"));
        }
    }

    #[test]
    fn the_fix_takes_the_highest_fixed_version_and_names_the_count() {
        let cache = fix_cache(
            Ecosystem::Cargo,
            "smallvec",
            "1.6.0",
            &[
                ("GHSA-1", HIGH, &events("1.6.1")),
                ("GHSA-2", AdvisorySeverity::Low, &events("1.8.0")),
                (
                    "GHSA-3",
                    HIGH,
                    &[("introduced", "0"), ("last_affected", "9.0.0")],
                ),
            ],
        );
        let actions = actions_at(
            &cache,
            &Settings::default(),
            "/p/Cargo.toml",
            "[dependencies]\nsmallvec = \"1.6.0\"\n",
            1,
        );
        assert_eq!(
            summary_of(&actions),
            [(
                "Fix 2 of 3 vulnerabilities: update smallvec to 1.8.0".to_owned(),
                "1.8.0".to_owned()
            )]
        );
    }

    #[test]
    fn the_fix_skips_a_version_that_a_later_interval_of_an_advisory_still_affects() {
        // GHSA-A is affected on [0, 1.1.0) and [1.5.0, 1.8.0). GHSA-B is affected on [0, 1.6.0).
        // 1.6.0 would fix GHSA-B only, so the action must move on to 1.8.0.
        let cache = fix_cache(
            Ecosystem::Cargo,
            "review_demo",
            "1.0.0",
            &[
                (
                    "GHSA-A",
                    HIGH,
                    &[
                        ("introduced", "0"),
                        ("fixed", "1.1.0"),
                        ("introduced", "1.5.0"),
                        ("fixed", "1.8.0"),
                    ],
                ),
                ("GHSA-B", HIGH, &events("1.6.0")),
            ],
        );
        let actions = actions_at(
            &cache,
            &Settings::default(),
            "/p/Cargo.toml",
            "[dependencies]\nreview_demo = \"1.0.0\"\n",
            1,
        );
        assert_eq!(
            summary_of(&actions),
            [(
                "Fix 2 vulnerabilities: update review_demo to 1.8.0".to_owned(),
                "1.8.0".to_owned()
            )]
        );
    }

    #[test]
    fn a_bounded_python_requirement_is_fixed_only_within_its_bounds() {
        let pyproject = "[project]\ndependencies = [\n  \"flask>=0.12.2,<1\",\n]\n";
        // The fix of 2.3.2 would break `<1`, so the action takes the fix of 0.12.3 and says it is partial.
        let partial = fix_cache(
            Ecosystem::PyPI,
            "flask",
            "0.12.2",
            &[
                ("GHSA-1", HIGH, &events("0.12.3")),
                ("GHSA-2", HIGH, &events("2.3.2")),
            ],
        );
        assert_eq!(
            summary_of(&actions_at(
                &partial,
                &Settings::default(),
                "/p/pyproject.toml",
                pyproject,
                2
            )),
            [(
                "Fix 1 of 2 vulnerabilities: update flask to 0.12.3".to_owned(),
                "0.12.3".to_owned()
            )]
        );
        // When every fix leaves the bounds, no action is offered.
        let blocked = fix_cache(
            Ecosystem::PyPI,
            "flask",
            "0.12.2",
            &[("GHSA-2", HIGH, &events("2.3.2"))],
        );
        assert!(
            actions_at(
                &blocked,
                &Settings::default(),
                "/p/pyproject.toml",
                pyproject,
                2
            )
            .is_empty()
        );
        // The fix of 0.12.3 fits, and replaces the lower bound only.
        let fits = fix_cache(
            Ecosystem::PyPI,
            "flask",
            "0.12.2",
            &[("GHSA-1", HIGH, &events("0.12.3"))],
        );
        let actions = actions_at(
            &fits,
            &Settings::default(),
            "/p/pyproject.toml",
            pyproject,
            2,
        );
        assert_eq!(
            summary_of(&actions),
            [(
                "Fix 1 vulnerability: update flask to 0.12.3".to_owned(),
                "0.12.3".to_owned()
            )]
        );
    }

    #[test]
    fn a_strict_greater_than_pin_is_not_rewritten() {
        let cache = fix_cache(
            Ecosystem::PyPI,
            "requests",
            "2.19.0",
            &[("GHSA-1", HIGH, &events("2.20.0"))],
        );
        assert!(
            actions_at(
                &cache,
                &Settings::default(),
                "/p/requirements.txt",
                "requests>2.19.0\n",
                0
            )
            .is_empty()
        );
    }

    #[test]
    fn settings_and_the_cache_decide_whether_a_fix_is_offered() {
        let text = "[dependencies]\nsmallvec = \"1.6.0\"\n";
        let cache = fix_cache(
            Ecosystem::Cargo,
            "smallvec",
            "1.6.0",
            &[("GHSA-1", AdvisorySeverity::Low, &events("1.6.1"))],
        );
        let offered = |settings: &Settings, cache: &Cache| {
            actions_at(cache, settings, "/p/Cargo.toml", text, 1).len()
        };
        assert_eq!(offered(&Settings::default(), &cache), 1);
        // Vulnerabilities are off, so no advisory is shown and no fix is offered.
        let off = Settings {
            vulnerabilities: false,
            ..Settings::default()
        };
        assert_eq!(offered(&off, &cache), 0);
        // The advisory is below the minimum severity, so it is not shown and not fixed.
        let strict = Settings {
            minimum_severity: AdvisorySeverity::High,
            ..Settings::default()
        };
        assert_eq!(offered(&strict, &cache), 0);
        // An ignored package and a disabled ecosystem get nothing.
        let ignoring = Settings {
            ignore: vec!["smallvec".to_owned()],
            ..Settings::default()
        };
        assert_eq!(offered(&ignoring, &cache), 0);
        let mut disabled = Settings::default();
        disabled.enabled.remove(&Ecosystem::Cargo);
        assert_eq!(offered(&disabled, &cache), 0);
        // A cold cache offers nothing.
        assert_eq!(offered(&Settings::default(), &Cache::new(TTL_SECS)), 0);
    }

    #[test]
    fn the_fix_comes_before_the_update_to_the_latest_release() {
        let mut cache = fix_cache(
            Ecosystem::PyPI,
            "requests",
            "2.19.0",
            &[("GHSA-1", HIGH, &events("2.20.0"))],
        );
        cache.put_version_info(
            Ecosystem::PyPI,
            "requests",
            VersionInfo {
                latest: Some("2.31.0".to_owned()),
                versions: Vec::new(),
            },
            FIX_NOW,
        );
        let actions = actions_at(
            &cache,
            &Settings::default(),
            "/p/requirements.txt",
            "requests==2.19.0\n",
            0,
        );
        assert_eq!(
            summary_of(&actions),
            [
                (
                    "Fix 1 vulnerability: update requests to 2.20.0".to_owned(),
                    "2.20.0".to_owned()
                ),
                (
                    "Update requests to 2.31.0 (minor)".to_owned(),
                    "2.31.0".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn only_the_fix_is_preferred_when_a_line_has_both_actions() {
        let mut cache = fix_cache(
            Ecosystem::PyPI,
            "requests",
            "2.19.0",
            &[("GHSA-1", HIGH, &events("2.20.0"))],
        );
        cache.put_version_info(
            Ecosystem::PyPI,
            "requests",
            VersionInfo {
                latest: Some("2.31.0".to_owned()),
                versions: Vec::new(),
            },
            FIX_NOW,
        );
        let actions = actions_at(
            &cache,
            &Settings::default(),
            "/p/requirements.txt",
            "requests==2.19.0\n",
            0,
        );
        let preferred: Vec<bool> = actions.iter().map(|action| action.preferred).collect();
        assert_eq!(preferred, [true, false]);
    }

    // the action that loads the deferred advisories

    /// A cache that lists `deferred` advisories of one dependency that wait for their details.
    fn deferred_cache(eco: Ecosystem, package: &str, version: &str, deferred: usize) -> Cache {
        let mut cache = Cache::new(TTL_SECS);
        let listed = (0..deferred)
            .map(|number| Vulnerability {
                id: format!("GHSA-{number:04}"),
                severity: AdvisorySeverity::Medium,
                summary: crate::osv::DEFERRED_SUMMARY.to_owned(),
                url: None,
            })
            .collect();
        cache.put_vulnerabilities(eco, package, version, listed, FIX_NOW);
        cache
    }

    const SMALLVEC: &str = "[dependencies]\nsmallvec = \"1.6.0\"\n";

    #[test]
    fn deferred_advisories_get_an_action_that_loads_them() {
        let settings = Settings::default();
        let cache = deferred_cache(Ecosystem::Cargo, "smallvec", "1.6.0", 33);
        let actions = actions_at(&cache, &settings, "/p/Cargo.toml", SMALLVEC, 1);
        assert_eq!(actions.len(), 1);
        let load = &actions[0];
        assert_eq!(load.title, "Load 33 more vulnerabilities of smallvec");
        assert_eq!(load.kind.as_deref(), Some("quickfix"));
        assert!(!load.preferred);
        // The action has no edit: picking it runs the load, which resolves it.
        assert!(load.edits.is_empty());
        assert_eq!(load.data.as_deref(), Some("load-vulnerabilities:smallvec"));

        let one = deferred_cache(Ecosystem::Cargo, "smallvec", "1.6.0", 1);
        let titles: Vec<String> = actions_at(&one, &settings, "/p/Cargo.toml", SMALLVEC, 1)
            .into_iter()
            .map(|action| action.title)
            .collect();
        assert_eq!(titles, ["Load 1 more vulnerability of smallvec"]);
    }

    #[test]
    fn no_load_action_without_deferred_advisories_or_when_their_details_are_cached() {
        let settings = Settings::default();
        // Nothing is deferred.
        let none = deferred_cache(Ecosystem::Cargo, "smallvec", "1.6.0", 0);
        assert!(actions_at(&none, &settings, "/p/Cargo.toml", SMALLVEC, 1).is_empty());
        // Another package already loaded the details of two of the three, so only one waits.
        let mut cache = deferred_cache(Ecosystem::Cargo, "smallvec", "1.6.0", 3);
        for number in 0..2 {
            cache.put_advisory(
                Vulnerability {
                    id: format!("GHSA-{number:04}"),
                    severity: AdvisorySeverity::Low,
                    summary: "Loaded".to_owned(),
                    url: None,
                },
                FIX_NOW,
            );
        }
        let titles: Vec<String> = actions_at(&cache, &settings, "/p/Cargo.toml", SMALLVEC, 1)
            .into_iter()
            .map(|action| action.title)
            .collect();
        assert_eq!(titles, ["Load 1 more vulnerability of smallvec"]);
        // Vulnerabilities off, an ignored package and a cold cache offer nothing.
        let cache = deferred_cache(Ecosystem::Cargo, "smallvec", "1.6.0", 3);
        let off = Settings {
            vulnerabilities: false,
            ..Settings::default()
        };
        assert!(actions_at(&cache, &off, "/p/Cargo.toml", SMALLVEC, 1).is_empty());
        let ignoring = Settings {
            ignore: vec!["smallvec".to_owned()],
            ..Settings::default()
        };
        assert!(actions_at(&cache, &ignoring, "/p/Cargo.toml", SMALLVEC, 1).is_empty());
        assert!(
            actions_at(
                &Cache::new(TTL_SECS),
                &settings,
                "/p/Cargo.toml",
                SMALLVEC,
                1
            )
            .is_empty()
        );
    }

    #[test]
    fn two_lines_of_the_same_package_give_one_load_action() {
        let cache = deferred_cache(Ecosystem::Cargo, "smallvec", "1.6.0", 3);
        let text =
            "[dependencies]\nsmallvec = \"1.6.0\"\n\n[dev-dependencies]\nsmallvec = \"1.6.0\"\n";
        let selection = Range::new(Position::new(1, 0), Position::new(4, 0));
        let actions = code_actions(
            &cache,
            &Settings::default(),
            "/p/Cargo.toml",
            Some("/p"),
            text,
            selection,
            FIX_NOW,
        );
        assert_eq!(actions.len(), 1);
    }

    /// The versions that the registry lists for flask, newest first.
    fn flask_versions() -> VersionInfo {
        VersionInfo {
            latest: Some("2.3.2".to_owned()),
            versions: ["2.3.2", "0.12.3", "0.12.2"].map(str::to_owned).to_vec(),
        }
    }

    #[test]
    fn the_fix_and_the_load_action_read_the_lowest_allowed_version_of_a_range() {
        // `0.12.1` does not exist: the analysis checked `0.12.2`, so the actions must read its advisories.
        let pyproject = "[project]\ndependencies = [\n  \"flask>=0.12.1,<1\",\n]\n";
        let mut cache = fix_cache(
            Ecosystem::PyPI,
            "flask",
            "0.12.2",
            &[("GHSA-1", HIGH, &events("0.12.3"))],
        );
        cache.put_version_info(Ecosystem::PyPI, "flask", flask_versions(), FIX_NOW);
        assert_eq!(
            summary_of(&actions_at(
                &cache,
                &Settings::default(),
                "/p/pyproject.toml",
                pyproject,
                2
            )),
            [(
                "Fix 1 vulnerability: update flask to 0.12.3".to_owned(),
                "0.12.3".to_owned()
            )]
        );

        let mut deferred = deferred_cache(Ecosystem::PyPI, "flask", "0.12.2", 2);
        deferred.put_version_info(Ecosystem::PyPI, "flask", flask_versions(), FIX_NOW);
        let titles: Vec<String> = actions_at(
            &deferred,
            &Settings::default(),
            "/p/pyproject.toml",
            pyproject,
            2,
        )
        .into_iter()
        .map(|action| action.title)
        .collect();
        assert_eq!(titles, ["Load 2 more vulnerabilities of flask"]);
    }
}
