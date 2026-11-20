//! The "newer releases" section of the hover.

use crate::actions::checked_version_for;
use crate::cache::Cache;
use crate::fixes::{shown_advisories, still_affecting};
use crate::model::{Affected, Dependency, Ecosystem};
use crate::settings::Settings;
use crate::update::newer_releases;
use std::fmt::Write;

/// The most release lines that the section shows.
const MAX_RELEASES: usize = 10;
/// The most advisory ids that one release line names. The others are counted.
const MAX_IDS: usize = 3;

/// The Markdown section that lists the releases newer than the checked version of `dep`.
///
/// It reads the cache only. It returns `None` when the cache holds no registry list for the
/// package (an ecosystem without a registry client, an expired answer) or when the dependency has
/// no checked version. Each release line carries its marks: the bounds of the requirement, the
/// pre-release flag, and the advisories of the checked version that still affect the release.
/// Security marks need the `vulnerabilities` setting and a cached vulnerability list for the
/// checked version.
pub fn version_history(
    eco: Ecosystem,
    dep: &Dependency,
    cache: &Cache,
    settings: &Settings,
    now: u64,
) -> Option<String> {
    let info = cache.version_info(eco, &eco.normalize_package(&dep.name), now)?;
    let checked = checked_version_for(cache, eco, dep, now)?;
    let newer = newer_releases(eco, &checked, &info.versions);
    if newer.is_empty() {
        return Some(format!("No version after {checked}."));
    }
    let shown = &newer[..newer.len().min(MAX_RELEASES)];

    // The vulnerability lists are keyed by the name as the manifest writes it (the quick fix reads
    // them the same way), unlike the registry lists above. See A.4 in the TODO.
    // The advisories of the checked version, read once. `None` turns the security marks off.
    let advisories = settings
        .vulnerabilities
        .then(|| cache.vulnerabilities(eco, &dep.name, &checked, now))
        .flatten()
        .map(|listed| shown_advisories(cache, listed, settings.minimum_severity, now));
    // One pass parses each advisory once and probes every shown release.
    let still_affected: Vec<Vec<usize>> = advisories.as_ref().map_or_else(Vec::new, |known| {
        let affected: Vec<&[Affected]> = known.loaded.iter().map(|(_, lists)| *lists).collect();
        let texts: Vec<&str> = shown.iter().map(|release| release.text).collect();
        still_affecting(eco, &dep.name, &checked, &affected, &texts)
    });
    let latest_allowed = dep
        .requirement
        .as_ref()
        .and_then(|requirement| requirement.latest_allowed(eco, &info.versions));

    let mut text = format!("Versions after {checked}:");
    for (index, release) in shown.iter().enumerate() {
        text.push_str("\n- `");
        text.push_str(release.text);
        text.push('`');
        let mut marks = String::new();
        if let Some(requirement) = &dep.requirement {
            if !requirement.allows(eco, release.text) {
                add_mark(&mut marks, "outside your bounds");
            } else {
                add_mark(&mut marks, "allowed");
                if latest_allowed.as_deref() == Some(release.text) {
                    add_mark(&mut marks, "latest allowed");
                }
            }
        }
        if release.is_prerelease {
            add_mark(&mut marks, "pre-release");
        }
        if let (Some(known), Some(indices)) = (&advisories, still_affected.get(index))
            && !indices.is_empty()
        {
            let mut mark = String::from("still affected: ");
            for (position, advisory_index) in indices.iter().take(MAX_IDS).enumerate() {
                if position > 0 {
                    mark.push_str(", ");
                }
                // An id sits in a code span, so a backtick inside it must not close the span.
                let _ = write!(
                    mark,
                    "`{}`",
                    known.loaded[*advisory_index].0.replace('`', "'")
                );
            }
            if indices.len() > MAX_IDS {
                let _ = write!(mark, ", +{}", indices.len() - MAX_IDS);
            }
            add_mark(&mut marks, &mark);
        }
        if !marks.is_empty() {
            text.push_str(" — ");
            text.push_str(&marks);
        }
    }
    if newer.len() > MAX_RELEASES {
        let _ = write!(text, "\n- … {} more", newer.len() - MAX_RELEASES);
    }
    // A blank line ends the list, so a footer is not read as part of the last item.
    if let Some(known) = &advisories {
        text.push_str("\n\nAdvisories of newer versions are not checked.");
        match known.unloaded_count {
            0 => {}
            1 => text.push_str("\n\n1 advisory is not loaded, so it is not compared."),
            count => {
                let _ = write!(
                    text,
                    "\n\n{count} advisories are not loaded, so they are not compared."
                );
            }
        }
    }
    Some(text)
}

/// Appends `mark` to `marks`, after a separator when `marks` is not empty.
fn add_mark(marks: &mut String, mark: &str) {
    if !marks.is_empty() {
        marks.push_str(", ");
    }
    marks.push_str(mark);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::Cache;
    use crate::model::{
        AdvisorySeverity, Affected, Dependency, Ecosystem, RangeEvent, VersionInfo, Vulnerability,
    };
    use crate::osv::deferred;
    use crate::settings::Settings;

    const NOW: u64 = 1_000;
    /// The registry list of `requests`, newest first. `>1.12,<2.10` allows its last four entries.
    const LIST: [&str; 7] = [
        "3.0.0", "2.34.2", "2.10.0", "2.9.2", "2.9.1", "2.9.0rc1", "2.0.0",
    ];

    fn dependency(line: &str) -> Dependency {
        Ecosystem::PyPI
            .parse(line)
            .into_iter()
            .next()
            .expect("one dependency")
    }

    fn range_dependency() -> Dependency {
        dependency("requests>1.12,<2.10\n")
    }

    fn cache_with_list(versions: &[&str]) -> Cache {
        let mut cache = Cache::new(3_600);
        let info = VersionInfo {
            latest: versions.first().map(|text| (*text).to_owned()),
            versions: versions.iter().map(|text| (*text).to_owned()).collect(),
        };
        cache.put_version_info(Ecosystem::PyPI, "requests", info, NOW);
        cache
    }

    fn advisory(id: &str) -> Vulnerability {
        Vulnerability {
            id: id.to_owned(),
            severity: AdvisorySeverity::High,
            summary: "An old flaw".to_owned(),
            url: None,
        }
    }

    /// Stores the advisories of `requests 2.0.0`, each fixed at its version of `fixed_at`.
    fn store_advisories(cache: &mut Cache, advisories: &[(&str, &str)]) {
        let listed: Vec<Vulnerability> = advisories.iter().map(|(id, _)| advisory(id)).collect();
        cache.put_vulnerabilities(Ecosystem::PyPI, "requests", "2.0.0", listed, NOW);
        for (id, fixed_at) in advisories {
            let affected = vec![Affected {
                ecosystem: "PyPI".to_owned(),
                name: "requests".to_owned(),
                ranges: vec![vec![
                    RangeEvent::Introduced("0".to_owned()),
                    RangeEvent::Fixed((*fixed_at).to_owned()),
                ]],
                versions: Vec::new(),
            }];
            cache.put_affected(id, affected, NOW);
        }
    }

    fn history(dep: &Dependency, cache: &Cache, settings: &Settings) -> Option<String> {
        version_history(Ecosystem::PyPI, dep, cache, settings, NOW)
    }

    const BOUND_LINES: &str = "Versions after 2.0.0:\n\
- `3.0.0` — outside your bounds\n\
- `2.34.2` — outside your bounds\n\
- `2.10.0` — outside your bounds\n\
- `2.9.2` — allowed, latest allowed\n\
- `2.9.1` — allowed\n\
- `2.9.0rc1` — allowed, pre-release";

    #[test]
    fn lists_newer_releases_with_bound_marks() {
        let cache = cache_with_list(&LIST);
        assert_eq!(
            history(&range_dependency(), &cache, &Settings::default()).as_deref(),
            Some(BOUND_LINES)
        );
    }

    #[test]
    fn marks_the_releases_that_an_advisory_still_affects() {
        let mut cache = cache_with_list(&LIST);
        store_advisories(&mut cache, &[("GHSA-b", "2.9.2")]);
        let text = history(&range_dependency(), &cache, &Settings::default()).expect("a section");
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines.contains(&"- `2.9.1` — allowed, still affected: `GHSA-b`"),
            "{text}"
        );
        assert!(
            lines.contains(&"- `2.9.0rc1` — allowed, pre-release, still affected: `GHSA-b`"),
            "{text}"
        );
        assert!(
            lines.contains(&"- `2.9.2` — allowed, latest allowed"),
            "{text}"
        );
        assert!(lines.contains(&"- `3.0.0` — outside your bounds"), "{text}");
        assert!(
            text.ends_with("\n\nAdvisories of newer versions are not checked."),
            "{text}"
        );
    }

    #[test]
    fn three_ids_then_a_count() {
        let mut cache = cache_with_list(&LIST);
        store_advisories(
            &mut cache,
            &[
                ("GHSA-1", "3.0.0"),
                ("GHSA-2", "3.0.0"),
                ("GHSA-3", "3.0.0"),
                ("GHSA-4", "3.0.0"),
                ("GHSA-5", "3.0.0"),
            ],
        );
        let text = history(&range_dependency(), &cache, &Settings::default()).expect("a section");
        assert!(
            text.lines().any(|line| line
                == "- `2.9.2` — allowed, latest allowed, still affected: `GHSA-1`, `GHSA-2`, `GHSA-3`, +2"),
            "{text}"
        );
    }

    #[test]
    fn more_than_ten_releases_end_with_a_more_line() {
        let mut versions: Vec<String> =
            (1..=12).rev().map(|patch| format!("2.0.{patch}")).collect();
        versions.push("2.0.0".to_owned());
        let texts: Vec<&str> = versions.iter().map(String::as_str).collect();
        let cache = cache_with_list(&texts);
        let text = history(
            &dependency("requests>=2.0.0\n"),
            &cache,
            &Settings::default(),
        )
        .expect("a section");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "Versions after 2.0.0:");
        assert_eq!(
            lines.iter().filter(|line| line.starts_with("- `")).count(),
            10
        );
        assert_eq!(lines.last().copied(), Some("- … 2 more"));
    }

    #[test]
    fn no_newer_release_says_so() {
        let cache = cache_with_list(&["2.0.0"]);
        assert_eq!(
            history(&range_dependency(), &cache, &Settings::default()).as_deref(),
            Some("No version after 2.0.0.")
        );
    }

    #[test]
    fn a_dependency_without_requirement_has_no_bound_marks() {
        let cache = cache_with_list(&["3.0.0", "2.0.0"]);
        let mut dep = dependency("requests==2.0.0\n");
        dep.requirement = None;
        assert_eq!(
            history(&dep, &cache, &Settings::default()).as_deref(),
            Some("Versions after 2.0.0:\n- `3.0.0`")
        );
    }

    #[test]
    fn vulnerabilities_off_gives_no_security_mark_and_no_footer() {
        let mut cache = cache_with_list(&LIST);
        store_advisories(&mut cache, &[("GHSA-b", "2.9.2")]);
        let settings = Settings {
            vulnerabilities: false,
            ..Settings::default()
        };
        assert_eq!(
            history(&range_dependency(), &cache, &settings).as_deref(),
            Some(BOUND_LINES)
        );
    }

    #[test]
    fn advisories_without_details_add_the_not_loaded_line() {
        let mut cache = cache_with_list(&LIST);
        cache.put_vulnerabilities(
            Ecosystem::PyPI,
            "requests",
            "2.0.0",
            vec![deferred("GHSA-x")],
            NOW,
        );
        let text = history(&range_dependency(), &cache, &Settings::default()).expect("a section");
        assert!(
            text.ends_with(
                "\n\nAdvisories of newer versions are not checked.\n\n1 advisory is not loaded, so it is not compared."
            ),
            "{text}"
        );
        let mut many = cache_with_list(&LIST);
        many.put_vulnerabilities(
            Ecosystem::PyPI,
            "requests",
            "2.0.0",
            vec![deferred("GHSA-x"), deferred("GHSA-y")],
            NOW,
        );
        let text = history(&range_dependency(), &many, &Settings::default()).expect("a section");
        assert!(
            text.ends_with("\n\n2 advisories are not loaded, so they are not compared."),
            "{text}"
        );
    }

    #[test]
    fn an_id_with_a_backtick_stays_in_its_code_span() {
        let mut cache = cache_with_list(&LIST);
        store_advisories(&mut cache, &[("GHSA-`x", "2.9.2")]);
        let text = history(&range_dependency(), &cache, &Settings::default()).expect("a section");
        assert!(text.contains("still affected: `GHSA-'x`"), "{text}");
    }

    #[test]
    fn a_name_spelled_differently_finds_the_registry_list_and_the_advisories() {
        // The registry list is keyed by the normalized name, the vulnerability list by the written one.
        let mut cache = cache_with_list(&LIST);
        let listed = vec![advisory("GHSA-b")];
        cache.put_vulnerabilities(Ecosystem::PyPI, "Requests", "2.0.0", listed, NOW);
        let affected = vec![Affected {
            ecosystem: "PyPI".to_owned(),
            name: "requests".to_owned(),
            ranges: vec![vec![
                RangeEvent::Introduced("0".to_owned()),
                RangeEvent::Fixed("2.9.2".to_owned()),
            ]],
            versions: Vec::new(),
        }];
        cache.put_affected("GHSA-b", affected, NOW);
        let text = history(
            &dependency("Requests>1.12,<2.10\n"),
            &cache,
            &Settings::default(),
        )
        .expect("a section");
        assert!(
            text.contains("- `2.9.1` — allowed, still affected: `GHSA-b`"),
            "{text}"
        );
    }

    #[test]
    fn nothing_to_show_gives_none() {
        // No cached list.
        assert_eq!(
            history(
                &range_dependency(),
                &Cache::new(3_600),
                &Settings::default()
            ),
            None
        );
        // A declared version that names no registry version.
        let cache = cache_with_list(&LIST);
        let mut wildcard = dependency("requests==2.0.0\n");
        wildcard.version = "*".to_owned();
        wildcard.requirement = None;
        assert_eq!(history(&wildcard, &cache, &Settings::default()), None);
        // Cargo has no registry client, so it never has a list.
        let cargo = Ecosystem::Cargo
            .parse("[dependencies]\nserde = \"1.0.0\"\n")
            .into_iter()
            .next()
            .expect("one dependency");
        assert_eq!(
            version_history(Ecosystem::Cargo, &cargo, &cache, &Settings::default(), NOW),
            None
        );
    }
}
