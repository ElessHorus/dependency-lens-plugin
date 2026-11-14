//! Turns an analysis into editor decorations and problems for one manifest.

use crate::analysis::{Analysis, Entry, Status};
use crate::model::{AdvisorySeverity, Vulnerability};
use crate::osv::{is_deferred, is_placeholder};
use crate::text::to_range;
use openidea_plugin::{Decoration, Diagnostic, Range, Severity};
use std::cmp::Reverse;

/// Name of the decoration set that holds the version annotations of one manifest.
pub const DECORATION_SET: &str = "dependency-lens";

/// Separates the parts of one `after` text.
const PART_SEPARATOR: &str = " · ";
/// Source name of the problems this plugin publishes.
const DIAGNOSTIC_SOURCE: &str = "Dependency Lens";

/// Visual strength of an annotation. Variants are ordered from weakest to strongest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Tone {
    Muted,
    Info,
    Warning,
    Error,
}

impl Tone {
    /// The theme style name the IDE expects.
    fn style(self) -> &'static str {
        match self {
            Tone::Muted => "muted",
            Tone::Info => "info",
            Tone::Warning => "warning",
            Tone::Error => "error",
        }
    }
}

/// Editor decorations for every entry with a resolvable version range and something to show.
pub fn decorations(text: &str, analysis: &Analysis) -> Vec<Decoration> {
    analysis
        .entries
        .iter()
        .filter_map(|entry| {
            let range = to_range(text, entry.dependency.version_span)?;
            decoration_of(range, entry)
        })
        .collect()
}

/// One problem per entry with advisories, placed on the version range.
pub fn diagnostics(text: &str, analysis: &Analysis) -> Vec<Diagnostic> {
    analysis
        .entries
        .iter()
        .filter_map(|entry| {
            let range = to_range(text, entry.dependency.version_span)?;
            diagnostic_of(range, entry)
        })
        .collect()
}

/// How the advisories of one entry split up for display.
struct AdvisoryView<'a> {
    /// Advisories with a known severity, most severe first.
    known: Vec<&'a Vulnerability>,
    /// Advisories whose details are not loaded yet. They load by themselves, and their severity is unknown.
    waiting: Vec<&'a Vulnerability>,
    /// Advisories whose details load on request.
    deferred: Vec<&'a Vulnerability>,
}

impl<'a> AdvisoryView<'a> {
    fn of(vulnerabilities: &'a [Vulnerability]) -> Self {
        let mut view = AdvisoryView {
            known: Vec::new(),
            waiting: Vec::new(),
            deferred: Vec::new(),
        };
        for vulnerability in vulnerabilities {
            if is_deferred(vulnerability) {
                view.deferred.push(vulnerability);
            } else if is_placeholder(vulnerability) {
                view.waiting.push(vulnerability);
            } else {
                view.known.push(vulnerability);
            }
        }
        // `sort_by_key` is stable, so advisories of equal severity keep their order.
        view.known
            .sort_by_key(|vulnerability| Reverse(vulnerability.severity));
        view
    }

    /// Every advisory of the entry, loaded or not.
    fn total(&self) -> usize {
        self.known.len() + self.waiting.len() + self.deferred.len()
    }

    /// The worst known severity, or `None` when no advisory has loaded.
    fn worst(&self) -> Option<AdvisorySeverity> {
        self.known
            .first()
            .map(|vulnerability| vulnerability.severity)
    }
}

/// Builds the decoration of one entry, or `None` when it has nothing to show.
fn decoration_of(range: Range, entry: &Entry) -> Option<Decoration> {
    let parts: Vec<(String, Tone)> = status_part(&entry.status)
        .into_iter()
        .chain(vulnerability_part(&AdvisoryView::of(
            &entry.vulnerabilities,
        )))
        .collect();
    // The strongest tone of the parts sets the style, since `Tone` orders by strength.
    let tone = parts.iter().map(|(_, tone)| *tone).max()?;
    let after = parts
        .iter()
        .map(|(text, _)| text.as_str())
        .collect::<Vec<_>>()
        .join(PART_SEPARATOR);
    Some(Decoration {
        range,
        style: tone.style().to_owned(),
        hover: Some(hover_of(entry)),
        after: Some(after),
    })
}

/// The version part of the `after` text, or `None` when the status shows no version.
fn status_part(status: &Status) -> Option<(String, Tone)> {
    match status {
        Status::UpToDate => Some(("✓".to_owned(), Tone::Muted)),
        Status::Outdated { latest } => Some((format!("→ {latest}"), Tone::Info)),
        Status::Pending => Some(("…".to_owned(), Tone::Muted)),
        Status::Unknown(_) => Some(("?".to_owned(), Tone::Muted)),
        Status::NotChecked => None,
    }
}

/// The vulnerability part of the `after` text, or `None` without advisories.
fn vulnerability_part(view: &AdvisoryView<'_>) -> Option<(String, Tone)> {
    let count = view.total();
    if count == 0 {
        return None;
    }
    let text = if count == 1 {
        "⚠ 1 vulnerability".to_owned()
    } else {
        format!("⚠ {count} vulnerabilities")
    };
    let tone = if view.worst() >= Some(AdvisorySeverity::High) {
        Tone::Error
    } else {
        Tone::Warning
    };
    Some((text, tone))
}

/// Builds the Markdown hover: one block per fact, joined by blank lines.
fn hover_of(entry: &Entry) -> String {
    let version = entry
        .checked_version
        .as_deref()
        .unwrap_or(&entry.dependency.version);
    let mut blocks = vec![format!("**{}** {version}", entry.dependency.name)];
    match &entry.status {
        Status::Outdated { latest } => blocks.push(format!("Latest version: {latest}")),
        Status::Unknown(reason) => blocks.push(format!("Could not check: {reason}")),
        Status::UpToDate | Status::Pending | Status::NotChecked => {}
    }
    let view = AdvisoryView::of(&entry.vulnerabilities);
    if view.total() > 0 {
        if let Some(checked_version) = &entry.checked_version {
            blocks.push(format!("Checked version: {checked_version}"));
        }
        let mut advisory_lines: Vec<String> = view
            .known
            .iter()
            .chain(&view.waiting)
            .map(|vulnerability| advisory_line(vulnerability))
            .collect();
        if !view.deferred.is_empty() {
            advisory_lines.push(format!(
                "- {} more not loaded. Run \"Dependency Lens: Load all vulnerabilities\" to load them.",
                view.deferred.len()
            ));
        }
        blocks.push(advisory_lines.join("\n"));
    }
    blocks.join("\n\n")
}

/// Formats one advisory as a Markdown list item, with a link when it has a URL.
fn advisory_line(vulnerability: &Vulnerability) -> String {
    let severity = if is_placeholder(vulnerability) {
        "severity unknown"
    } else {
        severity_label(vulnerability.severity)
    };
    match &vulnerability.url {
        Some(url) => format!(
            "- [{}]({url}) ({severity}) – {}",
            vulnerability.id, vulnerability.summary
        ),
        None => format!(
            "- {} ({severity}) – {}",
            vulnerability.id, vulnerability.summary
        ),
    }
}

/// Builds the problem of one entry, or `None` when it has no advisories.
fn diagnostic_of(range: Range, entry: &Entry) -> Option<Diagnostic> {
    let view = AdvisoryView::of(&entry.vulnerabilities);
    // The code names the worst loaded advisory, else the first one that waits for its details.
    let first = view
        .known
        .first()
        .or_else(|| view.waiting.first())
        .or_else(|| view.deferred.first())?;
    let worst = view.worst();
    // Without a loaded advisory the severity is unknown, so the problem is a warning.
    let severity = match worst {
        Some(AdvisorySeverity::Critical | AdvisorySeverity::High) => Severity::Error,
        Some(AdvisorySeverity::Low) => Severity::Info,
        Some(AdvisorySeverity::Medium) | None => Severity::Warning,
    };
    let version = entry
        .checked_version
        .as_deref()
        .unwrap_or(&entry.dependency.version);
    let count = view.total();
    let noun = if count == 1 {
        "1 known vulnerability".to_owned()
    } else {
        format!("{count} known vulnerabilities")
    };
    let severity_text = worst.map_or("details not loaded", severity_label);
    let message = format!(
        "{} {version}: {noun} ({severity_text})",
        entry.dependency.name
    );
    let mut diagnostic = Diagnostic::new(range, severity, message).code(first.id.clone());
    diagnostic.source = Some(DIAGNOSTIC_SOURCE.to_owned());
    Some(diagnostic)
}

/// The English label of a severity, as shown to the user.
fn severity_label(severity: AdvisorySeverity) -> &'static str {
    match severity {
        AdvisorySeverity::Critical => "Critical",
        AdvisorySeverity::High => "High",
        AdvisorySeverity::Medium => "Medium",
        AdvisorySeverity::Low => "Low",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Dependency, Span};
    use openidea_plugin::{Document, Position};

    /// A dependency named `name` whose version text sits at `version_span`.
    fn dependency(name: &str, version: &str, version_span: Span) -> Dependency {
        Dependency {
            name: name.to_owned(),
            version: version.to_owned(),
            name_span: Span {
                line: version_span.line,
                line_start: 0,
                line_end: 0,
            },
            version_span,
            dev: false,
            optional: false,
            has_additional_version_constraints: false,
        }
    }

    /// A byte span of `len` bytes starting at `start` on line `line`.
    fn span(line: u32, start: u32, len: u32) -> Span {
        Span {
            line,
            line_start: start,
            line_end: start + len,
        }
    }

    fn vulnerability(id: &str, severity: AdvisorySeverity, url: Option<&str>) -> Vulnerability {
        Vulnerability {
            id: id.to_owned(),
            severity,
            summary: format!("Summary of {id}"),
            url: url.map(str::to_owned),
        }
    }

    /// An analysis holding one `serde` entry on line 1 of `SERDE_TEXT`.
    fn serde_entry(
        status: Status,
        vulnerabilities: Vec<Vulnerability>,
        checked_version: Option<&str>,
    ) -> Analysis {
        Analysis {
            entries: vec![Entry {
                dependency: dependency("serde", "1.0.0", span(1, 9, 5)),
                status,
                vulnerabilities,
                checked_version: checked_version.map(str::to_owned),
            }],
            pending: 0,
        }
    }

    const SERDE_TEXT: &str = "[dependencies]\nserde = \"1.0.0\"\n";

    #[test]
    fn decoration_table() {
        let high = vulnerability("GHSA-high", AdvisorySeverity::High, None);
        let medium_link = vulnerability(
            "GHSA-medium",
            AdvisorySeverity::Medium,
            Some("https://osv.dev/vulnerability/GHSA-medium"),
        );
        let low = vulnerability("GHSA-low", AdvisorySeverity::Low, None);
        let critical = vulnerability("GHSA-critical", AdvisorySeverity::Critical, None);
        let medium_two = [
            vulnerability("GHSA-medium-a", AdvisorySeverity::Medium, None),
            vulnerability("GHSA-medium-b", AdvisorySeverity::Medium, None),
        ];
        let outdated = || Status::Outdated {
            latest: "2.0.0".to_owned(),
        };
        // (status, vulnerabilities, checked version, expected after, expected style, expected hover)
        type DecorationCase = (
            Status,
            Vec<Vulnerability>,
            Option<&'static str>,
            Option<&'static str>,
            Option<&'static str>,
            &'static str,
        );
        let cases: Vec<DecorationCase> = vec![
            (
                Status::UpToDate,
                vec![],
                Some("1.0.0"),
                Some("✓"),
                Some("muted"),
                "**serde** 1.0.0",
            ),
            (
                outdated(),
                vec![],
                Some("1.0.0"),
                Some("→ 2.0.0"),
                Some("info"),
                "**serde** 1.0.0\n\nLatest version: 2.0.0",
            ),
            (
                Status::Pending,
                vec![],
                Some("1.0.0"),
                Some("…"),
                Some("muted"),
                "**serde** 1.0.0",
            ),
            (
                Status::Unknown("OSV: HTTP 500".to_owned()),
                vec![],
                Some("1.0.0"),
                Some("?"),
                Some("muted"),
                "**serde** 1.0.0\n\nCould not check: OSV: HTTP 500",
            ),
            (Status::NotChecked, vec![], Some("1.0.0"), None, None, ""),
            (
                Status::NotChecked,
                vec![high.clone()],
                Some("1.0.0"),
                Some("⚠ 1 vulnerability"),
                Some("error"),
                "**serde** 1.0.0\n\nChecked version: 1.0.0\n\n- GHSA-high (High) – Summary of GHSA-high",
            ),
            (
                Status::NotChecked,
                vec![low.clone()],
                Some("1.0.0"),
                Some("⚠ 1 vulnerability"),
                Some("warning"),
                "**serde** 1.0.0\n\nChecked version: 1.0.0\n\n- GHSA-low (Low) – Summary of GHSA-low",
            ),
            (
                Status::NotChecked,
                vec![critical],
                Some("1.0.0"),
                Some("⚠ 1 vulnerability"),
                Some("error"),
                "**serde** 1.0.0\n\nChecked version: 1.0.0\n\n- GHSA-critical (Critical) – Summary of GHSA-critical",
            ),
            (
                Status::NotChecked,
                medium_two.to_vec(),
                Some("1.0.0"),
                Some("⚠ 2 vulnerabilities"),
                Some("warning"),
                "**serde** 1.0.0\n\nChecked version: 1.0.0\n\n- GHSA-medium-a (Medium) – Summary of GHSA-medium-a\n- GHSA-medium-b (Medium) – Summary of GHSA-medium-b",
            ),
            (
                Status::UpToDate,
                vec![medium_link.clone()],
                Some("1.0.0"),
                Some("✓ · ⚠ 1 vulnerability"),
                Some("warning"),
                "**serde** 1.0.0\n\nChecked version: 1.0.0\n\n- [GHSA-medium](https://osv.dev/vulnerability/GHSA-medium) (Medium) – Summary of GHSA-medium",
            ),
            (
                outdated(),
                vec![high.clone(), high.clone()],
                Some("1.0.0"),
                Some("→ 2.0.0 · ⚠ 2 vulnerabilities"),
                Some("error"),
                "**serde** 1.0.0\n\nLatest version: 2.0.0\n\nChecked version: 1.0.0\n\n- GHSA-high (High) – Summary of GHSA-high\n- GHSA-high (High) – Summary of GHSA-high",
            ),
            (
                Status::Unknown("OSV: timeout".to_owned()),
                vec![medium_link.clone()],
                None,
                Some("? · ⚠ 1 vulnerability"),
                Some("warning"),
                "**serde** 1.0.0\n\nCould not check: OSV: timeout\n\n- [GHSA-medium](https://osv.dev/vulnerability/GHSA-medium) (Medium) – Summary of GHSA-medium",
            ),
        ];
        for (status, vulnerabilities, checked_version, after, style, hover) in cases {
            let analysis = serde_entry(status.clone(), vulnerabilities, checked_version);
            let decorations = decorations(SERDE_TEXT, &analysis);
            match after {
                None => assert!(decorations.is_empty(), "{status:?} should not decorate"),
                Some(after) => {
                    assert_eq!(decorations.len(), 1, "{status:?}");
                    let decoration = &decorations[0];
                    assert_eq!(decoration.after.as_deref(), Some(after), "{status:?}");
                    assert_eq!(Some(decoration.style.as_str()), style, "{status:?}");
                    assert_eq!(decoration.hover.as_deref(), Some(hover), "{status:?}");
                    assert_eq!(
                        decoration.range,
                        Range::new(Position::new(1, 9), Position::new(1, 14))
                    );
                }
            }
        }
    }

    #[test]
    fn wildcard_hover_shows_declared_version_when_nothing_was_checked() {
        let analysis = Analysis {
            entries: vec![Entry {
                dependency: dependency("serde", "*", span(1, 9, 1)),
                status: Status::Unknown("OSV: HTTP 500".to_owned()),
                vulnerabilities: vec![],
                checked_version: None,
            }],
            pending: 0,
        };
        let decorations = decorations("[dependencies]\nserde = \"*\"\n", &analysis);
        assert_eq!(
            decorations[0].hover.as_deref(),
            Some("**serde** *\n\nCould not check: OSV: HTTP 500")
        );
    }

    #[test]
    fn decorations_skip_entries_whose_range_does_not_resolve() {
        let analysis = Analysis {
            entries: vec![Entry {
                dependency: dependency("serde", "1.0.0", span(7, 0, 5)),
                status: Status::UpToDate,
                vulnerabilities: vec![],
                checked_version: Some("1.0.0".to_owned()),
            }],
            pending: 0,
        };
        assert!(decorations(SERDE_TEXT, &analysis).is_empty());
    }

    #[test]
    fn decoration_range_counts_utf16_units_after_non_ascii_text() {
        // "é" is 2 bytes and 1 UTF-16 unit; "🦀" is 4 bytes and 2 units.
        let text = "é🦀 = \"1.0.0\"\n";
        let analysis = Analysis {
            entries: vec![Entry {
                dependency: dependency("serde", "1.0.0", span(0, 10, 5)),
                status: Status::UpToDate,
                vulnerabilities: vec![],
                checked_version: Some("1.0.0".to_owned()),
            }],
            pending: 0,
        };
        let decorations = decorations(text, &analysis);
        let document = Document {
            version: 1,
            text: text.to_owned(),
        };
        assert_eq!(document.text_in(decorations[0].range), Some("1.0.0"));
    }

    #[test]
    fn diagnostic_table() {
        let high = vulnerability("GHSA-high", AdvisorySeverity::High, None);
        let medium = vulnerability("GHSA-medium", AdvisorySeverity::Medium, None);
        let low = vulnerability("GHSA-low", AdvisorySeverity::Low, None);
        let critical = vulnerability("GHSA-critical", AdvisorySeverity::Critical, None);
        // (vulnerabilities, expected severity, expected message, expected code)
        let cases: Vec<(Vec<Vulnerability>, Severity, &str, &str)> = vec![
            (
                vec![high.clone()],
                Severity::Error,
                "serde 1.0.0: 1 known vulnerability (High)",
                "GHSA-high",
            ),
            (
                vec![critical],
                Severity::Error,
                "serde 1.0.0: 1 known vulnerability (Critical)",
                "GHSA-critical",
            ),
            (
                vec![medium.clone(), medium.clone()],
                Severity::Warning,
                "serde 1.0.0: 2 known vulnerabilities (Medium)",
                "GHSA-medium",
            ),
            (
                vec![low],
                Severity::Info,
                "serde 1.0.0: 1 known vulnerability (Low)",
                "GHSA-low",
            ),
            (
                vec![medium, high],
                Severity::Error,
                "serde 1.0.0: 2 known vulnerabilities (High)",
                "GHSA-high",
            ),
        ];
        for (vulnerabilities, severity, message, code) in cases {
            let analysis = serde_entry(Status::NotChecked, vulnerabilities, Some("1.0.0"));
            let diagnostics = diagnostics(SERDE_TEXT, &analysis);
            assert_eq!(diagnostics.len(), 1, "{message}");
            let diagnostic = &diagnostics[0];
            assert_eq!(diagnostic.severity, severity, "{message}");
            assert_eq!(diagnostic.message, message);
            assert_eq!(diagnostic.code.as_deref(), Some(code));
            assert_eq!(diagnostic.source.as_deref(), Some("Dependency Lens"));
            assert!(!diagnostic.unnecessary);
            assert!(!diagnostic.deprecated);
            assert!(diagnostic.related.is_empty());
            assert_eq!(
                diagnostic.range,
                Range::new(Position::new(1, 9), Position::new(1, 14))
            );
        }
    }

    #[test]
    fn diagnostic_message_falls_back_to_declared_version() {
        let analysis = serde_entry(
            Status::NotChecked,
            vec![vulnerability("GHSA-high", AdvisorySeverity::High, None)],
            None,
        );
        let diagnostics = diagnostics(SERDE_TEXT, &analysis);
        assert_eq!(
            diagnostics[0].message,
            "serde 1.0.0: 1 known vulnerability (High)"
        );
    }

    #[test]
    fn no_diagnostic_without_advisories_or_resolvable_range() {
        let clean = serde_entry(Status::UpToDate, vec![], Some("1.0.0"));
        assert!(diagnostics(SERDE_TEXT, &clean).is_empty());

        let unresolved = Analysis {
            entries: vec![Entry {
                dependency: dependency("serde", "1.0.0", span(7, 0, 5)),
                status: Status::NotChecked,
                vulnerabilities: vec![vulnerability("GHSA-high", AdvisorySeverity::High, None)],
                checked_version: Some("1.0.0".to_owned()),
            }],
            pending: 0,
        };
        assert!(diagnostics(SERDE_TEXT, &unresolved).is_empty());
    }

    #[test]
    fn diagnostics_keep_manifest_order_across_entries() {
        let analysis = Analysis {
            entries: vec![
                Entry {
                    dependency: dependency("anyhow", "1.0.0", span(2, 10, 5)),
                    status: Status::NotChecked,
                    vulnerabilities: vec![vulnerability("GHSA-a", AdvisorySeverity::Low, None)],
                    checked_version: Some("1.0.0".to_owned()),
                },
                Entry {
                    dependency: dependency("serde", "1.0.0", span(1, 9, 5)),
                    status: Status::NotChecked,
                    vulnerabilities: vec![vulnerability("GHSA-s", AdvisorySeverity::High, None)],
                    checked_version: Some("1.0.0".to_owned()),
                },
            ],
            pending: 0,
        };
        let text = "[dependencies]\nserde = \"1.0.0\"\nanyhow = \"1.0.0\"\n";
        let messages: Vec<String> = diagnostics(text, &analysis)
            .into_iter()
            .map(|diagnostic| diagnostic.message)
            .collect();
        assert_eq!(
            messages,
            [
                "anyhow 1.0.0: 1 known vulnerability (Low)",
                "serde 1.0.0: 1 known vulnerability (High)",
            ]
        );
    }

    /// A deferred advisory: its details wait for a request from the user.
    fn deferred_vulnerability(id: &str) -> Vulnerability {
        Vulnerability {
            id: id.to_owned(),
            severity: AdvisorySeverity::Medium,
            summary: crate::osv::DEFERRED_SUMMARY.to_owned(),
            url: None,
        }
    }

    /// A retry placeholder: its details are not loaded yet.
    fn placeholder_vulnerability(id: &str) -> Vulnerability {
        Vulnerability {
            summary: crate::osv::PLACEHOLDER_SUMMARY.to_owned(),
            ..deferred_vulnerability(id)
        }
    }

    #[test]
    fn deferred_advisories_count_in_the_total_and_are_summed_up_in_one_hover_line() {
        let mut vulnerabilities = vec![
            vulnerability("GHSA-high", AdvisorySeverity::High, None),
            vulnerability("GHSA-low", AdvisorySeverity::Low, None),
        ];
        vulnerabilities
            .extend((0..5).map(|number| deferred_vulnerability(&format!("GHSA-d{number}"))));
        let analysis = serde_entry(Status::NotChecked, vulnerabilities, Some("1.0.0"));

        let decoration = &decorations(SERDE_TEXT, &analysis)[0];
        assert_eq!(decoration.after.as_deref(), Some("⚠ 7 vulnerabilities"));
        assert_eq!(decoration.style, "error");
        let hover = decoration.hover.as_deref().unwrap();
        assert!(hover.contains("GHSA-high"), "{hover}");
        assert!(!hover.contains("GHSA-d0"), "{hover}");
        assert!(
            hover.contains("5 more not loaded") && hover.contains("Load all vulnerabilities"),
            "{hover}"
        );

        let problem = &diagnostics(SERDE_TEXT, &analysis)[0];
        assert!(
            problem.message.contains("7 known vulnerabilities (High)"),
            "{}",
            problem.message
        );
        assert_eq!(problem.code.as_deref(), Some("GHSA-high"));
    }

    #[test]
    fn only_deferred_advisories_warn_without_naming_a_severity() {
        let vulnerabilities = vec![
            deferred_vulnerability("GHSA-d0"),
            deferred_vulnerability("GHSA-d1"),
        ];
        let analysis = serde_entry(Status::NotChecked, vulnerabilities, Some("1.0.0"));

        let decoration = &decorations(SERDE_TEXT, &analysis)[0];
        assert_eq!(decoration.after.as_deref(), Some("⚠ 2 vulnerabilities"));
        assert_eq!(decoration.style, "warning");

        let problem = &diagnostics(SERDE_TEXT, &analysis)[0];
        assert_eq!(problem.severity, Severity::Warning);
        assert!(
            problem
                .message
                .contains("2 known vulnerabilities (details not loaded)"),
            "{}",
            problem.message
        );
        assert_eq!(problem.code.as_deref(), Some("GHSA-d0"));
    }

    #[test]
    fn a_placeholder_shows_an_unknown_severity_and_never_the_worst_one() {
        let vulnerabilities = vec![
            placeholder_vulnerability("GHSA-wait"),
            vulnerability("GHSA-low", AdvisorySeverity::Low, None),
        ];
        let analysis = serde_entry(Status::NotChecked, vulnerabilities, Some("1.0.0"));
        let hover = decorations(SERDE_TEXT, &analysis)[0].hover.clone().unwrap();
        assert!(hover.contains("GHSA-wait (severity unknown)"), "{hover}");
        let problem = &diagnostics(SERDE_TEXT, &analysis)[0];
        // The only known severity is Low, so the problem is informational.
        assert_eq!(problem.severity, Severity::Info);
        assert!(problem.message.contains("(Low)"), "{}", problem.message);
    }
}
