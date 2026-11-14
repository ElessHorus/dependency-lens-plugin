//! Turns an analysis into editor decorations and problems for one manifest.

use crate::analysis::{Analysis, Entry, Status};
use crate::model::{AdvisorySeverity, Vulnerability};
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

/// Builds the decoration of one entry, or `None` when it has nothing to show.
fn decoration_of(range: Range, entry: &Entry) -> Option<Decoration> {
    let parts: Vec<(String, Tone)> = status_part(&entry.status)
        .into_iter()
        .chain(vulnerability_part(&entry.vulnerabilities))
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
fn vulnerability_part(vulnerabilities: &[Vulnerability]) -> Option<(String, Tone)> {
    let worst = vulnerabilities
        .iter()
        .map(|vulnerability| vulnerability.severity)
        .max()?;
    let count = vulnerabilities.len();
    let text = if count == 1 {
        "⚠ 1 vulnerability".to_owned()
    } else {
        format!("⚠ {count} vulnerabilities")
    };
    let tone = if worst >= AdvisorySeverity::High {
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
    if !entry.vulnerabilities.is_empty() {
        if let Some(checked_version) = &entry.checked_version {
            blocks.push(format!("Checked version: {checked_version}"));
        }
        let advisory_lines: Vec<String> = sorted_by_severity(&entry.vulnerabilities)
            .into_iter()
            .map(advisory_line)
            .collect();
        blocks.push(advisory_lines.join("\n"));
    }
    blocks.join("\n\n")
}

/// Formats one advisory as a Markdown list item, with a link when it has a URL.
fn advisory_line(vulnerability: &Vulnerability) -> String {
    let severity = severity_label(vulnerability.severity);
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
    let sorted = sorted_by_severity(&entry.vulnerabilities);
    // The first advisory is the worst one, because the list is sorted worst first.
    let first = sorted.first()?;
    let worst = first.severity;
    let severity = match worst {
        AdvisorySeverity::Critical | AdvisorySeverity::High => Severity::Error,
        AdvisorySeverity::Medium => Severity::Warning,
        AdvisorySeverity::Low => Severity::Info,
    };
    let version = entry
        .checked_version
        .as_deref()
        .unwrap_or(&entry.dependency.version);
    let count = sorted.len();
    let noun = if count == 1 {
        "1 known vulnerability".to_owned()
    } else {
        format!("{count} known vulnerabilities")
    };
    let message = format!(
        "{} {version}: {noun} ({})",
        entry.dependency.name,
        severity_label(worst)
    );
    let mut diagnostic = Diagnostic::new(range, severity, message).code(first.id.clone());
    diagnostic.source = Some(DIAGNOSTIC_SOURCE.to_owned());
    Some(diagnostic)
}

/// Returns the advisories with the most severe first; equal severities keep their order.
fn sorted_by_severity(vulnerabilities: &[Vulnerability]) -> Vec<&Vulnerability> {
    let mut sorted: Vec<&Vulnerability> = vulnerabilities.iter().collect();
    // `sort_by_key` is stable, so advisories of equal severity keep their order.
    sorted.sort_by_key(|vulnerability| Reverse(vulnerability.severity));
    sorted
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
}
