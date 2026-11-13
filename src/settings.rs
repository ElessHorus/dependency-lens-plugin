//! User settings that shape one analysis run.

use crate::model::{AdvisorySeverity, Ecosystem};
use std::collections::BTreeSet;

/// Settings that control which dependencies are analyzed and which advisories are shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Whether to query OSV.dev for advisories.
    pub vulnerabilities: bool,
    /// Lowest advisory severity that is reported.
    pub minimum_severity: AdvisorySeverity,
    /// Package names that are skipped.
    pub ignore: Vec<String>,
    /// Ecosystems that are analyzed.
    pub enabled: BTreeSet<Ecosystem>,
    /// Lifetime of cached registry and OSV answers, in seconds.
    pub cache_ttl_secs: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            vulnerabilities: true,
            minimum_severity: AdvisorySeverity::Low,
            ignore: Vec::new(),
            enabled: [
                Ecosystem::Cargo,
                Ecosystem::Npm,
                Ecosystem::PyPI,
                Ecosystem::Go,
                Ecosystem::Packagist,
                Ecosystem::Pub,
                Ecosystem::NuGet,
                Ecosystem::RubyGems,
                Ecosystem::Maven,
            ]
            .into_iter()
            .collect(),
            cache_ttl_secs: 3600,
        }
    }
}

impl Settings {
    /// Returns `true` when dependencies of `eco` are analyzed.
    pub fn is_enabled(&self, eco: Ecosystem) -> bool {
        self.enabled.contains(&eco)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_enable_every_ecosystem_with_one_hour_cache() {
        let settings = Settings::default();
        assert!(settings.vulnerabilities);
        assert_eq!(settings.minimum_severity, AdvisorySeverity::Low);
        assert!(settings.ignore.is_empty());
        assert_eq!(settings.enabled.len(), 9);
        assert!(settings.is_enabled(Ecosystem::Maven));
        assert_eq!(settings.cache_ttl_secs, 3600);
    }

    #[test]
    fn disabled_ecosystem_is_not_enabled() {
        let mut settings = Settings::default();
        settings.enabled.remove(&Ecosystem::Cargo);
        assert!(!settings.is_enabled(Ecosystem::Cargo));
        assert!(settings.is_enabled(Ecosystem::Npm));
    }
}
