//! User settings that shape one analysis run.

use crate::model::{AdvisorySeverity, Ecosystem};
use openidea_plugin::host;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet};

/// Largest cache lifetime that is accepted, in seconds (one week).
const MAX_CACHE_TTL_SECS: u64 = 604_800;

/// Severity names of the `minimumSeverity` setting, matched case-insensitively.
const SEVERITY_NAMES: [(&str, AdvisorySeverity); 4] = [
    ("low", AdvisorySeverity::Low),
    ("medium", AdvisorySeverity::Medium),
    ("high", AdvisorySeverity::High),
    ("critical", AdvisorySeverity::Critical),
];

/// Settings that control which dependencies are analyzed and which advisories are shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Whether to query OSV.dev for advisories.
    pub vulnerabilities: bool,
    /// Whether an outdated dependency gets an informational problem. The problem
    /// carries the quick fix in the hover, because the editor lists fixes per problem.
    pub outdated_problems: bool,
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
            outdated_problems: true,
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

    /// Returns the `ignore` names in the normal form of `eco`, ready for set lookups.
    ///
    /// A dependency is ignored when its own normal-form name is in the set.
    pub fn ignored_packages(&self, eco: Ecosystem) -> HashSet<Cow<'_, str>> {
        self.ignore
            .iter()
            .map(|entry| eco.normalize_package(entry))
            .collect()
    }

    /// Reads the settings from the host. See [`Settings::from_lookup`].
    pub fn from_host() -> Settings {
        Settings::from_lookup(host::setting)
    }

    /// Builds the settings from `lookup`, which returns the raw JSON text of one setting.
    ///
    /// Each missing or invalid value takes the default of the settings schema. A value
    /// with the wrong JSON type is invalid. Keys are flat, such as `ecosystems.pypi.enabled`.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Settings {
        let defaults = Settings::default();
        // Each key is parsed once and read as the type it needs. Invalid JSON reads as missing.
        let value_of =
            |key: &str| lookup(key).and_then(|raw| serde_json::from_str::<Value>(&raw).ok());
        let ignore = match value_of("ignore") {
            Some(Value::Array(items)) => items
                .into_iter()
                .filter_map(|item| match item {
                    Value::String(name) => Some(name),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        let enabled = Ecosystem::ALL
            .into_iter()
            .filter(|eco| {
                let key = format!("ecosystems.{}.enabled", eco.settings_id());
                value_of(&key)
                    .and_then(|value| value.as_bool())
                    .unwrap_or(true)
            })
            .collect();
        Settings {
            vulnerabilities: value_of("vulnerabilities")
                .and_then(|value| value.as_bool())
                .unwrap_or(defaults.vulnerabilities),
            outdated_problems: value_of("outdatedProblems")
                .and_then(|value| value.as_bool())
                .unwrap_or(defaults.outdated_problems),
            minimum_severity: value_of("minimumSeverity")
                .as_ref()
                .and_then(Value::as_str)
                .and_then(severity_from_name)
                .unwrap_or(defaults.minimum_severity),
            ignore,
            enabled,
            cache_ttl_secs: value_of("cacheTtlSeconds")
                .and_then(|value| cache_ttl_from(&value))
                .unwrap_or(defaults.cache_ttl_secs),
        }
    }
}

/// Returns the severity named `name`, ignoring ASCII case.
fn severity_from_name(name: &str) -> Option<AdvisorySeverity> {
    SEVERITY_NAMES
        .iter()
        .find(|(known_name, _)| known_name.eq_ignore_ascii_case(name))
        .map(|(_, severity)| *severity)
}

/// Reads a cache lifetime: a JSON number with no fraction and no sign, clamped to one week.
fn cache_ttl_from(value: &Value) -> Option<u64> {
    // A float that is whole, such as `60.0`, counts as an integer. Huge values saturate and are clamped.
    let seconds = value
        .as_f64()
        .filter(|seconds| seconds.fract() == 0.0 && *seconds >= 0.0)?;
    Some((seconds as u64).min(MAX_CACHE_TTL_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn defaults_enable_every_ecosystem_with_one_hour_cache() {
        let settings = Settings::default();
        assert!(settings.vulnerabilities);
        assert_eq!(settings.minimum_severity, AdvisorySeverity::Low);
        assert!(settings.ignore.is_empty());
        assert_eq!(settings.enabled.len(), 9);
        assert!(settings.is_enabled(Ecosystem::Maven));
        assert_eq!(settings.cache_ttl_secs, 3600);
        assert!(settings.outdated_problems);
    }

    #[test]
    fn outdated_problems_must_be_a_json_bool() {
        assert!(settings_from(&[("outdatedProblems", "\"false\"")]).outdated_problems);
        assert!(!settings_from(&[("outdatedProblems", "false")]).outdated_problems);
    }

    #[test]
    fn disabled_ecosystem_is_not_enabled() {
        let mut settings = Settings::default();
        settings.enabled.remove(&Ecosystem::Cargo);
        assert!(!settings.is_enabled(Ecosystem::Cargo));
        assert!(settings.is_enabled(Ecosystem::Npm));
    }

    /// Builds settings from `(key, raw JSON)` pairs. A key without a pair is missing.
    fn settings_from(pairs: &[(&str, &str)]) -> Settings {
        let values: HashMap<&str, &str> = pairs.iter().copied().collect();
        Settings::from_lookup(|key| values.get(key).map(|raw| (*raw).to_owned()))
    }

    #[test]
    fn empty_lookup_gives_the_defaults() {
        assert_eq!(settings_from(&[]), Settings::default());
    }

    #[test]
    fn vulnerabilities_must_be_a_json_bool() {
        assert!(settings_from(&[("vulnerabilities", "\"false\"")]).vulnerabilities);
        assert!(!settings_from(&[("vulnerabilities", "false")]).vulnerabilities);
    }

    #[test]
    fn minimum_severity_is_case_insensitive_and_falls_back_to_low() {
        let high = settings_from(&[("minimumSeverity", "\"HIGH\"")]);
        assert_eq!(high.minimum_severity, AdvisorySeverity::High);
        let unknown = settings_from(&[("minimumSeverity", "\"urgent\"")]);
        assert_eq!(unknown.minimum_severity, AdvisorySeverity::Low);
    }

    #[test]
    fn ignored_cargo_names_match_any_spelling() {
        for entry in ["rand-core", "Rand_Core"] {
            let settings = Settings {
                ignore: vec![entry.to_owned()],
                ..Settings::default()
            };
            assert!(
                settings
                    .ignored_packages(Ecosystem::Cargo)
                    .contains("rand_core"),
                "{entry}"
            );
        }
    }

    #[test]
    fn ignore_keeps_only_string_elements_of_an_array() {
        let mixed = settings_from(&[("ignore", r#"["serde", 3, "left-pad"]"#)]);
        assert_eq!(mixed.ignore, ["serde", "left-pad"]);
        let not_an_array = settings_from(&[("ignore", r#""serde""#)]);
        assert!(not_an_array.ignore.is_empty());
    }

    #[test]
    fn disabling_pypi_keeps_the_other_eight_ecosystems() {
        let settings = settings_from(&[("ecosystems.pypi.enabled", "false")]);
        assert_eq!(settings.enabled.len(), 8);
        assert!(!settings.is_enabled(Ecosystem::PyPI));
    }

    #[test]
    fn disabling_all_nine_ecosystems_leaves_none_enabled() {
        let keys: Vec<String> = Ecosystem::ALL
            .iter()
            .map(|eco| format!("ecosystems.{}.enabled", eco.settings_id()))
            .collect();
        let pairs: Vec<(&str, &str)> = keys.iter().map(|key| (key.as_str(), "false")).collect();
        assert!(settings_from(&pairs).enabled.is_empty());
    }

    #[test]
    fn cache_ttl_accepts_non_negative_integers_and_clamps_to_one_week() {
        assert_eq!(
            settings_from(&[("cacheTtlSeconds", "60")]).cache_ttl_secs,
            60
        );
        assert_eq!(settings_from(&[("cacheTtlSeconds", "0")]).cache_ttl_secs, 0);
        assert_eq!(
            settings_from(&[("cacheTtlSeconds", "60.0")]).cache_ttl_secs,
            60
        );
        assert_eq!(
            settings_from(&[("cacheTtlSeconds", "999999999")]).cache_ttl_secs,
            604_800
        );
    }

    #[test]
    fn cache_ttl_rejects_negative_fractional_and_non_numbers() {
        for raw in ["-5", "1.5", "\"x\""] {
            assert_eq!(
                settings_from(&[("cacheTtlSeconds", raw)]).cache_ttl_secs,
                3600,
                "{raw}"
            );
        }
    }

    #[test]
    fn invalid_json_gives_the_default_for_every_key() {
        for key in [
            "vulnerabilities",
            "outdatedProblems",
            "minimumSeverity",
            "ignore",
            "ecosystems.pypi.enabled",
            "cacheTtlSeconds",
        ] {
            assert_eq!(settings_from(&[(key, "{")]), Settings::default(), "{key}");
        }
    }
}
