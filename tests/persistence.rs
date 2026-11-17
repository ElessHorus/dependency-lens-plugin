//! End-to-end tests of the disk cache against the SDK mock host.

use dependency_lens::DependencyLens;
use dependency_lens::publish::DECORATION_SET;
use openidea_plugin::mock::MockHost;
use openidea_plugin::{Decoration, Error, Event, HttpResponse, LogLevel, Plugin, host};
use serde_json::{Value, json};
use std::cell::Cell;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

const PLUGIN_ID: &str = "elesshorus.dependency-lens";
const MANIFEST_PATH: &str = "/p/Cargo.toml";
const MANIFEST: &str =
    "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.0\"\n";
const CARGO_KEY: &str = "cache/crates.io";
const BATCH_SUFFIX: &str = "/v1/querybatch";
const DETAIL_PREFIX: &str = "https://api.osv.dev/v1/vulns/";
const HOUR_SECS: u64 = 60 * 60;
const DAY_SECS: u64 = 24 * HOUR_SECS;
const STORAGE_CAPABILITIES: [&str; 5] = [
    "events",
    "project.read",
    "editor.read",
    "storage",
    "net:api.osv.dev",
];

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The fake OSV service: `advisories` advisories for serde, a counter of its requests, and a switch
/// that makes the host cancel every request (a newer call supersedes the run).
struct Osv {
    advisories: Rc<Cell<usize>>,
    requests: Rc<Cell<u32>>,
    detail_requests: Rc<Cell<u32>>,
    batch_requests: Rc<Cell<u32>>,
    is_cancelling: Rc<Cell<bool>>,
}

impl Osv {
    fn new(advisories: usize) -> Self {
        Self {
            advisories: Rc::new(Cell::new(advisories)),
            requests: Rc::new(Cell::new(0)),
            detail_requests: Rc::new(Cell::new(0)),
            batch_requests: Rc::new(Cell::new(0)),
            is_cancelling: Rc::new(Cell::new(false)),
        }
    }

    /// Makes `host` answer like OSV.
    fn install(&self, host: &MockHost) {
        let advisories = self.advisories.clone();
        let requests = self.requests.clone();
        let detail_requests = self.detail_requests.clone();
        let batch_requests = self.batch_requests.clone();
        let is_cancelling = self.is_cancelling.clone();
        host.on_fetch(move |request| {
            requests.set(requests.get() + 1);
            if is_cancelling.get() {
                return Err(Error::Cancelled);
            }
            let body = if request.url.ends_with(BATCH_SUFFIX) {
                batch_requests.set(batch_requests.get() + 1);
                let query: Value =
                    serde_json::from_slice(request.body.as_deref().unwrap_or_default())
                        .unwrap_or(Value::Null);
                let results: Vec<Value> = query["queries"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|query| {
                        let count = if query["package"]["name"] == "serde" {
                            advisories.get()
                        } else {
                            0
                        };
                        let vulns: Vec<Value> = (0..count)
                            .map(|number| json!({ "id": format!("GHSA-{number:04}") }))
                            .collect();
                        json!({ "vulns": vulns })
                    })
                    .collect();
                json!({ "results": results }).to_string()
            } else if let Some(id) = request.url.strip_prefix(DETAIL_PREFIX) {
                detail_requests.set(detail_requests.get() + 1);
                json!({ "id": id, "summary": "Test advisory", "database_specific": { "severity": "HIGH" } })
                    .to_string()
            } else {
                return Err(Error::Failed(format!("unexpected request {}", request.url)));
            };
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: body.into_bytes(),
            })
        });
    }
}

/// A mock host with a project at `/p`, the given capabilities and `osv` as the network.
fn host_with(capabilities: &[&str], osv: &Osv) -> MockHost {
    let host = MockHost::install().with_capabilities(capabilities);
    host.set_project_root(Some("/p"));
    osv.install(&host);
    host
}

fn open_manifest(host: &MockHost, plugin: &mut DependencyLens, text: &str) {
    host.add_file("Cargo.toml", text);
    plugin.handle_events(
        &[Event::FileOpened(MANIFEST_PATH.to_owned())],
        &host.invocation(),
    );
}

fn decorations_of(host: &MockHost) -> Vec<Decoration> {
    host.decorations()
        .get(&(DECORATION_SET.to_owned(), MANIFEST_PATH.to_owned()))
        .cloned()
        .unwrap_or_default()
}

fn after_texts(host: &MockHost) -> Vec<Option<String>> {
    decorations_of(host)
        .into_iter()
        .map(|decoration| decoration.after)
        .collect()
}

/// Writes a Cargo block that names one advisory for `serde 1.0.0`, stored at `at`.
fn seed_cargo_block(at: u64) {
    let block = json!({
        "v": 1,
        "registry": {},
        "lists": { "serde": { "1.0.0": { "at": at, "total": 1, "ids": ["GHSA-seed"] } } },
        "advisories": { "GHSA-seed": {
            "at": at, "revision": null, "severity": "high", "summary": "Seeded advisory", "affected": []
        } }
    });
    host::storage::set(CARGO_KEY, &block.to_string()).unwrap();
}

#[test]
fn a_cold_open_with_a_fresh_disk_cache_makes_no_request() {
    let osv = Osv::new(1);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    let mut first = DependencyLens::default();
    open_manifest(&host, &mut first, MANIFEST);
    let requests_after_first_open = osv.requests.get();
    assert!(requests_after_first_open > 0);
    let first_decorations = after_texts(&host);
    assert_eq!(first_decorations, [Some("⚠ 1 vulnerability".to_owned())]);

    // The IDE unloads the plugin: a new instance starts with an empty memory cache.
    drop(first);
    let mut second = DependencyLens::default();
    open_manifest(&host, &mut second, MANIFEST);

    assert_eq!(osv.requests.get(), requests_after_first_open);
    assert_eq!(after_texts(&host), first_decorations);
}

#[test]
fn an_expired_disk_cache_is_shown_first_and_then_refreshed() {
    let osv = Osv::new(2);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    seed_cargo_block(now_secs() - 2 * HOUR_SECS);
    // The host cancels every request, so the run ends after its first, old-data pass.
    osv.is_cancelling.set(true);
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin, MANIFEST);

    assert!(osv.requests.get() > 0, "the real lookup was tried");
    assert_eq!(after_texts(&host), [Some("⚠ 1 vulnerability".to_owned())]);

    // Once the host answers, the normal pass replaces the old data.
    osv.is_cancelling.set(false);
    open_manifest(&host, &mut plugin, MANIFEST);
    assert_eq!(after_texts(&host), [Some("⚠ 2 vulnerabilities".to_owned())]);
}

#[test]
fn a_disk_cache_older_than_seven_days_is_not_shown() {
    let osv = Osv::new(2);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    seed_cargo_block(now_secs() - 8 * DAY_SECS);
    osv.is_cancelling.set(true);
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin, MANIFEST);

    assert!(decorations_of(&host).is_empty());
}

#[test]
fn only_the_opened_ecosystem_is_read_and_written() {
    let osv = Osv::new(1);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    // A PyPI block that is not a block: reading it would delete it.
    host::storage::set("cache/PyPI", "NOT-READ").unwrap();
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin, MANIFEST);

    let storage = host.storage();
    assert_eq!(
        storage.get("cache/PyPI").map(String::as_str),
        Some("NOT-READ")
    );
    let block: Value = serde_json::from_str(&storage[CARGO_KEY]).unwrap();
    assert_eq!(block["v"], 1);
}

#[test]
fn a_failing_or_missing_storage_does_not_change_the_analysis() {
    let with_storage = {
        let osv = Osv::new(1);
        let host = host_with(&STORAGE_CAPABILITIES, &osv);
        open_manifest(&host, &mut DependencyLens::default(), MANIFEST);
        decorations_of(&host)
    };
    let osv = Osv::new(1);
    // No `storage` capability: every storage call is denied.
    let host = host_with(
        &["events", "project.read", "editor.read", "net:api.osv.dev"],
        &osv,
    );
    open_manifest(&host, &mut DependencyLens::default(), MANIFEST);

    assert_eq!(decorations_of(&host), with_storage);
    assert!(host.storage().is_empty());
}

#[test]
fn an_undecodable_block_is_deleted_and_the_analysis_runs() {
    let osv = Osv::new(1);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    host::storage::set(CARGO_KEY, "not json").unwrap();
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin, MANIFEST);

    assert_eq!(after_texts(&host), [Some("⚠ 1 vulnerability".to_owned())]);
    let block: Value = serde_json::from_str(&host.storage()[CARGO_KEY]).unwrap();
    assert_eq!(block["v"], 1);
}

#[test]
fn an_undecodable_block_is_deleted_even_when_nothing_is_saved_after_it() {
    let osv = Osv::new(1);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    host::storage::set(CARGO_KEY, "not json").unwrap();
    let mut plugin = DependencyLens::default();
    // A manifest without dependencies changes nothing in the cache, so no save follows.
    open_manifest(
        &host,
        &mut plugin,
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    );

    assert!(!host.storage().contains_key(CARGO_KEY));
}

#[test]
fn private_and_ignored_packages_never_reach_the_disk() {
    let osv = Osv::new(1);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    host.set_setting("ignore", r#"["ignored-crate"]"#);
    let mut plugin = DependencyLens::default();
    plugin.activate(&host.context(PLUGIN_ID)).unwrap();
    let manifest = format!(
        "{MANIFEST}local-private = {{ path = \"../local-private\" }}\nignored-crate = \"1.0.0\"\n"
    );
    open_manifest(&host, &mut plugin, &manifest);

    let stored = host.storage()[CARGO_KEY].clone();
    assert!(stored.contains("serde"), "{stored}");
    assert!(!stored.contains("local-private"), "{stored}");
    assert!(!stored.contains("ignored-crate"), "{stored}");
}

#[test]
fn load_all_still_works_after_a_restore_from_disk() {
    let osv = Osv::new(25);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    let mut first = DependencyLens::default();
    open_manifest(&host, &mut first, MANIFEST);
    assert_eq!(osv.detail_requests.get(), 10);
    drop(first);

    let mut second = DependencyLens::default();
    open_manifest(&host, &mut second, MANIFEST);
    let decoration = decorations_of(&host).remove(0);
    assert_eq!(decoration.after.as_deref(), Some("⚠ 25 vulnerabilities"));
    let hover = decoration.hover.unwrap();
    assert!(hover.contains("15 more not loaded"), "{hover}");
    assert!(!hover.contains("osv.dev/vulnerability/)"), "{hover}");

    host.open_editor(MANIFEST_PATH, "toml", MANIFEST, &[]);
    let answer = second
        .run_command("load-vulnerabilities", &host.invocation(), None)
        .unwrap();
    assert_eq!(
        answer,
        Some("Dependency Lens: vulnerabilities loaded".to_owned())
    );
    // The ten stored advisories are not downloaded again: only the other fifteen are.
    assert_eq!(osv.detail_requests.get(), 25);
    let hover = decorations_of(&host).remove(0).hover.unwrap();
    assert!(!hover.contains("more not loaded"), "{hover}");

    // The disk still keeps the standard ten, however many the session loaded.
    let block: Value = serde_json::from_str(&host.storage()[CARGO_KEY]).unwrap();
    let list = &block["lists"]["serde"]["1.0.0"];
    assert_eq!(list["total"], 25);
    assert_eq!(list["ids"].as_array().unwrap().len(), 10);
    assert_eq!(block["advisories"].as_object().unwrap().len(), 10);
}

/// Sends one `settings-changed` event for `key`.
fn send_settings_changed(host: &MockHost, plugin: &mut DependencyLens, key: &str) {
    plugin.handle_events(
        &[Event::Other {
            kind: "settings-changed".to_owned(),
            data: format!(r#"["{key}"]"#),
        }],
        &host.invocation(),
    );
}

fn stored_cache_keys(host: &MockHost) -> Vec<String> {
    host.storage()
        .into_keys()
        .filter(|key| key.starts_with("cache/"))
        .collect()
}

#[test]
fn a_ttl_of_zero_writes_nothing_and_reads_nothing() {
    let osv = Osv::new(2);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    host.set_setting("cacheTtlSeconds", "0");
    let mut plugin = DependencyLens::default();
    plugin.activate(&host.context(PLUGIN_ID)).unwrap();
    // A fresh block, written after the activation: with a lifetime of zero it is neither read nor replaced.
    seed_cargo_block(now_secs());
    let seeded = host.storage()[CARGO_KEY].clone();
    open_manifest(&host, &mut plugin, MANIFEST);

    assert_eq!(after_texts(&host), [Some("⚠ 2 vulnerabilities".to_owned())]);
    assert_eq!(host.storage()[CARGO_KEY], seeded);
}

#[test]
fn changing_the_ttl_to_zero_deletes_the_blocks_and_back_to_a_positive_value_reads_the_disk_again() {
    let osv = Osv::new(2);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin, MANIFEST);
    assert_eq!(stored_cache_keys(&host), [CARGO_KEY]);

    host.set_setting("cacheTtlSeconds", "0");
    send_settings_changed(&host, &mut plugin, "cacheTtlSeconds");
    assert!(stored_cache_keys(&host).is_empty());

    // A fresh block appears on the disk. The new lifetime must read it, not the old memory.
    seed_cargo_block(now_secs());
    let requests_before = osv.requests.get();
    host.set_setting("cacheTtlSeconds", "3600");
    send_settings_changed(&host, &mut plugin, "cacheTtlSeconds");

    assert_eq!(osv.requests.get(), requests_before);
    assert_eq!(after_texts(&host), [Some("⚠ 1 vulnerability".to_owned())]);
}

#[test]
fn the_clear_cache_command_empties_memory_and_disk_and_refreshes() {
    let osv = Osv::new(1);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin, MANIFEST);
    host::storage::set("cache/PyPI", "STALE-BLOCK").unwrap();
    let requests_before = osv.requests.get();
    assert!(requests_before > 0);

    let answer = plugin
        .run_command("clear-cache", &host.invocation(), None)
        .unwrap();

    assert_eq!(answer, Some("Dependency Lens: cache cleared".to_owned()));
    // Every block was deleted. The shown manifest was analyzed again, so its block is new.
    assert_eq!(stored_cache_keys(&host), [CARGO_KEY]);
    assert!(osv.requests.get() > requests_before);
    assert_eq!(after_texts(&host), [Some("⚠ 1 vulnerability".to_owned())]);
}

#[test]
fn plugin_toml_declares_the_storage_capability_and_the_clear_cache_command() {
    let manifest = include_str!("../plugin.toml");
    let required = manifest
        .lines()
        .find(|line| line.starts_with("required"))
        .unwrap();
    assert!(required.contains("\"storage\""), "{required}");
    assert!(manifest.contains("id = \"clear-cache\""));
    assert!(manifest.contains("title = \"Dependency Lens: Clear cache\""));
}

#[test]
fn loading_a_block_logs_its_size_and_duration_at_debug_level() {
    let osv = Osv::new(1);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    seed_cargo_block(now_secs());
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin, MANIFEST);

    let lines: Vec<String> = host
        .logs()
        .into_iter()
        .filter(|(level, _)| matches!(level, LogLevel::Debug))
        .map(|(_, text)| text)
        .filter(|text| text.starts_with("cache: loaded crates.io"))
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("2 records") && lines[0].ends_with(" ms"),
        "{}",
        lines[0]
    );
}

const THREE_CRATES: &str = "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.0\"\ntokio = \"1.37.0\"\nanyhow = \"1.0.80\"\n";

/// Writes a Cargo block with an empty list for each `(package, version)`, stored at `at`.
fn seed_cargo_lists(at: u64, packages: &[(&str, &str)]) {
    let mut lists = serde_json::Map::new();
    for (package, version) in packages {
        lists.insert(
            (*package).to_owned(),
            json!({ *version: { "at": at, "total": 0, "ids": [] } }),
        );
    }
    let block = json!({ "v": 1, "registry": {}, "lists": lists, "advisories": {} });
    host::storage::set(CARGO_KEY, &block.to_string()).unwrap();
}

#[test]
fn expired_pairs_go_to_osv_in_one_batch() {
    let osv = Osv::new(0);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    seed_cargo_lists(
        now_secs() - 2 * HOUR_SECS,
        &[
            ("serde", "1.0.0"),
            ("tokio", "1.37.0"),
            ("anyhow", "1.0.80"),
        ],
    );
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin, THREE_CRATES);

    // The old data is on screen, so a slow package cannot blank it: no need to send the pairs in slices.
    assert_eq!(osv.batch_requests.get(), 1);
}

#[test]
fn a_package_added_to_ignore_leaves_the_disk_cache() {
    let osv = Osv::new(1);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin, MANIFEST);
    assert!(host.storage()[CARGO_KEY].contains("serde"));

    host.set_setting("ignore", r#"["serde"]"#);
    send_settings_changed(&host, &mut plugin, "ignore");

    assert!(!host.storage()[CARGO_KEY].contains("serde"));
}

#[test]
fn an_ignored_package_found_in_an_old_block_is_dropped_on_load() {
    let osv = Osv::new(1);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    seed_cargo_block(now_secs());
    host.set_setting("ignore", r#"["serde"]"#);
    let mut plugin = DependencyLens::default();
    plugin.activate(&host.context(PLUGIN_ID)).unwrap();
    open_manifest(&host, &mut plugin, MANIFEST);

    assert!(!host.storage()[CARGO_KEY].contains("serde"));
}

const WITH_UNVERSIONED: &str = "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.0\"\nwild = \"*\"\n";

#[test]
fn a_ttl_of_zero_does_not_blank_the_decorations_while_a_refresh_runs() {
    let osv = Osv::new(1);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    host.set_setting("cacheTtlSeconds", "0");
    let mut plugin = DependencyLens::default();
    plugin.activate(&host.context(PLUGIN_ID)).unwrap();
    open_manifest(&host, &mut plugin, WITH_UNVERSIONED);
    let shown = after_texts(&host);
    assert_eq!(shown, [Some("⚠ 1 vulnerability".to_owned())]);

    // The refresh cannot finish: what was on screen must stay.
    osv.is_cancelling.set(true);
    open_manifest(&host, &mut plugin, WITH_UNVERSIONED);

    assert_eq!(after_texts(&host), shown);
}

#[test]
fn a_cold_open_without_old_data_publishes_nothing_before_the_first_answer() {
    let osv = Osv::new(1);
    let host = host_with(&STORAGE_CAPABILITIES, &osv);
    osv.is_cancelling.set(true);
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin, WITH_UNVERSIONED);

    assert!(decorations_of(&host).is_empty());
}

#[test]
fn an_entry_that_still_waits_keeps_its_old_data_between_chunks() {
    use std::time::Duration;
    const PYPI_BODY: &str = r#"{"info":{"version":"2.0"},"releases":{"1.0":[{"yanked":false}],"2.0":[{"yanked":false}]}}"#;
    let host = MockHost::install().with_capabilities(&[
        "events",
        "project.read",
        "editor.read",
        "storage",
        "net:api.osv.dev",
        "net:pypi.org",
    ]);
    host.set_project_root(Some("/p"));
    let registry_requests = Rc::new(Cell::new(0));
    let counter = registry_requests.clone();
    host.on_fetch(move |request| {
        let body = if request.url.ends_with(BATCH_SUFFIX) {
            json!({ "results": [{ "vulns": [] }, { "vulns": [] }] }).to_string()
        } else if request.url.starts_with("https://pypi.org/pypi/") {
            counter.set(counter.get() + 1);
            // The second registry lookup is cancelled, so the run ends after its first chunk.
            if counter.get() > 1 {
                return Err(Error::Cancelled);
            }
            PYPI_BODY.to_owned()
        } else {
            return Err(Error::Failed(format!("unexpected request {}", request.url)));
        };
        Ok(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: body.into_bytes(),
        })
    });
    let at = now_secs() - 2 * HOUR_SECS;
    let old_registry = json!({ "at": at, "latest": "3.0", "all": ["3.0", "2.0", "1.0"] });
    let old_list = json!({ "1.0.0": { "at": at, "total": 0, "ids": [] } });
    let block = json!({
        "v": 1,
        "registry": { "requests": old_registry, "flask": old_registry },
        "lists": { "requests": old_list, "flask": old_list },
        "advisories": {}
    });
    host::storage::set("cache/PyPI", &block.to_string()).unwrap();

    // A chunk of one registry lookup: the second package waits after the first chunk.
    let mut plugin = DependencyLens::with_limits(Duration::from_secs(300), 1);
    host.add_file("requirements.txt", "requests==1.0.0\nflask==1.0.0\n");
    plugin.handle_events(
        &[Event::FileOpened("/p/requirements.txt".to_owned())],
        &host.invocation(),
    );

    let shown: Vec<Option<String>> = host
        .decorations()
        .get(&(DECORATION_SET.to_owned(), "/p/requirements.txt".to_owned()))
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|decoration| decoration.after)
        .collect();
    // The first package has its new answer. The second still shows the old one, not "…".
    assert_eq!(shown, [Some("→ 2.0".to_owned()), Some("→ 3.0".to_owned())]);
}
