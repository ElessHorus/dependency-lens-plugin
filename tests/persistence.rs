//! End-to-end tests of the disk cache against the SDK mock host.

use dependency_lens::DependencyLens;
use dependency_lens::publish::DECORATION_SET;
use openidea_plugin::mock::MockHost;
use openidea_plugin::{Decoration, Error, Event, HttpResponse, Plugin, host};
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
    is_cancelling: Rc<Cell<bool>>,
}

impl Osv {
    fn new(advisories: usize) -> Self {
        Self {
            advisories: Rc::new(Cell::new(advisories)),
            requests: Rc::new(Cell::new(0)),
            detail_requests: Rc::new(Cell::new(0)),
            is_cancelling: Rc::new(Cell::new(false)),
        }
    }

    /// Makes `host` answer like OSV.
    fn install(&self, host: &MockHost) {
        let advisories = self.advisories.clone();
        let requests = self.requests.clone();
        let detail_requests = self.detail_requests.clone();
        let is_cancelling = self.is_cancelling.clone();
        host.on_fetch(move |request| {
            requests.set(requests.get() + 1);
            if is_cancelling.get() {
                return Err(Error::Cancelled);
            }
            let body = if request.url.ends_with(BATCH_SUFFIX) {
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
