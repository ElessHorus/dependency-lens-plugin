//! End-to-end tests of the plugin against the SDK mock host.

use dependency_lens::DependencyLens;
use dependency_lens::publish::DECORATION_SET;
use openidea_plugin::mock::MockHost;
use openidea_plugin::providers::{Document, Providers};
use openidea_plugin::{
    Context, Decoration, Diagnostic, Error, Event, EventKind, FilesChanged, HttpRequest,
    HttpResponse, Plugin, Position, Range, Severity,
};
use serde_json::{Value, json};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::Duration;

const MANIFEST_PATH: &str = "/p/Cargo.toml";
const HIGH_ID: &str = "GHSA-serde-high";
const OSV_BATCH_SUFFIX: &str = "/v1/querybatch";
const OSV_DETAIL_PREFIX: &str = "https://api.osv.dev/v1/vulns/";
/// `serde = "1.0.0"` sits on line 5; its version text is columns 9..14.
const SERDE_VERSION_RANGE: Range = Range::new(Position::new(5, 9), Position::new(5, 14));
const MANIFEST: &str = "[package]\n\
name = \"demo\"\n\
version = \"0.1.0\"\n\
\n\
[dependencies]\n\
serde = \"1.0.0\"\n\
tokio = \"1\"\n";
const MANIFEST_WITHOUT_SERDE: &str = "[package]\n\
name = \"demo\"\n\
version = \"0.1.0\"\n\
\n\
[dependencies]\n\
tokio = \"1\"\n";

/// Answers the OSV batch (serde has one high advisory) and the advisory detail.
fn answer_osv(request: &HttpRequest) -> Result<HttpResponse, Error> {
    let body = if request.url.ends_with(OSV_BATCH_SUFFIX) {
        batch_answer(request)
    } else if let Some(id) = request.url.strip_prefix(OSV_DETAIL_PREFIX) {
        json!({
            "id": id,
            "summary": "Serde test advisory",
            "database_specific": { "severity": "HIGH" }
        })
        .to_string()
    } else {
        return Err(Error::Failed(format!("unexpected request {}", request.url)));
    };
    Ok(HttpResponse {
        status: 200,
        headers: Vec::new(),
        body: body.into_bytes(),
    })
}

/// One result per query, in query order: serde has the advisory, the others none.
fn batch_answer(request: &HttpRequest) -> String {
    let query_body: Value =
        serde_json::from_slice(request.body.as_deref().unwrap_or_default()).unwrap_or(Value::Null);
    let results: Vec<Value> = query_body["queries"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|query| {
            if query["package"]["name"] == "serde" {
                json!({ "vulns": [{ "id": HIGH_ID }] })
            } else {
                json!({ "vulns": [] })
            }
        })
        .collect();
    json!({ "results": results }).to_string()
}

/// A mock with the plugin's capabilities, a project at `/p`, and a counter of OSV requests.
fn host_counting_fetches(fetches: Rc<Cell<u32>>) -> MockHost {
    let host = MockHost::install().with_capabilities(&[
        "events",
        "project.read",
        "editor.read",
        "net:api.osv.dev",
    ]);
    host.set_project_root(Some("/p"));
    host.on_fetch(move |request| {
        fetches.set(fetches.get() + 1);
        answer_osv(request)
    });
    host
}

fn decorations_of(host: &MockHost, path: &str) -> Vec<Decoration> {
    host.decorations()
        .get(&(DECORATION_SET.to_owned(), path.to_owned()))
        .cloned()
        .unwrap_or_default()
}

fn diagnostics_of(host: &MockHost, path: &str) -> Vec<Diagnostic> {
    host.diagnostics().get(path).cloned().unwrap_or_default()
}

/// Writes the manifest into the mock project and sends one `FileOpened` event for it.
fn open_manifest(host: &MockHost, plugin: &mut DependencyLens) {
    host.add_file("Cargo.toml", MANIFEST);
    plugin.handle_events(
        &[Event::FileOpened(MANIFEST_PATH.to_owned())],
        &host.invocation(),
    );
}

#[test]
fn opening_manifest_shows_serde_advisory_only() {
    let host = host_counting_fetches(Rc::new(Cell::new(0)));
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin);

    let decorations = decorations_of(&host, MANIFEST_PATH);
    assert_eq!(decorations.len(), 1);
    assert_eq!(decorations[0].range, SERDE_VERSION_RANGE);
    assert_eq!(decorations[0].after.as_deref(), Some("⚠ 1 vulnerability"));
    assert_eq!(decorations[0].style, "error");
    assert!(
        decorations[0]
            .hover
            .as_deref()
            .is_some_and(|hover| hover.contains(HIGH_ID))
    );

    let diagnostics = diagnostics_of(&host, MANIFEST_PATH);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].range, SERDE_VERSION_RANGE);
    assert_eq!(diagnostics[0].severity, Severity::Error);
    assert_eq!(diagnostics[0].code.as_deref(), Some(HIGH_ID));
}

#[test]
fn advisories_are_shown_when_the_cache_lifetime_is_zero() {
    // `cacheTtlSeconds = 0` keeps nothing between refreshes; a refresh must still show what it fetched.
    let host = host_counting_fetches(Rc::new(Cell::new(0)));
    host.set_setting("cacheTtlSeconds", "0");
    let mut plugin = DependencyLens::default();
    plugin.activate(&host.context(PLUGIN_ID)).unwrap();
    open_manifest(&host, &mut plugin);

    let decorations = decorations_of(&host, MANIFEST_PATH);
    assert_eq!(decorations.len(), 1);
    assert_eq!(decorations[0].range, SERDE_VERSION_RANGE);
    assert_eq!(decorations[0].after.as_deref(), Some("⚠ 1 vulnerability"));
    let diagnostics = diagnostics_of(&host, MANIFEST_PATH);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].code.as_deref(), Some(HIGH_ID));
}

#[test]
fn saving_without_serde_clears_its_decoration_and_problem() {
    let host = host_counting_fetches(Rc::new(Cell::new(0)));
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin);
    assert_eq!(decorations_of(&host, MANIFEST_PATH).len(), 1);

    host.add_file("Cargo.toml", MANIFEST_WITHOUT_SERDE);
    plugin.handle_events(
        &[Event::FileSaved(MANIFEST_PATH.to_owned())],
        &host.invocation(),
    );
    assert!(decorations_of(&host, MANIFEST_PATH).is_empty());
    assert!(diagnostics_of(&host, MANIFEST_PATH).is_empty());
}

#[test]
fn emptying_the_manifest_clears_decorations_and_problems() {
    let host = host_counting_fetches(Rc::new(Cell::new(0)));
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin);

    host.add_file("Cargo.toml", "");
    plugin.handle_events(
        &[Event::FileSaved(MANIFEST_PATH.to_owned())],
        &host.invocation(),
    );
    assert!(decorations_of(&host, MANIFEST_PATH).is_empty());
    assert!(diagnostics_of(&host, MANIFEST_PATH).is_empty());
}

#[test]
fn removed_manifest_clears_decorations_and_problems() {
    let host = host_counting_fetches(Rc::new(Cell::new(0)));
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin);

    plugin.handle_events(
        &[Event::FilesChanged(FilesChanged {
            created: Vec::new(),
            modified: Vec::new(),
            removed: vec![MANIFEST_PATH.to_owned()],
        })],
        &host.invocation(),
    );
    assert!(decorations_of(&host, MANIFEST_PATH).is_empty());
    assert!(diagnostics_of(&host, MANIFEST_PATH).is_empty());
}

#[test]
fn files_that_are_not_manifests_are_never_read_or_queried() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_counting_fetches(fetches.clone());
    host.add_file("README.md", "# Demo\n");
    host.add_file("node_modules/x/package.json", "{}");
    host.add_file("target/Cargo.toml", MANIFEST);
    host.add_file("vendor/Cargo.toml", MANIFEST);
    host.add_file(".git/Cargo.toml", MANIFEST);
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[
            Event::FileOpened("/p/README.md".to_owned()),
            Event::FileOpened("/p/node_modules/x/package.json".to_owned()),
            Event::FileOpened("/p/target/Cargo.toml".to_owned()),
            Event::FileSaved("/p/vendor/Cargo.toml".to_owned()),
            Event::FileSaved("/p/.git/Cargo.toml".to_owned()),
        ],
        &host.invocation(),
    );
    assert_eq!(fetches.get(), 0);
    assert!(host.decorations().is_empty());
    assert!(host.diagnostics().is_empty());
}

#[test]
fn a_project_under_a_skipped_folder_name_is_still_analyzed() {
    // Only folders inside the project are skipped. The project itself may sit under `vendor`.
    let host = host_counting_fetches(Rc::new(Cell::new(0)));
    host.set_project_root(Some("/srv/vendor/app"));
    host.add_file("Cargo.toml", MANIFEST);
    host.add_file("target/Cargo.toml", MANIFEST);
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[
            Event::FileOpened("/srv/vendor/app/Cargo.toml".to_owned()),
            Event::FileOpened("/srv/vendor/app/target/Cargo.toml".to_owned()),
        ],
        &host.invocation(),
    );
    assert_eq!(diagnostics_of(&host, "/srv/vendor/app/Cargo.toml").len(), 1);
    assert!(diagnostics_of(&host, "/srv/vendor/app/target/Cargo.toml").is_empty());
}

#[test]
fn opening_an_unchanged_manifest_again_makes_no_request() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_counting_fetches(fetches.clone());
    let mut plugin = DependencyLens::default();
    open_manifest(&host, &mut plugin);
    let after_first_open = fetches.get();
    assert!(after_first_open > 0);

    plugin.handle_events(
        &[Event::FileOpened(MANIFEST_PATH.to_owned())],
        &host.invocation(),
    );
    assert_eq!(fetches.get(), after_first_open);
    assert_eq!(decorations_of(&host, MANIFEST_PATH).len(), 1);
}

#[test]
fn refresh_command_reports_unsupported_and_refreshed_files() {
    let host = host_counting_fetches(Rc::new(Cell::new(0)));
    let mut plugin = DependencyLens::default();

    host.open_editor("/p/README.md", "markdown", "# Demo\n", &[]);
    assert_eq!(
        plugin
            .run_command("refresh", &host.invocation(), None)
            .unwrap(),
        Some("Dependency Lens: not a supported manifest".to_owned())
    );

    host.open_editor("/p/Cargo.toml", "toml", MANIFEST, &[]);
    assert_eq!(
        plugin
            .run_command("refresh", &host.invocation(), None)
            .unwrap(),
        Some("Dependency Lens: refreshed".to_owned())
    );
    assert_eq!(decorations_of(&host, MANIFEST_PATH).len(), 1);
}

#[test]
fn unknown_command_is_not_found() {
    let host = host_counting_fetches(Rc::new(Cell::new(0)));
    let mut plugin = DependencyLens::default();
    let error = plugin
        .run_command("missing", &host.invocation(), None)
        .unwrap_err();
    assert!(matches!(error, Error::NotFound(_)));
}

#[test]
fn activation_subscribes_to_the_four_events() {
    let host = host_counting_fetches(Rc::new(Cell::new(0)));
    let mut plugin = DependencyLens::default();
    plugin.activate(&Context::default()).unwrap();
    assert_eq!(
        host.subscriptions(),
        BTreeSet::from([
            EventKind::FileOpened,
            EventKind::FileSaved,
            EventKind::FilesChanged,
            EventKind::SettingsChanged,
        ])
    );
}

const PLUGIN_ID: &str = "local.dependency-lens";
/// Batch path that OSV answers for each uncached `(name, version)` set.
const OSV_BATCH_PATH: &str = "/v1/querybatch";

/// Counts the OSV batch requests the plugin sent.
fn osv_batch_requests(host: &MockHost) -> usize {
    host.requests()
        .iter()
        .filter(|request| request.url.ends_with(OSV_BATCH_PATH))
        .count()
}

#[test]
fn disabled_pypi_setting_skips_requirements_and_keeps_cargo() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_with_pypi(fetches.clone());
    host.set_setting("ecosystems.pypi.enabled", "false");
    let mut plugin = DependencyLens::default();
    plugin.activate(&host.context(PLUGIN_ID)).unwrap();

    host.add_file("requirements.txt", REQUIREMENTS);
    plugin.handle_events(
        &[Event::FileOpened(REQUIREMENTS_PATH.to_owned())],
        &host.invocation(),
    );
    assert_eq!(fetches.get(), 0);
    assert!(decorations_of(&host, REQUIREMENTS_PATH).is_empty());

    open_manifest(&host, &mut plugin);
    assert_eq!(decorations_of(&host, MANIFEST_PATH).len(), 1);
}

#[test]
fn disabled_vulnerabilities_setting_sends_no_osv_request() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_counting_fetches(fetches.clone());
    host.set_setting("vulnerabilities", "false");
    let mut plugin = DependencyLens::default();
    plugin.activate(&host.context(PLUGIN_ID)).unwrap();

    open_manifest(&host, &mut plugin);
    assert_eq!(fetches.get(), 0);
    assert!(decorations_of(&host, MANIFEST_PATH).is_empty());
}

#[test]
fn settings_changed_event_disables_an_ecosystem_for_later_opens() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_counting_fetches(fetches.clone());
    let mut plugin = DependencyLens::default();
    plugin.activate(&host.context(PLUGIN_ID)).unwrap();

    host.set_setting("ecosystems.cargo.enabled", "false");
    plugin.handle_events(
        &[Event::Other {
            kind: "settings-changed".to_owned(),
            data: r#"["ecosystems.cargo.enabled"]"#.to_owned(),
        }],
        &host.invocation(),
    );
    assert_eq!(fetches.get(), 0);

    open_manifest(&host, &mut plugin);
    assert_eq!(fetches.get(), 0);
}

#[test]
fn settings_changed_event_with_zero_ttl_replaces_the_cache() {
    let host = host_counting_fetches(Rc::new(Cell::new(0)));
    let mut plugin = DependencyLens::default();
    plugin.activate(&host.context(PLUGIN_ID)).unwrap();

    host.set_setting("cacheTtlSeconds", "0");
    plugin.handle_events(
        &[Event::Other {
            kind: "settings-changed".to_owned(),
            data: r#"["cacheTtlSeconds"]"#.to_owned(),
        }],
        &host.invocation(),
    );
    open_manifest(&host, &mut plugin);
    plugin.handle_events(
        &[Event::FileOpened(MANIFEST_PATH.to_owned())],
        &host.invocation(),
    );
    assert_eq!(osv_batch_requests(&host), 2);
}

#[test]
fn file_of_another_open_project_is_read_through_its_own_project() {
    let host = host_counting_fetches(Rc::new(Cell::new(0)));
    host.set_project_root(Some("/p1"));
    host.add_project("/p2");
    host.add_file("/p2/Cargo.toml", MANIFEST);
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[Event::FileOpened("/p2/Cargo.toml".to_owned())],
        &host.invocation(),
    );
    let problems = host
        .diagnostics()
        .get("/p2/Cargo.toml")
        .cloned()
        .unwrap_or_default();
    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].code.as_deref(), Some(HIGH_ID));
}

#[test]
fn file_outside_the_window_project_is_found_through_project_of() {
    let host = host_counting_fetches(Rc::new(Cell::new(0)));
    host.set_project_root(None);
    host.add_project("/p2");
    host.add_file("/p2/Cargo.toml", MANIFEST);
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[Event::FileOpened("/p2/Cargo.toml".to_owned())],
        &host.invocation(),
    );
    assert_eq!(diagnostics_of(&host, "/p2/Cargo.toml").len(), 1);
}

const REQUIREMENTS_PATH: &str = "/p/requirements.txt";
const REQUIREMENTS: &str = "requests==2.28.0\nflask==2.31.0\n";
/// `requests==2.28.0` sits on line 0; its version text is columns 10..16.
const REQUESTS_VERSION_RANGE: Range = Range::new(Position::new(0, 10), Position::new(0, 16));
/// `flask==2.31.0` sits on line 1; its version text is columns 7..13.
const FLASK_VERSION_RANGE: Range = Range::new(Position::new(1, 7), Position::new(1, 13));
const PYPI_PAGE_BODY: &str =
    r#"{"info":{"version":"2.31.0"},"releases":{"2.31.0":[{"yanked":false}]}}"#;

/// Answers PyPI project pages with one release, and everything else as OSV does.
/// Every request increments `fetches`.
fn host_with_pypi(fetches: Rc<Cell<u32>>) -> MockHost {
    let host = MockHost::install().with_capabilities(&[
        "events",
        "project.read",
        "editor.read",
        "net:api.osv.dev",
        "net:pypi.org",
    ]);
    host.set_project_root(Some("/p"));
    host.on_fetch(move |request| {
        fetches.set(fetches.get() + 1);
        if request.url.starts_with("https://pypi.org/pypi/") {
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: PYPI_PAGE_BODY.as_bytes().to_vec(),
            })
        } else {
            answer_osv(request)
        }
    });
    host
}

#[test]
fn requirements_show_registry_versions_and_no_problems() {
    let host = host_with_pypi(Rc::new(Cell::new(0)));
    host.add_file("requirements.txt", REQUIREMENTS);
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[Event::FileOpened(REQUIREMENTS_PATH.to_owned())],
        &host.invocation(),
    );

    let decorations = decorations_of(&host, REQUIREMENTS_PATH);
    let requests = decorations
        .iter()
        .find(|decoration| decoration.range == REQUESTS_VERSION_RANGE)
        .expect("decoration on requests");
    assert_eq!(requests.after, Some("→ 2.31.0".to_string()));
    assert_eq!(requests.style, "info");
    let flask = decorations
        .iter()
        .find(|decoration| decoration.range == FLASK_VERSION_RANGE)
        .expect("decoration on flask");
    assert_eq!(flask.after, Some("✓".to_string()));
    assert_eq!(flask.style, "muted");
    assert!(diagnostics_of(&host, REQUIREMENTS_PATH).is_empty());
}

#[test]
fn quick_fix_on_a_pinned_requirement_is_served_from_the_cache() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_with_pypi(fetches.clone());
    host.add_file("requirements.txt", REQUIREMENTS);
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[Event::FileOpened(REQUIREMENTS_PATH.to_owned())],
        &host.invocation(),
    );
    let fetches_after_refresh = fetches.get();
    assert!(fetches_after_refresh > 0);

    let document = Document {
        path: REQUIREMENTS_PATH.to_owned(),
        language: "pip-requirements".to_owned(),
        version: 1,
        text: REQUIREMENTS.to_owned(),
    };
    let actions = Providers::code_actions(
        &mut plugin,
        &document,
        Range::new(Position::new(0, 3), Position::new(0, 3)),
    );
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].title, "Update requests to 2.31.0 (minor)");
    assert_eq!(fetches.get(), fetches_after_refresh);
}

const COMPOSER_PATH: &str = "/p/composer.json";
const COMPOSER: &str = "{\n    \"require\": {\n        \"monolog/monolog\": \"^3.0\"\n    }\n}\n";
/// `"monolog/monolog": "^3.0"` sits on line 2; its version text is columns 28..32.
const MONOLOG_VERSION_RANGE: Range = Range::new(Position::new(2, 28), Position::new(2, 32));
const PACKAGIST_PAGE_BODY: &str = r#"{"minified":"composer/2.0","packages":{"monolog/monolog":[{"version":"3.12.1"},{"version":"3.0.0"}]}}"#;

/// Answers requests under `registry_prefix` with `registry_body`, and everything else as OSV does.
/// Every request increments `fetches`. `registry_capability` is the `net:` grant of the registry host.
fn host_with_registry(
    fetches: Rc<Cell<u32>>,
    registry_capability: &'static str,
    registry_prefix: &'static str,
    registry_body: &'static str,
) -> MockHost {
    let host = MockHost::install().with_capabilities(&[
        "events",
        "project.read",
        "editor.read",
        "net:api.osv.dev",
        registry_capability,
    ]);
    host.set_project_root(Some("/p"));
    host.on_fetch(move |request| {
        fetches.set(fetches.get() + 1);
        if request.url.starts_with(registry_prefix) {
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: registry_body.as_bytes().to_vec(),
            })
        } else {
            answer_osv(request)
        }
    });
    host
}

/// A mock that answers Packagist p2 pages and OSV, counting every request.
fn host_with_packagist(fetches: Rc<Cell<u32>>) -> MockHost {
    host_with_registry(
        fetches,
        "net:repo.packagist.org",
        "https://repo.packagist.org/p2/",
        PACKAGIST_PAGE_BODY,
    )
}

#[test]
fn composer_requirement_shows_the_registry_version() {
    let host = host_with_packagist(Rc::new(Cell::new(0)));
    host.add_file("composer.json", COMPOSER);
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[Event::FileOpened(COMPOSER_PATH.to_owned())],
        &host.invocation(),
    );

    let decorations = decorations_of(&host, COMPOSER_PATH);
    let monolog = decorations
        .iter()
        .find(|decoration| decoration.range == MONOLOG_VERSION_RANGE)
        .expect("decoration on monolog");
    assert_eq!(monolog.after, Some("→ 3.12.1".to_string()));
    assert_eq!(monolog.style, "info");
    assert!(diagnostics_of(&host, COMPOSER_PATH).is_empty());
}

#[test]
fn composer_quick_fix_rewrites_the_range_and_is_served_from_the_cache() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_with_packagist(fetches.clone());
    host.add_file("composer.json", COMPOSER);
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[Event::FileOpened(COMPOSER_PATH.to_owned())],
        &host.invocation(),
    );
    let fetches_after_refresh = fetches.get();
    assert!(fetches_after_refresh > 0);

    let document = Document {
        path: COMPOSER_PATH.to_owned(),
        language: "json".to_owned(),
        version: 1,
        text: COMPOSER.to_owned(),
    };
    let actions = Providers::code_actions(
        &mut plugin,
        &document,
        Range::new(Position::new(2, 3), Position::new(2, 3)),
    );
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].title, "Update monolog/monolog to 3.12.1 (minor)");
    let (edit_path, edits) = &actions[0].edits[0];
    assert_eq!(edit_path, COMPOSER_PATH);
    assert_eq!(edits[0].range, MONOLOG_VERSION_RANGE);
    assert_eq!(edits[0].text, "^3.12");
    assert_eq!(fetches.get(), fetches_after_refresh);
}

const PUBSPEC_PATH: &str = "/p/pubspec.yaml";
const PUBSPEC: &str = "name: demo\ndependencies:\n  http: ^1.0.0\n";
/// `  http: ^1.0.0` sits on line 2; its version text is columns 8..14.
const HTTP_VERSION_RANGE: Range = Range::new(Position::new(2, 8), Position::new(2, 14));
const PUB_HTTP_BODY: &str = r#"{"name":"http","latest":{"version":"1.2.0"},"versions":[{"version":"1.0.0"},{"version":"1.2.0"}]}"#;

/// A mock that answers pub.dev package pages and OSV, counting every request.
fn host_with_pub(fetches: Rc<Cell<u32>>) -> MockHost {
    host_with_registry(
        fetches,
        "net:pub.dev",
        "https://pub.dev/api/packages/",
        PUB_HTTP_BODY,
    )
}

#[test]
fn pubspec_requirement_shows_the_registry_version() {
    let host = host_with_pub(Rc::new(Cell::new(0)));
    host.add_file("pubspec.yaml", PUBSPEC);
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[Event::FileOpened(PUBSPEC_PATH.to_owned())],
        &host.invocation(),
    );

    let decorations = decorations_of(&host, PUBSPEC_PATH);
    let http = decorations
        .iter()
        .find(|decoration| decoration.range == HTTP_VERSION_RANGE)
        .expect("decoration on http");
    assert_eq!(http.after, Some("→ 1.2.0".to_string()));
    assert_eq!(http.style, "info");
    assert!(diagnostics_of(&host, PUBSPEC_PATH).is_empty());
}

#[test]
fn pubspec_quick_fix_rewrites_the_range() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_with_pub(fetches.clone());
    host.add_file("pubspec.yaml", PUBSPEC);
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[Event::FileOpened(PUBSPEC_PATH.to_owned())],
        &host.invocation(),
    );
    let fetches_after_refresh = fetches.get();

    let document = Document {
        path: PUBSPEC_PATH.to_owned(),
        language: "yaml".to_owned(),
        version: 1,
        text: PUBSPEC.to_owned(),
    };
    let actions = Providers::code_actions(
        &mut plugin,
        &document,
        Range::new(Position::new(2, 3), Position::new(2, 3)),
    );
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].title, "Update http to 1.2.0 (minor)");
    let (edit_path, edits) = &actions[0].edits[0];
    assert_eq!(edit_path, PUBSPEC_PATH);
    assert_eq!(edits[0].range, HTTP_VERSION_RANGE);
    assert_eq!(edits[0].text, "^1.2.0");
    assert_eq!(fetches.get(), fetches_after_refresh);
}

const CSPROJ_PATH: &str = "/p/app.csproj";
const CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <ItemGroup>\n    <PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.3\" />\n  </ItemGroup>\n</Project>\n";
/// The version of `Newtonsoft.Json` sits on line 2; its version text is columns 57..63.
const NEWTONSOFT_VERSION_RANGE: Range = Range::new(Position::new(2, 57), Position::new(2, 63));
const NUGET_NEWTONSOFT_BODY: &str = r#"{"versions":["13.0.3","13.0.4"]}"#;

/// A mock that answers NuGet flat container indexes and OSV, counting every request.
fn host_with_nuget(fetches: Rc<Cell<u32>>) -> MockHost {
    host_with_registry(
        fetches,
        "net:api.nuget.org",
        "https://api.nuget.org/v3-flatcontainer/",
        NUGET_NEWTONSOFT_BODY,
    )
}

#[test]
fn csproj_requirement_shows_the_registry_version() {
    let host = host_with_nuget(Rc::new(Cell::new(0)));
    host.add_file("app.csproj", CSPROJ);
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[Event::FileOpened(CSPROJ_PATH.to_owned())],
        &host.invocation(),
    );

    let decorations = decorations_of(&host, CSPROJ_PATH);
    let newtonsoft = decorations
        .iter()
        .find(|decoration| decoration.range == NEWTONSOFT_VERSION_RANGE)
        .expect("decoration on Newtonsoft.Json");
    assert_eq!(newtonsoft.after, Some("→ 13.0.4".to_string()));
    assert_eq!(newtonsoft.style, "info");
    assert!(diagnostics_of(&host, CSPROJ_PATH).is_empty());
}

#[test]
fn csproj_quick_fix_replaces_the_version_and_is_served_from_the_cache() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_with_nuget(fetches.clone());
    host.add_file("app.csproj", CSPROJ);
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[Event::FileOpened(CSPROJ_PATH.to_owned())],
        &host.invocation(),
    );
    let fetches_after_refresh = fetches.get();

    let document = Document {
        path: CSPROJ_PATH.to_owned(),
        language: "xml".to_owned(),
        version: 1,
        text: CSPROJ.to_owned(),
    };
    let actions = Providers::code_actions(
        &mut plugin,
        &document,
        Range::new(Position::new(2, 3), Position::new(2, 3)),
    );
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].title, "Update Newtonsoft.Json to 13.0.4 (patch)");
    let (edit_path, edits) = &actions[0].edits[0];
    assert_eq!(edit_path, CSPROJ_PATH);
    assert_eq!(edits[0].range, NEWTONSOFT_VERSION_RANGE);
    assert_eq!(edits[0].text, "13.0.4");
    assert_eq!(fetches.get(), fetches_after_refresh);
}

const GEMFILE_PATH: &str = "/p/Gemfile";
const GEMFILE: &str = "gem 'rails', '~> 7.0.4'\n";
/// The version of `rails` sits on line 0; its version text is columns 17..22.
const RAILS_VERSION_RANGE: Range = Range::new(Position::new(0, 17), Position::new(0, 22));
const RUBYGEMS_RAILS_BODY: &str =
    r#"[{"number":"8.1.4.1","prerelease":false},{"number":"7.0.4","prerelease":false}]"#;

#[test]
fn gemfile_requirement_shows_the_registry_version_and_offers_a_major_update() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_with_registry(
        fetches.clone(),
        "net:rubygems.org",
        "https://rubygems.org/api/v1/versions/",
        RUBYGEMS_RAILS_BODY,
    );
    host.add_file("Gemfile", GEMFILE);
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[Event::FileOpened(GEMFILE_PATH.to_owned())],
        &host.invocation(),
    );

    let decorations = decorations_of(&host, GEMFILE_PATH);
    let rails = decorations
        .iter()
        .find(|decoration| decoration.range == RAILS_VERSION_RANGE)
        .expect("decoration on rails");
    assert_eq!(rails.after, Some("→ 8.1.4.1".to_string()));
    assert_eq!(rails.style, "info");
    assert!(diagnostics_of(&host, GEMFILE_PATH).is_empty());

    let fetches_after_refresh = fetches.get();
    let document = Document {
        path: GEMFILE_PATH.to_owned(),
        language: "ruby".to_owned(),
        version: 1,
        text: GEMFILE.to_owned(),
    };
    let actions = Providers::code_actions(
        &mut plugin,
        &document,
        Range::new(Position::new(0, 3), Position::new(0, 3)),
    );
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].title, "Update rails to 8.1.4.1 (major)");
    assert!(!actions[0].preferred);
    let (edit_path, edits) = &actions[0].edits[0];
    assert_eq!(edit_path, GEMFILE_PATH);
    assert_eq!(edits[0].range, RAILS_VERSION_RANGE);
    assert_eq!(edits[0].text, "8.1.4.1");
    assert_eq!(fetches.get(), fetches_after_refresh);
}

const PYPI_PREFIX: &str = "https://pypi.org/pypi/";
const PYPI_LATEST_BODY: &str =
    r#"{"info":{"version":"2.0"},"releases":{"2.0":[{"yanked":false}]}}"#;
/// Text of a decoration whose package has a newer release (`pkgN==1.0` against 2.0).
const LATEST_TEXT: &str = "→ 2.0";
/// Text of a decoration whose lookup has not run yet.
const PENDING_TEXT: &str = "…";

/// `count` pins `pkg{first}==1.0` … one per line, so every package name is distinct.
fn pinned_requirements(first: usize, count: usize) -> String {
    (first..first + count)
        .map(|number| format!("pkg{number}==1.0\n"))
        .collect()
}

/// A mock that answers PyPI pages with latest 2.0 and OSV, counting every request.
fn host_with_pypi_latest(fetches: Rc<Cell<u32>>) -> MockHost {
    host_with_registry(fetches, "net:pypi.org", PYPI_PREFIX, PYPI_LATEST_BODY)
}

/// Counts the PyPI lookups the plugin sent.
fn registry_requests(host: &MockHost) -> usize {
    host.requests()
        .iter()
        .filter(|request| request.url.starts_with(PYPI_PREFIX))
        .count()
}

/// The largest number of times one PyPI URL was requested; above one means a repeated lookup.
fn largest_repeat_of_a_lookup(host: &MockHost) -> usize {
    let mut counts = std::collections::HashMap::<String, usize>::new();
    for request in host.requests() {
        if request.url.starts_with(PYPI_PREFIX) {
            *counts.entry(request.url).or_default() += 1;
        }
    }
    counts.values().copied().max().unwrap_or(0)
}

/// Counts the decorations of `path` whose text is `after`.
fn count_decorations_with(host: &MockHost, path: &str, after: &str) -> usize {
    decorations_of(host, path)
        .iter()
        .filter(|decoration| decoration.after.as_deref() == Some(after))
        .count()
}

#[test]
fn default_limits_resolve_every_package_in_one_refresh() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_with_pypi_latest(fetches.clone());
    host.add_file("requirements.txt", &pinned_requirements(0, 300));
    let mut plugin = DependencyLens::default();
    plugin.handle_events(
        &[Event::FileOpened(REQUIREMENTS_PATH.to_owned())],
        &host.invocation(),
    );

    let decorations = decorations_of(&host, REQUIREMENTS_PATH);
    assert_eq!(decorations.len(), 300);
    assert!(
        decorations
            .iter()
            .all(|decoration| decoration.after.as_deref() == Some(LATEST_TEXT))
    );
    assert_eq!(fetches.get(), 1 + 300);
    assert_eq!(osv_batch_requests(&host), 1);

    let tasks = host.tasks();
    let last_report = tasks.last().and_then(|task| task.reports.last());
    assert_eq!(
        last_report.and_then(|(_, _, message)| message.as_deref()),
        Some("300 of 300")
    );
}

#[test]
fn zero_time_box_gives_each_save_one_chunk_until_all_resolve() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_with_pypi_latest(fetches.clone());
    host.add_file("requirements.txt", &pinned_requirements(0, 300));
    let mut plugin = DependencyLens::with_limits(Duration::ZERO, 20);
    plugin.handle_events(
        &[Event::FileOpened(REQUIREMENTS_PATH.to_owned())],
        &host.invocation(),
    );

    assert_eq!(fetches.get(), 1 + 20);
    assert_eq!(
        count_decorations_with(&host, REQUIREMENTS_PATH, LATEST_TEXT),
        20
    );
    assert_eq!(
        count_decorations_with(&host, REQUIREMENTS_PATH, PENDING_TEXT),
        280
    );
    assert!(
        decorations_of(&host, REQUIREMENTS_PATH)
            .iter()
            .filter(|decoration| decoration.after.as_deref() == Some(PENDING_TEXT))
            .all(|decoration| decoration.style == "muted")
    );

    for save_number in 1..=14 {
        plugin.handle_events(
            &[Event::FileSaved(REQUIREMENTS_PATH.to_owned())],
            &host.invocation(),
        );
        assert_eq!(
            fetches.get(),
            1 + 20 * (save_number + 1),
            "after save {save_number}"
        );
    }
    assert_eq!(registry_requests(&host), 300);
    assert_eq!(osv_batch_requests(&host), 1);
    assert_eq!(
        count_decorations_with(&host, REQUIREMENTS_PATH, LATEST_TEXT),
        300
    );
}

#[test]
fn batch_of_manifests_gives_each_its_first_chunk_then_each_save_finishes_it() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_with_pypi_latest(fetches.clone());
    let paths = [
        "/p/a/requirements.txt",
        "/p/b/requirements.txt",
        "/p/c/requirements.txt",
    ];
    host.add_file("a/requirements.txt", &pinned_requirements(0, 40));
    host.add_file("b/requirements.txt", &pinned_requirements(40, 40));
    host.add_file("c/requirements.txt", &pinned_requirements(80, 40));
    let mut plugin = DependencyLens::with_limits(Duration::ZERO, 20);
    plugin.handle_events(
        &paths.map(|path| Event::FileOpened(path.to_owned())),
        &host.invocation(),
    );

    assert_eq!(osv_batch_requests(&host), 3);
    assert_eq!(registry_requests(&host), 60);
    for path in paths {
        assert_eq!(count_decorations_with(&host, path, LATEST_TEXT), 20);
        assert_eq!(count_decorations_with(&host, path, PENDING_TEXT), 20);
    }

    plugin.handle_events(
        &paths.map(|path| Event::FileSaved(path.to_owned())),
        &host.invocation(),
    );
    assert_eq!(registry_requests(&host), 120);
    assert_eq!(osv_batch_requests(&host), 3);
    for path in paths {
        assert_eq!(count_decorations_with(&host, path, LATEST_TEXT), 40);
    }
}

#[test]
fn zero_cache_lifetime_resolves_everything_without_repeating_a_lookup() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_with_pypi_latest(fetches.clone());
    host.set_setting("cacheTtlSeconds", "0");
    host.add_file("requirements.txt", &pinned_requirements(0, 300));
    let mut plugin = DependencyLens::with_limits(Duration::from_secs(300), 20);
    plugin.activate(&host.context(PLUGIN_ID)).unwrap();
    plugin.handle_events(
        &[Event::FileOpened(REQUIREMENTS_PATH.to_owned())],
        &host.invocation(),
    );

    assert_eq!(
        count_decorations_with(&host, REQUIREMENTS_PATH, LATEST_TEXT),
        300
    );
    assert_eq!(registry_requests(&host), 300);
    assert_eq!(largest_repeat_of_a_lookup(&host), 1);
    assert_eq!(osv_batch_requests(&host), 1);
}

#[test]
fn progress_reports_grow_during_one_refresh() {
    let host = host_with_pypi_latest(Rc::new(Cell::new(0)));
    host.add_file("requirements.txt", &pinned_requirements(0, 300));
    let mut plugin = DependencyLens::with_limits(Duration::from_secs(300), 20);
    plugin.handle_events(
        &[Event::FileOpened(REQUIREMENTS_PATH.to_owned())],
        &host.invocation(),
    );

    let tasks = host.tasks();
    assert_eq!(tasks.len(), 1);
    let done_counts: Vec<u32> = tasks[0].reports.iter().map(|(done, _, _)| *done).collect();
    assert_eq!(
        done_counts,
        (1..=15).map(|chunk| chunk * 20).collect::<Vec<u32>>()
    );
    assert!(
        tasks[0]
            .reports
            .iter()
            .all(|(_, total, _)| *total == Some(300))
    );
}

#[test]
fn removed_manifest_stays_cleared_while_its_lookups_are_unfinished() {
    let host = host_with_pypi_latest(Rc::new(Cell::new(0)));
    host.add_file("requirements.txt", &pinned_requirements(0, 300));
    let mut plugin = DependencyLens::with_limits(Duration::ZERO, 20);
    plugin.handle_events(
        &[Event::FileOpened(REQUIREMENTS_PATH.to_owned())],
        &host.invocation(),
    );
    assert!(!decorations_of(&host, REQUIREMENTS_PATH).is_empty());

    plugin.handle_events(
        &[Event::FilesChanged(FilesChanged {
            created: Vec::new(),
            modified: Vec::new(),
            removed: vec![REQUIREMENTS_PATH.to_owned()],
        })],
        &host.invocation(),
    );
    assert!(decorations_of(&host, REQUIREMENTS_PATH).is_empty());
    assert!(diagnostics_of(&host, REQUIREMENTS_PATH).is_empty());
}

#[test]
fn time_box_too_large_for_the_clock_still_resolves_every_package() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_with_pypi_latest(fetches.clone());
    host.add_file("requirements.txt", &pinned_requirements(0, 300));
    let mut plugin = DependencyLens::with_limits(Duration::MAX, 20);
    plugin.handle_events(
        &[Event::FileOpened(REQUIREMENTS_PATH.to_owned())],
        &host.invocation(),
    );

    assert_eq!(
        count_decorations_with(&host, REQUIREMENTS_PATH, LATEST_TEXT),
        300
    );
    assert_eq!(fetches.get(), 1 + 300);
}

#[test]
fn scheduled_event_is_ignored() {
    let fetches = Rc::new(Cell::new(0));
    let host = host_with_pypi_latest(fetches.clone());
    let mut plugin = DependencyLens::default();
    plugin.handle_events(&[Event::Scheduled], &host.invocation());
    assert_eq!(fetches.get(), 0);
    assert!(host.tasks().is_empty());
    assert!(host.decorations().is_empty());
}
