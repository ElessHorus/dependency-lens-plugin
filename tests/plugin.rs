//! End-to-end tests of the plugin against the SDK mock host.

use dependency_lens::DependencyLens;
use dependency_lens::publish::DECORATION_SET;
use openidea_plugin::mock::MockHost;
use openidea_plugin::{
    Context, Decoration, Diagnostic, Error, Event, EventKind, FilesChanged, HttpRequest,
    HttpResponse, Plugin, Position, Range, Severity,
};
use serde_json::{Value, json};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;

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
fn activation_subscribes_to_the_three_events() {
    let host = host_counting_fetches(Rc::new(Cell::new(0)));
    let mut plugin = DependencyLens::default();
    plugin.activate(&Context::default()).unwrap();
    assert_eq!(
        host.subscriptions(),
        BTreeSet::from([
            EventKind::FileOpened,
            EventKind::FileSaved,
            EventKind::FilesChanged,
        ])
    );
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
