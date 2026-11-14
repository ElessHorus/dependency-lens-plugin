//! Dependency Lens: an OpenIDEA plugin.

pub mod actions;
pub mod analysis;
pub mod cache;
pub mod http;
pub mod model;
pub mod osv;
pub mod parsers;
pub mod publish;
pub mod registries;
pub mod settings;
pub mod text;
pub mod update;

use crate::analysis::{Budget, analyze};
use crate::cache::Cache;
use crate::http::HostHttp;
use crate::model::Ecosystem;
use crate::settings::Settings;
use openidea_plugin::providers::{CodeAction, Document, Providers};
use openidea_plugin::{
    Context, Decoration, Diagnostic, Error, Event, EventKind, Invocation, LogLevel, Plugin, Range,
    host, register_plugin,
};
use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Folders whose manifests belong to dependencies or build output, not to the project.
const SKIPPED_DIRECTORIES: [&str; 4] = ["node_modules", "target", "vendor", ".git"];
/// Wall-clock limit of one lookup run, kept below the host's 60 s task limit.
const LOOKUP_DEADLINE: Duration = Duration::from_secs(50);
/// Title of the background task shown while a manifest is analyzed.
const TASK_TITLE: &str = "Dependency Lens";

/// Dependency Lens plugin state: the analysis cache and the settings it runs with.
pub struct DependencyLens {
    cache: Cache,
    settings: Settings,
}

impl Default for DependencyLens {
    fn default() -> Self {
        let settings = Settings::default();
        Self {
            cache: Cache::new(settings.cache_ttl_secs),
            settings,
        }
    }
}

impl DependencyLens {
    /// Loads the settings from the host. The cache is replaced only when its lifetime changed.
    fn reload_settings(&mut self) {
        let settings = Settings::from_host();
        if settings.cache_ttl_secs != self.settings.cache_ttl_secs {
            self.cache = Cache::new(settings.cache_ttl_secs);
        }
        self.settings = settings;
    }

    /// Analyzes the manifest at `path` and publishes its decorations and problems.
    ///
    /// Publishes once, after the analysis. A cancelled task publishes nothing.
    fn refresh(&mut self, path: &str, ctx: &Invocation) {
        let Some(eco) = Ecosystem::detect(path) else {
            return;
        };
        // The deepest open project holding the path wins; the window's project is only a fallback.
        let Some(project) = host::project_of(path).or_else(|| ctx.project()) else {
            return;
        };
        let text = match project.read_file(path) {
            Ok(text) => text,
            Err(error) => {
                host::log(LogLevel::Warn, &format!("cannot read {path}: {error}"));
                return;
            }
        };
        let deps = eco.parse(&text);
        let task = host::begin_task(TASK_TITLE, true);
        let mut budget = Budget::new(usize::MAX, Some(Instant::now() + LOOKUP_DEADLINE));
        let analysis = analyze(
            eco,
            deps,
            &mut self.cache,
            &HostHttp,
            &self.settings,
            now_secs(),
            &mut budget,
        );
        if task.is_cancelled() {
            return;
        }
        let editor_decorations = publish::decorations(&text, &analysis);
        let problems = publish::diagnostics(&text, &analysis);
        publish_results(path, &editor_decorations, &problems);
    }
}

/// Replaces what the editor shows for `path`; empty lists clear the previous results.
fn publish_results(path: &str, editor_decorations: &[Decoration], problems: &[Diagnostic]) {
    log_failure(
        path,
        "decorations",
        host::set_decorations(path, publish::DECORATION_SET, editor_decorations),
    );
    log_failure(
        path,
        "diagnostics",
        host::publish_diagnostics(path, problems),
    );
}

/// Logs a failed host call. A failed publication must not stop the plugin.
fn log_failure(path: &str, what: &str, result: Result<(), Error>) {
    if let Err(error) = result {
        host::log(LogLevel::Warn, &format!("{what} for {path}: {error}"));
    }
}

/// Seconds since the UNIX epoch; zero when the clock is before it.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Whether `path` is a manifest the plugin analyzes, outside dependency and build folders.
pub(crate) fn is_manifest(path: &str) -> bool {
    Ecosystem::detect(path).is_some()
        && !path
            .split(['/', '\\'])
            .any(|part| SKIPPED_DIRECTORIES.contains(&part))
}

impl Plugin for DependencyLens {
    fn activate(&mut self, _ctx: &Context) -> Result<(), Error> {
        self.reload_settings();
        host::subscribe(EventKind::FileOpened)?;
        host::subscribe(EventKind::FileSaved)?;
        host::subscribe(EventKind::FilesChanged)?;
        host::subscribe(EventKind::SettingsChanged)
    }

    fn run_command(
        &mut self,
        id: &str,
        ctx: &Invocation,
        _arg: Option<&str>,
    ) -> Result<Option<String>, Error> {
        match id {
            "refresh" => {
                let editor = ctx
                    .editor()
                    .ok_or_else(|| Error::Invalid("no file is open".to_owned()))?;
                let path = editor.path();
                if !is_manifest(&path) {
                    return Ok(Some("Dependency Lens: not a supported manifest".to_owned()));
                }
                self.refresh(&path, ctx);
                Ok(Some("Dependency Lens: refreshed".to_owned()))
            }
            _ => Err(Error::NotFound(format!("command {id}"))),
        }
    }

    fn handle_events(&mut self, events: &[Event], ctx: &Invocation) {
        // Borrowed paths: the batch is read once and no path is copied.
        let mut changed_paths: Vec<&str> = Vec::new();
        let mut removed_paths: Vec<&str> = Vec::new();
        let mut settings_changed = false;
        for event in events {
            match event {
                Event::Other { kind, .. } if kind == "settings-changed" => settings_changed = true,
                Event::FileOpened(path) | Event::FileSaved(path) => changed_paths.push(path),
                Event::FilesChanged(changes) => {
                    changed_paths.extend(
                        changes
                            .created
                            .iter()
                            .chain(&changes.modified)
                            .map(String::as_str),
                    );
                    removed_paths.extend(changes.removed.iter().map(String::as_str));
                }
                _ => {}
            }
        }
        // Reloaded before any refresh below, so this batch's manifests use the new settings.
        if settings_changed {
            self.reload_settings();
        }
        for path in removed_paths.into_iter().filter(|path| is_manifest(path)) {
            publish_results(path, &[], &[]);
        }
        // A set skips a path that appears twice in one batch; the first occurrence keeps its place.
        let mut refreshed: HashSet<&str> = HashSet::new();
        for path in changed_paths.into_iter().filter(|path| is_manifest(path)) {
            if refreshed.insert(path) {
                self.refresh(path, ctx);
            }
        }
    }
}

impl Providers for DependencyLens {
    fn code_actions(&mut self, doc: &Document, selection: Range) -> Vec<CodeAction> {
        actions::code_actions(
            &self.cache,
            &self.settings,
            &doc.path,
            &doc.text,
            selection,
            now_secs(),
        )
    }
}

register_plugin!(DependencyLens, providers);
