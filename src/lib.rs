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

use crate::analysis::{Analysis, Budget, analyze};
use crate::cache::Cache;
use crate::http::HostHttp;
use crate::model::{Dependency, Ecosystem};
use crate::settings::Settings;
use openidea_plugin::host::Task;
use openidea_plugin::providers::{CodeAction, Document, Providers};
use openidea_plugin::{
    Context, Decoration, Diagnostic, Error, Event, EventKind, Invocation, LogLevel, Plugin, Range,
    host, register_plugin,
};
use std::collections::{BTreeSet, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Folders whose manifests belong to dependencies or build output, not to the project.
const SKIPPED_DIRECTORIES: [&str; 4] = ["node_modules", "target", "vendor", ".git"];
/// Time box of one `handle_events` call, kept below the host's 60 s task limit.
/// The deadline is checked between chunks, so a call can overrun it by one chunk.
const TIME_BOX: Duration = Duration::from_secs(50);
/// Registry lookups per chunk. Each chunk publishes its results before the next one starts.
const REGISTRY_CHUNK: usize = 20;
/// Title of the background task shown while a manifest is analyzed.
const TASK_TITLE: &str = "Dependency Lens";

/// Dependency Lens plugin state: the analysis cache, the settings it runs with, and the work left over.
pub struct DependencyLens {
    cache: Cache,
    settings: Settings,
    time_box: Duration,
    chunk: usize,
    /// Manifests whose registry lookups did not finish. Sorted, so each `Scheduled` event visits them in one order.
    pending_paths: BTreeSet<String>,
}

impl Default for DependencyLens {
    fn default() -> Self {
        let settings = Settings::default();
        Self {
            cache: Cache::new(settings.cache_ttl_secs),
            settings,
            time_box: TIME_BOX,
            chunk: REGISTRY_CHUNK,
            pending_paths: BTreeSet::new(),
        }
    }
}

impl DependencyLens {
    /// Creates a plugin with a custom time box per `handle_events` call and registry lookups per chunk.
    ///
    /// For tuning and tests. `Default` uses the constants. A chunk is at least one lookup,
    /// so every chunk makes progress.
    pub fn with_limits(time_box: Duration, chunk: usize) -> Self {
        Self {
            time_box,
            chunk: chunk.max(1),
            ..Self::default()
        }
    }

    /// Loads the settings from the host. The cache is replaced only when its lifetime changed.
    fn reload_settings(&mut self) {
        let settings = Settings::from_host();
        if settings.cache_ttl_secs != self.settings.cache_ttl_secs {
            self.cache = Cache::new(settings.cache_ttl_secs);
        }
        self.settings = settings;
    }

    /// Analyzes the manifest at `path` and publishes its decorations and problems, chunk by chunk.
    ///
    /// A path that comes after an expired `deadline` waits in `pending_paths`, so its file is not read.
    /// The first path of a batch always makes progress, even when the deadline has passed.
    fn refresh(
        &mut self,
        path: &str,
        ctx: &Invocation,
        deadline: Instant,
        batch_progressed: &mut bool,
    ) {
        if Instant::now() >= deadline && *batch_progressed {
            self.pending_paths.insert(path.to_owned());
            return;
        }
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
        let pending_count = self.publish_chunks(eco, path, &text, &deps, &task, deadline);
        // Every call publishes at least one chunk, so the batch has made progress from here on.
        *batch_progressed = true;
        if pending_count == 0 {
            self.pending_paths.remove(path);
        } else {
            self.pending_paths.insert(path.to_owned());
        }
    }

    /// Runs the registry lookups of `deps` in chunks and publishes after each chunk.
    ///
    /// Stops when no entry is pending, when the task is cancelled, or when `deadline` has passed.
    /// The deadline ends the loop only after one chunk of this call, so a call always makes progress.
    /// Returns the pending count of the last chunk.
    fn publish_chunks(
        &mut self,
        eco: Ecosystem,
        path: &str,
        text: &str,
        deps: &[Dependency],
        task: &Task,
        deadline: Instant,
    ) -> usize {
        let mut pending_count = 0;
        let mut is_first_chunk = true;
        loop {
            if !is_first_chunk && Instant::now() >= deadline {
                break;
            }
            is_first_chunk = false;
            // The dependency vector is cloned per chunk; the parse is not repeated.
            let mut budget = Budget::new(self.chunk, None);
            let analysis = analyze(
                eco,
                deps.to_vec(),
                &mut self.cache,
                &HostHttp,
                &self.settings,
                now_secs(),
                &mut budget,
            );
            publish_analysis(path, text, &analysis);
            pending_count = analysis.pending;
            // Pending entries are the only ones without a status, so the done count is a subtraction, not a scan.
            let total = analysis.entries.len();
            let done = total.saturating_sub(pending_count);
            task.report(
                done as u32,
                Some(total as u32),
                Some(&format!("{done} of {total}")),
            );
            if pending_count == 0 || task.is_cancelled() {
                break;
            }
        }
        pending_count
    }
}

/// Publishes the decorations and problems of one analysis of the manifest `text` at `path`.
fn publish_analysis(path: &str, text: &str, analysis: &Analysis) {
    let editor_decorations = publish::decorations(text, analysis);
    let problems = publish::diagnostics(text, analysis);
    publish_results(path, &editor_decorations, &problems);
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
                // A command is one batch of its own: it gets a fresh time box.
                let deadline = Instant::now() + self.time_box;
                let mut batch_progressed = false;
                self.refresh(&path, ctx, deadline, &mut batch_progressed);
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
        let mut scheduled = false;
        for event in events {
            match event {
                Event::Other { kind, .. } if kind == "settings-changed" => settings_changed = true,
                Event::Scheduled => scheduled = true,
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
            self.pending_paths.remove(path);
            publish_results(path, &[], &[]);
        }
        // One deadline and one progress flag for the whole batch, so the time box is shared.
        let deadline = Instant::now() + self.time_box;
        let mut batch_progressed = false;
        // A set skips a path that appears twice in one batch; the first occurrence keeps its place.
        let mut refreshed: HashSet<&str> = HashSet::new();
        for path in changed_paths.into_iter().filter(|path| is_manifest(path)) {
            if refreshed.insert(path) {
                self.refresh(path, ctx, deadline, &mut batch_progressed);
            }
        }
        // Nothing pending means no host call. Otherwise the set is taken, and the shared deadline bounds all its paths.
        if scheduled && !self.pending_paths.is_empty() {
            for path in std::mem::take(&mut self.pending_paths) {
                self.refresh(&path, ctx, deadline, &mut batch_progressed);
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
