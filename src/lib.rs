//! Dependency Lens: an OpenIDEA plugin.

pub mod actions;
pub mod analysis;
pub mod cache;
pub mod fixes;
pub mod http;
pub mod model;
pub mod osv;
pub mod parsers;
pub mod publish;
pub mod registries;
pub mod settings;
pub mod store;
pub mod text;
pub mod update;

use crate::analysis::{Analysis, Budget, analyze};
use crate::cache::Cache;
use crate::http::HostHttp;
use crate::model::{Dependency, Ecosystem};
use crate::osv::DEFAULT_DETAILS_PER_QUERY;
use crate::settings::Settings;
use openidea_plugin::host::Task;
use openidea_plugin::providers::{CodeAction, Document, Providers};
use openidea_plugin::{
    Context, Decoration, Diagnostic, Error, Event, EventKind, Invocation, LogLevel, Plugin, Range,
    host, register_plugin,
};
use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Folders whose manifests belong to dependencies or build output, not to the project.
const SKIPPED_DIRECTORIES: [&str; 4] = ["node_modules", "target", "vendor", ".git"];
/// Soft time cap of one `handle_events` call, checked between chunks.
/// Entries still pending at the cap are finished by the next open, save or refresh of their manifest.
const TIME_BOX: Duration = Duration::from_secs(300);
/// Hard limit of one chunk. Its lookups that start after this limit stay pending.
const CHUNK_LIMIT: Duration = Duration::from_secs(40);
/// How long the action that loads the deferred advisories may fetch details. The refresh that
/// follows must fit in the 60 s that an open task allows, so this stays well below it.
const LOAD_ACTION_LIMIT: Duration = Duration::from_secs(30);
/// Registry lookups per chunk. Each chunk publishes its results before the next one starts.
const REGISTRY_CHUNK: usize = 20;
/// Package versions that the first chunk of a manifest sends to OSV, at the least. Each chunk then
/// doubles the share, so a slow package delays only its own slice and the first dependency shows
/// at once. It costs a few more requests (one batch per slice): measured on 10 old PyPI packages,
/// the first one shows after 0.8 s instead of 11 s, and the whole manifest takes 1 to 2 s longer.
const OSV_FIRST_SLICE: usize = 1;
/// Offset of the fallback deadline used when a time box is too large for the clock.
const FAR_FUTURE: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
/// Title of the background task shown while a manifest is analyzed.
const TASK_TITLE: &str = "Dependency Lens";

/// The limits of one refresh of a manifest.
#[derive(Clone, Copy)]
struct RunLimits {
    /// The instant after which the chunk loop stops.
    deadline: Instant,
    /// Advisories per package version whose details load. `usize::MAX` loads every one.
    details_per_query: usize,
}

impl RunLimits {
    /// The limits of an open, a save or a refresh: ten advisories per package version.
    fn standard(deadline: Instant) -> Self {
        Self {
            deadline,
            details_per_query: DEFAULT_DETAILS_PER_QUERY,
        }
    }
}

/// Dependency Lens plugin state: the analysis cache, the settings it runs with, the manifests it
/// shows, and the chunk limits.
pub struct DependencyLens {
    cache: Cache,
    settings: Settings,
    /// Manifests with published results. A settings change republishes them.
    published_paths: HashSet<String>,
    time_box: Duration,
    chunk: usize,
}

impl Default for DependencyLens {
    fn default() -> Self {
        let settings = Settings::default();
        Self {
            cache: Cache::new(settings.cache_ttl_secs),
            settings,
            published_paths: HashSet::new(),
            time_box: TIME_BOX,
            chunk: REGISTRY_CHUNK,
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

    /// Lookups per chunk. Without a cache, a chunk cannot keep what it finds, so one pass does all of them.
    fn chunk_size(&self) -> usize {
        if self.settings.cache_ttl_secs == 0 {
            usize::MAX
        } else {
            self.chunk
        }
    }

    /// Analyzes the manifest at `path` and publishes its decorations and problems, chunk by chunk.
    ///
    /// Every call makes at least its first chunk, so each manifest of a batch makes progress.
    ///
    /// Returns the number of advisories of the manifest whose details are still not loaded,
    /// or `None` when the host cancelled the run because a newer call supersedes it.
    fn refresh(
        &mut self,
        path: &str,
        ctx: Option<&Invocation>,
        limits: RunLimits,
    ) -> Option<usize> {
        let Some(eco) = Ecosystem::detect(path) else {
            return Some(0);
        };
        // The deepest open project holding the path wins; the window's project is only a fallback.
        let Some(project) = host::project_of(path).or_else(|| ctx.and_then(Invocation::project))
        else {
            self.forget_shown(path);
            return Some(0);
        };
        let text = match project.read_file(path) {
            Ok(text) => text,
            Err(error) => {
                self.forget_shown(path);
                host::log(LogLevel::Warn, &format!("cannot read {path}: {error}"));
                return Some(0);
            }
        };
        let deps = eco.parse(&text);
        self.published_paths.insert(path.to_owned());
        let task = host::begin_task(TASK_TITLE, true);
        self.publish_chunks(eco, path, &text, &deps, &task, limits)
    }

    /// Stops tracking a manifest that cannot be read, and clears what the editor still shows for it.
    fn forget_shown(&mut self, path: &str) {
        if self.published_paths.remove(path) {
            publish_results(path, &[], &[]);
        }
    }

    /// Runs the registry lookups of `deps` in chunks and publishes after each chunk.
    ///
    /// Reports progress and checks cancellation after every chunk. The host renews the call's
    /// time budget on each of these, so a long manifest is not cut while it reports.
    /// Returns the number of advisories whose details are still not loaded after the last chunk,
    /// or `None` when the host cancelled a request of the first chunk.
    fn publish_chunks(
        &mut self,
        eco: Ecosystem,
        path: &str,
        text: &str,
        deps: &[Dependency],
        task: &Task,
        limits: RunLimits,
    ) -> Option<usize> {
        let chunk = self.chunk_size();
        // One clock reading serves the whole run. With a cache lifetime shorter than a chunk, a
        // fresh reading per chunk would expire the answers of the chunk before and repeat its work.
        let run_started_at = now_secs();
        let mut previous_pending = None;
        loop {
            // The dependency vector is cloned per chunk; the parse is not repeated.
            // Each chunk gets its own deadline. The first registry lookup of a chunk runs unless the deadline has passed,
            // and the OSV phase stops fetching advisory details once the deadline has passed.
            let mut budget = Budget::new(chunk, Some(Instant::now() + CHUNK_LIMIT))
                .with_detail_limit(limits.details_per_query);
            // Without a cache a chunk keeps nothing, so one pass does all of them, OSV included.
            if chunk != usize::MAX {
                budget = budget.with_first_osv_slice(OSV_FIRST_SLICE);
            }
            let analysis = analyze(
                eco,
                deps.to_vec(),
                &mut self.cache,
                &HostHttp,
                &self.settings,
                run_started_at,
                &mut budget,
            );
            if budget.is_cancelled() {
                // A newer call supersedes this one and refreshes the manifest. Publishing the
                // unfinished analysis would replace good results with `…` or `?`. After the first
                // chunk, what the editor shows is already a published result, so it stays as it is.
                return previous_pending.is_some().then_some(0);
            }
            publish_analysis(path, text, &analysis, self.settings.outdated_problems);
            let pending = analysis.pending;
            let unloaded = analysis.unloaded_advisory_count();
            // Pending entries are the only ones without a status, so the done count is a subtraction, not a scan.
            let total = analysis.entries.len();
            let done = total.saturating_sub(pending);
            task.report(
                done as u32,
                Some(total as u32),
                Some(&format!("{done} of {total}")),
            );
            let cancelled = task.is_cancelled();
            if !should_continue(
                pending,
                previous_pending,
                cancelled,
                Instant::now(),
                limits.deadline,
            ) {
                return Some(unloaded);
            }
            previous_pending = Some(pending);
        }
    }
}

/// The instant `time_box` from now. A box too large for the clock ends far in the future instead.
fn deadline_after(time_box: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(time_box)
        .or_else(|| now.checked_add(FAR_FUTURE))
        .unwrap_or(now)
}

/// Whether the chunk loop runs one more chunk after a chunk that left `pending` entries.
///
/// `previous_pending` is the pending count of the chunk before, or `None` after the first chunk.
/// A chunk that does not lower the pending count stops the loop, because the next chunk would repeat it.
fn should_continue(
    pending: usize,
    previous_pending: Option<usize>,
    cancelled: bool,
    now: Instant,
    deadline: Instant,
) -> bool {
    pending > 0
        && !cancelled
        && now < deadline
        && previous_pending.is_none_or(|previous| pending < previous)
}

/// Publishes the decorations and problems of one analysis of the manifest `text` at `path`.
fn publish_analysis(path: &str, text: &str, analysis: &Analysis, outdated_problems: bool) {
    let editor_decorations = publish::decorations(text, analysis);
    let problems = publish::diagnostics(text, analysis, outdated_problems);
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
///
/// Only the folders inside the project count as skipped, so a project that sits under a
/// folder named `vendor` or `target` is still analyzed.
pub(crate) fn is_manifest(path: &str) -> bool {
    // `&&` stops at the cheap name check, so the host is asked only for real manifest names.
    Ecosystem::detect(path).is_some() && is_manifest_in(path, project_root_of(path).as_deref())
}

/// The root of the open project that holds `path`, when the host knows one.
fn project_root_of(path: &str) -> Option<String> {
    host::project_of(path)?.root().ok()
}

/// Whether `path` is a manifest of the project at `project_root`. It does not ask the host.
pub(crate) fn is_manifest_in(path: &str, project_root: Option<&str>) -> bool {
    Ecosystem::detect(path).is_some() && !is_in_skipped_directory(path, project_root)
}

/// Whether `path` lies in a skipped folder, looking only at the part below `project_root`.
///
/// Without a project root, the whole path is checked.
fn is_in_skipped_directory(path: &str, project_root: Option<&str>) -> bool {
    let path_parts = path_components(path);
    // Whole components are compared, so `/p/app2` is not inside `/p/app`. Both separators count,
    // because the host may write a Windows path either way.
    let below_root = project_root.and_then(|root| {
        // Windows paths ignore case. A path with a drive colon or a backslash is one of them.
        let ignores_case = root.contains([':', '\\']);
        let mut remaining_parts = path_parts.clone();
        path_components(root)
            .all(|root_part| {
                remaining_parts.next().is_some_and(|part| {
                    part == root_part || (ignores_case && part.eq_ignore_ascii_case(root_part))
                })
            })
            .then_some(remaining_parts)
    });
    below_root
        .unwrap_or(path_parts)
        .any(|part| SKIPPED_DIRECTORIES.contains(&part))
}

/// The non-empty parts of a path, split at `/` and `\`.
fn path_components(path: &str) -> impl Iterator<Item = &str> + Clone {
    path.split(['/', '\\']).filter(|part| !part.is_empty())
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
                self.refresh(
                    &path,
                    Some(ctx),
                    RunLimits::standard(deadline_after(self.time_box)),
                );
                Ok(Some("Dependency Lens: refreshed".to_owned()))
            }
            "load-vulnerabilities" => {
                let editor = ctx
                    .editor()
                    .ok_or_else(|| Error::Invalid("no file is open".to_owned()))?;
                let path = editor.path();
                if !is_manifest(&path) {
                    return Ok(Some("Dependency Lens: not a supported manifest".to_owned()));
                }
                // The details of the deferred advisories load now, for this manifest only.
                let limits = RunLimits {
                    details_per_query: usize::MAX,
                    ..RunLimits::standard(deadline_after(self.time_box))
                };
                if !self.settings.vulnerabilities {
                    return Ok(Some(
                        "Dependency Lens: vulnerabilities are turned off".to_owned(),
                    ));
                }
                let message = match self.refresh(&path, Some(ctx), limits) {
                    None => "Dependency Lens: a newer request cancelled this one. Run the command again."
                        .to_owned(),
                    Some(0) => "Dependency Lens: vulnerabilities loaded".to_owned(),
                    Some(unloaded) => format!(
                        "Dependency Lens: {unloaded} advisories are still not loaded. Run the command again."
                    ),
                };
                Ok(Some(message))
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
            self.published_paths.remove(path);
            publish_results(path, &[], &[]);
        }
        // One deadline for the batch: manifests after it still get their first chunk.
        let deadline = deadline_after(self.time_box);
        // A set skips a path that appears twice in one batch; the first occurrence keeps its place.
        let mut refreshed: HashSet<&str> = HashSet::new();
        for path in changed_paths.into_iter().filter(|path| is_manifest(path)) {
            if refreshed.insert(path) {
                self.refresh(path, Some(ctx), RunLimits::standard(deadline));
            }
        }
        // A new setting changes what the shown manifests display. The cache answers most of it
        // without a request, and a disabled ecosystem clears its results.
        if settings_changed {
            let shown_paths: Vec<String> = self
                .published_paths
                .iter()
                .filter(|path| !refreshed.contains(path.as_str()))
                .cloned()
                .collect();
            for path in &shown_paths {
                self.refresh(path, Some(ctx), RunLimits::standard(deadline));
            }
        }
    }
}

impl DependencyLens {
    /// Loads the deferred advisories of the dependency `name` of the manifest `doc`, then shows them.
    ///
    /// A first run, limited to that dependency, puts every detail in the cache. It makes no registry
    /// lookup and publishes nothing. A standard refresh then publishes the manifest from the cache.
    fn load_vulnerabilities_of(&mut self, doc: &Document, name: &str) {
        let Some(eco) = Ecosystem::detect(&doc.path) else {
            return;
        };
        // The setting may have changed since the action was listed.
        if !self.settings.vulnerabilities {
            return;
        }
        let deps: Vec<Dependency> = eco
            .parse(&doc.text)
            .into_iter()
            .filter(|dependency| dependency.name == name)
            .collect();
        if deps.is_empty() {
            return;
        }
        // The call has a budget of 5 s. An open task lifts it to 60 s, so up to 100 details fit,
        // and the chunk limit stops the fetches before the budget ends.
        let task = host::begin_task(TASK_TITLE, true);
        let deadline = Instant::now() + LOAD_ACTION_LIMIT;
        let mut budget = Budget::new(0, Some(deadline)).with_detail_limit(usize::MAX);
        analyze(
            eco,
            deps,
            &mut self.cache,
            &HostHttp,
            &self.settings,
            now_secs(),
            &mut budget,
        );
        // The refresh opens its own task, so this one ends first.
        drop(task);
        // A superseded run leaves the manifest as it is. The newer call refreshes it.
        if !budget.is_cancelled() {
            self.refresh(&doc.path, None, RunLimits::standard(deadline));
        }
    }
}

impl Providers for DependencyLens {
    fn resolve_code_action(
        &mut self,
        doc: &Document,
        action: CodeAction,
    ) -> Result<CodeAction, Error> {
        let package = action
            .data
            .as_deref()
            .and_then(|data| data.strip_prefix(actions::LOAD_ACTION_PREFIX))
            .map(str::to_owned);
        if let Some(package) = package {
            self.load_vulnerabilities_of(doc, &package);
        }
        // The action has no edit, so the editor changes nothing.
        Ok(action)
    }

    fn code_actions(&mut self, doc: &Document, selection: Range) -> Vec<CodeAction> {
        actions::code_actions(
            &self.cache,
            &self.settings,
            &doc.path,
            project_root_of(&doc.path).as_deref(),
            &doc.text,
            selection,
            now_secs(),
        )
    }
}

register_plugin!(DependencyLens, providers);

#[cfg(test)]
mod loop_tests {
    use super::*;

    /// A deadline one minute away, so the time cap does not end the loop.
    fn open_deadline(now: Instant) -> Instant {
        now + Duration::from_secs(60)
    }

    #[test]
    fn continues_while_pending_and_progressing_before_the_deadline() {
        let now = Instant::now();
        assert!(should_continue(280, None, false, now, open_deadline(now)));
        assert!(should_continue(
            260,
            Some(280),
            false,
            now,
            open_deadline(now)
        ));
    }

    #[test]
    fn stops_when_nothing_is_pending() {
        let now = Instant::now();
        assert!(!should_continue(
            0,
            Some(20),
            false,
            now,
            open_deadline(now)
        ));
        assert!(!should_continue(0, None, false, now, open_deadline(now)));
    }

    #[test]
    fn stops_when_cancelled() {
        let now = Instant::now();
        assert!(!should_continue(
            260,
            Some(280),
            true,
            now,
            open_deadline(now)
        ));
    }

    #[test]
    fn stops_at_or_after_the_deadline() {
        let now = Instant::now();
        assert!(!should_continue(260, Some(280), false, now, now));
    }

    #[test]
    fn stops_when_the_pending_count_does_not_decrease() {
        let now = Instant::now();
        assert!(!should_continue(
            280,
            Some(280),
            false,
            now,
            open_deadline(now)
        ));
        assert!(!should_continue(
            281,
            Some(280),
            false,
            now,
            open_deadline(now)
        ));
    }

    #[test]
    fn deadline_after_saturates_instead_of_overflowing() {
        let before = Instant::now();
        assert!(deadline_after(Duration::MAX) > before);
    }
}

#[cfg(test)]
mod skipped_directory_tests {
    use super::is_in_skipped_directory;

    #[test]
    fn only_folders_below_the_project_root_are_skipped() {
        assert!(!is_in_skipped_directory(
            "/srv/vendor/app/Cargo.toml",
            Some("/srv/vendor/app")
        ));
        assert!(is_in_skipped_directory(
            "/srv/vendor/app/target/Cargo.toml",
            Some("/srv/vendor/app")
        ));
        assert!(is_in_skipped_directory(
            "/p/node_modules/x/package.json",
            None
        ));
    }

    #[test]
    fn the_root_must_end_at_a_path_boundary() {
        // `/p/app2` is not inside `/p/app`, so the whole path is checked, and it holds no skipped folder.
        assert!(!is_in_skipped_directory(
            "/p/app2/Cargo.toml",
            Some("/p/app")
        ));
        assert!(is_in_skipped_directory(
            "/p/app2/vendor/Cargo.toml",
            Some("/p/app")
        ));
    }

    #[test]
    fn mixed_separators_and_drive_letter_case_still_match_the_root() {
        assert!(!is_in_skipped_directory(
            "C:/work/vendor/app/Cargo.toml",
            Some("C:\\work\\vendor\\app")
        ));
        assert!(!is_in_skipped_directory(
            "c:\\work\\vendor\\app\\Cargo.toml",
            Some("C:\\work\\vendor\\app\\")
        ));
        assert!(is_in_skipped_directory(
            "C:/work/vendor/app/target/Cargo.toml",
            Some("C:\\work\\vendor\\app")
        ));
    }
}

#[cfg(test)]
mod path_case_tests {
    use super::is_in_skipped_directory;

    #[test]
    fn case_matters_on_a_unix_path_and_not_on_a_windows_path() {
        // `/p/vendor/App` is another directory than `/p/vendor/app` on Linux, so the root does
        // not match and the whole path is checked, which holds `vendor`.
        assert!(is_in_skipped_directory(
            "/p/vendor/App/Cargo.toml",
            Some("/p/vendor/app")
        ));
        assert!(!is_in_skipped_directory(
            "C:/Work/vendor/App/Cargo.toml",
            Some("c:\\work\\vendor\\app")
        ));
    }
}
