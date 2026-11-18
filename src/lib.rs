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
pub mod requirement;
pub mod settings;
pub mod store;
pub mod text;
pub mod update;

use crate::analysis::{Analysis, Budget, Entry, Status, analyze};
use crate::cache::Cache;
use crate::cache::persist::{Block, STALE_MAX_AGE_SECS, decode_block, encode_block};
use crate::http::HostHttp;
use crate::model::{Dependency, Ecosystem};
use crate::osv::DEFAULT_DETAILS_PER_QUERY;
use crate::settings::Settings;
use crate::store::{HostStore, Store, block_key};
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
    /// Ecosystems whose disk block this cache has already read. A block is read once, on first use.
    loaded_blocks: HashSet<Ecosystem>,
    /// Ecosystems whose disk block could not be read. The disk may still hold it, so this run does
    /// not write over it with what the memory alone knows.
    unreadable_blocks: HashSet<Ecosystem>,
    /// Whether a failure of the disk store was logged. One warning is enough: the store is optional.
    has_warned_about_store: bool,
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
            loaded_blocks: HashSet::new(),
            unreadable_blocks: HashSet::new(),
            has_warned_about_store: false,
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
            // The new cache is empty: its blocks load again from the disk when they are used.
            self.forget_loaded_blocks();
            if settings.cache_ttl_secs == 0 {
                // A lifetime of zero turns the disk cache off, so what it holds goes.
                self.clear_disk(&HostStore);
            }
        }
        // A package that is ignored from now on must leave the disk too: its block is written again,
        // and the filter of `save_blocks` leaves the package out.
        let has_new_ignored_name = settings
            .ignore
            .iter()
            .any(|name| !self.settings.ignore.contains(name));
        if has_new_ignored_name {
            for ecosystem in &self.loaded_blocks {
                self.cache.mark_dirty(*ecosystem);
            }
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

    /// Reads the disk block of `ecosystem` into the cache, once, the first time the ecosystem is used.
    ///
    /// Nothing is read when the cache lifetime is zero. A store error or a block that cannot be
    /// read is logged, and the analysis goes on as if the disk were empty. A block that cannot be
    /// read is deleted, so the next save replaces it.
    fn load_block(&mut self, ecosystem: Ecosystem, store: &dyn Store) {
        if self.settings.cache_ttl_secs == 0 || !self.loaded_blocks.insert(ecosystem) {
            return;
        }
        let started_at = Instant::now();
        let key = block_key(ecosystem);
        let text = match store.get(&key) {
            Ok(Some(text)) => text,
            Ok(None) => return,
            Err(error) => {
                self.unreadable_blocks.insert(ecosystem);
                return self.warn_about_store(&format!("cannot read {key}: {error}"));
            }
        };
        let Some(mut block) = decode_block(&text) else {
            self.warn_about_store(&format!(
                "{key} is not a readable cache block, so it is dropped"
            ));
            if let Err(error) = store.delete(&key) {
                self.warn_about_store(&format!("cannot delete {key}: {error}"));
            }
            return;
        };
        // A package that was ignored since the block was written leaves it, and the block is written again.
        if self.drop_ignored(ecosystem, &mut block) {
            self.cache.mark_dirty(ecosystem);
        }
        let record_count = block.record_count();
        self.cache.import_block(ecosystem, block, now_secs());
        // The cost of the disk path, for the cold-start check of docs/MAINTAINING.md.
        host::log(
            LogLevel::Debug,
            &format!(
                "cache: loaded {} ({record_count} records, {} bytes) in {} ms",
                ecosystem.osv_name(),
                text.len(),
                started_at.elapsed().as_millis()
            ),
        );
    }

    /// Writes the disk block of every ecosystem whose cache changed since the last save.
    ///
    /// A write that fails is logged, and the ecosystem stays out of date so that the next chunk tries again.
    fn save_blocks(&mut self, store: &dyn Store) {
        for ecosystem in self.cache.take_dirty() {
            if self.unreadable_blocks.contains(&ecosystem) {
                continue;
            }
            let key = block_key(ecosystem);
            let mut block = self.cache.export_block(ecosystem);
            // An ignored package never reaches the disk, even when it was cached before it was ignored.
            self.drop_ignored(ecosystem, &mut block);
            if let Err(error) = store.set(&key, &encode_block(&block)) {
                self.warn_about_store(&format!("cannot write {key}: {error}"));
                self.cache.mark_dirty(ecosystem);
            }
        }
    }

    /// Removes the packages of the `ignore` setting from `block`. Returns `true` when it removed one.
    fn drop_ignored(&self, ecosystem: Ecosystem, block: &mut Block) -> bool {
        let ignored = self.settings.ignored_packages(ecosystem);
        !ignored.is_empty()
            && block.retain_packages(|name| !ignored.contains(&ecosystem.normalize_package(name)))
    }

    /// Forgets which blocks were read, so that the next use of an ecosystem reads its block again.
    fn forget_loaded_blocks(&mut self) {
        self.loaded_blocks.clear();
        self.unreadable_blocks.clear();
    }

    /// Deletes the disk block of every ecosystem. Returns the ecosystems whose block stays on the disk.
    fn clear_disk(&mut self, store: &dyn Store) -> Vec<Ecosystem> {
        let mut not_deleted = Vec::new();
        for ecosystem in Ecosystem::ALL {
            let key = block_key(ecosystem);
            if let Err(error) = store.delete(&key) {
                self.warn_about_store(&format!("cannot delete {key}: {error}"));
                not_deleted.push(ecosystem);
            }
        }
        not_deleted
    }

    /// Empties the cache in memory and on the disk.
    ///
    /// A block that stays on the disk because its delete failed counts as read, so it does not come
    /// back after the clear: the next save of its ecosystem replaces it.
    fn clear_cache_and_disk(&mut self, store: &dyn Store) {
        self.cache.clear();
        self.forget_loaded_blocks();
        let not_deleted = self.clear_disk(store);
        self.loaded_blocks.extend(not_deleted);
    }

    /// Logs a failure of the disk store, the first time only.
    fn warn_about_store(&mut self, message: &str) {
        if !self.has_warned_about_store {
            self.has_warned_about_store = true;
            host::log(LogLevel::Warn, &format!("disk cache: {message}"));
        }
    }

    /// Publishes what the cache holds for `deps`, even when it is older than its lifetime.
    ///
    /// A cold open then shows the last known results at once, before any request. It runs without
    /// a request, so nothing is stored, and the normal pass that follows checks and replaces it.
    /// It does nothing when the cache already holds fresh data for every dependency, when the cache
    /// lifetime is zero, or when the old data tells nothing more than the fresh data.
    ///
    /// Returns what it published, so that the chunks that follow can keep it for the entries that still wait.
    fn show_old_data_first(
        &mut self,
        eco: Ecosystem,
        path: &str,
        text: &str,
        deps: &[Dependency],
        now: u64,
    ) -> Option<Analysis> {
        if self.settings.cache_ttl_secs == 0 {
            return None;
        }
        let run_offline = |cache: &mut Cache, settings: &Settings| {
            analyze(
                eco,
                deps.to_vec(),
                cache,
                &HostHttp,
                settings,
                now,
                &mut Budget::offline(),
            )
        };
        let fresh_pending = run_offline(&mut self.cache, &self.settings).pending;
        if fresh_pending == 0 {
            return None;
        }
        let settings = &self.settings;
        let old = self
            .cache
            .with_stale_reads(STALE_MAX_AGE_SECS, |cache| run_offline(cache, settings));
        // A manifest that the old data does not help keeps its decorations until the first answer.
        if old.pending >= fresh_pending {
            return None;
        }
        publish_analysis(path, text, &old, self.settings.outdated_problems);
        Some(old)
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
        self.load_block(eco, &HostStore);
        let old_data = self.show_old_data_first(eco, path, text, deps, run_started_at);
        let mut previous_pending = None;
        loop {
            // The dependency vector is cloned per chunk; the parse is not repeated.
            // Each chunk gets its own deadline. The first registry lookup of a chunk runs unless the deadline has passed,
            // and the OSV phase stops fetching advisory details once the deadline has passed.
            let mut budget = Budget::new(chunk, Some(Instant::now() + CHUNK_LIMIT))
                .with_detail_limit(limits.details_per_query);
            // Without a cache a chunk keeps nothing, so one pass does all of them, OSV included.
            // With old data on screen, a slow package cannot blank the manifest, so the pairs go to OSV in one batch.
            if chunk != usize::MAX && old_data.is_none() {
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
            let pending = analysis.pending;
            let cancelled = task.is_cancelled();
            // Whether the loop ends here is known before the publication: the last one must not
            // present old data as current for an entry that this run never re-checked.
            let is_last_chunk = !should_continue(
                pending,
                previous_pending,
                cancelled,
                Instant::now(),
                limits.deadline,
            );
            let cache = &self.cache;
            publish_over_old_data(
                path,
                text,
                &analysis,
                old_data.as_ref().filter(|_| !is_last_chunk),
                self.settings.outdated_problems,
                |entry| has_vulnerability_answer(cache, eco, entry, run_started_at),
            );
            self.save_blocks(&HostStore);
            // Pending entries are the only ones without a status, so the done count is a subtraction, not a scan.
            let total = analysis.entries.len();
            let done = total.saturating_sub(pending);
            task.report(
                done as u32,
                Some(total as u32),
                Some(&format!("{done} of {total}")),
            );
            if is_last_chunk {
                return Some(analysis.unloaded_advisory_count());
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

/// Publishes `analysis` like [`publish_analysis`], with `old_data` shown for the entries that still wait.
///
/// An entry that still waits keeps what the old data showed for it until its answer comes.
/// `has_answer` tells whether OSV already answered for an entry, whose advisories are then kept.
fn publish_over_old_data(
    path: &str,
    text: &str,
    analysis: &Analysis,
    old_data: Option<&Analysis>,
    outdated_problems: bool,
    has_answer: impl Fn(&Entry) -> bool,
) {
    let shown = old_data
        .filter(|_| analysis.pending > 0)
        .map(|old| fill_pending_from_old(analysis, old, has_answer));
    publish_analysis(
        path,
        text,
        shown.as_ref().unwrap_or(analysis),
        outdated_problems,
    );
}

/// Whether the cache holds a fresh OSV answer for the checked version of `entry`.
fn has_vulnerability_answer(cache: &Cache, eco: Ecosystem, entry: &Entry, now: u64) -> bool {
    entry.checked_version.as_deref().is_some_and(|version| {
        cache
            .vulnerabilities(eco, &entry.dependency.name, version, now)
            .is_some()
    })
}

/// Returns `analysis` with each entry that still waits replaced by what `old` showed for it.
///
/// An entry waits for OSV, or for its registry answer. When OSV has answered (`has_answer`), its
/// advisories are the news and stay: only its registry status comes from the old data. Old
/// advisories would hide a new one, or show one that OSV withdrew.
///
/// The two analyses come from the same dependencies, so their entries line up. If they do not, the
/// analysis is returned as it is.
fn fill_pending_from_old(
    analysis: &Analysis,
    old: &Analysis,
    has_answer: impl Fn(&Entry) -> bool,
) -> Analysis {
    if analysis.entries.len() != old.entries.len() {
        return analysis.clone();
    }
    let entries = analysis
        .entries
        .iter()
        .zip(&old.entries)
        .map(|(entry, old_entry)| {
            let is_same_dependency = entry.dependency.name == old_entry.dependency.name;
            let waits_with_old_data = entry.status == Status::Pending
                && is_same_dependency
                && old_entry.status != Status::Pending;
            if !waits_with_old_data {
                entry.clone()
            } else if has_answer(entry) {
                Entry {
                    status: old_entry.status.clone(),
                    ..entry.clone()
                }
            } else {
                old_entry.clone()
            }
        })
        .collect();
    Analysis {
        entries,
        pending: analysis.pending,
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
            "clear-cache" => {
                self.clear_cache_and_disk(&HostStore);
                // What the manifests show comes from the cache, so they are analyzed again.
                let deadline = deadline_after(self.time_box);
                self.refresh_shown_manifests(ctx, deadline, &HashSet::new());
                Ok(Some("Dependency Lens: cache cleared".to_owned()))
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
            self.refresh_shown_manifests(ctx, deadline, &refreshed);
        }
    }
}

impl DependencyLens {
    /// Analyzes again every manifest that shows results, except the ones in `already_refreshed`.
    fn refresh_shown_manifests(
        &mut self,
        ctx: &Invocation,
        deadline: Instant,
        already_refreshed: &HashSet<&str>,
    ) {
        let shown_paths: Vec<String> = self
            .published_paths
            .iter()
            .filter(|path| !already_refreshed.contains(path.as_str()))
            .cloned()
            .collect();
        for path in &shown_paths {
            self.refresh(path, Some(ctx), RunLimits::standard(deadline));
        }
    }

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
        // After an unload the cache is empty: read what the disk holds before the details are loaded.
        self.load_block(eco, &HostStore);
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
        // After an unload the decorations stay on screen but the cache is empty: read the disk first.
        if let Some(eco) = Ecosystem::detect(&doc.path) {
            self.load_block(eco, &HostStore);
        }
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
mod disk_cache_tests {
    use super::*;
    use crate::model::VersionInfo;
    use crate::store::MemoryStore;
    use openidea_plugin::mock::MockHost;

    #[test]
    fn a_failed_save_keeps_the_ecosystem_dirty_for_the_next_chunk() {
        let _host = MockHost::install();
        let mut plugin = DependencyLens::default();
        plugin
            .cache
            .put_version_info(Ecosystem::PyPI, "requests", VersionInfo::default(), 1);

        plugin.save_blocks(&MemoryStore::failing());
        assert!(plugin.cache.is_dirty(Ecosystem::PyPI));

        let store = MemoryStore::new();
        plugin.save_blocks(&store);
        assert!(!plugin.cache.is_dirty(Ecosystem::PyPI));
        assert_eq!(store.keys(), ["cache/PyPI"]);
    }

    /// An entry for the first dependency of `requirements`, with `status`.
    fn entry_with(requirements: &str, status: Status) -> crate::analysis::Entry {
        crate::analysis::Entry {
            dependency: Ecosystem::PyPI.parse(requirements).remove(0),
            status,
            vulnerabilities: Vec::new(),
            checked_version: Some("1.0".to_owned()),
        }
    }

    #[test]
    fn old_data_fills_only_the_entries_that_still_wait() {
        let outdated = Status::Outdated {
            latest: "2.0".to_owned(),
        };
        let analysis = Analysis {
            entries: vec![
                entry_with("a==1.0\n", Status::Pending),
                entry_with("b==1.0\n", Status::UpToDate),
                entry_with("c==1.0\n", Status::Pending),
            ],
            pending: 2,
        };
        let old = Analysis {
            entries: vec![
                entry_with("a==1.0\n", outdated.clone()),
                entry_with("b==1.0\n", outdated.clone()),
                entry_with("c==1.0\n", Status::Pending),
            ],
            pending: 1,
        };

        let shown = fill_pending_from_old(&analysis, &old, |_| false);

        // `a` waits and the old data knows it. `b` is already checked. `c` is unknown to both.
        let statuses: Vec<&Status> = shown.entries.iter().map(|entry| &entry.status).collect();
        assert_eq!(statuses, [&outdated, &Status::UpToDate, &Status::Pending]);
        assert_eq!(shown.pending, 2);
    }

    #[test]
    fn a_block_that_could_not_be_read_is_not_written_over() {
        let _host = MockHost::install();
        let mut plugin = DependencyLens::default();
        let store = MemoryStore::failing_reads();

        plugin.load_block(Ecosystem::PyPI, &store);
        plugin
            .cache
            .put_version_info(Ecosystem::PyPI, "requests", VersionInfo::default(), 1);
        plugin.save_blocks(&store);

        // The disk may still hold a block that was not read: memory alone must not replace it.
        assert!(store.keys().is_empty());
        // The ecosystem is not retried at every chunk either.
        assert!(!plugin.cache.is_dirty(Ecosystem::PyPI));
    }

    #[test]
    fn a_waiting_entry_keeps_its_fresh_advisories_and_takes_the_old_status() {
        let outdated = Status::Outdated {
            latest: "2.0".to_owned(),
        };
        let mut waiting = entry_with("a==1.0\n", Status::Pending);
        waiting.vulnerabilities = vec![crate::osv::anonymous_deferred()];
        let analysis = Analysis {
            entries: vec![waiting.clone()],
            pending: 1,
        };
        let old = Analysis {
            entries: vec![entry_with("a==1.0\n", outdated.clone())],
            pending: 0,
        };

        // OSV has answered for this entry: its advisories are the news, only its registry status waits.
        let kept = fill_pending_from_old(&analysis, &old, |_| true);
        assert_eq!(kept.entries[0].status, outdated);
        assert_eq!(kept.entries[0].vulnerabilities, waiting.vulnerabilities);

        // OSV has not answered: the old entry shows as it was.
        let replaced = fill_pending_from_old(&analysis, &old, |_| false);
        assert!(replaced.entries[0].vulnerabilities.is_empty());
    }

    #[test]
    fn a_block_that_could_not_be_deleted_is_not_read_back_after_a_clear() {
        use crate::cache::persist::{BLOCK_VERSION, Block, RegistryRecord, encode_block};
        let _host = MockHost::install();
        let mut plugin = DependencyLens::default();
        let mut block = Block {
            v: BLOCK_VERSION,
            ..Block::default()
        };
        block.registry.insert(
            "requests".to_owned(),
            RegistryRecord {
                at: now_secs(),
                latest: Some("2.0".to_owned()),
                all: Vec::new(),
            },
        );
        let store = MemoryStore::failing_deletes();
        store.set("cache/PyPI", &encode_block(&block)).unwrap();

        plugin.clear_cache_and_disk(&store);
        plugin.load_block(Ecosystem::PyPI, &store);

        // The block is still on the disk, but the user cleared the cache: it must not come back.
        assert!(
            plugin
                .cache
                .version_info(Ecosystem::PyPI, "requests", now_secs())
                .is_none()
        );
    }

    #[test]
    fn a_cache_lifetime_of_zero_reads_no_block() {
        let _host = MockHost::install();
        let mut plugin = DependencyLens::default();
        plugin.settings.cache_ttl_secs = 0;
        let store = MemoryStore::new();
        store
            .set(
                "cache/PyPI",
                r#"{"v":1,"registry":{},"lists":{},"advisories":{}}"#,
            )
            .unwrap();

        plugin.load_block(Ecosystem::PyPI, &store);

        // The block was not even read: it is not marked as loaded.
        assert!(plugin.loaded_blocks.is_empty());
    }

    #[test]
    fn a_store_that_cannot_be_read_counts_as_loaded_and_warns_once() {
        let host = MockHost::install();
        let mut plugin = DependencyLens::default();
        let store = MemoryStore::failing();

        plugin.load_block(Ecosystem::PyPI, &store);
        plugin.load_block(Ecosystem::PyPI, &store);
        plugin.load_block(Ecosystem::Cargo, &store);

        assert!(plugin.loaded_blocks.contains(&Ecosystem::PyPI));
        let warnings = host
            .logs()
            .into_iter()
            .filter(|(level, _)| matches!(level, LogLevel::Warn))
            .count();
        assert_eq!(warnings, 1);
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
