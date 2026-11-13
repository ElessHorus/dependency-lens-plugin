# Dependency Lens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An OpenIDEA community plugin (Rust, WebAssembly) that shows OSV vulnerabilities for nine ecosystems and newer versions plus an "update" quick fix for five of them, inline in manifest files.

**Architecture:** Event handlers (`file-opened`, `file-saved`, `files-changed`) read a manifest, parse it, answer from an in-memory cache, then look up the misses (one batched OSV call, one registry request per package) inside a time-boxed task, publishing decorations and diagnostics as results arrive. The `code-actions` provider only reads the cache. All parsing, registry reading, OSV logic and update rendering are pure functions behind an `Http` trait, tested without the IDE. Parsers and update logic are adapted from `mpiton/zed-depsy` (MIT).

**Tech Stack:** Rust 2021, `openidea-plugin` SDK (git tag of the installed tool), `taplo`, `quick-xml`, `serde`, `serde_json`, `semver`, `json-spanned-value`; target `wasm32-wasip2`; `openidea-plugin build/check/pack`.

**Spec:** `docs/superpowers/specs/2026-11-13-dependency-lens-design.md`

## Global Constraints

- Plugin API `openidea:plugin@1.8.0`; `engines.openidea = "^1.3"` (needs `files-changed`).
- Dev plugin id `local.dependency-lens`; the real `<publisher>.dependency-lens` is set in Task 18.
- Licence MIT. `NOTICE` credits `mpiton/zed-depsy` (Copyright (c) 2025 Mathieu). Never copy from `filllabs/dependi`.
- Positions published to the IDE: 0-based lines, **UTF-16** columns. depsy's spans are **byte** offsets within a line; convert at one place (`text::to_range`).
- `net:` capabilities: `api.osv.dev`, `pypi.org`, `repo.packagist.org`, `pub.dev`, `api.nuget.org`, `rubygems.org`. No `net:ask`. Other capabilities: `events`, `project.read`, `editor.read`, `editor.write`.
- Editor providers never call the network. A call without an open task may run 5 s; with one, 60 s. Lookup runs open a task and stop at 50 s.
- Calls to one plugin instance never run concurrently; `host::fetch` is synchronous.
- Docstrings and comments in English; sparse and purposeful. No `Any`/untyped escapes; no `unwrap` on input-derived data.
- Commit messages are Conventional Commits and end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Work on a branch (`git switch -c`), no worktrees.
- Run before each commit: `cargo fmt --all`, `cargo test`. Run `cargo clippy --all-targets -- -D warnings` at the end of each task that adds a module.
- The signing key (`openidea-plugin keygen`) is the author's secret: never create, read or commit it.
- Reference source: `/tmp/zed-depsy-src/repo/depsy-lsp/src` (shallow clone; re-clone `https://github.com/mpiton/zed-depsy` into an empty directory if missing). Pure parts only; never port `tower-lsp`, `tokio`, `reqwest`, `rusqlite`, `dashmap`, `clap`, lockfile parsers or `backend.rs`.

## Review Focus

Inputs the spec implies but no feature task exercises on its own. Each line has a named test in the owning task.

1. Non-ASCII text before a version on the same line (`"ünï" = "1.0"`): the published range must still cover the version in UTF-16 columns. (Task 2, repeated in Task 3.)
2. Versions that are not registry versions (`*`, `latest`, git/path/workspace, empty, unresolved `${property}`): no OSV query, no vulnerability, no crash. (Task 4.)
3. Registry or OSV failure (HTTP 429/500, invalid JSON, oversize body, `host::fetch` error): an "unknown" decoration with the reason in the hover; never an invented vulnerability or update. (Tasks 4, 6.)
4. A dependency removed or a manifest emptied between two runs: its decoration and diagnostic disappear; a non-manifest path is ignored. (Task 7.)
5. A very large manifest (hundreds of packages) hits the 50 s box: partial results, `pending` shown, cached packages not fetched again on the next run. (Task 6.)

## File Structure

```
plugin.toml  Cargo.toml  settings.schema.json  README.md  LICENSE  NOTICE
src/lib.rs            plugin wiring: Plugin + Providers impl, register_plugin!
src/model.rs          Ecosystem, Dependency, Span, VersionInfo, Vulnerability, AdvisorySeverity
src/text.rs           to_range: byte Span -> UTF-16 Range
src/http.rs           Http trait, HostHttp (host::fetch), FakeHttp (tests)
src/osv.rs            batch request/response, severity mapping
src/cache.rs          TTL cache for version info and vulnerabilities
src/settings.rs       Settings read from the host, defaults
src/analysis.rs       analyze(): cache, lookups, time box -> Analysis
src/publish.rs        Analysis -> Decoration / Diagnostic
src/actions.rs        cache -> CodeAction
src/update.rs         render_update (requirement rewriting), UpdateKind
src/parsers/{mod,cargo,npm,python,go,php,dart,csharp,ruby,maven,json_spans}.rs
src/registries/{mod,pypi,packagist,pub_dev,nuget,rubygems}.rs
tests/fixtures/<ecosystem>/...     manifests and recorded registry/OSV bodies
tests/plugin.rs       MockHost integration tests
.github/workflows/{ci.yml,release.yml}
```

---

### Task 1: Scaffold the repository and prove the WASM build

**Files:**
- Create: everything `openidea-plugin new` generates, plus `LICENSE`, `NOTICE`, `.gitignore`
- Modify: `Cargo.toml`, `plugin.toml`
- Test: `src/lib.rs` (`wasm_smoke` unit test)

**Interfaces:**
- Produces: a building crate `dependency-lens` exposing `pub mod` placeholders later tasks fill.

- [ ] **Step 1:** In `/home/florian/workspace/dependency-lens-plugin`, scaffold into an empty temp directory, then move the generated files next to the existing `docs/`: `openidea-plugin new /tmp/dl-scaffold --id local.dependency-lens --name "Dependency Lens"`. Do not pass `--sdk` (it must use the tool's git tag). Run `git init -b main`.
- [ ] **Step 2:** Write the failing test in `src/lib.rs`: `fn wasm_smoke()` asserts `taplo::parser::parse("a = 1").errors.is_empty()` and `quick_xml::Reader::from_str("<a/>").read_event().is_ok()` and `semver::Version::parse("1.2.3").is_ok()`. Run `cargo test wasm_smoke` → FAIL (crates missing).
- [ ] **Step 3:** Add dependencies to `Cargo.toml`: `taplo = "0.14"`, `quick-xml = "0.42"`, `serde = { version = "1", features = ["derive"] }`, `serde_json = "1"`, `semver = "1"`, `json-spanned-value = "0.2"`. Keep `crate-type = ["cdylib", "rlib"]`.
- [ ] **Step 4:** Run `cargo test wasm_smoke` → PASS, then `openidea-plugin build` → expect `dist/plugin.wasm` and a passing `check`.
- [ ] **Step 5:** Write `LICENSE` (MIT, `Copyright (c) <year> <author>`: leave the holder as `The Dependency Lens authors`) and `NOTICE` crediting `mpiton/zed-depsy` (MIT, Copyright (c) 2025 Mathieu). Add `dist/` handling to `.gitignore` (the registry package is built in release CI, not committed).
- [ ] **Step 6:** Commit on a new branch: `git switch -c feat/dependency-lens && git add -A && git commit -m "chore: scaffold plugin and verify wasm32-wasip2 build"`.

### Task 2: Model, UTF-16 conversion, manifest detection

**Files:**
- Create: `src/model.rs`, `src/text.rs`
- Test: `src/text.rs` and `src/model.rs` unit tests

**Interfaces:**
- Produces (`model.rs`):
  ```rust
  #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
  pub enum Ecosystem { Cargo, Npm, PyPI, Go, Packagist, Pub, NuGet, RubyGems, Maven }
  impl Ecosystem {
      pub fn detect(path: &str) -> Option<Ecosystem>;  // by file name
      pub fn osv_name(self) -> &'static str;           // "crates.io","npm","PyPI","Go","Packagist","Pub","NuGet","RubyGems","Maven"
      pub fn offers_updates(self) -> bool;             // true for PyPI, Packagist, Pub, NuGet, RubyGems
  }
  #[derive(Clone, Copy, Debug, PartialEq, Eq)]
  pub struct Span { pub line: u32, pub line_start: u32, pub line_end: u32 } // bytes within the line
  #[derive(Clone, Debug, PartialEq, Eq)]
  pub struct Dependency { pub name: String, pub version: String, pub name_span: Span,
      pub version_span: Span, pub dev: bool, pub optional: bool,
      pub has_additional_version_constraints: bool }
  #[derive(Clone, Debug, Default, PartialEq, Eq)]
  pub struct VersionInfo { pub latest: Option<String>, pub versions: Vec<String> }
  #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
  pub enum AdvisorySeverity { Low, Medium, High, Critical }
  #[derive(Clone, Debug, PartialEq, Eq)]
  pub struct Vulnerability { pub id: String, pub severity: AdvisorySeverity,
      pub summary: String, pub url: Option<String> }
  ```
- Produces (`text.rs`): `pub fn to_range(text: &str, span: Span) -> Option<openidea_plugin::Range>`.

- [ ] **Step 1: Failing tests.** `text`: for `"é = \"1.0\"\n"` (é is 2 bytes, 1 UTF-16 unit) a span with `line_start = 6, line_end = 9` gives `Range` columns `5..8`; an out-of-range span returns `None`; a span on line 2 of a CRLF text maps to line 1 (0-based). `model`: `detect("/p/Cargo.toml") == Some(Cargo)`, `package.json`→Npm, `go.mod`→Go, `pom.xml`→Maven, `requirements.txt`, `requirements-dev.txt`, `constraints.txt`, `pyproject.toml`, `hatch.toml`→PyPI, `composer.json`→Packagist, `pubspec.yaml`→Pub, `Foo.csproj`, `Directory.Build.props`, `Directory.Packages.props`→NuGet, `Gemfile`→RubyGems, `README.md`→None, `package-lock.json`→None. Run → FAIL.
- [ ] **Step 2: Implement** the types above and `to_range`: convert a byte offset on a line to UTF-16 by counting `encode_utf16` units of the prefix; return `None` if the span is outside the line or not on a char boundary.
- [ ] **Step 3:** `cargo test` → PASS; `cargo clippy --all-targets -- -D warnings`.
- [ ] **Step 4:** Commit `feat: add model and UTF-16 span conversion`.

### Task 3: Parser contract and the Cargo parser

**Files:**
- Create: `src/parsers/mod.rs`, `src/parsers/cargo.rs`, `tests/fixtures/cargo/Cargo.toml`
- Modify: `src/model.rs` (add `Ecosystem::parse`)

**Interfaces:**
- Consumes: `Dependency`, `Span`, `Ecosystem`.
- Produces: `impl Ecosystem { pub fn parse(self, text: &str) -> Vec<Dependency> }` dispatching to `parsers::<eco>::parse(text: &str) -> Vec<Dependency>`. A parser never panics; malformed input returns what it can or `vec![]`.

- [ ] **Step 1: Failing tests** in `src/parsers/cargo.rs` for this fixture, with exact expectations: `[dependencies]` `serde = "1.0"` → `name "serde"`, `version "1.0"`, `dev false`; `tokio = { version = "1", features = ["full"] }` → version `"1"`; `[dev-dependencies]` `tempfile = "3"` → `dev true`; `[target.'cfg(unix)'.dependencies]` `libc = "0.2"` found; `local = { path = "../local" }` and `g = { git = "https://x/y" }` are **not** returned; `[workspace.dependencies]` entries found; `"ünï" `-style key with non-ASCII bytes before the version keeps `to_range` on the version text (assert via `text::to_range` that `doc.text_in(range) == "1.0"`); malformed TOML returns `vec![]` without panicking.
- [ ] **Step 2:** Run `cargo test parsers::cargo` → FAIL.
- [ ] **Step 3: Port** `parsers/cargo.rs` from depsy (`taplo` DOM walk), dropping `registry`, `resolved_version`, `catalog_spec` and the `tower_lsp` import; skip path/git dependencies. Keep depsy's byte `Span` semantics.
- [ ] **Step 4:** `cargo test` → PASS; commit `feat: parse Cargo manifests`.

### Task 4: HTTP trait and OSV client

**Files:**
- Create: `src/http.rs`, `src/osv.rs`, `tests/fixtures/osv/{batch_response.json,vuln_detail.json}`

**Interfaces:**
- Produces (`http.rs`):
  ```rust
  pub trait Http { fn send(&self, request: &openidea_plugin::HttpRequest) -> Result<openidea_plugin::HttpResponse, String>; }
  pub struct HostHttp;                       // calls host::fetch, maps Error to String
  pub struct FakeHttp { /* canned (url prefix -> status, body), records requests */ }  // cfg(test)
  ```
- Produces (`osv.rs`):
  ```rust
  pub struct OsvQuery { pub ecosystem: Ecosystem, pub name: String, pub version: String }
  pub fn declared_version_for_osv(spec: &str) -> Option<String>;  // None = do not query
  pub fn query_batch(http: &dyn Http, queries: &[OsvQuery]) -> Result<Vec<Vec<Vulnerability>>, String>; // same order as input
  ```

- [ ] **Step 1: Failing tests.** `declared_version_for_osv` (operators and a `v` before a digit are stripped; only the first comma-separated part is kept; no zero padding, because the live OSV API answers partial versions such as `1.6` for crates.io and Go versions with or without `v`): `"^1.2"`→`Some("1.2")`, `"~1.2.3"`→`"1.2.3"`, `">=2.0, <3"`→`"2.0"`, `"==1.2.3"`→`"1.2.3"`, `"v0.9.1"`→`"0.9.1"`, `"1.2.3"`→same, `"*"`, `"latest"`, `""`, `"workspace:*"`, `"git+https://x"`, `"file:../x"`, `"${spring.version}"`→`None`. `query_batch`: with `FakeHttp` answering `POST https://api.osv.dev/v1/querybatch` from `batch_response.json` (a 3-query response: one package with two advisories, one with none, one with one), results align by index; advisory ids are validated (`[A-Za-z0-9-]{1,64}`, others dropped); severity from CVSS maps `9.0+`→Critical, `7.0–8.9`→High, `4.0–6.9`→Medium, else Low, and from `database_specific.severity` strings when no score; more than 1000 queries are split into several requests; HTTP 429, HTTP 500, invalid JSON and a transport `Err` each return `Err(reason)` mentioning the status or cause. Run → FAIL.
- [ ] **Step 2: Implement** `Http`, `HostHttp`, `FakeHttp`, `declared_version_for_osv`, `query_batch`. Port the request/response structs, advisory-id check and severity logic from depsy `vulnerabilities/osv.rs` and `normalize_version_for_osv`; replace `reqwest`/`tokio` with `Http`; use the batch endpoint for the version lists and, per distinct advisory id, `GET https://api.osv.dev/v1/vulns/{id}` only when the batch response lacks a summary or severity (cache of details is Task 5's job).
- [ ] **Step 3:** `cargo test` → PASS; clippy; commit `feat: add OSV batch client`.

### Task 5: Cache

**Files:**
- Create: `src/cache.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct Cache { /* ttl_secs */ }
  impl Cache {
      pub fn new(ttl_secs: u64) -> Self;
      pub fn version_info(&self, eco: Ecosystem, package: &str, now: u64) -> Option<&VersionInfo>;
      pub fn put_version_info(&mut self, eco: Ecosystem, package: &str, info: VersionInfo, now: u64);
      pub fn vulnerabilities(&self, eco: Ecosystem, package: &str, version: &str, now: u64) -> Option<&[Vulnerability]>;
      pub fn put_vulnerabilities(&mut self, eco: Ecosystem, package: &str, version: &str, vulns: Vec<Vulnerability>, now: u64);
      pub fn put_failure(&mut self, key_kind: FailureKind, eco: Ecosystem, package: &str, reason: String, now: u64); // failures cached 60 s
      pub fn failure(&self, kind: FailureKind, eco: Ecosystem, package: &str, now: u64) -> Option<&str>;
  }
  pub enum FailureKind { Registry, Osv }
  ```
  Package names are case-sensitive keys except PyPI (normalised by the caller).

- [ ] **Step 1: Failing tests:** an entry is returned at `now = t0 + ttl - 1` and gone at `t0 + ttl`; vulnerabilities are keyed by version (another version misses); a failure expires after 60 s and does not block a later success; `Cache::new(0)` stores nothing.
- [ ] **Step 2:** Implement with `HashMap` keyed by `(Ecosystem, String[, String])` holding `(value, stored_at)`. Default TTL 3600 s (Task 15 makes it a setting).
- [ ] **Step 3:** `cargo test` → PASS; commit `feat: add TTL cache`.

### Task 6: Analysis pipeline with time box

**Files:**
- Create: `src/analysis.rs`, `src/settings.rs`
- Test: `src/analysis.rs`

**Interfaces:**
- Consumes: `Ecosystem`, `Dependency`, `Cache`, `Http`, `osv::query_batch`, `declared_version_for_osv`.
- Produces:
  ```rust
  pub struct Settings { pub vulnerabilities: bool, pub minimum_severity: AdvisorySeverity,
      pub ignore: Vec<String>, pub enabled: std::collections::BTreeSet<Ecosystem>, pub cache_ttl_secs: u64 }
  impl Default for Settings { /* vulnerabilities on, minimum Low, no ignores, all ecosystems, 3600 s */ }
  pub enum Status { Pending, UpToDate, Outdated { latest: String }, Unknown(String), NotChecked }
  pub struct Entry { pub dependency: Dependency, pub status: Status, pub vulnerabilities: Vec<Vulnerability>, pub checked_version: Option<String> }
  pub struct Analysis { pub entries: Vec<Entry>, pub pending: usize }
  pub struct Budget { lookups_left: usize, deadline: Option<std::time::Instant> }
  impl Budget {
      pub fn new(max_lookups: usize, deadline: Option<std::time::Instant>) -> Self;
      /// Consumes one registry lookup; false when none is left or the deadline passed.
      pub fn take(&mut self) -> bool;
  }
  pub fn analyze(eco: Ecosystem, deps: Vec<Dependency>, cache: &mut Cache, http: &dyn Http,
      settings: &Settings, now: u64, budget: &mut Budget) -> Analysis;
  ```
  Registry hooks (`Ecosystem::registry_request`, `parse_registry`) arrive with Task 8; until then `offers_updates()` ecosystems yield `NotChecked` for status. Add them as `impl Ecosystem { pub fn registry_request(self, package: &str) -> Option<HttpRequest>; pub fn parse_registry(self, body: &str) -> Result<VersionInfo, String>; }` returning `None`/`Err` for now.

- [ ] **Step 1: Failing tests** (Cargo manifest, `FakeHttp`):
  - cache empty, 3 dependencies, OSV says `serde 1.0.0` has one High advisory → entries carry it, `status == NotChecked`, one OSV request total, `pending == 0`;
  - second `analyze` with same inputs makes **zero** requests (cache);
  - a dependency with `version "*"` is never in the OSV request (Review Focus 2);
  - OSV returns 500 → entries get `Status::Unknown("OSV: HTTP 500")`, empty vulnerabilities (Review Focus 3);
  - 300 dependencies with `Budget::new(2, None)`: OSV is still one batch call (batches do not consume lookups), but a PyPI-style registry stub is called at most 2 times; `pending == remaining uncached`; a second run with a fresh budget fetches only the previous misses (Review Focus 5);
  - `settings.ignore` containing `"serde"` removes it; `minimum_severity = High` drops Low/Medium advisories; `vulnerabilities = false` makes no OSV request.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement `analyze`: build OSV queries for dependencies whose declared version passes `declared_version_for_osv`, skip cached ones, send one `query_batch`, then per-package registry lookups for `offers_updates()` ecosystems, each consuming one `Budget::take()`; compare with `semver`/ecosystem rules from Task 8+ (until then, `NotChecked`).
- [ ] **Step 4:** `cargo test` → PASS; clippy; commit `feat: add analysis pipeline`.

### Task 7: Publishing and plugin wiring (Cargo end to end)

**Files:**
- Create: `src/publish.rs`, `src/lib.rs` (replace scaffold), `tests/plugin.rs`, `settings.schema.json`
- Modify: `plugin.toml`

**Interfaces:**
- Consumes: `analyze`, `Analysis`, `Ecosystem::detect/parse`, `text::to_range`.
- Produces (`publish.rs`):
  ```rust
  pub const DECORATION_SET: &str = "dependency-lens";
  pub fn decorations(text: &str, analysis: &Analysis) -> Vec<openidea_plugin::Decoration>;
  pub fn diagnostics(text: &str, analysis: &Analysis) -> Vec<openidea_plugin::Diagnostic>;
  ```
  Exact output: decoration `range` = the version range, `after` text and `style`:
  `✓` style `muted` (up to date, no advisories) · `→ {latest}` style `info` (outdated) · `⚠ {n} vulnerability` / `⚠ {n} vulnerabilities` style `error` when the worst is High or Critical, else `warning` · `?` style `muted` (unknown; reason in `hover`) · `…` style `muted` (pending) · combined as `→ {latest} · ⚠ {n} …` (style of the worst part). `NotChecked` without advisories → no decoration. `hover` is Markdown: checked version, each advisory as `[{id}]({url}) ({severity}) – {summary}`, or the failure reason. Diagnostic per advisory-bearing dependency on the version range: `Critical|High`→`Severity::Error`, `Medium`→`Warning`, `Low`→`Info`; `source = Some("Dependency Lens")`, `code = Some(first advisory id)`, message `"{name} {version}: {n} known vulnerabilities ({worst})"` (singular for 1).
- Produces (`lib.rs`): `#[derive(Default)] pub struct DependencyLens { cache: Cache, settings: Settings }`, `impl Plugin` (`activate` subscribes `EventKind::FileOpened`, `FileSaved`, `FilesChanged`; `handle_events` calls `refresh(path, project)` for each manifest path; `run_command("refresh")` refreshes the focused manifest) and `register_plugin!(DependencyLens, providers)`.
- `plugin.toml`: id `local.dependency-lens`, `engines.openidea = "^1.3"`, `activation = ["on-event:file-opened","on-event:file-saved","on-event:files-changed","on-command:*"]`, capabilities as in Global Constraints, `[[contributes.providers]] kinds = ["code-actions"] languages = ["*"]`, command `refresh` ("Dependency Lens: Refresh"), settings schema, `categories = ["tools"]`.

- [ ] **Step 1: Failing tests.** `publish`: table-driven for each status above with exact `after`/`style`; UTF-16 range assertion with non-ASCII; singular/plural. `tests/plugin.rs` with `MockHost` (`with_capabilities`, `add_file`, `on_fetch` serving OSV JSON, `host.decorations()`, `host.diagnostics()`):
  - open `/p/Cargo.toml` → decorations and diagnostics appear for the vulnerable dependency;
  - delete that dependency from the file, send `FileSaved` → its decoration and diagnostic are gone (Review Focus 4); empty the file → both sets empty;
  - `Event::FileOpened("/p/README.md")` → no fetch, no decorations;
  - a second `FileOpened` of the same unchanged file makes no new fetch (`host.fetches` is for VCS; count via a counter in `on_fetch`).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement `publish`, `refresh` (read file via `project.read_file`, `Ecosystem::detect`, `parse`, open `host::begin_task("Dependency Lens", true)`, call `analyze` with `HostHttp` and a 50 s deadline budget, call `host::set_decorations(path, DECORATION_SET, &items)` and `host::publish_diagnostics(path, &items)` after the cache pass and again after the lookups, stop if `task.is_cancelled()`), and `activate`.
- [ ] **Step 4:** `cargo test` and `openidea-plugin build` (must pass `check`); manual check: `openidea-plugin link`, open `fixtures/rust-app/Cargo.toml` of OpenIDEA, Settings › Plugins › Reload. Commit `feat: publish decorations and problems for Cargo manifests`.

---

## Ecosystem task contract (Tasks 8–16)

Each ecosystem task follows these steps; the task lists only what differs. `<eco>` is the module name.

- [ ] **Step 1: Failing parser tests** in `src/parsers/<eco>.rs` for the listed fixture and expectations, always including one case with non-ASCII text before a version (assert `text::to_range` + `Document::text_in` returns the version text) and one malformed input (returns `vec![]`/partial, no panic).
- [ ] **Step 2:** Run `cargo test parsers::<eco>` → FAIL.
- [ ] **Step 3: Port** the depsy parser named in the task (drop `tower_lsp` and lockfile code), keeping its byte `Span`s; wire it into `Ecosystem::parse`.
- [ ] **Step 4 (registry ecosystems only):** failing registry tests in `src/registries/<eco>.rs` using a recorded body in `tests/fixtures/<eco>/registry.json` (real, trimmed response): `request(package) -> HttpRequest` has the exact URL listed, and `parse(body) -> Result<VersionInfo, String>` returns the expected `latest` (stable only: pre-releases and yanked versions never `latest`) and `versions` newest-first; invalid JSON → `Err`. Implement from depsy's `registries/<eco>.rs` response structs, replacing `reqwest`; wire into `Ecosystem::registry_request` / `parse_registry`.
- [ ] **Step 5 (registry ecosystems only):** failing `analyze` test with `FakeHttp`: declared `1.0` and registry latest `2.0` → `Status::Outdated { latest: "2.0" }`; declared equal to latest → `UpToDate`; registry 404 → `Unknown("registry: HTTP 404")`. Implement the comparison with depsy's `version_utils`/semver rules for the ecosystem.
- [ ] **Step 6:** `cargo test`, clippy, `openidea-plugin build`; update `plugin.toml` (`net:` host, `suggest` manifest name) and commit `feat: support <Ecosystem> manifests`.

### Task 8: PyPI (parser, registry, update rendering)

**Files:** `src/parsers/python.rs`, `src/registries/pypi.rs`, `src/update.rs`, fixtures `tests/fixtures/python/{requirements.txt,pyproject.toml,hatch.toml,registry.json}`.

**Interfaces:**
- Produces (`update.rs`):
  ```rust
  #[derive(Clone, Copy, Debug, PartialEq, Eq)]
  pub enum UpdateKind { Major, Minor, Patch, Prerelease }
  pub fn render_update(eco: Ecosystem, dep: &Dependency, latest: &str) -> Option<String>; // the new text for dep.version_span
  pub fn update_kind(current: &str, latest: &str) -> UpdateKind;
  ```
  `render_update` returns `None` when `dep.has_additional_version_constraints` or the spec is not rewritable.

Particulars:
- Parser source: `parsers/python.rs`. Fixture expectations: `requests==2.28.0` → name `requests`, version `2.28.0` (the span covers the version text; the operator stays outside it); `flask>=2.0,<3` → `has_additional_version_constraints = true`; `-r other.txt`, comments, `git+https://…`, `-e .` skipped; `pyproject.toml` `[project] dependencies`, `[project.optional-dependencies]` (`optional = true`), `[tool.poetry.dependencies]` (skips `python`), `[dependency-groups]` (`dev = true`); `hatch.toml` per depsy.
- Registry URL: `https://pypi.org/pypi/{normalized}/json`, normalised lowercase with `[-_.]+` → `-`.
- `render_update` tests: `==2.28.0` + latest `2.31.0` → `2.31.0`; `>=2.0` + `2.31.0` → `2.31.0` (keeps `>=`, only the version part is replaced); compound constraint → `None`. `update_kind("2.28.0","3.0.0") == Major`, `("2.28.0","2.31.0") == Minor`, `("2.28.0","2.28.4") == Patch`, `("1.0","2.0b1") == Prerelease`.
- `suggest`: `requirements.txt`, `pyproject.toml`. Commit `feat: support PyPI manifests`.

### Task 9: Code-action quick fix

**Files:** Create `src/actions.rs`; modify `src/lib.rs` (`impl Providers`), `tests/plugin.rs`.

**Interfaces:**
- Consumes: `Cache`, `Ecosystem::parse`, `render_update`, `update_kind`, `text::to_range`.
- Produces: `pub fn code_actions(cache: &Cache, settings: &Settings, doc_path: &str, doc_text: &str, selection: Range, now: u64) -> Vec<openidea_plugin::providers::CodeAction>`. Title `Update {name} to {latest} (major|minor|patch|prerelease)`, `kind = Some("quickfix")`, `preferred = true` only for minor/patch, `edits = vec![(path, vec![TextEdit { range: version range, text: new }])]`. Reads the cache only; never calls `host::fetch`.

- [ ] **Step 1: Failing tests:** with the PyPI `requirements.txt` fixture cached as outdated (`requests 2.28.0`, latest `2.31.0`) and the cursor on that line: one action with the exact title `Update requests to 2.31.0 (minor)` and an edit replacing exactly `2.28.0`; cursor on another line → no action; up-to-date, unknown, pending or `NotChecked` → no action; a major update is not `preferred`; the call makes zero fetches (counter in `on_fetch` stays 0).
- [ ] **Step 2–4:** Run → FAIL; implement; `cargo test` → PASS; commit `feat: add update quick fix`.

### Task 10: npm (vulnerabilities only)

**Files:** `src/parsers/{npm,json_spans}.rs`, `tests/fixtures/npm/package.json`.
Particulars: sources `parsers/npm.rs`, `json_spans.rs`. Expectations: `dependencies`, `devDependencies` (`dev=true`), `peerDependencies`/`optionalDependencies` (`optional=true`); `"left-pad": "^1.3.0"` → version text `^1.3.0` (the span covers the string contents; OSV version `1.3.0`); `workspace:*`, `file:`, `git+`, `link:` kept as dependencies but `declared_version_for_osv` is `None`; `npm:real@^2.0.0` aliases are skipped (not returned); duplicate keys keep the last; invalid JSON → `vec![]`. No registry (Step 4–5 not applicable). `suggest`: `package.json`. Commit `feat: support npm manifests`.

### Task 11: Go (vulnerabilities only)

**Files:** `src/parsers/go.rs`, `tests/fixtures/go/go.mod`.
Particulars: source `parsers/go.rs`. Expectations: single-line `require github.com/pkg/errors v0.9.1` and `require ( … )` blocks, `// indirect` → `optional = true`, `replace` and `exclude` lines ignored, pseudo-versions (`v0.0.0-20200101-abcdef`) kept and passed to OSV as they are; the version span keeps the `v` (the stripped form is only for the OSV query, already covered by Task 4). `suggest`: `go.mod`. Commit `feat: support Go modules`.

### Task 12: Maven (vulnerabilities only)

**Files:** `src/parsers/maven.rs`, `tests/fixtures/maven/pom.xml`.
Particulars: source `parsers/maven.rs` (`quick-xml`). Expectations: `<dependencies>` with `<groupId>`/`<artifactId>`/`<version>` → name `group:artifact`; `<dependencyManagement>` entries found; `<scope>test</scope>` → `dev = true`; `<version>${junit.version}</version>` resolved from `<properties>` in the same file when defined (query uses the resolved value, the span stays on the placeholder, `has_additional_version_constraints = true` so no rewrite) and **not queried** when undefined; entries without a version skipped; CDATA and comments do not confuse spans; malformed XML → partial/empty, no panic. `suggest`: `pom.xml`. Commit `feat: support Maven manifests`.

### Task 13: Packagist (Composer)

**Files:** `src/parsers/php.rs`, `src/registries/packagist.rs`, `tests/fixtures/php/{composer.json,registry.json}`.
Particulars: parser source `parsers/php.rs`; `require` and `require-dev` (`dev = true`); skip `php`, `ext-*`, `lib-*`; version `^8.1` → span on the text. Registry URL `https://repo.packagist.org/p2/{vendor}/{package}.json`; `latest` = highest stable (skip `dev-*`, `-alpha/-beta/-RC`, and versions with `abandoned`). Render rule: keep `^`/`~`/`>=` operator, replace the version; `||` alternatives → `None`. `suggest`: `composer.json`. Commit `feat: support Composer manifests`.

### Task 14: pub.dev (Dart)

**Files:** `src/parsers/dart.rs`, `src/registries/pub_dev.rs`, `tests/fixtures/dart/{pubspec.yaml,registry.json}`.
Particulars: parser source `parsers/dart.rs`; `dependencies`, `dev_dependencies` (`dev=true`); map-form entries with `sdk:`, `path:`, `git:` skipped; hosted maps with `version:` handled; `any` not queried. Registry URL `https://pub.dev/api/packages/{name}`; `latest` from the `latest.version` field when stable, else the newest stable in `versions`; retracted versions ignored. Render keeps `^`. `suggest`: `pubspec.yaml`. Commit `feat: support pubspec manifests`.

### Task 15: NuGet (C#/.NET) and settings

**Files:** `src/parsers/csharp.rs`, `src/registries/nuget.rs`, `tests/fixtures/csharp/{app.csproj,Directory.Packages.props,registry.json}`, `src/settings.rs`.
Particulars: parser source `parsers/csharp.rs`; `<PackageReference Include="X" Version="1.2.3" />` and the nested `<Version>` form, `<PackageVersion>` in `Directory.Packages.props`, `VersionOverride`; `Version="$(Prop)"` resolved from `<PropertyGroup>` in the same file else not queried; floating `1.*` and ranges `[1.0,2.0)` not queried. Registry URL `https://api.nuget.org/v3-flatcontainer/{lowercase-id}/index.json` (confirm the host against depsy's `registries/nuget.rs` and fix the `net:` capability if it differs); `latest` = highest stable. Also in this task: read the contributed settings (`vulnerabilities`, `minimumSeverity`, `ignore`, per-ecosystem `enabled`, `cacheTtlSeconds`) from the host in `activate` and on `settings-changed`, with tests that a disabled ecosystem produces no fetch and no decoration. `suggest`: none (`.csproj` names vary). Commit `feat: support NuGet manifests and settings`.

### Task 16: RubyGems

**Files:** `src/parsers/ruby.rs`, `src/registries/rubygems.rs`, `tests/fixtures/ruby/{Gemfile,registry.json}`.
Particulars: parser source `parsers/ruby.rs`; `gem 'rails', '~> 7.0'`, groups (`group :development, :test do … end` → `dev = true`), `gem 'x'` without version skipped, `git:`/`path:`/`github:` skipped, two-constraint forms set `has_additional_version_constraints`. Registry URL `https://rubygems.org/api/v1/versions/{name}.json`; `latest` = highest non-prerelease, non-yanked. Render keeps `~>`. No `suggest` entry (the registry allows 8 paths; `Gemfile` is the one dropped). Commit `feat: support Gemfile manifests`.

### Task 17: Latency check and fixtures run

**Files:** `README.md` (a "Performance" section), `tests/plugin.rs` (`large_manifest_is_time_boxed`).

- [ ] **Step 1: Failing test:** a generated `requirements.txt` of 300 packages with `on_fetch` answering after counting calls: the first refresh publishes partial results with `…` decorations and the pending count in the task message; repeated `FileSaved` events complete the file; total fetches equal packages + OSV batches (no duplicates).
- [ ] **Step 2–3:** Run → FAIL; adjust `refresh` so a stopped run leaves `Pending` entries and later events continue (the cache makes this free); PASS.
- [ ] **Step 4 (manual, report numbers in the commit body):** link the plugin and open the manifests in OpenIDEA's `fixtures/{rust-app,ts-app,go-app,python-app,java-app,php-app}`; record seconds from open to final decorations, cold and warm.
- [ ] **Step 5:** Commit `test: time-box large manifests and record lookup latency`.

### Task 18: README, CI, release, registry files

**Files:** `README.md`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `plugin.toml`.

- [ ] **Step 1:** README: what it does, the nine ecosystems, screenshots (taken by the author), the limitation "checks the declared version, not the lockfile", and a table with the justification of each `net:` host (six rows).
- [ ] **Step 2:** `ci.yml`: install the Rust toolchain with `wasm32-wasip2`, install `openidea-plugin` from the OpenIDEA tag, run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `openidea-plugin build`; add a weekly `schedule` that runs `openidea-plugin build` against the **latest** OpenIDEA release (early warning for the 30-day delisting rule).
- [ ] **Step 3:** `release.yml`: on tag `v*`, build, `openidea-plugin pack . --key $KEY --publisher <publisher>` with the key from a repository secret, attach the `.oiplugin`, print its SHA-256.
- [ ] **Step 4 (author's actions, listed in the README's "Publishing" section, not run by the assistant):** choose the publisher id; `openidea-plugin keygen <publisher>.key`; replace `local.dependency-lens` by `<publisher>.dependency-lens` in `plugin.toml`; push a `v0.1.0` tag; open a PR to `l0ng-ai/openidea-plugins` adding `publishers/<publisher>.toml` and `plugins/<publisher>.dependency-lens.toml` (with `suggest = ["Cargo.toml","package.json","go.mod","pom.xml","pyproject.toml","requirements.txt","composer.json","pubspec.yaml"]`, the 8-path maximum). Contact the author of `zed-depsy` before the PR.
- [ ] **Step 5:** `openidea-plugin check` passes; commit `docs: add README, CI and release workflows`.

---

## Self-review

- **Spec coverage:** goals 1–7 → Tasks 3, 8–16 (ecosystems), 4 (OSV), 7 (decorations/problems), 8–9 (quick fix), 6 (never block: analysis time box, providers read cache), 1–18 (history by commit). Non-goals respected (no lockfiles, reports, completion). Constraints: UTF-16 (Task 2), six hosts and capabilities (Global, Task 7), one-instance and time limits (Task 6, 7, 17), registry rules (Task 18). Open points: WASM compile of adapted modules is proven per task by `openidea-plugin build`; provenance and publisher/key remain author actions (Task 18).
- **Type consistency:** `Ecosystem`, `Dependency`, `Span`, `VersionInfo`, `Vulnerability`, `AdvisorySeverity`, `Status`, `Entry`, `Analysis`, `Budget`, `Cache`, `Settings`, `Http` are defined once (Tasks 2, 4, 5, 6) and reused with the same names. Task 15 only adds reading `Settings` from the host.
- **Verified facts used:** OSV answers partial versions and Go versions with or without `v` (live check, 2026-11-13); a call may run 5 s, or 60 s with an open task; calls to one instance are serialised.
- **Gaps found and fixed in the spec:** Cargo/npm/Go/Maven need no registry (spec updated); declared-version lower bound used for OSV, with the limitation documented (spec updated).
- **Proportion:** ~18 tasks; bodies are not written out except for decisions the signature and tests do not fix.
