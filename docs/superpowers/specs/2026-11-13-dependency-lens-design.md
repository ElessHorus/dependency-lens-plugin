# Dependency Lens — design

An OpenIDEA plugin that shows dependency vulnerabilities and, for the
ecosystems the IDE does not cover, newer versions inline in manifest files.
Target: a **community plugin** in its author's own repository, listed through
the registry `l0ng-ai/openidea-plugins`. Plugin API `openidea:plugin@1.8.0`.

Working name: `<publisher>.dependency-lens`. The `openidea.*` prefix is
reserved for official plugins signed with the official key, so the author's
publisher id is used instead (see "Left to the author").

## Intent

OpenIDEA already offers version completion and a "Newer dependency version
available" inspection (with a quick fix) for Cargo, Go, Maven and npm
(`crates/ide-workspace/src/dependencies/`, `docs/en/guide/build-tools.mdx`).
It has **no vulnerability reporting** for dependencies, and no version
awareness for the other ecosystems it supports as languages (Python, PHP,
Dart, C#, Ruby). The plugin fills those two gaps and nothing more, so a
maintainer can accept it as non-duplicating.

The author first considered an official plugin (`plugins/official/`), then chose
the community route: the author owns and maintains the plugin in a separate
repository, signs the releases, and adds each version to the registry by pull
request. No issue or maintainer label is needed to start. The registry
maintainers still review the source and the requested capabilities of a new
plugin, and check that it does not duplicate an existing one.

## Goals

1. Cover the nine ecosystems of the `zed-depsy` code base, all of which
   OpenIDEA supports as languages (`languages/*.toml`):

   | Ecosystem | Manifests | Registry | Newer-version hints and quick fix |
   | --- | --- | --- | --- |
   | Rust | `Cargo.toml` | crates.io | no (built in) |
   | JavaScript / TypeScript | `package.json` (`pnpm-workspace.yaml` optional) | npm | no (built in) |
   | Go | `go.mod` | proxy.golang.org | no (built in) |
   | Java | `pom.xml` | Maven Central | no (built in) |
   | Python | `requirements*.txt`, `constraints.txt`, `pyproject.toml`, `hatch.toml` | PyPI | yes |
   | PHP | `composer.json` | Packagist | yes |
   | Dart / Flutter | `pubspec.yaml` | pub.dev | yes |
   | C# / .NET | `*.csproj`, `Directory.Build.props`, `Directory.Packages.props` | NuGet | yes |
   | Ruby | `Gemfile` | RubyGems | yes |

2. Report known vulnerabilities (OSV.dev) for direct dependencies in all nine.
3. For the five ecosystems the IDE does not cover: show the latest version,
   flag outdated dependencies, and offer an "update to X" quick fix labelled by
   semver distance (major, minor, patch).
4. Show the result in the editor as soon as the background lookup ends
   (no scrolling or editing needed):
   - end-of-line decoration per dependency (up to date, newer version,
     N vulnerabilities, unknown), with a Markdown hover;
   - a problem in the Problems view per vulnerable dependency, severity mapped
     from the advisory.
5. Keep the editor responsive: network work happens in event handlers, never in
   providers; providers only read a cache.
6. Make adding an ecosystem cheap: one parser and one registry client behind
   shared traits.
7. Keep the history readable: a foundation commit (traits, cache, publishing,
   OSV) first, then one commit per ecosystem. Reviewers of the registry read
   the whole source of a new plugin, so a clear structure helps.

## Non-goals

- No "newer version" hint or quick fix for Cargo, npm, Go or Maven (the IDE has
  them). Vulnerabilities still show for them.
- No lockfile parsing, transitive dependency scanning, report export,
  completion, private-registry authentication, alternative Cargo registries or
  persistent database in the first version. These exist in `zed-depsy` and can
  be added later.
- No Dependi Pro features and no use of any `dependi.io` service.
- No native binary and no language server.

## Anti-goals (a failure even if it works)

- Copying code from Fill Labs' Dependi (proprietary licence: no modification,
  no redistribution). The design is clean-room: nothing from
  `filllabs/dependi` is used, and no name or branding of Dependi or Depsy.
- Any provider that calls the network (it would be dropped at 50 ms and look
  broken).
- Asking for broader permissions than the registries it uses.
- Scope creep: one plugin, nine ecosystems, no extras. The registry rejects a
  plugin it cannot review or one that duplicates another.

## Constraints

- **Sandbox:** WebAssembly component, target `wasm32-wasip2`, built with
  `openidea-plugin build`. No threads, sockets, file system or processes.
  Network only through `host::fetch` (HTTPS, 16 MiB response cap), gated by
  `net:<host>` capabilities.
- **Budgets:** editor providers get 50 ms soft / 500 ms hard.
- **One instance, calls never concurrent** (checked in `plugins/README.md`,
  "calls are queued, never run concurrently in one instance"). `host::fetch` is
  synchronous. Consequences: registry lookups run one after the other; a
  provider call arriving during a lookup waits and is dropped at 50 ms; a newer
  event cannot cancel a running lookup, because it only runs after the current
  call returns. A `host::begin_task` handle shows progress and lets the user
  cancel, and renews the call's CPU budget on each `report`. Its wall-clock
  budget still bounds a call, so a lookup run is time-boxed.
- **Events:** `file-opened`, `file-saved` and `files-changed` (needs
  `engines.openidea = "^1.3"`) trigger analysis. `document-changed` (API 1.6)
  is optional for unsaved edits.
- **Decorations** (API 1.4): at most 10,000 items per file and 50 editor sets
  per plugin; `after` is plain text; `hover` is a string.
- **Ten-host worry is gone:** with the change above the plugin asks for six
  `net:` hosts, not ten.
- **Community registry rules** (`openidea-plugins` README and
  `docs/en/plugins/publishing/policy.mdx`):
  - a public source repository under an open-source licence, and a package
    built from it (no obfuscated or minified code not built from that source);
  - the README says what the plugin does and why it needs each network
    capability;
  - the package is signed with the publisher's Ed25519 key
    (`openidea-plugin keygen`, then `build` and `pack --key --publisher`), is
    attached to a release of the repository, and is pinned in the registry by
    URL and SHA-256 (`publishers/<publisher>.toml` the first time,
    `plugins/<publisher>.<name>.toml` for each version);
  - CI of the registry runs `openidea-plugin check` against the latest
    OpenIDEA release on every change and daily. A plugin that fails against a
    new release and has no fixed version within 30 days is delisted;
  - the registry can suggest the plugin when the open project contains certain
    files (`suggest`, up to 8 project-relative paths). Candidates: `Cargo.toml`,
    `package.json`, `go.mod`, `pom.xml`, `pyproject.toml`, `composer.json`,
    `pubspec.yaml`, `Gemfile`.
- **The author's own CI** builds with `openidea-plugin build`, runs `cargo test`
  against the SDK mock host, and runs `openidea-plugin check` on each release
  candidate and on a schedule against the latest OpenIDEA release.
- **SDK dependency:** the plugin depends on `openidea-plugin` from the
  repository's git tag (`{ git = "https://github.com/l0ng-ai/openidea", tag =
  "vX.Y.Z" }`), not by path. The tag sets the API the plugin is built for.
- **Licence:** `mpiton/zed-depsy` is MIT. Reused or adapted code keeps its
  copyright notice (Mathieu, 2025). The plugin is MIT too (my proposal: the
  simplest licence compatible with the base). The repository carries `LICENSE`
  and a `NOTICE` that credits `zed-depsy`. Fill Labs' Dependi is not a source
  (see anti-goals).
- **Coordinates:** UTF-16 columns and 0-based lines in every position the
  plugin publishes.

## Approaches considered

**A. Push from a background task (chosen).** An event parses the manifest and
starts a task. The task queries registries and OSV, fills an in-memory cache,
then publishes decorations and diagnostics. A `code-actions` provider reads the
cache. Results appear when the lookup ends. Cost: end-of-line decorations look
different from language-server inlay hints.

**B. Pull with `inlay-hints`, `hover` and `diagnostics` providers.** Native
look, but the editor asks again only after an edit or a scroll. On first open
the cache is empty and nothing shows until the user moves. Rejected.

**C. Run `depsy-lsp` as a language server.** Needs a native binary and the
high-risk `process:` capability, and breaks the sandbox model. A native binary
would not be accepted in an official plugin. Rejected.

**Reuse choice (decided by the author):** use `mpiton/zed-depsy` (MIT) as the
code base instead of writing from zero. It is already Rust, covers nine
ecosystems and has semver-aware update logic. Only the parts that fit the
sandbox are adapted:

| zed-depsy part | Use |
| --- | --- |
| `parsers/` (cargo, npm, python, go, php, dart, csharp, ruby, maven; taplo, quick-xml) | adapt: drop the `tower_lsp::lsp_types` import in `parsers/mod.rs`; spans are byte offsets, so convert to UTF-16 explicitly |
| `providers/version_edit.rs`, `registries/version_utils.rs`, `registries/url_sanitizer.rs`, `parsers/json_spans.rs` | reuse nearly as is |
| response structs and JSON reading in `registries/*.rs` and `vulnerabilities/osv.rs` | keep; move network I/O behind a plugin-side `Http` trait implemented with `host::fetch` |
| `backend.rs`, `cache/` (SQLite), `tokio`, `tower-lsp`, `reqwest`, `dashmap`, `clap`, `reports.rs`, lockfile parsers | not used |

## Design

- One Rust crate at the root of the plugin's own repository (`plugin.toml`,
  `Cargo.toml`, `src/`, `README.md`, `LICENSE`, `NOTICE`, `.github/`). Modules: `ecosystem` (trait
  and registry of ecosystems), `parsers`, `registries`, `osv`, `cache`,
  `publish` (decorations and diagnostics), `actions` (quick fix), `plugin`
  (SDK wiring).
- A trait `Http` with one method that returns status and body. The plugin
  implements it with `host::fetch`; tests implement it with canned responses.
  Everything else is pure and testable without the IDE.
- Cache: in-memory map keyed by (ecosystem, package) with a time-to-live,
  inside the plugin instance. Vulnerability results are keyed by (ecosystem,
  package, version). Persistence in plugin storage is optional.
- Flow per document: event → read the file → parse → deduplicate packages →
  answer what the cache has and publish it at once → look up the cache misses
  (one batched OSV call per file; one request per package for registries) →
  publish again every few lookups, so the first results show early → the cache
  serves code actions.
  Events for the same file that queue up during a run coalesce; after a run, a
  file whose text changed in the meantime is parsed again from its current
  content (compare the document version).
- Lookups are time-boxed per call. Packages not reached stay "pending" in the
  decoration and are finished by the next event on that file. The mechanism that
  triggers the continuation is left to the builder (see below).
- The editor-provider declaration uses `languages = ["*"]` and the handlers
  select manifests by file name, as `license-header` does. Manifests span many
  language ids (`toml`, `json`, `yaml`, `xml`, `gomod`, `ruby`, plain text for
  `requirements.txt`), so filtering by language id would miss files.
- Capabilities (declared, not `net:ask`), one `net:` per host actually used.
  Cargo, npm, Go and Maven need **only OSV** (the plugin shows no version hint
  for them), so they add no registry host. Hosts: `api.osv.dev`, `pypi.org`,
  `repo.packagist.org`, `pub.dev`, NuGet (host to confirm from the registry
  module), `rubygems.org`. Plus `events`, `project.read`, `editor.read`,
  `editor.write` (for the quick fix) and `storage` if used. Each host is
  justified in the README.
- **Which version is checked.** There is no lockfile parsing in v1, so OSV is
  asked about the version the manifest declares, reduced to its lower bound
  (operators and a `v` before a digit are stripped, the first part of a
  comma list is kept: `^1.2` → `1.2`, `==1.2.3` → `1.2.3`; the live OSV API
  accepts partial versions, so nothing is padded). Entries whose version is not a
  registry version (git, path, workspace, `*`, `latest`, an unresolved
  property) are not queried. The hover says which version was checked. Known
  limitation: a range whose resolved version is newer than its lower bound can
  show an advisory that the installed version no longer has; lockfile
  resolution is the follow-up that removes it.
- **Time limits.** A call without an open task may run 5 s; with an open task
  it may run 60 s (`host::begin_task`). A lookup run opens a task and stops at
  50 s.
- Behaviour on failure: network error, rate limit or a bad response shows an
  "unknown" decoration with the reason in the hover; it never shows a
  vulnerability or an update it cannot support.
- Settings (contributed schema): enable/disable per ecosystem, enable/disable
  vulnerability lookups, ignore list, minimum severity.

## Test-first plan (outline for the plan skill)

0. Build the pure parser/semver/OSV modules for `wasm32-wasip2` first. A
   throwaway crate already showed that `taplo`, `quick-xml`, `serde_json`,
   `semver` and `json-spanned-value` compile for this target; the adapted
   modules themselves are not yet checked.
1. Parser tests per ecosystem: names, versions and exact UTF-16 spans, with
   non-ASCII text in the file.
2. Registry tests: response bodies (recorded fixtures) → latest version.
3. OSV tests: batch request body, response → severity mapping.
4. Pipeline test with the mock host: open a manifest, run the task, assert the
   published decorations and diagnostics, assert providers return within the
   budget from the cache without calling `Http`.
5. `openidea-plugin check` passes; manual run on `fixtures/rust-app`,
   `ts-app`, `go-app`, `python-app`, `java-app`.

## Open points and risks

- **Provenance of zed-depsy.** It credits Dependi as "inspired by" and was
  renamed at Fill Labs' request. It is Rust where Dependi is TypeScript, so a
  copy is unlikely, but nobody has compared the two. Ask the author
  (`mpiton`) before the PR, and mention the reuse in it.
- **Slow first lookup.** Registry lookups are sequential and synchronous. A
  manifest with many uncached packages takes seconds on first open and holds the
  plugin instance meanwhile (quick fixes unavailable, hints partial). The cache,
  the OSV batch and progressive publishing reduce this but do not remove it.
  Measure it on `fixtures/` and a large real manifest before the PR.
- **Registry review.** A maintainer reads the source and the requested
  capabilities of a new plugin and checks for duplicates. Overlap with the IDE's
  own outdated-version inspection for Cargo, npm, Go and Maven is avoided by
  design; the README should say so. The six `net:` hosts need a clear
  justification each.
- **Maintenance load.** The plugin must keep passing `openidea-plugin check`
  against each new OpenIDEA release (30 days to fix before delisting), and the
  registries' response formats and OSV can change. The scheduled CI check in
  the author's repository is the early warning.
- **Signing key.** The publisher key is secret and only the author creates and
  keeps it (`openidea-plugin keygen`). It is never committed or given to an
  assistant. Releases are signed locally or with a CI secret.
- **Toolchain.** `rustup`, `wasm32-wasip2` and `openidea-plugin` are installed
  on the author's machine (checked).

## Left to the author

Decisions only the author can make before publishing: the publisher id (the
prefix of the plugin id, for example `alice` gives `alice.dependency-lens`),
the GitHub account and repository name that host the plugin, the signing key,
and confirming the MIT licence.

## Left to the builder

How a time-boxed run continues (re-triggering on the next event, an
`on-schedule` tick of at least 60 s, or another host mechanism), crate layout
details, cache lifetimes, exact decoration strings and styles,
severity mapping details, plugin icon, README wording (including the
justification of each network host), whether to persist the cache, whether to
react to `document-changed`, the plugin's display name, and the order of the
ecosystems in the first commits.

## Implementation notes (added after the build, 2026-11-14)

The sections above are the original design. Where the code differs, the code and the README win. The differences:

- **What the IDE covers.** OpenIDEA's "Newer dependency version available" inspection with a quick fix exists only for Cargo. Go has version completion; npm and Maven have completion sources. The plugin therefore shows vulnerabilities only (no version hint) for Cargo, npm, Go and Maven, and version hints plus the update quick fix for Python, PHP, Dart, C# and Ruby. Whether to add version hints for npm, Go and Maven (three more registries and hosts) is an open product decision.
- **Network.** Six `net:` hosts: `api.osv.dev`, `pypi.org`, `repo.packagist.org`, `pub.dev`, `api.nuget.org`, `rubygems.org`. Package names are checked against a conservative grammar per ecosystem before they enter a URL; every request gets a 10 s timeout when none is set.
- **Execution model (replaces the "time-boxed run" sections).** One continuous refresh per manifest in chunks of 20 lookups, publishing after every chunk. `Task::report` and `Task::is_cancelled` renew the host's call budget (verified in the host source), so a call is cut only after 60 s without a sign of life. Each chunk is bounded to 40 s (OSV advisory details included); a soft cap of 300 s stops further chunks, and entries still shown as `…` finish on the next open, save or "Dependency Lens: Refresh". There is no `on-schedule` activation: the host delivers `Scheduled` only to an inactive plugin.
- **Manifest API.** `engines.openidea = "^1.4"` (the `settings-changed` event); the SDK is pinned at the tag `v0.1.44` (plugin API 1.7).
- **Settings** are read in `activate` and on `settings-changed`; the ignore list compares normalised package names.
- **OSV details.** `querybatch` returns only advisory ids; details come from `GET /v1/vulns/{id}` (at most 100 per call, cached). Severity comes from `database_specific.severity`, else from a CVSS v3.x base score computed from the vector. A placeholder ("Details not loaded yet") is kept visible and retried; a failed OSV call stays `?` and is never replaced by the registry status.
- **Byte order mark** handling is central (`Ecosystem::parse`).
- **Known limitations and follow-ups:** the quick fix writes the exact latest version, so `~=` / `~>` requirements become narrower; `FilesChanged` analyses manifests nobody opened; the whole crate API is `pub` (only `DependencyLens` and `publish::DECORATION_SET` are needed outside); "outdated" for ranges compares the lower bound of the first alternative.
