# Dependency Lens

Dependency Lens is an OpenIDEA plugin written in Rust. It shows OSV vulnerabilities and newer-version hints inline in dependency manifests for nine ecosystems: Cargo, npm, Go, Maven, Python, PHP (Composer), Dart (Pub), C# (NuGet) and Ruby (Gems).

The plugin compiles to WebAssembly (`wasm32-wasip2`). It builds on its own, outside any IDE workspace (`[workspace]` in `Cargo.toml`).

## Commands

| Task | Command |
|------|---------|
| Format | `cargo fmt --all` |
| Lint (CI rule) | `cargo clippy --locked --all-targets -- -D warnings` |
| Test | `cargo test --locked` |
| Build the plugin package | `openidea-plugin build` |
| Check a package | `openidea-plugin check` |
| Link into the IDE | `openidea-plugin link <plugin folder>` |
| Update graphify | `graphify update .` |

- The IDE loads `dist/plugin.wasm`, not `target/`. Run `openidea-plugin build` after each code change, then choose Reload in Settings › Plugins. A plain `cargo build` does not update `dist/plugin.wasm`.
- Before a commit, run fmt, clippy and test. CI runs the same three checks and fails on any warning.

## Navigation

- Use graphify first for questions about the code. Read `graphify-out/GRAPH_REPORT.md`, then query the graph (`graphify query "<question>"`, `graphify path`, `graphify explain`).
- The graph holds the code only. It does not hold the docs, the README or `CLAUDE.md`. The folder is not in Git. The report names the commit it was built from. When that commit is not `HEAD`, or the folder is missing, run `graphify update .`. This command needs no LLM and no cost.
- The core types are `Ecosystem`, `Dependency`, `Cache`, `Vulnerability` and `DependencyLens` (`src/lib.rs`). The main entry points are `analyze()` in `src/analysis.rs` and `Ecosystem::parse()` in `src/model.rs`, which calls the `parse` function of each parser.
- Use Serena for symbol work (see the next section).
- Files that the tools do not show:
  - `docs/TODO.md`: the work list. `docs/MAINTAINING.md`: IDE checks and release steps. `docs/superpowers/specs/` and `plans/`: one design spec and one plan per item.
  - `tests/plugin.rs`: end-to-end tests against the SDK `MockHost`. `tests/persistence.rs`: disk cache tests. `tests/fixtures/<ecosystem>/`: manifests and recorded registry answers.
  - `plugin.toml`: manifest, capabilities and change notes. `settings.schema.json`: the plugin settings.
  - `src/parsers/<ecosystem>.rs` and `src/registries/<ecosystem>.rs`: one parser and one registry client for each ecosystem.

## Serena

Serena (language server `rust`) is set up for this project in `.serena/`. Use it for development work:

- Find a symbol with `find_symbol`. Read a file outline with `get_symbols_overview`. Find the callers of a symbol with `find_referencing_symbols`.
- Edit a whole function or type with `replace_symbol_body`, `insert_before_symbol` and `insert_after_symbol`. Rename with `rename_symbol`.
- Read a whole file only when the symbol tools are not enough.
- Serena counts lines from 0, and a symbol range includes its doc comments. Add 1 to compare with an editor or with `grep`.
- Check a file for errors with `get_diagnostics_for_file` before you run the full cargo checks.

## Invariants

- **Privacy.** A private or local package name must never reach OSV or a registry. A private index, repository or source (pip, uv, Poetry, Composer, Maven, Gemfile, Dart hosted, Cargo registry, Go replace) keeps its packages out of all lookups. A change to a parser or an analysis path must keep this rule. Add a test for each new source type.
- **Network capabilities.** Each host that the plugin contacts needs a `net:<host>` entry in `capabilities.required` in `plugin.toml`. A new host or a new capability needs a note in `change-notes`, because the user approves it at the update.
- **Version sync.** `version` must match in `plugin.toml`, `Cargo.toml` and `Cargo.lock`. The release workflow checks the tag against the first two.
- **SDK tag sync.** The `openidea-plugin` tag in `Cargo.toml` must match the tag in the `cargo install` line of `.github/workflows/ci.yml`.
- **Pinned actions.** Workflows pin each action to a commit SHA, with the version in a comment. Do not replace a SHA with a tag. See `docs/MAINTAINING.md` to update them.
- **No secrets in Git.** `*.key` and `*.oiplugin` are ignored. Never commit a signing key.

## Code rules

- Write docstrings and comments in English. Use `///` for public items and explain each non-obvious algorithm or edge case.
- Add a test first. Use a table of cases for parsers and version rules, as `src/requirement.rs` does. Put a manifest sample in `tests/fixtures/` when a test needs a file.
- Keep processing speed high. The plugin runs on the IDE thread budget (`Budget`, `TIME_BOX`). Avoid repeated parsing, repeated registry lookups and extra requests. Use sets and maps for membership tests.
- Do not add `Any` or `unsafe` code. The source has no `unsafe` code today.
- The release profile uses `panic = "abort"`. A panic stops the plugin. Outside tests, do not use `unwrap` or `expect` on manifest or network input. Return an error or a pending status instead.
- A new ecosystem needs: a parser, a registry client, a fixture, a `net:` capability, a README entry and an `ecosystems.<name>.enabled` toggle in `settings.schema.json`.

## Workflow

- One branch per `docs/TODO.md` item. Do not use git worktrees.
- Use conventional commits: `feat(scope):`, `fix(scope):`, `refactor(scope):`, `docs(scope):`, `chore:`.
- Merge a finished branch into `main` with a merge commit (`--no-ff`). Do not merge and do not push without an explicit go from the user.
- Mark an item `[x]` in `docs/TODO.md` only when its fix is merged. Keep the open items in the order that the file describes.
- Write docs, README text and change notes in short, direct sentences. Use one action per step in procedures.
- Use the IDE checks in `docs/MAINTAINING.md` for behavior that tests cannot show (timing, decorations, hover).
