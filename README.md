# Dependency Lens

<!-- screenshots: add before publishing -->

Dependency Lens is an OpenIDEA plugin. It shows, after the version of each declared dependency, the known OSV vulnerabilities of that version and, for some ecosystems, the newest registry release.

OpenIDEA's built-in outdated-dependency inspection covers Cargo only. This plugin adds OSV vulnerabilities for all nine ecosystems. It also adds version hints and an update quick fix for Python, PHP, Dart, C# and Ruby, and a quick fix that fixes a vulnerability for all nine ecosystems. For Cargo, npm, Go and Maven it shows no version hint and no update to the latest release.

## Supported files

| Ecosystem | Files | Registry | Version hint and quick fix |
| --- | --- | --- | --- |
| Rust | `Cargo.toml` | OSV only | No |
| npm | `package.json` | OSV only | No |
| Go | `go.mod` | OSV only | No |
| Java (Maven) | `pom.xml` | OSV only | No |
| Python | `pyproject.toml`, `hatch.toml`, `constraints.txt`, `requirements*.txt` | `pypi.org` | Yes |
| PHP (Composer) | `composer.json` | `repo.packagist.org` | Yes |
| Dart and Flutter | `pubspec.yaml` | `pub.dev` | Yes |
| .NET (NuGet) | `*.csproj`, `*.fsproj`, `*.vbproj`, `Directory.Build.props`, `Directory.Packages.props` | `api.nuget.org` | Yes |
| Ruby | `Gemfile` | `rubygems.org` | Yes |

Lock files are not read. Manifests in `node_modules`, `target`, `vendor` and `.git` folders are skipped.

## What is shown

### End-of-line decorations

Each decoration follows the version text of a dependency. Parts that apply appear in this order, joined by ` · `:

| Text | Meaning |
| --- | --- |
| `✓` | The declared version is the newest stable release. Only for the ecosystems with a registry. |
| `→ x.y.z` | A newer stable release `x.y.z` exists. |
| `…` | The registry lookup has not run yet. |
| `?` | The check failed. The hover gives the reason. |
| `⚠ 1 vulnerability` or `⚠ n vulnerabilities` | Known OSV advisories affect the checked version. |

Example: `→ 2.31.0 · ⚠ 2 vulnerabilities`.

### Hover

The hover shows the package name and the declared version. It adds the latest version when one is newer, and the reason when a check failed. When advisories exist, it adds the checked version and one line per advisory. Each advisory line links to its OSV page when OSV gives a link.

### Many advisories

On the first open of a manifest, the dependencies show in groups: the first one alone, then the next one, then 2, 4, 8 and so on. A slow package delays only its own group. This costs one OSV request for each group, so the whole manifest can take one or two seconds longer than a single pass. The plugin loads the details of the first 10 advisories of each package version. This keeps the first open of an old package fast, because each detail is one request. When one request for all the records of a package version is cheaper (several details to load, and at most 25 advisories for each request that it saves), the plugin asks OSV for all of them at once. The hover then shows all of them, and nothing is left to load for that package. The decoration and the problem still show the exact number of advisories. The hover lists the 10 loaded advisories and adds one line, for example `15 more not loaded`. Advisories that are not loaded have an unknown severity, so the `minimumSeverity` setting does not hide them, and they do not set the problem severity.

To load the others, use one of two ways. In the hover or the quick fix menu of the dependency, pick `Load <n> more vulnerabilities of <name>`: it loads the advisories of that dependency only, and shows them at once. Or run "Dependency Lens: Load all vulnerabilities" in the open manifest, which loads them for every dependency. One run loads up to 100 details by id, and a package with many advisories is read in a single request, whatever its size, up to 1500 advisories. Run it again when more are left. The loaded details stay in the cache for `cacheTtlSeconds`. After that, the manifest shows 10 advisories again.

### Problems view

Each dependency with advisories gets one problem, on its version text. The source is `Dependency Lens`. The code is the id of the most severe advisory. The message names the package, the version and the number of advisories.

| Worst advisory severity | Problem severity |
| --- | --- |
| Critical or High | Error |
| Medium | Warning |
| Low | Info |

A dependency with a newer stable release also gets an `Info` problem on its version text, with the code `outdated`. Its message is `<name> <version>: newer version <latest> available`. The editor shows a quick fix in the hover only where a problem exists, so this problem makes the update quick fix appear in the hover. This applies to the ecosystems that have a registry. Set `outdatedProblems` to `false` to turn it off. The inline hint and the quick fix stay.

### Quick fix

On a line with an outdated requirement, the quick fix title is `Update <name> to <version> (major|minor|patch|prerelease)`. Minor and patch updates are marked as preferred. The quick fix appears only after the registry lookup of that package has run, because the code action reads the cache and never calls the network.

#### Fix a vulnerability

On a line with known vulnerabilities, a second quick fix has the title `Fix <n> vulnerabilities: update <name> to <version>`. It works for all nine ecosystems, because it uses the fixed versions that OSV gives for each advisory, and not a registry. It is marked as preferred and comes before the update to the latest release.

- The target is the smallest version that fixes every advisory with a known fix. An advisory can affect several intervals of versions (such as `[0, 1.1.0)` and `[1.5.0, 1.8.0)`): the target is never a version that the advisory still affects, so it can be higher than the highest first fix. The title says `Fix 2 of 3 vulnerabilities` when an advisory has no known fix, or when its fix is out of reach (see below).
- The quick fix counts the advisories that the hover lists: their details are loaded, and their severity reaches `minimumSeverity`. Run "Dependency Lens: Load all vulnerabilities" to count the others.
- The operator stays: `^1.6.0` becomes `^1.6.1`, and a Go `v0.3.0` becomes `v0.3.3`. The new text is the full fixed version.
- A requirement with several constraints, such as `flask>=0.12.2,<1`, takes the highest fixed version that satisfies all of them. When none does, there is no quick fix.
- A requirement that names no single version gets no fix: a range (`>=1.0, <2`, `[2.0,3.0)`), a wildcard, `||`, a Maven property, and a strict `>`.
- The fix names the version where OSV closes the advisory. That version can have an advisory of its own, and the next analysis shows it.
- Like the other quick fix, it reads the cache, so it needs `cacheTtlSeconds` above `0`.

## Network access

The plugin contacts these six hosts. Each host is listed in the capabilities of `plugin.toml`.

| Host | Why it is needed |
| --- | --- |
| `api.osv.dev` | Queries OSV.dev for the known advisories of each declared package and version, and reads each advisory's details. Used when `vulnerabilities` is on. |
| `pypi.org` | Reads the latest release of each Python package, for the version hint and the quick fix. |
| `repo.packagist.org` | Reads the latest release of each Composer package, for the version hint and the quick fix. |
| `pub.dev` | Reads the latest release of each Dart or Flutter package, for the version hint and the quick fix. |
| `api.nuget.org` | Reads the latest release of each NuGet package, for the version hint and the quick fix. |
| `rubygems.org` | Reads the latest release of each gem, for the version hint and the quick fix. |

Cargo, npm, Go and Maven use only OSV. The registry hosts are used only for the ecosystems that show version hints.

Setting `ecosystems.<id>.enabled` to `false` turns an ecosystem off. Its manifests are not analyzed, so no request goes to OSV or to its registry.

The plugin sends only package names, the OSV ecosystem names and the declared versions. Packages of disabled ecosystems and packages in `ignore` are not sent. The plugin sends no secrets and no account data, and it has no telemetry.

### Private and local packages

The plugin does not send a package that the manifest takes from a source other than the public registry. It reads these signs:

- An entry with a local or private source is skipped: `path`, `git`, `hosted` (not pub.dev), `registry` and `source` (not the public index) options, `[tool.uv.sources]`, a Go `replace`, a Maven `system` scope, and Gemfile `path`, `git` and `source` blocks, `git_source` keys and `**options`.
- A manifest-wide private source hides the whole file, because any of its packages can come from that source: a pip `--index-url`, `--extra-index-url` or `--find-links` that is not the public PyPI index, a uv `index`, `index-url`, `extra-index-url` or `find-links` setting or a Poetry `[[tool.poetry.source]]` that is not explicit and not the public index, a Composer repository other than Packagist, a Maven `<repositories>` entry other than Maven Central, and a Gemfile `source` other than `https://rubygems.org`.
- A public source does not hide anything: `source 'https://rubygems.org'`, `hosted: https://pub.dev`, `source = "pypi"`, and the public Packagist or PyPI URLs.

The plugin reads only the text of the manifest. A private source that a tool sets outside the manifest, such as a pip configuration file or an environment variable, is not seen.

## Settings

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `vulnerabilities` | boolean | `true` | Query OSV.dev for known advisories. |
| `outdatedProblems` | boolean | `true` | Add an `Info` problem on each outdated version, so the update quick fix shows in the hover. |
| `minimumSeverity` | `low`, `medium`, `high` or `critical` | `low` | Hide advisories below this severity. |
| `ignore` | array of strings | `[]` | Package names that are skipped. |
| `ecosystems.<id>.enabled` | boolean | `true` | Analyze the manifests of one ecosystem. The ids are `cargo`, `npm`, `pypi`, `go`, `packagist`, `pub`, `nuget`, `rubygems` and `maven`. |
| `cacheTtlSeconds` | integer | `3600` | Lifetime of cached answers. `0` turns the cache off, and the quick fix then never appears, because it reads the cache. Values above one week (`604800`) are read as one week. |

### Ignoring a package

Add the package name to `ignore`, for example `["serde", "left-pad"]`. The name is compared after the normalisation of its ecosystem. For PyPI, names follow PEP 503: case and runs of `-`, `_` and `.` do not matter. For Composer and NuGet, case does not matter.

## Limitations

- For Cargo, npm, Go and Maven, the plugin shows no version hint and no update to the latest release. It still offers the fix for a vulnerability.
- For a Maven dependency, the fix orders versions as Maven does, including text qualifiers such as `RELEASE`, `M1` and `SR0`.
- The plugin checks the version declared in the manifest, not a lockfile.
- For a requirement with a range (`^1.2`, `>=2.0`, `||`), the plugin checks the lower bound of the first alternative. A newer release is then shown as outdated against that bound.
- The first lookup of a large manifest takes seconds. The lookups run one after another. The status bar shows the progress, and you can cancel the task. Each chunk of 20 lookups shows its results before the next chunk starts. After a five-minute soft cap, the entries that still show `…` finish on the next open, save or "Dependency Lens: Refresh" of their manifest.
- Answers are cached in memory for `cacheTtlSeconds` (one hour by default). OSV gives a revision (the `modified` time) with each advisory. After the lifetime, an advisory whose revision did not change stays valid without a new download, and one whose revision changed is downloaded again. The cache is lost when the IDE unloads the plugin. A failed lookup is retried after 60 seconds.
- The IDE unloads an idle plugin after about five minutes, and the in-memory cache is then empty. The "→ x" decorations stay on screen, but the update quick fix is unavailable until the next save or "Dependency Lens: Refresh".
- "Dependency Lens: Refresh" reads the file again, but it answers from the cache while the entries are younger than `cacheTtlSeconds`.
- The IDE cancels a running analysis when a newer open or save of the same kind arrives. The cancelled request is not a failure: the plugin shows nothing new for it, and the newer call asks again. If the newer call is for another file, the first manifest keeps what it showed until its next open or save.
- The update quick fix writes the exact latest version. A compatible-release requirement such as `~=2.28` (Python) or `~> 7.0` (Ruby) becomes narrower after the fix (`~=2.31.0`).
- Unlisted and deprecated package states are not shown. For NuGet, the latest release can be a version that its author unlisted, because the version index does not tell them apart.
- The Maven parser reads the `project/properties` block only, for `${name}` version placeholders.
- Composer `-p1` and `-patch` stabilities count as prereleases.

## Building

1. Build the plugin: `openidea-plugin build`.
2. Link the plugin folder into OpenIDEA: `openidea-plugin link <plugin folder>`.
3. In OpenIDEA, open Settings › Plugins and choose Reload.

The maintainer notes, with the manual checks in the IDE and the publishing steps, are in [docs/MAINTAINING.md](docs/MAINTAINING.md).

## Licence and credits

Dependency Lens is released under the MIT licence. See `LICENSE`.

It adapts code from [zed-depsy](https://github.com/mpiton/zed-depsy) (MIT, Copyright (c) 2025 Mathieu). See `NOTICE`.

Dependency Lens is not affiliated with Fill Labs, Dependi or the maintainers of OpenIDEA. The vulnerability data comes from [OSV.dev](https://osv.dev). The version data comes from the public registries of each ecosystem.
