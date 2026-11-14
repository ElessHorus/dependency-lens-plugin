# Dependency Lens

<!-- screenshots: add before publishing -->

Dependency Lens is an OpenIDEA plugin. It shows, after the version of each declared dependency, the known OSV vulnerabilities of that version and, for some ecosystems, the newest registry release.

OpenIDEA's built-in outdated-dependency inspection covers Cargo only. This plugin adds OSV vulnerabilities for all nine ecosystems. It also adds version hints and an update quick fix for Python, PHP, Dart, C# and Ruby. For npm, Go and Maven it shows vulnerabilities only.

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

### Problems view

Each dependency with advisories gets one problem, on its version text. The source is `Dependency Lens`. The code is the id of the most severe advisory. The message names the package, the version and the number of advisories.

| Worst advisory severity | Problem severity |
| --- | --- |
| Critical or High | Error |
| Medium | Warning |
| Low | Info |

### Quick fix

On a line with an outdated requirement, the quick fix title is `Update <name> to <version> (major|minor|patch|prerelease)`. Minor and patch updates are marked as preferred. The quick fix appears only after the registry lookup of that package has run, because the code action reads the cache and never calls the network.

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

## Settings

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `vulnerabilities` | boolean | `true` | Query OSV.dev for known advisories. |
| `minimumSeverity` | `low`, `medium`, `high` or `critical` | `low` | Hide advisories below this severity. |
| `ignore` | array of strings | `[]` | Package names that are skipped. |
| `ecosystems.<id>.enabled` | boolean | `true` | Analyze the manifests of one ecosystem. The ids are `cargo`, `npm`, `pypi`, `go`, `packagist`, `pub`, `nuget`, `rubygems` and `maven`. |
| `cacheTtlSeconds` | integer | `3600` | Lifetime of cached answers. `0` turns the cache off. Values above one week (`604800`) are read as one week. |

### Ignoring a package

Add the package name to `ignore`, for example `["serde", "left-pad"]`. The name is compared after the normalisation of its ecosystem. For PyPI, names follow PEP 503: case and runs of `-`, `_` and `.` do not matter. For Composer and NuGet, case does not matter.

## Limitations

- For npm, Go and Maven, the plugin shows vulnerabilities only. It shows no version hint and no quick fix.
- The plugin checks the version declared in the manifest, not a lockfile.
- For a requirement with a range (`^1.2`, `>=2.0`, `||`), the plugin checks the lower bound of the first alternative. A newer release is then shown as outdated against that bound.
- The first lookup of a large manifest takes seconds. The lookups run one after another. The status bar shows the progress, and you can cancel the task. Each chunk of 20 lookups shows its results before the next chunk starts. After a five-minute soft cap, the entries that still show `…` finish on the next open, save or "Dependency Lens: Refresh" of their manifest.
- Answers are cached in memory for `cacheTtlSeconds` (one hour by default). The cache is lost when the IDE unloads the plugin. A failed lookup is retried after 60 seconds.
- The IDE unloads an idle plugin after about five minutes, and the in-memory cache is then empty. The "→ x" decorations stay on screen, but the update quick fix is unavailable until the next save or "Dependency Lens: Refresh".
- "Dependency Lens: Refresh" reads the file again, but it answers from the cache while the entries are younger than `cacheTtlSeconds`.
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
