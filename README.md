# Dependency Lens

<!-- screenshots: add before publishing -->

Dependency Lens is an OpenIDEA plugin. It shows, after the version of each declared dependency, the known OSV vulnerabilities of that version and, for some ecosystems, the newest registry release.

OpenIDEA's built-in "Newer dependency version available" inspection covers Cargo, npm, Go and Maven. This plugin adds OSV vulnerabilities for all nine ecosystems. It also adds version hints and an update quick fix for Python, PHP, Dart, C# and Ruby.

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

- The plugin checks the version declared in the manifest, not a lockfile.
- For a requirement with a range (`^1.2`, `>=2.0`, `||`), the plugin checks the lower bound of the first alternative. A newer release is then shown as outdated against that bound.
- The first lookup of a large manifest takes seconds. The lookups run one after another. The status bar shows the progress, and you can cancel the task. Each chunk of 20 lookups shows its results before the next chunk starts. After a five-minute soft cap, the entries that still show `…` finish on the next open, save or "Dependency Lens: Refresh" of their manifest.
- Answers are cached in memory for `cacheTtlSeconds` (one hour by default). The cache is lost when the IDE unloads the plugin. A failed lookup is retried after 60 seconds.
- Unlisted and deprecated package states are not shown.
- The Maven parser reads the `project/properties` block only, for `${name}` version placeholders.
- Composer `-p1` and `-patch` stabilities count as prereleases.

## Verifying in OpenIDEA

These checks need the IDE GUI. The automated agents of this project cannot run them.

1. Build and link the plugin: `openidea-plugin build`, then `openidea-plugin link <plugin folder>`, then Settings › Plugins › Reload.
2. Open `fixtures/rust-app/Cargo.toml`, `ts-app/package.json`, `go-app/go.mod`, `python-app/requirements.txt` (or `pyproject.toml`) and `java-app/pom.xml` in the OpenIDEA checkout. Check the decorations, the hover, the Problems view and the quick fix.
3. Measure the time from opening a manifest to its final decoration. Do this cold and warm, on a manifest with 50 or more dependencies.
4. Open a manifest of a project that is not the main project of the window, in a multi-project window. Confirm that the decorations and the problems appear. The SDK mock could not show decorations for files of other projects.
5. Open a manifest saved with a UTF-8 byte order mark. Check that the decoration columns are correct.
6. Disable one ecosystem in the settings and confirm that no request is sent for its manifests.
7. Confirm the claim about OpenIDEA's built-in "Newer dependency version available" inspection in the first paragraph of this README.

## Publishing

1. Choose your publisher id. It is the prefix of your plugin ids, for example `<publisher>.dependency-lens`.
2. Create your signing key once: `openidea-plugin keygen <publisher>.key`. Keep the file secret and out of Git.
3. In `plugin.toml`, replace `local.dependency-lens` by `<publisher>.dependency-lens` in `id`.
4. In the GitHub repository, add the secret `OPENIDEA_PLUGIN_KEY` with the content of `<publisher>.key`. Add the variable `PUBLISHER` with the value `<publisher>`. The release workflow stops with a clear message when one of them is missing.
5. Push the tag `v0.1.0`: `git tag v0.1.0` and then `git push origin v0.1.0`. The release workflow checks that the tag matches `version` in `plugin.toml`. It then packs and signs the plugin, attaches `<publisher>.dependency-lens-0.1.0.oiplugin` to the GitHub release, and prints its SHA-256 in the job summary.
6. Open a pull request to `l0ng-ai/openidea-plugins`. It adds two files. First, `publishers/<publisher>.toml`:

   ```toml
   name = "<publisher>"
   owners = ["<github-account>"]
   keys = ["<public key>"]
   revoked-keys = []
   ```

   Second, `plugins/<publisher>.dependency-lens.toml`:

   ```toml
   repository = "https://github.com/<owner>/<repo>"
   suggest = ["Cargo.toml", "package.json", "go.mod", "pom.xml", "pyproject.toml", "requirements.txt", "composer.json", "pubspec.yaml"]

   [[versions]]
   version = "0.1.0"
   package = "https://github.com/<owner>/<repo>/releases/download/v0.1.0/<publisher>.dependency-lens-0.1.0.oiplugin"
   sha256 = "<SHA-256 from the job summary>"
   ```

   The `suggest` list holds at most eight project-relative paths, with no globs.
7. Before the registry pull request, contact the author of `mpiton/zed-depsy` to confirm that the code base reused here is independent of Dependi. Keep the `NOTICE` file.

## Licence and credits

Dependency Lens is released under the MIT licence. See `LICENSE`.

It adapts code from [zed-depsy](https://github.com/mpiton/zed-depsy) (MIT, Copyright (c) 2025 Mathieu). See `NOTICE`.

Dependency Lens is not affiliated with Fill Labs, Dependi or the maintainers of OpenIDEA. The vulnerability data comes from [OSV.dev](https://osv.dev). The version data comes from the public registries of each ecosystem.
