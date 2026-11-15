# Maintaining Dependency Lens

This page is for the maintainer. It lists the checks to run in the IDE, the steps to release the plugin, and the checks to run before the first release.

## Checks in OpenIDEA

Run these checks in the real IDE, after building and linking the plugin (see the Building section of the README). The IDE loads `dist/plugin.wasm`, not `target/`. Run `openidea-plugin build` after every code change, then choose Reload in Settings › Plugins. A stale `dist/plugin.wasm` runs old code, and a plain `cargo build` does not update it.

1. Open `fixtures/rust-app/Cargo.toml`, `ts-app/package.json`, `go-app/go.mod`, `python-app/requirements.txt` (or `pyproject.toml`) and `java-app/pom.xml` of the OpenIDEA checkout. Also open a `composer.json`, a `pubspec.yaml`, a `.csproj` file and a `Gemfile`. Check the decorations, the hover, the Problems view and the quick fix.
2. Measure the time from opening a manifest to its final decoration. Measure it cold and warm, on a manifest with 50 or more dependencies.
3. In a multi-project window, open a manifest of a project that is not the main project. Check that its decorations and problems appear.
4. Open a manifest saved with a UTF-8 byte order mark. Check that the decoration columns are correct.
5. Open a manifest with an old package that has many advisories, such as a `Gemfile` with `nokogiri 1.10.0`. Check that the first open is fast, that the hover lists 10 advisories and a line such as `N more not loaded`, and that the command "Dependency Lens: Load all vulnerabilities" loads the others.
5. Turn one ecosystem off in the settings. Check that no request is sent for its manifests.

## Before the first release

1. Run `actionlint` on both files in `.github/workflows/`.
2. Make a dry run in a scratch repository, with a throwaway key and a throwaway publisher id, on a test tag. Then check these points:
   - The job log contains no part of the key.
   - The job summary shows the SHA-256 of the package.
   - The release has the `.oiplugin` asset.
   Afterwards, delete the test tag and the test release.
3. Run `openidea-plugin check` on the produced `.oiplugin` file.
4. Check the plugin id prefix in `plugin.toml` before you push the release tag.

## Publishing

1. Choose your publisher id. It is the prefix of your plugin ids, for example `<publisher>.dependency-lens`.
2. Create your signing key once: `openidea-plugin keygen <publisher>.key`. Keep the file secret and out of Git.
3. Check that `id` in `plugin.toml` is `<publisher>.dependency-lens`.
4. In the GitHub repository, add the secret `OPENIDEA_PLUGIN_KEY` with the content of `<publisher>.key`. Add the variable `PUBLISHER` with the value `<publisher>`. The release workflow stops with a clear message when one of them is missing.
5. Set `version` in `plugin.toml`, in `Cargo.toml` and in `Cargo.lock` to the new version. Push the tag `v<version>`: `git tag v<version>` and then `git push origin v<version>`. The release workflow checks that the tag matches `version` in `plugin.toml` and in `Cargo.toml`. It then packs and signs the plugin, attaches `<publisher>.dependency-lens-<version>.oiplugin` to the GitHub release, and prints its SHA-256 in the job summary.
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
   version = "<version>"
   package = "https://github.com/<owner>/<repo>/releases/download/v<version>/<publisher>.dependency-lens-<version>.oiplugin"
   sha256 = "<SHA-256 from the job summary>"
   ```

   The `suggest` list holds at most eight project-relative paths, with no globs.
7. Before opening the registry pull request, tell the author of `mpiton/zed-depsy` (MIT) that this plugin reuses their code, credited in `NOTICE`.
