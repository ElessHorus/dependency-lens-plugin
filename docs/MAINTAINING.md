# Maintaining Dependency Lens

This page is for the maintainer. It lists the checks to run in the IDE, the steps to release the plugin, and the checks to run before the first release.

## Checks in OpenIDEA

Run these checks in the real IDE, after building and linking the plugin (see the Building section of the README).

1. Open `fixtures/rust-app/Cargo.toml`, `ts-app/package.json`, `go-app/go.mod`, `python-app/requirements.txt` (or `pyproject.toml`) and `java-app/pom.xml` of the OpenIDEA checkout. Also open a `composer.json`, a `pubspec.yaml`, a `.csproj` file and a `Gemfile`. Check the decorations, the hover, the Problems view and the quick fix.
2. Measure the time from opening a manifest to its final decoration. Measure it cold and warm, on a manifest with 50 or more dependencies.
3. In a multi-project window, open a manifest of a project that is not the main project. Check that its decorations and problems appear.
4. Open a manifest saved with a UTF-8 byte order mark. Check that the decoration columns are correct.
5. Turn one ecosystem off in the settings. Check that no request is sent for its manifests.

## Before the first release

1. Run `actionlint` on both files in `.github/workflows/`.
2. Make a dry run in a scratch repository, with a throwaway key and a throwaway publisher id, on a test tag. Then check these points:
   - The job log contains no part of the key.
   - The job summary shows the SHA-256 of the package.
   - The release has the `.oiplugin` asset.
   Afterwards, delete the test tag and the test release.
3. Run `openidea-plugin check` on the produced `.oiplugin` file.
4. Change the plugin id prefix in `plugin.toml` before you push the release tag.

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
7. Before opening the registry pull request, tell the author of `mpiton/zed-depsy` (MIT) that this plugin reuses their code, credited in `NOTICE`.
