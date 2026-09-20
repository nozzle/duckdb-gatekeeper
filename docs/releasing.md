# Releases and community publication

Gatekeeper's GitHub Releases and DuckDB community publication are separate steps.
Gatekeeper is published in the [community repository](https://github.com/duckdb/community-extensions)
(`extensions/gatekeeper/description.yml`); each release updates that descriptor by pull
request from the local [community descriptor](../community/description.yml). The local copy
is the prepared submission, not evidence of what is deployed: the tag its `repo.ref` names
must exist and pass CI before it is submitted.

## Prepare the release commit

1. Move the version. It is one edit in `versions.cmake` (`GATEKEEPER_VERSION`, which CMake and
   the generated C++ constants consume) and a set of coupled edits the package gate and the
   tests refuse to release without:
   - `community/description.yml`: `extension.version`, `repo.ref`, the preamble comment, and
     every `blob/vX.Y.Z/` documentation link (the gate requires all of them to name the
     release; `grep -n 'blob/v' community/description.yml` lists them).
   - `CHANGELOG.md`: rename `## Unreleased` to `## X.Y.Z - YYYY-MM-DD` and add a fresh, empty
     `## Unreleased` above it. The gate requires the release's section to have content and
     Unreleased to be empty when a tag is packaged; that section becomes the top of the
     GitHub Release notes.
   - The README and descriptor benchmark table: regenerate with
     `scripts/benchmark.py --markdown`; its footnote carries the extension version, and
     `test_documentation.py` checks it against the pin.
   `test/test_release_packaging.py` runs the gate against the checkout as the release commit
   leaves it, so it fails on the release PR until every edit above is made.
   DuckDB upgrades additionally require the full [repinning checklist](../inventories/README.md#repinning-the-engine).
2. Run the [contributor checks](../CONTRIBUTING.md#testing). Land the release preparation
   changes and verify the intended `main` commit's CI, including inventory audit,
   sanitizers, lakehouse integration, native/linked fuzz smoke, and distribution builds.
3. Require the full distribution matrix: Linux amd64/arm64 glibc and musl, macOS
   amd64/arm64, Windows amd64 MSVC/MinGW and ARM64 MSVC, and Wasm EH. Coverage differs by
   target, and the checklist is only what actually runs:
   - The reusable pipeline runs the SQL contract suite against a statically linked
     `unittest` on every native target except `linux_arm64` and the cross-compiled
     `osx_amd64`. For the musl builds and MinGW, that is the whole test.
   - The `loadable-test` jobs load the shipped artifact into the pinned Python package on
     six targets, `linux_amd64`, `linux_arm64`, `osx_arm64`, `osx_amd64`, `windows_amd64`,
     and `windows_arm64`, and run `scripts/smoke_loadable.py` on each (validation, policy
     setting, enforcement, log-only, and the audit log against the loadable). All but the
     two Windows targets also run the full Python suite; the two targets the pipeline skips
     get their only test here. No other artifact is loaded by a `loadable-test` job.
   - Wasm EH must pass the browser test of the actual distribution artifact.
   If a target is deferred, keep the workflow, `scripts/package_release.py`, packaging tests,
   and community descriptor aligned and document the reason.
4. Keep the README and security doc's distinction between DuckDB-signed community builds
   and unsigned local/GitHub builds intact. Source loading stays in CONTRIBUTING.

## Tag and publish GitHub assets

After checking out the validated release commit with a clean worktree, a maintainer runs:

```sh
git tag -a vX.Y.Z -m "Gatekeeper vX.Y.Z"
git push origin vX.Y.Z
```

The version-tag push triggers **Extension distribution** on that exact ref. It runs
the full platform builds/tests and Chromium against the distribution Wasm EH artifact.
Only after both succeed does the release job package the artifacts and publish a
GitHub Release. The tag must match the CMake and runtime extension versions.
Packaging also runs on PRs and `main`, uploading `gatekeeper-release-assets` as a CI
artifact so archive creation is tested before tagging. Only a version-tag push publishes
a GitHub Release.
Only stable `vMAJOR.MINOR.PATCH` tag pushes trigger distribution; prerelease and test
tags are excluded. The package gate validates the exact stable version again before
the tag-only publish job can run, using the canonical `versions.cmake` metadata.
It also checks `community/description.yml`'s `extension.version`, `repo.ref`, and every
`blob/` documentation link against that version, the engine metadata loaded by
`scripts/versions.py`, and `CHANGELOG.md` (`## Unreleased` must always exist; a tag additionally
needs its version's section with content and `## Unreleased` empty). The descriptor
must also cite the pinned DuckDB version and source revision in its compatibility
description. Keep the descriptor's version/ref
as unquoted scalars with two-space indentation; the standard-library-only packaging
check deliberately rejects changes to that local format.

`test/test_documentation.py` executes the descriptor's `hello_world` block against the
built extension and compares each statement's `-- ` response comments (header row first,
`|`-separated) with the actual result, and it checks that `extended_description` uses
only `###` headings. Both fields render on duckdb.org: `hello_world` as one SQL block
under the site's own "Installing and Loading" section (so it must not repeat
`INSTALL`/`LOAD`), and `extended_description` as markdown under "About gatekeeper",
followed by "Added Functions" and "Added Settings" tables generated from
`duckdb_functions()` and `duckdb_settings()`. Function descriptions and examples are
registered where each function is (`src/gatekeeper_extension.cpp`, `src/policy_setting.cpp`,
`src/enforcement.cpp`) and tested alongside the descriptor.

Each ZIP is named with the extension version, DuckDB version, platform, and `unsigned`.
Inside are the canonical binary filename, `LICENSE`, and `NOTICE`; `SHA256SUMS` covers
all ZIPs. Native and Wasm assets are unsigned development builds, not DuckDB-signed
community binaries. The release notes open with the release's `CHANGELOG.md` section and
link to versioned loading and security docs.

The publisher initially creates a draft and publishes it after all uploads succeed.
If upload/publication fails after draft creation, inspect that draft and the job logs.
To retry, delete the incomplete draft (not the tag), then rerun the failed release job.
The job refuses to create a release while any draft or published release for that tag
exists, and fails closed if the release lookup fails. An existing release is never
silently overwritten. Do not move a published version tag.

## Update the community descriptor manually

1. Check the tag workflow and GitHub Release assets. Copy
   `community/description.yml` over `extensions/gatekeeper/description.yml` in a checkout
   of [duckdb/community-extensions](https://github.com/duckdb/community-extensions),
   dropping the comment preamble. Recheck its current descriptor conventions before
   submission. The prepared descriptor pins a version tag; never replace it with a
   floating branch ref. The community repository pins the full commit SHA in `repo.ref`:
   substitute the SHA the tag points at (`git rev-parse vX.Y.Z^{}`) in the submitted copy
   only; the in-repo descriptor keeps the tag because it cannot name the commit that
   contains it.
2. State which engine the GitHub assets target, and link compatibility validation.
   The community repository can rebuild the source against another engine; the source
   has no fixed release allowlist. Each binary still loads only into the engine it was
   built from, and Gatekeeper enforces that itself when DuckDB's footer check is disabled.
   Compilation and regression tests, rather than inventory provenance, gate compatibility.
   Mention the engine coupling up front: the grammar is generated from the engine being
   compiled, DuckDB's in-tree JSON serializer is compiled into the extension, and internal
   binder entry points are used (see
   [Compatibility and review](security.md#compatibility-and-review)), which is why the
   build needs `requires_toolchains: python3` and why rebuilds for a new engine may need a
   source update.
3. Include the platform opt-ins, MVP/threads exclusions, Wasm runtime pin, and Python
   toolchain requirement. Reference the successful tag distribution run. The community
   repository builds and signs its own binaries; GitHub assets are not those binaries.
4. Submit the PR manually and follow its build results. This repository's workflows
   neither open that PR nor deploy to the community repository.

## After community deployment

Using DuckDB 1.5.5 with normal signature verification and a fresh extension directory,
verify installation, loading, and the descriptor's hello-world queries:

```sql
INSTALL gatekeeper FROM community;
LOAD gatekeeper;
SELECT allowed FROM gatekeeper_validate('SELECT 1');
SELECT code FROM gatekeeper_validate('DROP TABLE orders');
```

Expect `true` and `unsupported`, and `extension_version` in `duckdb_extensions()` equal to the
released version. `test/test_documentation.py` exercises the local README examples against a
source build; the community-install check above is the separate deployment verification.

Monitor DuckDB releases and test community-style rebuilds. Update our reproducible
build pins when adopting a new release for our own assets, and address actual build
or regression failures. Existing function names do not require repeat source review
on every engine update; new defaults can be added independently.
