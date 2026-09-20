# Releases and community publication

Gatekeeper's GitHub Releases and DuckDB community publication are separate steps.
Gatekeeper is published in the [community repository](https://github.com/duckdb/community-extensions)
(`extensions/gatekeeper/description.yml`); each release updates that descriptor by pull
request from the local [community descriptor](../community/description.yml). The local copy
is the prepared submission, not evidence of what is deployed: the tag its `repo.ref` names
must exist and pass CI before it is submitted.

## Prepare the release commit

1. Set the extension version in `versions.cmake` and align the community descriptor.
   CMake and generated C++ constants consume this canonical metadata. Update the
   release packaging tests when changing version pins. Regenerate the README and
   descriptor benchmark table (`scripts/benchmark.py --markdown`); its footnote carries the
   extension version, and `test_documentation.py` checks it against the pin.
   DuckDB upgrades additionally require the full [repinning checklist](../inventories/README.md#repinning-the-engine).
2. Run the [contributor checks](../CONTRIBUTING.md#testing). Land the release preparation
   changes and verify the intended `main` commit's CI, including inventory audit,
   sanitizers, lakehouse integration, native/linked fuzz smoke, and distribution builds.
3. Require the full distribution matrix: Linux amd64/arm64 glibc and musl, macOS
   amd64/arm64, Windows amd64 MSVC/MinGW and ARM64 MSVC, and Wasm EH. Every native
   target must pass the SQL contract suite. Wasm EH must pass the browser test of the actual distribution artifact.
   If a target is deferred, keep the workflow, `scripts/package_release.py`, packaging
   tests, and community descriptor aligned and document the reason.
4. Keep the README and security doc's distinction between DuckDB-signed community builds
   and unsigned local/GitHub builds intact. Source loading stays in CONTRIBUTING.

## Tag and publish GitHub assets

After checking out the validated release commit with a clean worktree, a maintainer runs:

```sh
git tag -a v0.1.2 -m "Gatekeeper v0.1.2"
git push origin v0.1.2
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
It also checks `community/description.yml`'s `extension.version` and `repo.ref`, and
the engine metadata loaded by `scripts/versions.py`. The descriptor must also cite the
pinned DuckDB version and source revision in its compatibility description.
Keep the descriptor's version/ref
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
community binaries. The release notes link to versioned loading and security docs.

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
