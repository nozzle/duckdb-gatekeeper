# Releases and community publication

Gatekeeper's GitHub Releases and DuckDB community publication are separate steps.
Gatekeeper is published in the [community repository](https://github.com/duckdb/community-extensions)
(`extensions/gatekeeper/description.yml`); each release updates that descriptor by pull
request from the local [community descriptor](../community/description.yml). The local copy
is the prepared submission, not evidence of what is deployed: the tag its `repo.ref` names
must exist and pass CI before it is submitted.

## Prepare the release commit

The 2.0 build matrix has nine native targets, including restored Windows MinGW with CRAN
DuckDB 2.0.0. Wasm EH has a separately matched development-host browser job, but its release
artifact remains excluded: the published runtime reports `v2.0.0-dev88614`, not `v2.0.0`.
Restore that release target, distribution browser job and packaging dependency together
when an official release-labeled host passes. MVP/threads exclusions remain separate.

1. Move the version. It is one edit in `versions.cmake` (`GATEKEEPER_VERSION`, which CMake and
   the generated C++ constants consume) and a set of coupled edits the package gate and the
   tests refuse to release without:
   - `community/description.yml`: `extension.version`, `repo.ref`, and every
     `blob/` documentation link, including `blob/main/` links (the gate requires all of them
     to name the release; `grep -n 'blob/' community/description.yml` lists them). The community
     repository builds `repo.ref` against DuckDB 2.0. `repo.variegata` names the release its
     DuckDB 1.5 binaries came from; it moves only on request to the community maintainers, so a
     release normally leaves it alone. `repo.ref_next` no longer triggers a build, and the gate
     rejects it.
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
   Published `docs/policy-v*.schema.json` files and their `$id` URLs are permanent. Keep
   historical schemas unchanged when adding a new version, even after the runtime stops
   accepting the old document format. Existing release users still resolve those URLs.
2. Run the [contributor checks](../CONTRIBUTING.md#testing). Land the release preparation
   changes and verify the intended `main` commit's CI, including inventory audit,
   sanitizers, lakehouse integration, native/linked fuzz smoke, and distribution builds.
3. Require the declared matrix: Linux amd64/arm64 glibc and musl, macOS amd64/arm64,
   Windows amd64 MSVC/MinGW and ARM64 MSVC (nine native targets). Intel macOS is an
   explicit opt-in on the 2.0 toolchain. Every shipped artifact must pass its official host:
   - The reusable pipeline runs the SQL contract suite against a statically linked
     `unittest` on every native target except `linux_arm64` and the cross-compiled
     `osx_amd64` (an upstream skip; those two get the full Python suite below instead).
   - Every shipped artifact is then loaded, as the loadable it is, into an official DuckDB
     host of the pinned engine, and the checks that cross the host/loadable ABI boundary run
     against it (validation over host-created bind data, replacement scans, the policy
     setting, an enforced connection, log-only mode, the audit log, the configuration lock):
     the pinned Python package for `linux_amd64`, `linux_arm64`, `osx_amd64`, `osx_arm64`,
     `windows_amd64`, and `windows_arm64` (`loadable-test`: `scripts/smoke_loadable.py` and
     the full Python suite); the engine's musl CLI in Alpine for `linux_amd64_musl` and
     `linux_arm64_musl` (`loadable-cli`: `scripts/smoke_cli.sh`); the CRAN R package for
     `windows_amd64_mingw` (`loadable-r`: `scripts/smoke_loadable.R`, the one leg that takes
      a client `Prepare()` into the shipped binary). The separate `wasm.yml` job tests the
      development-labeled Wasm host; the distribution `browser-test` stays deferred with its target.
     The R leg runs the portable SQL form of the smoke (`scripts/smoke/loadable.sql` and
     `enforced.sql`), which the Python leg and `test/test_smoke_sql.py` run as well. The CLI
     is one connection: it runs `loadable.sql` as is, and `scripts/smoke_cli.sh` replays the
     enforced half by hand as separate CLI processes (latch, allowed read, the four refusals,
     the audit records through `stdout` log storage, log-only), so a change to `enforced.sql`
     is mirrored there, not picked up.
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
every declared platform's build and official-host tests. The R job gates packaging; the
deferred distribution Wasm job must also gate packaging when that target is restored.
Only after the required jobs succeed does the release job package the artifacts and publish a
GitHub Release. The tag must match the CMake and runtime extension versions.
Packaging also runs on PRs and `main`, uploading `gatekeeper-release-assets` as a CI
artifact so archive creation is tested before tagging. Only a version-tag push publishes
a GitHub Release.
Only stable `vMAJOR.MINOR.PATCH` tag pushes trigger distribution; prerelease and test
tags are excluded. The package gate validates the exact stable version again before
the tag-only publish job can run, using the canonical `versions.cmake` metadata.
It also checks `community/description.yml`'s `extension.version`, `repo.ref`, and every
`blob/` documentation link against that version (non-tag PR/main packaging also permits
`blob/main/` links for unreleased documentation), the engine metadata loaded by
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
all ZIPs. Incoming CI artifacts may also contain the toolchain's
`test-support/<artifact-name-hash>/test-support.tar.gz`; packaging validates that exact
optional layout and omits it from release assets. Other extra files remain an error.
Native and Wasm assets are unsigned development builds, not DuckDB-signed
community binaries. The release notes open with the release's `CHANGELOG.md` section and
link to versioned loading and security docs. Relative changelog links are converted to
tag-pinned repository URLs when generating the GitHub Release body.

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
   floating branch ref. The community repository pins full commit SHAs in `repo.ref` and
   `repo.variegata`: substitute the SHA each tag points at (`git rev-parse vX.Y.Z^{}`) in the
   submitted copy only; the in-repo descriptor keeps tags because it cannot name the commit
   that contains it. The community repository builds every descriptor PR against its current
   DuckDB 2.0 engine (the commit it pins as `v2.0.0`) with its own
   `extension-ci-tools` revision; a failure there is first a question about that engine, then
   about the source. `compatibility.yml` pins the same engine and tools revision.
2. State that new GitHub assets target DuckDB 2.0.0, while published v0.4.3 assets target
   1.5.6. The community repository builds 2.0 from `repo.ref`; its 1.5 binaries stay at
   `repo.variegata` until maintainers explicitly rebuild them. Link compatibility validation
   and the retained 1.5 source-support deadline of 2027-03-01.
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

Using the DuckDB 2.0 engine the community repository deployed for (`v2.0.0`) with normal
signature verification and a fresh extension directory, verify
installation, loading, and the descriptor's hello-world queries:

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
