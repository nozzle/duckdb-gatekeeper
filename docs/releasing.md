# Releases and community publication

Gatekeeper's GitHub Releases and DuckDB community publication are separate steps.
The local [community descriptor](../community/description.yml) is prepared for the
first release; it is not evidence of publication. Its `v0.1.0` ref must exist and
pass CI before submission.

## Prepare the release commit

1. Keep the extension version in `extension_config.cmake`, `GatekeeperExtension::Version()`
   and its load-error message in `src/gatekeeper_extension.cpp`, and the community
   descriptor aligned. Update the release packaging tests when changing version pins.
   DuckDB upgrades additionally require the full [repinning checklist](../inventories/README.md#repinning-the-engine).
2. Run the [contributor checks](../CONTRIBUTING.md#testing). Land the release preparation
   changes and verify the intended `main` commit's CI, including inventory audit,
   sanitizers, lakehouse integration, native fuzz smoke, and distribution builds.
3. Require the full distribution matrix: Linux amd64/arm64 glibc and musl, macOS
   amd64/arm64, Windows amd64 MSVC/MinGW and ARM64 MSVC, and Wasm EH. Windows ARM64
   is newly opted in and must pass its native build and sqllogictests before support
   is advertised. Wasm EH must pass the browser test of the actual distribution artifact.
   If a target is deferred, keep the workflow, `scripts/package_release.py`, packaging
   tests, and community descriptor aligned and document the reason.
4. Leave the README and security doc's pending-publication statements in place until
   the community build has actually deployed. Source loading stays in CONTRIBUTING.

## Tag and publish GitHub assets

After checking out the validated release commit with a clean worktree, a maintainer runs:

```sh
git tag -a v0.1.0 -m "Gatekeeper v0.1.0"
git push origin v0.1.0
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
the tag-only publish job can run, including the version in the load-time error message.
It also checks `community/description.yml`'s `extension.version` and `repo.ref`, and
the C++ engine pin against `scripts/versions.py`. The descriptor must also cite the
pinned DuckDB version and source revision in its compatibility description.
Keep the descriptor's version/ref
as unquoted scalars with two-space indentation; the standard-library-only packaging
check deliberately rejects changes to that local format.

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

## Submit the community descriptor manually

1. Check the tag workflow and GitHub Release assets. Copy
   `community/description.yml` into `extensions/gatekeeper/description.yml` in a checkout
   of [duckdb/community-extensions](https://github.com/duckdb/community-extensions).
   Recheck its current descriptor conventions before submission. The prepared descriptor
   pins a version tag; never replace it with a floating branch ref.
2. Include the exact-engine restriction prominently in the PR: configure rejects any
   other source revision and load rejects any other DuckDB release. New DuckDB patch
   and minor releases require reviewed repins and a new descriptor ref; bulk rebuilds
   may fail and installation on newer engines may be unavailable until then.
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

Expect `true` and `unsupported`. Then remove the pending-publication qualifications
in `README.md` and `docs/security.md`, leaving the distinction between signed community
builds and unsigned local/GitHub builds intact. Run `test/test_documentation.py` after
the edit. It exercises local README examples; the community-install smoke check above
is a separate deployment verification.

Monitor DuckDB releases and perform the coordinated repin for each supported patch
or minor release. Do not relax the source or engine checks to make a bulk build pass.
