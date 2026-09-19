# Dependency maintenance

Dependabot checks routine GitHub Actions and Python dependency updates monthly. Our reproducible DuckDB build pins are updated manually; they are not a source compatibility allowlist.

Whenever bumping the supported DuckDB version:

- Review and update GitHub Actions, Python tooling and integration requirements, `extension-ci-tools`, and container base/fixture images to current stable compatible releases. Include major upgrades where compatible; record any deferred updates and their reasons in the PR.
- Update the `duckdb` submodule, Python package pin, release build metadata, fuzz image, and other build-engine references together, following [inventories/README.md](inventories/README.md#repinning-the-engine). Keep source revisions, action SHAs, and container digests pinned; do not replace them with floating references. Community rebuilds may use another engine checkout; generate against that source and rely on DuckDB's binary compatibility checks plus Gatekeeper's load-time build-engine guard, which is stamped from the build tree rather than a hardcoded release.
- Coordinate the DuckDB-Wasm runtime and npm lock in `test/wasm` and the Emscripten pin in `scripts/build_wasm.py`; run the EH browser tests, which assert the runtime's embedded engine against the pin in `versions.cmake`. The npm package version differs from its embedded engine version.
- Python requirements are edited in `requirements*.in` and locked with hashes into `requirements*.txt` via `uv pip compile --universal --generate-hashes --python-version 3.10 -o <name>.txt <name>.in`; regenerate the lock files whenever an `.in` file changes.
- Follow [inventories/AGENTS.md](inventories/AGENTS.md) when changing defaults. Existing function implementations are trusted across engine upgrades; repeat source review and inventory reclassification are not upgrade prerequisites. Inventory drift is a maintenance report. Do not regenerate an allowlist from runtime discovery or overwrite historical provenance merely to match a build version.
- Rebuild the extension and run the full test suite, inventory audit, formatting checks, lakehouse integration tests, and native/linked SQL fuzz smoke tests. Exercise changed Actions on CI and rebuild changed container images. Include required formatting changes from formatter upgrades.
- Update installation, compatibility, and maintenance documentation for any changed requirements, and summarize dependency updates and validation results in the PR.

Keep DuckDB excluded from routine Dependabot updates so its package and source pins cannot drift independently.
