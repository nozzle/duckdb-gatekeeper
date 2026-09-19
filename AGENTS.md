# Dependency maintenance

Dependabot checks routine GitHub Actions and Python dependency updates monthly. Our reproducible DuckDB build pins are updated manually; they are not a source compatibility allowlist.

Whenever bumping the supported DuckDB version:

- Follow the one repinning procedure in [inventories/README.md](inventories/README.md#repinning-the-engine): it lists every pin that moves together (submodule, `versions.cmake`, Python package and lock files, fuzz image, Wasm runtime and Emscripten, `extension-ci-tools`) and what reads each. Keep source revisions, action SHAs, and container digests pinned; do not replace them with floating references.
- In the same pass, review GitHub Actions, Python tooling and integration requirements, and container base/fixture images for current stable compatible releases, major upgrades included where compatible; record deferred updates and their reasons in the PR. Lock files are regenerated as [CONTRIBUTING.md](CONTRIBUTING.md#dependencies) describes.
- Follow [inventories/AGENTS.md](inventories/AGENTS.md) when changing defaults. Existing function implementations are trusted across engine upgrades; repeat source review and inventory reclassification are not upgrade prerequisites. Inventory drift is a maintenance report. Do not regenerate an allowlist from runtime discovery or overwrite historical provenance merely to match a build version.
- Rebuild the extension and run the full test suite, inventory audit, formatting checks, lakehouse integration tests, native/linked SQL fuzz smoke tests, and the EH browser tests. Exercise changed Actions on CI and rebuild changed container images. Include required formatting changes from formatter upgrades.
- Update installation, compatibility, and maintenance documentation for any changed requirements, and summarize dependency updates and validation results in the PR.

Keep DuckDB excluded from routine Dependabot updates so its package and source pins cannot drift independently.
