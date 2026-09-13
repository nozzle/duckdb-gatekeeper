# Dependency maintenance

Dependabot checks routine GitHub Actions and Python dependency updates monthly. DuckDB upgrades are coordinated manually, including patch releases.

Whenever bumping the supported DuckDB version:

- Review and update GitHub Actions, Python tooling and integration requirements, `extension-ci-tools`, and container base/fixture images to current stable compatible releases. Include major upgrades where compatible; record any deferred updates and their reasons in the PR.
- Update the `duckdb` submodule, Python package pin, build/version checks, fuzz image, and other engine-version references together, following [inventories/README.md](inventories/README.md#repinning-the-engine). Keep source revisions, action SHAs, and container digests pinned; do not replace them with floating references.
- Python requirements are edited in `requirements*.in` and locked with hashes into `requirements*.txt` via `uv pip compile --universal --generate-hashes --python-version 3.10 -o <name>.txt <name>.in`; regenerate the lock files whenever an `.in` file changes.
- Follow [inventories/AGENTS.md](inventories/AGENTS.md) for source review, signature comparisons, generation, and baseline acceptance. Do not regenerate an allowlist from runtime discovery or overwrite a baseline just to pass an audit.
- Rebuild the extension and run the full test suite, inventory audit, formatting checks, lakehouse integration tests, and native/linked SQL fuzz smoke tests. Exercise changed Actions on CI and rebuild changed container images. Include required formatting changes from formatter upgrades.
- Update installation, compatibility, and maintenance documentation for any changed requirements, and summarize dependency updates and validation results in the PR.

Keep DuckDB excluded from routine Dependabot updates so its package and source pins cannot drift independently.
