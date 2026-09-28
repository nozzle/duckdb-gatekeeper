# 0.4.1 dependency and compatibility review

Reviewed 2026-09-28. The release moves to DuckDB 1.5.6 (`069cc9f9b5be802405797faecc284961b07c70ef`)
and extension-ci-tools `3fd6109fc01555673b7c7123eba8d0d143fe8ce4` (all three references).
The newer 2.0 compatibility snapshot is `d591bb1da2de3cb12329c75aff2c31bebe922b59`.
The independent wheel-matched Quack/deep-suite candidate remains `d4e72566aa`; historical
inventory captures, classifications, default identities, and source reviews are unchanged.
The 1.5.6 runtime drift report has no added names or changed signatures; five ICU collation
names (`icu_collate_fy`, `icu_collate_lij`, `icu_collate_nso`, `icu_collate_st`, `icu_collate_tn`)
are absent from this Python runtime relative to the historical baseline. All 919 compiled
default identities are preserved; no grants are generated from this report.

## Dependency pass

- Python tooling remains at current stable CMake 4.4.3, Ninja 1.13.2, pytest 9.1.1,
  clang-format 23.1.1 and jsonschema 4.26.0. Boto3 moves to 1.43.103; all three universal
  hash locks are regenerated. The fuzz image installs that same engine/tooling lock.
- Direct Actions remain current: checkout 7.0.1, setup-python 7.0.0, setup-node 7.0.0,
  upload-artifact 7.0.1, download-artifact 8.0.1 and ccache-action 1.2.24. The R setup
  pin is retained with the disabled R host job. Reusable workflow internals remain
  controlled by the coordinated extension-ci-tools pin.
- Ubuntu 26.04 fuzz base moves to digest `da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78`.
  CI explicitly rebuilds the image and runs its native fuzz target. The musl CLI host
  moves to Alpine 3.24, digest `294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6`.
  RustFS 1.0.0 and the Iceberg REST fixture registry digests still match the existing pins.
- esbuild 0.28.2 and Playwright 1.63.0 remain current. No published DuckDB-Wasm runtime
  embeds 1.5.6: `1.33.1-dev64.0` still embeds 1.5.5. CRAN R likewise remains at 1.5.5.
  EH and MinGW are explicitly excluded from 0.4.1 packaging/descriptor/distribution, with
  host jobs retained but disabled. Their npm/Emscripten and CRAN/R pins are intentionally
  deferred until compatible official hosts exist, not relabeled as 1.5.6 validation.

## Compatibility checks

The current 2.0 engine replaced table-function named-parameter maps with signature-based
typed keyword arguments. The adapter selects that API when available and retains the
old map on 1.5 and the older wheel-matched 2.0 snapshot. Optional options must stay absent
when omitted, retain ANY values, and reject unknown/duplicate options. Newer 2.0 rejects
duplicates itself before Gatekeeper's callback; the portable SQL assertion accepts both
precise diagnostics.

The 1.5.6 full PEG diagnostic suite retains the prior phase/position expectations. The
recursive PEG matcher remains in 1.5.6; its deep-nesting crash exclusions and the guidance
against enabling that override for untrusted SQL remain. PRAGMA preprocessing/audit-forgery
expected failures likewise remain. The historical source-tooling tests use a separate 1.5.5
checkout, rather than rewriting provenance to the new build engine.

Release gating requires the full Python suite under both release parsers, the wheel-matched
2.0 suite, current 2.0 SQL/native probes and loadable guard, runtime inventory drift report,
formatting, lakehouse/Quack integration, sanitizer/native+linked fuzz, and eight-platform
native distribution. Re-enable EH/R checks as part of restoring those platforms.
