# Quack authorization scope

Gatekeeper evidence (`objects`, `caller_objects`, `functions`, and the same audit fields)
describes the **checked local binding**, not recursively complete remote lineage. There is
no allow-remote override and no evidence-completeness field. Decisions and audit evidence are
host-only; they may disclose trusted definitions and must not be forwarded to untrusted callers.

## Support matrix

| Route | DuckDB 1.5.5 / Quack c154811 | DuckDB 2.0 / Quack fa3f82c + engine patches |
| --- | --- | --- |
| Attached base table | Explicit refusal | Local-binding route, with `remote_pushdown` disabled and table bind identity present |
| Local trusted view over attached base table | Explicit refusal | Same requirements; view is caller object, attached table is local dependency evidence |
| Caller-written `quack_query`, `quack_query_by_name`, `.query()` in submitted SQL | Never-bind refusal, even if granted | Same |
| Remote view or trusted body containing remote SQL | Private validation/nonparameterized submission refuses before transmission; deferred bind is unsupported (see below) | Same |
| Native Prepare with constant opaque remote SQL | Unsupported: preparation may transmit before any text hook | Text gate refuses caller-written delegation |
| Parameterized native handle with caller-written remote function and unresolved SQL argument | Execution refuses before transmission | Same |
| Whole-query / partial SQL pushdown | Feature absent | Refused before planning when any remote-capable catalog is attached and remote pushdown is enabled |
| CONNECT | Feature absent | Unsupported local enforcement deployment; see #106's pre-callback boundary |
| Server-created connections | No automatic enforcement | No automatic enforcement |
| Log-only | Records refusals, permits execution | Same except CONNECT/DISCONNECT remain refused to preserve local routing |

The pushdown refusal is deliberately conservative and database-wide: even a local-looking
query can contain a remote subquery or resolve through a remote search path. A host can set
`SET disabled_optimizers='remote_pushdown'` before enforcement (preserve other disabled
optimizers when configuring an existing host). Gatekeeper does not silently change it.

### Why these boundaries exist

* Quack `PREPARE_REQUEST` executes SQL, rather than merely describing it. Its explicit query
  functions send that request **during bind**. Even `EXPLAIN` can execute remotely.
* The engine's pre-bind `RemotePushdownOptimizer` rewrites whole queries and subqueries into
  `quack_query_by_name`. The resulting operator is an ordinary `LogicalGet`; post-bind
  operator allowlisting or divergence detection alone is too late.
* Both Quack SQL functions are on the caller's never-bind list, like `query`/`query_table`.
  Qualified grants cannot override that refusal. Private catalog authorization additionally
  refuses opaque Quack functions and remote views reached through trusted definitions.
  Never-bind is separate from `blocked_functions`: an empty block list does not admit delegation.
  Ordinary caller-function blocks use qualified rules, for example
  `blocked_functions := [{catalog:'system', schema_path:['main'], name:'md5', type:'scalar'}]`.
  A matching block wins over a grant and cannot be cleared by request options; it does not
  reach inside a trusted local view. The independent remote-scope refusal still applies to
  that view's Quack dependencies. See [qualified function rules](qualified-functions.md).
* **Deferred trusted-body binding is unsupported.** For example, a host view containing
  `quack_query_by_name(...)`, a remote view, or the attachment's `.query()` macro can execute
  remotely when a parameterized statement binds it before Gatekeeper's private check. The final
  Permission Error does not undo that execution. The fixture proves the residual with server
  request logs and sequence increments. It is the same bind-time trust limitation as dynamic
  `query()` inside host definitions: hosts must not expose opaque remote SQL through those
  definitions and must not treat a later denial as proof of zero I/O.
* DuckDB 1.5 native Prepare has no QueryBegin text gate. Preparing constant remote SQL can
  transmit even though executing the handle is refused. Use submitted SQL/text preflight for
  untrusted text; do not expose this raw preparation route as a protected remote API.
* Gatekeeper does not control the host's extension loading lifecycle or wrap extension bind
  callbacks. Unrelated extensions can load before Gatekeeper or after enforcement on a host
  connection. Opaque delegation remains unsupported rather than broadening the sandbox to
  manage all extension loads.
* The 1.5 pin sends only a base table's leaf name, discarding schema qualification, and exposes
  no `get_bind_info` table identity. The executable schema-collision regression demonstrates a
  read of `other.orders` returning `main.orders`. All its Quack objects are therefore refused
  by authorization, even inside a trusted local view.
* The 2.0 pin retains qualified names and table bind info. Its base-table scan transmits at
  scan initialization. Opaque external Quack `LogicalGet`s without a table identity are
  refused as a backstop. This does not expose the server's internal dependencies or guarantee
  stable server definitions: the host owns the remote schema, attachment snapshot, and any
  server authorization callback that can rewrite SQL.
* `ClientContext::SubmitStatement` calls CONNECT's `RemoteExecute` **before QueryBegin**.
  Local statement checks do not turn that generic callback into an authorized boundary.
  Do not CONNECT an enforced connection via native host APIs, nor try to activate local
  enforcement by sending `CALL gatekeeper_enforce()` while CONNECT-ed: it may install on
  the server instead. #106 owns the engine-routing/native-host restrictions.

## Server policy and sessions

The listener creates a fresh DuckDB `Connection` for each logical session. Loading Gatekeeper,
configuring its global ceiling, or enforcing the listener's control connection does not enforce
those new connections. The fixture verifies this and verifies **explicit** installation by
issuing `CALL gatekeeper_enforce()` through one attachment. A second attachment remains
unenforced. That experiment is not an automatic installation API or a deployment recommendation.

An attachment retains its session across calls and named-attachment DISCONNECT/CONNECT.
Local cursors sharing an attachment can share that remote session. Authentication/authorization
callbacks use separate temporary connections. `OnConnectionOpened` exists upstream but runs
before Quack installs its session marker and under a connection-manager lock; no automatic
Gatekeeper installation mechanism has been verified. The 1.5 protocol also has an Append path
outside SQL query hooks. Server-side enforcement of the entire protocol remains unsupported.

## Running the disposable fixture

Build Gatekeeper normally, then:

```sh
.venv/bin/python scripts/test_quack.py
```

The runner downloads **hash-verified** Quack and httpfs 1.5.5 core artifacts into ignored
`build/quack-artifacts`. Supported download platforms are Linux AMD64/ARM64 and macOS ARM64.
It uses separate in-memory client/server databases and a loopback listener, a random token,
bounded readiness polling, explicit LOAD paths, no autoinstall/autoload, and finally cleanup.
No Docker or extra Python dependencies are required. The release pin reserves then releases
a candidate port before binding; a race fails setup rather than connecting to a foreign server.

Server-side `Quack` logs prove whether a PREPARE request arrived. A sequence-backed remote
view proves execution independently of transactional rollback. Setup/metadata requests are
excluded by an explicit observation baseline. Held C API prepared handles use the same engine
library as the Python host, testing preparation separately from execution and policy changes.
The runner fails on a bad download checksum or missing/incompatible explicit artifact. Tests
include successful host extension loads, pre-transmission refusals, and positive demonstrations
of the unsupported deferred-bind residual. A passing suite does not mean those residuals are protected.

```sh
GATEKEEPER_EXTENSION=/absolute/gatekeeper.duckdb_extension \
  /path/to/matched-python/bin/python scripts/test_quack.py \
  --quack /absolute/quack.duckdb_extension \
  --httpfs /absolute/httpfs.duckdb_extension
```

For a custom candidate build, supply both explicit paths as above. For the exact pinned
candidate, use `--candidate` instead: the runner downloads and verifies its pinned artifacts
and rejects explicit paths. Gatekeeper and both extensions must match that Python engine.
A 1.5.5 Python package cannot test 2.0 binaries. The 1.5 Quack protocol is
version 1, while the 2.0 pin is version 3; build both sides from the same set.

### Reproducible source pins / candidate co-build

| Component | Release fixture | Inspected candidate |
| --- | --- | --- |
| DuckDB | `d8cdaa33fda8df955cc76ef58a280f68f4cd43fa` | `d4e72566aa8dcb35fc727e2a5ced8e9a2f6d8143` |
| Quack | `c1548111c1bfd16207e22fd3cb7e4bde1335b9d0` | `fa3f82c53cf587838d55efbd24f31b0c055684a9` |
| httpfs | `827222fb45a043a7a852d1f7aae46901492a3cda` | `0507d4ae4914ef30be5952bda0a547aa2b7ca981` |

The engine's `.github/config/extensions/{quack,httpfs}.cmake` descriptors are the authority:
use their `APPLY_PATCHES`, not Quack's own different bundled engine/httpfs pins. Candidate
patches cover table columns, binder include, literal constants, QueryResult, and nested-name
tests. The current compatibility workflow pins a different 2.0 snapshot (`6844d1bd…`); use
each snapshot's own patch set. No engine pin in Gatekeeper is changed for this fixture.

With OpenSSL/curl development dependencies available, an isolated co-build is:

```sh
cmake -G Ninja -S /path/to/pinned-engine -B build/quack-candidate \
  -DCMAKE_BUILD_TYPE=Release -DOVERRIDE_GIT_DESCRIBE= \
  -DDUCKDB_EXTENSION_CONFIGS="$PWD/extension_config.cmake" \
  '-DBUILD_EXTENSIONS=quack;httpfs;json;autocomplete' \
  -DBUILD_SHELL=ON -DBUILD_UNITTESTS=ON -DENABLE_UNITTEST_CPP_TESTS=OFF \
  -DUNITTEST_ROOT_DIRECTORY="$PWD" -DGATEKEEPER_NATIVE_PROBES=ON
cmake --build build/quack-candidate --parallel 4 --target shell unittest \
  gatekeeper_loadable_extension quack_loadable_extension httpfs_loadable_extension
```

For release source builds, use the release engine and `-DOVERRIDE_GIT_DESCRIBE=v1.5.5`.
Keep candidate directories separate from existing builds. Follow CONTRIBUTING's exact-engine
Python-wheel procedure before running the candidate fixture. Merely co-building the CLI does
not provide a matching Python package.

## Validation and remaining limits

The implementation was exercised against real macOS ARM64 1.5.5 **and 2.0** artifacts, using
separate isolated Gatekeeper builds. The candidate Python package was `2.0.0.dev2609221243`,
whose `PRAGMA version` is `v2.0.0-alpha42986`, source `d4e72566aa`; build Gatekeeper with that
exact explicit version label when testing in this wheel. The verified candidate downloads were:

```text
https://extensions.duckdb.org/v2.0.0-alpha42986/osx_arm64/quack.duckdb_extension.gz
SHA256 f6a675a4a129d16d3ba1f34961c785bca7bb0f9c00fccd06b6fb29b837a0bfc1
https://extensions.duckdb.org/v2.0.0-alpha42986/osx_arm64/httpfs.duckdb_extension.gz
SHA256 40e01cc8ccae5f6cd822907c6d6ceaff53dc5f65a85191d1191fe1bd4f9dbe20
```

The footers identify `fa3f82c53c` and `0507d4ae49` respectively, matching the source pins.
Verify compressed bytes before decompression and supply the explicit paths above; automatic
downloads default to the supported 1.5.5 release. `--candidate` selects this exact candidate
on Linux AMD64 or macOS ARM64, checks the Python version and engine source ID, and fails if
any selected test skips. Both platform/version URLs can change,
so the checksum, not the URL alone, is the artifact pin. Candidate errors can surface while
fetching results; server-denial tests drain the result before asserting the error.
The dedicated `Quack candidate integration` workflow pins the Linux CPython 3.13 wheel by
SHA256, checks out the exact engine commit, builds Gatekeeper, downloads the
hash-pinned matching protocol-3 extensions, and executes the entire suite with zero skips.
Existing compatibility and release pins are unchanged. Release tests skip full/partial pushdown
and CONNECT only on 1.5, where those features do not exist.
The candidate test executes positive transport controls before checking refusals.

Quack currently disables scan-level filter pushdown and rejects multiple streaming scans of
one session. Disabling SQL pushdown can therefore make some joins unsupported. Its catalog is
a snapshot; remote mutation requires refresh/reattach. The fixture records observable requests
and execution, not a complete trace of every upstream native hook. #106's native callback
counter probe and the engine's source ordering remain necessary for pre-RemoteExecute claims.

Sources:
* [Quack source](https://github.com/duckdb/duckdb-quack), especially pinned `quack_scan.cpp`,
  `quack_server.cpp`, `storage/quack_table.cpp`, `storage/quack_view.cpp`, `storage/quack_catalog.cpp`.
* [Remote pushdown upstream design](https://github.com/duckdb/duckdb/pull/22914).
* [Current upstream overview](https://duckdb.org/docs/current/quack/overview). Quack's older
  `docs/usage.md` has stale `rpc_*` names; the fixture uses the pinned source's `Quack` log and `/quack` route.
