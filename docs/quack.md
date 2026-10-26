# Quack authorization scope

Gatekeeper evidence (`objects`, `caller_objects`, `functions`, `caller_functions`, and the same audit fields)
describes the **checked local binding**, not recursively complete remote lineage. There is
no allow-remote override and no evidence-completeness field. Decisions and audit evidence are
host-only; they may disclose trusted definitions and must not be forwarded to untrusted callers.
Resolved remote-object refusals retain `object_type` (`table` or `view`), and resolved
opaque-function refusals retain `function_type`, alongside their exact catalog/schema/name
in validation and audit violations. The other kind field is empty; success-only evidence
lists remain empty on denial. These identities describe the local entry, not server lineage.

Trusted definitions retain their general table/function allowlist, block, and caller never-bind
exemptions. Those exemptions do not expand the **supported execution scope** or bypass
Gatekeeper's control-plane restrictions. The private catalog callback checks unsupported Quack
scope regardless of caller attribution, so allowing a view or macro cannot admit opaque remote
delegation. That private check is not an interception point for an earlier engine bind: deferred
trusted-body binding can already have executed remotely when the refusal arrives.
See [trusted expansion](security.md#function-enforcement-and-trusted-expansion) for the origin rules.

## Support matrix

| Route | DuckDB 1.5.6 / Quack 7e80f7f | DuckDB 2.0.0 / Quack f96420e |
| --- | --- | --- |
| Attached base table | Explicit refusal | Local-binding route, with `remote_pushdown` disabled and table bind identity present |
| Local trusted view over attached base table | Explicit refusal | Same requirements; view is caller object, attached table is local dependency evidence |
| Caller-written `quack_query`, `quack_query_by_name`, `.query()` in submitted SQL | Never-bind refusal, even if granted | Same |
| Remote view or trusted body containing remote SQL, when reached by private validation/nonparameterized submission | Private catalog callback refuses unsupported scope before transmission, regardless of caller attribution | Same |
| Deferred binding of a remote view or trusted body containing remote SQL | Unsupported: engine binding can execute remotely before the private callback's later refusal | Same |
| Native Prepare with constant opaque remote SQL | Unsupported: preparation may transmit before any text hook | Text gate refuses caller-written delegation |
| Parameterized native handle with caller-written remote function and unresolved SQL argument | Execution refuses before transmission | Same |
| Whole-query / partial SQL pushdown | Feature absent | Refused before planning when any remote-capable catalog is attached and remote pushdown is enabled |
| CONNECT | Feature absent | Unsupported local enforcement deployment; see [the pre-callback boundary](security.md#connect-mode-and-native-host-state) |
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
  reach inside a trusted local view. The independent remote-scope check still applies to
  that view's Quack dependencies: it refuses opaque delegation and remote views on both engines,
  and all attached Quack objects on 1.5. A trusted local view over a 2.0 base table can use the
  supported local-binding route in the matrix. See [qualified function rules](qualified-functions.md).
  Grants and blocks match exact entry names, including aliases: a `read_parquet` grant does
  not authorize `parquet_scan`, or vice versa. Held prepared handles are reauthorized against
  the current policy. Internal entries require exact schema components for explicit grants;
  the actual entry metadata determines this, not the extension's namespace.
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

The runner downloads **hash-verified** Quack and httpfs 2.0.0 or retained 1.5.6 core artifacts into ignored
`build/quack-artifacts`. Supported download platforms are Linux AMD64/ARM64 and macOS ARM64.
It uses separate in-memory client/server databases and a loopback listener, a random token,
explicit LOAD paths, no autoinstall/autoload, and finally cleanup. Readiness requires a successful
synchronous server bind, then a Quack query reading a per-fixture random marker stored only on that server.
No Docker or extra Python dependencies are required. The 1.5 pin reserves then releases
a candidate port before binding; bind failures retry up to five candidates and then fail setup,
without probing or attaching to the competing listener. The 2.0 pin binds port `0` directly
and returns the OS-allocated endpoint. Arbitrary HTTP responses are never accepted as readiness.

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

For a custom candidate build, supply both explicit paths as above. Automatic downloads verify
both the Python version and the engine source ID for the two supported releases. Gatekeeper
and both extensions must match that host; a 1.5 Python package cannot test 2.0 binaries.
Build both client and server from the same engine/protocol set. The 2.0 fixture requires zero skips.

### Reproducible source pins / candidate co-build

| Component | Primary 2.0 fixture | Retained 1.5 fixture |
| --- | --- | --- |
| DuckDB | `d54cbbe3df17e8e5ce68312f483b4155836112aa` | `069cc9f9b5be802405797faecc284961b07c70ef` |
| Quack | `f96420ed46aee9c42064bdb99ddfd1230d6c0086` | `7e80f7ffcc98d0b3e81d0e1df8cc1c2da240a64b` |
| httpfs | `77392a72077a85897db2519fae11e2c0da972b8a` | `4bc690dba4496c765777a0269d48fdbaff7cdc11` |

These release pins match their engine descriptors and the downloaded artifact footers;
compressed SHA256 values for all three supported platforms are in `scripts/test_quack.py`.
The support matrix was established by the original 1.5.5/Quack c154811 investigation. Its historical
DuckDB `d8cdaa33fd`, Quack `c1548111c1`, and httpfs `827222fb45` evidence is preserved;
the 0.4.1 release fixture was rerun on 1.5.6 with the pins above (16 passed, one 2.0-only skip).

The engine's `.github/config/extensions/{quack,httpfs}.cmake` descriptors are the authority:
use their source revisions and any `APPLY_PATCHES`, not Quack's own bundled engine/httpfs pins.
The current fixture follows the coordinated 2.0 release pin; the historical September alpha
required engine patches for table columns, literal constants, QueryResult and nested names.

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

For primary source builds, use the release engine and `-DOVERRIDE_GIT_DESCRIBE=v2.0.0`.
Keep candidate directories separate from existing builds. Follow CONTRIBUTING's exact-engine
Python-wheel procedure before running the candidate fixture. Merely co-building the CLI does
not provide a matching Python package.

## Validation and remaining limits

The released 2.0.0 Python host and matching Gatekeeper/Quack/httpfs loadables pass all 17
transport and authorization tests on macOS ARM64. The primary Linux job runs the same fixture;
the retained 1.5 workflow runs its matching fixture through the extended support window.
Compressed hashes for all three supported platforms are in `scripts/test_quack.py`.

### Historical candidate evidence

The original implementation was exercised against real macOS ARM64 1.5.5 **and 2.0** artifacts,
then rerun for the 0.4.1 release on 1.5.6, using separate isolated Gatekeeper builds.
The candidate Python package was `2.0.0.dev2609221243`,
whose `PRAGMA version` is `v2.0.0-alpha42986`, source `d4e72566aa`; build Gatekeeper with that
exact explicit version label when testing in this wheel. The verified candidate downloads were:

```text
https://extensions.duckdb.org/v2.0.0-alpha42986/osx_arm64/quack.duckdb_extension.gz
SHA256 f6a675a4a129d16d3ba1f34961c785bca7bb0f9c00fccd06b6fb29b837a0bfc1
https://extensions.duckdb.org/v2.0.0-alpha42986/osx_arm64/httpfs.duckdb_extension.gz
SHA256 40e01cc8ccae5f6cd822907c6d6ceaff53dc5f65a85191d1191fe1bd4f9dbe20
```

Those historical footers identify `fa3f82c53c` and `0507d4ae49`. The old `--candidate` runner
and wheel-specific workflow have been replaced by released-2.0 coverage and the retained
1.5 maintenance job. URLs can change, so checksums remain the artifact pins. Tests drain
results before asserting server errors and execute positive transport controls before refusals.
Only 1.5 skips the full/partial pushdown and CONNECT case, since it lacks those features.

### Current limitations

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
