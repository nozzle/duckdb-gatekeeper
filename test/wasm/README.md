# Wasm EH support and browser tests

Gatekeeper supports the **EH (native WebAssembly exception handling)** bundle of
DuckDB-Wasm with embedded **DuckDB 1.5.5**. The tested npm package is
`@duckdb/duckdb-wasm@1.33.1-dev64.0`; its package version is independent of the
engine version. Pin this package and verify its embedded engine; do not bypass engine
metadata/version checks.

## Build and test locally

Requires Docker, Python 3.10+, Node.js 22+, and initialized repository submodules.
From the repository root:

```sh
python3 scripts/build_wasm.py --jobs 4
npm ci --ignore-scripts --prefix test/wasm
```

Then from `test/wasm`:

```sh
npx playwright install --with-deps chromium
npm test
```

`build_wasm.py` uses a digest-pinned Emscripten 3.1.71 image (linux/amd64, also
usable through Docker emulation on Apple Silicon). It builds the EH side module
at `build/wasm_eh/extension/gatekeeper/gatekeeper.duckdb_extension.wasm`.
`GATEKEEPER_WASM_EXTENSION=/absolute/path/to/artifact.wasm npm test` tests an
alternative artifact, including one produced by the distribution pipeline.

The smoke test starts a localhost server and an actual Chromium worker. It fails
on assertions, unexpected page errors, or a 90-second timeout. Requests outside
the local origin are blocked. Coverage includes binding errors, view dependency
identities, prepared parameters, policy ceilings, narrowing, shared configuration,
atomic replacement, reset/readback, and configuration locking. This supplements
the native suite; it does not exercise browser lakehouse integrations or all
browser engines.

## Load in an application

Serve the extension over HTTP(S) with `Content-Type: application/wasm`, alongside
the matching DuckDB-Wasm assets. Preserve the leaf filename
`gatekeeper.duckdb_extension.wasm`: DuckDB derives the C++ entrypoint name from it.
Use same-origin assets or configure CORS. Choose the **EH** worker explicitly;
automatic bundle selection may choose an unsupported target.

```js
import * as duckdb from '@duckdb/duckdb-wasm';

const worker = new Worker('/duckdb/duckdb-browser-eh.worker.js');
const db = new duckdb.AsyncDuckDB(new duckdb.ConsoleLogger(), worker);
await db.instantiate('/duckdb/duckdb-eh.wasm');
// Current CI artifacts are unsigned development builds.
await db.open({ allowUnsignedExtensions: true });
const conn = await db.connect();
await conn.query(`LOAD '${location.origin}/extensions/gatekeeper.duckdb_extension.wasm'`);
await conn.query('CREATE TABLE orders(id INTEGER)');
await conn.query(`CALL gatekeeper_configure(
  allowed_tables := [{catalog: 'memory', schema: 'main', 'table': 'orders'}]
)`);
await conn.query('SET lock_configuration = true');
const check = await conn.prepare('SELECT * FROM gatekeeper_validate(?)');
const result = (await check.query('SELECT * FROM orders')).toArray()[0];
console.log(result.allowed, result.code);
await check.close();
await conn.close();
await db.terminate();
```

Use native Arrow result columns, including nested lists of STRUCTs; Gatekeeper does
not require loading the SQL JSON extension. The runtime supplies the yyjson imports used by Gatekeeper's internal
AST serialization. That linkage is exercised by the browser test, not inferred
from compilation alone.

Configure trusted catalog objects, host security settings, and policy before
locking, as described in the main security documentation. Browser validation is
useful for local policy checks but cannot enforce authorization on a server
against a user who controls their browser.

## Excluded targets

- **MVP:** builds/loads, but the tested runtime throws `_setThrew is not defined`
  on a missing-table error even without Gatekeeper. Exception paths cannot be
  supported until the runtime is fixed and regression-tested.
- **Threads/COI:** excluded because loader recovery after an engine error and the
  distribution toolchain's thread/shared-memory flags are not verified. Supporting
  it requires repeatable load/error/recovery tests with the actual distribution artifact.

## Maintenance

When repinning DuckDB, coordinate the npm runtime pin and lockfile, the embedded
version assertion in `smoke.mjs`, this documentation, and Emscripten compatibility
with `extension-ci-tools`. DuckDB-Wasm is excluded from routine Dependabot updates.
Other npm test dependencies receive monthly updates. Browser CI builds and tests
EH on every PR; the distribution workflow also builds the standard `wasm_eh`
artifact through the community tooling, downloads that exact artifact, and runs
the same browser checks against it.
