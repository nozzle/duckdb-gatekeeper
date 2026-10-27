# Wasm EH support and browser tests

**Wasm EH source-build browser CI is enabled. Release distribution is still deferred.**
The pinned `@duckdb/duckdb-wasm@1.33.1-dev110.0` runtime embeds the same source as DuckDB
2.0.0 (`d54cbbe3df17e8e5ce68312f483b4155836112aa`), but reports **`v2.0.0-dev88614`**.
It cannot load a release-labeled `v2.0.0` extension. `runtime.json` records the observed
host identity, and `build_wasm.py` builds for that exact label and revision. The browser
asserts both; neither engine footer checks nor Gatekeeper's load-time guard are bypassed.

The runtime now calls its single-threaded **EH (native WebAssembly exception handling)**
bundle `base`, with `duckdb-base.wasm` and `duckdb-browser-base.worker.js`. Its npm version
is independent of the embedded engine. Historical Gatekeeper v0.4.0 Wasm assets still
match DuckDB 1.5.5 and `@duckdb/duckdb-wasm@1.33.1-dev64.0`.

## Build and test locally

Requires Docker, Python 3.11+, Node.js 22+, and initialized repository submodules.
From the current checkout:

```sh
python3 scripts/build_wasm.py --jobs 4
npm ci --ignore-scripts --prefix test/wasm
```

Then from `test/wasm`:

```sh
npx playwright install --with-deps chromium
npm test
```

`build_wasm.py` uses a digest-pinned Emscripten 6.0.9 image (linux/amd64, also
usable through Docker emulation on Apple Silicon). It builds the EH side module
at `build/wasm_eh/extension/gatekeeper/gatekeeper.duckdb_extension.wasm`.
`GATEKEEPER_WASM_EXTENSION=/absolute/path/to/artifact.wasm npm test` tests an
alternative artifact for the same runtime identity. The native distribution workflow's
release-labeled Wasm artifact remains excluded until a matching official host is available.

The smoke test starts a localhost server and an actual Chromium worker. It fails
on assertions, unexpected page errors, or a 90-second timeout. Requests outside
the local origin are blocked. Coverage includes binding errors, view dependency
identities, prepared parameters, policy ceilings, narrowing, shared configuration,
atomic replacement, reset/readback, an enforced connection with its audit records and
log-only mode, and configuration locking. This supplements the native suite; it does
not exercise browser lakehouse integrations or all browser engines.

## Load in an application

Serve the extension over HTTP(S) with `Content-Type: application/wasm`, alongside
the matching DuckDB-Wasm assets. Preserve the leaf filename
`gatekeeper.duckdb_extension.wasm`: DuckDB derives the C++ entrypoint name from it.
Use same-origin assets or configure CORS. Choose the **base/EH** worker explicitly;
automatic bundle selection may choose an unsupported target.

```js
import * as duckdb from '@duckdb/duckdb-wasm';

const worker = new Worker('/duckdb/duckdb-browser-base.worker.js');
const db = new duckdb.AsyncDuckDB(new duckdb.ConsoleLogger(), worker);
await db.instantiate('/duckdb/duckdb-base.wasm');
// Current CI artifacts are unsigned development builds.
await db.open({ allowUnsignedExtensions: true });
const conn = await db.connect();
await conn.query(`LOAD '${location.origin}/extensions/gatekeeper.duckdb_extension.wasm'`);
await conn.query('CREATE TABLE orders(id INTEGER)');
await conn.query(`CALL gatekeeper_configure(
  allowed_tables := [{catalog: 'memory', schema_path: ['main'], 'table': 'orders'}]
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

- **MVP:** the 2.0 runtime requires Wasm exception handling and publishes no MVP bundle.
  The historical 1.5 MVP host also failed exception paths (`_setThrew is not defined`).
- **Threads/COI:** excluded because the toolchain's `wasm_threads` artifacts cannot load. The
  `wasm_threads` target in `extension-ci-tools` never passes `-DUSE_WASM_THREADS=1`, so the side
  module is linked without `-pthread -sSHARED_MEMORY=1` and the threaded main module rejects
  its memory import (`LinkError: mismatch in shared state of memory`). This is
  [extension-ci-tools#391](https://github.com/duckdb/extension-ci-tools/issues/391), still present
  in the pinned toolchain, and it affects DuckDB's own core extensions
  ([duckdb-wasm#2041](https://github.com/duckdb/duckdb-wasm/issues/2041)), so no COI deployment
  can load extensions today. The exit condition, and the COI browser test to add when it is
  met, are in [#101](https://github.com/nozzle/duckdb-gatekeeper/issues/101).

## Maintenance

When repinning DuckDB, coordinate the npm runtime/lock, `runtime.json`, this documentation,
and Emscripten with `extension-ci-tools`. `smoke.mjs` holds the Wasm source revision to
`versions.cmake` and separately checks the exact runtime label. DuckDB-Wasm is excluded from
routine Dependabot updates; other npm test dependencies receive monthly updates.
The standalone browser job tests the matched development host. Restore stable Wasm distribution,
its distribution-artifact browser test, packaging dependency and descriptor entry together only
after an official release-labeled runtime passes. Windows MinGW has its matching CRAN 2.0.0 host
and is restored independently.
