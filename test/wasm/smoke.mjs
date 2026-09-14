import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFileSync} from 'node:fs';
import {dirname, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';
import {chromium} from 'playwright';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const dist = resolve(here, 'node_modules/@duckdb/duckdb-wasm/dist');
const artifact = resolve(process.env.GATEKEEPER_WASM_EXTENSION ||
  resolve(root, 'build/wasm_eh/extension/gatekeeper/gatekeeper.duckdb_extension.wasm'));
const bundle = await build({entryPoints: [resolve(dist, 'duckdb-browser.mjs')], bundle: true,
  format: 'esm', write: false});
// An explicit route map keeps the development server from exposing the checkout.
const routes = new Map([
  ['/', ['text/html', '<!doctype html><title>Gatekeeper Wasm tests</title>']],
  ['/duckdb.mjs', ['text/javascript', bundle.outputFiles[0].contents]],
  ['/duckdb-browser-eh.worker.js', ['text/javascript', readFileSync(resolve(dist, 'duckdb-browser-eh.worker.js'))]],
  ['/duckdb-eh.wasm', ['application/wasm', readFileSync(resolve(dist, 'duckdb-eh.wasm'))]],
  ['/gatekeeper.duckdb_extension.wasm', ['application/wasm', readFileSync(artifact)]],
]);
const server = createServer((req, res) => {
  const route = routes.get(req.url);
  if (!route) {res.writeHead(404); res.end(); return;}
  res.setHeader('Content-Type', route[0]);
  res.end(route[1]);
});
await new Promise((resolve, reject) => {server.once('error', reject); server.listen(0, '127.0.0.1', resolve);});
let browser;
// A hung Wasm worker must fail CI rather than wait for the workflow timeout.
const watchdog = setTimeout(() => {console.error('Wasm smoke test timed out after 90 seconds'); process.exit(1);}, 90_000);
try {
  browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const origin = `http://127.0.0.1:${server.address().port}`;
  // Tests are entirely local: accidental extension autoload/network access fails.
  await page.route('**/*', route => route.request().url().startsWith(origin + '/') ? route.continue() : route.abort());
  await page.goto(origin);
  const report = await page.evaluate(async () => {
    const wasm = await import('/duckdb.mjs');
    const worker = new Worker('/duckdb-browser-eh.worker.js');
    const db = new wasm.AsyncDuckDB(new wasm.VoidLogger(), worker);
    let con;
    const passed = [];
    const check = (name, value) => {if (!value) throw Error(name); passed.push(name);};
    try {
      await db.instantiate('/duckdb-eh.wasm');
      await db.open({allowUnsignedExtensions: true});
      con = await db.connect();
      const rows = async sql => (await con.query(sql)).toArray().map(r => r.toJSON());
      const version = (await rows('SELECT version() AS version'))[0].version;
      check('embedded DuckDB version', version === 'v1.5.5');
      await con.query('SET autoload_known_extensions=false; SET autoinstall_known_extensions=false');
      await con.query(`LOAD '${location.origin}/gatekeeper.duckdb_extension.wasm'`);
      const decision = async (sql, options = '') => JSON.parse(JSON.stringify(
        (await rows(`SELECT * FROM gatekeeper_validate('${sql.replaceAll("'", "''")}'${options})`))[0],
        (_, v) => typeof v === 'bigint' ? Number(v) : v));
      const rejects = async (sql, message) => {
        try {await con.query(sql);} catch (e) {return e.message.includes(message);}
        return false;
      };
      let d = await decision('SELECT 1');
      check('simple query', d.allowed && d.code === 'ok');
      d = await decision('DROP TABLE t');
      check('write denied', !d.allowed && d.code === 'unsupported');
      d = await decision("SELECT * FROM read_parquet('/missing.parquet')");
      check('reader preflight', !d.allowed && d.code === 'forbidden' && d.error_message === '');
      d = await decision('SELECT * FROM missing_table');
      check('missing table binding error', !d.allowed && d.code === 'binding' && d.error_message.includes('does not exist'));
      check('worker usable after engine exception', (await decision('SELECT 1')).allowed);
      d = await decision("SELECT 1 LIMIT len(repeat('x', 1000000))");
      check('bind-time computation denied', !d.allowed && d.violations.some(v => v.rule === 'bind_time_expression'));
      await con.query('CREATE VIEW unnested AS SELECT unnest([1,2]) x');
      d = await decision('SELECT * FROM unnested', ", blocked_functions := ['unnest']");
      check('UNNEST in trusted expansion blocked', d.code === 'forbidden');
      d = await decision("SELECT list_transform(['a'], lambda x: x COLLATE nocase = 'A')", ", blocked_functions := ['lower']");
      check('lambda collation implementation blocked', d.code === 'forbidden');
      d = await decision('SELECT list_sum([1,2])', ", blocked_functions := ['sum']");
      check('list aggregate implementation blocked', d.code === 'forbidden');
      d = await decision('SELECT list_sum($1)', ", blocked_functions := ['sum']");
      check('deferred aggregate binding rejected', !d.allowed && d.code === 'binding' && d.functions.length === 0);
      d = await decision('SELECT list_sum($1::INTEGER[])', ", blocked_functions := ['sum']");
      check('typed aggregate parameter still blocked', d.code === 'forbidden');
      d = await decision('SELECT list_sum([1,2])');
      check('list aggregate dependency', d.allowed && d.functions.some(f => f.name === 'sum' && f.type === 'aggregate'));
      await con.query('CREATE TABLE t(x INT); CREATE TABLE secret(x INT); CREATE VIEW v AS SELECT * FROM t');
      d = await decision('SELECT * FROM v');
      check('view dependencies', d.allowed && d.objects.some(o => o.table === 'v') && d.objects.some(o => o.table === 't'));
      check('submitted parameter binding', (await decision('SELECT * FROM t WHERE x = $1')).allowed);
      const prepared = await con.prepare('SELECT * FROM gatekeeper_validate(?)');
      try {
        check('host prepared validation', (await prepared.query('SELECT 1')).toArray()[0].allowed);
        await con.query("CALL gatekeeper_configure(blocked_functions := ['md5'], allowed_tables := [{schema:'main', 'table':'t'}, {schema:'main', 'table':'v'}])");
        check('prepared validation observes new policy', !(await prepared.query("SELECT md5('x')")).toArray()[0].allowed);
      } finally {await prepared.close();}
      d = await decision("SELECT md5('x')", ', blocked_functions := []::VARCHAR[]');
      check('function ceiling', !d.allowed && d.code === 'forbidden');
      check('denial dependencies empty', d.objects.length === 0 && d.functions.length === 0);
      d = await decision('SELECT * FROM secret', ", allowed_tables := [{schema:'main', 'table':'secret'}]");
      check('object ceiling', !d.allowed && d.code === 'forbidden');
      check('authorized view under ceiling', (await decision('SELECT * FROM v')).allowed);
      check('request narrowing', !(await decision('SELECT * FROM t', ', allowed_tables := []')).allowed);
      const second = await db.connect();
      try {
        check('policy shared across connections', !(await second.query("SELECT * FROM gatekeeper_validate('SELECT md5(''x'')')")).toArray()[0].allowed);
      } finally {await second.close();}
      check('malformed configuration rejected', await rejects("CALL gatekeeper_configure(allowed_tables := [{catlog:'x', schema:'main', 'table':'t'}])", 'unknown table field'));
      check('invalid replacement atomic', !(await decision("SELECT md5('x')")).allowed);
      await con.query('RESET gatekeeper_policy');
      check('RESET restores defaults', (await decision("SELECT md5('x')")).allowed);
      await con.query("CALL gatekeeper_configure(blocked_functions := ['md5'])");
      await con.query('CALL gatekeeper_configure()');
      check('CALL replaces whole policy', (await decision("SELECT md5('x')")).allowed);
      await con.query("SET gatekeeper_policy = current_setting('gatekeeper_policy')");
      check('canonical SET round trip', (await decision('SELECT 1')).allowed);
      await con.query("CALL gatekeeper_configure(blocked_functions := ['md5'])");
      await con.query('SET lock_configuration = true');
      check('CALL respects lock', await rejects('CALL gatekeeper_configure()', 'locked'));
      check('RESET respects lock', await rejects('RESET gatekeeper_policy', 'locked'));
      check('SET respects lock', await rejects("SET gatekeeper_policy = current_setting('gatekeeper_policy')", 'locked'));
      check('locked policy enforced', !(await decision("SELECT md5('x')")).allowed);
      return {version, passed};
    } finally {
      if (con) await con.close();
      await db.terminate();
    }
  });
  assert.deepEqual(errors, [], 'uncaught browser errors');
  console.log(JSON.stringify(report, null, 2));
  console.log(`${report.passed.length} Wasm EH checks passed`);
} finally {
  clearTimeout(watchdog);
  if (browser) await browser.close();
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
