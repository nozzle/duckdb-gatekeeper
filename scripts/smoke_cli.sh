#!/bin/sh
# Loadable smoke through the official DuckDB CLI, for the artifacts no Python package can load: the musl
# targets, whose CLI DuckDB publishes as duckdb_cli-linux-{amd64,arm64}-musl (dynamically linked against
# musl, so it can dlopen a musl extension). Runs in an Alpine container from the distribution workflow.
#
#   sh scripts/smoke_cli.sh <duckdb-cli> <gatekeeper.duckdb_extension> <engine version> <platform>
#   e.g.  sh scripts/smoke_cli.sh ./duckdb build/distributed/gatekeeper.duckdb_extension v1.5.5 linux_amd64_musl
#
# The CLI is one connection, so the checks come in two forms. scripts/smoke/loadable.sql, the half the other
# hosts share, is read as one stdin script under -bail (every statement asserts inside SQL). The half that needs
# a second connection (scripts/smoke/enforced.sql) is replayed here as separate CLI processes: each latches its
# own connection with gatekeeper_enforce(), and the audit log is observed through the engine's stdout log
# storage instead of a host connection reading duckdb_logs_parsed(). Refusals are read from stderr. The record
# patterns below are the engine's rendering of the structured Gatekeeper log entry; this script runs against the
# pinned engine only.
set -eu

if [ $# -ne 4 ]; then
	echo "usage: $0 <duckdb-cli> <extension> <engine version> <platform>" >&2
	exit 2
fi
cli=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
extension=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
version=$3
platform=$4
smoke=$(cd "$(dirname "$0")" && pwd)/smoke
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cd "$scratch"

fail() {
	echo "::error::smoke_cli: $*" >&2
	exit 1
}
count() {
	grep -c -- "$1" "$2" || true
}
duckdb() {
	"$cli" -unsigned -init /dev/null -csv -noheader "$@"
}
load="LOAD '$(printf %s "$extension" | sed "s/'/''/g")'"

# 1. The host is the pinned engine, the artifact is this platform's, and it loads.
reported=$("$cli" --version)
case $reported in
"$version "*) ;;
*) fail "the CLI reports '$reported', expected $version" ;;
esac
got=$(duckdb -c "$load" -c "PRAGMA platform")
[ "$got" = "$platform" ] || fail "the CLI's platform is '$got', expected $platform"
got=$(duckdb -c "$load" -c "SELECT extension_version FROM duckdb_extensions() WHERE extension_name = 'gatekeeper' AND loaded")
[ -n "$got" ] || fail "gatekeeper did not load"
echo "host $reported $platform, extension $got"

# 2. The shared single-connection half, every statement asserting for itself.
{
	echo "$load;"
	cat "$smoke/loadable.sql"
} | duckdb -bail >loadable.out || fail "loadable.sql failed on the CLI (the failing statement's error is above)"

# 3. The configuration lock is the host's.
if lock_error=$(duckdb -c "$load" -c "SET lock_configuration = true" -c "CALL gatekeeper_configure()" 2>&1 >/dev/null); then
	fail "gatekeeper_configure ignored lock_configuration"
fi
case $lock_error in
*locked*) ;;
*) fail "unexpected lock error: $lock_error" ;;
esac

# 4. Enforcement through the host's query hooks and log manager, on the CLI's own connection.
setup() {
	cat <<EOF
$load;
CREATE SCHEMA reporting;
CREATE TABLE reporting.orders AS SELECT 20.0 AS amount;
CREATE TABLE secret AS SELECT 'x' AS token;
CALL gatekeeper_configure(allowed_tables := [{'schema_path': ['reporting'], 'table': '*'}]);
CALL enable_logging('Gatekeeper', storage = 'stdout');
SET logging_level = 'debug';
EOF
}
{
	setup
	cat <<'EOF'
SELECT enforced FROM gatekeeper_enforce();
SELECT sum(amount) AS allowed_sum FROM reporting.orders;
SELECT * FROM secret;
CREATE TABLE u(x INTEGER);
SET threads = 1;
CALL disable_logging();
EOF
} | duckdb >enforce.out 2>enforce.err || true
grep -qx 'true' enforce.out || fail "gatekeeper_enforce did not latch"
grep -qx '20.0' enforce.out || fail "the allowed read did not run: $(cat enforce.out enforce.err)"
[ "$(count 'Gatekeeper denied this statement' enforce.err)" = 4 ] ||
	fail "expected 4 refusals, stderr was: $(cat enforce.err)"
grep -q "'mode': enforce, .*'allowed': true, 'code': ok" enforce.out || fail "no audit record for the allowed read"
[ "$(count "'mode': enforce, .*'allowed': false, 'code': forbidden" enforce.out)" = 1 ] ||
	fail "expected one forbidden record: $(grep Gatekeeper enforce.out)"
[ "$(count "'mode': enforce, .*'allowed': false, 'code': unsupported" enforce.out)" = 3 ] ||
	fail "expected three unsupported records: $(grep Gatekeeper enforce.out)"

# 5. Log-only, set before latching: the same decision is recorded and nothing is refused.
{
	setup
	cat <<'EOF'
SET gatekeeper_log_only = true;
SELECT enforced FROM gatekeeper_enforce();
SELECT count(*) AS secret_rows FROM secret;
EOF
} | duckdb >logonly.out 2>logonly.err || true
[ ! -s logonly.err ] || fail "log-only refused something: $(cat logonly.err)"
grep -qx '1' logonly.out || fail "the log-only read did not run: $(cat logonly.out)"
[ "$(count "'mode': log_only, .*'allowed': false, 'code': forbidden" logonly.out)" = 1 ] ||
	fail "expected one log_only record: $(grep Gatekeeper logonly.out)"

echo "$(basename "$extension") ($platform): CLI smoke checks passed"
