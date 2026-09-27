"""Explicit opt-in, isolated official-extension inventory collection (never grants policy)."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
REPOSITORIES = {"core": "https://extensions.duckdb.org",
                "core_nightly": "https://nightly-extensions.duckdb.org"}
SCHEMA_VERSION = 2
CAPTURE_PROTOCOL = "gatekeeper-isolated-staged-capture-v2"
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_DEPENDENCIES = 16


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def file_digest(path):
    with Path(path).open("rb") as stream:
        sha = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
        return sha.hexdigest()


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def name_token(value):
    if not re.fullmatch(r"[a-z][a-z0-9_]*", value):
        raise ValueError("invalid extension name")
    return value


def sql_string(value):
    return "'" + str(value).replace("'", "''") + "'"


def inventory_names(directory):
    return [name_token(path.stem) for path in sorted(Path(directory).glob("*.json"))]


def canonical_name(name, registry):
    name_token(name)
    matches = {row["extension_name"] for row in registry
               if name == row["extension_name"] or name in row.get("aliases", [])}
    if len(matches) > 1:
        raise ValueError("ambiguous engine extension alias")
    # Official extensions such as UI need not appear in every engine's built-in registry.
    return name_token(next(iter(matches), name))


def function_delta(before, after):
    """Complete overload groups keyed by exact qualified identity, including changed groups."""
    def groups(rows):
        result = {}
        for row in rows:
            key = (row["catalog"], tuple(row["schema_path"]), row["name"], row["kind"])
            result.setdefault(key, []).append(row)
        return {key: sorted(value, key=encoded) for key, value in result.items()}

    old, new = groups(before), groups(after)
    return {"added": [row for key in sorted(new.keys() - old.keys()) for row in new[key]],
            "removed": [row for key in sorted(old.keys() - new.keys()) for row in old[key]],
            "changed": [{"before": old[key], "after": new[key]} for key in sorted(old.keys() & new.keys())
                        if old[key] != new[key]]}


def isolated_environment(home):
    # Allowlist, not a credentials denylist: no cloud tokens, proxy credentials, Python
    # injection, loader overrides, user-installed extension store, or auth configuration.
    return {"HOME": str(home), "USERPROFILE": str(home), "TMPDIR": str(home),
            "TMP": str(home), "TEMP": str(home), "PATH": "/usr/bin:/bin",
            "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"),
            "XDG_DATA_HOME": str(home / "data"), "AWS_EC2_METADATA_DISABLED": "true",
            "CAPTURE_EXTENSIONS_CHILD": "1"}


def run_child(python, spec, timeout):
    """A process and temporary HOME/store per attempt; native failures cannot abort the matrix."""
    with tempfile.TemporaryDirectory(prefix="gatekeeper-capture-") as temporary:
        home = Path(temporary).resolve()
        request, response = home / "request.json", home / "response.json"
        write_json(request, spec)
        command = [str(python), "-I", "-B", str(Path(__file__).resolve()), "_child", str(request), str(response)]
        try:
            with subprocess.Popen(command, cwd=home, env=isolated_environment(home),
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, start_new_session=True) as process:
                timed_out = False
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                finally:
                    # Also reap descendants if a failed native extension left any behind.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                result = json.loads(response.read_text()) if response.exists() else {}
                if timed_out:
                    result.update(status="timeout", error={"code": "process_timeout"})
                elif process.returncode:
                    result.update(status="crash" if process.returncode < 0 else "failed",
                                  error={"code": "process_exit", "returncode": process.returncode})
                elif result.get("status") == "running" or not result:
                    result.update(status="failed", error={"code": "missing_worker_result"})
                return result
        except OSError:
            return {"status": "failed", "error": {"code": "python_launch_failed"}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("artifact redirects are not allowed")


def artifact_url(engine, repository, name):
    revision = engine["extension_abi"]
    platform = engine["platform"]
    for value in (revision, platform):
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", value) or value in {".", ".."}:
            raise ValueError("invalid engine artifact identity")
    return f"{REPOSITORIES[repository]}/{revision}/{platform}/{name_token(name)}.duckdb_extension.gz"


def copy_bounded(source, destination):
    size = 0
    with destination.open("wb") as target:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            size += len(block)
            if size > MAX_ARTIFACT_BYTES:
                raise ValueError("artifact exceeds size limit")
            target.write(block)


def download(engine, repository, name, directory, expected=None):
    url = artifact_url(engine, repository, name)
    if expected is not None and expected["url"] != url:
        raise ValueError("locked artifact URL differs from engine/repository/name")
    compressed = directory / (name + ".duckdb_extension.gz")
    binary = directory / (name + ".duckdb_extension")
    # No proxy discovery or redirects: only the exact official engine/platform URL.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "gatekeeper-inventory-capture/1"})
    with opener.open(request, timeout=30) as response:
        copy_bounded(response, compressed)
    compressed_sha = file_digest(compressed)
    if expected is not None and expected["download_sha256"] != compressed_sha:
        raise ValueError("locked download hash mismatch")
    with gzip.open(compressed, "rb") as stream:
        copy_bounded(stream, binary)
    sha = file_digest(binary)
    if expected is not None and expected["sha256"] != sha:
        raise ValueError("locked binary hash mismatch")
    return binary, {"name": name, "repository": repository, "url": url,
                    "download_sha256": compressed_sha, "sha256": sha,
                    "bytes": binary.stat().st_size}


def registry_rows(db):
    cursor = db.execute("SELECT * FROM duckdb_extensions() ORDER BY extension_name")
    return [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]


def loaded_rows(registry):
    # Never serialize install_path/installed_from: local INSTALL records absolute paths.
    return [{"name": row["extension_name"], "version": row["extension_version"],
             "install_mode": row["install_mode"],
             **({"signature_key_fingerprint": row["signature_key_fingerprint"]}
                if row.get("signature_key_fingerprint") else {})}
            for row in registry if row["loaded"]]


def validate_lock(lock, selected):
    """Reject legacy adapters and incomplete load protocols before launching a worker."""
    if lock.get("schema_version") != SCHEMA_VERSION or lock.get("capture_protocol") != CAPTURE_PROTOCOL:
        raise ValueError("lock must come from collector protocol v2 discovery")
    if set(selected) - lock["extensions"].keys():
        raise ValueError("lock selected extension set mismatch")
    for name in selected:
        pin = lock["extensions"][name]
        installs, loads = pin["install_names"], pin["load_names"]
        if not loads or loads[-1] != pin["resolved_name"] or len(loads) != len(set(loads)):
            raise ValueError("lock must contain ordered preloads followed by target")
        if set(loads) - set(installs):
            raise ValueError("locked loads must be installed or explicitly recorded builtins")
        for token in installs + loads:
            name_token(token)
        if pin["status"] == "ok":
            if "motherduck" in loads or not pin.get("stages_sha256"):
                raise ValueError("successful lock lacks permitted staged capture")
        elif pin.get("stages_sha256") is not None:
            raise ValueError("incomplete capture cannot claim verified stages")


def engine_identity(db, duckdb):
    import _duckdb

    cursor = db.execute("PRAGMA version")
    result = dict(zip([column[0] for column in cursor.description], cursor.fetchone()))
    result.update(python_package_version=duckdb.__version__, python_version=sys.version.split()[0],
                  native_module_sha256=file_digest(_duckdb.__file__),
                  platform=db.execute("PRAGMA platform").fetchone()[0])
    # DuckDB's GetVersionDirectoryName uses the source ID for -dev builds. Alpha
    # release artifacts use the complete library version, not the pip package version.
    version = result["library_version"]
    result["extension_abi"] = result["source_id"] if "-dev" in version else (
        version if version.startswith("v") else "v" + version)
    return result


def missing_dependency(error, registry):
    # This is a bounded hint to a NEW process, never a command or a URL from an error.
    patterns = [r'(?i)autoloading extension [\'"]([a-z0-9_]+)[\'"] failed',
                r'(?i)extension [\'"](?:[^\'"\n]*/)?([a-z0-9_]+)\.duckdb_extension[\'"] not found',
                r'(?i)requires the ([a-z0-9_]+) extension to be loaded']
    for pattern in patterns:
        match = re.search(pattern, str(error))
        if match:
            name = canonical_name(match[1], registry)
            if any(row["extension_name"] == name for row in registry):
                return name
    return None


def child(request, response):
    if os.environ.get("CAPTURE_EXTENSIONS_CHILD") != "1":
        raise SystemExit("Use collect/worker --allow-install; _child is an internal protocol")
    # Disable core dumps before importing native code. Captured artifacts never include
    # stdout, stderr, credentials, native exception text, or personal absolute paths.
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    sys.path.insert(0, str(ROOT / "scripts"))
    spec = json.loads(Path(request).read_text())
    result = {"status": "running", "phase": "connect", "artifacts": [],
              "capture_protocol": CAPTURE_PROTOCOL}
    write_json(response, result)
    registry = []
    try:
        import duckdb
        from audit_inventory import capture_functions

        home = Path.cwd()
        (home / ".duckdb").mkdir()
        store = home / "extensions"
        store.mkdir()
        downloads = home / "downloads"
        downloads.mkdir()
        config = {"autoload_known_extensions": "false", "autoinstall_known_extensions": "false",
                  "allow_unsigned_extensions": "false", "allow_community_extensions": "false",
                  "allow_persistent_secrets": "false", "secret_directory": str(home / "secrets"),
                  "extension_directories": "['" + str(store).replace("'", "''") + "']",
                  "threads": "1"}
        with duckdb.connect(config=config) as db:
            engine = engine_identity(db, duckdb)
            registry = registry_rows(db)
            initial = loaded_rows(registry)
            result.update(engine=engine, initial_extensions=initial)
            if spec.get("engine") is not None and spec["engine"] != engine:
                raise ValueError("engine identity mismatch")
            result["phase"] = "base_capture"
            before = capture_functions(db)
            base = {"schema_version": SCHEMA_VERSION, "capture_protocol": CAPTURE_PROTOCOL,
                    "snapshot_type": "base", "engine": engine,
                    "loaded_extensions": initial, "functions": before}
            if spec.get("extension") is None:
                result.update(status="ok", base=base)
                write_json(response, result)
                return
            result["base_sha256"] = digest(base)
            if result["base_sha256"] != spec["base_sha256"]:
                raise ValueError("fresh process base differs")
            target = canonical_name(spec["extension"], registry)
            names = list(dict.fromkeys(canonical_name(name, registry) for name in spec["install_names"]))
            loads = [canonical_name(name, registry) for name in spec["load_names"]]
            if not loads or loads[-1] != target or len(set(loads)) != len(loads) or set(loads) - set(names):
                raise ValueError("invalid ordered load plan")
            result.update(resolved_name=target, install_names=names, load_names=loads,
                          stages=[{"stage": "before", "loaded_extensions": initial,
                                   "functions_sha256": digest(before)}])
            expected = spec.get("artifacts")
            expected_by_name = {entry["name"]: entry for entry in expected} if expected is not None else None
            for name in names:
                if any(row["extension_name"] == name and row["loaded"] for row in registry):
                    continue
                result.update(phase="download", active_extension=name)
                write_json(response, result)
                if expected_by_name is not None and name not in expected_by_name:
                    result.update(status="unavailable", error={"code": "artifact_not_in_lock"})
                    write_json(response, result)
                    return
                pin = expected_by_name[name] if expected_by_name is not None else None
                binary, artifact = download(engine, spec["repository"], name, downloads, pin)
                result["artifacts"].append(artifact)
                result["phase"] = "install"
                write_json(response, result)
                db.execute("INSTALL " + sql_string(binary))
                row = next(row for row in registry_rows(db) if row["extension_name"] == name)
                artifact["version"] = row["extension_version"]
                if pin is not None and artifact != pin:
                    raise ValueError("installed artifact differs from lock")
                if file_digest(row["install_path"]) != artifact["sha256"]:
                    raise ValueError("installed artifact hash mismatch")
                write_json(response, result)
            if expected is not None and result["artifacts"] != expected:
                raise ValueError("artifact set differs from lock")
            # Proprietary initialization is not audited as offline. INSTALL checks metadata
            # without invoking its entrypoint; no LOAD, authentication, or service connection.
            if "motherduck" in names:
                result.update(status="skipped", phase="load",
                              error={"code": "motherduck_load_requires_offline_review"})
                write_json(response, result)
                return
            previous = before
            for index, name in enumerate(loads):
                result.update(phase="load", active_extension=name)
                write_json(response, result)
                db.execute("LOAD " + sql_string(name))
                result["phase"] = "extension_capture"
                after = capture_functions(db)
                result["stages"].append({"stage": "target" if index == len(loads) - 1 else "dependency",
                                         "load_name": name, "loaded_extensions": loaded_rows(registry_rows(db)),
                                         "functions_sha256": digest(after),
                                         "functions": function_delta(previous, after)})
                previous = after
                write_json(response, result)
            loaded = loaded_rows(registry_rows(db))
            allowed = {row["name"] for row in initial} | {row["name"] for row in result["artifacts"]}
            if any(row["name"] not in allowed for row in loaded):
                raise ValueError("unrecorded loaded dependency")
            for path in store.rglob("*.duckdb_extension"):
                if not any(path.name == artifact["name"] + ".duckdb_extension"
                           and file_digest(path) == artifact["sha256"] for artifact in result["artifacts"]):
                    raise ValueError("unrecorded installed artifact")
            result.update(status="ok", loaded_extensions=loaded,
                          dependencies_loaded=[row["name"] for row in loaded
                                               if row["name"] != target and row not in initial],
                          functions=function_delta(before, after), function_count=len(after))
            result["stages_sha256"] = digest(result["stages"])
            if spec.get("stages_sha256") is not None and spec["stages_sha256"] != result["stages_sha256"]:
                result.update(status="failed", error={"code": "locked_stages_mismatch"})
    except Exception as error:
        dependency = missing_dependency(error, registry) if result["phase"] == "load" else None
        result.update(status="needs_dependency" if dependency else "failed",
                      error={"code": "operation_failed", "type": type(error).__name__})
        if dependency:
            result["dependency"] = dependency
        if isinstance(error, urllib.error.HTTPError):
            result.update(status="unavailable", error={"code": "http_error", "http_status": error.code})
        # Intentionally omit arbitrary exception messages: native errors can contain
        # absolute paths, environment values, URLs with tokens, and embedded SQL.
    write_json(response, result)


def collect_one(python, extension, repository, base, timeout, dependencies=(), pin=None, preloads=()):
    spec = {"extension": extension, "repository": repository, "engine": base["engine"],
            "base_sha256": digest(base), "install_names": list(dict.fromkeys([*dependencies, *preloads, extension])),
            "load_names": [*preloads, extension]}
    if pin is not None:
        spec.update(install_names=pin["install_names"], load_names=pin["load_names"], artifacts=pin["artifacts"],
                    stages_sha256=pin.get("stages_sha256"))
    attempts = []
    for _ in range(MAX_DEPENDENCIES + 1):
        result = run_child(python, spec, timeout)
        attempts.append({key: result[key] for key in ("status", "phase", "error", "dependency") if key in result})
        if result["status"] != "ok" and result.get("artifacts"):
            attempts[-1]["artifacts"] = result["artifacts"]
        if result["status"] != "needs_dependency" or pin is not None:
            break
        dependency = result["dependency"]
        if dependency in spec["install_names"]:
            break
        spec["install_names"].insert(0, dependency)
    if result["status"] == "needs_dependency":
        result["status"] = "failed"
    result.update(schema_version=SCHEMA_VERSION, snapshot_type="extension_delta", inventory=extension,
                  capture_protocol=CAPTURE_PROTOCOL, repository=repository, base_sha256=digest(base), attempts=attempts)
    # No successful observation may be inferred from an incomplete discovery record.
    if pin is not None and pin["status"] != "ok" and result["status"] == "ok":
        result.update(status="failed", error={"code": "discovery_was_incomplete"})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("collect", "worker"):
        command = commands.add_parser(name, help="collect all inventories" if name == "collect" else "collect a subset")
        command.add_argument("--allow-install", action="store_true", required=True,
                             help="explicitly authorize downloading/installing/loading official extensions")
        command.add_argument("--python", type=Path, required=True, help="exact interpreter/venv for this engine")
        command.add_argument("--output", type=Path, required=True, help="new output directory (never overwritten)")
        command.add_argument("--inventories", type=Path, default=ROOT / "inventories/extensions")
        command.add_argument("--extension", action="append", default=[], required=name == "worker")
        command.add_argument("--dependency", action="append", default=[], help="explicit install-only dependency (repeatable)")
        command.add_argument("--preload", action="append", default=[], metavar="TARGET=NAME",
                             help="explicit ordered dependency LOAD before TARGET (repeatable, discovery only)")
        command.add_argument("--repository", choices=REPOSITORIES, default="core")
        command.add_argument("--timeout", type=float, default=180, help="seconds per isolated attempt")
        mode = command.add_mutually_exclusive_group(required=True)
        mode.add_argument("--discover", action="store_true", help="exploratory downloads; write lock.json")
        mode.add_argument("--lock", type=Path, help="verify exact engine, base and all artifact hashes before LOAD")
    args = parser.parse_args(argv)
    if os.name != "posix":
        parser.error("isolated process-group collection currently requires POSIX")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    available = inventory_names(args.inventories)
    selected = sorted(set(args.extension or available))
    if not selected or set(selected) - set(available):
        parser.error("--extension must name inventoried extensions")
    for name in args.dependency:
        name_token(name)
    preloads = {name: [] for name in selected}
    for preload in args.preload:
        target, separator, name = preload.partition("=")
        if not separator or target not in preloads:
            parser.error("--preload must be TARGET=NAME for a selected inventory")
        name_token(name)
        preloads[target].append(name)
    lock = json.loads(args.lock.read_text()) if args.lock else None
    if lock is not None:
        try:
            validate_lock(lock, selected)
        except (ValueError, KeyError, TypeError) as error:
            parser.error("invalid capture lock: " + str(error))
    if lock is not None and (args.dependency or args.preload or any(lock["extensions"][name]["repository"] != args.repository
                                                  for name in selected)):
        parser.error("locked dependencies/repository must match; omit --dependency on replay")
    python = args.python.expanduser().absolute()  # Do not resolve a venv interpreter symlink.
    args.output.mkdir(parents=True, exist_ok=False)
    base_result = run_child(python, {}, args.timeout)
    if base_result["status"] != "ok":
        write_json(args.output / "base-failure.json", base_result)
        return 1
    base = base_result["base"]
    if lock is not None and (lock["engine"] != base["engine"] or lock["base_sha256"] != digest(base)):
        write_json(args.output / "base-failure.json", {"status": "failed", "error": {"code": "lock_base_mismatch"}})
        return 1
    write_json(args.output / "base.json", base)
    manifest = {"schema_version": SCHEMA_VERSION, "capture_protocol": CAPTURE_PROTOCOL, "engine": base["engine"],
                "base_sha256": digest(base), "extensions": {}}
    summary = {"schema_version": SCHEMA_VERSION, "capture_protocol": CAPTURE_PROTOCOL,
               "collector_sha256": file_digest(__file__), "mode": "verified" if lock else "discovery",
               "evidence_kind": "collector_locked_replay" if lock else "collector_discovery",
               "base_sha256": digest(base), "extensions": {}}
    for extension in selected:
        pin = lock["extensions"][extension] if lock is not None else None
        result = collect_one(python, extension, args.repository, base, args.timeout, args.dependency, pin,
                             preloads[extension])
        result["mode"] = summary["mode"]
        write_json(args.output / (extension + ".json"), result)
        manifest["extensions"][extension] = {"repository": args.repository,
                                             "resolved_name": result.get("resolved_name", extension),
                                             "status": result["status"],
                                             "stages_sha256": result.get("stages_sha256") if result["status"] == "ok" else None,
                                             "load_names": result.get("load_names", [*preloads[extension], extension]),
                                             "install_names": result.get("install_names", [*args.dependency, *preloads[extension], extension]),
                                             "artifacts": result.get("artifacts", [])}
        summary["extensions"][extension] = result["status"]
        if lock is None:
            write_json(args.output / "lock.json", manifest)
        write_json(args.output / "summary.json", summary)
        print(f"{extension}: {result['status']}", flush=True)
    return int(any(status != "ok" for status in summary["extensions"].values()))


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "_child":
        child(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit(main())
