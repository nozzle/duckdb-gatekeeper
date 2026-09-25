"""Run the opt-in, disposable Quack fixture; download only checksum-pinned 1.5.5 artifacts."""
import argparse
import gzip
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

import duckdb

ROOT = Path(__file__).resolve().parents[1]
# SHA256 of the compressed core-repository downloads, whose footer revisions are c154811 / 827222f.
PINS = {
    "linux_amd64": {
        "quack": "7b2c417e3797c2d85673655dea420ead9bbbb24e686ee8dbe37bef9fa8768207",
        "httpfs": "7cdd52a3135388718884a9b71e3987ba723002121e8e9de399c4ed619d824a05",
    },
    "linux_arm64": {
        "quack": "3b8857a7643a527a2ab6045e49bedf11f24114bc52e86287e400f75a4e20fbdc",
        "httpfs": "0820e0b5b74efaa23608c239df8e744a68943318d530b483a529eace19cb5475",
    },
    "osx_arm64": {
        "quack": "a551db5ca9db6964a48f3c1f77076be0875bbdb0f335b139f77798c8fa92df51",
        "httpfs": "758acc0b0c4fbf09506f387ff6f52826b1038b7b6849ded39928d2f992945230",
    },
}


def artifacts(cache):
    with duckdb.connect() as db:
        platform = db.execute("PRAGMA platform").fetchone()[0]
    if duckdb.__version__ != "1.5.5" or platform not in PINS:
        raise SystemExit("Automatic downloads require DuckDB 1.5.5 on " + ", ".join(PINS)
                         + "; supply both --quack and --httpfs for another matched build")
    cache = cache / "v1.5.5" / platform
    cache.mkdir(parents=True, exist_ok=True)
    paths = {}
    for name, digest in PINS[platform].items():
        archive = cache / (name + ".duckdb_extension.gz")
        if archive.exists():
            payload = archive.read_bytes()
        else:
            url = f"https://extensions.duckdb.org/v1.5.5/{platform}/{archive.name}"
            request = urllib.request.Request(url, headers={"User-Agent": "gatekeeper-quack-fixture"})
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = response.read()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise SystemExit(f"Checksum mismatch: {archive}; refusing to load")
        archive.write_bytes(payload)
        paths[name] = cache / (name + ".duckdb_extension")
        paths[name].write_bytes(gzip.decompress(payload))
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / "build/quack-artifacts")
    parser.add_argument("--quack", type=Path)
    parser.add_argument("--httpfs", type=Path)
    args = parser.parse_args()
    if bool(args.quack) != bool(args.httpfs):
        parser.error("--quack and --httpfs must be supplied together")
    paths = {"quack": args.quack, "httpfs": args.httpfs} if args.quack else artifacts(args.cache)
    env = os.environ.copy()
    env["GATEKEEPER_QUACK_TESTS"] = "1"
    for name, path in paths.items():
        env["GATEKEEPER_" + name.upper() + "_EXTENSION"] = str(path.resolve(strict=True))
    subprocess.run([sys.executable, "-m", "pytest", "test/integration/test_quack.py", "-q", "-rs"],
                   cwd=ROOT, env=env, check=True, timeout=180)


if __name__ == "__main__":
    main()
