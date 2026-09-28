"""Run the disposable Quack fixture with checksum-pinned release or explicit candidate artifacts."""
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
# SHA256 of the compressed 1.5.6 core-repository downloads (quack 7e80f7f / httpfs 4bc690d).
PINS = {
    "linux_amd64": {
        "quack": "ad8bb34b2f513bcac0d01b96af0406fd2025f8ee3d3b878e45e30d0e6eab7b04",
        "httpfs": "19e6906934a845487c96f9c94beee250c71e32bb9be260eb27ad96939a1df5f0",
    },
    "linux_arm64": {
        "quack": "db025c62bb79a4f50f935036b3a342c3579b3794a8c76a54814be7551e6873d6",
        "httpfs": "b18472a0e85cbf15ca4ebbe335173f87b62a074cd0f26072d4c756205c6239d0",
    },
    "osx_arm64": {
        "quack": "4738b82495795d77d859e87782714b5bc5e5ff0679ae6b388de3fef08c393b69",
        "httpfs": "b9f9ca8e64d913a80d6666a370e0e518ee4cc8ecb9990a2b9d2273204d8caad4",
    },
}
CANDIDATE_PINS = {
    "linux_amd64": {
        "quack": "fd9167dbea6bc2aa1bd70cf31514ede70568ccc609c9dcf2070b146aaea18b80",
        "httpfs": "bcc3df9a3b7449e999659b51914d6c04545ba9923addb31a69683f2a8e59653d",
    },
    "osx_arm64": {
        "quack": "f6a675a4a129d16d3ba1f34961c785bca7bb0f9c00fccd06b6fb29b837a0bfc1",
        "httpfs": "40e01cc8ccae5f6cd822907c6d6ceaff53dc5f65a85191d1191fe1bd4f9dbe20",
    },
}


def artifacts(cache, candidate=False):
    with duckdb.connect() as db:
        platform = db.execute("PRAGMA platform").fetchone()[0]
        identity = db.execute("PRAGMA version").fetchone()
    version = "v2.0.0-alpha42986" if candidate else "v1.5.6"
    pins = CANDIDATE_PINS if candidate else PINS
    if candidate:
        if duckdb.__version__ != "2.0.0.dev2609221243" or identity[:2] != (version, "d4e72566aa"):
            raise SystemExit("Candidate fixture requires 2.0.0.dev2609221243 / alpha42986 / d4e72566aa")
    elif duckdb.__version__ != "1.5.6":
        raise SystemExit("Release fixture requires DuckDB 1.5.6")
    if platform not in pins:
        raise SystemExit("Automatic downloads for " + version + " support " + ", ".join(pins)
                         + "; supply both --quack and --httpfs for another matched build")
    cache = cache / version / platform
    cache.mkdir(parents=True, exist_ok=True)
    paths = {}
    for name, digest in pins[platform].items():
        archive = cache / (name + ".duckdb_extension.gz")
        if archive.exists():
            payload = archive.read_bytes()
        else:
            url = f"https://extensions.duckdb.org/{version}/{platform}/{archive.name}"
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
    parser.add_argument("--candidate", action="store_true", help="use the exact pinned 2.0 fixture; require zero skips")
    args = parser.parse_args()
    if bool(args.quack) != bool(args.httpfs):
        parser.error("--quack and --httpfs must be supplied together")
    if args.candidate and args.quack:
        parser.error("--candidate uses its verified artifact pins; omit explicit paths")
    paths = {"quack": args.quack, "httpfs": args.httpfs} if args.quack else artifacts(args.cache, args.candidate)
    env = os.environ.copy()
    env["GATEKEEPER_QUACK_TESTS"] = "1"
    if args.candidate:
        env["GATEKEEPER_QUACK_CANDIDATE"] = "1"
    for name, path in paths.items():
        env["GATEKEEPER_" + name.upper() + "_EXTENSION"] = str(path.resolve(strict=True))
    subprocess.run([sys.executable, "-m", "pytest", "test/integration/test_quack.py", "-q", "-rs"],
                   cwd=ROOT, env=env, check=True, timeout=180)


if __name__ == "__main__":
    main()
