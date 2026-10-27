"""Run the disposable Quack fixture with checksum-pinned supported releases or explicit matched artifacts."""
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
# SHA256 of compressed 2.0.0 downloads (quack f96420ed46 / httpfs 77392a7207).
PINS = {
    "linux_amd64": {
        "quack": "f9a5c0d2e0eef0f7546aba4579ab80d75d167cdf48830459faf67378ab2000fe",
        "httpfs": "ee6c7d7e60a5da1b6f6bf6156b4298b55ddce0496a5bfe628bd6ab6d47eb8e3e",
    },
    "linux_arm64": {
        "quack": "9f7938a11eb9ff8026ccc9c6403ac4a9b1ba347f8c12ecd815f86eea09ed6005",
        "httpfs": "f524888fc7d74cc0c6c4a8f7ed5beedac5b12e71cb426503f882c72ce6afbd43",
    },
    "osx_arm64": {
        "quack": "d6779fb4adf9835e31f3b34cfdb1444cec1dd3af8f5ca99071271a91bae52cfc",
        "httpfs": "6aea2d728cb7eedb978ca264ce190e31284271e9ea4f68b2424bf20806b46638",
    },
}
# Retained 1.5.6 core downloads (quack 7e80f7f / httpfs 4bc690d), through 2027-03-01.
LEGACY_PINS = {
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


def artifacts(cache):
    with duckdb.connect() as db:
        platform = db.execute("PRAGMA platform").fetchone()[0]
        identity = db.execute("PRAGMA version").fetchone()
    if duckdb.__version__ == "2.0.0" and identity[:2] == ("v2.0.0", "d54cbbe3df"):
        version, pins = "v2.0.0", PINS
    elif duckdb.__version__ == "1.5.6" and identity[:2] == ("v1.5.6", "069cc9f9b5"):
        version, pins = "v1.5.6", LEGACY_PINS
    else:
        raise SystemExit("Automatic fixtures require DuckDB 2.0.0/d54cbbe3df or 1.5.6/069cc9f9b5; "
                         "supply --quack and --httpfs for another matched build")
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
    args = parser.parse_args()
    if bool(args.quack) != bool(args.httpfs):
        parser.error("--quack and --httpfs must be supplied together")
    paths = {"quack": args.quack, "httpfs": args.httpfs} if args.quack else artifacts(args.cache)
    env = os.environ.copy()
    env["GATEKEEPER_QUACK_TESTS"] = "1"
    if int(duckdb.__version__.split(".")[0]) >= 2:
        env["GATEKEEPER_QUACK_REQUIRE_NO_SKIPS"] = "1"
    for name, path in paths.items():
        env["GATEKEEPER_" + name.upper() + "_EXTENSION"] = str(path.resolve(strict=True))
    subprocess.run([sys.executable, "-m", "pytest", "test/integration/test_quack.py", "-q", "-rs"],
                   cwd=ROOT, env=env, check=True, timeout=180)


if __name__ == "__main__":
    main()
