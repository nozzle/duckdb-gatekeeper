"""Prepare the checksum-pinned alternative parser for the running test engine.

DuckDB 2.0 uses legacy_parser; retained 1.5 uses autocomplete's PEG override. Downloads stay in
the workspace's build/parser-fixtures cache. Tests verify the cached binary before its first LOAD.
"""
import argparse
from functools import lru_cache
import gzip
import hashlib
import json
from pathlib import Path
import urllib.request

import duckdb

from check_engine_stamp import FOOTER_SIZE, footer_field

ROOT = Path(__file__).resolve().parents[1]
PINS = ROOT / "test/compatibility/parser-pins.json"
CACHE = ROOT / "build/parser-fixtures"


def fixture():
    version = duckdb.__version__
    pins = json.loads(PINS.read_text())
    if version not in pins:
        raise RuntimeError(f"No alternative-parser pin for DuckDB {version}; set GATEKEEPER_PARSER_EXTENSION "
                           "to an explicitly matched candidate parser")
    pin = pins[version]
    with duckdb.connect() as db:
        label, source = db.execute("PRAGMA version").fetchone()[:2]
        platform = db.execute("PRAGMA platform").fetchone()[0]
    if label != "v" + version or len(source) < 7 or not pin["engine_revision"].startswith(source):
        raise RuntimeError(f"Parser fixture engine mismatch: {label}/{source}")
    if platform not in pin["platforms"]:
        raise RuntimeError(f"No parser fixture for {platform}; set GATEKEEPER_PARSER_EXTENSION explicitly")
    directory = CACHE / version / platform / pin["platforms"][platform]["binary_sha256"]
    path = directory / (pin["extension"] + ".duckdb_extension")
    return version, platform, pin, path


def verify(binary, version, platform, pin):
    if hashlib.sha256(binary).hexdigest() != pin["platforms"][platform]["binary_sha256"]:
        raise RuntimeError("Parser binary checksum mismatch")
    expected = ["4", platform, "v" + version, pin["extension_version"], "CPP"]
    if len(binary) < FOOTER_SIZE or [footer_field(binary, n) for n in range(1, 6)] != expected:
        raise RuntimeError("Parser fixture metadata mismatch")


@lru_cache(maxsize=None)
def checked_path(name):
    """Read-only, once per process: ordinary test connections never install or download a parser."""
    version, platform, pin, path = fixture()
    if pin["extension"] != name:
        raise RuntimeError(f"The parser fixture for DuckDB {version} is {pin['extension']}, not {name}")
    if not path.is_file():
        raise RuntimeError("Missing pinned parser fixture; run python scripts/prepare_test_parser.py first")
    verify(path.read_bytes(), version, platform, pin)
    return path


def prepare():
    version, platform, pin, path = fixture()
    if path.exists():
        verify(path.read_bytes(), version, platform, pin)
        return path
    url = f"https://extensions.duckdb.org/v{version}/{platform}/{pin['extension']}.duckdb_extension.gz"
    request = urllib.request.Request(url, headers={"User-Agent": "gatekeeper-parser-fixture"})
    with urllib.request.urlopen(request, timeout=90) as response:
        archive = response.read()
    if hashlib.sha256(archive).hexdigest() != pin["platforms"][platform]["archive_sha256"]:
        raise RuntimeError("Parser download checksum mismatch")
    binary = gzip.decompress(archive)
    verify(binary, version, platform, pin)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(binary)
    return path


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(prepare())


if __name__ == "__main__":
    main()
