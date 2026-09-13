"""Package the complete distribution run as unsigned, engine-specific release assets."""
import argparse
import hashlib
from pathlib import Path
import re
import zipfile

from versions import SUPPORTED_DUCKDB

ROOT = Path(__file__).resolve().parents[1]
# Keep aligned with MainDistributionPipeline.yml and the community descriptor.
PLATFORMS = (
    "linux_amd64", "linux_arm64", "linux_amd64_musl", "linux_arm64_musl",
    "osx_amd64", "osx_arm64", "windows_amd64", "windows_arm64",
    "windows_amd64_mingw", "wasm_eh",
)


def release_version(tag):
    def extract(pattern, text, location):
        match = re.search(pattern, text)
        if match is None:
            raise ValueError(f"Cannot read release version from {location}")
        return match.group(1)

    config = (ROOT / "extension_config.cmake").read_text()
    version = extract(r"EXTENSION_VERSION\s+(\d+\.\d+\.\d+)\)", config, "extension_config.cmake")
    source = (ROOT / "src/gatekeeper_extension.cpp").read_text()
    runtime_version = extract(r'GatekeeperExtension::Version\(\) const\s*\{\s*return "([^"]+)";',
                              source, "src/gatekeeper_extension.cpp Version()")
    error_version = extract(r'"Gatekeeper ([^" ]+) supports DuckDB %s only;',
                            source, "src/gatekeeper_extension.cpp load-error message")
    if (tag and tag != f"v{version}") or runtime_version != version or error_version != version:
        raise ValueError(f"Tag {tag!r}, CMake version {version}, runtime version {runtime_version}, "
                         f"and load-error version {error_version} must agree")
    return version


def package_release(tag, artifacts, output):
    version = release_version(tag)
    tag = tag or f"v{version}"
    prefix = f"gatekeeper-v{SUPPORTED_DUCKDB}-extension-"
    expected = {prefix + platform for platform in PLATFORMS}
    actual = {path.name for path in artifacts.iterdir()}
    if actual != expected:
        raise ValueError(f"Incomplete distribution: missing {sorted(expected - actual)}, unexpected {sorted(actual - expected)}")

    # Validate the entire input before producing anything that could be published.
    binaries = []
    for platform in PLATFORMS:
        directory = artifacts / (prefix + platform)
        name = "gatekeeper.duckdb_extension" + (".wasm" if platform == "wasm_eh" else "")
        binary = directory / name
        if not binary.is_file() or binary.is_symlink() or binary.stat().st_size == 0:
            raise ValueError(f"Missing or empty binary: {binary}")
        if set(directory.iterdir()) != {binary}:
            raise ValueError(f"Unexpected files in artifact: {directory}")
        binaries.append((platform, binary))
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError(f"Output must be empty and a directory: {output}")
    output.mkdir(parents=True, exist_ok=True)

    checksums = []
    for platform, binary in binaries:
        name = f"gatekeeper-{tag}-duckdb-v{SUPPORTED_DUCKDB}-{platform}-unsigned.zip"
        archive = output / name
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.write(binary, binary.name)
            for notice in ("LICENSE", "NOTICE"):
                bundle.write(ROOT / notice, notice)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksums.append(f"{digest}  {name}\n")
    (output / "SHA256SUMS").write_text("".join(checksums))
    (output / "RELEASE_NOTES.md").write_text(
        f"Gatekeeper {version} supports **DuckDB {SUPPORTED_DUCKDB} only**.\n\n"
        "These are **unsigned development binaries**, built from the workflow's source ref. "
        "They are not DuckDB-signed community binaries. The full distribution matrix "
        "and the Chromium test of its Wasm EH artifact passed before packaging.\n\n"
        "Select the archive matching your DuckDB platform, verify it against `SHA256SUMS`, "
        "and extract it. Each archive includes the canonical extension filename, LICENSE, "
        "and NOTICE. Native builds require explicit unsigned loading; Wasm requires the "
        "pinned EH runtime and unsigned-extension setting. Checksums do not provide "
        "DuckDB signature verification.\n\n"
        f"See [loading instructions](https://github.com/nozzle/duckdb-gatekeeper/blob/{tag}/CONTRIBUTING.md#loading-unsigned-builds), "
        f"[Wasm setup](https://github.com/nozzle/duckdb-gatekeeper/blob/{tag}/test/wasm/README.md), "
        f"and the [security model](https://github.com/nozzle/duckdb-gatekeeper/blob/{tag}/docs/security.md).\n\n"
        "New DuckDB patch/minor releases need a reviewed repin and rebuild. "
        "Community submission and deployment are separate from this GitHub Release.\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Release tag, or empty to check packaging on PRs/main")
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    package_release(args.tag, args.artifacts, args.output)


if __name__ == "__main__":
    main()
