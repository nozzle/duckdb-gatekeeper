# Digest pinned; Dependabot updates it with the tag.
FROM ubuntu:26.04@sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y --no-install-recommends clang libclang-rt-dev python3 python3-venv ca-certificates git cmake ninja-build && rm -rf /var/lib/apt/lists/*
# Build context is the repository root (.dockerignore admits only the hashed lock file). A venv keeps
# the hash-verified install separate from Debian-owned site-packages. Rebuild on engine
# repins: this lock now supplies DuckDB 1.5.6 for Gatekeeper 0.4.1.
COPY requirements-dev.txt /tmp/requirements-dev.txt
RUN python3 -m venv /opt/gatekeeper && /opt/gatekeeper/bin/python -m pip install --require-hashes -r /tmp/requirements-dev.txt
ENV PATH="/opt/gatekeeper/bin:${PATH}"
WORKDIR /work
ENTRYPOINT ["python3", "scripts/fuzz_native.py"]
