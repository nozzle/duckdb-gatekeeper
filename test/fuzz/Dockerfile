# Digest pinned; Dependabot updates it with the tag.
FROM ubuntu:26.04@sha256:513c074113a871b51a8d16ab445c88779d6452d937a164fb5cc479f32668a41d
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y --no-install-recommends clang libclang-rt-dev python3 python3-pip ca-certificates git cmake ninja-build && rm -rf /var/lib/apt/lists/*
# Build context is the repository root (.dockerignore admits only the hashed lock file).
COPY requirements-dev.txt /tmp/requirements-dev.txt
RUN python3 -m pip install --break-system-packages --require-hashes -r /tmp/requirements-dev.txt
WORKDIR /work
ENTRYPOINT ["python3", "scripts/fuzz_native.py"]
