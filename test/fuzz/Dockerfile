FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y --no-install-recommends clang libclang-rt-18-dev python3 python3-pip ca-certificates git cmake ninja-build && rm -rf /var/lib/apt/lists/*
COPY requirements-inventory.txt /tmp/requirements-inventory.txt
RUN python3 -m pip install --break-system-packages duckdb==1.5.5 -r /tmp/requirements-inventory.txt
WORKDIR /work
ENTRYPOINT ["python3", "scripts/fuzz_native.py"]
