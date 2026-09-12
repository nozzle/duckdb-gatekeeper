FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y --no-install-recommends clang libclang-rt-18-dev python3 python3-pip ca-certificates && rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install --break-system-packages duckdb==1.5.5
WORKDIR /work
ENTRYPOINT ["python3", "scripts/fuzz_native.py"]
