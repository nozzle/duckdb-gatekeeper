"""Run disposable localhost Iceberg/MinIO and local DuckLake integration tests."""
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import uuid


def main():
    root = Path(__file__).resolve().parents[1]
    project = "gatekeeper-test-" + uuid.uuid4().hex[:8]
    command = ["docker", "compose", "-p", project, "-f", str(root / "test/integration/compose.yml")]
    try:
        subprocess.run(command + ["up", "-d"], check=True)
        for url in ["http://127.0.0.1:19000/minio/health/live", "http://127.0.0.1:18181/v1/config"]:
            for attempt in range(60):
                try:
                    with urllib.request.urlopen(url, timeout=2) as response:
                        if response.status == 200:
                            break
                except OSError:
                    time.sleep(1)
            else:
                raise RuntimeError("Service failed to become ready: " + url)
        env = os.environ.copy()
        env["GATEKEEPER_LAKEHOUSE_TESTS"] = "1"
        subprocess.run([sys.executable, "-m", "pytest", "test/integration", "-q"], cwd=root, env=env, check=True)
    finally:
        active_failure = sys.exc_info()[0] is not None
        try:
            subprocess.run(command + ["down", "--volumes"], check=True)
        except (OSError, subprocess.CalledProcessError) as error:
            if not active_failure:
                raise
            print(f"Lakehouse cleanup also failed: {error}", file=sys.stderr)


if __name__ == "__main__":
    main()
