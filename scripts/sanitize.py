"""Sanitizer runtime settings and the libFuzzer run the fuzz and sanitized-test runners share."""
import os
from pathlib import Path
import subprocess


def environment(mixed_runtime):
    """ASan/UBSan options for an instrumented run, on top of the current environment.

    Leak detection is off everywhere: the engine's process-lifetime globals are reported as leaks and drown
    real findings. ``mixed_runtime`` is for an instrumented Gatekeeper running inside an uninstrumented host
    (the pinned duckdb Python package, the linked fuzz target's libduckdb): standard-library containers cross
    that ABI and the container-overflow check misfires on them. The native validator fuzz target is
    instrumented end to end and keeps the check.
    """
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1" + (":detect_container_overflow=0" if mixed_runtime else "")
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    return env


def run_libfuzzer(binary, corpus, log, seconds, max_len, env):
    """Runs a libFuzzer target with the repository's fixed settings (5 s per-input timeout, crash artifacts
    next to the log), keeps its full output in ``log``, prints the summary lines, and raises on a finding."""
    log = Path(log)
    with log.open("w") as handle:
        result = subprocess.run([str(binary), str(corpus), f"-max_total_time={seconds}", f"-max_len={max_len}",
                                 "-timeout=5", f"-artifact_prefix={log.parent}/"], env=env, stdout=handle, stderr=handle)
    for line in log.read_text(errors="replace").splitlines():
        if "DONE" in line or line.startswith("Done ") or "ERROR:" in line or "SUMMARY:" in line:
            print(line)
    print("Full log:", log)
    result.check_returncode()
