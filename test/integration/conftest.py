"""The candidate Quack CI leg must run every selected case, never silently skip a feature."""
import os

import pytest


def pytest_sessionfinish(session, exitstatus):
    if os.getenv("GATEKEEPER_QUACK_CANDIDATE") != "1":
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter and reporter.stats.get("skipped"):
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
