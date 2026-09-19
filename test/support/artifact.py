"""The repository, the loadable artifact under test, and connections with it loaded.

The default location and the load idiom are scripts/artifact.py's; this module adds the GATEKEEPER_EXTENSION
override the distribution workflow uses to point the suite at a downloaded platform artifact.
"""
import os
from pathlib import Path

import artifact as loadable
from artifact import literal  # noqa: F401  (re-exported: tests build SQL with it)

ROOT = loadable.ROOT
EXTENSION = Path(os.getenv("GATEKEEPER_EXTENSION", loadable.DEFAULT_EXTENSION))


def connect(extension=EXTENSION, **config):
    """A fresh in-memory database with the artifact under test loaded; closed again if the load fails."""
    return loadable.connect(extension, **config)
