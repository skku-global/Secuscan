"""Puts `backend/` on sys.path so a suite can be run from anywhere.

WHY THIS EXISTS: these suites import the modules under test directly - `import
billing`, `from scanning.engine import run_scan` - because they test functions, not
HTTP. That only resolves if `backend/` is on the path, and until now it got there
via a PYTHONPATH the runner had to remember to export. A forgotten export produced
an ImportError that reads like a broken test rather than a missing variable.

One line at the top of each suite instead: `import _path`. It resolves because
Python puts the script's own directory on sys.path[0], so `backend/tests/` is
already importable whenever one of these files is the thing being run.

Nothing under live/ or probes/ needs this - those talk to a running server over
HTTP and import no backend module at all.
"""

import pathlib
import sys

BACKEND = pathlib.Path(__file__).resolve().parent.parent

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
