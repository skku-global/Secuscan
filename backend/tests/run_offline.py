#!/usr/bin/env python
"""Run every offline suite in this directory and sum the result.

OFFLINE means: imports the backend modules directly and needs no running server, no
database, no network. These are the suites that can run on a fresh checkout with
nothing started - so they are the ones worth a one-command runner and the ones a
pre-commit or CI step would call.

  python backend/tests/run_offline.py

Each suite already exits non-zero on failure (that is its contract), so this runner
is a thin loop: it runs each as a subprocess, prints a one-line verdict, and exits
non-zero if any did. It does NOT reach into their internals - a suite's own
`N passed, M failed` line stays the source of truth, and this only tallies exits.

The live/ and probes/ trees are deliberately NOT run here: they need `uvicorn` up on
:8000 (and, for probes, a human reading the output). See tests/README.md.
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Explicit, not a glob: a runner that discovers its own work silently skips a suite
# whose name stops matching, and a test that silently stops running is worse than one
# that fails. Adding a suite is a one-line edit here, on purpose.
SUITES = [
    "test_branches.py",
    "test_https_branches.py",
    "test_rate_limit.py",
    "test_password.py",
    "test_reset.py",
    "test_payments.py",
    "test_google_auth.py",
    "test_credentials.py",
    "test_tier2_retention.py",
    "test_account_enumeration.py",
    "test_engine_e2e.py",
]


def main() -> int:
    results = []
    for name in SUITES:
        path = HERE / name
        if not path.exists():
            print(f"MISSING  {name}  - listed in run_offline.py but not on disk")
            results.append((name, None))
            continue
        proc = subprocess.run([sys.executable, str(path)],
                              capture_output=True, text=True)
        # Two harness styles live here and both are fine. Five suites count as they go
        # and print "N passed, M failed" at the end; test_engine_e2e.py bails on the
        # first failure instead, so it has no tally to print - for that one, count the
        # ok lines rather than leaving the column blank and looking like it did nothing.
        tally = ""
        for line in reversed(proc.stdout.splitlines()):
            if "passed," in line:
                tally = line.strip()
                break
        else:
            checks = sum(1 for line in proc.stdout.splitlines()
                         if line.strip().startswith("ok "))
            if checks:
                tally = f"{checks} checks passed (fails fast, no tally)"
        ok = proc.returncode == 0
        print(f"{'ok  ' if ok else 'FAIL'} {name:24s} {tally}")
        if not ok and proc.stdout:
            # On failure the tail is what you want to see, so show it rather than
            # making the reader re-run the suite by hand to find out why.
            print("     --- last output ---")
            for line in proc.stdout.splitlines()[-12:]:
                print("     " + line)
            if proc.stderr.strip():
                for line in proc.stderr.splitlines()[-6:]:
                    print("     " + line)
        results.append((name, ok))

    passed = sum(1 for _, ok in results if ok)
    failed = sum(1 for _, ok in results if ok is False)
    missing = sum(1 for _, ok in results if ok is None)
    print(f"\n{passed} suite(s) passed, {failed} failed"
          + (f", {missing} missing" if missing else ""))
    return 1 if (failed or missing) else 0


if __name__ == "__main__":
    raise SystemExit(main())
