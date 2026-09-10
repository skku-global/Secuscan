#!/usr/bin/env python
"""Run the live suites - the ones that need the API up - and sum the result.

  python backend/tests/run_live.py

WHY THIS IS A SEPARATE RUNNER FROM run_offline.py: the offline suites can run on a
fresh checkout with nothing started, and these cannot. Folding them together would
mean the single command everyone runs fails for a reason that is not a bug - a
server that isn't up - and a suite that cries wolf gets ignored.

It PRE-FLIGHTS the server rather than letting httpx raise. Without that, forgetting
to start uvicorn produces a ConnectError traceback that reads like a broken test.

WHAT THESE DO TO YOUR DATABASE: each signs up a throwaway account
(`checkout-<timestamp>@example.test` and friends) and leaves it there, and
e2e_lapse.py additionally hand-edits that account's `currentPeriodEnd` into the past
through pymongo, because a lazy downgrade with no scheduler can only be tested by
moving the date. They never touch an account they did not create. Point them at a
development database, not a real one.

probes/ is not run here on purpose: those scripts print for a human to read and
assert nothing, so their exit code cannot mean anything. See tests/README.md.
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = "http://127.0.0.1:8000"

SUITES = [
    "live/e2e_checkout.py",
    "live/e2e_lapse.py",
]


def server_is_up() -> tuple[bool, str]:
    """Cheapest unauthenticated GET the API has, used only as a heartbeat."""
    try:
        import httpx
    except ImportError:
        return False, "httpx is not installed (pip install -r backend/requirements.txt)"
    try:
        response = httpx.get(f"{BASE}/billing/plans", timeout=5.0)
    except Exception as exc:
        return False, f"no answer from {BASE} ({type(exc).__name__})"
    if response.status_code != 200:
        return False, f"{BASE}/billing/plans answered {response.status_code}"
    return True, ""


def main() -> int:
    up, why = server_is_up()
    if not up:
        print(f"SKIPPED - {why}")
        print("\nStart the API first, from backend/:")
        print("  python -m uvicorn main:app --host 127.0.0.1 --port 8000")
        return 2

    results = []
    for name in SUITES:
        path = HERE / name
        if not path.exists():
            print(f"MISSING  {name}  - listed in run_live.py but not on disk")
            results.append((name, None))
            continue
        proc = subprocess.run([sys.executable, str(path)],
                              capture_output=True, text=True)
        tally = next((line.strip() for line in reversed(proc.stdout.splitlines())
                      if "passed," in line), "")
        ok = proc.returncode == 0
        print(f"{'ok  ' if ok else 'FAIL'} {name:24s} {tally}")
        if not ok:
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
