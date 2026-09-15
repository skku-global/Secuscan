"""Dedicated unit tests for scanning/engine.py.

engine.py is the layer between the API and the checks. It owns:
  1. which checks to run (TIER1_CHECKS, TIER2_CHECKS),
  2. running them and collecting findings,
  3. scoring (calculate_score),
  4. crash handling (_crash_finding).

test_engine_e2e.py tests the engine end-to-end against a real HTTP fixture.
This file tests the engine's own logic in isolation, with synthetic findings
and mocked checks.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import _path  # noqa: F401  - puts backend/ on sys.path

from scanning.checks._finding import CRITICAL, PASSED, SKIPPED, WARNING
from scanning.engine import (
    CHECKS,
    SEVERITY_CREDIT,
    TIER1_CHECKS,
    TIER2_CHECKS,
    UNSCORED_SEVERITIES,
    _crash_finding,
    calculate_score,
    run_scan,
)

PASS_COUNT = 0
FAIL_COUNT = 0


def check(label, got, want):
    global PASS_COUNT, FAIL_COUNT
    ok = got == want
    if ok:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    mark = "ok  " if ok else "FAIL"
    detail = "" if ok else f"   (got {got!r}, wanted {want!r})"
    print(f"  {mark} {label}{detail}")


def finding(severity, check_id="test"):
    """Build a minimal finding dict for scoring tests."""
    return {"severity": severity, "id": check_id, "checkId": check_id}


# =========================================================================
print("calculate_score: basic cases")
# =========================================================================

check("all PASSED -> 100", calculate_score([finding(PASSED)] * 5), 100)
check("all CRITICAL -> 0", calculate_score([finding(CRITICAL)] * 5), 0)
check("all WARNING -> 50", calculate_score([finding(WARNING)] * 4), 50)

# Mixed: 1 PASSED + 1 CRITICAL = 50% credit from 2 scored checks = 50
check("1 pass + 1 critical -> 50",
      calculate_score([finding(PASSED), finding(CRITICAL)]), 50)

# 2 PASSED + 1 WARNING = (1 + 1 + 0.5) / 3 = 83.33... -> 83
check("2 pass + 1 warning -> 83",
      calculate_score([finding(PASSED), finding(PASSED), finding(WARNING)]), 83)


# =========================================================================
print("\ncalculate_score: SKIPPED handling")
# =========================================================================
# SKIPPED drops from both numerator and denominator.

check("all SKIPPED -> 0 (no scored checks)",
      calculate_score([finding(SKIPPED)] * 3), 0)

# 1 PASSED + 2 SKIPPED = 100% (scored count is 1)
check("1 pass + 2 skipped -> 100",
      calculate_score([finding(PASSED), finding(SKIPPED), finding(SKIPPED)]), 100)

# 1 CRITICAL + 1 SKIPPED = 0% (scored count is 1)
check("1 critical + 1 skipped -> 0",
      calculate_score([finding(CRITICAL), finding(SKIPPED)]), 0)


# =========================================================================
print("\ncalculate_score: edge cases")
# =========================================================================

check("empty list -> 0", calculate_score([]), 0)

# Unknown severity falls through to 0.0 credit (safe direction).
check("unknown severity -> treated as failure (0 credit)",
      calculate_score([finding("unknown")]), 0)

# 1 passed + 1 unknown = (1.0 + 0.0) / 2 = 50
check("1 pass + 1 unknown -> 50",
      calculate_score([finding(PASSED), finding("mystery")]), 50)

# Single findings
check("single PASSED -> 100", calculate_score([finding(PASSED)]), 100)
check("single CRITICAL -> 0", calculate_score([finding(CRITICAL)]), 0)
check("single WARNING -> 50", calculate_score([finding(WARNING)]), 50)


# =========================================================================
print("\ncalculate_score: severity credit map integrity")
# =========================================================================
check("PASSED credit is 1.0", SEVERITY_CREDIT[PASSED], 1.0)
check("WARNING credit is 0.5", SEVERITY_CREDIT[WARNING], 0.5)
check("CRITICAL credit is 0.0", SEVERITY_CREDIT[CRITICAL], 0.0)
check("SKIPPED not in credit map", SKIPPED not in SEVERITY_CREDIT, True)
check("SKIPPED in unscored set", SKIPPED in UNSCORED_SEVERITIES, True)


# =========================================================================
print("\n_crash_finding: shape and content")
# =========================================================================
exc = ValueError("something broke")
crash = _crash_finding("test_check", exc)

check("crash id", crash["id"], "test_check")
check("crash checkId", crash["checkId"], "test_check")
check("crash severity is WARNING", crash["severity"], WARNING)
check("crash has title", "title" in crash, True)
check("crash has description", "description" in crash, True)
check("crash has explanation", "explanation" in crash, True)
check("crash has fix", "fix" in crash, True)
check("crash has evidence", "evidence" in crash, True)
check("crash evidence has error type", crash["evidence"]["error"], "ValueError")
check("crash evidence has check name", crash["evidence"]["check"], "test_check")

# The exception MESSAGE must not leak into the finding (it could contain
# fragments of the target's response).
check("crash does not contain exception message",
      "something broke" not in str(crash), True)


# =========================================================================
print("\n_crash_finding: tier propagation")
# =========================================================================
crash_t1 = _crash_finding("check_a", exc, tier=1)
crash_t2 = _crash_finding("check_b", exc, tier=2)
check("crash tier=1", crash_t1["tier"], 1)
check("crash tier=2", crash_t2["tier"], 2)

# Default tier is 1
crash_default = _crash_finding("check_c", exc)
check("crash default tier is 1", crash_default["tier"], 1)


# =========================================================================
print("\nregistry: check counts and structure")
# =========================================================================
check("7 Tier 1 checks", len(TIER1_CHECKS), 7)
check("5 Tier 2 checks", len(TIER2_CHECKS), 5)
check("CHECKS is TIER1_CHECKS (backward compat)", CHECKS is TIER1_CHECKS, True)

# No check appears in both tiers.
t1_set = set(TIER1_CHECKS)
t2_set = set(TIER2_CHECKS)
check("no overlap between tiers", len(t1_set & t2_set), 0)

# Every check is a callable.
for c in TIER1_CHECKS + TIER2_CHECKS:
    check(f"{c.__name__} is callable", callable(c), True)


# =========================================================================
print("\nrun_scan: tier 1 only (mocked checks)")
# =========================================================================

run = asyncio.run


async def mock_check_pass(target):
    return finding(PASSED, "mock_pass")


async def mock_check_warn(target):
    return finding(WARNING, "mock_warn")


async def mock_check_crash(target):
    raise RuntimeError("boom")


# Patch the registries to use our mocks.
with patch("scanning.engine.TIER1_CHECKS", [mock_check_pass, mock_check_warn]):
    with patch("scanning.engine.TIER2_CHECKS", [mock_check_crash]):
        result = run(run_scan("https://example.com", tier=1))

check("tier 1 scan has 2 findings", len(result["findings"]), 2)
check("tier 1 scan tier field", result["tier"], 1)
check("tier 1 scan has score", isinstance(result["score"], int), True)
check("tier 1 scan has targetUrl", result["targetUrl"], "https://example.com")
check("tier 1 scan has id", len(result["id"]) > 0, True)
check("tier 1 scan has scannedAt", "scannedAt" in result, True)
check("tier 1 scan has discovery", "discovery" in result, True)


# =========================================================================
print("\nrun_scan: tier 2 includes both tiers")
# =========================================================================

with patch("scanning.engine.TIER1_CHECKS", [mock_check_pass]):
    with patch("scanning.engine.TIER2_CHECKS", [mock_check_warn]):
        result = run(run_scan("https://example.com", tier=2))

check("tier 2 scan has 2 findings (T1+T2)", len(result["findings"]), 2)
check("tier 2 scan tier field", result["tier"], 2)


# =========================================================================
print("\nrun_scan: crash resilience")
# =========================================================================

with patch("scanning.engine.TIER1_CHECKS", [mock_check_pass, mock_check_crash]):
    with patch("scanning.engine.TIER2_CHECKS", []):
        result = run(run_scan("https://example.com", tier=1))

check("crash does not abort scan", len(result["findings"]), 2)
crashed = [f for f in result["findings"] if f["severity"] == WARNING and
           f.get("evidence", {}).get("error") == "RuntimeError"]
check("crashed check produces a WARNING finding", len(crashed), 1)
passed = [f for f in result["findings"] if f["severity"] == PASSED]
check("good check still passes", len(passed), 1)


# =========================================================================
print("\nrun_scan: discovery failure is not fatal")
# =========================================================================

with patch("scanning.engine.TIER1_CHECKS", [mock_check_pass]):
    with patch("scanning.engine.TIER2_CHECKS", []):
        with patch("scanning.engine.discover", side_effect=Exception("dns broke")):
            result = run(run_scan("https://unreachable.example", tier=1))

check("discovery failure still produces a result", "findings" in result, True)
check("discovery failure: scan has findings", len(result["findings"]) >= 1, True)
check("discovery notes mention failure",
      any("discovery" in n.lower() for n in result["discovery"]["notes"]), True)


# =========================================================================
# SUMMARY
# =========================================================================
print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")

if FAIL_COUNT:
    raise SystemExit(1)
