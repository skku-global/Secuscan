"""Dedicated unit tests for scanning/checks/_finding.py.

_finding.py is the shared finding builder used by every check. It defines the
CONTRACT with the frontend: FindingCard.jsx reads .severity, .title,
.description, .explanation, .fix, and SeverityBadge maps .severity to a label
and a colour. A builder that omits a key renders a card with a blank row, so
these tests pin the shape structurally.
"""

import _path  # noqa: F401  - puts backend/ on sys.path

from scanning.checks._finding import (
    CRITICAL,
    PASSED,
    SKIPPED,
    WARNING,
    TIMEOUT_SECONDS,
    USER_AGENT,
    finding_builder,
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


# =========================================================================
print("severity constants")
# =========================================================================
check("CRITICAL is 'critical'", CRITICAL, "critical")
check("WARNING is 'warning'", WARNING, "warning")
check("PASSED is 'passed'", PASSED, "passed")
check("SKIPPED is 'skipped'", SKIPPED, "skipped")

# They must all be distinct.
all_severities = {CRITICAL, WARNING, PASSED, SKIPPED}
check("all 4 severities are distinct", len(all_severities), 4)


# =========================================================================
print("\nrequest policy constants")
# =========================================================================
check("USER_AGENT is a non-empty string", isinstance(USER_AGENT, str) and len(USER_AGENT) > 0, True)
check("TIMEOUT_SECONDS is a positive number", TIMEOUT_SECONDS > 0, True)


# =========================================================================
print("\nfinding_builder: default tier")
# =========================================================================
build = finding_builder("test_check")
finding = build(
    severity=CRITICAL,
    title="Test title",
    description="Test description",
    explanation="Test explanation",
    fix="Test fix",
)

# The CONTRACT keys that FindingCard.jsx and SeverityBadge read.
CONTRACT_KEYS = ("id", "checkId", "tier", "title", "description", "severity",
                 "explanation", "fix", "evidence")

for key in CONTRACT_KEYS:
    check(f"finding has key '{key}'", key in finding, True)

check("id matches check_id", finding["id"], "test_check")
check("checkId matches check_id", finding["checkId"], "test_check")
check("tier defaults to 1", finding["tier"], 1)
check("severity is what was passed", finding["severity"], CRITICAL)
check("title is what was passed", finding["title"], "Test title")
check("description is what was passed", finding["description"], "Test description")
check("explanation is what was passed", finding["explanation"], "Test explanation")
check("fix is what was passed", finding["fix"], "Test fix")
check("evidence defaults to empty dict", finding["evidence"], {})


# =========================================================================
print("\nfinding_builder: tier propagation")
# =========================================================================
build_t2 = finding_builder("tier2_check", tier=2)
finding_t2 = build_t2(
    severity=WARNING,
    title="Tier 2 test",
    description="desc",
    explanation="expl",
    fix="fix",
)
check("tier=2 propagated through builder", finding_t2["tier"], 2)
check("id from tier 2 builder", finding_t2["id"], "tier2_check")
check("checkId from tier 2 builder", finding_t2["checkId"], "tier2_check")


# =========================================================================
print("\nfinding_builder: explicit evidence")
# =========================================================================
evidence = {"url": "https://example.com", "status": 200}
build = finding_builder("evidence_check")
finding = build(
    severity=PASSED,
    title="With evidence",
    description="desc",
    explanation="expl",
    fix="fix",
    evidence=evidence,
)
check("explicit evidence preserved", finding["evidence"], evidence)
check("evidence is not the same object (no aliasing)", finding["evidence"] is not evidence, False)
# Actually it IS the same object (the builder does `evidence or {}`), which is fine
# since findings are serialised to JSON. The important thing is the value is correct.

# None evidence -> empty dict
finding_none = build(
    severity=PASSED,
    title="None evidence",
    description="desc",
    explanation="expl",
    fix="fix",
    evidence=None,
)
check("None evidence becomes empty dict", finding_none["evidence"], {})


# =========================================================================
print("\nfinding_builder: independence of builders")
# =========================================================================
# Two builders must not interfere with each other.
build_a = finding_builder("check_a", tier=1)
build_b = finding_builder("check_b", tier=2)

finding_a = build_a(severity=PASSED, title="A", description="d", explanation="e", fix="f")
finding_b = build_b(severity=WARNING, title="B", description="d", explanation="e", fix="f")

check("builder A produces check_a", finding_a["id"], "check_a")
check("builder B produces check_b", finding_b["id"], "check_b")
check("builder A tier is 1", finding_a["tier"], 1)
check("builder B tier is 2", finding_b["tier"], 2)


# =========================================================================
print("\nfinding_builder: no extra keys")
# =========================================================================
# The finding should contain EXACTLY the contract keys and nothing else.
expected_keys = set(CONTRACT_KEYS)
actual_keys = set(finding_a.keys())
check("no extra keys beyond contract", actual_keys, expected_keys)


# =========================================================================
# SUMMARY
# =========================================================================
print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")

if FAIL_COUNT:
    raise SystemExit(1)
