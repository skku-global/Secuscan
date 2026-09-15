"""
THE SCAN ENGINE - the layer between the API and the individual checks.

WHY THIS FILE EXISTS
main.py should not know that https_check exists, and https_check should not know
that an HTTP API exists. This file is the seam between them. It owns exactly four
responsibilities:

  1. finding the site's login and signup pages ONCE, before anything runs,
  2. knowing WHICH checks to run,
  3. running them concurrently and collecting the findings,
  4. turning that pile of findings into one scan result with a score.

The payoff is that adding the next check touches only the CHECKS list below. No
endpoint changes, no frontend changes - the response shape is defined here, once.
"""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

# PYTHON-SPECIFIC: a RELATIVE import. The leading dot means "starting from this
# package", so `.checks.https_check` is scanning/checks/https_check.py. This is
# why the __init__.py files matter - without them there is no package for the dot
# to be relative to. Rough JS equivalent: `from './checks/https_check'`.
from .checks._finding import CRITICAL, PASSED, SKIPPED, WARNING
from .checks.cookies_check import check_cookies
from .checks.exposure_check import check_exposure
from .checks.headers_check import check_headers
from .checks.https_check import check_https
from .checks.mfa_check import check_mfa
from .checks.password_check import check_password
from .checks.rate_limit_check import check_rate_limit
from .checks.account_enumeration_check import check_account_enumeration
from .checks.session_cookie_check import check_session_cookie
from .checks.logout_check import check_logout
from .checks.password_reset_check import check_password_reset
from .checks.two_factor_check import check_two_factor
from .discovery import ScanTarget, discover
from credentials import scrub_credentials

# THE CHECK REGISTRY - split into tiers.
# Tier 1 checks are passive, non-intrusive external checks running on all scans.
# Tier 2 checks are deep, active, access-gated checks requiring client-provided test account credentials.
TIER1_CHECKS = [
    check_https,
    check_headers,
    check_cookies,
    check_exposure,
    check_mfa,
    check_rate_limit,
    check_password,
]

TIER2_CHECKS = [
    check_account_enumeration,
    check_session_cookie,
    check_logout,
    check_password_reset,
    check_two_factor,
]

# Kept for backwards compatibility with tests and callers expecting CHECKS
CHECKS = TIER1_CHECKS


# --- Scoring ---------------------------------------------------------------

# HOW MUCH CREDIT EACH RESULT EARNS, as a fraction of the check's weight.
#
# WHY THIS REPLACED FLAT PENALTIES. The old scheme subtracted 40 points per
# critical and 15 per warning from 100. That was fine for two checks and breaks at
# five: five criticals is -200, so a site failing three checks and a site failing
# all five both report 0, and the number stops distinguishing the cases it exists
# to distinguish. Worse, every check added made the scale harsher without anyone
# choosing that - the policy drifted as a side effect of shipping features.
#
# Credit-based scoring is proportional instead: the score is the share of applicable
# checks passed, so adding a sixth check changes what the score MEASURES without
# changing how severely it punishes. A warning earns half credit because "real,
# worth fixing, not an emergency" is genuinely between a pass and a failure.
SEVERITY_CREDIT = {
    PASSED: 1.0,
    WARNING: 0.5,
    CRITICAL: 0.0,
}

# SKIPPED is deliberately absent from the map above, and that absence is the whole
# mechanism. A skipped check is dropped from the numerator AND the denominator, so
# it neither costs score nor inflates it - a brochure site with no login is scored
# out of the checks that could actually be applied to it. This is what _finding.py
# means by "it carries a zero penalty": not zero credit, but no participation.
#
# Named here rather than left implicit so that a future check returning some new
# severity fails loudly (see below) instead of quietly scoring as harmless.
UNSCORED_SEVERITIES = {SKIPPED}


# WHY THIS EXISTS
# A client cannot act on seven separate findings without some sense of "how bad is
# this overall". The number is a communication device, not a measurement, so the
# formula is deliberately simple and stated in one place where it can be argued
# with.
#
# EVERY CHECK CARRIES EQUAL WEIGHT, which is the most arguable decision here: a
# site served over plain HTTP is in worse shape than one that merely does not
# advertise MFA, and this scores them the same. Per-check weights are the obvious
# refinement, and they are not here yet because a weight table is a second policy
# to defend and equal weighting is at least honestly uniform. When it changes, it
# changes in this function and nowhere else.
def calculate_score(findings: list) -> int:
    # PYTHON-SPECIFIC: `list` as a type hint is the same idea as `dict` elsewhere -
    # documentation, not enforcement.
    earned = 0.0
    scored = 0

    for finding in findings:
        severity = finding["severity"]

        if severity in UNSCORED_SEVERITIES:
            continue

        # .get() with a default of 0.0 means an unrecognised severity is counted as
        # a failure rather than skipped. That is the safe direction: a malformed
        # check drags the score down and gets noticed, where scoring it as harmless
        # would hide it. It still cannot crash the scan.
        earned += SEVERITY_CREDIT.get(severity, 0.0)
        scored += 1

    if scored == 0:
        # Unreachable with the current registry - check_https and check_headers
        # always return a scoreable severity, even when the site is unreachable - so
        # this branch means the CHECKS list is empty or every check raised, which is
        # a bug in the scanner rather than a fact about the site.
        #
        # It returns 0 rather than 100 on purpose: a scan that tested nothing must
        # not render as a clean bill of health. An empty report scoring zero is an
        # obvious defect; a green 100 with no findings is a lie that looks fine.
        return 0

    # PYTHON-SPECIFIC: round() returns an int when called with one argument, which
    # is what the frontend's ScoreGauge expects. Python 3 rounds halves to even
    # (round(2.5) == 2), which is irrelevant at this precision but surprising if
    # you go looking for it.
    return round(100 * earned / scored)


# --- Running the checks ----------------------------------------------------


# WHY A CHECK THAT RAISES MUST NOT END THE SCAN
# Every check parses somebody else's HTML, headers and cookies. That input is
# arbitrary, so a check CAN raise on a shape nobody anticipated - and the cost of
# letting that propagate is a 500 for the whole scan, losing four good findings
# because the fifth hit an edge case. So a crash is converted into a finding: the
# report says which check failed and that its result is missing, which is both
# honest to the client and far easier to debug than a stack trace in a log.
#
# It is deliberately a WARNING and never a PASSED. A check that crashed observed
# nothing, and nothing observed can never be reported as nothing wrong.
def _crash_finding(check_name: str, exc: BaseException, tier: int = 1) -> dict:
    return {
        "id": check_name,
        "checkId": check_name,
        # WHY tier IS HERE AND WAS NOT BEFORE
        # Every finding a check builds carries a tier, because _finding.py's builder puts
        # one on unconditionally - and the report splits the two tiers into separate
        # sections by reading it. This dict is assembled by hand rather than through that
        # builder, so it was the one finding in the system with no tier on it: a crashed
        # Tier 2 check rendered in the Tier 1 section, filed under checks the client did
        # not pay for and did not run. The caller passes the tier of the registry the
        # check came from, which is the only place that knows it.
        "tier": tier,
        "title": "A check could not be completed",
        "description": f"The {check_name} check stopped with an internal error",
        "severity": WARNING,
        "explanation": (
            f"This check did not finish: it stopped with {type(exc).__name__}. That "
            "is a fault in the scanner, not a finding about the site - nothing was "
            "observed here, so nothing is claimed either way. The rest of the report "
            "is unaffected.\n\nThe result for this check is missing rather than "
            "passing, because a check that did not run cannot report a clean result."
        ),
        "fix": (
            "No action on your side. Re-run the scan; if the same check fails again, "
            "this is worth reporting to us with the address you scanned."
        ),
        # The exception TYPE, never str(exc) - an exception message can carry a
        # fragment of the target's response, and this document is stored and shown.
        "evidence": {"error": type(exc).__name__, "check": check_name},
    }


# WHY THIS EXISTS
# This is the function the API calls, and the only thing main.py knows about the
# scanning system. It exists so that the endpoint stays a thin translation layer:
# take a request, call run_scan, return JSON. All scanning logic lives behind this
# one door, which is what will let the same engine later be driven by a scheduled
# re-scan job instead of an HTTP request.
#
# The returned dictionary matches the scan contract the frontend renders, key for
# key - see frontend/src/hooks/useScan.js and components/FindingCard.jsx.
#
# login_url is optional and comes from the client when it knows better than
# discovery does. It is threaded through rather than guessed at because a site
# whose login lives somewhere unconventional otherwise gets three checks skipped
# for no reason. discovery still refuses an off-host value - see _same_site there.
async def run_scan(
    url: str,
    login_url: str | None = None,
    tier: int = 1,
    credentials: dict | None = None,
) -> dict:
    # DISCOVERY RUNS ONCE, BEFORE ANY CHECK.
    try:
        if tier == 2:
            active_checks = TIER1_CHECKS + TIER2_CHECKS
        else:
            active_checks = TIER1_CHECKS

        try:
            target = await discover(url, login_url, credentials=credentials)
        except Exception:
            # Discovery already treats an unreachable host as "found nothing" rather
            # than an error, so this catches only the genuinely unexpected. A bare
            # target still lets check_https run - it makes its own request - so a
            # discovery fault degrades the scan instead of failing it.
            target = ScanTarget(url=url, credentials=credentials)
            target.notes.append(
                "Endpoint discovery could not be completed, so the checks that read the "
                "login and signup pages were skipped."
            )

        # PYTHON-SPECIFIC: asyncio.gather is the equivalent of Promise.all - it starts
        # every coroutine and waits for all of them.
        results = await asyncio.gather(
            *(check(target) for check in active_checks),
            return_exceptions=True,
        )

        # PYTHON-SPECIFIC: zip() pairs the registry with the results.
        findings = []
        for check, result in zip(active_checks, results):
            if isinstance(result, BaseException):
                # The tier comes from the registry the check is actually in, not from the
                # scan's tier: a Tier 1 check crashing during a Tier 2 scan is still a
                # Tier 1 result and belongs in that section of the report.
                check_tier = 2 if check in TIER2_CHECKS else 1
                findings.append(_crash_finding(check.__name__, result, tier=check_tier))
            else:
                findings.append(result)

        return {
            "id": uuid4().hex[:8],
            "targetUrl": url,
            "scannedAt": datetime.now(timezone.utc).isoformat(),
            "tier": tier,
            "paymentStatus": "active",
            "score": calculate_score(findings),
            "findings": findings,
            "discovery": {
                "notes": list(target.notes),
                "loginUrl": target.login.url if target.login else None,
                "signupUrl": target.signup.url if target.signup else None,
                "loginWasSupplied": target.login_was_supplied,
            },
        }
    finally:
        # Zeroize client-provided test account credentials in memory immediately after scan completion
        scrub_credentials(credentials)
        if "target" in locals() and hasattr(target, "credentials"):
            scrub_credentials(target.credentials)

