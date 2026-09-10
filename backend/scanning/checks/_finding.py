"""
THE SHARED FINDING BUILDER - one definition of what a finding looks like.

WHY THIS FILE EXISTS NOW AND NOT BEFORE
https_check.py and headers_check.py each carried a private _build_finding, and
headers_check.py said out loud why that was acceptable:

    "Duplicated rather than shared for now: two copies of two constants is
     cheaper than a shared module that every future check has to be wired into,
     and the moment there is a third copy is the moment to extract it."

Five new checks arrived at once. This is that moment, and the note was the plan.

WHAT THE DUPLICATION WAS ACTUALLY RISKING
The finding dict is a CONTRACT with the frontend. FindingCard.jsx reads .severity,
.title, .description, .explanation and .fix, and SeverityBadge maps .severity to a
label and a colour. A check that omits a key renders a card with a blank row - on
that check only, on that one code path only, which is the hardest kind of bug to
notice. Seven files each free to forget a key is seven chances to ship a report
with a hole in it. One builder makes the shape structural instead of remembered.

THE LEADING UNDERSCORE IN THE FILENAME is the same convention as _build_finding
itself: this module is internal to scanning/checks/. Nothing outside the package
should import it, because nothing outside the package should be building findings.
"""


# --- Severity vocabulary ---------------------------------------------------

# WHY THESE ARE NAMED CONSTANTS AND NOT JUST STRINGS
# `severity="critcal"` is a typo that Python cannot catch: it is a perfectly valid
# string, so the check runs, the finding is stored, and engine.py's
# PENALTY_BY_SEVERITY.get(..., 0) quietly scores it as harmless. A misspelled
# CRITCAL is an ImportError at startup instead - loud, immediate, and before any
# traffic. Same reasoning as exporting an enum rather than passing magic strings.
CRITICAL = "critical"
WARNING = "warning"
PASSED = "passed"

# THE FOURTH SEVERITY, added with the Tier 1 expansion.
#
# WHY IT HAD TO EXIST: three of the seven checks depend on finding a login or
# signup page, and plenty of sites have neither. Before this, "I could not test
# this" had to be reported as a WARNING, which costs score - so a brochure site
# with no login form was marked down for not having one. That is not a security
# finding, it is a coverage gap, and conflating the two makes the score dishonest
# in the one direction a security product cannot afford.
#
# It carries a zero penalty in engine.py. The finding is still RETURNED and still
# rendered, so the report says plainly which checks did not run - the alternative
# considered was dropping the finding entirely, and a silently shorter list means a
# client cannot tell a check that was skipped from one that never existed.
SKIPPED = "skipped"


# --- Shared request policy -------------------------------------------------

# Identify the scanner honestly. A site owner reading their access log should be
# able to tell who hit them and why - that matters for a consent-based service.
#
# This once said it mattered MOST for the rate-limiting check, "whose traffic is
# the one thing here that could be mistaken for an attack". That check is now
# passive and sends nothing (see rate_limit_check.py), so Tier 1 is entirely GET
# requests for pages a visitor would fetch anyway. The honest identification is
# kept regardless: a scan that has to hide what it is has answered the question of
# whether it should be running.
USER_AGENT = "SecuScan/0.1 (+security audit; authorised scans only)"

# Long enough for a slow-but-alive server, short enough that a dead host does not
# hold the API request open. Now that the checks run concurrently (see engine.py)
# this is close to the whole scan's worst-case duration rather than one seventh of
# it, which is what made the parallelism worth doing.
TIMEOUT_SECONDS = 10.0


# --- The builder -----------------------------------------------------------


# WHY A FACTORY RATHER THAN A PLAIN FUNCTION
# The obvious shared version takes check_id as its first argument:
#
#     build_finding(CHECK_ID, severity=..., title=...)
#
# ...which means every one of the ~30 existing call sites has to pass CHECK_ID,
# every time, and any that forgets gets a finding attributed to the wrong check.
# Instead each module calls this ONCE at import to get a builder that already knows
# its own id:
#
#     _build_finding = finding_builder(CHECK_ID)
#
# and every call site below stays exactly as it was written. That is why extracting
# this changed one line in each existing check instead of twenty.
#
# PYTHON-SPECIFIC: this is a CLOSURE. `build` is defined inside finding_builder and
# refers to check_id, which is finding_builder's parameter - so the returned
# function keeps that value alive after finding_builder has finished. This is the
# same mechanism as a JS function returning an arrow function that closes over an
# argument; Python just does it with `def` inside `def`.
def finding_builder(check_id: str, tier: int = 1):
    def build(
        severity: str,
        title: str,
        description: str,
        explanation: str,
        fix: str,
        evidence: dict | None = None,
    ) -> dict:
        # PYTHON-SPECIFIC: `severity: str` and `-> dict` are TYPE HINTS -
        # documentation and tooling aids, NOT runtime enforcement. Passing an int
        # would not raise. The closest JS analogue is TypeScript, except TS blocks
        # the build and Python does not.
        #
        # PYTHON-SPECIFIC: `dict | None = None` means "a dict or nothing,
        # defaulting to nothing". None is Python's null.
        return {
            # BOTH KEYS, DELIBERATELY, and they hold the same value. `id` is what
            # React uses for its list key; `checkId` is what FindingCard prints at
            # the bottom of an expanded card. They are one value today and might
            # not always be - a re-scan that reported the same check twice would
            # need distinct ids and the same checkId - so the distinction is kept
            # rather than collapsed.
            "id": check_id,
            "checkId": check_id,
            # TIER IDENTIFIER: 1 for passive external checks, 2 for authenticated
            # access-gated deep checks. Lets UI badges and reports cleanly distinguish tiers.
            "tier": tier,
            "title": title,
            "description": description,
            "severity": severity,
            "explanation": explanation,
            "fix": fix,
            # Beyond the frontend contract: what was actually OBSERVED. The UI
            # ignores keys it does not know, so carrying it costs nothing on the
            # page - and it is written to MongoDB, which is what makes a finding
            # auditable months later. A security report you cannot re-check is
            # worth very little.
            #
            # PYTHON-SPECIFIC: `evidence or {}` supplies an empty dict when the
            # caller passed nothing, because None is falsy. Storing None here would
            # make every consumer test for it.
            "evidence": evidence or {},
        }

    return build
