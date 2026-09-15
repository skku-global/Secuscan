"""
ACCOUNT ENUMERATION CHECK — Tier 2, Check #5.

WHY THIS FILE EXISTS
Account enumeration (CWE-204: Response Discrepancy Information Exposure) occurs when an
application's authentication, registration, or password-recovery endpoints reveal whether
a specific username or email address is registered in the system.

Common leakage vectors include:
  1. Differential error messages:
     e.g., "User not found" vs. "Incorrect password", or "Invalid email" vs. "Bad password".
  2. Differential response codes:
     e.g., HTTP 404 for missing accounts vs. HTTP 401 for wrong passwords.
  3. Response timing discrepancy:
     When an account exists, the server computes a slow cryptographic password hash
     (e.g., bcrypt / argon2), taking ~100–300ms. If nonexistent accounts are rejected early
     before hashing, the response returns in ~5–15ms, exposing user existence via timing side-channel.

WHY THIS IS A TIER 2 CHECK
Unlike Tier 1 checks which are strictly passive and read-only, this check requires an active,
authorized test account username provided by the client. It submits probes to the login/auth
endpoint comparing the application's treatment of the known client test account against
a randomized non-existent account.

CRITICAL SECURITY & AUDITING RULE:
The client-provided password is NEVER sent in this check or logged in any finding evidence.
Both probes submit an identical dummy, non-functional candidate password. The only information
sought is whether the server responds differently when the username is known versus unknown.
"""

import json
import logging
import re
import time
from statistics import median
from urllib.parse import urljoin
from uuid import uuid4

import httpx

from ._finding import PASSED, SKIPPED, WARNING, TIMEOUT_SECONDS, USER_AGENT, finding_builder
from ._session import _BLOCKED_HINTS, _BLOCKED_STATUSES, _field_names, visible_text

_log = logging.getLogger("checks.account_enumeration")

CHECK_ID = "account_enumeration_check"

# Tier 2 finding builder: stamps findings with "tier": 2
_build_finding = finding_builder(CHECK_ID, tier=2)

# Distinctive error strings indicating explicit account existence or absence
USER_NOT_FOUND_HINTS = re.compile(
    r"(user (not found|doesn't exist|does not exist)|no (such )?user|"
    r"email (not found|not registered|does not exist)|account (not found|does not exist)|"
    r"unregistered email|unknown account)",
    re.I,
)

# Responses that mean the probe was turned away before the application ever looked up
# an account. These are the false-PASS family: they come back identical for both probes,
# which is this check's success condition, while testing nothing whatsoever.
#
# IMPORTED, NOT COPIED. This was a local copy that had drifted from _session.py's - it
# never learned the WAF product names, so a scan stopped by Cloudflare produced two
# identical interstitials and read as a clean pass. See the note on _BLOCKED_HINTS there.
BLOCKED_HINTS = _BLOCKED_HINTS

WRONG_PASSWORD_HINTS = re.compile(
    r"(incorrect password|wrong password|invalid password|bad password|"
    r"password does not match|password is incorrect)",
    re.I,
)


# Statuses that mean the request was turned away before any account lookup happened.
# Both probes get the same one, which is indistinguishable from a clean pass unless it
# is checked for explicitly. Same list, same reason, same object as _session.py's.
_PRE_AUTH_STATUSES = _BLOCKED_STATUSES

# A 404 IS NOT A WALL AND IT IS CERTAINLY NOT A PASS. Kept separate from the wall set
# above, and local to this file, because the two mean different things to a reader and
# to _session: a wall is something standing in front of the application, while this is
# the application saying there is nothing here at all. No authentication logic runs at a
# 404, so two 404s cannot be evidence about account existence - yet they are byte for
# byte identical, which is this check's PASS condition. The report then read "returned
# identical HTTP 404 responses" as a clean bill of health, most easily reached by the
# /api/login fallback below, which is a guess by construction.
#
# BOTH sides must be in this set, exactly as with the wall gate, and here that is not a
# detail: 404 for an unknown account against 401 for a known one is the single most
# blatant shape this leak takes, and section 3 of the suite pins it. A guard that fired
# on either side alone would delete the check's best finding.
_NO_ENDPOINT_STATUSES = frozenset({404, 410})


def _mask_account(value: str) -> str:
    """Mask a client-supplied test account identifier for report evidence.

    The client supplied this address and the report goes back to the client, so this
    is not a secrecy boundary so much as a hygiene one: a scan report is a document
    that gets forwarded, pasted into tickets and archived, and half of a credential
    pair does not need to be legible in it for the reader to know which account was
    tested. The domain is kept because that is the part that identifies the system.
    """
    value = (value or "").strip()

    if "@" in value:
        local, _, domain = value.partition("@")
        head = local[:2] if len(local) > 2 else local[:1]
        return f"{head}{'*' * max(len(local) - len(head), 1)}@{domain}"

    if len(value) <= 2:
        return "*" * len(value)

    return f"{value[:2]}{'*' * (len(value) - 2)}"


def _extract_error_message(response: httpx.Response) -> str:
    """Extract human-readable error text from JSON or HTML response."""
    try:
        data = response.json()
        if isinstance(data, dict):
            for key in ("error", "message", "detail", "msg", "errors", "description"):
                val = data.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
                if isinstance(val, list) and val and isinstance(val[0], str):
                    return val[0].strip()
        elif isinstance(data, list) and data and isinstance(data[0], str):
            return data[0].strip()
    except Exception:
        pass

    # The visible text, which drops script and style bodies before the tags. This check
    # compares two messages for being distinguishable, so an inline script is doubly
    # dangerous here: it ships the site's whole error vocabulary ("user not found",
    # "invalid password") to BOTH probes identically, which both plants the hints this
    # check searches for and makes the two responses look reassuringly the same.
    return visible_text(response)[:300]


async def check_account_enumeration(target) -> dict:
    """Probe the authentication endpoint with existing vs nonexistent username and compare responses."""
    credentials = target.credentials or {}
    username = str(credentials.get("username") or "").strip()

    if not username:
        return _build_finding(
            severity=SKIPPED,
            title="Tier 2 test account credentials required",
            description="No test account username was provided for account enumeration verification",
            explanation=(
                "Account enumeration verification is a Tier 2 active audit check that tests "
                "whether your authentication service exposes account existence by comparing "
                "the server's response to an existing account versus an unregistered account.\n\n"
                "To run this check, provide the username/email of a dedicated test account in "
                "the Tier 2 access form."
            ),
            fix="Provide a dedicated test account username in the scan request to enable this check.",
            evidence={"reason": "missing_credentials_username"},
        )

    # Determine base host / URL
    base_url = str(credentials.get("stagingUrl") or target.url or "").strip()

    # WHICH FIELD NAMES TO POST UNDER - read from _session, not worked out again here.
    #
    # This file used to carry its own copy of that loop and its own copy of the username
    # name-hint, and the copy had every defect the shared one was fixed for: it tested the
    # NAME before the TYPE, so `<input type="submit" name="login">`, a "remember my
    # username" checkbox and a trailing OTP box all matched - and it assigned as it went,
    # so the LAST match won, which is precisely where those fields sit in a form. Three of
    # ten ordinary login forms went out under the wrong field name.
    #
    # THE COST HERE IS NOT A FAILED LOGIN, IT IS A FALSE PASSED. The username never
    # reaches the server, so both probes are turned away identically - and identical
    # responses are this check's pass condition. Against a mock that really does leak,
    # the same site reports WARNING with a plain form and PASSED once an ordinary submit
    # button named "login" is added to it. A customer who enumerates was told they do not.
    #
    # NEVER COPY BETWEEN CHECK MODULES, IMPORT. Third time this rule has been broken in
    # this directory, third time both copies had drifted. One difference is deliberate and
    # is an improvement: _field_names carries hidden CSRF fields through, where this copy
    # dropped them. An unusable token is detected as a wall and skipped; a missing one is
    # more likely to come back as a 400, which lands in the PASSED branch.
    username_field, password_field, extra_fields = _field_names(target)

    # Locate login form or login page endpoint
    login_form = target.login_form()
    submit_url = None
    method = "POST"

    if login_form is not None:
        submit_url = urljoin(target.login.url if target.login else base_url, login_form.submit_url or "")
        method = (login_form.method or "POST").upper()
    else:
        # Fallback to standard auth endpoints on target URL
        if target.login and target.login.url:
            submit_url = target.login.url
        else:
            submit_url = urljoin(base_url, "/api/login")

    # Construct two probes with an intentionally non-functional dummy password.
    # CRITICAL: We NEVER send or log the client's actual password.
    dummy_password = "SecuScanDummyProbeP@ssw0rd!#"
    nonexistent_user = f"secuscan_probe_{uuid4().hex[:10]}@example.invalid"

    payload_existing = {**extra_fields, username_field: username, password_field: dummy_password}
    payload_nonexistent = {**extra_fields, username_field: nonexistent_user, password_field: dummy_password}

    # WHY THE TIMING IS SAMPLED MORE THAN ONCE, AND WHY THE PROBES ALTERNATE
    # An earlier version of this check timed a single request of each and raised a
    # finding when they differed by more than 250ms. Two things made that unsound.
    #
    # The first request over a new connection pays for DNS, the TCP handshake and the
    # TLS handshake - and the existing-account probe was always the one that sent it.
    # So it was systematically the slower of the two, in precisely the direction that
    # raises this finding: the check manufactured its own evidence. On top of that, a
    # single sample of anything crossing a network varies by more than 250ms on its
    # own often enough to be worthless as a signal.
    #
    # So one throwaway request warms the connection and is not measured, the two probes
    # then alternate, and the verdict is taken on the MEDIAN of each set - which
    # discards a single outlier instead of reporting it.
    #
    # THE SAMPLE COUNT IS DELIBERATELY SMALL. Every existing-account round is a failed
    # login against a real account, and enough failed logins in a row will trip a
    # lockout policy - which would invalidate this check AND leave the client's test
    # account unusable for the rest of the scan. Three is enough for a median to throw
    # away one outlier and few enough to stay under the usual lockout thresholds.
    ROUNDS = 3

    times_existing: list[float] = []
    times_nonexistent: list[float] = []
    res_existing = None
    res_nonexistent = None

    async with httpx.AsyncClient(
        timeout=TIMEOUT_SECONDS,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/html"},
        follow_redirects=False,
    ) as client:

        async def send(payload):
            if method == "POST":
                # Send JSON if the endpoint looks like an API, otherwise form-encoded.
                if "/api/" in submit_url or "json" in submit_url:
                    return await client.post(submit_url, json=payload)
                return await client.post(submit_url, data=payload)
            return await client.get(submit_url, params=payload)

        try:
            # Warm-up, not measured. It deliberately uses the NONEXISTENT account, so
            # paying for the handshake does not cost the client's real test account an
            # extra failed login.
            await send(payload_nonexistent)

            for _ in range(ROUNDS):
                t0 = time.perf_counter()
                res_existing = await send(payload_existing)
                times_existing.append(time.perf_counter() - t0)

                t0 = time.perf_counter()
                res_nonexistent = await send(payload_nonexistent)
                times_nonexistent.append(time.perf_counter() - t0)

        except httpx.RequestError as exc:
            return _build_finding(
                severity=SKIPPED,
                title="Could not connect to authentication endpoint",
                description=f"Request to {submit_url} failed during account enumeration test",
                explanation=f"Connection error while probing {submit_url}: {exc}",
                fix="Verify the staging URL or login URL is reachable and accepts test connections.",
                evidence={"endpoint": submit_url, "error": str(exc)},
            )

    dur_existing = median(times_existing)
    dur_nonexistent = median(times_nonexistent)

    msg_existing = _extract_error_message(res_existing)
    msg_nonexistent = _extract_error_message(res_nonexistent)

    status_diff = res_existing.status_code != res_nonexistent.status_code
    timing_delta_ms = abs(dur_existing - dur_nonexistent) * 1000

    # Look for textual discrepancy
    has_not_found_hint = bool(USER_NOT_FOUND_HINTS.search(msg_nonexistent) or USER_NOT_FOUND_HINTS.search(res_nonexistent.text))
    has_wrong_pw_hint = bool(WRONG_PASSWORD_HINTS.search(msg_existing) or WRONG_PASSWORD_HINTS.search(res_existing.text))
    text_diff = (msg_existing != msg_nonexistent) and (has_not_found_hint or has_wrong_pw_hint)

    evidence = {
        "endpoint": submit_url,
        "method": method,
        "usernameField": username_field,
        "testedExistingUser": _mask_account(username),
        "timingSamplesPerAccount": ROUNDS,
        "statusCodeExisting": res_existing.status_code,
        "statusCodeNonexistent": res_nonexistent.status_code,
        "messageExisting": msg_existing[:150],
        "messageNonexistent": msg_nonexistent[:150],
        "timingExistingMs": round(dur_existing * 1000, 1),
        "timingNonexistentMs": round(dur_nonexistent * 1000, 1),
        "timingDeltaMs": round(timing_delta_ms, 1),
    }

    # WHY THERE IS A GUARD IN FRONT OF THE VERDICTS
    # Two identical responses are this check's PASS condition, and there is a whole
    # family of ways to get two identical responses that say nothing about account
    # enumeration at all: a CSRF token this check did not carry, a WAF, a rate limiter
    # that engaged partway through the rounds above, or a URL that was never the login
    # endpoint in the first place. Every one of those turns BOTH probes away before the
    # application ever looks up an account.
    #
    # Reporting that as "no account enumeration detected" is the worst thing this file
    # can do. A finding that says a control was verified when in truth nothing was
    # tested is more damaging than no finding at all, because it is the point at which
    # the client stops looking. So an endpoint that was never reached is SKIPPED, and
    # the finding says which wall the probes hit.
    #
    # BOTH statuses are tested against the pre-auth set, and they do NOT have to match.
    # Requiring them to be equal was a real gap, and the comment above named the case it
    # missed: "a rate limiter that engaged partway through the rounds above" turns the
    # later probe away with a DIFFERENT status from the earlier one - 403 then 429, say -
    # and the probes run alternately, so a limiter tripping mid-run lands on one and not
    # the other. That reached `status_diff` below and was reported as "the endpoint
    # returns different status codes for valid vs invalid accounts": a WARNING about
    # account enumeration, raised against a server that never looked up an account.
    # Neither 403 nor 429 says anything about whether an account exists, so when both
    # sides are pre-auth there is nothing to compare and the honest answer is SKIPPED.
    blocked_status = (
        res_existing.status_code in _PRE_AUTH_STATUSES
        and res_nonexistent.status_code in _PRE_AUTH_STATUSES
    )
    blocked_text = bool(
        BLOCKED_HINTS.search(msg_existing) and BLOCKED_HINTS.search(msg_nonexistent)
    )

    if (
        res_existing.status_code in _NO_ENDPOINT_STATUSES
        and res_nonexistent.status_code in _NO_ENDPOINT_STATUSES
    ):
        return _build_finding(
            severity=SKIPPED,
            title="No authentication endpoint was found to test",
            description=(
                "Both enumeration probes were answered with HTTP "
                f"{res_existing.status_code}, so there was no authentication logic to test"
            ),
            explanation=(
                f"Both probes to {submit_url} were answered with HTTP "
                f"{res_existing.status_code}. Nothing at that address looked up an "
                "account, so this check has no evidence either way.\n\n"
                "This usually means the scan could not find your sign-in form and fell "
                "back to a conventional path that your application does not use - a "
                "single-page application that authenticates through its own API is the "
                "common case.\n\n"
                "Reported as skipped rather than passed on purpose: two identical "
                "responses are what a passing result looks like here, and an address "
                "that answers nothing at all would otherwise read as a clean bill of "
                "health."
            ),
            fix=(
                "Enter your sign-in page or authentication endpoint directly in the "
                "Tier 2 access form and re-run the scan."
            ),
            evidence=evidence,
        )

    if blocked_status or blocked_text:
        return _build_finding(
            severity=SKIPPED,
            title="Authentication endpoint could not be tested",
            description=(
                "Both enumeration probes were rejected before reaching the "
                "authentication logic, so account enumeration was not tested"
            ),
            explanation=(
                f"Both probes to {submit_url} were turned away before the application "
                f"appeared to look up an account (HTTP {res_existing.status_code} for the "
                f"existing account, HTTP {res_nonexistent.status_code} for the "
                "nonexistent one).\n\n"
                "This usually means one of: the endpoint requires a CSRF token or nonce "
                "that this check does not carry, a WAF or bot filter intercepted the "
                "request, rate limiting engaged during the probe rounds, or the URL "
                "tested is not the login endpoint.\n\n"
                "This is reported as skipped rather than passed on purpose. Identical "
                "responses are what a passing result looks like, and reporting a wall "
                "as a clean bill of health would be actively misleading."
            ),
            fix=(
                "Provide a direct authentication endpoint in the Tier 2 access form, or "
                "allowlist the scanner's source address for the duration of the scan, so "
                "the probes reach the authentication logic."
            ),
            evidence=evidence,
        )

    # Case 1: Direct message discrepancy (e.g. "User not found" vs "Incorrect password")
    if text_diff or (has_not_found_hint and not has_wrong_pw_hint):
        return _build_finding(
            severity=WARNING,
            title="Account enumeration via error messages",
            description="The authentication endpoint reveals whether an account exists via differential error messages",
            explanation=(
                f"When submitting invalid credentials, the endpoint {submit_url} responded with different "
                f"error messages depending on whether the username exists in the system:\n\n"
                f"- Existing user: \"{msg_existing[:100]}\"\n"
                f"- Nonexistent user: \"{msg_nonexistent[:100]}\"\n\n"
                "This allows an attacker to compile a list of valid accounts, usernames, or email addresses "
                "prior to launching password-spraying or credential-stuffing attacks."
            ),
            fix=(
                "Use generic error messages across all authentication and password-reset flows. "
                "Always return a unified message such as \"Invalid username or password\" regardless "
                "of whether the account exists."
            ),
            evidence=evidence,
        )

    # Case 2: Status code discrepancy (e.g. 401 for wrong password, 404 for wrong user)
    # THE 200 RESPONSE IS NOT AN EXCEPTION. An earlier version required BOTH statuses
    # to be non-200 before reporting a discrepancy, which quietly excluded the single
    # most blatant shape this leak takes: 200 for one account and 401 or 302 for the
    # other. When both probes are 200 there is no discrepancy to report anyway, so the
    # condition only ever suppressed the case worth reporting. Both probes sent the
    # same wrong password; the only variable is whether the account exists, so any
    # difference in status is attributable to that.
    if status_diff:
        return _build_finding(
            severity=WARNING,
            title="Account enumeration via HTTP status codes",
            description="The authentication endpoint returns different HTTP status codes for valid vs invalid accounts",
            explanation=(
                f"The authentication endpoint returned HTTP {res_existing.status_code} for the existing "
                f"account, but HTTP {res_nonexistent.status_code} when a nonexistent account was submitted.\n\n"
                "Even if the displayed user interface looks identical, automated tools and scripts "
                "can leverage this status difference to enumerate registered accounts."
            ),
            fix=(
                "Return the same HTTP response status (typically 401 Unauthorized or 400 Bad Request) "
                "for all authentication failures regardless of whether the username was recognized."
            ),
            evidence=evidence,
        )

    # Case 3: Significant timing discrepancy (> 250ms delta)
    if timing_delta_ms > 250:
        return _build_finding(
            severity=WARNING,
            title="Potential account enumeration via response timing",
            description="A significant response timing delta was observed between existing and nonexistent accounts",
            explanation=(
                f"The server took {evidence['timingExistingMs']}ms to respond to the existing account probe, "
                f"compared to {evidence['timingNonexistentMs']}ms for the nonexistent account probe "
                f"(delta: {evidence['timingDeltaMs']}ms).\n\n"
                "This often happens when password hashing (e.g. bcrypt/argon2) only executes after "
                "confirming the user exists in the database. An attacker measuring latency can "
                "statistically determine account presence."
            ),
            fix=(
                "Ensure constant-time behavior: when an account does not exist, compute a dummy password hash "
                "with the same cost parameters before returning the error response."
            ),
            evidence=evidence,
        )

    # Uniform responses: check passed
    return _build_finding(
        severity=PASSED,
        title="No account enumeration detected",
        description="The authentication endpoint returns uniform responses for existing and nonexistent accounts",
        explanation=(
            f"The authentication endpoint at {submit_url} returned identical HTTP {res_existing.status_code} "
            f"responses and consistent error messages for both existing and nonexistent account probes. "
            f"Response timing was within acceptable parity ({evidence['timingDeltaMs']}ms delta)."
        ),
        fix="No action required. Maintain uniform generic error responses across all authentication flows.",
        evidence=evidence,
    )
