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
from urllib.parse import urljoin
from uuid import uuid4

import httpx

from ._finding import PASSED, SKIPPED, WARNING, TIMEOUT_SECONDS, USER_AGENT, finding_builder

_log = logging.getLogger("checks.account_enumeration")

CHECK_ID = "account_enumeration_check"

# Tier 2 finding builder: stamps findings with "tier": 2
_build_finding = finding_builder(CHECK_ID, tier=2)

# Common field name patterns for authentication forms
USERNAME_FIELD_HINT = re.compile(r"(user|email|login|account|identifier|name)", re.I)

# Distinctive error strings indicating explicit account existence or absence
USER_NOT_FOUND_HINTS = re.compile(
    r"(user (not found|doesn't exist|does not exist)|no (such )?user|"
    r"email (not found|not registered|does not exist)|account (not found|does not exist)|"
    r"unregistered email|unknown account)",
    re.I,
)

WRONG_PASSWORD_HINTS = re.compile(
    r"(incorrect password|wrong password|invalid password|bad password|"
    r"password does not match|password is incorrect)",
    re.I,
)


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

    # Strip HTML tags for basic text extraction
    clean_text = re.sub(r"<[^>]+>", " ", response.text)
    clean_text = " ".join(clean_text.split())
    return clean_text[:300]


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

    # Locate login form or login page endpoint
    login_form = target.login_form()
    submit_url = None
    method = "POST"
    username_field = "email"
    password_field = "password"
    extra_fields = {}

    if login_form is not None:
        submit_url = urljoin(target.login.url if target.login else base_url, login_form.submit_url or "")
        method = (login_form.method or "POST").upper()

        # Identify form field names
        for f in login_form.fields:
            if f.type == "password":
                password_field = f.name or "password"
            elif USERNAME_FIELD_HINT.search(f.name or "") or f.type in ("text", "email"):
                username_field = f.name or "email"
            elif f.type == "hidden" and f.name and "csrf" not in f.name.lower():
                # Keep static nonces/flags
                extra_fields[f.name] = f.attrs.get("value", "")
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

    async with httpx.AsyncClient(
        timeout=TIMEOUT_SECONDS,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/html"},
        follow_redirects=False,
    ) as client:
        try:
            # Probe 1: Known existing test account
            t0 = time.perf_counter()
            if method == "POST":
                # Try sending JSON if endpoint looks like an API, otherwise standard form-encoded
                if "/api/" in submit_url or "json" in submit_url:
                    res_existing = await client.post(submit_url, json=payload_existing)
                else:
                    res_existing = await client.post(submit_url, data=payload_existing)
            else:
                res_existing = await client.get(submit_url, params=payload_existing)
            dur_existing = time.perf_counter() - t0

            # Probe 2: Randomized nonexistent account
            t0 = time.perf_counter()
            if method == "POST":
                if "/api/" in submit_url or "json" in submit_url:
                    res_nonexistent = await client.post(submit_url, json=payload_nonexistent)
                else:
                    res_nonexistent = await client.post(submit_url, data=payload_nonexistent)
            else:
                res_nonexistent = await client.get(submit_url, params=payload_nonexistent)
            dur_nonexistent = time.perf_counter() - t0

        except httpx.RequestError as exc:
            return _build_finding(
                severity=SKIPPED,
                title="Could not connect to authentication endpoint",
                description=f"Request to {submit_url} failed during account enumeration test",
                explanation=f"Connection error while probing {submit_url}: {exc}",
                fix="Verify the staging URL or login URL is reachable and accepts test connections.",
                evidence={"endpoint": submit_url, "error": str(exc)},
            )

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
        "testedExistingUser": username,
        "statusCodeExisting": res_existing.status_code,
        "statusCodeNonexistent": res_nonexistent.status_code,
        "messageExisting": msg_existing[:150],
        "messageNonexistent": msg_nonexistent[:150],
        "timingExistingMs": round(dur_existing * 1000, 1),
        "timingNonexistentMs": round(dur_nonexistent * 1000, 1),
        "timingDeltaMs": round(timing_delta_ms, 1),
    }

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
    if status_diff and res_existing.status_code != 200 and res_nonexistent.status_code != 200:
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
