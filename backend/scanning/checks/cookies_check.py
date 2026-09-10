"""
SESSION AND COOKIE HANDLING CHECK - spec section 5, Tier 1.

WHY THIS FILE EXISTS
A session cookie is a bearer credential: whoever holds it is the user, no password
required. Three flags decide whether that credential can be stolen, and all three
are one word each in the Set-Cookie header:

  Secure    - the cookie is never sent over plain HTTP, so a network attacker on
              the same Wi-Fi cannot read it off an unencrypted request.
  HttpOnly  - JavaScript cannot read document.cookie for it, so a cross-site
              scripting bug cannot exfiltrate the session.
  SameSite  - the cookie is withheld on cross-site requests, which is most of the
              defence against cross-site request forgery.

The failure this catches is a login that hands out a session cookie missing one of
these. It is invisible in normal use - the site works perfectly - and it is the
difference between an XSS bug that defaces a page and one that steals every logged-in
session.

WHAT THIS CHECK READS AND DOES NOT DO
It reads cookies the site set on the pages discovery already fetched, INCLUDING the
redirect hops (a session cookie is very often set by the redirect after login, not
by the final page). It sends no requests of its own and submits no forms. It cannot
see a cookie that only appears after authentication - that needs a real login, which
is Tier 2 - so a clean result here is honestly scoped to the public pages.
"""

import re

from ._finding import PASSED, WARNING, CRITICAL, SKIPPED, finding_builder

CHECK_ID = "cookies_check"

# PYTHON-SPECIFIC: finding_builder(CHECK_ID) returns a function that already knows
# this check's id, so every call below reads as _build_finding(severity=..., ...)
# with no id to forget. See scanning/checks/_finding.py for why it is a factory.
_build_finding = finding_builder(CHECK_ID)

# Names that mark a cookie as SESSION OR AUTH state rather than an analytics or
# preference cookie. The distinction sets severity: a missing HttpOnly on a session
# cookie is a stolen login; on a "which banner did I dismiss" cookie it is nothing.
#
# Matched case-insensitively as a substring, so "PHPSESSID", "connect.sid" and
# "__Host-session" all hit "sess"/"sid".
SESSION_NAME_HINTS = (
    "sess", "sid", "auth", "token", "jwt", "login", "remember", "csrf", "xsrf",
)

# A session cookie that lives this long is a stolen-token that works this long. Not a
# hard rule - "remember me" legitimately lasts weeks - so it is a warning, and the
# number is named here so it can be argued with rather than buried in the code.
LONG_LIVED_DAYS = 90
LONG_LIVED_SECONDS = LONG_LIVED_DAYS * 24 * 60 * 60


# PYTHON-SPECIFIC: a dataclass would work, but a Set-Cookie is naturally a bag of
# optional attributes, so a plain dict-returning parser is simpler and the caller
# reads it with .get(). Returning None for "not a real cookie line" lets the caller
# skip junk in one check.
def _parse_cookie(raw: str) -> dict | None:
    # A Set-Cookie is "name=value; Attr; Attr=val; ...". The first part is the
    # cookie itself; the rest are attributes. split(";") then handle the head
    # specially.
    parts = [p.strip() for p in raw.split(";") if p.strip()]

    if not parts or "=" not in parts[0]:
        return None

    name = parts[0].split("=", 1)[0].strip()

    # PYTHON-SPECIFIC: a dict comprehension building the attribute map. Attributes
    # are case-insensitive per the spec, so the key is lowercased; flag attributes
    # like "Secure" have no "=" and are stored as True.
    attrs: dict = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attrs[key.strip().lower()] = value.strip()
        else:
            attrs[part.strip().lower()] = True

    return {"name": name, "attrs": attrs}


def _is_session_cookie(name: str) -> bool:
    lowered = name.lower()
    # PYTHON-SPECIFIC: any() with a generator - True as soon as one hint is found,
    # and it stops there rather than testing the rest.
    return any(hint in lowered for hint in SESSION_NAME_HINTS)


def _max_age_seconds(attrs: dict) -> int | None:
    # Max-Age wins over Expires per the spec when both are present, and it is a plain
    # integer, so it is the one worth reading. A malformed value is treated as absent
    # rather than crashing the check.
    raw = attrs.get("max-age")

    if raw in (None, True):
        return None

    try:
        return int(raw)
    except (ValueError, TypeError):
        return None


# WHY THIS EXISTS
# The check itself. It reads every cookie discovery saw across the home, login and
# signup pages, judges each against the three flags, and reports the worst case with
# every problem cookie named.
#
# It takes the ScanTarget rather than a URL because the cookies were already
# collected during discovery - re-fetching to read them again would be three wasted
# requests and could produce DIFFERENT cookies (a session id rotates), so the report
# would describe cookies the client can no longer see.
async def check_cookies(target) -> dict:
    # PYTHON-SPECIFIC: a set comprehension over the pages that exist, de-duplicating
    # by nothing yet - just gathering. `for page in (...) if page` skips the None
    # pages (a site with no login page has target.login is None).
    raw_cookies: list[str] = []
    for page in (target.home, target.login, target.signup):
        if page is not None:
            raw_cookies.extend(page.set_cookies)

    # De-duplicate identical Set-Cookie lines seen on more than one page, preserving
    # order. dict.fromkeys is the idiomatic ordered-unique in Python - a set would
    # lose the order that makes the evidence readable.
    raw_cookies = list(dict.fromkeys(raw_cookies))

    if not raw_cookies:
        # NOT a pass and NOT a failure. No cookies were observed on the public pages,
        # which for a check about cookie flags means there was nothing to test. A
        # site may well set its session cookie only after login, which this external
        # scan never performs.
        return _build_finding(
            severity=SKIPPED,
            title="No cookies to check",
            description="The pages scanned set no cookies",
            explanation=(
                "None of the pages reached during this scan set a cookie, so there "
                "were no cookie flags to inspect. A session cookie is often issued "
                "only after signing in, which an external scan does not do - so this "
                "is a limit of the scan, not a statement that the site is safe."
            ),
            fix=(
                "No action from this check. When you add authenticated scanning, the "
                "session cookie set at login is the one whose flags matter most."
            ),
            evidence={"cookiesObserved": 0},
        )

    # PYTHON-SPECIFIC: building the problem list as (name, [reasons]) pairs. A cookie
    # can fail more than one flag, and a report that says "sessionid: no Secure, no
    # HttpOnly" in one line is far more actionable than three findings about one
    # cookie.
    critical_problems: list[str] = []
    warnings: list[str] = []
    inspected: list[dict] = []

    for raw in raw_cookies:
        parsed = _parse_cookie(raw)

        if parsed is None:
            continue

        name = parsed["name"]
        attrs = parsed["attrs"]
        is_session = _is_session_cookie(name)

        reasons: list[str] = []

        # PYTHON-SPECIFIC: `"secure" not in attrs` tests dict membership by key. The
        # parser stored flag attributes as True, so presence is the whole test.
        if "secure" not in attrs:
            reasons.append("no Secure flag (sent over plain HTTP too)")

        if "httponly" not in attrs:
            reasons.append("no HttpOnly flag (readable by JavaScript)")

        if "samesite" not in attrs:
            reasons.append("no SameSite attribute (sent on cross-site requests)")

        max_age = _max_age_seconds(attrs)
        if is_session and max_age is not None and max_age > LONG_LIVED_SECONDS:
            reasons.append(
                f"lives {max_age // 86400} days (a stolen session stays valid that long)"
            )

        inspected.append(
            {"name": name, "session": is_session, "problems": reasons}
        )

        if not reasons:
            continue

        summary = f"{name}: " + "; ".join(reasons)

        # THE SEVERITY SPLIT. Missing Secure or HttpOnly on a SESSION cookie is the
        # session-hijack case, and that is the critical one. The same flags missing
        # on an analytics cookie, or a missing SameSite on anything, is a warning -
        # real, worth fixing, not an emergency.
        session_flag_missing = is_session and (
            "secure" not in attrs or "httponly" not in attrs
        )

        if session_flag_missing:
            critical_problems.append(summary)
        else:
            warnings.append(summary)

    if not critical_problems and not warnings:
        return _build_finding(
            severity=PASSED,
            title="Cookies set securely",
            description=f"All {len(inspected)} cookies carry the protective flags",
            explanation=(
                "Every cookie observed was set with the Secure, HttpOnly and SameSite "
                "protections appropriate to it. A cookie stolen by a network "
                "eavesdropper or a cross-site script is the fast route to a hijacked "
                "session, and these flags close it."
            ),
            fix="No action needed.",
            evidence={"cookies": inspected},
        )

    # PYTHON-SPECIFIC: chain the two lists with + for the evidence, but keep them
    # separate for the severity decision above.
    severity = CRITICAL if critical_problems else WARNING
    all_problems = critical_problems + warnings

    detail_lines = "\n".join(f"- {p}" for p in all_problems)

    return _build_finding(
        severity=severity,
        title=(
            "Session cookies missing protective flags"
            if critical_problems
            else "Cookies missing some protective flags"
        ),
        description=(
            f"{len(all_problems)} cookie(s) are missing flags that protect them"
        ),
        explanation=(
            "The following cookies were set without one or more protective "
            f"attributes:\n{detail_lines}\n\nSecure keeps a cookie off plaintext "
            "connections, HttpOnly hides it from JavaScript so an injected script "
            "cannot steal it, and SameSite stops it riding along on forged "
            "cross-site requests. A session cookie missing Secure or HttpOnly is the "
            "single most direct path from a common web bug to a hijacked account."
        ),
        fix=(
            "Set Secure, HttpOnly and SameSite=Lax (or Strict) on every session and "
            "authentication cookie, at the framework's session config so a new "
            "cookie cannot be added without them. Use SameSite=None only with Secure, "
            "and only for a cookie that genuinely must cross sites."
        ),
        evidence={"cookies": inspected, "problems": all_problems},
    )
