"""
SESSION COOKIE CHECK - Tier 2. The attributes on the cookie that actually holds the session.

WHY THIS EXISTS WHEN cookies_check.py ALREADY RUNS
The Tier 1 cookie check reads whatever cookies a site hands an anonymous visitor. That is
a real check and it stays, but it is looking at the wrong cookies: the ones set before
sign-in are consent banners, locale preferences, A/B test buckets and CSRF tokens. The
cookie that matters - the one that IS the user's authenticated session, the one worth
stealing - is only set when somebody logs in, and Tier 1 never logs in.

So this check signs in with the client's test account and reads the attributes on the
cookie the login itself returned. Same vocabulary as the Tier 1 check, entirely different
cookie, and the severity is higher for the same defect: Secure missing on a locale cookie
is untidy, Secure missing on a session cookie means the session travels in clear text the
first time someone types the domain without https://.

WHAT EACH ATTRIBUTE PREVENTS
  Secure    - the cookie is never sent over plain HTTP, so it cannot be read off an
              unencrypted request by anyone sharing the network.
  HttpOnly  - JavaScript cannot read document.cookie for it, so an XSS bug on any page of
              the site cannot exfiltrate the session. This is the attribute that turns a
              cross-site scripting bug from account takeover into a defacement.
  SameSite  - the browser will not attach it to cross-site requests, which is what stops
              a form on somebody else's site from acting as the logged-in user. Lax is
              the modern browser default and is sufficient for most sites; None without
              Secure is refused by browsers outright.

WHY THE RAW Set-Cookie LINES AND NOT A COOKIE JAR
httpx.Cookies parses into name/value pairs and throws the attributes away - HttpOnly and
SameSite simply are not on the object. Reading them requires the literal header lines,
which is why SessionOutcome carries set_cookie_lines alongside the jar.
"""

from ._finding import CRITICAL, PASSED, SKIPPED, WARNING, finding_builder

# THE VOCABULARY IS IMPORTED, NOT RETYPED. An identical-looking local copy of these two
# patterns lived here and had already drifted from _session.py's: that one carries an
# extra `_sid` alternative, so a cookie named `app_sid_v2` counted as a session to the
# login and NOT to this check. The result was this check reporting "no Set-Cookie header
# was available" on a site that had just set one - a silent loss of coverage, and the
# exact failure the old docstring's "deliberately the same vocabulary" claim was meant to
# rule out. One definition, imported, cannot drift.
from ._session import (
    _CSRF_NAME_HINT as _CSRF_NAME,
    _SESSION_NAME_HINT as _SESSION_NAME,
    authenticated_session,
    session_skip_finding,
)

CHECK_ID = "session_cookie_check"

_build_finding = finding_builder(CHECK_ID, tier=2)


def _parse_attributes(line: str) -> dict:
    """Pull the name and the security attributes off one Set-Cookie header line.

    Attribute names are case-insensitive per RFC 6265, so everything is lowered before
    comparison - "httponly", "HttpOnly" and "HTTPONLY" are the same attribute, and a
    check that only matched the documented spelling would report a false positive against
    a server that chose a different one.
    """
    parts = [p.strip() for p in line.split(";")]
    if not parts or "=" not in parts[0]:
        return {}

    name, _, _value = parts[0].partition("=")
    attrs = {"name": name.strip(), "secure": False, "httponly": False, "samesite": ""}

    for part in parts[1:]:
        lowered = part.lower()
        if lowered == "secure":
            attrs["secure"] = True
        elif lowered == "httponly":
            attrs["httponly"] = True
        elif lowered.startswith("samesite"):
            _, _, value = part.partition("=")
            attrs["samesite"] = value.strip().lower()

    return attrs


def _session_cookies(lines: list) -> list:
    """The parsed session cookies from a set of Set-Cookie lines.

    CSRF tokens are excluded even though they often match the session pattern - a
    "csrftoken" contains "token", and one is set on the login page before anyone
    authenticates. A CSRF token is MEANT to be readable by the page's own JavaScript so it
    can be echoed into a header, so reporting "HttpOnly missing" on one is a false
    positive - and a noisy check trains its reader to skim. The same exclusion is what
    stops a FAILED login from looking like a successful one in _session.py; see the note
    on _CSRF_NAME_HINT there.
    """
    out = []
    for line in lines:
        attrs = _parse_attributes(line)
        if not attrs:
            continue
        name = attrs["name"]
        if _CSRF_NAME.search(name):
            continue
        if _SESSION_NAME.search(name):
            out.append(attrs)
    return out


async def check_session_cookie(target) -> dict:
    """Sign in, then read the security attributes on the session cookie that came back."""
    outcome = await authenticated_session(target)

    if not outcome.ok:
        return session_skip_finding(_build_finding, outcome, "session cookie attributes")

    cookies = _session_cookies(outcome.set_cookie_lines)

    if not cookies:
        # The login established a session (authenticated_session only reports ok when a
        # session-shaped cookie exists in the jar) but no Set-Cookie line survived to be
        # parsed. That happens when the cookie was set on a redirect hop this check did
        # not see. Nothing was observed, so nothing is claimed.
        return _build_finding(
            severity=SKIPPED,
            title="Session cookie attributes could not be read",
            description="The sign-in succeeded but no Set-Cookie header was available to inspect",
            explanation=(
                "The test account signed in successfully, but the raw Set-Cookie headers "
                "for the session were not visible to this check - typically because the "
                "cookie was issued on a redirect hop.\n\nThis is reported as skipped "
                "rather than passed because the attributes were never read. Nothing is "
                "claimed about them either way."
            ),
            fix="No action required. This is a limitation of the scan, not a finding about the site.",
            evidence={"cookieNames": sorted(outcome.cookies)[:10]},
        )

    # The report describes every session cookie, but the VERDICT is taken on the worst one.
    # A site setting a hardened `sessionid` alongside a bare `remember_token` is only as
    # safe as the weaker of the two, because either one is enough to impersonate the user.
    missing_secure = [c["name"] for c in cookies if not c["secure"]]
    missing_httponly = [c["name"] for c in cookies if not c["httponly"]]
    missing_samesite = [c["name"] for c in cookies if not c["samesite"]]
    samesite_none_insecure = [
        c["name"] for c in cookies if c["samesite"] == "none" and not c["secure"]
    ]

    evidence = {
        "sessionCookies": [
            {
                "name": c["name"],
                "secure": c["secure"],
                "httpOnly": c["httponly"],
                "sameSite": c["samesite"] or "(not set)",
            }
            for c in cookies
        ],
        "loginEndpoint": outcome.submit_url,
    }

    # WHY MISSING Secure IS CRITICAL AND THE OTHERS ARE WARNINGS
    # Without Secure the session is transmitted in clear text on the first plain-HTTP
    # request to the domain - which any link, any typed address without the scheme, and
    # any downgrade attack produces. That is passive interception of a live session by
    # anyone on the path, requiring no bug on the site at all. Missing HttpOnly and
    # SameSite are serious, but each needs a second thing to go wrong (an XSS bug, a
    # cross-site request) before the session is lost.
    #
    # ORDER: SameSite=None-without-Secure is tested BEFORE the general missing-Secure
    # case, and the order is load-bearing. Every cookie in samesite_none_insecure is also
    # in missing_secure - None without Secure is by definition a missing Secure - so the
    # general case would swallow it and this branch could never run. Both are CRITICAL, so
    # nothing changes in severity; what changes is which explanation the reader gets. The
    # None combination is the more specific and more actionable of the two: it is refused
    # outright by current browsers, so the site is likely to be losing sessions as well as
    # exposing them.
    if samesite_none_insecure:
        return _build_finding(
            severity=CRITICAL,
            title="Session cookie uses SameSite=None without Secure",
            description="The session cookie is sent on cross-site requests and is not restricted to HTTPS",
            explanation=(
                f"The session cookie {', '.join(samesite_none_insecure)} sets "
                "SameSite=None without Secure.\n\nSameSite=None explicitly permits the "
                "cookie on cross-site requests, which is the combination that makes "
                "cross-site request forgery possible. Modern browsers reject this "
                "combination outright, so the cookie may also be dropped entirely - "
                "the session becomes both unsafe and unreliable."
            ),
            fix=(
                "Use SameSite=Lax unless a genuine cross-site flow requires otherwise. If "
                "SameSite=None is truly needed, it must be paired with Secure."
            ),
            evidence=evidence,
        )

    if missing_secure:
        return _build_finding(
            severity=CRITICAL,
            title="Session cookie is not marked Secure",
            description="The authenticated session cookie can be sent over an unencrypted connection",
            explanation=(
                f"The session cookie {', '.join(missing_secure)} was set without the "
                "Secure attribute.\n\nWithout it the browser will attach the cookie to "
                "plain HTTP requests as well as HTTPS ones. Anyone able to observe the "
                "network - on shared Wi-Fi, at an ISP, or anywhere along the path - can "
                "read the session identifier off a single unencrypted request and use it "
                "to act as that signed-in user. No vulnerability in the application is "
                "needed; the cookie simply travels in the clear.\n\nA single plain-HTTP "
                "request is enough, and one is easy to cause: any link written as "
                "http://, any address typed without the scheme."
            ),
            fix=(
                "Add the Secure attribute to the session cookie, so it reads "
                "`Set-Cookie: <name>=...; Secure; HttpOnly; SameSite=Lax`. Serve the site "
                "over HTTPS only and redirect HTTP to HTTPS."
            ),
            evidence=evidence,
        )

    if missing_httponly:
        return _build_finding(
            severity=WARNING,
            title="Session cookie is readable by JavaScript",
            description="The session cookie is missing the HttpOnly attribute",
            explanation=(
                f"The session cookie {', '.join(missing_httponly)} was set without "
                "HttpOnly, so any JavaScript running on the site can read it through "
                "document.cookie.\n\nThis is what decides how bad a cross-site scripting "
                "bug turns out to be. With HttpOnly, an injected script can act within "
                "the page. Without it, the script reads the session cookie and sends it "
                "elsewhere - the attacker keeps the session after the page is closed, and "
                "changing the password does not necessarily end it.\n\nThe attribute "
                "costs nothing: server-side session cookies are never read by the site's "
                "own scripts."
            ),
            fix=(
                "Add HttpOnly to the session cookie. If a script genuinely needs a value "
                "from the server, put that value in a separate non-session cookie."
            ),
            evidence=evidence,
        )

    if missing_samesite:
        return _build_finding(
            severity=WARNING,
            title="Session cookie has no SameSite attribute",
            description="The session cookie does not declare a SameSite policy",
            explanation=(
                f"The session cookie {', '.join(missing_samesite)} was set without a "
                "SameSite attribute.\n\nSameSite tells the browser not to attach the "
                "cookie to requests originating from other sites, which is the defence "
                "against cross-site request forgery: a form on an attacker's page "
                "submitting to your site would otherwise arrive carrying the victim's "
                "session.\n\nBrowsers now default to Lax when the attribute is absent, so "
                "this is mitigated in current versions - but the default is browser "
                "policy rather than yours, it varies by browser and version, and relying "
                "on it means the protection is not something you control."
            ),
            fix=(
                "Set SameSite=Lax on the session cookie explicitly. Use Strict if no "
                "cross-site navigation needs to arrive authenticated."
            ),
            evidence=evidence,
        )

    return _build_finding(
        severity=PASSED,
        title="Session cookie is correctly protected",
        description="The session cookie sets Secure, HttpOnly and SameSite",
        explanation=(
            f"The session cookie {', '.join(c['name'] for c in cookies)} carries all "
            "three protections: Secure (never sent over plain HTTP), HttpOnly (not "
            "readable by JavaScript, so a cross-site scripting bug cannot steal the "
            "session) and SameSite (not attached to cross-site requests, which blocks "
            "cross-site request forgery).\n\nThis was read from the cookie your test "
            "account actually received when signing in, not from an anonymous visit."
        ),
        fix="No action required.",
        evidence=evidence,
    )
