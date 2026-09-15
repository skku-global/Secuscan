"""
LOGOUT CHECK - Tier 2. Does signing out actually destroy the session?

WHY THIS IS WORTH TESTING
"Sign out" is the control a user reaches for when they are on a shared computer, when
they think something is wrong, or when they have just been told their password leaked. It
is the one security action every user knows how to perform, and it is very often the
least tested path in an application.

The common defect is that logout clears the cookie in the BROWSER without invalidating
the session on the SERVER. The user sees themselves signed out and is satisfied; the
session identifier that was in that cookie still works. Anyone holding a copy - from a
shared machine's cookie jar, a proxy log, a backup, or the XSS bug that started the whole
problem - remains signed in as that user indefinitely. Nothing the user can do ends it,
because the control that is supposed to end it does not.

HOW THIS CHECK PROVES IT, AND WHY THE BASELINE MATTERS
The obvious test - log out, replay the old cookie, see if the page looks logged in - is
not reliable on its own, because "looks logged in" is not something a scanner can judge
from HTML. So the check takes THREE observations of the same protected page:

  1. AUTHENTICATED   - with the live session cookie, before logout.
  2. ANONYMOUS       - with no cookies at all. This is the baseline: what the server
                       serves someone who is not signed in.
  3. REPLAYED        - with the old cookie, after logging out.

The verdict comes from comparing 3 against 1 and 2 rather than from reading 3 alone:

  - If REPLAYED resembles ANONYMOUS, the session was destroyed. That is the pass.
  - If REPLAYED resembles AUTHENTICATED and the two differ from each other, the session
    survived logout. That is the finding.
  - If AUTHENTICATED and ANONYMOUS are indistinguishable, this page could not tell signed
    in from signed out, so the experiment proves nothing and the result is SKIPPED. This
    is the case that would otherwise produce a false pass, and it is common: the page
    tried may simply be public.

The third branch is the one that makes this check honest. Without the anonymous baseline
every unprotected page reads as "logout works", because the replayed response looks the
same as the anonymous one for a reason that has nothing to do with the session.

A fourth outcome is checked before any of those comparisons: whether the sign-out request
was processed at all. If the application refused it - a logout endpoint that requires POST
answers 405 to the GET a sign-out link sends, and a rate-limited or blocked one answers 403
or 429 - then nothing ended the session, so the cookie surviving proves nothing. That case
is SKIPPED, because the alternative is a CRITICAL finding against a site whose only
mistake was refusing a method it does not accept.
"""

import re
from urllib.parse import urlparse

import httpx

from ._endpoints import LOGOUT_PATHS, candidate_paths, find_logout
from ._finding import CRITICAL, PASSED, SKIPPED, TIMEOUT_SECONDS, USER_AGENT, finding_builder
from ._session import _looks_blocked, authenticated_session, session_skip_finding

CHECK_ID = "logout_check"

_build_finding = finding_builder(CHECK_ID, tier=2)


# Markers that a page is being served to someone signed IN. Used only to describe the
# observation in evidence - never to decide the verdict, which rests on the comparison.
_SIGNED_IN_HINT = re.compile(r"(log\s?out|sign\s?out|my account|dashboard|profile|settings)", re.I)

# Markers that a page is being served to someone signed OUT.
_SIGNED_OUT_HINT = re.compile(r"(log\s?in|sign\s?in|sign\s?up|register|forgot.{0,12}password)", re.I)


def _fingerprint(response: httpx.Response) -> tuple:
    """A coarse, comparable summary of a response: status, redirect path and length.

    Deliberately NOT the whole body. Two fetches of the same page differ constantly in
    ways that mean nothing here - a CSRF token, a timestamp, a request id, a rotating
    advert - so comparing raw text would report every site as changed. The status, the
    redirect destination and the rough size are stable across repeat fetches while still
    differing between a signed-in and a signed-out render, which is the only distinction
    this check needs. _similar() below does the comparing.
    """
    location = response.headers.get("location", "")
    # Only the path of a redirect: query strings carry per-request tokens.
    if location:
        location = urlparse(location).path

    text = re.sub(r"<[^>]+>", " ", response.text or "")
    text = " ".join(text.split())

    return (response.status_code, location, len(text))


def _similar(a: tuple, b: tuple) -> bool:
    """Whether two fingerprints describe the same rendered state.

    Status and redirect destination must match exactly - those are categorical, and a 200
    is not a near-miss for a 302. Length is compared with a tolerance instead of exactly,
    because two fetches of the same page are never quite the same size: a CSRF token, a
    request id, a timestamp or a rotating advert all move it by a few bytes. Five percent
    absorbs that while still separating a page that renders a whole account menu from one
    that renders a sign-in link.
    """
    if a[0] != b[0] or a[1] != b[1]:
        return False

    longer = max(a[2], b[2])
    if longer == 0:
        return True

    return abs(a[2] - b[2]) / longer <= 0.05


def _describe(response: httpx.Response) -> dict:
    text = re.sub(r"<[^>]+>", " ", response.text or "")
    text = " ".join(text.split())
    return {
        "status": response.status_code,
        "redirectTo": urlparse(response.headers.get("location", "")).path or None,
        "looksSignedIn": bool(_SIGNED_IN_HINT.search(text)),
        "looksSignedOut": bool(_SIGNED_OUT_HINT.search(text)),
    }


async def check_logout(target) -> dict:
    """Sign in, sign out, then replay the old session cookie and see if it still works."""
    outcome = await authenticated_session(target)

    if not outcome.ok:
        return session_skip_finding(_build_finding, outcome, "session invalidation on logout")

    logout_urls = find_logout(target) or candidate_paths(target, LOGOUT_PATHS)
    if not logout_urls:
        return _build_finding(
            severity=SKIPPED,
            title="No sign-out endpoint was found",
            description="This check could not locate a logout link to test",
            explanation=(
                "The test account signed in successfully, but no sign-out link was found "
                "on the pages the scanner fetched, and none of the conventional logout "
                "paths applied.\n\nWithout somewhere to sign out, whether signing out "
                "destroys the session cannot be tested. Reported as skipped rather than "
                "passed: nothing was observed."
            ),
            fix=(
                "If your application has a sign-out endpoint at an unconventional "
                "address, supplying the login URL in the scan request helps the scanner "
                "find the pages around it."
            ),
            evidence={"triedPaths": [u for u in candidate_paths(target, LOGOUT_PATHS)][:6]},
        )

    # The page used as the experiment's subject. The login page is the best available
    # choice: every site has one, it is already known to exist, and it is the page most
    # likely to render differently for a signed-in user - most applications redirect an
    # authenticated visitor away from their own login form.
    probe_url = target.login.url if target.login else target.url
    logout_url = logout_urls[0]

    headers = {"User-Agent": USER_AGENT, "Accept": "text/html"}

    async with httpx.AsyncClient(
        timeout=TIMEOUT_SECONDS, headers=headers, follow_redirects=False
    ) as client:
        try:
            # 1. AUTHENTICATED - the protected page as the signed-in user sees it.
            authed = await client.get(probe_url, cookies=outcome.cookies)

            # 2. ANONYMOUS - the same page with no cookies. The baseline.
            anon = await client.get(probe_url, cookies={})

            # Sign out, carrying the session. GET is used because that is what following
            # a sign-out link does, which is what this check is testing.
            logout_response = await client.get(logout_url, cookies=outcome.cookies)

            # 3. REPLAYED - the protected page with the cookie that has now been logged
            # out. This is the whole question.
            replayed = await client.get(probe_url, cookies=outcome.cookies)

        except httpx.RequestError as exc:
            return _build_finding(
                severity=SKIPPED,
                title="Could not complete the sign-out test",
                description="A request failed while testing whether logout destroys the session",
                explanation=(
                    f"The connection failed while testing the sign-out flow "
                    f"({type(exc).__name__}), so the result is unknown.\n\nThis is a "
                    "connectivity result, not a security finding."
                ),
                fix="Re-run the scan. If this recurs, the endpoint may be rate-limiting the scanner.",
                evidence={"logoutUrl": logout_url, "error": type(exc).__name__},
            )

    # DID THE LOGOUT ACTUALLY HAPPEN? If the request was refused, the session surviving the
    # replay proves nothing except that nothing was done to it - and reporting that as
    # "signing out does not destroy the session" is a CRITICAL finding against a site that
    # may well invalidate sessions perfectly.
    #
    # This is not a hypothetical. The commonest case is a logout endpoint that requires
    # POST, which is correct anti-CSRF practice (logout CSRF is a real attack: an <img>
    # pointing at /logout signs a visitor out of somebody else's site), and the scanner's
    # GET gets a 405. The careful site is the one that gets the false critical. A
    # rate-limited or WAF-blocked logout endpoint produces the same shape.
    logout_status = logout_response.status_code
    if logout_status >= 400 or _looks_blocked(logout_response):
        return _build_finding(
            severity=SKIPPED,
            title="Sign-out could not be completed",
            description=(
                f"The sign-out request to {logout_url} was refused with "
                f"{logout_status}, so the session was never asked to end"
            ),
            explanation=(
                f"This check signs out by following the sign-out link, which is a GET to "
                f"{logout_url}. That request came back {logout_status}, so the "
                "application did not process a sign-out at all.\n\nWhen no sign-out "
                "actually happened, the session still working afterwards says nothing "
                "about whether signing out destroys it - and the result is reported as "
                "skipped rather than as a finding for exactly that reason. A logout "
                "endpoint that requires POST (a sound defence against logout CSRF, where "
                "a third-party page forces a visitor to be signed out) answers 405 to a "
                "GET, and a rate-limited or firewall-blocked one answers 403 or 429.\n\n"
                "This is a limitation of the scan, not a statement about the site."
            ),
            fix=(
                "No action indicated. To confirm this by hand: sign in, copy the session "
                "cookie, sign out through the site's own button, then replay that cookie "
                "and check the server no longer accepts it."
            ),
            evidence={
                "logoutUrl": logout_url,
                "logoutStatus": logout_status,
                "probeUrl": probe_url,
                "authenticated": _describe(authed),
                "anonymous": _describe(anon),
                "afterLogout": _describe(replayed),
            },
        )

    fp_authed = _fingerprint(authed)
    fp_anon = _fingerprint(anon)
    fp_replayed = _fingerprint(replayed)

    evidence = {
        "logoutUrl": logout_url,
        "probeUrl": probe_url,
        "authenticated": _describe(authed),
        "anonymous": _describe(anon),
        "afterLogout": _describe(replayed),
    }

    # THE EXPERIMENT WAS INCONCLUSIVE. If the page looks identical whether or not a
    # session is presented, it cannot report on a session's fate - so a matching replay
    # says nothing. This branch comes FIRST because every other branch below assumes the
    # probe page can tell the two states apart, and without this guard an unprotected
    # page would sail into the PASSED branch and report a control that was never tested.
    if _similar(fp_authed, fp_anon):
        return _build_finding(
            severity=SKIPPED,
            title="Session invalidation could not be tested",
            description="The page used for the test looks the same signed in and signed out",
            explanation=(
                f"To test whether signing out destroys a session, this check needs a page "
                f"that visibly differs for a signed-in user. {probe_url} returned "
                "effectively the same response with and without the session cookie, so "
                "replaying the cookie after logout proves nothing either way.\n\nThis is "
                "reported as skipped rather than passed on purpose. An unchanged response "
                "is what a correctly destroyed session looks like AND what an unprotected "
                "page looks like, and reporting the second as the first would claim a "
                "control had been verified when nothing was tested."
            ),
            fix=(
                "No action indicated. To let this check run, the scan request can supply a "
                "login URL whose page differs for an authenticated visitor."
            ),
            evidence=evidence,
        )

    # THE SESSION SURVIVED LOGOUT. The replayed cookie still gets the signed-in view, and
    # that view is demonstrably different from the anonymous one - so the old session
    # identifier is still being honoured after the user asked to sign out.
    if _similar(fp_replayed, fp_authed):
        return _build_finding(
            severity=CRITICAL,
            title="Signing out does not destroy the session",
            description="A session cookie captured before logout still works after logout",
            explanation=(
                f"The test account signed in, then signed out via {logout_url}. The "
                f"session cookie captured before signing out was then replayed against "
                f"{probe_url} and still returned the signed-in view - identical to the "
                "authenticated response and clearly different from the anonymous one.\n\n"
                "This means signing out clears the cookie in the user's browser without "
                "invalidating the session on the server. The user believes they have "
                "signed out; the session identifier they were using remains valid.\n\n"
                "Anyone holding a copy of that identifier stays signed in as that user "
                "indefinitely - from a shared or public computer, a proxy or server log, "
                "a backup, or the cross-site scripting bug that prompted the user to sign "
                "out in the first place. Signing out is the one action a user takes when "
                "they suspect something is wrong, and here it does not help them."
            ),
            fix=(
                "Invalidate the session server-side on logout rather than only clearing "
                "the cookie: delete the session record from your session store (or mark "
                "it revoked) so the identifier is rejected on its next use. For stateless "
                "JWT sessions, keep a server-side revocation list and check it on every "
                "request, or keep access tokens short-lived with a refresh token that "
                "logout revokes.\n\nExpiring the cookie in the browser is not sufficient: "
                "the cookie is a copy, and the server must stop honouring the value."
            ),
            evidence=evidence,
        )

    # THE SESSION WAS DESTROYED. The replayed cookie now gets the anonymous view, which is
    # the correct behaviour and the only branch that earns a pass.
    if _similar(fp_replayed, fp_anon):
        return _build_finding(
            severity=PASSED,
            title="Signing out destroys the session",
            description="A session cookie captured before logout no longer works afterwards",
            explanation=(
                f"The test account signed in, signed out via {logout_url}, and the session "
                f"cookie captured beforehand was then replayed against {probe_url}. The "
                "server responded as it does to an anonymous visitor, so the session was "
                "invalidated rather than merely cleared from the browser.\n\nThis is the "
                "behaviour that makes signing out meaningful: a copy of the session "
                "identifier taken before logout - from a shared computer, a log, or a "
                "backup - is of no use afterwards."
            ),
            fix="No action required.",
            evidence=evidence,
        )

    # The replayed response matches neither baseline. Something changed, but not into a
    # state this check can name - a partially invalidated session, a redirect to an error
    # page, or a different page entirely. Worth reporting as untested rather than guessed.
    return _build_finding(
        severity=SKIPPED,
        title="Session invalidation was inconclusive",
        description="The response after logout matched neither the signed-in nor the signed-out view",
        explanation=(
            f"After signing out, replaying the old session cookie against {probe_url} "
            "produced a response that matched neither the authenticated view nor the "
            "anonymous one.\n\nThe session state after logout could not be determined "
            "from this, so nothing is claimed about it. This can happen when logout "
            "redirects somewhere unexpected, or when the page varies for reasons "
            "unrelated to the session."
        ),
        fix=(
            "Worth verifying by hand: sign in, copy the session cookie, sign out, then "
            "replay that cookie and confirm the server no longer accepts it."
        ),
        evidence=evidence,
    )
