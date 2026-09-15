"""
TESTS FOR THE SHARED ENDPOINT FINDER (_endpoints.py).

This module is the one piece of Tier 2 that three checks depend on at once - the logout,
password-reset and two-factor checks all start by asking it "where is the thing I am
supposed to test?" - and it had no suite of its own. A wrong answer here does not produce
a wrong answer about this module, it produces a confident finding from whichever check
asked, about a page that was never the endpoint.

Verifies:
  1. Ordinary links are found: href match, text match, and either one alone.
  2. THE SELF-REFERENCE GUARD. A link that resolves to a page the scanner already fetched
     is not an endpoint. `<a href="#">Sign out</a>` is how a JavaScript sign-out button
     looks to a parser, and urljoin resolves that bare "#" to the page's own address, so
     without this guard find_logout answers "the page you are on". This is asserted in
     BOTH directions: the self-link is dropped AND a real /logout link is still returned.
  3. A fragment is never the evidence. It is stripped before the patterns are applied, so
     a path that matches on its own merits keeps its match while carrying one, and a
     "#logout" that names the endpoint only in the part the server never receives does
     not become a candidate. Nothing is lost by this: the conventional path list covers
     the pages a fragment would have pointed into.
  4. Non-navigational hrefs (mailto:, tel:, javascript:) are refused, including with the
     leading whitespace that urljoin preserves verbatim.
  5. The third-party guard: an off-site sign-out link - what a site using an external
     identity provider has - is discarded, because scanning it would send this scan's
     traffic to somebody who never consented.
  6. Duplicates collapse, so a link in both the header and the footer is one request.
  7. candidate_paths resolves conventional paths against the target and is same-site.
  8. THE REGRESSION, END TO END. A site that destroys sessions correctly but whose visible
     sign-out control is a JavaScript button must not be reported CRITICAL - and a site
     that genuinely fails to invalidate must still be. The gate narrows the finding; it
     does not remove it.

Section 8 is the one that matters. Before the self-reference guard it failed: the check
returned CRITICAL "signing out does not destroy the session" against the correct site.
The refused-sign-out gate added earlier does not catch this case, because fetching the
homepage succeeds - it answers 200, not the >= 400 that gate looks for.
"""

import asyncio
from unittest.mock import patch

import httpx

import _path  # noqa: F401 - puts backend/ on sys.path
from scanning.checks._endpoints import (
    LOGOUT_PATHS,
    SECURITY_PATHS,
    _same_document,
    candidate_paths,
    find_logout,
    find_reset,
    find_security,
)
from scanning.checks._finding import CRITICAL, PASSED
from scanning.checks._session import SessionOutcome
from scanning.checks.logout_check import check_logout
from scanning.discovery import Page, ScanTarget, _parse_page

PASS_COUNT = 0
FAIL_COUNT = 0

_real_AsyncClient = httpx.AsyncClient

SITE = "https://example.com"


def check(label, got, want):
    global PASS_COUNT, FAIL_COUNT
    ok = got == want
    if ok:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f"   (got {got!r}, wanted {want!r})"))


def client_factory(transport):
    def _factory(*args, **kwargs):
        kwargs["transport"] = transport
        return _real_AsyncClient(*args, **kwargs)

    return _factory


def page(url, links):
    return Page(url=url, status=200, html="", text="", links=links)


def target(login_links=None, home_links=None, url=SITE):
    """A target with a login page and optionally a homepage, carrying the given links."""
    return ScanTarget(
        url=url,
        login=page(f"{SITE}/login", login_links or []),
        home=page(f"{SITE}/", home_links) if home_links is not None else None,
    )


def run_tests():
    print("\n--- 1. Ordinary links are found ----------------------------")

    check(
        "href names the endpoint",
        find_logout(target([(f"{SITE}/auth/signout", "")])),
        [f"{SITE}/auth/signout"],
    )
    check(
        "text names the endpoint, href is opaque",
        find_logout(target([(f"{SITE}/a/x7f2", "Sign out")])),
        [f"{SITE}/a/x7f2"],
    )
    check(
        "reset link on the login page",
        find_reset(target([(f"{SITE}/forgot-password", "Forgot password?")])),
        [f"{SITE}/forgot-password"],
    )
    check(
        "security link",
        find_security(target([(f"{SITE}/account/security", "Security")])),
        [f"{SITE}/account/security"],
    )
    check("an unrelated link is not a candidate", find_logout(target([(f"{SITE}/pricing", "Pricing")])), [])
    check(
        "the \\b on 'out' keeps Outlet out of it",
        find_logout(target([(f"{SITE}/outlet", "Outlet")])),
        [],
    )

    print("\n--- 2. THE SELF-REFERENCE GUARD ----------------------------")

    # What <a href="#">Sign out</a> becomes after urljoin: the page's own address.
    check(
        "href='#' on the login page yields nothing",
        find_logout(target([(f"{SITE}/login", "Sign out")])),
        [],
    )
    check(
        "href='#' on the homepage yields nothing",
        find_logout(target(home_links=[(f"{SITE}/", "Sign out")])),
        [],
    )
    check(
        "a self-link with a trailing slash is still the same document",
        find_logout(target(url=SITE, home_links=[(f"{SITE}", "Log out")])),
        [],
    )
    # THE OTHER DIRECTION. The guard must not swallow a real endpoint.
    check(
        "a real /logout link is still returned",
        find_logout(target([(f"{SITE}/logout", "Log out")])),
        [f"{SITE}/logout"],
    )
    check(
        "a real link survives alongside a self-link",
        find_logout(target([(f"{SITE}/login", "Sign out"), (f"{SITE}/logout", "Log out")])),
        [f"{SITE}/logout"],
    )

    print("\n--- 3. Fragments -------------------------------------------")

    check("_same_document drops the fragment", _same_document("https://x.test/a#b"), "https://x.test/a")
    check("_same_document drops a trailing slash", _same_document("https://x.test/a/"), "https://x.test/a")
    check("_same_document keeps a bare origin", _same_document("https://x.test/"), "https://x.test")
    check(
        "a path matching on its own merits keeps its match when it carries a fragment",
        find_security(target([(f"{SITE}/account/security#totp", "Settings")])),
        [f"{SITE}/account/security"],
    )
    # A FRAGMENT IS NEVER THE EVIDENCE. "/settings#security" matches the security pattern
    # only in the "#security" part, which is never transmitted, so it is not a candidate
    # here. That is the same rule that stops "/dashboard#logout" from being taken for a
    # sign-out endpoint and producing the false CRITICAL section 8 pins - and unlike that
    # case, nothing is lost: "/settings" is in SECURITY_PATHS, so the two-factor check
    # probes it from the conventional list anyway.
    check(
        "a fragment alone does not make a candidate",
        find_security(target([(f"{SITE}/settings#security", "Settings")])),
        [],
    )
    check("...but the conventional list still covers it", f"{SITE}/settings" in candidate_paths(target(), SECURITY_PATHS), True)
    check(
        "'#logout' names the endpoint only in the part the server never sees",
        find_logout(target([(f"{SITE}/login#logout", "Leave")])),
        [],
    )

    print("\n--- 4. Non-navigational hrefs ------------------------------")

    for href in ("mailto:support@example.com", "tel:+441234567890", "javascript:doLogout()"):
        check(f"{href.split(':')[0]}: refused", find_logout(target([(href, "Sign out")])), [])
    check(
        "JavaScript: with odd casing refused",
        find_logout(target([("JavaScript:doLogout()", "Sign out")])),
        [],
    )
    check(
        "leading whitespace does not smuggle a scheme past",
        find_logout(target([("  javascript:doLogout()", "Sign out")])),
        [],
    )

    print("\n--- 5. The third-party guard -------------------------------")

    for href in (
        "https://accounts.google.com/logout",
        "https://example.okta.com/login/signout",
        "https://evil.test/logout",
    ):
        check(f"off-site {href.split('/')[2]} discarded", find_logout(target([(href, "Sign out")])), [])
    check(
        "a subdomain of the target is still off-site unless same_site says otherwise",
        find_logout(target([(f"{SITE}/logout", "Sign out")])),
        [f"{SITE}/logout"],
    )

    print("\n--- 6. Duplicates ------------------------------------------")

    check(
        "header and footer copies are one candidate",
        find_logout(target([(f"{SITE}/logout", "Log out"), (f"{SITE}/logout", "Sign out")])),
        [f"{SITE}/logout"],
    )
    check(
        "two fragments on one path collapse",
        find_security(target([(f"{SITE}/settings#a", "Security"), (f"{SITE}/settings#b", "Security")])),
        [f"{SITE}/settings"],
    )

    print("\n--- 7. candidate_paths -------------------------------------")

    paths = candidate_paths(target(), LOGOUT_PATHS)
    check("every conventional logout path resolves", len(paths), len(LOGOUT_PATHS))
    check("resolved against the target", paths[0], f"{SITE}/logout")
    check("all same-site", all(p.startswith(SITE) for p in paths), True)

    print("\n--- 8. THE REGRESSION, END TO END --------------------------")

    # Prove first that a real parser really does resolve href="#" onto the page. This is
    # what makes the guard necessary rather than theoretical.
    html = "<html><body><nav><a href='#'>Sign out</a></nav></body></html>"
    parsed = _parse_page(httpx.Response(200, text=html, request=httpx.Request("GET", f"{SITE}/")))
    check("the parser resolves href='#' to the page itself", parsed.links, [(f"{SITE}/", "Sign out")])

    IN = (
        "<html><body><nav>Dashboard | My account | Settings</nav><h1>Welcome back</h1>"
        "<p>You have 3 new messages waiting for you today.</p></body></html>"
    )
    OUT = "<html><body><h1>Sign in</h1><form><input type='password'></form></body></html>"

    def make_target(links):
        t = ScanTarget(url=SITE, login=page(f"{SITE}/login", links))
        t._session_outcome = SessionOutcome(
            ok=True,
            reason="",
            submit_url=f"{SITE}/login",
            cookies={"sessionid": "abc"},
            set_cookie_lines=["sessionid=abc; Path=/"],
        )
        return t

    def server(invalidates: bool):
        """A site whose /logout does - or does not - destroy the session server-side."""
        state = {"out": False}

        def handler(request: httpx.Request):
            if request.url.path == "/logout":
                state["out"] = True
                return httpx.Response(302, headers={"location": "/"})
            signed_in = "sessionid" in request.headers.get("cookie", "")
            if not signed_in or (state["out"] and invalidates):
                return httpx.Response(200, text=OUT)
            return httpx.Response(200, text=IN)

        return handler

    def verdict(links, invalidates):
        transport = httpx.MockTransport(server(invalidates))
        with patch("scanning.checks.logout_check.httpx.AsyncClient", client_factory(transport)):
            return asyncio.run(check_logout(make_target(links)))

    # The correct site with a JavaScript sign-out button. Before the guard this was
    # CRITICAL: the check GET the homepage, got a healthy 200, replayed the cookie and
    # found the session alive - because nothing had signed out.
    f = verdict([(f"{SITE}/login", "Sign out")], invalidates=True)
    check("js sign-out on a correct site is NOT critical", f["severity"] == CRITICAL, False)
    check("...it falls back to /logout and passes", f["severity"], PASSED)

    f = verdict([(f"{SITE}/login#logout", "Leave")], invalidates=True)
    check("href='#logout' on a correct site is NOT critical", f["severity"] == CRITICAL, False)

    # THE OTHER DIRECTION, and the reason this is a gate and not a removal.
    f = verdict([(f"{SITE}/logout", "Log out")], invalidates=False)
    check("a site that really does not invalidate is still CRITICAL", f["severity"], CRITICAL)
    check("...and says so", "does not destroy" in f["title"], True)

    f = verdict([(f"{SITE}/logout", "Log out")], invalidates=True)
    check("a site that does invalidate still passes", f["severity"], PASSED)

    # And with no link at all the conventional paths still carry the check.
    f = verdict([], invalidates=False)
    check("no links -> conventional paths still find it -> CRITICAL", f["severity"], CRITICAL)

    print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()
