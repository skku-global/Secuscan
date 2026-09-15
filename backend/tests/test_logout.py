"""
TESTS FOR THE LOGOUT CHECK (Tier 2).

The check answers one question - does signing out actually destroy the session, or does
it only clear the cookie in the browser? - by taking three observations of the same page
and comparing them: authenticated, anonymous, and the old cookie replayed after logout.

Verifies:
  1. No session -> SKIPPED, tier 2.
  2. A surviving session is CRITICAL: the replayed cookie still gets the signed-in view.
  3. A destroyed session is PASSED: the replayed cookie gets the anonymous view.
  4. THE FALSE-PASS GUARD. When the probe page looks identical signed in and signed out,
     the experiment proves nothing and the result is SKIPPED. Without this, every
     unprotected page would read as "logout works" - the replayed response matches the
     anonymous one for a reason that has nothing to do with the session. This is the
     single most important assertion in the file.
  5. Small body differences do not count as a state change. A CSRF token or a timestamp
     moves the length by a few bytes on every fetch; only a real difference counts.
  6. No logout endpoint -> SKIPPED, not a finding. A site may legitimately have none.
  7. A REFUSED sign-out -> SKIPPED, never CRITICAL. A logout endpoint that requires POST
     answers 405 to the GET a sign-out link sends, so nothing ends the session; the same
     goes for a blocked or rate-limited one. The replay surviving that must not read as
     "signing out does not destroy the session". A processed logout that still fails to
     invalidate stays CRITICAL - the gate narrows the finding, it does not remove it.
"""

import asyncio
from unittest.mock import patch

import httpx

import _path  # noqa: F401 - puts backend/ on sys.path
from scanning.checks._finding import CRITICAL, PASSED, SKIPPED
from scanning.checks._session import SessionOutcome
from scanning.checks.logout_check import _fingerprint, _similar, check_logout
from scanning.discovery import Page, ScanTarget

PASS_COUNT = 0
FAIL_COUNT = 0

_real_AsyncClient = httpx.AsyncClient

SIGNED_IN_BODY = (
    "<html><body><nav>Dashboard | My account | Settings | Log out</nav>"
    "<h1>Welcome back, tester</h1><p>You have 3 new messages waiting for you today.</p>"
    "</body></html>"
)
SIGNED_OUT_BODY = "<html><body><h1>Sign in</h1><form><input type='password'></form></body></html>"


def check(label, got, want):
    global PASS_COUNT, FAIL_COUNT
    ok = got == want
    if ok:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f"   (got {got!r}, wanted {want!r})"))


def run(coro):
    return asyncio.run(coro)


def client_factory(transport):
    def _factory(*args, **kwargs):
        kwargs["transport"] = transport
        return _real_AsyncClient(*args, **kwargs)

    return _factory


def seeded_target(ok=True, reason="", links=None):
    """A target signed in already, with a login page and a logout link."""
    login_page = Page(
        url="https://example.com/login",
        status=200,
        html="",
        text="",
        links=links if links is not None else [("https://example.com/logout", "Log out")],
    )
    target = ScanTarget(url="https://example.com", login=login_page)
    target._session_outcome = SessionOutcome(
        ok=ok,
        reason=reason,
        submit_url="https://example.com/login",
        cookies={"sessionid": "abc"},
        set_cookie_lines=["sessionid=abc; Path=/"],
    )
    return target


def server(before_logout, after_logout, anonymous):
    """A handler that serves a different body depending on cookie and logout state.

    `before_logout` and `after_logout` are what the probe page returns to a request
    CARRYING the session cookie, before and after /logout is hit. `anonymous` is what it
    returns to a request without one.
    """
    state = {"logged_out": False}

    def handler(request: httpx.Request):
        if "/logout" in request.url.path:
            state["logged_out"] = True
            return httpx.Response(302, headers={"location": "/"})

        has_cookie = "sessionid" in request.headers.get("cookie", "")
        if not has_cookie:
            return httpx.Response(200, text=anonymous)
        return httpx.Response(200, text=after_logout if state["logged_out"] else before_logout)

    return handler


def run_tests():
    print("\n--- 1. No session, no verdict ------------------------------")

    for reason in ("no_credentials", "rejected", "blocked", "no_session_cookie"):
        f = run(check_logout(seeded_target(ok=False, reason=reason)))
        check(f"{reason} -> SKIPPED", f["severity"], SKIPPED)
        check(f"{reason} -> tier 2", f.get("tier"), 2)

    print("\n--- 2. The session survives logout -> CRITICAL -------------")

    # The cookie still gets the signed-in page after logging out.
    transport = httpx.MockTransport(server(SIGNED_IN_BODY, SIGNED_IN_BODY, SIGNED_OUT_BODY))
    with patch("scanning.checks.logout_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_logout(seeded_target()))

    check("surviving session -> CRITICAL", f["severity"], CRITICAL)
    check("tier is 2", f.get("tier"), 2)
    check("the title says what happened", "does not destroy" in f["title"], True)
    check("the fix names server-side invalidation", "server-side" in f["fix"], True)
    check("evidence names the logout url", f["evidence"]["logoutUrl"], "https://example.com/logout")
    check("cookie value is not in the finding", "abc" in repr(f["evidence"]), False)

    print("\n--- 3. The session is destroyed -> PASSED ------------------")

    # After logout the cookie gets the same page an anonymous visitor gets.
    transport = httpx.MockTransport(server(SIGNED_IN_BODY, SIGNED_OUT_BODY, SIGNED_OUT_BODY))
    with patch("scanning.checks.logout_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_logout(seeded_target()))

    check("destroyed session -> PASSED", f["severity"], PASSED)
    check("tier is 2", f.get("tier"), 2)
    check("no action required", f["fix"], "No action required.")

    print("\n--- 4. THE FALSE-PASS GUARD --------------------------------")

    # The probe page is public: identical with and without a session. The replayed
    # response matches the anonymous one, but for a reason that has nothing to do with
    # the session being destroyed. This MUST NOT read as a pass.
    public = "<html><body><h1>Our product</h1><p>A public marketing page.</p></body></html>"
    transport = httpx.MockTransport(server(public, public, public))
    with patch("scanning.checks.logout_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_logout(seeded_target()))

    check("indistinguishable page -> SKIPPED", f["severity"], SKIPPED)
    check("NOT passed", f["severity"] == PASSED, False)
    check("NOT critical", f["severity"] == CRITICAL, False)
    check("the finding explains why it did not test", "skipped rather than passed" in f["explanation"], True)

    print("\n--- 4b. A refused sign-out is SKIPPED, never CRITICAL -----")

    # The closest thing to a false CRITICAL this check can produce. A logout endpoint that
    # requires POST is CORRECT anti-CSRF practice - logout CSRF is a real attack, where an
    # <img> on somebody else's page signs a visitor out - and it answers 405 to the GET a
    # sign-out link sends. Nothing ends the session, so the old cookie keeps working, and
    # comparing the replay against the authenticated view reported "signing out does not
    # destroy the session" against a site that may invalidate perfectly. The careful sites
    # were the ones being told they had a vulnerability.
    def refused(status, destroys=False):
        def handler(request):
            if "/logout" in request.url.path:
                if destroys:
                    handler.state["out"] = True
                return httpx.Response(status, text="no")
            has_cookie = "sessionid" in request.headers.get("cookie", "")
            if not has_cookie:
                return httpx.Response(200, text=SIGNED_OUT_BODY)
            return httpx.Response(200, text=SIGNED_OUT_BODY if handler.state["out"] else SIGNED_IN_BODY)

        handler.state = {"out": False}
        return handler

    for status, label in (
        (405, "POST-only logout"),
        (403, "blocked logout"),
        (429, "rate-limited logout"),
        (500, "logout error"),
        (404, "no logout there"),
    ):
        transport = httpx.MockTransport(refused(status))
        with patch("scanning.checks.logout_check.httpx.AsyncClient", client_factory(transport)):
            f = run(check_logout(seeded_target()))
        check(f"{label} ({status}) -> SKIPPED", f["severity"], SKIPPED)
        check(f"{label} -> NOT critical", f["severity"] == CRITICAL, False)

    # THE GATE MUST NOT SWALLOW THE REAL FINDING. A logout that IS processed and still
    # leaves the session alive is exactly what this check exists to catch, so a 302 that
    # fails to invalidate must stay CRITICAL.
    transport = httpx.MockTransport(refused(302, destroys=False))
    with patch("scanning.checks.logout_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_logout(seeded_target()))
    check("a processed logout that fails is still CRITICAL", f["severity"], CRITICAL)

    transport = httpx.MockTransport(refused(302, destroys=True))
    with patch("scanning.checks.logout_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_logout(seeded_target()))
    check("a processed logout that works is still PASSED", f["severity"], PASSED)

    print("\n--- 5. Trivial body differences are not a state change -----")

    # A CSRF token and a request id move the length a little on every fetch. That must
    # not read as the session surviving, nor as the page differing by state.
    jittered_a = SIGNED_OUT_BODY.replace("<form>", "<form><input type='hidden' value='tok_aaaa'>")
    jittered_b = SIGNED_OUT_BODY.replace("<form>", "<form><input type='hidden' value='tok_bbbb'>")
    # Signed-in page differs properly; the two anonymous renders differ only by the token.
    transport = httpx.MockTransport(server(SIGNED_IN_BODY, jittered_a, jittered_b))
    with patch("scanning.checks.logout_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_logout(seeded_target()))
    check("token jitter still reads as destroyed", f["severity"], PASSED)

    # The comparison itself, directly.
    check("identical fingerprints are similar", _similar((200, "", 1000), (200, "", 1000)), True)
    check("2% length difference is similar", _similar((200, "", 1000), (200, "", 1020)), True)
    check("40% length difference is not", _similar((200, "", 1000), (200, "", 1400)), False)
    check("different status is never similar", _similar((200, "", 1000), (302, "", 1000)), False)
    check("different redirect is never similar", _similar((302, "/home", 0), (302, "/login", 0)), False)
    check("two empty bodies are similar", _similar((200, "", 0), (200, "", 0)), True)

    print("\n--- 6. Redirect destinations are compared, not queries -----")

    # A redirect to /login with a rotating ?next= must compare equal to itself; the query
    # string carries per-request values and is deliberately dropped.
    r1 = httpx.Response(302, headers={"location": "/login?next=/a&t=111"}, text="")
    r2 = httpx.Response(302, headers={"location": "/login?next=/b&t=222"}, text="")
    check("query strings are ignored in redirects", _fingerprint(r1), _fingerprint(r2))

    r3 = httpx.Response(302, headers={"location": "/dashboard"}, text="")
    check("different redirect paths differ", _fingerprint(r1) == _fingerprint(r3), False)

    print("\n--- 7. No logout endpoint ----------------------------------")

    target = seeded_target(links=[("https://example.com/about", "About us")])
    # No logout link, and the conventional paths are all that is left. Serve 404 for them
    # so nothing matches; the check should still resolve candidates and then run.
    transport = httpx.MockTransport(server(SIGNED_IN_BODY, SIGNED_OUT_BODY, SIGNED_OUT_BODY))
    with patch("scanning.checks.logout_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_logout(target))
    # Conventional paths exist, so the check proceeds using /logout rather than skipping.
    check("falls back to conventional paths", f["evidence"]["logoutUrl"], "https://example.com/logout")

    # With no base URL at all there are no candidate paths either.
    bare = ScanTarget(url="")
    bare._session_outcome = SessionOutcome(ok=True, cookies={"sessionid": "abc"})
    f = run(check_logout(bare))
    check("no endpoint at all -> SKIPPED", f["severity"], SKIPPED)
    check("no endpoint -> tier 2", f.get("tier"), 2)

    print("\n--- 8. A third-party logout link is never followed ---------")

    # An external identity provider's logout. Following it would send this scan's traffic
    # to a system whose owner never consented to being scanned.
    target = seeded_target(links=[("https://accounts.google.com/Logout", "Sign out")])
    transport = httpx.MockTransport(server(SIGNED_IN_BODY, SIGNED_OUT_BODY, SIGNED_OUT_BODY))
    with patch("scanning.checks.logout_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_logout(target))
    check("third-party logout is not used", "google.com" in repr(f["evidence"]), False)

    print("\n--- 9. A failed request is SKIPPED, never PASSED -----------")

    def exploding(request):
        raise httpx.ConnectTimeout("timed out")

    with patch(
        "scanning.checks.logout_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(exploding)),
    ):
        f = run(check_logout(seeded_target()))
    check("transport failure -> SKIPPED", f["severity"], SKIPPED)
    check("the error TYPE is reported, not the message", f["evidence"]["error"], "ConnectTimeout")

    print("\n--- 10. The finding shape is complete ----------------------")

    transport = httpx.MockTransport(server(SIGNED_IN_BODY, SIGNED_IN_BODY, SIGNED_OUT_BODY))
    with patch("scanning.checks.logout_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_logout(seeded_target()))

    for key in ("id", "checkId", "tier", "title", "description", "severity", "explanation", "fix", "evidence"):
        check(f"finding carries {key}", key in f, True)
    check("checkId is this check", f["checkId"], "logout_check")

    print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()
