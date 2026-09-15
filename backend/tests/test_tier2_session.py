"""
TESTS FOR THE SHARED TIER 2 SESSION HELPERS (_session.py and _endpoints.py).

These two modules are not checks - they are the foundation the four authenticated checks
stand on, which makes them the highest-leverage thing in the Tier 2 set to test. A bug in
a check produces one wrong finding. A bug here produces four, and two of the properties
below are safety properties rather than correctness ones.

Verifies:
  1. Every failure reason is reported, and every one of them is SKIPPED - never PASSED.
  2. THE LOGIN HAPPENS ONCE. Four checks run concurrently under asyncio.gather; if each
     performed its own login, a client's test account would collect four failed attempts
     in a second and trip a lockout. The memo behind the lock is what prevents that.
  3. A CSRF cookie alone does NOT count as a session. This is load-bearing: the reset
     check uses a successful login as its proof that the client owns the mailbox it is
     about to email, so a false success opens that gate.
  4. A wall (403, CAPTCHA, CSRF rejection) is reported as blocked, never as a login.
  5. THE PASSWORD NEVER APPEARS in an outcome, a finding, or an evidence block. The login
     request body contains it, so anything echoing a response or an exception message is
     a leak path.
  6. Endpoint discovery matches href OR text, ignores mailto:/tel:/javascript:, and
     refuses off-site URLs - a "Sign out" link pointing at an identity provider must
     never be followed, because that third party did not consent to being scanned.
  7. A SCRIPT BODY IS NOT TEXT. Stripping tags without first dropping <script> and
     <style> bodies leaves the application's own JavaScript in what this module reads as
     "what the page says", so an inline `window.csrfToken = ...` turned a login that
     WORKED into reason="blocked". One shared session means one such tag costs all four
     checks - four skips against a site that let the scanner straight in.
  8. ONE WALL VOCABULARY. The three modules that decide "was this a wall?" each carried
     their own copy and all three had drifted. Asserted by object identity, so a phrase
     added to one and not the others fails here.
  9. A WAF interstitial is diagnosed as blocked rather than as a missing session cookie,
     whose remediation would tell a customer stopped at the front door that no action is
     needed.
 10. THE USERNAME BOX IS A TEXT-ENTRY INPUT, not merely a name that matches the hint.
     A hidden field ("login_challenge", "account_id"), a submit button named "login", a
     "remember my username" checkbox and a tenant <select> all match that hint, and all
     of them sit at the END of a form, where the old last-match-wins chain let them take
     the title. Four of six ordinary login-form shapes resolved the wrong field.
"""

import ast
import asyncio
import inspect
from unittest.mock import patch

import httpx

import _path  # noqa: F401 - puts backend/ on sys.path
from scanning.checks._endpoints import (
    LOGOUT_PATHS,
    RESET_PATHS,
    candidate_paths,
    find_logout,
    find_reset,
    find_security,
)
from scanning.checks._finding import SKIPPED, finding_builder
from scanning.checks._session import (
    _BLOCKED_HINTS,
    _BLOCKED_STATUSES,
    _USERNAME_HINT,
    _field_names,
    SessionOutcome,
    authenticated_session,
    same_site,
    session_skip_finding,
    visible_text,
)
from scanning.checks import _session as session_mod
from scanning.checks import account_enumeration_check as acct
from scanning.checks import password_reset_check as reset
from scanning.checks import session_cookie_check as scc
from scanning.checks import two_factor_check as twofa
from scanning.discovery import Field, Form, Page, ScanTarget, _parse_page

PASS_COUNT = 0
FAIL_COUNT = 0

_real_AsyncClient = httpx.AsyncClient

# The password used by every login test below. Asserted absent from findings.
TEST_PASSWORD = "CorrectHorseBatteryStaple!42"


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


def login_target(**credentials):
    """A target with a real login form, so _submit_url and _field_names have something."""
    login_page = Page(
        url="https://example.com/login",
        status=200,
        html="<form action='/login' method='post'></form>",
        text="Sign in",
        forms=[
            Form(
                submit_url="https://example.com/login",
                method="post",
                fields=[
                    Field(tag="input", type="text", name="email"),
                    Field(tag="input", type="password", name="password"),
                ],
            )
        ],
    )
    creds = {"username": "tester@example.com", "password": TEST_PASSWORD}
    creds.update(credentials)
    return ScanTarget(url="https://example.com", login=login_page, credentials=creds)


def run_tests():
    print("\n--- 1. The reasons a login does not happen -----------------")

    no_creds = ScanTarget(url="https://example.com")
    out = run(authenticated_session(no_creds))
    check("no credentials -> not ok", out.ok, False)
    check("no credentials -> reason", out.reason, "no_credentials")

    blank_password = login_target(password="")
    out = run(authenticated_session(blank_password))
    check("blank password -> reason", out.reason, "no_credentials")

    # A target with credentials but nothing to post to: no login page and no URL.
    no_form = ScanTarget(url="", credentials={"username": "a@b.com", "password": TEST_PASSWORD})
    out = run(authenticated_session(no_form))
    check("no form -> reason", out.reason, "no_form")

    print("\n--- 2. Walls are not logins --------------------------------")

    def blocked_handler(request):
        return httpx.Response(403, text="Forbidden - request blocked")

    target = login_target()
    with patch(
        "scanning.checks._session.httpx.AsyncClient",
        client_factory(httpx.MockTransport(blocked_handler)),
    ):
        out = run(authenticated_session(target))
    check("403 -> not ok", out.ok, False)
    check("403 -> reason is blocked", out.reason, "blocked")

    def captcha_handler(request):
        return httpx.Response(200, text="<p>Please complete the CAPTCHA to continue</p>")

    target = login_target()
    with patch(
        "scanning.checks._session.httpx.AsyncClient",
        client_factory(httpx.MockTransport(captcha_handler)),
    ):
        out = run(authenticated_session(target))
    check("captcha on a 200 -> reason is blocked", out.reason, "blocked")

    print("\n--- 3. A refusal is not a login ----------------------------")

    def rejected_handler(request):
        return httpx.Response(200, text="<p>Invalid username or password</p>")

    target = login_target()
    with patch(
        "scanning.checks._session.httpx.AsyncClient",
        client_factory(httpx.MockTransport(rejected_handler)),
    ):
        out = run(authenticated_session(target))
    check("error text on a 200 -> not ok", out.ok, False)
    check("error text on a 200 -> reason is rejected", out.reason, "rejected")

    print("\n--- 4. What counts as a session ----------------------------")

    def token_body_handler(request):
        # A bearer-token API: a real success, but nothing cookie-based to replay.
        return httpx.Response(200, json={"accessToken": "eyJhbGciOi"})

    target = login_target()
    with patch(
        "scanning.checks._session.httpx.AsyncClient",
        client_factory(httpx.MockTransport(token_body_handler)),
    ):
        out = run(authenticated_session(target))
    check("bearer token in body -> not ok", out.ok, False)
    check("bearer token in body -> reason", out.reason, "no_session_cookie")

    # THE CSRF CASE. A failed login still hands back a csrftoken, and "csrftoken"
    # contains "token". If that counted as a session, this would report ok.
    def csrf_only_handler(request):
        return httpx.Response(
            200,
            text="<p>Sign in</p>",
            headers={"set-cookie": "csrftoken=abc123; Path=/"},
        )

    target = login_target()
    with patch(
        "scanning.checks._session.httpx.AsyncClient",
        client_factory(httpx.MockTransport(csrf_only_handler)),
    ):
        out = run(authenticated_session(target))
    check("csrf cookie alone -> not ok", out.ok, False)
    check("csrf cookie alone -> reason", out.reason, "no_session_cookie")

    check(
        "session_cookie_names ignores csrf",
        SessionOutcome(ok=False, cookies={"csrftoken": "a", "locale": "en"}).session_cookie_names(),
        [],
    )
    check(
        "session_cookie_names finds the real one",
        SessionOutcome(ok=False, cookies={"sessionid": "a", "csrftoken": "b"}).session_cookie_names(),
        ["sessionid"],
    )

    def success_handler(request):
        return httpx.Response(
            302,
            headers={
                "location": "/dashboard",
                "set-cookie": "sessionid=s3cr3t; Path=/; Secure; HttpOnly; SameSite=Lax",
            },
        )

    target = login_target()
    with patch(
        "scanning.checks._session.httpx.AsyncClient",
        client_factory(httpx.MockTransport(success_handler)),
    ):
        out = run(authenticated_session(target))
    check("session cookie on a 302 -> ok", out.ok, True)
    check("session cookie is in the jar", out.cookies.get("sessionid"), "s3cr3t")
    check("raw Set-Cookie line was kept", len(out.set_cookie_lines), 1)
    check("reason is empty on success", out.reason, "")

    print("\n--- 5. The login happens exactly once ----------------------")

    # THE LOCKOUT PROPERTY. Four checks call this concurrently; the account gets one
    # attempt, not four.
    calls = {"n": 0}

    def counting_handler(request):
        calls["n"] += 1
        return httpx.Response(
            200, headers={"set-cookie": "sessionid=once; Path=/"}, text="Welcome"
        )

    target = login_target()

    async def four_concurrent_checks():
        return await asyncio.gather(*(authenticated_session(target) for _ in range(4)))

    with patch(
        "scanning.checks._session.httpx.AsyncClient",
        client_factory(httpx.MockTransport(counting_handler)),
    ):
        outcomes = run(four_concurrent_checks())

    check("four concurrent callers -> one login request", calls["n"], 1)
    check("all four got a session", all(o.ok for o in outcomes), True)
    check("all four got the same outcome object", len({id(o) for o in outcomes}), 1)

    # And a later caller gets the memo rather than a fifth request.
    with patch(
        "scanning.checks._session.httpx.AsyncClient",
        client_factory(httpx.MockTransport(counting_handler)),
    ):
        again = run(authenticated_session(target))
    check("a later caller still makes no new request", calls["n"], 1)
    check("the later caller got the memo", again.cookies.get("sessionid"), "once")

    print("\n--- 6. The password never escapes --------------------------")

    def echoing_handler(request):
        # A server that echoes the request body back - the worst case for a leak.
        return httpx.Response(200, text=f"<p>Invalid login: {request.content.decode()}</p>")

    target = login_target()
    with patch(
        "scanning.checks._session.httpx.AsyncClient",
        client_factory(httpx.MockTransport(echoing_handler)),
    ):
        out = run(authenticated_session(target))

    check("echoed body -> still not a login", out.ok, False)
    check("password is not in the outcome detail", TEST_PASSWORD in out.detail, False)
    check("password is not in the submit url", TEST_PASSWORD in out.submit_url, False)

    build = finding_builder("test_check", tier=2)
    finding = session_skip_finding(build, out, "a test subject")
    check("skip finding severity is SKIPPED", finding["severity"], SKIPPED)
    check("skip finding tier is 2", finding.get("tier"), 2)
    check("skip finding check id is the caller's", finding["checkId"], "test_check")
    check("password is not anywhere in the finding", TEST_PASSWORD in repr(finding), False)

    # A transport error must report the exception TYPE, never str(exc) - the message can
    # carry a fragment of the request, and the request holds the password.
    def exploding_handler(request):
        raise httpx.ConnectError(f"failed while sending {TEST_PASSWORD}")

    target = login_target()
    with patch(
        "scanning.checks._session.httpx.AsyncClient",
        client_factory(httpx.MockTransport(exploding_handler)),
    ):
        out = run(authenticated_session(target))
    check("transport error -> reason", out.reason, "unreachable")
    check("transport error detail is the type only", out.detail, "ConnectError")
    check("password is not in the error detail", TEST_PASSWORD in out.detail, False)

    print("\n--- 7. Every failure reason produces a SKIPPED finding -----")

    for reason in ("no_credentials", "no_form", "blocked", "rejected", "no_session_cookie", "unreachable"):
        finding = session_skip_finding(
            build, SessionOutcome(ok=False, reason=reason), "the thing under test"
        )
        check(f"{reason} -> SKIPPED", finding["severity"], SKIPPED)
        check(f"{reason} -> names what went untested", "the thing under test" in repr(finding), True)

    # An unrecognised reason must still produce a finding rather than a KeyError.
    finding = session_skip_finding(build, SessionOutcome(ok=False, reason="something_new"), "x")
    check("unknown reason still returns SKIPPED", finding["severity"], SKIPPED)

    print("\n--- 8. same_site keeps the scan on the client's own site ---")

    check("same host", same_site("https://example.com/a", "https://example.com/b"), True)
    check("www subdomain", same_site("https://example.com/", "https://www.example.com/x"), True)
    check("bare to www", same_site("https://www.example.com/", "https://example.com/x"), True)
    check("identity provider refused", same_site("https://example.com/", "https://accounts.google.com/logout"), False)
    check("lookalike domain refused", same_site("https://example.com/", "https://notexample.com/"), False)
    check("suffix attack refused", same_site("https://example.com/", "https://example.com.evil.net/"), False)
    check("empty base refused", same_site("", "https://example.com/"), False)

    print("\n--- 9. Finding the authenticated endpoints -----------------")

    page = Page(
        url="https://example.com/",
        status=200,
        html="",
        text="",
        links=[
            ("https://example.com/logout", ""),           # href match, no text
            ("https://example.com/a/x7f2", "Sign out"),   # text match, opaque href
            ("https://example.com/outlet", "Outlet"),     # must NOT match "out"
            ("mailto:support@example.com", "Log out"),    # non-navigational
            ("https://accounts.google.com/Logout", "Sign out"),  # third party
            ("https://example.com/forgot-password", "Forgot password?"),
            ("https://example.com/settings/security", "Security"),
        ],
    )
    target = ScanTarget(url="https://example.com", home=page)

    logout = find_logout(target)
    check("logout found by href", "https://example.com/logout" in logout, True)
    check("logout found by text", "https://example.com/a/x7f2" in logout, True)
    check("'Outlet' is not a logout link", "https://example.com/outlet" in logout, False)
    check("mailto: is not followed", any(u.startswith("mailto:") for u in logout), False)
    check("third-party logout refused", any("google.com" in u for u in logout), False)

    check(
        "reset link found",
        find_reset(target),
        ["https://example.com/forgot-password"],
    )
    check(
        "security link found",
        "https://example.com/settings/security" in find_security(target),
        True,
    )

    # Duplicated links across header and footer are one candidate, not two requests.
    dup_page = Page(
        url="https://example.com/",
        status=200,
        html="",
        text="",
        links=[("https://example.com/logout", "Log out"), ("https://example.com/logout", "Sign out")],
    )
    check(
        "duplicate links collapse",
        find_logout(ScanTarget(url="https://example.com", home=dup_page)),
        ["https://example.com/logout"],
    )

    # No pages at all must return empty rather than raise.
    check("no pages -> no candidates", find_logout(ScanTarget(url="https://example.com")), [])

    paths = candidate_paths(ScanTarget(url="https://example.com"), LOGOUT_PATHS)
    check("candidate paths are absolute", paths[0], "https://example.com/logout")
    check("candidate paths cover the list", len(paths), len(LOGOUT_PATHS))
    check(
        "reset candidate paths resolve too",
        candidate_paths(ScanTarget(url="https://example.com"), RESET_PATHS)[0],
        "https://example.com/forgot-password",
    )

    print("\n--- 10. A SCRIPT BODY IS NOT TEXT --------------------------")

    # Tag-stripping alone leaves every line of every inline <script> in what _session.py
    # then treats as "what the page says", which lets the JavaScript an ordinary
    # application ships decide what the scan concludes. Both strings below are shapes a
    # real dashboard emits, and neither says anything about the sign-in that just
    # succeeded. Before visible_text() they cost the customer ALL FOUR Tier 2 checks:
    # one shared session, lost on a login that worked.

    def page_handler(html, status=200, set_cookie="sessionid=abc; Path=/"):
        def handler(request):
            headers = {"set-cookie": set_cookie} if set_cookie else {}
            return httpx.Response(status, text=html, headers=headers)

        return handler

    def login_with(html, status=200, set_cookie="sessionid=abc; Path=/"):
        """One login against a site whose response body is `html`. Fresh target each time,
        because authenticated_session memoises per ScanTarget."""
        with patch(
            "scanning.checks._session.httpx.AsyncClient",
            client_factory(httpx.MockTransport(page_handler(html, status, set_cookie))),
        ):
            return run(authenticated_session(login_target()))

    WELCOME = "<h1>Welcome back</h1><p>You have 3 new messages.</p>"

    out = login_with('<script>window.csrfToken = "a1b2c3";</script>' + WELCOME)
    check("inline script naming csrfToken -> login still ok", out.ok, True)
    check("...and no wall reason", out.reason, "")

    out = login_with('<script>if (!r.ok) show("invalid password");</script>' + WELCOME)
    check("inline script carrying the refusal vocabulary -> still ok", out.ok, True)

    out = login_with('<style>.captcha-box { display: none }</style>' + WELCOME)
    check("style body naming captcha -> still ok", out.ok, True)

    out = login_with('<script>/* rate limit: 100/min */</script>' + WELCOME)
    check("a comment inside a script -> still ok", out.ok, True)

    # THE OTHER DIRECTION, and the reason this is a narrowing and not a removal. When the
    # page REALLY says it, in text a human would read, the wall must still be detected.
    out = login_with("<h1>Access denied</h1><p>Request blocked by security policy.</p>",
                     set_cookie=None)
    check("a wall in visible text is still a wall", out.reason, "blocked")

    out = login_with("<p>Invalid username or password. Please try again.</p>", set_cookie=None)
    check("a refusal in visible text is still a refusal", out.reason, "rejected")

    # And directly, so the failure points at the helper rather than at a login.
    resp = httpx.Response(200, text='<script>var t = "csrf";</script><p>Hello</p>',
                          request=httpx.Request("GET", "https://example.com/"))
    check("visible_text drops the script body", "csrf" in visible_text(resp), False)
    check("visible_text keeps the visible text", visible_text(resp), "Hello")
    check("visible_text survives an undecodable body", visible_text(object()), "")

    print("\n--- 11. ONE WALL VOCABULARY, NOT FOUR COPIES ---------------")

    # Three modules each carried their own hand-written copy of this vocabulary and all
    # three had drifted. Asserting the OBJECT is shared, not a list of words: a phrase
    # added to one module and not the others cannot fail a hardcoded list, but it cannot
    # survive this. Same rule as test_session_cookie.py section 10b.
    # Stated as "no module may hold a PRIVATE copy" rather than "these four names are
    # equal", so it keeps working whichever way a module refers to the vocabulary - and
    # so a copy re-added under any of these names, in any of these modules, fails here
    # even though nothing defines it today.
    SHARED = {
        "_BLOCKED_HINTS": _BLOCKED_HINTS,
        "BLOCKED_HINTS": _BLOCKED_HINTS,
        "_BLOCKED_STATUSES": _BLOCKED_STATUSES,
        "_PRE_AUTH_STATUSES": _BLOCKED_STATUSES,
    }
    for mod in (acct, reset, twofa):
        short = mod.__name__.rsplit(".", 1)[-1]
        for name, shared in SHARED.items():
            local = getattr(mod, name, None)
            check(f"{short}.{name} is not a private copy", local is None or local is shared, True)

    # AND A SECOND ASSERTION, BECAUSE THE ONE ABOVE IS WEAKER THAN IT READS.
    # re.compile CACHES by (pattern, flags). A module that pastes the identical pattern
    # text back in is handed the SAME OBJECT, so `local is shared` passes and the copy
    # goes unnoticed - which is exactly what happened with the username hint in
    # account_enumeration_check. Nothing at runtime can separate an alias from a paste,
    # because they are one object. So this asks the SOURCE what each module compiles,
    # the way test_branches.py asks Tier 1 modules what verbs they contain.
    #
    # Implicit string concatenation is not a way round it: Python's parser folds adjacent
    # literals into one constant, so a pattern written across six lines arrives here as
    # the single string it becomes.
    #
    # The identity test above still earns its place - it is what catches a copy that has
    # DRIFTED, the state all three of these were found in. The two together are what make
    # the claim true: an edited copy fails the first, a pasted one fails the second.
    def compiled_patterns(mod):
        """Every pattern text the module's own source passes to re.compile."""
        found = []
        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name != "compile":
                continue
            if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                found.append(node.args[0].value)
        return found

    SHARED_PATTERNS = {
        "the wall vocabulary": _BLOCKED_HINTS,
        "the username hint": _USERNAME_HINT,
    }
    for mod in (acct, reset, twofa, scc):
        short = mod.__name__.rsplit(".", 1)[-1]
        compiled = compiled_patterns(mod)
        for label, shared in SHARED_PATTERNS.items():
            check(f"{short} compiles no copy of {label}",
                  shared.pattern in compiled, False)

    # The helper has to be able to see something, or the four checks above pass by
    # finding nothing at all - which is how a source-level assertion rots.
    check("the scan does read the modules' patterns",
          len(compiled_patterns(twofa)) > 0, True)
    check("...and it would catch a copy", _USERNAME_HINT.pattern in compiled_patterns(session_mod), True)

    # ...and that the modules actually USE the shared one, which the check above cannot
    # say on its own: a module defining nothing would pass it while calling anything.
    check("enumeration check reads the shared hints", acct.BLOCKED_HINTS is _BLOCKED_HINTS, True)
    check("enumeration check reads the shared statuses", acct._PRE_AUTH_STATUSES is _BLOCKED_STATUSES, True)
    check("reset check uses the shared detector itself", reset._looks_blocked.__module__,
          "scanning.checks._session")
    check("two-factor check uses the shared text extractor", twofa._visible_text is visible_text, True)

    # The drift that existed, in both directions. These WAF names were known only to the
    # reset check, so a scan stopped by Cloudflare was a wall there and a mystery in the
    # module that decides whether anyone is logged in at all.
    for name in ("cloudflare", "incapsula", "turnstile", "recaptcha", "hcaptcha"):
        check(f"every module now knows {name!r}", bool(_BLOCKED_HINTS.search(name)), True)

    # ...and the two deliberate narrowings taken when the copies were merged, without
    # which the union would be wider than any of the three originals.
    check("'Identity verification queue' is not a wall",
          bool(_BLOCKED_HINTS.search("Identity verification queue: 3 pending")), False)
    check("...but 'verification required' is",
          bool(_BLOCKED_HINTS.search("Additional verification required")), True)
    check("an admin page listing 'Blocked users' is not a wall",
          bool(_BLOCKED_HINTS.search("Blocked users: 3")), False)
    check("...but 'blocked by security policy' is",
          bool(_BLOCKED_HINTS.search("Request blocked by security policy")), True)

    print("\n--- 12. A WAF INTERSTITIAL IS A WALL, NOT A MISSING COOKIE -")

    # A Cloudflare challenge answers 200 and sets no session cookie, so with the WAF names
    # missing from this module's vocabulary it fell through to "no_session_cookie" - whose
    # remediation begins "No action if your application uses bearer tokens". That is not a
    # vague message, it is advice to do nothing, given to a customer whose scan was stopped
    # at the front door. Diagnosing the wall is what makes the remediation right.
    CHALLENGE = (
        "<html><head><title>Just a moment...</title></head><body>"
        "<h1>Checking your browser before accessing example.com</h1>"
        "<p>This process is automatic. Cloudflare Ray ID: 8a1f2c</p></body></html>"
    )
    out = login_with(CHALLENGE, set_cookie=None)
    check("Cloudflare 200 challenge -> blocked", out.reason, "blocked")
    check("...not no_session_cookie", out.reason == "no_session_cookie", False)

    build2 = finding_builder("test_check", tier=2)
    finding = session_skip_finding(build2, out, "the session cookie")
    check("the WAF finding is SKIPPED", finding["severity"], SKIPPED)
    check("...and does not tell them no action is needed",
          "no action" in repr(finding).lower(), False)
    check("...and does tell them about the allowlist",
          "allowlist" in repr(finding).lower(), True)

    print("\n--- 13. A HIDDEN FIELD IS NOT THE USERNAME BOX -------------")

    # _field_names tested the NAME hint before the type, so a hidden field whose name
    # happens to match - "login_challenge" (Ory), "account_id", a prefilled hidden
    # "email" - was taken for the username input. One mistake became three: the username
    # went out under the hidden field's name, the value the server was waiting for was
    # dropped, and the real username field was never sent. The login fails for a reason
    # no part of the report can explain, and all four Tier 2 checks skip.

    def posted_payload(fields):
        """The form body _perform_login actually sends, for a login form of `fields`."""
        seen = {}

        def handler(request):
            body = request.content.decode()
            seen.update(dict(pair.split("=", 1) for pair in body.split("&") if "=" in pair))
            return httpx.Response(200, text="<h1>Welcome back</h1>",
                                  headers={"set-cookie": "sessionid=abc; Path=/"})

        page = Page(
            url="https://example.com/login",
            status=200,
            html="",
            text="Sign in",
            forms=[Form(submit_url="https://example.com/login", method="post", fields=fields)],
        )
        target = ScanTarget(
            url="https://example.com",
            login=page,
            credentials={"username": "tester@example.com", "password": TEST_PASSWORD},
        )
        with patch(
            "scanning.checks._session.httpx.AsyncClient",
            client_factory(httpx.MockTransport(handler)),
        ):
            run(authenticated_session(target))
        return seen

    from urllib.parse import unquote_plus

    sent = posted_payload([
        Field(tag="input", type="hidden", name="login_challenge", attrs={"value": "xyz789"}),
        Field(tag="input", type="text", name="email"),
        Field(tag="input", type="password", name="password"),
    ])
    check("the hidden value is carried through unchanged",
          unquote_plus(sent.get("login_challenge", "")), "xyz789")
    check("the username goes in the real username field",
          unquote_plus(sent.get("email", "")), "tester@example.com")
    check("the username does NOT overwrite the hidden field",
          unquote_plus(sent.get("login_challenge", "")) == "tester@example.com", False)

    # THE SEVERE ORDERING, and the one a form is most likely to have: hidden state fields
    # appended at the END. The old chain then reached "login_challenge" after it had
    # already found "email", and overwrote it - so the username went out under the hidden
    # field's name, the real username field was never sent at all, AND the value the
    # server was waiting for was dropped. Three failures from one elif.
    sent = posted_payload([
        Field(tag="input", type="text", name="email"),
        Field(tag="input", type="password", name="password"),
        Field(tag="input", type="hidden", name="login_challenge", attrs={"value": "xyz789"}),
    ])
    check("hidden field last: username still goes to the username field",
          unquote_plus(sent.get("email", "")), "tester@example.com")
    check("hidden field last: the hidden value is still carried",
          unquote_plus(sent.get("login_challenge", "")), "xyz789")
    check("hidden field last: the real username field is not dropped",
          "email" in sent, True)

    # A hidden CSRF nonce still rides along - that behaviour is load-bearing and unchanged.
    sent = posted_payload([
        Field(tag="input", type="hidden", name="csrf_token", attrs={"value": "nonce42"}),
        Field(tag="input", type="email", name="username"),
        Field(tag="input", type="password", name="password"),
    ])
    check("a CSRF nonce is still carried", unquote_plus(sent.get("csrf_token", "")), "nonce42")
    check("the username field is still found by type",
          unquote_plus(sent.get("username", "")), "tester@example.com")

    # And the ordinary form, with nothing hidden, is untouched.
    sent = posted_payload([
        Field(tag="input", type="text", name="email"),
        Field(tag="input", type="password", name="password"),
    ])
    check("an ordinary form still posts username and password",
          (unquote_plus(sent.get("email", "")), "password" in sent),
          ("tester@example.com", True))

    print("\n--- 14. ONLY A TEXT-ENTRY INPUT IS THE USERNAME BOX -------")

    # Section 13 proves what reaches the wire. This proves the resolver that decides it,
    # against HTML put through the REAL parser - so it pins discovery's contribution too:
    # that an <input> with no type attribute counts as text, that TYPE="HIDDEN" is
    # lowered, and that a nameless input falls back to its id.
    #
    # Every "WRONG" row below was the answer before this fix, and the first four are
    # ordinary markup rather than anything exotic. A submit button named "login" is on a
    # great many sites.

    def username_field_for(inner_html):
        page = _parse_page(httpx.Response(
            200,
            text=f"<html><body><form action='/login' method='post'>{inner_html}</form></body></html>",
            request=httpx.Request("GET", "https://example.com/login"),
        ))
        target = ScanTarget(url="https://example.com", login=page)
        return _field_names(target)[0]

    EMAIL = "<input type='email' name='email'>"
    PW = "<input type='password' name='password'>"

    SHAPES = [
        # (label, form body, the field that IS the username)
        ("a submit button named 'login' does not take the title",
         EMAIL + PW + "<input type='submit' name='login' value='Sign in'>", "email"),
        ("nor a 'remember my username' checkbox",
         EMAIL + PW + "<input type='checkbox' name='remember_username' value='1'>", "email"),
        ("nor a tenant <select name='account_type'>",
         EMAIL + PW + "<select name='account_type'><option>Staff</option></select>", "email"),
        ("nor a trailing OTP field on a combined sign-in form",
         EMAIL + PW + "<input type='text' name='otp_code'>", "email"),
        ("nor a textarea, whatever it is called",
         EMAIL + PW + "<textarea name='account_notes'></textarea>", "email"),
        # THE OTHER DIRECTION. None of this may cost the resolver a field it used to find.
        ("a plain form still resolves", EMAIL + PW, "email"),
        ("a form whose username field is called 'user'",
         "<input type='text' name='user'><input type='password' name='pass'>", "user"),
        ("an input with NO type attribute is a text box",
         "<input name='login_id'>" + PW, "login_id"),
        ("an input with an UNRECOGNISED type is a text box too, as in a browser",
         "<input type='username' name='uname'>" + PW, "uname"),
        ("a nameless input falls back to its id",
         "<input type='text' id='emailAddress'>" + PW, "emailAddress"),
        ("TYPE='HIDDEN' in capitals is still hidden",
         "<input TYPE='HIDDEN' NAME='account_id' value='7'>" + EMAIL + PW, "email"),
        ("no name hint anywhere -> the first text-entry input",
         "<input type='text' name='q1'>" + PW, "q1"),
        ("a search box before the username does not win",
         "<input type='search' name='q'>" + EMAIL + PW, "email"),
        ("the FIRST hinted field wins, not the last",
         EMAIL + "<input type='text' name='company_name'>" + PW, "email"),
    ]
    for label, body, want in SHAPES:
        check(label, username_field_for(body), want)

    # And a form with nothing typeable in it at all must fall back rather than raise.
    check("a form with no text entry at all keeps the default",
          username_field_for(PW + "<input type='submit' name='login'>"), "email")

    print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()
