"""
TESTS FOR THE PASSWORD RESET CHECK (Tier 2).

Verifies:
  1. THE ABUSE GATE. Without a successful login, the check sends NOTHING. This is the
     property that stops SecuScan being used to fire password-reset emails at an address
     someone typed into a form - the username field is client-supplied text, so a
     successful login is the only evidence that the client actually controls the mailbox
     the reset email will land in. The test asserts on request COUNT, not just severity:
     a check that skipped but had already sent the probe would pass a severity assertion
     and still have emailed a stranger.
  2. Enumeration by status code and by message -> WARNING.
  3. A uniform response -> PASSED.
  4. A reset token in the JSON response -> CRITICAL, and checked before enumeration
     because it is strictly worse.
  5. A CSRF token in a re-rendered HTML form is NOT a leaked reset token - that would be
     a false CRITICAL against a correctly built site. The same section pins the two
     false positives that a token-shaped KEY alone produced: an underscore-separated
     status value under `code`, and a value belonging to a LATER sibling key. Both are
     the normal shape of a correct response, so both directions are asserted - the
     correct responses stay clean AND the genuine leaks still go CRITICAL.
  6. A wall (CAPTCHA, CSRF, rate limit) is SKIPPED, never PASSED: two identical
     rejections look exactly like two identical correct answers.
  7. The probe address is at .invalid, which RFC 2606 reserves - so it can never collide
     with a real person's mailbox.
  8. The test account's password never appears anywhere in the finding.
"""

import asyncio
from unittest.mock import patch
from urllib.parse import unquote_plus

import httpx

import _path  # noqa: F401 - puts backend/ on sys.path
from scanning.checks._finding import CRITICAL, PASSED, SKIPPED, WARNING
from scanning.checks._session import SessionOutcome
from scanning.checks.password_reset_check import check_password_reset
from scanning.discovery import Field, Form, Page, ScanTarget

PASS_COUNT = 0
FAIL_COUNT = 0

_real_AsyncClient = httpx.AsyncClient

TEST_PASSWORD = "CorrectHorseBatteryStaple!42"
TEST_USERNAME = "tester@example.com"

RESET_FORM_HTML = (
    "<html><body><form action='/forgot-password' method='post'>"
    "<input name='email' type='email'><input name='csrf' type='hidden' value='tok123'>"
    "</form></body></html>"
)


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
    login_page = Page(
        url="https://example.com/login",
        status=200,
        html="",
        text="",
        links=links if links is not None else [("https://example.com/forgot-password", "Forgot password?")],
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
    target = ScanTarget(
        url="https://example.com",
        login=login_page,
        credentials={"username": TEST_USERNAME, "password": TEST_PASSWORD},
    )
    target._session_outcome = SessionOutcome(
        ok=ok,
        reason=reason,
        submit_url="https://example.com/login",
        cookies={"sessionid": "abc"},
        set_cookie_lines=["sessionid=abc; Path=/"],
    )
    return target


def reset_server(known_response, unknown_response, form_html=RESET_FORM_HTML, log=None):
    """Serves the reset form on GET and different answers per address on POST."""

    def handler(request: httpx.Request):
        if log is not None:
            log.append((request.method, str(request.url)))

        if request.method == "GET":
            return httpx.Response(200, text=form_html, headers={"content-type": "text/html"})

        # unquote first: a form POST percent-encodes the @ in an address, so a plain
        # substring test for the username would never match and BOTH probes would take
        # the unknown branch - which looks exactly like a correctly uniform endpoint.
        body = unquote_plus(request.content.decode("utf-8", "replace"))
        if TEST_USERNAME in body:
            return known_response
        return unknown_response

    return handler


def run_tests():
    print("\n--- 1. THE ABUSE GATE: no login, no email ------------------")

    # This is the assertion that matters most in the file. A check that reported SKIPPED
    # but had already fired the probe would satisfy a severity assertion and still have
    # sent a password-reset email to an address the client merely typed.
    for reason in ("no_credentials", "rejected", "blocked", "no_session_cookie", "unreachable"):
        log = []
        transport = httpx.MockTransport(
            reset_server(httpx.Response(200, text="sent"), httpx.Response(200, text="sent"), log=log)
        )
        with patch(
            "scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)
        ):
            f = run(check_password_reset(seeded_target(ok=False, reason=reason)))

        check(f"{reason} -> SKIPPED", f["severity"], SKIPPED)
        check(f"{reason} -> tier 2", f.get("tier"), 2)
        check(f"{reason} -> NOT ONE REQUEST WAS SENT", log, [])

    print("\n--- 2. Enumeration by status code -> WARNING ---------------")

    transport = httpx.MockTransport(
        reset_server(
            httpx.Response(200, text="We have sent you a reset link"),
            httpx.Response(404, text="No account found with that email"),
        )
    )
    with patch("scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_password_reset(seeded_target()))

    check("status difference -> WARNING", f["severity"], WARNING)
    check("tier is 2", f.get("tier"), 2)
    check("evidence records both statuses", f["evidence"]["statusForUnknownAddress"], 404)
    check("the fix gives the uniform wording", "If an account exists" in f["fix"], True)

    print("\n--- 3. Enumeration by message -> WARNING -------------------")

    transport = httpx.MockTransport(
        reset_server(
            httpx.Response(200, text="Check your email for a reset link"),
            httpx.Response(200, text="That email is not registered with us"),
        )
    )
    with patch("scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_password_reset(seeded_target()))

    check("message difference -> WARNING", f["severity"], WARNING)
    check("the title names the leak", "which addresses have accounts" in f["title"], True)

    print("\n--- 4. A uniform response -> PASSED ------------------------")

    uniform = "If an account exists for that address, we have sent reset instructions."
    transport = httpx.MockTransport(
        reset_server(httpx.Response(200, text=uniform), httpx.Response(200, text=uniform))
    )
    with patch("scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_password_reset(seeded_target()))

    check("identical answers -> PASSED", f["severity"], PASSED)
    check("no action required", f["fix"], "No action required.")

    print("\n--- 5. Different text alone is not enumeration -------------")

    # Reset pages differ on every render - a rotating CSRF token, the address echoed back.
    # A bare text difference that names neither state is not evidence of a leak.
    transport = httpx.MockTransport(
        reset_server(
            httpx.Response(200, text="<form><input value='tok_aaa'></form> Request received"),
            httpx.Response(200, text="<form><input value='tok_bbb'></form> Request received"),
        )
    )
    with patch("scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_password_reset(seeded_target()))
    check("token jitter is not enumeration", f["severity"], PASSED)

    print("\n--- 6. A leaked reset token -> CRITICAL --------------------")

    leaked = httpx.Response(
        200,
        json={"ok": True, "resetToken": "9f2b1c7d4e8a6b5c3d1e0f7a"},
        headers={"content-type": "application/json"},
    )
    transport = httpx.MockTransport(
        reset_server(leaked, httpx.Response(200, json={"ok": True}, headers={"content-type": "application/json"}))
    )
    with patch("scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_password_reset(seeded_target()))

    check("token in the response -> CRITICAL", f["severity"], CRITICAL)
    check("the leaked field is named", f["evidence"]["leakedField"], "resetToken")
    check("the explanation says takeover", "account takeover" in f["explanation"], True)

    print("\n--- 7. A CSRF token in HTML is NOT a leaked reset token ----")

    # The reset page re-renders its own form, and that form legitimately carries a CSRF
    # token in a hidden input. Reporting that as CRITICAL would be a false alarm against
    # a correctly built site - the JSON-only restriction is what prevents it.
    html_with_token = (
        "<html><body><p>If an account exists, we have sent instructions.</p>"
        "<form><input type='hidden' name='csrf_token' value='a1b2c3d4e5f6a7b8'></form></body></html>"
    )
    transport = httpx.MockTransport(
        reset_server(
            httpx.Response(200, text=html_with_token, headers={"content-type": "text/html"}),
            httpx.Response(200, text=html_with_token, headers={"content-type": "text/html"}),
        )
    )
    with patch("scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_password_reset(seeded_target()))
    check("csrf token in HTML -> not CRITICAL", f["severity"] == CRITICAL, False)
    check("csrf token in HTML -> PASSED", f["severity"], PASSED)

    # A JSON status string is not a token either.
    status_json = httpx.Response(200, json={"code": "EMAIL_SENT"}, headers={"content-type": "application/json"})
    transport = httpx.MockTransport(reset_server(status_json, status_json))
    with patch("scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_password_reset(seeded_target()))
    check("a status string is not a token", f["severity"], PASSED)

    # THE TWO FALSE POSITIVES. Both of these are the normal shape of a CORRECT reset
    # endpoint, and both used to raise a CRITICAL "full account takeover" against a site
    # leaking nothing. An earlier detector matched a token-shaped key and then searched
    # the following 200 characters for any long-ish string, which broke in two ways.
    false_positives = {
        # The value's underscore defeated the old `isalpha()` entropy guard, so this
        # ordinary success acknowledgement read as a leaked secret.
        "sent-confirmation": '{"code": "reset_email_sent", "message": "Check your inbox"}',
        "status-and-message": '{"code": "link_sent", "message": "We sent a reset link"}',
        # Worse: the old scan ran past the end of `code`'s short value and grabbed the
        # value belonging to a LATER key, then blamed `code` for it.
        "later-trace-key": '{"success": true, "code": "sent", "trace": "abcdef1234567890abcdef"}',
        # A 4-digit number under the generic `code` key is an application status code far
        # more often than it is a login code.
        "four-digit-app-code": '{"code": "4201"}',
        # A numeric status, and a boolean/null where a token would be.
        "numeric-status": '{"code": 200, "message": "sent"}',
        "null-token": '{"token": null, "message": "sent"}',
    }
    for label, body in false_positives.items():
        fp = httpx.Response(200, text=body, headers={"content-type": "application/json"})
        transport = httpx.MockTransport(reset_server(fp, fp))
        with patch("scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)):
            f = run(check_password_reset(seeded_target()))
        check(f"a correct response is not a leak: {label}", f["severity"] == CRITICAL, False)

    # AND THE REAL LEAKS STILL HAVE TO BE CAUGHT. Narrowing a detector is only safe if it
    # keeps firing on what it exists to find.
    real_leaks = {
        "hex reset token": '{"reset_token": "8f14e45fceea167a5a36dedd4bea2543", "ok": true}',
        "six-digit otp": '{"otp": "481920", "message": "sent"}',
        "six digits under code": '{"code": "391204", "message": "sent"}',
        "four digits under otp": '{"otp": "4819", "message": "sent"}',
        "jwt": '{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123DEF456"}',
    }
    for label, body in real_leaks.items():
        rl = httpx.Response(200, text=body, headers={"content-type": "application/json"})
        transport = httpx.MockTransport(reset_server(rl, rl))
        with patch("scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)):
            f = run(check_password_reset(seeded_target()))
        check(f"a real leak is still CRITICAL: {label}", f["severity"], CRITICAL)

    print("\n--- 8. A wall is SKIPPED, never PASSED ---------------------")

    # Two identical rejections look exactly like two identical correct answers. The
    # difference matters, so this must not read as a clean result.
    blocked = httpx.Response(403, text="Forbidden: CSRF token missing")
    transport = httpx.MockTransport(reset_server(blocked, blocked))
    with patch("scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_password_reset(seeded_target()))

    check("both probes blocked -> SKIPPED", f["severity"], SKIPPED)
    check("NOT passed", f["severity"] == PASSED, False)
    check("the finding explains the distinction", "identical rejections" in f["explanation"], True)

    captcha = httpx.Response(200, text="Please complete the CAPTCHA before continuing")
    transport = httpx.MockTransport(reset_server(captcha, captcha))
    with patch("scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_password_reset(seeded_target()))
    check("captcha on a 200 -> SKIPPED", f["severity"], SKIPPED)

    print("\n--- 9. The probe address can never be a real mailbox -------")

    log = []
    uniform_r = httpx.Response(200, text=uniform)
    transport = httpx.MockTransport(reset_server(uniform_r, uniform_r, log=log))
    with patch("scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)):
        run(check_password_reset(seeded_target()))

    check("one GET plus two POSTs, and no more", len(log), 3)
    check("the form is read first", log[0][0], "GET")
    check("then exactly two probes", [m for m, _ in log[1:]], ["POST", "POST"])

    # The absent-address probe must go FIRST: if a rate limiter trips after one request,
    # the spent probe is the harmless one rather than an email to the client's account.
    captured = []

    def capturing(request):
        if request.method == "POST":
            # unquote_plus for the same reason as reset_server: the @ is percent-encoded
            # on the wire, so a raw substring test would never see the address.
            captured.append(unquote_plus(request.content.decode("utf-8", "replace")))
            return httpx.Response(200, text=uniform)
        return httpx.Response(200, text=RESET_FORM_HTML, headers={"content-type": "text/html"})

    with patch(
        "scanning.checks.password_reset_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(capturing)),
    ):
        run(check_password_reset(seeded_target()))

    check("the nonexistent address is probed first", "example.invalid" in captured[0], True)
    check("the real address is probed second", TEST_USERNAME in captured[1], True)
    check("the probe address is at .invalid", "@example.invalid" in captured[0], True)
    check("the probe is randomised", "secuscan_probe_" in captured[0], True)

    print("\n--- 10. No reset flow is SKIPPED, not a finding ------------")

    # A site may legitimately have no self-service reset - accounts managed by an admin or
    # an external identity provider do not need one.
    bare = ScanTarget(url="", credentials={"username": TEST_USERNAME, "password": TEST_PASSWORD})
    bare._session_outcome = SessionOutcome(ok=True, cookies={"sessionid": "abc"})
    f = run(check_password_reset(bare))
    check("no reset flow -> SKIPPED", f["severity"], SKIPPED)
    check("no reset flow -> not a warning", f["severity"] == WARNING, False)
    check("the finding says it is not a fault", "not reported as a fault" in f["explanation"], True)

    print("\n--- 11. The password never escapes -------------------------")

    def echoing(request):
        if request.method == "GET":
            return httpx.Response(200, text=RESET_FORM_HTML, headers={"content-type": "text/html"})
        return httpx.Response(200, text=f"Received: {request.content.decode()}")

    with patch(
        "scanning.checks.password_reset_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(echoing)),
    ):
        f = run(check_password_reset(seeded_target()))
    check("password is not in the finding", TEST_PASSWORD in repr(f), False)

    print("\n--- 12. The finding shape is complete ----------------------")

    transport = httpx.MockTransport(reset_server(uniform_r, uniform_r))
    with patch("scanning.checks.password_reset_check.httpx.AsyncClient", client_factory(transport)):
        f = run(check_password_reset(seeded_target()))

    for key in ("id", "checkId", "tier", "title", "description", "severity", "explanation", "fix", "evidence"):
        check(f"finding carries {key}", key in f, True)
    check("checkId is this check", f["checkId"], "password_reset_check")

    print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()
