"""
TESTS FOR THE TWO-FACTOR CHECK (Tier 2).

This check is the authenticated answer to the question mfa_check.py can only guess at
from the public pages: is there actually a way for a user to turn 2FA on?

Verifies:
  1. No session -> SKIPPED, tier 2.
  2. Enrolment controls found -> PASSED, and the KIND of factor is named: phishing-
     resistant (passkey, security key), authenticator app, or SMS.
  3. SMS-only is a PASS with the SIM-swap caveat stated rather than scored - the same
     position the Tier 1 check takes, so the two never appear to disagree.
  4. Nothing found on a page that WAS read -> WARNING.
  5. THE LOGIN-SCREEN TRAP. A security page fetched with a session that did not carry
     returns the login page. That page has no 2FA controls on it, and reading it naively
     produces the report's worst outcome: "no two-factor authentication available",
     stated confidently, about a page the scanner was never shown. Every login screen
     must be SKIPPED instead. This is the most important assertion in the file.
  6. Script and style bodies are not searched - an analytics snippet naming a
     "securityKey" variable is not a control a user can press.
"""

import asyncio
from unittest.mock import patch

import httpx

import _path  # noqa: F401 - puts backend/ on sys.path
from scanning.checks._finding import PASSED, SKIPPED, WARNING
from scanning.checks._session import SessionOutcome
from scanning.checks.two_factor_check import check_two_factor
from scanning.discovery import Page, ScanTarget

PASS_COUNT = 0
FAIL_COUNT = 0

_real_AsyncClient = httpx.AsyncClient

LOGIN_SCREEN = (
    "<html><body><h1>Sign in to your account</h1>"
    "<form><input name='email'><input name='password' type='password'>"
    "<a href='/forgot'>Forgot password?</a></form>"
    "<p>Don't have an account? Create an account</p></body></html>"
)

ACCOUNT_PAGE_NO_2FA = (
    "<html><body><h1>Account settings</h1>"
    "<p>Change your name, email address and mailing preferences.</p>"
    "<a href='/account/email'>Change email</a></body></html>"
)

ACCOUNT_PAGE_TOTP = (
    "<html><body><h1>Security</h1>"
    "<h2>Two-factor authentication</h2>"
    "<p>Set up an authenticator app to protect your account.</p>"
    "<button>Set up authenticator app</button></body></html>"
)

ACCOUNT_PAGE_PASSKEY = (
    "<html><body><h1>Security</h1>"
    "<p>Add a security key or passkey for phishing-resistant sign-in.</p>"
    "<button>Add a security key</button></body></html>"
)

ACCOUNT_PAGE_SMS = (
    "<html><body><h1>Security</h1>"
    "<h2>Two-factor authentication</h2>"
    "<p>Enable two-factor authentication and we will send a code by text message "
    "to your mobile number.</p></body></html>"
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
    home = Page(
        url="https://example.com/",
        status=200,
        html="",
        text="",
        links=links if links is not None else [("https://example.com/settings/security", "Security")],
    )
    target = ScanTarget(url="https://example.com", home=home)
    target._session_outcome = SessionOutcome(
        ok=ok,
        reason=reason,
        submit_url="https://example.com/login",
        cookies={"sessionid": "abc"},
        set_cookie_lines=["sessionid=abc; Path=/"],
    )
    return target


def serving(body, status=200):
    def handler(request):
        return httpx.Response(status, text=body, headers={"content-type": "text/html"})

    return handler


def run_tests():
    print("\n--- 1. No session, no verdict ------------------------------")

    for reason in ("no_credentials", "rejected", "blocked", "no_session_cookie"):
        f = run(check_two_factor(seeded_target(ok=False, reason=reason)))
        check(f"{reason} -> SKIPPED", f["severity"], SKIPPED)
        check(f"{reason} -> tier 2", f.get("tier"), 2)

    print("\n--- 2. An authenticator app -> PASSED ----------------------")

    with patch(
        "scanning.checks.two_factor_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(serving(ACCOUNT_PAGE_TOTP))),
    ):
        f = run(check_two_factor(seeded_target()))

    check("totp enrolment -> PASSED", f["severity"], PASSED)
    check("tier is 2", f.get("tier"), 2)
    check("the factor kind is named", "authenticator app" in f["description"], True)
    check("evidence records the factor", f["evidence"]["factors"]["authenticatorApp"], True)
    check("evidence names the page read", "security" in f["evidence"]["securityPage"], True)

    print("\n--- 3. A passkey is reported as phishing-resistant ---------")

    with patch(
        "scanning.checks.two_factor_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(serving(ACCOUNT_PAGE_PASSKEY))),
    ):
        f = run(check_two_factor(seeded_target()))

    check("passkey enrolment -> PASSED", f["severity"], PASSED)
    check("named as phishing-resistant", "phishing-resistant" in f["description"], True)
    check("evidence records it", f["evidence"]["factors"]["phishingResistant"], True)

    print("\n--- 4. SMS only is a PASS with the caveat stated -----------")

    with patch(
        "scanning.checks.two_factor_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(serving(ACCOUNT_PAGE_SMS))),
    ):
        f = run(check_two_factor(seeded_target()))

    check("sms only -> PASSED", f["severity"], PASSED)
    check("the title says only by SMS", "only by SMS" in f["title"], True)
    check("the SIM-swap risk is explained", "SIM" in f["explanation"], True)
    check("it is not scored down", f["severity"] == WARNING, False)
    check("evidence records sms", f["evidence"]["factors"]["sms"], True)

    print("\n--- 5. Nothing offered on a page that WAS read -> WARNING --")

    with patch(
        "scanning.checks.two_factor_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(serving(ACCOUNT_PAGE_NO_2FA))),
    ):
        f = run(check_two_factor(seeded_target()))

    check("no enrolment found -> WARNING", f["severity"], WARNING)
    check("tier is 2", f.get("tier"), 2)
    check("the finding says where it looked", "pagesTried" in f["evidence"], True)
    check("it is hedged as not-found", "not-found rather than not-present" in f["explanation"], True)
    check("the fix suggests TOTP", "TOTP" in f["fix"], True)
    check("the fix mentions recovery codes", "recovery codes" in f["fix"], True)

    print("\n--- 6. THE LOGIN-SCREEN TRAP -------------------------------")

    # The session did not carry, so every account page returns the login screen. A login
    # screen has no 2FA controls on it. Reporting that as "no 2FA offered" would be a
    # confident, wrong, and damaging answer about a page the scanner never saw.
    with patch(
        "scanning.checks.two_factor_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(serving(LOGIN_SCREEN))),
    ):
        f = run(check_two_factor(seeded_target()))

    check("login screen everywhere -> SKIPPED", f["severity"], SKIPPED)
    check("NOT a warning", f["severity"] == WARNING, False)
    check("NOT a pass", f["severity"] == PASSED, False)
    check("the finding explains the trap", "never shown" in f["explanation"], True)

    # A redirect to the login page is the same situation.
    def redirecting(request):
        if "/login" in request.url.path:
            return httpx.Response(200, text=LOGIN_SCREEN, headers={"content-type": "text/html"})
        return httpx.Response(302, headers={"location": "https://example.com/login"})

    with patch(
        "scanning.checks.two_factor_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(redirecting)),
    ):
        f = run(check_two_factor(seeded_target()))
    check("redirect to login -> SKIPPED", f["severity"], SKIPPED)

    print("\n--- 7. A change-password form is not a login screen --------")

    # An account page legitimately has a password input on it - the change-password form.
    # Requiring login-page PROSE as well as the input is what keeps this from being read
    # as a wall and skipped.
    account_with_password_form = (
        "<html><body><h1>Security</h1>"
        "<h2>Change password</h2><form><input type='password' name='current'></form>"
        "<h2>Two-factor authentication</h2><button>Set up authenticator app</button>"
        "</body></html>"
    )
    with patch(
        "scanning.checks.two_factor_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(serving(account_with_password_form))),
    ):
        f = run(check_two_factor(seeded_target()))
    check("password field alone is not a login screen", f["severity"], PASSED)

    print("\n--- 8. Scripts and styles are not searched -----------------")

    # An analytics snippet naming a "securityKey" variable is not a control a user can
    # press. Matching on it would be a false PASS - the worst direction to be wrong in.
    script_only = (
        "<html><head><script>var securityKey = null; // passkey rollout flag\n"
        "function setUpAuthenticatorApp(){}</script>"
        "<style>.passkey-badge{display:none}</style></head>"
        "<body><h1>Account settings</h1><p>Change your name and email.</p></body></html>"
    )
    with patch(
        "scanning.checks.two_factor_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(serving(script_only))),
    ):
        f = run(check_two_factor(seeded_target()))
    check("script contents do not earn a pass", f["severity"], WARNING)

    print("\n--- 9. It stops at the first page that answers -------------")

    visited = []

    def counting(request):
        visited.append(str(request.url))
        if "security" in str(request.url):
            return httpx.Response(200, text=ACCOUNT_PAGE_TOTP, headers={"content-type": "text/html"})
        return httpx.Response(200, text=ACCOUNT_PAGE_NO_2FA, headers={"content-type": "text/html"})

    with patch(
        "scanning.checks.two_factor_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(counting)),
    ):
        f = run(check_two_factor(seeded_target()))
    check("found on the first page -> one request", len(visited), 1)
    check("and it passed", f["severity"], PASSED)

    # With no link, it falls back to conventional paths - capped, so it never crawls.
    visited.clear()
    target = seeded_target(links=[("https://example.com/about", "About")])
    with patch(
        "scanning.checks.two_factor_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(counting)),
    ):
        run(check_two_factor(target))
    check("conventional paths are capped at four", len(visited) <= 4, True)

    print("\n--- 10. Third-party and unreachable cases ------------------")

    # An identity provider's security page belongs to someone who did not consent.
    target = seeded_target(links=[("https://accounts.google.com/security", "Security")])
    with patch(
        "scanning.checks.two_factor_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(serving(ACCOUNT_PAGE_TOTP))),
    ):
        f = run(check_two_factor(target))
    check("third-party page is not fetched", "google.com" in repr(f["evidence"]), False)

    bare = ScanTarget(url="")
    bare._session_outcome = SessionOutcome(ok=True, cookies={"sessionid": "abc"})
    f = run(check_two_factor(bare))
    check("no candidates at all -> SKIPPED", f["severity"], SKIPPED)

    def exploding(request):
        raise httpx.ConnectTimeout("timed out")

    with patch(
        "scanning.checks.two_factor_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(exploding)),
    ):
        f = run(check_two_factor(seeded_target()))
    check("every request failing -> SKIPPED", f["severity"], SKIPPED)
    check("NOT reported as missing 2FA", f["severity"] == WARNING, False)

    print("\n--- 11. The finding shape is complete ----------------------")

    with patch(
        "scanning.checks.two_factor_check.httpx.AsyncClient",
        client_factory(httpx.MockTransport(serving(ACCOUNT_PAGE_TOTP))),
    ):
        f = run(check_two_factor(seeded_target()))

    for key in ("id", "checkId", "tier", "title", "description", "severity", "explanation", "fix", "evidence"):
        check(f"finding carries {key}", key in f, True)
    check("checkId is this check", f["checkId"], "two_factor_check")
    check("the session cookie value never appears", "abc" in repr(f), False)

    print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()
