"""
TESTS FOR ACCOUNT ENUMERATION CHECK (Tier 2 Check #5).

Verifies:
  1. Missing credentials or username returns SKIPPED with tier=2.
  2. Differential error messages (e.g. "User not found" vs "Incorrect password")
     triggers WARNING ("Account enumeration via error messages").
  3. Differential HTTP status codes (e.g. 404 vs 401) triggers WARNING
     ("Account enumeration via HTTP status codes").
  4. Uniform responses (same status code, generic "Invalid credentials" error)
     returns PASSED.
  5. Findings strictly carry tier=2.
  6. The submitted password is NEVER present in the finding or evidence.
"""

import asyncio
from unittest.mock import patch
import httpx

import _path  # noqa: F401 - puts backend/ on sys.path
from scanning.checks._finding import PASSED, SKIPPED, WARNING
from scanning.checks.account_enumeration_check import check_account_enumeration
from scanning.discovery import Field, Form, Page, ScanTarget

PASS_COUNT = 0
FAIL_COUNT = 0


_real_AsyncClient = httpx.AsyncClient


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


def run_tests():
    print("\n--- 1. Missing Credentials ---------------------------------")
    target_no_creds = ScanTarget(url="https://example.com")
    f1 = run(check_account_enumeration(target_no_creds))
    check("no credentials severity is SKIPPED", f1["severity"], SKIPPED)
    check("finding tier is 2", f1.get("tier"), 2)

    target_empty_user = ScanTarget(
        url="https://example.com",
        credentials={"username": "", "password": "abc"},
    )
    f2 = run(check_account_enumeration(target_empty_user))
    check("empty username severity is SKIPPED", f2["severity"], SKIPPED)
    check("empty username tier is 2", f2.get("tier"), 2)

    print("\n--- 2. Differential Error Messages (Leak Detected) ---------")
    # Simulate an endpoint leaking "User not found" vs "Incorrect password"
    login_page = Page(
        url="https://example.com/login",
        status=200,
        html="<form action='/login' method='post'><input name='email'><input name='password' type='password'></form>",
        text="Login",
        forms=[
            Form(
                submit_url="/login",
                method="POST",
                fields=[
                    Field(tag="input", type="text", name="email"),
                    Field(tag="input", type="password", name="password"),
                ],
            )
        ],
    )
    target_leaking = ScanTarget(
        url="https://example.com",
        login=login_page,
        credentials={"username": "alice@example.com", "password": "SecretActualPassword123!"},
    )

    def mock_handler_message_diff(request: httpx.Request):
        content = request.content.decode("utf-8")
        if "alice" in content:
            return httpx.Response(401, json={"error": "Incorrect password"})
        return httpx.Response(401, json={"error": "User does not exist"})

    def client_factory(transport):
        def _factory(*args, **kwargs):
            kwargs["transport"] = transport
            return _real_AsyncClient(*args, **kwargs)
        return _factory

    transport_diff = httpx.MockTransport(mock_handler_message_diff)

    with patch("scanning.checks.account_enumeration_check.httpx.AsyncClient", client_factory(transport_diff)):
        f3 = run(check_account_enumeration(target_leaking))

    check("differential message severity is WARNING", f3["severity"], WARNING)
    check("differential message title", f3["title"], "Account enumeration via error messages")
    check("finding tier is 2", f3.get("tier"), 2)
    # Critical security assertion: password is never in finding or evidence
    finding_str = str(f3)
    check("actual password not in finding", "SecretActualPassword123!" in finding_str, False)
    check("dummy password not in finding evidence", "SecuScanDummyProbeP@ssw0rd!#" in str(f3["evidence"]), False)

    print("\n--- 3. Differential Status Codes (Leak Detected) -----------")
    def mock_handler_status_diff(request: httpx.Request):
        content = request.content.decode("utf-8")
        if "alice" in content:
            return httpx.Response(401, json={"message": "Authentication failed"})
        return httpx.Response(404, json={"message": "Authentication failed"})

    transport_status_diff = httpx.MockTransport(mock_handler_status_diff)

    with patch("scanning.checks.account_enumeration_check.httpx.AsyncClient", client_factory(transport_status_diff)):
        f4 = run(check_account_enumeration(target_leaking))

    check("differential status code severity is WARNING", f4["severity"], WARNING)
    check("differential status code title", f4["title"], "Account enumeration via HTTP status codes")
    check("finding tier is 2", f4.get("tier"), 2)

    print("\n--- 4. Uniform Generic Error (PASSED) -----------------------")
    def mock_handler_uniform(request: httpx.Request):
        return httpx.Response(401, json={"message": "Invalid username or password"})

    transport_uniform = httpx.MockTransport(mock_handler_uniform)

    with patch("scanning.checks.account_enumeration_check.httpx.AsyncClient", client_factory(transport_uniform)):
        f5 = run(check_account_enumeration(target_leaking))

    check("uniform error severity is PASSED", f5["severity"], PASSED)
    check("uniform error title", f5["title"], "No account enumeration detected")
    check("finding tier is 2", f5.get("tier"), 2)

    print("\n--- 5. A wall is not a pass --------------------------------")
    # THE MOST IMPORTANT SECTION IN THIS FILE. Identical responses are the check's PASS
    # condition, and the easiest way to get identical responses is for both probes to
    # be turned away before the application ever looks up an account: a CSRF token the
    # check does not carry, a WAF, a rate limiter. Reporting that as "no account
    # enumeration detected" tells the client a control was verified when nothing was
    # tested at all, which is the point at which they stop looking.
    def mock_handler_csrf(request: httpx.Request):
        return httpx.Response(403, json={"error": "CSRF token missing or invalid"})

    transport_csrf = httpx.MockTransport(mock_handler_csrf)

    with patch("scanning.checks.account_enumeration_check.httpx.AsyncClient", client_factory(transport_csrf)):
        f6 = run(check_account_enumeration(target_leaking))

    check("a CSRF wall is SKIPPED, not PASSED", f6["severity"], SKIPPED)
    check("  and it is emphatically not a pass", f6["severity"] == PASSED, False)
    check("  the title says it could not be tested",
          f6["title"], "Authentication endpoint could not be tested")
    check("  finding tier is 2", f6.get("tier"), 2)

    # Rate limiting engaging partway through the probe rounds looks the same from here.
    def mock_handler_rate_limited(request: httpx.Request):
        return httpx.Response(429, json={"message": "Too many requests"})

    transport_rate_limited = httpx.MockTransport(mock_handler_rate_limited)

    with patch("scanning.checks.account_enumeration_check.httpx.AsyncClient", client_factory(transport_rate_limited)):
        f7 = run(check_account_enumeration(target_leaking))

    check("a rate-limited endpoint is SKIPPED", f7["severity"], SKIPPED)
    check("  and not PASSED", f7["severity"] == PASSED, False)

    # A 200 carrying a CSRF complaint in the body is the same wall wearing a different
    # status code, so the text hints have to catch that one on their own.
    def mock_handler_soft_csrf(request: httpx.Request):
        return httpx.Response(200, json={"error": "Invalid CSRF token"})

    transport_soft_csrf = httpx.MockTransport(mock_handler_soft_csrf)

    with patch("scanning.checks.account_enumeration_check.httpx.AsyncClient", client_factory(transport_soft_csrf)):
        f8 = run(check_account_enumeration(target_leaking))

    check("a 200 CSRF complaint is SKIPPED too", f8["severity"], SKIPPED)

    print("\n--- 6. A 200 is not exempt from the status check ------------")
    # 200 for one account and 401 for the other is the most blatant shape this leak
    # takes. An earlier version required BOTH statuses to be non-200 before reporting a
    # discrepancy, which excluded precisely this case.
    def mock_handler_200_vs_401(request: httpx.Request):
        content = request.content.decode("utf-8")
        if "alice" in content:
            return httpx.Response(200, json={"message": "Please check your password"})
        return httpx.Response(401, json={"message": "Please check your password"})

    transport_200_vs_401 = httpx.MockTransport(mock_handler_200_vs_401)

    with patch("scanning.checks.account_enumeration_check.httpx.AsyncClient", client_factory(transport_200_vs_401)):
        f9 = run(check_account_enumeration(target_leaking))

    check("200 vs 401 is reported", f9["severity"], WARNING)
    check("  as a status code discrepancy",
          f9["title"], "Account enumeration via HTTP status codes")

    print("\n--- 7. The test account is not spelled out in the report ----")
    # The client supplied this address and the report goes back to the client, so this
    # is hygiene rather than secrecy - but a scan report gets forwarded, pasted into
    # tickets and archived, and half a credential pair does not need to be legible in
    # it for the reader to know which account was tested.
    evidence = f5["evidence"]

    check("the full address is not in the evidence",
          "alice@example.com" in str(evidence), False)
    check("nor anywhere else in the finding",
          "alice@example.com" in str(f5), False)
    check("but the domain survives, so the account stays identifiable",
          str(evidence.get("testedExistingUser", "")).endswith("@example.com"), True)
    check("and the number of timing samples is on the record",
          evidence.get("timingSamplesPerAccount"), 3)

    print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()
