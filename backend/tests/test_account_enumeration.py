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
  7. THE USERNAME GOES OUT UNDER THE RIGHT FIELD NAME, read from _session's shared
     helper rather than from a private copy of it. The copy tested the name before the
     type and let the LAST match win, so an ordinary submit button named "login", a
     "remember my username" checkbox or a trailing OTP box took the username's place -
     and because the username then never reached the server, both probes were turned
     away identically, which is this check's PASS condition. A site that really does
     enumerate was told it does not.
  8. A 404 IS NOT A CLEAN BILL OF HEALTH. Two 404s are byte-for-byte identical, so an
     address with no authentication logic behind it - most easily the guessed
     /api/login fallback - read as "no account enumeration detected". Both sides must
     be 404 for the guard to fire, because 404-for-unknown against 401-for-known is
     the most blatant shape of the leak itself (section 3).
"""

import asyncio
import inspect
from unittest.mock import patch
from urllib.parse import parse_qs

import httpx

import _path  # noqa: F401 - puts backend/ on sys.path
from scanning.checks._finding import PASSED, SKIPPED, WARNING
from scanning.checks import _session as session_mod
from scanning.checks import account_enumeration_check as acct_mod
from scanning.checks.account_enumeration_check import check_account_enumeration
from scanning.discovery import Field, Form, Page, ScanTarget, _parse_page

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

    print("\n--- 3b. TWO DIFFERENT PRE-AUTH STATUSES ARE STILL A WALL ---")

    # The false WARNING this pins. The guard used to require the two statuses to be
    # EQUAL before it would call the endpoint unreachable, but its own rationale names
    # the case that breaks: "a rate limiter that engaged partway through the rounds".
    # The probes alternate, so a limiter tripping mid-run answers one 403 and the next
    # 429 - two different statuses, neither of which involved an account lookup. That
    # fell straight through to the status_diff branch and reported "the endpoint returns
    # different HTTP status codes for valid vs invalid accounts": an enumeration warning
    # against a server that never looked an account up. Found by pointing a real tier=2
    # scan at the e2e fixture, which answers every POST 405.
    def mock_handler_mixed_wall(pair):
        seen = {"n": 0}

        def handler(request: httpx.Request):
            # The check sends an unmeasured warm-up first, then alternates
            # existing/nonexistent. Flipping on every call is what a limiter engaging
            # mid-run looks like from the outside.
            status = pair[seen["n"] % 2]
            seen["n"] += 1
            return httpx.Response(status, text="Forbidden")

        return handler

    for a, b in ((403, 429), (429, 403), (405, 501), (503, 429)):
        transport_mixed = httpx.MockTransport(mock_handler_mixed_wall((a, b)))
        with patch("scanning.checks.account_enumeration_check.httpx.AsyncClient", client_factory(transport_mixed)):
            fw = run(check_account_enumeration(target_leaking))
        check(f"{a}/{b} -> SKIPPED", fw["severity"], SKIPPED)
        check(f"  {a}/{b} -> NOT a warning", fw["severity"] == WARNING, False)

    # THE GUARD MUST NOT SWALLOW A REAL FINDING. Neither 401 nor 404 is a pre-auth
    # status - both mean the application looked and answered differently - so the
    # status_diff branch asserted in section 3 above must still fire. This pins the
    # boundary: one probe walled off and one answered is still reported.
    def mock_handler_one_wall(request: httpx.Request):
        content = request.content.decode("utf-8")
        if "alice" in content:
            return httpx.Response(403, text="Forbidden")
        return httpx.Response(404, json={"message": "No such user"})

    transport_one_wall = httpx.MockTransport(mock_handler_one_wall)
    with patch("scanning.checks.account_enumeration_check.httpx.AsyncClient", client_factory(transport_one_wall)):
        fo = run(check_account_enumeration(target_leaking))
    check("one probe walled, one answered -> still reported", fo["severity"], WARNING)

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

    print("\n--- 8. THE USERNAME GOES OUT UNDER THE RIGHT FIELD NAME ----")

    # Driven through the REAL parser and a server that really does enumerate, because
    # the failure this pins is not a wrong string somewhere - it is a WARNING quietly
    # becoming a PASSED. The markup below differs from an ordinary login form by one
    # submit button, which every second site has.

    def leaky(request: httpx.Request):
        """A site that leaks: it reads the field its own form declares."""
        body = parse_qs(request.content.decode("utf-8"))
        user = (body.get("username") or [""])[0]
        if not user:
            # What a server says when the field it wants was never sent - and note the
            # 400: not in the pre-auth set, so it falls through to the PASSED branch.
            return httpx.Response(400, json={"error": "username is required"})
        if "alice" in user:
            return httpx.Response(401, json={"error": "Incorrect password"})
        return httpx.Response(404, json={"error": "User does not exist"})

    def verdict_for(inner_html, handler=leaky):
        page = _parse_page(httpx.Response(
            200,
            text=f"<html><body><form action='/login' method='post'>{inner_html}</form></body></html>",
            request=httpx.Request("GET", "https://example.com/login"),
        ))
        target = ScanTarget(
            url="https://example.com",
            login=page,
            credentials={"username": "alice@example.com", "password": "SecretActualPassword123!"},
        )
        with patch("scanning.checks.account_enumeration_check.httpx.AsyncClient",
                   client_factory(httpx.MockTransport(handler))):
            return run(check_account_enumeration(target))

    PLAIN = "<input type='text' name='username'><input type='password' name='password'>"

    f10 = verdict_for(PLAIN)
    check("the control: a leaky site is reported", f10["severity"], WARNING)
    check("  under the field its form declares", f10["evidence"]["usernameField"], "username")

    f11 = verdict_for(PLAIN + "<input type='submit' name='login' value='Sign in'>")
    check("a submit button named 'login' is not the username box",
          f11["evidence"]["usernameField"], "username")
    check("  so the leak is still reported", f11["severity"], WARNING)

    f12 = verdict_for(PLAIN + "<input type='checkbox' name='remember_username' value='1'>")
    check("a remember-me checkbox is not the username box",
          f12["evidence"]["usernameField"], "username")
    check("  so the leak is still reported", f12["severity"], WARNING)

    f13 = verdict_for(PLAIN + "<input type='text' name='otp_code'>")
    check("a trailing OTP box does not take the username's place",
          f13["evidence"]["usernameField"], "username")
    check("  so the leak is still reported", f13["severity"], WARNING)

    # The hidden case is checked against the WIRE, not the evidence, because it has two
    # halves and the second one is invisible in the finding: a hidden field mistaken for
    # the username box is also never sent as ITSELF, so the server loses a value it was
    # waiting on - "login_challenge" (Ory) is required, and without it the request never
    # reaches an account lookup at all.
    bodies = []

    def leaky_recording(request: httpx.Request):
        bodies.append(request.content.decode("utf-8"))
        return leaky(request)

    f14 = verdict_for(
        "<input type='hidden' name='login_challenge' value='abc'>" + PLAIN,
        handler=leaky_recording,
    )
    check("a hidden field whose name matches is not the username box",
          f14["evidence"]["usernameField"], "username")
    check("  so the leak is still reported", f14["severity"], WARNING)
    check("  the hidden value is sent as itself",
          all("login_challenge=abc" in b for b in bodies), True)
    check("  and the username is not sent under its name",
          any("login_challenge=alice" in b for b in bodies), False)

    # The rule underneath all five: this module must not work the field names out for
    # itself. The seam is the helper, so that is what is asserted - the shared object,
    # not merely equal behaviour.
    check("the field names come from the shared helper",
          acct_mod._field_names is session_mod._field_names, True)

    # AND THE PATTERN, WHICH NEEDS A DIFFERENT KIND OF ASSERTION THAN IT LOOKS.
    # `local is shared` is worth nothing for a compiled pattern: re.compile caches by
    # (pattern, flags), so a module that pastes the identical pattern text back in is
    # handed the SAME object and the identity test passes. Not hypothetical - the
    # private copy this section exists for satisfied it. Nothing at runtime can tell an
    # alias from a paste, because they are one object, so the question is asked of the
    # source instead. test_tier2_session.py section 11 asks it of every check module;
    # this asks it here too, because this is the module it happened in.
    check("no private copy of the username hint in the source",
          session_mod._USERNAME_HINT.pattern in inspect.getsource(acct_mod), False)

    print("\n--- 9. A 404 IS NOT A CLEAN BILL OF HEALTH -----------------")

    # The guessed /api/login fallback makes this easy to reach: no login form was found,
    # so the check probes a conventional path, gets two identical 404s - and identical
    # responses are what passing looks like here. The report read "returned identical
    # HTTP 404 responses" as the good news.
    def gone(request: httpx.Request):
        return httpx.Response(404, text="<h1>404 Not Found</h1>")

    target_no_form = ScanTarget(
        url="https://example.com",
        credentials={"username": "alice@example.com", "password": "SecretActualPassword123!"},
    )
    with patch("scanning.checks.account_enumeration_check.httpx.AsyncClient",
               client_factory(httpx.MockTransport(gone))):
        f15 = run(check_account_enumeration(target_no_form))

    check("two 404s are not a pass", f15["severity"], SKIPPED)
    check("  and the title says what happened",
          f15["title"], "No authentication endpoint was found to test")
    check("  the guessed endpoint is on the record",
          f15["evidence"]["endpoint"], "https://example.com/api/login")
    # A skip reason selects the remediation, so it must not be the wall one: telling a
    # customer to allowlist the scanner is wrong advice when nothing blocked it.
    check("  the fix asks for the endpoint, not an allowlist",
          "allowlist" in f15["fix"].lower(), False)
    check("  and does ask for the sign-in page",
          "sign-in page" in f15["fix"], True)

    def also_gone(request: httpx.Request):
        return httpx.Response(410, text="gone")

    with patch("scanning.checks.account_enumeration_check.httpx.AsyncClient",
               client_factory(httpx.MockTransport(also_gone))):
        f16 = run(check_account_enumeration(target_no_form))
    check("410 is treated the same way", f16["severity"], SKIPPED)

    # BOTH SIDES, and this is the assertion that stops the new guard eating the check's
    # best finding: 404 for an unknown account against 401 for a known one IS the leak,
    # not a missing endpoint. Section 3 covers it from the other direction; it is
    # repeated here against the guard that could silence it.
    f17 = verdict_for(PLAIN)
    check("404 on one side only is still the leak", f17["severity"], WARNING)
    check("  reported as a message discrepancy",
          f17["title"], "Account enumeration via error messages")

    print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()
