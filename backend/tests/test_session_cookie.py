"""
TESTS FOR THE SESSION COOKIE CHECK (Tier 2).

Verifies:
  1. No session -> SKIPPED, tier 2, never PASSED.
  2. The severity ladder: missing Secure and SameSite=None-without-Secure are CRITICAL;
     missing HttpOnly and missing SameSite are WARNINGs.
  3. Attribute names are matched case-insensitively, per RFC 6265. A server writing
     "httponly" or "HTTPONLY" is doing nothing wrong, and reporting it as a defect would
     be a false positive on a correct site.
  4. CSRF cookies are not judged on HttpOnly - they are MEANT to be readable by the
     page's own scripts, so complaining about them is noise, and a noisy check trains
     its reader to skim.
  5. THE VERDICT IS TAKEN ON THE WORST COOKIE. A hardened `sessionid` alongside a bare
     `remember_token` is only as safe as the weaker one, because either is enough to
     impersonate the user.
"""

import asyncio

import _path  # noqa: F401 - puts backend/ on sys.path
from scanning.checks._finding import CRITICAL, PASSED, SKIPPED, WARNING
from scanning.checks._session import SessionOutcome
from scanning.checks.session_cookie_check import check_session_cookie
from scanning.discovery import ScanTarget

PASS_COUNT = 0
FAIL_COUNT = 0


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


def seeded(set_cookie_lines, cookies=None, ok=True, reason=""):
    """A target whose login has already happened.

    _session.py memoises the outcome on the ScanTarget itself, so a test can pre-seed it
    and drive the check without any HTTP at all. That is the seam the design gives us for
    free, and it keeps these tests about cookie ATTRIBUTES rather than about logging in -
    which test_tier2_session.py already covers.
    """
    target = ScanTarget(url="https://example.com")
    target._session_outcome = SessionOutcome(
        ok=ok,
        reason=reason,
        submit_url="https://example.com/login",
        cookies=cookies if cookies is not None else {"sessionid": "abc"},
        set_cookie_lines=set_cookie_lines,
    )
    return target


def run_tests():
    print("\n--- 1. No session, no verdict ------------------------------")

    for reason in ("no_credentials", "rejected", "blocked", "no_session_cookie"):
        target = seeded([], ok=False, reason=reason)
        f = run(check_session_cookie(target))
        check(f"{reason} -> SKIPPED", f["severity"], SKIPPED)
        check(f"{reason} -> tier 2", f.get("tier"), 2)

    print("\n--- 2. Missing Secure is CRITICAL --------------------------")

    f = run(check_session_cookie(seeded(["sessionid=abc; Path=/; HttpOnly; SameSite=Lax"])))
    check("no Secure -> CRITICAL", f["severity"], CRITICAL)
    check("no Secure -> names the attribute", "Secure" in f["title"], True)
    check("no Secure -> names the cookie", "sessionid" in f["explanation"], True)
    check("tier is 2", f.get("tier"), 2)

    print("\n--- 3. SameSite=None without Secure is CRITICAL ------------")

    # ASSERT ON THE TITLE, NOT JUST THE SEVERITY. This case is also a missing-Secure case,
    # so a severity-only assertion passes whichever branch answers - and for a while it did
    # pass while the branch below was unreachable dead code, because the general
    # missing-Secure rule returned first and produced the same CRITICAL. The title is what
    # distinguishes the specific, actionable diagnosis from the generic one.
    f = run(check_session_cookie(seeded(["sid=abc; HttpOnly; SameSite=None"])))
    check("SameSite=None, no Secure -> CRITICAL", f["severity"], CRITICAL)
    check(
        "the specific SameSite=None diagnosis is the one reported",
        "SameSite=None" in f["title"],
        True,
    )
    check("it says browsers refuse the combination", "reject" in f["explanation"], True)

    # With Secure it is merely permissive, not the refused-by-browsers combination.
    f = run(check_session_cookie(seeded(["sid=abc; Secure; HttpOnly; SameSite=None"])))
    check("SameSite=None with Secure -> not critical", f["severity"] == CRITICAL, False)

    print("\n--- 4. Missing HttpOnly is a WARNING -----------------------")

    f = run(check_session_cookie(seeded(["sessionid=abc; Secure; SameSite=Lax"])))
    check("no HttpOnly -> WARNING", f["severity"], WARNING)
    check("no HttpOnly -> explains the XSS consequence", "document.cookie" in f["explanation"], True)

    print("\n--- 5. Missing SameSite is a WARNING -----------------------")

    f = run(check_session_cookie(seeded(["sessionid=abc; Secure; HttpOnly"])))
    check("no SameSite -> WARNING", f["severity"], WARNING)
    check("no SameSite -> names the attribute", "SameSite" in f["title"], True)

    print("\n--- 6. All three present is a PASS -------------------------")

    f = run(check_session_cookie(seeded(["sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"])))
    check("fully hardened -> PASSED", f["severity"], PASSED)
    check("pass says it read the real session", "test account" in f["explanation"], True)

    f = run(check_session_cookie(seeded(["sessionid=abc; Secure; HttpOnly; SameSite=Strict"])))
    check("SameSite=Strict -> PASSED", f["severity"], PASSED)

    print("\n--- 7. Attribute names are case-insensitive ----------------")

    # RFC 6265 makes these case-insensitive. A server writing them differently is correct,
    # and a check that only matched one spelling would report a false CRITICAL.
    f = run(check_session_cookie(seeded(["sessionid=abc; secure; httponly; samesite=lax"])))
    check("all lowercase -> PASSED", f["severity"], PASSED)

    f = run(check_session_cookie(seeded(["sessionid=abc; SECURE; HTTPONLY; SAMESITE=LAX"])))
    check("all uppercase -> PASSED", f["severity"], PASSED)

    f = run(check_session_cookie(seeded(["sessionid=abc; Secure; HttpOnly; SameSite=LAX"])))
    check("mixed-case value -> PASSED", f["severity"], PASSED)

    print("\n--- 8. CSRF cookies are not judged on HttpOnly -------------")

    # A CSRF token must be readable by the page's own JavaScript. Reporting it as a
    # finding would be a false positive against a correctly built site.
    f = run(
        check_session_cookie(
            seeded(
                [
                    "sessionid=abc; Secure; HttpOnly; SameSite=Lax",
                    "csrftoken=xyz; Secure; SameSite=Lax",
                ]
            )
        )
    )
    check("csrf without HttpOnly -> still PASSED", f["severity"], PASSED)
    check("csrf is not in the evidence", "csrftoken" in repr(f["evidence"]), False)

    print("\n--- 9. The verdict follows the worst cookie ----------------")

    f = run(
        check_session_cookie(
            seeded(
                [
                    "sessionid=abc; Secure; HttpOnly; SameSite=Lax",
                    "remember_token=xyz; Path=/",
                ]
            )
        )
    )
    check("one hardened, one bare -> CRITICAL", f["severity"], CRITICAL)
    check("the finding names the weak one", "remember_token" in f["explanation"], True)
    check("both cookies are in the evidence", len(f["evidence"]["sessionCookies"]), 2)

    print("\n--- 10. Cookies that are not sessions are ignored ----------")

    f = run(
        check_session_cookie(
            seeded(
                [
                    "sessionid=abc; Secure; HttpOnly; SameSite=Lax",
                    "locale=en-GB; Path=/",
                    "theme=dark; Path=/",
                ]
            )
        )
    )
    check("preference cookies do not lower the verdict", f["severity"], PASSED)
    check("only the session cookie is reported", len(f["evidence"]["sessionCookies"]), 1)

    print("\n--- 10b. The session vocabulary cannot drift -------------")

    # This check and _session.py must agree on what counts as a session cookie, and they
    # are only guaranteed to because they now share ONE definition. They did not before:
    # a local copy here lacked the `_sid` alternative _session.py carries, so a cookie
    # named `app_sid_v2` was a session to the login and invisible to this check - which
    # then reported "no Set-Cookie header was available" about a cookie it had been handed.
    # Asserting the AGREEMENT rather than a hardcoded name list is the point: a new name
    # added to one regex and not the other fails here, which is the bug this pins.
    from scanning.checks import _session as session_mod
    from scanning.checks import session_cookie_check as scc

    for name in ("app_sid_v2", "connect.sid", "PHPSESSID", "_sid", "auth_token", "jwt", "remember_me"):
        agreed = bool(scc._SESSION_NAME.search(name)) == bool(session_mod._SESSION_NAME_HINT.search(name))
        check(f"both modules agree on {name}", agreed, True)

    check(
        "the two regexes are the same object",
        scc._SESSION_NAME is session_mod._SESSION_NAME_HINT,
        True,
    )

    # A cookie name the drifted copy used to miss is now read and reported.
    f = run(check_session_cookie(seeded(["app_sid_v2=abc; HttpOnly"], {"app_sid_v2": "abc"})))
    check("a `_sid`-style cookie is no longer skipped", f["severity"], CRITICAL)
    check("it is reported by name", "app_sid_v2" in f["title"] or "app_sid_v2" in f["explanation"], True)

    print("\n--- 11. Nothing parseable is SKIPPED, never PASSED ---------")

    # The login established a session but the Set-Cookie lines were not visible - set on
    # a redirect hop this check did not see. Nothing observed, so nothing claimed.
    f = run(check_session_cookie(seeded([])))
    check("no Set-Cookie lines -> SKIPPED", f["severity"], SKIPPED)
    check("no Set-Cookie lines -> tier 2", f.get("tier"), 2)

    f = run(check_session_cookie(seeded(["locale=en-GB; Path=/"])))
    check("no session-shaped cookie -> SKIPPED", f["severity"], SKIPPED)

    # A malformed line must not raise.
    f = run(check_session_cookie(seeded(["", "garbage-without-equals", "sessionid=a; Secure; HttpOnly; SameSite=Lax"])))
    check("malformed lines are survived", f["severity"], PASSED)

    print("\n--- 12. The finding shape is complete ----------------------")

    f = run(check_session_cookie(seeded(["sessionid=abc; Path=/"])))
    for key in ("id", "checkId", "tier", "title", "description", "severity", "explanation", "fix", "evidence"):
        check(f"finding carries {key}", key in f, True)
    check("checkId is this check", f["checkId"], "session_cookie_check")
    check("cookie VALUE is never in the finding", "abc" in f["evidence"].get("loginEndpoint", ""), False)
    check(
        "cookie value is not in the reported attributes",
        any("abc" == c.get("name") for c in f["evidence"]["sessionCookies"]),
        False,
    )

    print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()
