"""Branch tests for the new checks and the engine's crash handling.

Builds synthetic Page / ScanTarget objects rather than serving HTTP, because
these branches are about the DECISION each check makes given known input - no
network needed, and the fixture reads as the case it is testing.
"""

import asyncio
import re

import _path  # noqa: F401  - puts backend/ on sys.path; must precede the imports below
from scanning.checks._finding import CRITICAL, PASSED, SKIPPED, WARNING
from scanning.checks.cookies_check import check_cookies
from scanning.checks.mfa_check import check_mfa
from scanning.discovery import Field, Form, Page, ScanTarget
import inspect

from scanning.engine import (
    TIER1_CHECKS,
    TIER2_CHECKS,
    _crash_finding,
    calculate_score,
)

PASS_COUNT = 0
FAIL_COUNT = 0


def check(label, got, want):
    global PASS_COUNT, FAIL_COUNT
    ok = got == want
    if ok:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    mark = "ok  " if ok else "FAIL"
    detail = "" if ok else f"   (got {got!r}, wanted {want!r})"
    print(f"  {mark} {label}{detail}")


def page(url, text="", links=None, cookies=None, forms=None, headers=None):
    links = links or []

    # Discovery's parser captures a link's text into the PAGE text as well as into
    # the link (see _PageParser.handle_data), so a fixture that keeps the two apart
    # describes a Page that discovery cannot produce. Mirroring it here keeps these
    # tests honest about what the checks will really be handed.
    full_text = " ".join([text] + [link_text for _, link_text in links]).strip()

    return Page(
        url=url,
        status=200,
        html=f"<html><body>{full_text}</body></html>",
        text=full_text,
        forms=forms or [],
        links=links,
        set_cookies=cookies or [],
        headers=headers or {},
    )


def login_form():
    return Form(
        submit_url="/session",
        method="post",
        fields=[
            Field(tag="input", type="email", name="email"),
            Field(tag="input", type="password", name="password"),
        ],
    )


run = asyncio.run

# =========================================================================
print("mfa_check branches")
# =========================================================================

# A brochure site: no login, no signup, no password field anywhere. This is the
# case SKIPPED was invented for - it must not cost score.
brochure = ScanTarget(
    url="https://brochure.example",
    home=page("https://brochure.example/", text="We make excellent widgets. Call us."),
)
result = run(check_mfa(brochure))
check("brochure site -> skipped", result["severity"], SKIPPED)
check("brochure evidence loginFound", result["evidence"]["loginFound"], False)

# An account system with no MFA wording and no MFA route: the honest warning.
no_mfa = ScanTarget(
    url="https://plain.example",
    home=page("https://plain.example/", text="Welcome", links=[("https://plain.example/login", "Sign in")]),
    login=page(
        "https://plain.example/login",
        text="Sign in with your email and password.",
        forms=[login_form()],
    ),
)
result = run(check_mfa(no_mfa))
check("account, no MFA -> warning", result["severity"], WARNING)
check("never critical", result["severity"] != CRITICAL, True)

# SMS is the ONLY factor mentioned: a pass, but the caveat must be in the title.
sms_only = ScanTarget(
    url="https://sms.example",
    home=page("https://sms.example/"),
    login=page(
        "https://sms.example/login",
        text=(
            "Two-factor authentication is on. We will send an SMS code to your "
            "mobile number to confirm it is you."
        ),
        forms=[login_form()],
    ),
)
result = run(check_mfa(sms_only))
check("SMS only -> passed", result["severity"], PASSED)
check("SMS only says so in title", "only by SMS" in result["title"], True)
check("SMS only strongFactorSeen", result["evidence"]["strongFactorSeen"], False)
check("SMS only smsMentioned", result["evidence"]["smsMentioned"], True)

# SMS *and* an authenticator: the strong factor must win, so no SMS caveat. This is
# the case the phrase-vs-page-text bug got wrong.
sms_and_totp = ScanTarget(
    url="https://both.example",
    home=page("https://both.example/"),
    login=page(
        "https://both.example/login",
        text=(
            "Two-factor authentication is required. Use your authenticator app, or "
            "have an SMS code sent to your mobile number."
        ),
        forms=[login_form()],
    ),
)
result = run(check_mfa(sms_and_totp))
check("SMS + TOTP -> passed", result["severity"], PASSED)
check("SMS + TOTP no SMS caveat", "only by SMS" not in result["title"], True)
check("SMS + TOTP strongFactorSeen", result["evidence"]["strongFactorSeen"], True)

# A published route alone is enough. The link TEXT here deliberately carries no MFA
# vocabulary ("Manage passkeys" would be matched by MFA_TEXT via the page text), so
# the only thing that can produce a hit is the href - which is what this asserts.
route_only = ScanTarget(
    url="https://route.example",
    home=page(
        "https://route.example/",
        text="Welcome",
        links=[("https://route.example/settings/passkeys", "Manage")],
    ),
    login=page("https://route.example/login", text="Sign in", forms=[login_form()]),
)
result = run(check_mfa(route_only))
check("route only -> passed", result["severity"], PASSED)
check("route only strongFactorSeen", result["evidence"]["strongFactorSeen"], True)

# A loose password field with no <form> - the React case discovery carries
# separately - still counts as an account system.
spa = ScanTarget(
    url="https://spa.example",
    home=page("https://spa.example/", text="Sign in to continue"),
)
spa.home.loose_password_fields = [Field(tag="input", type="password", name="password")]
result = run(check_mfa(spa))
check("SPA loose password -> warning not skipped", result["severity"], WARNING)

# Duplicate MFA links across pages are one fact, not three.
dupes = ScanTarget(
    url="https://dupes.example",
    home=page("https://dupes.example/", text="Hi", links=[("https://dupes.example/2fa", "2FA")]),
    login=page(
        "https://dupes.example/login",
        text="Sign in",
        links=[("https://dupes.example/2fa", "2FA")],
        forms=[login_form()],
    ),
)
result = run(check_mfa(dupes))
check("duplicate hrefs deduped", len(result["evidence"]["pathEvidence"]), 1)

# =========================================================================
print("\ncookies_check branches")
# =========================================================================

no_cookies = ScanTarget(url="https://nc.example", home=page("https://nc.example/"))
result = run(check_cookies(no_cookies))
check("no cookies -> skipped", result["severity"], SKIPPED)

fully_flagged = ScanTarget(
    url="https://good.example",
    home=page(
        "https://good.example/",
        cookies=["sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"],
    ),
)
result = run(check_cookies(fully_flagged))
check("flagged session cookie -> passed", result["severity"], PASSED)

bare_session = ScanTarget(
    url="https://bad.example",
    home=page("https://bad.example/", cookies=["sessionid=abc; Path=/"]),
)
result = run(check_cookies(bare_session))
check("bare session cookie -> critical", result["severity"], CRITICAL)

# A non-session cookie missing the same flags is a warning, not an emergency.
analytics_only = ScanTarget(
    url="https://an.example",
    home=page("https://an.example/", cookies=["_ga=GA1.2.3; Path=/"]),
)
result = run(check_cookies(analytics_only))
check("analytics cookie -> warning", result["severity"], WARNING)

# A long-lived session cookie that IS otherwise flagged is a warning.
long_lived = ScanTarget(
    url="https://ll.example",
    home=page(
        "https://ll.example/",
        cookies=[
            "sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=31536000"
        ],
    ),
)
result = run(check_cookies(long_lived))
check("year-long session cookie -> warning", result["severity"], WARNING)

# A malformed Set-Cookie must be skipped, not crash the check.
malformed = ScanTarget(
    url="https://mf.example",
    home=page(
        "https://mf.example/",
        cookies=["", "   ", "novalue", "sessionid=abc; Secure; HttpOnly; SameSite=Lax"],
    ),
)
result = run(check_cookies(malformed))
check("malformed cookies survived", result["severity"], PASSED)

# Max-Age that is not a number must not crash the parser.
bad_max_age = ScanTarget(
    url="https://bma.example",
    home=page(
        "https://bma.example/",
        cookies=["sessionid=abc; Secure; HttpOnly; SameSite=Lax; Max-Age=forever"],
    ),
)
result = run(check_cookies(bad_max_age))
check("non-numeric Max-Age survived", result["severity"], PASSED)

# =========================================================================
print("\nengine crash handling")
# =========================================================================

crash = _crash_finding("exploding_check", ValueError("secret leaked in message"))
check("crash -> warning", crash["severity"], WARNING)
check("crash names the check", crash["checkId"], "exploding_check")
check("crash records exception type", crash["evidence"]["error"], "ValueError")

# The exception MESSAGE must never be stored - it can carry a fragment of the
# target's response, and this document is written to MongoDB and rendered.
blob = repr(crash)
check("crash omits exception message", "secret leaked" not in blob, True)

contract = ("id", "checkId", "title", "description", "severity",
            "explanation", "fix", "evidence")
check("crash meets finding contract", [k for k in contract if k not in crash], [])

# A crashed check must count against the score, never as a free pass.
check("crash costs score", calculate_score([crash]), 50)


# =========================================================================
print("\n--- Tier 1 is passive, and stays passive --------------------------------")
# =========================================================================
#
# THE HARDEST RULE IN THIS CODEBASE, AND UNTIL NOW THE ONLY UNGUARDED ONE.
# A Tier 1 scan runs against a site whose owner asked for a scan and nothing more. It
# reads pages that discovery.py already fetched with GETs and it forms an opinion. It
# does not submit forms, does not attempt logins and does not write anything, because a
# single POST would turn an audit into an unauthorised active test of somebody else's
# production system on a plan that never asked their permission for it.
#
# That rule survived on convention right up until an active check moved in next door.
# scanning/checks/ now holds a Tier 2 check that posts login attempts on purpose, and it
# is imported into the same module as the Tier 1 registry, a few lines above it. Moving
# a name between those two lists is a two-second edit that reads to a reviewer as
# bookkeeping - and until this section existed, nothing anywhere would have failed.
#
# So the registry is checked by NAME and the modules are checked by SOURCE. The second
# half is the one that earns its keep: it also catches a POST added to a check that is
# ALREADY in Tier 1, which is the version of this mistake nobody would think to look for.

check("Tier 1 has the expected number of checks", len(TIER1_CHECKS), 7)

_tier1_modules = {c.__name__: inspect.getmodule(c) for c in TIER1_CHECKS}
_tier2_names = {c.__name__ for c in TIER2_CHECKS}

# Every Tier 2 check by name. Listed explicitly rather than derived from the registry,
# because deriving it from the thing under test would make this assertion vacuous - a
# check that moved to Tier 1 would simply disappear from both sides and pass.
for _tier2_name in (
    "check_account_enumeration",
    "check_session_cookie",
    "check_logout",
    "check_password_reset",
    "check_two_factor",
):
    check(f"{_tier2_name} is Tier 2", _tier2_name in _tier2_names, True)
    check(f"  and is nowhere in Tier 1", _tier2_name in _tier1_modules, False)

check("Tier 2 has the expected number of checks", len(TIER2_CHECKS), 5)

# THE SHARED TIER 2 HELPERS POST, AND MUST STAY OUT OF TIER 1.
# _session.py submits credentials and _endpoints.py imports it. Neither is a check, so
# neither appears in a registry - but a Tier 1 check that imported either would gain the
# ability to post without any name moving between the two lists above. The source walk
# below would catch the .post( itself; this catches the import, which is the earlier and
# clearer signal.
# Matched as an IMPORT STATEMENT, not as a bare substring: cookies_check.py has a local
# _is_session_cookie() helper, and a substring test flags that as importing _session -
# a false failure that would train the next reader to edit the assertion rather than
# believe it.
_SESSION_IMPORT = re.compile(r"^\s*(from|import)\s+.*\b_session\b", re.M)
_ENDPOINTS_IMPORT = re.compile(r"^\s*(from|import)\s+.*\b_endpoints\b", re.M)

for _name, _module in sorted(_tier1_modules.items()):
    _src = inspect.getsource(_module)
    check(f"{_name} does not import the session helper", bool(_SESSION_IMPORT.search(_src)), False)
    check(f"  {_name} does not import the endpoint finder", bool(_ENDPOINTS_IMPORT.search(_src)), False)

for _name, _module in sorted(_tier1_modules.items()):
    _source = inspect.getsource(_module)
    check(f"{_name} sends no POST", ".post(" in _source, False)
    check(f"  {_name} sends no PUT, PATCH or DELETE",
          any(verb in _source for verb in (".put(", ".patch(", ".delete(")), False)

# The tiers must not overlap at all: a check sitting in both lists would send its Tier 2
# traffic on every Tier 1 scan.
check("the tiers share no checks", sorted(set(_tier1_modules) & _tier2_names), [])

# =========================================================================
print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
raise SystemExit(1 if FAIL_COUNT else 0)
