"""Branch tests for the passive rate-limiting check.

Two things are being pinned here, and the second matters more than the first:

  1. the evidence ladder picks the right verdict, and
  2. THE CHECK NEVER SENDS A REQUEST. Tier 1 makes no POSTs, so the test asserts
     that too - by handing check_rate_limit a ScanTarget and monkeypatching
     httpx.AsyncClient to explode if anything touches it.
"""

import asyncio

import httpx

import _path  # noqa: F401  - puts backend/ on sys.path; must precede the imports below
from scanning.checks._finding import CRITICAL, PASSED, SKIPPED, WARNING
from scanning.checks.rate_limit_check import check_rate_limit
from scanning.discovery import Field, Form, Page, ScanTarget

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


def page(url, text="", html=None, headers=None, status=200, forms=None, links=None):
    links = links or []
    full_text = " ".join([text] + [t for _, t in links]).strip()
    return Page(
        url=url,
        status=status,
        # html defaults to wrapping the text, but tests that care about markup
        # (CAPTCHA script tags) pass it explicitly - a widget lives in the markup and
        # is deliberately absent from page.text.
        html=html if html is not None else f"<html><body>{full_text}</body></html>",
        text=full_text,
        forms=forms or [],
        links=links,
        set_cookies=[],
        headers=headers or {},
    )


def login_form(extra_fields=()):
    return Form(
        submit_url="/session",
        method="post",
        fields=[
            Field(tag="input", type="email", name="email"),
            Field(tag="input", type="password", name="password"),
            *extra_fields,
        ],
    )


def with_login(url, login_page):
    return ScanTarget(url=url, home=page(f"{url}/"), login=login_page)


run = asyncio.run

print("rate_limit_check branches")

# --- 0. THE CENTRAL GUARANTEE: no network, at all ------------------------------
# If the check ever constructs an HTTP client, this raises and the test fails. This
# is the assertion that encodes "Tier 1 sends no POSTs, ever, no exceptions".
_real_client = httpx.AsyncClient


class Exploding:
    def __init__(self, *a, **k):
        raise AssertionError("rate_limit_check must not make ANY request")


httpx.AsyncClient = Exploding
try:
    target = with_login(
        "https://plain.example",
        page("https://plain.example/login", text="Sign in", forms=[login_form()]),
    )
    result = run(check_rate_limit(target))
    check("sends no requests", result["severity"], WARNING)
    check("evidence records the method", result["evidence"]["method"],
          "passive; no authentication requests were sent")
finally:
    httpx.AsyncClient = _real_client

# --- 1. Nothing to inspect ------------------------------------------------------
result = run(check_rate_limit(ScanTarget(url="https://empty.example")))
check("no pages -> skipped", result["severity"], SKIPPED)

# --- 2. A brochure site has no login to rate-limit ------------------------------
brochure = ScanTarget(
    url="https://brochure.example",
    home=page("https://brochure.example/", text="We make excellent widgets."),
)
result = run(check_rate_limit(brochure))
check("no credential form -> skipped", result["severity"], SKIPPED)
check("skipped does not claim a finding", result["evidence"]["loginFound"], False)

# --- 3. A 429 tripped by ordinary GETs is the strongest signal ------------------
throttled = ScanTarget(
    url="https://429.example",
    home=page("https://429.example/", status=429),
    login=page("https://429.example/login", text="Sign in", forms=[login_form()]),
)
result = run(check_rate_limit(throttled))
check("429 during scan -> passed", result["severity"], PASSED)
check("429 title says active", result["title"], "Rate limiting is active")
check("429 recorded in evidence", len(result["evidence"]["throttledDuringScan"]), 1)

# --- 4. Rate-limit headers ------------------------------------------------------
for header_name in ("ratelimit-remaining", "x-ratelimit-limit",
                    "x-rate-limit-reset", "retry-after", "ratelimit"):
    t = with_login(
        "https://hdr.example",
        page("https://hdr.example/login", text="Sign in", forms=[login_form()],
             headers={header_name: "99"}),
    )
    r = run(check_rate_limit(t))
    check(f"header {header_name} -> passed", r["severity"], PASSED)

# A header that merely CONTAINS the word must not match.
t = with_login(
    "https://nothdr.example",
    page("https://nothdr.example/login", text="Sign in", forms=[login_form()],
         headers={"x-generated-by": "ratelimiter-cache", "content-type": "text/html"}),
)
r = run(check_rate_limit(t))
check("unrelated header value -> not passed", r["severity"], WARNING)

# --- 5. CAPTCHA in the markup, which page.text deliberately omits ---------------
recaptcha_html = (
    '<html><body><form method="post" action="/session">'
    '<input type="email" name="email"><input type="password" name="password">'
    '<div class="g-recaptcha" data-sitekey="6Lc-abc"></div>'
    '<script src="https://www.google.com/recaptcha/api.js"></script>'
    "</form></body></html>"
)
t = with_login(
    "https://cap.example",
    page("https://cap.example/login", text="Sign in", html=recaptcha_html,
         forms=[login_form()]),
)
r = run(check_rate_limit(t))
check("recaptcha markup -> passed", r["severity"], PASSED)
check("captcha title", r["title"], "Automated login attempts are challenged")
check("captcha found in markup", r["evidence"]["captchaEvidence"][0]["foundIn"], "markup")

for vendor in ("hcaptcha.com/1/api.js", "cf-turnstile", "challenges.cloudflare.com/turnstile",
               "js.arkoselabs.com", "friendly-challenge", "geetest"):
    t = with_login(
        "https://v.example",
        page("https://v.example/login", text="Sign in",
             html=f'<html><body><script src="{vendor}"></script></body></html>',
             forms=[login_form()]),
    )
    r = run(check_rate_limit(t))
    check(f"vendor {vendor[:28]} -> passed", r["severity"], PASSED)

# The field-name fallback, for a widget whose script URL is unrecognised.
t = with_login(
    "https://fld.example",
    page("https://fld.example/login", text="Sign in",
         forms=[login_form(extra_fields=[Field(tag="input", type="hidden",
                                               name="captcha_token")])]),
)
r = run(check_rate_limit(t))
check("captcha form field -> passed", r["severity"], PASSED)
check("field hit labelled", r["evidence"]["captchaEvidence"][0]["foundIn"], "form field")

# The same widget in a shared layout on every page is one fact, not three.
dupe_html = '<html><body><script src="https://hcaptcha.com/1/api.js"></script></body></html>'
t = ScanTarget(
    url="https://dupe.example",
    home=page("https://dupe.example/", html=dupe_html),
    login=page("https://dupe.example/login", text="Sign in", html=dupe_html,
               forms=[login_form()]),
    signup=page("https://dupe.example/signup", text="Register", html=dupe_html,
                forms=[login_form()]),
)
r = run(check_rate_limit(t))
check("captcha deduped across pages", len(r["evidence"]["captchaEvidence"]), 1)

# --- 6. A documented policy alone is CAPPED AT WARNING --------------------------
# This is the rule the product decision asked for: indirect evidence does not earn a
# full pass, because a site could otherwise pass this check by editing a help page.
for wording in (
    "Your account will be temporarily locked after 5 failed login attempts.",
    "Too many failed sign-in attempts. Please contact support.",
    "We use rate limiting to protect against brute force attacks.",
    "After 3 incorrect attempts you must wait 15 minutes before trying again.",
):
    t = with_login(
        "https://doc.example",
        page("https://doc.example/login", text=f"Sign in. {wording}",
             forms=[login_form()]),
    )
    r = run(check_rate_limit(t))
    check(f"policy text -> warning: {wording[:34]}", r["severity"], WARNING)
    check("  policy not scored as passed", r["severity"] != PASSED, True)
    check("  policy recorded", len(r["evidence"]["documentedPolicy"]) >= 1, True)

t = with_login(
    "https://doc.example",
    page("https://doc.example/login",
         text="Sign in. Your account will be temporarily locked after 5 failed login attempts.",
         forms=[login_form()]),
)
r = run(check_rate_limit(t))
check("policy title names the gap", "could not be verified" in r["title"], True)

# --- 7. Generic error wording must NOT count as a policy ------------------------
# "try again later" is on every 500 page ever written. A pattern that matches it
# would hand out warnings-with-evidence for nothing.
for innocuous in (
    "Something went wrong. Please try again later.",
    "This page is blocked in your region.",
    "Sign in to continue to your dashboard.",
):
    t = with_login(
        "https://gen.example",
        page("https://gen.example/login", text=f"Sign in. {innocuous}",
             forms=[login_form()]),
    )
    r = run(check_rate_limit(t))
    check(f"innocuous text not policy: {innocuous[:30]}",
          len(r["evidence"]["documentedPolicy"]), 0)

# --- 8. Nothing visible ---------------------------------------------------------
t = with_login(
    "https://bare.example",
    page("https://bare.example/login", text="Sign in with your email and password.",
         forms=[login_form()]),
)
r = run(check_rate_limit(t))
check("nothing visible -> warning", r["severity"], WARNING)
check("nothing visible title", r["title"], "No login rate limiting was visible")

# --- 9. Ladder precedence -------------------------------------------------------
# A site with all three signals must report the STRONGEST, so the explanation stands
# on the fact rather than the claim.
all_three = with_login(
    "https://all.example",
    page("https://all.example/login",
         text="Sign in. Your account will be locked after 5 failed attempts.",
         html=recaptcha_html,
         headers={"ratelimit-remaining": "42"},
         forms=[login_form()]),
)
r = run(check_rate_limit(all_three))
check("headers outrank captcha and text", r["title"], "Rate limiting is in place")
check("but all evidence is kept: headers", len(r["evidence"]["rateLimitHeaders"]), 1)
check("but all evidence is kept: captcha", len(r["evidence"]["captchaEvidence"]) >= 1, True)
check("but all evidence is kept: policy", len(r["evidence"]["documentedPolicy"]) >= 1, True)

captcha_and_text = with_login(
    "https://ct.example",
    page("https://ct.example/login",
         text="Sign in. Too many failed attempts will lock the account.",
         html=recaptcha_html, forms=[login_form()]),
)
r = run(check_rate_limit(captcha_and_text))
check("captcha outranks text", r["title"], "Automated login attempts are challenged")

# --- 10. Never critical, on any input ------------------------------------------
severities = set()
for t in (ScanTarget(url="https://a.example"), brochure, throttled, all_three,
          captcha_and_text,
          with_login("https://b.example",
                     page("https://b.example/login", text="Sign in",
                          forms=[login_form()]))):
    severities.add(run(check_rate_limit(t))["severity"])
check("never critical", CRITICAL not in severities, True)
check("only known severities", severities <= {PASSED, WARNING, SKIPPED}, True)

# --- 11. The finding contract ---------------------------------------------------
contract = ("id", "checkId", "title", "description", "severity",
            "explanation", "fix", "evidence")
r = run(check_rate_limit(all_three))
check("meets finding contract", [k for k in contract if k not in r], [])
check("attributed to this check", r["checkId"], "rate_limit_check")

# --- 12. A signup form with no login still counts -------------------------------
signup_only = ScanTarget(
    url="https://su.example",
    home=page("https://su.example/"),
    signup=page("https://su.example/signup", text="Create an account",
                forms=[login_form()]),
)
r = run(check_rate_limit(signup_only))
check("signup-only is not skipped", r["severity"], WARNING)

# A loose password field with no <form> - the React case - also counts.
spa = ScanTarget(url="https://spa.example", home=page("https://spa.example/", text="Sign in"))
spa.home.loose_password_fields = [Field(tag="input", type="password", name="password")]
r = run(check_rate_limit(spa))
check("SPA loose password is not skipped", r["severity"], WARNING)

print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
raise SystemExit(1 if FAIL_COUNT else 0)
