"""False-positive audit for the 7 Tier 1 checks.

METHOD: for each check, build a table of REALISTIC CORRECT-SITE SHAPES -
ScanTargets that represent a properly-secured site - and verify the check
returns PASSED or SKIPPED on every one. A check that returns WARNING or
CRITICAL for a correctly-configured site has a false positive, which is the
worst direction a security scanner can fail in: it costs the client's trust,
and trust is the product.

This is the same method that found bugs invisible to code reading in every
Tier 2 module it touched. For Tier 1, the shapes come from real-world sites
that are genuinely well-configured, reduced to the minimal fixture that
exercises the decision.

NOT TESTED HERE: whether the checks correctly FIND problems. That is the job
of test_branches.py, test_https_branches.py, test_rate_limit.py and
test_password.py. This file is exclusively about what the checks must NOT
flag.
"""

import asyncio

import _path  # noqa: F401  - puts backend/ on sys.path

from scanning.checks._finding import CRITICAL, PASSED, SKIPPED, WARNING
from scanning.checks.cookies_check import check_cookies
from scanning.checks.exposure_check import check_exposure
from scanning.checks.headers_check import check_headers
from scanning.checks.https_check import check_https
from scanning.checks.mfa_check import check_mfa
from scanning.checks.password_check import check_password
from scanning.checks.rate_limit_check import check_rate_limit
from scanning.discovery import Field, Form, Page, ScanTarget

PASS_COUNT = 0
FAIL_COUNT = 0


def check(label, got, want, *, allow=None):
    """Assert got == want, or got in allow if allow is a set."""
    global PASS_COUNT, FAIL_COUNT
    ok = got == want if allow is None else got in allow
    if ok:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    mark = "ok  " if ok else "FAIL"
    detail = "" if ok else f"   (got {got!r}, wanted {want!r})"
    print(f"  {mark} {label}{detail}")


run = asyncio.run


# ---------------------------------------------------------------------------
# FIXTURE HELPERS
# ---------------------------------------------------------------------------
# These build the data structures the checks actually receive.  Every Page
# mirrors what discovery would produce: link text is folded into page.text,
# headers are lowercase-keyed, and set_cookies carries the raw header lines.


def make_page(
    url,
    text="",
    links=None,
    cookies=None,
    forms=None,
    headers=None,
    html=None,
    status=200,
    loose_pw=None,
):
    links = links or []
    full_text = " ".join([text] + [link_text for _, link_text in links]).strip()
    return Page(
        url=url,
        status=status,
        html=html if html is not None else f"<html><body>{full_text}</body></html>",
        text=full_text,
        forms=forms or [],
        links=links,
        set_cookies=cookies or [],
        headers=headers or {},
        loose_password_fields=loose_pw or [],
    )


def login_form(**overrides):
    """A standard login form with email + password."""
    fields = overrides.pop("fields", [
        Field(tag="input", type="email", name="email"),
        Field(tag="input", type="password", name="password"),
    ])
    return Form(submit_url=overrides.pop("submit_url", "/session"),
                method=overrides.pop("method", "post"),
                fields=fields)


def signup_form(**overrides):
    """A standard signup form: email + password + confirm."""
    attrs = overrides.pop("pw_attrs", {"minlength": "12", "maxlength": "128",
                                        "autocomplete": "new-password"})
    fields = overrides.pop("fields", [
        Field(tag="input", type="email", name="email"),
        Field(tag="input", type="password", name="password", attrs=attrs),
        Field(tag="input", type="password", name="password_confirmation", attrs=attrs),
    ])
    return Form(submit_url=overrides.pop("submit_url", "/users"),
                method=overrides.pop("method", "post"),
                fields=fields)


ALL_SECURITY_HEADERS = {
    "content-security-policy": "default-src 'self'; script-src 'self'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
}


# =========================================================================
print("headers_check false-positive shapes")
# =========================================================================
# A correctly-configured site: all five security headers present.

target = ScanTarget(
    url="https://good.example",
    home=make_page("https://good.example/", headers=ALL_SECURITY_HEADERS),
)
result = run(check_headers(target))
check("all 5 headers present -> passed", result["severity"], PASSED)

# CSP with frame-ancestors supersedes X-Frame-Options.
# A site that sets frame-ancestors in CSP but omits X-Frame-Options is correct.
headers_with_frame_ancestors = {
    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    # X-Frame-Options deliberately omitted
    "referrer-policy": "strict-origin-when-cross-origin",
}
target = ScanTarget(
    url="https://csp-frames.example",
    home=make_page("https://csp-frames.example/", headers=headers_with_frame_ancestors),
)
result = run(check_headers(target))
check("frame-ancestors in CSP, no X-Frame-Options -> passed", result["severity"], PASSED)

# frame-ancestors after a semicolon (not first directive).
headers_mid_csp = {
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'; report-uri /csp",
    "strict-transport-security": "max-age=63072000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}
target = ScanTarget(
    url="https://midcsp.example",
    home=make_page("https://midcsp.example/", headers=headers_mid_csp),
)
result = run(check_headers(target))
check("frame-ancestors mid-policy, no XFO -> passed", result["severity"], PASSED)


# =========================================================================
print("\ncookies_check false-positive shapes")
# =========================================================================
# A site whose session cookie has all three protective flags.

correct_cookie = "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"
target = ScanTarget(
    url="https://cookies-ok.example",
    home=make_page("https://cookies-ok.example/"),
    login=make_page("https://cookies-ok.example/login", cookies=[correct_cookie],
                    forms=[login_form()]),
)
result = run(check_cookies(target))
check("session cookie with all flags -> passed", result["severity"], PASSED)

# Multiple cookies, all properly flagged - including a non-session one.
cookies = [
    "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax",
    "cart_items=3; Path=/; Secure; SameSite=Lax; Max-Age=600",
    "_csrf_token=xyz; Path=/; Secure; HttpOnly; SameSite=Strict",
]
target = ScanTarget(
    url="https://multi-cookies.example",
    home=make_page("https://multi-cookies.example/"),
    login=make_page("https://multi-cookies.example/login", cookies=cookies,
                    forms=[login_form()]),
)
result = run(check_cookies(target))
check("multiple cookies, all flagged -> passed", result["severity"], PASSED)

# A site with no cookies at all is SKIPPED, not WARNING.
target = ScanTarget(
    url="https://no-cookies.example",
    home=make_page("https://no-cookies.example/"),
)
result = run(check_cookies(target))
check("no cookies -> skipped", result["severity"], SKIPPED)

# A non-session cookie (analytics) with all flags - still a pass.
target = ScanTarget(
    url="https://analytics.example",
    home=make_page("https://analytics.example/",
                   cookies=["_ga=GA1.2.123; Path=/; Secure; HttpOnly; SameSite=Lax"]),
)
result = run(check_cookies(target))
check("analytics cookie with all flags -> passed", result["severity"], PASSED)


# =========================================================================
print("\nexposure_check false-positive shapes")
# =========================================================================
# A clean site: no version headers, no secrets in the body.

target = ScanTarget(
    url="https://clean.example",
    home=make_page("https://clean.example/", text="Welcome to our secure application.",
                   headers={"server": "nginx", "content-type": "text/html"}),
)
result = run(check_exposure(target))
check("clean page, generic server header -> passed", result["severity"], PASSED)

# A page with a hex string that is NOT a secret (asset hash).  Must not fire.
target = ScanTarget(
    url="https://assets.example",
    home=make_page(
        "https://assets.example/",
        html='<html><script src="/js/app.a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2.js"></script></html>',
        text="",
        headers={"server": "nginx"},
    ),
)
result = run(check_exposure(target))
check("40-char hex asset hash -> no false alarm", result["severity"], PASSED)

# A page that says "Whoops! Page not found" - NOT the Laravel debug page.
target = ScanTarget(
    url="https://friendly404.example",
    home=make_page(
        "https://friendly404.example/",
        text="Whoops! Page not found. Try the homepage instead.",
        headers={"server": "nginx"},
    ),
)
result = run(check_exposure(target))
check("friendly Whoops 404, not debug page -> passed", result["severity"], PASSED)

# A page with "Traceback" in ordinary text content (e.g. docs about tracebacks).
target = ScanTarget(
    url="https://docs.example",
    home=make_page(
        "https://docs.example/",
        text="When debugging, look for the traceback in the logs. File access is logged.",
        headers={"server": "nginx"},
    ),
)
result = run(check_exposure(target))
check("docs mentioning 'traceback' without real trace -> passed", result["severity"], PASSED)

# Server header without a version number.
target = ScanTarget(
    url="https://noversion.example",
    home=make_page("https://noversion.example/",
                   text="Hello",
                   headers={"server": "nginx", "x-powered-by": "Express"}),
)
result = run(check_exposure(target))
check("server headers without version numbers -> passed", result["severity"], PASSED)


# =========================================================================
print("\nmfa_check false-positive shapes")
# =========================================================================
# A site that advertises MFA via page wording.

target = ScanTarget(
    url="https://mfa-wording.example",
    home=make_page("https://mfa-wording.example/"),
    login=make_page(
        "https://mfa-wording.example/login",
        text="Sign in. Two-factor authentication is required. Open your authenticator app.",
        forms=[login_form()],
    ),
)
result = run(check_mfa(target))
check("MFA wording on login page -> passed", result["severity"], PASSED)

# A site that advertises MFA via a link to /settings/security.
target = ScanTarget(
    url="https://mfa-link.example",
    home=make_page("https://mfa-link.example/"),
    login=make_page(
        "https://mfa-link.example/login",
        text="Sign in with your credentials.",
        forms=[login_form()],
        links=[("/settings/security", "Security settings")],
    ),
)
result = run(check_mfa(target))
check("link to /settings/security -> passed", result["severity"], PASSED)

# A brochure site with no login -> SKIPPED.
target = ScanTarget(
    url="https://brochure.example",
    home=make_page("https://brochure.example/", text="We make excellent widgets."),
)
result = run(check_mfa(target))
check("brochure site, no login -> skipped", result["severity"], SKIPPED)

# A site with MFA evidence via passkey link.
target = ScanTarget(
    url="https://passkey.example",
    home=make_page("https://passkey.example/"),
    login=make_page(
        "https://passkey.example/login",
        text="Sign in.",
        forms=[login_form()],
        links=[("/passkeys/", "Manage passkeys")],
    ),
)
result = run(check_mfa(target))
check("link to /passkeys/ -> passed", result["severity"], PASSED)

# MFA mentioned on signup page, not login.
target = ScanTarget(
    url="https://signup-mfa.example",
    home=make_page("https://signup-mfa.example/"),
    login=make_page("https://signup-mfa.example/login", text="Sign in.",
                    forms=[login_form()]),
    signup=make_page("https://signup-mfa.example/signup",
                     text="Create your account. Protect it with two-factor authentication.",
                     forms=[signup_form()]),
)
result = run(check_mfa(target))
check("MFA wording on signup page -> passed", result["severity"], PASSED)


# =========================================================================
print("\nrate_limit_check false-positive shapes")
# =========================================================================
# A site with rate-limit headers on the login page.

target = ScanTarget(
    url="https://ratelimit.example",
    home=make_page("https://ratelimit.example/"),
    login=make_page(
        "https://ratelimit.example/login",
        text="Sign in.",
        forms=[login_form()],
        headers={"ratelimit-remaining": "99", "ratelimit-limit": "100"},
    ),
)
result = run(check_rate_limit(target))
check("rate-limit headers on login -> passed", result["severity"], PASSED)

# A site with a CAPTCHA on the login page.
target = ScanTarget(
    url="https://captcha.example",
    home=make_page("https://captcha.example/"),
    login=make_page(
        "https://captcha.example/login",
        text="Sign in.",
        forms=[login_form()],
        html='<html><body><script src="https://www.google.com/recaptcha/api.js"></script><form><input type="password" name="password"></form></body></html>',
    ),
)
result = run(check_rate_limit(target))
check("reCAPTCHA on login page -> passed", result["severity"], PASSED)

# A site that got rate-limited during the scan (429).
target = ScanTarget(
    url="https://throttled.example",
    home=make_page("https://throttled.example/"),
    login=make_page(
        "https://throttled.example/login",
        text="Sign in.",
        forms=[login_form()],
        status=429,
    ),
)
result = run(check_rate_limit(target))
check("429 during scan -> passed", result["severity"], PASSED)

# A brochure site with no login -> SKIPPED.
target = ScanTarget(
    url="https://brochure-rate.example",
    home=make_page("https://brochure-rate.example/", text="Widgets for sale."),
)
result = run(check_rate_limit(target))
check("brochure site, no login -> skipped", result["severity"], SKIPPED)

# hCaptcha on login form.
target = ScanTarget(
    url="https://hcaptcha.example",
    home=make_page("https://hcaptcha.example/"),
    login=make_page(
        "https://hcaptcha.example/login",
        text="Sign in.",
        forms=[login_form()],
        html='<html><body><div class="h-captcha" data-sitekey="abc123"></div><form><input type="password" name="password"></form></body></html>',
    ),
)
result = run(check_rate_limit(target))
check("hCaptcha on login -> passed", result["severity"], PASSED)

# X-RateLimit-Limit header (older spelling).
target = ScanTarget(
    url="https://xrate.example",
    home=make_page("https://xrate.example/"),
    login=make_page(
        "https://xrate.example/login",
        text="Sign in.",
        forms=[login_form()],
        headers={"x-ratelimit-limit": "100", "x-ratelimit-remaining": "98"},
    ),
)
result = run(check_rate_limit(target))
check("X-RateLimit-Limit header -> passed", result["severity"], PASSED)

# Retry-After header.
target = ScanTarget(
    url="https://retry.example",
    home=make_page("https://retry.example/"),
    login=make_page(
        "https://retry.example/login",
        text="Sign in.",
        forms=[login_form()],
        headers={"retry-after": "60"},
    ),
)
result = run(check_rate_limit(target))
check("Retry-After header -> passed", result["severity"], PASSED)

# Turnstile CAPTCHA.
target = ScanTarget(
    url="https://turnstile.example",
    home=make_page("https://turnstile.example/"),
    login=make_page(
        "https://turnstile.example/login",
        text="Sign in.",
        forms=[login_form()],
        html='<html><body><div class="cf-turnstile" data-sitekey="xxx"></div><form><input type="password" name="password"></form></body></html>',
    ),
)
result = run(check_rate_limit(target))
check("Cloudflare Turnstile -> passed", result["severity"], PASSED)


# =========================================================================
print("\npassword_check false-positive shapes")
# =========================================================================
# A well-configured signup form: minlength=12, maxlength=128, autocomplete=new-password.

target = ScanTarget(
    url="https://good-pw.example",
    home=make_page("https://good-pw.example/"),
    signup=make_page(
        "https://good-pw.example/signup",
        text="Create an account. Your password must be at least 12 characters.",
        forms=[signup_form()],
    ),
)
result = run(check_password(target))
check("good signup form (min=12, max=128) -> passed", result["severity"], PASSED)

# A signup form with minlength=8 (floor) and no maxlength.
target = ScanTarget(
    url="https://floor-pw.example",
    home=make_page("https://floor-pw.example/"),
    signup=make_page(
        "https://floor-pw.example/signup",
        text="Create an account.",
        forms=[signup_form(pw_attrs={"minlength": "8", "autocomplete": "new-password"})],
    ),
)
result = run(check_password(target))
check("signup with minlength=8 (floor) -> passed", result["severity"], PASSED)

# A site that states "at least 10 characters" in text with minlength=10 in markup.
target = ScanTarget(
    url="https://stated-pw.example",
    home=make_page("https://stated-pw.example/"),
    signup=make_page(
        "https://stated-pw.example/signup",
        text="Create an account. Your password must be at least 10 characters long.",
        forms=[signup_form(pw_attrs={"minlength": "10", "maxlength": "128",
                                     "autocomplete": "new-password"})],
    ),
)
result = run(check_password(target))
check("stated + markup minimum of 10 -> passed", result["severity"], PASSED)

# "Spaces and symbols are welcome" must NOT trigger composition-rule detection.
target = ScanTarget(
    url="https://permissive-pw.example",
    home=make_page("https://permissive-pw.example/"),
    signup=make_page(
        "https://permissive-pw.example/signup",
        text="Your password must be at least 12 characters. Spaces and symbols are welcome.",
        forms=[signup_form()],
    ),
)
result = run(check_password(target))
check("'Spaces and symbols are welcome' is not a composition rule -> passed",
      result["severity"], PASSED)

# A brochure site with no password field -> SKIPPED.
target = ScanTarget(
    url="https://brochure-pw.example",
    home=make_page("https://brochure-pw.example/", text="We sell widgets."),
)
result = run(check_password(target))
check("brochure site, no password field -> skipped", result["severity"], SKIPPED)

# A signup form with a pattern using a lookahead (composition assertion, not restriction).
# ^(?=.*[A-Z]).{8,}$ asserts uppercase but does NOT restrict characters.
target = ScanTarget(
    url="https://lookahead-pw.example",
    home=make_page("https://lookahead-pw.example/"),
    signup=make_page(
        "https://lookahead-pw.example/signup",
        text="Create an account.",
        forms=[signup_form(pw_attrs={
            "minlength": "12",
            "maxlength": "128",
            "autocomplete": "new-password",
            "pattern": r"^(?=.*[A-Z]).{12,}$",
        })],
    ),
)
result = run(check_password(target))
check("lookahead pattern (not restrictive) -> passed", result["severity"], PASSED)

# maxlength=64 (generous threshold) should not be a problem.
target = ScanTarget(
    url="https://max64-pw.example",
    home=make_page("https://max64-pw.example/"),
    signup=make_page(
        "https://max64-pw.example/signup",
        text="Create an account.",
        forms=[signup_form(pw_attrs={"minlength": "12", "maxlength": "64",
                                     "autocomplete": "new-password"})],
    ),
)
result = run(check_password(target))
check("maxlength=64 (generous) -> passed", result["severity"], PASSED)

# autocomplete="new-password" on signup (correct value).
target = ScanTarget(
    url="https://autocomplete-pw.example",
    home=make_page("https://autocomplete-pw.example/"),
    signup=make_page(
        "https://autocomplete-pw.example/signup",
        text="Create an account.",
        forms=[signup_form(pw_attrs={"minlength": "12", "autocomplete": "new-password"})],
    ),
    login=make_page(
        "https://autocomplete-pw.example/login",
        text="Sign in.",
        forms=[login_form(fields=[
            Field(tag="input", type="email", name="email"),
            Field(tag="input", type="password", name="password",
                  attrs={"autocomplete": "current-password"}),
        ])],
    ),
)
result = run(check_password(target))
check("correct autocomplete values -> passed", result["severity"], PASSED)


# =========================================================================
print("\nexposure_check: tricky non-secrets that must not match")
# =========================================================================

# A page discussing FIDO keys that contains "at org.fidoalliance.example".
# This must NOT match the Java stack trace pattern - there's no (File.java:N).
target = ScanTarget(
    url="https://fido-docs.example",
    home=make_page(
        "https://fido-docs.example/",
        text="at org.fidoalliance.example.Auth Class usage guide.",
        headers={"server": "nginx"},
    ),
)
result = run(check_exposure(target))
check("'at org.' without file:line -> no Java trace alarm", result["severity"], PASSED)

# A page with "ORA-" followed by text (not 5 digits).
target = ScanTarget(
    url="https://oracle-text.example",
    home=make_page(
        "https://oracle-text.example/",
        text="ORA-cle Database is our backend choice for enterprise clients.",
        headers={"server": "nginx"},
    ),
)
result = run(check_exposure(target))
check("'ORA-' without 5 digits -> no SQL error alarm", result["severity"], PASSED)


# =========================================================================
# SUMMARY
# =========================================================================
print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")

if FAIL_COUNT:
    raise SystemExit(1)
