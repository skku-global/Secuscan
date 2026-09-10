"""Branch tests for the passive password-policy check.

Three things are pinned here:

  1. THE CHECK NEVER SENDS A REQUEST. Same guarantee as rate_limit_check, asserted
     the same way - httpx.AsyncClient is replaced with something that explodes.
  2. The verdict ladder, including the two cases that are easy to get backwards:
     a login form's minlength is NOT a password policy, and a generous maxlength
     is NOT a pass on its own.
  3. THE POLICY STANCE: composition rules earn nothing. A site demanding an
     uppercase letter and a digit must not score better for it, because that is
     what current guidance says about them - see the file header.
"""

import asyncio

import httpx

import _path  # noqa: F401  - puts backend/ on sys.path; must precede the imports below
from scanning.checks._finding import CRITICAL, PASSED, SKIPPED, WARNING
from scanning.checks.password_check import check_password
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


def page(url, text="", forms=None, links=None, status=200):
    links = links or []
    # Discovery merges link text into page text - mirrored here so the fixture
    # describes a Page discovery could actually produce.
    full_text = " ".join([text] + [t for _, t in links]).strip()
    return Page(
        url=url,
        status=status,
        html=f"<html><body>{full_text}</body></html>",
        text=full_text,
        forms=forms or [],
        links=links,
        set_cookies=[],
        headers={},
    )


def pw(name="password", type="password", **attrs):
    """One password input. attrs land in Field.attrs the way discovery puts them."""
    return Field(tag="input", type=type, name=name, attrs=attrs)


def form(*fields, url="/register", method="post"):
    return Form(submit_url=url, method=method, fields=list(fields))


def signup_form(*password_fields):
    """A form discovery's looks_like_signup() will recognise: two password boxes."""
    return form(
        Field(tag="input", type="email", name="email"),
        *(password_fields or (pw(), pw(name="confirm_password"))),
    )


def signup_target(*fields, host="https://su.example", text="Create an account"):
    """A target whose SIGNUP page carries the given password field(s)."""
    return ScanTarget(
        url=host,
        home=page(f"{host}/"),
        signup=page(f"{host}/signup", text=text,
                    forms=[form(Field(tag="input", type="email", name="email"), *fields)]),
    )


run = asyncio.run

print("password_check branches")

# --- 0. THE CENTRAL GUARANTEE: no network, at all -------------------------------
_real_client = httpx.AsyncClient


class Exploding:
    def __init__(self, *a, **k):
        raise AssertionError("password_check must not make ANY request")


httpx.AsyncClient = Exploding
try:
    r = run(check_password(signup_target(pw(minlength="12"))))
    check("sends no requests", r["severity"], PASSED)
    check("evidence records the method", r["evidence"]["method"],
          "passive; no candidate passwords were submitted")
finally:
    httpx.AsyncClient = _real_client

# --- 1. Nothing to inspect ------------------------------------------------------
r = run(check_password(ScanTarget(url="https://empty.example")))
check("no pages -> skipped", r["severity"], SKIPPED)
check("no pages counts them", r["evidence"]["pagesInspected"], 0)

# A brochure site has no password field to hold to a policy.
brochure = ScanTarget(
    url="https://brochure.example",
    home=page("https://brochure.example/", text="We make excellent widgets."),
)
r = run(check_password(brochure))
check("no password field -> skipped", r["severity"], SKIPPED)
check("skipped claims no finding", r["evidence"]["signupFound"], False)

# --- 2. An adequate declared minimum -------------------------------------------
r = run(check_password(signup_target(pw(minlength="8"))))
check("minlength 8 -> passed", r["severity"], PASSED)
check("minlength 8 read off markup", r["evidence"]["minlengthAttribute"], 8)
check("minlength 8 is the effective minimum", r["evidence"]["effectiveMinimum"], 8)

r = run(check_password(signup_target(pw(minlength="16"))))
check("minlength 16 -> passed", r["severity"], PASSED)
check("16 described as doing real work", "real work" in r["explanation"], True)

# --- 3. A short minimum ---------------------------------------------------------
for short in ("1", "4", "6", "7"):
    r = run(check_password(signup_target(pw(minlength=short))))
    check(f"minlength {short} -> warning", r["severity"], WARNING)
check("short minimum names the floor", "below the 8" in r["explanation"], True)

# --- 4. maxlength: the one signal the browser really enforces -------------------
# A cap at or below 24 rules out a passphrase, and hints at a fixed-width column.
r = run(check_password(signup_target(pw(minlength="8", maxlength="16"))))
check("maxlength 16 -> warning despite good minimum", r["severity"], WARNING)
check("maxlength 16 mentions hashing", "hashed" in r["explanation"], True)
check("good minimum still credited", "In the site's favour" in r["explanation"], True)

# Between 25 and 63: below current guidance, but not crippling - a milder wording.
r = run(check_password(signup_target(pw(minlength="8", maxlength="32"))))
check("maxlength 32 -> warning", r["severity"], WARNING)
check("maxlength 32 not called a hashing hint", "hashed" in r["explanation"], False)

# 64 or more is room for a passphrase.
r = run(check_password(signup_target(pw(minlength="8", maxlength="64"))))
check("maxlength 64 -> passed", r["severity"], PASSED)
check("64 credited as room", "leaves space for a passphrase" in r["explanation"], True)

# A GENEROUS MAXIMUM IS NOT A POLICY. Room to type a long password is not a rule
# requiring one - this must not pass on the strength of maxlength alone.
r = run(check_password(signup_target(pw(maxlength="128"))))
check("generous maxlength alone -> warning", r["severity"], WARNING)
check("generous maxlength alone title", r["title"], "No password policy was visible")
check("and no 'None characters' in the description",
      "None" in r["description"], False)
check("the room is acknowledged", "128 characters of room" in r["explanation"], True)

# --- 5. A login form's minlength is NOT the password policy ---------------------
# It only has to admit passwords that already exist, so minlength=1 on sign-in says
# nothing about what registration allows. Reading it as policy invents a finding.
login_only = ScanTarget(
    url="https://li.example",
    home=page("https://li.example/"),
    login=page("https://li.example/login", text="Sign in",
               forms=[form(Field(tag="input", type="email", name="email"),
                           pw(minlength="1"))]),
)
r = run(check_password(login_only))
check("login minlength ignored as policy", r["evidence"]["minlengthAttribute"], None)
check("login minlength -> no policy visible", r["title"], "No password policy was visible")

# But a login form's maxlength DOES bind - it stops a long existing password
# being typed at all.
login_capped = ScanTarget(
    url="https://lc.example",
    home=page("https://lc.example/"),
    login=page("https://lc.example/login", text="Sign in",
               forms=[form(Field(tag="input", type="email", name="email"),
                           pw(maxlength="12"))]),
)
r = run(check_password(login_capped))
check("login maxlength -> warning", r["severity"], WARNING)
check("login maxlength recorded", r["evidence"]["maxlengthAttribute"], 12)
check("login maxlength named as the login form", "login form" in r["explanation"], True)

# A confirm-password pair on a page discovery labelled "home" is still signup.
home_signup = ScanTarget(
    url="https://hs.example",
    home=page("https://hs.example/", text="Join", forms=[signup_form(pw(minlength="10"),
                                                                    pw(name="confirm_password"))]),
)
r = run(check_password(home_signup))
check("confirm-pair on home read as signup", r["evidence"]["minlengthAttribute"], 10)
check("confirm-pair on home -> passed", r["severity"], PASSED)

# --- 6. Password managers -------------------------------------------------------
for blocking in ("off", "false", "none", "OFF"):
    r = run(check_password(signup_target(pw(minlength="12", autocomplete=blocking))))
    check(f"autocomplete={blocking} -> warning", r["severity"], WARNING)
check("manager block explains reuse", "reuse it" in r["explanation"], True)
check("manager block recorded", len(r["evidence"]["passwordManagerBlocked"]), 1)

# The correct values must not be penalised.
for good in ("new-password", "current-password"):
    r = run(check_password(signup_target(pw(minlength="12", autocomplete=good))))
    check(f"autocomplete={good} -> passed", r["severity"], PASSED)
    check(f"  {good} not flagged", len(r["evidence"]["passwordManagerBlocked"]), 0)

# --- 7. A pattern that forbids characters --------------------------------------
for restrictive in (r"[A-Za-z0-9]+", r"\w{8,}", r"[a-zA-Z0-9]{8,32}"):
    r = run(check_password(signup_target(pw(minlength="12", pattern=restrictive))))
    check(f"pattern {restrictive!r} -> warning", r["severity"], WARNING)
check("pattern warning names passphrases", "passphrase" in r["explanation"], True)

# A length-only pattern forbids nothing, and a LOOKAHEAD is a composition rule
# rather than a character ban - neither may be reported as restrictive.
for harmless in (r".{8,}", r".{12,64}", r"^(?=.*[A-Z])(?=.*\d).{8,}$", r"[^ ]{10,}"):
    r = run(check_password(signup_target(pw(minlength="12", pattern=harmless))))
    check(f"pattern {harmless!r} not restrictive",
          len(r["evidence"]["restrictivePatterns"]), 0)
    check(f"  and still passes", r["severity"], PASSED)

# --- 8. A stated minimum in the page's own words -------------------------------
for wording, expected in (
    ("Your password must be at least 10 characters long.", 10),
    ("Choose a password with a minimum of 12 characters.", 12),
    ("Passwords must be 14+ characters.", 14),
    ("Use 16 or more characters for your password.", 16),
    ("No fewer than 9 characters, please.", 9),
):
    r = run(check_password(signup_target(pw(), text=f"Create an account. {wording}")))
    check(f"stated: {wording[:38]!r}", r["evidence"]["effectiveMinimum"], expected)
    check("  stated minimum -> passed", r["severity"], PASSED)

# Wording that states a SHORT minimum is still a problem.
r = run(check_password(signup_target(pw(), text="Password must be at least 6 characters.")))
check("stated short minimum -> warning", r["severity"], WARNING)

# The MARKUP wins a disagreement, because it is what the user actually meets - but
# both are kept, since the mismatch is itself worth seeing.
r = run(check_password(signup_target(
    pw(minlength="6"), text="Create an account. Passwords must be at least 12 characters.")))
check("markup and text disagree -> lower binds", r["evidence"]["effectiveMinimum"], 6)
check("  the stated claim is still recorded",
      r["evidence"]["statedMinimums"][0]["length"], 12)
check("  disagreement -> warning", r["severity"], WARNING)

# Absurd numbers must not be read as a policy.
r = run(check_password(signup_target(pw(), text="Founded in 1998. At least 4000 characters of documentation.")))
check("absurd stated length ignored", r["evidence"]["effectiveMinimum"], None)

# --- 9. THE POLICY STANCE: composition rules earn NOTHING ----------------------
# This is the assertion that keeps the check from drifting back to the intuitive
# but wrong version. A site demanding a capital and a digit must not score better.
composition = "Password must contain one uppercase letter, one number and a special character."
with_rules = run(check_password(signup_target(pw(), text=f"Register. {composition}")))
without_rules = run(check_password(signup_target(pw(), text="Register.")))
check("composition rules do not earn a pass", with_rules["severity"], WARNING)
check("composition rules change nothing", with_rules["severity"], without_rules["severity"])
check("composition rules are still reported",
      len(with_rules["evidence"]["compositionRules"]), 1)
check("and explained rather than praised", "Password1!" in with_rules["explanation"], True)

# They are also not a PROBLEM - a good minimum plus composition rules still passes.
r = run(check_password(signup_target(pw(minlength="12"), text=f"Register. {composition}")))
check("minimum + composition rules -> passed", r["severity"], PASSED)
check("  note carried into a pass", "Password1!" in r["explanation"], True)

# Forced expiry IS a problem, for the same underlying reason.
for rotation in ("Your password expires every 90 days.",
                 "Passwords must be changed every 60 days."):
    r = run(check_password(signup_target(pw(minlength="12"), text=f"Register. {rotation}")))
    check(f"rotation {rotation[:32]!r} -> warning", r["severity"], WARNING)
check("rotation explains incrementing", "increment" in r["explanation"], True)

# --- 9b. Wording that only PERMITS characters is not a rule demanding them -------
# The e2e fixture caught this: "Spaces and symbols are welcome" was being recorded as
# a composition requirement, so the report told the client about a rule it did not
# have. A demand needs a cue, and a class word in the next sentence must not pair
# with a cue in this one.
for permissive in (
    "Spaces and symbols are welcome.",
    "Your password may contain any character you like.",
    "We accept punctuation, emoji and spaces.",
    "Please enter your phone number. It must include the area code.",
    "Your password must be at least 12 characters.",
):
    r = run(check_password(signup_target(pw(minlength="12"), text=f"Register. {permissive}")))
    check(f"permissive: {permissive[:38]!r} not a rule",
          len(r["evidence"]["compositionRules"]), 0)

# A demand does register, however it is phrased.
for demand in (
    "Password must contain one uppercase letter and a special character.",
    "Your password should include at least one number.",
    "Use a mixture of upper case and lower case letters.",
    "The password requires one symbol.",
):
    r = run(check_password(signup_target(pw(minlength="12"), text=f"Register. {demand}")))
    check(f"demand: {demand[:38]!r} registers",
          len(r["evidence"]["compositionRules"]), 1)
    check("  but still passes on its minimum", r["severity"], PASSED)

# Expiry wording unrelated to passwords must not register either.
for unrelated in ("Your free trial is valid for 30 days.",
                  "This offer expires every Friday.",
                  "Your session expires after 20 minutes of inactivity."):
    r = run(check_password(signup_target(pw(minlength="12"), text=f"Register. {unrelated}")))
    check(f"unrelated expiry: {unrelated[:34]!r} not rotation",
          len(r["evidence"]["rotationRules"]), 0)
    check("  and still passes", r["severity"], PASSED)

# --- 10. A password box that is not type="password" -----------------------------
cleartext = ScanTarget(
    url="https://ct.example",
    home=page("https://ct.example/", text="Sign in",
              forms=[form(Field(tag="input", type="email", name="email"),
                          Field(tag="input", type="text", name="password"))]),
)
r = run(check_password(cleartext))
check("type=text password -> warning", r["severity"], WARNING)
check("cleartext recorded", r["evidence"]["cleartextPasswordFields"][0]["name"], "password")
check("cleartext explains form history", "form history" in r["explanation"], True)

# Things that merely TALK ABOUT a password are not password boxes.
not_boxes = ScanTarget(
    url="https://nb.example",
    home=page("https://nb.example/", text="Sign in",
              forms=[form(Field(tag="input", type="email", name="email"),
                          pw(),
                          Field(tag="input", type="text", name="password_hint"),
                          Field(tag="input", type="hidden", name="password_reset_token"),
                          Field(tag="input", type="checkbox", name="show_password"),
                          Field(tag="submit", type="submit", name="forgot_password"))]),
)
r = run(check_password(not_boxes))
check("hint/token/toggle not cleartext boxes",
      len(r["evidence"]["cleartextPasswordFields"]), 0)

# --- 11. Malformed markup must not crash ---------------------------------------
r = run(check_password(signup_target(pw(minlength="eight", maxlength=""))))
check("unparseable minlength survived", r["evidence"]["minlengthAttribute"], None)
check("unparseable minlength -> warning", r["severity"], WARNING)

# A valueless attribute arrives as "" from discovery's _as_dict, not None.
r = run(check_password(signup_target(pw(minlength="12", required="", autocomplete=""))))
check("valueless attributes survived", r["severity"], PASSED)

# --- 12. The lowest declared value binds ---------------------------------------
# Two password boxes with different rules: the weaker one is what the site accepts.
mixed = ScanTarget(
    url="https://mx.example",
    home=page("https://mx.example/"),
    signup=page("https://mx.example/signup", text="Register",
                forms=[form(Field(tag="input", type="email", name="email"),
                            pw(minlength="12", maxlength="64"),
                            pw(name="confirm", minlength="8", maxlength="20"))]),
)
r = run(check_password(mixed))
check("lowest minimum binds", r["evidence"]["minlengthAttribute"], 8)
check("lowest maximum binds", r["evidence"]["maxlengthAttribute"], 20)
check("lowest maximum -> warning", r["severity"], WARNING)

# --- 13. Several problems at once are all reported ------------------------------
awful = run(check_password(signup_target(
    pw(minlength="4", maxlength="10", autocomplete="off", pattern=r"[A-Za-z0-9]+"),
    text="Register. Password expires every 30 days.")))
check("many problems -> warning", awful["severity"], WARNING)
check("many problems all counted", awful["description"], "Found 5 problem(s) with the password rules")
check("still never critical", awful["severity"] != CRITICAL, True)

# --- 14. The SPA case: a loose password field with no <form> --------------------
spa = ScanTarget(url="https://spa.example", home=page("https://spa.example/", text="Sign in"))
spa.home.loose_password_fields = [pw(maxlength="12")]
r = run(check_password(spa))
check("SPA loose field is not skipped", r["severity"], WARNING)
check("SPA loose maxlength counted", r["evidence"]["maxlengthAttribute"], 12)

# --- 15. Never critical, on any input ------------------------------------------
severities = set()
for t in (ScanTarget(url="https://a.example"), brochure, login_only, login_capped,
          cleartext, mixed, spa, home_signup,
          signup_target(pw(minlength="4", maxlength="6", autocomplete="off"))):
    severities.add(run(check_password(t))["severity"])
check("never critical", CRITICAL not in severities, True)
check("only known severities", severities <= {PASSED, WARNING, SKIPPED}, True)

# --- 16. The finding contract ---------------------------------------------------
contract = ("id", "checkId", "title", "description", "severity",
            "explanation", "fix", "evidence")
check("meets finding contract", [k for k in contract if k not in awful], [])
check("attributed to this check", awful["checkId"], "password_check")

# Every branch must advise a breached-password list, which is the control that
# catches the weak passwords no length or composition rule does.
for label, result in (("problems", awful), ("passed", run(check_password(signup_target(pw(minlength="12"))))),
                      ("nothing visible", run(check_password(signup_target(pw()))))):
    check(f"{label} branch recommends a breach list", "breach" in result["fix"].lower(), True)

print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
raise SystemExit(1 if FAIL_COUNT else 0)
