"""
CONFIG.PY - every environment variable the app reads, in one place.

WHY THIS FILE EXISTS
Until now database.py read os.environ directly, which worked because there was
exactly one setting. Auth brings six more - an API key, a from-address, a Google
client id, a feature switch - and scattering os.environ.get() calls across four
modules has two specific failure modes worth avoiding:

  1. A MISSING KEY IS DISCOVERED LATE. os.environ.get() with a default never
     complains, so a mistyped RESEND_API_KEY becomes "email silently does not
     send" at the moment a user is locked out of their account. The checks here
     run at import, so the server says what is wrong before it accepts traffic.
  2. NOBODY CAN TELL WHAT THE APP NEEDS. There is no way to answer "what goes in
     the .env file" except grepping. This file IS that answer.

A .ENV FILE DOES NOTHING ON ITS OWN. Worth stating plainly because it is a
genuinely common first hour of confusion: the shell does not read .env, Python
does not read .env, and os.environ only contains what the operating system put
there. load_dotenv() below is the line that makes the file mean anything.

NOTHING SECRET IS EVER LOGGED FROM HERE. The values are read and held; the
diagnostics print names and whether something is set, never the value itself. A
stack trace or a startup banner is one of the most common ways an API key ends up
in a log aggregator.
"""

import os
from pathlib import Path

from dotenv import load_dotenv


# WHY THIS EXISTS
# PYTHON-SPECIFIC: __file__ is the path of this source file, so this resolves to
# backend/.env regardless of the directory uvicorn was started from. The obvious
# alternative - load_dotenv() with no argument - searches upward from the CURRENT
# WORKING DIRECTORY, so it finds the file when you launch from backend/ and
# silently finds nothing when you launch from the repository root. That produces a
# server that works for one person and not another, which is the worst class of
# configuration bug.
_ENV_PATH = Path(__file__).resolve().parent / ".env"

# override=False means a variable already present in the real environment wins
# over the file. That is the right precedence for deployment: the container or
# systemd unit sets the truth, and .env is the local development convenience.
load_dotenv(_ENV_PATH, override=False)


# --- Small readers ---------------------------------------------------------


# WHY THIS EXISTS
# os.environ.get() returns whatever is in the variable including an empty string,
# and an empty string is the single most common way a setting is "present but not
# set" - a line like `RESEND_API_KEY=` in a .env file. Treating "" as absent is
# what makes the required-check below actually catch that case.
def _text(name: str, default: str = "") -> str:
    value = os.environ.get(name, "")
    return value.strip() or default


# WHY THIS EXISTS
# Environment variables are always strings, so a switch arrives as the TEXT
# "false" - and `bool("false")` is True in Python, because every non-empty string
# is truthy. That one-line mistake turns a feature flag permanently on, and it is
# invisible on reading. Hence an explicit list of what counts as yes.
def _flag(name: str, default: bool = False) -> bool:
    raw = _text(name).lower()

    if not raw:
        return default

    return raw in {"1", "true", "yes", "on"}


# WHY THIS EXISTS
# Several settings are naturally a list - allowed origins today, probably allowed
# hosts tomorrow - and an environment variable can only ever be one string. Comma
# separation is the convention every deployment tool already understands.
#
# PYTHON-SPECIFIC: the `if item.strip()` at the end of the comprehension drops
# empty entries, so a trailing comma or a doubled one produces a shorter list
# rather than an origin of "" - which would match nothing and be invisible in a
# config dump.
def _list(name: str) -> list[str]:
    return [item.strip() for item in _text(name).split(",") if item.strip()]


# --- Database --------------------------------------------------------------

MONGO_URL = _text("SECUSCAN_MONGO_URL", "mongodb://127.0.0.1:27017")


# --- Product identity ------------------------------------------------------

# Shown by an authenticator app beside the 6-digit code, so a user with twelve
# entries in Google Authenticator can tell which one is ours. It is baked into
# the QR code at enrolment and stored in nothing, so changing it only affects
# people who enrol afterwards.
APP_NAME = _text("SECUSCAN_APP_NAME", "SecuScan")

# Where the frontend lives. Used in the emails - a recovery message with no link
# back to the site is a dead end - and nowhere else.
APP_URL = _text("SECUSCAN_APP_URL", "http://localhost:5173")


# --- Browser origins (CORS) ------------------------------------------------

# WHY THIS IS CONFIGURABLE NOW AND WAS NOT BEFORE
# The origin list used to be two hardcoded strings in main.py: localhost:5173 and
# 127.0.0.1:5173. That is correct exactly until Vite finds 5173 already taken -
# by a second terminal, a previous run that did not exit, another project - at
# which point it silently moves to 5174 and prints the new URL. Every request the
# browser makes is then blocked, and the error the developer sees says nothing
# about ports:
#
#   No 'Access-Control-Allow-Origin' header is present on the requested resource
#
# The server is fine, curl is fine, and the frontend simply cannot talk to it.
# Hardcoding a port that a dev server chooses at runtime was the bug.
#
# Comma-separated, e.g.
#   SECUSCAN_CORS_ORIGINS=https://app.example.com,https://www.example.com
CORS_ORIGINS = _list("SECUSCAN_CORS_ORIGINS")


# WHY A REGEX AND NOT A LONGER LIST: the port is not knowable in advance. Listing
# 5173 through 5180 just moves the cliff edge to 5181, and the person who hits it
# gets the same undiagnosable error. Matching any port on the loopback host is the
# only version that does not have an edge.
#
# ANY PORT, BUT ONLY ON THIS MACHINE. The host part is anchored on both sides, so
# "localhost" matches and "localhost.evil.com" - which contains it - does not.
# That anchoring is the whole security of the pattern, and is why it is written
# here as a constant rather than assembled from a setting somewhere.
_DEV_ORIGIN_PATTERN = r"^http://(localhost|127\.0\.0\.1)(:\d+)?$"


# WHY THE DEV PATTERN SWITCHES ITSELF OFF
# Returning None the moment CORS_ORIGINS is set means configuring the variable for
# production also REMOVES the loopback allowance, in one step, without anybody
# having to remember a second one. The alternative - a separate "dev mode" flag -
# is a flag somebody forgets to turn off, and a forgotten flag here means a
# production API that trusts any page served from the machine it runs on.
def cors_origin_regex() -> str | None:
    if CORS_ORIGINS:
        return None

    return _DEV_ORIGIN_PATTERN


# --- Two-factor authentication ---------------------------------------------

# THE ENFORCEMENT SWITCH.
#
# False (the default): a user may enrol in TOTP from their account, and login
# proceeds normally for anyone who has not. This is what lets the feature ship
# without breaking the three accounts already in the database, and without making
# every new signup scan a QR code before they can run one scan.
#
# True: an account with no TOTP secret is refused a session and told to enrol.
# The flag is read at request time rather than captured at import, so flipping it
# takes a restart and not a redeploy.
#
# WHY A SWITCH RATHER THAN A DECISION: "should 2FA be mandatory" is a policy
# question about a business, not a technical one, and the honest engineering
# answer is to make both positions available and let the switch record which one
# is in force. What matters is that the enforcement is written and tested now -
# adding it later is the version that never happens.
def require_2fa() -> bool:
    return _flag("SECUSCAN_REQUIRE_2FA", default=False)


# --- Google Sign-In --------------------------------------------------------

# The OAuth client id from Google Cloud Console. NOT a secret: it ships inside
# the JavaScript bundle, appears in the page source, and is designed to be public.
# What makes the flow safe is that Google signs the ID token and we verify that
# signature - see google_auth.py.
#
# The matching client SECRET is deliberately absent from this file. The Identity
# Services flow never uses it, and an unused secret in a config module is an
# invitation for somebody to start using it.
GOOGLE_CLIENT_ID = _text("SECUSCAN_GOOGLE_CLIENT_ID")


def google_enabled() -> bool:
    # The button is hidden in the UI when this is empty, and the endpoint refuses
    # rather than pretending. A half-configured sign-in path that returns 500 is
    # worse than one that is visibly switched off.
    return bool(GOOGLE_CLIENT_ID)


# --- Email -----------------------------------------------------------------

# WHICH SENDER TO USE. The seam that keeps the provider swappable: mailer.py
# reads this name and builds the matching sender, so changing provider is one
# environment variable plus one class, and no change at any call site.
#
#   "resend"  - the real one, calls the Resend HTTP API.
#   "console" - prints the message to the server log instead of sending. Present
#               for tests and for a machine with no API key, NOT as a fallback:
#               it is selected explicitly by name and never substituted in
#               silently, because a recovery code that goes to a log file instead
#               of an inbox while the UI says "check your email" is a lie the
#               product tells a locked-out user.
EMAIL_PROVIDER = _text("SECUSCAN_EMAIL_PROVIDER", "resend").lower()

RESEND_API_KEY = _text("RESEND_API_KEY")

# Must be an address on a domain verified in the Resend dashboard; Resend rejects
# anything else, which is the whole point of domain verification. The display-name
# form ("SecuScan <security@example.com>") is accepted as-is.
EMAIL_FROM = _text("SECUSCAN_EMAIL_FROM")


# --- Payments --------------------------------------------------------------

# WHICH PROCESSOR TO USE. The same seam as EMAIL_PROVIDER above, doing the same
# job for the same reason: payments/__init__.py reads this name and builds the
# matching provider, so main.py's checkout endpoint names no company at all.
#
#   "mock"   - the only one that works today. Validates that a card number is
#              well-FORMED, writes an order, grants the plan. NO MONEY MOVES.
#              See the header of payments/mock_card.py, which is emphatic about
#              this, and about the fact that a Luhn-valid number is not an
#              authorised one.
#   "paddle" - the real one, and not finished. Selecting it without the four
#              credentials below gets a provider that refuses every checkout and
#              a startup warning naming what is absent.
#
# THE DEFAULT IS "mock" AND THAT IS SAFE IN EXACTLY ONE DIRECTION. A deployment
# that forgets this variable takes no money, which is the harmless failure. The
# harmful one - taking a real card number into a fictional processor - needs
# somebody to have deliberately put this app in front of real customers, and the
# warning printed at every startup says so.
#
# WHAT MUST NEVER HAPPEN, and payments/__init__.py enforces it: "paddle" failing
# to configure does NOT fall back to "mock". Granting paid plans for free because
# a secret is missing is not a degraded mode, it is a giveaway.
PAYMENT_PROVIDER = _text("SECUSCAN_PAYMENT_PROVIDER", "mock").lower()

# Sandbox vs production, for the provider that has both. Defaults to the sandbox,
# because the wrong default here spends real money rather than failing to.
PADDLE_SANDBOX = _flag("SECUSCAN_PADDLE_SANDBOX", default=True)

# The client-side token. NOT a secret, in the same way GOOGLE_CLIENT_ID is not: it
# ships in the browser bundle so the overlay can open. It is here rather than
# hardcoded because it differs between sandbox and production.
PADDLE_CLIENT_TOKEN = _text("SECUSCAN_PADDLE_CLIENT_TOKEN")

# The server-side API key. This one IS a secret - it can create and refund
# transactions - and it must never be sent to the browser.
PADDLE_API_KEY = _text("SECUSCAN_PADDLE_API_KEY")

# The webhook signing secret, which is the load-bearing one. Paddle's callback is
# what grants a plan under a real integration, so an unverified callback is an
# unauthenticated endpoint that hands out subscriptions. See handle_webhook in
# payments/paddle.py.
PADDLE_WEBHOOK_SECRET = _text("SECUSCAN_PADDLE_WEBHOOK_SECRET")


# WHY THIS EXISTS
# Paddle charges for an entry in ITS catalogue, identified by a price id, rather
# than for an amount we send it. That is the same principle billing.PLANS already
# follows - the client cannot choose the price - enforced one layer further out.
#
# So each purchasable plan needs a price id, and it is looked up by plan id rather
# than stored in PLANS: the ids are environment-specific (a sandbox price id is not
# a production one) and PLANS is source code.
#
# PYTHON-SPECIFIC: the f-string builds the variable name, so adding a plan to the
# catalogue needs no edit here - only a SECUSCAN_PADDLE_PRICE_<ID> in the
# environment. payments/paddle.py's missing_credentials() walks PLANS and calls
# this, which is what makes a new plan with no price id a startup warning instead
# of a failed checkout.
def paddle_price_id(plan_id: str) -> str:
    return _text(f"SECUSCAN_PADDLE_PRICE_{(plan_id or '').strip().upper()}")


# --- Tier 2 Credentials ----------------------------------------------------

# Fernet symmetric encryption key for encrypting client-submitted test credentials
# at rest. If unset, a deterministic local development key is used with a warning.
CREDENTIALS_KEY = _text("SECUSCAN_CREDENTIALS_KEY")


# --- Startup validation ----------------------------------------------------


# WHY THIS EXISTS
# Called once from the lifespan startup in main.py. It reports what is missing
# rather than raising, for a specific reason: none of these settings are needed to
# scan a website or to sign in with a password, so a missing RESEND_API_KEY must
# not stop the server booting. What it must not do is fail silently - the person
# running this needs to know that account recovery will not work before a user
# discovers it.
#
# Returns a list of sentences. main.py prints them.
def startup_warnings() -> list[str]:
    warnings: list[str] = []

    if not _ENV_PATH.exists():
        warnings.append(
            f"No .env file at {_ENV_PATH}. Reading configuration from the "
            "environment only."
        )

    # NOT a problem - a statement of fact, printed because the failure it prevents
    # is invisible from the server side. A blocked request never reaches a route,
    # so the access log shows nothing at all and the server looks healthy while
    # the frontend is completely unable to reach it.
    if CORS_ORIGINS:
        warnings.append(
            "CORS: allowing " + ", ".join(CORS_ORIGINS) + " (from "
            "SECUSCAN_CORS_ORIGINS). The loopback development allowance is OFF."
        )
    else:
        warnings.append(
            "CORS: SECUSCAN_CORS_ORIGINS is not set, so any port on localhost or "
            "127.0.0.1 is allowed. Correct for development; set the variable to "
            "your real domain before deploying."
        )

    if not GOOGLE_CLIENT_ID:
        warnings.append(
            "SECUSCAN_GOOGLE_CLIENT_ID is not set - Google Sign-In is disabled. "
            "The button is hidden in the UI and POST /auth/google returns 503."
        )

    if EMAIL_PROVIDER == "resend":
        # PYTHON-SPECIFIC: `not RESEND_API_KEY` covers both absent and empty,
        # because _text() already collapsed the empty case to "".
        if not RESEND_API_KEY:
            warnings.append(
                "SECUSCAN_EMAIL_PROVIDER=resend but RESEND_API_KEY is not set - "
                "email recovery codes cannot be sent."
            )

        if not EMAIL_FROM:
            warnings.append(
                "SECUSCAN_EMAIL_FROM is not set - email recovery codes cannot be "
                "sent. Use an address on your Resend-verified domain, e.g. "
                '"SecuScan <security@yourdomain.com>".'
            )
    elif EMAIL_PROVIDER == "console":
        warnings.append(
            "SECUSCAN_EMAIL_PROVIDER=console - recovery codes will be PRINTED TO "
            "THIS LOG rather than emailed. Development only."
        )
    else:
        warnings.append(
            f'SECUSCAN_EMAIL_PROVIDER="{EMAIL_PROVIDER}" is not a known sender. '
            'Expected "resend" or "console". Email is disabled.'
        )

    # WHY THE PAYMENT WARNING IS UNCONDITIONAL ON THE MOCK
    # Every other warning in this function reports something MISSING. This one
    # reports something working, because what it is working as is the problem: a
    # checkout that grants paid plans on a checksum. That is correct for
    # development and is the single most dangerous thing in this codebase to leave
    # switched on by accident, so it is printed at every single startup rather than
    # only when something is absent.
    if PAYMENT_PROVIDER == "mock":
        warnings.append(
            "SECUSCAN_PAYMENT_PROVIDER=mock - checkout validates the SHAPE of a "
            "card and grants the plan. NO MONEY MOVES and no card is authorised. "
            "Never point this at real customers."
        )
    elif PAYMENT_PROVIDER == "paddle":
        # PYTHON-SPECIFIC: imported here rather than at the top of the module.
        # payments/paddle.py imports config, so a module-level import would be a
        # circular one; by the time this function runs, both modules are loaded.
        from payments.paddle import missing_credentials

        missing = missing_credentials()

        if missing:
            warnings.append(
                "SECUSCAN_PAYMENT_PROVIDER=paddle but it is not configured, so "
                "POST /billing/checkout returns 503. Missing: "
                + "; ".join(missing)
            )
        elif PADDLE_SANDBOX:
            warnings.append(
                "SECUSCAN_PAYMENT_PROVIDER=paddle in SANDBOX. Real cards are not "
                "charged. Set SECUSCAN_PADDLE_SANDBOX=false for production."
            )
    else:
        warnings.append(
            f'SECUSCAN_PAYMENT_PROVIDER="{PAYMENT_PROVIDER}" is not a known '
            'provider. Expected "mock" or "paddle". Checkout is disabled - it '
            "does NOT fall back to the mock, because granting paid plans for "
            "free is not a degraded mode."
        )

    return warnings
