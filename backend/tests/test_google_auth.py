"""Branch tests for the Google ID-token verification.

WHAT BROUGHT THIS FILE INTO EXISTENCE: a live 401 on /auth/google whose server log
read `Token used too early, 1788950768 < 1788950785` - the machine's clock was 22
seconds behind Google's, and the verifier allowed a tolerance of exactly zero. Every
Google sign-in failed, and nothing in the browser said why.

So what is pinned here is mostly ONE ARGUMENT: that a clock-skew tolerance is passed
to google-auth, and that it is a sane size. That reads like a trivial thing to test
until you notice the failure mode - the kwarg is easy to drop in a refactor, the
library's default is 0, and the resulting outage is invisible from the client. A test
is cheaper than diagnosing it twice.

The signature check itself is NOT re-tested here: verifying a real Google signature
needs Google's keys and a token only Google can mint, so a test of it would be a test
of a mock. What IS testable without the network is which arguments we hand the
library, and that the claim checks we make ourselves - issuer, email_verified - still
refuse what they should. Those are the checks google-auth does not make for us.

Run from anywhere (the `import _path` line puts backend/ on sys.path):
  python backend/tests/test_google_auth.py
"""

import time

import _path  # noqa: F401  - puts backend/ on sys.path; must precede the imports below
import config
import google_auth
from google.oauth2 import id_token

PASS_COUNT = 0
FAIL_COUNT = 0


def check(label, got, want):
    global PASS_COUNT, FAIL_COUNT
    ok = got == want
    if ok:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    suffix = "" if ok else "   (got {!r}, wanted {!r})".format(got, want)
    print("  {} {}{}".format("ok  " if ok else "FAIL", label, suffix))


class Recorder:
    """Stands in for google-auth's verifier and records how it was called.

    The real one needs the network and a token Google signed. What matters here are
    the ARGUMENTS, so this returns a minimal valid claim set and remembers what it
    was handed.
    """

    def __init__(self, claims=None, raises=None):
        self.calls = []
        self.claims = claims
        self.raises = raises

    def __call__(self, token, request, audience, **kwargs):
        recorded = {"token": token, "audience": audience}
        recorded.update(kwargs)
        self.calls.append(recorded)
        if self.raises is not None:
            raise self.raises
        now = int(time.time())
        base = {
            "iss": "https://accounts.google.com",
            "sub": "1234567890",
            "email": "ada@example.com",
            "email_verified": True,
            "name": "Ada Lovelace",
            "iat": now,
            "exp": now + 3600,
        }
        base.update(self.claims or {})
        return base


def with_verifier(recorder, fn):
    """Swap google-auth's verifier for the duration of one call, then put it back."""
    original = id_token.verify_oauth2_token
    google_auth.id_token.verify_oauth2_token = recorder
    try:
        return fn()
    finally:
        google_auth.id_token.verify_oauth2_token = original


def accepts(recorder, token="a.b.c"):
    """True if verification succeeded, False if it raised GoogleTokenError."""
    try:
        with_verifier(recorder, lambda: google_auth.verify_google_id_token(token))
        return True
    except google_auth.GoogleTokenError:
        return False


# The client id has to look configured, or verify_google_id_token refuses before it
# reaches the library at all. Restored at the end.
ORIGINAL_CLIENT_ID = config.GOOGLE_CLIENT_ID
TEST_CLIENT_ID = "test-client-id.apps.googleusercontent.com"
config.GOOGLE_CLIENT_ID = TEST_CLIENT_ID


# ============================================================================
print("\n--- 1. The clock-skew tolerance is passed, and is a sane size ----------")
# ============================================================================

# WHY THIS IS THE FIRST AND MOST IMPORTANT CHECK: with no tolerance, a server whose
# clock runs a few seconds slow rejects every token Google issues. That is a total
# sign-in outage produced by drift alone.
rec = Recorder()
profile = with_verifier(rec, lambda: google_auth.verify_google_id_token("a.b.c"))

check("the verifier was called once", len(rec.calls), 1)
check("a clock skew was passed at all", "clock_skew_in_seconds" in rec.calls[0], True)
check("the skew is not zero", rec.calls[0].get("clock_skew_in_seconds", 0) > 0, True)

# Both ends move: google-auth widens `exp` by the same amount it widens `iat`, so a
# generous value quietly extends how long a captured token stays usable. The upper
# bound is the half of this test that stops "fix the outage" becoming "accept
# anything".
skew = rec.calls[0]["clock_skew_in_seconds"]
check("the skew is at least 10s (real clocks drift)", skew >= 10, True)
check("the skew is at most 60s (it also extends exp)", skew <= 60, True)

# The audience is still the configured client id - the check that stops a token
# minted for somebody else's application being replayed at ours.
check("the audience is the configured client id", rec.calls[0]["audience"], TEST_CLIENT_ID)
check("the token is passed through unchanged", rec.calls[0]["token"], "a.b.c")


# ============================================================================
print("\n--- 2. A good token still yields the fields the caller needs -----------")
# ============================================================================

check("email survives", profile["email"], "ada@example.com")
check("name survives", profile["name"], "Ada Lovelace")
check("the stable subject id is the googleId", profile["googleId"], "1234567890")


# ============================================================================
print("\n--- 3. The claim checks google-auth does NOT make for us ---------------")
# ============================================================================

# The issuer. A substring match here would accept accounts.google.com.attacker.example.
for issuer, allowed in [
    ("https://accounts.google.com", True),
    ("accounts.google.com", True),
    ("https://accounts.google.com.attacker.example", False),
    ("", False),
]:
    # The label states the EXPECTATION, not the input. "issuer X accepted" printed
    # next to "ok" reads as though the attacker issuer got in, which is the exact
    # opposite of what passing means here.
    verdict = "accepted" if allowed else "REFUSED"
    check("issuer {!r} is {}".format(issuer, verdict), accepts(Recorder(claims={"iss": issuer})), allowed)

# An unverified email is the account-takeover primitive: /auth/google links a Google
# id onto an EXISTING account matched by email address.
for verified, allowed in [(True, True), (False, False), (None, False)]:
    check(
        "email_verified={!r} is {}".format(verified, "accepted" if allowed else "REFUSED"),
        accepts(Recorder(claims={"email_verified": verified})),
        allowed,
    )


# ============================================================================
print("\n--- 4. Refusals that happen before any network call --------------------")
# ============================================================================

# No client id: refusing is the only safe answer, because a verification with the
# audience check skipped is not a verification.
config.GOOGLE_CLIENT_ID = ""
rec = Recorder()
check("unconfigured server refuses", accepts(rec), False)
check("and never called the verifier", len(rec.calls), 0)

config.GOOGLE_CLIENT_ID = TEST_CLIENT_ID
for bad in ["", None, 12345]:
    rec = Recorder()
    check("credential {!r} refused".format(bad), accepts(rec, token=bad), False)
    check("  and never called the verifier for {!r}".format(bad), len(rec.calls), 0)

# A library ValueError - bad signature, wrong audience, expired, too early - becomes
# one GoogleTokenError with a message safe to show a user, never the library's text.
rec = Recorder(raises=ValueError("Token used too early, 100 < 130."))
try:
    with_verifier(rec, lambda: google_auth.verify_google_id_token("a.b.c"))
    message = "(no exception)"
except google_auth.GoogleTokenError as error:
    message = str(error)

check("library failure becomes our message", message, "That Google sign-in could not be verified.")
check("and does not leak the library's text", "Token used too early" in message, False)

config.GOOGLE_CLIENT_ID = ORIGINAL_CLIENT_ID

print("\n{} passed, {} failed".format(PASS_COUNT, FAIL_COUNT))
raise SystemExit(1 if FAIL_COUNT else 0)
