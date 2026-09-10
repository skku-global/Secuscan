"""
GOOGLE_AUTH.PY - verifying a Google ID token.

WHY THIS FILE EXISTS
The browser gets a token from Google and posts it to us. This file answers the one
question that matters about it: did Google really issue this, to us, for this
person, and recently. Everything else about Google Sign-In is ordinary session
handling that main.py already does.

It is a separate module for the same reason auth.py is: this is a security check
with a small number of steps, every one of which is load-bearing, and it should be
readable in one screen without an HTTP handler wrapped around it.

HOW THE FLOW ACTUALLY WORKS - the short version, because the OAuth documentation
is written for six flows at once
  1. The page loads Google's script and shows their button.
  2. The user clicks it and picks an account, inside Google's own UI. Nothing about
     that step passes through our code, which is the point - we never see a
     password, and there is nothing for us to get wrong.
  3. Google hands the BROWSER a signed JSON Web Token describing the user: their
     email, name, picture, a stable id, and who the token was issued to.
  4. The browser posts that token to us.
  5. We verify the signature against Google's public keys and check the claims.
     That is this file.
  6. We look up or create the account and issue OUR OWN session, identical to the
     one a password login produces.

WHY THERE IS NO CLIENT SECRET ANYWHERE IN HERE
This is the Identity Services flow, not the server-side redirect flow. The token
arrives already signed by Google, and a signature verified against Google's
published public keys proves origin on its own - there is nothing for a shared
secret to add. The redirect flow needs a secret because it exchanges an
authorization CODE for a token over a back channel, and that exchange has to prove
which application is asking. We skip that exchange entirely.

The practical consequence, worth knowing when configuring the Cloud Console: this
flow needs Authorized JavaScript origins and no redirect URI at all.

THE ONE MISTAKE THIS FILE EXISTS TO PREVENT
Decoding a JWT is not verifying it. A JWT is base64 with dots in it - anyone can
read one, and anyone can write one that says whatever they like. A library that
decodes without checking the signature will happily hand back
{"email": "admin@yourcompany.com", "email_verified": true} from a token an attacker
typed by hand. Every check below is what turns "the token says" into "Google says".
"""

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

import config


# WHY THIS EXISTS
# Google's tokens name their issuer as one of these two strings. Both are correct
# and which one appears has varied over time, so both are accepted - and the check
# is against an explicit set rather than a substring match, because
# `"accounts.google.com" in issuer` would also accept
# "accounts.google.com.attacker.example".
_VALID_ISSUERS = {"https://accounts.google.com", "accounts.google.com"}


# WHY THIS EXISTS
# How far this server's clock may disagree with Google's before a sign-in is
# refused. Without it the tolerance is ZERO, and that is not a safe default for a
# check made against somebody else's clock: Google stamps `iat` from its own time,
# so a server running even a few seconds slow rejects every token it is handed
# with "Token used too early" - a total sign-in outage caused by nothing but drift,
# which reads as "Google is broken" and is invisible without the server log.
#
# It is not a licence to run a wrong clock. A machine 22 seconds out is a machine
# with an NTP problem and this only stops that problem from taking Google Sign-In
# down with it.
#
# WHAT IT COSTS, because the value is a real trade and not a free win: google-auth
# applies it to BOTH ends - `iat - skew` and `exp + skew` - so a captured token
# stays acceptable this many seconds past its expiry too. Thirty seconds against a
# token that lives about an hour widens the replay window by under a tenth of a
# percent, and buys tolerance of ordinary clock drift. Minutes would be a different
# decision; this is why the number is small and named rather than inline.
_CLOCK_SKEW_SECONDS = 30


# WHY THIS EXISTS
# PYTHON-SPECIFIC: a custom exception class, so main.py can catch this one thing
# and turn it into a 401 without also swallowing programming errors. `pass` is the
# whole body - the class name carries all the meaning, which is normal for an
# exception type.
class GoogleTokenError(Exception):
    pass


# WHY THIS EXISTS
# The verification. Returns a small dict of the fields we actually use, or raises
# GoogleTokenError with a message safe to show a user.
#
# PYTHON-SPECIFIC: this is a SYNCHRONOUS function called from async endpoints, and
# that is a deliberate compromise worth naming. google-auth's verifier does a
# blocking HTTP fetch of Google's public keys, which briefly blocks the event loop.
# It is acceptable because the keys are cached in the transport after the first
# call, so it happens roughly daily rather than per sign-in. The clean version runs
# it in a thread pool; noting it here is better than pretending the issue is not
# there.
def verify_google_id_token(token: str) -> dict:
    if not config.google_enabled():
        # Refusing rather than attempting. With no client id configured there is no
        # audience to check the token against, and a verification with the audience
        # check skipped is not a verification - it would accept a token Google
        # issued for somebody else's application entirely.
        raise GoogleTokenError("Google Sign-In is not configured on this server.")

    if not token or not isinstance(token, str):
        raise GoogleTokenError("No Google credential was supplied.")

    try:
        # THE LINE THAT DOES THE WORK, and every argument is a security control.
        #
        # This call, in order:
        #   - splits the JWT and reads its header to find which key signed it,
        #   - fetches Google's current public keys (cached after the first call),
        #   - VERIFIES THE SIGNATURE, which is what proves Google issued it,
        #   - checks `exp`, so an old token is refused - the window is about an
        #     hour, and without this check a token captured once would work
        #     forever,
        #   - checks `aud` against the client id passed here, which is what stops
        #     a token issued for a DIFFERENT application being replayed at ours.
        #     That last one is the check people leave out, and leaving it out means
        #     anyone with any Google OAuth client can mint tokens we accept.
        claims = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            config.GOOGLE_CLIENT_ID,
            # See _CLOCK_SKEW_SECONDS. The library's default here is 0, which makes
            # the `iat` check assume this machine's clock is exactly right.
            clock_skew_in_seconds=_CLOCK_SKEW_SECONDS,
        )
    except ValueError as error:
        # PYTHON-SPECIFIC: google-auth signals every verification failure as
        # ValueError - bad signature, expired, wrong audience, malformed. They are
        # deliberately collapsed into one message here: the differences are useful
        # to an attacker probing what we accept and of no use to a real user, which
        # is the same reasoning as the single login error message in main.py.
        #
        # The real reason is printed for the operator, because "sign-in is broken"
        # is otherwise impossible to diagnose - a wrong client id in .env looks
        # exactly like a hostile token from in here.
        print(f"[google_auth] ID token rejected: {error}")
        raise GoogleTokenError("That Google sign-in could not be verified.") from error

    # --- Claim checks the library does not make for us -----------------------

    # The issuer. google-auth checks the signature chain but does not insist on the
    # issuer string, so it is checked explicitly.
    if claims.get("iss") not in _VALID_ISSUERS:
        raise GoogleTokenError("That Google sign-in could not be verified.")

    # WHY email_verified MATTERS, and it is the subtle one.
    #
    # A Google Workspace administrator can create an account with any email address
    # they like on a domain they control. What they cannot do is get Google to mark
    # an address verified without proving control of it. So without this check,
    # somebody could in principle present a token bearing a colleague's address -
    # and if we matched accounts on email alone, that would be an account takeover.
    #
    # Absent counts as false. PYTHON-SPECIFIC: .get() returns None for a missing
    # key, and `is not True` treats None, False and any surprising value alike -
    # deliberately stricter than `if not claims.get(...)`.
    if claims.get("email_verified") is not True:
        raise GoogleTokenError(
            "That Google account's email address is not verified, so it cannot be "
            "used to sign in."
        )

    email = (claims.get("email") or "").strip().lower()

    if not email:
        # Possible in principle if the profile scope was not granted. There is no
        # account to find or create without an address.
        raise GoogleTokenError("That Google account did not supply an email address.")

    # `sub` is Google's stable, permanent id for the user - the SUBJECT of the
    # token. It is the value to store as the account link, not the email: an email
    # address can be changed by its owner or reassigned by a Workspace admin, and
    # `sub` never changes for the life of the account. Matching on email alone is
    # the more common implementation and the wrong one.
    subject = claims.get("sub") or ""

    if not subject:
        raise GoogleTokenError("That Google sign-in could not be verified.")

    return {
        "googleId": subject,
        "email": email,
        # A display name is a convenience, not a credential. Falling back to the
        # local part of the address means an account always has something to show
        # in the corner of the screen rather than an empty label.
        "name": (claims.get("name") or "").strip() or email.split("@")[0],
    }
