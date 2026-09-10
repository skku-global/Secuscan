"""
AUTH.PY - passwords and sessions.

WHY THIS FILE EXISTS
Authentication is the one part of a security product that cannot be improvised,
so every decision that could be got wrong is made once, here, and nowhere else.
main.py owns HTTP and database.py owns storage; this file owns the cryptography
and the password rules. One place to audit, one place to change when the advice
moves on.

Nothing in here imports FastAPI or pymongo, deliberately. These are plain
functions over strings, so they can be reasoned about - and tested - without a
server or a database running.

THE THREE THINGS THIS FILE GETS RIGHT
  1. Passwords are hashed with Argon2id. Never encrypted, never stored.
  2. Session tokens are random, not derived from the user - so nothing about the
     account can be read out of a token, and a token cannot be forged.
  3. The password rules live next to the hashing, so "what counts as acceptable"
     is enforced on the server instead of trusted from the browser.
"""

import hashlib
import io
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from uuid import uuid4

import pyotp
import segno
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError

# PYTHON-SPECIFIC: the third-party imports are grouped below the standard-library
# ones, which is PEP 8's convention and a genuinely useful one - it makes "what
# does this file need installed" readable at a glance.
#
#   pyotp  - RFC 6238 TOTP. Small, and the reference implementation in Python.
#   segno  - QR code rendering. Chosen over the more common `qrcode` package
#            because it has NO dependencies at all; qrcode pulls in Pillow, an
#            image library with a large native surface, to draw a grid of squares.


# WHY THIS EXISTS
# One hasher instance, reused. It carries the cost parameters - how much memory
# and CPU a single hash burns - and those parameters are the entire security
# argument for a password hash: a slow hash is what makes a stolen database
# expensive to attack rather than merely inconvenient.
#
# Argon2id specifically, not SHA-256 and not MD5. General-purpose hashes are built
# to be fast, which is exactly the wrong property here - a GPU can try billions of
# SHA-256 guesses a second. Argon2id is deliberately memory-hungry, which is what
# defeats that hardware. It won the Password Hashing Competition and is OWASP's
# current first recommendation.
#
# PYTHON-SPECIFIC: the library defaults (time_cost=3, memory_cost=64MiB,
# parallelism=4) already exceed OWASP's stated minimum, so they are left alone
# rather than hand-tuned. Writing them out here would only invite drifting behind
# the library defaults later.
_hasher = PasswordHasher()

# WHY THIS EXISTS
# A login attempt for an email that does not exist must take about as long as one
# with the wrong password. Otherwise the response time itself answers the question
# "is this address registered?" - a timing side channel that turns a login form
# into an account-enumeration oracle. Verifying against this throwaway hash spends
# the same work a real check would.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))


# --- Password policy -------------------------------------------------------

# Length is the rule that actually matters. Every extra character multiplies the
# search space, while the composition rules people usually reach for mostly
# produce "Password1!" - which is ten characters of nothing. 12 is the floor OWASP
# suggests for an account protected by a password alone.
PASSWORD_MIN_LENGTH = 12

# An upper bound is a denial-of-service guard, not a strength rule. Argon2 is meant
# to be slow, so a request carrying a 10MB "password" would happily occupy a core
# for a while. 128 characters is far past any real passphrase.
PASSWORD_MAX_LENGTH = 128

# A deliberately short list, not a breach corpus. It catches the handful of guesses
# an attacker tries first, which is most of the value for a few lines of code. A
# real deployment checks candidates against the Have I Been Pwned range API
# instead, and that is the upgrade path from here.
_COMMON_PASSWORDS = frozenset(
    {
        "password", "password1", "password123", "passw0rd", "letmein",
        "qwerty", "qwertyuiop", "111111", "123456", "1234567", "12345678",
        "123456789", "1234567890", "iloveyou", "admin", "administrator",
        "welcome", "welcome1", "monkey", "dragon", "football", "baseball",
        "sunshine", "princess", "changeme", "trustno1", "abc123", "abcd1234",
        "secuscan", "secuscan1", "secuscan123", "secret", "starwars",
    }
)


# WHY THIS EXISTS
# The single source of truth for "is this password good enough". The signup
# endpoint calls it before anything is written, so a weak password never reaches
# the database - regardless of what the browser did or did not check.
#
# The frontend has its own copy of these rules in lib/passwordPolicy.js, and that
# duplication is intentional rather than sloppy: the browser copy exists to give
# live feedback while someone types, and this one exists to enforce. Only one of
# them is a control. Anyone can skip the browser entirely with curl.
#
# Returns None when the password is acceptable, or a sentence to show the user - a
# message rather than a boolean, because "rejected, and here is which rule" is the
# difference between fixing it and guessing.
def password_problem(password: str, email: str = "", name: str = "") -> str | None:
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters."

    if len(password) > PASSWORD_MAX_LENGTH:
        return f"Password must be {PASSWORD_MAX_LENGTH} characters or fewer."

    # PYTHON-SPECIFIC: any() with a GENERATOR EXPRESSION - the same idea as
    # JavaScript's .some(), except the parentheses are the entire syntax and
    # nothing is built into an intermediate list. isalpha() is a per-character
    # test here because it is being called on single characters.
    has_letter = any(character.isalpha() for character in password)
    has_other = any(not character.isalpha() for character in password)

    # One mild variety rule, not the usual four. Twelve characters of pure letters
    # is still a dictionary-attack target, but demanding upper AND lower AND digit
    # AND symbol is what drives people to reuse a password they already remember,
    # which is a worse outcome than a slightly simpler one they do not.
    if not (has_letter and has_other):
        return "Password must mix letters with at least one number or symbol."

    # Checked twice: the password as typed, and its alphabetic core with digits
    # and symbols stripped out. The 12-character minimum has a predictable side
    # effect - people take the word they already use and pad it, so what the rule
    # actually produces is "password1234" and "letmein!!2026". Without the second
    # check this list would be dead code, because every entry short enough to match
    # it directly already fails the length rule above.
    letters_only = "".join(c for c in password.lower() if c.isalpha())

    if password.lower() in _COMMON_PASSWORDS or letters_only in _COMMON_PASSWORDS:
        return "That password is too close to one of the most commonly guessed. Choose another."

    # Something derived from the account it protects is public knowledge wearing a
    # disguise: the email is on the signup form, and the name is often on the
    # company website.
    for personal in _personal_strings(email, name):
        if personal in password.lower():
            return "Password must not contain your name or email address."

    return None


# WHY THIS EXISTS
# Pulls out the pieces of an identity worth checking a password against. Kept
# separate so the rule above reads as one line, and so "what counts as personal"
# can grow later - a company name, say - without touching the policy itself.
def _personal_strings(email: str, name: str) -> list[str]:
    # The part before the @. A whole address rarely appears in a password; the
    # local part very often does.
    local_part = email.split("@")[0].strip().lower()

    # PYTHON-SPECIFIC: str.split() with no argument splits on ANY run of
    # whitespace and discards empties, which is what a typed-in name needs.
    name_parts = [part.lower() for part in name.split()]

    # Fragments of one or two characters match far too much to mean anything.
    return [value for value in [local_part, *name_parts] if len(value) >= 3]


# --- Hashing ---------------------------------------------------------------

# WHY THIS EXISTS
# The only function in the codebase that turns a password into something storable.
# The output is one string containing the algorithm, its parameters, the salt and
# the digest - so the hash is self-describing, and verifying it later needs no
# extra columns and no remembered settings.
#
# A fresh random salt goes into every hash, generated by the library. Two people
# with the same password therefore get different hashes, which is what stops one
# cracked password from unlocking every account that shares it.
def hash_password(password: str) -> str:
    return _hasher.hash(password)


# WHY THIS EXISTS
# The other half - and note the shape of it: nothing anywhere decrypts a password,
# because a hash cannot be reversed. Checking a login means hashing the attempt
# with the same salt and parameters, which are read back out of the stored hash,
# and comparing the results.
#
# Wrapped in try/except because argon2 signals a mismatch by raising, and a wrong
# password is not an exceptional event on a login form - it is the normal case
# several times a day. Callers get a boolean.
def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except VerificationError:
        # Covers VerifyMismatchError (simply the wrong password) and any other
        # verification failure. Both mean "do not let them in", so both are False.
        return False
    except InvalidHash:
        # The stored value is not an Argon2 hash at all - corruption, or a row
        # written by some earlier scheme. Refusing is the only safe answer.
        return False


# WHY THIS EXISTS
# Spends the CPU a real verification would spend, then returns nothing. Called on
# the path where the email does not exist, so that path costs what the
# existing-account path costs. See _DUMMY_HASH above for why the equivalence
# matters more than it looks like it should.
def waste_time_like_a_verification() -> None:
    verify_password(_DUMMY_HASH, "not-the-password")


# --- Identifiers and session tokens ----------------------------------------

# WHY THIS EXISTS
# Ids for user records. Full 32 hex characters, unlike the 8-character scan ids -
# scan ids are short because they appear in URLs people paste around, and a user
# id has no reason to be either short or guessable.
def new_user_id() -> str:
    return uuid4().hex


# WHY THIS EXISTS
# A session token is a bearer credential: whoever holds it IS the user until it
# expires. So it has exactly one requirement, which is to be unguessable.
#
# PYTHON-SPECIFIC: `secrets`, not `random`. The random module is a Mersenne
# Twister whose internal state can be reconstructed from a handful of observed
# outputs; it exists for simulations and shuffling, not for credentials. secrets
# draws from the operating system cryptographic source. Choosing the wrong one of
# these two modules is a real, repeatedly published vulnerability class.
#
# token_urlsafe(32) is 32 random BYTES - 256 bits - rendered as roughly 43
# URL-safe characters. Not 32 characters, which is the usual misreading.
def new_session_token() -> str:
    return secrets.token_urlsafe(32)


# WHY THIS EXISTS
# The database stores the HASH of a session token, never the token itself. If the
# database ever leaks, an attacker gets a list of useless digests rather than a set
# of live logins they can paste straight into a browser.
#
# SHA-256 is right here even though it would be wrong for a password. A password is
# low-entropy and guessable, so it needs a deliberately slow hash; a token is
# already 256 bits of randomness, so there is nothing to guess and no reason to pay
# the Argon2 cost on every authenticated request.
def hash_token(token: str) -> str:
    # PYTHON-SPECIFIC: hashlib works on bytes, not str - hence .encode() - and
    # .hexdigest() renders the result as text so it can live in a JSON document.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# How long a login lasts. Long enough not to be irritating, short enough that a
# token left behind on a shared machine does not work forever. MongoDB enforces
# this itself through the TTL index in database.py, so an expired session
# disappears even if nothing ever asks about it again.
SESSION_TTL_DAYS = 30


# WHY THIS EXISTS
# The moment a new session stops being valid, computed in one place so the API
# layer never invents its own expiry.
#
# PYTHON-SPECIFIC: timezone.utc, and never a bare datetime.now(). A naive datetime
# carries no timezone, so comparing one against a value read back from the database
# raises TypeError - and worse, it silently means "whatever this machine's clock
# says", which is a genuine source of off-by-hours bugs.
def session_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)


# --- Email -----------------------------------------------------------------

# Not a full RFC 5322 validator, on purpose. Real addresses are far stranger than
# most regexes assume, and the only actual proof an address works is sending mail
# to it. This rejects obvious typos - missing @, missing dot, embedded spaces - and
# claims nothing more than that.
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# WHY THIS EXISTS
# The email is the login identifier, so two spellings of one address must not
# become two accounts. Lowercasing and trimming makes "  Ada@Example.com  " and
# "ada@example.com" the same key - which is also what makes the unique index in
# MongoDB mean what people assume it means.
def normalise_email(email: str) -> str:
    return email.strip().lower()


def looks_like_email(email: str) -> bool:
    # PYTHON-SPECIFIC: re.match anchors at the start only, never at the end, which
    # is why the pattern carries its own ^ and $. bool() converts the match object
    # (or None) into a real boolean instead of leaking a match object to callers.
    return bool(_EMAIL_PATTERN.match(email))


# ============================================================================
# TWO-FACTOR AUTHENTICATION (TOTP)
#
# WHY THIS SECTION IS IN THIS FILE
# The same argument as the password rules at the top: this is cryptography with
# exactly one correct implementation, so it is written once and audited once. An
# endpoint should call verify_totp() and never see a time step or a raw secret.
#
# WHAT TOTP ACTUALLY IS, because the name hides a very simple idea
# The server and the phone share one random secret, agreed once at enrolment. To
# produce a code, both sides take the CURRENT TIME divided into 30-second steps,
# and compute HMAC-SHA1(secret, step number), then squeeze six digits out of the
# result. Same secret plus same 30-second window equals the same six digits, so
# the phone can prove it holds the secret without ever sending it.
#
# The consequences of that design are the whole reason this works offline:
#   - Nothing is transmitted at enrolment except the secret, once.
#   - The phone needs no network afterwards. It only needs a clock.
#   - The server keeps no per-login state. It recomputes from the clock too.
#
# It is RFC 6238, and Google Authenticator, Authy, 1Password and Microsoft
# Authenticator all implement the same specification - which is why the QR code
# below works in any of them rather than needing an app of ours.
# ============================================================================

# The digits and the window. These are not tuneables - they are what every
# authenticator app assumes, and changing either produces codes that the app
# generates and the server rejects, with nothing on screen to indicate why.
# Written out rather than left implicit precisely so nobody "improves" them.
TOTP_DIGITS = 6
TOTP_PERIOD_SECONDS = 30

# HOW MUCH CLOCK DRIFT TO FORGIVE.
#
# A phone's clock is not exactly the server's. With no tolerance, a user whose
# phone runs eight seconds fast is rejected while the code on their screen is the
# one they are typing - an unfixable-looking bug that generates support tickets.
#
# valid_window=1 accepts the previous, current and next 30-second step, so up to
# roughly 30 seconds of drift either way, and it also covers the genuinely common
# case of a code typed just as it rolls over.
#
# The cost of widening this is precise and worth understanding: every extra step
# multiplies an attacker's chance of guessing a random 6-digit code. At window=1
# three codes in a million are live at any moment; at window=5 it is eleven. 1 is
# the value RFC 6238 recommends, and the rate limit on the endpoint is what makes
# even that unusable.
TOTP_VALID_WINDOW = 1


# WHY THIS EXISTS
# The shared secret, generated on the server. 32 base32 characters is 160 bits,
# which is what RFC 4226 specifies for HMAC-SHA1 and what authenticator apps
# expect to receive.
#
# BASE32, not hex and not base64, and that is not a style choice: the otpauth://
# URI format requires base32, and it is the alphabet that survives being read off
# a screen and typed by hand - no case sensitivity, no characters that look like
# each other. A user whose camera will not focus on the QR code types this string
# instead, which is why it has to stay human-transcribable.
#
# pyotp uses `secrets` underneath, so this draws on the OS cryptographic source
# and not the Mersenne Twister - the same distinction drawn at new_session_token.
def new_totp_secret() -> str:
    return pyotp.random_base32()


# WHY THIS EXISTS
# Builds the pyotp object with OUR parameters rather than the library defaults.
# The defaults happen to match, and that is exactly the problem: three call sites
# each constructing their own TOTP is three places for one of them to drift.
#
# PYTHON-SPECIFIC: a leading underscore is the convention for "private to this
# module". Python does not enforce it; it is a message to the next reader.
def _totp(secret: str) -> "pyotp.TOTP":
    return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_PERIOD_SECONDS)


# WHY THIS EXISTS
# The string that goes into the QR code. It is a URI in a format Google defined
# and everybody else adopted:
#
#   otpauth://totp/SecuScan:ada@example.com?secret=ABC...&issuer=SecuScan
#
# Both label parts matter to the user rather than to the protocol. `issuer` is
# what the app displays as the account name, and the email in the path is what
# distinguishes two SecuScan accounts on one phone. Omit them and the entry reads
# as an unlabelled six-digit code among eleven others.
#
# NOTE THAT THE SECRET IS IN THIS STRING. That is unavoidable - transferring the
# secret IS what enrolment does - and it is why this URI may only ever be returned
# over an authenticated request, must never be logged, and is shown once.
def totp_provisioning_uri(secret: str, email: str, issuer: str) -> str:
    return _totp(secret).provisioning_uri(name=email, issuer_name=issuer)


# WHY THIS EXISTS
# Renders the provisioning URI as a QR code the browser can display.
#
# WHY A DATA URI RATHER THAN AN IMAGE ENDPOINT: a GET /2fa/qr.png would put the
# secret in a URL, which lands in server logs and browser history, and it would
# need authentication of its own. Embedding the SVG in the JSON response the
# browser already asked for means the image inherits that request's authentication
# and leaves no trace anywhere else.
#
# SVG rather than PNG because it is text - so it embeds in JSON with no base64
# step - and because it stays sharp at any size, which matters for something a
# phone camera has to focus on.
def totp_qr_data_uri(provisioning_uri: str) -> str:
    # PYTHON-SPECIFIC: an in-memory file, so nothing touches disk. Writing a QR code
    # containing a live secret into a temp file would be a small disaster of its own.
    #
    # BytesIO AND NOT StringIO, WHICH IS WHERE THIS FUNCTION USED TO 500. SVG is text,
    # so a text buffer looks like the obvious choice - but segno writes its own UTF-8
    # header and therefore emits BYTES for every output kind, SVG included. Handed a
    # StringIO it raised "string argument expected, got 'bytes'" from deep inside the
    # codecs module, and because the only caller is an endpoint the symptom was a bare
    # 500 on /2fa/setup with nothing in it naming a QR code.
    #
    # [General] The lesson is not about segno: "this format is textual" is a fact about
    # the format, and says nothing about whether a given writer hands you str or bytes.
    buffer = io.BytesIO()

    # scale is the module size. border=2 is the "quiet zone" around the code,
    # which is not decoration - scanners use it to find the code's edges, and a QR
    # image with no margin frequently will not read at all.
    segno.make(provisioning_uri, error="m").save(buffer, kind="svg", scale=4, border=2)

    # Back to text for the data URI. utf-8 is not a guess - it is what segno declares
    # in the XML header it just wrote, and it is what the charset in the URI below
    # promises the browser.
    svg = buffer.getvalue().decode("utf-8")

    # quote() percent-encodes the SVG so it is legal inside a URI. safe="" forces
    # even / and : to be encoded; the default leaves / alone, which works in
    # practice, but relying on that default is how a stray character eventually
    # breaks the image with no error message anywhere.
    return "data:image/svg+xml;charset=utf-8," + quote(svg, safe="")


# WHY THIS EXISTS
# Strips a typed code down to digits. Authenticator apps display "123 456", so
# people type the space; doing this in one place means every caller is equally
# forgiving. This is presentation cleanup, not validation - the length check
# belongs to the caller.
def _clean_code(code: str) -> str:
    # PYTHON-SPECIFIC: \D is "any non-digit". re.sub replaces every match, so this
    # removes spaces, hyphens and anything else that came along.
    return re.sub(r"\D", "", code or "")


# WHY THIS EXISTS
# The check. True when the six digits match the secret for the current time
# window, within the drift tolerance above.
#
# THE COMPARISON IS CONSTANT-TIME, which is pyotp's doing rather than ours - it
# uses hmac.compare_digest internally. That matters for the same reason the login
# timing does: a comparison that returns early at the first wrong digit lets an
# attacker recover a code one digit at a time by measuring response times. It is
# the sort of detail that makes hand-rolling this a bad idea.
def verify_totp(secret: str, code: str) -> bool:
    cleaned = _clean_code(code)

    if len(cleaned) != TOTP_DIGITS:
        return False

    try:
        return _totp(secret).verify(cleaned, valid_window=TOTP_VALID_WINDOW)
    except Exception:
        # A malformed stored secret - not base32, or truncated. Refusing is the
        # only safe answer, exactly as with a corrupt password hash above.
        return False


# ============================================================================
# REPLAY PROTECTION
#
# WHY THIS EXISTS, and it is the part of TOTP most implementations leave out
# A code stays valid for its whole 30-second window - 90 seconds here, once drift
# tolerance is counted. So a code, once used, still works INSIDE that window, and
# anyone who read it over a shoulder or captured it on a phishing page can replay
# it while it is live.
#
# The fix is one rule: a code accepted for an account is never accepted again for
# that account. Storing the last accepted time step is enough, because steps only
# move forward - "this step is not greater than the last one I accepted" catches
# every replay without keeping a list of used codes.
#
# This is RFC 6238 section 5.2, and it is a requirement rather than a refinement.
# ============================================================================


# WHY THIS EXISTS
# Finds which step an accepted code belongs to, so the caller can store it. "The
# current step" is not the answer: with drift tolerance an accepted code may
# belong to the step before or after, and recording the wrong number would either
# fail to block a replay or reject the next legitimate code.
#
# Returns None when nothing matched, which is the same signal as failure - so an
# endpoint can call this alone rather than calling verify_totp() as well.
def matched_totp_step(secret: str, code: str) -> int | None:
    cleaned = _clean_code(code)

    if len(cleaned) != TOTP_DIGITS:
        return None

    try:
        totp = _totp(secret)
    except Exception:
        return None

    now = int(time.time())

    # PYTHON-SPECIFIC: range(-1, 2) yields -1, 0, 1 - the stop value is exclusive.
    # Offsets are tried oldest first, so a code typed a moment before a rollover is
    # attributed to the window it actually came from.
    for offset in range(-TOTP_VALID_WINDOW, TOTP_VALID_WINDOW + 1):
        at_time = now + (offset * TOTP_PERIOD_SECONDS)

        try:
            # `at=` asks pyotp for the code at a specific moment. Comparing against
            # each candidate step is what identifies WHICH step matched, which
            # totp.verify() does not report.
            #
            # PYTHON-SPECIFIC: compare_digest rather than ==, for the constant-time
            # reason given above. It is the same function pyotp uses internally,
            # and using == here would undo that protection on this path.
            if secrets.compare_digest(totp.at(at_time), cleaned):
                # // is FLOOR DIVISION, returning an int. Plain / gives a float,
                # and a float step compared against a stored int is a subtle way to
                # break this check later.
                return at_time // TOTP_PERIOD_SECONDS
        except Exception:
            return None

    return None


# ============================================================================
# RECOVERY CODES
#
# WHY THESE EXIST
# TOTP has one failure mode that has nothing to do with attackers: the phone is
# lost, broken or wiped, and the secret is gone with it. With no second way in,
# the only remaining option is an operator disabling 2FA on request - which is a
# social-engineering target and does not scale past a handful of users.
#
# Recovery codes are that second way: ten single-use passwords, generated at
# enrolment, shown exactly once, and stored HASHED so that a database leak does
# not hand over ten working 2FA bypasses.
#
# WHY THESE GET ARGON2 AND SESSION TOKENS GET SHA-256
# The rule is about entropy, not about what kind of secret it is. A session token
# is 256 random bits, so a fast hash is fine - there is nothing to brute force.
# These are deliberately short enough for a human to write on paper, which puts
# them in the same guessable range as a password, so they get the same slow hash.
# The cost is up to ten Argon2 verifications on a recovery attempt, which is a
# rare event and correctly expensive.
# ============================================================================

RECOVERY_CODE_COUNT = 10

# Base32-ish, and for the same reason as the TOTP secret: these get written down
# and typed back in. The omissions are the characters people actually confuse on
# paper - 0 against O, and 1 against I and L - so none of 0, 1, I, L or O appear.
# U is dropped as well, which is Crockford's convention: it is the one letter whose
# accidental appearance can turn a random code into a word somebody reads twice.
_RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"

# 10 characters from a 30-character alphabet is a little over 49 bits: far past
# guessable, and short enough to write on the back of a card.
_RECOVERY_CODE_LENGTH = 10


# WHY THIS EXISTS
# Makes one code, hyphenated into two groups of five. The hyphen is presentation
# and is stripped before hashing, so a user who leaves it out still gets in.
def new_recovery_code() -> str:
    # PYTHON-SPECIFIC: secrets.choice() rather than random.choice(), for the reason
    # given at new_session_token(). The generator expression is joined in one pass.
    raw = "".join(
        secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_CODE_LENGTH)
    )

    return f"{raw[:5]}-{raw[5:]}"


# WHY THIS EXISTS
# One spelling of a code. Users type lowercase, drop the hyphen, or add spaces -
# none of which should decide whether somebody gets back into their account.
# Normalising in one function shared by generation and verification is what makes
# that true; two copies of this rule is how "the code on my card does not work"
# happens.
def normalise_recovery_code(code: str) -> str:
    # PYTHON-SPECIFIC: a generator inside join, filtering as it goes. isalnum()
    # drops hyphens, spaces and anything else that came along for the ride.
    return "".join(
        character for character in (code or "").upper() if character.isalnum()
    )


# WHY THIS EXISTS
# A full set. Returns the plaintext to show the user ONCE and the hashes to store,
# as two separate values - so no caller can store the plaintext by accident or
# display the hashes by mistake.
#
# PYTHON-SPECIFIC: a tuple return, unpacked at the call site as
# `codes, hashes = new_recovery_codes()`. The rough JS equivalent is returning an
# array and destructuring it.
def new_recovery_codes() -> tuple[list[str], list[str]]:
    codes = [new_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
    hashes = [hash_password(normalise_recovery_code(code)) for code in codes]

    return codes, hashes


# WHY THIS EXISTS
# Checks a typed code against the stored hashes and reports WHICH one matched, by
# index - because the caller's next job is to delete exactly that one. None for no
# match.
#
# EVERY HASH IS CHECKED EVEN ONCE A MATCH IS FOUND. Returning early would let the
# response time reveal the matching code's position in the list. That is a small
# leak, and a free one to close: the loop records the index and keeps going.
def find_recovery_code(stored_hashes: list[str], code: str) -> int | None:
    cleaned = normalise_recovery_code(code)

    if not cleaned:
        return None

    matched: int | None = None

    # PYTHON-SPECIFIC: enumerate() yields (index, value) pairs - the idiomatic way
    # to loop when the position matters, rather than indexing over range(len(...)).
    for index, stored in enumerate(stored_hashes):
        if verify_password(stored, cleaned) and matched is None:
            matched = index

    return matched


# ============================================================================
# EMAIL ONE-TIME CODES (account recovery only)
#
# WHY THESE EXIST, AND WHY THEY ARE NOT THE PRIMARY SECOND FACTOR
# Email OTP is the weaker mechanism and it is placed accordingly. TOTP proves
# possession of a device; an emailed code proves access to an inbox - and an inbox
# is reachable from anywhere, is often protected by a password alone, and is the
# very thing a password reset would go to. Making it the primary second factor
# means the "second" factor collapses back into the first.
#
# So it sits here as the fallback for one specific situation: TOTP is enrolled and
# the authenticator is unavailable. It is rate limited harder than TOTP, expires in
# ten minutes rather than 30 seconds, and is single use.
#
# 6 digits, matching the TOTP length, so the entry field and the keypad on a phone
# are the same for both. Consistency in what a user has to type is worth more here
# than the two extra digits would add, given the expiry and the rate limit are
# what actually bound the guessing.
# ============================================================================

EMAIL_CODE_DIGITS = 6

# Ten minutes. Long enough for mail to be delivered and read on another device,
# short enough that a code sitting in an unattended inbox stops working quickly.
EMAIL_CODE_TTL_MINUTES = 10


# WHY THIS EXISTS
# A random 6-digit code, as a string with leading zeros preserved - "042871" is a
# valid code and must not become 42871.
#
# PYTHON-SPECIFIC: secrets.randbelow(1000000) gives 0..999999 uniformly, and the
# :06d format spec zero-pads to six characters. The tempting one-liner -
# choosing six digits independently - is equivalent here, but randbelow makes the
# uniformity obvious at a glance.
def new_email_code() -> str:
    return f"{secrets.randbelow(10 ** EMAIL_CODE_DIGITS):0{EMAIL_CODE_DIGITS}d}"


# WHY THIS EXISTS
# The moment an email code stops working, computed in one place for the same
# reason session_expiry() is.
def email_code_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=EMAIL_CODE_TTL_MINUTES)


# WHY THIS EXISTS
# Email codes are stored hashed, like everything else that functions as a
# credential. SHA-256 rather than Argon2, and the entropy argument that governs
# that choice elsewhere points the other way here - six digits is only a million
# possibilities, which a fast hash cannot protect.
#
# What protects it instead is the ATTEMPT LIMIT on the endpoint plus the ten-minute
# expiry: three wrong guesses invalidate the code, so an offline attack on the hash
# is irrelevant because there is nothing to attack offline - the hash is only ever
# compared against a code the attacker would have to already hold. Argon2 here
# would add real cost to every verification and close no actual hole.
#
# PYTHON-SPECIFIC: reuses hash_token() above rather than calling hashlib again, so
# there is one SHA-256 call site in the file.
def hash_email_code(code: str) -> str:
    return hash_token(_clean_code(code))


# How many wrong guesses a single emailed code tolerates before it is destroyed.
# Three, because the code is six digits and the window is ten minutes: at three
# attempts per code the chance of guessing one is three in a million, and requesting
# a fresh code is itself rate limited.
EMAIL_CODE_MAX_ATTEMPTS = 3
