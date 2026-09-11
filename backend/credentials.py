"""
CREDENTIALS ENCRYPTION AND STORAGE - secure handling of Tier 2 test account credentials.

WHY THIS FILE EXISTS
Tier 2 checks require authenticated access: a staging URL, username, and password for a
dedicated, disposable test account supplied by the client. These credentials must never
be stored in plaintext, logged, or exposed in scan reports.

This module owns:
  1. Authenticated symmetric encryption at rest (Fernet: AES-128-CBC + HMAC-SHA256)
     under SECUSCAN_CREDENTIALS_KEY.
  2. Packaging encrypted credential blobs for MongoDB persistence with a TTL sweep.
  3. Dropping sensitive fields as early as possible once a check has finished with them.

WHY THERE IS NO DEVELOPMENT FALLBACK KEY
There used to be one: with SECUSCAN_CREDENTIALS_KEY unset, this module derived a key
from a constant seed written a few lines further down, so local runs and unit tests
needed no configuration at all. That is a convenience with an unacceptable failure mode.
A key committed to the repository is a key held by every reader of the repository, so a
deployment that simply never set the variable would encrypt real client passwords under
a published key and report itself healthy while doing it - "encrypted at rest" in the
same sense that a door is locked when the key is taped to it.

The precedent is already set elsewhere in this codebase: a misconfigured Paddle does not
quietly fall back to the mock, because granting paid plans for free is not a degraded
mode. Encrypting client passwords under a public key is not a degraded mode either. So
an unset key fails closed - encrypt_credentials raises, the Tier 2 scan path answers 503
rather than storing anything, and config.startup_warnings() says so at every startup.
"""

import base64
import json
import logging

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import config

_log = logging.getLogger("credentials")


# A passphrase is stretched rather than hashed once. A single SHA-256 of a human-chosen
# passphrase can be searched at billions of guesses per second on commodity hardware; at
# this iteration count the same search costs roughly six orders of magnitude more. The
# salt is a fixed application constant rather than a per-record random value, which is
# weaker than a per-record salt would be - its job is to separate SecuScan's key space
# from other products deriving keys from the same passphrase, not to defeat a targeted
# attacker. The real recommendation is a generated key, and the log line below says so.
_KDF_SALT = b"secuscan.credentials.kdf.v1"
_KDF_ITERATIONS = 600_000

_GENERATE_HINT = (
    "Generate one with: python -c "
    "\"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
)


class CredentialsKeyMissing(RuntimeError):
    """SECUSCAN_CREDENTIALS_KEY is unset, so credentials cannot be encrypted.

    Raised rather than returned. There is nothing a caller could usefully do with a
    False here except refuse the request, and a helper returning a value somebody can
    ignore is an encryption requirement somebody can ignore.
    """


def key_is_configured() -> bool:
    """Whether a credentials key is set, without building or logging anything.

    Used by config.startup_warnings() and by the Tier 2 request path, so that a missing
    key is reported as the configuration problem it is rather than surfacing as a 500.
    """
    return bool(getattr(config, "CREDENTIALS_KEY", "").strip())


def _get_fernet() -> Fernet:
    raw_key = getattr(config, "CREDENTIALS_KEY", "").strip()

    if not raw_key:
        raise CredentialsKeyMissing(
            "SECUSCAN_CREDENTIALS_KEY is not set, so Tier 2 credentials cannot be "
            "encrypted. " + _GENERATE_HINT
        )

    # TWO ACCEPTED SHAPES, CHECKED RATHER THAN CAUGHT.
    # A generated Fernet key is 32 url-safe base64 bytes and is used as it stands.
    # Anything else is treated as a passphrase and stretched into one. The previous
    # version worked out which case it was in by calling Fernet() and catching a bare
    # Exception, which also swallowed genuine faults and made a typo in a real key
    # indistinguishable from a deliberate passphrase - quietly encrypting under a
    # different key than the operator believed they had configured.
    candidate = raw_key.encode("utf-8")

    try:
        decoded = base64.urlsafe_b64decode(candidate)
    except (ValueError, TypeError):
        decoded = b""

    if len(decoded) == 32:
        return Fernet(candidate)

    _log.warning(
        "SECUSCAN_CREDENTIALS_KEY is not a generated Fernet key, so it is being "
        "stretched as a passphrase. A generated key is stronger. %s",
        _GENERATE_HINT,
    )

    derived = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_SALT,
        iterations=_KDF_ITERATIONS,
    ).derive(candidate)

    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_credentials(*, staging_url: str, username: str, password: str) -> str:
    """Encrypt test account credentials into an authenticated Fernet token string.

    Raises CredentialsKeyMissing when no key is configured. Callers must let that
    refuse the request rather than storing anything.
    """
    payload = json.dumps({
        "stagingUrl": staging_url.strip(),
        "username": username.strip(),
        "password": password,
    }).encode("utf-8")

    return _get_fernet().encrypt(payload).decode("utf-8")


def decrypt_credentials(token: str) -> dict:
    """Decrypt a Fernet token into the credentials dictionary.

    Returns a dict with keys 'stagingUrl', 'username' and 'password'.
    Raises ValueError if the token is absent, corrupted, or tampered with.

    Fernet authenticates before it decrypts, so a token whose ciphertext has been edited
    is refused outright rather than yielding altered plaintext. That is the reason this
    module uses Fernet rather than a bare AES mode.
    """
    try:
        decrypted = _get_fernet().decrypt(token.encode("utf-8"))
        return json.loads(decrypted.decode("utf-8"))
    except CredentialsKeyMissing:
        # Not a corrupt token - a missing key. Propagated unchanged so that the caller
        # can tell a configuration fault from a tampering attempt.
        raise
    except (InvalidToken, ValueError, TypeError, AttributeError) as exc:
        # The token is never logged: it is the ciphertext of a live password. The
        # exception TYPE is logged instead, which is all a diagnosis needs.
        _log.warning("Could not decrypt a credentials token: %s", type(exc).__name__)
        raise ValueError("Invalid or corrupted credential token") from exc


# Field names dropped by scrub_credentials. A constant so that a field added to the
# credential shape later is scrubbed by editing one tuple rather than by remembering to.
_SENSITIVE_FIELDS = ("password", "passphrase", "token", "secret")


def scrub_credentials(credentials: dict | None) -> None:
    """Drop the sensitive fields from a credentials dict once a check is done with them.

    WHAT THIS DOES, AND WHAT IT DOES NOT DO.

    It removes the last reference this process holds to the password, so the string
    becomes eligible for garbage collection at that point rather than living as long as
    the request does. That is worth doing, and it is all that this does.

    It does NOT overwrite the bytes in memory. Python strings are immutable, so
    assigning a run of null characters over the field builds a NEW string and rebinds
    the slot: the original is untouched on the heap, and copies of it may also survive
    in the raw request body buffer, in any traceback that captured the frame, and in the
    interpreter's free lists. An earlier version of this function performed exactly that
    assignment and called it zeroization in its docstring.

    This note is long because the gap between those two things is precisely the kind of
    finding SecuScan sells - a control named after a guarantee it does not provide. The
    guarantees that are real here are the encryption at rest and the 24-hour TTL.
    """
    if not isinstance(credentials, dict):
        return

    for field in _SENSITIVE_FIELDS:
        if field in credentials:
            credentials[field] = None
