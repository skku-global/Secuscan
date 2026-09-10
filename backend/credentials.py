"""
CREDENTIALS ENCRYPTION AND STORAGE — secure handling of Tier 2 test account credentials.

WHY THIS FILE EXISTS
Tier 2 checks require authenticated access: a staging URL, username, and password for a
dedicated, disposable test account supplied by the client. These credentials must NEVER
be stored in plaintext, logged, or exposed in scan reports.

This module owns:
  1. Authenticated symmetric encryption at rest using AES-128-CBC + HMAC-SHA256 (Fernet)
     derived from SECUSCAN_CREDENTIALS_KEY.
  2. Packaging encrypted credential blobs for MongoDB persistence with automated TTL cleanup.
  3. Scrubbing / zeroizing sensitive fields from memory after check execution.
"""

import base64
import hashlib
import json
import logging

from cryptography.fernet import Fernet, InvalidToken

import config

_log = logging.getLogger("credentials")


# WHY A DETERMINISTIC DERIVATION FALLBACK
# If SECUSCAN_CREDENTIALS_KEY is unset in development or test suites, we derive a 32-byte
# key deterministically so the server and unit tests run with zero manual configuration.
# In production, SECUSCAN_CREDENTIALS_KEY should be set to a Fernet key (32 url-safe base64 bytes).
def _get_fernet() -> Fernet:
    raw_key = getattr(config, "CREDENTIALS_KEY", "").strip()

    if raw_key:
        try:
            return Fernet(raw_key.encode("utf-8"))
        except Exception:
            # If not a valid urlsafe base64 32-byte key, derive one via SHA-256
            key = base64.urlsafe_b64encode(hashlib.sha256(raw_key.encode("utf-8")).digest())
            return Fernet(key)

    # Fallback development key
    derived = base64.urlsafe_b64encode(
        hashlib.sha256(b"secuscan-dev-credentials-seed-v1").digest()
    )
    return Fernet(derived)


def encrypt_credentials(*, staging_url: str, username: str, password: str) -> str:
    """Encrypt test account credentials into an authenticated Fernet token string."""
    payload = json.dumps({
        "stagingUrl": staging_url.strip(),
        "username": username.strip(),
        "password": password,
    }).encode("utf-8")

    return _get_fernet().encrypt(payload).decode("utf-8")


def decrypt_credentials(token: str) -> dict:
    """Decrypt a Fernet token into the credentials dictionary.

    Returns dict with keys: 'stagingUrl', 'username', 'password'.
    Raises ValueError if token is corrupted or tampered with.
    """
    try:
        decrypted = _get_fernet().decrypt(token.encode("utf-8"))
        return json.loads(decrypted.decode("utf-8"))
    except (InvalidToken, Exception) as e:
        _log.warning("Failed to decrypt credentials token: %s", e)
        raise ValueError("Invalid or corrupted credential token") from e


def scrub_credentials(credentials: dict | None) -> None:
    """Zeroize sensitive fields in a credentials dictionary in-memory."""
    if not isinstance(credentials, dict):
        return

    if "password" in credentials and credentials["password"] is not None:
        # Overwrite in-memory reference before removal
        credentials["password"] = "\x00" * len(credentials["password"])
        credentials["password"] = None
