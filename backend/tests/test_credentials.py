"""
TESTS FOR TIER 2 CREDENTIALS ENCRYPTION AND STORAGE.

Verifies:
  1. Authenticated Fernet encryption round trip, and that neither half of the
     credential pair appears in the ciphertext.
  2. Corrupted or tampered tokens raise ValueError rather than yielding altered
     plaintext.
  3. scrub_credentials drops every sensitive field and leaves the rest alone.
  4. THAT AN UNSET SECUSCAN_CREDENTIALS_KEY FAILS CLOSED. This is the one that
     matters: the module used to derive a key from a constant seed in its own source
     when the variable was missing, so an unconfigured deployment encrypted real
     client passwords under a key published in the repository and looked healthy
     doing it.
  5. A passphrase is accepted, but stretched rather than hashed once.

Run from anywhere (the `import _path` line puts backend/ on sys.path):
  python backend/tests/test_credentials.py
"""

import base64
import hashlib

import _path  # noqa: F401 - puts backend/ on sys.path
import config
import credentials

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


# A real Fernet key - 32 url-safe base64 bytes - derived deterministically so the suite
# does not depend on a generated one, and obviously a test key so it can never be
# mistaken for something that should have been kept.
#
# IT IS SET EXPLICITLY, and that is the point of this line. There is no longer any
# fallback for the suite to lean on: a test file that ran without configuring a key
# would be exercising a code path that must not exist.
TEST_KEY = base64.urlsafe_b64encode(
    hashlib.sha256(b"secuscan-offline-test-key").digest()
).decode()


def run_tests():
    saved_key = config.CREDENTIALS_KEY
    config.CREDENTIALS_KEY = TEST_KEY

    print("\n--- 1. Encryption and Decryption Roundtrip -----------------")
    test_staging = "https://staging.client.test"
    test_user = "audit_runner@client.test"
    test_pass = "P@ssw0rd!SuperSecret99"

    token = credentials.encrypt_credentials(
        staging_url=test_staging,
        username=test_user,
        password=test_pass,
    )

    check("encrypt produces non-empty string", bool(token), True)
    check("plaintext password not in token", test_pass in token, False)
    check("plaintext username not in token", test_user in token, False)

    decrypted = credentials.decrypt_credentials(token)
    check("decrypted stagingUrl", decrypted.get("stagingUrl"), test_staging)
    check("decrypted username", decrypted.get("username"), test_user)
    check("decrypted password", decrypted.get("password"), test_pass)

    print("\n--- 2. Tampered / Corrupted Token Handling -----------------")
    # Fernet authenticates before it decrypts, so an edited ciphertext is refused
    # outright rather than producing altered plaintext. That property is the reason
    # this module uses Fernet and not a bare AES mode, so it is pinned here.
    tampered = token[:-4] + "AAAA"
    tamper_failed = False
    try:
        credentials.decrypt_credentials(tampered)
    except ValueError:
        tamper_failed = True
    check("tampered token rejected with ValueError", tamper_failed, True)

    # Completely invalid string
    garbage_failed = False
    try:
        credentials.decrypt_credentials("not-a-fernet-token")
    except ValueError:
        garbage_failed = True
    check("garbage token rejected with ValueError", garbage_failed, True)

    print("\n--- 3. Sensitive fields are dropped ------------------------")
    # NOT called zeroization, and the docstring on scrub_credentials explains at
    # length why. Python strings are immutable; this drops the last reference so the
    # string can be collected, and it does not overwrite the bytes. The test is named
    # after what the code does.
    cred_dict = {
        "stagingUrl": "https://staging.test",
        "username": "tester",
        "password": "SecretPassword123!",
        "token": "abc123",
    }
    credentials.scrub_credentials(cred_dict)
    check("password is dropped", cred_dict["password"], None)
    check("token is dropped too", cred_dict["token"], None)
    check("username still intact", cred_dict["username"], "tester")
    check("stagingUrl still intact", cred_dict["stagingUrl"], "https://staging.test")

    # None and non-dict inputs are ignored rather than raising. The previous version
    # of this assertion was check(label, True, True), which passes whatever the code
    # does - the call above it would have to raise for the tally to notice, and a
    # raise would abort the suite before the check line ever ran. So the outcome is
    # captured in a variable instead.
    non_dict_ok = True
    try:
        credentials.scrub_credentials(None)
        credentials.scrub_credentials("string")
        credentials.scrub_credentials(42)
    except Exception:
        non_dict_ok = False
    check("scrubbing a non-dict does not raise", non_dict_ok, True)

    print("\n--- 4. An unset key fails closed ---------------------------")
    # THE SECTION THIS FILE EXISTS FOR.
    #
    # This module used to derive a key from a constant seed in its own source when
    # SECUSCAN_CREDENTIALS_KEY was missing. A deployment that never set the variable
    # therefore encrypted live client passwords under a key that every reader of the
    # repository holds, reported no error, and satisfied a docstring promising that
    # credentials are never stored in plaintext.
    #
    # The rule matches the one the payments package already follows: a misconfigured
    # processor does not fall back to the mock, because granting paid plans for free
    # is not a degraded mode. Encrypting under a published key is not one either.
    config.CREDENTIALS_KEY = ""

    check("key_is_configured is honest about it", credentials.key_is_configured(), False)

    refused = None
    try:
        credentials.encrypt_credentials(
            staging_url="https://staging.test",
            username="tester",
            password="SecretPassword123!",
        )
        refused = "(no exception)"
    except credentials.CredentialsKeyMissing:
        refused = "CredentialsKeyMissing"

    check("encrypting with no key raises", refused, "CredentialsKeyMissing")
    check("  and it is not a ValueError, which callers treat as a bad token",
          issubclass(credentials.CredentialsKeyMissing, ValueError), False)

    # Decryption distinguishes the two failures as well: a missing key is a
    # configuration fault and must not be reported as a corrupt token, or an operator
    # will go looking for tampering that never happened.
    decrypt_refused = None
    try:
        credentials.decrypt_credentials(token)
        decrypt_refused = "(no exception)"
    except credentials.CredentialsKeyMissing:
        decrypt_refused = "CredentialsKeyMissing"
    except ValueError:
        decrypt_refused = "ValueError"

    check("decrypting with no key says the key is missing",
          decrypt_refused, "CredentialsKeyMissing")

    # And the operator is told at startup, rather than finding out when a paying
    # customer's Tier 2 scan is refused.
    warning_text = " ".join(config.startup_warnings())
    check("startup names the missing variable",
          "SECUSCAN_CREDENTIALS_KEY" in warning_text, True)

    print("\n--- 5. A passphrase is accepted, but stretched -------------")
    # A key that is not 32 base64 bytes is treated as a passphrase and run through
    # PBKDF2 rather than a single SHA-256. It still has to round trip, and it must
    # NOT produce the same key as the raw-Fernet path.
    config.CREDENTIALS_KEY = "correct horse battery staple"

    passphrase_token = credentials.encrypt_credentials(
        staging_url=test_staging,
        username=test_user,
        password=test_pass,
    )
    check("a passphrase round trips",
          credentials.decrypt_credentials(passphrase_token).get("password"), test_pass)

    # A token written under the passphrase must be unreadable under the test key.
    config.CREDENTIALS_KEY = TEST_KEY
    crossed = None
    try:
        credentials.decrypt_credentials(passphrase_token)
        crossed = "(decrypted)"
    except ValueError:
        crossed = "refused"
    check("and its tokens do not open under a different key", crossed, "refused")

    config.CREDENTIALS_KEY = saved_key

    print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()
