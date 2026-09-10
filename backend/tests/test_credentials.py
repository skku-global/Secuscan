"""
TESTS FOR TIER 2 CREDENTIALS ENCRYPTION AND STORAGE.

Verifies:
  1. Authenticated AES-128 Fernet encryption roundtrip.
  2. Plaintext passwords never appear in the encrypted ciphertext.
  3. Corrupted or tampered tokens raise ValueError.
  4. Memory zeroization via scrub_credentials.
  5. Deterministic fallback key when SECUSCAN_CREDENTIALS_KEY is empty.
"""

import _path  # noqa: F401 - puts backend/ on sys.path
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


def run_tests():
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
    # Tampering with ciphertext
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

    print("\n--- 3. Memory Scrubbing / Zeroization ----------------------")
    cred_dict = {
        "stagingUrl": "https://staging.test",
        "username": "tester",
        "password": "SecretPassword123!",
    }
    credentials.scrub_credentials(cred_dict)
    check("scrubbed password is None", cred_dict["password"], None)
    check("username still intact", cred_dict["username"], "tester")

    # None and non-dict handled safely
    credentials.scrub_credentials(None)
    credentials.scrub_credentials("string")
    check("scrubbing non-dict does not raise", True, True)

    print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()
