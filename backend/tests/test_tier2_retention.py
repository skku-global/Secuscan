"""
TESTS FOR TIER 2 CREDENTIAL RETENTION.

Retention is opt-in per scan. The default Tier 2 scan uses the client's test
account password for the length of the run and writes it nowhere; a client who
wants to re-run the audit later can ask for it to be kept for 24 hours. Three
separate claims fall out of that, and each one is a promise printed on the scan
form, so each one is pinned here:

  1. AN EXPIRED CREDENTIAL BLOB IS NEVER READ BACK. Mongo's TTL monitor sweeps
     about once a minute, so "past expiresAt but not yet deleted" is a state this
     collection spends real time in. The read path re-checks. This was the check
     the credentials collection was missing while the other four had it.

  2. A SCAN THAT DID NOT ASK FOR RETENTION STORES NOTHING - and, because there is
     nothing to encrypt, still runs on a server with no credentials key at all.

  3. A SCAN THAT DID ASK, ON A SERVER THAT CANNOT ENCRYPT, IS REFUSED BEFORE THE
     SCAN RUNS. The 503 body says "this scan was not run", and section 4 exists
     because that sentence is worth nothing unless something proves it.

Run from anywhere (the `import _path` line puts backend/ on sys.path):
  python backend/tests/test_tier2_retention.py
"""

import asyncio
import base64
import hashlib
from datetime import datetime, timedelta, timezone

import _path  # noqa: F401 - puts backend/ on sys.path
import config
import credentials
import database
import main

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


# Same construction as test_credentials.py: a real Fernet key, derived so the
# suite needs no generated one, and obviously a test key.
TEST_KEY = base64.urlsafe_b64encode(
    hashlib.sha256(b"secuscan-offline-test-key").digest()
).decode()

USER = {"id": "user-1", "planId": "starter", "email": "client@example.test"}
PASSWORD = "TestAccountPassword!42"
USERNAME = "audit_runner@client.test"


# --- Fakes -----------------------------------------------------------------


class FakeCollection:
    """Just enough of a Motor collection for get_scan_credentials."""

    def __init__(self, document=None):
        self.document = document

    async def find_one(self, query):
        return self.document


class FakeDatabase:
    """Records what main.create_scan asked the database to do.

    Recording rather than asserting inline, because the interesting assertions in
    sections 3 and 4 are about calls that must NOT happen, and a fake that raises
    on an unexpected call can only fail the suite - it cannot report which of the
    two writes was the one that leaked.
    """

    def __init__(self):
        self.saved_scans = []
        self.saved_credentials = []

    async def save_scan(self, scan, user_id):
        self.saved_scans.append((scan, user_id))
        return True

    async def save_scan_credentials(self, *, scan_id, user_id, encrypted_blob, ttl_hours):
        self.saved_credentials.append({
            "scanId": scan_id,
            "userId": user_id,
            "blob": encrypted_blob,
            "ttlHours": ttl_hours,
        })


class ScanRecorder:
    """Stands in for scanning.engine.run_scan and remembers whether it ran."""

    def __init__(self):
        self.calls = []

    async def __call__(self, *, url, login_url, tier, credentials):
        self.calls.append({
            "url": url,
            "tier": tier,
            "credentials": credentials,
        })
        return {"id": "scan-1", "targetUrl": url, "tier": tier, "findings": []}


def make_request(retain):
    """A valid Tier 2 ScanRequest with retention set either way."""
    return main.ScanRequest(
        url="https://client.test",
        consent=True,
        tier=2,
        credentials=main.Tier2Credentials(
            username=USERNAME,
            password=PASSWORD,
            retain=retain,
        ),
    )


def create_scan(request, db, scanner):
    """Run main.create_scan against the fakes, returning (result, exception)."""
    previous_db, previous_run = main.database, main.run_scan
    main.database, main.run_scan = db, scanner
    try:
        return asyncio.run(main.create_scan(request, user=USER)), None
    except main.HTTPException as exc:
        return None, exc
    finally:
        main.database, main.run_scan = previous_db, previous_run


def run_tests():
    saved_key = config.CREDENTIALS_KEY
    saved_resolver = main._resolves_to_public_address

    # The URL validator on ScanRequest does a real DNS lookup, which an offline
    # suite must not do - and which would make this file's results depend on
    # whether the machine running it has a network.
    main._resolves_to_public_address = lambda hostname: True

    try:
        print("\n--- 1. An expired blob is never read back -----------------")
        # THE BUG THIS SECTION EXISTS FOR.
        #
        # database.py carries a note saying every collection storing an expiresAt
        # has to re-check it on read, because the TTL monitor sweeps roughly once
        # a minute and "expired but not yet deleted" must never count as valid.
        # Four collections did. The credentials collection - the one whose
        # documents are live client passwords - did not, so for up to a minute
        # past the deadline a scan could still read credentials whose retention
        # window the client had been told was over.
        saved_get_collection = database._get_collection
        now = datetime.now(timezone.utc)

        def with_document(document):
            database._get_collection = lambda name=None: FakeCollection(document)

        def read():
            return asyncio.run(database.get_scan_credentials("scan-1", "user-1"))

        try:
            with_document({
                "_id": "cred-1", "scanId": "scan-1", "userId": "user-1",
                "encryptedBlob": "token", "expiresAt": now + timedelta(hours=1),
            })
            check("a live blob is returned", (read() or {}).get("encryptedBlob"), "token")

            with_document({
                "_id": "cred-1", "scanId": "scan-1", "userId": "user-1",
                "encryptedBlob": "token", "expiresAt": now - timedelta(seconds=30),
            })
            check("an expired blob reads as absent", read(), None)

            # pymongo hands back NAIVE UTC datetimes by default. Comparing one
            # against an aware datetime raises TypeError rather than returning
            # False, so this is the shape the real driver actually produces and
            # the one most likely to break the check above.
            with_document({
                "_id": "cred-1", "scanId": "scan-1", "userId": "user-1",
                "encryptedBlob": "token",
                "expiresAt": (now - timedelta(seconds=30)).replace(tzinfo=None),
            })
            check("  including a naive UTC datetime from the driver", read(), None)

            with_document({
                "_id": "cred-1", "scanId": "scan-1", "userId": "user-1",
                "encryptedBlob": "token",
            })
            check("a document with no expiresAt is not treated as expired",
                  (read() or {}).get("encryptedBlob"), "token")

            with_document(None)
            check("a missing document reads as absent", read(), None)
        finally:
            database._get_collection = saved_get_collection

        print("\n--- 2. Retention is off unless asked for -------------------")
        # The direction of this default is the whole safety property. A caller
        # that has never heard of the field - an older frontend, a curl call, a
        # future integration - stores nothing rather than silently opting a
        # client's password into a day on disk.
        implicit = main.Tier2Credentials(username=USERNAME, password=PASSWORD)
        check("retain defaults to False", implicit.retain, False)

        explicit = main.Tier2Credentials(username=USERNAME, password=PASSWORD, retain=True)
        check("and is True when asked for", explicit.retain, True)

        print("\n--- 3. No retention means no key needed, and nothing kept --")
        # An unset credentials key used to refuse every Tier 2 scan. That was
        # right when every Tier 2 scan stored its credentials, and is wrong now
        # that the default stores none: the key protects data AT REST, and this
        # request creates none.
        config.CREDENTIALS_KEY = ""
        db, scanner = FakeDatabase(), ScanRecorder()
        result, error = create_scan(make_request(retain=False), db, scanner)

        check("the scan is not refused", error, None)
        check("  and it actually ran", len(scanner.calls), 1)
        check("  with the credentials it needs", scanner.calls[0]["credentials"]["password"], PASSWORD)
        check("the result is stored", len(db.saved_scans), 1)
        check("NOTHING is written to the credentials collection", db.saved_credentials, [])

        print("\n--- 4. Retention with no key refuses BEFORE scanning -------")
        # The 503 body tells the client "this scan was not run". These are the
        # assertions that make that sentence true rather than reassuring.
        db, scanner = FakeDatabase(), ScanRecorder()
        result, error = create_scan(make_request(retain=True), db, scanner)

        check("the request is refused", getattr(error, "status_code", None), 503)
        check("run_scan was never called", scanner.calls, [])
        check("no scan was stored", db.saved_scans, [])
        check("no credentials were stored", db.saved_credentials, [])

        # The client is not told which environment variable is missing. An
        # unauthenticated caller learning a deployment's configuration gaps is a
        # gift to somebody mapping it.
        detail = getattr(error, "detail", "")
        check("the variable is not named to the client",
              "SECUSCAN_CREDENTIALS_KEY" in detail, False)
        check("  but the client is told what to do instead",
              "keep the credentials" in detail, True)

        print("\n--- 5. Retention with a key stores ciphertext --------------")
        config.CREDENTIALS_KEY = TEST_KEY
        db, scanner = FakeDatabase(), ScanRecorder()
        result, error = create_scan(make_request(retain=True), db, scanner)

        check("the scan runs", error, None)
        check("credentials are stored once", len(db.saved_credentials), 1)

        record = db.saved_credentials[0]
        check("scoped to the scan", record["scanId"], "scan-1")
        check("scoped to the user", record["userId"], USER["id"])
        check("with the 24 hour window", record["ttlHours"], 24)

        # The point of the storage layer, asserted against the stored value
        # rather than against the function that produced it.
        check("the password is not in the stored blob", PASSWORD in record["blob"], False)
        check("the username is not either", USERNAME in record["blob"], False)
        check("and it decrypts back to what the client submitted",
              credentials.decrypt_credentials(record["blob"])["password"], PASSWORD)

        # The staging URL defaults to the target when the client leaves it blank,
        # so a Tier 2 check reading the blob has a URL to work with either way.
        check("the staging url falls back to the target",
              credentials.decrypt_credentials(record["blob"])["stagingUrl"],
              "https://client.test")

    finally:
        config.CREDENTIALS_KEY = saved_key
        main._resolves_to_public_address = saved_resolver

    print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()
