"""Dedicated unit and integration tests for Account Deletion & Data Export.

Verifies that:
1. GET /auth/export produces a sanitized, complete export of account details,
   order history, and scan findings without leaking password hashes, TOTP secrets,
   or test account credentials.
2. DELETE /auth/account enforces step-up authentication (password check for
   password accounts, explicit confirm=True for OAuth accounts).
3. Database functions delete_user_account_data and export_user_account_data
   perform the required deletions and anonymizations.
"""

import asyncio
import json
from datetime import datetime, timezone

import _path  # noqa: F401  - puts backend/ on sys.path

import auth
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
    mark = "ok  " if ok else "FAIL"
    detail = "" if ok else f"   (got {got!r}, wanted {want!r})"
    print(f"  {mark} {label}{detail}")


# =========================================================================
print("\n--- 1. Database export_user_account_data -------------------")
# =========================================================================

class MockCursor:
    def __init__(self, docs):
        self.docs = list(docs)
        self.idx = 0

    def sort(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.idx >= len(self.docs):
            raise StopAsyncIteration
        doc = self.docs[self.idx]
        self.idx += 1
        return doc



class MockDatabase:
    def __init__(self):
        self.users = {}
        self.sessions = []
        self.scans = []
        self.credentials = []
        self.orders = []

    def get_collection(self, name=database.COLLECTION_NAME):
        db = self
        class Coll:
            async def find_one(self, query):
                uid = query.get("_id") or query.get("userId")
                return db.users.get(uid)

            def find(self, query, projection=None):
                uid = query.get("userId")
                if name == database.COLLECTION_NAME:
                    matching = [d for d in db.scans if d.get("userId") == uid]
                elif name == database.ORDERS_COLLECTION:
                    matching = [d for d in db.orders if d.get("userId") == uid]
                else:
                    matching = []
                return MockCursor(matching)

            def sort(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            async def delete_one(self, query):
                uid = query.get("_id")
                had = uid in db.users
                db.users.pop(uid, None)
                class Result:
                    deleted_count = 1 if had else 0
                return Result()

            async def delete_many(self, query):
                uid = query.get("userId")
                if name == database.SESSIONS_COLLECTION:
                    before = len(db.sessions)
                    db.sessions = [s for s in db.sessions if s.get("userId") != uid]
                    count = before - len(db.sessions)
                elif name == database.COLLECTION_NAME:
                    before = len(db.scans)
                    db.scans = [s for s in db.scans if s.get("userId") != uid]
                    count = before - len(db.scans)
                elif name == database.CREDENTIALS_COLLECTION:
                    before = len(db.credentials)
                    db.credentials = [c for c in db.credentials if c.get("userId") != uid]
                    count = before - len(db.credentials)
                else:
                    count = 0
                class Result:
                    deleted_count = count
                return Result()

            async def update_many(self, query, update):
                uid = query.get("userId")
                count = 0
                for o in db.orders:
                    if o.get("userId") == uid:
                        o.update(update.get("$set", {}))
                        count += 1
                class Result:
                    modified_count = count
                return Result()

        return Coll()


test_db = MockDatabase()
test_user = {
    "_id": "user-export-1",
    "email": "jane@example.com",
    "name": "Jane Doe",
    "createdAt": datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc),
    "passwordHash": auth.hash_password("SecretPassword42!"),
    "totpSecret": "JBSWY3DPEHPK3PXP",
    "totpConfirmedAt": datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc),
    "planId": "starter",
    "subscription": {
        "status": "active",
        "currentPeriodEnd": datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc),
    },
}
test_db.users["user-export-1"] = test_user
test_db.orders.append({
    "_id": "ord_1",
    "userId": "user-export-1",
    "planId": "starter",
    "amountCents": 4900,
    "currency": "USD",
    "status": "paid",
    "createdAt": datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc),
})
test_db.scans.append({
    "_id": "scan_1",
    "id": "scan_1",
    "userId": "user-export-1",
    "targetUrl": "https://example.com",
    "scannedAt": "2026-09-02T10:00:00+00:00",
    "tier": 1,
    "score": 95,
    "findings": [],
})

saved_get_coll = database._get_collection
database._get_collection = test_db.get_collection

try:
    export_data = asyncio.run(database.export_user_account_data("user-export-1"))
    check("export_data is returned", export_data is not None, True)
    check("export_data version is 1.0", export_data.get("version"), "1.0")

    account = export_data.get("account", {})
    check("account email is present", account.get("email"), "jane@example.com")
    check("account name is present", account.get("name"), "Jane Doe")
    check("account twoFactorEnabled is True", account.get("twoFactorEnabled"), True)
    check("account authProvider is email", account.get("authProvider"), "email")

    # Sensitive fields must NEVER be present
    check("passwordHash is NOT in export", "passwordHash" in account, False)
    check("totpSecret is NOT in export", "totpSecret" in account, False)
    check("totpPendingSecret is NOT in export", "totpPendingSecret" in account, False)
    check("recoveryCodeHashes is NOT in export", "recoveryCodeHashes" in account, False)

    orders = export_data.get("orders", [])
    check("orders count is 1", len(orders), 1)
    check("order amountCents is 4900", orders[0].get("amountCents"), 4900)

    scans = export_data.get("scans", [])
    check("scans count is 1", len(scans), 1)
    check("scan targetUrl is https://example.com", scans[0].get("targetUrl"), "https://example.com")
finally:
    database._get_collection = saved_get_coll


# =========================================================================
print("\n--- 2. Database delete_user_account_data -------------------")
# =========================================================================

test_db2 = MockDatabase()
test_db2.users["user-del-1"] = {"_id": "user-del-1", "email": "del@example.com"}
test_db2.sessions.append({"userId": "user-del-1", "tokenHash": "th1"})
test_db2.sessions.append({"userId": "user-del-1", "tokenHash": "th2"})
test_db2.scans.append({"_id": "s1", "userId": "user-del-1"})
test_db2.credentials.append({"_id": "c1", "userId": "user-del-1"})
test_db2.orders.append({"_id": "o1", "userId": "user-del-1", "amountCents": 14900})

database._get_collection = test_db2.get_collection

try:
    del_result = asyncio.run(database.delete_user_account_data("user-del-1"))
    check("userDeleted is True", del_result.get("userDeleted"), True)
    check("sessionsDeleted is 2", del_result.get("sessionsDeleted"), 2)
    check("scansDeleted is 1", del_result.get("scansDeleted"), 1)
    check("credentialsDeleted is 1", del_result.get("credentialsDeleted"), 1)

    check("User is no longer in users collection", "user-del-1" in test_db2.users, False)
    check("Sessions are wiped", len(test_db2.sessions), 0)
    check("Scans are wiped", len(test_db2.scans), 0)
    check("Credentials are wiped", len(test_db2.credentials), 0)
    check("Orders are anonymized with userDeleted=True", test_db2.orders[0].get("userDeleted"), True)
finally:
    database._get_collection = saved_get_coll


# =========================================================================
print("\n--- 3. main.py GET /auth/export endpoint -------------------")
# =========================================================================

class FakeDBForEndpoints:
    def __init__(self, export_payload=None):
        self.export_payload = export_payload
        self.deleted_user_id = None

    async def export_user_account_data(self, user_id):
        if self.export_payload and user_id == self.export_payload["account"]["id"]:
            return self.export_payload
        return None

    async def delete_user_account_data(self, user_id):
        self.deleted_user_id = user_id
        return {"userDeleted": True, "sessionsDeleted": 1, "scansDeleted": 2}


fake_db = FakeDBForEndpoints(export_payload={
    "exportedAt": "2026-09-16T00:00:00+00:00",
    "version": "1.0",
    "account": {
        "id": "u-test-ep",
        "email": "test@example.com",
    },
    "orders": [],
    "scans": [],
})

saved_main_db = main.database
main.database = fake_db

user_auth = {"id": "u-test-ep", "email": "test@example.com"}

try:
    response = asyncio.run(main.export_account(user=user_auth))
    check("Response status is 200", response.status_code, 200)
    check("media_type is application/json", response.media_type, "application/json")
    check(
        "Content-Disposition attachment header is set",
        response.headers.get("content-disposition"),
        'attachment; filename="secuscan-account-data.json"',
    )
    body = json.loads(response.body.decode())
    check("Export body contains version 1.0", body.get("version"), "1.0")
    check("Export body contains account id", body.get("account", {}).get("id"), "u-test-ep")
finally:
    main.database = saved_main_db


# =========================================================================
print("\n--- 4. main.py DELETE /auth/account endpoint ---------------")
# =========================================================================

main.database = fake_db

user_pw = {
    "id": "u-test-pw",
    "email": "pw@example.com",
    "passwordHash": auth.hash_password("CorrectHorseBattery99!"),
}

user_google = {
    "id": "u-test-google",
    "email": "google@example.com",
    "googleId": "goog-123456",
    # No passwordHash
}

try:
    # 1. Reject when confirm is False
    err = None
    try:
        req = main.DeleteAccountRequest(confirm=False)
        asyncio.run(main.delete_account(req, user=user_pw))
    except main.HTTPException as exc:
        err = exc
    check("Reject with 400 when confirm is False", err.status_code if err else None, 400)

    # 2. Reject password user when password missing
    err = None
    try:
        req = main.DeleteAccountRequest(confirm=True, password=None)
        asyncio.run(main.delete_account(req, user=user_pw))
    except main.HTTPException as exc:
        err = exc
    check("Reject with 400 when password missing on password account", err.status_code if err else None, 400)

    # 3. Reject password user when password incorrect
    err = None
    try:
        req = main.DeleteAccountRequest(confirm=True, password="WrongPassword123!")
        asyncio.run(main.delete_account(req, user=user_pw))
    except main.HTTPException as exc:
        err = exc
    check("Reject with 401 when password incorrect", err.status_code if err else None, 401)
    check("Error detail states password was incorrect", err.detail if err else "", "Your password was incorrect.")

    # 4. Allow password user with correct password
    fake_db.deleted_user_id = None
    req = main.DeleteAccountRequest(confirm=True, password="CorrectHorseBattery99!")
    res = asyncio.run(main.delete_account(req, user=user_pw))
    check("Delete succeeds with correct password", res.get("deleted"), True)
    check("Database delete_user_account_data was invoked for user", fake_db.deleted_user_id, "u-test-pw")

    # 5. Allow Google-only user with confirm=True without password
    fake_db.deleted_user_id = None
    req = main.DeleteAccountRequest(confirm=True)
    res_goog = asyncio.run(main.delete_account(req, user=user_google))
    check("Delete succeeds for Google user with confirm=True", res_goog.get("deleted"), True)
    check("Database delete_user_account_data was invoked for Google user", fake_db.deleted_user_id, "u-test-google")

finally:
    main.database = saved_main_db


# Summary
print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
raise SystemExit(1 if FAIL_COUNT else 0)
