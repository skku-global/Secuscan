"""Dedicated tests for plan limit enforcement (scanLimit and siteLimit).

Verifies that:
1. billing.get_billing_period_start computes accurate 30-day windows for Free
   and active paid subscriptions.
2. database.count_user_scans and database.get_user_distinct_sites extract
   period-scoped scan and site counts.
3. main.create_scan enforces scanLimit and siteLimit per plan, refusing requests
   before running the engine or storing anything.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import _path  # noqa: F401  - puts backend/ on sys.path

import billing
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
print("\n--- 1. Billing period start calculation --------------------")
# =========================================================================

NOW = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

# Free account: rolling 30-day window
free_user = {"id": "u-free", "planId": "free"}
start = billing.get_billing_period_start(free_user, now=NOW)
check("Free account period start is 30 days before now", start, NOW - timedelta(days=30))

# Active paid account: 30 days before currentPeriodEnd
ends_future = datetime(2026, 9, 25, 0, 0, 0, tzinfo=timezone.utc)
starter_user = {
    "id": "u-starter",
    "planId": "starter",
    "subscription": {
        "status": "active",
        "currentPeriodEnd": ends_future,
    },
}
start_starter = billing.get_billing_period_start(starter_user, now=NOW)
check(
    "Active subscription period start is 30 days before currentPeriodEnd",
    start_starter,
    ends_future - timedelta(days=30),
)

# Active paid account with ISO string currentPeriodEnd
starter_user_iso = {
    "id": "u-starter-iso",
    "planId": "starter",
    "subscription": {
        "status": "active",
        "currentPeriodEnd": ends_future.isoformat(),
    },
}
start_iso = billing.get_billing_period_start(starter_user_iso, now=NOW)
check(
    "ISO string currentPeriodEnd parses and gives same period start",
    start_iso,
    ends_future - timedelta(days=30),
)

# Lapsed paid account: currentPeriodEnd in the past falls back to rolling 30 days
lapsed_user = {
    "id": "u-lapsed",
    "planId": "starter",
    "subscription": {
        "status": "active",
        "currentPeriodEnd": datetime(2026, 9, 10, 0, 0, 0, tzinfo=timezone.utc),
    },
}
start_lapsed = billing.get_billing_period_start(lapsed_user, now=NOW)
check(
    "Lapsed subscription falls back to rolling 30 days from now",
    start_lapsed,
    NOW - timedelta(days=30),
)


# =========================================================================
print("\n--- 2. Database count_user_scans & get_user_distinct_sites ---")
# =========================================================================

class MockCursor:
    def __init__(self, docs):
        self.docs = list(docs)
        self.idx = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.idx >= len(self.docs):
            raise StopAsyncIteration
        doc = self.docs[self.idx]
        self.idx += 1
        return doc


class MockScansCollection:
    def __init__(self, docs):
        self.docs = docs

    async def count_documents(self, query):
        user_id = query.get("userId")
        since = query.get("scannedAt", {}).get("$gte")
        count = 0
        for doc in self.docs:
            if doc.get("userId") != user_id:
                continue
            if since and doc.get("scannedAt", "") < since:
                continue
            count += 1
        return count

    def find(self, query, projection=None):
        user_id = query.get("userId")
        since = query.get("scannedAt", {}).get("$gte")
        matching = []
        for doc in self.docs:
            if doc.get("userId") != user_id:
                continue
            if since and doc.get("scannedAt", "") < since:
                continue
            matching.append(doc)
        return MockCursor(matching)


# Populate mock scans
test_docs = [
    {
        "_id": "s1",
        "userId": "u1",
        "targetUrl": "https://example.com/app",
        "targetHost": "example.com",
        "scannedAt": "2026-09-10T10:00:00+00:00",
    },
    {
        "_id": "s2",
        "userId": "u1",
        "targetUrl": "https://EXAMPLE.com/login",
        "targetHost": "example.com",
        "scannedAt": "2026-09-12T10:00:00+00:00",
    },
    {
        "_id": "s3",
        "userId": "u1",
        "targetUrl": "https://api.example.com/health",
        # Backward compatibility: older scan without targetHost
        "scannedAt": "2026-09-14T10:00:00+00:00",
    },
    {
        "_id": "s4",
        "userId": "u1",
        "targetUrl": "https://old.com",
        "targetHost": "old.com",
        "scannedAt": "2026-08-01T10:00:00+00:00",  # older than 30 days
    },
    {
        "_id": "s5",
        "userId": "u2",
        "targetUrl": "https://other-user.com",
        "targetHost": "other-user.com",
        "scannedAt": "2026-09-14T10:00:00+00:00",
    },
]

mock_coll = MockScansCollection(test_docs)
saved_get_coll = database._get_collection
database._get_collection = lambda name=database.COLLECTION_NAME: mock_coll

try:
    # All scans for u1
    total_u1 = asyncio.run(database.count_user_scans("u1"))
    check("count_user_scans returns total scans for user", total_u1, 4)

    # Scans for u1 since 2026-09-01
    recent_u1 = asyncio.run(
        database.count_user_scans("u1", since=datetime(2026, 9, 1, tzinfo=timezone.utc))
    )
    check("count_user_scans filters by cutoff date", recent_u1, 3)

    # Scans for u2
    total_u2 = asyncio.run(database.count_user_scans("u2"))
    check("count_user_scans scopes strictly to userId", total_u2, 1)

    # Distinct sites for u1 since 2026-09-01
    sites_u1 = asyncio.run(
        database.get_user_distinct_sites(
            "u1", since=datetime(2026, 9, 1, tzinfo=timezone.utc)
        )
    )
    check(
        "get_user_distinct_sites normalizes and deduplicates hostnames",
        sites_u1,
        ["api.example.com", "example.com"],
    )
finally:
    database._get_collection = saved_get_coll


# =========================================================================
print("\n--- 3. main.create_scan limit enforcement ------------------")
# =========================================================================

class FakeDBForScan:
    def __init__(self, scans=0, sites=None):
        self.scans = scans
        self.sites = list(sites or [])
        self.saved = []

    async def count_user_scans(self, user_id, since=None):
        return self.scans

    async def get_user_distinct_sites(self, user_id, since=None):
        return list(self.sites)

    async def save_scan(self, scan, user_id):
        self.saved.append((scan, user_id))
        return True


class FakeRunner:
    def __init__(self):
        self.calls = 0

    async def __call__(self, *, url, login_url, tier, credentials):
        self.calls += 1
        return {"id": "scan-1234", "targetUrl": url, "tier": tier, "findings": []}


# Stub DNS resolver for offline testing so test hostnames pass Pydantic validation
saved_resolver = main._resolves_to_public_address
main._resolves_to_public_address = lambda hostname: True

def make_request(url="https://myapp.com", tier=1):
    return main.ScanRequest(url=url, consent=True, tier=tier)



# --- Test Free Plan Limits (scanLimit=1, siteLimit=1) ---
fake_db = FakeDBForScan(scans=0, sites=[])
fake_runner = FakeRunner()
main.database = fake_db
main.run_scan = fake_runner

user_free = {"id": "user-free-1", "planId": "free"}

# 1. Free user 1st scan allowed
res = asyncio.run(main.create_scan(make_request("https://myapp.com"), user=user_free))
check("Free user 1st scan succeeds", res["id"], "scan-1234")
check("Engine was called for allowed scan", fake_runner.calls, 1)

# 2. Free user 2nd scan blocked (scanLimit=1 reached)
fake_db.scans = 1
fake_db.sites = ["myapp.com"]
fake_runner.calls = 0
error = None
try:
    asyncio.run(main.create_scan(make_request("https://myapp.com"), user=user_free))
except main.HTTPException as exc:
    error = exc

check("Free user 2nd scan refused with 403", error.status_code if error else None, 403)
check(
    "Scan limit message names the limit",
    "Scan limit reached for this billing period (1 scan)" in (error.detail if error else ""),
    True,
)
check("Engine was NOT called when scan limit reached", fake_runner.calls, 0)

# 3. Free user site limit enforcement (siteLimit=1)
# Suppose scans=0 (e.g. new month) but site already used
fake_db.scans = 0
fake_db.sites = ["existing.com"]
error = None
try:
    asyncio.run(main.create_scan(make_request("https://newsite.com"), user=user_free))
except main.HTTPException as exc:
    error = exc

check("Free user scanning 2nd site refused with 403", error.status_code if error else None, 403)
check(
    "Site limit message names the limit",
    "Site limit reached for this billing period (1 target site)" in (error.detail if error else ""),
    True,
)
check("Engine was NOT called when site limit reached", fake_runner.calls, 0)

# 4. Scanning the SAME site does not consume a new site slot
fake_db.scans = 0
fake_db.sites = ["existing.com"]
fake_runner.calls = 0
res = asyncio.run(main.create_scan(make_request("https://existing.com/page"), user=user_free))
check("Re-scanning existing site is allowed", res["id"], "scan-1234")
check("Engine was called when re-scanning same site", fake_runner.calls, 1)


# --- Test Starter Plan Limits (scanLimit=10, siteLimit=1) ---
user_starter = {
    "id": "user-starter-1",
    "planId": "starter",
    "subscription": {
        "status": "active",
        "currentPeriodEnd": datetime.now(timezone.utc) + timedelta(days=20),
    },
}

fake_db.scans = 9
fake_db.sites = ["starter-site.com"]
fake_runner.calls = 0
res = asyncio.run(main.create_scan(make_request("https://starter-site.com"), user=user_starter))
check("Starter user 10th scan succeeds", res["id"], "scan-1234")

fake_db.scans = 10
fake_runner.calls = 0
error = None
try:
    asyncio.run(main.create_scan(make_request("https://starter-site.com"), user=user_starter))
except main.HTTPException as exc:
    error = exc

check("Starter user 11th scan refused with 403", error.status_code if error else None, 403)
check(
    "Scan limit message names 10 scans",
    "Scan limit reached for this billing period (10 scans)" in (error.detail if error else ""),
    True,
)
check("Engine was NOT called on 11th scan", fake_runner.calls, 0)


# --- Test Business Plan Limits (scanLimit=None, siteLimit=10) ---
user_business = {
    "id": "user-biz-1",
    "planId": "business",
    "subscription": {
        "status": "active",
        "currentPeriodEnd": datetime.now(timezone.utc) + timedelta(days=20),
    },
}

# 100 scans on 5 sites -> allowed
fake_db.scans = 100
fake_db.sites = [f"site{i}.com" for i in range(5)]
fake_runner.calls = 0
res = asyncio.run(main.create_scan(make_request("https://site1.com"), user=user_business))
check("Business user with 100 scans runs successfully", res["id"], "scan-1234")

# 10 sites already scanned -> 11th site refused
fake_db.sites = [f"site{i}.com" for i in range(10)]
error = None
try:
    asyncio.run(main.create_scan(make_request("https://site11.com"), user=user_business))
except main.HTTPException as exc:
    error = exc

check("Business user scanning 11th site refused with 403", error.status_code if error else None, 403)
check(
    "Business site limit error mentions 10 target sites",
    "Site limit reached for this billing period (10 target sites)" in (error.detail if error else ""),
    True,
)

# Scanning one of the existing 10 sites -> allowed
fake_runner.calls = 0
res = asyncio.run(main.create_scan(make_request("https://site3.com/sub"), user=user_business))
check("Business user re-scanning existing site of 10 is allowed", res["id"], "scan-1234")


# --- Test Enterprise Plan Limits (scanLimit=None, siteLimit=None) ---
user_enterprise = {
    "id": "user-ent-1",
    "planId": "enterprise",
}
fake_db.scans = 9999
fake_db.sites = [f"site{i}.com" for i in range(50)]
fake_runner.calls = 0
res = asyncio.run(main.create_scan(make_request("https://brandnewsite.com"), user=user_enterprise))
check("Enterprise user has no scan or site limits", res["id"], "scan-1234")
check("Engine was called for enterprise user", fake_runner.calls, 1)


# --- Test Lapsed Subscription Reverts to Free Limits ---
user_lapsed_starter = {
    "id": "user-lapsed-1",
    "planId": "starter",
    "subscription": {
        "status": "active",
        "cancelAtPeriodEnd": True,
        # Expired 5 days ago
        "currentPeriodEnd": datetime.now(timezone.utc) - timedelta(days=5),
    },
}
fake_db.scans = 1
fake_db.sites = ["lapsed.com"]
error = None
try:
    asyncio.run(main.create_scan(make_request("https://lapsed.com"), user=user_lapsed_starter))
except main.HTTPException as exc:
    error = exc

check("Lapsed subscription is treated as Free and enforces scanLimit=1", error.status_code if error else None, 403)


# Restore patched globals
main._resolves_to_public_address = saved_resolver

# Summary
print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
raise SystemExit(1 if FAIL_COUNT else 0)

