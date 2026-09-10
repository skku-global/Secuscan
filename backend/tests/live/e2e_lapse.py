"""The lazy downgrade, proved the only way it can be: by moving the date.

Plan step 7's second half. There is no scheduler, so nothing runs when a period ends -
the correctness comes entirely from a comparison made at READ time. The way to test
that is to hand-edit currentPeriodEnd into the past, exactly as the plan says, and then
read the account back.

THE ORDERS MUST SURVIVE. A cancellation does not un-buy the month already paid for.
"""

import sys
import time
from datetime import datetime, timedelta, timezone

import httpx
from pymongo import MongoClient

BASE = "http://127.0.0.1:8000"
PASS, FAIL = 0, 0


def check(label, got, want):
    global PASS, FAIL
    ok = got == want
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f"   (got {got!r}, wanted {want!r})"))


EMAIL = f"lapse-{int(time.time())}@example.test"
PASSWORD = "a-long-enough-passphrase-42"

client = httpx.Client(base_url=BASE, timeout=30)
created = client.post("/auth/signup", json={
    "name": "Lapse Tester", "email": EMAIL, "password": PASSWORD})
auth = {"Authorization": f"Bearer {created.json()['token']}"}

print("\n--- Buy, then cancel ------------------------------------------------------")
client.post("/billing/checkout", headers=auth, json={
    "planId": "business", "cardName": "Lapse Tester",
    "cardNumber": "5555 5555 5555 4444", "cardExpiry": "07/30", "cardCvc": "321"})
sub = client.get("/billing/subscription", headers=auth).json()
check("on Business", sub["plan"]["id"], "business")
check("brand detected from the prefix", sub["subscription"]["cardBrand"], "Mastercard")
check("one receipt", len(sub["orders"]), 1)

client.post("/billing/cancel", headers=auth)
mid = client.get("/billing/subscription", headers=auth).json()
check("cancelled but still Business", mid["plan"]["id"], "business")
check("and still has a subscription block", mid["subscription"] is None, False)

print("\n--- Move the clock, by moving the date ------------------------------------")
mongo = MongoClient("mongodb://127.0.0.1:27017")
users = mongo["secuscan"]["users"]

yesterday = datetime.now(timezone.utc) - timedelta(days=1)
result = users.update_one(
    {"email": EMAIL},
    {"$set": {"subscription.currentPeriodEnd": yesterday}},
)
check("one record edited by hand", result.modified_count, 1)

# THE STORED RECORD IS STILL UNTOUCHED AT THIS POINT: planId says business and the
# subscription is still there. Nothing has run. The next read is the whole test.
raw_before = users.find_one({"email": EMAIL})
check("the database still says business", raw_before["planId"], "business")

print("\n--- The next read is the downgrade ---------------------------------------")
lapsed = client.get("/billing/subscription", headers=auth).json()
check("READS AS FREE", lapsed["plan"]["id"], "free")
check("the subscription block is gone", lapsed["subscription"], None)
check("THE RECEIPT IS INTACT", len(lapsed["orders"]), 1)
check("and still says Business was bought", lapsed["orders"][0]["planName"], "Business")
check("for the real figure", lapsed["orders"][0]["amountCents"], 14900)

check("/auth/me agrees it is Free",
      client.get("/auth/me", headers=auth).json()["plan"]["id"], "free")

# THE HOUSEKEEPING WRITE. Correctness came from the read above; this is only tidiness,
# and the point of checking it is that it is allowed to be absent without the answers
# changing - which the two reads above already proved.
raw_after = users.find_one({"email": EMAIL})
print(f"\n  (record after the read: planId={raw_after.get('planId')!r}, "
      f"subscription={'present' if raw_after.get('subscription') else 'cleared'})")

print("\n--- Buying again after lapsing -------------------------------------------")
again = client.post("/billing/checkout", headers=auth, json={
    "planId": "starter", "cardName": "Lapse Tester",
    "cardNumber": "4242 4242 4242 4242", "cardExpiry": "12/29", "cardCvc": "123"})
check("a lapsed account can buy again", again.status_code, 200)
final = client.get("/billing/subscription", headers=auth).json()
check("now on Starter", final["plan"]["id"], "starter")
check("not carrying the old cancellation",
      final["subscription"]["cancelAtPeriodEnd"], False)
check("two receipts, oldest kept", len(final["orders"]), 2)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
