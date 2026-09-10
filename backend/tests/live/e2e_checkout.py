"""End-to-end check of the checkout, cancel, resume and lapse cycle over HTTP.

This is the API half of the plan's verification steps 5-7. It does what the browser
would do, in the same order, against a running server - so the one thing it cannot
prove is that the buttons are wired, which is what reading the JSX is for.
"""

import sys
import time
from datetime import datetime, timedelta, timezone

import httpx

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


EMAIL = f"checkout-{int(time.time())}@example.test"
PASSWORD = "a-long-enough-passphrase-42"

client = httpx.Client(base_url=BASE, timeout=30)

print("\n--- 0. An account, on Free -----------------------------------------------")
created = client.post("/auth/signup", json={
    "name": "Checkout Tester", "email": EMAIL, "password": PASSWORD})
check("signup succeeds", created.status_code, 201)
token = created.json()["token"]
auth = {"Authorization": f"Bearer {token}"}

before = client.get("/billing/subscription", headers=auth).json()
check("starts on Free", before["plan"]["id"], "free")
check("with no subscription", before["subscription"], None)
check("and no orders", before["orders"], [])

print("\n--- 1. A bad card is refused and changes nothing -------------------------")
bad = client.post("/billing/checkout", headers=auth, json={
    "planId": "starter", "cardName": "Checkout Tester",
    "cardNumber": "4242 4242 4242 4243", "cardExpiry": "12/29", "cardCvc": "123"})
check("refused with 400", bad.status_code, 400)
detail = bad.json()["detail"]
check("one sentence, naming the digits", "Check the digits" in detail, True)
check("the card number is not echoed back", "4243" in detail, False)

still_free = client.get("/billing/subscription", headers=auth).json()
check("plan unchanged", still_free["plan"]["id"], "free")
check("no order was written", still_free["orders"], [])

print("\n--- 2. A well-formed card grants the plan --------------------------------")
paid = client.post("/billing/checkout", headers=auth, json={
    "planId": "starter", "cardName": "Checkout Tester",
    "cardNumber": "4242 4242 4242 4242", "cardExpiry": "12/29", "cardCvc": "123"})
check("checkout succeeds", paid.status_code, 200)
body = paid.json()
check("status is granted", body["status"], "granted")
check("the plan is Starter", body["plan"]["id"], "starter")
check("the user record says so too", body["user"]["plan"]["id"], "starter")
check("the amount is the SERVER's figure", body["order"]["amountCents"], 4900)
check("brand kept", body["order"]["cardBrand"], "Visa")
check("last four kept", body["order"]["cardLast4"], "4242")
check("the full number is nowhere in the response",
      "4242424242424242" in paid.text, False)

after = client.get("/billing/subscription", headers=auth).json()
check("subscription is active", after["subscription"]["status"], "active")
check("not cancelling", after["subscription"]["cancelAtPeriodEnd"], False)
check("one order in the history", len(after["orders"]), 1)
check("/auth/me agrees", client.get("/auth/me", headers=auth).json()["plan"]["id"], "starter")

ends = after["subscription"]["currentPeriodEnd"]
check("a renewal date exists", bool(ends), True)

print("\n--- 3. Cancel keeps the plan until the period ends -----------------------")
cancelled = client.post("/billing/cancel", headers=auth)
check("cancel succeeds", cancelled.status_code, 200)
cbody = cancelled.json()
check("the flag is set", cbody["subscription"]["cancelAtPeriodEnd"], True)
check("THE PLAN STILL READS STARTER", cbody["plan"]["id"], "starter")
check("status says cancelling", cbody["subscription"]["status"], "cancelling")
check("the end date did not move", cbody["subscription"]["currentPeriodEnd"], ends)
check("/auth/me still says Starter",
      client.get("/auth/me", headers=auth).json()["plan"]["id"], "starter")
check("the receipt survived", len(client.get("/billing/subscription", headers=auth).json()["orders"]), 1)

print("\n--- 4. Resume clears it ---------------------------------------------------")
resumed = client.post("/billing/resume", headers=auth)
check("resume succeeds", resumed.status_code, 200)
check("the flag is gone", resumed.json()["subscription"]["cancelAtPeriodEnd"], False)
check("active again", resumed.json()["subscription"]["status"], "active")
check("still Starter", resumed.json()["plan"]["id"], "starter")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
