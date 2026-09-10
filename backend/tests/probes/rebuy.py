"""What happens if somebody buys the plan they are already on?

Not in the plan, and not tested until now. It became reachable BECAUSE of this
session's work: the new "Change plan" button in Settings sends a paying customer to
the pricing table, where the plan they already have is one of the buttons.
"""
import time
import httpx

BASE = "http://127.0.0.1:8000"
client = httpx.Client(base_url=BASE, timeout=30)

EMAIL = f"rebuy-{int(time.time())}@example.test"
created = client.post("/auth/signup", json={
    "name": "Rebuy Tester", "email": EMAIL, "password": "a-long-enough-passphrase-42"})
auth = {"Authorization": f"Bearer {created.json()['token']}"}

CARD = {"cardName": "Rebuy Tester", "cardNumber": "4242 4242 4242 4242",
        "cardExpiry": "12/29", "cardCvc": "123"}

first = client.post("/billing/checkout", headers=auth, json={"planId": "starter", **CARD})
print("first  buy :", first.status_code, first.json()["subscription"]["currentPeriodEnd"])

time.sleep(1.2)
second = client.post("/billing/checkout", headers=auth, json={"planId": "starter", **CARD})
print("second buy :", second.status_code,
      second.json().get("subscription", {}).get("currentPeriodEnd")
      if second.status_code == 200 else second.json())

state = client.get("/billing/subscription", headers=auth).json()
print("plan       :", state["plan"]["id"])
print("orders     :", len(state["orders"]), "->",
      [o["amountCents"] for o in state["orders"]])
print("period end :", state["subscription"]["currentPeriodEnd"])

up = client.post("/billing/checkout", headers=auth, json={"planId": "business", **CARD})
print("upgrade    :", up.status_code, up.json()["plan"]["id"] if up.status_code == 200 else up.json())
final = client.get("/billing/subscription", headers=auth).json()
print("orders now :", len(final["orders"]), "->",
      [(o["planName"], o["amountCents"]) for o in final["orders"]])
