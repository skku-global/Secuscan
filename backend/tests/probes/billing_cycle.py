"""End-to-end exercise of signup -> plans -> checkout -> subscription -> cancel."""

import json
import secrets
import sys

import httpx

BASE = "http://127.0.0.1:8000"


def show(label, response):
    try:
        body = response.json()
    except Exception:
        body = response.text
    print(f"--- {label}: {response.status_code}")
    print(json.dumps(body, indent=2)[:900])
    print()
    return body


with httpx.Client(base_url=BASE, timeout=20.0) as client:
    email = f"billing-{secrets.token_hex(4)}@example.com"
    password = "Sc4nnerCorrectHorse!"

    body = show("signup", client.post("/auth/signup", json={
        "name": "Billing Tester",
        "email": email,
        "password": password,
    }))

    token = body.get("token")
    if not token:
        sys.exit("signup failed, stopping")

    headers = {"Authorization": f"Bearer {token}"}

    show("plans", client.get("/billing/plans"))
    show("me (free)", client.get("/auth/me", headers=headers))
    show("subscription (empty)", client.get("/billing/subscription", headers=headers))

    # Rejections first.
    show("checkout unknown plan", client.post("/billing/checkout", headers=headers, json={
        "planId": "platinum", "cardName": "A B",
        "cardNumber": "4242424242424242", "cardExpiry": "12/28", "cardCvc": "123",
    }))
    show("checkout free plan", client.post("/billing/checkout", headers=headers, json={
        "planId": "free", "cardName": "A B",
        "cardNumber": "4242424242424242", "cardExpiry": "12/28", "cardCvc": "123",
    }))
    show("checkout enterprise", client.post("/billing/checkout", headers=headers, json={
        "planId": "enterprise", "cardName": "A B",
        "cardNumber": "4242424242424242", "cardExpiry": "12/28", "cardCvc": "123",
    }))
    show("checkout bad card", client.post("/billing/checkout", headers=headers, json={
        "planId": "starter", "cardName": "A B",
        "cardNumber": "4242424242424241", "cardExpiry": "12/28", "cardCvc": "123",
    }))
    show("checkout expired", client.post("/billing/checkout", headers=headers, json={
        "planId": "starter", "cardName": "A B",
        "cardNumber": "4242424242424242", "cardExpiry": "01/20", "cardCvc": "123",
    }))
    show("checkout no auth", client.post("/billing/checkout", json={
        "planId": "starter", "cardName": "A B",
        "cardNumber": "4242424242424242", "cardExpiry": "12/28", "cardCvc": "123",
    }))

    # THE TAMPERING TEST: an amount in the body must change nothing.
    show("checkout with amountCents=1", client.post("/billing/checkout", headers=headers, json={
        "planId": "business", "cardName": "Ada Lovelace",
        "cardNumber": "4242 4242 4242 4242", "cardExpiry": "12/28", "cardCvc": "123",
        "amountCents": 1, "currency": "XXX",
    }))

    show("subscription after buy", client.get("/billing/subscription", headers=headers))
    show("me after buy", client.get("/auth/me", headers=headers))

    # Second purchase: upgrade path, ledger should grow.
    show("checkout starter (amex)", client.post("/billing/checkout", headers=headers, json={
        "planId": "starter", "cardName": "Ada Lovelace",
        "cardNumber": "3782 822463 10005", "cardExpiry": "3/2029", "cardCvc": "1234",
    }))
    show("subscription after 2nd", client.get("/billing/subscription", headers=headers))

    show("cancel", client.post("/billing/cancel", headers=headers))
    show("cancel again", client.post("/billing/cancel", headers=headers))
    show("subscription after cancel", client.get("/billing/subscription", headers=headers))
