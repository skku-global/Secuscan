"""Exercise every auth endpoint against the running API."""

import time

import httpx

BASE = "http://127.0.0.1:8000"
EMAIL = f"ada+{int(time.time())}@example.com"
GOOD = "tram-oyster-914"

c = httpx.Client(base_url=BASE, timeout=30)


def show(label, response):
    body = response.text
    if len(body) > 210:
        body = body[:210] + "..."
    print(f"{label:34s} {response.status_code}  {body}")


print("--- signup: policy rejections (server side, no browser involved) ---")
for bad, why in [
    ("short1!", "under 12"),
    ("abcdefghijklmnop", "letters only"),
    ("password1234", "padded common word"),
    ("ada-is-my-name-1", "contains name"),
]:
    r = c.post("/auth/signup", json={"name": "Ada Lovelace", "email": EMAIL, "password": bad})
    detail = r.json().get("detail")
    msg = detail[0]["msg"] if isinstance(detail, list) else detail
    print(f"{why:34s} {r.status_code}  {msg}")

print()
print("--- signup: accepted ---")
r = c.post("/auth/signup", json={"name": "  Ada Lovelace  ", "email": "  ADA+X@Example.COM  ".replace("ADA+X", EMAIL.split("@")[0]), "password": GOOD})
show("signup", r)
token = r.json()["token"]
user = r.json()["user"]
print(f"{'token length':34s} {len(token)} chars")
print(f"{'name trimmed / email lowercased':34s} {user['name']!r} {user['email']!r}")
print(f"{'password echoed back?':34s} {'passwordHash' in r.text or GOOD in r.text}")

print()
print("--- signup: duplicate email ---")
r = c.post("/auth/signup", json={"name": "Impostor", "email": EMAIL, "password": GOOD})
show("second signup, same email", r)

print()
print("--- session ---")
show("me, with token", c.get("/auth/me", headers={"Authorization": f"Bearer {token}"}))
show("me, no header", c.get("/auth/me"))
show("me, wrong scheme", c.get("/auth/me", headers={"Authorization": token}))
show("me, forged token", c.get("/auth/me", headers={"Authorization": "Bearer " + "a" * 43}))

print()
print("--- login ---")
start = time.perf_counter()
r = c.post("/auth/login", json={"email": EMAIL, "password": "definitely-wrong-99"})
wrong_pw_ms = (time.perf_counter() - start) * 1000
show("wrong password", r)

start = time.perf_counter()
r = c.post("/auth/login", json={"email": f"nobody-{int(time.time())}@example.com", "password": "definitely-wrong-99"})
no_account_ms = (time.perf_counter() - start) * 1000
show("no such account", r)
print(f"{'timing: wrong pw vs no account':34s} {wrong_pw_ms:.0f} ms vs {no_account_ms:.0f} ms")

r = c.post("/auth/login", json={"email": EMAIL.upper(), "password": GOOD})
show("correct, email in CAPS", r)
second_token = r.json()["token"]
print(f"{'new token differs from signup':34s} {second_token != token}")

print()
print("--- logout revokes the server side ---")
show("logout", c.post("/auth/logout", headers={"Authorization": f"Bearer {token}"}))
show("me, with revoked token", c.get("/auth/me", headers={"Authorization": f"Bearer {token}"}))
show("me, with other token", c.get("/auth/me", headers={"Authorization": f"Bearer {second_token}"}))
show("logout again (idempotent)", c.post("/auth/logout", headers={"Authorization": f"Bearer {token}"}))

print()
print("--- forgot password: identical for real and unknown addresses ---")
# WHY THIS IS NO LONGER A BYTE COMPARISON
# It used to be, back when the endpoint was a no-op that returned a fixed sentence.
# It now returns a real challenge token, which is a fresh secret on every call and is
# therefore SUPPOSED to differ between any two responses - including two calls for the
# same address. Comparing the raw text would print False for a correctly behaving
# server, which is worse than printing nothing at all: the next person to run this
# would go hunting for a leak that is not there.
#
# So the comparison is: every field except the token must match, and the token must be
# present in both and different in both.
start = time.perf_counter()
a = c.post("/auth/forgot-password", json={"email": EMAIL})
known_ms = (time.perf_counter() - start) * 1000

start = time.perf_counter()
b = c.post("/auth/forgot-password", json={"email": f"nobody-{int(time.time())}@example.com"})
unknown_ms = (time.perf_counter() - start) * 1000

show("known address", a)
show("unknown address", b)

ja, jb = a.json(), b.json()
without_token = lambda body: {k: v for k, v in body.items() if k != "challenge"}

print(f"{'same status':34s} {a.status_code == b.status_code}")
print(f"{'same fields':34s} {sorted(ja) == sorted(jb)}")
print(f"{'same body apart from challenge':34s} {without_token(ja) == without_token(jb)}")
print(f"{'both got a challenge':34s} {bool(ja.get('challenge')) and bool(jb.get('challenge'))}")
print(f"{'and the two differ (they must)':34s} {ja.get('challenge') != jb.get('challenge')}")
print(f"{'timing: known vs unknown':34s} {known_ms:.0f} ms vs {unknown_ms:.0f} ms")

# The decoy is only worth having if it survives the NEXT step too. A challenge issued
# for an address with no account must fail the same way, with the same words, as a
# wrong code against a real one - otherwise the leak has simply moved one call along.
wrong_code = {"code": "000000", "newPassword": "Sufficiently-Long-Passphrase-9"}
ra = c.post("/auth/reset-password", json={"challenge": ja.get("challenge"), **wrong_code})
rb = c.post("/auth/reset-password", json={"challenge": jb.get("challenge"), **wrong_code})

show("wrong code, real address", ra)
show("wrong code, unknown address", rb)
print(f"{'same status':34s} {ra.status_code == rb.status_code}")
print(f"{'same message':34s} {ra.text == rb.text}")

print()
print("--- rate limit on login ---")
codes = []
for _ in range(14):
    codes.append(c.post("/auth/login", json={"email": EMAIL, "password": "wrong-guess-1234"}).status_code)
print(f"{'14 rapid attempts':34s} {codes}")
