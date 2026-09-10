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
a = c.post("/auth/forgot-password", json={"email": EMAIL})
b = c.post("/auth/forgot-password", json={"email": "nobody-at-all@example.com"})
show("known address", a)
show("unknown address", b)
print(f"{'responses byte-identical':34s} {a.text == b.text and a.status_code == b.status_code}")

print()
print("--- rate limit on login ---")
codes = []
for _ in range(14):
    codes.append(c.post("/auth/login", json={"email": EMAIL, "password": "wrong-guess-1234"}).status_code)
print(f"{'14 rapid attempts':34s} {codes}")
