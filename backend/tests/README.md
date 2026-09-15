# SecuScan backend tests

Two commands. The first needs nothing running; the second needs the API up.

```
python backend/tests/run_offline.py     # everything that can run on a fresh checkout
python backend/tests/run_live.py        # the suites that talk to a running server
```

Setup, once: `pip install -r backend/requirements.txt`.

---

## The rule that separates the three trees

The directory is split by **what a failure is allowed to mean**, which is the only
division that matters when you are staring at a red line and deciding whether you
broke something.

| tree | needs | a non-zero exit means |
|---|---|---|
| `tests/*.py` | nothing | **a bug** |
| `tests/live/` | uvicorn on :8000, MongoDB | **a bug** |
| `tests/probes/` | uvicorn on :8000 | *nothing* — they assert nothing |

That third row is why neither runner executes `probes/`. A script that only prints
has no verdict to give, so its exit code is noise, and a runner that tallied it
would be inventing a pass or a fail out of whether the last line happened to raise.

Folding the live suites into the offline runner was rejected for a related reason:
the one command everybody runs would then fail for a cause that is not a bug — a
server nobody started — and a suite that cries wolf gets ignored, which costs more
than it ever saves.

---

## `tests/*.py` — the offline suites

No server, no database, no network. They import the backend modules directly and
test functions rather than HTTP, so they run on a fresh checkout with nothing
started. These are the ones worth wiring into CI or a pre-commit hook.

| suite | what it pins |
|---|---|
| `test_discovery.py` | the parser and the host rule every check stands on — a wrong answer here is not one wrong finding, it is a wrong premise under every finding in the report. That **nothing inside `<template>` is real** (its contents are inert by specification, yet a form in one counted as a form — and since `login_form()` takes the *first* form with a password box, a “change password” modal template took the login's place, while one such template in an SPA shell made every probed path look like a login page); that **an unclosed tag is still a tag** (a `<form>` or `<a>` missing its closing tag was dropped entirely, so a login page short one `</form>` reported “no login form found” and skipped the whole authenticated tier); that a script body is not page text, while `<noscript>` is suppressed as text but kept as markup — the right way round for a scanner that runs no JavaScript; and **the host rule**, in both directions — `notexample.com` and an OAuth provider refused, userinfo before an `@` unable to smuggle a host past it, and `www.` not treated as a site boundary, which had made scanning `acme.com` and `www.acme.com` two different scans of one site; and that **a signup form is never the login form** — the one property here whose wrong answer lands on the client's site rather than on our report, since `_session.py` posts the supplied credentials at whatever `login_form()` returns, and “the first form with a password box” aimed them at the registration form on every page that puts its “Create your account” panel above the sign-in form |
| `test_branches.py` | check verdicts for cookies and MFA, and the engine's crash handling, from synthetic `Page` / `ScanTarget` objects — **and that no Tier 1 check module contains a POST, PUT, PATCH or DELETE**, checked against the source of every module in the registry |
| `test_https_branches.py` | how `check_https` builds its probe URL, and its refusal semantics. Serves a real socket, all on 127.0.0.1 |
| `test_rate_limit.py` | the passive evidence ladder — **and that the check sends no request at all** |
| `test_password.py` | the password-policy ladder, including that composition rules earn nothing — **and again, no request** |
| `test_reset.py` | the enumeration rule on the reset flow: a known and an unknown address get the same answer, the same failures and the same timing budget, and the decoy challenge that makes them identical is refused everywhere except the one resolver written for it |
| `test_payments.py` | the provider seam, that a card number never reaches a result, and that a misconfigured Paddle never falls back to the mock |
| `test_google_auth.py` | that a clock-skew tolerance is passed to google-auth and is a sane size, plus the claim checks the library does not make for us |
| `test_credentials.py` | that Tier 2 credentials survive an encrypt/decrypt round trip, that neither half appears in the ciphertext, that a tampered token is refused rather than half-read, and that an unset key fails closed |
| `test_tier2_retention.py` | that credential retention is opt-in and off by default, that a scan which did not ask for it stores nothing and needs no encryption key, that one which did ask is refused *before* `run_scan` on a server that cannot encrypt, and that an expired blob reads as absent rather than waiting on the TTL sweep |
| `test_account_enumeration.py` | the Tier 2 enumeration check's verdict ladder — message, status and timing discrepancies — that it skips rather than passes when a probe never reached the authentication logic, and that no password reaches a finding. Then the two ways this check produced a **false PASSED** — the worst verdict it can emit, because it tells a customer whose site really does enumerate that it does not. **The username must go out under the field name the form declares**: the module worked the names out from a private copy of the shared helper that tested the name before the type and let the *last* match win, so an ordinary `<input type="submit" name="login">`, a “remember my username” checkbox or a trailing OTP box took the username's place. The username then never reached the server, both probes were turned away identically — and identical is what passing looks like here. Against one leaky mock site, a single submit button is the whole difference between WARNING and PASSED. And **a 404 is not a clean bill of health**: two 404s are byte-for-byte identical, so the guessed `/api/login` fallback reported "returned identical HTTP 404 responses" as good news. Both sides must now be 404 or 410 before the check skips — both, because 404-for-unknown against 401-for-known *is* the leak — and the skip carries its own remediation (enter your sign-in page) rather than the wall check's "allowlist the scanner" |
| `test_tier2_session.py` | the two shared Tier 2 helpers: that four checks running concurrently produce **exactly one** login attempt behind a lock, that every failure reason skips rather than fails, that a CSRF cookie alone is not a session, and that the password reaches neither an outcome, a finding nor an error detail. Then four properties about *reading the page*, all of which cost a paying customer all four Tier 2 checks at once because they share one session: **a script body is not text** (tag-stripping alone left `window.csrfToken = ...` in what the module read as "what the page says", turning a login that worked into `blocked`); **one wall vocabulary, not four copies** (three modules each hand-wrote it, all three drifted).; that a **WAF interstitial** is diagnosed as a wall rather than a missing session cookie, whose remediation tells a customer stopped at the front door that no action is needed; and that **only a text-entry input is the username box** — a hidden field (`login_challenge`, `account_id`), a submit button named `login`, a “remember my username” checkbox and a tenant `<select>` all match the username name-hint, and all of them sit at the *end* of a form, where the old last-match-wins chain let them take the title. Four of six ordinary login-form shapes resolved the wrong field: the username went out under that field's name, the real one was never sent, and the login failed for a reason nothing in the report could explain. Driven through the **real parser**, so it pins discovery's share too — the `text` default for an untyped input, the lowercasing of `TYPE="HIDDEN"`, and the fallback from `name` to `id`. The one-vocabulary rule is pinned twice, because the obvious assertion is weaker than it reads: `local is shared` catches a copy that has **drifted**, but `re.compile` caches by (pattern, flags), so a module that pastes the identical pattern text back in is handed the *same object* and the identity test passes — which is exactly how the private username hint survived inside `account_enumeration_check`. Nothing at runtime can separate an alias from a paste, because they are one object, so the second assertion asks the **source**: an AST walk over each check module collecting every literal it hands to `re.compile`, the way `test_branches.py` asks Tier 1 modules which verbs they contain. Demonstrated by pasting the copy back into the file — every identity assertion still passes and only the source one fails |
| `test_endpoints.py` | the shared endpoint finder the logout, reset and 2FA checks all start from — that a link resolving to a page the scanner **already fetched** is not an endpoint. `<a href="#">Sign out</a>` is how a JavaScript sign-out button looks to a parser, and `urljoin` resolves that bare `#` to the page's own address; the logout check then fetched the homepage, got a healthy 200 (so the refused-sign-out gate, which only fires on `>= 400`, did not catch it) and reported CRITICAL against a site whose logout is fine. Pinned in both directions: the self-link is dropped **and** a real `/logout` still reports CRITICAL when the session really does survive |
| `test_session_cookie.py` | the attributes on the session cookie a real login returns — the severity ladder, RFC 6265 case-insensitivity, that CSRF cookies are not judged on `HttpOnly`, that the verdict follows the **worst** cookie rather than the first, and that this check and `_session.py` cannot drift apart on what counts as a session cookie (they share one regex; a local copy had already diverged, making `app_sid_v2` a session to the login and invisible here) |
| `test_logout.py` | that signing out destroys the session server-side, decided by comparing three observations of one page — **and that a page looking identical signed in and signed out is skipped, never passed**, which is the difference between testing logout and testing nothing. Also that a **refused** sign-out (405 from a POST-only endpoint, 403/429 from a blocked one) is skipped rather than reported CRITICAL: nothing ended the session, so the cookie still working proves nothing — while a logout that *was* processed and still failed stays CRITICAL |
| `test_password_reset.py` | the reset flow's enumeration answer, and whether a reset token reaches the response body — **and that without a successful login the check sends nothing at all**, asserted on request count rather than severity, because the address probed is client-supplied text. The leak detector is pinned in both directions: ordinary success responses (`{"code": "reset_email_sent"}`, a value belonging to a later sibling key) must not raise a CRITICAL, and real tokens, OTPs and JWTs must still do so |
| `test_two_factor.py` | whether 2FA enrolment is reachable behind a login, and **that a login screen served to a session that did not carry is skipped rather than reported as “no 2FA offered”** — a confident wrong answer about a page the scanner was never shown |
| `test_contact.py` | the Settings contact form's endpoint — **that the sender is taken from the session and cannot be overridden by a field in the body**, asserted by trying six such fields and checking the address the mailer actually received; plus that it answers 503 and 502 rather than a false "sent", that the subject cannot carry a newline into a mail header, and that the body is escaped before it reaches our own mailbox |
| `test_engine_e2e.py` | the whole engine against a deliberately imperfect fixture site on localhost |

**`_path.py`** is the one-line import at the top of each suite. It puts `backend/`
on `sys.path` so a suite runs from any working directory. Before it, that job
belonged to a `PYTHONPATH` the caller had to remember to export, and forgetting
produced an `ImportError` that reads like a broken test rather than a missing
variable. Nothing under `live/` or `probes/` needs it — those speak HTTP and import
no backend module.

**Two harness styles live here, and both are fine.** Every suite but one counts as it goes and
prints `N passed, M failed`; `test_engine_e2e.py` bails on the first failure instead,
so it has no tally and the runner counts its `ok` lines rather than leaving the
column blank and looking like it did nothing.

**The suite list in `run_offline.py` is explicit, not a glob.** A runner that
discovers its own work silently skips a suite whose name stops matching, and a test
that silently stops running is worse than one that fails. Adding a suite is a
deliberate one-line edit to `SUITES`.

---

## `tests/live/` — end to end over HTTP

Start the API first:

```
cd backend && python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

`run_live.py` pre-flights that server with a `GET /billing/plans` before running
anything, and exits **2** with `SKIPPED` if it gets no answer. Without the
pre-flight, forgetting to start uvicorn produces a `ConnectError` traceback that
reads like a broken test.

- **`e2e_checkout.py`** — signup → checkout → cancel → resume, the way the browser
  would do it, in that order. The one thing it cannot prove is that the buttons are
  wired to it; that is what the browser scripts and reading the JSX are for.
- **`e2e_lapse.py`** — the lazy downgrade. There is no scheduler, so nothing runs
  when a period ends and the correctness comes entirely from a comparison made at
  read time. The only way to test that is to move the date, so this one reaches
  past the API into MongoDB with pymongo and hand-edits `currentPeriodEnd` into the
  past. It also asserts the orders ledger **survives** — a cancellation does not
  un-buy a month already paid for.

### What these do to your database

Each signs up a throwaway account (`checkout-<timestamp>@example.test` and friends)
and **leaves it there**; `e2e_lapse.py` additionally rewrites that account's period
end through pymongo. They never touch an account they did not create, but they do
accumulate. **Point them at a development database, not a real one.**

---

## `tests/probes/` — scripts for a human to read

Not run by either runner, on purpose (see the table above). They print request and
response for a person deciding whether a response *looks* right — which is the job
at the moment a contract is still being settled, before there is a stable answer
worth asserting.

- `auth_endpoints.py` — every auth endpoint in sequence, with bodies.
- `billing_cycle.py` — signup → plans → checkout → subscription → cancel, as JSON.
- `rebuy.py` — what happens when somebody buys the plan they are already on. It
  became reachable when Settings grew a "Change plan" button that sends a paying
  customer to a pricing table where their current plan is one of the buttons.

They need the API up, and they create throwaway accounts too.

---

## The browser scripts

Rendering, theming and whether the buttons are actually wired live in
**`frontend/tests/`**, which has its own README. They drive a real browser and need
both servers up, so they are neither offline nor runnable from here.
