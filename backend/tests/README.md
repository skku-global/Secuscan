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
| `test_branches.py` | check verdicts for cookies and MFA, and the engine's crash handling, from synthetic `Page` / `ScanTarget` objects — **and that no Tier 1 check module contains a POST, PUT, PATCH or DELETE**, checked against the source of every module in the registry |
| `test_https_branches.py` | how `check_https` builds its probe URL, and its refusal semantics. Serves a real socket, all on 127.0.0.1 |
| `test_rate_limit.py` | the passive evidence ladder — **and that the check sends no request at all** |
| `test_password.py` | the password-policy ladder, including that composition rules earn nothing — **and again, no request** |
| `test_reset.py` | the enumeration rule on the reset flow: a known and an unknown address get the same answer, the same failures and the same timing budget, and the decoy challenge that makes them identical is refused everywhere except the one resolver written for it |
| `test_payments.py` | the provider seam, that a card number never reaches a result, and that a misconfigured Paddle never falls back to the mock |
| `test_google_auth.py` | that a clock-skew tolerance is passed to google-auth and is a sane size, plus the claim checks the library does not make for us |
| `test_credentials.py` | that Tier 2 credentials survive an encrypt/decrypt round trip, that neither half appears in the ciphertext, that a tampered token is refused rather than half-read, and that an unset key fails closed |
| `test_tier2_retention.py` | that credential retention is opt-in and off by default, that a scan which did not ask for it stores nothing and needs no encryption key, that one which did ask is refused *before* `run_scan` on a server that cannot encrypt, and that an expired blob reads as absent rather than waiting on the TTL sweep |
| `test_account_enumeration.py` | the Tier 2 enumeration check's verdict ladder — message, status and timing discrepancies — that it skips rather than passes when a probe never reached the authentication logic, and that no password reaches a finding |
| `test_engine_e2e.py` | the whole engine against a deliberately imperfect fixture site on localhost |

**`_path.py`** is the one-line import at the top of each suite. It puts `backend/`
on `sys.path` so a suite runs from any working directory. Before it, that job
belonged to a `PYTHONPATH` the caller had to remember to export, and forgetting
produced an `ImportError` that reads like a broken test rather than a missing
variable. Nothing under `live/` or `probes/` needs it — those speak HTTP and import
no backend module.

**Two harness styles live here, and both are fine.** Six suites count as they go and
print `N passed, M failed`; `test_engine_e2e.py` bails on the first failure instead,
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
