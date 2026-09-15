"""Branch tests for the payments seam and the end-of-period cancellation logic.

Three things are being pinned here, and the third matters most:

  1. the mock provider grants on a well-formed card and refuses with one sentence
     otherwise, and THE CARD NUMBER NEVER APPEARS IN ITS RESULT;
  2. the Paddle skeleton refuses to be built and says what is missing, rather than
     pretending - and a misconfigured Paddle NEVER falls back to the mock, because
     granting paid plans for free is not a degraded mode;
  3. a cancelled subscription lapses on a comparison done at READ time, with nothing
     running on a schedule - so the tests hand `now` in and never touch the clock.

Run from anywhere (the `import _path` line puts backend/ on sys.path):
  python backend/tests/test_payments.py
"""

import asyncio
from contextlib import contextmanager
import hashlib as _hashlib
import hmac as _hmac
import json as _json
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import HTTPException

import _path  # noqa: F401  - puts backend/ on sys.path; must precede the imports below
import billing
import config
import payments
from payments import CheckoutOutcome, PaymentProvider, ProviderNotConfigured
from payments import mock_card, paddle

PASS_COUNT = 0
FAIL_COUNT = 0


def check(label, got, want):
    global PASS_COUNT, FAIL_COUNT
    ok = got == want
    if ok:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f"   (got {got!r}, wanted {want!r})"))


def run(coro):
    return asyncio.run(coro)


NOW = datetime(2026, 9, 4, 12, 0, 0, tzinfo=timezone.utc)

STARTER = billing.find_plan("starter")
FREE = billing.find_plan("free")

# A Luhn-valid test number. Every payment processor on earth publishes this one, and
# it is here for the same reason: it is unmistakably not a real card.
GOOD_CARD = {
    "name": "A Person",
    "number": "4242 4242 4242 4242",
    "expiry": "12/29",
    "cvc": "123",
}


def card(**overrides):
    merged = dict(GOOD_CARD)
    merged.update(overrides)
    return merged


# ============================================================================
print("\n--- 1. CheckoutOutcome: three states, one field to read -----------------")
# ============================================================================

granted = CheckoutOutcome.granted({"brand": "Visa", "last4": "4242"}, "ref_1")
check("granted status", granted.status, "granted")
check("granted is ok", granted.ok, True)
check("granted carries no problem", granted.problem, None)
check("granted has no client action", granted.client_action, None)

pending = CheckoutOutcome.pending({"token": "t"}, "ref_2")
check("pending status", pending.status, "pending")
check("pending is ok", pending.ok, True)
check("pending carries the browser's next step", pending.client_action, {"token": "t"})

refused = CheckoutOutcome.refused("Enter your card number.")
check("refused status", refused.status, "refused")
check("refused is NOT ok", refused.ok, False)
check("refused carries the sentence", refused.problem, "Enter your card number.")
check("refused grants no payment method", refused.payment_method, {})

# THE MUTABLE DEFAULT TRAP, pinned. `payment_method: dict = {}` in the dataclass
# would give every instance the SAME dict, so writing to one outcome would show up
# in another. default_factory=dict is what makes these separate objects.
a, b = CheckoutOutcome.refused("x"), CheckoutOutcome.refused("y")
a.payment_method["leaked"] = True
check("outcomes do not share a payment_method dict", b.payment_method, {})


# ============================================================================
print("\n--- 2. The mock provider grants on shape alone --------------------------")
# ============================================================================

mock = mock_card.MockCardProvider()
check("provider names itself", mock.name, "mock")

out = run(mock.create_checkout(plan=STARTER, user={"id": "u1"}, card=card(), now=NOW))
check("good card is granted", out.status, "granted")
check("brand is detected", out.payment_method["brand"], "Visa")
check("last four are kept", out.payment_method["last4"], "4242")
check("expiry month is kept", out.payment_method["expiryMonth"], 12)
check("expiry year is expanded", out.payment_method["expiryYear"], 2029)
check("reference is prefixed", out.provider_ref.startswith("mock_"), True)
check("nothing is pending", out.client_action, None)

# THE BOUNDARY, ASSERTED. Everything the outcome carries gets stringified and the
# full card number is looked for in it. This is the one property the whole package
# is arranged around, so it is checked against the OBJECT rather than by reading the
# code that built it.
check(
    "the card number is nowhere in the outcome",
    "4242424242424242" in repr(out) or "4242 4242 4242 4242" in repr(out),
    False,
)

second = run(mock.create_checkout(plan=STARTER, user={"id": "u1"}, card=card(), now=NOW))
check("references are not a constant", second.provider_ref == out.provider_ref, False)

# --- refusals: one sentence, naming the field ---------------------------------

bad_luhn = run(mock.create_checkout(
    plan=STARTER, user={"id": "u1"}, card=card(number="4242424242424243"), now=NOW))
check("a mistyped digit is refused", bad_luhn.status, "refused")
check("and says to check the digits", "Check the digits" in bad_luhn.problem, True)

expired = run(mock.create_checkout(
    plan=STARTER, user={"id": "u1"}, card=card(expiry="01/20"), now=NOW))
check("an expired card is refused", expired.status, "refused")
check("and says so", "expired" in expired.problem, True)

no_name = run(mock.create_checkout(
    plan=STARTER, user={"id": "u1"}, card=card(name="  "), now=NOW))
check("a missing name is refused", no_name.status, "refused")
check("naming the field", "name printed on the card" in no_name.problem, True)

amex_short = run(mock.create_checkout(
    plan=STARTER, user={"id": "u1"},
    card=card(number="378282246310005", cvc="123"), now=NOW))
check("amex with a 3-digit CVC is refused", amex_short.status, "refused")
check("and asks for 4", "4 digits" in amex_short.problem, True)

amex_ok = run(mock.create_checkout(
    plan=STARTER, user={"id": "u1"},
    card=card(number="378282246310005", cvc="1234"), now=NOW))
check("amex with 4 is granted", amex_ok.status, "granted")
check("amex brand", amex_ok.payment_method["brand"], "American Express")

# NO CARD AT ALL MUST NOT GRANT. `card` is optional on the interface because a real
# provider does not want one; this provider cannot work without it, and the failure
# mode that matters is granting a plan on the strength of nothing.
no_card = run(mock.create_checkout(plan=STARTER, user={"id": "u1"}, card=None, now=NOW))
check("no card does not grant", no_card.status, "refused")
empty_card = run(mock.create_checkout(plan=STARTER, user={"id": "u1"}, card={}, now=NOW))
check("an empty card does not grant", empty_card.status, "refused")


# ============================================================================
print("\n--- 3. The base provider is the 'switched off' one ----------------------")
# ============================================================================

off = PaymentProvider()
check("base provider is named none", off.name, "none")

refused_off = run(off.create_checkout(
    plan=STARTER, user={"id": "u1"}, card=card(), now=NOW))
check("a perfect card is still refused", refused_off.status, "refused")
check("and says payments are not configured",
      "not configured" in refused_off.problem, True)
check("base webhook handler answers None",
      run(off.handle_webhook(headers={}, body=b"")), None)


# ============================================================================
print("\n--- 4. The Paddle skeleton is honest about what it lacks ----------------")
# ============================================================================

_saved = (
    config.PADDLE_CLIENT_TOKEN,
    config.PADDLE_API_KEY,
    config.PADDLE_WEBHOOK_SECRET,
    config.paddle_price_id,
)
config.PADDLE_CLIENT_TOKEN = ""
config.PADDLE_API_KEY = ""
config.PADDLE_WEBHOOK_SECRET = ""
config.paddle_price_id = lambda plan_id: ""

missing = paddle.missing_credentials()
check("something is missing", len(missing) > 0, True)

joined = " ".join(missing)
for needed in (
    "SECUSCAN_PADDLE_CLIENT_TOKEN",
    "SECUSCAN_PADDLE_API_KEY",
    "SECUSCAN_PADDLE_WEBHOOK_SECRET",
):
    check(f"names {needed}", needed in joined, True)

# The price ids are derived from the CATALOGUE, so a plan added later is covered
# without editing paddle.py. Both purchasable plans must be named; neither of the
# two unpurchasable ones should be.
check("names the Starter price id", "SECUSCAN_PADDLE_PRICE_STARTER" in joined, True)
check("names the Business price id", "SECUSCAN_PADDLE_PRICE_BUSINESS" in joined, True)
check("does not ask for a Free price id",
      "SECUSCAN_PADDLE_PRICE_FREE" in joined, False)
check("does not ask for an Enterprise price id",
      "SECUSCAN_PADDLE_PRICE_ENTERPRISE" in joined, False)

try:
    paddle.PaddleProvider()
    check("constructing unconfigured Paddle raises", False, True)
except ProviderNotConfigured as exception:
    check("constructing unconfigured Paddle raises", True, True)
    check("the message names the webhook secret",
          "WEBHOOK_SECRET" in str(exception), True)

# --- with credentials present, it builds and then refuses to pretend ----------
#
# The point of these four lines is NOT to test Paddle - there is nothing behind it.
# It is to prove the skeleton's failure is about MISSING CREDENTIALS and not a
# permanent raise, and that once built it does not quietly grant a plan. A stub
# that granted would be the worst possible bug in this package.
#
# create_checkout runs against a STUBBED transport, never the real Paddle API.
#
# WHY THAT IS NOT A SHORTCUT. An offline suite that reaches the internet is not an
# offline suite. It would pass or fail on network weather and on whether a sandbox key
# had been rotated, it would post a checkout attempt to a third party every time
# somebody ran the tests, and on a machine with no egress it would report a failure
# that has nothing to do with this code. The stub is also the only way to assert the
# two things below that actually matter, since neither of them is visible in a 403.
#
# handle_webhook with no Paddle-Signature header returns None - signature
# verification is the first check, and a missing header means nothing is processed.


class _StubResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = _json.dumps(payload)

    def json(self):
        return self._payload


class _StubClient:
    """Stands in for httpx.AsyncClient: records the request, returns `reply`."""

    sent = None
    reply = None

    def __init__(self, *_args, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def post(self, url, **kwargs):
        type(self).sent = {
            "url": url,
            "headers": kwargs.get("headers") or {},
            "body": kwargs.get("json") or {},
        }
        return type(self).reply


class _StubHttpx:
    AsyncClient = _StubClient
    # The REAL exception class, so paddle's `except httpx.HTTPError` still binds.
    HTTPError = httpx.HTTPError


config.PADDLE_CLIENT_TOKEN = "test_token"
config.PADDLE_API_KEY = "test_key"
config.PADDLE_WEBHOOK_SECRET = "test_secret"
config.paddle_price_id = lambda plan_id: "pri_test"

check("with credentials, nothing is missing", paddle.missing_credentials(), [])

built = paddle.PaddleProvider()
check("and it builds", built.name, "paddle")

_real_httpx = paddle.httpx
paddle.httpx = _StubHttpx

# A key Paddle rejects must REFUSE - not raise, and not grant.
_StubClient.reply = _StubResponse(403, {"error": {"code": "authentication_malformed"}})
rejected = run(built.create_checkout(plan=STARTER, user={"id": "u1"}, card=card(), now=NOW))
check("a rejected key refuses", rejected.status, "refused")
check("  and it is not granted", rejected.status == "granted", False)
check("  and Paddle's own error text is not repeated to the user",
      "authentication_malformed" in (rejected.problem or ""), False)

# THE ONE THAT MATTERS HERE. Paddle ACCEPTED the transaction, and the outcome is still
# pending. A provider that granted on this response would hand out a paid plan on a
# transaction nobody has paid for yet - the entitlement is the webhook's job, and this
# is the assertion that stops a later edit from moving it earlier.
_StubClient.reply = _StubResponse(200, {"data": {"id": "txn_123"}})
accepted = run(built.create_checkout(plan=STARTER, user={"id": "u1"}, card=card(), now=NOW))
check("an accepted transaction PENDS", accepted.status, "pending")
check("  it is not granted", accepted.status == "granted", False)
check("  the browser is given the transaction id",
      accepted.client_action["transaction_id"], "txn_123")

# AND THE CARD NEVER LEFT THIS PROCESS. create_checkout accepts one only because the
# seam is shared with the mock; a real processor collects the card itself. So the
# request body is searched for every part of the card that was handed in.
_sent_body = _json.dumps(_StubClient.sent["body"])
check("no card number reached Paddle", "4242" in _sent_body, False)
check("no CVC reached Paddle", "123" in _sent_body, False)
check("no expiry reached Paddle", "12/29" in _sent_body, False)
check("no cardholder name reached Paddle", "A Person" in _sent_body, False)
check("but the user id did", _StubClient.sent["body"]["custom_data"]["user_id"], "u1")
check("and the plan id did", _StubClient.sent["body"]["custom_data"]["plan_id"], "starter")

paddle.httpx = _real_httpx

webhook_result = run(built.handle_webhook(headers={}, body=b"{}"))
check("handle_webhook returns None with no signature",
      webhook_result, None)


# ============================================================================
print("\n--- 5. Selection never falls back to the mock --------------------------")
# ============================================================================

_saved_name = config.PAYMENT_PROVIDER

# PADDLE_SANDBOX IS PINNED HERE TOO, and the reason is the bug this line was written
# to fix. Selecting the mock depends on TWO settings now, not one: the mock is
# refused when the server also claims to be live, because provider=mock with
# sandbox=false is a contradiction and the safe reading of a contradictory payment
# config is no payments. This section sets the provider and used to inherit the
# sandbox flag from whatever .env happened to say - so it went red the moment a
# developer set SECUSCAN_PADDLE_SANDBOX=false on the way to going live, which is
# exactly the "fails BECAUSE the configuration is right" trap the note at the end of
# this section already warns about.
_saved_sandbox = config.PADDLE_SANDBOX

config.PAYMENT_PROVIDER = "mock"
config.PADDLE_SANDBOX = True
check("mock is selected by name", payments._build_provider().name, "mock")

# THE MOCK IS REFUSED WHEN THE SERVER SAYS IT IS LIVE.
# Same doctrine as the unconfigured-paddle case below, read from the other end.
# Setting sandbox=false states intent to handle real money; the mock grants plans on
# a Luhn checksum. This is what a half-finished go-live looks like - the sandbox flag
# flipped, the provider never switched - and resolving it toward the mock would hand
# out free subscriptions on a production domain.
config.PADDLE_SANDBOX = False
_mock_live = payments._build_provider()
check("the mock is refused when sandbox is false", _mock_live.name, "none")
check("and it is NOT the mock", _mock_live.name == "mock", False)
check("so a card sent to it is refused",
      run(_mock_live.create_checkout(
          plan=STARTER, user={"id": "u1"}, card=card(), now=NOW)).status,
      "refused")
config.PADDLE_SANDBOX = True

# THE ONE THAT MATTERS. Paddle selected and unconfigured must produce the switched-
# off provider - not the mock. "The processor is broken, so grant plans using a
# checksum" is a sentence no system should be able to execute.
config.PAYMENT_PROVIDER = "paddle"
config.PADDLE_CLIENT_TOKEN = ""
config.PADDLE_API_KEY = ""
config.PADDLE_WEBHOOK_SECRET = ""
config.paddle_price_id = lambda plan_id: ""

built_paddle = payments._build_provider()
check("unconfigured paddle is switched off", built_paddle.name, "none")
check("and is NOT the mock", built_paddle.name == "mock", False)
check("a card sent to it is refused",
      run(built_paddle.create_checkout(
          plan=STARTER, user={"id": "u1"}, card=card(), now=NOW)).status,
      "refused")

config.PAYMENT_PROVIDER = "stripe"
unknown = payments._build_provider()
check("an unknown provider is switched off", unknown.name, "none")
check("and is NOT the mock", unknown.name == "mock", False)

config.PAYMENT_PROVIDER = _saved_name
config.PADDLE_SANDBOX = _saved_sandbox
(
    config.PADDLE_CLIENT_TOKEN,
    config.PADDLE_API_KEY,
    config.PADDLE_WEBHOOK_SECRET,
    config.paddle_price_id,
) = _saved
# The section has just spent thirty lines rewriting the provider config, so the last
# thing to check is that putting it back produces the provider this deployment asked
# for.
#
# WHAT THIS DELIBERATELY DOES NOT ASSERT IS A PARTICULAR PROVIDER. It used to: it
# checked for "mock", which was true on every developer machine right up until somebody
# configured Paddle for real - and a correctly configured deployment then turned the
# suite red. A test that fails BECAUSE the configuration is right is worse than no test
# at all, because the obvious way to make it pass again is to unconfigure Paddle.
#
# So the invariant is stated the way the section actually means it: the mock is reached
# when, and only when, it was asked for by name. No amount of missing credentials and
# no unrecognised provider string can arrive at it.
_restored = payments.provider_name()
check("the mock is reached only by asking for it by name",
      _restored == "mock", _saved_name == "mock" and _saved_sandbox)
check("and the restored provider is a real one",
      _restored in ("mock", "paddle", "none"), True)
check("so payments are available", payments.payments_available(), True)


# ============================================================================
print("\n--- 6. A cancelled plan lapses on a read, not on a schedule ------------")
# ============================================================================


def subscription(cancel=False, ends_in_days=10, aware=True, plan_id="starter"):
    ends = NOW + timedelta(days=ends_in_days)

    # PYMONGO RETURNS NAIVE DATETIMES. `aware=False` is the shape a value actually
    # read back out of the database has, and comparing naive with aware raises
    # TypeError rather than guessing - so this is not a hypothetical case.
    if not aware:
        ends = ends.replace(tzinfo=None)

    return {
        "planId": plan_id,
        "status": "cancelling" if cancel else "active",
        "currentPeriodEnd": ends,
        "cancelAtPeriodEnd": cancel,
        "cardBrand": "Visa",
        "cardLast4": "4242",
    }


lapsed = billing.subscription_has_lapsed

check("no subscription has not lapsed", lapsed(None, NOW), False)
check("an empty subscription has not lapsed", lapsed({}, NOW), False)

# A LIVE PLAN PAST ITS PERIOD END IS A RENEWAL, NOT AN EXPIRY. Treating a missed
# renewal as a downgrade would cut off paying customers the moment a real processor
# was slow with a webhook, so only an explicit cancellation ends a plan here.
check("an uncancelled plan past its end has not lapsed",
      lapsed(subscription(cancel=False, ends_in_days=-30), NOW), False)

check("cancelled with time left has not lapsed",
      lapsed(subscription(cancel=True, ends_in_days=10), NOW), False)
check("cancelled and past its end HAS lapsed",
      lapsed(subscription(cancel=True, ends_in_days=-1), NOW), True)
check("cancelled at the exact boundary has lapsed",
      lapsed(subscription(cancel=True, ends_in_days=0), NOW), True)

# NO END DATE MEANS IMMEDIATE. There is no later moment to defer to, so holding the
# entitlement open would hold it open forever.
check("cancelled with no end date has lapsed",
      lapsed({"cancelAtPeriodEnd": True, "planId": "starter"}, NOW), True)
check("cancelled with a non-date end has lapsed",
      lapsed({"cancelAtPeriodEnd": True, "currentPeriodEnd": "soon"}, NOW), True)

# The naive-datetime pair. Both must answer without raising.
check("naive past date lapses",
      lapsed(subscription(cancel=True, ends_in_days=-1, aware=False), NOW), True)
check("naive future date does not lapse",
      lapsed(subscription(cancel=True, ends_in_days=10, aware=False), NOW), False)

# --- the plan a user is actually on ------------------------------------------

before = {"id": "u1", "planId": "starter",
          "subscription": subscription(cancel=True, ends_in_days=10)}
after = {"id": "u1", "planId": "starter",
         "subscription": subscription(cancel=True, ends_in_days=-1)}

check("inside the paid period the plan is Starter",
      billing.effective_plan_for_user(before, NOW)["id"], "starter")
check("after it the plan is Free",
      billing.effective_plan_for_user(after, NOW)["id"], "free")

# plan_for_user is UNCHANGED and still answers what the record says. Two functions
# with one clear difference, rather than one with a boolean argument - and the
# checkout endpoint still wants the stored answer.
check("plan_for_user still reads the record",
      billing.plan_for_user(after)["id"], "starter")

check("the subscription survives inside the period",
      billing.effective_subscription(before["subscription"], NOW) is None, False)
check("and is gone once it lapses",
      billing.effective_subscription(after["subscription"], NOW), None)

# An account that predates billing entirely: no planId, no subscription.
check("a legacy account resolves to Free",
      billing.effective_plan_for_user({"id": "old"}, NOW)["id"], "free")


# ============================================================================
print("\n--- 7. The card code really did leave billing.py -----------------------")
# ============================================================================

# The move is the point of the refactor, so it is asserted rather than assumed. A
# re-added shim in billing.py would make the seam decorative.
for gone in ("card_problem", "describe_card", "passes_luhn", "card_brand",
             "expiry_is_future"):
    check(f"billing no longer has {gone}", hasattr(billing, gone), False)

for present in ("card_problem", "describe_card", "passes_luhn", "card_brand",
                "expiry_is_future"):
    check(f"payments.mock_card has {present}", hasattr(mock_card, present), True)

# And the half that survives a real processor is untouched.
for kept in ("PLANS", "find_plan", "plan_for_user", "public_plan", "format_amount",
             "period_end", "DEFAULT_PLAN_ID", "BILLING_PERIOD_DAYS"):
    check(f"billing still has {kept}", hasattr(billing, kept), True)

check("prices are unchanged", STARTER["amountCents"], 4900)
check("business is unchanged", billing.find_plan("business")["amountCents"], 14900)
check("period is 30 days", billing.period_end(STARTER, NOW), NOW + timedelta(days=30))
check("free has no period", billing.period_end(FREE, NOW), None)
check("formatting is unchanged", billing.format_amount(4900), "$49.00")




# ============================================================================
print("\n--- 9. A signature that PASSES, and the window it expires in ----------")
# ============================================================================
# NOTHING PREVIOUSLY TESTED A SIGNATURE THAT PASSES. Section 4 checks that a missing
# header returns None, which proves a guard exists and proves nothing about the
# arithmetic behind it - a verifier that rejected everything would have satisfied
# every assertion in this file. So this section signs bodies the way Paddle does and
# pins both answers.

_SECRET = "test_secret"

config.PADDLE_CLIENT_TOKEN = "test_token"
config.PADDLE_API_KEY = "test_key"
config.PADDLE_WEBHOOK_SECRET = _SECRET
config.paddle_price_id = lambda plan_id: "pri_test"


def _sign(body, ts=None, secret=_SECRET, extra_h1=()):
    """Build a Paddle-Signature header the way Paddle does: a ts, then an h1 over
    `ts:body`. `extra_h1` prepends decoy digests, which is what a key rotation
    looks like on the wire."""
    stamp = str(int((ts or datetime.now(timezone.utc)).timestamp()))
    digest = _hmac.new(
        secret.encode("utf-8"),
        stamp.encode("utf-8") + b":" + body,
        _hashlib.sha256,
    ).hexdigest()
    return ";".join([f"ts={stamp}"] + [f"h1={h}" for h in extra_h1] + [f"h1={digest}"])


_EVENT = {
    "event_id": "evt_01",
    "event_type": "transaction.completed",
    "data": {
        "id": "txn_555",
        "subscription_id": "sub_1",
        "custom_data": {"user_id": "u1", "plan_id": "starter"},
    },
}
_BODY = _json.dumps(_EVENT).encode("utf-8")

_wh = paddle.PaddleProvider()


def _hook(header, body=_BODY):
    return run(_wh.handle_webhook(headers={"paddle-signature": header}, body=body))


_good = _hook(_sign(_BODY))
check("a valid signature is accepted", _good is not None, True)
check("  and the event is dispatched", _good["action"], "grant_plan")
check("  carrying the event id de-duplication needs", _good["event_id"], "evt_01")
check("  and the user from custom_data", _good["user_id"], "u1")
check("  and the transaction id the order stores", _good["transaction_id"], "txn_555")

# THE BYTES ARE WHAT IS SIGNED, which is why the endpoint takes a raw Request and
# not a parsed model. One altered byte is the whole assertion.
check("a tampered body is refused", _hook(_sign(_BODY), _BODY.replace(b"u1", b"u2")), None)
check("the wrong secret is refused", _hook(_sign(_BODY, secret="not_it")), None)
check("a header with no h1 is refused", _hook("ts=1700000000"), None)

# KEY ROTATION. Paddle sends several h1 components while two keys are live and only
# one is ours. Matching ANY is the requirement; matching only the first would break
# every delivery for the length of a rotation.
check("a rotation with decoy digests still verifies",
      _hook(_sign(_BODY, extra_h1=("0" * 64, "f" * 64))) is not None, True)

# FRESHNESS. A signature that never expires is a replay credential: one captured
# transaction.completed body, re-POSTed, is another thirty days - every time.
check("a two-hour-old signature is refused",
      _hook(_sign(_BODY, ts=datetime.now(timezone.utc) - timedelta(hours=2))), None)

# The same hole with the sign flipped. A signature minted against a forward-dated ts
# would otherwise stay replayable until that date arrived.
check("a future-dated signature is refused",
      _hook(_sign(_BODY, ts=datetime.now(timezone.utc) + timedelta(hours=2))), None)

# Just inside the window still works, so the window is a window and not a wall.
check("a one-minute-old signature is accepted",
      _hook(_sign(_BODY, ts=datetime.now(timezone.utc) - timedelta(seconds=60))) is not None,
      True)

check("an unparseable ts is refused", _hook("ts=nonsense;h1=" + "a" * 64), None)
check("_timestamp_is_fresh refuses an empty ts", paddle._timestamp_is_fresh(""), False)
check("  and the window is five minutes", paddle._SIGNATURE_MAX_AGE_SECONDS, 300.0)
check("valid JSON is still required after a good signature",
      _hook(_sign(b"not json"), b"not json"), None)


# ============================================================================
print("\n--- 10. Production selects the live API base --------------------------")
# ============================================================================
# A one-line mapping, and the line that decides whether a charge is real money. It
# earns a test because its failure is silent in the direction that matters: a live
# deployment still pointed at sandbox-api.paddle.com takes no money and looks fine
# doing it.

_saved_sb = config.PADDLE_SANDBOX

config.PADDLE_SANDBOX = True
check("sandbox targets the sandbox API",
      paddle.PaddleProvider()._api_base, "https://sandbox-api.paddle.com")
check("  and reports sandbox to the browser",
      paddle.PaddleProvider()._environment, "sandbox")

config.PADDLE_SANDBOX = False
check("production targets the live API",
      paddle.PaddleProvider()._api_base, "https://api.paddle.com")
check("  and reports production to the browser",
      paddle.PaddleProvider()._environment, "production")

config.PADDLE_SANDBOX = _saved_sb


# ============================================================================
print("\n--- 11. One payment writes one order, however often it is delivered ---")
# ============================================================================
# THE DEFECT THIS SECTION EXISTS FOR. Paddle guarantees at-least-once delivery and
# retries anything that has not answered 200 within five seconds, so a slow reply
# does not lose an event - it duplicates one. Before the claim, each delivery of one
# transaction.completed wrote another receipt and re-ran set_user_plan with a fresh
# thirty-day period: one sale, N orders, and a subscription extending itself every
# time the network hiccuped.
#
# THIS DRIVES THE REAL ENDPOINT. Re-implementing the claim over a dict would test a
# copy of the logic and pass happily while main.py did something else - so main is
# imported and its collaborators are swapped, which is the pattern test_reset.py
# already uses. The import is here rather than at the top because it is heavy and
# only this section needs it.
import main  # noqa: E402

_RealStorageError = main.database.StorageError


class _FakeDatabase:
    """Only the five calls the webhook path makes. `fail_on` names a method that
    should raise StorageError, which is how the transient-blip cases are driven."""

    StorageError = _RealStorageError

    def __init__(self, fail_on=""):
        self.claims = set()
        self.orders = []
        self.plans = []
        self.released = []
        self.fail_on = fail_on

    async def claim_webhook_event(self, event_id, provider=""):
        if self.fail_on == "claim":
            raise _RealStorageError("claim is down")
        # THE INSERT IS THE TEST, exactly as the unique _id makes it in Mongo -
        # not a read followed by a write, which leaves a window two concurrent
        # deliveries both pass through.
        if event_id in self.claims:
            return False
        self.claims.add(event_id)
        return True

    async def release_webhook_event(self, event_id):
        self.released.append(event_id)
        self.claims.discard(event_id)

    async def create_order(self, order):
        if self.fail_on == "create_order":
            raise _RealStorageError("mongo blipped")
        self.orders.append(order)

    async def set_user_plan(self, user_id, plan_id, subscription):
        self.plans.append((user_id, plan_id, subscription))

    async def find_user_by_id(self, user_id):
        return {"id": user_id, "email": "ada@example.com"}


class _FakePayments:
    """main.py reaches through the module for both of these."""

    @staticmethod
    def get_provider():
        return _wh

    @staticmethod
    def provider_name():
        return "paddle"


class _FakeRequest:
    def __init__(self, body, header):
        self._body = body
        self.headers = {"paddle-signature": header}

    async def body(self):
        return self._body


@contextmanager
def _mounted(db):
    previous = (main.database, main.payments)
    main.database, main.payments = db, _FakePayments()
    try:
        yield db
    finally:
        main.database, main.payments = previous


def _deliver(db, body=_BODY, header=None):
    """One webhook delivery through the real route. Returns the response dict, or
    the HTTP status for the paths that raise."""
    with _mounted(db):
        try:
            return run(main.billing_webhook(_FakeRequest(body, header or _sign(body))))
        except HTTPException as error:
            return {"status": error.status_code}


_db = _FakeDatabase()

check("the first delivery grants", _deliver(_db)["action"], "grant_plan")
check("  and writes one order", len(_db.orders), 1)
check("  and sets the plan once", len(_db.plans), 1)
check("  recording the paddle transaction id", _db.orders[0]["providerRef"], "txn_555")
check("  with the price from the catalogue, not the payload",
      _db.orders[0]["amountCents"], STARTER["amountCents"])

check("the second delivery is a duplicate", _deliver(_db)["action"], "duplicate")
check("the third delivery is a duplicate", _deliver(_db)["action"], "duplicate")
check("  and the order count never moved", len(_db.orders), 1)
check("  and the plan was not re-granted", len(_db.plans), 1)

# A DIFFERENT event still writes - the claim de-duplicates, it does not block.
_other = dict(_EVENT, event_id="evt_02")
_other_body = _json.dumps(_other).encode("utf-8")
check("a different event still grants", _deliver(_db, _other_body)["action"], "grant_plan")
check("  so two events wrote two orders", len(_db.orders), 2)

# THE FAILED-WRITE PATH, and the reason the release exists. A claim held by a
# delivery that then failed to write would suppress every retry of the only event
# that could fix it - a charged customer with no order and no code path left to
# produce one. 503 asks Paddle to redeliver; the release makes the redelivery
# something other than a duplicate.
_blip = _FakeDatabase(fail_on="create_order")
check("a failed write asks for a retry", _deliver(_blip)["status"], 503)
check("  and wrote no order", len(_blip.orders), 0)
check("  and released the claim", _blip.released, ["evt_01"])
check("  so the claim is free again", "evt_01" in _blip.claims, False)

_blip.fail_on = ""
check("  and the redelivery succeeds", _deliver(_blip)["action"], "grant_plan")
check("  writing the order the customer paid for", len(_blip.orders), 1)

# A claim that cannot be READ is not a claim that says "no". Guessing either way is
# wrong, so the endpoint declines to guess and asks for the event again.
check("an unreadable claim asks for a retry too",
      _deliver(_FakeDatabase(fail_on="claim"))["status"], 503)

# A bad signature never reaches the claim at all.
_unsigned = _FakeDatabase()
check("a bad signature is ignored, not claimed",
      _deliver(_unsigned, header="ts=1;h1=" + "a" * 64)["action"], "ignored")
check("  and nothing was claimed", len(_unsigned.claims), 0)
check("  and nothing was written", len(_unsigned.orders), 0)


print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
raise SystemExit(1 if FAIL_COUNT else 0)
