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
from datetime import datetime, timedelta, timezone

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
# create_checkout with fake credentials hits the real Paddle API, which rejects the
# key - so it returns a REFUSED outcome rather than granting. That is the correct
# behaviour: no plan is given away, and no NotImplementedError is thrown either.
#
# handle_webhook with no Paddle-Signature header returns None - signature
# verification is the first check, and a missing header means nothing is processed.
config.PADDLE_CLIENT_TOKEN = "test_token"
config.PADDLE_API_KEY = "test_key"
config.PADDLE_WEBHOOK_SECRET = "test_secret"
config.paddle_price_id = lambda plan_id: "pri_test"

check("with credentials, nothing is missing", paddle.missing_credentials(), [])

built = paddle.PaddleProvider()
check("and it builds", built.name, "paddle")

checkout_result = run(built.create_checkout(plan=STARTER, user={"id": "u1"}, card=card(), now=NOW))
check("create_checkout does not grant on fake credentials",
      checkout_result.status == "granted", False)
check("create_checkout refuses or pends (not a giveaway)",
      checkout_result.status in ("refused", "pending"), True)

webhook_result = run(built.handle_webhook(headers={}, body=b"{}"))
check("handle_webhook returns None with no signature",
      webhook_result, None)


# ============================================================================
print("\n--- 5. Selection never falls back to the mock --------------------------")
# ============================================================================

_saved_name = config.PAYMENT_PROVIDER

config.PAYMENT_PROVIDER = "mock"
check("mock is selected by name", payments._build_provider().name, "mock")

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
(
    config.PADDLE_CLIENT_TOKEN,
    config.PADDLE_API_KEY,
    config.PADDLE_WEBHOOK_SECRET,
    config.paddle_price_id,
) = _saved
check("the real configuration is the mock", payments.provider_name(), "mock")
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


print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
raise SystemExit(1 if FAIL_COUNT else 0)
