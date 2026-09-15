"""
BILLING.PY - the plan catalogue and the subscription calendar, with no HTTP in
sight and, as of this session, no card code either.

WHAT THIS FILE USED TO BE, BECAUSE THE CHANGE IS THE INTERESTING PART
It held two things: the plan catalogue and the card checks. Its own header said
what would eventually happen to the second half - "when this becomes real, the
card fields stop being posted to us at all ... and this module keeps the plan
catalogue and loses the card functions entirely." That is now done, and it was
done BEFORE a real processor arrived rather than during the migration, which is
the only time it is a cheap change. Luhn, expiry parsing, brand detection and
describe_card all live in payments/mock_card.py, behind the interface in
payments/base.py.

So the split this file was always going to need is the split it has:

  billing.py           WHAT CAN BE BOUGHT and FOR HOW LONG. A policy list plus
                       calendar arithmetic. Belongs on the SERVER for a reason
                       given at length under PLANS below.
  payments/            WHETHER A PAYMENT HAPPENED. One interface, one mock that
                       grants on a checksum, one honest skeleton for Paddle.

Neither needs FastAPI, pymongo or a request object, so neither is in main.py. The
same reasoning that keeps auth.py separate: a security-relevant check with a small
number of load-bearing steps should be readable on its own.

WHAT THIS IS STILL NOT, AND THE HONESTY MATTERS MORE HERE THAN ANYWHERE ELSE IN
THE APP
There is no payment processor behind any of this. Nothing in SecuScan contacts a
bank, an acquirer, Stripe or Paddle, and no money moves when a checkout succeeds.
What `POST /billing/checkout` does is validate a card's SHAPE, record an order in
our own database, and grant the plan - a complete, working purchase cycle against
our own records and a completely fictional one against anybody's money. The full
version of that warning, including why a Luhn-valid number is not an authorised
one, is at the top of payments/mock_card.py, which is the file that does it.

WHAT IS STILL HERE, and it is the half that survives a real processor unchanged:
the price list, the whitelist that publishes it, money formatting, how long a
period lasts, and - added this session - when a cancelled plan actually ends.
"""

from datetime import datetime, timedelta, timezone


# ============================================================================
# THE PLAN CATALOGUE
#
# WHY THE PRICES LIVE HERE AND NOT IN THE REACT BUNDLE
# frontend/src/lib/pricing.js has the same four plans in it, and that is not the
# duplication it looks like. That file is MARKETING COPY - the taglines, the
# feature bullets, which card gets the "Most popular" ribbon. This file is the
# PRICE, and the price has to be the server's opinion for one blunt reason: the
# amount charged must not be a number the client sent.
#
# The failure that follows from getting this wrong is a single line of curl.
# `POST /billing/checkout {"planId": "business", "amountCents": 1}` succeeds
# against any endpoint that trusts a client-supplied amount, and every checkout
# implementation that has ever been exploited this way looked reasonable first.
# So the request body names a plan, this table decides what a plan costs, and
# there is no field in the request that can influence the figure.
#
# The frontend still gets these numbers - GET /billing/plans serves them - which
# is what keeps the displayed price and the charged price the same value rather
# than two values that agree today.
# ============================================================================

# WHY CENTS AND NOT DOLLARS: floating point cannot represent 49.99, so a float
# price is a rounding error waiting for a large enough invoice. Integer minor
# units are what payment systems use, universally, for exactly this reason.
PLANS = [
    {
        "id": "free",
        "name": "Free",
        "amountCents": 0,
        "currency": "USD",
        "interval": "forever",
        # The CHECK DEPTH from the spec, not a billing concept - see the note at
        # the top of frontend/src/lib/pricing.js. Several plans can grant one tier.
        "tier": 1,
        "scanLimit": 1,
        "siteLimit": 1,
        # Whether this plan is bought with a card at all. Free needs no payment and
        # Enterprise is a conversation, so neither is purchasable - and that is a
        # property of the plan rather than a special case in the endpoint.
        "purchasable": False,
    },
    {
        "id": "starter",
        "name": "Starter",
        "amountCents": 4900,
        "currency": "USD",
        "interval": "month",
        "tier": 2,
        "scanLimit": 10,
        "siteLimit": 1,
        "purchasable": True,
    },
    {
        "id": "business",
        "name": "Business",
        "amountCents": 14900,
        "currency": "USD",
        "interval": "month",
        "tier": 2,
        # None rather than a very large number. "Unlimited" is a real state and a
        # sentinel like 999999 is a limit somebody eventually hits.
        "scanLimit": None,
        "siteLimit": 10,
        "purchasable": True,
    },
    {
        "id": "enterprise",
        "name": "Enterprise",
        # No amount at all. Not 0, which would mean free, and not a guess - the
        # price genuinely does not exist until somebody has talked to a customer.
        "amountCents": None,
        "currency": "USD",
        "interval": "custom",
        "tier": 2,
        "scanLimit": None,
        "siteLimit": None,
        "purchasable": False,
    },
]

# The plan every account starts on, and the one a cancellation returns to.
DEFAULT_PLAN_ID = "free"

# PYTHON-SPECIFIC: a dict comprehension, built once at import. Lookup by id
# happens on every checkout and every subscription read, and scanning a
# four-element list each time would be fine - this is for readability at the call
# site, where `find_plan(id)` says what it means.
_PLANS_BY_ID = {plan["id"]: plan for plan in PLANS}


# WHY THIS EXISTS
# Turns a plan id from a request into the plan, or None. The one place that knows
# an unknown id is not an error worth raising here - the endpoint decides what to
# do about it, because only the endpoint knows what status code to answer with.
def find_plan(plan_id: str) -> dict | None:
    return _PLANS_BY_ID.get((plan_id or "").strip().lower())


# WHY THIS EXISTS
# The plan a user is on, resolved safely. Reads the field the checkout wrote and
# falls back to Free.
#
# THE FALLBACK IS LOAD-BEARING, not defensive noise. Every account created before
# billing existed has no plan field at all, and a KeyError on the dashboard for
# every one of them is a worse outcome than showing Free - which is also the
# truth, since they have paid nothing. It also covers a plan being retired from
# the catalogue while somebody is still on it.
def plan_for_user(user: dict) -> dict:
    return find_plan(user.get("planId") or "") or _PLANS_BY_ID[DEFAULT_PLAN_ID]


# WHY THIS EXISTS
# The public shape of a plan. Everything in PLANS is already public - there is no
# secret in a price list - so this is a copy rather than a filter, and it exists
# to give the frontend one stable contract instead of the raw table.
#
# It stays a whitelist anyway, for the same reason _public_user in main.py is one:
# a field added to PLANS later (an internal margin note, a processor's price id)
# is absent from responses by default instead of exposed until somebody remembers.
def public_plan(plan: dict) -> dict:
    return {
        "id": plan["id"],
        "name": plan["name"],
        "amountCents": plan["amountCents"],
        "currency": plan["currency"],
        "interval": plan["interval"],
        "tier": plan["tier"],
        "scanLimit": plan["scanLimit"],
        "siteLimit": plan["siteLimit"],
        "purchasable": plan["purchasable"],
    }


# WHY THIS EXISTS
# "$49.00" from 4900. Formatting money is the kind of thing that gets written
# inline four times and then disagrees with itself, so it is one function - used
# by the receipt email and by nothing else on the server, since the frontend
# formats its own.
#
# PYTHON-SPECIFIC: divmod returns the quotient and remainder in one call, which is
# exactly the dollars-and-cents split. The f-string's `:02d` pads the cents, so
# 4905 renders "$49.05" rather than "$49.5".
def format_amount(amount_cents: int | None, currency: str = "USD") -> str:
    if amount_cents is None:
        return "Custom pricing"

    dollars, cents = divmod(int(amount_cents), 100)

    symbol = "$" if currency.upper() == "USD" else f"{currency.upper()} "

    return f"{symbol}{dollars:,}.{cents:02d}"


# ============================================================================
# THE SUBSCRIPTION PERIOD
# ============================================================================

# A month, as a number of days. WHY NOT CALENDAR MONTHS: "one month after the 31st
# of January" has no answer, and every codebase that tries to compute one grows a
# small pile of special cases. A fixed 30-day period is unambiguous, is what plenty
# of real subscription products use, and never lands on a date that does not exist.
BILLING_PERIOD_DAYS = 30


# WHY THIS EXISTS
# When the plan just bought runs out. Returns None for a plan with no interval -
# Free does not expire, and neither does an Enterprise agreement negotiated
# elsewhere.
#
# `started` is passed in rather than read from the clock here, so the order and
# the subscription it creates agree to the microsecond. Two calls to now() a few
# lines apart is the kind of drift that makes a support conversation impossible.
def period_end(plan: dict, started: datetime) -> datetime | None:
    if plan.get("interval") != "month":
        return None

    return started + timedelta(days=BILLING_PERIOD_DAYS)


# ============================================================================
# WHEN A CANCELLED PLAN ACTUALLY ENDS
#
# WHY THIS SECTION EXISTS AT ALL, AND WHY IT IS PURE FUNCTIONS
# `POST /billing/cancel` used to downgrade the account immediately, and the comment
# on that endpoint argued for it honestly: end-of-period cancellation is the kinder
# behaviour, but it needs something running on a schedule to do the downgrade when
# the date arrives, and a `cancelAtPeriodEnd` flag with nothing to honour it is
# worse than not offering it, because the account keeps its entitlements forever.
#
# THAT ARGUMENT HAD A HOLE IN IT, which is what this section is. The flag does not
# need a scheduler - it needs the READ to be period-aware. Nothing consults a
# subscription except in the course of answering a request, and every one of those
# requests knows what time it is. So "has this lapsed?" is a comparison done at read
# time, and the account is correct on every single read with nothing running in the
# background at all.
#
# A scheduler would still be nice for tidiness (it would keep the stored record in
# step with reality) and it is still not required for CORRECTNESS. The endpoints do
# an opportunistic tidy-up instead - see the note on reconciliation in main.py -
# and if that write never happens, the answers stay right regardless.
#
# BOTH FUNCTIONS ARE PURE AND TAKE `now`. No database, no clock of their own. That
# is what makes "the plan a week from now" a test rather than a system-clock
# experiment, and it is the same reason period_end() above takes `started`.
# ============================================================================


# WHY THIS EXISTS
# The one comparison the whole scheme rests on: is this subscription over?
#
# THE THREE WAYS IT CAN ANSWER FALSE ARE ALL DELIBERATE:
#   - No subscription at all. Nothing to lapse; the account is already Free.
#   - Not cancelled. A live subscription past its period end is a RENEWAL, not an
#     expiry, and treating a missed renewal as a downgrade would silently cut off
#     paying customers the moment a real processor was slow with a webhook. Only an
#     explicit cancellation ends a plan here.
#   - Cancelled but with no end date. Free and Enterprise have no monthly interval,
#     so period_end() returned None for them - see below for why that means "now".
def subscription_has_lapsed(
    subscription: dict | None, now: datetime | None = None
) -> bool:
    if not subscription:
        return False

    if not subscription.get("cancelAtPeriodEnd"):
        return False

    period_ends = subscription.get("currentPeriodEnd")

    # NO END DATE MEANS THE CANCELLATION IS IMMEDIATE. A plan with no interval has
    # no period to run out, so there is no later moment to defer to and holding the
    # entitlement open would hold it open forever. Falling back to "now" is the only
    # reading that terminates.
    if not isinstance(period_ends, datetime):
        return True

    reference = now or datetime.now(timezone.utc)

    # PYTHON-SPECIFIC: pymongo returns datetimes NAIVE - no tzinfo - even though it
    # stored them as UTC, and comparing a naive datetime with an aware one raises
    # TypeError rather than guessing. So the stored value is re-labelled as UTC,
    # which is what it always was. Getting this wrong is not a wrong answer, it is
    # a 500 on the billing screen.
    if period_ends.tzinfo is None:
        period_ends = period_ends.replace(tzinfo=timezone.utc)

    return period_ends <= reference


# WHY THIS EXISTS
# The plan a user is ACTUALLY on, right now - which is plan_for_user() plus the
# question above. Every read path uses this, so /auth/me and /billing/subscription
# cannot disagree about whether a cancelled plan has run out.
#
# WHY plan_for_user() STAYS AND IS NOT SIMPLY REPLACED: it answers "what does the
# stored record say", which is still the right question in one place - the checkout
# endpoint, which is about to overwrite that record anyway. Two functions with one
# clear difference beats one function with a boolean argument.
def effective_plan_for_user(user: dict, now: datetime | None = None) -> dict:
    if subscription_has_lapsed(user.get("subscription"), now):
        return _PLANS_BY_ID[DEFAULT_PLAN_ID]

    return plan_for_user(user)


# WHY THIS EXISTS
# The subscription as a READER should see it, with a status that reflects the clock.
# A lapsed subscription is reported as "ended" rather than as the "cancelling" the
# database still says, so the billing screen does not offer to resume something that
# is already over.
#
# Returns None once the subscription has lapsed AND the caller wants the account to
# look Free - which is every caller, because a subscription block describing a plan
# the user no longer has is the confusion this whole section removes. The ORDERS
# survive, and they are what the billing history is built from.
def effective_subscription(
    subscription: dict | None, now: datetime | None = None
) -> dict | None:
    if not subscription:
        return None

    if subscription_has_lapsed(subscription, now):
        return None

    return subscription


# WHY THIS EXISTS
# Determines the start of the user's current billing period for quota enforcement.
# For accounts with an active subscription (currentPeriodEnd is in the future),
# the current period starts BILLING_PERIOD_DAYS (30 days) before currentPeriodEnd.
# For Free accounts or accounts without an active subscription, a rolling 30-day
# window (now - BILLING_PERIOD_DAYS) is used, matching the "1 scan per month"
# cadence promised for Free.
def get_billing_period_start(user: dict, now: datetime | None = None) -> datetime:
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)

    sub = user.get("subscription")
    if isinstance(sub, dict):
        period_ends = sub.get("currentPeriodEnd")
        if isinstance(period_ends, str):
            try:
                period_ends = datetime.fromisoformat(period_ends)
            except ValueError:
                period_ends = None
        if isinstance(period_ends, datetime):
            if period_ends.tzinfo is None:
                period_ends = period_ends.replace(tzinfo=timezone.utc)
            if period_ends > reference:
                return period_ends - timedelta(days=BILLING_PERIOD_DAYS)

    return reference - timedelta(days=BILLING_PERIOD_DAYS)

