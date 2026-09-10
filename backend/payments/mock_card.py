"""
PAYMENTS/MOCK_CARD.PY - the card checks, and the provider that grants a plan
without charging anybody.

WHY THIS FILE EXISTS, AND WHY IT IS THE ONE THAT GETS DELETED
Everything here is a stand-in. It validates that a card number is well-FORMED and
then grants the plan, which is a complete purchase cycle against our own database
and a completely fictional one against anybody's money. The header of billing.py
made this point at length and it is worth repeating in the file that does it:

  - A card number that passes every check below has NOT been authorised. Luhn is a
    checksum designed to catch a mistyped digit; it says nothing about whether an
    account exists or has funds. `4242424242424242` passes. So does a number
    somebody invented that happens to check out.
  - Taking a real card number on a real site and processing it this way is not
    something to do. It is PCI DSS scope with no processor to hand the scope to.

When a real processor is wired in, this module is not edited - it is DELETED, along
with the four card fields on CheckoutRequest in main.py. The processor's own iframe
collects the number, we never see it, and the questions this file answers stop
being ours to ask. That is what the seam in base.py is for.

WHY THE CARD FUNCTIONS ARE HERE RATHER THAN IN billing.py
They used to be in billing.py, which meant the plan catalogue and the payment
mechanism lived in one file and would have had to be separated during the
migration - the worst possible time. billing.py is now the catalogue: what can be
bought, what it costs, how long a period lasts. This is the mechanism, and it is
one `git rm` away from gone.

NOTHING IN THIS FILE LOGS, and that is not an oversight to be tidied up later. A
card number in a log file is a card number in every backup, every log aggregator
and every laptop that has ever run `tail` against it. The functions take a number
and return a verdict; the number goes nowhere else.
"""

import re
import uuid
from datetime import datetime, timezone

from .base import CheckoutOutcome, PaymentProvider


# Minimum and maximum digit counts across the brands in the wild. Visa is 13 or
# 16, Amex 15, Mastercard 16, UnionPay up to 19. A range rather than a per-brand
# rule, because the brand table below is a display convenience and must not become
# the thing that decides whether a real card is accepted.
_CARD_MIN_DIGITS = 13
_CARD_MAX_DIGITS = 19

# BRAND BY LEADING DIGITS, in the order they are tested - and the order matters,
# because some prefixes are prefixes of others. The patterns are deliberately
# loose: this only picks the logo to show and the CVC length to expect, so a card
# that matches nothing is "Card" and is still accepted.
_BRANDS = [
    ("Visa", r"^4"),
    ("Mastercard", r"^(5[1-5]|2[2-7])"),
    ("American Express", r"^3[47]"),
    ("Discover", r"^(6011|64[4-9]|65)"),
    ("Diners Club", r"^3(0[0-5]|[68])"),
    ("JCB", r"^35(2[89]|[3-8])"),
    ("UnionPay", r"^62"),
]

# Amex prints four digits on the front; everyone else prints three on the back.
_AMEX_CVC_DIGITS = 4
_DEFAULT_CVC_DIGITS = 3


# WHY THIS EXISTS
# One spelling of a card number. People type spaces, hyphens, and the groups the
# card itself is printed in - none of which should decide whether a payment form
# works. The same reasoning as normalise_recovery_code in auth.py: normalising in
# one function shared by every check is what stops "my card is valid, the site
# says it isn't".
def _digits_only(value: str) -> str:
    return re.sub(r"\D", "", value or "")


# WHY THIS EXISTS
# The Luhn checksum, which is the only mathematical property a card number has.
#
# HOW IT WORKS, because it looks arbitrary until it does not: walk the digits from
# the right, double every second one, and where doubling gives a two-digit result
# add those two digits together. A valid number's total is divisible by 10. It is
# a 1954 patent designed to catch exactly two kinds of human error - one wrong
# digit, and two adjacent digits swapped - which between them are most of the
# mistakes anyone makes copying a number off a card.
#
# WHAT IT DOES NOT DO, and the reason the file header labours the point: it is
# arithmetic on the digits. There is no bank involved, no account, no balance.
# A number that satisfies Luhn is well-formed, not funded.
#
# PYTHON-SPECIFIC: `reversed()` walks the string right to left without building a
# copy, and enumerate supplies the position so "every second digit" is a parity
# test rather than an index dance.
def passes_luhn(number: str) -> bool:
    digits = _digits_only(number)

    if not digits:
        return False

    total = 0

    for position, character in enumerate(reversed(digits)):
        digit = int(character)

        # Every second digit counting from the right, which is position 1, 3, 5...
        if position % 2 == 1:
            digit *= 2

            # 14 becomes 1 + 4. Subtracting 9 is the same operation and is the form
            # the algorithm is usually written in - worth recognising rather than
            # rederiving.
            if digit > 9:
                digit -= 9

        total += digit

    return total % 10 == 0


# WHY THIS EXISTS
# The brand, for the receipt and the saved order. A display concern with one
# functional consequence: Amex expects a 4-digit CVC, so the brand has to be known
# before the CVC can be checked.
def card_brand(number: str) -> str:
    digits = _digits_only(number)

    for name, pattern in _BRANDS:
        if re.match(pattern, digits):
            return name

    # An unrecognised prefix is not a rejection. New ranges are issued, and a
    # brand table that refuses anything it has not heard of is a table that starts
    # declining real cards. "Card" is honest and the payment proceeds.
    return "Card"


# WHY THIS EXISTS
# Splits "12/28" or "12/2028" or "1228" into a month and a full year, or returns
# None. Separated from the expiry CHECK below because the two questions are
# different - "is this even a date" and "is that date in the future" - and a
# function that answered both would have to return a verdict and a value.
#
# PYTHON-SPECIFIC: a tuple return unpacked at the call site. The `| None` in the
# annotation is modern Python for Optional.
def _parse_expiry(expiry: str) -> tuple[int, int] | None:
    digits = _digits_only(expiry)

    # 4 digits is MMYY, 6 is MMYYYY. Both take the month from the first two, which
    # is why the branches look identical - the difference is handled by the
    # two-digit-year rule below.
    if len(digits) in {4, 6}:
        month, year = int(digits[:2]), int(digits[2:])

    # 3 and 5 digits are the same two forms with the month's leading zero left off,
    # which is how a person types March: "3/29". There is no ambiguity to worry
    # about - reading the first TWO digits of "329" gives month 32, which is not a
    # month, so a single-digit month is the only reading that parses at all.
    elif len(digits) in {3, 5}:
        month, year = int(digits[:1]), int(digits[1:])

    else:
        return None

    if not 1 <= month <= 12:
        return None

    # A two-digit year means this century. "28" is 2028, and there is no reading of
    # a card expiry under which it means 1928 - cards are issued with a horizon of
    # a few years, so the ambiguity a two-digit year usually carries does not exist
    # here.
    if year < 100:
        year += 2000

    return month, year


# WHY THIS EXISTS
# Whether an expiry is in the future. A card is valid through the END of its
# printed month - a card marked 09/26 works on the 30th of September 2026 - which
# is the detail this gets right and a naive comparison against the 1st does not.
#
# The horizon check catches a typed year that is plainly wrong (2099) without
# refusing a legitimately long-dated card.
def expiry_is_future(expiry: str, now: datetime | None = None) -> bool:
    parsed = _parse_expiry(expiry)

    if parsed is None:
        return False

    month, year = parsed

    # PYTHON-SPECIFIC: the default is None and the real default is computed inside,
    # because a datetime.now() written in the signature would be evaluated ONCE at
    # import and freeze the clock at server start. A mutable or time-based default
    # argument is one of Python's genuinely famous traps.
    reference = now or datetime.now(timezone.utc)

    if year > reference.year + 20:
        return False

    if year < reference.year:
        return False

    if year == reference.year and month < reference.month:
        return False

    return True


# WHY THIS EXISTS
# The whole card, checked, with a sentence naming the FIRST thing wrong. Returns
# None when there is nothing wrong.
#
# WHY IT RETURNS A MESSAGE RATHER THAN A BOOLEAN: this mirrors
# auth.password_problem(), and for the same reason. "Your card details are
# invalid" on a form with four fields is a dead end, and a caller handed a
# boolean has nothing better to say. Naming the field is the difference between a
# user fixing a typo and a user giving up.
#
# ONE PROBLEM AT A TIME is deliberate, and the opposite of what postPublic in
# api.js does with validation errors. A payment form is four fields the user is
# looking straight at; listing every fault at once reads as an interrogation,
# where a password policy genuinely benefits from stating all its rules.
def card_problem(number: str, expiry: str, cvc: str, name: str) -> str | None:
    if not (name or "").strip():
        return "Enter the name printed on the card."

    digits = _digits_only(number)

    if not digits:
        return "Enter your card number."

    if not _CARD_MIN_DIGITS <= len(digits) <= _CARD_MAX_DIGITS:
        return (
            f"A card number is between {_CARD_MIN_DIGITS} and {_CARD_MAX_DIGITS} "
            "digits. Check for a missing or extra digit."
        )

    if not passes_luhn(digits):
        # The wording says "check" rather than "invalid" on purpose. Luhn failing
        # means a digit is wrong, and the useful instruction is to look again -
        # not to conclude the card does not work.
        return "That card number is not valid. Check the digits and try again."

    if not (expiry or "").strip():
        return "Enter the expiry date from the front of the card."

    if _parse_expiry(expiry) is None:
        return "Enter the expiry date as MM/YY."

    if not expiry_is_future(expiry):
        return "That card has expired. Use a card with a future expiry date."

    cvc_digits = _digits_only(cvc)

    expected = (
        _AMEX_CVC_DIGITS
        if card_brand(digits) == "American Express"
        else _DEFAULT_CVC_DIGITS
    )

    if len(cvc_digits) != expected:
        where = (
            "on the front of the card"
            if expected == _AMEX_CVC_DIGITS
            else "on the back of the card"
        )
        return f"The security code is {expected} digits, {where}."

    return None


# WHY THIS EXISTS
# THE BOUNDARY THE CARD NUMBER DOES NOT CROSS. Everything after checkout - the
# order document, the receipt, the billing history screen - is built from what this
# returns, and what it returns is a brand and four digits.
#
# So the card number exists in the process for the length of one request handler
# and is referenced by nothing that outlives it. That is the property that makes
# swapping in a real processor a small change: the rest of the system already
# describes a payment method the way a processor's token does, because it was never
# given anything more.
#
# THE LAST FOUR DIGITS ARE NOT A SECRET and are not treated as one - they are
# printed on receipts everywhere, precisely because four digits identify a card to
# its owner without identifying it to anyone else.
def describe_card(number: str, expiry: str) -> dict:
    digits = _digits_only(number)
    parsed = _parse_expiry(expiry)

    return {
        "brand": card_brand(digits),
        "last4": digits[-4:],
        # Stored so a billing screen can say "expires 12/28" and warn before a
        # renewal fails. Month and year only; nothing here narrows the card down.
        "expiryMonth": parsed[0] if parsed else None,
        "expiryYear": parsed[1] if parsed else None,
    }


# ============================================================================
# THE PROVIDER
# ============================================================================


# WHY THIS EXISTS
# The functions above wrapped in the interface from base.py, so main.py can ask
# "did this payment work" without knowing that today the answer comes from a
# checksum.
#
# IT ALWAYS ANSWERS "granted" OR "refused", NEVER "pending". There is nothing
# asynchronous about a checksum - the request that validates the card is the
# request that can hand over the plan. A real provider is the opposite way round
# most of the time, which is exactly why the endpoint has to be written against
# both answers rather than against this one.
class MockCardProvider(PaymentProvider):
    # Read by config warnings and by the /billing/plans response, so a developer
    # looking at either can see which processor is in force. "mock" is a word
    # chosen to be impossible to mistake for a company.
    name = "mock"

    async def create_checkout(
        self,
        *,
        plan: dict,
        user: dict,
        card: dict | None = None,
        now: datetime,
    ) -> CheckoutOutcome:
        # `card` is optional on the interface because a real provider never gets
        # one. This provider cannot work without it, and an empty dict here means
        # the endpoint was changed without this being updated - so it refuses
        # rather than granting a plan on the strength of no card at all.
        card = card or {}

        problem = card_problem(
            card.get("number", ""),
            card.get("expiry", ""),
            card.get("cvc", ""),
            card.get("name", ""),
        )

        if problem:
            return CheckoutOutcome.refused(problem)

        # THE LINE THE CARD NUMBER DOES NOT CROSS, and it is inside this method for
        # a reason: `number` is a local in this frame and in describe_card's, and
        # the CheckoutOutcome that leaves here carries a brand and four digits.
        # Nothing above this function has ever held the number except the request
        # model, and nothing below it can.
        method = describe_card(card.get("number", ""), card.get("expiry", ""))

        return CheckoutOutcome.granted(
            payment_method=method,
            # A synthetic reference, so the order document has the same shape it
            # will have under a real processor - where this is the id you paste
            # into a dashboard to find the payment. The `mock_` prefix means one
            # of these turning up in a real ledger is unmistakable.
            #
            # PYTHON-SPECIFIC: uuid4 is random rather than derived from the clock
            # or the machine, and .hex drops the dashes.
            provider_ref=f"mock_{uuid.uuid4().hex[:16]}",
        )
