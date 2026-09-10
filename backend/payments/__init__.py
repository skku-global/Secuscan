"""
PAYMENTS - which processor is in force, and the one function that answers it.

WHY THIS PACKAGE EXISTS
Until now the payment mechanism was six functions in billing.py and two calls in a
FastAPI endpoint. That works exactly as long as there is one mechanism. The moment
a real processor arrives, the endpoint has to learn that entitlement can be granted
LATER, by a webhook, in a request the user is not waiting on - and an endpoint
being taught that during a payments migration is an endpoint being rewritten at the
worst possible time.

So the mechanism moved behind an interface first, while the only implementation is
one nobody can lose money to.

WHAT IS WHERE
  base.py       the interface, and CheckoutOutcome - the result type that can
                describe both "granted now" and "pending, open this overlay"
  mock_card.py  Luhn, expiry, brand, and a provider that grants synchronously.
                The file that gets DELETED, not edited, when this becomes real
  paddle.py     the second implementation, minus the four credentials nobody has.
                Refuses to be built and says what is missing

WHAT CALLERS SEE
    from payments import get_provider
    outcome = await get_provider().create_checkout(plan=..., user=..., card=...,
                                                   now=...)
    if outcome.status == "granted": ...

That is the whole surface. main.py names no provider, and the two card functions it
used to call directly (billing.card_problem, billing.describe_card) are now
somebody else's business - which is the point.

THIS MIRRORS mailer.py ON PURPOSE. One environment variable names the provider, one
builder turns the name into an object, and adding a provider is a class plus a line
in _build_provider(). A reader who has understood the email seam has understood
this one, and consistency between two seams doing the same job is worth more than
whatever either could gain by being clever separately.
"""

from .base import CheckoutOutcome, PaymentProvider, ProviderNotConfigured
from .mock_card import MockCardProvider

import config

# PYTHON-SPECIFIC: `as _` style re-exports are not used here; the names above are
# imported so `from payments import CheckoutOutcome` works. Listing them in __all__
# documents which of them are the package's public surface, as opposed to reachable
# by accident.
__all__ = [
    "CheckoutOutcome",
    "PaymentProvider",
    "ProviderNotConfigured",
    "get_provider",
    "provider_name",
    "payments_available",
]


# WHY THIS EXISTS
# The lookup that turns a configuration string into an object. One place to add a
# provider, and one place that decides what an unrecognised name does.
#
# THE PADDLE BRANCH CATCHES, AND THAT IS THE INTERESTING PART
# PaddleProvider's constructor raises when its credentials are absent - see the
# long note there on why it must not degrade quietly. Catching that here and
# installing the base PaymentProvider gives the deployment the same treatment
# config.py gives a missing Google client id: the server boots, everything
# unrelated works, and the one endpoint that needs the missing thing says so
# plainly instead of half working.
#
# WHAT IT MUST NEVER DO IS FALL BACK TO THE MOCK. "Paddle is misconfigured, so
# grant plans for free using a checksum" is a sentence no system should be able to
# execute. The mock is selected by name, explicitly, and is never substituted in -
# the same rule mailer.py has about printing recovery codes to a log.
def _build_provider() -> PaymentProvider:
    if config.PAYMENT_PROVIDER == "mock":
        return MockCardProvider()

    if config.PAYMENT_PROVIDER == "paddle":
        # PYTHON-SPECIFIC: imported inside the function rather than at the top of
        # the module. paddle.py imports billing, billing imports nothing from here,
        # and keeping this import local means a deployment on the mock never
        # touches the Paddle module at all - so a syntax error in an unfinished
        # integration cannot stop the server that is not using it.
        from .paddle import PaddleProvider

        try:
            return PaddleProvider()
        except ProviderNotConfigured:
            # The reason is not swallowed - config.startup_warnings() prints it at
            # boot, from the same missing_credentials() list this raised on.
            return PaymentProvider()

    # An unknown name. PaymentProvider() refuses every checkout, and config already
    # warned about it at startup. Guessing at the intended provider would be worse,
    # and guessing "mock" would be worst of all.
    return PaymentProvider()


# Built once at import and reused, so credentials are read once rather than on
# every checkout - the same arrangement as mailer.py's module-level _sender.
_provider = _build_provider()


def get_provider() -> PaymentProvider:
    return _provider


def provider_name() -> str:
    return _provider.name


# WHY THIS EXISTS
# Lets an endpoint answer "payments are not available on this server" with a 503
# instead of accepting a card and doing nothing with it. The same honesty rule
# mailer.email_available() exists for, and /auth/forgot-password already follows.
def payments_available() -> bool:
    return _provider.name != "none"
