"""
PAYMENTS/BASE.PY - the shape every payment provider has to fit.

WHY THIS FILE IS SEPARATE FROM __init__.py
It holds the two types (`CheckoutOutcome`, `PaymentProvider`) that both the mock
and the Paddle skeleton need to import. Putting them in __init__.py instead would
mean mock_card.py importing from the package that imports mock_card.py - a
circular import, which Python resolves by half-initialising one of the modules and
then failing somewhere unrelated. A separate module for the shared types is the
ordinary fix, and __init__.py re-exports them so callers never mention this file.

WHAT A PROVIDER IS FOR
main.py should not know who processes a payment. It knows a plan, a user, and
whatever the browser sent; it hands those to a provider and gets back a verdict.
That is the same arrangement mailer.py uses for email, and it is here for the same
reason: the endpoint is the last code in the app that should be edited because a
commercial relationship changed.
"""

from dataclasses import dataclass, field
from datetime import datetime


# WHY THIS EXISTS
# A provider that cannot be built says so with this, and __init__.py catches it.
# See _build_provider() there for why an unconfigured processor must not take the
# whole server down with it.
class ProviderNotConfigured(RuntimeError):
    pass


# ============================================================================
# THE RESULT TYPE
#
# WHY THIS IS A DATACLASS AND NOT A BOOLEAN, AND IT IS THE ONE DECISION IN THIS
# PACKAGE THAT MATTERS
#
# The mock grants a plan synchronously: the request that validates the card is the
# request that hands over the entitlement. A real processor usually cannot work
# that way. Paddle's overlay checkout returns a transaction that is still pending
# when the browser comes back, and the plan is granted later, by a webhook, in a
# request that has no connection to the one the user is waiting on.
#
# A function that returns True/False can describe the first case and not the
# second. So this type describes both, and the endpoint branches on `status` -
# which means the day a real provider is wired in, the endpoint already has the
# branch it needs instead of needing a new shape threaded through it.
# ============================================================================


@dataclass
class CheckoutOutcome:
    # granted  - the entitlement is the caller's to write, now. The mock's answer.
    # pending  - money is in flight. Do NOT grant; hand `client_action` to the
    #            browser and wait for handle_webhook() to say it landed.
    # refused  - it did not work, and `problem` is one sentence saying why.
    #
    # THREE STATES RATHER THAN TWO. A refusal is not a missing success, and the
    # alternative - two states plus a `problem` field that is sometimes set -
    # spreads the real question ("did this work?") across two fields that can
    # disagree. Every caller should be reading one.
    status: str

    # The brand and last four digits, or whatever the provider is willing to say
    # about the instrument. NEVER the full number: see describe_card in
    # mock_card.py on why that boundary is the thing that makes this swap cheap.
    #
    # PYTHON-SPECIFIC: default_factory=dict rather than `= {}`. A mutable default
    # in a signature is created ONCE and shared by every instance, which is one of
    # Python's genuinely famous traps - two outcomes would silently share a dict.
    payment_method: dict = field(default_factory=dict)

    # The provider's own id for this payment, stored on the order so a support
    # conversation can be traced into the processor's dashboard. The mock has no
    # dashboard, so it puts its own order id here rather than leaving it empty and
    # letting the field look optional.
    provider_ref: str | None = None

    # What the BROWSER must do next, for a provider whose checkout finishes
    # somewhere else - an overlay token, a redirect URL. None for the mock,
    # because there is nowhere else to go.
    client_action: dict | None = None

    # One plain sentence, set only when status == "refused". Rendered as-is beside
    # the card fields, so it names the field at fault - see the note on
    # card_problem in mock_card.py about why a boolean would be useless here.
    problem: str | None = None

    # --- Constructors, so a caller never types a status string ---------------
    #
    # PYTHON-SPECIFIC: @classmethod with `cls` builds an instance of whatever class
    # it was called on. These exist because `CheckoutOutcome(status="grantd", ...)`
    # is a typo that no test would catch, and `CheckoutOutcome.granted(...)` is one
    # that cannot be written.

    @classmethod
    def granted(
        cls,
        payment_method: dict,
        provider_ref: str | None = None,
    ) -> "CheckoutOutcome":
        return cls(
            status="granted",
            payment_method=payment_method,
            provider_ref=provider_ref,
        )

    @classmethod
    def pending(
        cls,
        client_action: dict,
        provider_ref: str | None = None,
        payment_method: dict | None = None,
    ) -> "CheckoutOutcome":
        return cls(
            status="pending",
            payment_method=payment_method or {},
            provider_ref=provider_ref,
            client_action=client_action,
        )

    @classmethod
    def refused(cls, problem: str) -> "CheckoutOutcome":
        return cls(status="refused", problem=problem)

    # PYTHON-SPECIFIC: @property makes this read as an attribute - `outcome.ok` -
    # rather than a call. Used by the endpoint to decide between an error response
    # and a success one, without repeating the string comparison at each site.
    @property
    def ok(self) -> bool:
        return self.status in {"granted", "pending"}


# ============================================================================
# THE INTERFACE
# ============================================================================


# WHY THIS EXISTS
# PYTHON-SPECIFIC: a plain class used as an INTERFACE, not an abstract base class -
# the same choice mailer.Sender makes, and for the same reasons. Python has no
# `interface` keyword and anything with matching methods works wherever a provider
# is expected. The class exists to document the shape in one place and to give the
# type hints something to name.
#
# THE BASE IS ALSO THE "NOT CONFIGURED" PROVIDER. Its create_checkout refuses
# instead of raising, so a deployment with a broken payment configuration answers
# "payments are not available" on one endpoint rather than failing to boot. That is
# the treatment Google Sign-In already gets in config.py: visibly switched off
# beats half working.
class PaymentProvider:
    name = "none"

    # WHY THE ARGUMENTS ARE KEYWORD-ONLY
    # PYTHON-SPECIFIC: the bare `*` means everything after it must be passed by
    # name. `create_checkout(plan, user, card)` is three dicts in an order nobody
    # can remember, and swapping two of them is a bug that type hints do not
    # catch. `create_checkout(plan=..., user=..., card=...)` cannot be got wrong.
    #
    # WHY `card` IS OPTIONAL, and it is the point of the whole seam: the mock needs
    # card fields because the browser posted them to us. A real processor must
    # never receive them - its own iframe collects the number and we are handed a
    # token - so its implementation ignores this argument entirely. A signature
    # that REQUIRED a card would be a signature only a mock can satisfy.
    async def create_checkout(
        self,
        *,
        plan: dict,
        user: dict,
        card: dict | None = None,
        now: datetime,
    ) -> CheckoutOutcome:
        return CheckoutOutcome.refused(
            "Payments are not configured on this server. Nothing was charged."
        )

    # WHY THIS EXISTS
    # The other half of a real integration: the processor's callback saying a
    # pending payment settled. Returns the provider's own reference and what
    # happened, or None when the payload is not something this provider handles.
    #
    # The mock never calls it - it has no webhooks, because it grants
    # synchronously - and it is declared anyway so the shape a real provider needs
    # is visible now rather than discovered during the migration.
    async def handle_webhook(self, *, headers: dict, body: bytes) -> dict | None:
        return None
