"""
PAYMENTS/PADDLE.PY - the real processor, as far as it can honestly be written
without credentials.

WHAT THIS FILE IS
A skeleton that REFUSES TO BE BUILT and names exactly what it is missing. Not a
stub that pretends, not a mock with a different label, and not a set of invented
seller ids and price tokens that look plausible in a diff and fail in production.

WHY THAT IS THE USEFUL THING TO COMMIT
The point of the seam in base.py is that swapping processors touches one module.
That claim is worth nothing unless somebody has actually tried to write the second
implementation, because "we designed for it" is how interfaces that fit exactly one
implementation get shipped. Writing this one is what proved the interface needed
`status="pending"` and a `client_action`: Paddle's overlay does not settle inside
the request that opens it, so an interface returning a boolean could not have
described it at all.

So this file's job is to be the second implementation, minus the four secrets
nobody has. Everything about the SHAPE of the integration is here and checkable;
nothing about it is faked.

WHAT IS ACTUALLY MISSING, and all four come from a Paddle dashboard nobody has
opened yet:
  - a client-side token, for the overlay in the browser
  - a server-side API key, for creating and reading transactions
  - a webhook signing secret, without which a callback granting a plan is just an
    unauthenticated POST that grants plans
  - a price id per purchasable plan, because Paddle charges for ITS catalogue
    entry, not for an amount we send it - which is the same principle billing.PLANS
    already follows, enforced by somebody else

HOW THE FLOW DIFFERS FROM THE MOCK, since this is the part that shaped the seam:
  1. The browser opens Paddle's overlay with a price id and a client token. The
     card is typed into Paddle's iframe. We never see it, and CheckoutRequest's
     four card fields stop existing.
  2. This provider returns status="pending" with the overlay's parameters as
     `client_action`. NO PLAN IS GRANTED YET.
  3. Paddle POSTs a signed `transaction.completed` webhook. handle_webhook()
     verifies the signature and only then is the entitlement written.

Step 3 is why the webhook secret is not optional and why this cannot be
half-configured: an endpoint that grants plans on an unverified callback is a
free-subscription endpoint with extra steps.
"""

import hashlib
import hmac
import json
import logging
from datetime import datetime

import httpx

import config

from .base import CheckoutOutcome, PaymentProvider, ProviderNotConfigured


# A logger rather than bare print(), because the webhook handler is the part of a
# payment integration that fails at 2am on a Saturday and the timestamps and levels
# that logging provides are what makes that investigation possible.
_log = logging.getLogger("payments.paddle")

# Paddle's two environments. Named here rather than inlined so the sandbox is a
# configuration choice a developer can see, not a URL somebody has to remember to
# change before going live.
_API_BASE = {
    "sandbox": "https://sandbox-api.paddle.com",
    "production": "https://api.paddle.com",
}

# Timeout for outbound calls to the Paddle API. Long enough for a slow sandbox, short
# enough that a hung connection does not block a checkout for a minute.
_TIMEOUT_SECONDS = 15.0


# WHY THIS EXISTS
# The one place that decides what "configured" means, so the check cannot drift
# from the requirement. Returns the human names of everything absent - plural,
# because telling somebody about one missing variable at a time when four are
# missing is four restarts.
def missing_credentials() -> list[str]:
    missing: list[str] = []

    if not config.PADDLE_CLIENT_TOKEN:
        missing.append("SECUSCAN_PADDLE_CLIENT_TOKEN (client-side, for the overlay)")

    if not config.PADDLE_API_KEY:
        missing.append("SECUSCAN_PADDLE_API_KEY (server-side, for transactions)")

    if not config.PADDLE_WEBHOOK_SECRET:
        missing.append(
            "SECUSCAN_PADDLE_WEBHOOK_SECRET (without it, webhooks cannot be verified)"
        )

    # WHY THE PRICE IDS ARE CHECKED AGAINST THE CATALOGUE RATHER THAN LISTED HERE
    # A plan added to billing.PLANS next quarter needs a price id too, and a
    # hardcoded list of two would not know that. Importing billing here is safe -
    # it is a catalogue with no imports of its own beyond the standard library.
    import billing

    for plan in billing.PLANS:
        if not plan["purchasable"]:
            continue

        if not config.paddle_price_id(plan["id"]):
            missing.append(
                f"SECUSCAN_PADDLE_PRICE_{plan['id'].upper()} "
                f"(the Paddle price id for the {plan['name']} plan)"
            )

    return missing


# ============================================================================
# SIGNATURE VERIFICATION
#
# THE SIGNATURE CHECK IS THE WHOLE POINT OF THE WEBHOOK. Paddle signs the raw
# body with the webhook secret and sends the digest in a `Paddle-Signature`
# header. Verification is HMAC-SHA256 over the RAW bytes, which is why
# handle_webhook takes `bytes` and not a parsed dict - re-serialising JSON
# changes the bytes and breaks the digest.
#
# Compared with hmac.compare_digest, never `==`, for the same constant-time
# reason auth.py's token comparison uses it.
# ============================================================================

def _verify_paddle_signature(
    *, signature_header: str, body: bytes, secret: str
) -> bool:
    """Verify the Paddle-Signature header against the raw request body.

    The header format is: ts=<unix_timestamp>;h1=<hex_hmac_sha256>[;h1=...]

    The signed payload is: <timestamp>:<raw_body>

    Returns True when the signature matches any h1 component, False otherwise.
    """
    ts: str | None = None
    signatures: list[str] = []

    # Parse the header into its components. Multiple h1 components may be present
    # when multiple webhook keys are active or during secret rotation.
    for segment in signature_header.split(";"):
        if "=" in segment:
            key, _, value = segment.partition("=")
            key = key.strip()
            value = value.strip()
            if key == "ts":
                ts = value
            elif key == "h1":
                signatures.append(value)

    if not ts or not signatures:
        _log.warning("Paddle-Signature header is missing ts or h1 component")
        return False

    # Build the signed payload: timestamp + ":" + raw body.
    signed_payload = ts.encode("utf-8") + b":" + body

    expected = hmac.new(
        secret.strip().encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    return any(hmac.compare_digest(expected, sig) for sig in signatures)


class PaddleProvider(PaymentProvider):
    name = "paddle"

    # WHY THE CONSTRUCTOR RAISES RATHER THAN DEGRADING
    # mailer.py's unconfigured sender returns False and sends nothing, which is the
    # right call for an email that can be resent. It is the wrong call here. A
    # payment provider that silently does nothing while the interface says the plan
    # was granted is the single worst failure this package could have - it hands out
    # subscriptions for free and looks healthy doing it.
    #
    # So this refuses to exist, and __init__.py catches the refusal and installs
    # the base PaymentProvider instead - which answers "payments are not
    # configured" on the one endpoint that asks. The server boots; scanning and
    # sign-in are unaffected; checkout is honestly switched off. That is exactly
    # how config.py already treats a missing Google client id.
    def __init__(self) -> None:
        missing = missing_credentials()

        if missing:
            raise ProviderNotConfigured(
                "Paddle is selected as the payment provider but is not configured. "
                "Missing: " + "; ".join(missing)
            )

        self._environment = (
            "sandbox" if config.PADDLE_SANDBOX else "production"
        )
        self._api_base = _API_BASE[self._environment]
        self._api_key = config.PADDLE_API_KEY
        self._webhook_secret = config.PADDLE_WEBHOOK_SECRET
        self._client_token = config.PADDLE_CLIENT_TOKEN

    async def create_checkout(
        self,
        *,
        plan: dict,
        user: dict,
        card: dict | None = None,
        now: datetime,
    ) -> CheckoutOutcome:
        # `card` IS IGNORED, DELIBERATELY, and this is the assertion that the seam
        # works. A real processor collects the card itself; if this method ever
        # reads that argument, the migration has gone wrong and PCI scope has
        # quietly come back.
        del card

        price_id = config.paddle_price_id(plan["id"])

        # WHY custom_data CARRIES THE USER ID AND THE PLAN ID
        # Paddle's webhook does not know what it is granting or to whom unless we
        # tell it. custom_data is round-tripped through the transaction and arrives
        # in every webhook about it, so the handler can look up the account and the
        # plan without a second API call. The plan id is included because the price
        # id alone is not enough to find the entry in billing.PLANS - it is an
        # environment-specific token, not a catalogue key.
        payload = {
            "items": [{"price_id": price_id, "quantity": 1}],
            "custom_data": {
                "user_id": user["id"],
                "plan_id": plan["id"],
            },
            # "automatic" means Paddle handles collection via the checkout overlay.
            "collection_mode": "automatic",
        }

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    f"{self._api_base}/transactions",
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
        except httpx.HTTPError as exc:
            _log.error("Could not reach Paddle: %s: %s", type(exc).__name__, exc)
            return CheckoutOutcome.refused(
                "We could not reach the payment processor. Try again in a moment."
            )

        if response.status_code >= 400:
            # Log the body for diagnostics but never surface it to the user: Paddle's
            # error messages can contain internal details.
            _log.error(
                "Paddle refused the transaction (%d): %s",
                response.status_code,
                response.text[:500],
            )
            return CheckoutOutcome.refused(
                "The payment could not be started. Please try again."
            )

        data = response.json().get("data", {})
        transaction_id = data.get("id")

        # PENDING, NOT GRANTED. Everything the browser needs to open the overlay
        # goes back in client_action, and the entitlement waits for the webhook.
        # The endpoint must not write a subscription off the back of this.
        return CheckoutOutcome.pending(
            provider_ref=transaction_id,
            client_action={
                # What the frontend passes to Paddle.Checkout.open().
                "provider": "paddle",
                "environment": self._environment,
                "client_token": self._client_token,
                "transaction_id": transaction_id,
            },
        )

    async def handle_webhook(self, *, headers: dict, body: bytes) -> dict | None:
        # ------------------------------------------------------------------
        # STEP 1: VERIFY THE SIGNATURE
        #
        # This is the load-bearing line. Without it, this function is an
        # unauthenticated POST that grants plans - a free-subscription
        # endpoint with extra steps.
        # ------------------------------------------------------------------
        signature_header = headers.get("paddle-signature") or headers.get(
            "Paddle-Signature", ""
        )

        if not signature_header:
            _log.warning("Webhook received with no Paddle-Signature header")
            return None

        if not _verify_paddle_signature(
            signature_header=signature_header,
            body=body,
            secret=self._webhook_secret,
        ):
            _log.warning("Webhook signature verification failed")
            return None

        # ------------------------------------------------------------------
        # STEP 2: PARSE THE PAYLOAD
        #
        # The body has already been verified, so parsing it is safe.
        # ------------------------------------------------------------------
        try:
            event = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            _log.error("Webhook body is not valid JSON after passing signature check")
            return None

        event_type = event.get("event_type", "")
        event_id = event.get("event_id", "")
        data = event.get("data", {})

        # custom_data is round-tripped through the transaction and propagated to
        # the subscription by Paddle, so it is available on every event type that
        # concerns us.
        custom_data = data.get("custom_data") or {}
        user_id = custom_data.get("user_id")
        plan_id = custom_data.get("plan_id")

        _log.info(
            "Webhook %s (event_id=%s, user=%s, plan=%s)",
            event_type, event_id, user_id, plan_id,
        )

        # ------------------------------------------------------------------
        # STEP 3: DISPATCH ON THE EVENT TYPE
        #
        # Exactly the 5 events the webhook subscription is configured for.
        # Anything else is logged and ignored - not an error, because Paddle
        # can add fields to existing events and the correct response to an
        # unknown event is silence, not a crash.
        # ------------------------------------------------------------------

        if event_type == "transaction.completed":
            return self._handle_transaction_completed(
                data=data, event_id=event_id,
                user_id=user_id, plan_id=plan_id,
            )

        if event_type == "transaction.payment_failed":
            return self._handle_transaction_payment_failed(
                data=data, event_id=event_id,
                user_id=user_id, plan_id=plan_id,
            )

        if event_type == "subscription.canceled":
            return self._handle_subscription_canceled(
                data=data, event_id=event_id,
                user_id=user_id, plan_id=plan_id,
            )

        if event_type == "subscription.past_due":
            return self._handle_subscription_past_due(
                data=data, event_id=event_id,
                user_id=user_id, plan_id=plan_id,
            )

        if event_type == "subscription.updated":
            return self._handle_subscription_updated(
                data=data, event_id=event_id,
                user_id=user_id, plan_id=plan_id,
            )

        _log.info("Ignoring unhandled event type: %s", event_type)
        return None

    # ------------------------------------------------------------------
    # EVENT HANDLERS
    #
    # Each returns a dict that tells the CALLER (the webhook endpoint in
    # main.py) what to do. The handler does not touch the database itself -
    # that is the endpoint's responsibility, for the same reason
    # create_checkout does not write orders: the endpoint is the code that
    # knows how to build a subscription document and call database.py.
    #
    # The dict always carries:
    #   action     - a machine-readable verb the endpoint switches on
    #   event_type - the original event, for logging
    #   event_id   - for idempotency: the endpoint should skip an event_id
    #                it has already processed
    #   user_id    - which account to act on
    #   plan_id    - which plan was bought (may be None for some events)
    #
    # Plus event-specific fields documented on each handler.
    # ------------------------------------------------------------------

    def _handle_transaction_completed(
        self, *, data: dict, event_id: str,
        user_id: str | None, plan_id: str | None,
    ) -> dict:
        """Grant the plan.

        The endpoint should create an order and set the user's plan, matching
        the "granted" branch of the checkout endpoint.
        """
        transaction_id = data.get("id")
        subscription_id = data.get("subscription_id")

        # Extract payment method details if available, for the order and
        # subscription documents (cardBrand / cardLast4 on the billing screen).
        payments_list = data.get("payments") or []
        payment_method = {}
        if payments_list:
            pm = payments_list[0].get("method_details") or {}
            card_details = pm.get("card") or {}
            payment_method = {
                "brand": (card_details.get("type") or "").capitalize() or None,
                "last4": card_details.get("last4"),
            }

        return {
            "action": "grant_plan",
            "event_type": "transaction.completed",
            "event_id": event_id,
            "user_id": user_id,
            "plan_id": plan_id,
            "transaction_id": transaction_id,
            "subscription_id": subscription_id,
            "payment_method": payment_method,
        }

    def _handle_transaction_payment_failed(
        self, *, data: dict, event_id: str,
        user_id: str | None, plan_id: str | None,
    ) -> dict:
        """Log the failed payment attempt. No plan change.

        The endpoint should log this for support visibility but must not alter
        the user's plan or subscription. A failed renewal is not a cancellation.
        """
        transaction_id = data.get("id")

        _log.warning(
            "Payment failed for user=%s plan=%s txn=%s",
            user_id, plan_id, transaction_id,
        )

        return {
            "action": "payment_failed",
            "event_type": "transaction.payment_failed",
            "event_id": event_id,
            "user_id": user_id,
            "plan_id": plan_id,
            "transaction_id": transaction_id,
        }

    def _handle_subscription_canceled(
        self, *, data: dict, event_id: str,
        user_id: str | None, plan_id: str | None,
    ) -> dict:
        """Set cancelAtPeriodEnd. Do not revoke access immediately.

        Per the existing design in billing.py and main.py's cancel endpoint:
        access continues until the period ends, resolved lazily on the next
        read by billing.subscription_has_lapsed().
        """
        subscription_id = data.get("id")

        # Paddle's current_billing_period tells us when the paid period runs out.
        billing_period = data.get("current_billing_period") or {}
        period_ends_at = billing_period.get("ends_at")

        return {
            "action": "cancel_at_period_end",
            "event_type": "subscription.canceled",
            "event_id": event_id,
            "user_id": user_id,
            "plan_id": plan_id,
            "subscription_id": subscription_id,
            "period_ends_at": period_ends_at,
        }

    def _handle_subscription_past_due(
        self, *, data: dict, event_id: str,
        user_id: str | None, plan_id: str | None,
    ) -> dict:
        """Flag the account so the user can be warned. Do not revoke access yet.

        A past-due subscription means Paddle's automatic retry is still in
        progress. The user should see a banner, but their entitlements stay
        until Paddle either recovers the payment or cancels the subscription.
        """
        subscription_id = data.get("id")

        _log.warning(
            "Subscription past due for user=%s sub=%s",
            user_id, subscription_id,
        )

        return {
            "action": "flag_past_due",
            "event_type": "subscription.past_due",
            "event_id": event_id,
            "user_id": user_id,
            "plan_id": plan_id,
            "subscription_id": subscription_id,
        }

    def _handle_subscription_updated(
        self, *, data: dict, event_id: str,
        user_id: str | None, plan_id: str | None,
    ) -> dict:
        """Sync plan and renewal-date changes.

        The endpoint should update the subscription document with the new
        billing period and, if the items changed, resolve the new plan from
        the price id.
        """
        subscription_id = data.get("id")
        status = data.get("status")
        next_billed_at = data.get("next_billed_at")
        scheduled_change = data.get("scheduled_change")

        billing_period = data.get("current_billing_period") or {}
        period_ends_at = billing_period.get("ends_at")
        period_starts_at = billing_period.get("starts_at")

        # Extract the current price id from the first item, so the endpoint can
        # resolve it back to a plan in billing.PLANS via config.paddle_price_id().
        items = data.get("items") or []
        current_price_id = None
        if items:
            price = items[0].get("price") or {}
            current_price_id = price.get("id")

        return {
            "action": "sync_subscription",
            "event_type": "subscription.updated",
            "event_id": event_id,
            "user_id": user_id,
            "plan_id": plan_id,
            "subscription_id": subscription_id,
            "status": status,
            "current_price_id": current_price_id,
            "period_starts_at": period_starts_at,
            "period_ends_at": period_ends_at,
            "next_billed_at": next_billed_at,
            "scheduled_change": scheduled_change,
        }
