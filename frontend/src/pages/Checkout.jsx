/* ============================================================================
   CHECKOUT.JSX — the payment page at "/checkout/:planId".

   WHY THIS EXISTS: the pricing table on the landing page had four buttons that did
   nothing. This is what they now point at. A visitor picks a plan, arrives here,
   and either pays for it or is told plainly why they cannot.

   ---------------------------------------------------------------------------
   THE ONE RULE THIS PAGE IS BUILT AROUND: THE PRICE IS NOT OURS TO STATE.

   The figure shown in the summary comes from GET /billing/plans, and the request
   that buys the plan sends a plan ID and no amount. Both halves matter:

     - Showing a price from lib/pricing.js — which sits right there, already
       imported by the landing page, already listing these same four plans — would
       create a second copy of the number. Two copies agree until one is edited,
       and the failure mode is a customer shown $49 and billed $149.
     - Sending an amount would be worse than a duplicate; it would be an amount the
       CUSTOMER controls. api.js says this at its own checkout(): "If a future edit
       adds an `amountCents` argument here, that is the bug." Same rule, this end.

   So pricing.js supplies the words on this page and the server supplies every
   number on it. Nothing computes a total.

   ---------------------------------------------------------------------------
   WHERE THE CARD NUMBER GOES

   Into one piece of React state, into one fetch body, and nowhere else. It is not
   logged, not stored, not put in a URL, and not sent to any third party — the form
   posts to SecuScan's own API, which reduces the number to a brand and four digits
   before anything is written down (billing.describe_card). The receipt at the end
   of this page renders `order.cardLast4`, because that is genuinely all that came
   back.

   AND NOTHING IS ACTUALLY CHARGED. There is no payment processor behind this. The
   server records an order with status "authorised" and grants the plan, which is a
   complete and working billing system with the one step that moves money left out.
   The page SAYS SO, in the notice above the form, and that is not optional
   decoration: a form that looks exactly like a real payment form while doing
   something else is the precise thing a security product must not ship. Somebody
   would type a real card into it.

   ---------------------------------------------------------------------------
   FOUR PLANS, THREE OF WHICH ARE NOT AN ORDINARY PURCHASE

   The catalogue marks `purchasable` per plan, and this page has to handle every
   case rather than assuming a form is always the answer:

     free        — purchasable: false. Nothing to pay. Send them to the dashboard.
     starter     — purchasable: true.  The form.
     business    — purchasable: true.  The form.
     enterprise  — purchasable: false, amountCents: null. Priced by conversation.

   The server enforces all of this too (checkout() refuses a non-purchasable plan
   before it looks at the card), so what is here is not the control — it is the
   difference between an explanation and a 400 after typing a card number in.

   ---------------------------------------------------------------------------
   [React] WHY THE PLAN IS FETCHED RATHER THAN PASSED IN ROUTER STATE

   Landing could hand the plan over in `navigate(..., { state })` and save a
   request. It must not: this URL is shareable, bookmarkable and reloadable, and a
   page that only works when you arrive from one particular link is a page that
   breaks on refresh. The plan ID in the path is the whole input.
   ========================================================================== */

import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  AlertCircle,
  ArrowLeft,
  Check,
  CreditCard,
  Info,
  Loader2,
  Lock,
  ShieldCheck,
} from 'lucide-react'

import TopBar from '../components/TopBar'
import { useAuth } from '../context/AuthContext'
import * as api from '../lib/api'
import {
  cvcLength,
  digitsOnly,
  formatAmount,
  formatCardNumber,
  formatExpiry,
  intervalSuffix,
} from '../lib/cardFormat'
import { PRICING_PLANS, PRICING_ANCHOR } from '../lib/pricing'
import { initPaddle, openPaddleCheckout } from '../lib/paddle'
import '../styles/checkout.css'

/* WHY THE MARKETING COPY IS LOOKED UP BY ID: the server's plan carries a name, a
   price and two limits — everything needed to CHARGE for it, and nothing that says
   what it is for. "Everything in Starter, plus scheduled weekly scans" is a
   sentence a billing catalogue has no business holding. So the two are joined here,
   by id, and the join is allowed to fail: a plan the server knows about and
   pricing.js has never heard of still renders, just without the feature list. The
   opposite arrangement — no price unless the marketing file agrees — would let a
   copy edit take the checkout page down. */
function marketingFor(planId) {
  return PRICING_PLANS.find((entry) => entry.id === planId) ?? null
}

/* A date the way a receipt says it. [General] `undefined` as the first argument to
   toLocaleDateString means "use the browser's own locale" — which is the right
   answer for a date a human is reading, and better than hardcoding en-US for
   somebody in Lagos or Berlin. */
function formatDate(iso) {
  if (!iso) return ''

  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })
}

export default function Checkout() {
  /* [React] useParams reads the `:planId` segment out of the path that App.jsx
     declared. It is a string from a URL, so it is untrusted input — which is fine,
     because the only thing done with it is a lookup that either matches a plan or
     does not. */
  const { planId } = useParams()

  const navigate = useNavigate()
  const { user, refreshUser } = useAuth()

  /* The catalogue. `null` means "still asking" and is distinct from an empty array,
     which would mean "the server has no plans" — a different thing to render. */
  const [plans, setPlans] = useState(null)
  const [billingConfig, setBillingConfig] = useState(null)
  const [loadError, setLoadError] = useState('')

  const [cardName, setCardName] = useState('')
  const [cardNumber, setCardNumber] = useState('')
  const [cardExpiry, setCardExpiry] = useState('')
  const [cardCvc, setCardCvc] = useState('')

  const [error, setError] = useState('')
  const [paying, setPaying] = useState(false)
  const [processing, setProcessing] = useState(false)

  /* The completed purchase: { order, plan, subscription, user }. Non-null means the
     page stops being a form and becomes a receipt. [React] One piece of state rather
     than a `done` boolean beside the data — a boolean and a payload that can
     disagree is two sources of truth for one fact. */
  const [receipt, setReceipt] = useState(null)

  const isPaddle = billingConfig?.provider === 'paddle'

  /* ------------------------------------------------------------------------
     LOADING THE CATALOGUE AND BILLING CONFIG
     ---------------------------------------------------------------------- */

  useEffect(() => {
    /* The same cancellation flag as every other fetching effect in this app: a
       response arriving after the user has navigated away would call setState on a
       component that no longer exists. */
    let cancelled = false

    Promise.all([api.fetchPlans(), api.fetchBillingConfig()])
      .then(([plansResult, configResult]) => {
        if (cancelled) return

        setPlans(plansResult)
        setBillingConfig(configResult)

        if (configResult?.provider === 'paddle' && configResult?.clientToken) {
          initPaddle({
            clientToken: configResult.clientToken,
            environment: configResult.environment || 'sandbox',
          }).catch((err) => {
            console.warn('[Paddle Init Warning]', err)
          })
        }
      })
      .catch((caught) => {
        if (cancelled) return

        /* WHY THIS ONE SURFACES rather than falling back to something sensible:
           there is no sensible fallback for a price. Everything else on this page
           can degrade — the feature list, the brand label — but a checkout that
           cannot read the catalogue must not guess, and saying so is the only
           honest option. */
        setLoadError(caught.message || 'Plans could not be loaded.')
      })

    return () => {
      cancelled = true
    }
  }, [])

  /* ------------------------------------------------------------------------
     POLL FOR WEBHOOK SETTLEMENT WHEN PROCESSING
     ---------------------------------------------------------------------- */

  useEffect(() => {
    if (!processing) return

    let cancelled = false
    let attempts = 0
    const maxAttempts = 15 // 30 seconds of polling (2s intervals)

    const interval = setInterval(async () => {
      attempts += 1
      try {
        const me = await api.fetchMe()
        if (cancelled) return

        if (me?.plan?.id === planId) {
          refreshUser(me)
          clearInterval(interval)
          navigate('/dashboard', {
            state: {
              notice: `Your ${me?.plan?.name || 'new'} plan is now active!`,
            },
          })
        } else if (attempts >= maxAttempts) {
          clearInterval(interval)
        }
      } catch {
        // Transient network error, keep polling
      }
    }, 2000)

    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [processing, planId, refreshUser, navigate])

  /* ------------------------------------------------------------------------
     PAYING
     ---------------------------------------------------------------------- */

  const submit = useCallback(
    async (event) => {
      // [React] Without this the browser does a full page navigation on submit and
      // the whole app reloads, losing the state this function is about to set.
      event.preventDefault()

      setError('')
      setPaying(true)

      try {
        const payload = isPaddle
          ? { planId }
          : {
              planId,
              cardName,
              /* THE SPACES COME OUT HERE. The server strips them anyway — see
                 _digits_only in payments/mock_card.py — so this is not a correctness
                 fix. It is the display format not leaking into the wire format, which
                 keeps the two independent: change the grouping tomorrow and the
                 request body is unaffected. */
              cardNumber: digitsOnly(cardNumber),
              cardExpiry,
              cardCvc: digitsOnly(cardCvc),
            }

        const result = await api.checkout(payload)
        const action = result.clientAction || result.client_action

        /* BRANCH 1: PADDLE ASYNCHRONOUS CHECKOUT
           When the active provider is Paddle, create_checkout returns "pending" with
           client_action carrying { provider, environment, client_token, transaction_id }.
           The Paddle overlay opens, and webhooks settle the transaction asynchronously. */
        if (
          result.status === 'pending' &&
          (action?.provider === 'paddle' || action?.transaction_id || action?.transactionId)
        ) {
          await openPaddleCheckout({
            clientToken: action?.client_token || action?.clientToken || billingConfig?.clientToken,
            transactionId: action?.transaction_id || action?.transactionId,
            environment: action?.environment || billingConfig?.environment || 'sandbox',
            onCompleted: () => {
              setPaying(false)
              setProcessing(true)
            },
            onClosed: ({ completed }) => {
              setPaying(false)
              if (completed) {
                setProcessing(true)
              } else {
                // User closed or cancelled without completing payment
                window.location.href = `/#${PRICING_ANCHOR}`
              }
            },
            onError: (err) => {
              console.error('[Paddle Error]', err)
              setPaying(false)
              setError('Payment could not be completed. Please try again.')
            },
          })
          return
        }

        /* BRANCH 2: MOCK SYNCHRONOUS CHECKOUT
           Under the mock provider, the plan is granted synchronously inside this
           request, returning status="granted" and a complete order record. */
        if (result.status === 'granted') {
          setCardNumber('')
          setCardCvc('')
          setCardName('')
          setCardExpiry('')

          /* WHY THE USER OBJECT FROM THE RESPONSE, and not a refetch: the server
             already sent the updated account back for exactly this — see the note on
             the endpoint. Putting it straight into context means the dashboard shows
             the new plan the instant this page links to it. A refetch would work and
             would be one more round trip during which the app shows the old plan,
             which reads as the payment not having taken. */
          if (result.user) {
            refreshUser(result.user)
          }

          setReceipt(result)

          /* [React] Back to the top. The receipt replaces a form the user may have
             scrolled down through, and without this they land halfway down a page
             whose content has entirely changed. */
          window.scrollTo({ top: 0, behavior: 'smooth' })
          return
        }

        /* BRANCH 3: UNEXPECTED STATUS */
        setError(
          result.problem ||
            'This payment needs a step this page cannot complete yet. Nothing has been charged.',
        )
      } catch (caught) {
        /* The server's sentence, rendered as-is. card_problem — now in
           payments/mock_card.py, behind the provider interface — returns one
           problem in one sentence written for a person: "That card has expired.",
           "The security code should be 3 digits." — and rewording it here would
           replace a specific message with a vaguer one. */
        setError(caught.message || 'The payment could not be completed.')
      } finally {
        // [React] In `finally` so the button comes back whichever way the request
        // ended. In the success branch only, a failed payment leaves a dead form.
        setPaying(false)
      }
    },
    [planId, isPaddle, billingConfig, cardName, cardNumber, cardExpiry, cardCvc, refreshUser],
  )

  /* ------------------------------------------------------------------------
     THE SHELL

     Six different things can be on this page — loading, load failure, unknown
     plan, unbuyable plan, the form, the receipt — and all six need the same
     header and the same <main id="main"> for the skip link to land on. Rather
     than repeat that six times, each branch returns `shell(...)`. [React]
     ---------------------------------------------------------------------- */

  function shell(children) {
    return (
      /* `container-wide` (1040px), NOT `container` (720px), and the two-column
         layout is the whole reason. At 720px the split gives the card fields about
         300px — narrower than they are on a phone, where they get the full width —
         so the page was worst exactly where there was most room. The receipt branch
         sets its own narrow max-width, so it is unaffected by the wider shell. */
      <div className="container-wide">
        {/* WAS to="/pricing", WHICH IS NOT A ROUTE. App.jsx has no /pricing entry,
            so this link and the one below it both landed on the 404 page - from a
            payment page, which is the worst place in the app to show somebody a dead
            end. The plans live in a section of the landing page, so that is where
            this points.

            [React] A plain <a>, not a <Link>. React Router does not scroll to a hash
            fragment: <Link to="/#pricing"> would navigate to the landing page and
            leave the reader at the top of it, looking for a pricing table they were
            promised. A real anchor makes the browser do the scrolling. */}
        <TopBar meta={<a href={`/#${PRICING_ANCHOR}`}>All plans</a>} />

        <main id="main">{children}</main>
      </div>
    )
  }

  /* A "go back" line used by every dead end. Reused rather than retyped so the
     three failure states cannot drift into three different affordances. */
  const backToPricing = (
    <p className="co-back">
      {/* Same fix as the header link above, for the same reason. */}
      <a className="link-quiet" href={`/#${PRICING_ANCHOR}`}>
        <ArrowLeft size={14} strokeWidth={2} aria-hidden="true" />
        Back to all plans
      </a>
    </p>
  )

  /* ------------------------------------------------------------------------
     BRANCH 1 — STILL LOADING
     ---------------------------------------------------------------------- */

  if (plans === null && !loadError) {
    return shell(
      <div className="co-loading">
        {/* [React] aria-hidden on the icon and the text beside it doing the
            announcing. A screen reader reading "loader" tells nobody anything. */}
        <Loader2 className="co-spin" size={18} strokeWidth={2} aria-hidden="true" />
        <span>Loading plan details…</span>
      </div>,
    )
  }

  /* ------------------------------------------------------------------------
     BRANCH 2 — THE CATALOGUE DID NOT LOAD
     ---------------------------------------------------------------------- */

  if (loadError) {
    return shell(
      <section className="card co-card">
        <h1 className="page-title">Checkout unavailable</h1>

        <p className="auth-error" role="alert">
          <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
          <span>{loadError}</span>
        </p>

        <p className="co-text">
          Nothing has been charged. This is a problem reading the price list, not a
          problem with your account — try again in a moment.
        </p>

        {backToPricing}
      </section>,
    )
  }

  const plan = plans.find((entry) => entry.id === planId) ?? null

  /* ------------------------------------------------------------------------
     BRANCH 3 — NO SUCH PLAN

     A hand-typed URL, or a plan that was removed from the catalogue after
     somebody bookmarked it. Either way the honest answer is short.
     ---------------------------------------------------------------------- */

  if (!plan) {
    return shell(
      <section className="card co-card">
        <h1 className="page-title">That plan does not exist</h1>

        <p className="co-text">
          There is no plan called <code className="co-code">{planId}</code>. It may
          have been renamed or withdrawn.
        </p>

        {backToPricing}
      </section>,
    )
  }

  const marketing = marketingFor(plan.id)

  /* ------------------------------------------------------------------------
     BRANCH 4 — A REAL PLAN THAT IS NOT BOUGHT WITH A CARD

     Free and Enterprise, and the two need completely different sentences: one is
     already yours, the other is a conversation. Both would be a 400 from the
     server, and arriving at that 400 after filling in a card form is the outcome
     this branch exists to prevent.
     ---------------------------------------------------------------------- */

  if (!plan.purchasable) {
    const isFree = plan.amountCents === 0

    return shell(
      <section className="card co-card">
        <h1 className="page-title">{plan.name}</h1>

        {isFree ? (
          <>
            <p className="co-text">
              The {plan.name} plan costs nothing, so there is nothing to pay for.
              Every account has it from the moment it is created.
            </p>

            <Link className="btn-primary" to="/dashboard">
              Go to your dashboard
            </Link>
          </>
        ) : (
          <>
            <p className="co-text">
              {plan.name} is priced individually — scan volume, the number of sites
              and how your team needs it set up all change the figure, so there is no
              button that could quote you honestly.
            </p>

            <p className="co-text">
              Tell us what you need and we will put a number to it.
            </p>

            {/* [General] A mailto: link rather than a contact form, because a
                contact form that posts nowhere is worse than an address that
                works. This is the smallest thing that is actually true. */}
            <a className="btn-primary" href="mailto:sales@secuscan.app?subject=Enterprise%20plan">
              Email us about Enterprise
            </a>
          </>
        )}

        {backToPricing}
      </section>,
    )
  }

  /* ------------------------------------------------------------------------
     BRANCH 4.5 — PAYMENT PROCESSING (ASYNC WEBHOOK SETTLEMENT)
     ---------------------------------------------------------------------- */

  if (processing) {
    return shell(
      <section className="card co-card" style={{ textAlign: 'center', padding: '3.5rem 1.5rem' }}>
        <div style={{ margin: '0 auto 1.5rem', display: 'flex', justifyContent: 'center' }}>
          <Loader2 className="co-spin" size={36} strokeWidth={2.5} style={{ color: 'var(--accent)' }} aria-hidden="true" />
        </div>

        <h1 className="page-title" style={{ fontSize: '1.5rem', marginBottom: '0.75rem' }}>
          Payment processing, your plan will update shortly
        </h1>

        <p className="co-text" style={{ maxWidth: '480px', margin: '0 auto 1.5rem', fontSize: '0.9375rem' }}>
          We received your transaction and are waiting for confirmation from Paddle to activate your{' '}
          <strong>{plan.name}</strong> subscription. This usually takes just a few moments.
        </p>

        <div className="co-actions" style={{ justifyContent: 'center' }}>
          <button
            className="btn-primary"
            type="button"
            onClick={() =>
              navigate('/dashboard', {
                state: {
                  notice: 'Payment processing, your plan will update shortly.',
                },
              })
            }
          >
            Go to dashboard
          </button>
        </div>
      </section>,
    )
  }

  /* ------------------------------------------------------------------------
     BRANCH 5 — DONE. THE RECEIPT.
     ---------------------------------------------------------------------- */

  if (receipt) {
    const { order } = receipt

    return shell(
      <section className="card co-card co-receipt">
        <div className="co-tick" aria-hidden="true">
          <Check size={22} strokeWidth={2.5} />
        </div>

        <h1 className="page-title">You are on {receipt.plan.name}</h1>

        <p className="co-text">
          Your plan is active now. Everything below is also in your billing history,
          under Settings.
        </p>

        <dl className="co-facts">
          <div className="co-fact">
            <dt>Plan</dt>
            <dd>{order.planName}</dd>
          </div>

          <div className="co-fact">
            <dt>Amount</dt>
            <dd>
              {formatAmount(order.amountCents, order.currency)}
              {intervalSuffix(order.interval)}
            </dd>
          </div>

          <div className="co-fact">
            <dt>Card</dt>
            {/* The whole of what the system knows about the card. See the header. */}
            <dd>
              {order.cardBrand} ending {order.cardLast4}
            </dd>
          </div>

          <div className="co-fact">
            <dt>Renews</dt>
            <dd>{formatDate(order.periodEnd)}</dd>
          </div>

          <div className="co-fact">
            <dt>Reference</dt>
            <dd>
              <code className="co-code">{order.id}</code>
            </dd>
          </div>
        </dl>

        <div className="co-actions">
          <button className="btn-primary" type="button" onClick={() => navigate('/dashboard')}>
            Start scanning
          </button>

          <Link className="btn-secondary" to="/settings">
            Billing settings
          </Link>
        </div>
      </section>,
    )
  }

  /* ------------------------------------------------------------------------
     BRANCH 6 — THE FORM
     ---------------------------------------------------------------------- */

  /* Already on it. NOT a block — the server allows it, and buying a plan you
     already have is a legitimate way to start a fresh period or move to a
     different card. It is worth SAYING, though, because the far more likely reason
     somebody is here is that they lost track. */
  const alreadyOnThisPlan = user?.plan?.id === plan.id

  return shell(
    <>
      <h1 className="page-title">Checkout</h1>
      <p className="page-sub">
        {/* The plan name in the subtitle so it is on screen before any scrolling,
            on a phone where the summary card may start below the fold. */}
        You are subscribing to {plan.name}.
      </p>

      <div className="co-layout">
        {/* ORDER SUMMARY FIRST IN THE MARKUP, and moved to the right by CSS on a
            wide screen. [General] Source order is what a screen reader and the tab
            key follow, and "what am I buying" should be read before "type your card
            number" regardless of where the two sit visually. */}
        <section className="card co-card co-summary" aria-labelledby="co-summary-title">
          <h2 className="co-heading" id="co-summary-title">
            Order summary
          </h2>

          <div className="co-price">
            <span className="co-amount">
              {formatAmount(plan.amountCents, plan.currency)}
            </span>
            <span className="co-interval">{intervalSuffix(plan.interval)}</span>
          </div>

          <p className="co-plan-name">{plan.name}</p>

          {marketing?.description && <p className="co-text">{marketing.description}</p>}

          {/* The limits come from the SERVER's plan, not from the marketing copy,
              because these two numbers are enforced — they are what the account is
              actually granted. A feature bullet that overstates them would be a
              promise nothing keeps. */}
          <ul className="co-limits">
            <li>
              <Check size={14} strokeWidth={2.5} aria-hidden="true" />
              {plan.scanLimit === null
                ? 'Unlimited scans'
                : `${plan.scanLimit} scans per month`}
            </li>
            <li>
              <Check size={14} strokeWidth={2.5} aria-hidden="true" />
              {plan.siteLimit === null ? 'Unlimited sites' : `${plan.siteLimit} sites`}
            </li>
          </ul>

          {alreadyOnThisPlan && (
            <p className="co-note">
              <Info size={14} strokeWidth={2} aria-hidden="true" />
              <span>
                You are already on {plan.name}. Paying again starts a new billing
                period from today.
              </span>
            </p>
          )}
        </section>

        {/* THE PAYMENT FORM (BRANCHES ON PROVIDER: PADDLE OVERLAY VS MOCK CARD FORM) */}
        {isPaddle ? (
          <section className="card co-card co-form-card" aria-labelledby="co-pay-title">
            <h2 className="co-heading" id="co-pay-title">
              <Lock size={16} strokeWidth={2} aria-hidden="true" />
              Secure payment
            </h2>

            <p className="co-text" style={{ margin: '0 0 1.5rem', fontSize: '0.9375rem' }}>
              You will be directed to Paddle's secure checkout overlay to enter your payment details and subscribe to {plan.name}.
            </p>

            {error && (
              <p className="auth-error" role="alert" style={{ marginBottom: '1.25rem' }}>
                <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
                <span>{error}</span>
              </p>
            )}

            <form className="auth-form" onSubmit={submit}>
              <button className="btn-primary" type="submit" disabled={paying} style={{ width: '100%' }}>
                {paying ? (
                  <>
                    <Loader2 className="co-spin" size={15} strokeWidth={2} aria-hidden="true" />
                    Opening checkout…
                  </>
                ) : (
                  <>
                    <Lock size={15} strokeWidth={2} aria-hidden="true" />
                    Proceed to Checkout
                  </>
                )}
              </button>
            </form>

            <p className="co-fine" style={{ marginTop: '1.5rem' }}>
              <ShieldCheck size={14} strokeWidth={2} aria-hidden="true" />
              <span>
                Payments are securely processed by Paddle, our Merchant of Record.
                SecuScan never sees or stores your payment details.
              </span>
            </p>
          </section>
        ) : (
          <section className="card co-card co-form-card" aria-labelledby="co-pay-title">
            <h2 className="co-heading" id="co-pay-title">
              <CreditCard size={16} strokeWidth={2} aria-hidden="true" />
              Card details
            </h2>

            {/* THE HONESTY NOTICE. Not removable. See the header — a form that looks
                like a real payment form while being something else is the one thing
                this page must not be, and this paragraph is what makes it not that. */}
            <p className="co-demo" role="note">
              <AlertCircle size={15} strokeWidth={2} aria-hidden="true" />
              <span>
                <strong>No card is charged.</strong> SecuScan is not connected to a
                payment processor. Your card is checked for shape only, recorded as a
                brand and last four digits, and the plan is applied immediately. Please
                do not enter a card you would not want stored as four digits.
              </span>
            </p>

            <form className="auth-form" onSubmit={submit}>
              <div className="field">
                <label className="field-label" htmlFor="co-name">
                  Name on card
                </label>
                <input
                  className="input auth-input"
                  id="co-name"
                  type="text"
                  value={cardName}
                  onChange={(event) => setCardName(event.target.value)}
                  placeholder="As printed on the card"
                  /* [General] The autoComplete tokens are the reason a browser can
                     fill this form in one tap. They are a fixed vocabulary — "cc-name"
                     is understood, "cardname" is ignored silently — which is why they
                     are worth getting exactly right. */
                  autoComplete="cc-name"
                  required
                  disabled={paying}
                />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="co-number">
                  Card number
                </label>
                <input
                  className="input auth-input co-mono"
                  id="co-number"
                  /* type="text" AND NOT type="number". A number input strips leading
                     zeros, offers a spinner nobody wants on a card field, and refuses
                     the spaces the formatter inserts. inputMode is the attribute that
                     actually brings up the numeric keypad on a phone. [General] */
                  type="text"
                  inputMode="numeric"
                  value={cardNumber}
                  onChange={(event) => setCardNumber(formatCardNumber(event.target.value))}
                  placeholder="4242 4242 4242 4242"
                  autoComplete="cc-number"
                  required
                  disabled={paying}
                />
              </div>

              <div className="co-pair">
                <div className="field">
                  <label className="field-label" htmlFor="co-expiry">
                    Expiry
                  </label>
                  <input
                    className="input auth-input co-mono"
                    id="co-expiry"
                    type="text"
                    inputMode="numeric"
                    value={cardExpiry}
                    onChange={(event) => setCardExpiry(formatExpiry(event.target.value))}
                    placeholder="MM/YY"
                    autoComplete="cc-exp"
                    required
                    disabled={paying}
                  />
                </div>

                <div className="field">
                  <label className="field-label" htmlFor="co-cvc">
                    Security code
                  </label>
                  <input
                    className="input auth-input co-mono"
                    id="co-cvc"
                    type="text"
                    inputMode="numeric"
                    value={cardCvc}
                    /* The length follows the brand — four on Amex, three otherwise.
                       A cap, not a check: the server decides, and this only stops a
                       fifth digit being typed into a field that has no use for it. */
                    maxLength={cvcLength(cardNumber)}
                    onChange={(event) => setCardCvc(digitsOnly(event.target.value))}
                    placeholder={cvcLength(cardNumber) === 4 ? '4 digits' : '3 digits'}
                    autoComplete="cc-csc"
                    required
                    disabled={paying}
                  />
                </div>
              </div>

              {error && (
                <p className="auth-error" role="alert">
                  <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
                  <span>{error}</span>
                </p>
              )}

              <button className="btn-primary" type="submit" disabled={paying}>
                {paying ? (
                  'Processing…'
                ) : (
                  <>
                    <Lock size={15} strokeWidth={2} aria-hidden="true" />
                    Pay {formatAmount(plan.amountCents, plan.currency)}
                  </>
                )}
              </button>

              {/* The amount is on the button as well as in the summary, deliberately.
                  It is the last thing read before the irreversible action, and a
                  button that says only "Pay" asks somebody to trust that they
                  remember what they scrolled past. */}
            </form>

            <p className="co-fine">
              <ShieldCheck size={14} strokeWidth={2} aria-hidden="true" />
              <span>
                Your card number is sent to SecuScan and to nobody else. It is never
                written to our database — only the brand and the last four digits are
                kept, so a receipt can identify which card you used.
              </span>
            </p>
          </section>
        )}
      </div>

      {backToPricing}
    </>,
  )
}
