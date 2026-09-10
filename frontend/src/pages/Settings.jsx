/* ============================================================================
   SETTINGS.JSX — the account page at "/settings".

   WHY THIS EXISTS: six things a signed-in user needs to do to their own account,
   and until now none of them had a home. In order down the page:

     1. Read who they are — address, how they get in, when the account started.
     2. See what they pay, stop paying it, and read their receipts.
     3. Turn TOTP two-factor on, or off.
     4. Replace their recovery codes.
     5. Change their password.
     6. Sign out of everything.

   THIS FILE REPLACED pages/Security.jsx, at the user's direction, and the reason is
   worth recording: "Security" was the wrong name for a page that also shows an email
   address and a created date. /dashboard/security now redirects here (see App.jsx),
   because a link somebody bookmarked should not 404 to prove a point about naming.

   ---------------------------------------------------------------------------
   ONE ENROLMENT FLOW, TWO DOORS INTO IT

   The TOTP setup on this page is NOT a second implementation of the one at
   /login/enrol. Both end in the same two server helpers — _issue_totp_setup and
   _complete_totp_setup in main.py — reached through two endpoint pairs that differ
   only in what authenticates the caller:

     /2fa/enrol/start + /2fa/enrol/finish   authenticated by a login CHALLENGE
     /2fa/setup       + /2fa/confirm        authenticated by a SESSION

   Two pairs rather than one because at /login/enrol there is no session yet — that
   is the entire situation that page exists for. What must not be duplicated is the
   secret generation, the pending-then-promote rule and the recovery code minting,
   and none of it is: this page and that page are two forms over one flow.

   ---------------------------------------------------------------------------
   WHY EVERY DESTRUCTIVE ACTION HERE ASKS FOR THE PASSWORD AGAIN

   A session token is a BEARER credential — whoever holds it is the user, as far as
   the server can tell. So anything doable with a session alone is doable by whoever
   steals one, and the three actions on this page are precisely what such a person
   wants: turn the second factor off, mint themselves ten permanent bypasses, or
   change the password and own the account outright. Asking for the password is
   step-up authentication, and it is the same reason a bank asks for a PIN to change
   an address on a session you are already inside.

   ---------------------------------------------------------------------------
   WHAT "VIEW YOUR RECOVERY CODES" CAN AND CANNOT MEAN

   It can only ever be a COUNT, and that is not a shortcut taken here. The server
   stores Argon2 hashes of the codes (new_recovery_codes in auth.py), so there is no
   endpoint that could list the unused ones — not because none was written, but
   because the data to answer with does not exist. /2fa/status returns
   recoveryCodesLeft, an integer, and the only way to see codes again is to replace
   the set. The page says that in as many words rather than offering a "view" button
   that shows a number.

   ---------------------------------------------------------------------------
   A GOOGLE-ONLY ACCOUNT CANNOT USE MOST OF THIS, and the page says so rather than
   offering buttons that will 400. Such an account has no SecuScan password to step
   up against, and Google has already applied whatever second factor it has. Both
   `hasPassword` and `hasGoogle` come from the user object for exactly this branch —
   two booleans and not one "method" string, because an account created with a
   password that later linked Google has both, and can use every form on this page.
   ========================================================================== */

import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldCheck,
  ShieldOff,
  AlertCircle,
  KeyRound,
  RefreshCw,
  Smartphone,
  Mail,
  CalendarDays,
  LogOut,
  Lock,
  Check,
  X,
  CreditCard,
  Receipt,
  ArrowUpRight,
  Ban,
  Undo2,
} from 'lucide-react'

import TopBar from '../components/TopBar'
import RecoveryCodes from '../components/RecoveryCodes'
import { useAuth } from '../context/AuthContext'
import { checkPassword, PASSWORD_MIN_LENGTH } from '../lib/passwordPolicy'
import { formatAbsoluteDate } from '../lib/formatDate'
import { formatAmount, intervalSuffix } from '../lib/cardFormat'
import { PRICING_ANCHOR } from '../lib/pricing'
import * as api from '../lib/api'
import '../styles/auth.css'
import '../styles/settings.css'

export default function Settings() {
  /* refreshUser is new here, and it is what stops the "Plan" a visitor reads in the
     TopBar from disagreeing with the one this page just changed. Cancelling returns
     the updated account, so the whole app learns about it in the same tick rather
     than on the next /auth/me. */
  const { user, signOut, refreshUser } = useAuth()

  /* The server's view of this account's 2FA state: { enabled, required, hasPassword,
     isGoogleAccount, recoveryCodesLeft, emailAvailable }. Null until it answers,
     which is why the sections below guard on it rather than reading `.enabled` off
     nothing. */
  const [status, setStatus] = useState(null)
  const [loadError, setLoadError] = useState('')

  /* THE BILLING PICTURE: { plan, subscription, orders } from GET /billing/subscription.
     Null until it answers.

     `subscription` inside it is null on a Free account — a STATE, not a missing value,
     and the section below reads it that way. `orders` is the receipt history and
     deliberately survives a cancellation: what somebody paid for last month happened,
     whether or not they are still a customer. That is most of why the history is worth
     showing at all. */
  const [billing, setBilling] = useState(null)

  /* A SEPARATE ERROR FROM loadError, and the separation is the point. loadError blanks
     this entire page — see the early return — which is right for /2fa/status, since
     almost every section below depends on it. It would be wrong here: a billing
     endpoint that is down must not take away somebody's ability to change their
     password or turn on two-factor. So this failure is rendered inside the billing
     section and nowhere else. */
  const [billingError, setBillingError] = useState('')

  /* The enrolment secret and QR, once "Turn on" has been pressed. Non-null is what
     replaces the 2FA section with the scan-and-confirm step. */
  const [setup, setSetup] = useState(null)

  /* Fresh codes to display once, from either /2fa/confirm or /2fa/recovery-codes.
     Non-empty takes over the whole page — see the early return further down for why
     that is deliberate rather than lazy. */
  const [freshCodes, setFreshCodes] = useState([])

  /* WHICH FORM IS OPEN: '' | 'cancel' | 'regenerate' | 'disable' | 'password' |
     'signout'. A single string rather than five booleans, because they are mutually
     exclusive and five booleans can all be true at once. Opening one closes the
     others, which falls out of the representation instead of needing to be enforced. */
  const [panel, setPanel] = useState('')

  /* One set of fields shared by the open form. Not per-form state: only one form is
     ever on screen, and `openPanel` clears these on every switch — so there is no
     way for a password typed into one form to still be in memory behind another. */
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')

  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  /* A sentence confirming something that produced no visible artefact — turning 2FA
     off, changing a password. Cleared by the next action. */
  const [done, setDone] = useState('')

  /* WHY A useCallback AND NOT JUST A LINE IN THE EFFECT: three things load this —
     the effect below on first render, and the cancel and resume actions afterwards,
     both of which change what the server would say. Re-reading rather than patching
     the local copy is the same choice refreshStatus() makes further down, for the
     same reason: the server owns whether a period has lapsed, and it resolves that
     on every read.

     [React] useCallback keeps one function identity across renders, so the effect's
     dependency array does not re-fire it on every keystroke in the password field. */
  const loadBilling = useCallback(async () => {
    try {
      setBilling(await api.fetchSubscription())
      setBillingError('')
    } catch (caught) {
      setBillingError(caught.message)
    }
  }, [])

  useEffect(() => {
    /* NO `cancelled` FLAG NEEDED HERE, unlike the effect below. loadBilling only ever
       sets state, and React tolerates a set on an unmounted component - it is a no-op,
       not the warning it used to be. The 2FA effect keeps its flag because it was
       written against the older behaviour and changing it would be churn. */
    loadBilling()
  }, [loadBilling])

  useEffect(() => {
    let cancelled = false

    api
      .fetchTwoFactorStatus()
      .then((result) => {
        if (cancelled) return
        setStatus(result)
      })
      .catch((caught) => {
        if (cancelled) return
        setLoadError(caught.message)
      })

    /* [React] The cleanup function. React runs it when the component unmounts, and
       `cancelled` is what stops a response that arrives afterwards from calling
       setState on something no longer on screen. */
    return () => {
      cancelled = true
    }
  }, [])

  /* Live feedback on the new password, using the same module the signup form uses.
     WHY SHARED: two copies of the rules is how a form starts accepting a password
     the API rejects. This is the browser copy — the enforcement copy is
     auth.password_problem in Python, and /auth/change-password calls it with the
     same email and name passed here. */
  const strength = checkPassword(newPassword, {
    email: user?.email ?? '',
    name: user?.name ?? '',
  })

  /* WHY THIS EXISTS: five handlers below all finish by needing the server's new view
     of the account, and re-fetching is more honest than patching the local copy from
     what we think happened. The recovery code count in particular is the server's to
     state — a local decrement would already be wrong if a code had been spent in
     another tab. */
  async function refreshStatus() {
    try {
      setStatus(await api.fetchTwoFactorStatus())
    } catch {
      /* Deliberately swallowed. The ACTION succeeded and only the refresh failed;
         turning that into an error message would tell the user their change failed
         when it did not. A stale count is a cosmetic problem a reload fixes. */
    }
  }

  /* [General] One wrapper around every action, because all of them share the same
     four lines of ceremony — clear the messages, set busy, catch into `error`, clear
     busy. Written out six times, the sixth copy is where the `finally` gets forgotten
     and the page stays stuck on "Working…". */
  async function run(action) {
    if (busy) return

    setError('')
    setDone('')
    setBusy(true)

    try {
      await action()
    } catch (caught) {
      /* The server's message, shown as written. These are sentences meant for a
         user — "Your current password is incorrect." — and rewriting them here would
         mean maintaining a second set of wordings that drifts from the first. */
      setError(caught.message)
    } finally {
      setBusy(false)
    }
  }

  /* Opening a form clears every field and message. WHY IT MATTERS beyond tidiness:
     without it, a password typed into the change-password form is still in state when
     the sign-out-everywhere form opens, and its submit would send it — a field the
     user cannot see contributing to a request they did not intend. */
  function openPanel(next) {
    setPanel((current) => (current === next ? '' : next))
    setCode('')
    setPassword('')
    setNewPassword('')
    setError('')
    setDone('')
  }

  /* --- The actions ------------------------------------------------------- */

  /* WHY CANCELLING IS TWO CLICKS: `openPanel('cancel')` shows a panel that states
     what actually happens, and only the button inside it calls the endpoint. A
     one-click cancel next to four other buttons is a bill somebody loses by
     mis-clicking, and there is no undo that returns the month.

     THE WORDING IN THAT PANEL IS THE PART THAT MATTERS, though, more than the extra
     click: the plan does NOT stop today. It runs to the end of the period already
     paid for and then lapses. A confirmation that said "are you sure?" and nothing
     else would leave the user to guess which of those two things they were agreeing
     to, and the two are a month apart. */
  function cancelPlan() {
    return run(async () => {
      const result = await api.cancelSubscription()

      /* The account, everywhere, in one go - the TopBar and the dashboard read the
         same context. See the note where refreshUser is destructured. */
      refreshUser(result.user)

      /* AND THEN RE-READ, rather than building the panel out of `result`. The response
         carries plan and subscription but not the ORDERS, and the history below is
         part of this section. One request that returns all three consistently beats
         patching two of them and leaving the third stale. */
      await loadBilling()

      setPanel('')

      /* The date comes from the SERVER's copy of the subscription, not from the one
         this page was showing a moment ago. If the two ever disagree, the server is
         right, and this is the sentence the user will remember. */
      const endsOn = result.subscription?.currentPeriodEnd

      setDone(
        endsOn
          ? `Your plan is cancelled and will not renew. You keep everything it ` +
            `includes until ${formatAbsoluteDate(endsOn)}.`
          : 'Your plan is cancelled. The account is back on Free.',
      )
    })
  }

  /* WHY THIS EXISTS: see the note on POST /billing/resume. End-of-period cancellation
     opens a window in which the plan is live and set to stop, and without this the
     only way back is to buy the same month twice. A flag a user can set and cannot
     unset is a trap.

     ONE CLICK, NOT TWO. The asymmetry is deliberate: this is the recoverable
     direction. Making somebody confirm that they want to keep paying for the thing
     they are already paying for is friction for no benefit. */
  function resumePlan() {
    return run(async () => {
      const result = await api.resumeSubscription()

      refreshUser(result.user)
      await loadBilling()

      setDone('Your plan will renew as normal. Nothing was charged for this.')
    })
  }

  function startEnrolment() {
    return run(async () => {
      setSetup(await api.setupTwoFactor())
      setCode('')
      setPanel('')
    })
  }

  function confirmEnrolment(event) {
    event.preventDefault()

    return run(async () => {
      const result = await api.confirmTwoFactor(code)

      setFreshCodes(result.recoveryCodes ?? [])
      setSetup(null)
      setCode('')
      await refreshStatus()
    })
  }

  function regenerate(event) {
    event.preventDefault()

    return run(async () => {
      const result = await api.regenerateRecoveryCodes(code)

      setFreshCodes(result.recoveryCodes ?? [])
      setPanel('')
      setCode('')
      await refreshStatus()
    })
  }

  function disable(event) {
    event.preventDefault()

    return run(async () => {
      await api.disableTwoFactor({ password, code })

      setPanel('')
      setCode('')
      setPassword('')
      setDone(
        'Two-factor authentication is off, and your recovery codes have been deleted. Turning it back on will issue a brand new key — your authenticator app will need to scan a fresh QR code.',
      )
      await refreshStatus()
    })
  }

  function submitPassword(event) {
    event.preventDefault()

    return run(async () => {
      const result = await api.changePassword({
        currentPassword: password,
        newPassword,
      })

      setPanel('')
      setPassword('')
      setNewPassword('')

      /* THE COUNT COMES FROM THE SERVER, not from a guess. It is the number of OTHER
         sessions that were ended — this one survives on purpose, since the request
         already proved knowledge of the old password. Saying so explicitly is the
         difference between a user trusting the change and wondering whether their
         other laptop is still signed in. */
      const others = result.otherSessionsSignedOut ?? 0

      setDone(
        others > 0
          ? `Password changed. ${others} other ${others === 1 ? 'session was' : 'sessions were'} signed out; this one stays.`
          : 'Password changed. There were no other sessions to sign out.',
      )
    })
  }

  function signOutEverywhere(event) {
    event.preventDefault()

    return run(async () => {
      await api.signOutEverywhere(password)

      /* THE ORDER HERE IS THE WHOLE THING. The server has already deleted every
         session including this one, so the token in localStorage is inert — but it
         is still SITTING there, and the app still believes it is signed in until
         something clears it.

         signOut() from AuthContext is what clears it, and it is the right call
         rather than a bare clearSession() for a reason worth knowing: it fires the
         same SESSION_ENDED_EVENT an expiring session fires, so the app winds down
         through exactly one code path however a session ends. Its api.logout() call
         will now 401 and be ignored — api.logout never throws, by design. */
      await signOut()
    })
  }

  /* --- Shell ------------------------------------------------------------- */

  /* WHY THE PAGE CHROME IS A FUNCTION RATHER THAN REPEATED: there are four exit
     points below and each needs the same TopBar, heading and container. Four copies
     is three chances for one of them to lose the skip-link target. */
  function shell(children) {
    return (
      <div className="container">
        <TopBar meta={<Link to="/dashboard">Dashboard</Link>} />

        <main id="main">
          <h1 className="page-title">Settings</h1>
          <p className="page-sub">Your account, how you sign in, and where you are signed in.</p>

          {children}
        </main>
      </div>
    )
  }

  /* --- Fresh codes take over the page ------------------------------------ */

  /* WHY THIS IS AN EARLY RETURN RATHER THAN A PANEL AMONG THE OTHERS: these values
     exist in readable form exactly once, and a user who scrolls past them has lost
     them permanently. Nothing else should be competing for attention while they are
     on screen — not the password form, not the sign-out button. */
  if (freshCodes.length > 0) {
    return shell(
      <section className="card set-card">
        <RecoveryCodes
          codes={freshCodes}
          accountEmail={user?.email ?? ''}
          continueLabel="Done"
          /* No gate here, unlike the login path. This user already has a session and
             can navigate away regardless, so a checkbox blocking a button they do not
             need to press would be theatre. See the prop's comment in
             RecoveryCodes.jsx. */
          requireAcknowledgement={false}
          onContinue={() => setFreshCodes([])}
        />
      </section>,
    )
  }

  /* --- Enrolment takes over the 2FA section ------------------------------ */

  if (setup) {
    return shell(
      <section className="card set-card">
        <h2 className="set-heading">Scan this with your authenticator app</h2>

        <p className="set-text">
          Google Authenticator, 1Password, Bitwarden, Authy — any of them. This is the
          standard TOTP scheme, not something specific to SecuScan.
        </p>

        {/* [React] The QR is an inline SVG data URI from the server — see
            totp_qr_data_uri in auth.py for why it is not a separate image endpoint.
            An <img> is correct rather than dangerouslySetInnerHTML: a data URI in src
            is inert, where injecting SVG markup into the document would let a
            compromised server run script in this page. */}
        <img
          className="enrol-qr"
          src={setup.qr}
          /* NOT the secret in the alt text, which would put the credential into a
             screen reader's output for anyone within earshot. The manual-entry block
             below is the accessible path, and it says so. */
          alt="QR code for setting up two-factor authentication"
          width={180}
          height={180}
        />

        <p className="set-text">No camera? Type this key in by hand instead:</p>

        <p className="enrol-secret mono">{setup.secret}</p>

        <p className="enrol-step-meta">
          {setup.digits} digits, refreshing every {setup.period} seconds.
        </p>

        <form className="auth-form" onSubmit={confirmEnrolment}>
          <div className="field">
            <label className="field-label" htmlFor="set-confirm-code">
              Enter the code it shows
            </label>
            <input
              className="input auth-input auth-code-input"
              id="set-confirm-code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              maxLength={6}
              value={code}
              onChange={(event) => setCode(event.target.value)}
              required
              disabled={busy}
              /* Autofocus is justified here: the page has one field, the user just
                 pressed the button that produced it, and typing the code is the only
                 thing left to do. */
              autoFocus
            />
          </div>

          <p className="auth-fine">
            This is what proves the key reached your app rather than only appearing on
            this screen. Nothing is switched on until it does.
          </p>

          {error && (
            <p className="auth-error" role="alert">
              <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
              <span>{error}</span>
            </p>
          )}

          <div className="set-actions">
            <button className="btn-primary" type="submit" disabled={busy || !code}>
              {busy ? 'Confirming…' : 'Turn on two-factor'}
            </button>

            {/* CANCELLING LEAVES THE PENDING SECRET ON THE SERVER, and that is
                harmless by design: a pending secret is not 2FA — see
                set_pending_totp_secret in database.py — and the next /2fa/setup
                overwrites it. Nothing to clean up, so no endpoint to call. */}
            <button
              className="btn-secondary"
              type="button"
              disabled={busy}
              onClick={() => {
                setSetup(null)
                setCode('')
                setError('')
              }}
            >
              Cancel
            </button>
          </div>
        </form>
      </section>,
    )
  }

  /* --- The page proper -------------------------------------------------- */

  /* Read from the user object rather than /2fa/status. Both know these facts, and the
     user object is the right source: it is the account record, where /2fa/status is a
     two-factor endpoint that happens to report them. `?? false` because an old cached
     user in localStorage predates these fields. */
  const hasPassword = user?.hasPassword ?? status?.hasPassword ?? false
  const hasGoogle = user?.hasGoogle ?? status?.isGoogleAccount ?? false

  /* Unpacked once, so the section below reads as prose rather than as five
     `billing?.something` chains. All three are safe before the fetch lands: null plan,
     null subscription, empty history — which is exactly what a Free account looks like
     anyway, so there is one shape to render and not two. */
  const plan = billing?.plan ?? null
  const subscription = billing?.subscription ?? null
  const orders = billing?.orders ?? []

  /* THE ONE BOOLEAN THE WHOLE PANEL TURNS ON. `currentPeriodEnd` is a single date with
     two opposite meanings — the day the card is charged again, or the day access stops
     — and this is what tells them apart. See the note on it in _public_subscription:
     "renews on the 4th" shown to somebody who cancelled is the kind of wrong that
     generates a chargeback. */
  const cancelling = Boolean(subscription?.cancelAtPeriodEnd)

  /* A PAID PLAN IS ONE THE SERVER PRICED ABOVE ZERO, not one whose id is in a list
     here. amountCents comes from billing.PLANS, so a plan added or repriced on the
     server needs no edit on this page. `> 0` rather than truthiness because
     Enterprise's amount is null - no figure exists until somebody has been quoted -
     and null is not a price of zero. */
  const onPaidPlan = Boolean(plan && plan.amountCents > 0)

  return shell(
    <>
      {/* ================= 1. ACCOUNT ==================================== */}

      <section className="card set-card">
        <h2 className="set-heading">Account</h2>

        <dl className="set-facts">
          {/* [General] <dl> — a description list — is the right element for
              label/value pairs, and it is what makes a screen reader announce "Email:
              you@company.com" rather than reading two unrelated lines of text. <dt>
              is the term, <dd> the description. */}
          <div className="set-fact">
            <dt>
              <Mail size={14} strokeWidth={2} aria-hidden="true" />
              Email
            </dt>
            <dd>{user?.email}</dd>
          </div>

          <div className="set-fact">
            <dt>
              <KeyRound size={14} strokeWidth={2} aria-hidden="true" />
              Sign-in method
            </dt>
            <dd>
              {/* BOTH ARE POSSIBLE AT ONCE, which is why this is not a ternary over a
                  single "method" field. An account created with a password that later
                  signs in with Google — see link_google_id in database.py — has both,
                  and can use every form on this page. */}
              {hasPassword && hasGoogle
                ? 'Password, and Google'
                : hasGoogle
                  ? 'Google'
                  : 'Email and password'}
            </dd>
          </div>

          <div className="set-fact">
            <dt>
              <CalendarDays size={14} strokeWidth={2} aria-hidden="true" />
              Account created
            </dt>
            <dd>
              {/* `createdAt` has been stored since the first signup and was simply
                  never returned — nothing had asked for it. An account that predates
                  this field being served says so rather than rendering "Invalid
                  Date". */}
              {user?.createdAt ? formatAbsoluteDate(user.createdAt) : 'Not recorded'}
            </dd>
          </div>

          {/* THE "Plan" ROW USED TO BE HERE, reading `user?.plan?.name ?? 'Free'`,
              and it was the entire billing UI. It moved into its own section below
              rather than being kept as well: the plan now comes with a price, a
              status, a date, a card and a receipt history, and a row up here saying
              "Starter" beside a panel saying "Starter" is one fact rendered twice.
              Two renderings of one fact is how they eventually disagree. */}
        </dl>
      </section>

      {/* ================= 2. BILLING ==================================== */}

      {/* WHY THIS SITS SECOND, ABOVE TWO-FACTOR
          The order of this page runs "who you are, then what you pay, then how you are
          protected". Money before security is not a claim about which matters more — it
          is that a billing question is the one somebody arrives here URGENTLY wanting
          answered ("what am I being charged, and when?"), and burying it under three
          security sections means scrolling past things they did not come for. */}
      <section className="card set-card">
        <h2 className="set-heading">Plan and billing</h2>

        {/* RENDERED HERE RATHER THAN BLANKING THE PAGE — see the note on billingError.
            /billing/subscription being down must not cost somebody the ability to
            change their password. */}
        {billingError && (
          <p className="auth-error" role="alert">
            <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
            <span>{billingError}</span>
          </p>
        )}

        {!billing && !billingError && (
          <p className="set-text" role="status">
            Loading your plan…
          </p>
        )}

        {billing && (
          <>
            <dl className="set-facts">
              <div className="set-fact">
                <dt>
                  <ShieldCheck size={14} strokeWidth={2} aria-hidden="true" />
                  Plan
                </dt>
                {/* `?? 'Free'` for the same reason billing.plan_for_user falls back to
                    it on the server: an account that predates billing has no plan
                    field, and Free is both the safe answer and the true one, since
                    they have paid nothing. */}
                <dd>{plan?.name ?? 'Free'}</dd>
              </div>

              <div className="set-fact">
                <dt>
                  <CreditCard size={14} strokeWidth={2} aria-hidden="true" />
                  Price
                </dt>
                <dd>
                  {/* THE FIGURE IS THE SERVER'S. formatAmount turns an integer number
                      of cents into "$49.00" and invents nothing; a null amount —
                      Enterprise, which has no price until somebody has been quoted —
                      comes out as "Custom pricing" rather than as "$0.00", which would
                      be a quote we are not entitled to give. intervalSuffix adds
                      "/ month" only for the intervals that actually recur, so Free
                      reads "$0.00" and not "$0.00 / month". */}
                  {formatAmount(plan?.amountCents, plan?.currency ?? 'USD')}
                  {intervalSuffix(plan?.interval)}
                </dd>
              </div>

              <div className="set-fact">
                <dt>
                  <CalendarDays size={14} strokeWidth={2} aria-hidden="true" />
                  {/* THE LABEL CHANGES, not just the date beside it. One stored date,
                      two opposite meanings, and the label is the clearest place to say
                      which one is on screen. */}
                  {cancelling ? 'Access until' : subscription ? 'Renews' : 'Status'}
                </dt>
                <dd>
                  {subscription?.currentPeriodEnd
                    ? formatAbsoluteDate(subscription.currentPeriodEnd)
                    : subscription
                      ? 'No renewal date recorded'
                      : /* NO SUBSCRIPTION IS A STATE, NOT A GAP. A Free account has
                           never had one, and saying so beats an empty value or a dash
                           the reader has to interpret. */
                        'Nothing to renew'}
                </dd>
              </div>

              {/* THE CARD ROW APPEARS ONLY IF THERE IS A CARD. An empty "Card:" row on
                  a Free account invites the reader to wonder whether one is on file and
                  simply not being shown. */}
              {subscription?.cardLast4 && (
                <div className="set-fact">
                  <dt>
                    <CreditCard size={14} strokeWidth={2} aria-hidden="true" />
                    Card
                  </dt>
                  <dd>
                    {/* A BRAND AND FOUR DIGITS IS ALL THAT EXISTS TO SHOW. The number
                        never reached the database — describe_card in
                        payments/mock_card.py reduces it to this at the boundary — so
                        this is not a redaction of something stored, it is the whole
                        record. */}
                    {subscription.cardBrand} ending {subscription.cardLast4}
                  </dd>
                </div>
              )}
            </dl>

            {/* WHY A SENTENCE AS WELL AS THE ROWS ABOVE: "Access until 4 October" is
                precise and does not say WHY. Somebody who cancelled a fortnight ago and
                came back to check needs to be told that the cancellation is still in
                force and the plan is still working — which no single field above says on
                its own. */}
            {cancelling && (
              <p className="set-text">
                This plan is cancelled and will not renew. Everything it includes keeps
                working until the date above, and then the account returns to Free.
              </p>
            )}

            {/* --- The controls ------------------------------------------------ */}

            {onPaidPlan ? (
              <>
                <div className="set-actions">
                  {cancelling ? (
                    /* ONE CLICK, no confirmation. This is the direction that costs
                       nobody anything: the worst outcome of an accidental press is that
                       a plan somebody is paying for carries on, and it can be cancelled
                       again immediately. Guarding the recoverable direction as heavily
                       as the destructive one teaches people to click through both. */
                    <button
                      className="btn-primary"
                      type="button"
                      disabled={busy}
                      onClick={resumePlan}
                    >
                      <Undo2 size={15} strokeWidth={2} />
                      {busy ? 'Working…' : 'Keep my plan'}
                    </button>
                  ) : (
                    <button
                      className="btn-secondary"
                      type="button"
                      disabled={busy}
                      onClick={() => openPanel('cancel')}
                    >
                      <Ban size={15} strokeWidth={2} />
                      Cancel plan
                    </button>
                  )}

                  {/* CHANGING PLAN IS A PURCHASE, so it goes where a purchase goes
                      rather than to a separate "change plan" flow that would need its
                      own endpoint. POST /billing/checkout already overwrites the plan
                      on the account, so switching Starter to Business is the ordinary
                      path and not a special case. */}
                  <a className="btn-secondary" href={`/#${PRICING_ANCHOR}`}>
                    <ArrowUpRight size={15} strokeWidth={2} />
                    Change plan
                  </a>
                </div>

                {panel === 'cancel' && (
                  <div className="set-panel">
                    <h3 className="set-panel-title">Cancel your {plan.name} plan</h3>

                    {/* THE WHOLE REASON THIS PANEL EXISTS IS THIS PARAGRAPH. A
                        confirmation that only asks "are you sure?" leaves the user to
                        guess whether they lose access today or at the end of the month,
                        and those are a month apart. This says which, with the date. */}
                    <p className="set-text">
                      {subscription?.currentPeriodEnd
                        ? `You keep everything the ${plan.name} plan includes until ` +
                          `${formatAbsoluteDate(subscription.currentPeriodEnd)}, the ` +
                          'end of the period already paid for. Nothing further is ' +
                          'charged, and after that date the account returns to Free.'
                        : `The ${plan.name} plan ends immediately, because there is no ` +
                          'paid period recorded on this account to run out.'}
                    </p>

                    <p className="auth-fine">
                      Your scans and reports are not touched, and your receipts stay in
                      the billing history below. You can undo this at any point before
                      the plan ends.
                    </p>

                    {error && (
                      <p className="auth-error" role="alert">
                        <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
                        <span>{error}</span>
                      </p>
                    )}

                    <div className="set-actions">
                      <button
                        className="btn-primary"
                        type="button"
                        disabled={busy}
                        onClick={cancelPlan}
                      >
                        {busy ? 'Cancelling…' : 'Cancel this plan'}
                      </button>

                      <button
                        className="btn-secondary"
                        type="button"
                        disabled={busy}
                        onClick={() => setPanel('')}
                      >
                        Keep it
                      </button>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <>
                <p className="set-text">
                  {plan?.id === 'enterprise'
                    ? 'This account is on an Enterprise agreement. Anything to do with ' +
                      'billing on it goes through your named contact rather than ' +
                      'through this page.'
                    : 'You are on the Free plan — one Tier 1 external audit a month, ' +
                      'nothing to pay and nothing to cancel.'}
                </p>

                {/* NOT A <Link>, and the reason is a real bug rather than a preference:
                    React Router does not scroll to a hash, so to="/#pricing" would
                    navigate to the landing page and leave the reader at the top of it,
                    hunting for a pricing table. A plain anchor lets the browser do the
                    scrolling. Same reason as the buttons on the landing page — see
                    planDestination in lib/pricing.js, which spells it out. */}
                {plan?.id !== 'enterprise' && (
                  <div className="set-actions">
                    <a className="btn-primary" href={`/#${PRICING_ANCHOR}`}>
                      <ArrowUpRight size={15} strokeWidth={2} />
                      See the paid plans
                    </a>
                  </div>
                )}
              </>
            )}

            {/* --- Billing history --------------------------------------------- */}

            {/* WHY THE RECEIPTS OUTLIVE THE PLAN
                clear_user_plan removes the subscription and leaves the orders alone,
                deliberately: a cancellation does not un-buy the months already paid for,
                and somebody who left three months ago may still need the receipts for
                those three months. A history that vanished along with the plan would be
                a history missing exactly when it is wanted.

                An empty list renders nothing at all rather than an empty table. A Free
                account has never paid for anything, and the sentence above already says
                so better than a heading with nothing under it. */}
            {orders.length > 0 && (
              <div className="set-orders">
                <h3 className="set-panel-title">
                  <Receipt size={14} strokeWidth={2} aria-hidden="true" />
                  Billing history
                </h3>

                <ul className="set-order-list">
                  {/* [React] `key` is the order id — a real, stable, server-issued
                      identifier. Using the array index instead is what makes React
                      reuse the wrong row when a new receipt arrives at the top of the
                      list, because index 0 stops meaning the same order. */}
                  {orders.map((order) => (
                    <li className="set-order" key={order.id}>
                      <div className="set-order-main">
                        <span className="set-order-plan">{order.planName}</span>
                        <span className="set-order-date">
                          {formatAbsoluteDate(order.createdAt)}
                        </span>
                      </div>

                      <div className="set-order-side">
                        <span className="set-order-amount">
                          {formatAmount(order.amountCents, order.currency)}
                        </span>
                        {order.cardLast4 && (
                          <span className="set-order-card">
                            {order.cardBrand} ····{order.cardLast4}
                          </span>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>

                {/* THE HONEST LINE, and it stays until a real processor is wired in.
                    Every figure above is a true record of a real request, and not one of
                    them moved any money — the only payment provider the server has
                    validates the SHAPE of a card and grants the plan. Somebody reading
                    their own billing history is entitled to know that before they go
                    looking for the charge on a statement. */}
                <p className="auth-fine">
                  These are records of checkouts completed in SecuScan. No card has been
                  charged — payment processing is not connected yet.
                </p>
              </div>
            )}
          </>
        )}
      </section>

      {/* ================= 3. TWO-FACTOR ================================= */}

      <section className="card set-card">
        <h2 className="set-heading">Two-factor authentication</h2>

        {/* A GOOGLE-ONLY ACCOUNT GETS AN EXPLANATION, NOT A DISABLED BUTTON. It has no
            SecuScan password for a second factor to sit behind, and /2fa/disable would
            refuse it anyway — so the honest thing is to say where the control actually
            lives. */}
        {/* WHY THIS FAILURE IS RENDERED HERE AND NOT AT THE TOP OF THE PAGE: /2fa/status
            is the only request on this page whose answer nothing else needs. The account
            facts come from the user object, and the plan, card and receipts come from
            /billing/subscription — so a two-factor endpoint that is down costs the reader
            this section and nothing else. It used to blank the page, which meant a failing
            2FA request took away the cancel button for a subscription, and that is the
            same mistake billingError above is careful not to make in the other direction. */}
        {loadError ? (
          <p className="auth-error" role="alert">
            <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
            <span>{loadError}</span>
          </p>
        ) : !status ? (
          <p className="set-text" role="status">
            Loading your two-factor status…
          </p>
        ) : !hasPassword ? (
          <p className="set-text">
            This account signs in with Google and has no SecuScan password, so there is
            nothing here for a second factor to protect. Whatever two-step verification
            you have on your Google account already applies — Google checks it before it
            hands us a signed credential, and we never see your password at all. Manage
            it in your Google account&apos;s own security settings.
          </p>
        ) : (
          <>
            <p className="set-state">
              <span
                className={`set-state-icon ${status.enabled ? 'is-on' : 'is-off'}`}
                aria-hidden="true"
              >
                {status.enabled ? (
                  <ShieldCheck size={18} strokeWidth={2} />
                ) : (
                  <ShieldOff size={18} strokeWidth={2} />
                )}
              </span>

              {status.enabled ? 'On' : 'Off'}
            </p>

            {status.enabled ? (
              <>
                <p className="set-text">
                  Signing in asks for a six-digit code from your authenticator app after
                  your password.
                </p>

                {/* THE COUNT IS THE ONLY THING THAT CAN BE SHOWN, and the sentence says
                    why rather than leaving it looking like a missing feature. The codes
                    are stored as Argon2 hashes, so listing the unused ones is not an
                    endpoint nobody wrote — it is a question the stored data cannot
                    answer. */}
                {status.recoveryCodesLeft === 0 ? (
                  <p className="auth-error" role="alert">
                    <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
                    <span>
                      No recovery codes left. If you lose your phone, you will not be
                      able to sign in. Generate a new set now.
                    </span>
                  </p>
                ) : (
                  <p className="set-count">
                    <KeyRound size={15} strokeWidth={2} aria-hidden="true" />
                    <span className="tabular">{status.recoveryCodesLeft}</span> unused
                    recovery {status.recoveryCodesLeft === 1 ? 'code' : 'codes'} left
                  </p>
                )}

                <p className="auth-fine">
                  The codes themselves cannot be shown again — only hashes of them are
                  stored, so used and unused alike are unreadable to us. Generating a new
                  set is the only way to see codes on screen again, and it replaces every
                  code you have now.
                </p>
              </>
            ) : (
              <>
                <p className="set-text">
                  Your password is the only thing between anyone who has it and your scan
                  history. An authenticator app adds a code that changes every 30 seconds,
                  which a stolen password on its own cannot produce.
                </p>

                {/* Naming the enforcement switch when it is on, because it changes what
                    "off" means for this account: the next sign-in will stop and demand
                    enrolment anyway, so doing it here is strictly easier. */}
                {status.required && (
                  <p className="auth-notice" role="status">
                    This server requires two-factor authentication. You will be asked to
                    set it up the next time you sign in, so it is easier to do it now.
                  </p>
                )}
              </>
            )}

            <div className="set-actions">
              {status.enabled ? (
                <>
                  <button
                    className="btn-secondary"
                    type="button"
                    disabled={busy}
                    onClick={() => openPanel('regenerate')}
                  >
                    <RefreshCw size={15} strokeWidth={2} />
                    New recovery codes
                  </button>

                  <button
                    className="btn-secondary"
                    type="button"
                    disabled={busy}
                    onClick={() => openPanel('disable')}
                  >
                    <ShieldOff size={15} strokeWidth={2} />
                    Turn off
                  </button>
                </>
              ) : (
                <button
                  className="btn-primary"
                  type="button"
                  disabled={busy}
                  onClick={startEnrolment}
                >
                  <Smartphone size={15} strokeWidth={2} />
                  {busy ? 'Starting…' : 'Turn on two-factor'}
                </button>
              )}
            </div>
          </>
        )}

        {/* --- Regenerate form ----------------------------------------- */}

        {panel === 'regenerate' && (
          <form className="auth-form set-panel" onSubmit={regenerate}>
            <h3 className="set-panel-title">Generate new recovery codes</h3>

            {/* THE WARNING BEFORE THE ACTION, not after it. Once the request is sent
                the old codes are gone, so the sentence that matters has to be readable
                while the field is still empty. */}
            <p className="set-text">
              This replaces every code you have now. Any you have written down or saved
              stop working the moment the new set appears, so only do this if you can
              save the new ones.
            </p>

            <div className="field">
              <label className="field-label" htmlFor="set-regen-code">
                Current code from your app
              </label>
              <input
                className="input auth-input auth-code-input"
                id="set-regen-code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                maxLength={6}
                value={code}
                onChange={(event) => setCode(event.target.value)}
                required
                disabled={busy}
                autoFocus
              />
            </div>

            {error && (
              <p className="auth-error" role="alert">
                <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
                <span>{error}</span>
              </p>
            )}

            <button className="btn-primary" type="submit" disabled={busy || !code}>
              {busy ? 'Generating…' : 'Replace my recovery codes'}
            </button>
          </form>
        )}

        {/* --- Disable form -------------------------------------------- */}

        {panel === 'disable' && (
          <form className="auth-form set-panel" onSubmit={disable}>
            <h3 className="set-panel-title">Turn off two-factor authentication</h3>

            <p className="set-text">
              Your account goes back to a password alone and your recovery codes are
              deleted. Turning it on again later issues a completely new key, so your
              authenticator app will need to scan a fresh QR code — the old entry in it
              will be dead.
            </p>

            <div className="field">
              <label className="field-label" htmlFor="set-disable-password">
                Your password
              </label>
              <input
                className="input auth-input"
                id="set-disable-password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
                disabled={busy}
              />
            </div>

            <div className="field">
              <label className="field-label" htmlFor="set-disable-code">
                A current code, or a recovery code
              </label>
              {/* NOT .auth-code-input and NOT autoComplete="one-time-code": a recovery
                  code is accepted here too, and it is neither six digits nor something
                  a phone should offer to autofill. */}
              <input
                className="input auth-input"
                id="set-disable-code"
                type="text"
                autoComplete="off"
                placeholder="123456"
                value={code}
                onChange={(event) => setCode(event.target.value)}
                required
                disabled={busy}
              />
            </div>

            <p className="auth-fine">
              Both are needed because a stolen session should not be enough to weaken an
              account. If your phone is gone, a recovery code works in place of the code.
            </p>

            {error && (
              <p className="auth-error" role="alert">
                <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
                <span>{error}</span>
              </p>
            )}

            <button
              className="btn-primary"
              type="submit"
              disabled={busy || !code || !password}
            >
              {busy ? 'Turning off…' : 'Turn off two-factor'}
            </button>
          </form>
        )}
      </section>

      {/* ================= 4. PASSWORD =================================== */}

      {/* WHY THIS SECTION IS ABSENT RATHER THAN DISABLED for a Google account: there is
          no SecuScan password to change, so there is nothing for the form to do. A
          disabled form invites the question "why?"; the account section above already
          answers it by naming Google as the sign-in method. */}
      {hasPassword && (
        <section className="card set-card">
          <h2 className="set-heading">Password</h2>

          <p className="set-text">
            Changing it signs out your other devices automatically. This one stays signed
            in — you have just proved you know the old password, so this is not the
            session in doubt.
          </p>

          <div className="set-actions">
            <button
              className="btn-secondary"
              type="button"
              disabled={busy}
              onClick={() => openPanel('password')}
            >
              <Lock size={15} strokeWidth={2} />
              Change password
            </button>
          </div>

          {panel === 'password' && (
            <form className="auth-form set-panel" onSubmit={submitPassword}>
              <div className="field">
                <label className="field-label" htmlFor="set-current-password">
                  Current password
                </label>
                <input
                  className="input auth-input"
                  id="set-current-password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  disabled={busy}
                  autoFocus
                />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="set-new-password">
                  New password
                </label>
                <input
                  className="input auth-input"
                  id="set-new-password"
                  type="password"
                  /* "new-password", not "current-password" — this is the distinction
                     that makes a password manager offer to GENERATE one here and to
                     save the result, rather than filling in the old one. */
                  autoComplete="new-password"
                  placeholder={`At least ${PASSWORD_MIN_LENGTH} characters`}
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  required
                  disabled={busy}
                />
              </div>

              {/* The same meter and checklist as the signup form, from the same module.
                  [React] It appears only once there is something to check — four red
                  crosses greeting an empty field reads as failure before the user has
                  done anything. */}
              {newPassword.length > 0 && (
                <div className="pw-check">
                  <div className="pw-meter" aria-hidden="true">
                    <div
                      className={`pw-meter-fill met-${strength.metCount}`}
                      style={{ width: `${(strength.metCount / 4) * 100}%` }}
                    />
                  </div>

                  <p className="pw-label">{strength.label}</p>

                  <ul className="pw-list">
                    {strength.requirements.map((requirement) => (
                      <li
                        key={requirement.id}
                        className={requirement.met ? 'pw-met' : 'pw-unmet'}
                      >
                        {/* Icon AND colour, never colour alone — about one man in twelve
                            cannot reliably tell the green from the red. */}
                        {requirement.met ? (
                          <Check size={14} strokeWidth={2.5} />
                        ) : (
                          <X size={14} strokeWidth={2.5} />
                        )}
                        {requirement.label}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {error && (
                <p className="auth-error" role="alert">
                  <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
                  <span>{error}</span>
                </p>
              )}

              {/* Disabled until the browser's copy of the rules is satisfied. NOT the
                  security control — auth.password_problem on the server is, and it runs
                  regardless of what happened in here. This only spares the user a round
                  trip to be told something the page already knew. */}
              <button
                className="btn-primary"
                type="submit"
                disabled={busy || !password || !strength.accepted}
              >
                {busy ? 'Changing…' : 'Change password'}
              </button>
            </form>
          )}
        </section>
      )}

      {/* ================= 5. SESSIONS =================================== */}

      <section className="card set-card">
        <h2 className="set-heading">Signed-in devices</h2>

        <p className="set-text">
          If you think someone else has your password, this ends every session on the
          account — every browser, every phone, and this one.
        </p>

        {/* SAYING OUT LOUD THAT IT INCLUDES THIS BROWSER, before the click. The reason
            is the decision behind the endpoint: whoever presses this suspects an
            intruder, and under that suspicion there is no basis for treating the device
            in front of them as the trustworthy one. A control with an exception is a
            control people misread. */}
        <p className="auth-fine">
          You will be signed out here too and sent back to the sign-in page. That is
          deliberate — if you are not certain which device is compromised, the browser
          you are reading this on cannot be assumed clean.
        </p>

        {!hasPassword ? (
          <p className="set-text">
            This account signs in with Google, so SecuScan has no password to check
            before doing something this disruptive. Use your Google account&apos;s
            &ldquo;sign out of all sessions&rdquo; instead — it revokes the credential we
            rely on.
          </p>
        ) : (
          <>
            <div className="set-actions">
              <button
                className="btn-secondary"
                type="button"
                disabled={busy}
                onClick={() => openPanel('signout')}
              >
                <LogOut size={15} strokeWidth={2} />
                Sign out everywhere
              </button>
            </div>

            {panel === 'signout' && (
              <form className="auth-form set-panel" onSubmit={signOutEverywhere}>
                <h3 className="set-panel-title">Sign out of every device</h3>

                <div className="field">
                  <label className="field-label" htmlFor="set-signout-password">
                    Your password
                  </label>
                  <input
                    className="input auth-input"
                    id="set-signout-password"
                    type="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    required
                    disabled={busy}
                    autoFocus
                  />
                </div>

                {/* WHY A PASSWORD FOR AN ACTION THAT ONLY REMOVES ACCESS: without it,
                    anyone holding a stolen session could sign the real owner out of
                    every device and keep working — a denial of service against the
                    account's owner, performed with the account's own security feature. */}
                <p className="auth-fine">
                  Required so that a stolen session cannot use this to lock you out.
                </p>

                {error && (
                  <p className="auth-error" role="alert">
                    <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
                    <span>{error}</span>
                  </p>
                )}

                <button className="btn-primary" type="submit" disabled={busy || !password}>
                  {busy ? 'Signing out…' : 'Sign out everywhere'}
                </button>
              </form>
            )}
          </>
        )}
      </section>

      {/* THE CONFIRMATION LIVES AT THE BOTTOM, not beside each button. WHY: it is
          written by four different actions, and a copy inside each section is four
          places for the wording to drift. role="status" rather than "alert" — these are
          successes, and an assertive announcement for good news is more alarming than
          the news. */}
      {done && (
        <p className="auth-notice set-done" role="status">
          <Check size={15} strokeWidth={2} aria-hidden="true" />
          <span>{done}</span>
        </p>
      )}

      {/* An error from an action taken with no form open — "Turn on two-factor" is the
          only one. Errors from a form render inside that form, next to the field that
          caused them. */}
      {error && !panel && (
        <p className="auth-error" role="alert">
          <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
          <span>{error}</span>
        </p>
      )}
    </>,
  )
}
