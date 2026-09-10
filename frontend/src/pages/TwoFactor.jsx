/* ============================================================================
   TWOFACTOR.JSX — the second half of a login, at "/login/verify".

   WHY THIS EXISTS: /auth/login answered with a challenge instead of a session,
   because the account has an authenticator. The password is already proved; this
   page proves possession of the phone and turns the challenge into a session.

   HOW IT GOT HERE, AND WHY THAT MATTERS TO THE FIRST THING THE FILE DOES: the
   challenge arrives in router state, not in the URL — see the long note in
   Login.jsx for why a short-lived credential must not be a query parameter. The
   consequence is that a refresh, a bookmark, or a pasted link has no challenge,
   and the page must handle that rather than render a form that cannot work.

   THREE WAYS OUT OF HERE, and the page offers all three because the situations
   are genuinely different:

     1. THE AUTHENTICATOR CODE. The ordinary case, and the default view.
     2. A RECOVERY CODE. The phone is lost, broken, or wiped. Each printed code
        works exactly once and signing in with one does NOT switch 2FA off — see
        the endpoint comment in main.py for why that would be the wrong kindness.
     3. AN EMAILED CODE. Only offered when the server reports email is configured;
        a button leading to "email is not set up" is worse than no button.

   NOTHING HERE DECIDES ANYTHING. Every code is checked on the server, against a
   secret this page never sees, with its own attempt counter and its own replay
   protection. What this file owns is which form is on screen.
   ========================================================================== */

import { useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Shield, AlertCircle, KeyRound, Mail, Smartphone } from 'lucide-react'

import { useAuth } from '../context/AuthContext'
import * as api from '../lib/api'
import '../styles/auth.css'

/* The three modes as data, so the tab strip and the form both read from one list
   and a fourth method cannot appear in one and not the other. [General] */
const MODES = {
  totp: {
    icon: Smartphone,
    tab: 'Authenticator',
    title: 'Enter your code',
    sub: 'Open your authenticator app and type the six digits it shows.',
    label: 'Six-digit code',
    placeholder: '123456',
    /* [General] `inputMode` asks a phone for the numeric keypad without making
       the field type="number" — which would bring a spinner, allow "1e5", and
       silently strip a leading zero. For a code that is DIGITS rather than a
       QUANTITY, text plus inputMode is the correct pair. */
    inputMode: 'numeric',
    autoComplete: 'one-time-code',
    maxLength: 6,
    submit: 'Verify and sign in',
  },
  recovery: {
    icon: KeyRound,
    tab: 'Recovery code',
    title: 'Use a recovery code',
    sub: 'One of the codes printed when you set up two-factor authentication. Each works once.',
    label: 'Recovery code',
    placeholder: 'xxxx-xxxx-xxxx',
    inputMode: 'text',
    /* NOT 'one-time-code' here. That hint makes a phone offer the SMS or
       authenticator code it just saw, which is exactly the wrong suggestion on
       the field for a printed backup code. */
    autoComplete: 'off',
    maxLength: 32,
    submit: 'Use this code',
  },
  email: {
    icon: Mail,
    tab: 'Email me a code',
    title: 'Code sent by email',
    sub: 'A one-time code has gone to the address on your account.',
    label: 'Emailed code',
    placeholder: '123456',
    inputMode: 'numeric',
    autoComplete: 'one-time-code',
    maxLength: 8,
    submit: 'Verify and sign in',
  },
}

export default function TwoFactor() {
  const location = useLocation()
  const navigate = useNavigate()
  const { adoptSession } = useAuth()

  /* [General] Read once into locals rather than referenced through
     location.state?.x at eight call sites. The nullish defaults are what make
     this page render sensibly when state is missing entirely. */
  const challenge = location.state?.challenge ?? ''
  const emailAvailable = location.state?.emailAvailable ?? false
  const from = location.state?.from ?? null

  const [mode, setMode] = useState('totp')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  /* Set from the response to /2fa/email-code, so the page can say where the code
     went. The address is MASKED by the server — see _mask_email in main.py for why
     an unauthenticated caller never gets the whole thing. */
  const [emailNotice, setEmailNotice] = useState('')
  const [sendingEmail, setSendingEmail] = useState(false)

  /* How many recovery codes remain. Starts from what the login response said and
     is updated from the recovery response, which returns the count AFTER spending
     one — so a user who has just used their last code is told so on the way in
     rather than discovering it at the next login. */
  const [codesLeft, setCodesLeft] = useState(
    location.state?.recoveryCodesLeft ?? 0,
  )

  /* NO CHALLENGE, NO PAGE. The most likely cause by far is a refresh, and the
     honest response is to send them back to the form that can start a new one —
     a challenge is single-use and short-lived, so there is nothing to recover.

     [React] The redirect happens during render rather than in an effect. That is
     the right tool for "this route is not valid for this state": an effect would
     render the broken page for one frame first. */
  if (!challenge) {
    return (
      <Navigate
        to="/login"
        replace
        state={{
          from,
          /* Explaining WHY they are back at the password form. Without this the
             page appears to have thrown the login away for no reason. */
          notice:
            'That sign-in attempt expired. Enter your password again to get a new code.',
        }}
      />
    )
  }

  const active = MODES[mode]

  /* WHY THE SWITCH CLEARS BOTH FIELDS: a six-digit authenticator code left in the
     box after switching to the recovery tab would be submitted against the
     recovery endpoint, fail, and burn one of the challenge's few attempts. */
  function switchMode(next) {
    setMode(next)
    setCode('')
    setError('')
  }

  async function requestEmailCode() {
    if (sendingEmail) return

    setError('')
    setSendingEmail(true)

    try {
      const result = await api.sendEmailCode(challenge)

      /* switchMode first, then the notice. Order matters only in that switchMode
         clears `error` — and a stale error from a previous tab sitting above a
         "code sent" line would contradict it. */
      switchMode('email')

      setEmailNotice(
        `Code sent to ${result.sentTo}. It expires in ${result.expiresInMinutes} minutes.`,
      )
    } catch (caught) {
      /* A 503 lands here when email is not configured after all — the button is
         hidden in that case, so this means the server's configuration changed
         between login and now. The server's sentence names the alternatives. */
      setError(caught.message)
    } finally {
      setSendingEmail(false)
    }
  }

  async function handleSubmit(event) {
    event.preventDefault()

    if (submitting) return

    setError('')
    setSubmitting(true)

    try {
      /* One call per mode, and the shapes they return differ only in that
         recovery adds a count. All three end with { token, user }, which is what
         makes adoptSession the single place a session gets stored. */
      let result

      if (mode === 'totp') {
        result = await api.verifyTwoFactor({ challenge, code })
      } else if (mode === 'recovery') {
        result = await api.recoverTwoFactor({ challenge, code })
      } else {
        result = await api.verifyEmailCode({ challenge, code })
      }

      /* THE SESSION IS STORED BY AUTHCONTEXT, NOT HERE. adoptSession is exposed
         precisely so this page does not write its own saveSession + setUser +
         setStatus — there is one function in the app that turns a token into a
         session, and a second copy here is how a future edit ends up storing a
         token without updating the UI, or the reverse. */
      adoptSession(result)

      if (typeof result.recoveryCodesLeft === 'number') {
        setCodesLeft(result.recoveryCodesLeft)
      }

      /* WHERE THEY LAND. `from` is whatever RequireAuth was protecting when it
         bounced them to the login page, forwarded through the challenge so the
         second factor does not cost somebody the page they asked for. */
      navigate(from?.pathname ?? '/dashboard', { replace: true })
    } catch (caught) {
      /* The messages that arrive here are worth distinguishing, because the server
         is deliberately specific about some and vague about others:

           401 "not correct"      — wrong code. Try again.
           401 "already used"     — a correct code, replayed. Wait for the next one.
           401 "expired"          — the challenge is gone; the form below sends
                                    them back to /login.
           429                    — too many attempts, on this challenge or this
                                    client.

         Shown as written, since each one implies a different next action and
         flattening them into "invalid code" would remove exactly that. */
      setError(caught.message)

      // The code is spent either way — a wrong one is wrong, a right one is
      // already used. Leaving it in the box invites resubmitting the same failure.
      setCode('')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main id="main" className="auth-page">
      <Link to="/" className="auth-brand">
        <Shield size={20} strokeWidth={2} />
        SecuScan
      </Link>

      <h1 className="auth-title">{active.title}</h1>
      <p className="auth-sub">{active.sub}</p>

      <div className="auth-card">
        {/* THE MODE STRIP. Buttons rather than links: switching does not change
            the URL, because the URL cannot carry the challenge and a route per
            mode would multiply the "no challenge" case by three.

            [General] role="tablist" is deliberately NOT used. A real tablist
            brings keyboard obligations — arrow keys move between tabs, Tab leaves
            the strip — and a group of three buttons that each swap the form below
            is honestly described as a group of buttons. Claiming a pattern and
            implementing half of it is worse for a screen reader user than not
            claiming it. `aria-pressed` says which one is on. */}
        <div className="auth-modes" role="group" aria-label="How to verify">
          {Object.entries(MODES).map(([key, entry]) => {
            // Email is only an option when the server can actually send one.
            if (key === 'email' && !emailAvailable) return null

            const Icon = entry.icon

            return (
              <button
                key={key}
                type="button"
                className={`auth-mode ${mode === key ? 'is-active' : ''}`}
                aria-pressed={mode === key}
                disabled={submitting}
                onClick={() => {
                  /* Choosing the email tab SENDS a code, because a tab that
                     shows an empty box for a code nobody has requested is a dead
                     end. Guarded on already having sent one, so switching back
                     and forth does not mail a fresh code each time — each send
                     invalidates the last, and the rate limit on that endpoint is
                     deliberately tight. */
                  if (key === 'email' && !emailNotice) {
                    requestEmailCode()
                    return
                  }

                  switchMode(key)
                }}
              >
                <Icon size={15} strokeWidth={2} />
                {entry.tab}
              </button>
            )
          })}
        </div>

        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="field">
            <label className="field-label" htmlFor="twofactor-code">
              {active.label}
            </label>
            <input
              /* [React] The `key` forces React to build a NEW input when the mode
                 changes rather than reusing the old one. Without it the browser
                 keeps its autofill state and the field's own history across a
                 switch, so a phone that offered an SMS code on the authenticator
                 tab keeps offering it on the recovery tab. */
              key={mode}
              className={`input auth-input ${mode === 'recovery' ? '' : 'auth-code-input'}`}
              id="twofactor-code"
              type="text"
              inputMode={active.inputMode}
              autoComplete={active.autoComplete}
              placeholder={active.placeholder}
              maxLength={active.maxLength}
              value={code}
              onChange={(event) => setCode(event.target.value)}
              /* [React] autoFocus is usually a bad habit — it moves focus without
                 being asked. This is the exception the rule allows for: the page
                 exists to receive one short code, there is nothing else to do on
                 it, and every user arriving here is already reading a code off a
                 screen in their hand. */
              autoFocus
              required
              disabled={submitting}
            />
          </div>

          {emailNotice && mode === 'email' && (
            <p className="auth-notice" role="status">
              {emailNotice}
            </p>
          )}

          {/* The warning that actually matters on this page. At zero there is no
              way back into the account if the phone is also gone, and the only fix
              is to sign in and regenerate — which is why it names that next step
              rather than just reporting the number. */}
          {mode === 'recovery' && codesLeft === 0 && (
            <p className="auth-notice" role="status">
              No recovery codes are left on this account. Sign in with your
              authenticator app, then generate a new set from Security settings.
            </p>
          )}

          {mode === 'recovery' && codesLeft > 0 && (
            <p className="pw-label">
              {codesLeft} recovery {codesLeft === 1 ? 'code' : 'codes'} remaining.
            </p>
          )}

          {error && (
            <p className="auth-error" role="alert">
              <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
              <span>{error}</span>
            </p>
          )}

          <button
            className="btn-primary"
            type="submit"
            disabled={submitting || code.trim().length === 0}
          >
            {submitting ? 'Checking…' : active.submit}
          </button>
        </form>
      </div>

      {/* A way out that is not "guess again". Starting over costs a password entry
          and is sometimes genuinely the fastest fix — a challenge that has been
          sitting open while somebody hunted for a phone has probably expired. */}
      <p className="auth-alt">
        <Link to="/login" replace>
          Start again with your password
        </Link>
      </p>
    </main>
  )
}
