/* ============================================================================
   ENROL.JSX — forced two-factor setup during login, at "/login/enrol".

   WHY THIS EXISTS: this server has SECUSCAN_REQUIRE_2FA switched on and the
   account signing in has no authenticator. /auth/login therefore answered with a
   challenge whose method is "enrol" — not a session, because handing one over
   would let the user close this page and carry on with no second factor, which is
   the whole thing the switch exists to prevent.

   WHAT THE USER SEES, IN ORDER:

     1. A QR code and the secret in text. Two forms of the same value, because a
        desktop authenticator has no camera and a phone camera sometimes will not
        focus.
     2. A box for the first code, which is what proves the secret was actually
        stored somewhere rather than glanced at.
     3. The recovery codes, once, and an acknowledgement — then the dashboard.

   THE SESSION ARRIVES AT STEP 3, NOT STEP 1. /2fa/enrol/finish returns
   { token, user, recoveryCodes } together, so by the time the codes are on screen
   the user IS signed in. That ordering is deliberate on the server's side and has
   a consequence here worth being explicit about: this page holds a live session
   while still showing the codes panel, so the "Continue" button is a navigation
   and not a login. Nothing is lost if the tab dies at that moment except the codes
   themselves — which is exactly why the panel makes saving them a gate.

   WHY THE SECRET IS NOT ENABLED UNTIL A CODE IS TYPED: see _complete_totp_setup
   in main.py. A secret promoted at issue time locks out anyone who closed the tab
   before scanning, using a secret nobody ever stored.
   ========================================================================== */

import { useEffect, useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Shield, AlertCircle, ShieldCheck } from 'lucide-react'

import { useAuth } from '../context/AuthContext'
import RecoveryCodes from '../components/RecoveryCodes'
import * as api from '../lib/api'
import '../styles/auth.css'

export default function Enrol() {
  const location = useLocation()
  const navigate = useNavigate()
  const { adoptSession } = useAuth()

  const challenge = location.state?.challenge ?? ''
  const from = location.state?.from ?? null

  /* The QR code, the secret and the parameters to display beside them. Null until
     /2fa/enrol/start answers. */
  const [setup, setSetup] = useState(null)

  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  /* THE CODES, AND THE STEP CHANGE. Non-empty means enrolment finished, a session
     exists, and the page has switched from "scan this" to "save these". One piece
     of state carrying both facts, rather than a separate `step` that could
     disagree with it. */
  const [recoveryCodes, setRecoveryCodes] = useState([])

  const [accountEmail, setAccountEmail] = useState('')

  useEffect(() => {
    // Nothing to fetch without a challenge; the redirect below handles that case.
    if (!challenge) return

    let cancelled = false

    api
      .startEnrolment(challenge)
      .then((result) => {
        if (cancelled) return
        setSetup(result)
      })
      .catch((caught) => {
        if (cancelled) return

        /* A 409 means 2FA was enabled from another device while this login was in
           flight — the server's message says to sign in again, which is right. A
           401 means the challenge expired. Both are shown as written. */
        setError(caught.message)
      })

    return () => {
      cancelled = true
    }
  }, [challenge])

  /* Same reasoning as the verify page: no challenge means a refresh or a pasted
     URL, and a challenge cannot be recovered. Back to the password form with an
     explanation rather than a form that cannot work. */
  if (!challenge) {
    return (
      <Navigate
        to="/login"
        replace
        state={{
          from,
          notice:
            'That sign-in attempt expired. Enter your password again to set up two-factor authentication.',
        }}
      />
    )
  }

  async function handleSubmit(event) {
    event.preventDefault()

    if (submitting) return

    setError('')
    setSubmitting(true)

    try {
      const result = await api.finishEnrolment({ challenge, code })

      /* SESSION FIRST, THEN THE CODES ON SCREEN. Storing it before rendering the
         panel means the Continue button lands on a dashboard that is already
         authenticated — the alternative order shows the codes, then navigates to a
         guard that bounces the user back to /login, losing the codes on the way. */
      adoptSession(result)

      setAccountEmail(result.user?.email ?? '')
      setRecoveryCodes(result.recoveryCodes ?? [])
    } catch (caught) {
      setError(caught.message)
      setCode('')
    } finally {
      setSubmitting(false)
    }
  }

  /* --- Step 2: the codes ------------------------------------------------- */

  if (recoveryCodes.length > 0) {
    return (
      <main id="main" className="auth-page">
        <Link to="/" className="auth-brand">
          <Shield size={20} strokeWidth={2} />
          SecuScan
        </Link>

        <h1 className="auth-title">Two-factor authentication is on</h1>
        <p className="auth-sub">
          One last thing, and it is the part people regret skipping.
        </p>

        <div className="auth-card">
          <RecoveryCodes
            codes={recoveryCodes}
            accountEmail={accountEmail}
            continueLabel="Continue to dashboard"
            onContinue={() =>
              navigate(from?.pathname ?? '/dashboard', { replace: true })
            }
          />
        </div>
      </main>
    )
  }

  /* --- Step 1: scan and confirm ------------------------------------------ */

  return (
    <main id="main" className="auth-page">
      <Link to="/" className="auth-brand">
        <Shield size={20} strokeWidth={2} />
        SecuScan
      </Link>

      <h1 className="auth-title">Set up two-factor authentication</h1>
      {/* SAYING WHY, not just what. Being stopped mid-login by a setup screen is
          irritating; being told it is a policy on this server rather than a random
          new hurdle is the difference between irritating and hostile. */}
      <p className="auth-sub">
        Your password was correct. This server requires a second factor, so there is
        one step left before you are in.
      </p>

      <div className="auth-card">
        {/* THE ERROR CAN ARRIVE BEFORE THE QR CODE — a 409 or an expired challenge
            fails the initial request, so `setup` stays null. Rendering the error
            above the setup block means that case shows a message rather than an
            empty card. */}
        {error && (
          <p className="auth-error" role="alert">
            <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
            <span>{error}</span>
          </p>
        )}

        {!setup && !error && (
          <p className="auth-notice" role="status">
            Generating your setup code…
          </p>
        )}

        {setup && (
          <>
            <ol className="enrol-steps">
              <li>
                <p className="enrol-step-title">Open an authenticator app</p>
                <p className="enrol-step-text">
                  Google Authenticator, 1Password, Bitwarden, Authy — any of them.
                  This is the standard TOTP scheme, not something specific to us.
                </p>
              </li>

              <li>
                <p className="enrol-step-title">Scan this code</p>

                {/* [React] The QR is an inline SVG data URI from the server — see
                    totp_qr_data_uri in auth.py for why it is not a separate image
                    endpoint. An <img> is correct rather than dangerouslySetInnerHTML:
                    a data URI in src is inert, where injecting SVG markup into the
                    document would let a compromised server run script in this page. */}
                <img
                  className="enrol-qr"
                  src={setup.qr}
                  /* NOT the secret in the alt text, which would put the credential
                     into a screen reader's output for anyone within earshot. The
                     manual-entry block below is the accessible path, and it says so. */
                  alt="QR code for setting up two-factor authentication"
                  width={180}
                  height={180}
                />

                <p className="enrol-step-text">
                  No camera? Type this key into the app by hand instead:
                </p>

                {/* [General] The secret in a fixed-width face, letter-spaced, and
                    selectable. It is a credential and it is also something a human
                    has to transcribe accurately, so legibility wins over hiding it
                    — it is already on screen in the QR code, which is not
                    meaningfully harder to photograph. */}
                <p className="enrol-secret mono">{setup.secret}</p>

                <p className="enrol-step-meta">
                  {setup.digits} digits, refreshing every {setup.period} seconds.
                </p>
              </li>

              <li>
                <p className="enrol-step-title">Enter the code it shows</p>
                <p className="enrol-step-text">
                  This is what proves the key reached your app rather than just
                  appearing on this screen.
                </p>
              </li>
            </ol>

            <form className="auth-form" onSubmit={handleSubmit}>
              <div className="field">
                <label className="field-label" htmlFor="enrol-code">
                  Six-digit code
                </label>
                <input
                  className="input auth-input auth-code-input"
                  id="enrol-code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="123456"
                  maxLength={6}
                  value={code}
                  onChange={(event) => setCode(event.target.value)}
                  required
                  disabled={submitting}
                />
              </div>

              <button
                className="btn-primary"
                type="submit"
                disabled={submitting || code.trim().length === 0}
              >
                {submitting ? (
                  'Confirming…'
                ) : (
                  <>
                    <ShieldCheck size={15} strokeWidth={2} />
                    Turn on and sign in
                  </>
                )}
              </button>
            </form>
          </>
        )}
      </div>

      <p className="auth-alt">
        <Link to="/login" replace>
          Start again with your password
        </Link>
      </p>
    </main>
  )
}
