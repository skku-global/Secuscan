/* ============================================================================
   RESETPASSWORD.JSX — the second half of a reset, at "/reset-password".

   WHY THIS EXISTS: /auth/forgot-password answered with a challenge and emailed a
   six-digit code. This page collects the code and the new password together and
   spends both in one request.

   ONE FORM, NOT TWO. The code could be verified on its own screen first, the way
   the login flow verifies before it does anything else, and that was rejected:
   verifying separately would have to hand back something that proves the code was
   right — and that something is a second credential to design, store and expire,
   bought in exchange for an extra click. Sending the code and the password
   together means the code is checked and spent in the same request that uses it.

   HOW IT GOT HERE, AND WHY THE FIRST THING THE FILE DOES IS A REDIRECT: the
   challenge arrives in router state, not in the URL — see the long note in
   Login.jsx for why a short-lived credential must not be a query parameter. So a
   refresh, a bookmark or a pasted link has no challenge, and the page must send
   those users back rather than render a form that cannot work.

   IT DOES NOT SIGN ANYBODY IN. There is no token in the response and no
   adoptSession call here, because a code emailed to an inbox proves access to that
   inbox and nothing else — auth.py makes the argument at length. A reset sets the
   password and stops; the user then signs in with it, which is also how an account
   with two-factor authentication still meets its authenticator afterwards. That
   costs one extra sign-in and buys the guarantee that inbox access alone can never
   produce a session.

   THIS PAGE STILL CANNOT TELL YOU WHETHER THE ACCOUNT EXISTS. An address that was
   never registered gets a challenge and a stored code too, so a wrong code here
   fails with the same words and the same counter either way. Nothing below
   branches on it, because nothing below can see it.
   ========================================================================== */

import { useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Shield, AlertCircle, Check, X } from 'lucide-react'

import * as api from '../lib/api'
import { checkPassword, PASSWORD_MIN_LENGTH } from '../lib/passwordPolicy'
import '../styles/auth.css'

export default function ResetPassword() {
  const location = useLocation()
  const navigate = useNavigate()

  const challenge = location.state?.challenge ?? ''
  const sentTo = location.state?.sentTo ?? ''
  const expiresInMinutes = location.state?.expiresInMinutes ?? 0

  /* The address the user typed on the previous page. NOT shown anywhere — it is
     here so the checker below can enforce "nothing from your name or email", the
     one rule that needs to know who is resetting. The server applies the same rule
     against the real account record; this is the browser half of the pair Signup's
     header describes. */
  const email = location.state?.email ?? ''

  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  /* The server's sentence from the previous step, carried through and shown above
     the code box. Vague on purpose — see ForgotPassword.jsx — and useful exactly
     where it is: somebody who mistyped their address reads it here, wondering why
     no code has arrived. */
  const notice = location.state?.notice ?? ''

  const strength = checkPassword(password, { email })

  /* NO CHALLENGE, NO PAGE. Almost always a refresh, and there is nothing to
     recover — the challenge is single-use and short-lived — so the honest response
     is the form that can start a new one.

     [React] Redirecting during render rather than from an effect, the same choice
     TwoFactor.jsx makes and for the same reason: an effect would paint the broken
     form for one frame first. */
  if (!challenge) {
    return (
      <Navigate
        to="/forgot-password"
        replace
        state={{
          notice:
            'That reset request expired. Enter your email again to get a new code.',
        }}
      />
    )
  }

  async function handleSubmit(event) {
    event.preventDefault()

    if (submitting) return

    /* [General] The button is already disabled while the password fails a rule,
       but Enter in a text field submits a form regardless of the button's state —
       so the button alone is not the guard it looks like. Copied from Signup, and
       it matters more here: getting refused by the server costs one of only three
       attempts on the code. */
    if (!strength.accepted) {
      setError('Choose a password that meets all four requirements.')
      return
    }

    setError('')
    setSubmitting(true)

    try {
      await api.resetPassword({ challenge, code, newPassword: password })

      /* Straight to the login form, with no session and nothing stored. `replace`
         so Back does not return to a form whose challenge has just been spent.

         Login renders location.state.notice, which is what turns this from a
         silent bounce into an explanation of what just happened and what to do. */
      navigate('/login', {
        replace: true,
        state: {
          notice: 'Your password has been changed. Sign in with it.',
        },
      })
    } catch (caught) {
      /* Worth distinguishing, because each implies a different next action:

           401 "not correct"   — wrong code, and one of three attempts is gone.
           401 "expired"       — the code aged out; start again.
           400 <policy>        — the server refused the password. Shown verbatim,
                                 since it names the rule that failed.
           429 "cancelled"     — attempts exhausted, the reset is dead.

         Shown as written. Flattening them into "invalid" would remove exactly the
         part the user needs. */
      setError(caught.message)

      // The code is spent on a wrong guess; leaving it in the box invites
      // resubmitting the same failure. The password survives — retyping it after
      // a mistyped code would be a punishment for the wrong mistake.
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

      <h1 className="auth-title">Choose a new password</h1>
      <p className="auth-sub">
        {sentTo
          ? `Type the code sent to ${sentTo}, then pick a new password.`
          : 'Type the code from your email, then pick a new password.'}
      </p>

      <div className="auth-card">
        {notice && (
          <p className="auth-notice" role="status">
            {notice}
            {expiresInMinutes > 0 &&
              ` The code expires in ${expiresInMinutes} minutes.`}
          </p>
        )}

        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="field">
            <label className="field-label" htmlFor="reset-code">
              Six-digit code
            </label>
            <input
              className="input auth-input auth-code-input"
              id="reset-code"
              type="text"
              /* [General] `inputMode` asks a phone for the numeric keypad without
                 making the field type="number" — which would bring a spinner,
                 allow "1e5", and silently strip a leading zero. For a code that is
                 DIGITS rather than a QUANTITY, text plus inputMode is the pair. */
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              maxLength={6}
              value={code}
              onChange={(event) => setCode(event.target.value)}
              /* [React] autoFocus is usually a bad habit. This is the exception:
                 the user arrives already reading a code off another screen. */
              autoFocus
              required
              disabled={submitting}
            />
          </div>

          <div className="field">
            <label className="field-label" htmlFor="reset-password">
              New password
            </label>
            <input
              className="input auth-input"
              id="reset-password"
              type="password"
              placeholder={`At least ${PASSWORD_MIN_LENGTH} characters`}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              /* "new-password" is what asks a password manager to OFFER TO
                 GENERATE one — and to store what it generates. On a reset page
                 that is the single most useful attribute there is: the user is
                 here because the old password was unrecoverable. */
              autoComplete="new-password"
              required
              disabled={submitting}
            />
          </div>

          {/* [React] The checklist appears only once there is something to check.
              Four red crosses greeting an empty field reads as failure before the
              user has done anything. Markup and reasoning from Signup.jsx — same
              policy module, same rules, so the two pages cannot disagree about
              what a good password is. */}
          {password.length > 0 && (
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
                    {/* Icon AND colour, never colour alone — about one man in
                        twelve cannot reliably tell the green from the red. */}
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
              <AlertCircle
                className="icon"
                size={16}
                strokeWidth={2}
                aria-hidden="true"
              />
              <span>{error}</span>
            </p>
          )}

          <button
            className="btn-primary"
            type="submit"
            disabled={submitting || code.trim().length === 0 || !strength.accepted}
          >
            {submitting ? 'Setting password…' : 'Set new password'}
          </button>
        </form>
      </div>

      <p className="auth-alt">
        No code? <Link to="/forgot-password">Ask for another</Link>
      </p>
    </main>
  )
}
