/* ============================================================================
   FORGOTPASSWORD.JSX — the reset request form at "/forgot-password".

   WHAT IT DOES: takes an address, asks the server to email a six-digit code, and
   sends the user straight on to /reset-password to type it in. Two pages rather
   than one, for the same reason /login and /login/verify are two pages — the
   second step needs a credential that arrives out of band, and there is a gap in
   the middle where the user goes and opens their email.

   THIS PAGE CANNOT TELL YOU WHETHER AN ACCOUNT EXISTS, AND THAT IS DELIBERATE ON
   THE SERVER'S SIDE. /auth/forgot-password answers identically for a registered
   address and an unknown one — same fields, same status, a challenge either way —
   so there is nothing here to branch on and nothing to report. A reset form that
   says "no account with that email" is an account-enumeration tool wearing a
   helpful face, and it is one of the most commonly shipped versions of that
   mistake.

   The consequence for THIS file is that the success path has no condition in it.
   Submitting always moves to the next page. The server's own sentence — "If an
   account exists for that address, a reset code has been sent to it" — travels
   with it and is shown there, above the code box, which is where it does its real
   work: telling somebody who mistyped their address why nothing is arriving.
   ========================================================================== */

import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Shield, AlertCircle } from 'lucide-react'

import * as api from '../lib/api'
import '../styles/auth.css'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const location = useLocation()
  const navigate = useNavigate()

  /* Set when /reset-password sends somebody back here — a refresh that lost the
     challenge, or a code that expired. Without it the user arrives at a form they
     already filled in once, with no explanation of why they are looking at it
     again. Same pattern as Login.jsx. */
  const notice = location.state?.notice ?? ''

  async function handleSubmit(event) {
    event.preventDefault()

    if (submitting) return

    setError('')
    setSubmitting(true)

    try {
      const result = await api.requestPasswordReset(email)

      /* THE CHALLENGE TRAVELS IN ROUTER STATE, NOT IN THE URL. It is a short-lived
         credential, and a URL is pasted into tickets, logged by proxies and
         written to browser history — the same reasoning as the login challenge,
         set out at length in Login.jsx. The cost is that a refresh on the next
         page loses it, which is exactly what that page's guard is for.

         The address goes too, and not for display: the password checker on the
         next page needs it to enforce "nothing from your name or email" while the
         user types. */
      navigate('/reset-password', {
        state: {
          challenge: result.challenge,
          sentTo: result.sentTo,
          expiresInMinutes: result.expiresInMinutes,
          email,
          /* The server's own words, with a fallback in case the shape changes
             underneath this page. Not rewritten into something friendlier — the
             vagueness is the point, and it is what the header explains. */
          notice:
            result.message ??
            'If an account exists for that address, a reset code has been sent to it.',
        },
      })
    } catch (caught) {
      // Realistically a 429 or a network failure; there is nothing else in this
      // endpoint that can refuse.
      setError(caught.message)
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

      <h1 className="auth-title">Forgotten password</h1>
      <p className="auth-sub">Tell us the address on the account.</p>

      <div className="auth-card">
        {notice && (
          <p className="auth-notice" role="status">
            {notice}
          </p>
        )}

        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="field">
            <label className="field-label" htmlFor="forgot-email">
              Email
            </label>
            <input
              className="input auth-input"
              id="forgot-email"
              type="email"
              placeholder="you@company.com"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoComplete="email"
              required
              disabled={submitting}
              autoFocus
            />
          </div>

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

          <button className="btn-primary" type="submit" disabled={submitting}>
            {submitting ? 'Sending…' : 'Email me a code'}
          </button>
        </form>
      </div>

      <p className="auth-alt">
        <Link to="/login">Back to sign in</Link>
      </p>
    </main>
  )
}
