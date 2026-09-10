/* ============================================================================
   LOGIN.JSX — the sign-in page at "/login".

   WHY THIS EXISTS: this page is now real. It sends credentials to /auth/login,
   stores the session the server issues, and sends the user where they were
   trying to go.

   WHAT IT DELIBERATELY DOES NOT DO — and the contrast with Signup is the thing
   to notice — is check anything about the password. No length rule, no strength
   meter. The rules may have tightened since an account was created, and telling
   somebody their existing password is "too short" while refusing to sign them in
   would be absurd. A login asks one question: is this the right password? Only
   the server can answer it.

   ---------------------------------------------------------------------------
   A CORRECT PASSWORD IS NOT ALWAYS A SESSION, AND THIS PAGE IS WHERE THAT LIVES

   POST /auth/login answers in one of three shapes, all of them successes:

     { token, user }                — signed in. Nothing more to do.
     { challenge, method: 'totp' }  — password fine, a 6-digit code still needed.
     { challenge, method: 'enrol' } — password fine, but this server requires 2FA
                                      and the account has none yet.

   handleSubmit below branches on which one arrived. It used to navigate to the
   dashboard unconditionally, which for a 2FA account produced an app that
   believed it was signed in, held no token, and answered 401 to everything — a
   worse outcome than a failed login, because it looked like a successful one. The
   fix has two halves and this is the second: AuthContext no longer stores a
   challenge as a session (see adopt() there), and this page routes it to the page
   that can finish it.

   THE CHALLENGE TRAVELS IN ROUTER STATE, NOT IN THE URL. It is a short-lived
   credential — it authorises one narrow action, and for the few minutes it lives
   anyone holding it can complete a login. A URL is copied into chat messages,
   pasted into tickets, and written to server logs and browser history by default;
   router state is none of those. The cost is that a refresh on /login/verify
   loses it, which the verify page handles by sending the user back here rather
   than by showing a form that cannot work.
   ========================================================================== */

import { useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Shield, AlertCircle } from 'lucide-react'

import { useAuth } from '../context/AuthContext'
import { useAuthConfig } from '../hooks/useAuthConfig'
import GoogleSignIn from '../components/GoogleSignIn'
import '../styles/auth.css'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const { signIn, signedIn, checking } = useAuth()
  const { config, ready: configReady } = useAuthConfig()
  const navigate = useNavigate()
  const location = useLocation()

  /* WHERE TO GO AFTERWARDS. RequireAuth puts the page it bounced someone off
     into location.state, so a bookmarked report opens the report rather than
     dumping them on the dashboard.

     [General] Optional chaining all the way down, because state is null for
     anyone who came here by clicking "Sign in" — the ?? supplies the default. */
  const destination = location.state?.from?.pathname ?? '/dashboard'

  /* WHY THIS EXISTS: the verify and enrol pages send people back here when their
     challenge has gone — a refresh, or a form left open too long. Arriving at a
     password box with no explanation reads as the app having lost the login for no
     reason, so those pages pass a sentence and this renders it.

     Read straight from location.state rather than copied into useState: it is not
     something this page changes, and a second copy would survive a navigation the
     original did not. */
  const notice = location.state?.notice ?? ''

  /* Someone already signed in has no business on this page — most often they hit
     Back after logging in, and the browser shows the form again. Redirecting is
     kinder than an empty form that will not tell them they are already in.

     [React] The `checking` guard is what stops this firing during the initial
     /auth/me call, when signedIn is false only because the answer has not
     arrived yet. */
  if (!checking && signedIn) return <Navigate to={destination} replace />

  async function handleSubmit(event) {
    event.preventDefault()

    if (submitting) return

    setError('')
    setSubmitting(true)

    try {
      const result = await signIn({ email, password })

      /* THE UNION, HANDLED. `challenge` present means the password was right and
         the login is not finished. Which page finishes it depends on `method`,
         and the two are genuinely different jobs: one asks for a code from an app
         that already holds the secret, the other issues a new secret and a QR
         code to scan.

         [React] `state` is how a route hands data to the page it navigates to
         without putting it in the URL. `replace` keeps the login form out of the
         history behind the code form — pressing Back from the code page should
         leave the app, not return to a password form that will start a second
         challenge and invalidate the first. */
      if (result?.challenge) {
        const target = result.method === 'enrol' ? '/login/enrol' : '/login/verify'

        navigate(target, {
          replace: true,
          state: {
            challenge: result.challenge,
            /* Forwarded so the verify page can decide what to offer without a
               second request: whether email delivery is configured at all, and
               how many recovery codes are left. Both come from
               _challenge_response in main.py. */
            emailAvailable: result.emailAvailable ?? false,
            recoveryCodesLeft: result.recoveryCodesLeft ?? 0,
            expiresInSeconds: result.expiresInSeconds ?? null,
            /* Carried through so a bookmarked report still opens after the code
               step, rather than the second factor quietly costing the user the
               destination they asked for. */
            from: location.state?.from ?? null,
          },
        })

        return
      }

      /* [React] `replace` rather than a push. The login page should not be in
         the history behind the dashboard — pressing Back afterwards ought to
         leave the app, not return to a form that immediately redirects. */
      navigate(destination, { replace: true })
    } catch (caught) {
      /* The server's message, shown as it was written. For a failed sign-in that
         is deliberately vague — "Email or password is incorrect", identical for a
         wrong password and an address with no account — and the vagueness is the
         point: a more helpful message here would be a tool for working out which
         addresses have accounts. Rewriting it into something friendlier is
         exactly the mistake it exists to prevent. */
      setError(caught.message)

      /* [General] Clear the password, keep the email. A retry almost always
         means the password was mistyped, and making somebody retype an address
         they got right is the small daily friction that makes a login feel
         hostile. */
      setPassword('')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    /* [General] <main> rather than <div>: the skip link needs a landmark to
       land on, and on this page the form IS the whole content — there is no
       navigation to skip past, but the link exists on every route and must have
       a target on every route. */
    <main id="main" className="auth-page">
      <Link to="/" className="auth-brand">
        <Shield size={20} strokeWidth={2} />
        SecuScan
      </Link>

      <h1 className="auth-title">Sign in</h1>
      <p className="auth-sub">Access your scans and reports.</p>

      {/* The form sits on a card so the three fields read as one unit rather
          than as unrelated bars floating on the page background. */}
      <div className="auth-card">
        {/* ABOVE the Google button and the form both, because it explains why this
            page is on screen at all. role="status" rather than "alert": it is
            information, not a failure, and an assertive announcement for "your
            session expired, here is the form" is more alarming than the situation. */}
        {notice && (
          <p className="auth-notice" role="status">
            {notice}
          </p>
        )}

        {/* Google above the form, matching the signup page. Renders nothing when
            the server reports no client id, and the divider is tied to the same
            condition so there is never an "or" with one side missing.

            Note it does NOT branch on a challenge: /auth/google always answers
            with a session, because Google has already applied whatever second
            factor that account has. Hence a plain navigate here against
            handleSubmit's three-way branch above. */}
        {configReady && config.googleEnabled && (
          <>
            <GoogleSignIn
              clientId={config.googleClientId}
              enabled={config.googleEnabled}
              text="signin_with"
              disabled={submitting}
              onSignedIn={() => navigate(destination, { replace: true })}
            />

            <div className="auth-divider">
              <span>or use your email</span>
            </div>
          </>
        )}

        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="field">
            {/* [General] htmlFor links a label to its input by id, so clicking the
                label focuses the field. In plain HTML this attribute is `for`,
                but `for` is a reserved word in JavaScript — hence the rename,
                exactly like className. */}
            <label className="field-label" htmlFor="email">Email</label>
            <input
              className="input auth-input"
              id="email"
              type="email"
              placeholder="you@company.com"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              /* [General] autoComplete tells the browser's password manager what
                 this field is, which is what makes saved credentials offer
                 themselves. Omitting it does not disable autofill — it makes the
                 browser guess, and guess wrong on the signup page. */
              autoComplete="email"
              required
              disabled={submitting}
            />
          </div>

          <div className="field">
            {/* The label row now carries the reset link on its right. WHY HERE
                rather than under the button: it is the answer to a question asked
                by this exact field, and a user who cannot remember their password
                is looking at the password box when they realise it. */}
            <div className="field-row">
              <label className="field-label" htmlFor="password">Password</label>
              <Link className="field-aside-link" to="/forgot-password">
                Forgotten?
              </Link>
            </div>
            <input
              className="input auth-input"
              id="password"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              /* "current-password", not "new-password" — the distinction is how a
                 password manager knows to offer the saved one here and to suggest
                 a generated one on the signup form. */
              autoComplete="current-password"
              required
              disabled={submitting}
            />
          </div>

          {/* [React] role="alert" makes a screen reader announce this the moment it
              appears, without the user having to go looking for it. An error
              nobody is told about is an error nobody can act on. */}
          {error && (
            <p className="auth-error" role="alert">
              <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
              <span>{error}</span>
            </p>
          )}

          <button className="btn-primary" type="submit" disabled={submitting}>
            {submitting ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>

      {/* THE OTHER HALF OF THE STATE HANDOFF. RequireAuth's `from` arrives on this
          page and this link is where it used to die: a visitor bounced here from
          /checkout/starter who does not yet have an account clicks "Create one",
          and without `state` the signup page has no idea a plan was ever chosen.

          That is not the rare path — it is the NORMAL path for a new customer, who
          by definition has no account to sign in with. So the state is forwarded,
          and Signup reads it at all three of its exits. */}
      <p className="auth-alt">
        No account yet?{' '}
        <Link to="/signup" state={location.state}>
          Create one
        </Link>
      </p>
    </main>
  )
}
