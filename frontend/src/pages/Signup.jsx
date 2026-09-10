/* ============================================================================
   SIGNUP.JSX — account creation at "/signup".

   WHY THIS EXISTS: the counterpart to Login, and the place where the password
   rules become visible.

   THE LIVE CHECKLIST IS NOT A SECURITY CONTROL. Every rule it shows is enforced
   again by the server, in auth.py's password_problem(), and only that copy
   decides anything — everything here can be skipped with curl. What this exists
   to do is tell someone their password will be refused BEFORE they press the
   button, instead of after they have filled in three other fields. A check in
   the browser is UX; a check on the server is security. The same rule in both
   places is not duplication, it is two different jobs.

   See lib/passwordPolicy.js for the rules themselves, kept in one file so this
   component holds no opinion about what a good password is.

   ---------------------------------------------------------------------------
   THE PREMIUM LAYOUT, AND WHAT "PREMIUM" MEANT IN PRACTICE

   This page used to be the same 380px column as the login form. It is now a two
   panel split: the form on the left, and on the right a quiet panel saying what
   an account actually gets you. That is the one structural difference, and the
   reasoning behind it is narrow — a signup form is the highest-friction moment in
   the product, and the questions in someone's head at that moment ("is this
   free?", "will it charge me?", "what happens next?") have nowhere to be answered
   on a bare form. The panel answers them beside the field they are hesitating on.

   IT IS NOT A DIFFERENT DESIGN SYSTEM. There is no gradient, no shadow, no glass,
   no accent colour that appears nowhere else. Everything below is Clinical
   Ledger's own vocabulary — hairline borders, one tinted surface, tabular
   figures — arranged with more space and more hierarchy than the old page had.
   "Premium" here is spacing, type scale and restraint, because a security product
   that decorates its signup page reads as a marketing site rather than as a tool.
   Every colour is a token, so all three themes get this for free; see the note on
   the band tokens in tokens.css for why a literal hex here would break the white
   theme specifically.

   THE PANEL DISAPPEARS BELOW 900px, and the form is unchanged when it does. That
   ordering matters: the form is the page, the panel is support. A layout where the
   supporting column pushes the form below the fold on a phone would be a worse
   page than the one this replaced.
   ========================================================================== */

import { useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import {
  Shield,
  Check,
  X,
  AlertCircle,
  Radar,
  FileText,
  Lock,
  CreditCard,
} from 'lucide-react'

import { useAuth } from '../context/AuthContext'
import { useAuthConfig } from '../hooks/useAuthConfig'
import GoogleSignIn from '../components/GoogleSignIn'
import { checkPassword } from '../lib/passwordPolicy'
import '../styles/auth.css'

/* WHAT THE RIGHT-HAND PANEL SAYS. Data rather than four blocks of repeated JSX,
   for the usual reason — adding a fifth line is one entry here.

   EVERY CLAIM ON THIS LIST IS TRUE TODAY. That is a real constraint and not a
   pious one: a signup panel promising a feature that does not exist is the
   fastest way to make the first five minutes after signup feel like a bait and
   switch. "Seven external checks" is scanning/'s check count, the free scan is
   billing.PLANS's Free entry, the card line is what /billing/checkout actually
   does, and the 2FA line is a page that exists. Nothing aspirational. */
const SIGNUP_POINTS = [
  {
    icon: Radar,
    title: 'A real scan, not a demo',
    text: 'All seven external checks run against your live site the moment you submit a URL. The findings are the same ones a paid scan produces.',
  },
  {
    icon: FileText,
    title: 'A report you can forward',
    text: 'Every scan gets a shareable link your developer can open without an account, plus a printable version for the file.',
  },
  {
    icon: CreditCard,
    title: 'No card to start',
    text: 'The Free plan needs no payment details at all. Nothing charges you until you choose a plan yourself.',
  },
  {
    icon: Lock,
    title: 'Two-factor when you want it',
    text: 'Add an authenticator app from your account settings, with printed recovery codes in case the phone goes missing.',
  },
]

export default function Signup() {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const { register, signedIn, checking } = useAuth()

  /* What this server is actually configured to offer. Used for exactly one thing
     on this page — whether there is a Google button — and `ready` is what keeps
     the "or" divider from flashing into place a beat after the form renders.
     See hooks/useAuthConfig.js. */
  const { config, ready: configReady } = useAuthConfig()

  const navigate = useNavigate()
  const location = useLocation()

  /* [React] Recomputed on every render, and that is correct — it is a pure
     function of values that are already state, so caching it in a useState would
     create a second copy that can fall out of step with the field it describes.
     Derive what you can; store only what you cannot.

     The email and name go in because two of the rules are about them: a password
     may not contain either. So the checklist updates when the NAME field
     changes, not just the password one. */
  const strength = checkPassword(password, { email, name })

  /* WHERE TO GO AFTERWARDS — the same three lines Login.jsx has, and the reason
     they were missing here is worth writing down.

     RequireAuth bounces a signed-out visitor to /login with state={{ from }}, and
     Login honours it, so a bookmarked report survives signing in. Nobody is ever
     bounced to a SIGNUP page, which is why this page had no such logic and the
     comment on the Google button below said so outright.

     THAT REASONING BROKE THE MOMENT PRICING BUTTONS STARTED POINTING AT
     /checkout/:planId. The path is now: pick a plan → guard sends you to /login
     carrying "/checkout/starter" → you have no account, so you click "Create one" →
     you arrive HERE, and every exit went to /dashboard. The plan the visitor chose
     was thrown away at the one step a NEW customer is most likely to take, and the
     dashboard gives no hint that a purchase was ever in progress.

     So the state travels the whole way: the two cross-links between these pages
     forward it (see the bottom of each), and all three exits below read it.

     [General] Optional chaining and ?? throughout, because state is null for
     everybody who reached this page by choosing to sign up. */
  const destination = location.state?.from?.pathname ?? '/dashboard'

  if (!checking && signedIn) return <Navigate to={destination} replace />

  async function handleSubmit(event) {
    event.preventDefault()

    if (submitting) return

    /* [General] A last local check before sending. The button is already
       disabled when the password fails a rule, but Enter in a text field submits
       a form regardless of the button's state — so the button alone is not the
       guard it looks like. */
    if (!strength.accepted) {
      setError('Choose a password that meets all four requirements.')
      return
    }

    setError('')
    setSubmitting(true)

    try {
      await register({ name, email, password })

      /* `destination` rather than '/dashboard' — see the note above it. A visitor
         who came here from a pricing button lands back on the checkout for the plan
         they picked, with the account they just made. */
      navigate(destination, { replace: true })
    } catch (caught) {
      /* Worth knowing which messages arrive here, because they are not all the
         same kind of thing:

           409 — "That email is already registered." A real answer the user can
                 act on, and a deliberate trade: it does tell an attacker the
                 address exists. See the comment on signup() in main.py.
           422 — a password rule the browser did not catch. Should be rare; it
                 means the two copies of the policy have drifted, which is worth
                 noticing rather than smoothing over.
           429 — too many attempts. */
      setError(caught.message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    /* [General] <main> rather than <div>: the skip link needs a landmark to
       land on, and on this page the form IS the whole content — there is no
       navigation to skip past, but the link exists on every route and must have
       a target on every route. */
    <main id="main" className="auth-page auth-page-wide">
      <div className="auth-split">
        {/* --- The form column ------------------------------------------- */}
        {/* [General] A <section> with its own heading, so a screen reader's
            landmark list distinguishes the two columns. The old page had one
            column and needed no such thing; two unlabelled regions side by side
            is the version that reads as a wall of fields. */}
        <section className="auth-main" aria-labelledby="signup-heading">
          <Link to="/" className="auth-brand">
            <Shield size={20} strokeWidth={2} />
            SecuScan
          </Link>

          <h1 className="auth-title" id="signup-heading">
            Create an account
          </h1>
          <p className="auth-sub">
            Free to start. Your first scan runs as soon as you are in.
          </p>

          <div className="auth-card">
            {/* GOOGLE FIRST, AND THE ORDER IS THE DECISION. Someone who has a
                Google account and would rather use it should not have to read
                past three fields to find that out; someone who wants a password
                loses nothing by scrolling one button. It renders nothing at all
                when the server has no client id, and the divider below is tied to
                the same condition so there is never a lone "or". */}
            {configReady && config.googleEnabled && (
              <>
                <GoogleSignIn
                  clientId={config.googleClientId}
                  enabled={config.googleEnabled}
                  text="signup_with"
                  disabled={submitting}
                  /* THE SAME DESTINATION AS THE FORM. This comment used to read
                     "Straight to the dashboard. There is no `from` state to honour
                     here the way Login has — nobody is bounced to a SIGNUP page by
                     the route guard." The first sentence was the bug and the second
                     was true but not the whole story: nobody is bounced HERE, and
                     people are sent here by a link from the page they were bounced
                     to. One-click signup is the likeliest path of all for somebody
                     buying a plan, so this was the exit that mattered most. */
                  onSignedIn={() => navigate(destination, { replace: true })}
                />

                {/* [General] The line-through-the-middle divider, built with a
                    real element rather than an ::after on the form, because the
                    word has to sit ON the rule and be readable by a screen
                    reader as a word. aria-hidden would be wrong: "or" is the
                    only thing telling a non-visual reader these are
                    alternatives rather than steps. */}
                <div className="auth-divider">
                  <span>or use your email</span>
                </div>
              </>
            )}

            <form className="auth-form" onSubmit={handleSubmit}>
              <div className="field">
                {/* [General] Every id here is unique across the page. Duplicated
                    ids silently break label-to-input association, which is why
                    these are prefixed "signup-" rather than reusing Login's
                    plain "email". */}
                <label className="field-label" htmlFor="name">Name</label>
                <input
                  className="input auth-input"
                  id="name"
                  type="text"
                  placeholder="Your name"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  autoComplete="name"
                  required
                  disabled={submitting}
                />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="signup-email">Email</label>
                <input
                  className="input auth-input"
                  id="signup-email"
                  type="email"
                  placeholder="you@company.com"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  autoComplete="email"
                  required
                  disabled={submitting}
                />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="signup-password">
                  Password
                </label>
                <input
                  className="input auth-input"
                  id="signup-password"
                  type="password"
                  /* The minimum comes from the server now rather than being
                     typed into this placeholder. It is the same number either
                     way today; what changes is that raising it in auth.py no
                     longer leaves a form advertising the old figure.
                     AUTH_CONFIG_FALLBACK supplies it before the request lands,
                     so there is never a placeholder reading "At least
                     undefined characters". */
                  placeholder={`At least ${config.passwordMinLength} characters`}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  /* "new-password" is what asks a password manager to OFFER TO
                     GENERATE one, rather than filling in a saved password. The
                     single most useful attribute on this page. */
                  autoComplete="new-password"
                  required
                  disabled={submitting}
                />
              </div>

              {/* [React] The checklist appears only once there is something to
                  check. Four red crosses greeting an empty field reads as failure
                  before the user has done anything. */}
              {password.length > 0 && (
                <div className="pw-check">
                  {/* The bar tracks the RULES — how many of the four are met. The
                      word beside it describes margin BEYOND the minimum, which is
                      why they can disagree: a 12-character password shows a full
                      bar and "Meets the minimum". */}
                  <div className="pw-meter" aria-hidden="true">
                    <div
                      className={`pw-meter-fill met-${strength.metCount}`}
                      /* [React] An inline style is right for a value computed at
                         runtime. CSS cannot express "four twenty-fifths of the
                         way across" without a class per state, and the class is
                         already carrying the colour. */
                      style={{ width: `${(strength.metCount / 4) * 100}%` }}
                    />
                  </div>

                  <p className="pw-label">{strength.label}</p>

                  {/* [React] .map() over the rules rather than four hand-written
                      rows. The wording lives in passwordPolicy.js next to the rule
                      it describes, so a rule and its label cannot drift apart. */}
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
                /* Disabled until every rule passes. The checklist above is what
                   makes this honest rather than annoying: a dead button with no
                   explanation is the worst version of this pattern. */
                disabled={submitting || !strength.accepted}
              >
                {submitting ? 'Creating account…' : 'Create account'}
              </button>

              {/* WHY THIS SITS INSIDE THE CARD AND NOT IN A FOOTER: it is part of
                  the commitment being made by pressing the button above it, and a
                  legal-ish line floated away from the control it qualifies is the
                  pattern that gets described as dark. Kept short and specific —
                  it names what the account does, which is the only claim being
                  made. */}
              <p className="auth-fine">
                Scans run only against sites you tell us to scan. Nothing runs
                automatically on the Free plan.
              </p>
            </form>
          </div>

          {/* THE STATE IS FORWARDED, and this link is half of why the plan
              survives. Without `state` the round trip signup → "Sign in" → login
              loses the checkout the visitor was heading for, and they finish on a
              dashboard wondering what happened to the plan they picked.

              [React] `location.state` is passed straight through rather than
              rebuilt, so anything RequireAuth or another page put in there — the
              `notice` Login reads, for instance — survives the hop too. */}
          <p className="auth-alt">
            Already registered?{' '}
            <Link to="/login" state={location.state}>
              Sign in
            </Link>
          </p>
        </section>

        {/* --- The supporting column ------------------------------------- */}
        {/* [General] <aside> is the correct element: related to the page, not the
            page's own subject. It is second in the DOM as well as on the right, so
            a keyboard user tabs through the form before reaching anything here —
            source order and visual order agree, which is what stops a focus
            outline jumping across the screen. */}
        <aside className="auth-aside" aria-labelledby="signup-aside-heading">
          <p className="section-label" id="signup-aside-heading">
            What you get
          </p>

          <ul className="auth-points">
            {SIGNUP_POINTS.map((point) => {
              /* [React] The icon is a COMPONENT held in data, so it is assigned
                 to a capitalised local name before being rendered. Lowercase JSX
                 tags are treated as HTML elements — `<point.icon />` happens to
                 work because of the dot, but `<icon />` would silently render an
                 unknown <icon> tag, which is the bug this convention avoids. */
              const Icon = point.icon

              return (
                <li key={point.title}>
                  <span className="auth-point-icon" aria-hidden="true">
                    <Icon size={16} strokeWidth={2} />
                  </span>

                  <div>
                    <p className="auth-point-title">{point.title}</p>
                    <p className="auth-point-text">{point.text}</p>
                  </div>
                </li>
              )
            })}
          </ul>

          {/* THE HONEST FOOTNOTE. This app stores a password hash, an email and
              your scans, and it is worth saying so on the page asking for them
              rather than in a policy nobody opens. `mono` and `tabular` are
              base.css's own utilities — the same treatment findings get, which is
              the visual link between "we tell you the truth about your site" and
              "we tell you the truth about ourselves". */}
          <p className="auth-aside-note">
            Passwords are stored as <span className="mono">Argon2id</span> hashes,
            never as text. Sessions are server-side and expire; signing out ends
            them everywhere they were issued from this browser.
          </p>
        </aside>
      </div>
    </main>
  )
}
