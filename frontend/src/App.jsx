/* ============================================================================
   APP.JSX — the router. The single source of truth for "what URL shows what".

   WHY THIS EXISTS: this file is the app's table of contents. Every page in the
   blueprint's sitemap is registered here exactly once, so you can read this one
   file and know the whole app's structure.

   IT ALSO OWNS THE SKIP LINK, for one reason: a skip link only works if it is
   the FIRST focusable thing in the document, and this is the only component that
   renders before every page. Putting it in TopBar would have been closer to the
   markup it skips, but Report and the 404 page deliberately have no TopBar, so
   two routes would have silently lost it.
   ========================================================================== */

import { Routes, Route, Navigate } from 'react-router-dom'
import { Compass } from 'lucide-react'

import RequireAuth from './components/RequireAuth'
import Landing from './pages/Landing'
import Dashboard from './pages/Dashboard'
import ScanResult from './pages/ScanResult'
import History from './pages/History'
import Report from './pages/Report'
import Login from './pages/Login'
import Signup from './pages/Signup'
import TwoFactor from './pages/TwoFactor'
import Enrol from './pages/Enrol'
import ForgotPassword from './pages/ForgotPassword'
import ResetPassword from './pages/ResetPassword'
import Settings from './pages/Settings'
import Checkout from './pages/Checkout'

export default function App() {
  return (
    /* [React] A FRAGMENT wraps the skip link and the router, because a component
       may only return one element and this returns two things that must not be
       wrapped in a real <div> — an extra element here would sit between <body>
       and the page and could interfere with the full-bleed top bar's layout. */
    <>
      {/* WHY THIS EXISTS: a keyboard user landing on the report page would
          otherwise have to tab through the whole top bar — brand, history link,
          user name, sign out — on every single page before reaching the content
          they came for. This is WCAG 2.4.1, and it is one element.

          It is a plain <a>, not a <Link>: the target is an anchor within the
          page already on screen, and React Router would treat it as navigation.
          base.css hides it off-screen with a transform until it is focused —
          NOT with display:none, which would remove it from the tab order and
          make it unreachable, which is the classic way to ship a skip link that
          does nothing. */}
      <a className="skip-link" href="#main">
        Skip to content
      </a>

      {/* [React] <Routes> looks at the current URL and renders the ONE <Route>
          whose path matches. Think of it as a switch statement over the URL. */}
      <Routes>
        <Route path="/" element={<Landing />} />

        {/* The auth pages, now real. They stay OUTSIDE RequireAuth for the
            obvious reason — a guard that redirected signed-out visitors to the
            login page would redirect them away from the login page. */}
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />

        {/* THE SECOND HALF OF A LOGIN. Both of these are reached only by
            navigation from /login, which hands them a challenge in router state —
            never in the URL, because a challenge is a short-lived credential and a
            URL gets pasted into tickets and written to history. See the header of
            Login.jsx.

            THEY ARE NOT INSIDE RequireAuth, and that is the whole point: the user
            has proved their password and has no session yet. A guard here would
            bounce them back to /login, which is the page that sent them. Both pages
            do their own guarding instead — no challenge in state means a refresh
            happened, and they redirect to /login with a sentence explaining why. */}
        <Route path="/login/verify" element={<TwoFactor />} />
        <Route path="/login/enrol" element={<Enrol />} />

        {/* THE TWO HALVES OF A RESET, and the same arrangement for the same
            reasons. /reset-password is reached only by navigation from
            /forgot-password, which hands it a challenge in router state, and it
            guards itself when a refresh loses one.

            It is outside RequireAuth too, and stays outside it afterwards: a
            completed reset issues NO session. It sets the password and sends the
            user to /login to use it - see the header of ResetPassword.jsx for why
            an emailed code must not be able to mint a session on its own. */}
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />

        {/* [React] EVERY /dashboard route is wrapped in RequireAuth, because
            every one of them shows data the server will only hand to a session.
            Wrapping the element rather than adding a check inside each page keeps
            the rule visible HERE, in the routing table — which is where somebody
            adding a fourth dashboard route will be looking, and therefore where
            they are most likely to notice it applies to theirs too.

            It is a redirect, not a lock. See RequireAuth.jsx: the real check is
            the server's, on every request. */}
        <Route
          path="/dashboard"
          element={
            <RequireAuth>
              <Dashboard />
            </RequireAuth>
          }
        />

        {/* [React] The `:id` segment is a URL PARAMETER — a wildcard. This one
            route matches /dashboard/scan/4821, /dashboard/scan/4822, and so on.
            The page reads the actual value with the useParams() hook. */}
        <Route
          path="/dashboard/scan/:id"
          element={
            <RequireAuth>
              <ScanResult />
            </RequireAuth>
          }
        />

        <Route
          path="/dashboard/history"
          element={
            <RequireAuth>
              <History />
            </RequireAuth>
          }
        />

        {/* THE ACCOUNT PAGE — identity, two-factor, recovery codes, password, and
            "sign out everywhere". Guarded like every /dashboard route: everything on
            it acts on the signed-in account and every endpoint behind it requires a
            session.

            NOT UNDER /dashboard, deliberately. The pages below /dashboard are about
            SCANS — running them, reading them, listing them. This one is about the
            account, which is a different subject that happens to need the same
            guard, and a URL is the cheapest place to say so. */}
        <Route
          path="/settings"
          element={
            <RequireAuth>
              <Settings />
            </RequireAuth>
          }
        />

        {/* CHECKOUT — the page a pricing button now leads to. It existed before this
            route did: Checkout.jsx was written whole, complete with a card form, a
            receipt state and its own error handling, and nothing pointed at it. A
            page with no route is a page nobody can reach, and this one line is the
            difference between a paid plan being purchasable and not.

            GUARDED, AND THAT GUARD IS ALSO THE FEATURE. A purchase has to belong to
            an account, so RequireAuth is not optional here — but its redirect is
            doing a second job. It passes state={{ from: location }} on the way to
            /login, which is what carries "/checkout/starter" through signing up and
            back again, so a visitor who picks a plan and then discovers they need an
            account does not have to pick it a second time. See the note in Signup.jsx
            about the exit that used to throw that away.

            [React] `:planId` is a URL parameter, read with useParams(). It names a
            plan, and the SERVER decides what that plan costs and whether it is for
            sale at all — nothing about the price travels in the URL. See the note
            above CheckoutRequest in main.py. */}
        <Route
          path="/checkout/:planId"
          element={
            <RequireAuth>
              <Checkout />
            </RequireAuth>
          }
        />

        {/* THE OLD SECURITY PAGE, REDIRECTED RATHER THAN DELETED.

            /dashboard/security was a page that did the 2FA half of what /settings now
            does whole. Removing the route would 404 anyone who bookmarked it, to prove
            a point about naming that costs them their bookmark.

            [React] <Navigate> is a component that redirects when rendered. `replace`
            makes it REPLACE the current history entry instead of adding one — without
            it the browser's Back button returns here, this redirects again, and Back
            is broken for as long as the user keeps pressing it.

            No RequireAuth around it: /settings is already guarded, so an unauthenticated
            visitor lands there and is bounced to /login from a single place. Guarding
            both would mean two components deciding the same thing. */}
        <Route path="/dashboard/security" element={<Navigate to="/settings" replace />} />

        {/* Standalone report view — the shareable link sent to a client's dev.
            DELIBERATELY UNGUARDED, and the only route below /dashboard that is.
            The reader of a forwarded report has no account, so a guard here would
            break the one thing this page is for. It reads the public /report/:id
            endpoint, which the backend serves without a session; the id is what
            makes the link work, and it is not a permission. See the comment on
            get_shared_report in main.py. */}
        <Route path="/report/:id" element={<Report />} />

        {/* [React] path="*" is the catch-all: any URL that matched nothing above
            lands here, so a typo'd address shows a real page, not a blank screen. */}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </>
  )
}

/* A small component defined in the same file because it is only used here.
   Larger components each get their own file. */
function NotFound() {
  return (
    <div className="container">
      {/* The skip link's target exists here too. A 404 has no top bar to skip,
          but a link that points at nothing is worse than one that lands on the
          only content there is. */}
      <main id="main" className="empty-state">
        <span className="empty-state-icon" aria-hidden="true">
          <Compass size={20} strokeWidth={2} />
        </span>
        <h2>Page not found</h2>
        <p>That URL doesn&apos;t match anything in SecuScan.</p>
        {/* [General] a plain <a> does a full page reload; React Router's <Link>
            (used elsewhere) navigates instantly without one. Here a reload is
            harmless, but Link is the habit worth forming. */}
        <a className="btn-primary" href="/">Back to home</a>
      </main>
    </div>
  )
}
