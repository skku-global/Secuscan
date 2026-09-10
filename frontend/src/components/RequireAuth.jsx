/* ============================================================================
   REQUIREAUTH.JSX — the wrapper that keeps signed-out visitors off app pages.

   WHY THIS EXISTS: /dashboard, /dashboard/history and /dashboard/scan/:id all
   render nothing useful without a session — every request they make comes back
   401. Sending someone to the login page is a better answer than three error
   states saying the same thing.

   WHAT THIS IS NOT: protection. It is navigation. The data these pages show is
   protected by the server checking the token on every request, and that check is
   the only thing standing between a visitor and somebody else's scans. Deleting
   this file would make the app rude, not insecure — the pages would render and
   then fill with 401 errors.

   Worth stating plainly because the opposite belief is common and expensive: a
   route guard in a single-page app is a suggestion made by code the user is
   free to modify. Anyone can open devtools and set signedIn to true. All they
   get is an empty dashboard.
   ========================================================================== */

import { Navigate, useLocation } from 'react-router-dom'

import { useAuth } from '../context/AuthContext'

export default function RequireAuth({ children }) {
  const { signedIn, checking } = useAuth()
  const location = useLocation()

  /* THE STATE THAT IS EASY TO FORGET. On a fresh page load the context has a
     token but has not yet heard back from /auth/me, so `signedIn` is false —
     not because the user is signed out, but because the answer has not arrived.
     Redirecting here would bounce every signed-in user to the login page on
     every refresh, and then bounce them back a moment later.

     [React] Returning null renders nothing. That is deliberate: this resolves in
     a few milliseconds on a local API, and a spinner that appears and vanishes
     that fast is a flicker, not feedback. */
  if (checking) return null

  if (!signedIn) {
    /* [React] <Navigate> performs a redirect by being rendered — there is no
       imperative "go here" call in React Router's declarative API.

       `replace` swaps the current history entry instead of adding one, so the
       browser Back button does not land the user on the page they were just
       bounced off, which would bounce them again. A redirect loop the user
       drives with the Back button is a real and confusing bug.

       `state` carries where they were trying to go. Login reads it and sends
       them there after signing in, so a bookmarked report opens the report
       rather than dumping them on the dashboard. [React] location.state is the
       standard channel for passing data through a navigation without putting it
       in the URL. */
    return <Navigate to="/login" replace state={{ from: location }} />
  }

  /* [React] `children` is whatever this component wrapped in App.jsx. Returning
     it unchanged is what makes this a transparent gate: <RequireAuth><Dashboard
     /></RequireAuth> renders exactly <Dashboard /> once the check passes. */
  return children
}
