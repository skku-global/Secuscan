/* ============================================================================
   AUTHCONTEXT.JSX — who is signed in, shared by the whole app.

   WHY THIS EXISTS: three separate places need the answer to "is anyone signed
   in, and who" — the top bar showing a name, the route guard deciding whether
   to redirect, and the landing page choosing between a scan form and a prompt
   to sign up. A hook like useScans() cannot serve them, because each caller of
   a hook gets its OWN state: three components would run three /auth/me requests
   and could disagree with each other for a moment afterwards.

   [React] CONTEXT is the tool for exactly this shape of problem — one value,
   many readers, at different depths of the tree. It has three parts:

     1. createContext()  — makes the channel.
     2. <Provider>       — puts a value on it, wrapping the tree (see main.jsx).
     3. useContext()     — reads it from any component underneath, however deep,
                           with no prop passed through the components between.

   The thing to understand about context is what it is NOT. It is not a store
   and it does no caching or deduplication; it is prop-drilling with the drilling
   removed. The state below is ordinary useState — context only decides who can
   see it.

   WHAT IS TRUSTED HERE, AND WHAT IS NOT
   Nothing in this file is a security control, and it is worth being blunt about
   that. Anyone can set `user` in devtools and make the UI render as though they
   were signed in. What they cannot do is make the SERVER agree: every scan
   endpoint checks the token for itself, so a faked user object produces an app
   that looks signed in and returns 401 for everything. The redirects here are
   navigation, not protection.
   ========================================================================== */

import { createContext, useCallback, useContext, useEffect, useState } from 'react'

import * as api from '../lib/api'
import {
  SESSION_ENDED_EVENT,
  clearSession,
  readToken,
  saveSession,
} from '../lib/session'

/* [React] The channel itself. The argument is the DEFAULT value, used only by a
   component with no Provider above it — which in this app means a bug, so null
   is right: it turns that mistake into an immediate error in useAuth() rather
   than a silently empty object. */
const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)

  /* One status string, the same convention as useScan and useScans. `checking`
     is the state on first paint and it genuinely matters here: without it, the
     app would render its signed-out self for a moment before /auth/me answered,
     and a signed-in user reloading the dashboard would be bounced to the login
     page and then back. A visible flash of the wrong screen. [React] */
  const [status, setStatus] = useState('checking')   // checking | in | out

  /* WHY THIS EXISTS: the token in localStorage survived a reload; whether it is
     still VALID is a question only the server can answer. It may have expired,
     or been revoked by signing out on another device.

     [React] The effect runs once, after the first render — never during it.
     Rendering must be free of side effects, and a fetch is the clearest possible
     side effect. */
  useEffect(() => {
    // No token means signed out. Asking the server would be a guaranteed 401 and
    // a wasted round trip on every first visit.
    if (!readToken()) {
      setStatus('out')
      return
    }

    let cancelled = false

    api
      .fetchMe()
      .then((me) => {
        if (cancelled) return

        // fetchMe returns null for a rejected token rather than throwing, which
        // is what lets "signed out" be an outcome here instead of an error.
        setUser(me)
        setStatus(me ? 'in' : 'out')
      })
      .catch(() => {
        if (cancelled) return

        /* The server could not be reached. Signed-out is the safe assumption:
           the alternative is showing a dashboard whose every request will fail.
           Note the local token is deliberately NOT cleared here — it may be
           perfectly good, and the backend merely restarting. Throwing away a
           valid session because of one failed request would sign people out
           every time the API blinked. */
        setStatus('out')
      })

    return () => {
      cancelled = true
    }
  }, [])

  /* WHY THIS EXISTS: the session can end without any component asking it to —
     api.js clears it the instant a request comes back 401. This is how the UI
     finds out, so a token that dies in a background fetch takes the name out of
     the corner immediately instead of at the next navigation.

     [React] Subscribing in an effect and unsubscribing in its cleanup is the
     pattern for every external event source. Skipping the removeEventListener
     leaks a listener on every mount — invisible in a small app and a real
     problem in a long-lived one. */
  useEffect(() => {
    function handleSessionEnded() {
      setUser(null)
      setStatus('out')
    }

    window.addEventListener(SESSION_ENDED_EVENT, handleSessionEnded)

    return () => window.removeEventListener(SESSION_ENDED_EVENT, handleSessionEnded)
  }, [])

  /* WHY THIS EXISTS: every route to a signed-in state ends the same three steps —
     write the token, put the user in state, flip the status. There are now SIX such
     routes (signup, password login, Google, a 2FA code, a recovery code, an emailed
     code) and writing those steps six times is five chances to forget the
     saveSession() and produce an app that looks signed in with nothing stored.

     [React] useCallback keeps this function IDENTITY-STABLE between renders. It
     goes into the context value below, and a fresh function on every render would
     make that value new every time — re-rendering every consumer of this context
     whether or not anything actually changed. */
  const adoptSession = useCallback(({ token, user: signedIn }) => {
    // Storage first. If the app re-renders before the token is written, a
    // component could fire a request without one. [General]
    saveSession({ token, user: signedIn })

    setUser(signedIn)
    setStatus('in')

    return signedIn
  }, [])

  /* WHY THIS IS NOT JUST adoptSession(await call()) — AND THE BUG THAT TAUGHT IT
     A correct password does not always mean a session. POST /auth/login answers in
     one of three shapes, all of them successes:

       { token, user }                — signed in.
       { challenge, method: 'totp' }  — password fine, a code is still needed.
       { challenge, method: 'enrol' } — password fine, but this server requires 2FA
                                        and the account has none yet.

     This function used to destructure { token, user } unconditionally. On a 2FA
     account that meant saveSession({ token: undefined }) followed by
     setStatus('in') — an app rendering its signed-in self, showing a name in the
     corner, holding no session, and answering 401 to every single request. Worse
     than a failed login, because it looked like a successful one.

     So: the challenge shape is returned UNTOUCHED and nothing is stored. The caller
     is the only thing that can act on it anyway — it decides which page to navigate
     to — which is the same argument api.login() makes for not flattening the union.
     See handleSubmit in pages/Login.jsx. */
  const adopt = useCallback(
    async (call) => {
      const result = await call()

      if (result?.challenge) return result

      adoptSession(result)

      // Returning the whole payload rather than just the user, so a caller that
      // needs to tell the two outcomes apart can check for `.challenge` on one
      // value instead of comparing what came back against what it asked for.
      return result
    },
    [adoptSession],
  )

  const signIn = useCallback(
    (credentials) => adopt(() => api.login(credentials)),
    [adopt],
  )

  const register = useCallback(
    (details) => adopt(() => api.signup(details)),
    [adopt],
  )

  /* WHY GOOGLE GETS ITS OWN ENTRY RATHER THAN REUSING signIn: it takes a Google
     credential instead of an email and password, and it can never answer with a
     challenge — Google has already applied whatever second factor that account has.
     It still goes through adopt() so the session is stored by the same code. */
  const signInWithGoogle = useCallback(
    (credential) => adopt(() => api.signInWithGoogle(credential)),
    [adopt],
  )

  /* WHY THIS EXISTS: a plan changes underneath a session that is already valid.
     Buying or cancelling a plan returns an updated user, and the token is unchanged
     — so re-storing it alongside the new user is all that is needed.

     [General] readToken() rather than a token argument, because the caller does not
     have one: the checkout response contains a user and no token, precisely because
     the session it was made with is still the session. */
  const refreshUser = useCallback((updated) => {
    if (!updated) return

    saveSession({ token: readToken(), user: updated })
    setUser(updated)
  }, [])

  /* WHY THIS EXISTS: sign-out in the order that cannot strand anybody. The
     server call goes first so the request still carries a token — clearing
     storage first would send an unauthenticated logout that deletes nothing and
     leaves a live session behind on the server.

     api.logout() never throws (see api.js), so the local half always runs. That
     is the guarantee worth having: a user pressing "sign out" is always signed
     out of this browser, whatever the network did. */
  const signOut = useCallback(async () => {
    await api.logout()

    // Fires SESSION_ENDED_EVENT, which the effect above turns into setUser(null)
    // and setStatus('out') — so the state change happens through exactly the
    // same path as a session that expired on its own. One code path, one
    // behaviour, whichever way a session ends.
    clearSession()
  }, [])

  /* [React] Everything a consumer can see. `signedIn` is derived rather than
     stored: a second piece of state that has to be kept in agreement with
     `status` is a second piece of state that can disagree with it. */
  const value = {
    user,
    status,
    checking: status === 'checking',
    signedIn: status === 'in',
    signIn,
    register,
    signInWithGoogle,
    /* WHY THE 2FA PAGES GET THIS: they finish a login that started on the login
       page. They hold a challenge, they post a code, and the server hands back
       { token, user } — exactly what signIn receives after a no-2FA login. Exposing
       it means those pages do not write their own saveSession + setUser + setStatus;
       there is one place in this app that turns a token into a session. */
    adoptSession,
    refreshUser,
    signOut,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/* WHY THIS EXISTS: components call useAuth() rather than useContext(AuthContext),
   so the context object itself never has to be exported or imported anywhere.
   That is what keeps the Provider the only way in.

   The null check turns the most common context mistake — reading it from a
   component that is not inside the Provider — into a sentence naming the fix,
   instead of "cannot destructure property 'user' of null". [React] */
export function useAuth() {
  const context = useContext(AuthContext)

  if (context === null) {
    throw new Error('useAuth() must be called inside <AuthProvider>. See main.jsx.')
  }

  return context
}
