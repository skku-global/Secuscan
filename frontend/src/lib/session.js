/* ============================================================================
   SESSION.JS — where the browser keeps the signed-in user.

   WHY THIS EXISTS: the token the server issues has to survive a page reload, or
   every refresh would sign you out. This file is the only place in the app that
   touches storage, so "how a session is remembered" is one decision in one file
   rather than a habit sprinkled across pages.

   WHERE THE TOKEN LIVES, AND WHY THAT IS A COMPROMISE
   localStorage, which means any JavaScript running on this page can read it. If
   an attacker ever gets a script onto the page — a cross-site scripting hole, a
   compromised npm package — they can take the token and be you. The stronger
   answer is an httpOnly cookie, which JavaScript cannot read at all.

   It is not that here for one concrete reason: in development the API is on port
   8000 and the app is on 5173, which browsers treat as different sites, and a
   cookie that crosses that boundary needs SameSite=None plus Secure plus HTTPS.
   That is a deployment change, not a code change, so it is written down here as
   the known next step rather than pretended away.

   Two things reduce the damage in the meantime: the token expires after 30 days,
   and signing out revokes it on the server — so a stolen token has a lifetime,
   and there is a way to end it.
   ========================================================================== */

/* One namespaced key. [General] localStorage is shared across everything served
   from an origin, so an unprefixed key like "token" is asking for a collision. */
const STORAGE_KEY = 'secuscan.session'

/* WHY THIS EXISTS: a session can end somewhere no React component is watching —
   api.js clears it the moment the server answers 401 to a background request.
   Without a way to say so, the app would keep a stale name in the corner and a
   dashboard the user can no longer load, until they happened to navigate.

   [General] A CustomEvent on window is the whole mechanism. It keeps the
   dependency pointing one way: this file and api.js know nothing about React,
   and the auth context subscribes to them rather than being called by them. The
   alternative — importing a setState from here — would make a storage helper
   depend on the component tree, which is exactly backwards.

   Exported so the context can listen for the same name this file dispatches,
   instead of two files agreeing on a string literal and later disagreeing. */
export const SESSION_ENDED_EVENT = 'secuscan:session-ended'

/* WHY THIS EXISTS: localStorage can throw rather than return null — Safari in
   private mode, and any browser with site data blocked, raise on access. An auth
   helper that crashes the whole app because storage is unavailable would be a
   worse failure than simply not remembering the login, so every read and write
   here is wrapped. [General] */
export function readSession() {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (!raw) return null

    const parsed = JSON.parse(raw)

    // Guard against a half-written or hand-edited value. Anything without a
    // token is useless, so it is treated as no session at all.
    if (!parsed || typeof parsed.token !== 'string') return null

    return parsed
  } catch {
    return null
  }
}

/* Convenience read for the one thing most callers want. Returning null rather
   than an empty string matters: api.js tests it to decide whether to send an
   Authorization header at all, and an empty Bearer token is worse than none. */
export function readToken() {
  return readSession()?.token ?? null
}

/* WHY THIS EXISTS: called at exactly two moments, after signup and after login,
   with the response the server just sent. Storing the user alongside the token
   lets the UI show a name immediately on the next page load instead of waiting
   for a round trip.

   That cached copy is CONVENIENCE ONLY and is never trusted for anything that
   matters. The server re-reads the real record on every authenticated request —
   editing this value in devtools changes what a label says and nothing else. */
export function saveSession({ token, user }) {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ token, user }))
  } catch {
    /* Storage unavailable. The session then lasts until the tab is closed, which
       is a degraded experience rather than a broken one — the token is still in
       memory for the current page. Nothing to tell the user about. */
  }
}

/* WHY THIS EXISTS: the local half of signing out. The server half is a request
   that deletes the session row — see logout() in api.js. Both halves are needed:
   this one alone leaves a working credential on the server, and that one alone
   leaves a dead token in the browser that makes every request 401. */
export function clearSession() {
  try {
    window.localStorage.removeItem(STORAGE_KEY)
  } catch {
    // Nothing to clear if storage was never available.
  }

  /* Announced AFTER the removal, never before. A listener that re-reads storage
     must not be able to run while the old token is still sitting in it — that is
     the kind of ordering bug that works every time locally and fails once under
     a slow render. [General] */
  window.dispatchEvent(new CustomEvent(SESSION_ENDED_EVENT))
}
