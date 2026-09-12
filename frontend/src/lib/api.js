/* ============================================================================
   API.JS — the single place the frontend talks to the backend.

   WHY THIS EXISTS: every component that needs server data goes through this
   file, and nothing else in the app mentions fetch, a URL, or a status code.
   That matters for two reasons:

     1. This file IS the data source. It replaced a hand-written fixture module
        that exported getScanById(); this one exports fetchScan(). Same seam, real
        data — which is exactly why the fixture was written to that shape, and why
        swapping it out touched no component. The fixtures themselves are gone;
        their two surviving pure helpers live in lib/findings.js.
     2. When the API moves off localhost, or gains an auth token on every
        request, or needs a retry — this is the only file that changes.

   These are plain async functions, not React code. Deliberately: they know
   nothing about components, so they can be called from anywhere and tested
   without rendering anything.
   ========================================================================== */

import { readToken, clearSession } from './session'

/* [General] Vite exposes env vars starting with VITE_ on import.meta.env, and
   inlines them at build time. The fallback keeps local development working with
   no .env file at all; deployment sets VITE_API_URL to the real host.

   Note 127.0.0.1 rather than localhost. They are usually the same, but on some
   Windows setups localhost resolves to IPv6 ::1 first while uvicorn is listening
   on IPv4 only — which produces a connection refused that looks inexplicable. */
const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'

/* [General] FastAPI reports errors in two different shapes, and hitting the
   second one unprepared puts the literal text "[object Object]" in front of a
   user, which is why this helper exists rather than reading .detail directly.

     - HTTPException (our 404s):  { detail: "No scan found with id abc" }
     - Pydantic validation (422): { detail: [ { loc, msg, type }, ... ] }

   The 422 case is the one that matters most here: it is what the server returns
   when it rejects a URL or refuses a scan for missing consent, so its message is
   genuinely worth showing. */
function readErrorMessage(body, fallback) {
  const detail = body?.detail

  // [General] A plain string means HTTPException — already human-readable.
  if (typeof detail === 'string') return detail

  /* [General] An array means validation errors. Each entry has a `msg` that is
     the text from the Python validator, e.g. the consent or SSRF messages in
     main.py. Joining rather than taking the first means a request that is wrong
     in two ways explains both. */
  if (Array.isArray(detail)) {
    const messages = detail.map((item) => item?.msg).filter(Boolean)
    if (messages.length > 0) return messages.join('. ')
  }

  return fallback
}

/* [General] Reading the body can itself fail — a 502 from a proxy returns HTML,
   and response.json() throws on it. Returning null instead lets the caller fall
   back to a generic message rather than replacing a real HTTP error with a
   confusing JSON parse error. */
async function readBodySafely(response) {
  try {
    return await response.json()
  } catch {
    return null
  }
}

/* [General] Every request goes through here for one reason: fetch REJECTS on a
   network failure, and the error it throws is the browser's own
   "TypeError: Failed to fetch" — three words that say nothing about what to do.
   By far the most likely cause in development is that the backend is not
   running, so that is what the message says.

   Note the distinction this preserves. A rejected fetch means the server was
   never reached; a resolved fetch with ok === false means the server answered
   and said no. Only the first is handled here, so the server's own error
   messages further down are never overwritten by this generic one. */
async function request(path, options) {
  try {
    return await fetch(`${API_BASE}${path}`, options)
  } catch {
    throw new Error(
      `Could not reach the SecuScan API at ${API_BASE}. Check the backend is running.`,
    )
  }
}

/* WHY THIS EXISTS: every scan endpoint on the server now requires a session, so
   every scan request from here has to carry one. Building the header in one
   function rather than at four call sites means there is no version of this file
   where three requests are authenticated and the fourth quietly is not.

   [General] The header is OMITTED entirely when there is no token, rather than
   sent as "Bearer null". The server treats a missing header and a malformed one
   identically, so this changes nothing it does — but it makes the request in
   devtools honest about what the browser actually knows. */
function withAuth(headers = {}) {
  const token = readToken()

  // [General] Object spread with a conditional. `...(cond && obj)` spreads the
  // object when the condition holds and spreads `false` — which contributes
  // nothing — when it does not. A compact idiom worth recognising.
  return { ...headers, ...(token && { Authorization: `Bearer ${token}` }) }
}

/* WHY THIS EXISTS: the authenticated counterpart to request(). It does two jobs
   that every signed-in call needs and no caller should have to remember.

   1. Attaches the token.
   2. HANDLES 401 IN ONE PLACE. A 401 means the server rejected the token — it
      expired, or sign-out revoked it, or it was never valid. Whatever the cause,
      the copy in localStorage is now useless, and leaving it there produces the
      worst possible state: an app that looks signed in, shows a name in the
      corner, and fails every request. Clearing it here means a dead token is
      cleaned up by the first request that discovers it.

   clearSession() also announces itself (see session.js), which is what lets the
   auth context notice and re-render the app into its signed-out state without
   this file knowing React exists. */
async function authedRequest(path, options = {}) {
  const response = await request(path, {
    ...options,
    headers: withAuth(options.headers),
  })

  if (response.status === 401) {
    clearSession()

    const body = await readBodySafely(response)
    throw new Error(
      readErrorMessage(body, 'Your session has expired. Sign in again.'),
    )
  }

  return response
}

/* WHY THIS EXISTS: this is the function that actually runs a scan. It is the
   moment the product does its job — everything before it is a form, everything
   after it is a report.

   Both arguments are required by the server. `consent` is not a formality: the
   backend has its own validator that refuses the request unless it is true, so
   passing false here produces a 422, not a scan. The checkbox in the UI and that
   validator are two halves of one requirement.

   `options` optionally carries:
     - loginUrl: optional explicit login page URL
     - tier: 1 (default) or 2 (deep authenticated audit)
     - credentials: { stagingUrl, username, password, retain } for Tier 2 access */
export async function createScan(url, consent, options = {}) {
  const { loginUrl, tier = 1, credentials = null } = options
  const payload = { url, consent, tier }

  if (loginUrl && loginUrl.trim()) {
    payload.loginUrl = loginUrl.trim()
  }

  if (tier === 2 && credentials) {
    payload.credentials = {
      stagingUrl: credentials.stagingUrl ? credentials.stagingUrl.trim() : undefined,
      username: credentials.username ? credentials.username.trim() : '',
      password: credentials.password || '',
      /* Coerced rather than passed through. The backend defaults this to false
         when it is absent, so an undefined here would already do the safe
         thing - but sending the boolean the user actually chose means the
         request body says what was agreed to rather than relying on both ends
         agreeing about a missing field. */
      retain: Boolean(credentials.retain),
    }
  }

  const response = await authedRequest('/scan', {
    method: 'POST',
    /* [General] Without this header FastAPI will not parse the body as JSON and
       answers 422 complaining the fields are missing — a genuinely misleading
       error, since the fields are right there. */
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })

  if (!response.ok) {
    const body = await readBodySafely(response)
    /* [General] Throwing rather than returning an error value. fetch only
       rejects on network failure — a 404 or 422 is a RESOLVED promise with ok
       set to false, which is the single most common fetch mistake. Converting
       both failure kinds into a thrown Error means the caller needs one
       try/catch instead of two separate checks. */
    throw new Error(
      readErrorMessage(body, `The scan could not be started (${response.status}).`),
    )
  }

  // The scan object: id, targetUrl, scannedAt, tier, paymentStatus, score,
  // findings — plus `stored`, which says whether it was saved and can therefore
  // be reopened later.
  return response.json()
}

/* WHY THESE EXIST: Tier 2 credentials management on stored scans.
   Allows the user to check whether credentials are still held at rest,
   or explicitly purge credentials immediately after scan review. */
export async function getScanCredentials(id) {
  const response = await authedRequest(`/scan/${encodeURIComponent(id)}/credentials`)
  if (!response.ok) return { hasCredentials: false }
  return response.json()
}

export async function deleteScanCredentials(id) {
  const response = await authedRequest(`/scan/${encodeURIComponent(id)}/credentials`, {
    method: 'DELETE',
  })
  if (!response.ok) return false
  const body = await response.json()
  return Boolean(body.deleted)
}

/* WHY THIS EXISTS: the read side. The report page is reached by URL, so on load
   it has an id and nothing else, and this is how it turns that id into findings.
   It is what makes a report refreshable and shareable rather than a view that
   only exists immediately after a scan.

   Returns null for a scan that does not exist, and throws for everything else.
   That split is intentional and mirrors find_scan() in the backend: a wrong id
   is an ordinary outcome the page should render an empty state for, while a
   dead server is a genuine error worth surfacing differently. */
export async function fetchScan(id) {
  const response = await authedRequest(`/scan/${encodeURIComponent(id)}`)

  // [General] encodeURIComponent above stops a strange id from altering the
  // path. Ids are hex today, but the guard costs nothing and outlives them.

  if (response.status === 404) return null

  if (!response.ok) {
    const body = await readBodySafely(response)
    throw new Error(
      readErrorMessage(body, `The report could not be loaded (${response.status}).`),
    )
  }

  return response.json()
}

/* WHY THIS EXISTS: the dashboard and the history page both need "every scan on
   this account, newest first" — a question about the collection, not about one
   scan, so neither fetchScan nor createScan can answer it.

   Returns an array, empty when nothing has been scanned yet. Empty is a normal
   state, not an error: a new account genuinely has no scans, and the pages
   render an empty state for it rather than treating it as a failure. */
export async function fetchScans() {
  const response = await authedRequest('/scans')

  if (!response.ok) {
    const body = await readBodySafely(response)
    throw new Error(
      readErrorMessage(body, `Your scans could not be loaded (${response.status}).`),
    )
  }

  return response.json()
}

/* WHY THIS EXISTS: the forwarded report. fetchScan() above asks /scan/:id, which
   is owner-only — the right endpoint for the signed-in user reading their own
   result, and a guaranteed 404 for the developer they sent the link to.

   This asks /report/:id instead, which the server serves to anybody. Two
   functions rather than a flag on one, mirroring the two endpoints exactly: the
   call site then says which kind of access it is relying on, and "fetch this
   scan without checking who is asking" is never something that happens by
   leaving an argument off.

   Same null-for-404 contract as fetchScan, so useScan can treat them alike. */
export async function fetchSharedReport(id) {
  const response = await request(`/report/${encodeURIComponent(id)}`)

  if (response.status === 404) return null

  if (!response.ok) {
    const body = await readBodySafely(response)
    throw new Error(
      readErrorMessage(body, `The report could not be loaded (${response.status}).`),
    )
  }

  return response.json()
}

/* ============================================================================
   ACCOUNTS

   The four calls the auth context is built on. None of them touch storage —
   they return what the server said and let the caller decide what to keep. That
   separation is why session.js can be the only file that writes a token.
   ========================================================================== */

/* [General] Signup and login both answer with { token, user } and both report
   failure the same way, so the request/parse/throw sequence is written once
   here. The only thing that differs is the path and the body.

   RENAMED FROM postCredentials when two-factor arrived. The 2FA endpoints are
   unauthenticated POSTs with exactly this shape — /2fa/verify sends a challenge
   and a code, not credentials — and they need the same parse-and-throw. A helper
   whose name describes the SHAPE of the call rather than one use of it is a helper
   the next endpoint can reuse, which is the whole reason this file stays flat. */
async function postPublic(path, body, fallbackMessage) {
  const response = await request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    const parsed = await readBodySafely(response)

    /* The server's own message is what gets shown, and it is worth knowing what
       those messages are, because they are deliberate:

         409 — "That email is already registered." Specific, on signup only.
         401 — "Email or password is incorrect." Identical for a wrong password
               and an unknown address, so the response cannot be used to find out
               which addresses have accounts.
         422 — the password policy message from auth.py, naming the failed rule.
         429 — rate limited.

       Passing them through unedited keeps that thinking intact. Replacing them
       with one generic "sign-in failed" would throw away the only part of the
       response the user can act on. */
    throw new Error(readErrorMessage(parsed, fallbackMessage))
  }

  return response.json()
}

export async function signup({ name, email, password }) {
  return postPublic(
    '/auth/signup',
    { name, email, password },
    'The account could not be created.',
  )
}

/* WHY THE RETURN TYPE IS NOW A UNION, and why that is the caller's problem: the
   server answers a correct password in one of THREE ways, and the difference is
   not an error condition — all three are successes with `ok: true`.

     { token, user }                — signed in. No second factor on this account.
     { challenge, method: 'totp' }  — password accepted, a code is still required.
     { challenge, method: 'enrol' } — password accepted, but this server requires
                                      2FA and the account has none yet.

   This function deliberately does NOT branch on that. Flattening the three into
   one shape here would mean inventing a convention the server does not have, and
   the caller has to know which happened regardless — it decides which page to go
   to. See handleSubmit in pages/Login.jsx, and the state machine comment above
   CHALLENGE_TTL_MINUTES in main.py. */
export async function login({ email, password }) {
  return postPublic('/auth/login', { email, password }, 'Could not sign in.')
}

/* WHY THIS EXISTS: answers "is the token in storage still good, and who does it
   belong to" on every page load. Without it the app would trust whatever the
   browser remembered — and a token revoked on another device, or expired last
   week, looks exactly like a valid one from in here.

   Returns null rather than throwing when the session is dead, because "not
   signed in" is the ordinary state of a first visit, not a failure. A genuine
   error — a server that is down — still throws, so the context can tell the
   difference between "you are signed out" and "we could not find out". */
export async function fetchMe() {
  try {
    const response = await authedRequest('/auth/me')

    if (!response.ok) return null

    return await response.json()
  } catch (caught) {
    /* [General] authedRequest throws on a 401 after clearing the stored token,
       which is exactly the behaviour wanted everywhere else and is noise here.
       The token has already been cleaned up by the time this runs; all that is
       left to do is report "nobody is signed in".

       The message is matched rather than the status because the status is no
       longer available this far up. Fragile if the wording changes — which is
       why the check is for the marker word rather than the whole sentence. */
    if (/session/i.test(caught.message)) return null

    throw caught
  }
}

/* WHY THIS EXISTS: the server half of signing out — it deletes the session row,
   after which the token is inert no matter who holds it. clearSession() in
   session.js is the browser half, and both are needed.

   It never throws. Sign-out has to succeed from the user's point of view even
   when the network does not: the local half always runs, and a request that
   failed leaves at worst a session row that expires on its own in 30 days. A
   sign-out button that can error is a sign-out button that traps someone. */
export async function logout() {
  try {
    await request('/auth/logout', { method: 'POST', headers: withAuth() })
  } catch {
    // Deliberately swallowed. See above.
  }
}

/* WHY THIS EXISTS: the authenticated sibling of postPublic. Same parse-and-throw,
   through authedRequest instead of request — so it carries the token and inherits
   the 401 handling.

   The 2FA and billing sections below are almost entirely POSTs, split evenly
   between "nobody is signed in yet" (verify a login code) and "this is my own
   account" (turn 2FA on, buy a plan). Two helpers, one per side of that line,
   means a call site cannot accidentally send an authenticated action without a
   token — the function it reaches for either has one or does not exist. */
async function postAuthed(path, body, fallbackMessage) {
  const response = await authedRequest(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    /* [General] `body` is optional. JSON.stringify(undefined) returns undefined,
       not a string, and fetch treats an undefined body as no body at all — which
       is what endpoints like /billing/cancel want, since they take nothing. */
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  if (!response.ok) {
    const parsed = await readBodySafely(response)
    throw new Error(readErrorMessage(parsed, fallbackMessage))
  }

  return response.json()
}

/* WHY THIS EXISTS: the authenticated GET, which had no helper because the two that
   existed — fetchScan and fetchScans — each need their own 404 handling. The 2FA
   and billing reads do not: there is exactly one 2FA status and one subscription
   per account, so a 404 from either is a broken server rather than a missing thing. */
async function getAuthed(path, fallbackMessage) {
  const response = await authedRequest(path)

  if (!response.ok) {
    const parsed = await readBodySafely(response)
    throw new Error(readErrorMessage(parsed, fallbackMessage))
  }

  return response.json()
}

/* ============================================================================
   WHAT THE SERVER IS CONFIGURED TO DO

   Read before the auth pages render. See GET /auth/config in main.py for why this
   is a request rather than a build-time constant: the answers live in the server's
   environment, and a bundle that guessed them would show a Google button whose
   endpoint returns 503.
   ========================================================================== */

/* The shape of the answer when there is no answer. Exported so a component can use
   it as its initial state while the real request is still in flight, rather than
   writing its own `?? false` at every reference.

   Every value is the most CONSERVATIVE reading — nothing extra is available — so a
   partial outage hides optional features rather than offering ones that cannot work. */
export const AUTH_CONFIG_FALLBACK = {
  googleEnabled: false,
  googleClientId: '',
  require2fa: false,
  emailAvailable: false,
  // Matches auth.PASSWORD_MIN_LENGTH. The strength meter needs a number to render
  // at all, and this is the value the server has enforced since before the config
  // endpoint existed — so it is the right guess when the request fails.
  passwordMinLength: 12,
}

/* Returns { googleEnabled, googleClientId, require2fa, emailAvailable,
   passwordMinLength }.

   IT NEVER THROWS, and that is the whole design of this one. Every caller uses it
   to decide whether to render an OPTIONAL thing, so a failure has an obvious right
   answer: render the page without the optional thing. Throwing would mean a blank
   login form because a secondary request failed, which is a worse outcome than a
   missing Google button. */
export async function fetchAuthConfig() {
  try {
    const response = await request('/auth/config')

    if (!response.ok) return AUTH_CONFIG_FALLBACK

    return await response.json()
  } catch {
    return AUTH_CONFIG_FALLBACK
  }
}

/* ============================================================================
   GOOGLE SIGN-IN

   One call. Google Identity Services runs entirely in the browser and hands back a
   signed credential; this posts it to the server, which verifies the signature
   against Google's public keys before believing a word of it.
   ========================================================================== */

/* WHY THE ARGUMENT IS CALLED `credential` AND NOT `token`: it is Google's ID token
   — a JWT signed by Google, valid for about an hour, and NOT a SecuScan session.
   The response is what carries the session. Naming them differently is what stops
   somebody storing the wrong one.

   Returns { token, user }, the same shape as a password login with no second
   factor. Google has already done the second factor if the account has one, which
   is why there is no challenge branch here. */
export async function signInWithGoogle(credential) {
  return postPublic(
    '/auth/google',
    { credential },
    'Could not sign in with Google.',
  )
}

/* ============================================================================
   TWO-FACTOR AUTHENTICATION

   Two groups, and the split matters more than it looks:

     - CHALLENGE calls are unauthenticated. They happen between a correct password
       and a session, so there is no token to send — the challenge token IS the
       credential, and it authorises exactly one narrow action.
     - ACCOUNT calls are authenticated. Turning 2FA on, off, or regenerating codes
       is something a signed-in person does to their own account.

   Sending a challenge call through postAuthed would attach a token that does not
   exist yet; sending an account call through postPublic would drop the one that
   does. Hence two helpers and this comment.
   ========================================================================== */

/* THE CHALLENGE CALLS — no session yet. */

/* The ordinary case: an authenticator app code at login. Returns { token, user }. */
export async function verifyTwoFactor({ challenge, code }) {
  return postPublic('/2fa/verify', { challenge, code }, 'Could not verify that code.')
}

/* The lost-phone case: one of the printed recovery codes. Returns
   { token, user, recoveryCodesLeft } — the count is there so the page can say how
   many are left, since each one works exactly once. */
export async function recoverTwoFactor({ challenge, code }) {
  return postPublic('/2fa/recover', { challenge, code }, 'Could not use that recovery code.')
}

/* The other lost-phone case: mail a code to the account's address. Returns
   { sent, expiresInMinutes, sentTo } where sentTo is MASKED — the server never
   sends the full address back to an unauthenticated caller, since anyone holding a
   challenge has only proved they know a password. */
export async function sendEmailCode(challenge) {
  return postPublic('/2fa/email-code', { challenge }, 'Could not send a code by email.')
}

export async function verifyEmailCode({ challenge, code }) {
  return postPublic('/2fa/verify-email', { challenge, code }, 'Could not verify that code.')
}

/* FORCED ENROLMENT, which only happens when the server has SECUSCAN_REQUIRE_2FA on
   and the account has no authenticator yet. start returns { secret, qr, uri, digits,
   period } for the QR code; finish returns { token, user, recoveryCodes }. */
export async function startEnrolment(challenge) {
  return postPublic('/2fa/enrol/start', { challenge }, 'Could not start setup.')
}

export async function finishEnrolment({ challenge, code }) {
  return postPublic('/2fa/enrol/finish', { challenge, code }, 'Could not complete setup.')
}

/* THE ACCOUNT CALLS — signed in, acting on your own account. */

/* Returns { enabled, required, hasPassword, isGoogleAccount, recoveryCodesLeft,
   emailAvailable }. Deliberately thin — no secret, no code hashes. */
export async function fetchTwoFactorStatus() {
  return getAuthed('/2fa/status', 'Could not read your security settings.')
}

/* Issues a secret and a QR code. The secret is PENDING until confirmTwoFactor
   succeeds — see the note on totpPendingSecret in database.py for why an
   unconfirmed secret must not switch 2FA on. */
export async function setupTwoFactor() {
  return postAuthed('/2fa/setup', undefined, 'Could not start two-factor setup.')
}

/* Proves a phone actually holds the secret. Returns { enabled, recoveryCodes } —
   and those codes are shown ONCE. The server stores only their hashes, so this
   response is the only time they exist in readable form. */
export async function confirmTwoFactor(code) {
  return postAuthed('/2fa/confirm', { code }, 'Could not confirm that code.')
}

/* Both of these are step-up actions: they require the password AND a current code,
   because "disable my second factor" is exactly what someone who has stolen a
   session would like to do. */
export async function disableTwoFactor({ password, code }) {
  return postAuthed('/2fa/disable', { password, code }, 'Could not turn off two-factor.')
}

export async function regenerateRecoveryCodes(code) {
  return postAuthed('/2fa/recovery-codes', { code }, 'Could not generate new codes.')
}

/* ============================================================================
   ACCOUNT SETTINGS

   Two calls the settings page needs. Both are STEP-UP AUTHENTICATED: they send the
   current password even though a session is already attached, because a session
   token is a bearer credential and both of these actions are exactly what somebody
   holding a stolen one would want to do. See the block above /auth/change-password
   in main.py.
   ========================================================================== */

/* Returns { changed, otherSessionsSignedOut }. The count is how many OTHER devices
   were signed out — this session deliberately survives, since the request already
   proved knowledge of the old password. A Google-only account gets a 400 with a
   sentence naming Google, not a 401.

   NOTE the field names match the server's model exactly (currentPassword /
   newPassword). A mismatch here is a 422 with a field path rather than a message,
   which is the one error shape the forms in this app cannot render usefully. */
export async function setPassword(password) {
  return postAuthed(
    '/auth/set-password',
    { password },
    'Could not set your password.',
  )
}

export async function changePassword({ currentPassword, newPassword }) {
  return postAuthed(
    '/auth/change-password',
    { currentPassword, newPassword },
    'Could not change your password.',
  )
}

/* Ends EVERY session on the account, this one included — see the endpoint's header
   for why the current browser is not treated as trustworthy here. Returns
   { signedOut, sessionsEnded }.

   THE CALLER MUST CLEAR LOCAL STATE AFTER THIS RESOLVES. The token in localStorage
   keeps existing and stops working, so anything that does not call clearSession()
   next will look signed in until its first 401. The settings page uses AuthContext's
   signOut for that, which also fires SESSION_ENDED_EVENT. */
export async function signOutEverywhere(password) {
  return postAuthed(
    '/auth/sessions/revoke-all',
    { password },
    'Could not sign out your other sessions.',
  )
}

/* WHY THIS EXISTS: starts a password reset. The server emails a six-digit code and
   hands back the challenge that code will be spent against, which goes straight to
   resetPassword below.

   IT ANSWERS THE SAME WAY FOR AN ADDRESS WITH NO ACCOUNT - same fields, same status,
   a challenge either way. That is deliberate on the server's side and worth knowing
   here, because it means THIS FUNCTION CANNOT TELL YOU WHETHER AN ACCOUNT EXISTS and
   neither can the page calling it. A reset form that says "no account with that
   email" is an account-enumeration tool wearing a helpful face.

   Returns { requested, challenge, sentTo, expiresInMinutes, message }. `sentTo` is
   masked by the server - see _mask_email in main.py - and `message` is the server's
   own sentence, which the page shows as written. */
export async function requestPasswordReset(email) {
  return postPublic('/auth/forgot-password', { email }, 'Could not process that request.')
}

/* WHY THIS EXISTS: finishes the reset. The emailed code and the new password, in one
   call.

   IT RETURNS NO SESSION, which is why there is no adoptSession anywhere near it -
   just { reset: true }. The caller sends the user to /login to sign in with the
   password they have just chosen. An emailed code proves access to an inbox and
   nothing more, so it is not allowed to mint a session on its own; the endpoint
   comment in main.py makes the argument in full. The practical consequence is a good
   one: an account with two-factor authentication still meets its authenticator at
   the next sign-in, exactly as it would on any other day. */
export async function resetPassword({ challenge, code, newPassword }) {
  return postPublic(
    '/auth/reset-password',
    { challenge, code, newPassword },
    'Could not reset your password.',
  )
}

/* ============================================================================
   BILLING

   Read the plans, buy one, read what you bought, cancel it, change your mind.
   Five calls, matching the five endpoints one-to-one.

   ONE THING THIS FILE DELIBERATELY DOES NOT DO: send an amount. checkout() below
   takes a plan id and card details and nothing else, because the price is the
   server's to decide — see the note above CheckoutRequest in main.py. If a future
   edit adds an `amountCents` argument here, that is the bug.
   ========================================================================== */

/* WHY THE FRONTEND FETCHES PRICES IT ALREADY HAS IN lib/pricing.js: that file is
   marketing copy — taglines, feature bullets, which card gets the ribbon. This is
   the PRICE, and it comes from the same table the checkout charges from. Two
   constants that agree today are two constants that disagree after one edit, and
   the failure mode is a customer shown $49 and billed $149.

/* The shape of billing configuration when the request fails.

   THIS USED TO SAY provider: 'mock', AND THAT WAS A REAL HOLE. Checkout.jsx renders
   the mock card form for any provider that is not 'paddle', so one failed
   /billing/config — a cold start, a dropped connection, a 502 from the proxy —
   rendered a card form on the live site and put a real card number and CVC through
   our own backend. A transient network error is the last thing that should widen
   PCI scope.

   'unavailable' is a provider name no backend ever returns, which is the point: it
   cannot be mistaken for a working one, and Checkout branches on it explicitly. A
   failed config read means "we cannot take payment right now", never "use the fake
   processor". */
export const BILLING_CONFIG_FALLBACK = {
  provider: 'unavailable',
  clientToken: '',
  environment: '',
}

/* The providers this frontend knows how to render a payment form for. Anything
   else — 'unavailable' above, 'none' from a backend whose provider failed to
   configure, or a provider added to the server before the UI catches up — gets the
   "cannot take payment" screen rather than the wrong form. */
export const PAYABLE_PROVIDERS = ['paddle', 'mock']

/* Returns { provider, clientToken, environment }. Unauthenticated, read before
   rendering checkout so the UI can branch on whether to render mock or Paddle. */
export async function fetchBillingConfig() {
  try {
    const response = await request('/billing/config')

    if (!response.ok) return BILLING_CONFIG_FALLBACK

    return await response.json()
  } catch {
    return BILLING_CONFIG_FALLBACK
  }
}

/* WHY THE FRONTEND FETCHES PRICES IT ALREADY HAS IN lib/pricing.js: that file is
   marketing copy — taglines, feature bullets, which card gets the ribbon. This is
   the PRICE, and it comes from the same table the checkout charges from. Two
   constants that agree today are two constants that disagree after one edit, and
   the failure mode is a customer shown $49 and billed $149.

   Unauthenticated: the pricing table is the first thing a visitor reads. */
export async function fetchPlans() {
  const response = await request('/billing/plans')

  if (!response.ok) {
    const body = await readBodySafely(response)
    throw new Error(
      readErrorMessage(body, `Plans could not be loaded (${response.status}).`),
    )
  }

  return response.json()
}

/* Returns { plan, subscription, orders } for the signed-in account. `subscription`
   is null on a Free account — a state, not a missing value — and `orders` is the
   receipt history, which survives a cancellation. */
export async function fetchSubscription() {
  return getAuthed('/billing/subscription', 'Your billing details could not be loaded.')
}

/* THE PURCHASE. Returns { status, order, plan, subscription, user } or
   { status: "pending", plan, clientAction, providerRef }. */
export async function checkout({ planId, cardName, cardNumber, cardExpiry, cardCvc } = {}) {
  const payload = { planId }
  if (cardName !== undefined) payload.cardName = cardName
  if (cardNumber !== undefined) payload.cardNumber = cardNumber
  if (cardExpiry !== undefined) payload.cardExpiry = cardExpiry
  if (cardCvc !== undefined) payload.cardCvc = cardCvc

  return postAuthed(
    '/billing/checkout',
    payload,
    'The payment could not be completed.',
  )
}

/* Returns { cancelled, plan, subscription, user }.

   NOT IMMEDIATE, and the comment that used to be here said the opposite. It argued
   that the downgrade had to happen at once because nothing ran on a schedule to do
   it later — which was true about the scheduler and wrong about the conclusion. The
   server now sets `cancelAtPeriodEnd` and every READ resolves whether the period has
   run out, so the plan keeps working until the day it was paid up to with nothing
   running in the background. See POST /billing/cancel.

   So `subscription` in the response is usually still there, with `status: 'cancelling'`
   and `cancelAtPeriodEnd: true` — an account mid-notice, not an account downgraded.
   It comes back null only when there was no period to run out. A caller that treats
   any successful cancel as "now on Free" will show the wrong plan for a month. */
export async function cancelSubscription() {
  return postAuthed('/billing/cancel', undefined, 'Could not cancel your plan.')
}

/* Returns { resumed, plan, subscription, user }. Clears a scheduled cancellation.

   WHY THIS CALL HAS TO EXIST: end-of-period cancellation opens a window, days or
   weeks wide, where the plan is live and set to stop. Without this the only way back
   is to buy again — paying twice for one month. A flag a user can set and cannot
   unset is a trap.

   400 when there is nothing scheduled, and 400 with a different sentence when the
   period has ALREADY ended: that is not a cancellation to undo any more, it is a new
   purchase, and the server says so rather than granting a free month. Both arrive
   here as the server's own message, so the page can print it unchanged. */
export async function resumeSubscription() {
  return postAuthed('/billing/resume', undefined, 'Could not resume your plan.')
}
