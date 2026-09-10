/* ============================================================================
   GOOGLESIGNIN.JSX — the "Continue with Google" button, on both auth pages.

   WHY THIS EXISTS AS A COMPONENT: the login page and the signup page need the
   identical thing. There is no separate "sign up with Google" — the server's
   /auth/google endpoint creates an account if the verified email is new and signs
   in if it is not, because Google has already told us the address is real and
   there is nothing left for a signup form to ask. One component, one endpoint,
   two placements.

   HOW THIS FLOW ACTUALLY WORKS, because it is not the OAuth redirect dance most
   people picture:

     1. Google's script renders a button INSIDE a div we hand it.
     2. The user clicks it and completes whatever Google requires — a password, a
        passkey, their own 2FA. None of that touches this app.
     3. Google calls our callback with a `credential`: a JWT that Google has
        SIGNED, containing the email, name and subject id.
     4. We POST that credential to /auth/google. The server verifies the signature
        against Google's published keys before believing one field of it, and
        answers with a SecuScan session.

   WHAT IS TRUSTED, AND WHERE. Nothing in this file is a security boundary. The
   credential is not a session and this component never inspects it — it does not
   decode the JWT to show a name, because a JWT read in the browser is just
   base64 anyone can forge. Everything that matters happens in google_auth.py.

   THE SCRIPT LOADS ONLY WHEN IT IS NEEDED. It is a third-party script from
   accounts.google.com, so it is not in index.html: a bundle that fetches it on
   every page load pays that request even when Google Sign-In is switched off, and
   ships a Google connection to visitors of a page that never offers Google. The
   loader below runs when a caller has already checked `googleEnabled`.
   ========================================================================== */

import { useCallback, useEffect, useRef, useState } from 'react'
import { AlertCircle } from 'lucide-react'

import { useAuth } from '../context/AuthContext'

/* Google's own URL. Not configurable, and deliberately a constant rather than an
   argument: a prop that decided which third-party script to inject would be an
   invitation to inject a different one. */
const GSI_SRC = 'https://accounts.google.com/gsi/client'

/* WHY THE LOADER IS A MODULE-LEVEL PROMISE RATHER THAN AN EFFECT THAT APPENDS A
   <script>: two mounted instances of this component — or one instance remounted
   by StrictMode's deliberate double-invoke in development — would each append
   their own tag, and the second load resets Google's internal state underneath
   the first button. Caching the promise means the script is fetched at most once
   per page load however many times this component mounts.

   [General] This is the memoised-singleton pattern for a side effect that must
   not happen twice. It is not React-specific and the same shape works anywhere.

   `null` means "not started yet"; anything else is the in-flight or settled
   promise, which awaiting again resolves immediately. */
let scriptPromise = null

function loadGoogleScript() {
  if (scriptPromise) return scriptPromise

  scriptPromise = new Promise((resolve, reject) => {
    /* Already there — most likely a hot reload in development, where the module
       state above was thrown away but the DOM was not. Without this check the
       page ends up with a second tag and the first button stops responding. */
    const existing = document.querySelector(`script[src="${GSI_SRC}"]`)

    if (existing && window.google?.accounts?.id) {
      resolve()
      return
    }

    const script = document.createElement('script')

    script.src = GSI_SRC
    script.async = true
    script.defer = true
    script.onload = () => resolve()

    /* WHY A REJECTION MATTERS HERE: this request fails routinely and not because
       anything is broken — a corporate proxy that blocks Google, an ad blocker, a
       plane. The caller turns this into a sentence rather than a dead button, and
       the password form on the same page still works. */
    script.onerror = () => {
      // Cleared so a later mount can try again. A cached REJECTED promise would
      // make one bad moment permanent for the rest of the page's life.
      scriptPromise = null
      reject(new Error('Google Sign-In could not be loaded.'))
    }

    document.head.appendChild(script)
  })

  return scriptPromise
}

/* WHY THE PROPS ARE SHAPED THIS WAY

   `clientId` and `enabled` come from the caller rather than from a fetch in here,
   because both pages already read /auth/config for other reasons (the 2FA notice,
   the password minimum) and a second request for the same three booleans would be
   waste. See hooks/useAuthConfig.js.

   `onSignedIn` is a callback rather than a `navigate()` call inside this file. The
   destination differs — the login page honours wherever RequireAuth bounced
   someone from, the signup page goes to the dashboard — and a component that
   navigates on its own cannot be reused by a caller that wants somewhere else.

   `text` selects Google's own button wording. Their widget renders it, so the
   value is theirs: 'signup_with' on the signup page, 'signin_with' on login.
   Writing our own label is not an option — the button's exact appearance is
   something Google's brand terms specify, which is also why this component styles
   a container and never the button itself. */
export default function GoogleSignIn({
  clientId,
  enabled,
  onSignedIn,
  text = 'continue_with',
  disabled = false,
}) {
  const { signInWithGoogle } = useAuth()

  /* [React] A REF to the div Google renders into. This is the case refs exist
     for: handing a real DOM node to a library that manipulates it directly.
     Everything React draws should stay declarative; a third-party widget cannot
     be, so it gets a node of its own and React is told nothing else about it. */
  const buttonRef = useRef(null)

  const [error, setError] = useState('')

  /* Set while the POST to /auth/google is in flight. Google's own button cannot
     show a pending state, so the message below stands in for one — without it,
     clicking the button appears to do nothing for as long as the round trip
     takes. */
  const [signingIn, setSigningIn] = useState(false)

  /* WHY THE CALLBACK IS A REF AND NOT JUST A CLOSURE: Google keeps the function
     we hand to initialize() for the lifetime of the page. A fresh closure on
     every render would leave Google holding the FIRST one forever, complete with
     the first render's stale `onSignedIn`. Storing the current function in a ref
     and having the stable callback read `.current` is the standard way out of
     that — the identity Google holds never changes, and what it calls is always
     current. [React] */
  const handlerRef = useRef(null)

  handlerRef.current = async function handleCredential(response) {
    setError('')
    setSigningIn(true)

    try {
      /* signInWithGoogle goes through AuthContext's adopt(), so the session is
         stored by the same code path as a password login. This component writes
         nothing to storage itself, which is what keeps "one place turns a token
         into a session" true. */
      const result = await signInWithGoogle(response.credential)

      onSignedIn?.(result)
    } catch (caught) {
      /* What arrives here, and why none of it is smoothed over:
           503 — the server has no client id configured. Should be impossible,
                 since `enabled` gated the render, but a server restarted with a
                 different .env between page load and click would do it.
           401 — Google's signature did not verify. Genuinely alarming.
           429 — rate limited.
         The server's sentence is shown as written. */
      setError(caught.message)
    } finally {
      setSigningIn(false)
    }
  }

  /* [React] useCallback with an empty dependency array gives an identity that
     never changes, which is exactly what a long-lived third-party subscription
     needs. The indirection through the ref above is what makes that safe. */
  const stableCallback = useCallback((response) => {
    handlerRef.current?.(response)
  }, [])

  useEffect(() => {
    /* Nothing to do — and note this returns BEFORE the script is requested, so a
       server with no client id causes no third-party network activity at all. */
    if (!enabled || !clientId) return

    let cancelled = false

    loadGoogleScript()
      .then(() => {
        if (cancelled) return

        const id = window.google?.accounts?.id

        if (!id) {
          // The script loaded but did not define what it should. Not a case worth
          // a special message; the fallback covers it.
          setError('Google Sign-In is unavailable right now.')
          return
        }

        id.initialize({
          client_id: clientId,
          callback: stableCallback,
          /* WHY THIS IS FALSE: with FedCM on, Chrome renders the account chooser
             in browser-controlled UI. That is where the platform is going and it
             is the better experience, but it also changes how errors surface and
             cannot be tested against a client id that does not exist yet. Left
             off deliberately, as a decision rather than a default — turn it on
             once there is a real client id to test with. */
          use_fedcm_for_prompt: false,
        })

        /* Google draws the button into our div. The options are theirs, not ours;
           the width is fixed rather than percentage-based because their widget
           takes a number, and 100% of an unknown container is not a number it
           accepts. The container is what makes it fill the form — see auth.css. */
        id.renderButton(buttonRef.current, {
          type: 'standard',
          theme: 'outline',
          size: 'large',
          text,
          shape: 'rectangular',
          logo_alignment: 'left',
          width: 340,
        })
      })
      .catch((caught) => {
        if (cancelled) return

        /* THE MESSAGE SAYS WHAT STILL WORKS. A blocked third-party script is not
           the user's problem to solve, and "use the form above" is the only
           useful thing to tell them. */
        setError(`${caught.message} You can still sign in with your email above.`)
      })

    return () => {
      cancelled = true
    }
    /* `text` is in here because changing it must re-render Google's button; in
       practice it is a constant per page, so this effect runs once. */
  }, [clientId, enabled, stableCallback, text])

  // The caller need not write this condition itself — a component that renders
  // nothing when it has nothing to render keeps both pages free of `&&` chains.
  if (!enabled || !clientId) return null

  return (
    <div className="google-signin">
      {/* THE DIV GOOGLE OWNS. React must not put anything inside it: the widget
          replaces its children, and React would then be tracking nodes that are
          no longer there. It stays empty in our markup for that reason.

          `aria-busy` is the one honest thing that can be said about it while the
          POST runs — the button's own label is Google's and cannot be changed to
          "Signing in…". */}
      <div ref={buttonRef} aria-busy={signingIn || undefined} />

      {/* WHY A COVER RATHER THAN A DISABLED ATTRIBUTE: the button is not ours, so
          there is no prop to disable. This is a transparent layer that swallows
          clicks while the form is already submitting, which stops a double
          sign-in without touching Google's markup. It is inert whenever nothing
          is in flight, so it never intercepts a real click. */}
      {(signingIn || disabled) && (
        <span className="google-signin-cover" aria-hidden="true" />
      )}

      {signingIn && (
        <p className="google-signin-status" role="status">
          Signing you in…
        </p>
      )}

      {error && (
        <p className="auth-error" role="alert">
          <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
          <span>{error}</span>
        </p>
      )}
    </div>
  )
}
