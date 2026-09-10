/* ============================================================================
   USEAUTHCONFIG.JS — what the server is configured to offer, read once per page.

   WHY THIS EXISTS: three separate components need the same three answers before
   they can decide what to render — is there a Google button, does this server
   force 2FA, can it send email at all. Those answers live in the server's
   environment, so they cannot be constants in the bundle: a build that guessed
   "Google is on" would render a button whose endpoint returns 503.

   WHY A HOOK RATHER THAN CONTEXT, when AuthContext exists and is right next
   door: the config is not shared STATE. Nothing mutates it, nothing has to agree
   about it, and two components holding their own copy cannot disagree because
   both copies came from the same immutable answer. A hook is the lighter tool and
   this is the case it fits. Contrast `user`, which changes while the app is
   running and therefore has to be one value.

   [React] What each caller gets is its own useState, so two components using
   this hook do run two requests. That is a real cost and it is small: the
   response is a handful of booleans, the browser caches nothing but it is one
   round trip on a page that is already waiting for /auth/me, and the alternative
   — a fourth provider in main.jsx — is more moving parts than two GETs are worth.

   THE READY FLAG IS THE INTERESTING PART. See below.
   ========================================================================== */

import { useEffect, useState } from 'react'

import { AUTH_CONFIG_FALLBACK, fetchAuthConfig } from '../lib/api'

export function useAuthConfig() {
  /* Starts at the fallback rather than at null, so every consumer can read
     `config.googleEnabled` on the very first render without a `?.` or a guard.
     The fallback says "nothing optional is available", which is the correct thing
     to render while the answer is still in flight — a button that appears and
     then vanishes is worse than one that appears a moment late. */
  const [config, setConfig] = useState(AUTH_CONFIG_FALLBACK)

  /* WHY THIS EXISTS SEPARATELY FROM THE CONFIG ITSELF: "no Google button because
     the server says so" and "no Google button YET" are the same object, and a
     component that cannot tell them apart has to pick one wrong behaviour. The
     signup page uses it to hold back the "or continue with" divider — rendering
     the divider first and the button after it lands is a visible jump on every
     page load, on a page whose whole job is to look composed. */
  const [ready, setReady] = useState(false)

  useEffect(() => {
    /* The same cancellation flag as every other fetching effect in this app: a
       response that arrives after the component has gone would call setState on
       nothing. See useScans.js for the long version. */
    let cancelled = false

    /* NO .catch() HERE, AND IT IS NOT AN OVERSIGHT. fetchAuthConfig never
       rejects — it returns AUTH_CONFIG_FALLBACK on any failure, which is the
       contract written at its definition in api.js. Adding a catch would be
       unreachable code implying the opposite. */
    fetchAuthConfig().then((result) => {
      if (cancelled) return

      setConfig(result)
      setReady(true)
    })

    return () => {
      cancelled = true
    }
  }, [])

  return { config, ready }
}
