/* ============================================================================
   USESCANS.JS — loads every stored scan, newest first.

   WHY THIS EXISTS: Dashboard and History ask the server the same question and
   need the same four things back — the list, whether it is still loading,
   whether it failed, and why. Written inline it would be the same twenty lines
   of useState and useEffect copied into two files, and the second copy would
   drift from the first the moment either page changed.

   [React] THIS IS A CUSTOM HOOK, and it is worth understanding as a category.
   A custom hook is just a function that calls other hooks. There is no special
   syntax and nothing to register — the only hard rules are:

     1. the name MUST begin with "use", which is how React's linting knows to
        apply the rules of hooks to it, and
     2. it can only be called from a component or another hook, never from a
        condition, a loop, or an ordinary function.

   What it shares between the two pages is BEHAVIOUR, not state. Each component
   that calls it gets its own independent useState values — this is the part
   that surprises people coming from a store or a context. Two components using
   this hook do not share one list; they each run their own fetch.
   ========================================================================== */

import { useEffect, useState } from 'react'

import { fetchScans } from '../lib/api'

export function useScans() {
  const [scans, setScans] = useState([])

  /* One status string rather than separate booleans, for the same reason as the
     report page: loading, ready and failed are mutually exclusive, and a single
     value cannot contradict itself. [React] */
  const [status, setStatus] = useState('loading')   // loading | ready | error
  const [error, setError] = useState('')

  useEffect(() => {
    // The same cancellation flag as the report page — see ScanResult.jsx for
    // the full explanation of why a late response must not be allowed to land.
    let cancelled = false

    fetchScans()
      .then((result) => {
        if (cancelled) return
        setScans(result)
        setStatus('ready')
      })
      .catch((caught) => {
        if (cancelled) return
        setError(caught.message)
        setStatus('error')
      })

    return () => {
      cancelled = true
    }
    /* [React] An EMPTY dependency array means "run once, after the first
       render". Correct here because there is no id or filter to react to — the
       question this asks never changes. Contrast ScanResult, which passes [id]
       precisely because its question does. */
  }, [])

  /* [React] Returning an object rather than an array. Both are common — useState
     returns an array so you can name the pair whatever you like — but with three
     unrelated values, names at the call site are worth more than the freedom to
     rename. The caller writes `const { scans, status } = useScans()`. */
  return { scans, status, error }
}
