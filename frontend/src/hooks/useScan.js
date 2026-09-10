/* ============================================================================
   USESCAN.JS — loads ONE stored scan by id.

   WHY THIS EXISTS: two pages show a single scan — ScanResult (the in-app report)
   and Report (the standalone version that gets forwarded to someone else's
   developer). They look completely different and load their data identically, so
   the loading belongs here and the difference stays in the components.

   The companion hook useScans loads the whole list. Two hooks rather than one
   with a flag, because they answer different questions and return different
   shapes — a single hook doing both would need a branch in every caller.

   THE ONE ARGUMENT THAT IS NOT AN ID: `shared`. The two pages now read two
   different endpoints, because they serve two different readers.

     ScanResult — the owner, signed in, looking at their own scan. Reads
                  /scan/:id, which requires a session and returns 404 for a scan
                  belonging to somebody else.
     Report     — whoever was sent the link, with no account at all. Reads
                  /report/:id, which the server answers without a session.

   That is a difference in WHICH REQUEST TO SEND, not in what to do with the
   answer — identical states, identical shape, identical cancellation. So it is
   one flag here rather than a near-duplicate second hook. The flag defaults to
   false, so the authenticated path is what you get by forgetting it, and the
   public one has to be asked for by name.

   [React] Note the shape of what a hook shares: BEHAVIOUR, not state. Each
   component calling this gets its own independent fetch and its own useState
   values. Nothing is cached between them, which is worth knowing before you
   assume two pages showing the same scan only request it once. They do not.
   ========================================================================== */

import { useEffect, useState } from 'react'

import { fetchScan, fetchSharedReport } from '../lib/api'

export function useScan(id, { shared = false } = {}) {
  const [scan, setScan] = useState(null)

  /* [React] Four mutually exclusive states in one string. `missing` is separate
     from `error` on purpose: a wrong id is an ordinary thing a user can cause
     and deserves a calm empty state, while a dead backend is a genuine fault
     and should say so. Collapsing them would show one message for both. */
  const [status, setStatus] = useState('loading')   // loading | ready | missing | error
  const [error, setError] = useState('')

  useEffect(() => {
    /* [General] THE CANCELLATION FLAG. Two situations need it:

         - the user navigates to another id before this request finishes, and
         - React 19's StrictMode deliberately runs effects twice in development
           to surface exactly this class of bug.

       Either way an old response can arrive after a newer one. Without the flag
       it would overwrite the current report with the previous one — a bug that
       only appears under a slow network, which is the worst kind to debug. */
    let cancelled = false

    setStatus('loading')
    setError('')

    /* [General] Choosing the FUNCTION, then calling it — not calling one of two
       functions in a branch. Both have the same contract (a scan, or null for a
       404), so everything below this line is shared. */
    const load = shared ? fetchSharedReport : fetchScan

    /* [General] .then/.catch rather than await, because an effect callback
       cannot be async — React expects its return value to be a cleanup
       function, and an async function returns a promise instead. */
    load(id)
      .then((result) => {
        if (cancelled) return

        // fetchScan returns null for a 404 rather than throwing, which is what
        // lets "no such scan" be handled here as a state instead of an error.
        if (result === null) {
          setStatus('missing')
          return
        }

        setScan(result)
        setStatus('ready')
      })
      .catch((caught) => {
        if (cancelled) return
        setError(caught.message)
        setStatus('error')
      })

    /* [React] THE CLEANUP FUNCTION. Returning a function from an effect tells
       React to call it before the effect runs again and when the component
       unmounts. Here it just trips the flag above, so a late response finds
       cancelled === true and does nothing. */
    return () => {
      cancelled = true
    }

    /* [React] THE DEPENDENCY ARRAY. [id] means "re-run whenever the id changes",
       which is what makes navigating from one report to another actually load
       the new one. An empty [] here would be the classic bug: the first scan
       would load and every subsequent id would show stale data.

       `shared` is in the array too. It never actually changes — each page passes
       a literal — but the rule is that every value from outside the effect that
       the effect READS belongs in the dependencies. Omitting one because it
       "cannot change" is how a stale closure gets in later, when somebody makes
       it a prop. */
  }, [id, shared])

  return { scan, status, error }
}
