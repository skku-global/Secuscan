/* ============================================================================
   CREDENTIALRETENTION.JSX — what happened to the test-account credentials a
   client handed over for a Tier 2 scan, and a button to destroy them now.

   WHY THIS EXISTS
   The Tier 2 form asks a client to type a password into someone else's website.
   The only thing that makes that a reasonable request is a retention promise the
   client can check, and a promise nobody can verify is marketing. The backend
   has had GET and DELETE /scan/:id/credentials since Tier 2 was first wired up,
   and lib/api.js has had getScanCredentials and deleteScanCredentials since the
   same day — but nothing in the UI called either of them. The guarantee existed
   in three places and was reachable from none.

   The default answer this panel gives is "nothing was stored". Retention is
   opt-in on the scan form, so the common case is a scan that wrote nothing at
   all, and the panel says so rather than staying silent — "we did not keep it"
   is the reassuring half of the message and it is the half that goes unsaid if
   the component only renders when something is being held.
   ========================================================================== */

import { useEffect, useState } from 'react'
import { KeyRound, ShieldCheck, Trash2 } from 'lucide-react'

import { getScanCredentials, deleteScanCredentials } from '../lib/api'
import { formatDateTime } from '../lib/formatDate'

export default function CredentialRetention({ scanId }) {
  /* One state object rather than three booleans. The panel is only ever in one
     of these situations at a time, and separate isLoading/isEmpty/error flags
     are what make "loading and errored simultaneously" representable. */
  const [state, setState] = useState({ phase: 'loading' })
  const [purging, setPurging] = useState(false)

  useEffect(() => {
    /* [React] The cancelled flag is the standard guard against setting state on
       a component the user has already navigated away from. Without it, a slow
       response that lands after unmount warns in development and, in a page that
       remounts quickly, can apply a stale answer over a fresh one. */
    let cancelled = false

    getScanCredentials(scanId)
      .then((data) => {
        if (!cancelled) setState({ phase: 'ready', data })
      })
      .catch(() => {
        /* A failed status check is reported as unknown, NOT as "nothing stored".
           Those are different statements and only one of them is safe to make on
           no evidence: telling a client their password was discarded when the
           request to find out never completed is the exact kind of unearned
           reassurance this whole panel exists to avoid. */
        if (!cancelled) setState({ phase: 'error' })
      })

    return () => {
      cancelled = true
    }
  }, [scanId])

  async function handlePurge() {
    setPurging(true)
    const deleted = await deleteScanCredentials(scanId)
    setPurging(false)

    /* A DELETE that reports nothing deleted still ends with nothing stored, so
       both outcomes land in the same place. The only case worth distinguishing
       would be a network failure, and deleteScanCredentials already resolves
       false rather than throwing on one - so the status is re-read from the
       server instead of being assumed from the button press. */
    if (deleted) {
      setState({ phase: 'ready', data: { hasCredentials: false }, justPurged: true })
    } else {
      getScanCredentials(scanId)
        .then((data) => setState({ phase: 'ready', data }))
        .catch(() => setState({ phase: 'error' }))
    }
  }

  if (state.phase === 'loading') return null

  if (state.phase === 'error') {
    return (
      <div className="cred-retention is-unknown">
        <KeyRound size={15} strokeWidth={2} aria-hidden="true" />
        <span>
          Could not check whether test credentials are still stored for this scan.
        </span>
      </div>
    )
  }

  if (!state.data?.hasCredentials) {
    return (
      <div className="cred-retention is-clear">
        <ShieldCheck size={15} strokeWidth={2} aria-hidden="true" />
        <span>
          {state.justPurged
            ? 'Test account credentials deleted. Nothing is stored for this scan.'
            : 'No test account credentials are stored for this scan. They were used for the scan only and never written to storage.'}
        </span>
      </div>
    )
  }

  return (
    <div className="cred-retention is-held">
      <KeyRound size={15} strokeWidth={2} aria-hidden="true" />
      <div className="cred-retention-body">
        <span>
          Test account credentials are stored, encrypted, at your request.
          {state.data.expiresAt && (
            <> They are deleted automatically on {formatDateTime(state.data.expiresAt)}.</>
          )}
        </span>
        <span className="cred-retention-hint">
          Rotating or deleting the test account on your side is worth doing once the
          audit is reviewed, whichever way this goes.
        </span>
      </div>
      <button
        type="button"
        className="btn-secondary btn-sm"
        onClick={handlePurge}
        disabled={purging}
      >
        <Trash2 size={14} strokeWidth={2} />
        {purging ? 'Deleting…' : 'Delete now'}
      </button>
    </div>
  )
}
