/* ============================================================================
   SCANFORM.JSX — the URL input plus the mandatory consent checkbox.

   WHY THIS EXISTS: this is the front door of the whole product. It also carries
   a legal requirement, not just a UI one — the spec demands a consent step
   confirming the user is authorised to scan the target. Scanning a site you do
   not own or have permission to test is not something to make easy by accident,
   so the submit button stays disabled until the box is ticked.

   This now runs a REAL scan: it POSTs to the backend, waits for the checks to
   actually run against the target site, and navigates to the id the server
   returns. Because a real scan makes real network requests to someone else's
   server, it takes seconds rather than milliseconds — which is why this file
   grew a submitting state and a disabled button. Nothing here is instant any
   more, and pretending otherwise would invite double submissions.
   ========================================================================== */

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, AlertCircle } from 'lucide-react'

import { createScan } from '../lib/api'

export default function ScanForm() {
  /* [React] Four independent pieces of local state, one useState each.
     Grouping them into a single object is possible but rarely worth it. */
  const [url, setUrl] = useState('')
  const [consented, setConsented] = useState(false)
  const [error, setError] = useState('')

  /* [React] The submitting flag exists purely because the scan is slow. It
     drives two things: the button label, and the guard against a second submit
     while the first is still running. Any form that calls a network is
     incomplete without it. */
  const [submitting, setSubmitting] = useState(false)

  /* [React] useNavigate returns a function that changes the URL from code
     (as opposed to <Link>, which is for something the user clicks). */
  const navigate = useNavigate()

  /* [General] Basic client-side validation. This is a convenience check, not a
     security control — anything typed in a browser can be tampered with, which
     is why main.py validates the URL again on arrival. This one exists only to
     save a pointless round trip and give an instant answer. */
  function isValidUrl(value) {
    try {
      // [General] The built-in URL constructor throws if the string is not a
      // valid URL — so a try/catch is the simplest reliable test.
      const parsed = new URL(value)
      return parsed.protocol === 'http:' || parsed.protocol === 'https:'
    } catch {
      return false
    }
  }

  /* [React] The handler is now `async` because it awaits the scan. Note that
     React does not care — an event handler is allowed to return a promise, and
     nothing waits on it. That is also the catch: an error thrown inside an async
     handler will NOT be caught by any React error boundary, so the try/catch
     below is the only thing standing between a failed request and a form that
     silently does nothing. */
  async function handleSubmit(event) {
    // [General] Without this, the browser reloads the whole page on submit,
    // which is the default behaviour of an HTML form and destroys React state.
    event.preventDefault()

    // [General] Guard against a double submit. The button is disabled while
    // submitting, but Enter in the text field can still fire the form, so the
    // real defence belongs here rather than in the markup.
    if (submitting) return

    // [General] .trim() removes accidental leading/trailing spaces — a very
    // common source of "why doesn't my input work" confusion.
    const trimmed = url.trim()

    if (!isValidUrl(trimmed)) {
      setError('Enter a full URL, including https://')
      return   // stop here; do not submit
    }

    setError('')
    setSubmitting(true)

    try {
      /* [General] The consent value is sent explicitly rather than assumed from
         the disabled button. The server re-checks it, and passing the actual
         state means the two can never drift apart. */
      const scan = await createScan(trimmed, consented)

      /* If the scan ran but could not be filed, its id points at nothing — so
         navigating would land on a "not found" page and look like a bug. Saying
         so here is more honest than a confusing empty report. */
      if (scan.stored === false) {
        setError(
          'The scan ran, but the result could not be saved, so there is no report to open. Check the database connection and try again.',
        )
        return
      }

      /* THE PAYOFF. This used to be a hardcoded navigate to the example report;
         it is now the id of a scan that genuinely just ran against the URL
         above. [General] Template literal builds the path. */
      navigate(`/dashboard/scan/${scan.id}`)
    } catch (caught) {
      /* [General] Everything reaches here: a rejected fetch (server not
         running) and the errors api.js throws for a 4xx or 5xx. The server's own
         message is shown when there is one, because it is specific and useful —
         it is what explains a refused private address or a rejected URL. */
      setError(
        caught.message ||
          'The scan could not be started. Check the backend is running on port 8000.',
      )
    } finally {
      /* [General] `finally` runs on success, on failure, and on the early return
         above. Resetting the flag anywhere else would leave the form
         permanently stuck after one error — a bug worth knowing the shape of. */
      setSubmitting(false)
    }
  }

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      <div className="scan-input-row">
        {/* [React] A CONTROLLED INPUT — the defining React form pattern.
            `value` comes from state, and onChange writes back to state, so
            React state is the single source of truth for what is typed.
            Omit onChange and the field appears frozen: another classic bug. */}
        <input
          type="text"
          className="input scan-input mono"
          placeholder="https://your-site.com"
          value={url}
          /* event.target.value is the input's current text. [General] */
          onChange={(event) => setUrl(event.target.value)}
          aria-label="Target URL to scan"
          /* [General] Locking the field during the scan keeps the URL being
             scanned and the URL on screen the same thing. */
          disabled={submitting}
        />

        {/* [React] `disabled` takes a real boolean here, not a string.
            The button unlocks only once the consent box is ticked, and locks
            again while a scan is in flight. */}
        <button
          type="submit"
          className="btn-primary"
          disabled={!consented || submitting}
        >
          <Search size={16} strokeWidth={2} />
          {/* [React] A ternary inside JSX — the standard way to choose between
              two pieces of content. The label carries the waiting state; there
              is no spinner, because a spinner would be decoration and the
              design system is deliberately restrained. */}
          {submitting ? 'Scanning…' : 'Run scan'}
        </button>
      </div>

      {/* [General] Wrapping the checkbox in a <label> means clicking the text
          also toggles the box — a small accessibility win that is free. */}
      <label className="consent-row">
        <input
          type="checkbox"
          /* Checkboxes use `checked` rather than `value`, but the controlled
             pattern is identical: state in, onChange out. [React] */
          checked={consented}
          onChange={(event) => setConsented(event.target.checked)}
          disabled={submitting}
        />
        <span>
          I confirm I own this site or have written authorisation to scan it.
        </span>
      </label>

      {/* Show the validation message only when there is one. [React]

          role="alert" makes a screen reader announce the message the moment it
          appears. Without it the text is on the page but silent, so a
          non-sighted user submits, hears nothing, and has no idea the form
          refused — the failure is invisible rather than merely unstyled. */}
      {error && (
        <p className="scan-error" role="alert">
          <AlertCircle className="icon" size={16} strokeWidth={2} aria-hidden="true" />
          <span>{error}</span>
        </p>
      )}

      {/* [React] The waiting message is conditional on the same flag as the
          button. A real scan contacts the target site, so the delay needs
          explaining or it reads as a hang. */}
      {submitting && (
        <p className="scan-note">
          Running checks against the live site. This takes a few seconds.
        </p>
      )}

      {/* A standing reminder of what this button is really for. */}
      <p className="scan-note">
        Tier 1 scans are external only and run against the public site.
        Tier 2 requires access you grant explicitly.
      </p>
    </form>
  )
}
