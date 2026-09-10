/* ============================================================================
   RECOVERYCODES.JSX — the one screen where the recovery codes are readable.

   WHY THIS EXISTS AS A SHARED COMPONENT: three places produce a fresh set of
   codes — forced enrolment at login, voluntary enrolment from Security settings,
   and regenerating an existing set. All three have the same obligation, and it is
   an unusual one for a UI component: THIS IS THE ONLY TIME THESE CODES EXIST IN
   READABLE FORM. The server stores Argon2 hashes of them (see new_recovery_codes
   in auth.py), so there is no endpoint that can show them again, no "resend", and
   no support process that can recover them. A user who closes this panel without
   keeping the codes has lost them, permanently.

   That is what every decision below is about:

     - The acknowledgement checkbox. Not friction for its own sake — it is the one
       thing standing between "I skimmed a page of hex" and losing the only way
       back into an account whose phone later breaks. A plain Continue button gets
       clicked reflexively.
     - Copy and download, both. Copy suits a password manager, which is the right
       home for these; download suits a printer, which is the right home for
       someone who does not use one. Neither is a substitute for the other.
     - No auto-dismiss, no timeout, no navigation on a stray click.

   WHAT IT DOES NOT DO: nothing here is stored, and nothing is sent anywhere. The
   codes arrive as a prop from the response that generated them, live in this
   component's props for as long as it is mounted, and are gone on unmount.
   ========================================================================== */

import { useState } from 'react'
import { Copy, Download, Check, ShieldAlert } from 'lucide-react'

/* WHY THE DOWNLOAD IS BUILT HERE RATHER THAN FETCHED FROM AN ENDPOINT: an
   endpoint that serves recovery codes as a file is an endpoint that can serve them
   twice, which is exactly the property this feature must not have. The file is
   assembled in the browser from a value already on screen.

   [General] The Blob → object URL → synthetic click → revoke sequence is the
   standard way to make a browser save a string as a file with no server involved.
   The revoke is not optional housekeeping: an object URL holds its Blob in memory
   until the document goes away or the URL is released. */
function downloadCodes(codes, accountEmail) {
  const body = [
    'SecuScan two-factor recovery codes',
    accountEmail ? `Account: ${accountEmail}` : '',
    `Generated: ${new Date().toISOString()}`,
    '',
    'Each code works ONCE. Keep this file somewhere a stolen laptop cannot reach.',
    'Using a code does not switch two-factor authentication off.',
    '',
    ...codes,
    '',
  ]
    .filter(Boolean)
    .join('\r\n')   // CRLF, so the file is not one long line in Windows Notepad

  const url = URL.createObjectURL(new Blob([body], { type: 'text/plain' }))

  const link = document.createElement('a')
  link.href = url
  link.download = 'secuscan-recovery-codes.txt'
  link.click()

  URL.revokeObjectURL(url)
}

export default function RecoveryCodes({
  codes,
  accountEmail = '',
  onContinue,
  continueLabel = 'Continue',
  /* WHY THIS IS A PROP: on the login path there is nothing else to do, so the
     acknowledgement is the gate. In Security settings the user already has a
     session and can simply navigate away, so blocking them achieves nothing but
     an extra click. The caller knows which situation it is in. */
  requireAcknowledgement = true,
}) {
  const [acknowledged, setAcknowledged] = useState(!requireAcknowledgement)
  const [copied, setCopied] = useState(false)
  const [copyFailed, setCopyFailed] = useState(false)

  async function copyAll() {
    setCopyFailed(false)

    try {
      /* [General] navigator.clipboard needs a secure context (https, or
         localhost) AND a user gesture. Both hold inside a click handler on a dev
         server, and it still fails in the wild — an older browser, a hardened
         corporate policy, an iframe without the permission. Hence the catch, and
         hence the codes staying visible and selectable on screen: the clipboard
         is a convenience over the top of a working page, never the only route. */
      await navigator.clipboard.writeText(codes.join('\n'))

      setCopied(true)

      /* Reverts the button after a moment. No cleanup needed on unmount: setting
         state on an unmounted component is a no-op in React 18+, and this timer
         holds nothing but a closure over two setters. */
      setTimeout(() => setCopied(false), 2000)
    } catch {
      setCopyFailed(true)
    }
  }

  return (
    <div className="recovery-panel">
      <div className="recovery-head">
        <span className="recovery-icon" aria-hidden="true">
          <ShieldAlert size={18} strokeWidth={2} />
        </span>

        <div>
          <h2 className="recovery-title">Save your recovery codes</h2>
          {/* THE SENTENCE THAT HAS TO BE UNAMBIGUOUS. Not "keep these safe" —
              which reads as boilerplate — but what actually happens if they are
              lost, since that is the fact a user needs in order to bother. */}
          <p className="recovery-sub">
            This is the only time these are shown. We store only hashes of them, so
            they cannot be displayed again or sent to you.
          </p>
        </div>
      </div>

      {/* [General] <ol> rather than <ul>: the numbering is genuinely useful when
          reading a code off a printed sheet, and it comes free with the right
          element. `mono` and `tabular` are base.css utilities — a fixed-width face
          is what makes 0/O and 1/l distinguishable, which matters more here than
          anywhere else in the app. */}
      <ol className="recovery-list mono tabular">
        {codes.map((entry) => (
          <li key={entry}>{entry}</li>
        ))}
      </ol>

      <div className="recovery-actions">
        <button type="button" className="btn-secondary" onClick={copyAll}>
          {copied ? (
            <>
              <Check size={15} strokeWidth={2} />
              Copied
            </>
          ) : (
            <>
              <Copy size={15} strokeWidth={2} />
              Copy all
            </>
          )}
        </button>

        <button
          type="button"
          className="btn-secondary"
          onClick={() => downloadCodes(codes, accountEmail)}
        >
          <Download size={15} strokeWidth={2} />
          Download
        </button>
      </div>

      {copyFailed && (
        <p className="auth-notice" role="status">
          Copying was blocked by your browser. Select the codes above and copy them
          by hand, or use Download.
        </p>
      )}

      {requireAcknowledgement && (
        /* [General] The label WRAPS the input, which associates the two without
           needing an id at all — worth knowing as the alternative to htmlFor, and
           the better choice for a checkbox whose label is a sentence: the whole
           sentence becomes the click target. */
        <label className="recovery-ack">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
          />
          <span>I have saved these codes somewhere I can get to them.</span>
        </label>
      )}

      {onContinue && (
        <button
          type="button"
          className="btn-primary"
          disabled={!acknowledged}
          onClick={onContinue}
        >
          {continueLabel}
        </button>
      )}
    </div>
  )
}
