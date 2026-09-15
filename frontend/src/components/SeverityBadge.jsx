/* ============================================================================
   SEVERITYBADGE.JSX — the small coloured pill: Critical / Warning / Passed.

   WHY THIS EXISTS: severity is shown in several places (findings list, history
   rows, report view). One component means one definition of what a severity
   looks like, so the colours can never disagree between pages.
   ========================================================================== */

import { isUnverified } from '../lib/findings'

/* Maps the raw data value to the text a human reads.
   [General] A plain lookup object is the standard alternative to a long
   if/else chain — it works the same in any language with dictionaries. */
const LABELS = {
  critical: 'Critical',
  warning: 'Warning',
  passed: 'Passed',
  skipped: 'Skipped',
  info: 'Info',
}

/* Inline styling for severities not predefined in base.css (.badge.critical/warning/passed) */
const STYLES = {
  skipped: {
    color: 'var(--muted)',
    background: 'var(--surface-sunken)',
    borderColor: 'var(--border)',
  },
  info: {
    color: 'var(--navy)',
    background: 'var(--navy-tint)',
    borderColor: 'var(--border)',
  },
}

/* `severity` is one of: 'critical' | 'warning' | 'passed' | 'skipped' | 'info'

   `tier` is optional and only ever changes ONE case: a Tier 2 check that came
   back skipped. See below for why that case cannot be allowed to share a pill
   with the Tier 1 one. Callers that do not pass a tier get exactly the previous
   behaviour, which is what keeps this safe to add to a component used on four
   pages. */
export default function SeverityBadge({ severity, tier }) {
  /* THE ONE THAT MATTERS.

     'skipped' arrives from both tiers and means the opposite thing in each. A
     Tier 1 skip is "there was no login page, so there was nothing to look at" —
     nothing was withheld and nothing can be done. A Tier 2 skip is "this was
     attempted against the account you supplied and reached no conclusion" — a
     control the client paid to have verified was NOT verified, and there is
     usually a concrete step that would fix that.

     The reason varies by check and each finding's own explanation names it: the
     sign-in itself never succeeded (any Tier 2 check — see session_skip_finding
     in _session.py); a CSRF token, a WAF or a rate limiter turned the probes
     away (enumeration); no sign-out endpoint, a refused sign-out, or a probe
     page that looks identical signed in and signed out (logout); every candidate
     settings page returned a login screen (two-factor); no Set-Cookie line was
     visible on the login hop (session cookie). What they share is the part this
     function keys on — an answer was paid for, none was reached, and the result
     must not be read as a pass.

     A grey pill reading "Skipped" is the correct label for the first and a quiet
     misfiling of the second. This is the same failure the check itself guards
     against in the backend, where identical blocked responses are refused a PASS
     because a wall is not a clean bill of health. The guard is worth nothing if
     the UI puts the result back in the drawer marked "not applicable". */
  if (isUnverified({ severity, tier })) {
    return <span className="badge unverified">Not verified</span>
  }

  return (
    // [React] A TEMPLATE LITERAL (backticks with ${...}) builds the class name
    // by pasting the severity value straight in, producing e.g. "badge critical".
    // Because base.css defines .badge.critical, .badge.warning and .badge.passed,
    // the colour comes from CSS — with inline fallback styling for extended severities.
    <span className={`badge ${severity}`} style={STYLES[severity]}>
      {/* [General] Bracket lookup with a fallback: if severity is somehow an
          unexpected value, show capitalized string rather than raw lowercase. */}
      {LABELS[severity] || (typeof severity === 'string' ? severity.charAt(0).toUpperCase() + severity.slice(1) : severity)}
    </span>
  )
}
