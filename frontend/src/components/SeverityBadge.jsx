/* ============================================================================
   SEVERITYBADGE.JSX — the small coloured pill: Critical / Warning / Passed.

   WHY THIS EXISTS: severity is shown in several places (findings list, history
   rows, report view). One component means one definition of what a severity
   looks like, so the colours can never disagree between pages.
   ========================================================================== */

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

/* `severity` is one of: 'critical' | 'warning' | 'passed' | 'skipped' | 'info' */
export default function SeverityBadge({ severity }) {
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
