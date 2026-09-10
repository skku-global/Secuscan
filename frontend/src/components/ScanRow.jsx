/* ============================================================================
   SCANROW.JSX — one scan in a list, used by both Dashboard and History.

   WHY THIS EXISTS: the dashboard shows recent scans and the history page shows
   all of them. Rather than writing that row twice and letting the two drift
   apart, both pages render this component. History switches on the extra
   `showStatus` column with a prop.
   ========================================================================== */

import { Link } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'

import { countBySeverity } from '../lib/findings'
import { formatRelativeTime } from '../lib/formatDate'

/* Turn a score into a severity word, which then picks the colour via CSS.
   [General] Threshold logic like this belongs in one named function rather
   than being scattered inline wherever a score is displayed. */
function scoreClass(score) {
  if (score < 50) return 'critical'
  if (score < 80) return 'warning'
  return 'passed'
}

/* [React] DEFAULT PROP VALUE. `showStatus = false` means a caller that omits
   the prop gets false rather than undefined — so <ScanRow scan={s} /> works,
   and History opts in with <ScanRow scan={s} showStatus />. Note that writing
   a prop with no value is shorthand for ={true}. */
export default function ScanRow({ scan, showStatus = false }) {
  const criticalCount = countBySeverity(scan.findings, 'critical')

  return (
    /* The whole row is a link into the report. [General] Making the entire row
       clickable — rather than just a small "view" link at the end — gives a
       much bigger target and is easier on both mouse and touch. */
    <Link className="scan-row" to={`/dashboard/scan/${scan.id}`}>
      <div className="scan-row-main">
        <span className="scan-row-url mono">{scan.targetUrl}</span>
        <span className="scan-row-time">
          {formatRelativeTime(scan.scannedAt)}
          {/* Only mention criticals when there are some — "0 critical" is noise.
              [React] && renders nothing when the count is 0. */}
          {criticalCount > 0 && (
            <span className="scan-row-critical">
              {' '}&middot; {criticalCount} critical
            </span>
          )}
        </span>
      </div>

      <span className="scan-row-tier">Tier {scan.tier}</span>

      {/* Payment status only appears where it is useful — the history view. */}
      {showStatus && (
        <span className={`scan-row-status status-${scan.paymentStatus}`}>
          {scan.paymentStatus}
        </span>
      )}

      {/* `tabular` asks the font for fixed-width digits, so 7 and 100 occupy the
          same space and the score column lines up down a list of ten scans
          instead of wandering by a pixel or two per row. See base.css. */}
      <span className={`scan-row-score tabular ${scoreClass(scan.score)}`}>
        {scan.score}
        <span className="score-suffix">/100</span>
      </span>

      <ChevronRight className="scan-row-arrow" size={16} strokeWidth={2} />
    </Link>
  )
}
