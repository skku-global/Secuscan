/* ============================================================================
   REPORT.JSX — the standalone shareable report at "/report/:id".

   WHY THIS EXISTS: the blueprint treats the report as its own real feature, not
   an afterthought — because for a bank or an investor, this page may be the only
   part of the product they ever look at closely. It is deliberately separate
   from ScanResult: no dashboard navigation, no app chrome, nothing that assumes
   the reader has an account. This is the view that gets forwarded to someone
   else's developer.

   Findings are shown EXPANDED here rather than click-to-open, because a
   forwarded report should read as a complete document — the recipient should
   not have to discover that rows are clickable.
   ========================================================================== */

import { useEffect, useRef } from 'react'
import { useLocation, useNavigate, useParams, Link } from 'react-router-dom'
import { Shield, Download, AlertTriangle, CheckCircle2, FileSearch } from 'lucide-react'

import ScoreGauge from '../components/ScoreGauge'
import SeverityBadge from '../components/SeverityBadge'
import ReportSkeleton from '../components/ReportSkeleton'
import { useScan } from '../hooks/useScan'
import { sortBySeverity } from '../lib/findings'
import { formatAbsoluteDate } from '../lib/formatDate'
import '../styles/scanResult.css'
import '../styles/report.css'

const ICONS = {
  critical: AlertTriangle,
  warning: AlertTriangle,
  passed: CheckCircle2,
}

export default function Report() {
  /* [React] Same useParams() + useScan sequence as ScanResult. Two pages
     loading the same scan by id is exactly why that hook exists — the fetching
     is identical, and everything below this line is not. */
  const { id } = useParams()

  /* `shared: true` sends this to the public /report/:id endpoint instead of the
     owner-only /scan/:id. That is the entire reason this page still works for
     the person it was forwarded to: they have no account, and the authenticated
     endpoint would answer 401 for them. See useScan.js. */
  const { scan, status, error } = useScan(id, { shared: true })

  /* ARRIVING HERE TO PRINT. ScanResult's "Export report" navigates to this page
     with state.print set, because this is the version worth printing — every
     finding open, no top bar. This effect is what completes that handover.

     WHY IT IS NOT SIMPLY `if (location.state?.print) window.print()`:

     1. IT MUST WAIT FOR THE SCAN. The fetch is async, so on the first render
        `scan` is null and the page is a "Loading report" box. Printing then would
        produce a sheet of paper that says "Loading report". Hence the status
        check — this fires on the render where the findings actually exist.

     2. IT MUST FIRE ONCE. window.print() is BLOCKING: it holds the JS thread
        until the dialogue is dismissed. Without the ref, the re-render that
        follows would queue another one, and closing the dialogue would reopen it.
        A ref rather than state because changing it must NOT cause a re-render —
        that is the whole distinction between the two, and this is the textbook
        case for a ref.

     3. IT MUST NOT SURVIVE A REFRESH. React Router keeps location.state in the
        history entry, so pressing F5 on a printed report would re-trigger the
        dialogue with no user action behind it. `replace: true` with empty state
        rewrites the current entry, which also means the Back button behaves. */
  const location = useLocation()
  const navigate = useNavigate()
  const hasPrinted = useRef(false)

  useEffect(() => {
    if (!location.state?.print) return
    if (status !== 'ready' || !scan) return
    if (hasPrinted.current) return

    hasPrinted.current = true
    navigate(location.pathname, { replace: true, state: null })

    /* [General] One frame of delay. The effect runs after React commits the DOM
       but the browser has not necessarily PAINTED or applied the print
       stylesheet's layout yet, and window.print() snapshots what is laid out at
       the moment it is called. requestAnimationFrame hands the browser that
       frame first. Skipping this is why "print on load" sometimes produces a
       half-styled page. */
    const frame = requestAnimationFrame(() => window.print())

    // [React] Cleanup, in case the reader navigates away in that one frame.
    return () => cancelAnimationFrame(frame)
  }, [location.state, location.pathname, navigate, status, scan])

  /* This page has no app chrome by design, so its states are quieter than
     ScanResult's — no TopBar, and the fallback link goes home rather than to a
     dashboard the reader may not have access to. */
  if (status === 'loading') {
    return (
      <div className="container">
        <main id="main">
          <ReportSkeleton />
        </main>
      </div>
    )
  }

  if (status === 'error') {
    return (
      <div className="container">
        <main id="main" className="empty-state">
          <span className="empty-state-icon" aria-hidden="true">
            <AlertTriangle size={20} strokeWidth={2} />
          </span>
          <h2>Report unavailable</h2>
          <p>{error}</p>
          <Link className="btn-primary" to="/">Back to home</Link>
        </main>
      </div>
    )
  }

  // Same guard as ScanResult — never assume the id was valid.
  if (status === 'missing' || !scan) {
    return (
      <div className="container">
        <main id="main" className="empty-state">
          <span className="empty-state-icon" aria-hidden="true">
            <FileSearch size={20} strokeWidth={2} />
          </span>
          <h2>Report not found</h2>
          <p>No scan exists with the id “{id}”.</p>
          <Link className="btn-primary" to="/">Back to home</Link>
        </main>
      </div>
    )
  }

  const orderedFindings = sortBySeverity(scan.findings)

  return (
    <div className="container report-page">
      {/* Document-style masthead rather than app navigation. */}
      <header className="report-header">
        <div className="brand">
          <Shield className="brand-icon" size={18} strokeWidth={2} />
          SecuScan
        </div>
        <span className="top-bar-meta mono">Report #{scan.id}</span>
      </header>

      <main id="main">
        <div className="report-title-block">
          <p className="section-label">Security audit report</p>
          <h1 className="report-target mono">{scan.targetUrl}</h1>
          <p className="report-date">
            {/* Absolute date, not "3 days ago" — a forwarded document may be read
                weeks later, when a relative time would be meaningless. */}
            Scanned {formatAbsoluteDate(scan.scannedAt)} &middot; Tier {scan.tier} audit
            &middot; {scan.findings.length} checks
          </p>
        </div>

        <ScoreGauge score={scan.score} findings={scan.findings} />

        <p className="section-label">Findings, critical first</p>

        <div className="report-findings">
          {orderedFindings.map((finding) => {
            const Icon = ICONS[finding.severity]

            return (
              /* Not a button — nothing here is clickable, because everything is
                 already open. [General] Only use interactive elements for things
                 that are genuinely interactive. */
              <article className="report-finding" key={finding.id}>
                <div className="finding-head">
                  <Icon
                    className={`icon ${finding.severity}`}
                    size={18}
                    strokeWidth={2}
                  />
                  <div className="finding-body">
                    <div className="finding-title-row">
                      <p className="finding-title">{finding.title}</p>
                      {finding.tier === 2 && (
                        <span className="finding-tier-tag tier-2">Tier 2</span>
                      )}
                    </div>
                    <p className="finding-desc">{finding.description}</p>
                  </div>
                  <SeverityBadge severity={finding.severity} />
                </div>

                <div className="finding-detail">
                  <p className="detail-label">Why this matters</p>
                  <p className="detail-text">{finding.explanation}</p>

                  <p className="detail-label">Suggested fix</p>
                  <p className="detail-text">{finding.fix}</p>
                </div>
              </article>
            )
          })}
        </div>

        {/* NO LONGER A MOCK. window.print() opens the browser's own print
            dialogue, which on every current browser offers "Save as PDF" as a
            destination — so this button does exactly what it says without a
            server, a headless browser or a PDF library.

            WHAT MAKES IT REAL is report.css's @media print block: page-break
            rules so a finding is never split across sheets, print-color-adjust
            so the severity tints survive, and the actions row hidden so the
            button does not print itself. A print button without that stylesheet
            produces a mangled document and is worse than no button. See the long
            note at the bottom of report.css for where this approach stops being
            enough. */}
        <div className="report-actions">
          <button className="btn-primary" type="button" onClick={() => window.print()}>
            <Download size={16} strokeWidth={2} />
            Download PDF
          </button>
        </div>
      </main>

      <footer className="report-footer">
        <p>
          Generated by SecuScan. Findings reflect the state of the target at the
          time of scanning and are not a guarantee that no other issues exist.
        </p>
      </footer>
    </div>
  )
}
