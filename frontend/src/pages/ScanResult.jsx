/* ============================================================================
   SCANRESULT.JSX — the scan report. THIS IS THE PAGE THE MOCKUP SHOWS.

   WHY THIS EXISTS: this is the product's payoff — the screen a client actually
   reads after a scan. Everything else in the app exists to get someone here, or
   to help them come back to it later.

   It loads a real scan from the API by id, which is what makes a report
   something you can refresh, bookmark and send to a developer rather than a view
   that exists only in the seconds after a scan.

   The temporary demo-data fallback that lived here is gone. It existed only
   while Dashboard and History still linked to seeded mock ids; now that they
   list real scans, nothing links to an id the database does not have, and an
   unknown id can honestly say so.

   URL: /dashboard/scan/:id   e.g. /dashboard/scan/6ce060e0
   ========================================================================== */

import { Link, useParams } from 'react-router-dom'
import { Download, AlertTriangle, FileSearch } from 'lucide-react'

import TopBar from '../components/TopBar'
import ScoreGauge from '../components/ScoreGauge'
import FindingCard from '../components/FindingCard'
import ReportSkeleton from '../components/ReportSkeleton'
import CredentialRetention from '../components/CredentialRetention'
import { useScan } from '../hooks/useScan'
import { groupByTier } from '../lib/findings'
import { formatRelativeTime } from '../lib/formatDate'
import '../styles/scanResult.css'

export default function ScanResult() {
  /* [React] useParams() reads the wildcard values out of the current URL.
     The route is defined as "/dashboard/scan/:id", so this returns
     { id: '6ce060e0' } when the address bar shows /dashboard/scan/6ce060e0.
     Always a STRING, even when it looks like a number. */
  const { id } = useParams()

  /* [React] All the fetching, cancellation and status tracking lives in the
     hook — see hooks/useScan.js. What is left in this file is what this page
     actually does differently from the standalone Report page: nothing but
     layout. That is the test of whether a hook was worth extracting. */
  const { scan, status, error } = useScan(id)

  /* [General] Each state gets its own early return. Handling the awkward cases
     first — and returning — is what keeps the real report below free of nested
     conditionals, and it is the habit that stops a blank screen from reading
     scan.findings on null. */
  if (status === 'loading') {
    return (
      <div className="container">
        <TopBar />
        {/* The skeleton traces the report's own layout, so the page does not
            jump when the scan lands — see ReportSkeleton.jsx. */}
        <main id="main">
          <ReportSkeleton />
        </main>
      </div>
    )
  }

  if (status === 'error') {
    return (
      <div className="container">
        <TopBar />
        <main id="main" className="empty-state">
          <span className="empty-state-icon" aria-hidden="true">
            <AlertTriangle size={20} strokeWidth={2} />
          </span>
          <h2>Report unavailable</h2>
          {/* The server's own message, which is more useful than a generic one:
              it is what distinguishes a stopped backend from a real failure. */}
          <p>{error}</p>
          <Link className="btn-primary" to="/dashboard">
            Back to dashboard
          </Link>
        </main>
      </div>
    )
  }

  if (status === 'missing' || !scan) {
    return (
      <div className="container">
        <TopBar />
        <main id="main" className="empty-state">
          <span className="empty-state-icon" aria-hidden="true">
            <FileSearch size={20} strokeWidth={2} />
          </span>
          <h2>Scan not found</h2>
          <p>No scan exists with the id “{id}”.</p>
          <Link className="btn-primary" to="/dashboard">
            Back to dashboard
          </Link>
        </main>
      </div>
    )
  }

  /* Worst news first, WITHIN each tier — see groupByTier in lib/findings.js for
     why the two tiers are not interleaved. Empty groups are dropped, so a Tier 1
     scan renders as one unbroken list exactly as it did before. */
  const tierGroups = groupByTier(scan.findings)
  const showTierHeadings = tierGroups.length > 1

  return (
    <div className="container">
      {/* Template literal builds e.g. "Scan #6ce060e0". [General] */}
      <TopBar meta={`Scan #${scan.id}`} />

      <main id="main">
        {/* Monospace for the URL — technical values read more precisely. */}
        <div className="target-url mono">{scan.targetUrl}</div>
        <h1 className="page-title">Scan report</h1>

        <div className="scan-meta">
          {/* [General] The middot is written as an HTML entity so the separator
              cannot be mistaken for a stray character in the source. */}
          Scanned {formatRelativeTime(scan.scannedAt)} &middot;{' '}
          {scan.findings.length} checks run
        </div>

        {/* The four summary cards. Counts are derived inside the component. */}
        <ScoreGauge score={scan.score} findings={scan.findings} />

        {/* Only rendered for a Tier 2 scan, because a Tier 1 scan never asked for
            credentials and a panel saying none are stored would be answering a
            question the reader did not ask. */}
        {scan.tier === 2 && <CredentialRetention scanId={scan.id} />}

        {!showTierHeadings && (
          <p className="section-label">Findings, critical first</p>
        )}

        {tierGroups.map((group) => (
          <section className="tier-group" key={group.tier}>
            {showTierHeadings && (
              <div className="tier-group-heading">
                <p className="section-label">
                  {group.label}
                  <span className="tier-group-count">
                    {group.findings.length} {group.findings.length === 1 ? 'check' : 'checks'}
                  </span>
                </p>
                <p className="tier-group-blurb">{group.blurb}</p>
              </div>
            )}

            <div className="findings">
              {/* [React] RENDERING A LIST WITH .map()

                  .map() turns each finding object into a <FindingCard>. This is THE
                  way to render a list in React — there is no loop syntax in JSX.

                  The `key` prop is required and easy to forget. React uses it to
                  track which item is which between renders. Without a stable key,
                  expanding one row could visually "move" to another row when the
                  list changes. Use a real unique id, never the array index. */}
              {group.findings.map((finding) => (
                <FindingCard key={finding.id} finding={finding} />
              ))}
            </div>
          </section>
        ))}

        {/* NO LONGER A MOCK. It prints, and the browser's print dialogue offers
            "Save as PDF" — see the note on the same button in Report.jsx.

            The difference here is which document comes out. This page carries the
            top bar and has its findings COLLAPSED, so printing it would produce a
            page of titles with no explanations. So the button sends the user to
            the shareable report first and prints that: the version with every
            finding open, no app chrome, and the print stylesheet written for it.

            [General] `state` rides along with the navigation without appearing in
            the URL, which matters because /report/:id is a link people forward —
            a `?print=1` in the address bar would make every recipient's browser
            open a print dialogue. */}
        <div className="report-actions">
          <Link
            className="btn-primary"
            to={`/report/${scan.id}`}
            state={{ print: true }}
          >
            <Download size={16} strokeWidth={2} />
            Export report
          </Link>
        </div>

        {/* The shareable report lives behind a quiet text link rather than a
            second button — the mockup has one button here, and two competing
            primary actions would blunt the one that matters. */}
        <Link className="report-share-link" to={`/report/${scan.id}`}>
          Open shareable report →
        </Link>
      </main>
    </div>
  )
}
