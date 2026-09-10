/* ============================================================================
   HISTORY.JSX — every past scan, at "/dashboard/history".

   WHY THIS EXISTS: spec requirement 6 — a history section listing previous
   scans "tagged by tier and payment status", so a client can compare over time
   and see at a glance which scans their subscription actually covered.

   Same rows as the dashboard, with the payment-status column switched on. It
   shares the loading logic with the dashboard through useScans, which is the
   whole reason that hook exists.
   ========================================================================== */

import { FileSearch, AlertTriangle } from 'lucide-react'

import TopBar from '../components/TopBar'
import ScanRow from '../components/ScanRow'
import ScanListSkeleton from '../components/ScanListSkeleton'
import { useScans } from '../hooks/useScans'
import '../styles/dashboard.css'

export default function History() {
  const { scans, status, error } = useScans()

  return (
    <div className="container-wide">
      <TopBar meta="Scan history" />

      <main id="main">
        {/* Wrapped in .dash-head so the title block gets the same bottom
            spacing as the dashboard's, where the wrapper is also holding the
            "New scan" button. One class, one gap, both pages. */}
        <div className="dash-head">
          <div>
            <h1 className="page-title">Scan history</h1>
            <p className="page-sub">
              Every scan run on this account, newest first.
            </p>
          </div>
        </div>

        {/* [React] Each state gets its own branch. Written as separate && blocks
            rather than one chain of nested ternaries — same output, but each line
            reads on its own, and adding a fifth state later does not require
            untangling the previous four. */}

        {/* Six rows rather than three: this page lists everything, so a taller
            skeleton is closer to the real height and the page settles less when
            the data lands. */}
        {status === 'loading' && <ScanListSkeleton rows={6} />}

        {status === 'error' && (
          <div className="empty-state">
            <span className="empty-state-icon" aria-hidden="true">
              <AlertTriangle size={20} strokeWidth={2} />
            </span>
            <h2>Scans unavailable</h2>
            {/* The message from the server, or from api.js when the backend
                could not be reached at all. */}
            <p>{error}</p>
          </div>
        )}

        {/* The genuinely empty account. This used to be unreachable with mock
            data always populated — now it is the state every new account starts
            in, which is exactly why it was worth writing early. */}
        {status === 'ready' && scans.length === 0 && (
          <div className="empty-state">
            <span className="empty-state-icon" aria-hidden="true">
              <FileSearch size={20} strokeWidth={2} />
            </span>
            <h2>No scans yet</h2>
            <p>Run your first scan to see it here.</p>
          </div>
        )}

        {status === 'ready' && scans.length > 0 && (
          <div className="scan-list">
            {/* showStatus with no value means showStatus={true} — this is the
                only place the payment column appears. [React] */}
            {scans.map((scan) => (
              <ScanRow key={scan.id} scan={scan} showStatus />
            ))}
          </div>
        )}
      </main>
    </div>
  )
}
