/* ============================================================================
   DASHBOARD.JSX — the hub a signed-in user lands on, at "/dashboard".

   WHY THIS EXISTS: a returning client wants two things immediately — start a
   new scan, or reopen the last one. This page does only those, and links out to
   the full history rather than duplicating it.

   The scans listed here are real, loaded from the API. The mock array this page
   used to read is no longer imported, which is what allowed the demo-data
   fallback to come out of the report page.
   ========================================================================== */

import { Link } from 'react-router-dom'
import { Plus, FileSearch } from 'lucide-react'

import TopBar from '../components/TopBar'
import ScanRow from '../components/ScanRow'
import ScanListSkeleton from '../components/ScanListSkeleton'
import { useScans } from '../hooks/useScans'
import { countBySeverity } from '../lib/findings'
import '../styles/dashboard.css'

export default function Dashboard() {
  /* [React] One line replaces the whole load-and-track-status dance, because
     the hook owns it. Destructuring picks the three values out by name. */
  const { scans, status, error } = useScans()

  /* [General] .slice(0, 3) copies the first three items without touching the
     original array. The API returns newest-first, so this is "3 most recent".

     Note this runs on every render, including while status is 'loading' — which
     is safe only because the hook initialises scans to [] rather than null.
     Slicing null would crash. That initial value is doing real work. */
  const recentScans = scans.slice(0, 3)

  /* Total criticals across every scan — the one number worth surfacing at the
     top. [General] .reduce() walks the array accumulating a single result:
     `total` is the running sum, starting from the 0 passed in at the end. */
  const openCriticals = scans.reduce(
    (total, scan) => total + countBySeverity(scan.findings, 'critical'),
    0
  )

  /* [General] The subtitle has to say something sensible in four different
     situations, so it is worked out here rather than crammed into the JSX as
     nested ternaries — which is where that pattern stops being readable. */
  function subtitle() {
    if (status === 'loading') return 'Loading your scans…'
    if (status === 'error') return error
    if (scans.length === 0) return 'No scans yet. Run your first one to see it here.'
    if (openCriticals === 0) return 'No critical findings outstanding.'

    // Template literal keeps the wording grammatical for the 1 case. [General]
    return `${openCriticals} critical ${
      openCriticals === 1 ? 'finding' : 'findings'
    } across your scans.`
  }

  return (
    <div className="container-wide">
      <TopBar meta={<Link to="/dashboard/history">History</Link>} />

      <main id="main">
        <div className="dash-head">
          <div>
            <h1 className="page-title">Dashboard</h1>
            <p className="page-sub">{subtitle()}</p>
          </div>

          {/* New Scan sends the user back to the landing form, which is where the
              URL input and the consent checkbox live. */}
          <Link className="btn-primary" to="/">
            <Plus size={16} strokeWidth={2} />
            New scan
          </Link>
        </div>

        <p className="section-label">Recent scans</p>

        {/* Three placeholder rows rather than a message. They occupy the same
            height as the real list, so the page does not jump when the data
            arrives — see the note at the top of ScanListSkeleton.jsx. */}
        {status === 'loading' && <ScanListSkeleton rows={3} />}

        {/* The genuinely empty account. Reachable now that the mock data is
            gone: it is the state every new sign-up starts in. */}
        {status === 'ready' && scans.length === 0 && (
          <div className="empty-state">
            {/* A glyph in a quiet circle. WHY BOTHER: an empty state that is only
                two lines of centred text reads as an error the page is being
                polite about. An icon makes it read as a designed state — the
                difference between "something went wrong" and "nothing here yet".
                aria-hidden because the heading below already says it in words. */}
            <span className="empty-state-icon" aria-hidden="true">
              <FileSearch size={20} strokeWidth={2} />
            </span>
            <h2>No scans yet</h2>
            <p>Run your first scan and the report will appear here.</p>
            <Link className="btn-primary" to="/">
              <Plus size={16} strokeWidth={2} />
              Run a scan
            </Link>
          </div>
        )}

        {/* [React] The list renders only once there is something to list. After
            a failure the subtitle above carries the message, so repeating it
            here would say the same thing twice. */}
        {status === 'ready' && scans.length > 0 && (
          <div className="scan-list">
            {/* [React] Same .map() + key pattern as the findings list. */}
            {recentScans.map((scan) => (
              <ScanRow key={scan.id} scan={scan} />
            ))}
          </div>
        )}

        {/* "View all scans" only when there are any. On a brand-new account it
            led to a second empty page, which is a dead end dressed up as a
            link. */}
        {status === 'ready' && scans.length > 0 && (
          <Link className="text-link" to="/dashboard/history">
            View all scans →
          </Link>
        )}
      </main>
    </div>
  )
}
