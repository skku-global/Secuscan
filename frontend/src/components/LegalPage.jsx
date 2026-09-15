/* ============================================================================
   LEGALPAGE.JSX — the shared shell for /terms, /privacy and /refund.

   WHY THIS EXISTS: the three documents have identical chrome — top bar, a title,
   a "last updated" line, a prose column, a footer — and differ only in their
   text. Three copies of the chrome would be three places to fix the day the top
   bar changes, and the one that got missed would be the page nobody visits until
   a lawyer does.

   IT KEEPS THE TOP BAR, which is the one chrome decision worth explaining. The
   legal pages are PUBLIC — a signed-out visitor, and Paddle's verifier, must
   reach them — and TopBar is the same component that renders on the landing page
   for exactly that visitor. Dropping it here would strand a reader who arrived
   from the footer with no way back into the site. It renders signed-out
   correctly on its own; see the comment beside that branch in TopBar.jsx.

   [React] `children` is whatever is between the opening and closing tags at the
   call site, which is how each document supplies only its own text.
   ========================================================================== */

import TopBar from './TopBar'
import SiteFooter from './SiteFooter'
import '../styles/legal.css'

/* MONTH NAMES, SPELLED OUT RATHER THAN DERIVED.
   toLocaleDateString('en-GB', {day:'numeric', month:'long'}) is the obvious way to
   turn 2026-09-12 into "12 September 2026", and it is the wrong one here: the output
   depends on the ICU data bundled with whatever browser or Node build renders it,
   and a small-icu build quietly falls back to "September 12, 2026" or to the
   machine's own locale. These documents are the same text for every reader, so the
   formatting is a lookup table and not a runtime decision. */
const MONTHS = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December',
]

/* Takes the ISO date the page is written with ("2026-09-12") and returns the long
   form for display. Anything that does not parse is handed back untouched, so a
   typo shows up as an obvious odd string on the page rather than as "NaN undefined"
   or, worse, as a silently wrong date. */
function formatDate(iso) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso || '')
  if (!match) return iso

  const [, year, month, day] = match
  const name = MONTHS[Number(month) - 1]
  if (!name) return iso

  return `${Number(day)} ${name} ${year}`
}

export default function LegalPage({ title, updated, children }) {
  return (
    <div className="container">
      <TopBar />

      <main id="main">
        <article className="legal">
          <header className="legal-header">
            <h1 className="page-title">{title}</h1>

            {/* THE DATE IS NOT DECORATION. A policy with no visible revision date
                is a policy a reader cannot tell is current, and these documents
                change whenever the product does.

                The call site passes ISO 8601 and this renders the long form, so the
                attribute <time> wants and the words a reader reads come from one
                value instead of two that can disagree. */}
            <p className="legal-updated">
              Last updated <time dateTime={updated}>{formatDate(updated)}</time>
            </p>
          </header>

          {/* .legal-body carries all the prose rules. The documents write plain
              h2, p, ul and li with no classes, so the styling lives here once
              rather than being repeated on every element in three files. */}
          <div className="legal-body">{children}</div>
        </article>
      </main>

      <SiteFooter />
    </div>
  )
}
