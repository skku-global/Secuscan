/* ============================================================================
   REPORTSKELETON.JSX — the loading state for a single scan report.

   WHY THIS EXISTS: the same argument as ScanListSkeleton, but the stakes are
   higher here. A report is the page a user waits for after a several-second scan,
   so it is the one loading state they actually watch — and it was a centred
   "Loading report" line that then vanished and dropped a full page of content
   into place. That jump is the last thing the product does before showing its
   most important screen.

   This traces the real report's shape instead: the URL and title, the summary
   block with its dial, and four finding rows.

   [General] Note what a skeleton must NOT do — invent detail. There is no
   placeholder score, no fake severity colour, no guessed number of findings that
   happens to be wrong. Grey blocks are honest about knowing nothing yet; a
   half-filled dial would be a lie the page tells for 400ms.
   ========================================================================== */

/* Four rows, because a Tier 1 scan runs a handful of checks — close enough that
   the page barely moves, without pretending to know the real count. */
const ROWS = 4

export default function ReportSkeleton() {
  const rows = Array.from({ length: ROWS }, (_, index) => index)

  return (
    /* role="status" + aria-busy is the same pairing as the list skeleton: one
       polite announcement, and everything visual hidden from the reader. */
    <div role="status" aria-busy="true">
      <span className="sr-only">Loading report</span>

      <div aria-hidden="true">
        {/* The target URL and the page title. */}
        <span className="skeleton skeleton-text" style={{ width: '46%', marginBottom: 'var(--space-3)' }} />
        <span className="skeleton skeleton-title" style={{ width: '30%', marginBottom: 'var(--space-2)' }} />
        <span className="skeleton skeleton-text" style={{ width: '38%' }} />

        {/* THE SUMMARY BLOCK. It reuses .score-summary, so the real card's grid,
            padding, border and radius are all inherited — the skeleton cannot
            drift out of alignment with the component it stands in for, because it
            is using that component's own layout. */}
        <div className="score-summary report-skeleton-summary">
          {/* A ring, not a filled circle: the dial is a ring, and a solid disc
              here would visibly change shape when the real one arrives. */}
          <div className="score-dial report-skeleton-dial" />

          <div className="score-detail">
            <span className="skeleton skeleton-text" style={{ width: '92px', marginBottom: 'var(--space-3)' }} />
            <div className="score-counts">
              {/* Three count blocks, untinted — the tint depends on findings
                  nobody has yet. */}
              <span className="skeleton report-skeleton-count" />
              <span className="skeleton report-skeleton-count" />
              <span className="skeleton report-skeleton-count" />
            </div>
          </div>
        </div>

        {/* The findings list, reusing .findings and .finding for the dividers. */}
        <span
          className="skeleton skeleton-text"
          style={{ width: '140px', marginBottom: 'var(--space-3)' }}
        />
        <div className="findings">
          {rows.map((index) => (
            <div className="finding finding-skeleton" key={index}>
              <div className="finding-head">
                {/* The severity icon's slot. */}
                <span className="skeleton report-skeleton-icon" />
                <div className="finding-body">
                  {/* Widths vary per row so the block reads as text rather than
                      as a bar chart. [General] Deriving them from the index keeps
                      it deterministic — Math.random() here would reshuffle the
                      skeleton on every render. */}
                  <span
                    className="skeleton skeleton-text"
                    style={{ width: `${52 + index * 7}%` }}
                  />
                  <span
                    className="skeleton skeleton-text"
                    style={{ width: `${34 + index * 5}%` }}
                  />
                </div>
                {/* The severity badge's slot. */}
                <span className="skeleton report-skeleton-badge" />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
