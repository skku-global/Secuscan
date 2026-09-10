/* ============================================================================
   SCANLISTSKELETON.JSX — the loading state for a list of scans.

   WHY THIS EXISTS: Dashboard and History both showed a centred "Loading scans"
   message while the fetch was in flight. Two things are wrong with that, and
   neither is cosmetic.

   1. THE PAGE JUMPS. A one-line message occupies a completely different amount
      of space than three scan rows, so when the data lands everything below it
      moves. That is layout shift, and it is the thing that makes an app feel
      cheap even when it is fast.

   2. IT SAYS LESS. "Loading scans" tells you to wait. Three grey rows tell you
      to wait AND that a list of rows is what is coming — so the eye is already
      in the right place when the real content replaces them.

   [General] A skeleton should be the SHAPE of the content, not a spinner in the
   content's place. The rule of thumb is that it should be roughly the same height
   as what it stands in for; getting that wrong reintroduces the jump it exists to
   prevent.

   ============================================================================
   THE ACCESSIBILITY HALF, which is easy to skip and easy to get backwards.

   A screen reader must hear "loading" ONCE, as words. It must not hear anything
   about the placeholder blocks — they are decoration standing in for content that
   does not exist yet, and there is nothing useful to say about them.

   So: aria-hidden on the visual rows, and a real sentence in an .sr-only span.
   `aria-busy` on the container is the standard way to say "this region is
   currently being populated", and `role="status"` makes the announcement polite
   rather than interrupting whatever the user was reading.
   ========================================================================== */

/* How many placeholder rows to draw. Three, because the dashboard shows three
   recent scans — so on the page where this matters most, the skeleton is exactly
   the height of what replaces it. */
const DEFAULT_ROWS = 3

export default function ScanListSkeleton({ rows = DEFAULT_ROWS, label = 'Loading scans' }) {
  /* [General] Array.from with a length and a map function is the idiomatic way to
     build a list of N things when you only need the index. `new Array(3).map()`
     does NOT work — the array is empty rather than full of undefined, and map
     skips holes. This is a genuinely surprising bit of JavaScript. */
  const placeholders = Array.from({ length: rows }, (_, index) => index)

  return (
    <div className="scan-list" role="status" aria-busy="true">
      {/* The only thing a screen reader hears from this component. */}
      <span className="sr-only">{label}</span>

      {placeholders.map((index) => (
        /* [React] The index IS the right key here, unusually. The warning against
           index keys is about lists that reorder or filter — these rows are
           identical, stateless and never move, so there is nothing for a stable
           id to protect. */
        <div className="scan-row scan-row-skeleton" key={index} aria-hidden="true">
          <div className="scan-row-main">
            {/* Two bars at different widths, because a real row has a long URL
                above a short timestamp. Equal-width bars read as a loading
                graphic; unequal ones read as text. */}
            <span className="skeleton skeleton-title" style={{ width: '58%' }} />
            <span className="skeleton skeleton-text" style={{ width: '32%' }} />
          </div>

          {/* Stands in for the score column, which is right-aligned and fixed
              width — so this one keeps that width rather than a percentage. */}
          <span className="skeleton skeleton-text" style={{ width: '44px' }} />
        </div>
      ))}
    </div>
  )
}
