/* ============================================================================
   SCOREGAUGE.JSX — the summary row at the top of a scan report: the overall
   score, then the Critical / Warning / Passed counts.

   WHY THIS EXISTS: the overall grade is the first thing a non-technical client
   looks at (spec requirement 5). This component owns that summary.

   IMPORTANT: the three counts are CALCULATED from the findings array, never
   passed in as fixed numbers. When a real scan arrives with different findings,
   these cards stay correct with no extra work.

   ============================================================================
   WHY THERE IS NOW AN ACTUAL GAUGE.

   This file was called ScoreGauge and rendered four equal rectangles, one of
   which held a number. Nothing about it was a gauge — and the score, the single
   most important thing on the page, had exactly the same visual weight as the
   count of passed checks beside it. A client opening a report has one question
   first ("how bad is it?") and the layout gave them four answers of equal size.

   The score now gets a ring and its own column. The ring is not decoration: an
   arc is readable at a glance without reading the number, which is what makes a
   score a score rather than a statistic.

   HOW IT IS DRAWN — and why SVG rather than a CSS conic-gradient:
   `stroke-dasharray` on a circle takes a length in user units, so setting it to a
   fraction of the circumference draws exactly that fraction of the ring. That
   gives a real arc with a round cap and an animatable length, all in two elements
   and no images. A conic-gradient can fake it, but it cannot round the end of the
   arc and it cannot be transitioned smoothly in every browser.

   [General] Everything in this file is plain SVG maths. It would work identically
   in Vue or in a static HTML page.
   ========================================================================== */

import { countBySeverity } from '../lib/findings'

/* GEOMETRY. The viewBox is 100x100, so these are all in that coordinate space
   rather than in pixels — the SVG scales to whatever size the CSS gives it.
   Named constants because the circumference below depends on the radius, and two
   numbers that must agree should not both be typed by hand. */
const RADIUS = 42
const STROKE = 8
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

/* WHERE THE COLOUR OF THE RING COMES FROM.

   A score is a summary, and the spec reserves the three severity colours for
   findings. But an overall grade IS the aggregate of those findings, which is the
   one reading where a severity colour is saying exactly what it means rather than
   being borrowed for decoration — so the ring takes it.

   NOTE — this is a documented departure. dashboard.css deliberately keeps the
   score in the scan LIST neutral ink, matching the mockup, where the "Overall
   score" card is plain white while only the count cards carry a tint. The
   difference is deliberate: in a list of ten scans, ten coloured numbers is a
   heat map nobody asked for; on the report for one scan, the grade is the
   headline. Revert by returning 'neutral' unconditionally.

   The thresholds are a judgement call, so they live here as named boundaries
   rather than as bare numbers in an `if`. 70 is "one warning-sized problem";
   below 40 means at least one critical is in play given engine.py's 40-point
   critical penalty. */
const SCORE_GOOD = 70
const SCORE_POOR = 40

function toneForScore(score) {
  if (score >= SCORE_GOOD) return 'passed'
  if (score >= SCORE_POOR) return 'warning'
  return 'critical'
}

export default function ScoreGauge({ score, findings }) {
  // [General] Derive the counts at render time. Because this is a plain function
  // call on every render, the numbers always reflect the current findings.
  const critical = countBySeverity(findings, 'critical')
  const warning = countBySeverity(findings, 'warning')
  const passed = countBySeverity(findings, 'passed')

  /* [General] Clamped before it reaches the geometry. calculate_score in
     engine.py already clamps to 0-100, but this component does not get to assume
     that: a score of 120 would draw an arc longer than the circle and wrap back
     over itself, which looks like a rendering bug rather than like bad data.
     Guard at the point of use, not only at the point of production.

     `Number(score) || 0` also absorbs a null or undefined score from an older
     stored document, which would otherwise render "NaN" in the middle of the
     ring. */
  const safeScore = Math.max(0, Math.min(100, Number(score) || 0))

  /* THE ONE LINE THAT DRAWS THE ARC. dasharray sets the length of the drawn
     portion; the rest of the circumference is the gap. */
  const arcLength = (safeScore / 100) * CIRCUMFERENCE

  const tone = toneForScore(safeScore)

  const counts = [
    { key: 'critical', label: 'Critical', value: critical },
    { key: 'warning', label: 'Warning', value: warning },
    { key: 'passed', label: 'Passed', value: passed },
  ]

  return (
    <section className="score-summary" aria-label="Scan summary">
      {/* --- The gauge ---------------------------------------------------- */}
      <div className={`score-dial ${tone}`}>
        {/* [General] aria-hidden on the SVG and the real value in text below it.
            A screen reader gets "Security score 72 out of 100" from the figure;
            reading out the geometry would be noise. */}
        <svg
          className="score-dial-svg"
          viewBox="0 0 100 100"
          aria-hidden="true"
          focusable="false"
        >
          {/* The track: the full ring, in the sunken surface colour. Without it
              the arc floats with nothing to be a fraction OF, and a low score
              reads as a broken graphic rather than as a small amount. */}
          <circle
            className="score-dial-track"
            cx="50"
            cy="50"
            r={RADIUS}
            fill="none"
            strokeWidth={STROKE}
          />

          {/* The arc. Two transforms rather than one because they do different
              jobs: the rotation moves the start point to 12 o'clock (SVG angles
              start at 3 o'clock), and without it a score would begin filling from
              the right-hand side, which nobody reads as a starting point. */}
          <circle
            className="score-dial-arc"
            cx="50"
            cy="50"
            r={RADIUS}
            fill="none"
            strokeWidth={STROKE}
            strokeLinecap="round"
            /* [General] The dasharray trick: "draw this much, then leave the
               rest". Passing the two lengths explicitly rather than relying on
               dashoffset keeps the maths readable — one number is the arc, the
               other is everything else. */
            strokeDasharray={`${arcLength} ${CIRCUMFERENCE - arcLength}`}
            transform="rotate(-90 50 50)"
          />
        </svg>

        {/* The number sits in the middle of the ring, positioned by CSS rather
            than as SVG <text> — real text can be selected, scales with the user's
            font size, and takes the app's tabular figures. */}
        <div className="score-dial-value">
          <span className="score-dial-number tabular">{safeScore}</span>
          <span className="score-dial-total tabular">/100</span>
        </div>
      </div>

      {/* --- The score's label and the three counts ----------------------- */}
      <div className="score-detail">
        <p className="score-dial-label">Security score</p>

        {/* [General] A definition list, not three divs. Each count genuinely is
            a term and its value, and <dl> is the element that says so — which is
            what lets a screen reader read "Critical, 2" as one unit rather than
            as two unrelated pieces of text.

            NOTE the <div> wrapper around each pair: it is REQUIRED by the HTML
            spec for grouping a dt/dd pair inside a dl, and it is also what makes
            each pair a single grid item. */}
        <dl className="score-counts">
          {counts.map((count) => (
            <div className={`score-count ${count.key}`} key={count.key}>
              <dt className="score-count-label">{count.label}</dt>
              <dd className="score-count-value tabular">{count.value}</dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  )
}
