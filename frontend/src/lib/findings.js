/* ============================================================================
   FINDINGS.JS — the two pure functions that read a findings array.

   WHY THIS FILE EXISTS: both of these used to live in mocks/scanData.js, in a
   378-line file whose other 250 lines were three hand-written example scans from
   before the backend existed. Those fixtures were dead — nothing imported them
   once lib/api.js started returning real scans — but four live components were
   still importing their helpers from a folder called `mocks`, which reads as
   "this page is not real yet" long after it became real.

   Deleting the fixtures and moving these here is the whole change. The functions
   themselves are unmodified.

   [General] Both are PURE: same input, same output, no state, no side effects.
   That is why they belong in lib/ rather than in a component — nothing about
   either one is React, and either could be unit-tested with no DOM at all.
   ========================================================================== */

/* ----------------------------------------------------------------------------
   SEVERITY COUNTS — derived, never stored.

   The report shows "2 critical / 1 warning / 4 passed". Those numbers are
   COMPUTED from the findings array rather than written down, so they cannot drift
   out of sync with the findings they describe.
-------------------------------------------------------------------------------*/
export function countBySeverity(findings, severity) {
  /* [General] The empty-array default guards the one case that actually happens:
     a scan document that stored no findings, or a page rendering before its data
     lands. `undefined.filter` would throw and blank the whole page — a summary
     card showing 0 is the right answer to "how many criticals are in nothing". */
  if (!findings) return 0

  // [General] .filter() keeps matching items; .length counts them.
  return findings.filter((f) => f.severity === severity).length
}

/* ----------------------------------------------------------------------------
   SEVERITY ORDERING — critical first, then warning, then passed.

   The report must lead with the worst news (spec: "Findings, critical first").
   Sorting here rather than relying on the order the engine happened to emit means
   adding a check to CHECKS in engine.py cannot reorder anyone's report.
-------------------------------------------------------------------------------*/
const SEVERITY_RANK = { critical: 0, warning: 1, passed: 2 }

/* An unrecognised severity sorts last rather than first. Without this, a typo or
   a new severity the frontend has not learned yet produces NaN from the
   subtraction below, and a comparator returning NaN leaves the array in an
   arbitrary order — so one unknown value would scramble the whole report rather
   than just misplacing itself. */
const UNKNOWN_RANK = 99

export function sortBySeverity(findings) {
  if (!findings) return []

  /* [General] Spread [...] copies the array first, because .sort() reorders the
     original in place — which would mutate the object a caller is still holding.
     A classic source of bugs, and invisible until something re-renders. */
  return [...findings].sort(
    (a, b) =>
      (SEVERITY_RANK[a.severity] ?? UNKNOWN_RANK) -
      (SEVERITY_RANK[b.severity] ?? UNKNOWN_RANK),
  )
}
