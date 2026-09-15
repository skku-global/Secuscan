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
const SEVERITY_RANK = { critical: 0, warning: 1, passed: 2, skipped: 3 }

/* 'skipped' is listed above rather than left to fall through to UNKNOWN_RANK.
   Both put it at the end, so this changes no output - but UNKNOWN_RANK is
   described below as the slot for a severity the frontend has not learned about
   yet, and skipped is one the backend has emitted since the first Tier 1 scan
   that could not find a login page. Naming it makes the position a decision.

   An unrecognised severity sorts last rather than first. Without this, a typo or
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

/* ----------------------------------------------------------------------------
   TIER GROUPING — which findings came from a passive scan and which required
   the client to hand over access.

   WHY THIS EXISTS: the two tiers answer different questions, and a reader who
   cannot tell them apart draws the wrong conclusion from both halves. A Tier 1
   pass means "we looked from outside and this looked right". A Tier 2 pass means
   "we logged in and confirmed it". Interleaving them in one severity-ranked list
   silently presents the weaker statement as the stronger one.

   Groups are returned in tier order with empty ones dropped, so a Tier 1 scan
   renders exactly as it always did: one group, no headings the reader has to
   work out are irrelevant.
-------------------------------------------------------------------------------*/
export const TIER_META = {
  1: {
    label: 'External checks',
    blurb:
      'Observed from outside, with no access to the site. These describe what any visitor could determine.',
  },
  2: {
    label: 'Access-gated checks',
    blurb:
      'Run against the test account you provided. These verify behaviour that cannot be observed from outside.',
  },
}

export function groupByTier(findings) {
  if (!findings) return []

  /* A finding with no tier field is treated as Tier 1. Every finding the current
     engine emits carries one, but scans stored before the tier stamp existed do
     not, and the alternative - a third "unknown tier" group - would put old
     reports in a bucket that describes nothing. Tier 1 is also the safe default
     to guess wrong in: it claims less. */
  return [1, 2]
    .map((tier) => ({
      tier,
      ...TIER_META[tier],
      findings: sortBySeverity(findings.filter((f) => (f.tier || 1) === tier)),
    }))
    .filter((group) => group.findings.length > 0)
}

/* ----------------------------------------------------------------------------
   UNVERIFIED — a Tier 2 check that never reached the thing it was testing.

   THE DISTINCTION THIS DRAWS IS THE POINT OF THE FUNCTION. Both tiers emit
   'skipped', and it means opposite things in each:

     Tier 1 skipped  "there is no login page, so there was nothing to check"
                     — no action available, nothing withheld from the reader.

     Tier 2 skipped  "this was attempted against the account you supplied and
                     reached no conclusion, so this control is UNVERIFIED" — the
                     client paid for an answer and did not get one, and there is
                     usually something they can do about it.

   Rendering both as a grey "Skipped" pill files the second under the first. The
   backend already refuses to call that case passed (see the guard in
   account_enumeration_check.py); this is the same refusal carried into the UI,
   which is where the client actually reads it.

   THE TIER 2 REASONS ARE PLURAL, AND DELIBERATELY NOT ENUMERATED HERE. When this
   function was written, account_enumeration_check was the only Tier 2 check and a
   blocked probe was the only way to reach this state. It is now one of several:
   the sign-in itself may never have succeeded (session_skip_finding in
   _session.py, shared by all four newer checks); a sign-out endpoint may be
   missing or may refuse the request; a settings page may return a login screen; a
   login hop may expose no Set-Cookie line; a probe page may look identical signed
   in and signed out. Each finding's own explanation names its reason, which is
   why this predicate tests only tier and severity — it is the one property they
   share, and a list here would go stale the next time a check is added.
-------------------------------------------------------------------------------*/
export function isUnverified(finding) {
  return Boolean(finding) && finding.severity === 'skipped' && finding.tier === 2
}
