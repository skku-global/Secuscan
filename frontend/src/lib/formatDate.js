/* ============================================================================
   FORMATDATE.JS — turn an ISO timestamp into human wording.

   WHY THIS EXISTS: the mockup says "Scanned 2 minutes ago", but the stored data
   is an ISO timestamp like '2026-09-02T09:14:00Z'. Something must translate
   between the two, and several pages need it (report, dashboard, history), so it
   lives in one shared place rather than being re-written in each.

   ============================================================================
   THE TWO BUGS THIS FILE USED TO HAVE.

   1. `new Date(undefined)` — or any unparseable string — produces an Invalid
      Date, whose getTime() is NaN. Every comparison against NaN is false, so the
      "under a minute" guard fell through, and `Math.floor(NaN / 31536000)` is
      NaN, which is not `>= 1`... so the loop found nothing and it returned "just
      now" for a timestamp it could not read at all. Claiming a scan happened
      seconds ago when the date is garbage is worse than admitting ignorance.

      (The original comment in this file said it returned "NaN years ago". It did
      not — the loop's `>= 1` test happened to catch it. The bug was the false
      "just now", which is harder to notice and more misleading.)

   2. A FUTURE timestamp produced a negative gap, which failed `secondsAgo < 60`
      only by being smaller, then found no unit `>= 1`, and also came back "just
      now". Clocks drift: a server a few seconds ahead of the browser makes every
      fresh scan momentarily future-dated, and this is exactly the timestamp a
      user is looking at when a scan finishes.

   Both now have an explicit answer. [General] Pure JavaScript, no React — this
   would work unchanged in Vue, a plain HTML page, or Node.
   ========================================================================== */

/* How many seconds are in each unit, largest first. The order matters: the
   function walks down this list and stops at the first unit that fits.

   The month and year figures are approximations (30 and 365 days). That is
   correct for this job — "3 months ago" is a rounded statement by nature, and
   nobody reads it expecting calendar arithmetic. Anywhere the exact date matters,
   formatAbsoluteDate below is the right function. */
const UNITS = [
  { name: 'year', seconds: 31536000 },
  { name: 'month', seconds: 2592000 },
  { name: 'day', seconds: 86400 },
  { name: 'hour', seconds: 3600 },
  { name: 'minute', seconds: 60 },
]

/* What to show when a timestamp cannot be read. Deliberately not an empty string:
   a blank space where a date should be looks like a layout bug, and someone will
   spend twenty minutes looking for the missing CSS. An em dash says "there is no
   value here" and is the conventional way to say it in a table. */
const UNKNOWN = '—'

/* How far ahead of the browser a timestamp may sit before it is treated as
   genuinely future-dated rather than as clock skew. Thirty seconds absorbs
   ordinary drift between a server and a laptop without hiding a real problem.

   [General] This constant is the whole fix for bug 2, and it is a judgement call,
   so it is named rather than buried in a comparison. */
const CLOCK_SKEW_TOLERANCE_SECONDS = 30

/* WHY THIS EXISTS: three functions below need the same "is this date usable?"
   answer, and getting it right takes two checks that are each easy to miss.

   THE INPUT CHECK COMES FIRST, and it is the non-obvious half. `new Date(null)`
   does NOT produce an Invalid Date — null coerces to the number 0, so it parses
   cleanly as 1 January 1970 and every validity test passes. A scan document with
   a missing timestamp therefore rendered "56 years ago", which looks like real
   data and is completely wrong. `new Date(0)` has the same problem, but a numeric
   0 is not a timestamp this app ever stores, whereas a null field is the ordinary
   shape of missing data. Requiring a non-empty STRING is what closes it.

   [General] Then Number.isNaN(date.getTime()) — THE way to test a Date in
   JavaScript. `date === 'Invalid Date'` compares against the string form and is
   always false; `date == null` is false because the object exists. An Invalid Date
   is a real Date object whose time value is NaN, and nothing else about it gives
   the problem away. */
function parseTimestamp(isoString) {
  // [General] typeof catches null, undefined, numbers and objects in one test —
  // note that `typeof null` is 'object', not 'null', so a null check alone would
  // not be enough even if one were written.
  if (typeof isoString !== 'string' || isoString.trim() === '') return null

  const date = new Date(isoString)

  // [General] Returning null rather than the Invalid Date means every caller's
  // guard is a plain falsy check, and none of them has to know how a bad Date
  // announces itself.
  return Number.isNaN(date.getTime()) ? null : date
}

export function formatRelativeTime(isoString) {
  // BUG 1's FIX. Say nothing rather than something wrong.
  const then = parseTimestamp(isoString)
  if (!then) return UNKNOWN

  // [General] Subtracting two dates gives the gap in MILLISECONDS, so divide by
  // 1000 for seconds.
  const secondsAgo = Math.floor((Date.now() - then.getTime()) / 1000)

  /* BUG 2's FIX, in two parts. A small negative gap is clock skew and reads as
     "just now", which is what the user expects for a scan that just finished. A
     large one is a genuinely future timestamp, and pretending it is in the past
     would be a lie the caller cannot detect. */
  if (secondsAgo < -CLOCK_SKEW_TOLERANCE_SECONDS) return 'scheduled'

  // Anything under a minute reads better as "just now" than "0 minutes ago".
  if (secondsAgo < 60) return 'just now'

  for (const unit of UNITS) {
    const amount = Math.floor(secondsAgo / unit.seconds)
    if (amount >= 1) {
      // [General] Add "s" for anything other than exactly 1 — the simplest
      // pluralisation that is correct for these particular words.
      return `${amount} ${unit.name}${amount === 1 ? '' : 's'} ago`
    }
  }

  return 'just now'
}

/* An absolute date, for places where "3 days ago" is too vague — a PDF report or
   an audit trail needs the actual date. */
export function formatAbsoluteDate(isoString) {
  const date = parseTimestamp(isoString)
  if (!date) return UNKNOWN

  // [General] toLocaleDateString formats according to the reader's own locale
  // settings. 'en-GB' is pinned here so the format stays predictable.
  return date.toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  })
}

/* WHY THIS EXISTS: a relative time is friendly but imprecise, and a printed
   report needs the precise one. This produces the full form — date and time — for
   a tooltip on a relative timestamp and for the report footer, so a reader can
   always get the exact moment without the page having to choose between the two.

   [General] Pairing a relative label with an exact `title` attribute is the
   standard way to have both: glanceable by default, precise on hover. */
export function formatDateTime(isoString) {
  const date = parseTimestamp(isoString)
  if (!date) return UNKNOWN

  return date.toLocaleString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}
