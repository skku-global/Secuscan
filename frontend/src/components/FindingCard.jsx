/* ============================================================================
   FINDINGCARD.JSX — one row in the findings list, which expands when clicked.

   WHY THIS EXISTS: spec requirement 4 — "clicking on any individual finding
   should expand to show a plain-language explanation of the risk and a suggested
   fix". Collapsed, the row matches the approved mockup; expanded, it teaches the
   client what the problem actually means.

   KEY IDEA — LOCAL STATE. Each card remembers its OWN open/closed state. The page
   above it does not track which rows are open, because nothing else needs to
   know. Keeping state as close as possible to where it is used is one of the most
   useful habits in React.

   ============================================================================
   THE STRUCTURAL BUG THIS FILE USED TO HAVE, because it is worth understanding
   rather than just fixing.

   The whole row — header AND expanded detail — was inside a single <button>. Two
   separate problems came out of that:

   1. INVALID HTML. A <button> may only contain phrasing content, and <p> and
      <div> are flow content. The HTML parser is lenient enough not to visibly
      break, but the DOM you get is not the DOM you wrote, and nothing about that
      is dependable.

   2. THE PANEL CLOSED WHEN YOU USED IT. Every click inside the detail — selecting
      a sentence to copy, or just clicking to steady your reading position —
      bubbled to the button and toggled it shut. So the feature closed itself
      exactly when someone was reading it.

   THE FIX is the standard disclosure shape: a <button> that is only the header,
   and a sibling panel that is not inside it. The button controls the panel via
   aria-controls; the panel is an ordinary region. This is also what a screen
   reader expects — "button, expanded" followed by a region, rather than a button
   whose label is four paragraphs long.
   ========================================================================== */

import { useId, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  HelpCircle,
  Info,
  MinusCircle,
} from 'lucide-react'
import SeverityBadge from './SeverityBadge'

/* Which Lucide icon represents each severity.
   [General] Lookup object again — same pattern as SeverityBadge's LABELS.
   Includes 'skipped' for checks where conditions were not applicable (e.g. no login page)
   and a default fallback to guarantee a valid component is always resolved. */
const ICONS = {
  critical: AlertTriangle,
  warning: AlertTriangle,
  passed: CheckCircle2,
  skipped: MinusCircle,
  info: Info,
}

/* Fallback icon when finding.severity is unrecognized, missing, or new.
   Prevents React element type invalid (undefined component) errors. */
const DEFAULT_ICON = HelpCircle

export default function FindingCard({ finding }) {
  /* [React] THE useState HOOK — the single most important thing here.

     It returns exactly two things, which array destructuring names in one line:
       isOpen    the current value  (starts as false — collapsed)
       setIsOpen the ONLY way to change it

     Never write `isOpen = true` directly. Calling setIsOpen(...) is what tells
     React "this changed, re-run this component and update the screen". A plain
     assignment would change the variable but leave the page stale. */
  const [isOpen, setIsOpen] = useState(false)

  /* [React] useId generates an id that is unique across the page and stable
     across re-renders. It exists for exactly this: wiring aria-controls to a
     panel when the same component appears many times on one page. Hand-writing
     `id={finding.id}` would work until two findings shared an id, and duplicate
     ids silently break every aria relationship on the page. */
  const panelId = useId()

  /* [React] Capitalised because JSX treats lowercase names as HTML tags and
     capitalised names as components. `Icon` must be capital-I to render below.
     Defaults to DEFAULT_ICON so unknown/unhandled severities never produce `undefined`. */
  const Icon = ICONS[finding?.severity] || DEFAULT_ICON
  const severity = finding?.severity || 'unknown'

  return (
    /* The wrapper is a plain <div>. It carries the row's border and hover tint —
       which used to live on the button — so the header and the open panel read as
       one row rather than as two stacked things. */
    <div className={`finding ${isOpen ? 'is-open' : ''}`}>
      {/* [General] A <button>, because this is genuinely clickable: buttons are
          keyboard-focusable and work with screen readers for free. It now wraps
          ONLY the header, which is what makes the markup valid and stops a click
          in the detail panel closing it. */}
      <button
        type="button"
        className="finding-head"
        /* [React] onClick takes a FUNCTION, not a function call. Note the arrow:
           `() => setIsOpen(...)` hands React a function to run later. Writing
           `onClick={setIsOpen(!isOpen)}` (no arrow) would call it immediately
           during render — a very common beginner bug.

           The updater form `(open) => !open` is used rather than `!isOpen`
           because it reads the value React is about to apply rather than the one
           captured when this render happened. For a toggle the difference rarely
           bites, but it is free to get right. */
        onClick={() => setIsOpen((open) => !open)}
        /* [General] aria-expanded tells assistive technology whether this control
           is currently open; aria-controls says WHICH element it opens. The pair
           is what makes a disclosure announce itself correctly. */
        aria-expanded={isOpen}
        aria-controls={panelId}
      >
        {/* Severity icon, tinted by the same class-name trick as the badge. */}
        <Icon
          className={`icon ${severity}`}
          style={severity === 'skipped' ? { color: 'var(--muted)' } : undefined}
          size={18}
          strokeWidth={2}
          aria-hidden="true"
        />

        <div className="finding-body">
          {/* A <span> in a div, not a <p>: still invalid inside a button, and
              this content genuinely is the button's label rather than prose. */}
          <span className="finding-title">{finding.title}</span>
          <span className="finding-desc">{finding.description}</span>
        </div>

        <SeverityBadge severity={finding.severity} />

        {/* THE CHEVRON — a deliberate change from the mockup, which ends each row
            at the severity badge.

            The old comment argued that an arrow would push every badge ~30px in
            from the right edge and that hover plus the pointer cursor were signal
            enough. Two things are wrong with that. Hover does not exist on touch,
            so on a phone there was no affordance at all. And a disclosure with no
            state indicator gives the user nothing to look at to tell open from
            closed except the panel itself.

            It rotates rather than swapping to a second icon, so the transition
            carries the state change. Revert by deleting this element and the
            .finding-chevron rules. */}
        <ChevronDown
          className="finding-chevron"
          size={16}
          strokeWidth={2}
          aria-hidden="true"
        />
      </button>

      {/* [React] CONDITIONAL RENDERING with &&. When isOpen is false React
          renders nothing here — the panel is not merely hidden with CSS, it
          genuinely is not in the page, so its text cannot be found by ctrl-F or
          read out by a screen reader walking the document. */}
      {isOpen && (
        /* [General] role="region" plus a label makes this a landmark a screen
            reader user can jump to, rather than an anonymous div. */
        <div
          className="finding-detail"
          id={panelId}
          role="region"
          aria-label={`Details for ${finding.title}`}
        >
          <p className="detail-label">Why this matters</p>
          <p className="detail-text">{finding.explanation}</p>

          <p className="detail-label">Suggested fix</p>
          <p className="detail-text">{finding.fix}</p>

          {/* The backend check module this finding came from. Useful while
              developing, and it maps each row to a file in
              backend/scanning/checks/. */}
          <p className="detail-check mono">check: {finding.checkId}</p>
        </div>
      )}
    </div>
  )
}
