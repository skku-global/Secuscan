/* ============================================================================
   THEME.JS — which palette the app is painted in.

   WHY THIS EXISTS: tokens.css can define as many palettes as it likes, but
   something has to decide WHICH one is active and remember the answer across
   reloads. That decision is one line of DOM (`data-theme` on <html>) plus one
   localStorage key, and this file is the only place in the app that touches
   either — the same containment session.js gives the auth token.

   THREE STATES, NOT TWO. A plain light/dark switch would have been simpler, but
   the app already answers the OS setting through prefers-color-scheme, and a
   two-state toggle would have to overrule that permanently the first time it was
   touched. So "system" is a real, returnable state:

     system  — no attribute. prefers-color-scheme decides, as it did before.
     navy    — the original palette, pinned. Paper-grey page, navy top bar.
     white   — a true-white page and a white top bar.

   HOW THE ATTRIBUTE MAKES THAT WORK: "system" REMOVES the attribute rather than
   setting it to "system", because the dark block in tokens.css is guarded by
   `:root:not([data-theme])`. Absence is what hands control back to the OS, so
   there is nothing to keep in sync — the guard and this function cannot disagree.
   ========================================================================== */

/* Namespaced for the same reason session.js namespaces its key: localStorage is
   shared across everything on the origin. */
const STORAGE_KEY = 'secuscan.theme'

/* THE THEMES, IN CYCLE ORDER. The array is the single source of truth for both
   "is this a real theme" and "what comes next", so adding a fourth palette means
   adding one entry here and one block in tokens.css.

   `label` is what the button says, and it is deliberately the user's own word for
   it: the navy theme is called navy because that is the colour people point at,
   not "default" or "brand", which describe it only from the inside. */
export const THEMES = [
  { id: 'system', label: 'System' },
  { id: 'navy', label: 'Navy' },
  { id: 'white', label: 'White' },
]

/* The state the app is in before anyone chooses — and the one an unrecognised
   stored value falls back to. */
export const DEFAULT_THEME = 'system'

/* WHY THIS EXISTS: a stored value can be anything. It was written by an older
   version of this file, or hand-edited in devtools, or belongs to a theme that
   has since been deleted. Validating against THEMES rather than trusting the
   string keeps a stale value from putting `data-theme="midnight"` on <html>,
   which would match no block and silently render an unstyled palette. */
function isKnown(theme) {
  return THEMES.some((entry) => entry.id === theme)
}

/* [General] Wrapped for the same reason session.js wraps its reads: localStorage
   THROWS rather than returning null in Safari's private mode and wherever site
   data is blocked. A theme preference is the last thing that should be able to
   crash the app, so an unavailable store simply means "system". */
export function readTheme() {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY)
    return isKnown(stored) ? stored : DEFAULT_THEME
  } catch {
    return DEFAULT_THEME
  }
}

/* WHY THIS IS SEPARATE FROM saveTheme: applying and remembering are genuinely
   different operations. The inline script in index.html applies without saving
   (it has nothing new to record), and a future "preview this theme" control would
   want the same. Fusing them would make the read-only case impossible. */
export function applyTheme(theme) {
  const root = document.documentElement

  if (theme === 'system' || !isKnown(theme)) {
    /* See the header: absence, not `data-theme="system"`. This is the line that
       lets prefers-color-scheme back in. */
    root.removeAttribute('data-theme')
    return
  }

  root.setAttribute('data-theme', theme)
}

export function saveTheme(theme) {
  try {
    window.localStorage.setItem(STORAGE_KEY, theme)
  } catch {
    /* Storage unavailable. The choice still applies to this page — applyTheme has
       already run — it just will not survive a reload. A degraded experience
       rather than a broken one, and nothing worth interrupting the user over. */
  }
}

/* WHY THE CYCLE LIVES HERE and not in the component: "what comes after white"
   is a fact about the set of themes, and the set of themes is this file's
   business. A component that computed it would have to know the order, which is
   the second copy of THEMES that later disagrees with the first.

   [General] The modulo is what makes it a cycle rather than a walk off the end —
   the last theme wraps to the first. */
export function nextTheme(theme) {
  const index = THEMES.findIndex((entry) => entry.id === theme)

  /* -1 when the current value is unknown. Adding 1 to it lands on 0, so an
      unrecognised theme advances to the first real one instead of to the second. */
  return THEMES[(index + 1) % THEMES.length].id
}

/* A label for a theme id, for the button face and its accessible name. Falls
   back to the id so a missing entry shows something rather than "undefined". */
export function themeLabel(theme) {
  return THEMES.find((entry) => entry.id === theme)?.label ?? theme
}
