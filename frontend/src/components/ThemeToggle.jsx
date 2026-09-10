/* ============================================================================
   THEMETOGGLE.JSX — the palette control that lives in the top bar.

   WHY THIS EXISTS: the app had exactly one appearance and took its cue only from
   the operating system, so a preference for a plain white page had nowhere to go.
   This is the control that gives it somewhere. The palettes themselves are in
   styles/tokens.css and the remembering is in lib/theme.js — this file is only the
   button.

   WHY A CYCLING BUTTON RATHER THAN THREE RADIOS: there are three states and they
   have a natural order, and the control sits in a band that already holds a
   wordmark, page meta, a user name and a sign-out. A segmented control there
   would be the widest thing in the bar and would draw more attention than a
   preference deserves. One 28px target that advances on click keeps the bar quiet.

   THE COST OF THAT CHOICE, and how it is paid: a cycling button does not show
   what the other options are, so a user cannot see where they will land. The
   accessible name says it outright — "Theme: System. Switch to Navy." — which
   makes the next step visible to a screen reader and, through `title`, to a mouse
   user hovering it.
   ========================================================================== */

import { useEffect, useState } from 'react'
import { Monitor, Palette, Sun } from 'lucide-react'

import {
  applyTheme,
  nextTheme,
  readTheme,
  saveTheme,
  themeLabel,
} from '../lib/theme'

/* WHY A LOOKUP OBJECT RATHER THAN A CHAIN OF TERNARIES: adding a fourth palette
   should touch THEMES in theme.js and this one map, and nothing else. A ternary
   chain is the version where the fourth theme renders no icon at all because
   somebody edited two of the three places it appears.

   The icons are chosen to say which STATE is active, not what will happen next:
   a monitor for "whatever the machine says", a palette for the brand's own
   colours, a sun for the white page. */
const ICONS = {
  system: Monitor,
  navy: Palette,
  white: Sun,
}

export default function ThemeToggle() {
  /* [React] The initialiser is a FUNCTION, not readTheme() called directly.
     Passing the call would re-read localStorage on every single render and throw
     the result away; passing the function means React runs it once, on mount.
     [General] This is the "lazy initial state" pattern. */
  const [theme, setTheme] = useState(readTheme)

  /* WHY AN EFFECT WHEN index.html ALREADY APPLIED THE THEME: the inline script
     there runs before first paint and is what prevents a flash of the wrong
     palette, but it is one line of HTML that a future edit could drop. This makes
     the component self-sufficient — if the attribute is missing when React mounts,
     it appears one frame later instead of never.

     [React] The empty dependency array means "once, after the first render". */
  useEffect(() => {
    applyTheme(readTheme())
  }, [])

  /* WHY THIS EXISTS: the app is the kind of thing people keep open in two tabs —
     a dashboard in one, a report in the other. Choosing White in one tab and
     finding the other still navy reads as the setting not having saved.

     [General] The `storage` event fires in OTHER tabs on the same origin, never in
     the one that wrote the value, which is exactly the behaviour wanted here: the
     writing tab already updated its own state in handleClick.

     The cleanup return is not optional. Without it, every mount adds a listener
     and none are ever removed, and under StrictMode's deliberate double-mount you
     start with two. */
  useEffect(() => {
    function handleStorage() {
      const stored = readTheme()
      applyTheme(stored)
      setTheme(stored)
    }

    window.addEventListener('storage', handleStorage)
    return () => window.removeEventListener('storage', handleStorage)
  }, [])

  const upcoming = nextTheme(theme)

  function handleClick() {
    /* ORDER MATTERS, mildly: apply first so the paint happens on this frame, then
       persist, then re-render the button's label. Saving first would work too, but
       applying first means a localStorage failure still changes the page — see the
       swallowed catch in saveTheme. */
    applyTheme(upcoming)
    saveTheme(upcoming)
    setTheme(upcoming)
  }

  /* [React] A COMPONENT HELD IN A VARIABLE. Lucide icons are components, and JSX
     treats a lowercase tag as an HTML element — so this has to be capitalised to
     render as <Icon /> rather than as an unknown <icon> tag. That capitalisation
     rule catches everyone once. */
  const Icon = ICONS[theme] ?? Monitor

  const description = `Theme: ${themeLabel(theme)}. Switch to ${themeLabel(upcoming)}.`

  return (
    <button
      className="theme-toggle"
      type="button"
      onClick={handleClick}
      /* Both attributes, deliberately. `title` is the hover tooltip and reaches a
         mouse user; `aria-label` is the accessible name and reaches a screen
         reader. Neither one covers the other, and the button has no text of its
         own to fall back on. */
      title={description}
      aria-label={description}
    >
      {/* [General] aria-hidden on the glyph so a screen reader announces the
          button's label once, instead of the label plus an unnamed graphic. */}
      <Icon size={15} strokeWidth={2} aria-hidden="true" />
    </button>
  )
}
