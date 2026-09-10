/* ============================================================================
   TOPBAR.JSX — the brand header that appears at the top of every page.

   WHY THIS EXISTS: the shield mark and "SecuScan" wordmark must look identical
   everywhere. Defining them once here means a future logo change is a one-file
   edit, and no page can accidentally drift from the others.

   It also carries the account controls, for the same reason: "who am I signed in
   as, and how do I leave" belongs in one place that every page already renders,
   not repeated on each one.

   ---------------------------------------------------------------------------
   THE NARROW-SCREEN PROBLEM THIS FILE NOW SOLVES

   Signed in, the right-hand cluster holds up to five things: a theme toggle, a
   page link the page supplied, "Settings", the user's name, and "Sign out". That
   is comfortable at 1200px and impossible at 380px — the items either overflow the
   band or squeeze until every label truncates to nothing.

   So below a breakpoint they collapse into a menu behind one button. The rules
   that make a disclosure menu actually work, all of which are easy to leave out:

     - It closes when the route changes. Otherwise tapping "Settings" navigates
       and leaves the menu hanging open over the new page.
     - It closes on Escape, because that is what Escape means, and a menu with no
       keyboard exit traps somebody who opened it by accident.
     - It closes on a click outside itself — the gesture everyone tries first.
     - The button reports `aria-expanded`, so a screen reader announces "collapsed"
       or "expanded" rather than reading an unlabelled icon.

   THE THEME TOGGLE STAYS OUT OF THE MENU on purpose. It is a 28px icon, it fits
   at any width, and burying a control that costs nothing to show makes the menu
   longer for no gain.
   ========================================================================== */

import { useEffect, useRef, useState } from 'react'
import {
  LayoutDashboard,
  LogIn,
  LogOut,
  Menu,
  Settings,
  Shield,
  User,
  X,
} from 'lucide-react'
import { Link, useLocation, useNavigate } from 'react-router-dom'

import { useAuth } from '../context/AuthContext'
import ThemeToggle from './ThemeToggle'

/* [React] PROPS are the inputs to a component — like function arguments.
   Writing `{ meta }` in the parameter list is DESTRUCTURING: it pulls the
   `meta` property out of the props object so you can write `meta` instead of
   `props.meta`. [General] Destructuring is plain modern JavaScript.

   `meta` is optional — pages that have nothing to show on the right simply
   omit it, e.g. <TopBar /> versus <TopBar meta="Scan #4821" />. */
export default function TopBar({ meta }) {
  /* [React] Read straight from context, not passed down as a prop. This is the
     payoff of AuthContext: TopBar appears on five pages, and without context
     every one of them would have to accept a `user` prop and pass it through —
     including pages that have no other reason to know who is signed in. */
  const { user, signedIn, checking, signOut } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  const [menuOpen, setMenuOpen] = useState(false)

  /* [React] A REF is a box holding a value that survives re-renders without
     causing one. Attached to a DOM node via `ref={}`, `.current` becomes that
     element — which is how the click-outside check below can ask "is the thing
     you clicked inside me?". State could not do this job: the element is not
     something React re-renders in response to. */
  const navRef = useRef(null)

  async function handleSignOut() {
    setMenuOpen(false)

    await signOut()

    /* Home, not the login page. Signing out and immediately being asked to sign
       in reads as a failed attempt to leave. [General] */
    navigate('/')
  }

  /* CLOSE ON NAVIGATION.

     [React] The dependency array is `[location.pathname]`, so this runs on every
     route change and only on a route change. Without it the menu stays open on
     top of the page it just navigated to — the single most common bug in a
     hand-rolled mobile menu, and invisible on a desktop where the menu is hidden
     by CSS anyway. */
  useEffect(() => {
    setMenuOpen(false)
  }, [location.pathname])

  /* CLOSE ON ESCAPE, AND ON A CLICK OUTSIDE.

     Both listeners are on `document` because both are about things happening
     somewhere this component does not render. */
  useEffect(() => {
    /* [React] The early return is what keeps two global listeners from being
       attached while the menu is shut. An effect that always listens would run
       these handlers on every click on every page, forever. */
    if (!menuOpen) return

    function onKeyDown(event) {
      if (event.key === 'Escape') setMenuOpen(false)
    }

    function onPointerDown(event) {
      /* [General] .contains() walks the DOM tree, so this is true for a click on
         the button, on a link inside the panel, or on anything nested in either.
         The `?.` guards the frame after unmount, when .current is null. */
      if (navRef.current?.contains(event.target)) return

      setMenuOpen(false)
    }

    document.addEventListener('keydown', onKeyDown)
    /* "pointerdown" rather than "click": it fires before focus moves and covers
       mouse, touch and pen with one listener. [General] */
    document.addEventListener('pointerdown', onPointerDown)

    /* [React] THE CLEANUP FUNCTION. React calls it before the effect runs again
       and when the component unmounts. Skipping it here would leave a listener
       per open-close cycle attached to the document for the life of the tab. */
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.removeEventListener('pointerdown', onPointerDown)
    }
  }, [menuOpen])

  /* WHY THE ITEMS ARE BUILT ONCE AND RENDERED TWICE: the desktop row and the
     mobile panel show the same things, and writing them out twice is how the two
     drift — a link added to one and forgotten in the other is a feature that
     exists only on a phone. CSS decides which copy is visible; this decides what
     is in them. [React] */
  function accountItems() {
    if (checking) {
      /* Nothing at all while /auth/me is still in flight. Rendering "Sign in"
         here and swapping it for the user's name a moment later reads, to a
         returning user, as having been signed out. */
      return null
    }

    if (!signedIn) {
      return (
        <Link className="top-bar-link" to="/login">
          <LogIn size={14} strokeWidth={2} aria-hidden="true" />
          <span>Sign in</span>
        </Link>
      )
    }

    return (
      <>
        <Link className="top-bar-link" to="/dashboard">
          <LayoutDashboard size={14} strokeWidth={2} aria-hidden="true" />
          <span>Dashboard</span>
        </Link>

        <Link className="top-bar-link" to="/settings">
          <Settings size={14} strokeWidth={2} aria-hidden="true" />
          <span>Settings</span>
        </Link>

        <span className="top-bar-divider" aria-hidden="true" />

        <span className="top-bar-user" title={user?.name ? `Signed in as ${user.name}` : undefined}>
          <User size={13} strokeWidth={2} aria-hidden="true" />
          <span>{user?.name || user?.email}</span>
        </span>

        <button className="top-bar-signout" type="button" onClick={handleSignOut}>
          <LogOut size={13} strokeWidth={2} aria-hidden="true" />
          <span>Sign out</span>
        </button>
      </>
    )
  }

  return (
    // [React] className, not class — `class` is a reserved word in JavaScript,
    // so JSX renames the HTML attribute. This trips up everyone once.
    <div className="top-bar">
      {/* [React] <Link> is React Router's replacement for <a>. It changes the
          URL and swaps the page instantly, with no full-page reload. */}
      <Link to="/" className="brand">
        {/* [React] Lucide icons are components, so props set their size and
            colour. strokeWidth is camelCase — JSX uses camelCase for attributes
            that are hyphenated in plain HTML (stroke-width). */}
        <Shield className="brand-icon" size={18} strokeWidth={2} />
        SecuScan
      </Link>

      {/* The ref goes on the wrapper holding BOTH the button and the panel, so a
          click on the button counts as "inside" — otherwise the outside-click
          handler closes the menu in the same gesture that opened it, and the menu
          appears not to work at all. */}
      <div className="top-bar-right" ref={navRef}>
        {/* WHY THE THEME CONTROL LIVES HERE: TopBar is rendered by every page
            with a band, so one line in this file puts the control everywhere —
            the same argument that already put the account controls here.

            It sits OUTSIDE the `signedIn` branch, and that is the point: a
            visitor reading the landing page is exactly the person most likely to
            have an opinion about the colour scheme, and making them sign up
            before they can change it would be absurd. */}
        <ThemeToggle />

        {/* THE DESKTOP ROW. Hidden by CSS below the breakpoint. */}
        <div className="top-bar-items">
          {/* [React] CONDITIONAL RENDERING. Render meta only if it doesn't duplicate Dashboard */}
          {meta &&
            !(
              meta?.props?.to === '/dashboard' ||
              meta?.props?.children === 'Dashboard' ||
              (typeof meta === 'string' && meta === 'Dashboard')
            ) && <span className="top-bar-meta">{meta}</span>}

          {accountItems()}
        </div>

        {/* THE MENU BUTTON. Hidden by CSS above the breakpoint. */}
        <button
          className="top-bar-burger"
          type="button"
          /* [General] aria-expanded is the whole accessibility of a disclosure
             control. Without it the button is an unlabelled icon and nothing
             announces that pressing it revealed anything. */
          aria-expanded={menuOpen}
          aria-controls="top-bar-menu"
          /* An icon button has no text, so it needs a name of its own. The label
             changes with the state for the same reason the icon does. */
          aria-label={menuOpen ? 'Close menu' : 'Open menu'}
          onClick={() => setMenuOpen((open) => !open)}
        >
          {menuOpen ? (
            <X size={20} strokeWidth={2} aria-hidden="true" />
          ) : (
            <Menu size={20} strokeWidth={2} aria-hidden="true" />
          )}
        </button>

        {/* THE PANEL.

            [React] Rendered only while open rather than hidden with CSS, so its
            links are not in the tab order when it is shut. A visually hidden
            panel whose links can still be tabbed into is a keyboard user landing
            on controls they cannot see. */}
        {menuOpen && (
          <div className="top-bar-menu" id="top-bar-menu">
            {signedIn && user && (
              <>
                <div className="top-bar-menu-user">
                  <span className="top-bar-menu-user-label">Signed in as</span>
                  <span className="top-bar-menu-user-name">{user.name || user.email}</span>
                </div>
                <div className="top-bar-menu-divider" />
              </>
            )}

            {signedIn ? (
              <>
                <Link className="top-bar-menu-item" to="/dashboard">
                  <LayoutDashboard size={15} strokeWidth={2} aria-hidden="true" />
                  <span>Dashboard</span>
                </Link>

                <Link className="top-bar-menu-item" to="/settings">
                  <Settings size={15} strokeWidth={2} aria-hidden="true" />
                  <span>Settings</span>
                </Link>

                <div className="top-bar-menu-divider" />

                <button
                  className="top-bar-menu-item top-bar-menu-signout"
                  type="button"
                  onClick={handleSignOut}
                >
                  <LogOut size={15} strokeWidth={2} aria-hidden="true" />
                  <span>Sign out</span>
                </button>
              </>
            ) : (
              !checking && (
                <Link className="top-bar-menu-item" to="/login">
                  <LogIn size={15} strokeWidth={2} aria-hidden="true" />
                  <span>Sign in</span>
                </Link>
              )
            )}
          </div>
        )}
      </div>
    </div>
  )
}
