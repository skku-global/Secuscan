/* ============================================================================
   MAIN.JSX — the entry point. This is the first file that runs.

   WHY THIS EXISTS: index.html contains one empty <div id="root">. This file
   finds that div and tells React to take it over. Everything you see in the
   browser is rendered from here downward.
   ========================================================================== */

import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App.jsx'
import { AuthProvider } from './context/AuthContext'
import './styles/base.css'   // [General] importing CSS in JS is a bundler feature (Vite)

// [React] createRoot(...).render(...) is how React 18+ starts an app.
ReactDOM.createRoot(document.getElementById('root')).render(
  // [React] StrictMode is a development-only helper. It deliberately runs some
  // code twice to surface bugs early. It disappears in the production build.
  <React.StrictMode>
    {/* [React] BrowserRouter enables URL-based navigation. It must wrap any
        component that uses routes, links, or reads URL params. */}
    <BrowserRouter>
      {/* [React] AuthProvider goes INSIDE BrowserRouter and OUTSIDE App, and
          both halves of that matter.

          Inside the router, because anything the provider renders — and any
          component reading its context — may want to navigate or read the URL,
          and React Router's hooks throw outside a router.

          Outside App, because App is where the routes live: the provider has to
          be above every page, or a page would read a context that is not there.
          One provider at the top is also what makes the /auth/me check happen
          ONCE per page load rather than once per component that asks. */}
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
