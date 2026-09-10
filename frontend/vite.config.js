import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Vite's config. The React plugin enables JSX compilation and hot-reload
// (edit a file, the browser updates without a full refresh).
export default defineConfig({
  plugins: [react()],

  server: {
    /* WHY THE PORT IS PINNED AND WHY IT IS ALLOWED TO FAIL
       Vite's default behaviour is to take 5173 if it is free and quietly move to
       5174, 5175, ... if it is not — printing the new URL and carrying on. That is
       a sensible default for a site with no backend, and it is the wrong one here,
       because the port is part of the ORIGIN and two things are registered against
       a specific origin:

         - Google Sign-In. The client id in Google Cloud Console has an
           "Authorised JavaScript origins" list. An origin that is not on it makes
           Google refuse the button with "The given origin is not allowed for the
           given client ID" — a console error with no visible symptom on the page.
         - The API's CORS allowlist, once SECUSCAN_CORS_ORIGINS is set for a real
           deployment. (In development the server matches any loopback port on
           purpose, so drifting no longer breaks the API — see config.py.)

       strictPort turns "silently serve from an origin nothing recognises" into
       "refuse to start, and say the port is taken". The second is a ten-second
       fix; the first cost an afternoon of CORS errors that named no port. */
    port: 5173,
    strictPort: true,
  },
})
