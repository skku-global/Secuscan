/* ============================================================================
   SITEFOOTER.JSX — the public site's footer, shared by every page a stranger
   can reach.

   WHY THIS EXISTS, AND WHY IT MOVED OUT OF LANDING.JSX
   The footer used to be fourteen lines of markup inside Landing.jsx, and that was
   correct while "/" was the only public page. It is not correct now: the three
   legal pages are ALSO public, they are reached BY this footer, and a reader who
   follows a link to the Terms and then finds no way to reach the Privacy Policy
   or to get back to the site has been handed a dead end. So the footer renders on
   all four pages, which means it cannot live inside one of them.

   THE LINKS ARE THE POINT. Paddle's domain verification looks for a reachable
   Terms, Privacy and Refund — a page that exists at a URL nobody links to is not
   a policy, it is a URL. This footer is what makes them reachable from every
   public surface rather than only from the address bar.

   [React] <Link> is right here and <a> would be wrong: these are real routes in
   this app, so React Router should handle them without a full page reload. Note
   that this is the opposite of the rule for the mailto: and #fragment links
   elsewhere in the app — those must be plain <a>, because <Link> would try to
   route "mailto:..." as a path. See the note in lib/pricing.js.
   ========================================================================== */

import { Link } from 'react-router-dom'

import '../styles/footer.css'

/* Defined as data so the footer and the routes in App.jsx are the same three
   destinations written twice rather than once. Adding a Cookie Policy is a line
   here plus a line there, and the label and the path cannot drift into pointing
   at different pages. */
export const LEGAL_LINKS = [
  { label: 'Terms of Service', to: '/terms' },
  { label: 'Privacy Policy', to: '/privacy' },
  { label: 'Refund Policy', to: '/refund' },
]

export default function SiteFooter() {
  return (
    /* Outside <main> deliberately: a page footer is not part of the page's main
       content, and putting it inside would make the skip link land a keyboard user
       on a region that ends with the site's boilerplate. */
    <footer className="landing-footer">
      <nav className="footer-links" aria-label="Legal">
        {LEGAL_LINKS.map((link) => (
          <Link key={link.to} to={link.to}>
            {link.label}
          </Link>
        ))}
      </nav>

      <p>
        SecuScan only scans sites you own or are authorised to test.
        Every scan requires explicit confirmation of that authorisation.
      </p>
    </footer>
  )
}
