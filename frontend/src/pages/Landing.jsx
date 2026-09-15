/* ============================================================================
   LANDING.JSX — the public front page at "/".

   WHY THIS EXISTS: this is the only page a stranger sees before deciding
   whether to trust SecuScan. It has three jobs, in order: explain what the tool
   does, let someone start a scan immediately, and show what the paid tiers add.

   Everything here is presentation — the actual scan submission lives in
   the ScanForm component so this page stays readable.
   ========================================================================== */

import { Link } from 'react-router-dom'
import { Check, ShieldCheck, FileText, Repeat } from 'lucide-react'

import TopBar from '../components/TopBar'
import SiteFooter from '../components/SiteFooter'
import ScanForm from '../components/ScanForm'
import { PRICING_PLANS, PRICING_ANCHOR, planDestination } from '../lib/pricing'
import '../styles/landing.css'

/* The three selling points under the hero. Defined as data rather than repeated
   JSX so adding a fourth is a one-line change. [General] a data-driven UI is a
   universal pattern, not a React-specific one. */
const VALUE_POINTS = [
  {
    icon: ShieldCheck,
    title: 'Checks that matter',
    text: 'Rate limiting, HTTPS, security headers, exposed data, sessions, MFA and password policy — the mistakes that actually get small companies breached.',
  },
  {
    icon: FileText,
    title: 'A report you can forward',
    text: 'Plain language, colour-coded by severity, with a suggested fix on every finding. Written to be handed straight to a developer.',
  },
  {
    icon: Repeat,
    title: 'Ongoing, not one-off',
    text: 'Security is not a single audit. Paid plans re-scan on a schedule, so a regression shows up before a customer finds it.',
  },
]

/* WHY THIS IS ITS OWN COMPONENT
   The pricing card's call to action is one of three different HTML elements
   depending on the plan, and the choice is not cosmetic:

     <Link>  a real route — the two plans that can be bought.
     <a>     a #fragment on this page, or a mailto:. Both must be plain anchors.
             [React] React Router's <Link> does NOT scroll to a hash (it navigates
             and leaves you at the top, which looks like a broken button), and a
             "mailto:" given to <Link> is treated as a path to route to.

   Inlining that as a ternary inside .map() would put two nested conditionals in the
   middle of the card markup. planDestination() in lib/pricing.js decides WHERE, this
   decides WHICH ELEMENT, and the card just renders it.

   All three carry the same className, so the visitor sees one button either way. */
function PlanButton({ plan }) {
  const destination = planDestination(plan)
  const className = plan.featured ? 'btn-primary' : 'btn-secondary'

  if (destination.kind === 'route') {
    return (
      <Link className={className} to={destination.href}>
        {plan.cta}
      </Link>
    )
  }

  return (
    <a className={className} href={destination.href}>
      {plan.cta}
    </a>
  )
}

export default function Landing() {
  return (
    <div className="container-wide">
      {/* No `meta` any more. The "Sign in" link used to be passed from here, which
          meant a signed-in visitor to the landing page saw "Sign in" AND "Sign out"
          side by side — TopBar now owns both halves of that decision. See the
          comment beside the signed-out branch in TopBar.jsx. */}
      <TopBar />

      <main id="main">
        {/* --- Hero: the pitch, then straight into the scan form ------------- */}
        {/* id="scan" is the target of the Free plan's button further down the page.
            A CTA reading "Run a free scan" that goes anywhere other than the scan
            form is a button that lies. */}
        <section className="hero" id="scan">
          <h1 className="hero-title">
            Find the security holes in your web app before someone else does.
          </h1>
          <p className="hero-sub">
            SecuScan audits your site for the authentication and account-security
            weaknesses that most often go unnoticed — then explains each one in
            language you can act on, whether or not you write code.
          </p>

          {/* The scan input and its mandatory consent checkbox. */}
          <ScanForm />
        </section>

        {/* --- Three value points ------------------------------------------- */}
        <section className="value-grid">
          {/* [React] .map() over data to render repeated markup, with a `key` on
              each item so React can tell them apart. */}
          {VALUE_POINTS.map((point) => {
            /* Capitalised so JSX renders it as a component, not an HTML tag.
               Assigning to a capitalised variable is the standard way to use a
               component chosen from data. [React] */
            const Icon = point.icon

            return (
              <div className="value-card" key={point.title}>
                {/* The icon sits in a tinted square rather than floating as a bare
                    glyph, so it reads as a deliberate element and gives every card
                    the same anchor regardless of text length. A <span> wrapper is
                    needed because the box is 36px and the glyph inside is 20px —
                    sizing the svg itself could only do one or the other. */}
                <span className="value-icon" aria-hidden="true">
                  <Icon size={20} strokeWidth={2} />
                </span>
                <h3 className="value-title">{point.title}</h3>
                <p className="value-text">{point.text}</p>
              </div>
            )
          })}
        </section>

        {/* --- Pricing ------------------------------------------------------- */}
        {/* THE ID IS LOAD-BEARING and comes from lib/pricing.js rather than being
            typed here. Settings' "Upgrade" link and Checkout's three dead ends all
            point at "/#pricing", and this is the only thing in the app that makes
            that fragment resolve to anything. Renaming it in one place breaks four
            links silently — a wrong #fragment scrolls nowhere and reports nothing —
            so the string lives beside the function those callers already import. */}
        <section className="pricing" id={PRICING_ANCHOR}>
          <h2 className="section-heading">Plans</h2>
          <p className="section-sub">
            Tier 1 checks run from outside and need nothing but your permission.
            Tier 2 goes deeper into code, config and session behaviour, and only
            runs once you grant access.
          </p>

          <div className="pricing-grid">
            {PRICING_PLANS.map((plan) => (
              /* [React] Template literal builds the class list, appending
                 "featured" only for the highlighted plan. The `? :` TERNARY is a
                 compact if/else that works inside an expression. */
              <div
                className={`pricing-card ${plan.featured ? 'featured' : ''}`}
                key={plan.id}
              >
                {/* Only the featured plan gets the little ribbon. [React] */}
                {plan.featured && <span className="pricing-flag">Most popular</span>}

                <h3 className="plan-name">{plan.name}</h3>

                <div className="plan-price">
                  <span className="plan-amount">{plan.price}</span>
                  <span className="plan-cadence">{plan.cadence}</span>
                </div>

                <p className="plan-tagline">{plan.tagline}</p>

                {/* Which check depth this plan unlocks — keeps the billing plan
                    and the spec's Tier 1 / Tier 2 model visibly connected. */}
                <span className={`plan-tier tier-${plan.tier}`}>
                  Tier {plan.tier} checks
                </span>

                <ul className="plan-features">
                  {plan.features.map((feature) => (
                    <li key={feature}>
                      <Check size={14} strokeWidth={2} />
                      {feature}
                    </li>
                  ))}
                </ul>

                {/* WAS A DEAD BUTTON. The comment here used to read "MOCK: no
                    checkout yet", and it was accurate: a <button> with no onClick,
                    which a visitor deciding to pay would click and watch do nothing.
                    This is the line the whole session was for. */}
                <PlanButton plan={plan} />
              </div>
            ))}
          </div>
        </section>
      </main>

      {/* Outside <main> deliberately: a page footer is not part of the page's
          main content, and putting it inside would make the skip link land a
          keyboard user on a region that ends with the site's boilerplate.

          The definition lives in SiteFooter now, because the legal pages carry
          the same footer and Paddle's domain check looks for those links on the
          pages it checks. One component means the links cannot drift apart. */}
      <SiteFooter />
    </div>
  )
}
