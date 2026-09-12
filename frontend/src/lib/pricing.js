/* ============================================================================
   PRICING.JS — the plan cards on the landing page.

   WHY THIS FILE EXISTS: this was the last live export in mocks/scanData.js, and
   it is not a mock. The prices are the real intended prices, and as of this
   session the buttons work — Starter and Business go to /checkout/:planId, which
   is a real page posting to a real endpoint. What is still not real is the money:
   the server's only payment provider validates the SHAPE of a card and grants the
   plan without charging anything. See payments/mock_card.py, which is emphatic
   about it. So the data is real, the flow is real, and the charge is fictional.

   NOTE the distinction, because it is easy to conflate the two:
     - `tier` is the CHECK DEPTH from spec section 5 (Tier 1 external,
       Tier 2 access-gated).
     - a PLAN is a billing product. Several plans can grant the same tier.

   Prices are USD per month. Enterprise shows no number.
   ========================================================================== */

export const PRICING_PLANS = [
  {
    id: 'free',
    name: 'Free',
    price: '$0',
    cadence: 'forever',
    tier: 1,
    tagline: 'See real findings before you pay anything.',
    features: [
      'Tier 1 external audit',
      'All 7 external checks',
      'Full report + PDF export',
      '1 scan per month',
    ],
    cta: 'Run a free scan',
    featured: false,
  },
  {
    id: 'starter',
    name: 'Starter',
    price: '$49',
    cadence: 'per month',
    tier: 2,
    tagline: 'For a single product you want kept under watch.',
    features: [
      'Everything in Free',
      'Tier 2 full audit (access-gated)',
      'Up to 10 scans per month',
      '1 target site',
      'Email support',
    ],
    cta: 'Start with Starter',
    featured: false,
  },
  {
    id: 'business',
    name: 'Business',
    price: '$149',
    cadence: 'per month',
    tier: 2,
    tagline: 'For teams running several products at once.',
    features: [
      'Everything in Starter',
      'Unlimited scans',
      'Up to 10 target sites',
      'Scheduled recurring audits',
      'Priority support',
    ],
    cta: 'Choose Business',
    featured: true, // draws the highlighted border — the plan to steer people toward
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: 'Custom',
    cadence: 'contact us',
    tier: 2,
    tagline: 'For banks and regulated businesses.',
    features: [
      'Everything in Business',
      'Unlimited target sites',
      'Manual code review checklist',
      'VAT-compliant invoicing',
      'Named security contact',
    ],
    cta: 'Contact us',
    featured: false,
  },
]


/* ============================================================================
   WHERE EACH BUTTON GOES

   WHY THIS IS A FUNCTION HERE AND NOT A TERNARY IN Landing.jsx
   Three of the four plans go somewhere different, and for a different reason each
   time: two are bought, one is already owned by everyone, one is a conversation.
   That branch has to be identical on the landing page and inside Checkout.jsx —
   which independently decides whether a plan is buyable before rendering a card
   form. Two copies of "is this plan for sale" is how a Buy button ends up pointing
   at a page that then says the plan cannot be bought.

   THE SERVER STILL DECIDES. billing.PLANS carries `purchasable` and the checkout
   endpoint refuses anything without it, so this function is about which LINK to
   draw, never about what may be sold. Editing it cannot open a plan for purchase.

   The `kind` is what the caller renders, and the three values are genuinely three
   different HTML elements rather than a styling detail:

     'route'   an internal navigation → <Link to={href}>
     'anchor'  a place on the landing page → <a href={href}>, so the browser does
               the scrolling. React Router's <Link> does NOT scroll to a hash; a
               #fragment handed to it navigates and then sits at the top of the
               page, which looks like a broken button.
     'mailto'  an external handler → <a href={href}>, and never a <Link>, which
               would try to route "mailto:..." as a path.
   ========================================================================== */

/* The one address, reused rather than retyped. A second copy is a second thing to
   forget when it changes — and this file had already been proven right about that:
   Checkout.jsx's Enterprise branch hardcoded the old address instead of importing
   this, so a change here would have left that one button on a dead mailbox.

   RENAMED FROM SALES_EMAIL, because the address is no longer only for sales. The
   same mailbox now receives enterprise enquiries, the Settings contact form, and
   the "something went wrong" routes on the checkout screens, so a name describing
   one of those three would be wrong on the other two.

   The backend has its own copy in config.SUPPORT_EMAIL. That is not a duplicate of
   this: this is the address a BROWSER opens a mail client to, and that is the
   recipient the SERVER mails from the contact endpoint. Neither can read the
   other's, and the backend's is settable per deployment. */
export const CONTACT_EMAIL = 'admin@skkuglobal.com'

/* The id on Landing's pricing section, exported so the pages that link INTO it
   cannot drift from the page that defines it. Settings' "Upgrade" link is the
   caller that matters: it lives on another route, so it needs "/#pricing" and a
   plain <a>, for the scrolling reason above. */
export const PRICING_ANCHOR = 'pricing'

export function planDestination(plan) {
  /* Free is not bought, it is already there — every account has it from creation,
     which is why the CTA reads "Run a free scan" rather than "Buy". So the button
     goes to the thing it is inviting: the scan form at the top of the page. */
  if (plan.id === 'free') {
    return { kind: 'anchor', href: '#scan' }
  }

  /* No price exists to put on a button. Not "contact sales as well as paying" —
     there is genuinely no figure until somebody has talked to a customer, and
     billing.PLANS says the same by carrying amountCents: null. */
  if (plan.id === 'enterprise') {
    return {
      kind: 'mailto',
      /* encodeURIComponent, so a subject with a space or an ampersand in it does
         not truncate the mailto at the first special character. [General] */
      href: `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent('Enterprise plan')}`,
    }
  }

  return { kind: 'route', href: `/checkout/${plan.id}` }
}
