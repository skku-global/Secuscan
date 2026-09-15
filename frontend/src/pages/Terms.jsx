/* ============================================================================
   TERMS.JSX — the Terms of Service at /terms.

   WHY THIS PAGE EXISTS: Paddle requires a reachable Terms before it will enable
   live checkout on a domain, and beyond that requirement a paid product with no
   published terms is one a buyer has no basis to trust.
   ========================================================================== */

import { Link } from 'react-router-dom'

import LegalPage from '../components/LegalPage'
import { CONTACT_EMAIL } from '../lib/pricing'

export default function Terms() {
  return (
    <LegalPage title="Terms of Service" updated="2026-09-12">
      <div className="legal-note">
        <p>
          <strong>In short:</strong> you may only scan websites you own or have
          written permission to test. Paid plans are billed monthly through Paddle
          and you can cancel at any time, keeping access until the end of the
          period you have already paid for.
        </p>
      </div>

      <h2>1. Who these terms are between</h2>
      <p>
        These terms govern your use of SecuScan (the &ldquo;Service&rdquo;), a web
        security scanning service operated by the SecuScan team
        (&ldquo;we&rdquo;, &ldquo;us&rdquo;). By creating an account, running a
        scan, or subscribing to a paid plan, you agree to them.
      </p>
      <p>
        If you are agreeing on behalf of a company or another organisation, you
        confirm that you have the authority to bind that organisation to these
        terms.
      </p>

      <h2>2. What the Service is</h2>
      <p>
        SecuScan performs automated security audits of web applications and
        produces a report of what it found, ordered by severity, with a suggested
        fix for each finding.
      </p>
      <p>Audits run at one of two depths:</p>
      <ul>
        <li>
          <strong>Tier 1</strong> is an external audit. It inspects only what any
          visitor to your site can see, using standard GET requests. It never
          attempts to log in, never submits a form, and never modifies anything.
        </li>
        <li>
          <strong>Tier 2</strong> is an access-gated audit. It examines
          authentication, session handling and account-security behaviour, and it
          runs only when you supply test credentials for a target you are
          authorised to test.
        </li>
      </ul>

      <h2>3. You must be authorised to scan a target</h2>
      <div className="legal-note">
        <p>
          <strong>This is the condition the Service depends on.</strong> You may
          only scan a website that you own or that you hold written authorisation
          to test. Every scan requires you to confirm that authorisation before it
          will run.
        </p>
      </div>
      <p>
        Unauthorised scanning of computer systems is a criminal offence in many
        jurisdictions, including under the Computer Fraud and Abuse Act in the
        United States and the Computer Misuse Act in the United Kingdom. The
        confirmation you give is a statement of fact, and we rely on it.
      </p>
      <p>
        If we have reasonable grounds to believe a target was scanned without
        authorisation, we may suspend the account, stop any scheduled scans, and
        cooperate with a lawful request from the target&rsquo;s owner or from law
        enforcement.
      </p>

      <h2>4. Acceptable use</h2>
      <p>You agree not to:</p>
      <ul>
        <li>scan any target you are not authorised to scan;</li>
        <li>
          use the Service to build a list of vulnerable systems, or to scan
          addresses in bulk for the purpose of finding targets;
        </li>
        <li>
          attempt to overload, circumvent the rate limits of, or otherwise
          interfere with the Service or the infrastructure it runs on;
        </li>
        <li>
          resell, sublicense or provide the Service to third parties as your own
          unless we have agreed that in writing;
        </li>
        <li>
          use the Service where doing so would breach an obligation you already
          owe to somebody else.
        </li>
      </ul>
      <p>
        Our scans are deliberately rate-limited and non-destructive. You must not
        attempt to exceed those limits, and any attempt to do so is a breach of
        these terms.
      </p>

      <h2>5. Your account</h2>
      <p>
        You are responsible for keeping your password confidential and for
        everything that happens under your account. We recommend enabling
        two-factor authentication, which is available in your account settings. Tell
        us promptly at the address at the end of this page if you believe your
        account has been accessed without your permission.
      </p>
      <p>
        You must be old enough to enter into a binding contract in your
        jurisdiction to hold an account, and the information you give us must be
        accurate.
      </p>

      <h2>6. Plans, billing and cancellation</h2>
      <p>
        SecuScan offers a Free plan and the paid Starter, Business and Enterprise
        plans described on our pricing page. Paid plans are billed monthly in
        advance in US dollars.
      </p>
      <p>
        <strong>Paddle is our Merchant of Record.</strong> Paddle sells the
        subscription to you, processes your payment, and handles any applicable
        sales tax or VAT. Your card is charged by Paddle, not by us &mdash; see{" "}
        <Link to="/privacy">the Privacy Policy</Link> for what that means for your
        card details.
      </p>
      <p>
        <strong>
          Cancellation takes effect at the end of the period you have already paid
          for.
        </strong>{" "}
        When you cancel, the subscription is set to cancel at the end of the
        current billing period. You keep full access to the plan until that date,
        you are not charged again, and the account then returns to the Free plan.
        We do not delete your scan history when a plan lapses.
      </p>
      <p>
        If you change plan, the change takes effect as described at checkout.
        Refunds are covered by our <Link to="/refund">Refund Policy</Link>.
      </p>
      <p>
        We may change prices or plan features in future. If we change the price of
        a plan you are on, we will give you notice before it applies to you, and you
        can cancel before the change takes effect.
      </p>

      <h2>7. What a report does and does not tell you</h2>
      <p>
        <strong>
          A SecuScan report is informational guidance, not a guarantee.
        </strong>{" "}
        It describes weaknesses that automated checks can detect from outside your
        application, and where you have granted access, from inside a test account.
        It cannot find everything. It is not a penetration test, it is not a
        certification, and a clean report does not mean your application is secure.
      </p>
      <p>
        Findings are produced automatically and may occasionally be wrong &mdash;
        a check can report something that is not exploitable in your particular
        configuration, or miss something that is. Treat every finding as a lead to
        investigate rather than a verdict.
      </p>
      <p>
        We are not liable for vulnerabilities that were not detected, nor for any
        consequence of acting, or not acting, on what a report says.
      </p>

      <h2>8. Availability</h2>
      <p>
        We aim to keep the Service available but we do not promise uninterrupted
        service. Scans may be delayed or refused if a target rate-limits or blocks
        us. We may suspend the Service for maintenance, or decline to scan a
        particular target where we have a legitimate reason to.
      </p>

      <h2>9. Limitation of liability</h2>
      <p>
        To the fullest extent permitted by law, we are not liable for indirect,
        incidental, special or consequential damages, or for lost profits, lost
        revenue, lost data or business interruption, arising out of or relating to
        your use of the Service.
      </p>
      <p>
        Our total liability to you for any claim relating to the Service is limited
        to the amount you paid us for the Service in the twelve months before the
        event giving rise to the claim.
      </p>
      <p>
        Nothing in these terms excludes or limits liability that cannot lawfully be
        excluded or limited, including liability for death or personal injury
        caused by negligence, or for fraud.
      </p>

      <h2>10. Suspension and termination</h2>
      <p>We may suspend or terminate your access to the Service if:</p>
      <ul>
        <li>you breach these terms, including the authorisation requirement;</li>
        <li>
          we are required to by law, or by a lawful request from an authority;
        </li>
        <li>
          your account is being used in a way that creates a risk to the Service,
          to another customer, or to the security of a third party.
        </li>
      </ul>
      <p>
        Where it is reasonable to do so, we will tell you why and give you the
        opportunity to put it right. You may stop using the Service and close your
        account at any time by writing to us at the address below. Section 11 sets
        out what happens to your data afterwards, and section 6 explains that
        cancelling a paid plan is not the same as closing your account.
      </p>

      <h2>11. Changes to these terms</h2>
      <p>
        We may update these terms as the Service changes. If we make a material
        change, we will update the date at the top of this page and, where the
        change affects a paid plan, tell you by email before it takes effect.
        Continuing to use the Service after a change means you accept the updated
        terms.
      </p>

      <h2>12. Governing law</h2>
      <p>
        These terms are governed by the laws of the jurisdiction in which the
        SecuScan business is established, and the courts of that jurisdiction have
        exclusive jurisdiction over any dispute. The specific jurisdiction, and the
        registered name and address of the business, will be published in this
        section before live billing is enabled.
      </p>

      <div className="legal-contact">
        <p>
          Questions about these terms, or about anything on this page, go to{" "}
          <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>.
        </p>
        <p>
          See also our <Link to="/privacy">Privacy Policy</Link> and{" "}
          <Link to="/refund">Refund Policy</Link>.
        </p>
      </div>
    </LegalPage>
  )
}
