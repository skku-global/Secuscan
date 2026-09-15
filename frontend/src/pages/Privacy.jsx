/* ============================================================================
   PRIVACY.JSX — the Privacy Policy at /privacy.

   WHY THIS PAGE EXISTS: it is required for Paddle's domain verification, and more
   importantly it is the page that has to be TRUE. Every claim below was checked
   against the implementation rather than written from a template, because a
   privacy policy that describes a product other than the one running is worse
   than no policy: it is a written misstatement.

   THE SPECIFIC FACTS THAT WERE VERIFIED, and where:
     - session tokens live in localStorage, NOT a cookie  (lib/session.js)
     - Tier 2 credentials are Fernet-encrypted at rest     (credentials.py)
     - the 24-hour retention window is opt-in per scan     (ScanForm.jsx,
                                                            test_tier2_retention.py)
     - there is no analytics or tracking of any kind       (no match in either tree)
     - card details never reach this application           (payments/paddle.py)
   ========================================================================== */

import { Link } from 'react-router-dom'

import LegalPage from '../components/LegalPage'
import { CONTACT_EMAIL } from '../lib/pricing'

export default function Privacy() {
  return (
    <LegalPage title="Privacy Policy" updated="2026-09-12">
      <div className="legal-note">
        <p>
          <strong>In short:</strong> we collect the account details you give us and
          the scans you run. Test credentials for an access-gated audit are
          encrypted at rest and destroyed when the scan finishes unless you
          explicitly ask us to keep them for 24 hours. We never see your card
          details &mdash; Paddle handles payment. We run no analytics and no
          advertising trackers.
        </p>
      </div>

      <h2>1. Who we are</h2>
      <p>
        SecuScan (&ldquo;we&rdquo;, &ldquo;us&rdquo;) provides automated web
        security scanning. This policy explains what personal data we hold, why we
        hold it, who else sees it, and what you can ask us to do with it.
      </p>
      <p>
        The registered name and address of the business, and the jurisdiction whose
        data protection law governs us, will be published in this section before
        live billing is enabled. Until then, write to the address at the end of this
        page with any question about this policy.
      </p>

      <h2>2. What we collect</h2>

      <h3>Account information</h3>
      <ul>
        <li>
          <strong>Your email address</strong>, which identifies your account and is
          where we send security codes and service notices.
        </li>
        <li>
          <strong>Your name</strong>, if you give one when signing up.
        </li>
        <li>
          <strong>Your password, stored only as a hash.</strong> We never store the
          password itself and cannot recover it. If you sign up with Google we
          store no password at all.
        </li>
        <li>
          <strong>Two-factor authentication data</strong>, if you enable it: a TOTP
          shared secret, plus one-way hashes of your recovery codes. We can tell you
          how many recovery codes you have left, but we cannot show you the codes.
        </li>
        <li>
          <strong>Session records</strong>, so you can see where you are signed in
          and revoke a device.
        </li>
      </ul>

      <h3>Scan data</h3>
      <ul>
        <li>
          <strong>The target URL</strong> you asked us to scan, and when you asked.
        </li>
        <li>
          <strong>The findings</strong> the scan produced, and the report we
          generated from them.
        </li>
        <li>
          <strong>Access-gated test credentials, for Tier 2 scans only.</strong> If
          you supply a username and password so we can test authentication from the
          inside, those values are handled differently from everything else here
          &mdash; see section 3.
        </li>
      </ul>

      <h3>Billing information</h3>
      <p>
        <strong>
          We never see, receive or store your card number, expiry date or security
          code.
        </strong>{" "}
        Payment is handled entirely by Paddle, our Merchant of Record. What reaches
        us when a payment completes is limited to the outcome and a summary: which
        plan, whether the transaction succeeded, and the card&rsquo;s brand and last
        four digits so the receipt can identify which card was used. See section 5.
      </p>

      <h3>What we do NOT collect</h3>
      <p>
        We run <strong>no analytics, no advertising trackers, no session recording
        and no third-party marketing scripts</strong>. There is no cookie on this
        site used for tracking. Your session is carried in a token the application
        stores in your browser&rsquo;s local storage, which is sent to our API as a
        header &mdash; see section 7 for what that means on a shared computer.
      </p>

      <h2>3. Test credentials for access-gated scans</h2>
      <p>
        A Tier 2 audit works from the inside: it needs a test account on the target
        so it can examine what happens at login, how sessions behave, and whether
        account recovery can be abused. That means you may send us a username and
        password belonging to a test account. Those are the most sensitive values
        this application ever holds, so they are treated differently from everything
        else.
      </p>
      <ul>
        <li>
          <strong>Encrypted at rest.</strong> Credentials are encrypted with
          authenticated symmetric encryption (Fernet: AES-128-CBC with an
          HMAC-SHA256 authentication tag) before they are written to storage. A
          copy of the database alone does not reveal them.
        </li>
        <li>
          <strong>Destroyed by default.</strong> The credentials are deleted as soon
          as the scan that needed them finishes &mdash; the default is that nothing
          is kept.
        </li>
        <li>
          <strong>Kept for 24 hours only if you ask.</strong> At the point of
          submitting the credentials you may tick one box to retain them for 24
          hours, so an audit can be re-run after a fix without retyping them. If you
          do not tick it, nothing is retained. If you do, the record carries an
          expiry and is destroyed automatically when it passes.
        </li>
        <li>
          <strong>Never used for any other purpose</strong>, and never used against
          any target other than the one you submitted them for.
        </li>
        <li>
          <strong>Kept out of logs and out of URLs.</strong> Credential values are
          never written to an application log, never placed in a link, and are
          discarded from memory as soon as they are no longer needed for the scan.
        </li>
      </ul>
      <p>
        <strong>Please use a dedicated test account</strong> for access-gated
        scans, not a real user&rsquo;s account and not an administrator account you
        also use for other things. The credentials you submit should be ones whose
        exposure would not harm anyone.
      </p>

      <h2>4. Why we hold it, and our legal basis</h2>
      <ul>
        <li>
          <strong>To provide the service you asked for</strong> &mdash; running your
          scans, storing your reports, showing your history. This is performance of
          our contract with you.
        </li>
        <li>
          <strong>To keep accounts secure</strong> &mdash; authentication,
          two-factor, blocking repeated failed logins, and rate limits that protect
          the service from abuse. This is our legitimate interest in keeping the
          service and your account safe.
        </li>
        <li>
          <strong>To take payment</strong> &mdash; billing for a paid plan. This is
          performance of our contract, and part of it is a legal obligation to keep
          records of transactions.
        </li>
        <li>
          <strong>To contact you about the service</strong> &mdash; security codes,
          receipts, and notices of a change to these policies or to your plan terms.
        </li>
      </ul>
      <p>
        We do not sell your personal data, and we do not use it to build advertising
        profiles.
      </p>

      <h2>5. Who else sees your data</h2>
      <p>
        We use a small number of service providers. Each one sees only what its job
        requires:
      </p>
      <ul>
        <li>
          <strong>Paddle</strong> &mdash; payments. Paddle acts as Merchant of
          Record, meaning Paddle is the seller of the subscription to you. Paddle
          receives your card details and billing information directly, and sends us
          back only what section 2 describes. Paddle&rsquo;s own privacy policy
          governs what it does with your payment data.
        </li>
        <li>
          <strong>Resend</strong> &mdash; transactional email. This is how a
          confirmation, a security code or a receipt reaches your inbox, so Resend
          processes your email address and the contents of those messages.
        </li>
        <li>
          <strong>MongoDB Atlas</strong> &mdash; database hosting. Your account
          record, scan history and (for the 24-hour window, if you opted in)
          encrypted credential records are stored in a managed database.
        </li>
        <li>
          <strong>Google</strong> &mdash; only if you choose to sign in with Google.
          If you use that option, Google confirms your identity to us and we receive
          your email address and name. We receive no password, and if you never use
          Google sign-in, Google receives nothing from us at all.
        </li>
      </ul>
      <p>
        We may also disclose data where the law requires it, or where it is
        necessary to investigate a breach of our{" "}
        <Link to="/terms">Terms of Service</Link> &mdash; in particular a scan run
        against a target without authorisation. We do not otherwise share your
        personal data with anyone.
      </p>

      <h2>6. How long we keep it</h2>
      <ul>
        <li>
          <strong>Account data</strong> is kept while your account exists, and is
          deleted when you ask us to close it.
        </li>
        <li>
          <strong>Scan results and reports</strong> are kept so your history stays
          useful, and we do not currently expire them automatically. You can ask us
          to delete a scan or your whole history at any time.
        </li>
        <li>
          <strong>Access-gated test credentials</strong> are deleted when the scan
          finishes, or after 24 hours if you opted to retain them. Nothing is kept
          beyond that.
        </li>
        <li>
          <strong>Session records</strong> are removed when you sign out, when you
          revoke a device, or when the session expires.
        </li>
        <li>
          <strong>Billing records</strong> are retained as long as tax and
          accounting law requires, which is a period we cannot shorten. These are
          held by Paddle as Merchant of Record.
        </li>
      </ul>

      <h2>7. Security, and what you should know about your browser</h2>
      <p>
        Passwords are stored as one-way hashes. Test credentials are encrypted at
        rest. Sessions can be revoked individually or all at once, and we recommend
        enabling two-factor authentication, which is available in your settings.
      </p>
      <p>
        <strong>Your session is stored in your browser&rsquo;s local storage</strong>{" "}
        rather than a cookie. Practically, this means two things worth knowing: the
        session is not protected by the browser&rsquo;s cookie restrictions, and any
        script running on a page of this site could read it. We ship no third-party
        scripts, so nothing else should ever be running on these pages &mdash; but on
        a shared or public computer you should sign out when you are done, which
        clears the stored session.
      </p>
      <p>
        We also use local storage to remember which colour theme you picked. That
        value never leaves your browser.
      </p>

      <h2>8. Your rights</h2>
      <p>
        Depending on where you live, you have some or all of the following rights
        over your personal data:
      </p>
      <ul>
        <li>
          <strong>Access</strong> &mdash; to know what we hold about you.
        </li>
        <li>
          <strong>Correction</strong> &mdash; to have inaccurate data put right.
        </li>
        <li>
          <strong>Deletion</strong> &mdash; to have your account and its data
          erased.
        </li>
        <li>
          <strong>Portability</strong> &mdash; to receive a copy of your data in a
          usable format.
        </li>
        <li>
          <strong>Objection</strong> &mdash; to object to processing we base on
          legitimate interests.
        </li>
        <li>
          <strong>Withdrawal of consent</strong> &mdash; where we rely on consent.
        </li>
      </ul>
      <p>
        <strong>
          To exercise any of these, email us at the address at the end of this page.
        </strong>{" "}
        We will respond within 30 days. We may need to verify that the request comes
        from the account holder before we act on it, because a deletion request that
        anyone could send about anyone would be a way to destroy somebody
        else&rsquo;s account.
      </p>
      <p>
        If you are in the UK or EU and are not satisfied with our response, you have
        the right to complain to your national data protection authority.
      </p>

      <h2>9. Children</h2>
      <p>
        SecuScan is a business tool and is not intended for children. We do not
        knowingly collect personal data from anyone under the age required to enter a
        binding contract in their jurisdiction. If you believe a child has created an
        account, write to us and we will remove it.
      </p>

      <h2>10. Changes to this policy</h2>
      <p>
        If we change how we handle personal data, we will update the date at the top
        of this page. If the change is material &mdash; particularly anything
        affecting test credentials &mdash; we will tell account holders by email
        before it takes effect.
      </p>

      <div className="legal-contact">
        <p>
          Privacy questions, data requests and deletion requests go to{" "}
          <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>.
        </p>
        <p>
          See also our <Link to="/terms">Terms of Service</Link> and{" "}
          <Link to="/refund">Refund Policy</Link>.
        </p>
      </div>
    </LegalPage>
  )
}
