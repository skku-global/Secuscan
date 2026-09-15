/* ============================================================================
   REFUND.JSX — the Refund Policy at /refund.

   WHY THE WINDOW IS 14 DAYS: the user suggested "7-14 days, your call". 14 was
   chosen because it is the standard consumer distance-selling cooling-off period
   in the UK and EU, so the policy does not have to explain why it is shorter than
   the law the customer may already have. Where a statutory right is longer than
   this window, the law wins and the policy says so rather than pretending
   otherwise.

   WHAT WAS VERIFIED RATHER THAN ASSUMED:
     - cancellation is end-of-period, not immediate (billing.py cancelAtPeriodEnd,
       confirmed against the frontend's Cancel button copy)
     - Paddle is Merchant of Record, so Paddle issues the refund
       (payments/paddle.py: "_environment", transactions API)
     - a plan downgrade does not delete scan history (scans are keyed by user id,
       not by plan)
   ========================================================================== */

import { Link } from 'react-router-dom'

import LegalPage from '../components/LegalPage'
import { CONTACT_EMAIL } from '../lib/pricing'

export default function Refund() {
  return (
    <LegalPage title="Refund Policy" updated="2026-09-12">
      <div className="legal-note">
        <p>
          <strong>In short:</strong> if you are not satisfied, tell us within{" "}
          <strong>14 days</strong> of a charge and we will refund it. Cancel any
          time from your billing settings &mdash; you keep the plan until the end of
          the period you already paid for, and you are not charged again.
        </p>
      </div>

      <h2>1. Scope</h2>
      <p>
        This policy covers payments for SecuScan subscriptions &mdash; the Starter
        and Business plans. The Free plan involves no payment. Enterprise
        arrangements are governed by the separate agreement you sign with us, which
        takes precedence over this page where the two differ.
      </p>

      <h2>2. Refunds within 14 days</h2>
      <p>
        If you are unhappy with a subscription charge, contact us within{" "}
        <strong>14 days</strong> of that charge and we will refund it in full. You
        do not have to justify the request, and you do not have to have found a
        fault with the service.
      </p>
      <p>
        This applies to a first charge and to any renewal charge &mdash; a renewal
        you did not expect is exactly the kind of charge this window is for. If you
        have paid for several months and only now decided the service is not for
        you, the 14-day window applies to the most recent charge; write to us
        anyway and we will look at the whole history with you rather than hiding
        behind the window.
      </p>

      <h2>3. Refunds after 14 days</h2>
      <p>
        Outside the 14-day window, subscription fees are generally non-refundable
        for the period already billed. We will still refund in these cases:
      </p>
      <ul>
        <li>
          <strong>We charged you in error</strong> &mdash; a duplicate charge, a
          charge after a cancellation you completed, or a charge for a plan you did
          not select.
        </li>
        <li>
          <strong>A paid feature was substantially unavailable</strong> for a
          sustained period during the month you paid for, and we could not fix it.
          A single interrupted or failed scan is not this; a month in which paid
          scanning did not work is.
        </li>
        <li>
          <strong>You were charged after asking us to cancel</strong>, where the
          request reached us in time to act on it.
        </li>
        <li>
          <strong>The law requires it.</strong> Where your local consumer law gives
          you a longer or stronger right of cancellation or refund than this policy,
          that law applies and this policy does not reduce it.
        </li>
      </ul>

      <h2>4. Cancelling your subscription</h2>
      <p>
        You can cancel at any time from your billing settings &mdash; there is no
        need to email us, and no retention call to sit through. When you cancel:
      </p>
      <ul>
        <li>
          <strong>You keep the plan until the end of the period you have paid
          for.</strong> Access does not stop the moment you click cancel. This is
          what your billing settings will show you, with the date your plan ends.
        </li>
        <li>
          <strong>You are not charged again.</strong> Cancellation stops the next
          renewal; it does not refund the current period. If you want the current
          period refunded as well and you are within 14 days of the charge, that is
          the request in section 2.
        </li>
        <li>
          <strong>Your data survives.</strong> Cancelling, or dropping to the Free
          plan when your paid period ends, does not delete your scan history or
          reports. Tier 1 scanning continues on the Free plan.
        </li>
      </ul>
      <p>
        If you cancel and then change your mind before the period ends, you can
        resubscribe; you may need to enter payment details again, as we hold none.
      </p>

      <h2>5. How to request a refund</h2>
      <p>
        Email <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a> from the
        address on your account, with the subject &ldquo;Refund request&rdquo;. It
        helps if you include the date of the charge and the plan, but if you cannot
        find them we can locate the payment from your account.
      </p>
      <p>
        We will acknowledge your request within <strong>2 business days</strong> and
        tell you our decision within <strong>5 business days</strong>. If we approve
        a refund we will also tell you the amount and where it is going.
      </p>
      <p>
        You can also write to us at the same address with any question about a
        charge before requesting a refund &mdash; if something on your statement
        does not look right, ask first and we will work it out.
      </p>

      <h2>6. How refunds are paid</h2>
      <p>
        Paddle is our Merchant of Record: Paddle is the seller of your subscription
        and processes the payment, so <strong>Paddle issues the refund</strong>{" "}
        against the original payment method. We never hold your card details and
        cannot send money to a card ourselves.
      </p>
      <p>
        A refund is normally back on your statement within{" "}
        <strong>5 to 10 business days</strong>, though the exact timing depends on
        your bank or card issuer, which is the part we cannot control. Refunds are
        made in the original currency of the charge; if your bank converts currency,
        a small difference in the returned amount can come from exchange rates
        rather than from the refund itself.
      </p>

      <h2>7. Chargebacks</h2>
      <p>
        If you believe a charge is wrong, please contact us before asking your bank
        to reverse it. A chargeback usually freezes the account while it is
        investigated and takes far longer than writing to us &mdash; and in almost
        every case we can simply refund you directly and much sooner.
      </p>

      <h2>8. Changes to this policy</h2>
      <p>
        We may update this policy. The change will not apply retroactively to a
        charge already made under the previous version, and we will update the date
        at the top of this page when it changes.
      </p>

      <div className="legal-contact">
        <p>
          Refund requests and billing questions go to{" "}
          <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>.
        </p>
        <p>
          See also our <Link to="/terms">Terms of Service</Link> and{" "}
          <Link to="/privacy">Privacy Policy</Link>.
        </p>
      </div>
    </LegalPage>
  )
}
