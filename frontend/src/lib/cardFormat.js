/* ============================================================================
   CARDFORMAT.JS — how a card number looks while it is being typed.

   WHY THIS EXISTS: a card is printed in groups — 4242 4242 4242 4242 — and a
   16-digit run with no spaces is genuinely hard to check against the plastic in
   your hand. Grouping as the user types is the difference between spotting a
   transposed digit and submitting it.

   ---------------------------------------------------------------------------
   EVERYTHING IN THIS FILE IS COSMETIC. None of it validates anything.

   That is worth stating at the top because the functions LOOK like validation:
   there is a brand table and a CVC length, and both mirror something real in
   backend/billing.py. The difference is what happens when they are wrong. A brand
   this file fails to recognise shows a generic label and the payment proceeds
   exactly as before, because billing.card_brand on the server decides the brand
   that gets recorded. A CVC length this file gets wrong caps a text field two
   digits short, which is annoying and not a security event.

   The rule that matters: THE SERVER REJECTS BAD CARDS, and it is the only thing
   that does. billing.card_problem runs Luhn, the digit-count range, the expiry
   parse and the CVC length, and it runs whatever this file did or did not do.
   Nothing here is allowed to be the reason a payment is accepted.

   Which is also why there is no Luhn check in this file. It would be a second
   implementation of the one check on the page that is genuinely load-bearing, and
   a browser copy of a security check is a copy that eventually disagrees with the
   original — and the argument for "we already checked" is how the original gets
   deleted.

   ---------------------------------------------------------------------------
   AND THE CARD NUMBER GOES NOWHERE. These functions take a string and return a
   string. Nothing here stores, logs, or reports — the number lives in one piece
   of React state and in one fetch body, and that is the whole of its existence in
   the browser. See the note above checkout() in api.js.
   ========================================================================== */

/* Every non-digit removed. [General] `\D` is "any character that is not a digit",
   and the `g` flag replaces every match rather than the first — without it, typing
   two spaces would leave one behind. Same normalisation as _digits_only in
   billing.py, and for the same reason: people type the spaces the card is printed
   with, and that must not decide whether the form works. */
export function digitsOnly(value) {
  return (value ?? '').replace(/\D/g, '')
}

/* American Express prints 15 digits in a 4-6-5 pattern and everyone else prints 16
   in fours. Getting this wrong is not a failure — it is a number grouped oddly —
   but it is the detail that makes an Amex feel unhandled. */
const AMEX_GROUPS = [4, 6, 5]
const DEFAULT_GROUPS = [4, 4, 4, 4]

/* WHY A LOOSE TEST AND NOT THE SERVER'S FULL TABLE: this picks a label and a
   grouping, so a prefix it misses costs a generic label. The server's _BRANDS is
   the list that reaches the database, and copying all seven entries here would be
   seven more things to keep in step for no gain. */
const DISPLAY_BRANDS = [
  ['Visa', /^4/],
  ['Mastercard', /^(5[1-5]|2[2-7])/],
  ['American Express', /^3[47]/],
  ['Discover', /^(6011|64[4-9]|65)/],
]

/* The brand to show beside the field, or '' when there is nothing to say yet.

   RETURNS AN EMPTY STRING RATHER THAN "Card" for an unrecognised number, which is
   the one place this deliberately differs from the server. billing.card_brand has
   to return something storable; this only has to decide whether to show a label,
   and "Card" beside a card field is noise. */
export function displayBrand(value) {
  const digits = digitsOnly(value)

  if (digits.length < 2) return ''

  for (const [name, pattern] of DISPLAY_BRANDS) {
    if (pattern.test(digits)) return name
  }

  return ''
}

/* How many digits the CVC has. Amex prints four on the front, everyone else three
   on the back — the one place the brand has a functional consequence, and it is
   only a `maxLength` and a hint. The server checks the real length. */
export function cvcLength(cardNumber) {
  return displayBrand(cardNumber) === 'American Express' ? 4 : 3
}

/* The longest a card number gets, in digits. UnionPay runs to 19, so the input's
   cap has to allow it — an input that silently refuses the 18th digit of a real
   card is a bug the user cannot diagnose. */
const MAX_CARD_DIGITS = 19

/* "4242424242424242" → "4242 4242 4242 4242".

   [General] The loop walks the group sizes, slicing off each one in turn. Anything
   past the last group (a 19-digit UnionPay number against a 16-digit pattern) is
   appended as a final group rather than dropped — dropping digits the user typed
   is the one behaviour a formatter must never have. */
export function formatCardNumber(value) {
  const digits = digitsOnly(value).slice(0, MAX_CARD_DIGITS)

  const groups = displayBrand(digits) === 'American Express' ? AMEX_GROUPS : DEFAULT_GROUPS

  const parts = []
  let index = 0

  for (const size of groups) {
    if (index >= digits.length) break

    parts.push(digits.slice(index, index + size))
    index += size
  }

  // Whatever is left over, in one piece. See above.
  if (index < digits.length) parts.push(digits.slice(index))

  return parts.join(' ')
}

/* "1228" → "12/28", and "1" → "1" so the slash does not appear before the month is
   even typed.

   WHY THE SLASH IS INSERTED RATHER THAN TYPED: on a phone the numeric keypad has
   no slash, and a field that demands one is a field that cannot be completed
   without switching keyboards. billing.py's _parse_expiry accepts "1228" happily —
   this is for the person reading the field back, not for the parser. */
export function formatExpiry(value) {
  const digits = digitsOnly(value).slice(0, 4)

  if (digits.length <= 2) return digits

  return `${digits.slice(0, 2)}/${digits.slice(2)}`
}

/* Cents to "$49.00".

   WHY THE FRONTEND FORMATS ITS OWN rather than using the server's format_amount:
   the number crosses as an integer, which is the value that matters, and a
   pre-formatted string would have to carry a locale decision the server has no
   basis for making. What must never happen is the frontend inventing the FIGURE —
   this takes one it was given.

   [General] Intl.NumberFormat is the browser's own currency formatter: it knows
   that USD shows two decimals and JPY shows none, which is exactly the kind of
   rule that gets hardcoded wrong. */
export function formatAmount(amountCents, currency = 'USD') {
  if (amountCents === null || amountCents === undefined) return 'Custom pricing'

  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency,
  }).format(amountCents / 100)
}


/* "month" -> " / month". The other half of a price: formatAmount() above gives the
   figure, this gives what the figure is per.

   IT LIVED IN Checkout.jsx AND ITS COMMENT PREDICTED THIS MOVE — "a tiny function
   because the alternative is the same ternary written in three places, and the third
   one is where it gets written backwards." The Settings billing panel is the second
   place, so it moved here beside formatAmount rather than being copied.

   IT ALSO HAD A LATENT BUG, worth writing down because the move is what exposed it.
   The original was `interval === 'yearly' ? ' / year' : ' / month'`, so EVERY value
   that was not 'yearly' produced " / month" — including 'forever' and 'custom', which
   are the intervals billing.PLANS gives Free and Enterprise. It never misbehaved
   because its one caller only ever passed an order's interval, and an order only
   exists for a plan that is billed monthly. Rendering a plan rather than an order is
   what makes 'forever' reachable, and "$0.00 / month" for the Free plan would have
   been the result.

   So the recurring intervals are named explicitly and everything else returns '' —
   which is right for 'forever' and 'custom', and is also the safe answer for a value
   this function has not been taught: no suffix is a partial truth, and the wrong
   suffix is a wrong price. */
export function intervalSuffix(interval) {
  if (interval === 'month' || interval === 'monthly') return ' / month'
  if (interval === 'year' || interval === 'yearly') return ' / year'

  return ''
}
