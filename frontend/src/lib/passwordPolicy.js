/* ============================================================================
   PASSWORDPOLICY.JS — the password rules, as the browser sees them.

   WHY THIS EXISTS: someone typing a password needs to know whether it will be
   accepted BEFORE they press the button. Finding out from a server error, after
   filling in four other fields, is the version of this experience everyone has
   suffered and nobody wants.

   THIS IS NOT THE SECURITY CONTROL. The identical rules live in the backend, in
   auth.py's password_problem(), and that copy is the one that decides anything.
   Everything here can be bypassed by anyone willing to open devtools or use
   curl — so this file exists purely to be helpful, and the server exists to be
   right. That split is worth internalising: a check in the browser is UX, and a
   check on the server is security. The same rule written in both places is not
   redundant, it is two different jobs.

   [General] Plain functions over strings, no React. So the rules can be reused
   by any future page (a change-password screen, say) without dragging component
   state along with them.
   ========================================================================== */

// Mirrors PASSWORD_MIN_LENGTH in backend/auth.py. If one moves, both move.
export const PASSWORD_MIN_LENGTH = 12

/* The same shortlist as the backend, for the same reason: it catches the first
   handful of guesses an attacker makes. Kept identical so the browser never
   promises to accept something the server will refuse. */
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', 'passw0rd', 'letmein',
  'qwerty', 'qwertyuiop', '111111', '123456', '1234567', '12345678',
  '123456789', '1234567890', 'iloveyou', 'admin', 'administrator',
  'welcome', 'welcome1', 'monkey', 'dragon', 'football', 'baseball',
  'sunshine', 'princess', 'changeme', 'trustno1', 'abc123', 'abcd1234',
  'secuscan', 'secuscan1', 'secuscan123', 'secret', 'starwars',
])

/* WHY THIS EXISTS: pulls the pieces of an identity a password should not
   contain. Same logic as _personal_strings() in auth.py.

   [General] .split('@')[0] takes the part before the at-sign — the local part of
   the address, which is what people actually reuse as a password. Fragments
   shorter than three characters match far too much to be meaningful. */
function personalStrings(email, name) {
  const localPart = email.split('@')[0].trim().toLowerCase()

  // [General] .split(/\s+/) splits on any run of whitespace, so a double space
  // in a typed name does not produce an empty entry.
  const nameParts = name.trim().toLowerCase().split(/\s+/)

  return [localPart, ...nameParts].filter((value) => value.length >= 3)
}

/* WHY THIS EXISTS: the one function the UI calls. It answers two different
   questions at once, and keeping them distinct is the whole design:

     - `requirements` — will this be ACCEPTED? Four pass/fail rules, mirroring
       the server exactly. This is what the checklist under the field renders.
     - `label` — how much margin is there BEYOND acceptable? Length is the only
       honest input to that, so it is the only thing this looks at.

   The distinction matters because a strength meter that just says "Strong"
   teaches nothing, and a bare list of rules gives no reason to exceed them. The
   bar tracks the rules; the word rewards going further. */
export function checkPassword(password, { email = '', name = '' } = {}) {
  const lower = password.toLowerCase()

  // [General] /[^a-zA-Z]/ is "any character that is NOT a letter" — the ^ inside
  // square brackets negates the set. .test() returns a boolean, unlike .match().
  const hasLetter = /[a-zA-Z]/.test(password)
  const hasOther = /[^a-zA-Z]/.test(password)

  // Strip digits and symbols before checking the common list, exactly as the
  // server does: a 12-character minimum turns "letmein" into "letmein1234", and
  // without this the list would never match anything long enough to be typed.
  const lettersOnly = lower.replace(/[^a-z]/g, '')

  const containsPersonal = personalStrings(email, name).some((personal) =>
    lower.includes(personal),
  )

  /* An array of objects rather than four booleans, so the component can .map()
     over it and the wording lives here next to the rule it describes — instead
     of drifting apart in JSX. [React] */
  const requirements = [
    {
      id: 'length',
      label: `At least ${PASSWORD_MIN_LENGTH} characters`,
      met: password.length >= PASSWORD_MIN_LENGTH,
    },
    {
      id: 'variety',
      label: 'A number or symbol, not only letters',
      met: hasLetter && hasOther,
    },
    {
      id: 'uncommon',
      label: 'Not a commonly guessed password',
      met: password.length > 0 && !COMMON_PASSWORDS.has(lower) && !COMMON_PASSWORDS.has(lettersOnly),
    },
    {
      id: 'impersonal',
      label: 'Nothing from your name or email',
      met: password.length > 0 && !containsPersonal,
    },
  ]

  const metCount = requirements.filter((requirement) => requirement.met).length
  const accepted = metCount === requirements.length

  return {
    requirements,
    metCount,
    accepted,
    /* Deliberately not a percentage or a number of "bits". Entropy estimates on
       human-chosen passwords are guesswork dressed up as arithmetic, and showing
       one implies a precision nobody has. A short phrase is honest. */
    label: describeStrength(password, metCount, requirements.length),
  }
}

/* WHY THIS EXISTS: turns an accepted password into a sense of how much room it
   has beyond the minimum. Extracted so checkPassword() reads as one thought.

   The thresholds are about length only, because length is the property that
   actually multiplies an attacker's work — every extra character is another
   whole factor of the search space.

   WHY THE UNACCEPTED CASE COUNTS RATHER THAN JUDGING. It used to read "Not
   accepted yet", which was reported as confusing, and the report was right: it
   announces a verdict without a remedy, so it reads as "something is wrong with
   this form" rather than "you are three characters short". Sitting directly above
   a half-filled bar, it looks like the page is stuck.

   A count is the honest version of the same sentence. It says progress is being
   made, says exactly how much is left, and points at the checklist below — which
   is where the specific answer already was. */
function describeStrength(password, metCount, total) {
  if (password.length === 0) return ''

  if (metCount < total) {
    const left = total - metCount

    /* [General] The ternary is the singular/plural fix. "1 requirements left" is
       the kind of small wrongness that makes an otherwise careful page feel
       unfinished — which is precisely the impression this whole line is being
       rewritten to avoid. */
    return left === 1 ? '1 requirement left' : `${left} requirements left`
  }

  if (password.length < 16) return 'Meets the minimum'
  if (password.length < 20) return 'Strong'
  return 'Very strong'
}
