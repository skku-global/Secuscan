"""
PASSWORD POLICY CHECK - spec section 7, Tier 1.

WHY THIS FILE EXISTS
A password is the one secret standing between a stranger and an account, and the rules
a site sets around it decide how much that secret is worth. A form that accepts "cat"
is a form whose accounts can be guessed; a form that caps the password at ten
characters has put a ceiling on how strong any account can ever be.

WHAT MODERN GUIDANCE ACTUALLY SAYS - READ THIS BEFORE JUDGING THE VERDICTS
The obvious version of this check is wrong, and it is worth saying why in the file
that could have shipped it. The intuitive rules - demand an uppercase letter, a digit
and a symbol; expire passwords every 90 days - are the rules NIST SP 800-63B now
advises AGAINST, because of what they do to real users:

  - composition rules produce predictable passwords. Forced to add a capital and a
    number, people write "Password1!". The rule adds a few bits of entropy in theory
    and almost none in practice, because everybody satisfies it the same way.
  - forced rotation makes passwords worse. A user made to change quarterly picks
    something they can increment: "Spring2024", "Summer2024".
  - LENGTH is what actually buys strength, and it is the one thing a user can supply
    cheaply. A four-word passphrase beats "P@ss1" by an enormous margin.

So this check does NOT penalise a site for having no complexity requirements. It
reports them when it finds them, notes that they are no longer recommended, and scores
on the things that genuinely matter:

  1. is there a visible MINIMUM, and is it at least 8 characters,
  2. is there a MAXIMUM low enough to cap real passwords,
  3. is the browser's password manager obstructed,
  4. does a pattern forbid characters a strong passphrase would use.

WHY THE MAXIMUM IS THE STRONGEST SIGNAL HERE
Everything else on this list is advisory: `minlength` is a hint the server may or may
not enforce. `maxlength` is not advisory - the browser refuses the keystroke, so a
maxlength of 12 means no user of this form has a password longer than 12 characters,
whatever the server would have accepted. That is a directly observed cap on every
account, which is why it is weighted the way it is below.

WHAT THIS CHECK CANNOT SEE
It reads markup and page text. It cannot submit "cat" to find out whether the server
accepts it, cannot know whether the password is checked against a breach list, and
cannot see hashing. A site can enforce an excellent policy server-side and declare
none of it in HTML - so, as with mfa_check and rate_limit_check, this NEVER returns
critical, and "nothing was visible" is reported as exactly that rather than as "no
policy exists".
"""

import re

from ._finding import PASSED, SKIPPED, WARNING, finding_builder

CHECK_ID = "password_check"

_build_finding = finding_builder(CHECK_ID)


# --- The policy this check holds sites to -----------------------------------

# THE FLOOR, from NIST SP 800-63B: 8 characters for a user-chosen password. Below this
# the search space is small enough to brute-force offline if a hash ever leaks.
MIN_ACCEPTABLE_LENGTH = 8

# What is worth aiming for rather than merely accepting. Not a failure to miss - a
# minimum of 8 is reported as adequate - but named so the advice can be specific.
RECOMMENDED_MIN_LENGTH = 12

# NIST's guidance is that a service should accept at least 64 characters, which is
# room for a passphrase. A maxlength below this is a real constraint, but a generous
# one - plenty of sites cap at 32 or 40 with no practical harm.
GENEROUS_MAX_LENGTH = 64

# Below this the cap starts biting on ordinary passphrases: "correct horse battery"
# is 22 characters. A maximum here is a genuine limit on account strength, not a
# formality, and it is usually a sign of a fixed-width database column - which in turn
# hints the password may not be hashed, since a hash is a fixed length regardless.
CONSTRAINING_MAX_LENGTH = 24

# A stated minimum in the page's own words: "at least 8 characters", "minimum of 12
# characters", "8 or more characters", "must be 10+ characters".
#
# PYTHON-SPECIFIC: (?: ... ) is a NON-CAPTURING group - it groups for alternation
# without adding to the numbered groups, so the only captures here are the digits. That
# is what lets the code below read match.group(1) and match.group(2) without counting
# parentheses.
STATED_MINIMUM = re.compile(
    r"(?:at least|minimum(?: of)?|no fewer than|must be(?: at least)?|"
    r"should be(?: at least)?)\s+(\d{1,3})\s*(?:characters|chars|letters)"
    r"|(\d{1,3})\s*(?:\+|or more)\s*(?:characters|chars)",
    re.I,
)

# Composition rules, detected so they can be REPORTED rather than rewarded. Their
# presence is neither a pass nor a failure here - see the file header.
#
# WHY THIS NEEDS A REQUIREMENT CUE AND NOT JUST THE CLASS WORDS. The first version
# matched "symbol" on its own, and the e2e fixture caught it immediately: "Spaces and
# symbols are welcome" is a sentence PERMITTING symbols, and it was being recorded as a
# rule demanding one. A rule has to be phrased as a demand, so the cue is required
# first and the class word has to follow it inside the same sentence.
COMPOSITION_RULE = re.compile(
    # The demand ...
    r"(?:must (?:contain|include|have)|should (?:contain|include|have)|"
    r"needs? to (?:contain|include)|requires?|at least one|include at least|"
    r"combination of|mix(?:ture)? of)"
    # ... then anything up to the end of the sentence. [^.!?] cannot cross into the
    # next sentence, which stops a demand in one sentence pairing with a class word
    # in the one after it.
    r"[^.!?]{0,60}?"
    # ... then the class of character being demanded. "number" is deliberately only
    # matched WITH A COUNT: "must include your phone number" is not a password rule.
    r"(upper[\s\-]?case|lower[\s\-]?case|capital letter|special character|"
    r"symbol|punctuation|(?:one|two|a|\d+)\s+(?:number|digit)|numeric)",
    re.I,
)

# Wording that describes forced expiry, which is advised against for the same reason
# composition rules are: it makes users pick incrementable passwords.
#
# Anchored on the word "password" for the same reason as above - "your trial is valid
# for 30 days" is not a password policy.
ROTATION_RULE = re.compile(
    r"password[^.!?]{0,40}?(?:expires?|expiry|expiration|must be changed|"
    r"needs? to be changed|valid for \d+ days)"
    r"|(?:change|update|rotate) your password every",
    re.I,
)

# A `pattern` attribute that WHITELISTS characters, which is how a form ends up
# forbidding the spaces and symbols a passphrase wants. Two shapes cover almost every
# real instance:
#
#   \w           - "word characters": letters, digits and underscore, and NOTHING else.
#                  No space, no punctuation. pattern="\w{8,}" bans "correct horse".
#   [A-Za-z0-9]  - the same ban written out by hand.
#
# The lookahead guard at the use site is what keeps this from firing on
# ^(?=.*[A-Z]).{8,}$ - that contains [A-Z] but forbids nothing, because the .{8,} still
# accepts every character. It is a composition rule, reported separately below and
# deliberately not penalised.
ALNUM_ONLY_PATTERN = re.compile(r"\\w|\[(?:[A-Za-z0-9]|[A-Za-z]-[A-Za-z]|\d-\d)+\]")

MAX_TEXT = 200_000

# Field names that indicate a password box even when the input's type does not.
#
# PYTHON-SPECIFIC: \b is a word boundary, and _ counts as a WORD character - so
# r"password\b" does NOT match "password_hint", because there is no boundary between
# "d" and "_". That is worth naming, because the first version of this pattern ended
# every stem with \b and therefore matched almost no real field: production form names
# are full of underscores. The stems are matched without a trailing boundary instead,
# and the things that merely talk about a password are excluded by name at the use site.
PASSWORD_NAME = re.compile(r"pass(?:word|wd|phrase|code)|\bpass\b|pwd", re.I)

# Input types that are never a password box however they are named. A checkbox called
# "show_password" is the reveal toggle sitting NEXT TO the password field, not a
# password being typed in the clear.
NOT_AN_INPUT_BOX = ("password", "hidden", "checkbox", "radio", "submit", "button", "reset")


# --- Small helpers ----------------------------------------------------------


# PYTHON-SPECIFIC: int() raises ValueError on anything unparseable, and markup is
# arbitrary - minlength="eight" is legal HTML that a browser ignores. This returns None
# instead, so a malformed attribute is "no minimum stated" rather than a crashed check.
def _as_int(value) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# --- The check -------------------------------------------------------------


# WHY THIS TAKES THE ScanTarget AND MAKES NO REQUESTS
# The signup form is already parsed - discovery fetched the page, and Form/Field carry
# every attribute off each input (see Field.attrs). Tier 1 sends no POSTs, so there is
# no version of this check that submits a candidate password to see what happens; the
# markup and the page wording are the whole evidence base.
async def check_password(target) -> dict:
    pages = [
        (label, page)
        for label, page in (
            ("signup", target.signup),
            ("login", target.login),
            ("home", target.home),
        )
        if page is not None
    ]

    if not pages:
        return _build_finding(
            severity=SKIPPED,
            title="Could not check the password policy",
            description="No page content was retrieved",
            explanation=(
                "The scan retrieved no page bodies, so there was no form to read and no "
                "wording to read it from. Whether the site was reachable at all is "
                "reported by the other checks."
            ),
            fix="Confirm the site is reachable, then re-run the scan.",
            evidence={"pagesInspected": 0},
        )

    # WHICH FORM CARRIES THE POLICY, and why the distinction matters.
    #
    # A signup form's `minlength` IS the password policy: it is the rule applied when a
    # password is chosen. A login form's `minlength` is not - it only has to admit
    # passwords that already exist, so a login form with minlength=1 says nothing about
    # what the site allows at registration. Reading a minimum off the login form is how
    # this check would report a policy the site does not have.
    #
    # `maxlength` and `autocomplete` are different: they constrain what a user can TYPE,
    # so they matter on either form. A login form capped at 16 characters locks out
    # anyone whose password is longer, whatever registration allowed.
    signup_fields: list[tuple[str, object]] = []
    typing_fields: list[tuple[str, object]] = []

    for label, page in pages:
        for form in page.forms:
            for pw_field in form.password_fields():
                typing_fields.append((label, pw_field))

                # The signup form is the authority on the minimum. Identified by the
                # page it came from OR by the confirm-password shape, since plenty of
                # sites put registration somewhere discovery labelled "home".
                if label == "signup" or form.looks_like_signup():
                    signup_fields.append((label, pw_field))

        # The React case: a password input with no surrounding <form>, which discovery
        # carries separately. It constrains typing the same way.
        for pw_field in page.loose_password_fields:
            typing_fields.append((label, pw_field))

    # A PASSWORD BOX THAT IS NOT type="password" - looked for separately, because by
    # definition it is absent from password_fields(). The consequence is concrete: the
    # characters are visible on screen, and the browser stores the value in ordinary
    # form history where a password would never have been kept.
    cleartext_fields: list[dict] = []
    for label, page in pages:
        for form in page.forms:
            for any_field in form.fields:
                lowered = any_field.name.lower()
                if (
                    any_field.type not in NOT_AN_INPUT_BOX
                    and PASSWORD_NAME.search(any_field.name)
                    # Fields that TALK ABOUT a password rather than hold one:
                    # "password_hint", "forgot_password", "password_reset_token".
                    and not any(word in lowered
                                for word in ("hint", "forgot", "reset", "token", "csrf"))
                ):
                    cleartext_fields.append(
                        {"where": label, "name": any_field.name[:60], "type": any_field.type}
                    )

    if not typing_fields and not cleartext_fields:
        return _build_finding(
            severity=SKIPPED,
            title="No password field found to check",
            description="No sign-in or registration form was located",
            explanation=(
                "A password policy is a rule about a password field, and the scan found "
                "none on the pages it reached - so there is nothing here to hold to a "
                "policy.\n\nThis is a limit of what the scan could see rather than a "
                "finding. A site whose registration page lives somewhere the scan did "
                "not look would appear identical from outside."
            ),
            fix=(
                "No action from this check. If the site does have a registration or "
                "sign-in page, re-run the scan with its address supplied directly so "
                "this check can read it."
            ),
            evidence={
                "pagesInspected": [label for label, _ in pages],
                "signupFound": target.signup is not None,
            },
        )

    # --- Read the markup ----------------------------------------------------

    # PYTHON-SPECIFIC: a generator inside max() with a default. min()/max() raise
    # ValueError on an empty sequence, and default= is how that is avoided without a
    # length test first.
    declared_minimums = [
        value
        for _, pw_field in signup_fields
        if (value := _as_int(pw_field.attrs.get("minlength"))) is not None
    ]
    declared_maximums = [
        (label, value)
        for label, pw_field in typing_fields
        if (value := _as_int(pw_field.attrs.get("maxlength"))) is not None
    ]

    # THE LOWEST minimum and the LOWEST maximum are the ones that bind. If a site
    # declares minlength=8 on one field and 12 on another, 8 is what it accepts; if it
    # caps one field at 64 and another at 16, 16 is the real ceiling.
    markup_minimum = min(declared_minimums, default=None)
    lowest_maximum = min(declared_maximums, key=lambda pair: pair[1], default=None)

    # AUTOCOMPLETE. `off` on a password field is an attempt to stop the browser's
    # password manager, and its effect is the opposite of what it intends: a user who
    # cannot save a password picks one they can remember and reuses it. The correct
    # values are new-password on registration and current-password on sign-in, which
    # tell a manager what to offer.
    manager_blocked: list[dict] = []
    for label, pw_field in typing_fields:
        value = str(pw_field.attrs.get("autocomplete", "")).strip().lower()
        if value in ("off", "false", "none", "nope"):
            manager_blocked.append(
                {"where": label, "name": pw_field.name[:60], "autocomplete": value}
            )

    # A `pattern` that whitelists only letters and digits forbids the spaces and
    # symbols a passphrase uses. Only reported when a pattern is actually present -
    # having none is the normal, correct state.
    restrictive_patterns: list[dict] = []
    for label, pw_field in signup_fields:
        raw = str(pw_field.attrs.get("pattern", "")).strip()

        # A lookahead ASSERTS that something is present rather than restricting what is
        # allowed, so it bans no character - see the note on ALNUM_ONLY_PATTERN.
        if raw and "(?=" not in raw and "(?!" not in raw and ALNUM_ONLY_PATTERN.search(raw):
            restrictive_patterns.append({"where": label, "pattern": raw[:120]})

    # --- Read the wording ---------------------------------------------------

    stated_minimums: list[dict] = []
    composition_hits: list[dict] = []
    rotation_hits: list[dict] = []

    for label, page in pages:
        body_text = page.text[:MAX_TEXT]

        for match in STATED_MINIMUM.finditer(body_text):
            # PYTHON-SPECIFIC: this pattern has two alternatives with one capture each,
            # so exactly one of the groups is None on any given match. `or` picks the
            # one that fired.
            digits = match.group(1) or match.group(2)
            value = _as_int(digits)

            if value is not None and 1 <= value <= 256:
                stated_minimums.append(
                    {
                        "where": label,
                        "phrase": " ".join(match.group(0).split()),
                        "length": value,
                    }
                )

        for pattern, sink in ((COMPOSITION_RULE, composition_hits),
                             (ROTATION_RULE, rotation_hits)):
            match = pattern.search(body_text)
            if match is not None:
                sink.append(
                    {"where": label, "phrase": " ".join(match.group(0).split())}
                )

    # The lowest stated minimum binds, same reasoning as the markup.
    text_minimum = min((hit["length"] for hit in stated_minimums), default=None)

    # THE EFFECTIVE MINIMUM, and why markup wins a disagreement. `minlength` is what
    # the form enforces; a sentence is what the site says. Where they differ the
    # attribute is the one a user actually meets - but both are kept in the evidence,
    # because a site whose copy promises 12 and whose form accepts 6 has a bug worth
    # seeing.
    known_minimums = [v for v in (markup_minimum, text_minimum) if v is not None]
    effective_minimum = min(known_minimums) if known_minimums else None

    evidence = {
        "pagesInspected": [label for label, _ in pages],
        "signupFound": target.signup is not None,
        "minlengthAttribute": markup_minimum,
        "statedMinimums": stated_minimums,
        "effectiveMinimum": effective_minimum,
        "maxlengthAttribute": lowest_maximum[1] if lowest_maximum else None,
        "passwordManagerBlocked": manager_blocked,
        "restrictivePatterns": restrictive_patterns,
        "compositionRules": composition_hits,
        "rotationRules": rotation_hits,
        "cleartextPasswordFields": cleartext_fields,
        "method": "passive; no candidate passwords were submitted",
    }

    # --- Assemble the problems ---------------------------------------------
    #
    # Built as a list rather than decided in a chain of elifs, because a form can have
    # several of these at once and a report that mentions only the first is a report
    # that gets a second visit. The order is by how much each one costs an account.
    problems: list[str] = []
    strengths: list[str] = []

    if cleartext_fields:
        names = ", ".join(f"{hit['name']} (type={hit['type']})" for hit in cleartext_fields)
        problems.append(
            f"a password box is not marked type=\"password\" ({names}), so the "
            "characters are visible on screen and the browser keeps the value in "
            "ordinary form history"
        )

    if lowest_maximum is not None and lowest_maximum[1] <= CONSTRAINING_MAX_LENGTH:
        problems.append(
            f"the password field caps input at {lowest_maximum[1]} characters "
            f"(on the {lowest_maximum[0]} form), which is short enough to rule out a "
            "passphrase - and a low fixed cap often means the password is stored in a "
            "fixed-width column rather than hashed"
        )
    elif lowest_maximum is not None and lowest_maximum[1] < GENEROUS_MAX_LENGTH:
        problems.append(
            f"the password field caps input at {lowest_maximum[1]} characters "
            f"(on the {lowest_maximum[0]} form), below the 64 that current guidance "
            "asks services to accept"
        )

    if effective_minimum is not None and effective_minimum < MIN_ACCEPTABLE_LENGTH:
        problems.append(
            f"the shortest password accepted is {effective_minimum} characters, below "
            f"the {MIN_ACCEPTABLE_LENGTH} that is the current floor"
        )

    if manager_blocked:
        names = ", ".join(hit["name"] or "(unnamed)" for hit in manager_blocked)
        problems.append(
            f"autocomplete is switched off on a password field ({names}), which stops "
            "the browser's password manager saving it - users who cannot save a "
            "password choose one they can remember, and reuse it"
        )

    if restrictive_patterns:
        shown = ", ".join(hit["pattern"] for hit in restrictive_patterns)
        problems.append(
            f"a pattern attribute restricts the password to letters and digits "
            f"({shown}), which forbids the spaces and symbols a passphrase uses"
        )

    if rotation_hits:
        problems.append(
            f"the site describes forced password expiry (\"{rotation_hits[0]['phrase']}\"), "
            "which current guidance advises against - users made to change on a "
            "schedule pick passwords they can increment"
        )

    # WHAT COUNTS AS A STRENGTH. Only an observed minimum does. Note what is NOT here:
    # the presence of composition rules earns nothing, for the reasons in the header.
    if effective_minimum is not None and effective_minimum >= RECOMMENDED_MIN_LENGTH:
        strengths.append(
            f"a minimum of {effective_minimum} characters, which is above the floor and "
            "into the range where length does real work"
        )
    elif effective_minimum is not None and effective_minimum >= MIN_ACCEPTABLE_LENGTH:
        strengths.append(f"a minimum of {effective_minimum} characters, which meets the floor")

    if lowest_maximum is not None and lowest_maximum[1] >= GENEROUS_MAX_LENGTH:
        strengths.append(
            f"room for {lowest_maximum[1]} characters, which leaves space for a passphrase"
        )

    # A note that is neither a strength nor a problem, carried into the explanation so
    # the report says something useful about rules the site clearly worked at.
    composition_note = ""
    if composition_hits:
        composition_note = (
            "\n\nThis site also states composition requirements "
            f"(\"{composition_hits[0]['phrase']}\"). Those are not counted for or "
            "against it here: current guidance no longer recommends them, because "
            "forcing a capital and a digit mostly produces \"Password1!\" - the rule is "
            "satisfied the same way by everybody, so it adds far less than it appears "
            "to. Length is what buys strength. There is no need to remove the rules, "
            "but there is no need to add more either."
        )

    # --- The verdict --------------------------------------------------------
    #
    # NEVER CRITICAL, matching mfa_check and rate_limit_check. Everything above is
    # read off markup and page copy, and a site can enforce an excellent policy in
    # server code while declaring none of it in HTML. The strongest signal here -
    # maxlength, which the browser genuinely enforces - still caps a warning, because
    # a short maximum weakens accounts rather than exposing them.

    if problems:
        detail = "\n".join(f"- {problem}" for problem in problems)
        return _build_finding(
            severity=WARNING,
            title="The password policy has weaknesses",
            description=f"Found {len(problems)} problem(s) with the password rules",
            explanation=(
                "A password is the one secret between a stranger and an account, and "
                "the rules around it set how much that secret is worth. The scan found:"
                f"\n{detail}"
                + (
                    "\n\nIn the site's favour: " + "; ".join(strengths) + "."
                    if strengths
                    else ""
                )
                + composition_note
                + "\n\nStated carefully: this check reads the registration form's "
                "markup and the site's own wording. It submits nothing, so it cannot "
                "confirm what the server accepts - a site can enforce a stricter rule "
                "in code than it declares in HTML. The exception is the maximum "
                "length, which the browser itself enforces: where one was found, no "
                "user of that form has a longer password."
            ),
            fix=(
                "Set a minimum of at least 8 characters and prefer 12, accept at least "
                "64 so a passphrase fits, and allow every character including spaces "
                "and symbols. Drop any maxlength below 64 from the field. Leave "
                "autocomplete set to new-password on registration and "
                "current-password on sign-in so password managers work - a saved "
                "password is a stronger password. Do not add composition rules or "
                "forced expiry; if you want one more control, check new passwords "
                "against a breached-password list, which catches the weak ones that "
                "satisfy every rule."
            ),
            evidence=evidence,
        )

    # WHY THIS TESTS THE MINIMUM AND NOT `strengths`.
    #
    # A generous maxlength is a strength, but it is not a policy: a form that accepts up
    # to 64 characters and demands none is still a form that accepts "cat". Gating the
    # pass on an observed MINIMUM keeps "there is room for a good password" from being
    # reported as "there is a good password rule".
    #
    # Reaching here with a minimum also means it is at least MIN_ACCEPTABLE_LENGTH,
    # since anything shorter was added to `problems` and returned above.
    if effective_minimum is not None:
        detail = "\n".join(f"- {strength}" for strength in strengths)
        return _build_finding(
            severity=PASSED,
            title="The password policy looks reasonable",
            description=(
                f"A minimum of {effective_minimum} characters, with no problems found"
            ),
            explanation=(
                "The registration form declares a password policy, and what it "
                f"declares is sound:\n{detail}\n\nNothing was found working against "
                "it either: no low maximum capping how long a password can be, no "
                "attempt to switch off the browser's password manager, and no pattern "
                "forbidding the characters a passphrase needs."
                + composition_note
                + "\n\nWhat this does not confirm: the scan submits nothing, so it has "
                "read what the form DECLARES rather than tested what the server "
                "accepts, and it cannot see whether new passwords are checked against "
                "a list of known-breached ones. Both are worth verifying from the "
                "inside."
            ),
            fix=(
                "No action needed from this check. The most valuable thing to add next "
                "is a breached-password check at registration - it catches the weak "
                "passwords that satisfy every length and composition rule, which is "
                "the gap no policy closes on its own."
            ),
            evidence=evidence,
        )

    # NOTHING WAS DECLARED - no minlength, no minimum in the copy. Extremely common
    # markup, and it says nothing either way about what the server enforces.
    #
    # Reaching here, a maxlength can only be a GENEROUS one: anything below 64 was
    # counted as a problem above and returned. So the wording has to allow for a form
    # with plenty of room and no floor, which is a real and slightly odd combination -
    # rather than assert "no maximum either" and be wrong about it.
    if strengths:
        room = f" It does leave {lowest_maximum[1]} characters of room, but room to type a good password is not a rule requiring one."
    else:
        room = ""

    return _build_finding(
        severity=WARNING,
        title="No password policy was visible",
        description="The form declares no minimum length and none is documented",
        explanation=(
            "The scan found a password field, but nothing that says what it will "
            "accept: no minlength on the input and no minimum stated in the page "
            f"text.{room}\n\nThat matters because length is what makes a "
            "password worth anything. A form with no floor accepts \"cat\", and an "
            "account protected by \"cat\" is guessable in the time it takes to send the "
            "requests - which is also why this check and the rate-limiting check belong "
            "together: a weak password rule and an unlimited login form are the same "
            "vulnerability from two directions."
            + composition_note
            + "\n\nStated carefully: this is very common markup, and it does not mean "
            "the site accepts anything. Registration rules are usually enforced in "
            "server code, which is invisible from outside, and this check submits "
            "nothing. Treat it as a prompt to confirm the rule exists - and to declare "
            "it in the form, where it stops a weak password being typed rather than "
            "rejecting it afterwards."
        ),
        fix=(
            "Declare the rule in the form as well as enforcing it on the server: "
            "minlength=\"8\" or more on the password input gives immediate feedback "
            "instead of a failed submission. Accept at least 64 characters, allow every "
            "character including spaces, and check new passwords against a "
            "breached-password list - that single control catches more weak passwords "
            "than any composition rule."
        ),
        evidence=evidence,
    )
