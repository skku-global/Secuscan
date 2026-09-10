"""
MULTI-FACTOR AUTHENTICATION PRESENCE CHECK - spec section 5, Tier 1.

WHY THIS FILE EXISTS
A password is one secret, and secrets leak - reused from a breached site, phished,
guessed. Multi-factor authentication is the answer to "the password was not enough":
a second factor the attacker does not have. Its ABSENCE is the single biggest gap in
most account systems, which is why "is MFA even offered" is worth a check of its own.

WHAT THIS CHECK CAN AND CANNOT SEE - READ THIS BEFORE TRUSTING THE RESULT
It cannot log in, so it cannot confirm MFA actually works. What it can do is read the
public evidence that MFA EXISTS: the words "two-factor", "authenticator", "verification
code" on the login and account pages, and the routes a site publishes for it
(/settings/security, /2fa, /mfa). That is indirect, and the severity is capped
accordingly - this check never returns critical, because "I did not see it advertised"
is not the same as "it is not there". A site could offer MFA only after login, where
this scan cannot follow.

So a "warning" here means "no MFA option was visible on the public pages", stated
honestly as a prompt to look, not an accusation. That honesty is the product: a
security tool that cries critical on indirect evidence is one nobody believes the
third time.
"""

import re

from ._finding import PASSED, WARNING, SKIPPED, finding_builder

CHECK_ID = "mfa_check"

_build_finding = finding_builder(CHECK_ID)

# THE VOCABULARY OF A SECOND FACTOR. Wording a site uses when it offers MFA, on a
# login page ("enter your verification code"), an account page ("set up two-factor"),
# or a marketing page ("secure with 2FA").
#
# PYTHON-SPECIFIC: one compiled alternation rather than a list of substrings, because
# a regex gives word boundaries and optional spaces for free - "two factor", "two-factor"
# and "twofactor" in one pattern - where `"2fa" in text` would also match inside an
# unrelated word.
MFA_TEXT = re.compile(
    r"(two[\s\-]?factor|multi[\s\-]?factor|\bmfa\b|\b2fa\b|"
    r"authenticator app|authentication app|\btotp\b|"
    r"verification code|one[\s\-]?time (code|passcode|password)|\botp\b|"
    r"security key|passkey|webauthn|\bfido2?\b|"
    r"backup codes|recovery codes)",
    re.I,
)

# Routes a site publishes for enrolling or managing a second factor. Found as link
# hrefs on the pages discovery fetched - not probed, because a 404 on /2fa proves
# nothing and probing account routes on a site we cannot log into is noise.
#
# THE TRAILING `s?` IS LOAD-BEARING. Without it the pattern required a keyword to be
# followed immediately by / ? # or end-of-string, which missed every plural - and the
# plural is the form real sites use: /settings/passkeys, /security-keys,
# /recovery-codes, /authenticators. A missed route is a missed PASS, so on a site
# whose only public evidence of MFA was the link in its account nav, this check
# reported "no MFA option found".
#
# PYTHON-SPECIFIC: order matters inside an alternation - the engine takes the first
# branch that lets the whole pattern match, so the compound names are listed BEFORE
# the bare ones. `security` first would have `security[\-_]?key` never tried on
# /security-keys, and the pattern would rely on backtracking to recover.
#
# `security` on its own is the loosest entry here and it is kept deliberately: a
# route named /settings/security is where most sites put MFA enrolment. It does also
# match a /security policy page, which is a false positive - acceptable because this
# check never returns critical and the finding names the exact link it found, so a
# reader can judge the evidence rather than take the verdict on trust.
MFA_PATH = re.compile(
    r"/(two[\-_]?factor|multi[\-_]?factor|security[\-_]?key|recovery[\-_]?code|"
    r"backup[\-_]?code|authenticator|passkey|webauthn|security|2fa|mfa|totp|otp)"
    r"s?(/|$|\?|#)",
    re.I,
)

# WHY SMS IS TRACKED SEPARATELY, NOT COUNTED AS A WIN
# SMS one-time codes are MFA, and they are meaningfully better than nothing - but they
# are also the weakest common form (SIM-swap, SS7 interception), and NIST has advised
# against them for years. If the ONLY factor on offer is SMS, that is worth saying, so
# it is detected but reported with a caveat rather than as an unqualified pass.
SMS_TEXT = re.compile(r"(text message|via sms|sms code|code (via|by) text|mobile number)", re.I)
STRONG_MFA_TEXT = re.compile(
    r"(authenticator|\btotp\b|security key|passkey|webauthn|\bfido2?\b|backup codes)",
    re.I,
)

# A marketing page can name its second factor a dozen times. The distinct phrases
# are evidence; the repetitions are noise, so the evidence is capped per page.
MAX_PHRASES_PER_PAGE = 5


# --- The check -------------------------------------------------------------


# WHY THIS TAKES THE ScanTarget RATHER THAN A URL
# The evidence is spread across every page discovery already fetched: the login page
# says "enter your verification code", the signup page advertises "protected with
# 2FA", the footer links to /settings/security. Those bodies are already in memory,
# so re-requesting them here would be three wasted requests for text we hold - the
# same reasoning as cookies_check and exposure_check.
async def check_mfa(target) -> dict:
    # PYTHON-SPECIFIC: a list comprehension with a filter, building (label, Page)
    # pairs only for the pages that exist. `if page is not None` is doing real work -
    # a site with no signup page has target.signup is None, and attribute access on
    # None raises. Login comes first because a hit there is the most meaningful.
    pages = [
        (label, page)
        for label, page in (
            ("login", target.login),
            ("signup", target.signup),
            ("home", target.home),
        )
        if page is not None
    ]

    if not pages:
        return _build_finding(
            severity=SKIPPED,
            title="Could not check for multi-factor authentication",
            description="No page content was retrieved",
            explanation=(
                "The scan retrieved no page bodies, so there was nothing to read for "
                "evidence of multi-factor authentication. Whether the site was "
                "reachable at all is reported by the other checks."
            ),
            fix="Confirm the site is reachable, then re-run the scan.",
            evidence={"pagesInspected": 0},
        )

    # IS THERE AN ACCOUNT SYSTEM AT ALL?
    #
    # This is the question that decides SKIPPED versus a real result, and it is the
    # reason the SKIPPED severity had to be invented (see _finding.py). A brochure
    # site with no accounts has no second factor to offer, and reporting that as a
    # warning would mark it down for a feature it has no reason to have - a score
    # that is dishonest in the one direction a security product cannot afford.
    has_account_system = (
        target.login is not None
        or target.signup is not None
        # PYTHON-SPECIFIC: `for _, page in pages` unpacks each pair and throws the
        # label away - `_` is the conventional name for "deliberately unused".
        or any(page.has_password_input() for _, page in pages)
    )

    # WHERE THE EVIDENCE CAME FROM, kept as two separate piles because they are
    # different strengths of claim. Wording on the page ("authenticator app") is a
    # site SAYING it supports MFA. A link to /2fa is a site PUBLISHING a route for it.
    # Either alone is enough to pass; naming which one was seen is what lets a site
    # owner verify the finding instead of taking it on trust.
    text_hits: list[dict] = []
    path_hits: list[dict] = []

    # The capped page text, kept per page so the strong-factor and SMS questions
    # further down can be asked of the FULL wording rather than of the phrases
    # matched here. That distinction was a real bug: MFA_TEXT stops at its first
    # match, so a login page reading "Two-factor authentication is required ... open
    # your authenticator app" produced only "Two-factor", and the site's
    # authenticator support went unseen.
    page_texts: list[str] = []

    for label, page in pages:
        # Cap the text for the same reason exposure_check caps the body: the regexes
        # gain nothing from a multi-megabyte page, and wording buried past 200 KB is
        # wording no visitor ever read either.
        body_text = page.text[:200_000]
        page_texts.append(body_text)

        # PYTHON-SPECIFIC: finditer yields EVERY match, lazily, where .search returns
        # only the first. A page usually names its second factor more than one way -
        # "two-factor", "authenticator app", "recovery codes" - and each of those is
        # evidence a site owner can check, so collect the distinct ones.
        seen: set[str] = set()

        for match in MFA_TEXT.finditer(body_text):
            phrase = match.group(0).strip()

            # Lowercased only as the DUPLICATE key. The phrase itself is stored with
            # the site's own capitalisation, because the evidence should read back as
            # the words actually on the page.
            key = phrase.lower()

            if key in seen:
                continue

            seen.add(key)
            text_hits.append(
                {
                    "where": label,
                    "url": page.url,
                    # Stored VERBATIM, unlike exposure_check's redacted samples.
                    # There is nothing sensitive in the phrase "authenticator app" -
                    # it is marketing copy - and the exact wording matched is the
                    # most checkable evidence this check can offer.
                    "phrase": phrase,
                }
            )

            if len(seen) >= MAX_PHRASES_PER_PAGE:
                break

        for href, text in page.links:
            if MFA_PATH.search(href):
                path_hits.append(
                    {
                        "where": label,
                        "href": href,
                        # A link's text can be an entire nav block when the anchor
                        # wraps one, so it is truncated. Already whitespace-collapsed
                        # by the parser (see discovery._PageParser.handle_endtag).
                        "text": text[:80],
                    }
                )

    # PYTHON-SPECIFIC: de-duplicating dicts needs an explicit map, because dict.fromkeys
    # - the usual ordered-unique idiom - requires hashable items and a dict is not
    # hashable. setdefault keeps the FIRST sighting of each href, which is the most
    # relevant one given login pages are scanned first. The same /2fa link in a footer
    # on all three pages is one fact, not three.
    unique_paths: dict[str, dict] = {}
    for hit in path_hits:
        unique_paths.setdefault(hit["href"], hit)
    path_hits = list(unique_paths.values())

    if not has_account_system:
        return _build_finding(
            severity=SKIPPED,
            title="No account system found to check for MFA",
            description="No login or signup page was located",
            explanation=(
                "Multi-factor authentication protects an account, and this scan found "
                "no sign-in or registration page and no password field on the pages "
                "it reached - so there is no account system here to add a second "
                "factor to. This is a limit of what the scan could see, not a "
                "finding: a site whose login lives somewhere the scan did not look "
                "would look identical from outside."
            ),
            fix=(
                "No action from this check. If the site does have a login page, "
                "re-run the scan with its address supplied directly so this check "
                "can read it."
            ),
            evidence={
                "pagesInspected": [label for label, _ in pages],
                "loginFound": False,
            },
        )

    # THE SEVERITY DECISION, and the reason this check never returns critical.
    #
    # Absence of evidence is not evidence of absence: a site can offer MFA only after
    # login, where an unauthenticated scan cannot follow. So the worst this returns is
    # a warning worded as "nothing was visible", which is exactly what was observed.
    if not text_hits and not path_hits:
        return _build_finding(
            severity=WARNING,
            title="No multi-factor authentication option found",
            description="Nothing on the public pages advertises a second factor",
            explanation=(
                "This site has an account system, but none of the pages scanned "
                "mentioned two-factor authentication, an authenticator app, "
                "verification codes, security keys or passkeys, and none linked to a "
                "route for setting one up.\n\nA password is a single secret, and "
                "secrets leak - reused from a breached site, phished, or guessed. A "
                "second factor is what stops a leaked password becoming a lost "
                "account, and its absence is the largest single gap in most account "
                "systems.\n\nStated carefully: this scan reads only public pages and "
                "cannot sign in. If MFA is offered inside the account area, it exists "
                "and this check could not see it - so treat this as a prompt to "
                "confirm, not as a verdict."
            ),
            fix=(
                "Offer TOTP (an authenticator app such as Google Authenticator or "
                "1Password) as a second factor, and passkeys/WebAuthn if you can - "
                "both are free to implement and phishing-resistant in a way SMS is "
                "not. Issue one-time recovery codes at enrolment so a lost phone is "
                "not a lost account, and advertise the option where users will find "
                "it: on the login page and in account settings."
            ),
            evidence={
                "pagesInspected": [label for label, _ in pages],
                "loginFound": target.login is not None,
                "mfaEvidence": [],
            },
        )

    # SOMETHING WAS FOUND. What remains is deciding how strong it is.
    #
    # BOTH QUESTIONS BELOW ARE ASKED OF THE FULL PAGE TEXT, never of the phrases
    # collected above. "Does this site offer a strong factor anywhere" is a question
    # about the SITE, and asking it of the matched phrases answers it from whichever
    # wording MFA_TEXT happened to reach first - which is exactly how an
    # authenticator app goes unnoticed on a page that says "two-factor" earlier in
    # the same sentence.
    #
    # PYTHON-SPECIFIC: any() returns a real bool, unlike re.search which returns a
    # match object or None. That matters here because both values go into the evidence
    # dict, and a match object is not JSON-serialisable - it would fail on the way
    # into MongoDB rather than at the point of the mistake.
    has_strong = any(STRONG_MFA_TEXT.search(text) for text in page_texts) or any(
        # A route named /passkey or /authenticator is a strong factor published as a
        # path, even when no page wording mentions one.
        STRONG_MFA_TEXT.search(hit["href"])
        for hit in path_hits
    )

    # SMS matters only when it is the ONLY thing on offer, so this decides between an
    # unqualified pass and a caveated one - by this point some form of MFA is known to
    # be advertised. Tested against the page text because "we will text you a code"
    # does not itself match MFA_TEXT.
    mentions_sms = any(SMS_TEXT.search(text) for text in page_texts)

    # The human-readable evidence, built once and used by both branches below.
    detail_lines = "\n".join(
        [f"- \"{hit['phrase']}\" on the {hit['where']} page" for hit in text_hits]
        + [f"- a link to {hit['href']} on the {hit['where']} page" for hit in path_hits]
    )

    evidence = {
        "pagesInspected": [label for label, _ in pages],
        "loginFound": target.login is not None,
        "textEvidence": text_hits,
        "pathEvidence": path_hits,
        "strongFactorSeen": has_strong,
        "smsMentioned": mentions_sms,
    }

    # SMS-ONLY IS A QUALIFIED PASS, NOT A FAILURE.
    #
    # SMS codes are genuinely MFA and genuinely better than a password alone, so
    # scoring them as a failure would overstate the problem - this check asks whether
    # a second factor is OFFERED, and it is. But SIM-swap and SS7 interception are
    # real, NIST has advised against SMS for years, and a client who reads "passed"
    # and stops there has been done a disservice. So it passes with the caveat in the
    # title, where it cannot be missed.
    #
    # The alternative considered was a WARNING. It was rejected because it would score
    # a site that added SMS MFA identically to one that has none, which is the wrong
    # incentive - but this is a policy call, not a fact, and worth revisiting.
    if mentions_sms and not has_strong:
        return _build_finding(
            severity=PASSED,
            title="Multi-factor authentication offered, but only by SMS",
            description=(
                "A second factor is available; text-message codes are the weakest kind"
            ),
            explanation=(
                "The scan found evidence that a second factor is offered:\n"
                f"{detail_lines}\n\nThe only method mentioned, though, is a code sent "
                "by text message. That is real protection and far better than a "
                "password alone - but it is the weakest common form. A phone number "
                "can be taken over by persuading a mobile network to move it to a new "
                "SIM, and text messages can be intercepted in transit; both are used "
                "in practice against high-value accounts.\n\nThis is recorded as a "
                "pass because a second factor is genuinely on offer. The caveat is "
                "here so it is not mistaken for a strong one."
            ),
            fix=(
                "Add TOTP (an authenticator app) and, if you can, passkeys/WebAuthn, "
                "and make one of them the default offered at enrolment - keep SMS as "
                "a fallback for users with no other option rather than as the only "
                "route. Issue one-time recovery codes so a lost phone is not a lost "
                "account."
            ),
            evidence=evidence,
        )

    return _build_finding(
        severity=PASSED,
        title="Multi-factor authentication is offered",
        description=(
            f"Found {len(text_hits) + len(path_hits)} sign(s) of a second factor"
        ),
        explanation=(
            "The scan found evidence that this site offers a second factor beyond the "
            f"password:\n{detail_lines}\n\nThat is the single most effective account "
            "protection there is: it means a password leaked in someone else's breach "
            "is not enough on its own to take an account here.\n\nWhat this does not "
            "confirm: the scan cannot sign in, so it has read what the site "
            "ADVERTISES rather than tested that enrolment works, and it cannot tell "
            "whether MFA is available to every user or required for any. Both are "
            "worth verifying from the inside."
        ),
        fix=(
            "No action needed from this check. Worth confirming separately that the "
            "option is easy to find, that recovery codes are issued at enrolment, and "
            "that administrator accounts are required to use it rather than merely "
            "offered it."
        ),
        evidence=evidence,
    )
