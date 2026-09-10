"""
LOGIN RATE-LIMITING CHECK - spec section 6, Tier 1.

WHY THIS FILE EXISTS
A login form with no rate limit is a password guessing machine. Credential stuffing
is the most common attack on account systems by volume: take a list of email and
password pairs from someone else's breach, replay it against this site, and every
user who reused a password loses their account. The defence is not a stronger
password policy - it is refusing to answer the ten thousandth attempt.

THIS CHECK IS PASSIVE, AND THAT IS A DELIBERATE PRODUCT DECISION
The direct way to test a rate limit is to trip it: submit repeated failed logins and
see when the site says no. This check does not do that, and Tier 1 sends no POST
requests at all, ever.

The reason is that "repeated failed logins against somebody else's site" is
indistinguishable, from the far end, from the attack this check is about. It can lock
out a real account if the address guessed happens to belong to a live user, it puts
rubbish in the site owner's security logs, and it is the one thing a scanner can do
that is arguably an attack rather than an audit. A tool that behaves like an attacker
to prove the site would notice an attacker has picked the wrong trade.

So this reads only what the site already told us during discovery:

  1. rate-limit headers on the responses already fetched (RateLimit-*, Retry-After),
  2. a CAPTCHA widget on the login form,
  3. a lockout policy the site documents in its own page text,
  4. a 429 we tripped with ordinary GETs, which is the strongest signal of all.

WHAT THAT MEANS FOR THE RESULT - READ THIS BEFORE TRUSTING IT
None of the above proves a failed-password limit exists. A site can rate-limit
perfectly and advertise none of it, which is in fact the common case: the limiter
lives at the edge or in the application and says nothing until you trip it. So a
warning here means "no protection was visible from outside", never "this site has no
rate limiting" - and this check NEVER returns critical, for the same reason mfa_check
never does. Absence of evidence is not evidence of absence, and a security tool that
forgets that is one nobody believes the third time.

THE ACTIVE VERSION IS A TIER 2 CHECK, and when it is built it must use a dedicated
test account the client supplies for the purpose - never an address that might belong
to a real user.
"""

import re

from ._finding import PASSED, SKIPPED, WARNING, finding_builder

CHECK_ID = "rate_limit_check"

_build_finding = finding_builder(CHECK_ID)


# --- What counts as evidence ------------------------------------------------

# HEADERS THAT NAME A RATE LIMIT. The RateLimit-* family is the IETF draft standard
# (RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, RateLimit-Policy); the
# X-RateLimit-* and X-Rate-Limit-* spellings predate it and are still what most
# frameworks emit. Retry-After is the one that ships in the standard library of every
# HTTP stack, and it is the header a limiter sets when it turns a request away.
#
# This is the STRONGEST passive signal available, because it is the limiter itself
# talking: a site does not emit RateLimit-Remaining unless something is counting.
#
# PYTHON-SPECIFIC: matched against header NAMES rather than looked up by key, because
# the exact spelling varies and enumerating every variant would miss the next one.
# Header names in Page.headers are already lowercased - dict(httpx.Headers) does that
# on the way in - so this pattern does not need re.I, but it carries it anyway rather
# than depend on a normalisation happening two files away.
RATE_LIMIT_HEADER = re.compile(r"^(x-)?rate[\-_]?limit(-|$)|^retry-after$", re.I)

# CAPTCHA WIDGETS, found in the raw HTML of the login page.
#
# WHY THE RAW HTML AND NOT THE TEXT: a CAPTCHA is a script tag and a div, and
# discovery's parser deliberately suppresses script contents from page.text (see
# _PageParser.handle_starttag). The vendor's script URL is the marker, and it only
# exists in the markup.
#
# WHY THIS IS TREATED AS STRONG EVIDENCE: unlike page wording, these are not claims.
# A reCAPTCHA script tag is a machine-verifiable fact about what the login form does,
# and its purpose is precisely to stop automated submission at scale. It is not the
# same control as a failed-password counter - a CAPTCHA blunts volume, a lockout stops
# a targeted guess - but a login form behind one is not a password guessing machine.
CAPTCHA_MARKUP = re.compile(
    r"(recaptcha|hcaptcha|h-captcha|turnstile|cf-turnstile|data-sitekey|"
    r"friendly[\-]?challenge|friendlycaptcha|arkoselabs|funcaptcha|geetest|"
    r"altcha|mtcaptcha)",
    re.I,
)

# A form field whose name gives the widget away even when the vendor script is loaded
# from somewhere this pattern does not recognise.
CAPTCHA_FIELD = re.compile(r"captcha|sitekey|challenge[\-_]?response", re.I)

# A LOCKOUT POLICY THE SITE DOCUMENTS IN ITS OWN WORDS.
#
# The weakest of the three signals, and the phrasing is kept tight on purpose. "Try
# again later" was considered and rejected: it appears on every generic error page
# ever written, and a pattern that matches a 500 page is not evidence of a rate limit.
# What is left is wording that only makes sense if a limit exists - a count of
# attempts, a lockout, a cooldown, an explicit mention of throttling.
LOCKOUT_TEXT = re.compile(
    r"(too many (failed |unsuccessful |login |sign[\-\s]?in )*attempts|"
    r"\d+ (failed|unsuccessful|incorrect) (login |sign[\-\s]?in )?attempts|"
    r"account (will be |has been |is |may be )?(temporarily )?"
    r"(locked|suspended|disabled)|"
    r"locked out|lockout|"
    r"(temporarily |briefly )(blocked|throttled|rate[\-\s]?limited)|"
    r"rate[\-\s]?limit(ing|ed)|brute[\-\s]?force|"
    r"wait \d+ (second|minute|hour)s? before)",
    re.I,
)

# The same cap mfa_check uses, for the same reason: distinct phrases are evidence,
# repetitions are noise.
MAX_PHRASES_PER_PAGE = 5

# Matching the cap in the other checks. A regex gains nothing from a multi-megabyte
# page, and wording buried past 200 KB is wording no visitor read either.
MAX_TEXT = 200_000

# WHAT IS DELIBERATELY NOT EVIDENCE HERE: a CDN or WAF fingerprint. Seeing
# `server: cloudflare` means an edge rate limiter is AVAILABLE, not that it is
# configured on the login route - the free tier ships with none by default. Passing a
# site because it sits behind a CDN would award credit for a control nobody switched
# on, and a false pass in a security report is worse than no check at all.


# --- The check -------------------------------------------------------------


# WHY THIS TAKES THE ScanTarget AND MAKES NO REQUESTS
# Every signal above is already in memory: discovery fetched the login, signup and
# home pages, kept their headers, their raw HTML and their status codes. Re-requesting
# any of it would be a wasted round trip for bytes we hold - and for this check
# specifically, the one that must not generate traffic, "makes no requests" is a
# property worth being able to state plainly rather than argue about.
async def check_rate_limit(target) -> dict:
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
            title="Could not check login rate limiting",
            description="No page content was retrieved",
            explanation=(
                "The scan retrieved no page bodies or headers, so there was nothing to "
                "read for evidence of rate limiting. Whether the site was reachable at "
                "all is reported by the other checks."
            ),
            fix="Confirm the site is reachable, then re-run the scan.",
            evidence={"pagesInspected": 0},
        )

    # IS THERE A LOGIN TO RATE-LIMIT?
    #
    # Same reasoning as mfa_check, and the same reason SKIPPED exists. Rate limiting
    # here means rate limiting a CREDENTIAL SUBMISSION; a site with no login form has
    # no password endpoint to guess at, so marking it down would be marking it down
    # for not having a feature it has no reason to have.
    #
    # A signup form on its own still counts. It is not a login, but it submits
    # credentials and can be abused for bulk account creation, which wants the same
    # control.
    has_credential_form = (
        target.login is not None
        or target.signup is not None
        or any(page.has_password_input() for _, page in pages)
    )

    if not has_credential_form:
        return _build_finding(
            severity=SKIPPED,
            title="No login form found to check for rate limiting",
            description="No sign-in or registration form was located",
            explanation=(
                "Rate limiting matters where credentials are submitted, and this scan "
                "found no sign-in or registration form and no password field on the "
                "pages it reached - so there is no login endpoint here to protect."
                "\n\nThis is a limit of what the scan could see rather than a finding. "
                "A site whose login lives somewhere the scan did not look would appear "
                "identical from outside."
            ),
            fix=(
                "No action from this check. If the site does have a login page, re-run "
                "the scan with its address supplied directly so this check can read it."
            ),
            evidence={
                "pagesInspected": [label for label, _ in pages],
                "loginFound": False,
            },
        )

    # --- Gather the evidence, keeping the piles separate --------------------
    #
    # Four piles, because they are four different strengths of claim and the report has
    # to be able to say which one it is standing on. Collapsing them into a single
    # "found something" boolean is what would let a documented policy - the weakest
    # signal here - be reported with the same confidence as a live 429.
    header_hits: list[dict] = []
    captcha_hits: list[dict] = []
    text_hits: list[dict] = []
    throttled_hits: list[dict] = []

    for label, page in pages:
        # A 429 THAT WE TRIPPED WITH PLAIN GETs is the strongest evidence obtainable
        # without sending a single POST: the limiter did not merely advertise itself,
        # it acted. Worth noting that this makes the rest of the report less reliable
        # (a throttled scan may have missed pages), which is why it is surfaced rather
        # than quietly counted.
        if page.status == 429:
            throttled_hits.append({"where": label, "url": page.url, "status": 429})

        # PYTHON-SPECIFIC: .items() iterates key/value pairs together. A bare
        # `for name in headers` would need a second lookup to report what the header
        # said, and the value is part of the evidence.
        for name, value in page.headers.items():
            if RATE_LIMIT_HEADER.search(name):
                header_hits.append(
                    {
                        "where": label,
                        "header": name,
                        # Truncated but not redacted: a rate-limit header's value is a
                        # count or a timestamp, and there is nothing sensitive in "99".
                        "value": str(value)[:120],
                    }
                )

        # CAPTCHA is looked for on the raw markup rather than the text. The home page is
        # included because plenty of sites put the login form in a modal on the
        # homepage.
        markup = page.html[:MAX_TEXT]
        markup_match = CAPTCHA_MARKUP.search(markup)

        if markup_match is not None:
            captcha_hits.append(
                {
                    "where": label,
                    "url": page.url,
                    "marker": markup_match.group(0).lower(),
                    "foundIn": "markup",
                }
            )

        # The field-name fallback, for a widget whose vendor script this does not
        # recognise. Reads the forms discovery already parsed rather than the markup,
        # so it can say which FORM carried it - the part that matters, since a CAPTCHA
        # on a newsletter signup is not a CAPTCHA on the login.
        for form in page.forms:
            for form_field in form.fields:
                if CAPTCHA_FIELD.search(form_field.name):
                    captcha_hits.append(
                        {
                            "where": label,
                            "url": page.url,
                            "marker": form_field.name[:60],
                            "foundIn": "form field",
                        }
                    )

        # The documented-policy pile.
        body_text = page.text[:MAX_TEXT]
        seen: set[str] = set()

        for match in LOCKOUT_TEXT.finditer(body_text):
            # PYTHON-SPECIFIC: " ".join(s.split()) collapses any run of whitespace -
            # including the newlines a wrapped sentence carries - into single spaces.
            # The phrase goes into a report, so it should read as one line.
            phrase = " ".join(match.group(0).split())
            key = phrase.lower()

            if key in seen:
                continue

            seen.add(key)
            text_hits.append({"where": label, "url": page.url, "phrase": phrase})

            if len(seen) >= MAX_PHRASES_PER_PAGE:
                break

    # De-duplicated the same way mfa_check does its paths, and for the same reason: the
    # identical reCAPTCHA script tag in a shared layout on all three pages is one fact,
    # not three. Keyed on the marker AND where it was found, so a markup hit and a form
    # field hit are not collapsed into each other.
    unique_captcha: dict[tuple, dict] = {}
    for hit in captcha_hits:
        unique_captcha.setdefault((hit["marker"], hit["foundIn"]), hit)
    captcha_hits = list(unique_captcha.values())

    unique_headers: dict[str, dict] = {}
    for hit in header_hits:
        unique_headers.setdefault(hit["header"], hit)
    header_hits = list(unique_headers.values())

    evidence = {
        "pagesInspected": [label for label, _ in pages],
        "loginFound": target.login is not None,
        "rateLimitHeaders": header_hits,
        "captchaEvidence": captcha_hits,
        "documentedPolicy": text_hits,
        "throttledDuringScan": throttled_hits,
        # Stated in the stored document, not only in this file's docstring: a report
        # read months from now should say what the check was willing to do.
        "method": "passive; no authentication requests were sent",
    }

    # --- The severity decision ---------------------------------------------
    #
    # THE LADDER, strongest evidence first. Two rules govern it:
    #
    #   1. This check NEVER returns critical. Rate limiting is close to invisible from
    #      outside - a site can implement it perfectly and advertise nothing - so the
    #      worst finding available is a warning worded as "nothing was visible".
    #
    #   2. INDIRECT EVIDENCE DOES NOT EARN A FULL PASS. A header or a CAPTCHA widget is
    #      a fact about the site's behaviour; a sentence saying "your account may be
    #      locked" is the site describing itself, which is a claim this scan cannot
    #      check. So a documented policy alone is capped at a warning.
    #
    # THE COST OF RULE 2, stated plainly because it is arguable: under the credit
    # scoring in engine.py a warning is half credit, so a site that documents its
    # lockout policy scores the same as a site that shows nothing at all. That is a
    # real loss of signal, and the alternative - a caveated pass, the way mfa_check
    # treats SMS-only - was the other candidate. Capping won because the two cases are
    # not comparable: SMS-only is a WEAKER CONTROL that was definitely observed, where
    # a documented policy is a control that may not exist at all. Awarding full credit
    # for a sentence would mean a site could pass this check by editing its help page.

    if throttled_hits:
        return _build_finding(
            severity=PASSED,
            title="Rate limiting is active",
            description="The site throttled this scan's own requests",
            explanation=(
                "While reading public pages, the scan received HTTP 429 (Too Many "
                "Requests). That is the strongest evidence available without sending a "
                "single login attempt: the site is not merely advertising a rate "
                "limit, it enforced one.\n\nTwo caveats. First, this was observed on "
                "ordinary page requests, so it does not confirm the limit also covers "
                "failed passwords - the login endpoint usually needs its own, stricter "
                "limit. Second, because the scan was throttled, other checks in this "
                "report may have seen fewer pages than usual."
            ),
            fix=(
                "No action needed from this check. Worth confirming the login endpoint "
                "carries its own limit, counted per account as well as per IP address, "
                "since credential stuffing arrives from thousands of addresses at once."
            ),
            evidence=evidence,
        )

    if header_hits:
        detail = "\n".join(
            f"- {hit['header']}: {hit['value']} (on the {hit['where']} page)"
            for hit in header_hits
        )
        return _build_finding(
            severity=PASSED,
            title="Rate limiting is in place",
            description=f"Found {len(header_hits)} rate-limit header(s)",
            explanation=(
                "The site's responses carry headers that only a rate limiter emits:\n"
                f"{detail}\n\nSomething is counting requests and is prepared to turn "
                "them away, which is the control that stops a leaked password list "
                "being replayed against every account here.\n\nWhat this does not "
                "confirm: these headers were seen on ordinary page requests, and the "
                "scan sent no login attempts, so it cannot tell how strict the limit "
                "on failed passwords is - or whether the login endpoint has one at all."
            ),
            fix=(
                "No action needed from this check. Worth confirming that failed logins "
                "are limited per ACCOUNT as well as per IP address - credential "
                "stuffing spreads across thousands of addresses, so an IP-only limit "
                "barely slows it - and that legitimate users who hit the limit get a "
                "clear message rather than a generic error."
            ),
            evidence=evidence,
        )

    if captcha_hits:
        detail = "\n".join(
            f"- {hit['marker']} in the {hit['where']} page's {hit['foundIn']}"
            for hit in captcha_hits
        )
        return _build_finding(
            severity=PASSED,
            title="Automated login attempts are challenged",
            description="A CAPTCHA protects a credential form",
            explanation=(
                "The scan found a CAPTCHA widget on a page carrying a credential "
                f"form:\n{detail}\n\nA CAPTCHA is what stops a login form being "
                "submitted ten thousand times by a script, which is how credential "
                "stuffing works in practice - replaying email and password pairs from "
                "someone else's breach against this site.\n\nWhat this does not "
                "confirm: a CAPTCHA limits VOLUME, and a per-account lockout stops a "
                "TARGETED guess at one user. They are different controls and the "
                "second is not visible from outside, so this pass covers only the "
                "first."
            ),
            fix=(
                "No action needed from this check. A CAPTCHA is best paired with a "
                "limit on failed attempts per account, since the two cover different "
                "attacks. If the CAPTCHA only appears after a number of failures, that "
                "is the better design - confirm the threshold is low enough to matter."
            ),
            evidence=evidence,
        )

    if text_hits:
        detail = "\n".join(
            f'- "{hit["phrase"]}" on the {hit["where"]} page' for hit in text_hits
        )
        return _build_finding(
            severity=WARNING,
            title="A lockout policy is described but could not be verified",
            description="The site documents a limit; nothing observable confirms it",
            explanation=(
                "The pages scanned describe a limit on failed sign-in attempts:\n"
                f"{detail}\n\nThat is the site stating a policy, which is genuinely "
                "better than silence - but it is a claim rather than something this "
                "scan could observe. No rate-limit headers were present on any "
                "response, and no CAPTCHA was found on the credential forms, so there "
                "is nothing here to confirm the policy is implemented as written."
                "\n\nThis is recorded as a warning rather than a pass because a "
                "sentence on a help page is not a control. It is not an accusation "
                "either: the policy may well be enforced in application code, which is "
                "invisible from outside. It is a prompt to verify."
            ),
            fix=(
                "Confirm the documented limit is actually enforced - the quickest way "
                "is to try it against a test account of your own. Where it is "
                "enforced, consider making it observable: a Retry-After header on the "
                "rejection tells a legitimate client when to come back, and a "
                "RateLimit-Remaining header lets your own monitoring see the limit "
                "working. Count failures per account as well as per IP address."
            ),
            evidence=evidence,
        )

    # NOTHING WAS VISIBLE. This is the honest floor of the check, and the wording
    # matters: the finding is about what the scan could see, not about what the site
    # does. Rate limiting is genuinely common and genuinely invisible.
    return _build_finding(
        severity=WARNING,
        title="No login rate limiting was visible",
        description="Nothing observable protects the credential form from guessing",
        explanation=(
            "This site has a form that submits credentials, and the scan found no "
            "outward sign of a limit on attempts: no rate-limit or Retry-After headers "
            "on any response, no CAPTCHA on the credential forms, and no documented "
            "lockout policy in the page text.\n\nAn unlimited login form is a password "
            "guessing machine. Credential stuffing is the highest-volume attack on "
            "account systems: an attacker takes email and password pairs leaked from "
            "another site and replays them here, and every user who reused a password "
            "loses their account. The defence is not a stronger password rule - it is "
            "refusing to answer the ten thousandth attempt.\n\nStated carefully: this "
            "check is deliberately passive and sends no login attempts, so it reads "
            "only what the site reveals in public. Rate limiting implemented in "
            "application code, or at an edge that stays quiet until tripped, is "
            "invisible here and very common. Treat this as a prompt to confirm, not as "
            "a verdict that no limit exists."
        ),
        fix=(
            "Limit failed sign-in attempts, counted per ACCOUNT as well as per IP "
            "address - credential stuffing arrives from thousands of addresses at "
            "once, so an IP-only limit barely slows it. Add a progressive delay or a "
            "CAPTCHA after a handful of failures rather than a hard lockout, which an "
            "attacker can otherwise use to lock real users out deliberately. Return "
            "429 with a Retry-After header so well-behaved clients back off, and alert "
            "on the pattern: a spike in failures across many accounts is credential "
            "stuffing in progress."
        ),
        evidence=evidence,
    )
