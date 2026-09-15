"""
PASSWORD RESET CHECK - Tier 2. Does the reset flow leak who has an account?

WHAT THIS CHECK IS FOR
Password reset is the flow every attacker looks at first, because it is the one place an
application is designed to hand something out to an unauthenticated stranger. Two defects
are common enough to be worth a dedicated check:

  1. IT ANSWERS DIFFERENTLY FOR AN ADDRESS THAT HAS AN ACCOUNT. "We've sent you a link"
     for one address and "No account found with that email" for another turns the reset
     form into a membership oracle: anyone can test an address list against it and learn
     which of those people use this service. For most sites that is a privacy leak. For a
     site where the membership itself is sensitive - a health service, a legal service, a
     dating service, a service for a particular diagnosis or community - the list of who
     has an account IS the confidential data, and the reset form gives it away.

  2. IT RETURNS THE RESET TOKEN IN ITS OWN RESPONSE. This happens when a JSON API is
     built to be convenient during development and the token is never taken back out.
     Anyone who can name an address can then reset that account's password immediately,
     with no access to the mailbox at all. That is a complete account takeover by design,
     and it is why the JSON-body inspection below is CRITICAL rather than a warning.

WHY THIS CHECK REQUIRES A WORKING LOGIN FIRST
Testing (1) needs an address that HAS an account, and a reset request for a real address
sends a real email to it. The scanner will not do that to an address on a client's word
alone: the username field is client-supplied text, so without a gate this check would be
a way to make SecuScan send password-reset emails to anybody's mailbox on request - a
harassment vector wearing a security scanner's clothes.

Requiring authenticated_session() to succeed first is the gate. If the supplied test
account can actually sign in, the client demonstrably controls that mailbox, and the one
reset email this check triggers lands somewhere they own. Sites that use bearer tokens
rather than session cookies are skipped as a result, and that is the right trade: a
narrower check is better than one that can be pointed at a stranger.

The reset request itself does NOT change the password and does not end any session - it
sends a code. So triggering it does not disturb the other checks running concurrently,
and the test account is still usable afterwards.

REQUEST BUDGET: one GET for the form, then two POSTs - the test account's own address and
a random address at .invalid. That is the minimum that produces a comparison; a single
probe has nothing to compare against and cannot distinguish a careful uniform answer from
a leak.

WHAT THIS CHECK DELIBERATELY DOES NOT DO
No timing analysis. The enumeration check measures login timing because a password hash
is a predictable few hundred milliseconds; a reset endpoint queues an email, and whether
that is 5ms or 5s depends on the mail provider, the queue depth and the weather. Timing
here would produce a confident-looking number that means nothing, so only the STATUS and
the MESSAGE are compared.
"""

import re
from urllib.parse import urljoin
from uuid import uuid4

import httpx

from ._endpoints import RESET_PATHS, candidate_paths, find_reset
from ._finding import (
    CRITICAL,
    PASSED,
    SKIPPED,
    TIMEOUT_SECONDS,
    USER_AGENT,
    WARNING,
    finding_builder,
)
from ._session import (
    _looks_blocked,
    authenticated_session,
    session_skip_finding,
    visible_text,
)
from ..discovery import _parse_page

CHECK_ID = "password_reset_check"

_build_finding = finding_builder(CHECK_ID, tier=2)


# The field a reset form asks for. Reset forms have no password input, so the login
# check's field detection does not apply - there is exactly one field that matters.
_ADDRESS_HINT = re.compile(r"(email|e-mail|user|login|account|identifier|username)", re.I)

# Phrases that name an address as unknown. These are the leak: an answer that only
# appears for an address WITHOUT an account.
_NOT_FOUND_HINTS = re.compile(
    r"(no (account|user)|not (found|registered|recognis|recogniz)|"
    r"does ?n.t exist|unknown (email|user|account)|couldn.t find|"
    r"no such (user|account)|isn.t registered|not associated with)",
    re.I,
)

# Phrases that confirm an address HAS an account. The mirror image of the leak: an
# answer that only appears for an address WITH one.
_FOUND_HINTS = re.compile(
    r"((we|link|email|code|instructions).{0,30}(sent|on its way|emailed)|"
    r"check your (email|inbox)|sent you)",
    re.I,
)

# A wall, not an answer: this check no longer decides that for itself. _looks_blocked
# comes from _session.py (see the import above), and the vocabulary and status list it
# consults live there with it - imported rather than named here, so there is nothing in
# this file that CAN drift. It used to be a local copy of the same
# vocabulary, "kept local so this check reads on its own" - and the copy drifted. This one
# was the only one of the three that knew the WAF product names, so a Cloudflare
# interstitial was a wall here and a mystery everywhere else; it was also the only one
# matching a bare "blocked", which read an admin page listing "Blocked users" as a wall.
# Both directions of that drift are why there is one definition now.

# JSON keys that must never be in a reset response, each PAIRED WITH ITS OWN STRING
# VALUE. `token`, `code` and `otp` are the secret itself; `link` and `url` carry it in a
# query string.
#
# THE PAIRING IS LOAD-BEARING. An earlier version matched the key alone and then searched
# the next 200 characters for any long-ish string, which made two false positives
# possible on a correctly built site: a later sibling key's value could be attributed to
# the token key ("code": "sent", "trace": "abcdef1234567890abcdef" reported `code` as the
# leaked field), and a status value containing an underscore escaped the entropy guard
# below. Matching key and value in one pattern makes the first impossible outright.
_TOKEN_PAIR = re.compile(
    r"\"(reset_?token|reset_?code|token|code|otp|pin|secret|reset_?link|reset_?url|"
    r"access_?token|api_?key|auth_?token)\"\s*:\s*\"([^\"]{1,512})\"",
    re.I,
)

# Everything that is not a letter or a digit. Stripped before the character-class test
# below so that separators cannot be mistaken for entropy - see _looks_like_secret.
_SEPARATORS = re.compile(r"[^A-Za-z0-9]")
_CLASSES = (re.compile(r"[a-z]"), re.compile(r"[A-Z]"), re.compile(r"[0-9]"))

# Keys that name a credential outright, as opposed to `code`, which usually holds a
# status string and only sometimes holds the code itself. A short digit run means
# different things under the two: `{"otp": "4819"}` is a four-digit login code, while
# `{"code": "4201"}` is far more likely an application status code. See the digit rule
# in _looks_like_secret.
_CREDENTIAL_KEYS = frozenset(
    {
        "token",
        "reset_token",
        "resettoken",
        "reset_code",
        "resetcode",
        "otp",
        "pin",
        "secret",
        "access_token",
        "accesstoken",
        "api_key",
        "apikey",
        "auth_token",
        "authtoken",
    }
)


def _excerpt(response: httpx.Response, limit: int = 300) -> str:
    """The response's visible text, truncated.

    300 rather than _session.py's 200 because the two messages this check compares are
    whole sentences a human will read side by side in the finding, and a reset
    confirmation ("If an account exists for that address, we have sent...") runs past 200
    characters often enough to truncate the part that differs.

    The text itself comes from _session.visible_text, which drops script and style bodies
    before the tags - without that, an inline script carrying the word "captcha" or the
    site's own error strings decides what this check concludes.
    """
    return visible_text(response)[:limit]


def _reset_form_fields(page) -> tuple:
    """The address field name and any hidden fields on the reset form.

    A reset form is identified as the form WITHOUT a password input - the reset page
    often also carries the site's login form in a header or a sidebar, and posting the
    probe address into the login form would test the wrong endpoint entirely.
    """
    address_field = "email"
    extra = {}
    submit_url = ""

    if page is None:
        return address_field, extra, submit_url

    for form in page.forms:
        if form.has_password():
            continue

        named = [f for f in form.fields if f.name]
        if not any(_ADDRESS_HINT.search(f.name) or f.type == "email" for f in named):
            continue

        submit_url = form.submit_url or ""
        for f in named:
            if f.type == "hidden":
                # Carried through as sent, same reasoning as the login form: this may
                # pick up a valid CSRF nonce, and when it does not the resulting wall
                # is reported as a wall rather than forged around.
                extra[f.name] = f.attrs.get("value", "")
            elif _ADDRESS_HINT.search(f.name) or f.type in ("text", "email"):
                address_field = f.name
        break

    return address_field, extra, submit_url


def _looks_like_secret(value: str, key: str = "") -> bool:
    """Whether a value under a token-shaped key is actually a credential.

    The hard case is that a reset endpoint naming its own state - `{"code":
    "reset_email_sent"}` - is a token-shaped KEY holding a value that is not a secret.
    Reporting that as a leak is a CRITICAL false positive on a correct site, so the value
    has to qualify on its own.

    Two shapes qualify, and only two:

      * All digits, 4 to 8 of them. That is the length of a one-time code or PIN, which
        is a complete reset credential in itself. Under the generic `code` key the floor
        is 6 instead, because a 4-digit number there is much more likely to be an
        application status code than a login code - see _CREDENTIAL_KEYS.
      * At least 16 characters that, IGNORING SEPARATORS, span two or more of
        lowercase / uppercase / digits. That is the shape of a hex digest, a base64url
        token, a UUID or a JWT.

    Requiring two character classes rather than mere length is the point of the
    underscore rule: `reset_email_sent` is 16 characters, but once the separators are
    removed it is all lowercase letters, so it cannot pass. Length alone would let every
    underscore-separated status string through.
    """
    value = value.strip()
    if not value:
        return False

    if value.isdigit():
        floor = 4 if _SEPARATORS.sub("", key).lower() in _CREDENTIAL_KEYS else 6
        return floor <= len(value) <= 8

    compact = _SEPARATORS.sub("", value)
    if len(compact) < 16:
        return False

    return sum(1 for pattern in _CLASSES if pattern.search(compact)) >= 2


def _leaked_token(response: httpx.Response) -> str:
    """The name of a token-shaped key holding a secret in a JSON reset response, or "".

    Restricted to JSON on purpose. An HTML reset page re-renders its own form, and that
    form legitimately contains a CSRF token in a hidden input - reporting that as a
    leaked reset token would be a false positive on a correctly built site.
    """
    content_type = response.headers.get("content-type", "").lower()
    if "json" not in content_type:
        return ""

    body = response.text or ""
    for match in _TOKEN_PAIR.finditer(body):
        if _looks_like_secret(match.group(2), match.group(1)):
            return match.group(1)
    return ""


async def check_password_reset(target) -> dict:
    """Probe the reset flow with a real and a nonexistent address and compare the answers."""
    outcome = await authenticated_session(target)

    # The gate described at the top of this file: no proven control of the mailbox, no
    # reset email. session_skip_finding explains whichever wall was hit.
    if not outcome.ok:
        return session_skip_finding(_build_finding, outcome, "the password reset flow")

    credentials = target.credentials or {}
    username = str(credentials.get("username") or "").strip()

    reset_urls = find_reset(target) or candidate_paths(target, RESET_PATHS)
    if not reset_urls:
        return _build_finding(
            severity=SKIPPED,
            title="No password reset flow was found",
            description="This check could not locate a password reset page to test",
            explanation=(
                "No 'forgot password' link was found on the pages the scanner fetched, "
                "and none of the conventional reset paths applied.\n\nA site may "
                "legitimately have no self-service reset - accounts managed by an "
                "administrator or by an external identity provider do not need one - so "
                "this is not reported as a fault. It is reported as skipped because "
                "nothing was tested."
            ),
            fix=(
                "No action indicated. If your reset flow lives at an unconventional "
                "address, supplying the login URL in the scan request helps the scanner "
                "find the pages linked from it."
            ),
            evidence={"triedPaths": candidate_paths(target, RESET_PATHS)[:6]},
        )

    reset_url = reset_urls[0]
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html, application/json"}

    async with httpx.AsyncClient(
        timeout=TIMEOUT_SECONDS, headers=headers, follow_redirects=False
    ) as client:
        # 1. READ THE FORM. Needed to learn what the address field is called; a probe
        # posted under the wrong field name tests nothing and both answers would match,
        # which would read as a pass.
        try:
            page_response = await client.get(reset_url)
            page = _parse_page(page_response)
        except httpx.RequestError as exc:
            return _build_finding(
                severity=SKIPPED,
                title="Could not reach the password reset page",
                description="The request to the reset page failed",
                explanation=(
                    f"The reset page at {reset_url} could not be fetched "
                    f"({type(exc).__name__}), so the flow was not tested.\n\nThis is a "
                    "connectivity result, not a security finding."
                ),
                fix="Confirm the reset page is reachable and re-run the scan.",
                evidence={"resetUrl": reset_url, "error": type(exc).__name__},
            )

        address_field, extra, form_action = _reset_form_fields(page)
        submit_url = urljoin(reset_url, form_action) if form_action else reset_url

        # The nonexistent address. .invalid is reserved by RFC 2606 and can never be
        # registered, so this can never collide with a real person's mailbox - the same
        # reasoning and the same suffix as the Tier 1 enumeration check.
        absent_address = f"secuscan_probe_{uuid4().hex[:10]}@example.invalid"

        payload_present = {**extra, address_field: username}
        payload_absent = {**extra, address_field: absent_address}

        as_json = "/api/" in submit_url or "json" in (
            page_response.headers.get("content-type", "").lower()
        )

        async def send(payload):
            if as_json:
                return await client.post(submit_url, json=payload)
            return await client.post(submit_url, data=payload)

        try:
            # THE ABSENT ADDRESS GOES FIRST. If a rate limiter trips after one request,
            # the probe that was spent is the harmless one, and the check reports a wall
            # rather than having emailed the client's account for nothing.
            res_absent = await send(payload_absent)
            res_present = await send(payload_present)
        except httpx.RequestError as exc:
            return _build_finding(
                severity=SKIPPED,
                title="Could not complete the password reset test",
                description="A request to the reset endpoint failed",
                explanation=(
                    f"A probe to the reset endpoint failed ({type(exc).__name__}), so "
                    "the comparison could not be made.\n\nThis is a connectivity "
                    "result, not a security finding."
                ),
                fix="Re-run the scan.",
                evidence={"resetUrl": submit_url, "error": type(exc).__name__},
            )

    msg_present = _excerpt(res_present)
    msg_absent = _excerpt(res_absent)

    evidence = {
        "resetEndpoint": submit_url,
        "addressField": address_field,
        "statusForKnownAddress": res_present.status_code,
        "statusForUnknownAddress": res_absent.status_code,
        "messageForKnownAddress": msg_present[:150],
        "messageForUnknownAddress": msg_absent[:150],
    }

    # A WALL IS NOT A PASS. Checked before anything else, because a CSRF token this
    # check does not hold produces two identical rejections - which is byte-for-byte
    # what a correctly uniform reset endpoint produces. Reporting that as a clean
    # result would be claiming a control had been verified when the requests never
    # reached the application.
    if _looks_blocked(res_present) and _looks_blocked(res_absent):
        return _build_finding(
            severity=SKIPPED,
            title="The password reset probes were turned away",
            description="Both reset probes were rejected before the application processed them",
            explanation=(
                f"Both probes to {submit_url} were refused identically "
                f"(HTTP {res_absent.status_code} and {res_present.status_code}), which "
                "indicates they never reached the reset logic - typically a CSRF token "
                "this check does not carry, a CAPTCHA, a bot filter, or rate "
                "limiting.\n\nRate limiting and CAPTCHA on a reset form are good "
                "things to have. But they also mean nothing about this endpoint's "
                "behaviour was observed, so the result is skipped rather than passed: "
                "two identical rejections look exactly like two identical correct "
                "answers, and the difference matters."
            ),
            fix=(
                "No action indicated. To have this check run, allowlist the scanner's "
                "source address for the duration of the scan."
            ),
            evidence=evidence,
        )

    # THE TOKEN IS IN THE RESPONSE. Checked before enumeration because it is strictly
    # worse: an endpoint that hands out the reset secret does not need to be enumerated,
    # the address is already enough to take the account.
    leaked = _leaked_token(res_present) or _leaked_token(res_absent)
    if leaked:
        return _build_finding(
            severity=CRITICAL,
            title="The password reset response contains the reset token",
            description="The reset endpoint returns the secret it should only send by email",
            explanation=(
                f"The response from {submit_url} contains a `{leaked}` field holding a "
                "token-shaped value.\n\nA password reset code works because only the "
                "person reading that mailbox can see it. Returning it in the HTTP "
                "response removes that requirement entirely: anyone who knows an "
                "address can request a reset, read the token out of the reply, and set "
                "a new password on that account. No access to the email is needed at "
                "any point.\n\nThis is full account takeover from nothing but an email "
                "address, and it is usually a debugging convenience that was never "
                "removed."
            ),
            fix=(
                "Remove the token from the response body. The endpoint should return "
                "only a generic acknowledgement - the same one whether or not the "
                "address has an account - and the code should travel by email and "
                "nowhere else.\n\nIf the token is in the response to support an "
                "automated test, have the test read it from the mail transport or a "
                "test-only hook rather than from the production code path."
            ),
            evidence={**evidence, "leakedField": leaked},
        )

    status_differs = res_present.status_code != res_absent.status_code

    # A message difference only counts as enumeration when one of the two answers
    # actually NAMES the account's state. Reset pages differ constantly for reasons that
    # leak nothing - a CSRF token in the re-rendered form, the address echoed back into
    # the input - so a bare text difference is not evidence.
    absent_says_unknown = bool(_NOT_FOUND_HINTS.search(msg_absent))
    present_says_sent = bool(_FOUND_HINTS.search(msg_present))
    message_differs = msg_present != msg_absent and (absent_says_unknown or present_says_sent)

    if status_differs or message_differs:
        detail = []
        if status_differs:
            detail.append(
                f"the unknown address returned HTTP {res_absent.status_code} where the "
                f"known one returned HTTP {res_present.status_code}"
            )
        if message_differs:
            detail.append("the two addresses received different messages")

        return _build_finding(
            severity=WARNING,
            title="The password reset form reveals which addresses have accounts",
            description="The reset endpoint answers differently for a registered address",
            explanation=(
                f"Two reset requests were sent to {submit_url} - one for the test "
                "account's own address, one for a randomly generated address that "
                f"cannot exist. They were answered differently: {', and '.join(detail)}."
                "\n\nThat difference turns the reset form into a membership lookup. "
                "Anyone can submit an address and learn from the answer whether that "
                "person has an account here - no login, no rate limit to defeat beyond "
                "submitting a form, and nothing in your logs that looks unusual.\n\n"
                "What that discloses depends on what your service is. For many sites it "
                "is a privacy leak and a shortcut for credential-stuffing, letting an "
                "attacker narrow a breached address list to your actual users before "
                "trying a single password. For a service where being a customer is "
                "itself sensitive, the list of who has an account is the confidential "
                "information, and this hands it out an address at a time."
            ),
            fix=(
                "Return one identical response for every address: the same status code "
                "and the same message, whether or not an account exists. 'If an account "
                "exists for that address, we've sent reset instructions' is accurate in "
                "both cases and discloses nothing.\n\nThe flow behind it stays the "
                "same - send the email when the account exists, and do nothing when it "
                "does not. Only the reply the stranger sees has to be constant."
            ),
            evidence=evidence,
        )

    return _build_finding(
        severity=PASSED,
        title="The password reset form does not reveal who has an account",
        description="Registered and unregistered addresses receive the same response",
        explanation=(
            f"Two reset requests were sent to {submit_url} - one for the test account's "
            "own address and one for a randomly generated address that cannot exist. "
            "Both received the same status code and the same message, and the response "
            "carried no reset token.\n\nThis is the correct behaviour. Someone "
            "submitting an address to your reset form learns nothing about whether that "
            "address has an account here, so the form cannot be used to test an address "
            "list against your user base."
        ),
        fix="No action required.",
        evidence=evidence,
    )
