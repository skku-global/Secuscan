"""
TWO-FACTOR CHECK - Tier 2. Is there actually a way to turn 2FA on, behind the login?

HOW THIS DIFFERS FROM THE TIER 1 MFA CHECK
mfa_check.py reads the public pages - the homepage, the login page, the signup page - and
looks for any mention of multi-factor authentication. That is the only thing an
unauthenticated scanner can do, and it has a known weakness the check itself admits to:
almost every application keeps its two-factor setup on the account security page, which
is behind the login. So a site with excellent 2FA that simply does not advertise it on
its marketing pages gets a warning it does not deserve, and the only way to resolve that
is to sign in and look.

This check signs in and looks. It is the authoritative answer to the same question, and
its verdict should be read as superseding the Tier 1 one when both are present in a
report - which is exactly why it exists.

WHAT COUNTS AS AN ANSWER
Finding enrolment controls on the account security page is good evidence: a page offering
"Set up authenticator app", "Add a security key" or "Two-factor authentication" is a page
where a user can turn it on. Not finding them is weaker evidence - the page may live
somewhere this check did not look - so the absence is reported as a WARNING that says
where it looked, not as a statement that 2FA does not exist.

THE TRAP THIS CHECK HAS TO AVOID
The security page is behind authentication, so fetching it with a dead session returns
the login page. The login page has a password field and no 2FA controls, and reading it
naively produces the report's worst possible outcome: "no two-factor authentication
available", stated confidently, about a page the scanner was never actually shown. Every
fetch below is therefore tested for whether it landed on a login screen, and that case is
SKIPPED rather than answered.

WHAT KIND OF SECOND FACTOR
Where it can tell, the check distinguishes phishing-resistant factors (passkeys, security
keys, WebAuthn) and authenticator apps from SMS. SMS is genuinely better than nothing and
is reported as a pass, with the SIM-swap caveat stated rather than scored - the same
position mfa_check.py takes, kept deliberately consistent so the two checks never appear
to disagree.
"""

import re

import httpx

from ._endpoints import SECURITY_PATHS, candidate_paths, find_security
from ._finding import PASSED, SKIPPED, TIMEOUT_SECONDS, USER_AGENT, WARNING, finding_builder
from ._session import authenticated_session, session_skip_finding, visible_text

CHECK_ID = "two_factor_check"

_build_finding = finding_builder(CHECK_ID, tier=2)


# Controls that let a user ENROL. The verbs matter: "two-factor authentication" alone
# also appears in a security policy page that offers nothing, whereas "set up", "enable"
# and "add" next to it indicate a control rather than prose.
_ENROL_TEXT = re.compile(
    r"((set ?up|enable|turn on|add|configure|register|activate).{0,40}"
    r"(two[- ]?factor|2fa|mfa|authenticator|security key|passkey|totp|one[- ]?time)|"
    r"(two[- ]?factor|2fa|mfa).{0,40}(authentication|enabled|disabled|is (on|off))|"
    r"authenticator app|security key|passkey|scan.{0,20}qr code|recovery codes?|"
    r"backup codes?|verification codes?)",
    re.I,
)

# Phishing-resistant: possession of a key bound to the origin. These cannot be phished or
# replayed, which is the distinction worth drawing.
_STRONG_TEXT = re.compile(
    r"(passkey|security key|webauthn|fido2?|yubikey|hardware key|biometric|face id|touch id)",
    re.I,
)

# An authenticator app - a shared secret producing a rotating code. Phishable in real
# time, but immune to SIM swapping and to a leaked password alone.
_TOTP_TEXT = re.compile(
    r"(authenticator app|google authenticator|authy|1password|totp|"
    r"time[- ]based.{0,20}code|scan.{0,20}qr)",
    re.I,
)

# SMS delivery.
#
# THE BARE `mobile number` ALTERNATIVE IS DELIBERATELY LOOSE, AND IT MATCHES mfa_check.py
# EXACTLY (this pattern is its narrower twin - the phone-number branch here additionally
# requires "verif" nearby). The looseness is a real, accepted risk: an account page that
# merely displays a phone number, alongside a mention of recovery codes, would read as
# SMS-only and earn a PASS. It is left alone because the alternative is worse - narrowing
# it here but not in the Tier 1 check would make two checks that answer the same question
# give different verdicts on the same site, and the docstring's whole point is that this
# check SUPERSEDES the Tier 1 one rather than contradicting it. The failure mode is also
# bounded in a way a false PASS usually is not: the SMS-only branch still tells the reader
# their second factor is the weakest kind and names TOTP as the upgrade, so the advice is
# right even when the detection is generous.
_SMS_TEXT = re.compile(
    r"(text message|via sms|sms code|code (via|by) text|mobile number|phone number.{0,30}verif)",
    re.I,
)

# Markers that this page is a login screen rather than an account page - the trap the
# module docstring describes.
_LOGIN_PAGE_TEXT = re.compile(
    r"(sign in to|log in to|forgot.{0,12}password|remember me|"
    r"don.t have an account|create an account|new here)",
    re.I,
)


# Script and style bodies are dropped before the tags: an analytics snippet naming a
# "securityKey" variable is not a control the user can press. This check found that first
# and fixed it locally; the implementation now lives in _session.py so that the modules
# deciding whether a login worked get it too - there, an inline script was enough to turn
# a successful sign-in into "blocked" and cost all four Tier 2 checks their session.
_visible_text = visible_text


def _is_login_screen(response: httpx.Response, text: str) -> bool:
    """Whether this response is the login page rather than the page that was asked for.

    A password input plus login-page prose. Either alone is not enough: an account page
    can legitimately have a password field (the change-password form) and a security page
    can mention "forgot password" in a link, but the two together mean the session did
    not carry.
    """
    has_password_input = bool(re.search(r"type=[\"']?password", response.text or "", re.I))
    return has_password_input and bool(_LOGIN_PAGE_TEXT.search(text))


async def check_two_factor(target) -> dict:
    """Sign in, open the account security page, and see whether 2FA can be turned on."""
    outcome = await authenticated_session(target)

    if not outcome.ok:
        return session_skip_finding(_build_finding, outcome, "two-factor authentication availability")

    # Links found on already-fetched pages first, conventional paths second. Capped at
    # four: past that the check is no longer looking for a security page, it is crawling.
    candidates = find_security(target) or []
    for url in candidate_paths(target, SECURITY_PATHS):
        if url not in candidates:
            candidates.append(url)
    candidates = candidates[:4]

    if not candidates:
        return _build_finding(
            severity=SKIPPED,
            title="No account security page was found",
            description="This check could not locate an account settings page to inspect",
            explanation=(
                "The test account signed in, but no account or security settings page "
                "was found among the links the scanner had, and none of the "
                "conventional paths applied.\n\nWhether two-factor authentication can "
                "be enabled was therefore not tested. Reported as skipped rather than "
                "as an absence: nothing was observed."
            ),
            fix="No action indicated. This is a limitation of the scan, not a finding.",
            evidence={"triedPaths": candidate_paths(target, SECURITY_PATHS)[:6]},
        )

    headers = {"User-Agent": USER_AGENT, "Accept": "text/html"}
    visited = []
    login_walls = 0
    best_text = ""
    best_url = ""

    async with httpx.AsyncClient(
        timeout=TIMEOUT_SECONDS, headers=headers, follow_redirects=True
    ) as client:
        for url in candidates:
            try:
                response = await client.get(url, cookies=outcome.cookies)
            except httpx.RequestError as exc:
                visited.append({"url": url, "error": type(exc).__name__})
                continue

            text = _visible_text(response)
            landed = str(response.url)

            # THE TRAP. A redirect to the login page, or a login page served in place of
            # the account page, means this fetch shows nothing about the account.
            if _is_login_screen(response, text):
                login_walls += 1
                visited.append({"url": url, "status": response.status_code, "result": "login screen"})
                continue

            if response.status_code >= 400:
                visited.append({"url": url, "status": response.status_code})
                continue

            visited.append({"url": url, "status": response.status_code, "landedOn": landed})

            if _ENROL_TEXT.search(text):
                best_text = text
                best_url = landed
                break

            # Keep the longest real page seen, so the evidence names the page that was
            # actually examined when nothing matched anywhere.
            if len(text) > len(best_text):
                best_text = text
                best_url = landed

    # EVERY CANDIDATE WAS A LOGIN SCREEN. The session did not reach any account page, so
    # the absence of 2FA controls says nothing at all.
    if login_walls and not best_url:
        return _build_finding(
            severity=SKIPPED,
            title="The account pages could not be reached while signed in",
            description="Every candidate settings page returned a login screen",
            explanation=(
                "The test account signed in, but each account page this check tried "
                "returned a login screen rather than account content - so the session "
                "did not carry to those pages.\n\nThis usually means the application "
                "issues a second cookie or a bearer token that this check does not "
                "replay. Whether two-factor authentication is available was not "
                "determined, and is deliberately not guessed at: a login page has no "
                "2FA controls on it, and reading that as 'no 2FA offered' would be a "
                "confident answer about a page the scanner was never shown."
            ),
            fix="No action indicated. This is a limitation of the scan, not a finding.",
            evidence={"pagesTried": visited},
        )

    if not best_url:
        return _build_finding(
            severity=SKIPPED,
            title="The account security page could not be opened",
            description="No account settings page could be read while signed in",
            explanation=(
                "None of the candidate account pages could be read while signed in, so "
                "two-factor availability was not tested.\n\nReported as skipped rather "
                "than as an absence, because nothing was observed."
            ),
            fix="No action indicated.",
            evidence={"pagesTried": visited},
        )

    evidence = {
        "securityPage": best_url,
        "pagesTried": visited,
        "signedIn": True,
    }

    if not _ENROL_TEXT.search(best_text):
        return _build_finding(
            severity=WARNING,
            title="No way to enable two-factor authentication was found",
            description="The account security page offers no second-factor enrolment",
            explanation=(
                f"Signed in as the test account, {best_url} was read and no control for "
                "enabling two-factor authentication was found on it - no authenticator "
                "app setup, no security key or passkey registration, no backup "
                "codes.\n\nWithout a second factor, a password is the only thing "
                "standing between an attacker and an account. Passwords are reused "
                "across sites, and breaches elsewhere mean that lists of working "
                "address-and-password pairs for your users may already exist through no "
                "fault of yours or theirs. Two-factor authentication is what makes those "
                "lists useless against you.\n\nThis check looked on the account pages it "
                "could find, listed in the evidence. If your enrolment lives somewhere "
                "else, treat this as not-found rather than not-present."
            ),
            fix=(
                "Offer two-factor authentication on the account security page. An "
                "authenticator app (TOTP) is the usual starting point - it needs no SMS "
                "gateway and no per-message cost, and libraries exist for every "
                "framework. Passkeys or security keys are stronger still, because they "
                "cannot be phished.\n\nIssue recovery codes at enrolment so that a lost "
                "phone does not become a lost account, and require the current password "
                "before 2FA can be turned off."
            ),
            evidence=evidence,
        )

    # 2FA enrolment exists. Name which kind, because the difference is real.
    has_strong = bool(_STRONG_TEXT.search(best_text))
    has_totp = bool(_TOTP_TEXT.search(best_text))
    has_sms = bool(_SMS_TEXT.search(best_text))

    evidence["factors"] = {
        "phishingResistant": has_strong,
        "authenticatorApp": has_totp,
        "sms": has_sms,
    }

    # SMS ONLY. A pass, with the caveat stated - the same position the Tier 1 check
    # takes, worded consistently so the two never look like they disagree.
    if has_sms and not has_strong and not has_totp:
        return _build_finding(
            severity=PASSED,
            title="Two-factor authentication is offered, but only by SMS",
            description="A second factor can be enabled, delivered as a text message",
            explanation=(
                f"Signed in as the test account, {best_url} offers two-factor "
                "authentication by text message.\n\nThis is a real improvement over a "
                "password alone and it counts as a pass. It is worth knowing its limit: "
                "a code sent by SMS can be intercepted by persuading a mobile operator "
                "to move the number to a new SIM, which is a documented and "
                "unfortunately routine attack against accounts worth taking. The number "
                "is also often recoverable from public records.\n\nAn authenticator app "
                "removes the operator from the picture entirely, and a passkey removes "
                "phishing as well."
            ),
            fix=(
                "No action required. If you later want to strengthen it, offering an "
                "authenticator app (TOTP) alongside SMS lets security-conscious users "
                "opt out of the SIM-swap risk without taking anything away from anyone."
            ),
            evidence=evidence,
        )

    if has_strong:
        kind = "phishing-resistant factors (passkeys or security keys)"
    elif has_totp:
        kind = "an authenticator app"
    else:
        kind = "a second factor"

    return _build_finding(
        severity=PASSED,
        title="Two-factor authentication can be enabled",
        description=f"The account security page offers {kind}",
        explanation=(
            f"Signed in as the test account, {best_url} offers two-factor authentication "
            f"using {kind}.\n\nThis is the control that makes a stolen or reused password "
            "insufficient on its own. Because this was read from the account page while "
            "signed in, it reflects what your users can actually turn on - not what the "
            "marketing pages happen to mention."
        ),
        fix="No action required.",
        evidence=evidence,
    )
