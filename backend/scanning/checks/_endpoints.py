"""
FINDING THE AUTHENTICATED ENDPOINTS - logout, password reset, and account security.

WHY THIS FILE EXISTS
Three of the four authenticated checks start with the same question: where is the thing
I am supposed to test? The logout check needs the sign-out link, the reset check needs
the "forgot password" link, and the 2FA check needs the account-security page. Each would
otherwise carry its own list of candidate paths and its own link-scanning loop, which is
three copies of a list that will drift the moment one of them learns about a new
convention.

IT READS PAGES THAT WERE ALREADY FETCHED, FIRST.
discovery.py has already retrieved the homepage and the login page and parsed every link
out of them, and a Page carries those links as (absolute_url, text) pairs. Searching that
costs nothing and sends no traffic. Only when the links yield nothing does a check fall
back to probing conventional paths, and that decision belongs to the check rather than
here - this module finds and ranks candidates, it does not request them.

EVERY CANDIDATE IS FILTERED THROUGH same_site().
This is the rule discovery.py sets out at length and the reason it exists: a "Sign out"
link on a site using an external identity provider points at accounts.google.com or an
Okta tenant. Following it would send this scan's traffic to a third party who never
consented to being scanned - the precise thing a consent-based product cannot do. An
off-site match is discarded here rather than at the call site, so no check can forget.
"""

import re

from ._session import same_site


# --- What each endpoint looks like -----------------------------------------


# WHY HREF AND TEXT ARE MATCHED SEPARATELY
# A link's href and its visible text fail in opposite directions. "/auth/signout" has an
# unmistakable href and may have an icon for its text; "Sign out" has unmistakable text
# and may live behind "/a/x7f2". Matching either catches both shapes, and requiring both
# would miss both.

# LOGOUT. The \b on "out" keeps "logout" and "log out" while refusing "outlet" and
# "outbound" - a nav bar with "Outlet" in it should not read as a sign-out link.
_LOGOUT_HREF = re.compile(r"(logout|log-out|log_out|signout|sign-out|sign_out|/exit\b)", re.I)
_LOGOUT_TEXT = re.compile(r"\b(log\s?out|sign\s?out|log\s?off|sign\s?off)\b", re.I)

# PASSWORD RESET. "forgot", "reset password" and "recover" are the three conventions; the
# separate "password" requirement on "reset" keeps this off "reset filters" and the like.
_RESET_HREF = re.compile(
    r"(forgot[-_]?password|forgot|reset[-_]?password|password[-_]?reset|recover|lost[-_]?password)",
    re.I,
)
_RESET_TEXT = re.compile(
    r"(forgot.{0,12}password|reset.{0,12}password|password.{0,12}reset|"
    r"can.?t (log|sign) in|lost.{0,12}password|recover.{0,12}account)",
    re.I,
)

# ACCOUNT SECURITY, where two-factor enrolment lives when it exists.
_SECURITY_HREF = re.compile(
    r"(security|two[-_]?factor|2fa|mfa|authenticator|account/settings|settings/account|"
    r"account/security|profile/security)",
    re.I,
)
_SECURITY_TEXT = re.compile(
    r"(security|two[-\s]?factor|2fa|mfa|authenticator|account settings|my account)", re.I
)


# Conventional paths, tried only when no link matched. Ordered by how common they are, so
# a check that probes only the first few still has the best chance of a hit.
LOGOUT_PATHS = ("/logout", "/signout", "/sign-out", "/auth/logout", "/users/sign_out", "/account/logout")
RESET_PATHS = ("/forgot-password", "/password/reset", "/reset-password", "/account/recover", "/forgot")
SECURITY_PATHS = ("/settings/security", "/account/security", "/settings", "/account", "/profile/security")


# --- The search ------------------------------------------------------------


def _pages(target) -> list:
    """Every page discovery actually fetched, in one fixed search order.

    The login page comes first because it is the page that carries the links this module
    is usually asked for - "Forgot password?" lives there and nowhere else. The order is
    the same for all three finders: a signed-out homepage will not carry a sign-out link
    either way, so specialising the order per endpoint would buy nothing and would leave
    three orderings to keep in step.
    """
    return [p for p in (target.login, target.home, target.signup) if p is not None]


def _same_document(url: str) -> str:
    """A URL reduced to the document it addresses, for comparing two URLs for identity.

    Drops the fragment and a trailing slash, so "https://x.test/a#b", "https://x.test/a"
    and "https://x.test/a/" are recognised as one document.
    """
    url = (url or "").split("#", 1)[0]
    return url.rstrip("/") or url


def _match_links(target, href_pattern, text_pattern) -> list:
    """Absolute, same-site URLs from already-fetched pages whose href or text matches.

    Returns them in page order with duplicates removed, so a link appearing in both the
    header and the footer is one candidate rather than two requests.
    """
    found = []
    seen = set()

    # The documents discovery has already fetched. Any candidate that resolves to one of
    # these is rejected below - see THE SELF-REFERENCE GUARD.
    already_fetched = {_same_document(p.url) for p in _pages(target) if p.url}

    for page in _pages(target):
        for url, text in page.links:
            if not url:
                continue

            # .strip() before anything else: an href may carry leading whitespace, and
            # urljoin preserves it verbatim, so " javascript:x()" would otherwise read as
            # a scheme of " javascript" and slip past the next guard.
            raw = url.strip()

            # Non-navigational hrefs. A "mailto:" or "javascript:void(0)" is not an
            # endpoint.
            scheme = raw.split(":", 1)[0].lower() if ":" in raw else ""
            if scheme in ("mailto", "tel", "javascript"):
                continue

            # A fragment addresses a position WITHIN a document, never a different
            # document, and it is never transmitted to the server. Dropping it here is
            # what makes "/account/settings#security" match as "/account/settings", and
            # it is also what collapses a bare "#" or "#logout" onto the page the link
            # was found on - which the self-reference guard then rejects.
            candidate = raw.split("#", 1)[0]
            if not candidate or candidate in seen:
                continue

            # Matched AFTER the fragment is gone, deliberately. A href of "#logout" only
            # says "logout" in the part the server will never see; treating that as a
            # logout endpoint means requesting the current page instead.
            if not (href_pattern.search(candidate) or text_pattern.search(text or "")):
                continue

            # THE THIRD-PARTY GUARD. See the note at the top of this file.
            if not same_site(target.url, candidate):
                continue

            # THE SELF-REFERENCE GUARD.
            # A link that resolves to a page the scanner has already fetched is not an
            # endpoint, it is the document it was found on. This is what a JavaScript
            # control looks like to a parser: <a href="#">Sign out</a> is the sign-out
            # button on a great many sites, and urljoin resolves that bare "#" to the
            # page's own address. Without this guard find_logout answers "the homepage",
            # the logout check GETs it, gets a perfectly healthy 200 - so the refused-
            # sign-out gate, which only fires on >= 400, does not catch it - replays the
            # cookie, finds the session alive because nothing ever signed out, and
            # reports CRITICAL "signing out does not destroy the session" against a site
            # whose logout is fine. Dropping the candidate instead lets the check fall
            # through to the conventional paths below, where the real endpoint usually is.
            if _same_document(candidate) in already_fetched:
                continue

            seen.add(candidate)
            found.append(candidate)

    return found


def find_logout(target) -> list:
    """Candidate sign-out URLs, best first. May be empty."""
    return _match_links(target, _LOGOUT_HREF, _LOGOUT_TEXT)


def find_reset(target) -> list:
    """Candidate password-reset URLs, best first. May be empty."""
    return _match_links(target, _RESET_HREF, _RESET_TEXT)


def find_security(target) -> list:
    """Candidate account-security URLs, best first. May be empty."""
    return _match_links(target, _SECURITY_HREF, _SECURITY_TEXT)


def candidate_paths(target, paths) -> list:
    """Conventional paths resolved against the target, for a check that found no links.

    Same-site by construction - they are built from the target's own URL - but filtered
    anyway so that one function is the only thing deciding what is in scope.
    """
    from urllib.parse import urljoin

    base = target.url or ""
    out = []

    for path in paths:
        url = urljoin(base, path)
        if same_site(base, url):
            out.append(url)

    return out
