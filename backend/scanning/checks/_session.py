"""
THE SHARED AUTHENTICATED SESSION - one login per scan, reused by every Tier 2 check.

WHY THIS FILE EXISTS
Four Tier 2 checks need to be signed in: the session cookie check reads the cookie the
login actually set, the logout check needs a session to destroy, the 2FA check looks for
an enrolment page that only exists behind the login, and the reset check wants the
account page's view of password recovery. Written independently, each would log in for
itself.

THAT IS NOT A TIDINESS PROBLEM, IT IS A SAFETY ONE. engine.py runs the checks
concurrently through asyncio.gather, so four independent logins are four near-simultaneous
authentication attempts against one test account. If any of them gets the password
subtly wrong - a form field named differently than expected, a CSRF token not carried -
they are four FAILED logins in a burst, which is the shape of a credential-stuffing
attack and exactly what a lockout policy exists to stop. The client's test account would
be locked for the rest of the scan, every dependent check would report a wall, and the
scan would have caused the failure it then reported.

The same budgeting rule already governs account_enumeration_check.py, which holds itself
to three measured attempts plus one warm-up for precisely this reason. This module is how
that budget stays whole once there are five active checks instead of one: ONE login per
scan, whoever asks for it first, and every other check waits for that result and shares
it.

WHAT THE LOCK IS FOR
Memoising with a plain "if we have it, return it" is not enough under gather. All four
checks reach the cache miss before any of them finishes logging in, so all four log in -
the exact stampede this file exists to prevent. The asyncio.Lock makes the first caller
do the work and the other three wait on the result. It is created per ScanTarget rather
than at module level, because a module-level lock would serialise unrelated concurrent
scans against each other.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
It does not decide whether a site is secure. It performs one login, reports honestly
whether it worked, and hands back the evidence. Every verdict belongs to the check that
asked. A helper that returned "looks fine" would be a helper making findings, and four
checks would inherit one opinion.

TIER 2 ONLY. This module sends POST requests. It must never be imported by a Tier 1
check - see the source walk in tests/test_branches.py, which fails the build on a write
verb anywhere in a Tier 1 module, and the note there about how cheap the mistake is.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from ._finding import TIMEOUT_SECONDS, USER_AGENT

_log = logging.getLogger("checks.session")


# Field-name hints, shared with account_enumeration_check.py's reading of the same forms.
_USERNAME_HINT = re.compile(r"(user|email|login|account|identifier|name)", re.I)

# Input types that are NOT a box a person can type a username into.
#
# AN EXCLUDE LIST, NOT AN INCLUDE LIST, and that is the whole point: a browser renders an
# input with an unrecognised type as a plain text box, so <input type="username"> really is
# a text field on the real web. An include list of ("text", "email", ...) would miss it and
# fall back to guessing, which is worse than the one line this costs.
_NON_ENTRY_TYPES = frozenset({
    "password", "hidden", "submit", "button", "reset", "image",
    "file", "checkbox", "radio", "range", "color",
})

# Text that means the login was REFUSED, not completed. Checked against the response to
# the credentials POST, because a site that re-renders the login page with an error is
# returning HTTP 200 and would otherwise read as success.
_LOGIN_FAILED_HINTS = re.compile(
    r"(invalid|incorrect|failed|not recognised|not recognized|try again|"
    r"wrong (password|username|email)|does not match|unable to sign|"
    r"authentication failed|bad credentials)",
    re.I,
)

# THE WALLS - responses meaning the request never reached the application logic at all.
#
# THIS IS THE ONLY COPY. account_enumeration_check.py and password_reset_check.py import
# it from here, and logout_check.py imports _looks_blocked below, which is built on it.
# Each of those modules used to carry its own hand-written version of this vocabulary,
# "kept local so the check reads on its own", and all three had drifted apart: only the
# reset check knew the word "cloudflare", only this module knew "verification", only two
# of the three knew "not allowed", and the enumeration check had no status list at all.
# The drift is the bug, not the duplication - the same rule, and the same cause, as the
# local copy of the session-name pattern in session_cookie_check.py that made a cookie
# called app_sid_v2 a session to the login code and invisible to the check reading it.
#
# The vocabulary below is the UNION of what the three knew, with two deliberate
# narrowings where the widest version was reaching too far:
#
#   "verification" alone (this module's) matched any page using the word, so a dashboard
#   with an "Identity verification queue" panel read as a WAF interstitial. It now needs
#   a wall-shaped phrase around it.
#
#   "blocked" alone (the reset check's) matched an admin page listing "Blocked users".
#   Narrowed to the phrasings a wall actually uses.
#
# "captcha" covers recaptcha and hcaptcha as substrings; they need no alternatives.
_BLOCKED_HINTS = re.compile(
    r"(csrf|xsrf|"                                                 # a token this cannot forge
    r"captcha|turnstile|cloudflare|incapsula|are you a robot|"     # bot filters and WAFs
    r"forbidden|access denied|request blocked|blocked by|not allowed|"  # flat refusals
    r"too many|rate limit|try again later|"                        # rate limiting
    r"verification (required|needed)|(human|browser|security) verification)",  # interstitials
    re.I,
)

_BLOCKED_STATUSES = frozenset({403, 405, 419, 429, 501, 502, 503, 504})

# Cookie names that are a session rather than a preference. Used to tell "the login set
# something that looks like a session" from "the login set a locale cookie".
_SESSION_NAME_HINT = re.compile(
    r"(sess|sid$|^sid|auth|token|jwt|login|remember|identity|_sid)", re.I
)

# CSRF TOKENS ARE NOT SESSIONS, and this exclusion is load-bearing.
#
# A CSRF cookie is set on the login PAGE, before anyone authenticates - that is the whole
# point of it. It also matches the pattern above, because "csrftoken" contains "token".
# Without this exclusion, a login that FAILED still comes back carrying a csrftoken, the
# success test below sees a session-shaped cookie, and the outcome reports ok=True for an
# attempt that was refused.
#
# That is not just an inaccurate flag. password_reset_check.py uses a successful login as
# its proof that the client controls the mailbox it is about to have a reset email sent
# to - the gate that stops the check being pointed at a stranger's address. A false ok
# opens that gate. So the narrower name test is a safety property, not tidiness.
_CSRF_NAME_HINT = re.compile(r"(csrf|xsrf)", re.I)


# --- What a login attempt produced -----------------------------------------


# WHY THE OUTCOME IS A DATACLASS AND NOT A TUPLE
# Five checks read this. A tuple would make every one of them depend on the ORDER of the
# fields, so inserting anything in the middle silently rebinds names at four call sites -
# the kind of change that type hints do not catch and tests only catch by luck.
@dataclass
class SessionOutcome:
    """The result of the one login this scan performs.

    `ok` is the only field a caller should branch on for "am I signed in". Everything
    else exists so a check can explain itself: a finding that says "could not test" is
    only useful if it also says which wall it hit.
    """

    ok: bool
    # Why it did not work, as a short machine-readable token: no_form, no_credentials,
    # blocked, rejected, unreachable, no_session_cookie. Empty when ok.
    reason: str = ""
    # Where the credentials were sent, for evidence. A URL, never a payload.
    submit_url: str = ""
    # The cookie jar after a successful login. This is what the other checks replay.
    #
    # PYTHON-SPECIFIC: default_factory because a mutable default would be shared by
    # every instance - the same trap discovery.py's dataclasses document.
    cookies: dict = field(default_factory=dict)
    # Raw Set-Cookie header lines from the login response, including redirect hops. The
    # session cookie check reads the ATTRIBUTES off these, which a parsed cookie jar
    # throws away - httpx.Cookies keeps the value and discards HttpOnly and SameSite.
    set_cookie_lines: list = field(default_factory=list)
    status: int = 0
    # A short, scrubbed excerpt of the response, for evidence. Never the whole body.
    detail: str = ""

    def session_cookie_names(self) -> list:
        """The cookie names that look like a session rather than a preference.

        CSRF cookies are excluded even though they match the session pattern - see the
        note on _CSRF_NAME_HINT for why that exclusion carries weight.
        """
        return [
            n
            for n in self.cookies
            if _SESSION_NAME_HINT.search(n) and not _CSRF_NAME_HINT.search(n)
        ]


# --- Reading the login form ------------------------------------------------


def _field_names(target) -> tuple:
    """Work out what the login form calls its username and password inputs.

    Falls back to the conventional names when discovery found no form, because a site
    with a JavaScript login screen has no <form> element to read and guessing the two
    most common names is better than refusing to try.
    """
    username_field = "email"
    password_field = "password"
    extra = {}
    candidates = []

    form = target.login_form()
    if form is None:
        return username_field, password_field, extra

    for f in form.fields:
        if f.type == "password":
            password_field = f.name or password_field
        elif f.type == "hidden" and f.name:
            # HIDDEN IS TESTED BEFORE THE NAME HINT, because a field's type is evidence
            # and its name is only a guess. A hidden input is never the box a human types
            # a username into - but its name very often matches _USERNAME_HINT anyway:
            # "login_challenge" (Ory), "account_id", "user_token", or a prefilled hidden
            # "email" on a two-step sign-in. With the name test first, such a field was
            # taken for the username input, and one mistake became three: the username
            # went out under the hidden field's name, the value the server was waiting on
            # was dropped, and the real username field was never sent at all. The login
            # then fails for a reason nothing in the report can explain, and all four
            # Tier 2 checks skip against a site whose credentials were perfectly good.
            #
            # Hidden fields are otherwise carried through as the server sent them. This
            # picks up static flags and, when discovery happened to fetch the same page
            # the token was minted for, a CSRF nonce. It often will not be valid by the
            # time this POST goes out - that case is detected and reported as a wall, not
            # guessed around, because forging a CSRF token is not an audit's job.
            extra[f.name] = f.attrs.get("value", "")
        elif f.tag == "input" and f.name and f.type not in _NON_ENTRY_TYPES:
            # A field a username could actually be typed into. Collected rather than
            # assigned, because which one it is depends on the others - see below.
            candidates.append(f)

    # WHICH CANDIDATE IS THE USERNAME: the first one whose NAME says so, and failing that
    # simply the first one.
    #
    # FIRST, NOT LAST. The previous version assigned as it went, so the LAST field to
    # match won - and the fields that come last in a login form are the ones that are not
    # the username. A trailing "<input type='text' name='otp_code'>" on a combined
    # sign-in form took the title, and the real username field was never sent at all. In
    # a login form the username box comes first; that is the tab order every site uses.
    #
    # AND ONLY TEXT-ENTRY INPUTS ARE EVEN CONSIDERED, which is the same rule as the hidden
    # branch above: the type is evidence, the name is only a guess. Without it,
    # _USERNAME_HINT matched things nobody types a username into, and because they sit at
    # the END of a form they won:
    #
    #     <input type="submit" name="login">        -> "login" matches the hint
    #     <input type="checkbox" name="remember_username">  -> so does this
    #     <select name="account_type">              -> and this
    #
    # The first of those is ordinary markup on a great many sites. The cost each time is
    # the same and it is not small: the username goes out under that field's name, the
    # real username field is never sent, the login fails for a reason nothing in the
    # report can explain, and all four Tier 2 checks skip against a site whose credentials
    # were perfectly good.
    for f in candidates:
        if _USERNAME_HINT.search(f.name):
            username_field = f.name
            break
    else:
        if candidates:
            username_field = candidates[0].name

    return username_field, password_field, extra


def _submit_url(target) -> str:
    """Where the credentials POST should go."""
    base = target.login.url if target.login else target.url
    form = target.login_form()

    if form is not None and form.submit_url:
        return urljoin(base, form.submit_url)

    # No form action, or no form: post back to the login page itself, which is what an
    # action-less <form> does by definition.
    return base or target.url


def visible_text(response: httpx.Response) -> str:
    """The plain text of a response, with script and style bodies dropped first.

    A SCRIPT BODY IS NOT TEXT, and dropping it is a safety property rather than tidiness.
    Tag-stripping alone leaves every line of every inline <script> in what this module
    then calls "the response text", which hands the JavaScript an ordinary application
    ships the power to decide what the scan concludes. Two one-line examples, both of
    them shapes a real dashboard ships:

        <script>window.csrfToken = "a1b2c3";</script>   ->  matches the wall vocabulary
        <script>if (!r.ok) show("invalid");</script>    ->  matches the refusal vocabulary

    The first turns a login that WORKED into reason="blocked"; the second turns the same
    login into reason="rejected". Because every Tier 2 check shares this one session,
    either outcome costs the customer all four of them at once - four skips reported
    against a site that let the scanner straight in, carrying a remediation that tells
    them to allowlist a scanner nothing ever blocked.

    two_factor_check.py found this first and for its own reason (an analytics snippet
    naming a "securityKey" variable is not a control a user can press) and fixed it
    locally. It lives here now so that one implementation answers the question for every
    caller, and so the next module needing plain text inherits the fix and not the bug.
    """
    try:
        html = response.text or ""
    except Exception:
        return ""
    html = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    text = re.sub(r"<[^>]+>", " ", html)
    return " ".join(text.split())


def _excerpt(response: httpx.Response, limit: int = 200) -> str:
    """A short plain-text excerpt of a response, for evidence."""
    return visible_text(response)[:limit]


def _looks_blocked(response: httpx.Response) -> bool:
    """Whether the request was turned away before the application looked at it."""
    if response.status_code in _BLOCKED_STATUSES:
        return True
    return bool(_BLOCKED_HINTS.search(_excerpt(response, 400)))


# --- The one login ---------------------------------------------------------


async def _perform_login(target) -> SessionOutcome:
    """Log in once. Called under the lock; never call this directly."""
    credentials = target.credentials or {}
    username = str(credentials.get("username") or "").strip()
    password = str(credentials.get("password") or "")

    if not username or not password:
        return SessionOutcome(ok=False, reason="no_credentials")

    submit_url = _submit_url(target)
    if not submit_url:
        return SessionOutcome(ok=False, reason="no_form")

    username_field, password_field, extra = _field_names(target)
    payload = {**extra, username_field: username, password_field: password}

    async with httpx.AsyncClient(
        timeout=TIMEOUT_SECONDS,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html, application/json"},
        # NOT following redirects: a successful login is very often a 302, and the
        # Set-Cookie that matters rides on THAT response. Following it hands back the
        # destination page and the hop's headers have to be dug out of .history.
        follow_redirects=False,
    ) as client:
        try:
            if "/api/" in submit_url:
                response = await client.post(submit_url, json=payload)
            else:
                response = await client.post(submit_url, data=payload)
        except httpx.RequestError as exc:
            return SessionOutcome(
                ok=False,
                reason="unreachable",
                submit_url=submit_url,
                # The exception TYPE, never str(exc): a message can carry a fragment of
                # the request, and the request here contains the client's password.
                # Same rule as _crash_finding in engine.py.
                detail=type(exc).__name__,
            )

        set_cookie_lines = list(response.headers.get_list("set-cookie"))
        cookies = {c.name: c.value for c in client.cookies.jar}
        status = response.status_code
        # NOTE: this excerpt is sized for EVIDENCE, and it is reused below as the window
        # the failure hints are matched against. That is deliberate rather than an
        # oversight, and the two windows differ on purpose: _looks_blocked searches 400
        # because a wall (a Cloudflare interstitial, a captcha page) can put its tell
        # further down, while the failure hints are matched against this narrower one.
        # Widening it would raise the chance of calling a GOOD login "rejected" - a page
        # containing the word "invalid" somewhere past this point would cost all four
        # checks their session. Both paths return SKIPPED rather than PASSED, so the
        # trade is between two honest messages, and the narrower window is the safer one.
        excerpt = _excerpt(response)

        # A WALL IS NOT A LOGIN. Checked before success, because several of these come
        # back as a 200 and would otherwise read as "signed in".
        if _looks_blocked(response):
            return SessionOutcome(
                ok=False,
                reason="blocked",
                submit_url=submit_url,
                status=status,
                detail=excerpt,
                set_cookie_lines=set_cookie_lines,
            )

        # An explicit refusal in the body. A site that re-renders its login page with
        # "Invalid username or password" answers 200, sets no session, and is emphatically
        # not signed in.
        if _LOGIN_FAILED_HINTS.search(excerpt):
            return SessionOutcome(
                ok=False,
                reason="rejected",
                submit_url=submit_url,
                status=status,
                detail=excerpt,
                set_cookie_lines=set_cookie_lines,
            )

        outcome = SessionOutcome(
            ok=False,
            submit_url=submit_url,
            cookies=cookies,
            set_cookie_lines=set_cookie_lines,
            status=status,
            detail=excerpt,
        )

        # THE SUCCESS TEST IS A SESSION COOKIE, NOT A STATUS CODE.
        #
        # Every other signal available here is ambiguous. A 200 is what both a successful
        # login and a re-rendered error page return. A 302 is what a success returns and
        # also what a redirect back to /login?error=1 returns. What a successful login
        # must do, in every session-cookie design, is hand back something to present on
        # the next request - so the presence of a session-shaped cookie is the closest
        # thing to an unambiguous signal that exists without a second request.
        #
        # Sites using a bearer token in a JSON body rather than a cookie are NOT detected
        # by this, and that is deliberate: those checks would have nothing to replay
        # anyway, so "no session cookie" is the honest answer for them too. It is
        # reported as its own reason so the finding can say which case it was.
        if outcome.session_cookie_names():
            outcome.ok = True
            return outcome

        outcome.reason = "no_session_cookie"
        return outcome


# --- The memoised entry point ----------------------------------------------


async def authenticated_session(target) -> SessionOutcome:
    """The one authenticated session for this scan. Safe to call from every check.

    The first caller performs the login; concurrent callers wait for it and receive the
    same SessionOutcome. Only one login happens per scan no matter how many checks ask,
    which is the whole point - see the note at the top of this file about lockouts.
    """
    # PYTHON-SPECIFIC: the lock and the cache hang off the ScanTarget instance rather
    # than a module-level dict keyed by target. A module-level cache would have to be
    # cleaned up when a scan ends, and forgetting that is a memory leak that also means
    # a later scan of the same site could read a stale session. Tying the lifetime to the
    # object means it is collected with the scan.
    lock = getattr(target, "_session_lock", None)
    if lock is None:
        # Safe without a lock of its own: this runs in one event loop and there is no
        # await between the check and the assignment, so no other coroutine can
        # interleave here.
        lock = asyncio.Lock()
        target._session_lock = lock

    async with lock:
        cached = getattr(target, "_session_outcome", None)
        if cached is not None:
            return cached

        outcome = await _perform_login(target)
        target._session_outcome = outcome

        if not outcome.ok:
            # Logged at debug and WITHOUT the detail string: the reason token is safe,
            # the excerpt may contain a fragment of the target's page.
            _log.debug("tier 2 login did not establish a session: %s", outcome.reason)

        return outcome


# --- Turning a failed login into a finding ---------------------------------


# WHY THIS LIVES HERE
# Four checks share one login, so they share the same four ways of not having one, and
# each would otherwise write its own wording for the same situation. Worse, each would
# make its own decision about severity - and the right answer is always SKIPPED, never
# PASSED, for the reason account_enumeration_check.py sets out at length: a check that
# could not run has observed nothing, and nothing observed can never be reported as
# nothing wrong.
_SESSION_FAILURE_TEXT = {
    "no_credentials": (
        "Tier 2 test account credentials required",
        "No test account username and password were supplied for this check",
        "This is an access-gated check: it signs in with a dedicated test account and "
        "examines what the application does once authenticated. Without credentials "
        "there is nothing to sign in with.\n\nSupply a dedicated test account in the "
        "Tier 2 access form to enable this check.",
        "Provide a dedicated test account username and password in the scan request.",
    ),
    "no_form": (
        "No login form was found",
        "This check could not locate a login form to authenticate against",
        "Endpoint discovery did not find a login form on the site, so there was nowhere "
        "to submit the test credentials.\n\nIf the login lives at an address the scanner "
        "did not try, supplying it directly in the scan request will let this check run.",
        "Supply the login URL in the scan request so the check can authenticate.",
    ),
    "blocked": (
        "The login could not be completed",
        "The sign-in attempt was turned away before the application processed it",
        "The credentials were submitted, but the response indicates the request never "
        "reached the authentication logic - typically a CSRF token this check does not "
        "carry, a WAF or bot filter, or rate limiting.\n\nThis is reported as skipped "
        "rather than passed deliberately. Nothing about the application's behaviour was "
        "observed, and a wall reported as a clean result is worse than no result.",
        "Allowlist the scanner's source address for the duration of the scan, or supply "
        "a direct authentication endpoint, so the sign-in reaches the application.",
    ),
    "rejected": (
        "The test account credentials were not accepted",
        "The application refused the supplied test account sign-in",
        "The credentials were submitted and the application rejected them.\n\nUsually "
        "this means the password has changed, the account is locked, or the account "
        "requires a second factor that this check cannot complete. Nothing is claimed "
        "about the application's security here - the check simply could not get in.",
        "Confirm the test account credentials are current and that the account can sign "
        "in without a second factor, then re-run the scan.",
    ),
    "no_session_cookie": (
        "The sign-in did not establish a session cookie",
        "No session cookie was returned, so the authenticated checks could not proceed",
        "The credentials were submitted and nothing that looks like a session cookie "
        "came back.\n\nThis is the expected result for an application that returns a "
        "bearer token in the response body rather than setting a cookie - a common and "
        "perfectly sound design, and one this cookie-based check has nothing to examine "
        "in. It is reported as skipped rather than passed because nothing was observed.",
        "No action if your application uses bearer tokens rather than session cookies. "
        "Otherwise, confirm the test account can sign in normally.",
    ),
    "unreachable": (
        "Could not reach the login endpoint",
        "The request to the sign-in endpoint failed",
        "The connection to the login endpoint could not be completed, so the check did "
        "not run.\n\nThis is a connectivity result, not a security finding.",
        "Confirm the login URL is reachable from the public internet and re-run the scan.",
    ),
}


def session_skip_finding(build_finding, outcome: SessionOutcome, check_subject: str) -> dict:
    """Build the SKIPPED finding for a check that could not obtain a session.

    `build_finding` is the calling check's own _build_finding, so the finding carries
    that check's id and tier rather than this module's. `check_subject` names what went
    untested, in a few words, so four checks skipping for one reason do not produce four
    identical-looking findings.
    """
    title, description, explanation, fix = _SESSION_FAILURE_TEXT.get(
        outcome.reason, _SESSION_FAILURE_TEXT["rejected"]
    )

    evidence = {"reason": outcome.reason or "unknown", "untested": check_subject}
    if outcome.submit_url:
        evidence["endpoint"] = outcome.submit_url
    if outcome.status:
        evidence["status"] = outcome.status

    # SKIPPED, always. See the note above _SESSION_FAILURE_TEXT.
    from ._finding import SKIPPED

    return build_finding(
        severity=SKIPPED,
        title=title,
        description=f"{description} ({check_subject} was not tested)",
        explanation=explanation,
        fix=fix,
        evidence=evidence,
    )


# --- Shared helpers for the authenticated checks ----------------------------


def same_site(base_url: str, candidate_url: str) -> bool:
    """Whether a candidate URL belongs to the scanned site.

    Wraps discovery's rule rather than restating it, so there is one definition of "the
    same site" in the codebase. Every authenticated check filters through this before it
    requests anything: a logout or reset link pointing at an identity provider belongs to
    a third party, and following it would send this scan's traffic to a system whose
    owner never consented to being scanned.
    """
    from ..discovery import _same_site

    base_host = (urlparse(base_url).hostname or "").lower()
    if not base_host:
        return False

    return _same_site(base_host, candidate_url)
