"""
ENDPOINT DISCOVERY - finding the login and signup pages before any check runs.

WHY THIS FILE EXISTS
Three of the seven Tier 1 checks are about authentication: is login rate-limited,
is multi-factor authentication offered, is the password policy enforced. All three
need to know WHERE the login and signup pages are, and a scan request carries one
URL - usually a homepage.

If each check found them independently, one scan would fetch the homepage three
times and probe the same eight candidate paths three times: about 21 requests
where 7 would do. Worse, three separate discoveries can DISAGREE - a flaky probe
means the rate-limit check tests /login while the password check reads a form on a
different page, and the report contradicts itself with no way to tell why.

So discovery happens ONCE, in engine.py, before the checks run. The result is a
ScanTarget handed to every check. Checks that do not care about authentication
ignore it.

---------------------------------------------------------------------------
THE SAFETY PROPERTY THAT MATTERS MOST: THIS NEVER LEAVES THE TARGET'S HOST.

Following a "Sign in" link naively is how a scanner ends up probing
accounts.google.com, login.microsoftonline.com or an Okta tenant - third parties
who did not consent to anything, which is the exact thing SecuScan's consent gate
exists to prevent. Every candidate URL is filtered through _same_site() before a
single request is made to it. An off-host login link is RECORDED and not followed.

NOTHING HERE SUBMITS A FORM. Discovery is all GET requests. It reads pages and
parses what came back.

NOR DOES ANY CHECK. This used to read "the one check that sends a POST is the
rate-limiting check" - that check is now passive by decision, and TIER 1 SENDS NO
POST REQUESTS AT ALL. The reasoning is in rate_limit_check.py: submitting repeated
failed logins to somebody else's site is indistinguishable from the attack it would
be testing for. An active version is a Tier 2 check, and it will require a
dedicated test account the client supplies rather than any address that might
belong to a real user.
"""

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

# PYTHON-SPECIFIC: a relative import reaching INTO a subpackage - scanning/ is this
# module's package, so .checks._finding is scanning/checks/_finding.py. Discovery
# borrows the request policy rather than declaring its own, so the scanner
# identifies itself identically no matter which part of it is talking.
from .checks._finding import TIMEOUT_SECONDS, USER_AGENT


# --- What to look for ------------------------------------------------------

# Conventional paths, tried only when reading the page found nothing. Ordered by
# how likely each is to exist, because the probe budget below stops early - so the
# order is a real decision, not a list.
#
# /wp-login.php is last and included on purpose: WordPress is a large share of the
# web and its login page sits at a path nothing else uses, so it is a cheap and
# certain hit for a whole class of site.
COMMON_LOGIN_PATHS = (
    "/login",
    "/signin",
    "/sign-in",
    "/account/login",
    "/auth/login",
    "/users/sign_in",
    "/wp-login.php",
)

COMMON_SIGNUP_PATHS = (
    "/signup",
    "/sign-up",
    "/register",
    "/account/register",
    "/users/sign_up",
    "/create-account",
)

# WHY A REQUEST BUDGET AT ALL: the path lists above hold 13 entries. Probing all of
# them on a site that has none means 13 404s in somebody's access log for no result.
# This caps the wasted traffic, and it is the reason the lists are ordered.
MAX_PROBES = 8

# Link text and hrefs that suggest a sign-in or signup destination.
#
# PYTHON-SPECIFIC: re.compile builds the pattern object once at import instead of
# re-parsing the string on every call. re.I is the case-insensitive flag. The "?"
# after a space makes that space optional, so one pattern matches "login", "log in"
# and "Log In".
LOGIN_HINT = re.compile(r"(log ?in|sign ?in|signin|/auth\b|my account)", re.I)
SIGNUP_HINT = re.compile(
    r"(sign ?up|signup|register|create (an |your )?account|get started|join)", re.I
)

# A signup form usually asks for the password twice, or asks for a name. Used to
# tell a signup form from a login form when both are, structurally, just "a form
# with a password field in it".
CONFIRM_HINT = re.compile(r"(confirm|repeat|again|verify|password2|retype)", re.I)


# --- What comes back -------------------------------------------------------


# PYTHON-SPECIFIC: @dataclass writes __init__, __repr__ and __eq__ from the
# annotated attributes below. Without it this class would need a constructor that
# assigns four arguments to four attributes, which is pure noise. The rough JS
# equivalent is a plain object literal, except this one has named fields that a typo
# cannot silently invent.
@dataclass
class Field:
    """One input, select or textarea inside a form."""

    tag: str
    type: str
    name: str
    # PYTHON-SPECIFIC: a MUTABLE DEFAULT must use field(default_factory=...).
    # Writing `attrs: dict = {}` would share ONE dict between every instance ever
    # created - the classic Python gotcha, and the same trap as a default argument
    # of []. default_factory calls dict() freshly for each object.
    attrs: dict = field(default_factory=dict)


@dataclass
class Form:
    """One HTML form, with its fields and where it submits to."""

    submit_url: str
    method: str
    fields: list[Field] = field(default_factory=list)

    # PYTHON-SPECIFIC: an ordinary method on a dataclass. @property would let this
    # be read as .password_fields with no parentheses; it is left as a method
    # because it does real work - a scan of the field list - and a property that
    # loops reads like a cheap attribute access when it is not.
    def password_fields(self) -> list[Field]:
        return [f for f in self.fields if f.type == "password"]

    def has_password(self) -> bool:
        # An empty list is falsy in Python, so bool() of it is the whole test.
        return bool(self.password_fields())

    def looks_like_signup(self) -> bool:
        # Two password boxes is the confirm-password pattern, which login forms do
        # not have. One password box plus a field whose name says "confirm" is the
        # same signal spelled differently.
        if len(self.password_fields()) >= 2:
            return True

        return any(
            CONFIRM_HINT.search(f.name) and f.type == "password" for f in self.fields
        )


@dataclass
class Page:
    """One fetched page: the response, parsed into the parts checks care about."""

    url: str
    status: int
    html: str
    text: str
    forms: list[Form] = field(default_factory=list)
    links: list[tuple[str, str]] = field(default_factory=list)

    # Password inputs found OUTSIDE any form. A React or Vue login screen very often
    # has no <form> element at all - it binds a click handler to a button instead.
    # Ignoring those would report "no login form" on a large share of modern sites,
    # so they are carried separately and treated as a weaker signal.
    loose_password_fields: list[Field] = field(default_factory=list)

    # Every Set-Cookie header seen, INCLUDING the redirect hops.
    #
    # WHY THE HOPS MATTER: a session cookie is very often set by a redirect rather
    # than by the final 200. Reading only the last response's headers is how a cookie
    # check reports "no cookies set" on a site that sets three. httpx keeps the
    # intermediate responses in response.history, and _collect_cookies walks them.
    set_cookies: list[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)

    def forms_with_password(self) -> list[Form]:
        return [f for f in self.forms if f.has_password()]

    def has_password_input(self) -> bool:
        return bool(self.forms_with_password() or self.loose_password_fields)


@dataclass
class ScanTarget:
    """
    Everything discovery learned, handed to every check.

    A check reads what it needs and ignores the rest. `notes` exists so a check can
    tell the client HOW its endpoint was found - "the address you supplied", "a form
    on the homepage", "probed /login" - which is the difference between a finding a
    site owner can verify and one they have to take on trust.
    """

    url: str
    home: Page | None = None
    login: Page | None = None
    signup: Page | None = None
    notes: list[str] = field(default_factory=list)
    # True when the client supplied the login URL explicitly, so a check can say so
    # rather than implying it guessed correctly.
    login_was_supplied: bool = False
    # Tier 2 client-supplied test credentials (e.g. {"stagingUrl": ..., "username": ..., "password": ...})
    # Scoped exclusively to the current scan and scrubbed from memory after execution.
    credentials: dict | None = None

    def login_form(self) -> Form | None:
        if self.login is None:
            return None

        forms = self.login.forms_with_password()

        # PYTHON-SPECIFIC: `forms[0] if forms else None` is the conditional
        # expression - Python's ternary, with the condition in the middle. Guarded
        # with `if forms` rather than indexed directly because [0] on an empty list
        # raises IndexError where JS would hand back undefined.
        return forms[0] if forms else None

    def signup_form(self) -> Form | None:
        if self.signup is None:
            return None

        forms = self.signup.forms_with_password()

        return forms[0] if forms else None


# --- Parsing ---------------------------------------------------------------


# WHY THE STANDARD LIBRARY AND NOT BEAUTIFULSOUP
# bs4 would be nicer code and it is one line in requirements.txt. It is not here
# because html.parser ships with Python everywhere, and this file needs three things
# from a parser: forms with their inputs, links with their text, and the visible
# text. That is a small enough surface that a dependency - something every
# deployment has to install, pin and patch - is not yet worth it.
#
# PYTHON-SPECIFIC: subclassing HTMLParser and overriding handle_* gives a CALLBACK
# parser, not a tree builder. It streams: handle_starttag fires as each tag is
# encountered, and it is this class's job to remember where it is. That is why there
# is state below rather than a .find() call.
class _PageParser(HTMLParser):
    def __init__(self) -> None:
        # PYTHON-SPECIFIC: super().__init__() runs the parent's constructor.
        # HTMLParser genuinely needs its own setup, and skipping this line produces
        # an AttributeError deep inside the parser rather than an obvious error
        # here. convert_charrefs is on by default, which is what turns an escaped
        # ampersand back into a real character in the extracted text.
        super().__init__(convert_charrefs=True)

        self.forms: list[Form] = []
        self.links: list[tuple[str, str]] = []
        self.loose_password_fields: list[Field] = []

        self._text_parts: list[str] = []
        self._current_form: Form | None = None
        # A DEPTH COUNTER, not a boolean: <script> nested inside <script> is invalid
        # HTML but it appears in the wild, and a boolean would be switched off by the
        # first closing tag and leak JavaScript into the page text.
        self._suppress_depth = 0
        self._current_link_href: str | None = None
        self._current_link_text: list[str] = []

    # PYTHON-SPECIFIC: `attrs` arrives as a list of (name, value) TUPLES, not a dict,
    # and value is None for a valueless attribute such as "required". This normalises
    # both: a dict for lookup, and "" instead of None so callers never test for it.
    #
    # PYTHON-SPECIFIC: @staticmethod means no self - it is a plain function that
    # lives in the class's namespace because that is the only place it is used.
    @staticmethod
    def _as_dict(attrs) -> dict:
        return {name.lower(): (value or "") for name, value in attrs}

    def handle_starttag(self, tag: str, attrs) -> None:
        a = self._as_dict(attrs)

        if tag in ("script", "style", "noscript", "template"):
            self._suppress_depth += 1
            return

        if tag == "form":
            self._current_form = Form(
                # Stored RAW here and resolved to an absolute URL later, in
                # _parse_page, which is the only place that knows the page's own
                # address. A parser that resolved it would have to be told the base
                # URL as well, for no gain.
                submit_url=a.get("action", ""),
                method=a.get("method", "get").lower(),
            )
            return

        if tag in ("input", "select", "textarea"):
            f = Field(
                tag=tag,
                # Default "text" matches the browser: an <input> with no type
                # attribute IS a text input, and recording "" would make every such
                # field invisible to the email and name heuristics later.
                type=(a.get("type", "text").lower() if tag == "input" else tag),
                # Falling back to id because plenty of SPA forms label their inputs
                # with an id and no name - there is nothing to submit, so nothing
                # needed a name.
                name=a.get("name", "") or a.get("id", ""),
                attrs=a,
            )

            if self._current_form is not None:
                self._current_form.fields.append(f)
            elif f.type == "password":
                self.loose_password_fields.append(f)

            return

        if tag == "a":
            self._current_link_href = a.get("href", "")
            self._current_link_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript", "template"):
            # max(0, ...) so a stray closing tag with no opener cannot drive the
            # counter negative and permanently suppress the rest of the page.
            self._suppress_depth = max(0, self._suppress_depth - 1)
            return

        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
            return

        if tag == "a" and self._current_link_href is not None:
            self.links.append(
                (self._current_link_href, " ".join(self._current_link_text).strip())
            )
            self._current_link_href = None
            self._current_link_text = []

    def handle_data(self, data: str) -> None:
        if self._suppress_depth:
            return

        stripped = data.strip()

        if not stripped:
            return

        self._text_parts.append(stripped)

        # A link's text is captured twice on purpose - once into the page text, once
        # into the link - because "Sign in" needs to be findable as link text AND
        # countable as page wording for the MFA check.
        if self._current_link_href is not None:
            self._current_link_text.append(stripped)

    def page_text(self) -> str:
        return " ".join(self._text_parts)


# WHY THIS IS A FUNCTION AND NOT A Page CLASSMETHOD
# It needs both the httpx response and the parser, and it is the only place that
# resolves relative form actions against the page URL. Keeping it out here means Page
# stays a dumb record of what was found, with no knowledge of httpx at all - so a
# check can build a Page in a test with no network stack involved.
def _parse_page(response: httpx.Response) -> Page:
    # PYTHON-SPECIFIC: response.text decodes the body using the charset the server
    # declared. response.content would be raw bytes, and HTMLParser wants str.
    html = response.text
    parser = _PageParser()

    try:
        parser.feed(html)
    except Exception:
        # WHY A BARE except HERE, when that is normally poor practice: HTMLParser is
        # being fed arbitrary bytes from a stranger's server. Malformed markup, a
        # truncated response, or a binary body served as text/html can all raise, and
        # a parse failure must degrade to "no forms found" rather than taking down the
        # whole scan. Whatever the parser managed before the error is kept.
        pass

    page_url = str(response.url)

    for form in parser.forms:
        # An empty action means "submit to this page", which is exactly what urljoin
        # returns for an empty second argument. A relative action like "/session"
        # resolves against the page. Both cases collapse into one line, which is why
        # the raw value was kept until now.
        form.submit_url = urljoin(page_url, form.submit_url)

    return Page(
        url=page_url,
        status=response.status_code,
        html=html,
        text=parser.page_text(),
        forms=parser.forms,
        # Resolved to absolute here so that _same_site below never has to reason
        # about a relative href - a relative URL has no hostname, and a host check
        # that silently returns False for "/login" would reject the site's own
        # links.
        links=[
            (urljoin(page_url, href), text) for href, text in parser.links if href
        ],
        loose_password_fields=parser.loose_password_fields,
        set_cookies=_collect_cookies(response),
        # dict() of httpx's headers loses duplicates, which is exactly why set_cookies
        # is collected separately above - Set-Cookie is the one header that
        # legitimately appears many times in one response.
        headers=dict(response.headers),
    )


def _collect_cookies(response: httpx.Response) -> list[str]:
    values: list[str] = []

    # PYTHON-SPECIFIC: response.history is the list of responses that were followed
    # to get here, oldest first. Walking it before the final response keeps the
    # cookies in the order the server actually set them.
    for hop in list(response.history) + [response]:
        # .get_list() returns EVERY value for a repeated header, where .get() would
        # return one. For Set-Cookie that distinction is the whole point.
        values.extend(hop.headers.get_list("set-cookie"))

    return values


# --- Host safety -----------------------------------------------------------


# WHY THIS IS THE MOST IMPORTANT FUNCTION IN THE FILE
# Every candidate URL passes through it before a request is made. Without it, a
# homepage whose header says "Sign in with Google" leads the scanner to
# accounts.google.com, and SecuScan starts sending probe traffic at a third party
# that never consented - precisely what main.py's consent gate exists to stop.
#
# The rule is deliberately narrow: the same hostname, or one a subdomain of the
# other. That accepts the real cases (example.com to www.example.com, or a login on
# accounts.example.com) and rejects everything else.
#
# NO PUBLIC SUFFIX LIST, ON PURPOSE. The tempting shortcut is "compare the last two
# labels", which reads example.co.uk as the domain "co.uk" and would then treat every
# .co.uk site as the same site as every other. Getting that right needs the Public
# Suffix List, which is a dependency plus a data file that goes stale; getting it
# wrong is a scanner that probes strangers. Narrow and correct beats broad and
# occasionally catastrophic.
def _same_site(base_host: str, candidate_url: str) -> bool:
    candidate_host = (urlparse(candidate_url).hostname or "").lower()
    base_host = base_host.lower()

    if not candidate_host:
        return False

    if candidate_host == base_host:
        return True

    # THE DOT IS WHAT MAKES THIS SAFE. endswith("example.com") without it would match
    # "notexample.com", which is a different site owned by somebody else.
    return candidate_host.endswith("." + base_host) or base_host.endswith(
        "." + candidate_host
    )


# --- The discovery pass ----------------------------------------------------


async def _fetch(client: httpx.AsyncClient, url: str) -> Page | None:
    """One GET, parsed. None when the request failed for any reason."""
    try:
        response = await client.get(url)
    except httpx.RequestError:
        # Discovery treats an unreachable candidate as "not here" rather than as an
        # error worth propagating. Whether the SITE is reachable at all is answered by
        # the home fetch in discover(), and reported on by the checks.
        return None

    return _parse_page(response)


# WHY A PAGE ONLY COUNTS AS A LOGIN PAGE IF IT HAS A PASSWORD FIELD
# Probing /login on a site that has none very often returns 200 - a soft 404, a
# marketing page, or an SPA shell that serves identical HTML for every route.
# Accepting a 200 as proof would hand the rate-limiting check a URL that does not
# authenticate anybody, and it would then report "no rate limiting" about a page that
# never had a login to limit. A password input is the only cheap evidence that means
# what we need it to mean.
def _is_login_page(page: Page | None) -> bool:
    if page is None:
        return False

    if not (200 <= page.status < 400):
        return False

    return page.has_password_input()


# WHY THIS HELPER EXISTS: the same "build an ordered, de-duplicated candidate list"
# logic is needed for login and for signup, and writing it twice is how the two grow
# apart.
def _candidates(
    base_url: str, base_host: str, page: Page | None, hint, paths
) -> list[str]:
    found: list[str] = []

    def add(url: str) -> None:
        # THE SAME-SITE FILTER RUNS FIRST, before de-duplication, so an off-host URL
        # never enters the list at all - not even as something we might later decide
        # to fetch.
        if not _same_site(base_host, url):
            return

        # A fragment-only difference is the same page. Stripping it stops /login and
        # /login#form being probed as two candidates and burning two of eight.
        clean = url.split("#", 1)[0]

        if clean not in found:
            found.append(clean)

    # Links the page itself offers come FIRST: a link the site publishes is better
    # evidence than a path we guessed at.
    if page is not None:
        for href, text in page.links:
            if hint.search(text) or hint.search(href):
                add(href)

    for path in paths:
        add(urljoin(base_url, path))

    return found


# WHY THE BUDGET IS ENFORCED HERE AND NOT IN _candidates
# The candidate list is cheap to build and useful in full - it goes into the evidence,
# so a client can see what was tried. What must be capped is REQUESTS. Slicing at the
# point of fetching keeps those two concerns apart.
async def _probe(
    client: httpx.AsyncClient,
    candidates: list[str],
    target: ScanTarget,
    label: str,
) -> Page | None:
    tried: list[str] = []

    for candidate in candidates[:MAX_PROBES]:
        tried.append(candidate)

        page = await _fetch(client, candidate)

        if _is_login_page(page):
            target.notes.append(f"Found a {label} form at {candidate}.")
            return page

    if tried:
        target.notes.append(f"No {label} form found. Tried: " + ", ".join(tried) + ".")
    else:
        target.notes.append(f"No {label} candidates to try.")

    return None


# WHY THIS EXISTS
# The one entry point. engine.py calls it once per scan and hands the result to every
# check.
#
# IT NEVER RAISES. That is a hard requirement rather than a nicety: discovery runs
# BEFORE the checks, so an exception here means a scan that produces no findings at
# all instead of a scan that reports what it could. Every failure path below becomes a
# note plus a None page, and the checks report "skipped" from there.
async def discover(
    url: str,
    login_url: str | None = None,
    credentials: dict | None = None,
) -> ScanTarget:
    target = ScanTarget(url=url, credentials=credentials)

    base_host = (urlparse(url).hostname or "").lower()

    if not base_host:
        target.notes.append("The address could not be parsed, so nothing was fetched.")
        return target

    async with httpx.AsyncClient(
        # follow_redirects=True because a homepage very often redirects - http to
        # https, or the bare domain to www. The hops are not lost: _collect_cookies
        # walks response.history, which is what keeps the cookie check honest.
        follow_redirects=True,
        timeout=TIMEOUT_SECONDS,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        target.home = await _fetch(client, url)

        if target.home is None:
            target.notes.append(f"{url} could not be reached.")
            return target

        # --- The login page ---

        if login_url:
            # THE CLIENT'S VALUE IS USED VERBATIM AND NOT SECOND-GUESSED, with one
            # exception: it still has to be on the target's own site. Otherwise
            # "scan example.com, my login is at victim.example.org" is a request to
            # send traffic at a third party - the consent gate defeated by a second
            # field.
            if not _same_site(base_host, login_url):
                target.notes.append(
                    f"The supplied login URL is not on {base_host}, so it was "
                    "ignored and discovery ran instead."
                )
            else:
                page = await _fetch(client, login_url)

                if _is_login_page(page):
                    target.login = page
                    target.login_was_supplied = True
                    target.notes.append(f"Login page supplied by the client: {page.url}")
                else:
                    target.notes.append(
                        f"The supplied login URL {login_url} did not return a page "
                        "with a password field, so discovery ran instead."
                    )

        if target.login is None:
            # The homepage may itself BE the login page - very common for admin panels
            # and internal tools - and it costs nothing to check first because the page
            # is already fetched.
            if _is_login_page(target.home):
                target.login = target.home
                target.notes.append("A password field was found on the page supplied.")
            else:
                target.login = await _probe(
                    client,
                    _candidates(
                        url, base_host, target.home, LOGIN_HINT, COMMON_LOGIN_PATHS
                    ),
                    target,
                    "login",
                )

        # --- The signup page ---
        #
        # Second, with its own budget. A site with no signup page is entirely normal -
        # most business software does not let strangers register - so finding nothing
        # here is a skipped check and never a finding.
        signup_candidates = _candidates(
            url, base_host, target.home, SIGNUP_HINT, COMMON_SIGNUP_PATHS
        )

        # A page reached by a signup link that turns out to hold the LOGIN form is a
        # false positive worth avoiding, so the login page is excluded by URL.
        if target.login is not None:
            signup_candidates = [c for c in signup_candidates if c != target.login.url]

        target.signup = await _probe(client, signup_candidates, target, "signup")

    return target
