"""
SECURITY HEADERS CHECK - spec section 5, Tier 1.

WHY THIS FILE EXISTS
A browser will do whatever a page tells it to. Security headers are how a server
takes some of that permission back: which scripts may run, whether the page may
be framed, whether a later visit is allowed over plaintext at all. They are the
cheapest security work available - a few lines of server config, no code change -
which is exactly why their absence is worth reporting.

WHAT THIS CHECK IS AND IS NOT
It reports which headers are PRESENT, not whether their values are any good. A
Content-Security-Policy of `default-src *` would pass here and protects almost
nothing. Judging policy quality is a genuinely different job - it needs a parser
per header and an opinion about each directive - and folding it in here would
produce a check that answers two questions at once and is unclear about both.
Presence first; the value audit is its own check when it arrives.

The architecture is the same rule every check follows: take a URL, return one
finding. Adding this file changed one line in engine.py and nothing else.
"""

# No httpx import: this check no longer makes a request of its own. It reads the
# homepage discovery already fetched - see check_headers below.
import re

from ._finding import CRITICAL, PASSED, WARNING, finding_builder

# Matches the checkId the frontend already renders (frontend/src/mocks/scanData.js).
CHECK_ID = "headers_check"

# THE HEADERS THIS CHECK LOOKS FOR, and the reason each one matters.
#
# PYTHON-SPECIFIC: a tuple of tuples - the outer parentheses with commas make a
# TUPLE, which is a list that cannot be modified. Used here instead of a list
# because this is fixed reference data, and a type that cannot be mutated cannot
# be mutated by accident. It is also ORDERED, which matters: the report lists the
# headers in this sequence, most important first, rather than in whatever order a
# dict happened to produce.
#
# Header names are lowercase because the stored headers dict is
# case-insensitive, and keeping the lookup key lowercase means the comparison
# never depends on how the server chose to capitalise.
SECURITY_HEADERS = (
    (
        "content-security-policy",
        "Content-Security-Policy",
        "controls which scripts and styles the browser will run, so an injected "
        "script cannot execute",
    ),
    (
        "strict-transport-security",
        "Strict-Transport-Security",
        "tells the browser to refuse plaintext HTTP for this site on every later "
        "visit, closing the gap before a redirect can happen",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options",
        "stops the browser guessing a file's type, which is how an uploaded image "
        "gets executed as a script",
    ),
    (
        "x-frame-options",
        "X-Frame-Options",
        "prevents another site framing your pages to trick a signed-in user into "
        "clicking something they cannot see",
    ),
    (
        "referrer-policy",
        "Referrer-Policy",
        "limits how much of your URL is sent to other sites, which is how session "
        "ids and reset tokens leak in a Referer header",
    ),
)

# frame-ancestors in a CSP does the same job as X-Frame-Options and supersedes it;
# a modern site setting the former is not missing protection just because it
# omitted the latter. Reporting it as absent anyway would be a false positive, and
# a scanner that cries wolf about correct configuration is one people stop reading.
#
# A DIRECTIVE, NOT A SUBSTRING. This was `"frame-ancestors" in csp_value`, which
# also answers yes to a policy that merely mentions the word somewhere in a VALUE -
# `report-uri https://csp.example.com/frame-ancestors` is the shape that does it, and
# a CSP-reporting endpoint named after the directive it collects is not far-fetched.
# The cost is a false PASSED: X-Frame-Options is genuinely absent, nothing supersedes
# it, and the report says the site is covered. A CSP is `name value; name value`, so
# a directive name occurs at the start of the policy or just after a semicolon, and
# asking for that position is what separates a directive from a mention of one.
#
# This deliberately does NOT look at the directive's value. `frame-ancestors *`
# allows every framer and still counts as covered here - that is the presence-not-
# quality boundary this whole check is drawn on, stated in the module docstring, and
# widening it here would be the two-questions-at-once problem the docstring refuses.
FRAME_ANCESTORS_DIRECTIVE = re.compile(r"(?:^|;)\s*frame-ancestors\b", re.I)

# How many missing headers it takes to call this critical rather than a warning.
# A named constant because it is a judgement call, not a fact - it belongs
# somewhere it can be argued with instead of buried in an `if`.
#
# The reasoning: one or two gaps is an incomplete configuration. Missing all of
# them means nobody has considered response headers at all, which in practice
# predicts the rest of the deployment.
CRITICAL_MISSING_THRESHOLD = 4


_build_finding = finding_builder(CHECK_ID)


# WHY THIS EXISTS
# "Is X-Frame-Options missing?" has a wrong answer and a right one, and the
# difference is whether the CSP already covers it. Pulling that judgement into a
# named function keeps the loop below readable and puts the exception somewhere it
# can be explained rather than inlined as a mysterious extra condition.
def _is_covered_by_csp(header_key: str, csp_value: str) -> bool:
    if header_key != "x-frame-options":
        return False

    # re.I rather than .lower() because CSP directive names are case-insensitive and
    # the case-folding now belongs to the pattern along with the position rule.
    return FRAME_ANCESTORS_DIRECTIVE.search(csp_value) is not None


# WHY THIS EXISTS
# The check itself. One request to the address as given, then read what came back.
#
# It uses the URL the caller supplied rather than forcing the site root, which is
# the opposite of what https_check does - and the difference is deliberate. A
# redirect rule is server-wide, so testing the root is more reliable there.
# Headers can legitimately differ per response: an app may set a strict CSP on its
# login page and nothing on a marketing homepage. Checking the address the client
# actually asked about reports on the page they care about.
#
# WHERE THE RESPONSE COMES FROM, and why this check stopped making its own request.
# Discovery fetches the address the client supplied with follow_redirects=True, which
# is precisely the response this check wants - a bare 301 carries almost no headers,
# so the interesting one is at the end of the chain. That is the same response
# discovery already holds, so re-requesting it would be a second identical GET whose
# headers could legitimately DIFFER from the ones every other check reasoned about.
# One fetch, one set of headers, one story in the report.
async def check_headers(target) -> dict:
    page = target.home

    if page is None:
        # Same reasoning as in https_check: nothing was observed, so nothing is
        # claimed. A warning saying the check could not complete, never a critical
        # implying a failure that was never seen.
        return _build_finding(
            severity=WARNING,
            title="Could not check security headers",
            description="The site could not be reached",
            explanation=(
                f"The request to {target.url} failed before any response was "
                "received, so no headers could be read. This is not evidence of a "
                "security problem - the check simply could not complete."
            ),
            fix="Confirm the address is correct and the site is publicly reachable, then re-run the scan.",
            evidence={"url": target.url},
        )

    # Discovery stores the headers as a plain dict with LOWERCASE keys, because httpx
    # normalises header names on the way in (see discovery._parse_page). That is why
    # every key in SECURITY_HEADERS is written lowercase - the case-insensitivity now
    # comes from that normalisation rather than from httpx's mapping type, and a
    # capitalised lookup here would silently find nothing.
    headers = page.headers

    csp_value = headers.get("content-security-policy", "")

    # PYTHON-SPECIFIC: building two lists in one loop rather than two
    # comprehensions over the same data. A comprehension would be more idiomatic
    # for either list alone, but writing two would mean iterating twice and
    # repeating the CSP exception in both - and a rule stated twice is a rule that
    # ends up stated differently.
    present = []
    missing = []

    # HEADERS THE SERVER SENT WITH NOTHING IN THEM. Tracked separately from `missing`
    # although they count as missing, because the two need DIFFERENT remediation and
    # a finding that conflates them sends the customer to the wrong place.
    #
    # THIS WAS A FALSE PASSED, the worst direction this check can fail in. The test
    # was `header_key in headers` - PRESENCE OF THE KEY, not of a value - so a server
    # answering `Content-Security-Policy:` with an empty value was credited with a
    # policy it does not have, and a site sending all five that way was told "All five
    # protective response headers are present". Nothing was protecting anything. This
    # is reachable, not theoretical: httpx preserves an empty header value and
    # discovery stores it verbatim via `dict(response.headers)`, and the usual causes
    # are ordinary - `add_header X-Frame-Options "";` in nginx, or a framework reading
    # its policy from an environment variable that was never set.
    #
    # Every one of the five is useless empty, so there is no header here that wants an
    # exception: HSTS without max-age is invalid, the only meaningful value of
    # X-Content-Type-Options is `nosniff`, an empty X-Frame-Options is ignored, and an
    # empty Referrer-Policy means "fall back to the default" by specification - which
    # is the absence of a choice, not a choice.
    blank = []

    for header_key, display_name, purpose in SECURITY_HEADERS:
        # PYTHON-SPECIFIC: this unpacks each inner tuple into three names in one
        # step - the same idea as JS array destructuring,
        # `const [a, b, c] = tuple`.
        #
        # .strip() as well as truthiness, because a header holding only spaces is
        # every bit as empty as one holding nothing, and a server that emits one is
        # doing so by accident either way.
        value = headers.get(header_key, "").strip()

        if value or _is_covered_by_csp(header_key, csp_value):
            present.append(display_name)
        else:
            missing.append((display_name, purpose))

            # Sent, but empty. The key being there is what separates the two cases.
            if header_key in headers:
                blank.append(display_name)

    # PYTHON-SPECIFIC: an empty list is FALSY, so `if not missing` reads as "if
    # there is nothing missing". No .length check needed.
    if not missing:
        return _build_finding(
            severity=PASSED,
            title="Security headers set",
            description="All five protective response headers are present",
            explanation=(
                "Every header this check looks for was returned: "
                # PYTHON-SPECIFIC: str.join is backwards from what a JS habit
                # expects - the SEPARATOR owns the method, and the list is the
                # argument. `", ".join(list)`, never `list.join(", ")`.
                f"{', '.join(present)}. Note that this confirms the headers are "
                "set, not that their values are strict - a permissive "
                "Content-Security-Policy is present but protects little."
            ),
            fix=(
                "No action needed for presence. Worth reviewing the "
                "Content-Security-Policy value itself, since a policy allowing "
                "'unsafe-inline' or a wildcard source gives up most of its benefit."
            ),
            evidence={"url": page.url, "present": present},
        )

    # PYTHON-SPECIFIC: a LIST COMPREHENSION - [expression for item in list] builds
    # a new list in one line, the equivalent of JS's .map(). This pulls just the
    # display names out of the (name, purpose) pairs.
    missing_names = [name for name, _purpose in missing]

    # The underscore in `_purpose` is convention for "a value I am required to
    # name but do not use". Linters know it and stay quiet.

    severity = (
        CRITICAL if len(missing) >= CRITICAL_MISSING_THRESHOLD else WARNING
    )

    # A HEADER SENT EMPTY NEEDS ITS OWN SENTENCE. Telling a customer the response "did
    # not include" a header they can see in their own configuration reads as a scanner
    # error, and that costs the same credibility a false positive costs even though the
    # verdict itself is right. It also selects a different fix: nothing needs adding,
    # something needs explaining - which is the same rule the Tier 2 skip reasons
    # follow, where the reason is not a label but the thing that picks the remediation.
    blank_note = ""
    if blank:
        blank_note = (
            f"\n\n{len(blank)} of these WERE returned, but with an empty value: "
            f"{', '.join(blank)}. A browser ignores a header with no value, so it "
            "protects nothing - but the cause is configuration that produces a blank "
            "value, not a header nobody added, so look for the setting that is empty "
            "rather than adding a new line."
        )

    # Each missing header gets its own line saying what it would have done. A bare
    # list of header names tells a client what to paste; saying what each one
    # prevents tells them why it is worth the deploy.
    detail_lines = "\n".join(
        f"- {name}: {purpose}" for name, purpose in missing
    )

    # PYTHON-SPECIFIC: a GENERATOR EXPRESSION passed straight to join - same shape
    # as the comprehension above but without the brackets, so it produces values
    # one at a time instead of building a whole list first. For five items the
    # difference is nil; it is the idiomatic form when the result is consumed once.

    return _build_finding(
        severity=severity,
        title="Missing security headers",
        description=(
            f"{len(missing)} of {len(SECURITY_HEADERS)} protective headers "
            f"are {'absent or empty' if blank else 'absent'}: "
            f"{', '.join(missing_names)}"
        ),
        explanation=(
            f"The response from {page.url} did not carry usable values for the "
            f"following headers:\n{detail_lines}{blank_note}\n\nEach one is a single "
            "line of server configuration, and each closes an attack that is "
            "otherwise available on every page of the site."
        ),
        fix=(
            "Set these globally at the web server, load balancer or framework "
            "middleware rather than per route, so a new page cannot be added "
            "without them. Start Content-Security-Policy in report-only mode to "
            "see what it would break before enforcing it."
        ),
        evidence={
            "url": page.url,
            "status": page.status,
            "present": present,
            "missing": missing_names,
            # Only when there are any, so a report for the ordinary case is unchanged.
            **({"sentEmpty": blank} if blank else {}),
        },
    )
