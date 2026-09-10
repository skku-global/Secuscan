"""
HTTPS ENFORCEMENT CHECK - spec section 5, Tier 1 check #2.

PYTHON-SPECIFIC: this triple-quoted string at the very top of a file is a
"module docstring". It is not a comment - it is a real string that Python
stores as the module's .__doc__ attribute. Convention is to use it to say what
the file is for. JS has no direct equivalent; you would just write a // comment.

WHY THIS FILE EXISTS
Every check lives in its own file, and every check exports one function with the
same shape: take a URL, return one finding dictionary. That rule is the entire
architecture. It means adding the next six checks never edits this file - you
drop a new file in beside it and add one name to the CHECKS list in engine.py.
It also means a check can be tested on its own, with no server, no database and
no API layer involved.
"""

# PYTHON-SPECIFIC: imports name what you want rather than a default export.
# `from x import y` is close to JS's `import { y } from 'x'`.
# urllib.parse is in Python's standard library - nothing to install.
from urllib.parse import urlparse, urljoin

import httpx  # third-party; listed in requirements.txt

# The request policy (user agent, timeout), the severity vocabulary and the
# finding builder all now live in one place. See _finding.py for why the builder
# is a factory: it hands back a build function that already knows this check's id,
# so no call site below had to change when the private copy was deleted.
from ._finding import (
    CRITICAL,
    PASSED,
    TIMEOUT_SECONDS,
    USER_AGENT,
    WARNING,
    finding_builder,
)

# This check's stable identifier. It matches the checkId already used in the
# frontend's mock data (frontend/src/mocks/scanData.js), which is deliberate:
# the UI knows how to render a finding with this id, so real results drop in.
CHECK_ID = "https_check"

# PYTHON-SPECIFIC: a set literal uses braces but has no keys - {301, 302} is a
# SET, not a dict. Membership tests (`status in REDIRECT_STATUSES`) on a set are
# fast and read cleanly.
# 301/308 are permanent, 302/307 temporary, 303 see-other. All are redirects.
REDIRECT_STATUSES = {301, 302, 303, 307, 308}

_build_finding = finding_builder(CHECK_ID)


# WHY THIS EXISTS
# The single question this answers: if someone types the plain http:// address,
# do they end up on https://? That is the whole check. It is deliberately
# separate from "is the certificate valid" and "is HSTS set" - those are
# different checks that get their own files, and keeping this one narrow is what
# makes its result unambiguous.
#
# It returns a finding rather than a bare True/False because a security result is
# only useful with the reasoning attached: the client needs to know what was
# observed, why it matters, and what to do about it.
async def check_https(target) -> dict:
    # PYTHON-SPECIFIC: `async def` marks a coroutine. It behaves like an async
    # function in JS with ONE important difference. In JS, calling an async
    # function starts the work immediately and hands you a Promise. In Python,
    # calling `check_https(target)` runs NOTHING - it only builds a coroutine
    # object. The work begins when something awaits it. Forgetting the `await` is
    # the classic Python async bug: no error, just nothing happens.

    # Any path the caller supplied is ignored and the site root is tested. A
    # redirect rule is a server-wide setting, and testing the root stops a 404 on
    # some deep path being misread as "no redirect configured".
    # Every check now receives the ScanTarget, so the registry in engine.py needs no
    # special cases. This one wants only the address: unlike the checks that read
    # discovery's fetched pages, it has to make its OWN request to plain http://,
    # which is a response discovery never asks for.
    url = target.url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        # PYTHON-SPECIFIC: no braces - INDENTATION defines the block. The four
        # spaces below are what put this statement inside the `if`. Getting the
        # indentation wrong changes the program's meaning, not just its layout.
        return _build_finding(
            severity=WARNING,
            title="Could not check HTTPS enforcement",
            description="The address given could not be parsed as a URL",
            explanation=(
                # PYTHON-SPECIFIC: adjacent string literals inside parentheses
                # are joined automatically into one string. This is how long
                # messages get wrapped without backslashes or + signs.
                "The scanner needs a hostname to test, and none could be read "
                "from the value supplied. Nothing was contacted."
            ),
            fix="Re-run the scan with a full address, for example https://example.com",
        )

    # WHICH ADDRESS COUNTS AS "THE PLAIN HTTP ONE" depends on the scheme we were
    # given, and getting this wrong manufactured a false pass.
    #
    # For an https:// target the plaintext counterpart is port 80 - the address a
    # visitor actually types - so a non-default TLS port is dropped deliberately:
    # nobody serves cleartext on :8443, and probing there would test nothing.
    #
    # For an http:// target the site is ALREADY plaintext, at that exact port, so the
    # port has to be kept. Dropping it sent the probe to port 80 of a site running on
    # :60151; port 80 refused the connection, and the refusal branch below read that
    # as "no plaintext endpoint exposed" - a PASS awarded for never having tested the
    # site at all. Caught by the hermetic end-to-end run, which serves its fixture on
    # an ephemeral port.
    #
    # PYTHON-SPECIFIC: an f-string. The f prefix lets you embed expressions in
    # braces - the direct equivalent of a JS template literal's ${...}. urlparse's
    # .port is an int or None (None when the URL names no port), which is what makes
    # the condition below read as "was a port spelled out".
    target_is_plaintext = parsed.scheme == "http"

    if target_is_plaintext and parsed.port:
        plain_http_url = f"http://{hostname}:{parsed.port}/"
    else:
        plain_http_url = f"http://{hostname}/"

    # PYTHON-SPECIFIC: `async with` is an async context manager. It guarantees
    # the client's sockets are closed when the block exits, even if an exception
    # is raised inside - the same job as try/finally, but declared up front.
    # There is no direct JS equivalent; you would write try/finally by hand.
    #
    # follow_redirects=False is the heart of this check. httpx would happily
    # follow the redirect chain and hand back the final HTTPS page, at which
    # point we could no longer tell whether a redirect happened at all. Seeing
    # the raw 301 and its Location header is the entire point, so following is
    # turned OFF.
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=TIMEOUT_SECONDS,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        try:
            response = await client.get(plain_http_url)

        except httpx.ConnectError:
            # A REFUSAL MEANS TWO DIFFERENT THINGS depending on what we were asked to
            # scan, so the scheme decides which finding this is.
            #
            # Given an http:// target, the address that just refused IS the site. That
            # is not "HTTPS enforced", it is "the site is not there" - and a scanner
            # that reports a clean HTTPS result for a host it could not reach is
            # asserting something it never observed.
            if target_is_plaintext:
                return _build_finding(
                    severity=WARNING,
                    title="Could not check HTTPS enforcement",
                    description="The address given refused the connection",
                    explanation=(
                        f"The scan was asked to test {url}, which is an unencrypted "
                        f"address, and {plain_http_url} refused the connection. So "
                        "nothing was served there to examine. This is not evidence "
                        "about the site's HTTPS setup either way - the check could "
                        "not be completed."
                    ),
                    fix=(
                        "Confirm the address is correct and the site is publicly "
                        "reachable. If the site is served over HTTPS, re-run the scan "
                        "against its https:// address."
                    ),
                    evidence={
                        "httpUrl": plain_http_url,
                        "result": "connection refused",
                        "targetScheme": "http",
                    },
                )

            # Given an https:// target, nothing is listening on port 80 at all. This is
            # a PASS, and a slightly stronger one than a redirect: there is no
            # plaintext endpoint to downgrade to in the first place.
            #
            # PYTHON-SPECIFIC: `except SomeError:` is `catch (e)` narrowed to one
            # error type. Order matters here - ConnectError is a subclass of
            # RequestError, so it must be caught BEFORE the broader case below or
            # the general handler would swallow it.
            return _build_finding(
                severity=PASSED,
                title="HTTPS enforced",
                description="No plaintext HTTP service is exposed",
                explanation=(
                    f"{plain_http_url} refused the connection, so the site serves nothing "
                    "over unencrypted HTTP. There is no plaintext endpoint for an "
                    "attacker to intercept or downgrade a visitor to."
                ),
                fix="No action needed. Keep certificate auto-renewal running so HTTPS does not lapse.",
                evidence={
                    "httpUrl": plain_http_url,
                    "result": "connection refused",
                    "targetScheme": "https",
                },
            )

        except httpx.RequestError as exc:
            # DNS failure, timeout, unreachable network. Deliberately NOT
            # reported as critical: no security failure was observed, rather
            # nothing at all was observed. Claiming a vulnerability that was
            # never seen is the worse error for an audit tool - a false alarm
            # costs the client's trust, and trust is the product.
            #
            # PYTHON-SPECIFIC: `as exc` binds the exception object to a name,
            # like `catch (exc)` in JS. `type(exc).__name__` reads the class name
            # off the object as a string, e.g. "ConnectTimeout".
            return _build_finding(
                severity=WARNING,
                title="Could not check HTTPS enforcement",
                description="The site could not be reached over HTTP",
                explanation=(
                    f"The request to {plain_http_url} failed before any response "
                    f"was received ({type(exc).__name__}). This is not evidence "
                    "of a security problem - the check simply could not complete."
                ),
                fix="Confirm the address is correct and the site is publicly reachable, then re-run the scan.",
                evidence={"httpUrl": plain_http_url, "error": type(exc).__name__},
            )

    # Outside the `async with` block now: the connection is closed, but the
    # response object captured above is still ours to read.

    status = response.status_code

    # PYTHON-SPECIFIC: .get() on a dict returns a default instead of raising when
    # the key is missing. response.headers["location"] would blow up on a
    # response that has no Location header. In JS a missing property just gives
    # you undefined; Python dicts raise KeyError, so .get() is the safe form.
    location = response.headers.get("location", "")

    if status in REDIRECT_STATUSES:
        # A Location header is allowed to be relative, e.g. "/home". urljoin
        # resolves it against the URL that was requested, so a relative redirect
        # is correctly read as still-HTTP instead of breaking the scheme test.
        redirect_target = urljoin(plain_http_url, location)
        target_scheme = urlparse(redirect_target).scheme

        if target_scheme == "https":
            return _build_finding(
                severity=PASSED,
                title="HTTPS enforced",
                description="All traffic redirected to a secure connection",
                explanation=(
                    f"A plain HTTP request was answered with {status} and "
                    f"redirected to {redirect_target}. Visitors who type the "
                    "insecure address are moved to the encrypted one, so their "
                    "traffic cannot be read or altered in transit."
                ),
                fix="No action needed. Keep certificate auto-renewal running so this does not lapse.",
                evidence={
                    "httpUrl": plain_http_url,
                    "status": status,
                    "redirectedTo": redirect_target,
                },
            )

        # It redirects, but to another HTTP address - the visitor never reaches
        # TLS, so the redirect gives a false sense of security.
        return _build_finding(
            severity=CRITICAL,
            title="HTTPS not enforced",
            description="HTTP requests redirect to another insecure address",
            explanation=(
                f"A plain HTTP request was redirected with {status}, but the "
                f"destination was {redirect_target} - still unencrypted. Every "
                "page view, login form and session cookie on that address "
                "travels in clear text, readable by anyone on the same network."
            ),
            fix=(
                "Point the redirect at the https:// address, then add a "
                "Strict-Transport-Security header so browsers refuse the "
                "plaintext version on later visits."
            ),
            evidence={
                "httpUrl": plain_http_url,
                "status": status,
                "redirectedTo": redirect_target,
            },
        )

    if 200 <= status < 300:
        # PYTHON-SPECIFIC: a chained comparison. `200 <= status < 300` is legal
        # and means exactly what it looks like. The same expression in JS
        # silently misevaluates - there you must write `status >= 200 && status < 300`.
        #
        # The site answered the insecure address with real content and no
        # redirect. This is the failure the check exists to catch.
        return _build_finding(
            severity=CRITICAL,
            title="HTTPS not enforced",
            description="The site serves content over plain HTTP",
            explanation=(
                f"A request to {plain_http_url} returned {status} and served the "
                "page directly, with no redirect to HTTPS. Anyone sharing a "
                "network with your visitors - public Wi-Fi, a compromised router, "
                "an ISP - can read and modify that traffic, including credentials "
                "typed into a login form."
            ),
            fix=(
                "Redirect all HTTP traffic to HTTPS with a 301 at the web server "
                "or load balancer, then add a Strict-Transport-Security header so "
                "browsers stop using the plaintext address at all."
            ),
            evidence={"httpUrl": plain_http_url, "status": status},
        )

    # Anything else (4xx, 5xx): the server answered, but not in a way that says
    # whether a redirect rule exists. Reported as a warning - not a pass and not
    # a failure - because the honest answer is "inconclusive".
    return _build_finding(
        severity=WARNING,
        title="HTTPS enforcement unclear",
        description=f"The HTTP address returned an unexpected {status}",
        explanation=(
            f"A request to {plain_http_url} returned {status} rather than a "
            "redirect or a page. The server is reachable over plaintext HTTP but "
            "did not reveal whether it enforces HTTPS."
        ),
        fix="Check the web server configuration for an explicit HTTP-to-HTTPS redirect rule.",
        evidence={"httpUrl": plain_http_url, "status": status},
    )
