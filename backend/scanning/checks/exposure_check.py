"""
SENSITIVE DATA EXPOSURE CHECK - spec section 5, Tier 1.

WHY THIS FILE EXISTS
Servers leak. A crash renders a stack trace to the page instead of a 500, a debug
build ships with a config endpoint enabled, an error message quotes the SQL it was
about to run. Each one hands an attacker a free map: framework and version, file
paths, table names, sometimes a credential outright. This check reads what the site
actually returned and looks for the shapes of those leaks.

WHAT IT SCANS AND WHY IT SENDS NO REQUESTS OF ITS OWN
It inspects the response bodies discovery ALREADY fetched - home, login, signup -
plus their Server and X-Powered-By headers. That is deliberate: probing for leaks by
requesting /.env, /.git/config, /phpinfo.php and the like is a genuinely more
intrusive scan - it is hunting for files the owner did not link - and it belongs
behind the same explicit decision the rate-limit probe got, not folded in quietly
here. So this check is passive. It reports the leaks visible on the pages a browser
would fetch anyway.

THE FALSE-POSITIVE DISCIPLINE THAT MATTERS
A scanner that flags every 40-character hex string as a "leaked hash" is a scanner
people stop reading. Every pattern here is anchored to a CONTEXT that makes a match
mean something: a private-key header, a cloud-provider key prefix, a stack-trace
keyword next to a file path. A bare high-entropy string is not reported, because on
a real page it is far more often a cache-buster or an asset hash than a secret.
"""

import re

from ._finding import PASSED, WARNING, CRITICAL, finding_builder

CHECK_ID = "exposure_check"

_build_finding = finding_builder(CHECK_ID)

# THE PATTERNS. Each entry: (label, severity-when-found, compiled regex, why).
#
# PYTHON-SPECIFIC: re.compile with re.I where case varies. The patterns are written
# to demand CONTEXT - a prefix, a delimiter, a keyword - rather than raw entropy,
# because context is the whole difference between a finding and a false alarm.
#
# "critical" here means "this is a live secret or a direct internal disclosure";
# "warning" means "this reveals more than it should but is not itself a key".
_PATTERNS = (
    (
        "Private key block",
        CRITICAL,
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "A private key was served in a page body. Anyone who fetched it holds it.",
    ),
    (
        "AWS access key id",
        CRITICAL,
        # AKIA/ASIA then 16 uppercase-or-digit chars is the documented shape of an
        # AWS key id. The prefix is what stops this matching arbitrary text.
        re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
        "An AWS access key id is present, usually paired with a secret nearby.",
    ),
    (
        "Google API key",
        CRITICAL,
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "A Google API key ships in the page. Restrict it or rotate it.",
    ),
    (
        "Bearer/authorization token",
        CRITICAL,
        re.compile(r'(?i)authorization"?\s*[:=]\s*"?bearer\s+[A-Za-z0-9._\-]{20,}'),
        "An Authorization: Bearer token appears in a response body.",
    ),
    (
        "Password hash",
        CRITICAL,
        # bcrypt ($2a/$2b/$2y), Argon2, and crypt-SHA ($5$/$6$). All are unmistakable
        # by prefix, unlike a bare hex digest which could be anything.
        re.compile(r"\$(2[aby]|argon2(id|i|d)|5|6)\$[./A-Za-z0-9$+=,]{10,}"),
        "A password hash is exposed. Even a strong hash should never leave the server.",
    ),
    (
        "Python stack trace",
        WARNING,
        re.compile(r'Traceback \(most recent call last\):|File ".*", line \d+, in '),
        "A Python traceback reveals file paths, framework internals and code flow.",
    ),
    (
        "Java/JVM stack trace",
        WARNING,
        re.compile(r"\bat [a-z0-9_.]+\.[A-Za-z0-9_$]+\([A-Za-z0-9_]+\.java:\d+\)"),
        "A Java stack trace reveals package structure and library versions.",
    ),
    (
        "SQL error",
        WARNING,
        re.compile(
            r"(?i)(SQL syntax.*MySQL|Warning:\s+mysql_|PostgreSQL.*ERROR|"
            r"ORA-\d{5}|SQLSTATE\[|Unclosed quotation mark after)"
        ),
        "A database error was rendered to the page, often quoting the query.",
    ),
    (
        "Framework debug page",
        WARNING,
        re.compile(
            r"(Werkzeug Debugger|Whoops\?, looks like something went wrong|"
            r"DjangoDebug|Rails\.application|__debug__|APP_DEBUG)"
        ),
        "A debug interface is enabled, which exposes internals and sometimes a console.",
    ),
)

# Header values that name the exact software and version running. Low severity on
# its own - version disclosure only helps an attacker who already has a matching
# exploit - but it is free to read and worth saying, and its ABSENCE is a small
# positive signal.
_VERSIONED_HEADER = re.compile(r"\d+\.\d+")
_VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


# WHY THIS EXISTS
# One pass over each fetched page: scan the body against every pattern, then read the
# version headers. The heavy thinking is in the patterns above; this just applies
# them and shapes the finding.
#
# It takes the ScanTarget because the bodies were already fetched by discovery.
# Re-requesting them would be wasted traffic AND could miss the leak - a stack trace
# appears on the request that errored, and the next identical request may succeed.
async def check_exposure(target) -> dict:
    # PYTHON-SPECIFIC: a list of (page-label, Page) for the pages that exist, so the
    # finding can say WHERE a leak was, not just that there was one.
    pages = []
    for label, page in (
        ("home", target.home),
        ("login", target.login),
        ("signup", target.signup),
    ):
        if page is not None:
            pages.append((label, page))

    if not pages:
        return _build_finding(
            severity=PASSED,
            title="No responses to inspect for data exposure",
            description="No page content was retrieved",
            explanation=(
                "The scan retrieved no page bodies, so there was nothing to inspect "
                "for exposed secrets or error output. Reachability is reported by the "
                "other checks."
            ),
            fix="Confirm the site is reachable, then re-run the scan.",
            evidence={"pagesInspected": 0},
        )

    # PYTHON-SPECIFIC: a dict maps severity to a rank so "is this worse than what I
    # have" is one comparison, starting at the lowest.
    _RANK = {PASSED: 0, WARNING: 1, CRITICAL: 2}
    hits: list[dict] = []
    worst = PASSED
    version_disclosures: list[str] = []

    for label, page in pages:
        # Cap the text fed to the regexes: a multi-megabyte page would make the scan
        # slow for no gain, and a leak past 500 KB of minified JavaScript is not one a
        # human would ever have seen either.
        body = page.html[:500_000]

        for pattern_label, severity, regex, why in _PATTERNS:
            match = regex.search(body)

            if match is None:
                continue

            # THE MATCHED TEXT IS NOT STORED VERBATIM. That would copy the very secret
            # this check flags into the scan result in MongoDB and onto the report
            # page - turning a finding about a leak into a second copy of it. Only the
            # label, the page and a redacted marker are kept.
            hits.append(
                {
                    "type": pattern_label,
                    "where": label,
                    "url": page.url,
                    "why": why,
                    "sample": _redact(match.group(0)),
                }
            )

            if _RANK[severity] > _RANK[worst]:
                worst = severity

        for header in _VERSION_HEADERS:
            value = page.headers.get(header, "")
            if value and _VERSIONED_HEADER.search(value):
                version_disclosures.append(f"{label}: {header}: {value}")

    if not hits and not version_disclosures:
        return _build_finding(
            severity=PASSED,
            title="No sensitive data exposed",
            description="No secrets, stack traces or debug output were found",
            explanation=(
                "The pages inspected contained no private keys, cloud credentials, "
                "password hashes, stack traces, database errors or debug interfaces, "
                "and no version headers naming an exact release. This covers the "
                "public pages reached; it is not a guarantee about authenticated "
                "responses."
            ),
            fix="No action needed. Keep debug modes off in production builds.",
            evidence={"pagesInspected": len(pages)},
        )

    # Version disclosure alone, with no real leak, is a warning at most - and worth
    # its own gentler wording so it does not read as "you leaked a key".
    if not hits:
        return _build_finding(
            severity=WARNING,
            title="Software version disclosed in headers",
            description=(
                f"{len(version_disclosures)} response header(s) name exact software "
                "versions"
            ),
            explanation=(
                "No secrets or error output were found, but these headers announce "
                "the exact software and version in use:\n"
                + "\n".join(f"- {v}" for v in version_disclosures)
                + "\n\nThat lets an attacker skip straight to exploits known for that "
                "version. It is a small leak, not an emergency."
            ),
            fix=(
                "Suppress or genericise the Server, X-Powered-By and framework "
                "version headers at the web server or reverse proxy."
            ),
            evidence={"versionHeaders": version_disclosures},
        )

    # PYTHON-SPECIFIC: de-duplicate the hit TYPES for the one-line description while
    # keeping every individual hit in the evidence.
    types = list(dict.fromkeys(h["type"] for h in hits))
    detail_lines = "\n".join(
        f"- {h['type']} on the {h['where']} page: {h['why']}" for h in hits
    )

    return _build_finding(
        severity=worst,
        title=(
            "Sensitive data exposed in responses"
            if worst == CRITICAL
            else "Internal information disclosed in responses"
        ),
        description=f"Found: {', '.join(types)}",
        explanation=(
            "The scan found the following in page responses:\n"
            f"{detail_lines}\n\nData like this hands an attacker credentials, file "
            "paths or software details that should never leave the server. The full "
            "matched values are deliberately not stored in this report."
        ),
        fix=(
            "Return generic error pages in production and log the detail server-side "
            "instead. Remove any credential or key from responses and ROTATE it - "
            "treat anything served publicly as compromised. Turn off debug modes in "
            "the production build."
        ),
        evidence={
            "findings": hits,
            "versionHeaders": version_disclosures,
            "pagesInspected": len(pages),
        },
    )


# WHY REDACTION LIVES HERE
# The one job: prove a match was real without copying the secret. Keep a few leading
# characters for a human to recognise, replace the rest. Never the tail - the tail of
# a key is as sensitive as the head.
def _redact(value: str) -> str:
    value = value.strip()

    if len(value) <= 12:
        return value[:4] + "..."

    return value[:6] + "..." + f"[{len(value)} chars]"
