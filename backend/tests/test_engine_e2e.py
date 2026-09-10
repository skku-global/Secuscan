"""Hermetic end-to-end test of the scan engine.

Serves a small site on localhost with KNOWN properties, then runs the real
run_scan against it. No third-party traffic: every request stays on 127.0.0.1.

The fixture site is deliberately imperfect so the checks have something to find:
  - a session cookie with no Secure/HttpOnly/SameSite  -> cookies_check critical
  - no security headers at all                         -> headers_check critical
  - a Server header naming an exact version            -> exposure_check warning
  - served over plain http:// with no redirect         -> https_check critical
  - a real login form, found via a homepage link       -> discovery
  - MFA wording + a /settings/security link            -> mfa_check pass
  - a RateLimit-Remaining header on the login page     -> rate_limit_check pass
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import _path  # noqa: F401  - puts backend/ on sys.path; must precede the imports below
from scanning.engine import run_scan

HOME = b"""<!doctype html><html><head><title>Fixture Co</title></head><body>
<h1>Fixture Co</h1>
<p>Welcome to the fixture site used to test the scanner.</p>
<nav>
  <a href="/login">Sign in</a>
  <a href="/signup">Create an account</a>
  <a href="/settings/security">Security settings</a>
</nav>
</body></html>"""

LOGIN = b"""<!doctype html><html><head><title>Sign in</title></head><body>
<h1>Sign in</h1>
<form method="post" action="/session">
  <input type="email" name="email">
  <input type="password" name="password">
  <button type="submit">Sign in</button>
</form>
<p>Two-factor authentication is required. Open your authenticator app and
enter your verification code.</p>
<a href="/2fa/setup">Set up two-factor authentication</a>
</body></html>"""

SIGNUP = b"""<!doctype html><html><head><title>Create an account</title></head><body>
<h1>Create an account</h1>
<form method="post" action="/users">
  <input type="email" name="email">
  <input type="password" name="password" minlength="12" maxlength="128"
         autocomplete="new-password" required>
  <input type="password" name="password_confirmation" minlength="12" maxlength="128"
         autocomplete="new-password" required>
  <button type="submit">Register</button>
</form>
<p>Your password must be at least 12 characters. Spaces and symbols are welcome.</p>
</body></html>"""

PAGES = {"/": HOME, "/login": LOGIN, "/signup": SIGNUP}


NON_GET_REQUESTS = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record_and_reject(self):
        NON_GET_REQUESTS.append((self.command, self.path))
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # Every method the scanner must never use. Defined rather than left to the base
    # class's 501, so an unexpected request is RECORDED instead of merely refused.
    do_POST = _record_and_reject
    do_PUT = _record_and_reject
    do_PATCH = _record_and_reject
    do_DELETE = _record_and_reject

    def do_GET(self):
        body = PAGES.get(self.path)

        if body is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            # Deliberately still naming a version, so exposure_check has a hit
            # even on the probe 404s.
            self.send_header("Server", "nginx/1.18.0")
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # An exact version, which exposure_check flags as a small leak.
        self.send_header("Server", "nginx/1.18.0")
        # NO security headers at all -> headers_check should go critical.
        if self.path == "/login":
            # A session cookie with none of the three protective flags.
            self.send_header("Set-Cookie", "sessionid=fixture-abc123; Path=/")
            self.send_header("Set-Cookie", "cart_items=3; Path=/; Max-Age=600")
            # A rate limiter announcing itself. Sent with the ORIGINAL capitalisation
            # so the run also proves the header name is normalised on the way in -
            # rate_limit_check matches lowercase names.
            self.send_header("RateLimit-Remaining", "99")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # keep the test output readable


def main():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}/"
    print(f"fixture site serving at {url}\n")

    try:
        scan = asyncio.run(run_scan(url))
    finally:
        server.shutdown()

    print(f"score      : {scan['score']}")
    print(f"id         : {scan['id']}")
    print(f"targetUrl  : {scan['targetUrl']}")
    print(f"tier       : {scan['tier']}")
    print()
    print("discovery:")
    for key, value in scan["discovery"].items():
        print(f"  {key}: {value}")
    print()
    print(f"findings ({len(scan['findings'])}):")

    contract = ("id", "checkId", "title", "description", "severity",
                "explanation", "fix", "evidence")

    for finding in scan["findings"]:
        missing = [k for k in contract if k not in finding]
        flag = f"  !! MISSING KEYS: {missing}" if missing else ""
        print(f"  [{finding['severity']:>8}] {finding['checkId']:<16} "
              f"{finding['title']}{flag}")

    print()
    print("evidence detail:")
    for finding in scan["findings"]:
        print(f"  {finding['checkId']}: {finding['evidence']}")

    # THE TIER 1 GUARANTEE, asserted at the engine level: no check may submit a form.
    # The per-check test pins this for rate_limit_check by making httpx.AsyncClient
    # explode; this pins it for the whole scan, against a server that would have
    # answered a POST.
    print()
    if NON_GET_REQUESTS:
        print(f"  FAIL non-GET requests were sent: {NON_GET_REQUESTS}")
        raise SystemExit(1)
    print("  ok   Tier 1 sent no POST/PUT/PATCH/DELETE requests")

    # THE ATTRIBUTE PIPELINE, asserted end to end. password_check reads Field.attrs,
    # which only exists because discovery's parser kept every attribute off the input -
    # so a fixture whose minlength arrives as 12 proves the whole path works, the same
    # way the RateLimit-Remaining header pins header lowercasing.
    by_id = {f["checkId"]: f for f in scan["findings"]}
    pw = by_id.get("password_check")
    if pw is None:
        print("  FAIL password_check did not run")
        raise SystemExit(1)
    if pw["evidence"]["minlengthAttribute"] != 12:
        print(f"  FAIL minlength not parsed: {pw['evidence']['minlengthAttribute']!r}")
        raise SystemExit(1)
    if pw["evidence"]["maxlengthAttribute"] != 128:
        print(f"  FAIL maxlength not parsed: {pw['evidence']['maxlengthAttribute']!r}")
        raise SystemExit(1)
    if pw["severity"] != "passed":
        print(f"  FAIL good policy not passed: {pw['severity']!r}")
        raise SystemExit(1)
    if pw["evidence"]["passwordManagerBlocked"]:
        print("  FAIL autocomplete=new-password read as blocking")
        raise SystemExit(1)
    print("  ok   password_check read minlength/maxlength through the real parser")


if __name__ == "__main__":
    main()
