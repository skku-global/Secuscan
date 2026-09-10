"""Branch tests for check_https URL construction and refusal semantics.

The probe address is the thing that was wrong, so these tests pin it directly as
well as pinning the verdicts. Everything stays on 127.0.0.1.
"""

import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import _path  # noqa: F401  - puts backend/ on sys.path; must precede the imports below
from scanning.checks._finding import CRITICAL, PASSED, WARNING
from scanning.checks.https_check import check_https
from scanning.discovery import ScanTarget

PASS_COUNT = 0
FAIL_COUNT = 0


def check(label, got, want):
    global PASS_COUNT, FAIL_COUNT
    ok = got == want
    if ok:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f"   (got {got!r}, wanted {want!r})"))


def free_port():
    """A port that was bound and released, so nothing is listening on it."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Plain(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"<html><body>Served over plain HTTP, no redirect.</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


run = asyncio.run

print("check_https branches")

# 1. An http:// target on a live ephemeral port. The probe must reach THAT port and
#    see real content with no redirect -> the site genuinely fails to enforce HTTPS.
server = HTTPServer(("127.0.0.1", 0), Plain)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    result = run(check_https(ScanTarget(url=f"http://127.0.0.1:{port}/")))
finally:
    server.shutdown()

check("live plaintext port -> critical", result["severity"], CRITICAL)
check("probe kept the port", result["evidence"]["httpUrl"], f"http://127.0.0.1:{port}/")

# 2. An http:// target where nothing is listening. This is the false pass: it must be
#    a WARNING ("could not check"), never "HTTPS enforced".
dead = free_port()
result = run(check_https(ScanTarget(url=f"http://127.0.0.1:{dead}/")))
check("dead plaintext port -> warning", result["severity"], WARNING)
check("dead port not reported as pass", result["severity"] != PASSED, True)
check("dead port names the scheme", result["evidence"]["targetScheme"], "http")
check("dead port kept the port", result["evidence"]["httpUrl"], f"http://127.0.0.1:{dead}/")
check("title says could not check", "Could not check" in result["title"], True)

# 3. An https:// target. The plaintext counterpart is port 80, so a non-default TLS
#    port must be DROPPED - cleartext does not live on :8443.
result = run(check_https(ScanTarget(url="https://127.0.0.1:8443/")))
check("https target drops tls port", result["evidence"]["httpUrl"], "http://127.0.0.1/")

# 4. An https:// target whose port 80 refuses is the original, legitimate pass.
#    (Nothing listens on port 80 of 127.0.0.1 in this environment.)
check("https + refused port 80 -> passed", result["severity"], PASSED)
check("passed names the scheme", result["evidence"]["targetScheme"], "https")

# 5. A garbage address still cannot crash, and must not pass.
result = run(check_https(ScanTarget(url="not a url")))
check("unparseable -> warning", result["severity"], WARNING)

print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
raise SystemExit(1 if FAIL_COUNT else 0)
