"""
SECUSCAN API - the FastAPI entry point.

WHY THIS FILE EXISTS
This is the front door: it turns HTTP requests into calls to the scan engine and
engine results back into JSON. It is deliberately thin. No scanning logic lives
here, because the moment it does, the engine can no longer be driven by anything
other than an HTTP request - and scheduled re-scans (a paid-plan feature in the
spec) will need exactly that.

Three things are enforced here rather than in the engine, because all three are
properties of "who is asking", which only the API layer can see:
  1. the consent confirmation,
  2. refusing to scan internal network addresses, and
  3. the session - who is signed in, and which scans are therefore theirs.

Every scan endpoint requires a session. There is exactly one exception, GET
/report/{id}, which serves the link a client forwards to somebody without an
account; it is a separate endpoint rather than a flag on a protected one, so the
exception is visible in the routing table instead of hidden in a branch.

Start it with:   uvicorn main:app --reload
Interactive docs: http://127.0.0.1:8000/docs
"""

import ipaddress
import json
import secrets
import socket
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator, model_validator

import auth
import billing
import config
import database
import google_auth
import mailer
import payments
import credentials
from scanning.engine import run_scan


# WHY THIS EXISTS
# The database connection has to be opened once when the server starts and closed
# once when it stops - not per request. This function is where FastAPI lets you
# hook into both moments.
#
# FASTAPI: this is the "lifespan" pattern. Everything before `yield` runs at
# startup, before the first request is accepted; everything after runs at
# shutdown. If you find older tutorials using @app.on_event("startup"), that API
# is deprecated in favour of this.
#
# PYTHON-SPECIFIC: @asynccontextmanager turns a function containing one `yield`
# into an async context manager. `yield` here does not mean "generator of values"
# in the usual sense - it means "pause here and hand control back; resume when the
# block exits". It is the same machinery that makes `async with` work in
# https_check.py, viewed from the other side.
@asynccontextmanager
async def lifespan(app: FastAPI):
    # A failure here stops the server from starting at all, with the real reason
    # printed - which is what you want. A scanner that boots happily and then
    # cannot save anything is worse than one that refuses to boot.
    await database.connect()

    # WHY THESE ARE PRINTED HERE AND NOT RAISED
    # Every one of these is a feature that will be missing rather than a server that
    # cannot run - no Google client id means the button is hidden, no Resend key means
    # the email fallback is unavailable. Refusing to boot over any of them would make
    # a local checkout with an empty .env unusable for working on the scanner.
    #
    # Printing at startup is the compromise that matters: the warning appears once,
    # where somebody is looking, instead of as a mystery 503 to a user three weeks
    # later. See config.startup_warnings().
    for warning in config.startup_warnings():
        print(f"[config] {warning}")

    yield  # <- the server runs, and serves every request, at this line

    await database.disconnect()


# PYTHON-SPECIFIC / FASTAPI: `app` is the application object. The name matters:
# the start command `uvicorn main:app` literally means "in the module main, find
# the variable named app". Rename this and the start command must change too.
app = FastAPI(
    title="SecuScan API",
    version="0.1.0",
    description="Web application security auditing. One check wired up so far.",
    # Passing the function itself, not calling it - FastAPI runs it for us.
    lifespan=lifespan,
)

# FASTAPI: middleware wraps every request and response. Browsers refuse
# cross-origin requests unless the server opts in, and the React dev server runs
# on a different port to this one (8000) - which counts as cross-origin. Without
# this, the frontend's fetch() will fail with a CORS error even though curl works
# perfectly, which is a genuinely confusing first bug to hit.
#
# WHY THE ORIGINS ARE NO LONGER WRITTEN HERE: they were, as
# ["http://localhost:5173", "http://127.0.0.1:5173"], and that broke the whole
# frontend the first time Vite started on 5174 instead - which it does silently
# whenever 5173 is already in use. The port a dev server picks at runtime is not
# something a source file can know. config.py now supplies both halves: an
# explicit list for a real deployment, and a loopback-only regex for development
# that turns itself off as soon as the list is set. The reasoning is written out
# in full there.
#
# WHAT IS STILL FORBIDDEN: allow_origins=["*"] on an authenticated API. The regex
# below is anchored to localhost and 127.0.0.1 precisely so that it is not one.
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    # FASTAPI: matched against the Origin header when it is not in allow_origins.
    # None disables it entirely, which is what config returns once real origins
    # are configured.
    allow_origin_regex=config.cors_origin_regex(),
    # GET was added alongside POST when the report page started fetching a stored
    # scan. Only the methods actually used are listed - a browser sends a
    # preflight OPTIONS request for anything not on this list and gives up.
    allow_methods=["GET", "POST"],
    # Authorization was added for the session token. A header not on this list is
    # stripped by the browser before the request is sent, so a missing entry here
    # looks exactly like a server that ignores the token.
    allow_headers=["Content-Type", "Authorization"],
)


# WHY THIS EXISTS
# SecuScan makes an HTTP request to whatever address the caller supplies. Left
# unguarded that is a well-known vulnerability class called SSRF: someone posts
# http://localhost:9200 or http://169.254.169.254/ and uses this server as a
# proxy to reach things only it can see - internal admin panels, databases, or a
# cloud provider's credential endpoint. The scanner would faithfully report what
# it found there.
#
# Resolving the hostname first and rejecting private address space closes that.
# It matters more here than in most apps: shipping a security product with an
# open SSRF hole would be its own headline.
def _resolves_to_public_address(hostname: str) -> bool:
    try:
        # PYTHON-SPECIFIC: getaddrinfo returns a list of tuples describing every
        # address the name resolves to. A hostname can have several (IPv4 and
        # IPv6), and ALL of them must be public - checking only the first would
        # let a dual-homed name slip through.
        address_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        # Cannot resolve. Rejected here so the failure is a clear 422 about a bad
        # address, rather than a confusing check result later on.
        return False

    for info in address_infos:
        # The sockaddr tuple is the 5th element; its first item is the IP string.
        ip_address = ipaddress.ip_address(info[4][0])

        # PYTHON-SPECIFIC: these are properties, not method calls - no parentheses.
        # is_private covers 10.x / 192.168.x / 172.16-31.x, is_loopback covers
        # 127.x and ::1, and is_link_local covers 169.254.x, which is where every
        # major cloud provider parks its instance-credentials endpoint.
        if (
            ip_address.is_private
            or ip_address.is_loopback
            or ip_address.is_link_local
            or ip_address.is_reserved
            or ip_address.is_multicast
            or ip_address.is_unspecified
        ):
            return False

    return True


# ============================================================================
# WHO IS ASKING
#
# The session gate lives up here, above the endpoints, for a reason that is
# Python rather than design: `Depends(require_session)` is a DEFAULT ARGUMENT
# VALUE, and Python evaluates those when the `def` statement runs - at import,
# not at request time. A dependency defined below the endpoint that uses it is a
# NameError on startup. The accounts section further down owns everything else
# about auth; only this one piece has to come first.
# ============================================================================


# WHY THIS EXISTS
# The gate any endpoint can stand behind. It turns the Authorization header into a
# real user record, or ends the request with 401.
#
# FASTAPI: this is a DEPENDENCY. Declaring `user: dict = Depends(require_session)`
# on a handler makes FastAPI run this first, pass the result in, and skip the
# handler entirely if it raises - so an endpoint cannot accidentally forget to check
# the token. Header(...) tells FastAPI to read the value from a request header
# rather than the body. This is roughly what Express middleware does, except it is
# declared per route and its return value is typed.
async def require_session(
    authorization: str | None = Header(default=None),
) -> dict:
    # PYTHON-SPECIFIC: str.partition splits on the FIRST occurrence and always
    # returns three parts, so it cannot raise on a malformed header the way
    # split(" ")[1] would.
    scheme, _, token = (authorization or "").partition(" ")

    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Sign in to continue.")

    session = await database.find_session(auth.hash_token(token))

    if session is None:
        # One message for "no such token" and "expired token" alike. The
        # distinction is of no use to a legitimate client and of real use to
        # someone testing stolen tokens.
        raise HTTPException(status_code=401, detail="Your session has expired. Sign in again.")

    user = await database.find_user_by_id(session["userId"])

    if user is None:
        # A live session pointing at a deleted account. Rare, but treating it as
        # authenticated would mean a deleted user still had access.
        raise HTTPException(status_code=401, detail="Your session has expired. Sign in again.")

    return user


# WHY THIS EXISTS
# Tier 2 checks require authenticated access provided via dedicated test credentials.
# This schema defines the structure for client-submitted credentials (staging URL, username, password).
# Sensitive values are never logged or stored in plaintext.
class Tier2Credentials(BaseModel):
    stagingUrl: str | None = Field(None, description="Optional staging or test environment URL")
    username: str = Field(..., min_length=1, max_length=256, description="Dedicated test account username/email")
    password: str = Field(..., min_length=1, max_length=256, description="Dedicated test account password")

    # RETENTION IS OPT-IN AND DEFAULTS TO KEEPING NOTHING.
    # The default path never writes these credentials anywhere: they are held in memory
    # for the duration of the scan and dropped when it ends. A client who wants to
    # re-run the same audit later can ask for them to be kept, and that request is what
    # this flag is - a choice the client made, not a convenience the server assumed.
    #
    # Note the direction of the default. A boolean that defaults to False stores nothing
    # when an older client, a hand-rolled curl call, or a future caller omits the field.
    # Defaulting to True would mean every caller that had not heard of retention yet
    # silently opted their client's password into a day on disk.
    retain: bool = Field(
        default=False,
        description=(
            "Keep these credentials encrypted at rest for 24 hours so the scan can be "
            "re-run without re-entering them. Defaults to false, in which case they "
            "are used for this scan only and are never written to storage."
        ),
    )

    @field_validator("stagingUrl")
    @classmethod
    def validate_staging_url(cls, value: str | None) -> str | None:
        if not value or not value.strip():
            return None
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Staging URL must start with http:// or https://")
        if not parsed.hostname:
            raise ValueError("Staging URL must include a hostname")
        if not _resolves_to_public_address(parsed.hostname):
            raise ValueError("Staging URL must resolve to a public address")
        return value.strip()


# WHY THIS EXISTS
# FASTAPI: this class IS the request body schema. FastAPI reads the type hints,
# validates incoming JSON against them, rejects anything malformed with a 422 and
# a precise error message, and publishes the shape in the auto-generated docs -
# all without a line of parsing code. There is no real JS equivalent; the closest
# is defining a Zod schema and remembering to call it on every route.
class ScanRequest(BaseModel):
    # PYTHON-SPECIFIC: these are class-level annotations, not assignments. `url:
    # str` declares a required field of type str. Field(...) attaches metadata -
    # the ... (Ellipsis, a real Python value) means "required, no default".
    url: str = Field(..., description="Full address to scan, e.g. https://example.com")

    consent: bool = Field(
        ...,
        description=(
            "Must be true. Confirms the caller owns the target site or has "
            "written authorisation to scan it."
        ),
    )

    loginUrl: str | None = Field(
        default=None,
        description="Optional login page URL if discovery cannot locate it",
    )

    tier: int = Field(
        default=1,
        ge=1,
        le=2,
        description="Audit tier: 1 for passive external checks, 2 for deep authenticated audit",
    )

    credentials: Tier2Credentials | None = Field(
        default=None,
        description="Test account credentials required for Tier 2 scans",
    )

    # FASTAPI / PYTHON-SPECIFIC: a DECORATOR. The @ line modifies the function
    # underneath it - here it registers the function as a validator for the "url"
    # field. Decorators are the pattern you will see everywhere in FastAPI
    # (@app.post below is another). The rough JS analogue is a higher-order
    # function wrapping another function, except the @ syntax applies it in place.
    @field_validator("url")
    @classmethod
    def url_must_be_public_http(cls, value: str) -> str:
        # PYTHON-SPECIFIC: @classmethod means the first parameter is the class
        # itself (`cls`), not an instance (`self`). Pydantic requires validators
        # to be class methods. `cls` is unused here, which is normal.
        parsed = urlparse(value.strip())

        if parsed.scheme not in {"http", "https"}:
            # PYTHON-SPECIFIC: raising ValueError inside a Pydantic validator is
            # how you reject input. FastAPI catches it and converts it into a 422
            # response naming this field and this message - you do not build the
            # error response yourself.
            raise ValueError("URL must start with http:// or https://")

        if not parsed.hostname:
            raise ValueError("URL must include a hostname, e.g. https://example.com")

        if not _resolves_to_public_address(parsed.hostname):
            raise ValueError(
                "Only public internet addresses can be scanned. This hostname is "
                "unresolvable or points to a private, loopback or link-local address."
            )

        # A validator returns the value it wants stored, which is also the place
        # to normalise. The stripped string is what the engine receives.
        return value.strip()

    @field_validator("loginUrl")
    @classmethod
    def validate_login_url(cls, value: str | None) -> str | None:
        if not value or not value.strip():
            return None
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Login URL must start with http:// or https://")
        if not parsed.hostname:
            raise ValueError("Login URL must include a hostname")
        if not _resolves_to_public_address(parsed.hostname):
            raise ValueError("Login URL must resolve to a public address")
        return value.strip()

    @field_validator("consent")
    @classmethod
    def consent_must_be_given(cls, value: bool) -> bool:
        # THE CONSENT GATE. SecuScan is a consent-based service - it sends real
        # traffic at a real third party, and doing that without permission is at
        # best rude and in many places illegal.
        #
        # It lives at the boundary, not in the UI, deliberately. A checkbox in
        # React is a courtesy that anyone can bypass with curl; a server-side
        # refusal is the actual control. The frontend checkbox and this validator
        # are two halves of one requirement.
        if value is not True:
            raise ValueError(
                "Consent is required. Set consent=true to confirm you own this "
                "site or have permission to scan it."
            )
        return value


# WHY THIS EXISTS
# The one endpoint. It accepts a URL, hands it to the engine, and returns the
# result. Everything protective happens before this function body runs - by the
# time it executes, the URL is a validated public http(s) address and consent has
# been given, so there is nothing left to do but delegate.
#
# FASTAPI: @app.post("/scan") registers this function as the handler for POST
# /scan. The decorator is the routing table - there is no separate router file
# listing paths, which is the biggest structural difference from Express.
@app.post("/scan")
async def create_scan(
    request: ScanRequest, user: dict = Depends(require_session)
) -> dict:
    # Check plan entitlement and limits
    user_plan = billing.effective_plan_for_user(user)

    if request.tier == 2:
        if user_plan.get("tier", 1) < 2:
            raise HTTPException(
                status_code=403,
                detail="Tier 2 audits require a Starter or Business plan. Please upgrade your plan to run Tier 2 scans.",
            )
        if not request.credentials or not request.credentials.username or not request.credentials.password:
            raise HTTPException(
                status_code=422,
                detail="Tier 2 scans require dedicated test account credentials (username and password).",
            )

    # ENFORCE PLAN LIMITS (scanLimit and siteLimit)
    # A free account has scanLimit=1 and siteLimit=1; Starter has 10 scans and 1 site;
    # Business has unlimited scans and 10 sites; Enterprise has no limits.
    # Refusal happens here before running the engine, before encrypting credentials,
    # and before any external traffic is sent.
    scan_limit = user_plan.get("scanLimit")
    site_limit = user_plan.get("siteLimit")
    period_start = billing.get_billing_period_start(user)

    if scan_limit is not None:
        current_scans = await database.count_user_scans(user["id"], since=period_start)
        if current_scans >= scan_limit:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Scan limit reached for this billing period ({scan_limit} scan{'s' if scan_limit > 1 else ''}). "
                    f"Upgrade your plan to run more scans."
                ),
            )

    if site_limit is not None:
        target_host = (urlparse(request.url).hostname or "").lower()
        distinct_sites = await database.get_user_distinct_sites(user["id"], since=period_start)
        if target_host and (target_host not in distinct_sites) and len(distinct_sites) >= site_limit:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Site limit reached for this billing period ({site_limit} target site{'s' if site_limit > 1 else ''}). "
                    f"Upgrade your plan to scan additional sites."
                ),
            )

    cred_dict = None
    encrypted_blob = None
    if request.tier == 2 and request.credentials:
        staging_url = request.credentials.stagingUrl or request.url
        cred_dict = {
            "stagingUrl": staging_url,
            "username": request.credentials.username,
            "password": request.credentials.password,
        }
        # ENCRYPTED BEFORE THE SCAN RUNS, NOT AFTER.
        # If the credentials cannot be protected at rest, nothing about this request
        # should happen: not the scan, not the storage, not the charge against the
        # customer's quota. Doing the work first and discovering the problem at save
        # time would leave a completed Tier 2 scan whose credentials had nowhere safe
        # to go, and the tempting fix at that point is to store them anyway.
        #
        # WHY THE KEY IS ONLY REQUIRED WHEN RETENTION WAS ASKED FOR.
        # This gate used to be unconditional, which was right when every Tier 2 scan
        # stored its credentials. It is not right now that the default stores nothing:
        # SECUSCAN_CREDENTIALS_KEY protects data AT REST, and a scan that writes nothing
        # to disk has no data at rest to protect. Refusing it would be failing closed on
        # a requirement that does not apply to the request being made.
        #
        # The fail-closed property is unchanged where it means something. The moment a
        # client asks for their password to be kept, an unconfigured server refuses
        # rather than reaching for a fallback key.
        if not request.credentials.retain:
            encrypted_blob = None
        else:
            try:
                encrypted_blob = credentials.encrypt_credentials(
                    staging_url=staging_url,
                    username=request.credentials.username,
                    password=request.credentials.password,
                )
            except credentials.CredentialsKeyMissing:
                # 503 RATHER THAN 500: the server is fine, the deployment is
                # unconfigured, and that distinction is what tells an operator to go and
                # set a variable instead of reading a stack trace. Nothing is logged
                # here because config.startup_warnings() already names this exact
                # variable at every single startup - a second report at request time
                # would add no information that the operator has not already been
                # handed.
                #
                # The client is told nothing about which variable is missing. An
                # unauthenticated caller learning the server's configuration gaps is a
                # gift to somebody mapping the deployment. They are told that the scan
                # would run without retention, because that is actionable and reveals
                # nothing about the server.
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "Credentials cannot be stored on this server right now, so this "
                        "scan was not run. Nothing was stored. Re-run without asking to "
                        "keep the credentials, or contact support."
                    ),
                )

    scan = await run_scan(
        url=request.url,
        login_url=request.loginUrl,
        tier=request.tier,
        credentials=cred_dict,
    )

    # Filed before returning, so the id in this response is one the report page
    # can actually fetch back.
    stored = await database.save_scan(scan, user["id"])
    if stored and encrypted_blob:
        # Reached only when the client asked for retention - encrypted_blob is None on
        # the default path, so the default Tier 2 scan leaves nothing behind at all.
        # Scoped to (scanId, userId) and swept by the TTL index after 24 hours.
        await database.save_scan_credentials(
            scan_id=scan["id"],
            user_id=user["id"],
            encrypted_blob=encrypted_blob,
            ttl_hours=24,
        )

    scan["stored"] = stored
    return scan


# WHY THESE EXIST
# Endpoints allowing the client to inspect credential retention status or immediately
# delete stored credentials for a completed scan before the 24-hour TTL sweep.
# The decrypted password is NEVER returned over the API.
@app.get("/scan/{scan_id}/credentials")
async def get_credentials_status_for_scan(
    scan_id: str, user: dict = Depends(require_session)
) -> dict:
    doc = await database.get_scan_credentials(scan_id, user["id"])
    if not doc:
        return {"hasCredentials": False}
    return {
        "hasCredentials": True,
        "createdAt": doc.get("createdAt").isoformat() if doc.get("createdAt") else None,
        "expiresAt": doc.get("expiresAt").isoformat() if doc.get("expiresAt") else None,
    }


@app.delete("/scan/{scan_id}/credentials")
async def delete_credentials_for_scan(
    scan_id: str, user: dict = Depends(require_session)
) -> dict:
    deleted = await database.delete_scan_credentials(scan_id, user["id"])
    return {"deleted": deleted}



# WHY THIS EXISTS
# The dashboard and history pages need to know what has been scanned before, and
# a per-id endpoint cannot tell them - they have no ids to ask about until they
# have the list. This is the only endpoint that answers a question about the
# collection rather than about one scan.
#
# It used to be unfiltered, with a note here saying it MUST gain an owner filter
# at the same time as authentication or every user would see every scan. That is
# now done: the filter is in database.list_scans(), and the owner it filters on
# comes from the session rather than from anything the caller can set.
@app.get("/scans")
async def list_scans(user: dict = Depends(require_session)) -> list:
    return await database.list_scans(user["id"])


# WHY THIS EXISTS
# This is what makes a scan result a document rather than a moment. The report
# page loads from a URL - someone refreshes, bookmarks it, or sends it to a
# developer - and this is the endpoint that answers with the stored findings.
# Without it the frontend has no honest source for a report and has to fall back
# to mock data, which is exactly the gap this closes.
#
# FASTAPI: the braces in the path declare a PATH PARAMETER. FastAPI matches the
# name inside them to the function argument of the same name and passes the value
# in - so /scan/1ec0deed arrives as scan_id="1ec0deed". This mirrors React
# Router's /dashboard/scan/:id on the frontend.
#
# This is the OWNER'S view of a scan: signed in, and only their own. Someone
# else's id returns the same 404 as an id that was never issued - see find_scan()
# in database.py for why those two answers are deliberately identical. The
# shareable version of this, for a reader with no account, is /report/{id} below.
@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str, user: dict = Depends(require_session)) -> dict:
    scan = await database.find_scan(scan_id, user["id"])

    if scan is None:
        # FASTAPI: raising HTTPException is how you return an error status. It
        # reads oddly at first - you `raise` rather than `return` - but it means
        # any function, however deeply nested, can end the request with a proper
        # response instead of threading an error value back up by hand.
        #
        # 404 rather than 200-with-an-error-body, because "this scan does not
        # exist" is precisely what 404 means, and the frontend can then branch on
        # response.ok instead of parsing the body to find out whether it worked.
        raise HTTPException(status_code=404, detail=f"No scan found with id {scan_id}")

    return scan


# WHY THIS EXISTS
# The forwarded report. /report/:id in the frontend is the view a client sends to
# their own developer, and that developer has no SecuScan account - so this is the
# one read path with no session behind it.
#
# It is a SEPARATE ENDPOINT from the one above rather than a relaxation of it, and
# that is the entire safety argument. The rule "every scan endpoint requires a
# session" now has exactly one exception, it is named /report, it is six lines
# long, and it is the only place in the codebase that calls find_shared_scan().
# The alternative - making the session optional on /scan/{id} - hides the same
# exposure inside a branch of an endpoint that otherwise looks protected.
#
# WHAT ACTUALLY GUARDS IT: the 8-character id and nothing else. Anyone holding
# the link can read the report, and links travel through proxy logs, browser
# history and forwarded email. For a report the owner chose to share that is the
# accepted trade; it is not a permission, and it must not be mistaken for one.
# See find_shared_scan() in database.py for the upgrade path - a revocable
# per-share token, so the scan id stops being the credential.
#
# Note what is NOT here: no way to discover an id. There is no shared equivalent
# of /scans, so a stranger can read a report they were given and cannot find one
# they were not.
@app.get("/report/{scan_id}")
async def get_shared_report(scan_id: str) -> dict:
    scan = await database.find_shared_scan(scan_id)

    if scan is None:
        raise HTTPException(status_code=404, detail=f"No scan found with id {scan_id}")

    return scan


# ============================================================================
# ACCOUNTS
#
# Everything below this line is authentication. It sits in main.py for the same
# reason the consent gate and the SSRF guard do: all three are properties of "who
# is asking", which is a question only the boundary can answer.
# ============================================================================


# WHY THIS EXISTS
# An unlimited number of login attempts is not a small gap on a security product -
# it is the difference between a password policy and a suggestion. Twelve
# characters only helps if an attacker gets a few thousand guesses rather than a
# few billion.
#
# BE CLEAR ABOUT WHAT THIS IS: a dictionary in the memory of one process. It is
# wiped by every restart, and two uvicorn workers would each keep their own count
# and so allow twice the attempts. The real implementation is a shared counter in
# Redis, or a limiter in front of the app. This is the honest 20-line version -
# genuinely better than nothing on a single-process deployment, and not to be
# mistaken for the finished control.
_attempts: dict[str, list[float]] = {}

_ATTEMPT_LIMIT = 10
_ATTEMPT_WINDOW_SECONDS = 15 * 60


# WHY THIS EXISTS
# Answers "has this key had too many goes recently", and records the attempt while
# it is at it. A sliding window rather than a fixed one: with a fixed window an
# attacker simply waits for the clock to tick over and gets a fresh allowance.
def _too_many_attempts(key: str) -> bool:
    now = time.monotonic()
    cutoff = now - _ATTEMPT_WINDOW_SECONDS

    # PYTHON-SPECIFIC: a LIST COMPREHENSION filtering in place - the same as
    # JavaScript's .filter(). Old timestamps are dropped as a side effect of
    # reading, which is what keeps this dictionary from growing forever.
    recent = [stamp for stamp in _attempts.get(key, []) if stamp > cutoff]
    recent.append(now)
    _attempts[key] = recent

    return len(recent) > _ATTEMPT_LIMIT


# PYTHON-SPECIFIC: time.monotonic(), not time.time(). A monotonic clock only ever
# moves forward at a steady rate, so an NTP correction or a daylight-saving jump
# cannot make a window suddenly appear to have elapsed - or never elapse.


# WHY THIS EXISTS
# Rate limits are counted per client, and behind a proxy every request appears to
# come from the proxy. This is where that would be handled - and where getting it
# wrong is a vulnerability rather than a bug, because trusting a header an attacker
# controls means they can reset their own limit by changing one value.
#
# So the header is deliberately NOT read here. request.client.host is the real TCP
# peer, which cannot be spoofed. Behind a load balancer this needs to change to
# read X-Forwarded-For, and that change is only safe once the proxy is known to
# overwrite the header rather than append to it.
def _client_key(request: Request, scope: str) -> str:
    host = request.client.host if request.client else "unknown"
    return f"{scope}:{host}"


# WHY THIS EXISTS
# FASTAPI: the request body for signup. The password rules are enforced as part of
# parsing, so a weak password cannot reach the handler - the same structure as the
# consent gate above, where the protection is in the model rather than in an `if`
# somebody could forget to write.
class SignupRequest(BaseModel):
    name: str = Field(..., description="Display name")
    email: str = Field(..., description="Login identifier")
    password: str = Field(..., description="At least 12 characters")

    @field_validator("name")
    @classmethod
    def name_must_not_be_blank(cls, value: str) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError("Name is required.")

        # An upper bound on anything a user can type and the server will store.
        # Not about security so much as about not letting one signup put a novel
        # in the database.
        if len(cleaned) > 100:
            raise ValueError("Name must be 100 characters or fewer.")

        return cleaned

    @field_validator("email")
    @classmethod
    def email_must_look_like_one(cls, value: str) -> str:
        # Normalised INSIDE the validator, so the value that reaches the handler -
        # and therefore the database - is already the canonical form. Doing it in
        # the handler instead means every future handler has to remember to.
        cleaned = auth.normalise_email(value)

        if not auth.looks_like_email(cleaned):
            raise ValueError("Enter a valid email address.")

        return cleaned

    # FASTAPI / PYDANTIC: a MODEL validator rather than a field validator, because
    # the password rules need the email and the name to check the password does not
    # contain them - and a field validator only ever sees its own field. mode=
    # "after" means it runs once every individual field has already been validated,
    # so the values here are cleaned rather than raw.
    #
    # PYTHON-SPECIFIC: it takes `self` and returns `self`, unlike the @classmethod
    # field validators above. An "after" model validator receives the built model.
    @model_validator(mode="after")
    def password_must_meet_policy(self) -> "SignupRequest":
        problem = auth.password_problem(self.password, email=self.email, name=self.name)

        if problem:
            raise ValueError(problem)

        return self


# WHY THIS EXISTS
# Login has no policy validation on purpose. The rules may have tightened since an
# account was made, and refusing to let someone in because the password they
# already have is no longer long enough would be absurd. A login only asks whether
# the password is the right one.
class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalise(cls, value: str) -> str:
        return auth.normalise_email(value)


class ForgotPasswordRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def normalise(cls, value: str) -> str:
        return auth.normalise_email(value)


# The second half of the reset. It lives here beside its sibling rather than with the
# other challenge bodies further down, because the two are one flow and reading either
# alone tells you half a story - and because the endpoint that uses it is defined above
# those, so this class has to exist by then.
#
# `newPassword` is camelCase to match PasswordChangeRequest exactly. A model whose
# field names disagree with the one doing the same job elsewhere produces a 422 naming
# a field the form does not have, which is an error no user can act on.
class ResetPasswordRequest(BaseModel):
    challenge: str = Field(
        ..., description="The challenge token from /auth/forgot-password"
    )
    code: str = Field(..., description="The six digits emailed to the account")
    newPassword: str


# WHY THIS EXISTS
# The shape of a user in an API response, defined once. Everything not listed here
# stays on the server - above all passwordHash, which the database layer hands back
# with the record because login needs it.
#
# Building the response field by field rather than deleting the sensitive keys from
# the record is the safer direction: a field added to the database later is absent
# from responses by default, instead of being exposed until somebody remembers to
# add it to a blocklist.
def _public_user(user: dict) -> dict:
    # WHY THE PLAN IS PART OF THE USER RATHER THAN A SEPARATE FETCH
    # Every page that knows who is signed in also wants to know what they may do -
    # the dashboard shows the plan, the scan form obeys its limit, the pricing table
    # marks the current plan instead of offering to sell it again. Attaching it here
    # means /auth/me answers both questions in one round trip, and the frontend has
    # one source of truth rather than a user object and a plan object that can
    # disagree while a request is in flight.
    #
    # billing.plan_for_user() is what makes this safe on an account that predates
    # billing: no planId at all resolves to Free rather than raising.
    #
    # WHY effective_ RATHER THAN plan_for_user, AND IT IS THE WHOLE CANCELLATION
    # DESIGN IN ONE LINE: a cancelled plan keeps its entitlements until the period
    # it was paid for runs out, and nothing runs on a schedule to notice when that
    # happens. So the READ is period-aware. Every page in the app learns who the
    # user is from this function, which means every page is correct about a lapsed
    # subscription without anything having been written when it lapsed. See the
    # section at the bottom of billing.py.
    plan = billing.effective_plan_for_user(user)

    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "plan": billing.public_plan(plan),
        # The subscription sub-document, or None. Whitelisted rather than passed
        # through for the same reason this whole function is a whitelist - and there
        # is nothing sensitive in it, since the card is already reduced to a brand
        # and four digits before it is ever written.
        #
        # effective_subscription() answers None once a cancelled plan has run out,
        # so the pair above and below can never disagree - an account showing Free
        # with a subscription block beside it describing Starter is exactly the
        # confusion that would follow from resolving one of these and not the other.
        "subscription": _public_subscription(
            billing.effective_subscription(user.get("subscription"))
        ),
        # WHY THESE THREE ARE HERE AND NOT ON /2fa/status
        # The settings page opens with "this is your account": the address, how you
        # get in, and when it started. All three are facts about the ACCOUNT, and
        # /2fa/status already reports hasPassword and isGoogleAccount for its own
        # purposes - which is enough to derive the sign-in method, and is the wrong
        # place to read it from. An account screen asking a two-factor endpoint who
        # the user is means every future page needing the same fact does too.
        #
        # createdAt has been written since the first signup (see the record built in
        # the signup handler) and simply was never returned. Nothing had asked.
        "createdAt": _iso_utc(user.get("createdAt")),
        # WHY BOTH BOOLEANS RATHER THAN ONE "method" STRING: the two are not mutually
        # exclusive. An account created with a password that later signs in with
        # Google on the same address has both - see link_google_id in database.py -
        # and it can change its password AND use Google. A single field would have to
        # pick one, and the page would then hide a form that works.
        "hasPassword": bool(user.get("passwordHash")),
        "hasGoogle": bool(user.get("googleId")),
    }


# WHY THIS EXISTS
# The billing detail a signed-in user may see about their own subscription. Split out
# of _public_user because it has to answer None cleanly - a Free account has no
# subscription, and that is a state rather than a missing value.
#
# PYTHON-SPECIFIC: datetimes come back from pymongo as naive UTC. .isoformat() on a
# naive value produces a string with no timezone, which JavaScript's Date parses as
# LOCAL time - so a renewal date can shift by hours purely from being serialised.
# _iso_utc below is the one place that is dealt with.
def _public_subscription(subscription: dict | None) -> dict | None:
    if not subscription:
        return None

    return {
        "planId": subscription.get("planId"),
        "status": subscription.get("status"),
        "startedAt": _iso_utc(subscription.get("startedAt")),
        "currentPeriodEnd": _iso_utc(subscription.get("currentPeriodEnd")),
        # WHY THE UI NEEDS THIS AND NOT JUST THE DATE
        # `currentPeriodEnd` is one date with two completely different meanings: the
        # day the card gets charged again, or the day access stops. A billing screen
        # that cannot tell them apart has to say something vague, and "renews on the
        # 4th" shown to somebody who cancelled is the kind of wrong that generates a
        # chargeback. One boolean, and the sentence is unambiguous.
        #
        # PYTHON-SPECIFIC: bool() rather than passing the raw value through, because
        # a document written before this field existed has None here and JSON null
        # in a boolean field is a third state the frontend would have to handle.
        "cancelAtPeriodEnd": bool(subscription.get("cancelAtPeriodEnd")),
        "cardBrand": subscription.get("cardBrand"),
        "cardLast4": subscription.get("cardLast4"),
        "orderId": subscription.get("orderId"),
    }


# WHY THIS EXISTS
# One spelling of a timestamp in a JSON response. See the note above on why a naive
# datetime is a bug the moment it crosses into the browser: attaching UTC before
# formatting is what makes "expires 4 October" the same date on both sides.
def _iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.isoformat()


# WHY THIS EXISTS
# Issues a session and files it. Both signup and login end this way - a new account
# is signed in immediately, because making somebody type the password they just
# chose is friction with no security benefit.
#
# The token is returned and never stored; only its hash is written. So this is the
# one and only moment the token exists in a form anyone could use, which is why it
# goes straight into the response and nowhere else.
async def _start_session(user_id: str) -> str:
    token = auth.new_session_token()

    await database.create_session(
        {
            "tokenHash": auth.hash_token(token),
            "userId": user_id,
            "createdAt": datetime.now(timezone.utc),
            "expiresAt": auth.session_expiry(),
        }
    )

    return token


# WHY THIS EXISTS
# Account creation. Note the order: validate, hash, insert, then issue a session.
# The password is hashed before it touches the database and is never written
# anywhere in its original form - not in a log line, not in an error message.
@app.post("/auth/signup", status_code=201)
async def signup(request: SignupRequest, http_request: Request) -> dict:
    # Signup is throttled as well as login. Without it this endpoint is a free way
    # to find out which addresses are registered, one 409 at a time - and a way to
    # make the server burn 50ms of Argon2 per request.
    if _too_many_attempts(_client_key(http_request, "signup")):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Wait a few minutes and try again.",
        )

    user_id = auth.new_user_id()

    # PYTHON-SPECIFIC: the record is bound to a name rather than passed inline,
    # because the response below is built from the same dict. Writing the fields out
    # twice is how the stored account and the returned account drift apart.
    record = {
        "id": user_id,
        "name": request.name,
        "email": request.email,
        "passwordHash": auth.hash_password(request.password),
        "createdAt": datetime.now(timezone.utc),
        # WHY THE PLAN IS SET AT CREATION RATHER THAN LEFT TO THE FALLBACK
        # billing.plan_for_user() already answers Free for an account with no
        # planId, so this line changes no behaviour today. It is here because a
        # missing field and a field set to "free" look identical from the outside
        # but behave differently the moment anything queries on it - "find every
        # account on the Business plan" is a query, and so is "count paying
        # customers". An explicit value keeps those answerable.
        "planId": billing.DEFAULT_PLAN_ID,
    }

    created = await database.create_user(record)

    if not created:
        # THIS RESPONSE LEAKS WHETHER AN EMAIL IS REGISTERED, and that is a
        # deliberate trade rather than an oversight. The alternative - always
        # answering "check your email" - only works when there is an email step to
        # hide behind, which needs mail delivery this app does not have yet.
        # Telling someone their address is taken is also the only way they can
        # act on it. Revisit when verification emails land.
        raise HTTPException(
            status_code=409,
            detail="That email is already registered. Sign in instead.",
        )

    token = await _start_session(user_id)

    # _public_user rather than a hand-built dict. The three fields spelled out here
    # were the same three that function returns, right up until the plan was added -
    # at which point a fresh signup was the one response in the app with no plan in
    # it, and the dashboard rendered nothing for a brand new account.
    return {"token": token, "user": _public_user(record)}


# WHY THIS EXISTS
# The other door. Two details here are the whole security of this endpoint:
#   1. One message for both failure modes, so the response cannot be used to work
#      out which addresses have accounts.
#   2. Equal work on both paths, so the response TIME cannot be used for the same
#      purpose - see waste_time_like_a_verification in auth.py.
@app.post("/auth/login")
async def login(request: LoginRequest, http_request: Request) -> dict:
    # Keyed on the address as well as the client, so someone spraying one password
    # across many accounts from one machine is stopped by the per-client key, and a
    # botnet grinding one account is stopped by the per-email key.
    if _too_many_attempts(_client_key(http_request, "login")) or _too_many_attempts(
        f"login-email:{request.email}"
    ):
        raise HTTPException(
            status_code=429,
            detail="Too many sign-in attempts. Wait a few minutes and try again.",
        )

    user = await database.find_user_by_email(request.email)

    if user is None:
        auth.waste_time_like_a_verification()
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")

    # WHY .get() RATHER THAN user["passwordHash"]
    # A Google-only account has no passwordHash field at all - see /auth/google for
    # why it is absent rather than empty. Subscripting would raise a KeyError and
    # return a 500, which both tells an attacker the address exists and reads as a
    # broken server to the person who simply forgot they used the Google button.
    #
    # The empty-string fallback keeps the work equal on both paths: verify_password
    # still runs, still fails, and still takes about as long as a real verification.
    if not auth.verify_password(user.get("passwordHash") or "", request.password):
        # Same status, same wording, comparable timing. Deliberately identical to
        # the branch above - the two branches differing at all is the bug.
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")

    # --- The password was correct. Now: is that enough? ---------------------

    # WHY THE CHALLENGE COMES BEFORE THE ENFORCEMENT CHECK
    # An account with 2FA already on satisfies enforcement by definition, so testing
    # in this order means the enrolment branch below only ever sees accounts that
    # genuinely have no second factor.
    if _has_totp(user):
        challenge_token = await _start_challenge(user["id"], "totp")

        # NOTE WHAT IS NOT IN THIS RESPONSE: no session token, and no user record.
        # The password proved who they are; it did not prove they are still allowed
        # in. Returning even the name here would leak account details to anybody who
        # had guessed a password but could not pass the second factor.
        return _challenge_response(challenge_token, user)

    if _enrolment_required(user):
        # ENFORCEMENT IS ON AND THIS ACCOUNT HAS NO SECOND FACTOR.
        #
        # THE PROBLEM THIS BRANCH HAS TO SOLVE, which is easy to get wrong in both
        # directions: enrolling needs authorisation, but issuing a session would
        # defeat the switch - the user could take it, close the prompt, and carry on
        # using the app with no second factor. And refusing outright would lock every
        # existing account out permanently the moment the switch is flipped, with no
        # route back in.
        #
        # So the answer is a CHALLENGE, exactly like the 2FA path above. It is not a
        # session, so it grants access to nothing; it authorises one thing, which
        # here is enrolment rather than code entry. The endpoints that accept it are
        # /2fa/enrol/start and /2fa/enrol/finish, and nothing else in the app knows
        # it exists.
        challenge_token = await _start_challenge(user["id"], "enrol")

        return {
            "challenge": challenge_token,
            "method": "enrol",
            "expiresInSeconds": ENROLMENT_TTL_MINUTES * 60,
        }

    token = await _start_session(user["id"])

    return {"token": token, "user": _public_user(user)}


# WHY THIS EXISTS
# Lets the frontend answer "am I signed in, and as whom" after a page reload. The
# browser has a token in storage but no idea whether it is still valid, and only
# the server can say.
#
# It also means the name and email shown in the UI are read fresh on each load
# rather than trusted from whatever the browser cached at login.
@app.get("/auth/me")
async def read_current_user(user: dict = Depends(require_session)) -> dict:
    return _public_user(user)


# WHY THIS EXISTS
# A real sign-out, not a cosmetic one. Deleting the browser token alone would leave
# a working credential in every log and proxy cache it ever passed through; this
# removes the server side, after which the token is inert.
#
# 200 even when the token was already invalid. Sign-out is the one operation that
# should never fail - a user trying to leave must always be allowed to.
@app.post("/auth/logout")
async def logout(authorization: str | None = Header(default=None)) -> dict:
    scheme, _, token = (authorization or "").partition(" ")

    if scheme.lower() == "bearer" and token:
        await database.delete_session(auth.hash_token(token))

    return {"signedOut": True}


# ============================================================================
# ACCOUNT SETTINGS
#
# Two endpoints the settings page needs and nothing else provides: changing a
# password, and revoking every session on the account.
#
# BOTH ARE STEP-UP AUTHENTICATED, meaning a valid session is not sufficient - the
# current password is required as well. The reasoning is the same one behind
# /2fa/disable asking for a password and a code, and it is worth stating plainly
# because it is easy to read as pointless friction: a session token is a BEARER
# credential. Whoever holds it is the user, as far as the server can tell. So every
# action reachable with a session alone is an action reachable by whoever steals one,
# and "change the password" is the action that converts a stolen session into
# permanent ownership of the account.
# ============================================================================


# WHY THIS EXISTS
# FASTAPI: the change-password body. Two fields, and the OLD one is not optional.
#
# WHY currentPassword IS REQUIRED EVEN THOUGH THE USER IS SIGNED IN: see the block
# above. The one case where this rule is genuinely unhelpful is a Google-only account
# with no password to supply - and that account cannot use this endpoint at all,
# because there is no password to change. The handler says so rather than inventing a
# way to set a first one.
class PasswordChangeRequest(BaseModel):
    currentPassword: str = Field(..., description="The password being replaced")
    newPassword: str = Field(..., description=f"At least {auth.PASSWORD_MIN_LENGTH} characters")

    # WHY THE POLICY CHECK IS NOT HERE, unlike SignupRequest's model validator: it
    # needs the account's email and name to reject a password containing either, and
    # this model has neither - the account comes from the session, which Pydantic
    # cannot see. So the check happens in the handler, where the user record is in
    # hand. What CAN be checked without the account is checked here.
    @model_validator(mode="after")
    def new_password_must_differ(self) -> "PasswordChangeRequest":
        if self.newPassword == self.currentPassword:
            raise ValueError("That is the password you already have. Choose a different one.")

        return self


# WHY THIS EXISTS
# Changing a password from the settings page.
#
# THE ORDER OF OPERATIONS IS THE SECURITY OF THIS ENDPOINT, and it is deliberate:
#
#   1. Rate limit, because this is a password-guessing oracle otherwise. Somebody
#      with a stolen session could confirm the real password here at full speed.
#   2. Reject a Google-only account before anything else, because verify_password
#      against a missing hash is where a None gets passed to Argon2.
#   3. Verify the CURRENT password. Nothing is written before this passes.
#   4. Check the new password against the policy, with the account's own email and
#      name, so "MyName2024Secure" is refused the same way it is at signup.
#   5. Hash, then write.
#   6. Revoke the other sessions - AFTER the write, so a failure in step 5 cannot
#      sign the user out of everything and leave the old password in place.
#
# WHY OTHER SESSIONS GO AND THIS ONE STAYS: changing a password almost always means
# suspecting it is known. Leaving the other sessions alive makes the change cosmetic
# against anyone already holding one - they keep their access and never need the
# password again. Keeping the CURRENT session is a convenience with no cost: this
# request already proved knowledge of the old password, so it is not the session
# under suspicion, and revoking it too would dump the user on /login one second after
# succeeding.
class SetPasswordRequest(BaseModel):
    password: str = Field(..., description=f"At least {auth.PASSWORD_MIN_LENGTH} characters")


@app.post("/auth/set-password")
async def set_password(
    request: SetPasswordRequest,
    http_request: Request,
    user: dict = Depends(require_session),
) -> dict:
    if _too_many_attempts(_client_key(http_request, "set-password")):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Wait a few minutes and try again.",
        )

    if user.get("passwordHash"):
        raise HTTPException(
            status_code=400,
            detail="This account already has a password. Use change password instead.",
        )

    problem = auth.password_problem(
        request.password, email=user["email"], name=user["name"]
    )

    if problem:
        raise HTTPException(status_code=400, detail=problem)

    await database.set_password_hash(user["id"], auth.hash_password(request.password))

    updated_user = await database.find_user_by_id(user["id"])
    if not updated_user:
        raise HTTPException(status_code=500, detail="Failed to retrieve updated user.")

    return {"set": True, "user": _public_user(updated_user)}


@app.post("/auth/change-password")
async def change_password(
    request: PasswordChangeRequest,
    http_request: Request,
    authorization: str | None = Header(default=None),
    user: dict = Depends(require_session),
) -> dict:
    if _too_many_attempts(_client_key(http_request, "change-password")):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Wait a few minutes and try again.",
        )

    stored_hash = user.get("passwordHash")

    if not stored_hash:
        # A Google-only account. 400 rather than 401: nothing is wrong with the
        # caller's credentials, the operation simply does not apply to this account.
        raise HTTPException(
            status_code=400,
            detail=(
                "This account signs in with Google and has no SecuScan password to "
                "change. Manage it in your Google account instead."
            ),
        )

    if not auth.verify_password(stored_hash, request.currentPassword):
        raise HTTPException(status_code=401, detail="Your current password is incorrect.")

    # The same function signup calls, with the same arguments. One source of truth for
    # the policy - see password_problem in auth.py - so a password acceptable here is
    # acceptable there and the two cannot drift.
    problem = auth.password_problem(
        request.newPassword, email=user["email"], name=user["name"]
    )

    if problem:
        raise HTTPException(status_code=400, detail=problem)

    await database.set_password_hash(user["id"], auth.hash_password(request.newPassword))

    # PYTHON-SPECIFIC: the caller's own token hash, recovered the same way
    # require_session recovers it. The dependency returns the USER rather than the
    # session, so the hash is not available from it - hence reading the header again
    # here. Passing None instead would revoke this session too and sign the user out.
    _, _, token = (authorization or "").partition(" ")
    kept_hash = auth.hash_token(token) if token else None

    revoked = await database.delete_sessions_for_user(user["id"], except_hash=kept_hash)

    return {"changed": True, "otherSessionsSignedOut": revoked}


# WHY THIS EXISTS
# Request model for account deletion.
class DeleteAccountRequest(BaseModel):
    password: str | None = Field(default=None, description="Current password for password accounts")
    confirm: bool = Field(default=False, description="Must be true to permanently delete account")


# WHY THIS EXISTS
# GDPR/CCPA data export. Returns a machine-readable JSON archive containing the
# user's profile, purchase orders, and all audit findings.
@app.get("/auth/export")
async def export_account(user: dict = Depends(require_session)) -> Response:
    data = await database.export_user_account_data(user["id"])
    if not data:
        raise HTTPException(status_code=404, detail="User account not found.")

    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="secuscan-account-data.json"',
        },
    )


# WHY THIS EXISTS
# Complete account deletion (Right to be Forgotten).
#
# STEP-UP AUTHENTICATION IS ENFORCED:
#   - Accounts with a password must provide the correct current password.
#   - OAuth (Google) accounts must pass confirm=True.
#
# Deletes the user record, all active sessions, all historical scans, and any
# test credentials from the database. Financial orders are kept but anonymized.
@app.delete("/auth/account")
async def delete_account(
    request: DeleteAccountRequest,
    user: dict = Depends(require_session),
) -> dict:
    if not request.confirm:
        raise HTTPException(
            status_code=400,
            detail="Confirmation is required to permanently delete your account.",
        )

    stored_hash = user.get("passwordHash")
    if stored_hash:
        if not request.password:
            raise HTTPException(
                status_code=400,
                detail="Your current password is required to delete this account.",
            )
        if not auth.verify_password(stored_hash, request.password):
            raise HTTPException(
                status_code=401,
                detail="Your password was incorrect.",
            )

    result = await database.delete_user_account_data(user["id"])

    return {
        "deleted": True,
        "message": "Your account and all associated data have been permanently deleted.",
        "details": result,
    }


# WHY THIS EXISTS
# The "get help" box in Settings. A contact form that posts nowhere is worse than an
# address that works, so this is the endpoint that makes the form honest.
#
# WHY IT REQUIRES A SESSION, which is the decision that shapes everything else here:
# the sender's address is taken from the authenticated account and NOT from the
# request body. An anonymous form with a "your email" field is a way to make mail
# arrive at the support mailbox appearing to come from anybody - and a way to make
# this server send mail on a stranger's behalf, which is the same shape of abuse the
# Tier 2 password-reset check is gated against. Requiring a session costs a logged-out
# user nothing: the mailto: links on the public pages already reach the same mailbox.
#
# THE ORDER MATTERS, and it is the same order as change_password above:
#
#   1. Rate limit first. Even with a session this sends mail, and a send loop is a
#      way to flood the support mailbox from one account.
#   2. Refuse honestly if email is not configured. A 503 rather than accepting the
#      message and dropping it - the UI hides the form when emailAvailable is false,
#      so reaching this is a direct call or a config that changed mid-session.
#   3. Send, and report whether the provider took it. A False from the mailer becomes
#      a 502: the message did NOT go, and telling the user it did would leave them
#      waiting for an answer to something nobody received.
class ContactRequest(BaseModel):
    subject: str = Field(..., description="What the message is about")
    message: str = Field(..., description="The message body")

    # The address and name are deliberately NOT fields on this model. They come from
    # the session in the handler. See the note above - this is the whole security
    # property of the endpoint, and a field added here would quietly remove it.

    @field_validator("subject")
    @classmethod
    def subject_must_not_be_blank(cls, value: str) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError("A subject is required.")

        # An upper bound on anything a user can type that the server will send. Long
        # enough for a real subject line, short enough that it cannot be used to push
        # a wall of text through the header of a mail message.
        if len(cleaned) > 200:
            raise ValueError("Subject must be 200 characters or fewer.")

        # PYTHON-SPECIFIC: newlines are stripped from the SUBJECT specifically, not
        # merely trimmed. A newline in a mail header is header injection - it ends the
        # Subject: line and lets whatever follows be read as another header, which is
        # how a form like this becomes a way to add recipients. The provider's API
        # takes the subject as JSON rather than a raw header, so this is defence in
        # depth rather than the only thing standing between here and that - but it
        # costs one line and removes the question.
        return " ".join(cleaned.split())

    @field_validator("message")
    @classmethod
    def message_must_not_be_blank(cls, value: str) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError("A message is required.")

        if len(cleaned) > 5000:
            raise ValueError("Message must be 5000 characters or fewer.")

        return cleaned


@app.post("/contact")
async def send_contact_message(
    request: ContactRequest,
    http_request: Request,
    user: dict = Depends(require_session),
) -> dict:
    if _too_many_attempts(_client_key(http_request, "contact")):
        raise HTTPException(
            status_code=429,
            detail="Too many messages. Wait a few minutes and try again.",
        )

    if not mailer.email_available():
        raise HTTPException(
            status_code=503,
            detail=(
                "Email delivery is not configured on this server, so the message "
                f"cannot be sent. Email {config.SUPPORT_EMAIL} directly instead."
            ),
        )

    sent = await mailer.send_contact_message(
        to=config.SUPPORT_EMAIL,
        subject=request.subject,
        message=request.message,
        # From the SESSION. Not from the body - see the note on the model.
        from_email=user["email"],
        from_name=user.get("name", ""),
        user_id=user["id"],
    )

    if not sent:
        # The provider refused or was unreachable. The mailer has already printed the
        # reason for the operator; the user gets the address so the failure does not
        # leave them with no way through.
        raise HTTPException(
            status_code=502,
            detail=(
                "The message could not be sent just now. Email "
                f"{config.SUPPORT_EMAIL} directly, or try again in a few minutes."
            ),
        )

    return {"sent": True}


# WHY THIS EXISTS
# "Sign out everywhere" - every session on the account, including the one that asked.
#
# WHY IT ENDS THE CALLER'S SESSION TOO, which is a real decision and not an oversight:
# the reason anyone presses this is a suspicion that someone else is in the account.
# Under that suspicion there is no basis for treating the browser being used right now
# as the trustworthy one - it may be the compromised device, and the person pressing
# the button cannot know. "All except mine" also has to explain an exception, and a
# security control with an exception is one people misread. Signing out completely is
# the version that does what its label says.
#
# THE PASSWORD IS REQUIRED for the same reason it is on the endpoint above: with a
# stolen session alone, an attacker could otherwise sign the real owner out of every
# device and keep working. That is a denial of service against the account's owner
# performed with the account's own security feature.
#
# A Google-only account is refused rather than accommodated, and the message says
# where to go. Google's own "sign out of all sessions" is the equivalent control
# there, and inventing a password-free version here would mean a stolen session could
# use it.
class SignOutEverywhereRequest(BaseModel):
    password: str = Field(..., description="The account password, to prove it is you")


@app.post("/auth/sessions/revoke-all")
async def sign_out_everywhere(
    request: SignOutEverywhereRequest,
    http_request: Request,
    user: dict = Depends(require_session),
) -> dict:
    if _too_many_attempts(_client_key(http_request, "revoke-all")):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Wait a few minutes and try again.",
        )

    stored_hash = user.get("passwordHash")

    if not stored_hash:
        raise HTTPException(
            status_code=400,
            detail=(
                "This account signs in with Google. Sign out of all devices from your "
                "Google account instead."
            ),
        )

    if not auth.verify_password(stored_hash, request.password):
        raise HTTPException(status_code=401, detail="Your password is incorrect.")

    # except_hash omitted, so the caller's session goes with the rest. That is the
    # whole difference between this endpoint and the tail of change_password above.
    revoked = await database.delete_sessions_for_user(user["id"])

    # The count includes this session, so the UI can say "signed out of 3 devices"
    # truthfully. The response reaches the browser before the token stops working -
    # the deletion has already happened, so the NEXT request with this token gets a
    # 401, which is exactly what the frontend uses as its cue to clear local state.
    return {"signedOut": True, "sessionsEnded": revoked}


# WHY THIS EXISTS
# The start of a password reset: it emails a single-use code and hands back the
# challenge that code will be spent against.
#
# WHY A CODE TYPED INTO A PAGE RATHER THAN A LINK IN THE EMAIL. A reset link is a
# credential in a URL, and URLs leak by routes their sender does not control - browser
# history, Referer headers, the link scanners mail providers run on delivery (they do
# follow links), and the chat window where somebody pastes one asking "is this real?".
# A six-digit code typed into the tab the user already has open travels none of those,
# and it reuses the code machinery the second factor already has.
#
# THE ENUMERATION RULE, WHICH IS MOST OF THE DESIGN HERE. The response must not differ
# between a registered address and an unknown one - not in its fields, not in its
# status, and NOT AT THE NEXT STEP EITHER. That last clause is the one usually got
# wrong: issuing a challenge only for real accounts does not remove the leak, it moves
# it to the endpoint below.
#
# So an unknown address gets a REAL challenge with userId=None and a REAL stored code
# that was generated and thrown away unsent. Every downstream behaviour - the
# wrong-code message, the attempt counter, the cutoff - is then identical for the two
# cases because it is literally the same code path, rather than a second path written
# to look like the first. See _resolve_reset_challenge and /auth/reset-password.
@app.post("/auth/forgot-password")
async def forgot_password(
    request: ForgotPasswordRequest, http_request: Request
) -> dict:
    # Keyed on the address as well as the client, the pairing /auth/login uses. Here
    # the per-address key is the one that earns its keep: this endpoint SENDS MAIL, so
    # without it a botnet can use us to flood one person's inbox from a thousand
    # machines, and get our sending domain reported for it.
    if _too_many_attempts(_client_key(http_request, "forgot")) or _too_many_attempts(
        f"forgot-email:{request.email}"
    ):
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Wait a few minutes and try again.",
        )

    user = await database.find_user_by_email(request.email)

    # A challenge either way. userId=None is a state only _resolve_reset_challenge
    # accepts - every other challenge path treats it as dead and refuses it.
    challenge_token = await _start_challenge(user["id"] if user else None, "reset")
    token_hash = auth.hash_token(challenge_token)

    if user is not None and mailer.email_available():
        code = auth.new_email_code()

        # Hashed before storage, like every other credential here. Nothing keeps the
        # plaintext once the message is handed to the provider.
        await database.save_email_code(
            token_hash, auth.hash_email_code(code), auth.email_code_expiry()
        )

        # THE ADDRESS COMES FROM THE ACCOUNT, NEVER FROM THE REQUEST BODY - the rule
        # /2fa/email-code states at length. Here the two strings happen to be equal,
        # since the account was found BY that address; reading it off the record
        # anyway is what keeps this right if the lookup ever gains a second way to
        # match, an alias or a changed address among them.
        await mailer.send_password_reset_code(user["email"], code, user.get("name", ""))
    else:
        # THE DECOY - a real row, not a special case. A code is generated, hashed,
        # stored and discarded unsent, so find_email_code succeeds at the next step and
        # the comparison fails the ordinary way, through the ordinary lines.
        #
        # This branch also catches a registered address when mail is NOT configured,
        # and that is correct rather than accidental: answering 503 there would
        # announce that the address exists, which is the one thing this endpoint is
        # built not to do. The operator sees the misconfiguration in the startup
        # warnings; the caller sees exactly what everybody else sees.
        await database.save_email_code(
            token_hash,
            auth.hash_email_code(auth.new_email_code()),
            auth.email_code_expiry(),
        )

    return {
        "requested": True,
        # The ticket. It proves nothing on its own - it is the CODE that has to be
        # right, and the code only ever arrives by email.
        "challenge": challenge_token,
        # Masked, and masked from what the caller TYPED rather than from the account,
        # so one line serves both branches. For a real account the two are the same
        # string; for an unknown address there is no account to read one from.
        "sentTo": _mask_email(request.email),
        "expiresInMinutes": auth.EMAIL_CODE_TTL_MINUTES,
        # The deliberately vague sentence. Its "if" is the load-bearing word: it is
        # what declines to confirm whether the address is registered. Only the noun
        # changed when this endpoint became real - it sends a code, not a link.
        "message": (
            "If an account exists for that address, a reset code has been sent to it."
        ),
    }


# WHY THIS EXISTS
# Spends the emailed code and sets the new password.
#
# IT ISSUES NO SESSION, and the rest of the flow hangs off that. An emailed code
# proves access to an inbox and nothing more - the section header in auth.py makes the
# argument in full - so letting one mint a session would make the inbox a complete
# substitute for the password AND the second factor at once. This returns
# {reset: true} and stops. The user then signs in normally, which means an account
# with 2FA meets its authenticator on the ordinary login path, with no second-factor
# branch here to write or get wrong.
#
# WHAT IT DOES FOR AN ACCOUNT THAT HAS ONLY EVER USED GOOGLE: it sets a password,
# widening the account from one way in to two. That is a decision, not an oversight,
# and both sides of it are real. Against: an emailed code has attached a new
# credential to an account that did not have one. For: a Google-linked account's
# address IS its Google address, so whoever holds that inbox is already most of the
# way into the Google account itself - and refusing instead leaves a user who has lost
# their Google access with no route back at all, which was judged the worse failure.
@app.post("/auth/reset-password")
async def reset_password(
    request: ResetPasswordRequest, http_request: Request
) -> dict:
    if _too_many_attempts(_client_key(http_request, "reset")):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Wait a few minutes and try again.",
        )

    # May be (None, hash) - an unknown address's decoy. NOTHING BELOW BRANCHES ON THAT
    # until the code has already been checked and failed, and that ordering is the
    # whole reason the two cases cannot be told apart.
    user, token_hash = await _resolve_reset_challenge(request.challenge)

    record = await database.find_email_code(token_hash)

    if record is None:
        raise HTTPException(
            status_code=401, detail="That code has expired. Start again."
        )

    # PYTHON-SPECIFIC: secrets.compare_digest for a constant-time comparison, the same
    # as /2fa/verify-email. Both sides are SHA-256 hex of equal length, so == would
    # leak only how many leading characters matched - a small leak closed by one call.
    supplied = auth.hash_email_code(request.code)
    stored = record.get("codeHash", "")

    if not secrets.compare_digest(supplied, stored):
        attempts = await database.count_email_code_attempt(token_hash)

        if attempts >= auth.EMAIL_CODE_MAX_ATTEMPTS:
            # BOTH GO HERE, unlike /2fa/verify-email where the challenge deliberately
            # survives an exhausted code. There the user still has an authenticator
            # app and a recovery code to fall back on, so the login is worth keeping
            # open. Here the emailed code is the only factor there is, and a challenge
            # outliving it could do nothing at all except sit there until its TTL.
            await database.delete_email_code(token_hash)
            await database.delete_challenge(token_hash)

            raise HTTPException(
                status_code=429,
                detail=(
                    "Too many incorrect codes. That reset has been cancelled - "
                    "start again."
                ),
            )

        raise HTTPException(status_code=401, detail="That code is not correct.")

    # THE POLICY CHECK RUNS BEFORE THE BRANCH BELOW, on both paths, so that a rejected
    # password is rejected identically whether or not there is an account behind the
    # challenge. A decoy has no email or name to compare against, which costs only the
    # two similarity rules; length, composition and the common-password list do the
    # overwhelming majority of the rejecting and need no account at all.
    #
    # The same function signup and /auth/change-password call, with the same arguments.
    # One source of truth for the policy - see password_problem in auth.py - so a
    # password acceptable here is acceptable there and the two cannot drift apart.
    account = user or {}

    problem = auth.password_problem(
        request.newPassword,
        email=account.get("email", ""),
        name=account.get("name", ""),
    )

    if problem:
        raise HTTPException(status_code=400, detail=problem)

    if user is not None:
        await database.set_password_hash(
            user["id"], auth.hash_password(request.newPassword)
        )

        # EVERY session, with no except_hash - the opposite of /auth/change-password,
        # for the opposite reason. That request proves the OLD password, so the caller
        # is demonstrably not the party under suspicion and keeping their session is a
        # free convenience. This one proves only inbox access, and the reason people
        # reset a password is that they believe somebody else may be inside the
        # account. Any session still open could be that somebody's.
        await database.delete_sessions_for_user(user["id"])

    # Single use, on every path that got this far - the decoy included, so its rows do
    # not linger any longer than a real one's would.
    await database.delete_email_code(token_hash)
    await database.delete_challenge(token_hash)

    return {"reset": True}


# ============================================================================
# TWO-FACTOR AUTHENTICATION
#
# WHY THE LOGIN FLOW CHANGED SHAPE
# Before this, /auth/login answered a correct password with a session token and the
# user was in. With a second factor there are three possible answers, and the frontend
# has to be able to tell them apart:
#
#   { token, user }                    - signed in. No 2FA on this account.
#   { challenge, method: "totp" }      - password accepted, second factor required.
#   { challenge, method: "enrol" }     - password accepted, but this server requires
#                                        2FA and this account has none yet.
#
# A CHALLENGE IS NOT A SESSION, and that distinction is the security of this whole
# design. A challenge authorises exactly one narrow thing and expires in minutes.
# Anything holding one can read no scans, because require_session accepts session
# tokens only and knows nothing about challenges. The tempting alternative - a session
# with a "needs2fa": true flag on it - moves the check into every endpoint in the app,
# and the first endpoint that forgets to look at the flag is a complete 2FA bypass.
#
# THE STATE MACHINE, end to end:
#
#   POST /auth/login          password correct, no 2FA           -> session
#   POST /auth/login          password correct, 2FA enrolled      -> totp challenge
#   POST /auth/login          password correct, enrolment forced  -> enrol challenge
#
#   POST /2fa/verify          totp challenge + 6-digit code       -> session
#   POST /2fa/recover         totp challenge + recovery code      -> session
#   POST /2fa/email-code      totp challenge                      -> sends an email
#   POST /2fa/verify-email    totp challenge + emailed code       -> session
#
#   POST /2fa/enrol/start     enrol challenge                     -> secret + QR
#   POST /2fa/enrol/finish    enrol challenge + code              -> session + codes
#
# And voluntary enrolment, which needs an ordinary session because only a signed-in
# user can add a factor to their own account:
#
#   POST /2fa/setup           -> secret, QR code. Nothing enabled yet.
#   POST /2fa/confirm         -> a code proves the phone has it. Enabled + codes.
#   POST /2fa/disable         -> password + code. Off.
#   POST /2fa/recovery-codes  -> a fresh set, invalidating the old.
# ============================================================================

# How long a half-finished login stays open. Five minutes is enough to find a phone,
# unlock it and read six digits; it is not enough to leave a browser tab open
# overnight in a co-working space and finish the login in the morning.
CHALLENGE_TTL_MINUTES = 5

# Enrolment gets longer, because the user's next steps may include installing an
# authenticator app for the first time. Five minutes would time out somebody who went
# to find their phone and then had to visit an app store; fifteen will not. It is
# still a challenge rather than a session, so the extra time grants no access.
ENROLMENT_TTL_MINUTES = 15

# A password reset gets the same fifteen, for a different reason that matters more.
# The code it carries is valid for ten (auth.EMAIL_CODE_TTL_MINUTES), and a challenge
# shorter than its own code would expire while a perfectly good code was still sitting
# in the user's inbox - which reads to them as the reset being broken. The ticket has
# to outlive the thing it is a ticket for, so this stays comfortably above that ten,
# and any future edit to either number has to keep it that way.
RESET_TTL_MINUTES = 15

# The TTL each method gets, as a table rather than a chain of conditional expressions.
# Anything not named here falls back to CHALLENGE_TTL_MINUTES, so a method added later
# is short-lived until somebody deliberately decides otherwise - the safe direction for
# a default to point.
_CHALLENGE_TTL_MINUTES = {
    "enrol": ENROLMENT_TTL_MINUTES,
    "reset": RESET_TTL_MINUTES,
}

# How many wrong second-factor codes a single challenge tolerates before it is
# destroyed and the user starts again from the password.
#
# WHY THIS LIMIT IS THE REAL PROTECTION FOR TOTP: a 6-digit code is one in a million,
# but with drift tolerance three codes are live at once and each stays valid for about
# 90 seconds. Unlimited attempts against that is genuinely brute-forceable. Five per
# challenge, on top of the per-client limiter, makes it not.
CHALLENGE_MAX_ATTEMPTS = 5


# WHY THIS EXISTS
# Answers "does this account have 2FA switched on". A function rather than the
# expression inline, because the answer is derived from the presence of two separate
# fields and getting that test subtly wrong in one place out of six is how an account
# ends up holding a secret nothing ever checks.
#
# totpConfirmedAt is what makes it true, not totpSecret alone. A pending secret from an
# abandoned /2fa/setup is not 2FA and must never gate a login - see the comment on
# set_pending_totp_secret in database.py for the lockout that would cause.
def _has_totp(user: dict) -> bool:
    return bool(user.get("totpSecret")) and bool(user.get("totpConfirmedAt"))


# WHY THIS EXISTS
# The enforcement switch, applied. True when this account must enrol before it is
# allowed a session.
#
# WHO IS EXEMPT, AND WHY:
#   - Everyone, when the switch is off. That is the default, and it is why turning it
#     on later needs no migration.
#   - Google accounts, always. Google already applied whatever second factor the user
#     has on their Google account, and we can neither see nor improve on it. Demanding
#     our own on top would ask a user to prove themselves twice for one sign-in, and
#     would mean a Google user has to store a TOTP secret with us - which is exactly
#     what delegating to Google avoided.
#
# PYTHON-SPECIFIC: config.require_2fa() is a function call rather than a constant read,
# so flipping the switch takes effect on the next request instead of the next restart.
def _enrolment_required(user: dict) -> bool:
    if not config.require_2fa():
        return False

    if user.get("googleId"):
        return False

    return not _has_totp(user)


# WHY THIS EXISTS
# Opens a challenge and returns the token. The mirror image of _start_session, and
# deliberately built the same way: a random token, only its hash stored, the plaintext
# returned once and written nowhere.
#
# `method` records which factor the login is expecting. It is STORED rather than
# recomputed on each request, and _resolve_challenge checks it - so an enrolment
# challenge cannot be presented at /2fa/verify, and a login challenge cannot be used to
# re-enrol a new authenticator onto an account that already has one.
#
# WHY user_id IS OPTIONAL, which looks alarming and is used by exactly one caller:
# /auth/forgot-password issues a challenge for an address that has no account, so that
# its response cannot be used to discover which addresses do. That challenge has no
# user to point at. Only _resolve_reset_challenge will accept one - every other path
# runs through _resolve_challenge, which treats a missing user as a dead challenge and
# refuses it.
async def _start_challenge(user_id: str | None, method: str) -> str:
    token = auth.new_session_token()

    minutes = _CHALLENGE_TTL_MINUTES.get(method, CHALLENGE_TTL_MINUTES)

    await database.create_challenge(
        {
            "tokenHash": auth.hash_token(token),
            "userId": user_id,
            "method": method,
            "attempts": 0,
            "createdAt": datetime.now(timezone.utc),
            "expiresAt": datetime.now(timezone.utc) + timedelta(minutes=minutes),
        }
    )

    return token


# WHY THIS EXISTS
# Turns a challenge token from a request body into the user it belongs to, or ends the
# request. The shared front half of all six second-factor endpoints, so "is this
# challenge real, unexpired, for the right purpose, and whose is it" is answered by one
# piece of code rather than six near-copies.
#
# Returns the token hash alongside the user because every caller needs both - the user
# to check a code against, and the hash to count attempts and delete the challenge.
#
# PYTHON-SPECIFIC: a tuple return, unpacked at the call site as
# `user, token_hash = await _resolve_challenge(...)`. A small class would be more
# self-documenting and would be worth it at four fields; at two it is ceremony.
async def _resolve_challenge(challenge_token: str, expect: str) -> tuple[dict, str]:
    token_hash = auth.hash_token(challenge_token or "")

    challenge = await database.find_challenge(token_hash)

    if challenge is None:
        # Covers absent, expired and already-spent alike. One message, because the
        # differences are of no use to a legitimate user and of real use to somebody
        # probing with stolen or guessed challenge tokens.
        raise HTTPException(
            status_code=401,
            detail="That sign-in attempt has expired. Start again.",
        )

    if challenge.get("method") != expect:
        # Right token, wrong door. Not a case a real client can reach, which is
        # precisely why it is checked: it is the shape an attacker would try, taking a
        # challenge issued for one purpose and spending it on another.
        raise HTTPException(
            status_code=401,
            detail="That sign-in attempt has expired. Start again.",
        )

    user = await database.find_user_by_id(challenge["userId"])

    if user is None:
        # A live challenge pointing at a deleted account. Cleaned up rather than left
        # to the TTL sweep, since it can never succeed.
        await database.delete_challenge(token_hash)
        raise HTTPException(
            status_code=401,
            detail="That sign-in attempt has expired. Start again.",
        )

    return user, token_hash


# WHY THIS IS NOT JUST _resolve_challenge WITH expect="reset"
# That function guarantees a user, and rightly so: for every second-factor endpoint a
# challenge with no live account behind it is dead, so it deletes the challenge and
# refuses.
#
# A password reset needs the opposite guarantee. /auth/forgot-password issues a
# challenge for an UNKNOWN address too - userId=None - because handing one back only
# for real accounts would tell the caller which addresses are registered. Sending that
# challenge through _resolve_challenge would produce "that attempt has expired" where a
# real account produces "that code is not correct", and would destroy it on the first
# try where a real one survives several. Two observable differences, which is precisely
# the enumeration leak the decoy exists to close, moved one step further along.
#
# So this returns None for the user instead of raising, and the caller checks the CODE
# before it looks at whether there is an account. Everything an attacker can observe
# happens above that line.
async def _resolve_reset_challenge(challenge_token: str) -> tuple[dict | None, str]:
    token_hash = auth.hash_token(challenge_token or "")

    challenge = await database.find_challenge(token_hash)

    if challenge is None or challenge.get("method") != "reset":
        # Absent, expired, already spent, or issued for a different purpose - one
        # message for all four, the same reasoning as _resolve_challenge. The method
        # half is what stops a login challenge being spent here to set a new password
        # without ever knowing the old one.
        raise HTTPException(
            status_code=401,
            detail="That reset request has expired. Start again.",
        )

    user_id = challenge.get("userId")

    # PYTHON-SPECIFIC: guarded rather than calling find_user_by_id(None) and letting it
    # return None on its own. It would - nothing has a null _id - but only by accident,
    # and a correctness that depends on an accident is invisible to the next reader.
    user = await database.find_user_by_id(user_id) if user_id else None

    return user, token_hash


# WHY THIS EXISTS
# Counts a wrong code and destroys the challenge once the budget is gone. Called from
# every failure path, so the limit cannot be enforced on five endpoints and forgotten
# on the sixth.
#
# IT RAISES RATHER THAN RETURNING, and that is the design. There is nothing a caller
# would do with a boolean here except raise, and a helper returning a value somebody
# can ignore is a rate limit somebody can ignore.
#
# PYTHON-SPECIFIC: the `-> None` annotation is honest - the function never returns
# normally. Every call site therefore sits at the end of its branch, with nothing
# after it that could be mistaken for the success path.
async def _fail_challenge_attempt(token_hash: str) -> None:
    attempts = await database.count_challenge_attempt(token_hash)

    if attempts >= CHALLENGE_MAX_ATTEMPTS:
        await database.delete_challenge(token_hash)
        # The emailed code for this login goes too. Leaving it live would mean a code
        # in an inbox outlived the login it belonged to.
        await database.delete_email_code(token_hash)

        raise HTTPException(
            status_code=429,
            detail=(
                "Too many incorrect codes. That sign-in attempt has been cancelled - "
                "sign in again."
            ),
        )

    raise HTTPException(status_code=401, detail="That code is not correct.")


# WHY THIS EXISTS
# The response the frontend gets when a password was right but a second factor is
# needed. Built in one function because three endpoints have to agree about its shape,
# and because it must never accidentally grow a session token.
#
# `emailAvailable` tells the UI whether to offer "email me a code" at all. A button
# leading to "email is not configured" is worse than no button.
def _challenge_response(challenge_token: str, user: dict) -> dict:
    return {
        "challenge": challenge_token,
        "method": "totp",
        # How many recovery codes remain. A count, never the codes - the count is
        # useful to the user, and the codes are stored hashed so they could not be
        # returned even if it were a good idea.
        "recoveryCodesLeft": len(user.get("recoveryCodeHashes") or []),
        "emailAvailable": mailer.email_available(),
        "expiresInSeconds": CHALLENGE_TTL_MINUTES * 60,
    }


# WHY THIS EXISTS
# Turns ada.lovelace@example.com into a************e@example.com, for the one response
# that has to say where a code went without saying it to somebody who should not know.
#
# The rule is deliberately crude - first and last character of the local part - because
# a cleverer scheme that preserves the shape leaks more, and the only job here is
# "recognisable to the person who already owns it".
def _mask_email(email: str) -> str:
    local, _, domain = email.partition("@")

    if not domain:
        return "your email address"

    if len(local) <= 2:
        # Too short to mask meaningfully. Replacing it entirely beats returning it.
        return f"{'*' * len(local)}@{domain}"

    return f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}@{domain}"


# --- Request bodies --------------------------------------------------------


class ChallengeCodeRequest(BaseModel):
    challenge: str = Field(..., description="The challenge token from /auth/login")
    code: str = Field(..., description="Six digits from the authenticator app")


class ChallengeOnlyRequest(BaseModel):
    challenge: str = Field(..., description="The challenge token from /auth/login")


class RecoveryCodeRequest(BaseModel):
    challenge: str
    code: str = Field(..., description="One of the recovery codes issued at enrolment")


class TotpConfirmRequest(BaseModel):
    code: str = Field(..., description="Six digits, to prove the secret was stored")


# WHY THIS ASKS FOR A PASSWORD AS WELL AS A CODE
# Disabling 2FA is a security DOWNGRADE, and it is the single action an attacker
# holding a stolen session token would most want - it converts a temporary hold on one
# browser into permanent access. Requiring the password as well means a stolen session
# alone cannot weaken the account.
#
# This pattern is called step-up authentication, and it is the same reasoning behind a
# bank asking for a PIN to change an address on a session you are already signed into.
class TotpDisableRequest(BaseModel):
    password: str = Field(
        ..., description="The account password, to re-confirm identity"
    )
    code: str = Field(..., description="A current code, or a recovery code")


class GoogleSignInRequest(BaseModel):
    # The name Google's own JavaScript uses for this field, kept verbatim so the
    # frontend can pass their callback payload straight through without renaming.
    credential: str = Field(
        ..., description="The ID token from Google Identity Services"
    )


# --- The two halves of enrolment, shared by both routes into it ------------


# WHY THIS EXISTS
# Generates a secret and everything needed to display it, and enables nothing.
#
# It is a plain function rather than an endpoint because there are TWO ways to reach
# enrolment - a signed-in user choosing to add 2FA, and a forced enrolment during
# login - and they differ only in how the user is authorised. Sharing the body means
# the two routes cannot drift into treating the pending secret differently.
async def _issue_totp_setup(user: dict) -> dict:
    secret = auth.new_totp_secret()

    await database.set_pending_totp_secret(user["id"], secret)

    provisioning_uri = auth.totp_provisioning_uri(
        secret, email=user["email"], issuer=config.APP_NAME
    )

    return {
        # Shown as text beneath the QR code, for a phone whose camera will not focus
        # or a desktop authenticator with no camera at all.
        "secret": secret,
        # The QR code as an inline SVG data URI - see totp_qr_data_uri in auth.py for
        # why this is not a separate image endpoint.
        "qr": auth.totp_qr_data_uri(provisioning_uri),
        # The raw otpauth:// URI too, so a password manager can be handed the link
        # rather than photographing the screen displaying it.
        "uri": provisioning_uri,
        "digits": auth.TOTP_DIGITS,
        "period": auth.TOTP_PERIOD_SECONDS,
    }


# WHY THIS EXISTS
# The second half: a correct code proves the phone really holds the secret, so it is
# safe to start requiring it. Returns the recovery codes, which exist for exactly this
# moment and cannot be produced again.
#
# WHY ENROLMENT IS TWO REQUESTS AND NOT ONE. Switching 2FA on at the moment the secret
# is generated would enable it for a user who closed the tab without scanning - and
# with enforcement on, that locks them out of their own account using a secret nobody
# ever stored. The pending secret waits until a code proves otherwise.
async def _complete_totp_setup(user: dict, code: str) -> list[str]:
    pending = user.get("totpPendingSecret")

    if not pending:
        raise HTTPException(
            status_code=400,
            detail="Start setup first - there is no pending authenticator to confirm.",
        )

    step = auth.matched_totp_step(pending, code)

    if step is None:
        raise HTTPException(
            status_code=401,
            detail=(
                "That code is not correct. Check your phone's clock is set "
                "automatically, then try the current code."
            ),
        )

    codes, hashes = auth.new_recovery_codes()

    # ONE atomic write: promote the secret, store the code hashes, record the step that
    # confirmed it, clear the pending field. See confirm_totp in database.py for why
    # this must not be four separate updates.
    await database.confirm_totp(user["id"], pending, hashes, step)

    return codes


# --- Voluntary enrolment, from an ordinary session -------------------------


# WHY THIS EXISTS
# Step one for a user who already has a session and chooses to add 2FA.
#
# CALLING IT TWICE IS SAFE AND IS EXPECTED - a reload, or a second attempt with a
# different app. Each call replaces the pending secret, so the QR code on screen is
# always the one that will be accepted.
#
# What it must never do is replace a CONFIRMED secret, which is what the guard below
# prevents: without it, a stolen session could silently re-enrol 2FA onto an attacker's
# phone, and the real owner's authenticator would simply stop working.
@app.post("/2fa/setup")
async def start_totp_setup(user: dict = Depends(require_session)) -> dict:
    if not user.get("passwordHash"):
        raise HTTPException(
            status_code=400,
            detail=(
                "This account has no SecuScan password. Set an account password "
                "first before enabling two-factor authentication."
            ),
        )

    if _has_totp(user):
        raise HTTPException(
            status_code=409,
            detail=(
                "Two-factor authentication is already enabled. Disable it first if you "
                "want to enrol a different device."
            ),
        )

    return await _issue_totp_setup(user)


# WHY THIS EXISTS
# Step two of voluntary enrolment. The recovery codes come back HERE and exactly once -
# there is no endpoint that can show them again, because they are stored hashed and the
# server genuinely cannot. The UI has to make that clear at the moment it shows them.
@app.post("/2fa/confirm")
async def confirm_totp_setup(
    request: TotpConfirmRequest,
    http_request: Request,
    user: dict = Depends(require_session),
) -> dict:
    # Rate limited like every other code-checking endpoint. Enrolment is a code guess
    # too, and leaving it unlimited would let somebody with a session brute-force a
    # pending secret they do not hold.
    if _too_many_attempts(_client_key(http_request, "2fa-confirm")):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Wait a few minutes and try again.",
        )

    if _has_totp(user):
        raise HTTPException(
            status_code=409, detail="Two-factor authentication is already enabled."
        )

    codes = await _complete_totp_setup(user, request.code)

    return {"enabled": True, "recoveryCodes": codes}


# --- Forced enrolment, from a login that could not complete ----------------


# WHY THESE TWO ENDPOINTS EXIST SEPARATELY FROM THE PAIR ABOVE
# When the enforcement switch is on and an account has no second factor, the user is
# holding an enrol challenge and no session - so they cannot call /2fa/setup, which
# requires one. These are the same two steps, authorised by that challenge instead.
#
# THE ALTERNATIVE WOULD HAVE BEEN TO ISSUE A SESSION AND MARK IT INCOMPLETE, and it is
# worth being explicit about why that is worse: every endpoint in the app would then
# have to check the mark, and the first one that forgot would let a user skip enrolment
# entirely. A challenge grants access to nothing by construction, so there is nothing
# for anywhere else to remember.
@app.post("/2fa/enrol/start")
async def start_forced_enrolment(request: ChallengeOnlyRequest) -> dict:
    user, _ = await _resolve_challenge(request.challenge, expect="enrol")

    if _has_totp(user):
        # 2FA was enabled from another device while this login was in flight. Nothing
        # to enrol; the honest answer is to sign in again, which will now correctly ask
        # for a code.
        raise HTTPException(
            status_code=409,
            detail="Two-factor authentication is already enabled. Sign in again.",
        )

    return await _issue_totp_setup(user)


# WHY THIS EXISTS
# Finishes forced enrolment AND signs the user in, in one response. The session is
# issued here because at this point they have done everything the server asked: correct
# password, plus a working second factor they have just proved possession of. Making
# them type the password again would be friction with no security value.
@app.post("/2fa/enrol/finish")
async def finish_forced_enrolment(
    request: ChallengeCodeRequest, http_request: Request
) -> dict:
    if _too_many_attempts(_client_key(http_request, "2fa-enrol")):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Wait a few minutes and try again.",
        )

    user, token_hash = await _resolve_challenge(request.challenge, expect="enrol")

    codes = await _complete_totp_setup(user, request.code)

    # Spent. A challenge token is single use, exactly like a recovery code.
    await database.delete_challenge(token_hash)

    token = await _start_session(user["id"])

    return {
        "token": token,
        "user": _public_user(user),
        # Shown once, on a screen the user has to acknowledge before continuing.
        "recoveryCodes": codes,
    }


# --- Turning it off, and replacing the recovery codes ----------------------


# WHY THIS EXISTS
# Removing 2FA, with step-up authentication - see TotpDisableRequest for why the
# password is required alongside a code.
#
# A RECOVERY CODE IS ACCEPTED HERE as well as a TOTP code, and for most people who use
# this endpoint that is the whole point: the phone is gone, so they signed in with a
# recovery code and now need to remove the dead authenticator before enrolling a new
# one. Accepting only a TOTP code would make this endpoint useless in the exact
# situation it exists for.
@app.post("/2fa/disable")
async def disable_two_factor(
    request: TotpDisableRequest,
    http_request: Request,
    user: dict = Depends(require_session),
) -> dict:
    if _too_many_attempts(_client_key(http_request, "2fa-disable")):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Wait a few minutes and try again.",
        )

    if not _has_totp(user):
        # Already off. 200 rather than an error - the caller's goal is achieved, which
        # is the same reasoning as logout succeeding on an invalid token.
        return {"enabled": False}

    # A Google-only account has no password to step up against. It also cannot reach
    # here, since such an account never enrols TOTP - but the guard is explicit rather
    # than relying on that, because "cannot happen" is how a KeyError gets shipped.
    stored_hash = user.get("passwordHash")

    if not stored_hash or not auth.verify_password(stored_hash, request.password):
        raise HTTPException(status_code=401, detail="Password is incorrect.")

    accepted = auth.verify_totp(user["totpSecret"], request.code)

    if not accepted:
        # Fall back to a recovery code, for the lost-phone case above. Note this path
        # does NOT consume the code: the entire 2FA state including every remaining
        # code is about to be deleted, so spending one first would be pointless work.
        accepted = (
            auth.find_recovery_code(user.get("recoveryCodeHashes") or [], request.code)
            is not None
        )

    if not accepted:
        raise HTTPException(
            status_code=401,
            detail="That code is not correct. Use a current code or a recovery code.",
        )

    await database.disable_totp(user["id"])

    return {"enabled": False}


# WHY THIS EXISTS
# A fresh set of recovery codes, invalidating every code issued before - for the user
# who has spent eight of ten, or lost the paper they wrote them on.
#
# IT REQUIRES A SESSION AND A CURRENT CODE. The session alone is not enough: with only
# a stolen token, an attacker could mint themselves ten permanent 2FA bypasses and keep
# them working after the victim changed their password.
@app.post("/2fa/recovery-codes")
async def regenerate_recovery_codes(
    request: TotpConfirmRequest,
    http_request: Request,
    user: dict = Depends(require_session),
) -> dict:
    if _too_many_attempts(_client_key(http_request, "2fa-codes")):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Wait a few minutes and try again.",
        )

    if not _has_totp(user):
        raise HTTPException(
            status_code=400,
            detail=(
                "Enable two-factor authentication first - there is nothing to recover."
            ),
        )

    step = auth.matched_totp_step(user["totpSecret"], request.code)

    if step is None:
        raise HTTPException(status_code=401, detail="That code is not correct.")

    # Replay protection applies here too. Regenerating codes is a sensitive operation,
    # so the code authorising it is spent exactly like one used to sign in.
    if not await database.claim_totp_step(user["id"], step):
        raise HTTPException(
            status_code=401,
            detail="That code has already been used. Wait for the next one.",
        )

    codes, hashes = auth.new_recovery_codes()

    await database.replace_recovery_codes(user["id"], hashes)

    return {"recoveryCodes": codes}


# --- Completing a login ----------------------------------------------------


# WHY THIS EXISTS
# The second half of a 2FA login: a challenge plus six digits becomes a session.
#
# THE ORDER OF THE CHECKS IS THE SECURITY OF THIS ENDPOINT.
#   1. Resolve the challenge - is this a real, unexpired, half-finished login?
#   2. Verify the code       - do the digits match the secret?
#   3. Claim the time step   - is this code fresh, or a replay?
#   4. Delete the challenge  - so the challenge token cannot be spent twice.
#   5. Issue the session.
#
# Step 3 is the one usually missing in the wild. Without it a code works for its whole
# ~90-second window, so anybody who saw it typed - over a shoulder, or on a phishing
# page that forwarded it to us in real time - can use it again while it is live.
@app.post("/2fa/verify")
async def verify_two_factor(
    request: ChallengeCodeRequest, http_request: Request
) -> dict:
    if _too_many_attempts(_client_key(http_request, "2fa-verify")):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Wait a few minutes and try again.",
        )

    user, token_hash = await _resolve_challenge(request.challenge, expect="totp")

    if not _has_totp(user):
        # 2FA was disabled from another device while this login was in flight. Refusing
        # and restarting is correct: the login began under rules that no longer apply,
        # and the next attempt will succeed on the password alone.
        await database.delete_challenge(token_hash)
        raise HTTPException(
            status_code=401, detail="That sign-in attempt has expired. Start again."
        )

    step = auth.matched_totp_step(user["totpSecret"], request.code)

    if step is None:
        await _fail_challenge_attempt(token_hash)

    # Replay protection, checked AFTER the code is known to be correct. That order
    # matters twice over: a wrong code cannot burn a legitimate time step, and a
    # correct-but-reused code gets its own message - "already used" tells an honest
    # user to wait for the next code, where "not correct" would send them hunting for
    # a problem that does not exist.
    if not await database.claim_totp_step(user["id"], step):
        await _fail_challenge_attempt(token_hash)

    await database.delete_challenge(token_hash)

    # Any emailed code issued for this login goes too. It was an alternative to the
    # code just used, and leaving it live would mean a code sitting in an inbox
    # outlived the login it was issued for.
    await database.delete_email_code(token_hash)

    token = await _start_session(user["id"])

    return {"token": token, "user": _public_user(user)}


# WHY THIS EXISTS
# The lost-phone path: a challenge plus one of the ten recovery codes becomes a
# session, and that code is destroyed.
#
# IT DELIBERATELY DOES NOT DISABLE 2FA. A user who signs in with a recovery code still
# has 2FA on and will need another factor next time - which is why the remaining count
# is worth reporting. Silently disabling it on recovery would turn one leaked code from
# an inconvenience into the permanent removal of the second factor.
@app.post("/2fa/recover")
async def recover_with_code(
    request: RecoveryCodeRequest, http_request: Request
) -> dict:
    if _too_many_attempts(_client_key(http_request, "2fa-recover")):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Wait a few minutes and try again.",
        )

    user, token_hash = await _resolve_challenge(request.challenge, expect="totp")

    stored = user.get("recoveryCodeHashes") or []

    index = auth.find_recovery_code(stored, request.code)

    if index is None:
        await _fail_challenge_attempt(token_hash)

    # CONSUME IT BEFORE ISSUING THE SESSION. If the write fails, nobody gets in on a
    # code that was not spent - the safe direction. The reverse order hands out a
    # session and then possibly leaves the code reusable.
    #
    # The boolean matters: consume_recovery_code returns False when the array did not
    # change, which means another request spent this same code a moment earlier.
    # Treating that as a failure is what keeps single-use true under concurrency.
    if not await database.consume_recovery_code(user["id"], stored[index]):
        await _fail_challenge_attempt(token_hash)

    await database.delete_challenge(token_hash)
    await database.delete_email_code(token_hash)

    token = await _start_session(user["id"])

    return {
        "token": token,
        "user": _public_user(user),
        # One fewer than before, since the matched code has just been spent. Surfaced
        # so the UI can warn at zero - the moment a user has no recovery path left and
        # needs to regenerate.
        "recoveryCodesLeft": max(len(stored) - 1, 0),
    }


# WHY THIS EXISTS
# Emails a one-time code for the login currently in progress. The FALLBACK path, and it
# is worth restating why it is a fallback rather than the primary factor: an emailed
# code proves access to an inbox, and an inbox is reachable from anywhere and usually
# protected by a password alone. See the section header in auth.py.
#
# THE RESPONSE IS THE SAME WHETHER OR NOT THE MAIL WAS ACCEPTED. Reporting a delivery
# failure would leak which providers reject us and give an attacker a probe; there is
# nothing a user could do with the distinction anyway. The operator gets the real
# reason in the log - see mailer.py.
@app.post("/2fa/email-code")
async def send_email_code(
    request: ChallengeOnlyRequest, http_request: Request
) -> dict:
    # Limited harder than the code-checking endpoints, because this one SENDS MAIL.
    # Unlimited, it is a way to spend our Resend quota flooding somebody's inbox, and
    # a way to get our sending domain reported.
    if _too_many_attempts(_client_key(http_request, "2fa-email")):
        raise HTTPException(
            status_code=429,
            detail="Too many code requests. Wait a few minutes and try again.",
        )

    user, token_hash = await _resolve_challenge(request.challenge, expect="totp")

    if not mailer.email_available():
        # 503 rather than a pretence. The UI hides the button when emailAvailable is
        # false, so reaching this means a direct call or a configuration that changed
        # mid-session - and the honest answer is the useful one.
        raise HTTPException(
            status_code=503,
            detail=(
                "Email delivery is not configured on this server, so a code cannot be "
                "sent. Use your authenticator app or a recovery code."
            ),
        )

    code = auth.new_email_code()

    # Hashed before storage, like every other credential here. Nothing keeps the
    # plaintext once the message is handed to the provider.
    await database.save_email_code(
        token_hash, auth.hash_email_code(code), auth.email_code_expiry()
    )

    # THE ADDRESS COMES FROM THE ACCOUNT, NEVER FROM THE REQUEST. Taking it from the
    # body would let anybody holding a challenge redirect the code to an address they
    # control, which is a complete 2FA bypass - and it is a genuinely common
    # implementation mistake, because passing it in makes the endpoint easier to test.
    await mailer.send_recovery_code(user["email"], code, user.get("name", ""))

    return {
        "sent": True,
        "expiresInMinutes": auth.EMAIL_CODE_TTL_MINUTES,
        # Enough to reassure the right person that the code went to the right place,
        # and not enough to reveal the address to somebody who does not already know
        # it. The local part is masked; the domain is not, because a user unsure which
        # of two addresses they signed up with needs that much to act.
        "sentTo": _mask_email(user["email"]),
    }


# WHY THIS EXISTS
# Checks an emailed code and finishes the login.
#
# TWO SEPARATE ATTEMPT COUNTERS APPLY, and the distinction is the point: the challenge
# counter bounds attempts at the second factor as a whole, and the email-code counter
# bounds guesses at one particular six-digit code. Without the second, a user could
# request a fresh code every three guesses and grind through the space while never
# exhausting either limit.
@app.post("/2fa/verify-email")
async def verify_email_code(
    request: ChallengeCodeRequest, http_request: Request
) -> dict:
    if _too_many_attempts(_client_key(http_request, "2fa-verify-email")):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Wait a few minutes and try again.",
        )

    user, token_hash = await _resolve_challenge(request.challenge, expect="totp")

    record = await database.find_email_code(token_hash)

    if record is None:
        raise HTTPException(
            status_code=401, detail="That code has expired. Request a new one."
        )

    # PYTHON-SPECIFIC: secrets.compare_digest for a constant-time comparison. Both
    # values are SHA-256 hex digests of the same length, so == would leak only how many
    # leading characters matched - a small leak, and one that costs a single function
    # call to close.
    supplied = auth.hash_email_code(request.code)
    stored = record.get("codeHash", "")

    if not secrets.compare_digest(supplied, stored):
        attempts = await database.count_email_code_attempt(token_hash)

        if attempts >= auth.EMAIL_CODE_MAX_ATTEMPTS:
            # The CODE is destroyed and the CHALLENGE survives, which is deliberate: a
            # user who fat-fingered an emailed code three times can still finish with
            # their authenticator app or a recovery code rather than starting over.
            await database.delete_email_code(token_hash)

            raise HTTPException(
                status_code=429,
                detail=(
                    "Too many incorrect codes. That emailed code is no longer valid - "
                    "request a new one."
                ),
            )

        await _fail_challenge_attempt(token_hash)

    # Single use: gone the moment it works.
    await database.delete_email_code(token_hash)
    await database.delete_challenge(token_hash)

    token = await _start_session(user["id"])

    return {"token": token, "user": _public_user(user)}


# ============================================================================
# GOOGLE SIGN-IN
#
# WHAT THIS ENDPOINT IS, IN ONE SENTENCE: it takes a token Google gave the browser,
# checks that Google really issued it to us, and issues one of our own sessions.
#
# THE OUTCOME IS DELIBERATELY IDENTICAL TO A PASSWORD LOGIN. Same response shape, same
# kind of session record, same expiry - and require_session cannot tell the two apart.
# That is the answer to "how do both sign-in paths end up with the same kind of
# session": there is exactly one function that issues sessions, _start_session, and
# both paths call it. No other endpoint in the app needs to know which door a user came
# through, which is why adding Google Sign-In required no change at all to /scan,
# /scans or /scan/{id}.
#
# WHY NO SECOND FACTOR IS ASKED FOR HERE - see _enrolment_required above.
# ============================================================================


@app.post("/auth/google")
async def sign_in_with_google(
    request: GoogleSignInRequest, http_request: Request
) -> dict:
    if _too_many_attempts(_client_key(http_request, "google")):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Wait a few minutes and try again.",
        )

    if not config.google_enabled():
        raise HTTPException(
            status_code=503, detail="Google Sign-In is not configured on this server."
        )

    try:
        # Everything that makes this safe happens inside here. See google_auth.py -
        # and in particular the note that decoding a JWT is not verifying it.
        profile = google_auth.verify_google_id_token(request.credential)
    except google_auth.GoogleTokenError as error:
        # PYTHON-SPECIFIC: str(error) is the message the exception was raised with.
        # Those messages are written to be shown to a user; the diagnostic detail
        # stayed in the server log where google_auth printed it.
        raise HTTPException(status_code=401, detail=str(error)) from error

    # --- Find, link, or create ---------------------------------------------
    #
    # Three cases in a fixed order, and the order is what makes it efficient as well as
    # correct: the commonest first, creation last, so a returning user costs one
    # indexed lookup.

    # 1. ALREADY LINKED - every sign-in after the first. Matched on googleId, never on
    #    email, for the reason in google_auth.py: `sub` is permanent and an email
    #    address is not.
    user = await database.find_user_by_google_id(profile["googleId"])

    if user is None:
        # 2. AN ACCOUNT EXISTS WITH THIS EMAIL BUT NO GOOGLE LINK - somebody who signed
        #    up with a password in March and is clicking the Google button in
        #    September. Link the two rather than creating a second account, which would
        #    split their scan history in half.
        #
        #    This is only safe because verify_google_id_token already refused any token
        #    whose email Google does not report as verified. Without that check, this
        #    branch is an account-takeover primitive.
        existing = await database.find_user_by_email(profile["email"])

        if existing is not None:
            if not await database.link_google_id(existing["id"], profile["googleId"]):
                # The sparse unique index refused: this Google id is already on a
                # different account. Genuinely strange, and better reported than
                # papered over.
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "That Google account is already linked to a different "
                        "SecuScan account."
                    ),
                )

            # Re-read, so the session is issued against the linked record rather than
            # the pre-link copy sitting in memory.
            user = await database.find_user_by_id(existing["id"])

    if user is None:
        # 3. A NEW ACCOUNT. Note what is absent: no passwordHash field at all.
        #
        #    NOT an empty string and not null - the key simply does not exist. A
        #    Google-only account has no password, and a missing field is how to say so:
        #    it means verify_password can never be handed a stored value that something
        #    might compare equal to. /auth/login's `user.get("passwordHash") or ""` is
        #    what turns that absence into "this account cannot be signed into with a
        #    password".
        user_id = auth.new_user_id()

        created = await database.create_user(
            {
                "id": user_id,
                "name": profile["name"],
                "email": profile["email"],
                "googleId": profile["googleId"],
                "createdAt": datetime.now(timezone.utc),
                # Same starting plan as a password signup, for the same reason - see
                # the note in /auth/signup. How somebody made their account has
                # nothing to do with what they are entitled to.
                "planId": billing.DEFAULT_PLAN_ID,
            }
        )

        if not created:
            # The unique index on email refused, which means a concurrent request
            # created this same account a moment ago. Re-reading finds that one, so the
            # user is signed in rather than shown a race they cannot act on.
            user = await database.find_user_by_email(profile["email"])
        else:
            user = await database.find_user_by_id(user_id)

    if user is None:
        # Defensive. Reaching here means a read failed immediately after a successful
        # write - a server fault rather than anything the caller did, so it is a 500
        # and not a 4xx.
        raise HTTPException(
            status_code=500, detail="Could not complete Google sign-in."
        )

    # The same session a password login gets, from the same function.
    token = await _start_session(user["id"])

    return {"token": token, "user": _public_user(user)}


# ============================================================================
# WHAT THE FRONTEND NEEDS TO KNOW BEFORE ANYBODY SIGNS IN
# ============================================================================


# WHY THIS EXISTS
# The login page has to decide whether to render a Google button, and both auth pages
# whether to mention that 2FA is mandatory. Those answers live in the SERVER's
# environment, and baking them into the frontend bundle produces the worst kind of
# mismatch: a deployment showing a Google button whose endpoint returns 503.
#
# UNAUTHENTICATED, deliberately - it is read before anybody has signed in. Nothing here
# is secret. The Google client id is public by design and ships in the JS bundle either
# way, and whether 2FA is mandatory is visible to anyone who tries to sign up.
@app.get("/auth/config")
async def read_auth_config() -> dict:
    return {
        "googleEnabled": config.google_enabled(),
        "googleClientId": config.GOOGLE_CLIENT_ID,
        "require2fa": config.require_2fa(),
        "emailAvailable": mailer.email_available(),
        # So the password strength meter and the server agree on the minimum. Two
        # copies of that number is how a form accepts a password the API rejects.
        "passwordMinLength": auth.PASSWORD_MIN_LENGTH,
    }


# WHY THIS EXISTS
# Tells a signed-in user the state of their own 2FA, so an account screen can show
# "enabled" or an enrolment prompt without guessing.
#
# WHAT IT RETURNS IS DELIBERATELY THIN: four booleans and a count. No secret, no
# pending secret, no code hashes - none of which the UI needs and all of which would be
# a leak. `hasPassword` is there so the UI can hide the disable form for a Google-only
# account, which has no password to step up with.
@app.get("/2fa/status")
async def read_two_factor_status(user: dict = Depends(require_session)) -> dict:
    return {
        "enabled": _has_totp(user),
        "required": config.require_2fa(),
        "hasPassword": bool(user.get("passwordHash")),
        "isGoogleAccount": bool(user.get("googleId")),
        "recoveryCodesLeft": len(user.get("recoveryCodeHashes") or []),
        "emailAvailable": mailer.email_available(),
    }


# ============================================================================
# BILLING
#
# WHAT THIS IS, stated once at the top so nothing below has to keep apologising:
# there is no payment processor. `POST /billing/checkout` checks that a card is
# well-formed, writes an order, and grants the plan. No money moves. See the header
# of payments/mock_card.py for the full version, including why a Luhn-valid number is
# not an authorised one and what has to change before this faces a real customer.
#
# WHICH PROCESSOR IS IN FORCE is not this file's business any more. config.py's
# SECUSCAN_PAYMENT_PROVIDER names one, payments/__init__.py builds it, and the
# handler below asks it a question and reads the answer. That indirection is here for
# one reason: a real processor grants entitlements LATER, by webhook, and an endpoint
# that assumed a synchronous grant would have to be rewritten during the migration.
# It does not assume one - see the "pending" branch, which nothing can currently
# reach and which is written anyway.
#
# THE ONE THING TO GET RIGHT ANYWAY, and it is right here rather than in billing.py
# because it is a property of the REQUEST: the body names a plan, never an amount.
# CheckoutRequest below has no price field, so there is no value a client can send
# that influences what gets charged - billing.PLANS decides, on the server, every
# time. That is the difference between a demo and a demo with a hole in it.
# ============================================================================


# WHY THIS EXISTS
# FASTAPI: the checkout body. Four card fields, a plan id, and deliberately nothing
# else.
#
# WHAT IS NOT IN THIS MODEL IS THE POINT. No amountCents, no currency, no interval,
# no "discount" - every one of those is decided by the server from the plan id, so
# there is no field to tamper with. A single line of curl is all it takes to exploit
# an endpoint that trusts a client-sent amount, and every such endpoint looked
# reasonable when it was written.
#
# The card fields are validated in the HANDLER rather than in validators here, which
# is the opposite of SignupRequest's arrangement and for one specific reason: a
# Pydantic validation failure comes back as a 422 with a field path, and the payment
# form wants one plain sentence naming one problem. billing.card_problem() produces
# exactly that, and the handler turns it into a 400.
class CheckoutRequest(BaseModel):
    planId: str = Field(..., description="Which plan from GET /billing/plans")

    cardName: str | None = Field(default=None, description="Name as printed on the card")
    cardNumber: str | None = Field(default=None, description="Digits, spaces allowed")
    cardExpiry: str | None = Field(default=None, description="MM/YY or MM/YYYY")
    cardCvc: str | None = Field(default=None, description="3 digits, 4 on Amex")

    # An upper bound on every card field, because a field with no maximum is a field
    # somebody posts a megabyte into. Generous enough that no real card comes close.
    @field_validator("cardName", "cardNumber", "cardExpiry", "cardCvc")
    @classmethod
    def not_absurdly_long(cls, value: str | None) -> str | None:
        if value is None:
            return None

        if len(value) > 60:
            raise ValueError("That value is too long to be a card detail.")

        return value.strip()


# WHY THIS EXISTS
# What the payment setup is configured to do. Unauthenticated, read before checkout
# renders so the frontend knows whether to render the mock card form or the Paddle
# checkout overlay, and which client token and environment to initialize Paddle with.
@app.get("/billing/config")
async def read_billing_config() -> dict:
    provider = payments.provider_name()
    return {
        "provider": provider,
        "clientToken": config.PADDLE_CLIENT_TOKEN if provider == "paddle" else "",
        "environment": "sandbox" if config.PADDLE_SANDBOX else "production",
    }


# WHY THIS EXISTS
# The price list, as the frontend sees it. Unauthenticated, because the pricing table
# on the landing page is the first thing a visitor reads and gating it behind a login
# would be absurd.
#
# WHY THE FRONTEND FETCHES PRICES IT ALREADY HAS: frontend/src/lib/pricing.js carries
# the marketing copy for these same four plans, and it could carry the numbers too.
# It must not. The moment the displayed price and the charged price are two separate
# constants, they are two constants that agree until one of them is edited - and the
# failure is a customer shown $49 and billed $149. This endpoint makes the server's
# figure the only figure.
@app.get("/billing/plans")
async def list_plans() -> list:
    # PYTHON-SPECIFIC: a list comprehension over the catalogue, each entry passed
    # through the whitelist rather than returned raw - so a field added to PLANS for
    # internal use is absent here by default.
    return [billing.public_plan(plan) for plan in billing.PLANS]


# WHY THIS EXISTS
# The shape of an order in a response. A whitelist for the same reason _public_user is
# one, and with one field pointedly absent: there is no card number to omit, because
# the order document never had one. billing.describe_card() reduced it to a brand and
# four digits before anything was written.
def _public_order(order: dict) -> dict:
    return {
        "id": order["id"],
        "planId": order.get("planId"),
        "planName": order.get("planName"),
        "amountCents": order.get("amountCents"),
        "currency": order.get("currency"),
        "interval": order.get("interval"),
        "status": order.get("status"),
        "createdAt": _iso_utc(order.get("createdAt")),
        "periodEnd": _iso_utc(order.get("periodEnd")),
        "cardBrand": order.get("cardBrand"),
        "cardLast4": order.get("cardLast4"),
        # The processor's own id for this payment, so support can trace a receipt
        # into a dashboard. "mock_..." under the mock provider, which is a prefix
        # chosen to be unmistakable if one ever turns up in a real ledger.
        "providerRef": order.get("providerRef"),
    }


# WHY THIS EXISTS
# THE OPPORTUNISTIC TIDY-UP, and the important thing about it is that nothing
# depends on it running.
#
# A cancelled plan lapses when its paid period ends. Correctness comes entirely
# from the READ being period-aware - billing.effective_plan_for_user, used by
# _public_user above - so the stored record being a few days stale is invisible to
# every user of the system. What it is not is tidy: a users document claiming
# planId "starter" with a subscription that expired last month is a document that
# will mislead whoever runs a query against it.
#
# So the record gets fixed the next time somebody looks at their billing page. If
# they never look, nothing breaks. That is the difference between this and a
# scheduled job: a job that fails to run leaves the system WRONG, and this failing
# to run leaves it merely untidy.
#
# WHY IT RETURNS THE FRESH USER: the caller needs the post-write state to build its
# response, and re-reading is cheaper than reasoning about what the update did.
# Returns the user unchanged when there was nothing to do, which is the common case.
async def _reconcile_lapsed_plan(user: dict) -> dict:
    if not billing.subscription_has_lapsed(user.get("subscription")):
        return user

    # clear_user_plan already existed for the immediate-cancellation version of this
    # feature, and it does exactly the right thing: planId back to Free, the
    # subscription sub-document removed, and THE ORDERS UNTOUCHED. A cancellation
    # does not un-buy the months already paid for.
    await database.clear_user_plan(user["id"], billing.DEFAULT_PLAN_ID)

    return await database.find_user_by_id(user["id"]) or user


# WHY THIS EXISTS
# What the signed-in account is on, and what it has paid. One request rather than two,
# because the billing screen shows both together and a plan that disagrees with the
# order beside it is exactly the confusion this avoids.
#
# The plan also arrives on every /auth/me - see _public_user. That is not duplication
# worth removing: /auth/me answers "who am I" for every page, and this answers "what
# have I bought" for one. Splitting them means the dashboard does not fetch an order
# list it will never show.
@app.get("/billing/subscription")
async def read_subscription(user: dict = Depends(require_session)) -> dict:
    # The billing screen is the natural place to do the tidy-up, because it is the
    # one page whose whole subject is the thing that went stale. Note the ordering:
    # the reconcile happens FIRST, so everything below reads a record that already
    # agrees with the clock rather than each field having to be period-aware
    # separately.
    user = await _reconcile_lapsed_plan(user)

    plan = billing.effective_plan_for_user(user)

    # OWNER-SCOPED, and the argument is required by list_orders rather than optional -
    # see the note on that function. These are receipts; the one bug that must be
    # impossible here is one customer reading another's.
    orders = await database.list_orders(user["id"])

    return {
        "plan": billing.public_plan(plan),
        "subscription": _public_subscription(
            billing.effective_subscription(user.get("subscription"))
        ),
        "orders": [_public_order(order) for order in orders],
    }


# WHY THIS EXISTS
# The purchase. This is the endpoint the payment page posts to, and the order of
# operations in it is the whole design:
#
#   1. Look the plan up ON THE SERVER, from the id. The amount comes from here.
#   2. Refuse a plan that is not for sale, before touching the card.
#   3. Hand the card to the provider and read its verdict. Refused is a 400 with one
#      sentence; pending returns without granting anything.
#   4. Take the brand and four digits from the verdict, and let the number go.
#   5. Write the order. Raise if that fails - see below.
#   6. Grant the plan.
#
# WHY THE ORDER IS WRITTEN BEFORE THE PLAN IS GRANTED: if the process dies between
# the two, the outcome is a receipt for a plan that was not applied - visible, in the
# billing history, and fixable by support. The other order produces an account with
# entitlements nobody can account for, which is the version that is hard to detect
# and impossible to reconcile. Neither is good; one is much easier to find.
#
# THE REAL FIX for that gap is a transaction, and MongoDB supports them - but only on
# a replica set, and this app is developed against a standalone mongod where starting
# one raises. So the sequencing above is the mitigation, and this comment is here so
# nobody later assumes the two writes are atomic. They are not.
@app.post("/billing/checkout")
async def checkout(
    request: CheckoutRequest,
    http_request: Request,
    user: dict = Depends(require_session),
) -> dict:
    # Throttled like the auth endpoints. A checkout form with no limit is a free
    # card-testing service: post numbers until one stops failing the Luhn check, and
    # the response tells you which ones are well-formed. That is a real thing done to
    # real payment forms, and the fact that nothing here reaches a bank does not make
    # the endpoint a good place to practise.
    if _too_many_attempts(_client_key(http_request, "checkout")):
        raise HTTPException(
            status_code=429,
            detail="Too many payment attempts. Wait a few minutes and try again.",
        )

    plan = billing.find_plan(request.planId)

    if plan is None:
        raise HTTPException(status_code=404, detail="That plan does not exist.")

    # CHECKED BEFORE THE CARD, deliberately. Asking somebody to correct their CVC and
    # then telling them the plan was never for sale is two round trips to reach the
    # answer that was available on the first.
    if not plan["purchasable"]:
        if plan["id"] == billing.DEFAULT_PLAN_ID:
            detail = "The Free plan needs no payment. You already have it."
        else:
            detail = (
                plan["name"] + " is priced individually. Get in touch and we will "
                "set it up for you."
            )

        raise HTTPException(status_code=400, detail=detail)

    # A plan marked purchasable with no amount would be a catalogue error, not a user
    # error - so it is a 500. Unreachable with PLANS as it stands, which is exactly
    # when a check like this is worth writing: the catalogue is a list somebody will
    # edit.
    if plan["amountCents"] is None:
        raise HTTPException(
            status_code=500, detail="That plan is misconfigured. We have been notified."
        )

    # WHY THE PROVIDER IS CHECKED BEFORE THE CARD IS LOOKED AT
    # A server whose payment provider failed to configure must say so rather than
    # accepting card details and doing nothing with them. This is the same treatment
    # POST /auth/google gives a missing Google client id: visibly switched off beats
    # half working. It is unreachable on the mock, which is always available - and it
    # is written now because the day it becomes reachable is a day nobody is looking
    # at this function.
    if not payments.payments_available():
        raise HTTPException(
            status_code=503,
            detail="Payments are not available on this server. Nothing was charged.",
        )

    # ONE timestamp, used by the provider, by the order, and by the subscription the
    # order creates. Two calls to now() a few lines apart differ by microseconds, and
    # a receipt that disagrees with the period it paid for is a support conversation
    # with no good answer.
    now = datetime.now(timezone.utc)

    # THE CARD LEAVES THIS FUNCTION HERE AND GOES NOWHERE ELSE. The four fields are
    # gathered into one dict, handed to the provider, and never referenced again -
    # `request.cardNumber` appears nowhere below this call.
    #
    # WHY THE PROVIDER TAKES THE CARD AT ALL, given that a real one must not: because
    # today's provider is a checksum and needs the digits. A real provider ignores
    # this argument entirely (see the `del card` in payments/paddle.py, which is
    # there to prove it) and its own iframe collects the number instead - at which
    # point the four fields come off CheckoutRequest and this dict goes with them.
    outcome = await payments.get_provider().create_checkout(
        plan=plan,
        user=user,
        card={
            "name": request.cardName or "",
            "number": request.cardNumber or "",
            "expiry": request.cardExpiry or "",
            "cvc": request.cardCvc or "",
        },
        now=now,
    )

    if outcome.status == "refused":
        # 400 rather than 422. The card is well-formed JSON that failed a business
        # rule, and the form wants this sentence rendered as-is beside the fields.
        # One problem, one sentence - see card_problem in payments/mock_card.py.
        raise HTTPException(
            status_code=400,
            detail=outcome.problem or "The payment could not be completed.",
        )

    # WHY THIS BRANCH EXISTS WHEN NOTHING CAN CURRENTLY REACH IT
    # A real processor does not settle inside the request that starts the payment.
    # Paddle's overlay opens in the browser, the customer types their card into
    # Paddle's iframe, and the plan is granted LATER by a signed webhook. So the
    # correct response to a pending payment is "here is what the browser must do
    # next", and emphatically NOT a granted entitlement.
    #
    # Writing it now is the whole reason the provider seam was built before it was
    # needed. The alternative is discovering during a payments migration that the
    # endpoint, the response shape and the frontend all assume a synchronous grant.
    #
    # NO ORDER IS WRITTEN HERE. Nothing has been paid, so there is nothing to file;
    # the webhook that reports settlement is what creates the order and the
    # subscription together.
    if outcome.status == "pending":
        return {
            # The discriminator. Present on the granted response too, so a caller
            # branches on one field rather than sniffing for the presence of `order`.
            "status": "pending",
            "plan": billing.public_plan(plan),
            "clientAction": outcome.client_action,
            "providerRef": outcome.provider_ref,
        }

    # From here the outcome is "granted": the entitlement is ours to write.
    #
    # `payment_method` is a brand, four digits and an expiry month - which is
    # everything the receipt, the order and the billing screen are built from, and
    # is the same shape a real processor's token description has. That is the
    # property that makes this swap small.
    card = outcome.payment_method

    period_end = billing.period_end(plan, now)

    order_id = auth.new_user_id()

    order = {
        "id": order_id,
        "userId": user["id"],
        # The plan's name and price are COPIED into the order rather than looked up
        # from it later, and that is what makes this a ledger. A price change next
        # quarter must not rewrite what a customer was charged last month, so the
        # order carries its own figures and the catalogue is free to move.
        "planId": plan["id"],
        "planName": plan["name"],
        "amountCents": plan["amountCents"],
        "currency": plan["currency"],
        "interval": plan["interval"],
        # "authorised", not "paid". Nothing was captured because nothing was charged,
        # and a status field that claimed otherwise would be the one lie in the
        # database. When a processor is wired in, this is the field that carries its
        # verdict.
        "status": "authorised",
        "createdAt": now,
        "periodEnd": period_end,
        "cardBrand": card["brand"],
        "cardLast4": card["last4"],
        # The provider's own reference, stored so a receipt can be traced into a
        # processor's dashboard. Under the mock this is a "mock_..." string with no
        # dashboard behind it, and it is written anyway so the order document has
        # the shape it will have under a real processor rather than growing a field
        # during the migration.
        "providerRef": outcome.provider_ref,
    }

    try:
        await database.create_order(order)
    except database.StorageError:
        # WHY THIS CATCHES AND save_scan DOES NOT: a scan that ran but could not be
        # filed is still worth returning. A payment the system has no memory of is
        # not - so the failure surfaces as a failed payment, which is both true and
        # something the user can act on by trying again.
        #
        # database.StorageError rather than pymongo's own exception, so this file
        # still does not import a database driver - see the note on that class. The
        # exception is deliberately not included in the detail either: a driver error
        # string can carry the connection URI, and a URI can carry credentials.
        raise HTTPException(
            status_code=503,
            detail="We could not record that payment. Nothing was charged - try again.",
        )

    subscription = {
        "planId": plan["id"],
        "status": "active",
        "startedAt": now,
        "currentPeriodEnd": period_end,
        # WRITTEN FALSE EXPLICITLY rather than left absent. A buy after a cancel is
        # the case this exists for: the old subscription sub-document is replaced
        # wholesale by set_user_plan, and a missing key would read as falsey anyway -
        # but "anyway" is doing load-bearing work in that sentence, and a field whose
        # absence means something is a field somebody will misread. See
        # billing.subscription_has_lapsed.
        "cancelAtPeriodEnd": False,
        "cardBrand": card["brand"],
        "cardLast4": card["last4"],
        # The order that paid for this period, so the billing screen can link the two
        # and support can trace an entitlement back to its receipt.
        "orderId": order_id,
    }

    await database.set_user_plan(user["id"], plan["id"], subscription)

    # The updated account goes back in the response so the frontend can put the new
    # plan straight into its context. The alternative is the payment page navigating
    # to a dashboard that still shows the old plan until something refetches, which
    # reads as the purchase not having worked.
    updated = await database.find_user_by_id(user["id"]) or user

    return {
        # The discriminator, matching the pending branch above. A frontend that
        # checks this cannot be broken by a provider that starts answering "pending".
        "status": "granted",
        "order": _public_order(order),
        "plan": billing.public_plan(plan),
        "subscription": _public_subscription(subscription),
        "user": _public_user(updated),
    }


# ============================================================================
# THE WEBHOOK - where Paddle tells us what happened after a checkout or renewal.
#
# WHY THIS EXISTS
# Under the mock provider, the plan is granted synchronously inside create_checkout
# and this endpoint is never called. Under a real processor (Paddle), the checkout
# returns "pending" and the plan is granted LATER, when Paddle POSTs a signed
# webhook reporting that the transaction completed. This endpoint is the other half
# of that handshake.
#
# UNAUTHENTICATED BY DESIGN - there is no user session here. Paddle's servers are
# the caller, and the signature in the Paddle-Signature header is the authentication.
# The payment provider's handle_webhook() verifies that signature with
# hmac.compare_digest before any event data is read, so an unverified POST cannot
# reach the database writes below.
#
# WHY IT RETURNS 200 EVEN WHEN IT DOES NOTHING: Paddle retries on non-2xx responses.
# An event this server does not recognise is not an error worth retrying, and an
# unprocessable payload that would fail every time must not become an infinite retry
# loop. 200 means "received", not "acted upon".
#
# AND WHY IT NOW RETURNS 503 SOMETIMES. That rule was applied to one case it does not
# cover: a storage failure. "Retrying will not fix it" is true of a payload that is
# malformed in every delivery and false of a database that was briefly unreachable -
# and for a grant_plan event, 200 on a failed write means a customer has been charged
# and will never be granted anything, because nothing will ever deliver that event
# again. So the split is by CAUSE, not by convenience: permanent problems get 200,
# transient ones get 503 and a released claim.
#
# THE RETRIES ARE THE REASON FOR THE CLAIM. Paddle guarantees at-least-once delivery
# and gives a handler five seconds to answer, so a slow reply does not lose an event -
# it duplicates one. Every delivery is de-duplicated on Paddle's event_id before any
# write happens.
# ============================================================================
@app.post("/billing/webhook")
async def billing_webhook(request: Request) -> dict:
    # THE RAW BODY IS READ HERE AND PASSED AS BYTES. This is load-bearing: Paddle
    # signs the raw body, and re-serialising parsed JSON changes whitespace, which
    # changes bytes, which breaks the HMAC. FastAPI's Pydantic model would parse
    # first - so this endpoint takes the raw Request instead.
    body = await request.body()

    # Headers as a plain dict with lowercase keys, matching what the provider
    # expects. FastAPI's Headers object is case-insensitive, but the dict the
    # provider receives should be too - and dict(request.headers) lowercases keys
    # because that is what Starlette does.
    headers = dict(request.headers)

    provider = payments.get_provider()
    result = await provider.handle_webhook(headers=headers, body=body)

    if result is None:
        # Signature failed, header missing, or event not recognised.
        # 200 so Paddle does not retry. Nothing was processed.
        return {"ok": True, "action": "ignored"}

    action = result.get("action")
    user_id = result.get("user_id")
    event_id = result.get("event_id", "")

    # ------------------------------------------------------------------
    # IDEMPOTENCY: claim the event before anything is written.
    #
    # Paddle guarantees at-least-once delivery and retries anything that has not
    # answered 200 within five seconds. Both of those produce a second delivery of
    # one payment, and without this claim each delivery writes another receipt and
    # grants another thirty days. The claim is an atomic insert keyed on Paddle's
    # own event_id, so the second delivery loses the race rather than repeating the
    # work - see database.claim_webhook_event.
    #
    # An event with no id cannot be de-duplicated, so it is not claimed. That is
    # the mock provider's case rather than Paddle's; the unique index on
    # orders.providerRef is what keeps even that from writing two receipts.
    # ------------------------------------------------------------------
    claimed = False

    if event_id:
        try:
            claimed = await database.claim_webhook_event(
                event_id, provider=payments.provider_name()
            )
        except database.StorageError:
            # We cannot tell whether this event was already processed, so we must
            # not guess. 503 asks Paddle to redeliver, and the claim attempt is
            # idempotent - trying again is safe.
            print(f"[webhook] could not claim event {event_id} - asking for retry")
            raise HTTPException(
                status_code=503,
                detail="Could not record the event. Please redeliver.",
            )

        if not claimed:
            # Already processed. 200, because this is a success: the work behind
            # this event is done, which is exactly what Paddle wants to hear.
            print(f"[webhook] event {event_id} already processed - duplicate")
            return {"ok": True, "action": "duplicate"}
    else:
        print(f"[webhook] {action} event carries no event_id - not de-duplicated")

    # PYTHON-SPECIFIC: bare `except Exception` then `raise` re-raises the original
    # with its traceback intact. The breadth is deliberate - set_user_plan does not
    # wrap pymongo's errors the way create_order does, so the failures that must
    # release this claim are not all one type, and a claim held by a delivery that
    # died is a claim that silently suppresses every retry that could fix it.
    try:
        return await _apply_webhook_action(result, action, user_id, event_id)
    except Exception:
        if claimed:
            await database.release_webhook_event(event_id)
        raise


# WHY THE DISPATCH LIVES IN ITS OWN FUNCTION
# The route above owns exactly one concern: has this event already been handled, and
# if handling fails, hand the claim back so it can be handled later. Everything below
# owns what an event MEANS. Keeping them apart is what lets the claim be released on
# every failure path with one try/except, rather than a release call before each of
# the dozen returns in here - and a release somebody forgets to add to a new branch
# is a payment that can never be retried.
#
# It takes what the route already parsed rather than the request, so it does no I/O
# it does not need and is callable directly from a test.
async def _apply_webhook_action(
    result: dict, action: str | None, user_id: str, event_id: str
) -> dict:
    # Every action below needs a user. If custom_data did not carry a user_id,
    # there is nothing to act on - log it and move on.
    if not user_id:
        print(f"[webhook] {action} event {event_id} has no user_id - skipping")
        return {"ok": True, "action": "skipped", "reason": "no_user_id"}

    # ------------------------------------------------------------------
    # ACTION: grant_plan
    # The primary case. A transaction completed - write the order and
    # grant the plan, matching the "granted" branch of the checkout
    # endpoint line for line.
    # ------------------------------------------------------------------
    if action == "grant_plan":
        plan_id = result.get("plan_id")
        plan = billing.find_plan(plan_id) if plan_id else None

        if not plan:
            print(
                f"[webhook] grant_plan for user {user_id}: plan "
                f"{plan_id!r} not found in catalogue - skipping"
            )
            return {"ok": True, "action": "skipped", "reason": "unknown_plan"}

        user = await database.find_user_by_id(user_id)

        if not user:
            print(f"[webhook] grant_plan: user {user_id} not found - skipping")
            return {"ok": True, "action": "skipped", "reason": "unknown_user"}

        now = datetime.now(timezone.utc)
        period_end = billing.period_end(plan, now)
        order_id = auth.new_user_id()

        payment_method = result.get("payment_method") or {}

        order = {
            "id": order_id,
            "userId": user_id,
            "planId": plan["id"],
            "planName": plan["name"],
            "amountCents": plan["amountCents"],
            "currency": plan["currency"],
            "interval": plan["interval"],
            # "completed" rather than the mock's "authorised" - Paddle confirmed
            # the payment landed, so this is the truth.
            "status": "completed",
            "createdAt": now,
            "periodEnd": period_end,
            "cardBrand": payment_method.get("brand"),
            "cardLast4": payment_method.get("last4"),
            "providerRef": result.get("transaction_id"),
        }

        try:
            await database.create_order(order)
        except database.StorageError:
            print(f"[webhook] grant_plan: could not write order for user {user_id}")
            # THIS USED TO RETURN 200 WITH {"ok": False}, and the comment that
            # argued for it said "retrying will not fix a storage problem". That
            # reasoning is right for an unparseable payload and wrong here. A
            # transient Mongo blip is the one failure a retry DOES fix, and 200
            # tells Paddle never to send this event again - leaving a customer who
            # has been charged with no order, no plan, and no code path left in the
            # repo that would ever produce either.
            #
            # 503 asks Paddle to redeliver. The claim is released by the caller on
            # the way out, so the redelivery is not rejected as a duplicate.
            raise HTTPException(
                status_code=503,
                detail="Could not record the order. Please redeliver this event.",
            )

        subscription = {
            "planId": plan["id"],
            "status": "active",
            "startedAt": now,
            "currentPeriodEnd": period_end,
            "cancelAtPeriodEnd": False,
            "cardBrand": payment_method.get("brand"),
            "cardLast4": payment_method.get("last4"),
            "orderId": order_id,
            # The Paddle subscription id, stored so future webhook events about
            # this subscription can be correlated.
            "paddleSubscriptionId": result.get("subscription_id"),
        }

        await database.set_user_plan(user_id, plan["id"], subscription)

        print(
            f"[webhook] grant_plan: user {user_id} -> {plan['name']} "
            f"(order {order_id}, txn {result.get('transaction_id')})"
        )
        return {"ok": True, "action": "grant_plan"}

    # ------------------------------------------------------------------
    # ACTION: payment_failed
    # Log the attempt. Do not change the plan - a failed renewal is not
    # a cancellation, and Paddle will retry before escalating to
    # subscription.past_due or subscription.canceled.
    # ------------------------------------------------------------------
    if action == "payment_failed":
        print(
            f"[webhook] payment_failed: user {user_id}, "
            f"txn {result.get('transaction_id')}"
        )
        return {"ok": True, "action": "payment_failed"}

    # ------------------------------------------------------------------
    # ACTION: cancel_at_period_end
    # Paddle says the subscription is cancelled. Set the flag so access
    # continues until the period ends, then lapses on the next read -
    # exactly what the manual POST /billing/cancel does.
    # ------------------------------------------------------------------
    if action == "cancel_at_period_end":
        user = await database.find_user_by_id(user_id)

        if not user or not user.get("subscription"):
            print(
                f"[webhook] cancel_at_period_end: user {user_id} has no "
                "subscription - skipping"
            )
            return {"ok": True, "action": "skipped", "reason": "no_subscription"}

        updated_subscription = dict(user["subscription"])
        updated_subscription["cancelAtPeriodEnd"] = True
        updated_subscription["status"] = "cancelling"

        # If Paddle sent a period end date, use it - it is the authoritative
        # answer. Otherwise keep whatever we already have.
        period_ends_at = result.get("period_ends_at")
        if period_ends_at:
            try:
                updated_subscription["currentPeriodEnd"] = datetime.fromisoformat(
                    period_ends_at
                )
            except (ValueError, TypeError):
                pass  # keep the existing date

        plan_id = (
            updated_subscription.get("planId")
            or user.get("planId")
            or billing.DEFAULT_PLAN_ID
        )
        await database.set_user_plan(user_id, plan_id, updated_subscription)

        print(f"[webhook] cancel_at_period_end: user {user_id}")
        return {"ok": True, "action": "cancel_at_period_end"}

    # ------------------------------------------------------------------
    # ACTION: flag_past_due
    # The subscription's payment is overdue. Set the status so the user
    # can be warned, but do NOT revoke access - Paddle may still recover
    # the payment automatically.
    # ------------------------------------------------------------------
    if action == "flag_past_due":
        user = await database.find_user_by_id(user_id)

        if not user or not user.get("subscription"):
            print(
                f"[webhook] flag_past_due: user {user_id} has no "
                "subscription - skipping"
            )
            return {"ok": True, "action": "skipped", "reason": "no_subscription"}

        updated_subscription = dict(user["subscription"])
        updated_subscription["status"] = "past_due"

        plan_id = (
            updated_subscription.get("planId")
            or user.get("planId")
            or billing.DEFAULT_PLAN_ID
        )
        await database.set_user_plan(user_id, plan_id, updated_subscription)

        print(f"[webhook] flag_past_due: user {user_id}")
        return {"ok": True, "action": "flag_past_due"}

    # ------------------------------------------------------------------
    # ACTION: sync_subscription
    # The subscription was updated - a plan change, a renewal, or a
    # status change. Sync the billing period and, if the price changed,
    # the plan.
    # ------------------------------------------------------------------
    if action == "sync_subscription":
        user = await database.find_user_by_id(user_id)

        if not user or not user.get("subscription"):
            print(
                f"[webhook] sync_subscription: user {user_id} has no "
                "subscription - skipping"
            )
            return {"ok": True, "action": "skipped", "reason": "no_subscription"}

        updated_subscription = dict(user["subscription"])

        # Sync the status if Paddle sent one.
        paddle_status = result.get("status")
        if paddle_status:
            # Map Paddle's status names to the ones this app uses.
            status_map = {
                "active": "active",
                "past_due": "past_due",
                "canceled": "cancelling",
                "paused": "paused",
                "trialing": "active",
            }
            updated_subscription["status"] = status_map.get(
                paddle_status, paddle_status
            )

        # Sync the billing period dates.
        period_ends_at = result.get("period_ends_at")
        if period_ends_at:
            try:
                updated_subscription["currentPeriodEnd"] = datetime.fromisoformat(
                    period_ends_at
                )
            except (ValueError, TypeError):
                pass

        period_starts_at = result.get("period_starts_at")
        if period_starts_at:
            try:
                updated_subscription["startedAt"] = datetime.fromisoformat(
                    period_starts_at
                )
            except (ValueError, TypeError):
                pass

        # If the price changed, try to resolve the new plan from the catalogue.
        # The webhook handler extracts the price_id from items[0]; we walk
        # billing.PLANS to find which plan has that price_id configured.
        current_price_id = result.get("current_price_id")
        resolved_plan_id = None
        if current_price_id:
            for plan in billing.PLANS:
                if not plan["purchasable"]:
                    continue
                if config.paddle_price_id(plan["id"]) == current_price_id:
                    resolved_plan_id = plan["id"]
                    break

        # Use the resolved plan, or fall back to what the webhook carried, or
        # what the subscription already has.
        plan_id = (
            resolved_plan_id
            or result.get("plan_id")
            or updated_subscription.get("planId")
            or user.get("planId")
            or billing.DEFAULT_PLAN_ID
        )
        updated_subscription["planId"] = plan_id

        # If Paddle says the subscription is no longer cancelled, clear the flag.
        if paddle_status == "active":
            updated_subscription["cancelAtPeriodEnd"] = False

        await database.set_user_plan(user_id, plan_id, updated_subscription)

        print(f"[webhook] sync_subscription: user {user_id} -> plan {plan_id}")
        return {"ok": True, "action": "sync_subscription"}

    # An action this endpoint does not know about - logged, not crashed.
    print(f"[webhook] unknown action {action!r} from event {event_id} - ignoring")
    return {"ok": True, "action": "ignored"}


# WHY THIS EXISTS
# Leaving a paid plan. Flags the subscription to end when the period it has already
# been paid for runs out, and leaves the entitlements in place until then.
#
# THIS USED TO BE IMMEDIATE, AND THE COMMENT THAT ARGUED FOR IT IS WORTH KEEPING
# RATHER THAN QUIETLY DELETING. It said: end-of-period cancellation is the kinder
# behaviour and the one a real product wants, but it needs a scheduled job to do the
# downgrade when the date arrives - and a `cancelAtPeriodEnd` flag with nothing
# running to honour it is worse than not offering it, because the account keeps its
# entitlements forever. Immediate is honest about what the system can actually do.
#
# THE HOLE IN THAT ARGUMENT WAS THE PREMISE. The flag does not need a scheduler; it
# needs the READ to be period-aware, and every read happens inside a request that
# already knows what time it is. billing.effective_plan_for_user() does the
# comparison, _public_user() calls it, and every page in the app is therefore
# correct about a lapsed subscription with nothing running in the background. See
# the section at the bottom of billing.py.
#
# So the kinder behaviour is now the one the system can actually do. A customer who
# cancels on day 3 of a month they paid for keeps it until day 30, which is what
# they paid for.
#
# THE ORDERS SURVIVE, unchanged from before. A cancellation does not un-buy the
# months already paid for, and the billing history stays readable - which is the
# property that makes the ledger worth having.
@app.post("/billing/cancel")
async def cancel_subscription(user: dict = Depends(require_session)) -> dict:
    subscription = user.get("subscription")

    if not subscription:
        # 400 rather than a silent success. "Cancel" on an account with nothing to
        # cancel is a UI that is out of step with the server, and saying so is more
        # useful than pretending it worked.
        raise HTTPException(
            status_code=400, detail="There is no paid plan on this account to cancel."
        )

    # ALREADY CANCELLED IS NOT AN ERROR, and this is the one place that differs from
    # the immediate version, which had no such state to be in. Pressing cancel twice
    # is a double-click or a stale tab, and the second press is asking for exactly
    # the state the account is already in. Refusing it would be pedantry.
    if not subscription.get("cancelAtPeriodEnd"):
        # PYTHON-SPECIFIC: dict(...) copies before mutating, so the sub-document held
        # by the caller's `user` is not altered under it. set_user_plan's $set
        # replaces the whole subscription anyway - see the note on that function - so
        # the copy has to be complete rather than a patch.
        updated_subscription = dict(subscription)
        updated_subscription["cancelAtPeriodEnd"] = True
        # "cancelling", not "cancelled". The plan is still active and still granting
        # what it grants; what has changed is that it will not renew. A status field
        # saying "cancelled" beside working entitlements would be the one lie in the
        # database.
        updated_subscription["status"] = "cancelling"

        await database.set_user_plan(
            user["id"], subscription.get("planId") or user.get("planId") or
            billing.DEFAULT_PLAN_ID, updated_subscription
        )

    # A subscription with no currentPeriodEnd - Free or a hand-edited record - has no
    # period to run out, so billing.subscription_has_lapsed() treats the flag as
    # immediate and this reconcile completes the downgrade in the same request. That
    # is why the response below is built from the reconciled user rather than from
    # the values just written.
    updated = await _reconcile_lapsed_plan(
        await database.find_user_by_id(user["id"]) or user
    )

    return {
        "cancelled": True,
        "plan": billing.public_plan(billing.effective_plan_for_user(updated)),
        "subscription": _public_subscription(
            billing.effective_subscription(updated.get("subscription"))
        ),
        "user": _public_user(updated),
    }


# WHY THIS EXISTS
# Undoing a cancellation that has not taken effect yet.
#
# WHY IT IS NOT OPTIONAL: end-of-period cancellation creates a window - days or
# weeks - in which the plan is live and scheduled to stop. Without this endpoint a
# customer who changed their mind inside that window has no way back except buying
# again, and buying again would charge them for a period they have already paid for.
# A flag a user can set and cannot unset is a trap, and shipping the cancel half
# without this half would be shipping the trap.
#
# WHAT IT DELIBERATELY WILL NOT DO IS REVIVE A LAPSED PLAN. Once the period has run
# out the entitlement is genuinely gone and resuming would mean granting a month
# nobody paid for. That case gets a 400 pointing at checkout, which is the honest
# answer: this is not a cancellation to undo any more, it is a new purchase.
@app.post("/billing/resume")
async def resume_subscription(user: dict = Depends(require_session)) -> dict:
    subscription = user.get("subscription")

    if not subscription or not subscription.get("cancelAtPeriodEnd"):
        raise HTTPException(
            status_code=400,
            detail="There is no scheduled cancellation on this account to resume.",
        )

    # CHECKED BEFORE THE WRITE, because the flag being set is not enough - the date
    # matters. An account whose period ended last week has a `cancelAtPeriodEnd` that
    # is still true and a plan that is already over.
    if billing.subscription_has_lapsed(subscription):
        # The tidy-up happens here too, so the account the user is looking at stops
        # claiming a plan it no longer has the moment they touch this button.
        await _reconcile_lapsed_plan(user)

        raise HTTPException(
            status_code=400,
            detail="That plan has already ended. Choose a plan to start a new one.",
        )

    restored = dict(subscription)
    restored["cancelAtPeriodEnd"] = False
    restored["status"] = "active"

    await database.set_user_plan(
        user["id"], subscription.get("planId") or user.get("planId") or
        billing.DEFAULT_PLAN_ID, restored
    )

    updated = await database.find_user_by_id(user["id"]) or user

    return {
        "resumed": True,
        "plan": billing.public_plan(billing.effective_plan_for_user(updated)),
        "subscription": _public_subscription(
            billing.effective_subscription(updated.get("subscription"))
        ),
        "user": _public_user(updated),
    }
