"""
MONGODB PERSISTENCE - the one file that knows a database exists.

WHY THIS FILE EXISTS
Before this, a scan existed only inside the HTTP response that returned it: run a
scan, and the result was gone the moment the browser navigated. That is why the
report page had nothing to load. Persisting the scan is what turns a scan result
into a URL you can refresh, bookmark and send to a client.

It is a separate file so that the rest of the code never mentions MongoDB.
engine.py does not know results get saved; main.py calls save_scan() and
find_scan() without knowing what is underneath. Swapping Mongo for Postgres later
would be a rewrite of THIS FILE ONLY.

Driver note: this uses pymongo's AsyncMongoClient, not Motor. Motor was the async
MongoDB driver for years but is now end-of-life; async support moved into pymongo
itself. Anything you read online recommending `motor` is out of date.
"""

from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from pymongo import AsyncMongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError

import config

# WHY THIS READS FROM config RATHER THAN os.environ
# It used to call os.environ.get() directly here, which was right while there was
# exactly one setting. Auth brought six more, so every environment variable now
# comes from config.py - which is also the only module that loads the .env file.
# Reading os.environ here as well would mean this one setting worked differently
# from the other six, and would work or not depending on which directory the
# server was started from.
MONGO_URL = config.MONGO_URL

DATABASE_NAME = "secuscan"
COLLECTION_NAME = "scans"

# Five collections in one database. Users and sessions are separate documents
# rather than a list of sessions embedded in the user record, because a session
# expires and a user does not - and MongoDB can delete an expired document by
# itself (see the TTL index in connect()) only when that document is the whole
# thing being expired.
USERS_COLLECTION = "users"
SESSIONS_COLLECTION = "sessions"

# WHY TWO MORE COLLECTIONS FOR TWO-FACTOR AUTHENTICATION
#
# CHALLENGES holds the half-finished login: the password was right, the second
# factor has not been supplied yet. It cannot be a session, because a session IS
# access - anything holding one can read scans - and the whole purpose of the
# second factor is that the password alone grants nothing.
#
# EMAIL_CODES holds an issued recovery code. Separate from the challenge because
# the two have different lifetimes and different attempt counters, and because a
# user may request a code, give up, and finish with their authenticator instead.
#
# Both are short-lived and both get a TTL index, so an abandoned login cleans
# itself up rather than accumulating forever.
CHALLENGES_COLLECTION = "challenges"
EMAIL_CODES_COLLECTION = "email_codes"

# WHY BILLING GETS ITS OWN COLLECTION AND THE PLAN DOES NOT
#
# ORDERS is the ledger: one document per completed checkout, written once and never
# updated. That is the whole design intent - an order is a record of something that
# HAPPENED, so nothing in this file offers a way to change one. When a plan changes
# hands the ledger grows a row rather than editing a previous one, which is what
# makes the billing history screen trustworthy and a refund a new entry rather than
# a deletion.
#
# THE CURRENT PLAN, by contrast, lives on the user document as `planId` plus a small
# `subscription` sub-document. It is the answer to "what may this account do right
# now", it is read on every request that checks a limit, and it can never outlive or
# be shared by the account - the same three arguments that put the 2FA fields there.
# Deriving it from the ledger instead would mean sorting a growing list of orders to
# answer a question asked constantly.
#
# So: one mutable field saying what is true now, one immutable log saying how it got
# that way. Neither can be reconstructed from the other and both are cheap.
ORDERS_COLLECTION = "orders"

# WHY TIER 2 SCAN CREDENTIALS LIVE IN THEIR OWN COLLECTION
# Tier 2 test accounts (staging URL, username, encrypted password blob) are strictly
# scoped to a specific scanId and userId. Storing them separate from the scan document
# ensures scan result export / display never touches or leaks test credentials.
# Documents in this collection carry a TTL index on `expiresAt` (default 24h) so
# credentials automatically expire and are purged even if manual cleanup is missed.
CREDENTIALS_COLLECTION = "scan_credentials"

# WHY WEBHOOK EVENTS GET A COLLECTION OF THEIR OWN
# Paddle guarantees AT-LEAST-ONCE delivery: "your handler may occasionally receive
# the same event more than once". It also retries anything that does not answer 200
# within five seconds - for up to three days on a live account. So a slow reply is
# not a lost event, it is a SECOND event carrying the same payment.
#
# Without a record of what has already been processed, each of those deliveries
# writes another receipt and re-runs set_user_plan with a fresh thirty-day period.
# One sale, N orders, and a subscription that extends itself every time the network
# hiccups. This collection is the record: `_id` is Paddle's own `event_id`, so the
# uniqueness is MongoDB's problem rather than ours, and a duplicate is a failed
# insert instead of a second grant.
#
# It carries a TTL on expiresAt like the auth collections, set to outlive Paddle's
# three-day retry window with room to spare. Unlike ORDERS above, this IS swept -
# it is a de-duplication ledger, not a receipt. Once no retry can still arrive, the
# claim has done its whole job and keeping it forever would grow without bound.
WEBHOOK_EVENTS_COLLECTION = "webhook_events"

# How long a processed-event claim is kept. Paddle's live retry schedule spans three
# days; seven gives margin for a delivery that arrives at the very end of it.
WEBHOOK_EVENT_TTL_DAYS = 7

# PYTHON-SPECIFIC: a module-level variable holding the client, initialised to
# None and filled in at startup. A module in Python is a singleton - it executes
# once, no matter how many files import it - so this is the standard way to share
# one connection across the whole app. Opening a new client per request would
# waste a TCP handshake and a connection-pool setup every time.
_client: AsyncMongoClient | None = None


# WHY THIS EXISTS
# Opening the connection at startup rather than on first use means a
# misconfigured or stopped database fails immediately and loudly, when you are
# looking at the server log - instead of surfacing much later as a mysterious
# 500 on someone's first scan.
async def connect() -> None:
    # PYTHON-SPECIFIC: `global` is required to REASSIGN a module-level variable
    # from inside a function. Without it, Python would treat _client as a new
    # local variable and the assignment would silently vanish when the function
    # returned. Reading a global needs no declaration; only rebinding does.
    global _client

    _client = AsyncMongoClient(MONGO_URL, serverSelectionTimeoutMS=3000)

    # AsyncMongoClient connects lazily, so constructing it above proves nothing.
    # The ping is what actually confirms a reachable server.
    await _client.admin.command("ping")

    # WHY THE INDEXES ARE CREATED HERE
    # The first two are not optimisations. Both are correctness guarantees, which
    # is why they are set up at startup rather than left to a migration nobody
    # runs. create_index is idempotent - running it on every boot is the normal
    # pattern, not a leak.
    #
    # The unique index on email is what actually prevents two accounts sharing one
    # address. The obvious alternative - "look for the email, insert if it is not
    # there" - loses a race between two simultaneous signups: both look, both find
    # nothing, both insert. Only the database can settle that, and a unique index
    # is how you ask it to.
    await _client[DATABASE_NAME][USERS_COLLECTION].create_index("email", unique=True)

    # A TTL ("time to live") index. MongoDB deletes a session document by itself
    # once the timestamp in expiresAt has passed; expireAfterSeconds=0 means
    # "expire at exactly that moment" rather than "never". This makes expiry a
    # property of the data instead of something every read has to remember to
    # check, and a forgotten check is how sessions end up immortal.
    #
    # The sweep runs roughly once a minute, so an expired session can outlive its
    # timestamp briefly - which is why find_session() checks the time as well.
    # The index is the cleanup; the check is the guarantee.
    await _client[DATABASE_NAME][SESSIONS_COLLECTION].create_index(
        "expiresAt", expireAfterSeconds=0
    )

    # The one index here that IS an optimisation rather than a correctness
    # guarantee. list_scans() asks for "this owner's scans, newest first", and a
    # COMPOUND index on both fields in that order answers it without MongoDB
    # reading and sorting every document the owner has.
    #
    # The order of the two fields is the whole point and is not arbitrary: the
    # equality field comes first, the sort field second. Reversed, the index
    # cannot be used to satisfy the filter, and Mongo falls back to sorting in
    # memory - which it refuses outright past 32MB of results.
    await _client[DATABASE_NAME][COLLECTION_NAME].create_index(
        [("userId", 1), ("scannedAt", -1)]
    )

    # A SPARSE unique index on the Google account id, and `sparse` is the whole
    # subtlety. Without it, every password-only account would carry googleId: null,
    # and a unique index treats those nulls as colliding values - so the SECOND
    # password signup would be rejected as a duplicate. Sparse means "index only
    # the documents that actually have this field", which is exactly the intent:
    # one SecuScan account per Google account, and no constraint at all on accounts
    # that do not use Google.
    await _client[DATABASE_NAME][USERS_COLLECTION].create_index(
        "googleId", unique=True, sparse=True
    )

    # TTL indexes for the two short-lived auth collections, the same mechanism as
    # sessions. A login somebody walked away from halfway through disappears by
    # itself, and a recovery code that was emailed and never used stops existing.
    await _client[DATABASE_NAME][CHALLENGES_COLLECTION].create_index(
        "expiresAt", expireAfterSeconds=0
    )

    await _client[DATABASE_NAME][EMAIL_CODES_COLLECTION].create_index(
        "expiresAt", expireAfterSeconds=0
    )

    # The billing history query, which is "this account's orders, newest first" -
    # the same shape as the scans index above, and compound for the same reason:
    # equality field first, sort field second, or MongoDB cannot use the index to
    # satisfy the filter and sorts in memory instead.
    #
    # Note what this collection does NOT get: a TTL index. Everything else with an
    # expiresAt above is a half-finished login that should evaporate. A receipt is
    # the opposite kind of record - it is the thing a customer asks about eighteen
    # months later, so it is never swept.
    await _client[DATABASE_NAME][ORDERS_COLLECTION].create_index(
        [("userId", 1), ("createdAt", -1)]
    )

    # THE BACKSTOP UNDER WEBHOOK IDEMPOTENCY, and deliberately not the only defence.
    # claim_webhook_event below stops a duplicate delivery before it writes; this
    # stops a duplicate RECEIPT even if that logic is bypassed, refactored away, or
    # reached by a path nobody anticipated. One provider transaction can produce at
    # most one order document, enforced by the storage engine rather than by anyone
    # remembering to check.
    #
    # Sparse for the same reason googleId above is: the mock provider writes orders
    # with no providerRef, and a plain unique index treats every missing field as
    # the same null - so the second mock purchase in the system would collide with
    # the first. Sparse indexes "only reference documents that actually have this
    # field", which is exactly the intent.
    await _client[DATABASE_NAME][ORDERS_COLLECTION].create_index(
        "providerRef", unique=True, sparse=True
    )

    # The webhook de-duplication ledger. TTL only - every lookup is by _id, which
    # is indexed by definition, so there is nothing else to index here.
    await _client[DATABASE_NAME][WEBHOOK_EVENTS_COLLECTION].create_index(
        "expiresAt", expireAfterSeconds=0
    )

    # Tier 2 scan credentials TTL and lookup indexes.
    # expiresAt TTL index ensures automatic purge after the retention window (e.g. 24h).
    # Compound unique index on (scanId, userId) enforces strict ownership and lookup.
    await _client[DATABASE_NAME][CREDENTIALS_COLLECTION].create_index(
        "expiresAt", expireAfterSeconds=0
    )
    await _client[DATABASE_NAME][CREDENTIALS_COLLECTION].create_index(
        [("scanId", 1), ("userId", 1)], unique=True
    )


# WHY THIS EXISTS
# Closing the connection pool on shutdown lets MongoDB release its side of the
# sockets promptly. Skipping it mostly works and then produces confusing
# connection-limit warnings under --reload, which restarts the process often.
async def disconnect() -> None:
    global _client

    if _client is not None:
        await _client.close()
        _client = None


# WHY THIS EXISTS
# Every function below needs the same collection handle, and every one of them
# would otherwise repeat the same three-step lookup and the same "did we
# connect?" check. Centralising it means a forgotten startup produces one clear
# error message instead of an AttributeError on None.
# The default keeps every existing call site reading exactly as it did before
# the accounts collections arrived.
def _get_collection(name: str = COLLECTION_NAME):
    if _client is None:
        # PYTHON-SPECIFIC: RuntimeError is a built-in exception type. `raise` is
        # Python's `throw`.
        raise RuntimeError(
            "Database not connected. connect() runs in the FastAPI lifespan in "
            "main.py - if you see this, the app started without it."
        )

    # PYTHON-SPECIFIC: pymongo overloads the [] operator, so client[db][coll]
    # reads like dictionary access but is really "database, then collection".
    # Neither has to exist beforehand - MongoDB creates both on first write,
    # which is why there is no schema or migration step here.
    return _client[DATABASE_NAME][name]


# WHY THIS EXISTS
# The scan result has to outlive the request that produced it, or the report page
# has nothing to load. This is the write half of that.
#
# It deliberately does NOT raise on failure. A scan that ran correctly but could
# not be filed is still a valid result the caller should receive - losing the
# findings because of a database hiccup would be the worse outcome. The endpoint
# checks the return value to decide whether the scan is retrievable later.
#
# OWNERSHIP IS SET HERE AND NOWHERE ELSE. user_id is a required argument rather
# than an optional one on purpose: an optional owner is an owner somebody forgets
# to pass, and a scan saved without one is invisible to its owner's history and
# excluded from every access check that follows. Making it required means that
# mistake is a TypeError at import time, not a silent data problem in production.
async def save_scan(scan: dict, user_id: str) -> bool:
    collection = _get_collection()

    # MongoDB's primary key field is always called _id. Using our own short id as
    # the _id means one canonical identifier instead of two: no ObjectId to
    # translate, and the URL /dashboard/scan/<id> maps straight to a _id lookup.
    #
    # PYTHON-SPECIFIC: {**scan, "_id": ...} is dictionary unpacking - it builds a
    # NEW dict containing everything from scan plus the extra key. Identical in
    # spirit to JS object spread, { ...scan, _id: ... }. Building a copy matters:
    # mutating the caller's dict would add a stray _id to the JSON response.
    # userId is added to the STORED document only. It is deliberately not part
    # of the scan contract the engine produces or the API returns - the browser
    # already knows who is signed in, so sending the id back would be telling it
    # something it has no use for, and every field an API returns is a field
    # somebody eventually depends on.
    target_host = (urlparse(scan.get("targetUrl", "")).hostname or "").lower()
    document = {**scan, "_id": scan["id"], "userId": user_id, "targetHost": target_host}

    try:
        await collection.insert_one(document)
        return True
    except PyMongoError:
        # Swallowed on purpose - see the note above about not losing findings.
        return False


# WHY THIS EXISTS
# Both read paths below have to strip the same internal fields before a
# document can go out as JSON, and "strip the fields the client must not see" is
# exactly the kind of step that gets remembered in one function and forgotten in
# the next one somebody adds. One helper, called by both.
#
#   _id        - a duplicate; the scan already carries the same value in "id".
#   userId     - server-side bookkeeping. It leaks nothing dangerous, but the shared
#                report endpoint serves strangers, and an owner id is not theirs.
#   targetHost - internal query acceleration field.
def _public_scan(document: dict) -> dict:
    document.pop("_id", None)
    document.pop("userId", None)
    document.pop("targetHost", None)
    return document


# WHY THIS EXISTS
# The read half, and the reason the report page can exist at a URL at all. Given
# an id from the address bar, hand back the scan that was stored under it.
#
# Returns None rather than raising when nothing matches, because "no such scan"
# is an ordinary outcome - someone edits the URL, or follows a stale link - and
# the endpoint turns it into a 404. Exceptions are for the unexpected.
#
# THE ACCESS CHECK IS THE FILTER, which is the part worth looking at twice. The
# owner is a condition in the query rather than an `if` after it:
#
#     find_one({"_id": scan_id, "userId": user_id})   <- this
#     doc = find_one({"_id": scan_id})                <- not this
#     if doc["userId"] != user_id: ...
#
# Both are correct today. The first stays correct when somebody later adds an
# early return above the check, or reorders the function, or forgets it entirely
# in a new code path - because there is no moment in between where the document
# exists in a variable without having been authorised. A check you cannot skip
# beats a check you must remember.
#
# It also means "no such scan" and "not your scan" are the same answer. That is
# deliberate: a 403 would confirm the id belongs to somebody, which is a small
# fact an attacker enumerating ids would very much like to have.
async def find_scan(scan_id: str, user_id: str) -> dict | None:
    collection = _get_collection()

    document = await collection.find_one({"_id": scan_id, "userId": user_id})

    if document is None:
        return None

    return _public_scan(document)


# WHY THIS EXISTS
# The same lookup with the owner check deliberately absent, so that a report link
# forwarded to somebody without an account still opens. It is a SEPARATE FUNCTION
# rather than an optional argument on the one above, and the name says what it
# does, because "find_scan(scan_id)" with the owner left off would be the exact
# shape of an accidental authorisation bypass - it would read like a normal call
# and quietly skip the check.
#
# BE CLEAR ABOUT WHAT PROTECTS THIS: nothing but the 8-character id. That is 4.3
# billion values, which is not guessable one at a time but is not a permission
# either - anyone who has the link, or a proxy log or browser history containing
# it, can read the report. That is the accepted trade for a shareable document,
# and it is why exactly one endpoint calls this function.
#
# The upgrade, when it is needed: a per-share token the owner generates and can
# revoke, so a link can be withdrawn and the scan id stops being the credential.
async def find_shared_scan(scan_id: str) -> dict | None:
    document = await _get_collection().find_one({"_id": scan_id})

    if document is None:
        return None

    return _public_scan(document)


# WHY THIS EXISTS
# The dashboard and the history page both answer "what have I scanned before?",
# which no amount of fetching one scan at a time can answer - the browser does
# not know the ids until it has the list. This is that list.
#
# It returns whole scan documents rather than summaries. That looks wasteful and
# is the right call for now: the pages need per-scan severity counts, so a
# trimmed summary would have to carry them anyway, and the honest moment to add a
# projection is when a real account has enough scans for it to matter.
#
# THIS FUNCTION USED TO RETURN EVERY SCAN IN THE DATABASE. It was written that
# way when there were no accounts and one person ran everything, with a note in
# main.py saying it had to gain an owner filter the moment accounts existed. This
# is that filter. Left undone, the first thing signing in would have bought a
# user is the ability to read every other user's scan history.
#
# user_id is required, for the same reason it is required in save_scan: the
# version of this bug that actually ships is not somebody deciding to expose
# everything, it is somebody calling a function with an optional filter and not
# passing it.
async def list_scans(user_id: str, limit: int = 50) -> list:
    collection = _get_collection()

    # PYTHON-SPECIFIC: find(filter) returns a CURSOR, not a list: nothing is
    # fetched until you iterate it, which is why the async for below is doing the
    # real work. This is the query the compound index in connect() was built for.
    #
    # Sorting by scannedAt descending puts newest first, which is the order both
    # pages want. -1 means descending; 1 would be ascending.
    cursor = collection.find({"userId": user_id}).sort("scannedAt", -1).limit(limit)

    # PYTHON-SPECIFIC: `async for` iterates something that produces values
    # asynchronously, awaiting each batch from the database as it goes. A plain
    # `for` would fail here - the cursor is an async iterator, not a list.
    scans = []
    async for document in cursor:
        scans.append(_public_scan(document))

    return scans


# WHY THIS EXISTS
# Counts how many scans a user has executed, optionally since a given cutoff
# timestamp. Used by main.py to enforce plan scanLimit per billing period.
async def count_user_scans(user_id: str, since: datetime | str | None = None) -> int:
    collection = _get_collection()
    query = {"userId": user_id}
    if since:
        since_iso = since.isoformat() if isinstance(since, datetime) else str(since)
        query["scannedAt"] = {"$gte": since_iso}
    try:
        return await collection.count_documents(query)
    except PyMongoError:
        return 0


# WHY THIS EXISTS
# Returns the distinct target hostnames a user has scanned, optionally since a
# given cutoff timestamp. Used by main.py to enforce plan siteLimit.
# Collects both targetHost (indexed on newer documents) and falls back to
# parsing targetUrl so older scans are accounted for seamlessly.
async def get_user_distinct_sites(
    user_id: str, since: datetime | str | None = None
) -> list[str]:
    collection = _get_collection()
    query = {"userId": user_id}
    if since:
        since_iso = since.isoformat() if isinstance(since, datetime) else str(since)
        query["scannedAt"] = {"$gte": since_iso}
    try:
        cursor = collection.find(query, {"targetHost": 1, "targetUrl": 1})
        sites = set()
        async for document in cursor:
            host = document.get("targetHost")
            if not host and document.get("targetUrl"):
                host = (urlparse(document["targetUrl"]).hostname or "").lower()
            if host:
                sites.add(host)
        return sorted(list(sites))
    except PyMongoError:
        return []


# ============================================================================
# ACCOUNTS
#
# Everything below stores people rather than scans. It lives in this file for the
# same reason the scan functions do: main.py should be able to ask "is this email
# taken" without knowing that the answer involves a unique index in MongoDB.
# ============================================================================


# WHY THIS EXISTS
# MongoDB names the primary key `_id`, and the rest of the codebase calls it `id`.
# Rather than leaking that difference into every caller - or into JSON responses,
# where a leading underscore looks like an accident - the translation happens once,
# here.
#
# Note what this does NOT do: it does not strip passwordHash. Callers need it, in
# exactly one place, to verify a login. Keeping it means main.py has to build its
# responses field by field instead of returning the record wholesale, which is the
# right habit anyway - a wholesale return is how a password hash ends up in an API
# response after someone adds a column six months from now.
def _with_id(document: dict | None) -> dict | None:
    if document is None:
        return None

    # PYTHON-SPECIFIC: dict.pop(key) removes the key AND returns its value, so
    # this is a rename in one line. The dict came fresh from the driver, so
    # mutating it affects nobody else.
    document["id"] = document.pop("_id")
    return document


# WHY THIS EXISTS
# Account creation. Returns True when the account was made and False when the
# email is already registered - a boolean rather than an exception, because
# "somebody already signed up with that address" is an ordinary outcome of a
# signup form, not a fault.
#
# The duplicate is caught rather than pre-checked. That is the whole point of the
# unique index in connect(): the database is the only component that can decide
# uniqueness without a race, so the code asks it to try and then reads its answer.
async def create_user(user: dict) -> bool:
    collection = _get_collection(USERS_COLLECTION)

    # Same copy-then-add pattern as save_scan: build a new dict rather than
    # mutating the caller's, so nothing upstream ends up carrying a stray _id.
    document = {**user, "_id": user["id"]}
    document.pop("id", None)

    try:
        await collection.insert_one(document)
        return True
    except DuplicateKeyError:
        # PYTHON-SPECIFIC: DuplicateKeyError is raised for ANY unique index
        # violation on the collection. There is only one such index here, so it
        # can only mean the email - worth knowing before a second unique index
        # gets added and makes this message a lie.
        return False


# WHY THIS EXISTS
# The lookup a login is built on. Email is the identifier people type, so it is
# what gets searched - and because the unique index in connect() is on the same
# field, this is an index hit rather than a scan of every account.
#
# Callers must pass an already-normalised address. That responsibility sits in
# auth.normalise_email() rather than here, so there is one definition of "the same
# email" shared by the write path and the read path.
async def find_user_by_email(email: str) -> dict | None:
    return _with_id(await _get_collection(USERS_COLLECTION).find_one({"email": email}))


# WHY THIS EXISTS
# The lookup a SESSION is built on. A session document stores a user id, never a
# copy of the user - so the name and email shown to a signed-in person are read
# fresh here on each request rather than frozen at the moment they logged in.
async def find_user_by_id(user_id: str) -> dict | None:
    return _with_id(await _get_collection(USERS_COLLECTION).find_one({"_id": user_id}))


# WHY THIS EXISTS
# Records a login. The document holds the HASH of the session token as its `_id`,
# never the token - see auth.hash_token() for why. Using the hash as the primary
# key is deliberate: looking a session up is then the fastest operation MongoDB
# has, and it happens on every single authenticated request.
async def create_session(session: dict) -> None:
    document = {**session, "_id": session["tokenHash"]}
    document.pop("tokenHash", None)

    await _get_collection(SESSIONS_COLLECTION).insert_one(document)


# WHY THIS EXISTS
# Turns a token from an incoming request back into the session it represents, or
# None. This is the function that decides whether a request is authenticated, so
# it is the one place where being sloppy would hand out somebody else's account.
#
# It re-checks the expiry even though a TTL index already exists. The TTL sweep is
# periodic, roughly once a minute, so there is a window in which an expired
# document is still present - and "expired but not yet swept" must not count as
# logged in.
async def find_session(token_hash: str) -> dict | None:
    document = await _get_collection(SESSIONS_COLLECTION).find_one({"_id": token_hash})

    if document is None:
        return None

    if _has_expired(document.get("expiresAt")):
        return None

    document["tokenHash"] = document.pop("_id")
    return document


# WHY THIS EXISTS
# Four collections now store an expiresAt and all four have to re-check it on read,
# because the TTL index sweeps about once a minute and "expired but not yet deleted"
# must never count as valid. This was written inline in find_session first; the
# fourth copy is where one of them ends up subtly different from the others.
#
# PYTHON-SPECIFIC: pymongo returns datetimes as NAIVE UTC by default - no timezone
# attached - and comparing a naive datetime against an aware one raises TypeError
# rather than returning False. Attaching UTC here is the fix, and this is the right
# place for it because this is where the value re-enters Python.
#
# A missing expiresAt returns False - not expired. Nothing writes such a document
# today; treating the absence as "expired" would silently invalidate every session if
# a future write ever omitted the field, which is a worse failure than the reverse.
def _has_expired(expires_at: datetime | None) -> bool:
    if expires_at is None:
        return False

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    return expires_at <= datetime.now(timezone.utc)


# WHY THIS EXISTS
# Signing out. Deleting the row is what makes a logout real: the token in the
# browser still exists, and the only thing that stops it working is the absence of
# this record. That is the practical advantage of server-side sessions over a
# self-contained token - a JWT cannot be un-issued.
#
# Deleting something that is not there is not an error. A double-clicked sign-out
# button should not produce a failure.
async def delete_session(token_hash: str) -> None:
    await _get_collection(SESSIONS_COLLECTION).delete_one({"_id": token_hash})


# WHY THIS EXISTS
# "Sign out everywhere" - the button on the settings page for somebody who thinks
# their password is known. delete_session above can only revoke the one token the
# caller is holding, which is useless against an attacker holding a different one.
#
# WHY THE FILTER IS userId AND NOT _id, which is the whole reason this needs its own
# function: sessions are keyed by the HASH of their token, and the server does not
# keep the tokens. So there is no way to enumerate a user's sessions by identity and
# delete them one at a time - the query has to go the other way, from the account to
# every document pointing at it. That is what the userId field on the session
# document (see _start_session in main.py) is for.
#
# MONGO: delete_many, not delete_one. delete_one would remove ONE arbitrary session
# and report success, which on a security action is the worst kind of bug - it does
# something, so it looks like it worked.
#
# Returns the count so the UI can say "4 other devices signed out" rather than a
# vague "done". MONGO: deleted_count is how many documents actually went.
async def delete_sessions_for_user(user_id: str, except_hash: str | None = None) -> int:
    query: dict = {"userId": user_id}

    # PYTHON-SPECIFIC: the key is added only when there is something to exclude,
    # rather than always writing {"$ne": None}. A $ne against None would match every
    # document whose _id is not null - which is all of them - and happens to be
    # harmless here, but the habit of building a filter conditionally is what keeps a
    # "keep one" query from silently becoming a "keep none" query.
    if except_hash is not None:
        query["_id"] = {"$ne": except_hash}

    result = await _get_collection(SESSIONS_COLLECTION).delete_many(query)

    return result.deleted_count


# WHY THIS EXISTS
# The write half of a password change. Separate from the handler so that main.py
# never builds a $set against the users collection by hand - the same reason
# confirm_totp and disable_totp exist.
#
# IT TAKES A HASH, NOT A PASSWORD, and the parameter name says so. A function here
# accepting a plaintext password would be a function that could be called without
# hashing, and the resulting bug is unrecoverable: plaintext passwords in the
# database, discovered later, with no way to tell which ones were written that way.
# Hashing stays in the handler, next to the policy check.
#
# passwordChangedAt is recorded for the audit answer "when did this last change?".
# Nothing reads it yet, and it is written now because it cannot be backfilled later.
async def set_password_hash(user_id: str, password_hash: str) -> None:
    await _get_collection(USERS_COLLECTION).update_one(
        {"_id": user_id},
        {
            "$set": {
                "passwordHash": password_hash,
                "passwordChangedAt": datetime.now(timezone.utc),
            }
        },
    )


# ============================================================================
# TWO-FACTOR AUTHENTICATION STATE
#
# WHY IT LIVES ON THE USER DOCUMENT
# A TOTP secret has exactly the same lifetime as the account it protects, and it is
# read on every login that reaches the second factor. A separate collection would
# mean a second query on the hot path to fetch a field that can never outlive - or
# be shared by - the user record. Sessions are separate because they expire
# independently of the account; this does not.
#
# THE FIELDS, and the state machine they encode:
#   totpSecret          - the shared secret. Absent means "never enrolled".
#   totpPendingSecret   - a secret issued by /2fa/setup and not yet confirmed.
#   totpConfirmedAt     - when enrolment completed. Its presence IS "2FA is on".
#   totpLastStep        - the last accepted 30-second step; replay protection.
#   recoveryCodeHashes  - the unused recovery codes, hashed.
#
# WHY A PENDING SECRET IS SEPARATE FROM THE LIVE ONE, which is the important part:
# /2fa/setup hands out a secret and a QR code, and at that moment nobody knows
# whether the user actually scanned it. Writing it straight to totpSecret would
# switch 2FA on for an account whose owner closed the tab - and with enforcement on,
# that locks them out using a secret they never stored. So the secret waits in
# totpPendingSecret until a correct code proves a phone has it, and only then is it
# promoted. An abandoned setup leaves a pending secret that the next setup call
# overwrites, and nothing is ever enforced against it.
# ============================================================================


# WHY THIS EXISTS
# Records a setup attempt in progress. Deliberately overwrites any previous pending
# secret: a user who starts enrolment twice - reloading the page, or trying a
# different authenticator app - should end up bound to the QR code currently on their
# screen rather than to one from ten minutes ago.
async def set_pending_totp_secret(user_id: str, secret: str) -> None:
    # MONGO: the $set OPERATOR updates named fields and leaves the rest of the
    # document alone. Passing the fields as a bare dict instead would REPLACE the
    # whole document - deleting the password hash and the email address - which is
    # one of the easier ways to destroy data with this driver.
    await _get_collection(USERS_COLLECTION).update_one(
        {"_id": user_id},
        {"$set": {"totpPendingSecret": secret}},
    )


# WHY THIS EXISTS
# Promotes a confirmed secret and stores the recovery codes in ONE operation.
#
# The atomicity is the point. Three separate updates - write the secret, write the
# codes, clear the pending field - can be interrupted between any two of them by a
# crash or a dropped connection, and two of the resulting half-states are bad: 2FA
# switched on with no recovery codes, or codes issued against a secret that was never
# promoted. A single update_one either happens or does not.
#
# MONGO: $unset removes the pending field entirely rather than setting it to null. A
# leftover null still reads as "there is a pending enrolment" to any code that tests
# for the key's presence.
async def confirm_totp(
    user_id: str, secret: str, recovery_hashes: list[str], first_step: int
) -> None:
    await _get_collection(USERS_COLLECTION).update_one(
        {"_id": user_id},
        {
            "$set": {
                "totpSecret": secret,
                "totpConfirmedAt": datetime.now(timezone.utc),
                "recoveryCodeHashes": recovery_hashes,
                # The step that confirmed enrolment is recorded immediately, so the
                # very code used to switch 2FA on cannot then satisfy a login inside
                # the same 30-second window.
                "totpLastStep": first_step,
            },
            "$unset": {"totpPendingSecret": ""},
        },
    )


# WHY THIS EXISTS
# Replay protection's write half - and it is a CONDITIONAL update rather than a
# read-then-write, which is what makes it correct when two requests arrive together.
#
# The filter carries the step test, so MongoDB itself refuses the update when the
# stored step is already at or past this one. Two simultaneous requests holding the
# same code therefore produce one success and one failure, decided by the database.
# The read-then-write version - fetch the user, compare in Python, then write - has a
# window between the read and the write in which both requests see the old value and
# both proceed, which is precisely the replay this exists to stop.
#
# Returns True when the step was accepted, so the caller learns whether the code was
# fresh. MONGO: matched_count is how many documents the FILTER found, which is zero
# when the step test failed.
async def claim_totp_step(user_id: str, step: int) -> bool:
    result = await _get_collection(USERS_COLLECTION).update_one(
        {
            "_id": user_id,
            # MONGO: $or with $exists covers the first-ever use, where the field is
            # absent. An absent field is not "less than" anything - it does not
            # compare at all - so $lt alone would match nothing and reject every
            # first login. A genuinely easy thing to get wrong here.
            "$or": [
                {"totpLastStep": {"$lt": step}},
                {"totpLastStep": {"$exists": False}},
            ],
        },
        {"$set": {"totpLastStep": step}},
    )

    return result.matched_count == 1


# WHY THIS EXISTS
# Spends one recovery code by removing its hash from the list. Single use is the
# entire security property of a recovery code, and it is enforced here rather than at
# the call site so there is no path that verifies one without consuming it.
#
# MONGO: $pull removes matching entries from an array. Pulling by the hash VALUE
# rather than by position matters - an index-based update would remove the wrong code
# if two recovery attempts overlapped and one had already shortened the array.
async def consume_recovery_code(user_id: str, code_hash: str) -> bool:
    result = await _get_collection(USERS_COLLECTION).update_one(
        {"_id": user_id},
        {"$pull": {"recoveryCodeHashes": code_hash}},
    )

    # modified_count rather than matched_count: the user document is always matched,
    # so only "did the array actually change" answers whether the code was still
    # there to spend.
    return result.modified_count == 1


# WHY THIS EXISTS
# Replaces the whole set of recovery codes. Used when a user regenerates them, after
# spending several or after losing the printout.
#
# It replaces rather than appends, and that is the safe direction: appending would
# leave the old codes valid, so a printout somebody threw away would still work.
# Regenerating has to invalidate everything issued before it.
async def replace_recovery_codes(user_id: str, recovery_hashes: list[str]) -> None:
    await _get_collection(USERS_COLLECTION).update_one(
        {"_id": user_id},
        {"$set": {"recoveryCodeHashes": recovery_hashes}},
    )


# WHY THIS EXISTS
# Switches 2FA off and removes every trace of it - the secret, any pending secret,
# the recovery codes and the replay counter.
#
# $unset on all five rather than setting them to null, so the account returns to
# genuinely "never enrolled" rather than a distinguishable disabled state. Leaving a
# stale recoveryCodeHashes array behind would mean an old printout still worked
# against a re-enrolled account.
async def disable_totp(user_id: str) -> None:
    await _get_collection(USERS_COLLECTION).update_one(
        {"_id": user_id},
        {
            "$unset": {
                "totpSecret": "",
                "totpPendingSecret": "",
                "totpConfirmedAt": "",
                "totpLastStep": "",
                "recoveryCodeHashes": "",
            }
        },
    )


# ============================================================================
# GOOGLE ACCOUNTS
# ============================================================================


# WHY THIS EXISTS
# Finds the account linked to a Google user. Matched on googleId - Google's `sub`
# claim - and never on email, for the reason set out in google_auth.py: an email
# address can be changed by its owner or reassigned by a Workspace administrator,
# and `sub` cannot. Matching on email is the more common implementation, and it is
# the one that lets an account be taken over by whoever gets the address next.
#
# The sparse unique index in connect() is what makes this an index hit, and what
# guarantees at most one SecuScan account per Google account.
async def find_user_by_google_id(google_id: str) -> dict | None:
    return _with_id(
        await _get_collection(USERS_COLLECTION).find_one({"googleId": google_id})
    )


# WHY THIS EXISTS
# Attaches a Google id to an account that already exists with the same email address.
#
# WHEN THIS HAPPENS: somebody signed up with a password in March and clicks "Sign in
# with Google" in September. Same person, same verified address, so creating a second
# account would split their scan history in two. Linking is what a user expects - and
# it is only safe because google_auth.py has already refused any token whose email
# Google does not report as verified. Without that check this function would be an
# account-takeover primitive.
#
# The password stays on the account and keeps working. Removing it would silently take
# away a sign-in method somebody may still be using.
async def link_google_id(user_id: str, google_id: str) -> bool:
    try:
        result = await _get_collection(USERS_COLLECTION).update_one(
            {"_id": user_id},
            {"$set": {"googleId": google_id}},
        )
        return result.matched_count == 1
    except DuplicateKeyError:
        # The sparse unique index refused it: this Google id is already attached to a
        # DIFFERENT account. Rare, and a real answer rather than a crash - the caller
        # reports it instead of linking one Google account to two users.
        return False


# ============================================================================
# LOGIN CHALLENGES - the half-finished login
#
# WHY A COLLECTION AND NOT A SESSION
# Between "the password was correct" and "the second factor was correct" there is a
# state that has to survive across two HTTP requests. It must not be a session: a
# session IS access, and the whole point of a second factor is that the password
# alone grants none.
#
# So a challenge is a separate short-lived record holding a hashed random token, the
# user it belongs to, and a count of wrong attempts. It authorises exactly one thing
# - submitting a second factor - and expires in five minutes.
#
# The token is hashed with SHA-256 exactly like a session token, for the same reason:
# a leaked database yields useless digests rather than live half-logins.
# ============================================================================


# WHY THIS EXISTS
# Files a new challenge. Same "the _id IS the hash" pattern as sessions, so looking
# one up is a primary-key hit rather than a query.
async def create_challenge(challenge: dict) -> None:
    document = {**challenge, "_id": challenge["tokenHash"]}
    document.pop("tokenHash", None)

    await _get_collection(CHALLENGES_COLLECTION).insert_one(document)


# WHY THIS EXISTS
# Turns a challenge token back into its record, or None. It re-checks the expiry for
# the same reason find_session does: the TTL sweep runs about once a minute, so
# "expired but not yet deleted" is a real state, and it must not count as valid.
async def find_challenge(token_hash: str) -> dict | None:
    document = await _get_collection(CHALLENGES_COLLECTION).find_one({"_id": token_hash})

    if document is None:
        return None

    if _has_expired(document.get("expiresAt")):
        return None

    document["tokenHash"] = document.pop("_id")
    return document


# WHY THIS EXISTS
# Counts a failed second-factor attempt and reports the new total in one round trip.
#
# MONGO: $inc increments a field, creating it at the increment value when absent.
# return_document=AFTER asks for the UPDATED document; the default is BEFORE, and
# taking that default here would return a count one behind the truth, so the limit
# would fire one attempt late.
async def count_challenge_attempt(token_hash: str) -> int:
    document = await _get_collection(CHALLENGES_COLLECTION).find_one_and_update(
        {"_id": token_hash},
        {"$inc": {"attempts": 1}},
        return_document=ReturnDocument.AFTER,
    )

    if document is None:
        return 0

    return int(document.get("attempts", 0))


# WHY THIS EXISTS
# Destroys a challenge. Called on success - so a challenge token cannot be spent
# twice - and on too many failures, so a brute-force attempt has to start again from
# the password.
async def delete_challenge(token_hash: str) -> None:
    await _get_collection(CHALLENGES_COLLECTION).delete_one({"_id": token_hash})


# ============================================================================
# EMAILED RECOVERY CODES
# ============================================================================


# WHY THIS EXISTS
# Records an emailed code against the challenge it belongs to.
#
# The _id is the CHALLENGE's token hash, not the code's, which means issuing a second
# code for the same login replaces the first rather than leaving two valid. That is
# deliberate: a user who presses "email me a code" twice because the first was slow
# should end up with exactly one working code - the one that arrived most recently -
# and must not be able to widen the guessing surface by requesting ten.
#
# MONGO: upsert=True means insert if absent, update if present. The "replace or
# create" operation in one call, with no race between checking and writing.
async def save_email_code(
    challenge_hash: str, code_hash: str, expires_at: datetime
) -> None:
    await _get_collection(EMAIL_CODES_COLLECTION).update_one(
        {"_id": challenge_hash},
        {
            "$set": {
                "codeHash": code_hash,
                "expiresAt": expires_at,
                # Reset on reissue. A fresh code deserves a fresh attempt budget;
                # carrying the old count over would let two wrong guesses at the
                # first code invalidate the second one on arrival.
                "attempts": 0,
            }
        },
        upsert=True,
    )


# WHY THIS EXISTS
# Reads back the emailed code for a challenge, with the same expired-but-not-swept
# re-check as sessions and challenges.
async def find_email_code(challenge_hash: str) -> dict | None:
    document = await _get_collection(EMAIL_CODES_COLLECTION).find_one(
        {"_id": challenge_hash}
    )

    if document is None:
        return None

    if _has_expired(document.get("expiresAt")):
        return None

    return document


# WHY THIS EXISTS
# Counts a wrong guess at an emailed code. Separate from the challenge's own counter
# because the two bound different things: the challenge counter limits attempts at
# the second-factor step as a whole, and this one limits guesses at one six-digit
# code, so that requesting a fresh code cannot also refresh the budget for guessing
# the previous one.
async def count_email_code_attempt(challenge_hash: str) -> int:
    document = await _get_collection(EMAIL_CODES_COLLECTION).find_one_and_update(
        {"_id": challenge_hash},
        {"$inc": {"attempts": 1}},
        return_document=ReturnDocument.AFTER,
    )

    if document is None:
        return 0

    return int(document.get("attempts", 0))


# WHY THIS EXISTS
# Removes an emailed code once it is spent or exhausted. Single use is the property
# being enforced, and enforcing it by deletion rather than by a "used" flag means
# there is no spent record left for anybody to read a hash out of.
async def delete_email_code(challenge_hash: str) -> None:
    await _get_collection(EMAIL_CODES_COLLECTION).delete_one({"_id": challenge_hash})


# ============================================================================
# BILLING
#
# Two things are stored: the immutable order ledger and the mutable current plan.
# See the note beside ORDERS_COLLECTION at the top of this file for why those are
# not the same record.
#
# WHAT IS NOT STORED, and it is the most important line in this section: no card
# number reaches this file. The checkout endpoint validates the card, calls
# billing.describe_card() for a brand and the last four digits, and passes those
# two values here. There is no parameter below that could carry a card number even
# if somebody wanted to pass one.
# ============================================================================


# WHY THIS EXISTS
# The failure this file raises, when it raises at all.
#
# The whole premise of this module is that nothing else mentions MongoDB - so a
# handler writing `except PyMongoError` would have to import pymongo, and the
# abstraction would be gone in one line. This is the driver-agnostic name that lets
# main.py say "the storage layer failed" without knowing which storage layer.
#
# PYTHON-SPECIFIC: subclassing RuntimeError rather than Exception, so a caller that
# catches the broader type still catches this.
class StorageError(RuntimeError):
    pass


# WHY THIS EXISTS
# Files one completed checkout. Written once, never updated - the write half of an
# append-only ledger.
#
# It RAISES on failure, unlike save_scan() which returns a boolean, and the
# difference is deliberate. A scan that ran but could not be filed is still a
# useful result to hand back. A payment that was taken but not recorded is a
# customer who has been charged for something the system has no memory of - so the
# endpoint has to know, and the caller's `try` is what turns that into "the payment
# did not go through" rather than a silent success.
#
# The driver's exception is translated rather than propagated, for the reason given
# on StorageError above. `from None` suppresses the chained traceback: a pymongo
# error string can contain the connection URI, and a URI can contain credentials -
# so it stays out of anything that might reach a log or a response.
async def create_order(order: dict) -> None:
    document = {**order, "_id": order["id"]}
    document.pop("id", None)

    try:
        await _get_collection(ORDERS_COLLECTION).insert_one(document)
    except PyMongoError:
        raise StorageError("Could not write the order.") from None


# WHY THIS EXISTS
# Claims a provider webhook event, so the work behind it happens exactly once.
#
# THIS IS AN ATOMIC CONDITIONAL CLAIM, NOT A READ-THEN-WRITE, for the same reason
# claim_totp_step below is one: "has this event been seen?" followed by "mark it
# seen" leaves a window in which two concurrent deliveries both read no and both
# proceed - which is precisely the duplicate this exists to stop. Paddle retries in
# parallel with the original when the original is merely slow, so that window is not
# theoretical. Here the insert IS the test: the unique _id means the second one
# cannot land, and the driver tells us so.
#
# Returns True when the caller now owns the event and should do the work, False when
# somebody already has.
#
# PYTHON-SPECIFIC: DuplicateKeyError is caught BEFORE the broad PyMongoError clause,
# and the order is load-bearing. DuplicateKeyError is a subclass of PyMongoError, so
# a single `except PyMongoError` would swallow it and make "already processed" look
# identical to "the database is unreachable" - one of which must return 200 and the
# other of which must return 5xx so the event is redelivered.
async def claim_webhook_event(event_id: str, provider: str = "") -> bool:
    now = datetime.now(timezone.utc)

    document = {
        "_id": event_id,
        "provider": provider,
        "claimedAt": now,
        "expiresAt": now + timedelta(days=WEBHOOK_EVENT_TTL_DAYS),
    }

    try:
        await _get_collection(WEBHOOK_EVENTS_COLLECTION).insert_one(document)
    except DuplicateKeyError:
        return False
    except PyMongoError:
        raise StorageError("Could not claim the webhook event.") from None

    return True


# WHY THIS EXISTS
# Hands a claimed event back, so a delivery that failed halfway can be retried.
#
# The claim is taken before any write, which means a claim held by a delivery that
# then failed to write its order would permanently suppress every retry of the only
# event that could fix it - a charged customer with no receipt and no code path left
# that would ever produce one. Releasing turns that into "Paddle tries again", which
# is what at-least-once delivery is for.
#
# It does NOT raise. It is called from an error path that is already returning 5xx,
# and a second exception there would replace a useful failure with a confusing one.
# The worst case if the delete fails is a suppressed retry, which is the state we
# were in anyway - and the TTL eventually clears it regardless.
async def release_webhook_event(event_id: str) -> None:
    try:
        await _get_collection(WEBHOOK_EVENTS_COLLECTION).delete_one({"_id": event_id})
    except PyMongoError:
        pass


# WHY THIS EXISTS
# The billing history screen. Newest first, owner-scoped, and the compound index in
# connect() is what answers it without reading every order in the collection.
#
# user_id IS REQUIRED, with no default, for the same reason it is required on
# find_scan and list_scans - and here the stakes are higher, because the documents
# are receipts. An optional owner argument is an owner somebody eventually forgets
# to pass, and the bug that follows is one customer reading another's purchase
# history. Making it positional and mandatory turns that mistake into a TypeError
# the moment the code is imported.
async def list_orders(user_id: str, limit: int = 50) -> list:
    cursor = (
        _get_collection(ORDERS_COLLECTION)
        .find({"userId": user_id})
        .sort("createdAt", -1)
        .limit(limit)
    )

    # PYTHON-SPECIFIC: `async for` over a cursor fetches in batches under the hood
    # rather than pulling the whole result set into memory at once.
    orders = []

    async for document in cursor:
        orders.append(_with_id(document))

    return orders


# WHY THIS EXISTS
# Grants a plan. This is the single function that changes what an account is allowed
# to do, which is why it is one call rather than two updates in the endpoint - a
# planId that disagrees with the subscription beside it is the kind of state that
# produces a customer on Business rates with Free limits.
#
# WHY BOTH A FLAT planId AND A NESTED subscription: the flat field is what every
# limit check reads, and a one-field read is what it should be. The sub-document is
# the detail nobody needs on the hot path - when the period started, when it ends,
# which order paid for it, and the brand and last four digits of the card so the
# billing screen can say "Visa ending 4242" without going near the ledger.
#
# $set with a nested dict REPLACES the whole subscription sub-document, which is the
# intent: a new plan supersedes the old one entirely, and merging the two would leave
# last month's period end sitting next to this month's plan.
async def set_user_plan(user_id: str, plan_id: str, subscription: dict) -> None:
    await _get_collection(USERS_COLLECTION).update_one(
        {"_id": user_id},
        {"$set": {"planId": plan_id, "subscription": subscription}},
    )


# WHY THIS EXISTS
# Cancellation. Returns the account to the default plan and clears the subscription
# outright rather than leaving a cancelled one in place, so `subscription` present
# means "there is a paid plan here" with no flag to check alongside it.
#
# THE ORDERS ARE UNTOUCHED, which is the point of a ledger. A cancelled subscription
# does not un-buy the months that were paid for, and the receipts stay readable.
#
# PYTHON-SPECIFIC: $unset needs a value in the dict and the value is ignored by
# MongoDB entirely - the empty string is the conventional placeholder.
async def clear_user_plan(user_id: str, default_plan_id: str) -> None:
    await _get_collection(USERS_COLLECTION).update_one(
        {"_id": user_id},
        {"$set": {"planId": default_plan_id}, "$unset": {"subscription": ""}},
    )


# --- Tier 2 Credentials Persistence ---------------------------------------

# WHY CREDENTIALS ARE SCOPED BY BOTH scan_id AND user_id
# Tier 2 credentials grant access to client staging/test environments.
# By strictly associating each document with both scan_id and user_id,
# we prevent any cross-tenant credential leakage or unauthorized retrieval.
# An upsert on (scanId, userId) replaces any previously submitted token for
# that specific scan run.
async def save_scan_credentials(
    scan_id: str,
    user_id: str,
    encrypted_blob: str,
    ttl_hours: int = 24,
) -> None:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=ttl_hours)
    await _get_collection(CREDENTIALS_COLLECTION).update_one(
        {"scanId": scan_id, "userId": user_id},
        {
            "$set": {
                "scanId": scan_id,
                "userId": user_id,
                "encryptedBlob": encrypted_blob,
                "createdAt": now,
                "expiresAt": expires_at,
            }
        },
        upsert=True,
    )


async def get_scan_credentials(scan_id: str, user_id: str) -> dict | None:
    doc = await _get_collection(CREDENTIALS_COLLECTION).find_one(
        {"scanId": scan_id, "userId": user_id}
    )
    if not doc:
        return None

    # THE EXPIRY IS RE-CHECKED HERE, NOT LEFT TO THE INDEX.
    # _has_expired above says why in general: the TTL monitor sweeps about once a
    # minute, so "past expiresAt but not yet deleted" is a state every one of these
    # collections spends time in, and it must never read as valid. This collection was
    # the one that omitted the check. It is also the one where the record is a live
    # client password, so a stale read here hands a Tier 2 check credentials the
    # retention window already promised were gone.
    if _has_expired(doc.get("expiresAt")):
        return None

    return _with_id(doc)


async def delete_scan_credentials(scan_id: str, user_id: str) -> bool:
    result = await _get_collection(CREDENTIALS_COLLECTION).delete_one(
        {"scanId": scan_id, "userId": user_id}
    )
    return result.deleted_count > 0

