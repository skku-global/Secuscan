"""Branch tests for the password reset flow - above all its enumeration rule.

WHAT THIS FILE IS FOR. /auth/forgot-password is built so that its answer cannot be
used to discover which email addresses have accounts. The way it achieves that is
unusual and, read quickly, looks like dead code: an address with NO account still gets
a real challenge (userId=None) and a real stored code, generated and thrown away
unsent. That decoy is the whole defence, and the obvious "simplification" - return
early for an unknown address, skip the pointless row - reopens the leak completely
while making the endpoint look tidier. Nothing in the type system objects. So it is
pinned here instead.

THE SHAPE OF THE TESTS FOLLOWS THE SHAPE OF THE ARGUMENT. The property is not "the
response looks vague", it is "the two cases are indistinguishable", and the only
honest way to test a claim about two cases is to run both. So the suites below run the
SAME address through TWO WORLDS - one database where it is registered, one where it is
not - and compare what an attacker can see: status codes, detail strings, response
keys, and how many tries each one tolerates. A leak shows up as a difference.

That comparison extends past /auth/forgot-password on purpose. Issuing a challenge for
an unknown address does not remove the leak by itself - it MOVES it to
/auth/reset-password, where a decoy that answered "expired" while a real account
answered "not correct" would give the whole thing away one step further along. The
second half of this file is about that.

WHAT IS DELIBERATELY NOT TESTED HERE. The reset endpoint's password-policy check
compares the new password against the account's email and name, and a decoy has
neither, so those two similarity rules can behave differently between the worlds. That
is not a leak and is not treated as one: the check is reached only AFTER a correct
code, and a correct code for a real account arrives by email. Whoever can reach that
line is the inbox holder, not somebody enumerating addresses. The tests below use
passwords rejected by rules that need no account, which is the case an attacker could
actually construct.

Run from anywhere (the `import _path` line puts backend/ on sys.path):
  python backend/tests/test_reset.py
"""

import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import _path  # noqa: F401  - puts backend/ on sys.path; must precede the imports below
import auth
import main
from fastapi import HTTPException

PASS_COUNT = 0
FAIL_COUNT = 0


def check(label, got, want):
    global PASS_COUNT, FAIL_COUNT
    ok = got == want
    if ok:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    suffix = "" if ok else "   (got {!r}, wanted {!r})".format(got, want)
    print("  {} {}{}".format("ok  " if ok else "FAIL", label, suffix))


def section(title):
    print("\n{}".format(title))


# ---------------------------------------------------------------------------
# The stand-ins.
#
# These replace the `database` and `mailer` modules by name on `main`, which works
# because main.py imports them as modules and calls through them - `database.find_...`
# rather than a from-import bound at load time. So there is one place to intercept.
#
# The fake database is a dictionary, not a mock that records calls: nearly every
# assertion below is about STATE - was a decoy row written, did the challenge survive,
# was a password changed - and a dictionary answers that directly, where a call log
# would only tell you what was asked.
# ---------------------------------------------------------------------------


class FakeDatabase:
    def __init__(self):
        self.users = {}
        self.challenges = {}
        self.email_codes = {}
        self.password_writes = []
        self.session_wipes = []

    def add_user(self, user_id, email, name=""):
        self.users[user_id] = {
            "id": user_id,
            "email": email,
            "name": name,
            "passwordHash": "argon2-hash-of-the-old-password",
        }

    async def find_user_by_email(self, email):
        for user in self.users.values():
            if user["email"] == email:
                return dict(user)
        return None

    async def find_user_by_id(self, user_id):
        user = self.users.get(user_id)
        return dict(user) if user is not None else None

    async def create_challenge(self, challenge):
        self.challenges[challenge["tokenHash"]] = dict(challenge)

    async def find_challenge(self, token_hash):
        challenge = self.challenges.get(token_hash)

        if challenge is None:
            return None

        # The same expired-but-not-swept re-check the real one does, so an expiry set
        # in the past behaves here the way it would in Mongo.
        if challenge["expiresAt"] <= datetime.now(timezone.utc):
            return None

        return dict(challenge)

    async def delete_challenge(self, token_hash):
        self.challenges.pop(token_hash, None)

    async def save_email_code(self, challenge_hash, code_hash, expires_at):
        self.email_codes[challenge_hash] = {
            "codeHash": code_hash,
            "expiresAt": expires_at,
            "attempts": 0,
        }

    async def find_email_code(self, challenge_hash):
        record = self.email_codes.get(challenge_hash)

        if record is None:
            return None

        if record["expiresAt"] <= datetime.now(timezone.utc):
            return None

        return dict(record)

    async def count_email_code_attempt(self, challenge_hash):
        record = self.email_codes.get(challenge_hash)

        if record is None:
            return 0

        # Increment-then-return, matching find_one_and_update(ReturnDocument.AFTER).
        # Returning the count BEFORE the increment would give every challenge one extra
        # guess, which is exactly the kind of off-by-one this fake must not introduce.
        record["attempts"] += 1
        return record["attempts"]

    async def delete_email_code(self, challenge_hash):
        self.email_codes.pop(challenge_hash, None)

    async def set_password_hash(self, user_id, password_hash):
        self.password_writes.append((user_id, password_hash))
        if user_id in self.users:
            self.users[user_id]["passwordHash"] = password_hash

    async def delete_sessions_for_user(self, user_id, except_hash=None):
        self.session_wipes.append((user_id, except_hash))
        return 0


class FakeMailer:
    def __init__(self, available=True):
        self.available = available
        self.sent = []

    def email_available(self):
        return self.available

    async def send_password_reset_code(self, to, code, name=""):
        self.sent.append({"to": to, "code": code, "name": name})
        return True


class FakeClient:
    def __init__(self, host):
        self.host = host


class FakeRequest:
    """Only ever asked for .client.host, which is all _client_key reads."""

    def __init__(self, host="203.0.113.9"):
        self.client = FakeClient(host)


# THE CODE IS MADE DETERMINISTIC FOR THE WHOLE FILE, and that is what makes the decoy's
# success path reachable at all. A decoy's code is generated and discarded unsent, so
# in production nobody - tester included - can know it. Pinning the generator means the
# two worlds can be driven through IDENTICAL inputs all the way to the end, which is
# the only way to compare their outputs. The real generator is restored at the bottom.
FIXED_CODE = "424242"
REAL_NEW_EMAIL_CODE = auth.new_email_code

ADDRESS = "ada@example.com"

# Long, not in any common-password list, and sharing nothing with the address or name -
# so it is accepted on both paths for the same reason.
STRONG_PASSWORD = "correct-horse-battery-staple-71"


def fresh(email_available=True):
    """Builds a pair of clean fakes, and empties the rate limiter's memory.

    The limiter is module-level state keyed by client IP, and ten tries buys out a key
    for fifteen minutes. Creating a world is the moment to forget all that, so that a
    suite late in the file does not 429 during setup and send a reader hunting for a
    bug in the wrong place.

    IT IS DELIBERATELY NOT DONE IN alive(). The limit is 10 tries and these suites
    make 12, so clearing it on every call would quietly make the attempt counter
    untestable - the flood below would sail past a limit that the real endpoint
    enforces perfectly well. A limit this file clears on every request is a limit it
    cannot test.
    """
    main._attempts.clear()

    return (FakeDatabase(), FakeMailer(email_available))


@contextmanager
def alive(database, mailer):
    """Mounts one world on `main` for the duration of the block.

    WHY THIS IS NOT JUST AN ASSIGNMENT IN fresh(). `main.database` is ONE reference,
    and these tests deliberately keep TWO worlds alive at once to compare them. Drop
    the world as a parameter and every call reads whichever database was mounted last,
    which is how a run reports "the decoy is fine and the real account's challenge
    expired" while the implementation underneath is entirely correct. Making the world
    an argument means a suite cannot accidentally read the wrong one: it has to name it.

    The previous pairing is put back on the way out, so a mistake in one suite does not
    leak into the next one's failures.
    """
    previous = (main.database, main.mailer)
    main.database = database
    main.mailer = mailer

    try:
        yield database
    finally:
        main.database, main.mailer = previous


def forgot(database, address, request=None):
    with alive(*database):
        return asyncio.run(
            main.forgot_password(
                main.ForgotPasswordRequest(email=address), request or FakeRequest()
            )
        )


def outcome(database, challenge, code, new_password, request=None):
    """Runs /auth/reset-password and flattens the result into a comparable value.

    A raise and a return are both just "what the caller saw", and the whole file is
    built on comparing what two callers saw, so they have to be the same kind of thing.
    """
    body = main.ResetPasswordRequest(
        challenge=challenge, code=code, newPassword=new_password
    )

    with alive(*database):
        try:
            result = asyncio.run(main.reset_password(body, request or FakeRequest()))
            return {"kind": "ok", "body": result}
        except HTTPException as error:
            return {"kind": "http", "status": error.status_code, "detail": error.detail}


auth.new_email_code = lambda: FIXED_CODE


# ---------------------------------------------------------------------------
section("/auth/forgot-password - the two worlds answer identically")
# ---------------------------------------------------------------------------

# THE SAME ADDRESS IN BOTH WORLDS. Comparing a registered address against some other
# unregistered one would compare two different inputs and prove nothing: of course the
# masked address differs when the address differs. Holding the input fixed and varying
# only whether the account exists is what isolates the property.

world_real = fresh()
db_real, mail_real = world_real
db_real.add_user("u1", ADDRESS, "Ada")
answer_real = forgot(world_real, ADDRESS)

world_decoy = fresh()
db_decoy, mail_decoy = world_decoy
answer_decoy = forgot(world_decoy, ADDRESS)

check("same response keys", sorted(answer_real), sorted(answer_decoy))
check("same message", answer_real["message"], answer_decoy["message"])
check("  and it says 'if', not 'we have'", "If an account exists" in answer_real["message"], True)
check("same masked address", answer_real["sentTo"], answer_decoy["sentTo"])
check("  and it is masked", answer_real["sentTo"], "a*a@example.com")
check("same expiry advertised", answer_real["expiresInMinutes"], answer_decoy["expiresInMinutes"])
check("same 'requested' flag", answer_real["requested"], answer_decoy["requested"])
check("no field naming the account", [k for k in answer_real if k in ("userId", "user", "found", "exists")], [])

# A challenge in both, and one that is not a constant. Equal-length because a token
# whose length varied with the world would be a leak measurable in bytes.
check("real world got a challenge", bool(answer_real["challenge"]), True)
check("decoy world got a challenge", bool(answer_decoy["challenge"]), True)
check("same challenge length", len(answer_real["challenge"]), len(answer_decoy["challenge"]))
check("challenges are not a fixed string", answer_real["challenge"] != answer_decoy["challenge"], True)

# ---------------------------------------------------------------------------
section("/auth/forgot-password - the decoy is a real row, not a special case")
# ---------------------------------------------------------------------------

check("real world stored one challenge", len(db_real.challenges), 1)
check("decoy world stored one challenge", len(db_decoy.challenges), 1)

real_hash = auth.hash_token(answer_real["challenge"])
decoy_hash = auth.hash_token(answer_decoy["challenge"])

check("real challenge points at the account", db_real.challenges[real_hash]["userId"], "u1")
check("decoy challenge points at nobody", db_decoy.challenges[decoy_hash]["userId"], None)
check(
    "both are method 'reset'",
    (db_real.challenges[real_hash]["method"], db_decoy.challenges[decoy_hash]["method"]),
    ("reset", "reset"),
)

# THE CRUX OF THE WHOLE FILE. Delete the else-branch in forgot_password and this is the
# check that goes red - and it goes red before any of the /auth/reset-password suites
# below, which is the right order to read a failure in.
check("real world stored a code", len(db_real.email_codes), 1)
check("DECOY WORLD ALSO STORED A CODE", len(db_decoy.email_codes), 1)
check("  keyed to its own challenge", decoy_hash in db_decoy.email_codes, True)
check("  with a spent-attempt budget of zero", db_decoy.email_codes[decoy_hash]["attempts"], 0)

# Mail is the ONE thing that legitimately differs - and it differs where the attacker
# cannot see it, which is the entire trick.
check("real world sent one email", len(mail_real.sent), 1)
check("decoy world sent none", len(mail_decoy.sent), 0)
check("the email went to the account address", mail_real.sent[0]["to"], ADDRESS)
check("  and carried the account's name", mail_real.sent[0]["name"], "Ada")

# Stored hashed, like every other credential here.
check("stored code is a hash, not the code", db_real.email_codes[real_hash]["codeHash"] != FIXED_CODE, True)
check("  and it is the right hash", db_real.email_codes[real_hash]["codeHash"], auth.hash_email_code(FIXED_CODE))
check("the decoy's row is hashed the same way", db_decoy.email_codes[decoy_hash]["codeHash"], auth.hash_email_code(FIXED_CODE))

# ---------------------------------------------------------------------------
section("A reset challenge must outlive the code it carries")
# ---------------------------------------------------------------------------

# Not a style point. A challenge shorter than its own code expires while a perfectly
# good code is still sitting in the inbox, and the user reads that as the reset being
# broken. Either constant can be edited innocently; this is what notices.
check("challenge TTL exceeds code TTL", main.RESET_TTL_MINUTES > auth.EMAIL_CODE_TTL_MINUTES, True)
check("'reset' is in the TTL table at all", main._CHALLENGE_TTL_MINUTES.get("reset"), main.RESET_TTL_MINUTES)

lifetime = db_real.challenges[real_hash]["expiresAt"] - db_real.challenges[real_hash]["createdAt"]
check("the issued challenge really gets that long", round(lifetime.total_seconds() / 60), main.RESET_TTL_MINUTES)
check("  which is longer than the login default", main.RESET_TTL_MINUTES > main.CHALLENGE_TTL_MINUTES, True)

# ---------------------------------------------------------------------------
section("Unconfigured mail must not answer differently for a real account")
# ---------------------------------------------------------------------------

# A 503 here would announce that the address exists - the one thing the endpoint is
# built not to do - so a registered address takes the decoy branch when mail is off.
world_off = fresh(email_available=False)
db_off, mail_off = world_off
db_off.add_user("u1", ADDRESS, "Ada")
answer_off = forgot(world_off, ADDRESS)

check("still answers with the same keys", sorted(answer_off), sorted(answer_real))
check("same message as everyone else", answer_off["message"], answer_real["message"])
check("no mail was sent", len(mail_off.sent), 0)
check("but a code row still exists", len(db_off.email_codes), 1)
check(
    "  so the next step fails the ordinary way",
    auth.hash_token(answer_off["challenge"]) in db_off.email_codes,
    True,
)

# ---------------------------------------------------------------------------
section("The rate limit is keyed on the address, not only the client")
# ---------------------------------------------------------------------------

# This endpoint SENDS MAIL, so the per-address key is the one that earns its keep:
# without it a botnet floods one person's inbox from a thousand IPs and gets the
# sending domain reported for it. Each request comes from a different host below, so
# only the email key can be doing the stopping.
world_flood = fresh()
db_flood, mail_flood = world_flood
db_flood.add_user("u1", ADDRESS, "Ada")

blocked_at = None

for attempt in range(1, main._ATTEMPT_LIMIT + 3):
    try:
        forgot(world_flood, ADDRESS, FakeRequest(host="198.51.100.{}".format(attempt)))
    except HTTPException as error:
        blocked_at = (attempt, error.status_code)
        break

check("a distributed flood at one address is stopped", blocked_at is not None, True)
check("  with 429", blocked_at[1] if blocked_at else None, 429)
check("  at the limit, not after it", blocked_at[0] if blocked_at else None, main._ATTEMPT_LIMIT + 1)
check("  and mail stopped with it", len(mail_flood.sent), main._ATTEMPT_LIMIT)

# A different address from the same spread of hosts is unaffected - the limiter is not
# simply jammed shut for everyone once one address trips it.
check(
    "a different address still works",
    forgot(world_flood, "grace@example.com", FakeRequest(host="198.51.100.1"))["requested"],
    True,
)

# ---------------------------------------------------------------------------
section("/auth/reset-password - a wrong code is indistinguishable")
# ---------------------------------------------------------------------------

# Issuing a challenge for an unknown address does not close the leak by itself. It
# moves it here. These are the observable differences a naive second half would have.

world_real = fresh()
db_real, mail_real = world_real
db_real.add_user("u1", ADDRESS, "Ada")
challenge_real = forgot(world_real, ADDRESS)["challenge"]

world_decoy = fresh()
db_decoy, mail_decoy = world_decoy
challenge_decoy = forgot(world_decoy, ADDRESS)["challenge"]

wrong_real = outcome(world_real, challenge_real, "000000", STRONG_PASSWORD)
wrong_decoy = outcome(world_decoy, challenge_decoy, "000000", STRONG_PASSWORD)

check("same kind of answer", wrong_real["kind"], wrong_decoy["kind"])
check("same status", wrong_real["status"], wrong_decoy["status"])
check("  and it is 401", wrong_real["status"], 401)
check("same detail text", wrong_real["detail"], wrong_decoy["detail"])
check("  the code message, not the expiry one", wrong_real["detail"], "That code is not correct.")

# The decoy must survive a wrong guess exactly as a real challenge does. Destroying it
# on the first try - which _resolve_challenge would have done - is a difference an
# attacker can measure by simply guessing twice.
check("real challenge survived", auth.hash_token(challenge_real) in db_real.challenges, True)
check("decoy challenge survived too", auth.hash_token(challenge_decoy) in db_decoy.challenges, True)
check(
    "both counted one attempt",
    (
        db_real.email_codes[auth.hash_token(challenge_real)]["attempts"],
        db_decoy.email_codes[auth.hash_token(challenge_decoy)]["attempts"],
    ),
    (1, 1),
)

# ---------------------------------------------------------------------------
section("/auth/reset-password - the attempt budget runs out identically")
# ---------------------------------------------------------------------------


def burn_through_attempts(world, challenge):
    """Guesses wrong until the endpoint stops saying 'not correct'. Returns the trail."""
    seen = []

    for _ in range(auth.EMAIL_CODE_MAX_ATTEMPTS + 2):
        result = outcome(world, challenge, "000000", STRONG_PASSWORD)
        seen.append((result["kind"], result.get("status"), result.get("detail")))

        if result.get("status") != 401:
            break

    return seen


world_real = fresh()
db_real = world_real[0]
db_real.add_user("u1", ADDRESS, "Ada")
trail_real = burn_through_attempts(world_real, forgot(world_real, ADDRESS)["challenge"])

world_decoy = fresh()
db_decoy = world_decoy[0]
trail_decoy = burn_through_attempts(world_decoy, forgot(world_decoy, ADDRESS)["challenge"])

check("identical sequence of answers", trail_real, trail_decoy)
check("  it took the same number of tries", len(trail_real), len(trail_decoy))
check("  and that is the configured budget", len(trail_real), auth.EMAIL_CODE_MAX_ATTEMPTS)
check("the last answer is 429", trail_real[-1][1], 429)
check("  naming cancellation, not a bad code", "cancelled" in trail_real[-1][2], True)

# Exhaustion destroys BOTH rows, on both paths - unlike /2fa/verify-email, where the
# challenge deliberately survives because a recovery code could still rescue the login.
# Here the emailed code is the only factor there is, so a surviving challenge could do
# nothing but sit there.
check("real world: challenge destroyed", len(db_real.challenges), 0)
check("real world: code destroyed", len(db_real.email_codes), 0)
check("decoy world: challenge destroyed", len(db_decoy.challenges), 0)
check("decoy world: code destroyed", len(db_decoy.email_codes), 0)

# ---------------------------------------------------------------------------
section("/auth/reset-password - a weak password is refused identically")
# ---------------------------------------------------------------------------

# The policy check sits ABOVE the `if user is not None` branch precisely so that this
# is true. Moving it inside the branch would make a rejected password reveal, by its
# absence, that there was no account behind the challenge.

world_real = fresh()
db_real = world_real[0]
db_real.add_user("u1", ADDRESS, "Ada")
weak_real = outcome(world_real, forgot(world_real, ADDRESS)["challenge"], FIXED_CODE, "short")

world_decoy = fresh()
db_decoy = world_decoy[0]
weak_decoy = outcome(world_decoy, forgot(world_decoy, ADDRESS)["challenge"], FIXED_CODE, "short")

check("same status for a weak password", weak_real["status"], weak_decoy["status"])
check("  and it is 400, not 401", weak_real["status"], 400)
check("same rejection text", weak_real["detail"], weak_decoy["detail"])
check("the policy really ran", weak_real["detail"], auth.password_problem("short"))
check("no password was written", db_real.password_writes, [])

# ---------------------------------------------------------------------------
section("/auth/reset-password - even success looks the same from outside")
# ---------------------------------------------------------------------------

world_real = fresh()
db_real = world_real[0]
db_real.add_user("u1", ADDRESS, "Ada")
challenge_real = forgot(world_real, ADDRESS)["challenge"]
done_real = outcome(world_real, challenge_real, FIXED_CODE, STRONG_PASSWORD)

world_decoy = fresh()
db_decoy = world_decoy[0]
challenge_decoy = forgot(world_decoy, ADDRESS)["challenge"]
done_decoy = outcome(world_decoy, challenge_decoy, FIXED_CODE, STRONG_PASSWORD)

check("both succeeded", (done_real["kind"], done_decoy["kind"]), ("ok", "ok"))
check("identical response body", done_real["body"], done_decoy["body"])
check("  which is just {reset: true}", done_real["body"], {"reset": True})

# NO SESSION. An emailed code proves inbox access and nothing more, so letting one mint
# a session would make the inbox a complete substitute for the password AND the second
# factor at once. The user signs in afterwards, which is also how an account with 2FA
# meets its authenticator without a second-factor branch being written here.
check(
    "no session token in the response",
    [k for k in done_real["body"] if k in ("token", "user", "session")],
    [],
)

# ---------------------------------------------------------------------------
section("/auth/reset-password - what actually changed, and what did not")
# ---------------------------------------------------------------------------

check("the real account's password was written once", len(db_real.password_writes), 1)
check("  for the right user", db_real.password_writes[0][0], "u1")
check("  and stored hashed, not in the clear", db_real.password_writes[0][1] != STRONG_PASSWORD, True)
check("  with a hash that verifies", auth.verify_password(db_real.password_writes[0][1], STRONG_PASSWORD), True)
check("the decoy wrote no password anywhere", db_decoy.password_writes, [])

# EVERY session, with no except_hash - the opposite of /auth/change-password, and for
# the opposite reason. That request proves the old password, so the caller is
# demonstrably not the party under suspicion. This one proves only inbox access, and
# the reason people reset a password is that they think somebody else is inside.
check("every session was revoked", len(db_real.session_wipes), 1)
check("  for the right user", db_real.session_wipes[0][0], "u1")
check("  and none was spared", db_real.session_wipes[0][1], None)
check("the decoy revoked nothing", db_decoy.session_wipes, [])

# Single use, on every path that got this far - the decoy included, so its rows do not
# linger any longer than a real one's would.
check("real world: code consumed", len(db_real.email_codes), 0)
check("real world: challenge consumed", len(db_real.challenges), 0)
check("decoy world: code consumed", len(db_decoy.email_codes), 0)
check("decoy world: challenge consumed", len(db_decoy.challenges), 0)

replay_real = outcome(world_real, challenge_real, FIXED_CODE, "another-perfectly-fine-password-9")
replay_decoy = outcome(world_decoy, challenge_decoy, FIXED_CODE, "another-perfectly-fine-password-9")

check("replaying the challenge fails", replay_real["status"], 401)
check("  and fails identically in both worlds", replay_real["detail"], replay_decoy["detail"])
check("  saying the reset expired", replay_real["detail"], "That reset request has expired. Start again.")
check("no second password write", len(db_real.password_writes), 1)

# ---------------------------------------------------------------------------
section("Challenge types cannot be swapped")
# ---------------------------------------------------------------------------

# A login challenge spent here would set a new password without the old one ever being
# known - the shape an attacker would try, which is exactly why it is checked.
world = fresh()
db = world[0]
db.add_user("u1", ADDRESS, "Ada")
with alive(*world):
    login_challenge = asyncio.run(main._start_challenge("u1", "totp"))

swapped = outcome(world, login_challenge, FIXED_CODE, STRONG_PASSWORD)

check("a totp challenge is refused at reset", swapped["status"], 401)
check("  with the reset flow's expiry message", swapped["detail"], "That reset request has expired. Start again.")
check("  and no password was set", db.password_writes, [])

# And the other direction: the decoy must be dead everywhere except the one function
# written to accept it. This is the guarantee that lets userId=None exist at all.
world = fresh()
db = world[0]
decoy_challenge = forgot(world, ADDRESS)["challenge"]

try:
    with alive(*world):
        asyncio.run(main._resolve_challenge(decoy_challenge, "reset"))
    refusal = "(no exception)"
except HTTPException as error:
    refusal = error.status_code

check("_resolve_challenge refuses a userId=None challenge", refusal, 401)

# AND DESTROYS IT ON THE WAY OUT. _resolve_challenge treats "no live account behind
# this" as a dead challenge and cleans it up, which for a real user is right and for
# the decoy is fatal: one wrong-resolver call and the address that owns it can no
# longer be told apart from an address whose challenge never existed. That is the
# enumeration leak arriving by the back door, and it is the whole reason the reset
# flow is forbidden from routing through this function.
check("  and destroys it in passing", auth.hash_token(decoy_challenge) in db.challenges, False)

# _resolve_reset_challenge, the one caller that accepts it, returns None rather than
# raising - and returns the token hash regardless, because the caller needs it to count
# attempts on a challenge that has no user. A fresh decoy, the previous one having just
# been proven destroyable.
decoy_challenge = forgot(world, ADDRESS)["challenge"]

with alive(*world):
    user, token_hash = asyncio.run(main._resolve_reset_challenge(decoy_challenge))

check("_resolve_reset_challenge returns no user", user, None)
check("  but still returns the token hash", token_hash, auth.hash_token(decoy_challenge))

db.add_user("u1", ADDRESS, "Ada")
real_challenge = forgot(world, ADDRESS)["challenge"]
with alive(*world):
    user, token_hash = asyncio.run(main._resolve_reset_challenge(real_challenge))

check("  and finds the user when there is one", user["id"] if user else None, "u1")

# ---------------------------------------------------------------------------
section("An expired challenge or code is refused")
# ---------------------------------------------------------------------------

world = fresh()
db = world[0]
db.add_user("u1", ADDRESS, "Ada")
stale = forgot(world, ADDRESS)["challenge"]
db.challenges[auth.hash_token(stale)]["expiresAt"] = datetime.now(timezone.utc) - timedelta(seconds=1)

expired = outcome(world, stale, FIXED_CODE, STRONG_PASSWORD)

check("an expired challenge is refused", expired["status"], 401)
check("  and sets no password", db.password_writes, [])

# An expired CODE under a live challenge is a different failure and says so: the ticket
# is fine, the thing it is a ticket for is not.
world = fresh()
db = world[0]
db.add_user("u1", ADDRESS, "Ada")
live = forgot(world, ADDRESS)["challenge"]
db.email_codes[auth.hash_token(live)]["expiresAt"] = datetime.now(timezone.utc) - timedelta(seconds=1)

lapsed = outcome(world, live, FIXED_CODE, STRONG_PASSWORD)

check("an expired code is refused", lapsed["status"], 401)
check("  with the code's own message", lapsed["detail"], "That code has expired. Start again.")
check("  and sets no password", db.password_writes, [])


auth.new_email_code = REAL_NEW_EMAIL_CODE

print("\n{} passed, {} failed".format(PASS_COUNT, FAIL_COUNT))
raise SystemExit(1 if FAIL_COUNT else 0)
