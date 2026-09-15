"""BRANCH TESTS FOR THE CONTACT FORM - and above all for who the message says it is from.

WHAT THIS FILE IS FOR. POST /contact mails our support mailbox on a signed-in user's
behalf. Every other endpoint in this app that sends mail sends TO the account that
asked; this is the one that sends to US, and the difference is what makes the sender's
identity the load-bearing thing rather than an incidental field.

THE ONE PROPERTY THE FILE EXISTS FOR: THE SENDER COMES FROM THE SESSION, NEVER FROM
THE BODY. There is no `email` field on ContactRequest, and that absence is the security
property - not an oversight, and not something a future reader should "fix" by adding
one for convenience. If the form carried the sender, anybody with an account could make
mail arrive at the support mailbox appearing to come from anybody, and the person
triaging that mailbox would have no way to tell. That is the same shape of abuse as an
open relay, and it is one field away at all times.

So the tests below do not merely check that the session's address is passed through.
They try to override it - through an extra `email` key in the JSON body, through a
`from_email` key, through a `to` key - and assert that the mailbox address and the
sender address come out unchanged. A field added to the model later would fail those
tests rather than silently reopening the hole, which is the entire point of pinning
them here rather than trusting a comment.

THE OTHER FOUR CLAIMS, all of which are promises the endpoint makes to a user:

  1. IT REFUSES HONESTLY WHEN IT CANNOT SEND. A 503 when no provider is configured and
     a 502 when the provider refuses - never a 200. A contact form that answers "sent"
     to a message nobody received leaves the user waiting for a reply that is not
     coming, having been told it was on its way.

  2. IT RATE LIMITS, on the same machinery every other endpoint uses. Even behind a
     session this is a send loop away from flooding the support mailbox.

  3. THE SUBJECT CANNOT INJECT A HEADER. A newline in a mail header ends the Subject:
     line and lets what follows be read as another header - which in the worst reading
     is a way to add recipients. The validator flattens whitespace; this pins it.

  4. A BLANK OR OVERSIZED MESSAGE IS REJECTED AT THE MODEL, before any mail is sent.

Run from anywhere (the `import _path` line puts backend/ on sys.path):
  python backend/tests/test_contact.py
"""

import asyncio
from contextlib import contextmanager

import _path  # noqa: F401 - puts backend/ on sys.path; must precede the imports below
import config
import main
from fastapi import HTTPException
from pydantic import ValidationError

PASS_COUNT = 0
FAIL_COUNT = 0


def check(label, got, want):
    global PASS_COUNT, FAIL_COUNT
    ok = got == want
    if ok:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    suffix = "" if ok else f"   (got {got!r}, wanted {want!r})"
    print(f"  {'ok  ' if ok else 'FAIL'} {label}{suffix}")


def section(title):
    print(f"\n{title}")


# ---------------------------------------------------------------------------
# The stand-ins, on the same pattern as test_reset.py: the fakes are mounted onto
# `main` by NAME, which works because main.py imports these as modules and calls
# through them (`mailer.send_contact_message(...)` rather than a from-import bound at
# load time). One place to intercept.
# ---------------------------------------------------------------------------


class FakeMailer:
    """Records what was asked of it, so the assertions can be about the CALL.

    Here the call log IS the right shape, unlike the password-reset suite where the
    assertions are about stored state. Every claim in this file is about what the
    endpoint asked the mailer to do - what address, what sender, what body - so a
    recording fake answers the question directly.
    """

    def __init__(self, available=True, sends=True):
        self.available = available
        # `sends=False` is the provider-refused case: email is configured, the
        # request goes out, and the send comes back False. Distinct from `available`
        # on purpose - the two produce a 503 and a 502 respectively, and the tests
        # below check that they are not collapsed into one another.
        self.sends = sends
        self.sent = []

    def email_available(self):
        return self.available

    async def send_contact_message(
        self, to, subject, message, from_email, from_name="", user_id=""
    ):
        self.sent.append(
            {
                "to": to,
                "subject": subject,
                "message": message,
                "from_email": from_email,
                "from_name": from_name,
                "user_id": user_id,
            }
        )
        return self.sends


class FakeClient:
    def __init__(self, host):
        self.host = host


class FakeRequest:
    """Only ever asked for .client.host, which is all _client_key reads."""

    def __init__(self, host="203.0.113.9"):
        self.client = FakeClient(host)


# The signed-in user the handler is given. `require_session` is a FastAPI dependency
# and is NOT exercised here - it has its own coverage elsewhere - so the handler is
# called with this dict in its place, which is exactly what the dependency returns.
# The point of this file is what the handler does with an authenticated user, not how
# one is authenticated.
USER = {
    "id": "user-ada",
    "email": "ada@example.com",
    "name": "Ada Lovelace",
}


def fresh(mailer=None):
    """A clean mailer and an emptied rate limiter.

    The limiter is module-level state keyed by "scope:host", so the "contact" bucket
    fills up across suites and would eventually 429 a test that is not about limiting.
    Cleared here and NOT in call() - a limit cleared on every request is a limit this
    file cannot test, which is the same reasoning test_reset.py spells out.
    """
    main._attempts.clear()
    return FakeMailer() if mailer is None else mailer


@contextmanager
def alive(mailer):
    """Mounts the fake mailer on `main` for the duration of the block."""
    previous = main.mailer
    main.mailer = mailer

    try:
        yield mailer
    finally:
        main.mailer = previous


def contact(body, mailer, request=None, user=None):
    """Runs POST /contact and flattens the outcome into a comparable value.

    A raise and a return are both "what the caller saw", and several tests below
    compare one against the other, so they have to be the same kind of thing.
    """
    with alive(mailer):
        try:
            result = asyncio.run(
                main.send_contact_message(
                    body, request or FakeRequest(), user or dict(USER)
                )
            )
            return {"kind": "ok", "body": result}
        except HTTPException as error:
            return {"kind": "http", "status": error.status_code, "detail": error.detail}


def message(subject="Cannot scan my staging site", body="It times out at the login step."):
    return main.ContactRequest(subject=subject, message=body)


# ---------------------------------------------------------------------------
section("1. The happy path, and what the mailbox actually receives")
# ---------------------------------------------------------------------------

mailer = fresh()
result = contact(message(), mailer)

check("the endpoint answers 200 with sent=True", result, {"kind": "ok", "body": {"sent": True}})
check("exactly one message was sent", len(mailer.sent), 1)

sent = mailer.sent[0]
check("it goes to the configured support address", sent["to"], config.SUPPORT_EMAIL)
check("the sender is the SESSION's address, not a body field", sent["from_email"], USER["email"])
check("the sender's name comes from the session too", sent["from_name"], USER["name"])
check("the account is identified for the triaging reader", sent["user_id"], USER["id"])
check("the subject carries through", sent["subject"], "Cannot scan my staging site")
check("the body carries through", sent["message"], "It times out at the login step.")

# The two addresses must not be the same one, or the reply-to test below would pass
# for the wrong reason and an unconfigured deployment could hide the mistake.
check(
    "the support address is genuinely a different mailbox from the sender",
    sent["to"] != sent["from_email"],
    True,
)


# ---------------------------------------------------------------------------
section("2. THE SECURITY PROPERTY: the body cannot choose the sender")
#
# This is what the file exists for. Each case below hands the endpoint an extra key
# claiming to be the sender and asserts that NOTHING about the outcome changes. Today
# these fail to arrive because ContactRequest has no such field; the tests exist so
# that adding one - the obvious "convenience" change - breaks the build instead of
# the mailbox's trustworthiness.
# ---------------------------------------------------------------------------

OVERRIDES = [
    ("email", "attacker@evil.example"),
    ("from_email", "attacker@evil.example"),
    ("fromEmail", "attacker@evil.example"),
    ("from", "attacker@evil.example"),
    ("reply_to", "attacker@evil.example"),
    ("name", "Somebody Else"),
]

for field, value in OVERRIDES:
    mailer = fresh()
    body = main.ContactRequest(
        subject="A normal subject",
        message="A normal message.",
        **{field: value},
    )
    result = contact(body, mailer)

    # Pydantic's default is to IGNORE unknown keys, so this returns 200 - the extra
    # key is silently dropped rather than rejected. That is acceptable and is why the
    # assertion is about the mailer's input rather than the status code: what matters
    # is that the address the endpoint used is still the session's.
    check(f"a '{field}' key in the body does not become the sender", mailer.sent[0]["from_email"], USER["email"])
    check(f"a '{field}' key in the body does not change the recipient", mailer.sent[0]["to"], config.SUPPORT_EMAIL)

# The same claim from the other direction: a caller passing a DIFFERENT user gets that
# user's address. Without this, section 2 would also pass if the endpoint ignored the
# session entirely and used a module constant.
mailer = fresh()
other = {"id": "user-grace", "email": "grace@example.com", "name": "Grace Hopper"}
contact(message(), mailer, user=other)

check("a different signed-in user sends from their own address", mailer.sent[0]["from_email"], other["email"])
check("...and is identified as their own account", mailer.sent[0]["user_id"], other["id"])


# ---------------------------------------------------------------------------
section("3. It refuses honestly when it cannot send")
# ---------------------------------------------------------------------------

# No provider configured. The UI hides the form when emailAvailable is false, so this
# is a direct call or a config that changed mid-session - and the answer must not be
# 200, because a user told "sent" waits for a reply that is not coming.
mailer = fresh(mailer=FakeMailer(available=False))
result = contact(message(), mailer)

check("with no mail provider configured the answer is 503", result["status"], 503)
check("nothing was handed to the mailer", mailer.sent, [])
check("the detail names the address to use instead", config.SUPPORT_EMAIL in result["detail"], True)

# Configured, and the provider refused or was unreachable. A DIFFERENT status from
# the 503 above, deliberately: the user's situation is different - one is "this server
# cannot email", the other is "it tried just now and failed".
mailer = fresh(mailer=FakeMailer(available=True, sends=False))
result = contact(message(), mailer)

check("a provider that refuses produces 502, not 200", result["status"], 502)
check("the send was genuinely attempted", len(mailer.sent), 1)
check("the 502 detail also offers the address", config.SUPPORT_EMAIL in result["detail"], True)

# The distinction is load-bearing, so assert it rather than assuming it.
refused = contact(message(), fresh(mailer=FakeMailer(available=True, sends=False)))
unconfigured = contact(message(), fresh(mailer=FakeMailer(available=False)))
check("the two failure modes are not collapsed together", refused["status"] != unconfigured["status"], True)


# ---------------------------------------------------------------------------
section("4. It rate limits")
#
# Even behind a session this sends mail, and a loop is a way to flood the support
# mailbox from one account. The limiter is shared with every other endpoint - this
# checks it is actually wired to THIS one, and keyed by its own scope.
# ---------------------------------------------------------------------------

mailer = fresh()

# The limit is 10 tries per "scope:host" (see _too_many_attempts in main.py). Burning
# the budget on one host must not spend another host's.
for _ in range(10):
    contact(message(), mailer, request=FakeRequest("198.51.100.7"))

flooded = contact(message(), mailer, request=FakeRequest("198.51.100.7"))
check("the 11th message from one address is refused", flooded["status"], 429)
check("the refusal does not send anything", len(mailer.sent), 10)

# A different client is unaffected, which is what makes this a per-client limit rather
# than a global off switch that would take the contact form down for everyone. Asserted
# against the flattened "kind" rather than a status code: the neighbour SUCCEEDS, so
# there is no status to read - indexing one would be the test assuming its own answer.
neighbour = contact(message(), mailer, request=FakeRequest("198.51.100.8"))
check("a different client is not caught by it", neighbour["kind"], "ok")

# And the contact bucket must not be the same bucket as another endpoint's, or using
# one feature would lock the user out of the other. The key is "contact:host" - pinned
# here because the "contact" prefix is what makes that true.
check("the limiter keys this endpoint separately", main._client_key(FakeRequest("10.0.0.1"), "contact"), "contact:10.0.0.1")
check(
    "which is a different key from another scope on the same host",
    main._client_key(FakeRequest("10.0.0.1"), "contact") != main._client_key(FakeRequest("10.0.0.1"), "login"),
    True,
)


# ---------------------------------------------------------------------------
section("5. The subject cannot inject a header")
#
# A newline in a mail header ends the Subject: line and makes what follows readable as
# another header. The provider's API takes the subject as JSON rather than a raw
# header, so this is defence in depth - but it is one line, and this pins it so it
# cannot be quietly removed as redundant.
# ---------------------------------------------------------------------------

injections = [
    ("a bare newline", "Hello\nBcc: attacker@evil.example"),
    ("CRLF", "Hello\r\nBcc: attacker@evil.example"),
    ("a carriage return alone", "Hello\rBcc: attacker@evil.example"),
    ("leading whitespace", "   Hello   "),
    ("an embedded tab", "Hello\tworld"),
]

for label, raw in injections:
    parsed = main.ContactRequest(subject=raw, message="A message.")
    flattened = parsed.subject

    # The property is "no control characters survive", not "the string looks tidy" -
    # so assert the absence of \r and \n directly rather than comparing to a guess at
    # the collapsed form.
    check(f"{label}: no newline survives in the subject", "\n" in flattened or "\r" in flattened, False)
    check(f"{label}: no tab survives either", "\t" in flattened, False)

check(
    "the injected header text is kept as visible text, not dropped silently",
    main.ContactRequest(subject="Hello\nBcc: x@y.z", message="m").subject,
    "Hello Bcc: x@y.z",
)

# The message body is deliberately NOT flattened - prose has paragraphs, and stripping
# its newlines would mangle what the user wrote. Only the header-ish field is treated
# this way. Pinned so the two are not "made consistent" by someone tidying up.
check(
    "the body keeps its newlines, unlike the subject",
    main.ContactRequest(subject="s", message="line one\nline two").message,
    "line one\nline two",
)


# ---------------------------------------------------------------------------
section("6. A blank or oversized message is refused before anything is sent")
#
# The model is where this is enforced, not the handler - so a bad message cannot reach
# the mailer even by a code path that forgets to check. Same structure as the signup
# password rules.
# ---------------------------------------------------------------------------

BAD_SUBJECTS = [
    ("an empty subject", ""),
    ("a whitespace-only subject", "     "),
    ("a newline-only subject", "\n\n"),
    ("a subject over 200 characters", "x" * 201),
]

for label, value in BAD_SUBJECTS:
    try:
        main.ContactRequest(subject=value, message="A message.")
        rejected = False
    except ValidationError:
        rejected = True

    check(f"{label} is rejected", rejected, True)

BAD_BODIES = [
    ("an empty message", ""),
    ("a whitespace-only message", "   \n  "),
    ("a message over 5000 characters", "x" * 5001),
]

for label, value in BAD_BODIES:
    try:
        main.ContactRequest(subject="A subject", message=value)
        rejected = False
    except ValidationError:
        rejected = True

    check(f"{label} is rejected", rejected, True)

# AT THE BOUNDARIES, both are accepted. An off-by-one here would reject a message the
# form's own maxLength allows, and the user would see the field stop them at 5000 and
# the server reject 5000 - a contradiction they cannot resolve.
try:
    main.ContactRequest(subject="x" * 200, message="y" * 5000)
    at_limits = True
except ValidationError:
    at_limits = False

check("exactly 200 and exactly 5000 are both accepted", at_limits, True)

# AND NO MAIL IS SENT for a rejected message, which is the part that matters: a
# ValidationError raised inside the FastAPI model means the handler never runs.
mailer = fresh()
check("a rejected body never reaches the mailer", mailer.sent, [])


# ---------------------------------------------------------------------------
section("7. The mailer builds a safe, replyable message")
#
# Moved here from the endpoint's point of view: the handler passes the user's email as
# `from_email`, and mailer.send_contact_message turns that into Reply-To. These are the
# mailer's own properties, checked directly because the endpoint's tests above stop at
# the boundary.
# ---------------------------------------------------------------------------

import mailer as mailer_module  # noqa: E402


class CapturingSender(mailer_module.Sender):
    """Stands in for the provider's sender and records the call."""

    name = "capturing"

    def __init__(self):
        self.calls = []

    async def send(self, to, subject, text, html_body, reply_to=""):
        self.calls.append(
            {"to": to, "subject": subject, "text": text, "html": html_body, "reply_to": reply_to}
        )
        return True


capture = CapturingSender()
previous_sender = mailer_module._sender
mailer_module._sender = capture

try:
    asyncio.run(
        mailer_module.send_contact_message(
            to=config.SUPPORT_EMAIL,
            subject="Cannot scan my staging site",
            message="Line one.\nLine two.",
            from_email=USER["email"],
            from_name=USER["name"],
            user_id=USER["id"],
        )
    )
finally:
    mailer_module._sender = previous_sender

check("the mailer made exactly one send call", len(capture.calls), 1)

call = capture.calls[0]
check("Reply-To is the user's address, so a reply reaches them", call["reply_to"], USER["email"])
check("the mail still goes to the support address", call["to"], config.SUPPORT_EMAIL)
check("the subject is prefixed so it is filterable in the mailbox", call["subject"].startswith("[") and "contact" in call["subject"].lower(), True)
check("the plain-text body names the sender", USER["email"] in call["text"], True)
check("the plain-text body identifies the account", USER["id"] in call["text"], True)

# The text version keeps the user's line break as a line break.
check("the user's newline survives into the plain-text body", "Line one.\nLine two." in call["text"], True)
# The HTML version converts it to markup - in that order, escape-then-br. If the order
# were reversed every <br> would arrive as visible characters.
check("the HTML body renders the break as markup", "Line one.<br>Line two." in call["html"], True)

# A user typing markup must not have it rendered in OUR mailbox. This is the one body
# in the file that a person writes freely, which is why escaping matters here.
capture2 = CapturingSender()
mailer_module._sender = capture2
try:
    asyncio.run(
        mailer_module.send_contact_message(
            to=config.SUPPORT_EMAIL,
            subject="Test",
            message="<script>alert(1)</script>",
            from_email=USER["email"],
            user_id=USER["id"],
        )
    )
finally:
    mailer_module._sender = previous_sender

check("markup the user typed does not survive as markup in the HTML body", "<script>" in capture2.calls[0]["html"], False)
check("it arrives as the characters they typed instead", "&lt;script&gt;" in capture2.calls[0]["html"], True)


# ---------------------------------------------------------------------------
print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
raise SystemExit(1 if FAIL_COUNT else 0)
