"""
MAILER.PY - sending email, and the seam that keeps the provider replaceable.

WHY THIS FILE EXISTS
One feature needs email: the recovery code that gets a user back in when their
authenticator app is on a phone they no longer have. That is a small amount of
sending, and it would fit in twenty lines inside the endpoint that uses it.

It is a file with an interface instead, for one reason that is worth more than the
twenty lines saved: the endpoint should not know which company delivers its mail.
Today that is Resend. If it becomes SES or Postmark, the change should be one
class here and one environment variable - not an edit to an auth endpoint, which
is the last code in the app anyone should be touching for an unrelated reason.

WHAT "PLUGGABLE" MEANS CONCRETELY
  - Callers only ever see send_recovery_code(). They pass an address and a code.
  - A sender is a class with one async send() method.
  - config.EMAIL_PROVIDER names which one to build.
Adding a provider means writing a class and one line in _build_sender().

THE ONE RULE THIS FILE FOLLOWS ABOUT FAILURE
It reports whether the message was accepted, and it does not raise. A failed
delivery must not turn into a 500 on the endpoint - see the comment on
send_recovery_code for why the CALLER's response must be identical either way.
"""

import html
import httpx

import config


# The Resend HTTP API. One endpoint, JSON in, JSON out - no SDK needed, which is
# also one less dependency to keep current. httpx is already a dependency because
# the scanner uses it.
_RESEND_ENDPOINT = "https://api.resend.com/emails"

# A sent email should not hold a request open. Ten seconds is generous for one API
# call and short enough that a provider outage does not become a hung endpoint.
_TIMEOUT_SECONDS = 10.0


# --- The senders -----------------------------------------------------------


# WHY THIS EXISTS
# PYTHON-SPECIFIC: this is a plain class used as an INTERFACE, not an abstract base
# class. Python has no `interface` keyword and does not need one - anything with a
# matching async send() works wherever a sender is expected, which is duck typing.
# The class exists to document the shape in one place and to give the type hints
# below something to name.
class Sender:
    name = "none"

    async def send(self, to: str, subject: str, text: str, html_body: str) -> bool:
        # A sender that has not been configured. Returns False rather than raising,
        # so an unconfigured deployment degrades to "email does not work" instead
        # of "the recovery endpoint 500s".
        return False


# WHY THIS EXISTS
# The real one. Note what it does NOT do: no retry, no queue, no template engine.
# A recovery code is a single short message with a 10-minute life, so a retry that
# lands after the code has expired is worse than the user pressing the button
# again - which is a thing they will do anyway, immediately, without being asked.
class ResendSender(Sender):
    name = "resend"

    def __init__(self, api_key: str, from_address: str):
        self._api_key = api_key
        self._from = from_address

    async def send(self, to: str, subject: str, text: str, html_body: str) -> bool:
        headers = {
            # Resend uses a bearer token, the same shape as our own session
            # tokens. The key is read from config and never logged.
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "from": self._from,
            # PYTHON-SPECIFIC: the API wants a list of recipients even for one.
            "to": [to],
            "subject": subject,
            # BOTH parts, deliberately. A text/plain alternative alongside the
            # HTML is what stops a plain-text mail client showing raw markup, and
            # it measurably helps deliverability - an HTML-only message with no
            # text part is a spam signal. For a 6-digit code the text version is
            # also the one most people will actually read.
            "text": text,
            "html": html_body,
        }

        try:
            # PYTHON-SPECIFIC: `async with` closes the client even if the request
            # raises. A new client per send is slightly wasteful and correct;
            # a module-level client shared across an app that may fork workers is
            # the kind of thing that produces intermittent event-loop errors.
            async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    _RESEND_ENDPOINT, headers=headers, json=payload
                )

            if response.status_code >= 400:
                # The body carries Resend's own reason - an unverified from-domain,
                # a malformed address, a revoked key. Printed because the operator
                # needs it and the user must not see it: the reason an email failed
                # can reveal whether an address exists.
                print(
                    f"[mailer] Resend refused the message ({response.status_code}): "
                    f"{response.text[:400]}"
                )
                return False

            return True

        except httpx.HTTPError as error:
            # Network-level failure: DNS, TLS, timeout. Never the message content.
            print(f"[mailer] Could not reach Resend: {type(error).__name__}: {error}")
            return False


# WHY THIS EXISTS
# Prints the message instead of sending it. For tests, and for working on the
# recovery flow without spending real deliveries.
#
# IT IS NEVER SELECTED AUTOMATICALLY. config.EMAIL_PROVIDER has to name it. That
# rule is the whole reason this class is safe to have: a fallback that quietly
# activates when an API key is missing would put a live recovery code in a log
# file while the UI told the user to check their inbox, and on a shared host that
# log is readable by more people than the inbox is.
class ConsoleSender(Sender):
    name = "console"

    async def send(self, to: str, subject: str, text: str, html_body: str) -> bool:
        print("=" * 70)
        print(f"[mailer:console] TO: {to}")
        print(f"[mailer:console] SUBJECT: {subject}")
        print("-" * 70)
        print(text)
        print("=" * 70)
        return True


# --- Choosing one ----------------------------------------------------------


# WHY THIS EXISTS
# The lookup that turns a configuration string into an object. One place to add a
# provider, and one place that decides what an unrecognised name does.
#
# PYTHON-SPECIFIC: the module-level `_sender` below is built at import and reused,
# so the API key is read once rather than on every send.
def _build_sender() -> Sender:
    if config.EMAIL_PROVIDER == "resend":
        # Both halves are required. A key with no from-address produces a 422 from
        # Resend on every call, so refusing here turns a per-request mystery into
        # one startup warning - see config.startup_warnings().
        if config.RESEND_API_KEY and config.EMAIL_FROM:
            return ResendSender(config.RESEND_API_KEY, config.EMAIL_FROM)

        return Sender()

    if config.EMAIL_PROVIDER == "console":
        return ConsoleSender()

    # An unknown name. Sender() sends nothing, and config already warned about it
    # at startup. Guessing at the intended provider would be worse.
    return Sender()


_sender = _build_sender()


def email_available() -> bool:
    # Lets an endpoint tell a user "recovery by email is not configured" instead of
    # accepting the request and doing nothing. The honesty rule that
    # /auth/forgot-password already follows.
    return _sender.name != "none"


# --- The one message this app sends ----------------------------------------


# WHY THIS EXISTS
# The recovery email, written once. The wording is part of the security design
# rather than decoration, and three choices in it are deliberate:
#
#   1. IT NAMES THE EXPIRY. "Expires in 10 minutes" tells a user who receives one
#      unexpectedly that the window is short, and tells the legitimate user not to
#      go and make a cup of tea.
#   2. IT SAYS WHAT TO DO IF IT WAS NOT THEM. An unexpected recovery code is the
#      first observable signal that somebody has a user's password. A line telling
#      them to change it is the only thing in the message that can prevent an
#      account takeover.
#   3. NO LINK CARRIES THE CODE. The code is typed into a page the user already
#      has open. A magic link in an email is a credential in a URL - it lands in
#      browser history, in Referer headers, and in any link-scanner the recipient's
#      mail provider runs, and scanners do follow links.
#
# Returns True when the provider accepted it. The caller must respond identically
# either way - see the endpoint in main.py.
async def send_recovery_code(to: str, code: str, name: str = "") -> bool:
    app = config.APP_NAME

    # PYTHON-SPECIFIC: a conditional expression, the equivalent of a ternary. The
    # greeting is skipped rather than reading "Hello ," when no name is known.
    greeting = f"Hello {name}," if name else "Hello,"

    subject = f"Your {app} sign-in code"

    text = (
        f"{greeting}\n\n"
        f"Your {app} sign-in code is:\n\n"
        f"    {code}\n\n"
        "It expires in 10 minutes and can be used once.\n\n"
        "This code was requested because two-factor authentication could not be "
        "completed with an authenticator app.\n\n"
        "If you did not request it, someone may know your password. Sign in and "
        f"change it now: {config.APP_URL}\n\n"
        f"- {app}"
    )

    # PYTHON-SPECIFIC / SECURITY: html.escape() on every interpolated value. The
    # name comes from a signup form, so it is user-controlled text going into a
    # markup document - the same injection shape as XSS, and an email client is a
    # renderer like any other. The code is generated by us and is digits only, but
    # escaping it too costs nothing and means the rule here is "escape everything"
    # rather than "escape the ones that need it", which is the rule that survives
    # somebody editing this template later.
    safe_greeting = html.escape(greeting)
    safe_code = html.escape(code)
    safe_app = html.escape(app)
    safe_url = html.escape(config.APP_URL, quote=True)

    html_body = f"""\
<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
            font-size:15px;line-height:1.55;color:#1A1D23;max-width:520px">
  <p>{safe_greeting}</p>
  <p>Your {safe_app} sign-in code is:</p>
  <p style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
            font-size:30px;font-weight:600;letter-spacing:0.12em;
            padding:16px 20px;background:#F5F6F8;border-radius:10px;
            display:inline-block;margin:8px 0">{safe_code}</p>
  <p style="color:#5A6472">It expires in 10 minutes and can be used once.</p>
  <p style="color:#5A6472">This code was requested because two-factor
     authentication could not be completed with an authenticator app.</p>
  <p style="color:#5A6472">If you did not request it, someone may know your
     password. <a href="{safe_url}" style="color:#1B3A6B">Sign in and change it
     now</a>.</p>
  <p style="color:#8A94A6;font-size:13px">- {safe_app}</p>
</div>"""

    return await _sender.send(to, subject, text, html_body)


# WHY THIS IS A SIBLING OF send_recovery_code RATHER THAN A PARAMETER ON IT
# The two messages differ in the one part that is not decoration: what the reader
# should DO if they did not ask for it. Folding them together would mean a flag
# selecting between two paragraphs of security advice, and the wrong branch of that
# flag is a message that tells somebody their account is fine when it is not.
#
# THE "IF THIS WASN'T YOU" LINE IS DELIBERATELY CALM HERE, and that is the whole
# difference. An unexpected 2FA code means somebody got PAST the password and the
# only useful advice is "change it now". An unexpected reset code means somebody
# typed an address into a public form, which anybody can do at any time, and the
# password has NOT changed and will not change unless this code is used. Telling
# that reader to panic would be false, and a product that raises a false alarm
# teaches people to ignore the real one.
#
# The other three rules are the same as the recovery mail and for the same reasons:
# the expiry is named, every interpolated value is escaped, and NO LINK CARRIES THE
# CODE - it is typed into the page the user already has open, so it never lands in
# browser history, a Referer header, or a mail provider's link scanner.
async def send_password_reset_code(to: str, code: str, name: str = "") -> bool:
    app = config.APP_NAME

    greeting = f"Hello {name}," if name else "Hello,"

    subject = f"Your {app} password reset code"

    text = (
        f"{greeting}\n\n"
        f"Someone asked to reset the password on your {app} account. Your code is:\n\n"
        f"    {code}\n\n"
        "It expires in 10 minutes and can be used once.\n\n"
        "Type it into the page you started the reset from, then choose a new "
        "password.\n\n"
        "If you did not ask for this, you can ignore this email. Your password has "
        "not been changed, and it will not change unless this code is used.\n\n"
        f"- {app}"
    )

    safe_greeting = html.escape(greeting)
    safe_code = html.escape(code)
    safe_app = html.escape(app)

    html_body = f"""\
<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
            font-size:15px;line-height:1.55;color:#1A1D23;max-width:520px">
  <p>{safe_greeting}</p>
  <p>Someone asked to reset the password on your {safe_app} account. Your code is:</p>
  <p style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
            font-size:30px;font-weight:600;letter-spacing:0.12em;
            padding:16px 20px;background:#F5F6F8;border-radius:10px;
            display:inline-block;margin:8px 0">{safe_code}</p>
  <p style="color:#5A6472">It expires in 10 minutes and can be used once. Type it
     into the page you started the reset from, then choose a new password.</p>
  <p style="color:#5A6472">If you did not ask for this, you can ignore this email.
     Your password has not been changed, and it will not change unless this code is
     used.</p>
  <p style="color:#8A94A6;font-size:13px">- {safe_app}</p>
</div>"""

    return await _sender.send(to, subject, text, html_body)
