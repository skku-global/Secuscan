"""
TESTS FOR DISCOVERY (discovery.py) - THE PARSER AND THE HOST RULE.

This module runs before any check and hands its result to all of them, which makes it
the one place where a bug is not worth one wrong finding but a wrong premise underneath
every finding in the report. It had no suite of its own, and the four properties below
were each found by putting ordinary markup through it and comparing the answer to what a
browser shows.

Verifies:
  1. An ordinary login page parses: the form, its action resolved against the page, the
     fields with their types, the links resolved absolute, and the visible text.
  2. NOTHING INSIDE <template> IS REAL. Template contents are inert by specification -
     no browser renders them and nothing in one can be submitted - yet a form in there
     counted as a form. login_form() takes the FIRST form with a password box, so a
     "change password" modal template earlier in the document took the login's place;
     and has_password_input() is what _is_login_page believes, so an SPA shell carrying
     one template made every probed path look like a login page. Asserted in both
     directions, including the worse half: a template's </form> must not close the REAL
     form around it.
  3. AN UNCLOSED TAG IS STILL A TAG. A <form> or <a> whose closing tag never arrived was
     dropped entirely. Every browser closes both at the end of the document. A login page
     missing one </form> reported "no login form found", which skips the whole
     authenticated tier against a site whose only fault is one absent tag.
  4. A SCRIPT BODY IS NOT PAGE TEXT - the discovery half of the rule _session.visible_text
     enforces on responses. <noscript> is suppressed as text but kept as markup, which is
     the right way round for a scanner that runs no JavaScript.
  5. THE HOST RULE, which is the most important function in the file: every candidate URL
     passes through it before a request is made, and it is all that stands between this
     scanner and probe traffic aimed at a third party who never consented. Pinned in both
     directions - "notexample.com" and an OAuth provider are refused, userinfo before an @
     cannot smuggle a host past it, and "www." is not a site boundary, because treating it
     as one made scanning acme.com and www.acme.com two different scans of one site.
  6. Cookies are collected from the REDIRECT HOPS too, and repeated Set-Cookie headers
     all survive.
  7. A page only counts as a login page with a password field AND a non-error status.
  8. Candidates: off-site dropped before de-duplication, fragments stripped, links the
     site publishes ahead of paths we guessed, and the separator a real sign-in href
     actually uses.
  9. It never raises. Discovery runs before the checks, so an exception here is a scan
     with no findings at all rather than a scan reporting what it could.
 10. A SIGNUP FORM IS NEVER THE LOGIN FORM. login_form() returned the first form with a
     password box, and _session.py posts the client's credentials at whatever that is -
     so on a page whose "Create your account" panel sits above the sign-in form, the scan
     tried to REGISTER on a production system nobody asked us to write to. This is the
     only place in discovery where choosing wrong does something to the client's site
     rather than to our report, and the only one where the safe answer is None.
"""

import httpx

import _path  # noqa: F401 - puts backend/ on sys.path
from scanning.discovery import (
    LOGIN_HINT,
    ScanTarget,
    SIGNUP_HINT,
    Field,
    Form,
    Page,
    _candidates,
    _collect_cookies,
    _is_login_page,
    _parse_page,
    _same_site,
)

PASS_COUNT = 0
FAIL_COUNT = 0

SITE = "https://example.com"
PAGE_URL = SITE + "/login"


def check(label, got, want):
    global PASS_COUNT, FAIL_COUNT
    ok = got == want
    if ok:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f"   (got {got!r}, wanted {want!r})"))


def parse(html, url=PAGE_URL, status=200, headers=None, history=()):
    """Real markup through the real parser. Nothing here hand-builds a Form."""
    request = httpx.Request("GET", url)
    return _parse_page(httpx.Response(
        status, text=html, headers=headers or {}, request=request, history=list(history)
    ))


def field_names(page, index=0):
    """The field names of one parsed form, or [] when no such form was recorded.

    Tolerant on purpose. This suite is also run against the PRE-FIX parser to prove its
    assertions fail there, and a bare page.forms[0] raises IndexError in exactly the
    cases being pinned - which stops the run instead of reporting the failure.
    """
    try:
        return [f.name for f in page.forms[index].fields]
    except IndexError:
        return []


def first(seq):
    """seq[0], or None when it is empty. Tolerant for the same reason as field_names."""
    return seq[0] if seq else None


LOGIN_FORM = (
    "<form action='/session' method='post'>"
    "<input type='email' name='email'>"
    "<input type='password' name='password'>"
    "<input type='submit' value='Sign in'>"
    "</form>"
)


def run_tests():
    print("--- 1. AN ORDINARY LOGIN PAGE -----------------------------")

    p = parse(
        "<html><body><h1>Sign in</h1>"
        + LOGIN_FORM
        + "<a href='/register'>Create an account</a>"
        "<a href='https://status.example.net'>Status</a>"
        "</body></html>"
    )
    check("one form", len(p.forms), 1)
    check("the action is resolved against the page", p.forms[0].submit_url, SITE + "/session")
    check("the method is lowercased", p.forms[0].method, "post")
    check("three fields", field_names(p), ["email", "password", ""])
    check("the password field is found", [f.name for f in p.forms[0].password_fields()], ["password"])
    check("the page counts as a login page", p.has_password_input(), True)
    check("links are resolved absolute",
          first(p.links), (SITE + "/register", "Create an account"))
    check("an off-site link is still RECORDED here", len(p.links), 2)
    check("the visible text is kept", "Sign in" in p.text, True)

    # An empty action means "submit to this page", which is what urljoin returns.
    p = parse("<form method='post'><input type='password' name='pw'></form>")
    check("an empty action submits to the page itself", p.forms[0].submit_url, PAGE_URL)

    p = parse("<form action='https://auth.example.com/s' method='POST'>"
              "<input type='password' name='pw'></form>")
    check("an absolute action is left alone", p.forms[0].submit_url, "https://auth.example.com/s")
    check("METHOD='POST' is lowercased", p.forms[0].method, "post")

    print("\n--- 2. NOTHING INSIDE <template> IS REAL -------------------")

    p = parse("<html><body><template>" + LOGIN_FORM + "</template></body></html>")
    check("a form in a template is not a form", p.forms, [])
    check("...nor a loose password field", p.loose_password_fields, [])
    check("...so the page is not a login page", p.has_password_input(), False)
    check("...and _is_login_page agrees", _is_login_page(p), False)

    p = parse("<template><a href='/logout'>Sign out</a></template>")
    check("a link in a template is not a link", p.links, [])

    # THE WORSE HALF. A template's </form> used to close the REAL form wrapping it, so
    # every field after the template - here the password box - was lost from the form
    # and the form was recorded half-built.
    p = parse(
        "<form action='/session' method='post'>"
        "<input type='email' name='email'>"
        "<template><form action='/change-password'><input type='password' name='new'></form></template>"
        "<input type='password' name='password'>"
        "</form>"
    )
    check("the template's </form> does not close the real form", len(p.forms), 1)
    check("...and the fields after it are still in it",
          field_names(p), ["email", "password"])
    check("...so the real form still has its password", p.forms[0].has_password(), True)

    # A real form standing next to a template is unaffected.
    p = parse("<template><form><input type='password' name='new'></form></template>" + LOGIN_FORM)
    check("a real form beside a template is still found", len(p.forms), 1)
    check("...and it is the real one", p.forms[0].submit_url, SITE + "/session")

    # ...and <noscript> is deliberately NOT inert: the scanner runs no JavaScript, so a
    # noscript form is precisely the form a client like this one is given.
    p = parse("<noscript>" + LOGIN_FORM + "</noscript>")
    check("a form in <noscript> IS a form", len(p.forms), 1)

    print("\n--- 3. AN UNCLOSED TAG IS STILL A TAG ---------------------")

    UNCLOSED = ("<form action='/session' method='post'>"
                "<input type='email' name='email'>"
                "<input type='password' name='password'>")

    p = parse("<html><body>" + UNCLOSED)
    check("a form never closed is still a form", len(p.forms), 1)
    check("...with its fields", field_names(p), ["email", "password"])
    check("...so the page is a login page", _is_login_page(p), True)

    p = parse("<html><body>" + UNCLOSED + "</body></html>")
    check("a form closed only by </body> is still a form", len(p.forms), 1)

    p = parse("<a href='/logout'>Sign out")
    check("an anchor never closed is still a link",
          p.links, [(SITE + "/logout", "Sign out")])

    # Markup that relies on a block boundary to close its anchors - a nav written as
    # "<li><a href=/x>One" repeated - used to lose every link but the last.
    p = parse("<ul><li><a href='/login'>Sign in</li><li><a href='/help'>Help</li></ul>")
    check("consecutive unclosed anchors are all kept", len(p.links), 2)
    check("...the first one is not lost", first(p.links), (SITE + "/login", "Sign in"))

    # And the ordinary case is untouched: no duplicates from the flush.
    p = parse("<a href='/login'>Sign in</a><a href='/help'>Help</a>")
    check("closed anchors are recorded once each", len(p.links), 2)

    print("\n--- 4. A SCRIPT BODY IS NOT PAGE TEXT ---------------------")

    p = parse("<script>var msg = 'two-factor authentication is on';</script><p>Welcome</p>")
    check("script text is not page text", "two-factor" in p.text, False)
    check("...and the real text survives", p.text, "Welcome")

    p = parse("<style>.captcha { display:none }</style><p>Welcome</p>")
    check("style text is not page text", "captcha" in p.text, False)

    p = parse("<noscript>Enable JavaScript</noscript><p>Welcome</p>")
    check("noscript text is not page text", "Enable JavaScript" in p.text, False)

    # A depth counter, not a boolean: invalid but real markup nests these, and a stray
    # closing tag must not suppress the rest of the page.
    p = parse("</script><p>Welcome</p>")
    check("a stray </script> does not suppress the page", p.text, "Welcome")

    print("\n--- 5. THE HOST RULE --------------------------------------")

    HOSTS = [
        # (base host, candidate, same site?)
        ("example.com", SITE + "/login", True),
        ("example.com", "https://www.example.com/login", True),
        ("example.com", "https://accounts.example.com/login", True),
        ("www.example.com", "https://example.com/login", True),
        # THE WWW CASE, which made one site behave as two. accounts.example.com is
        # neither a parent nor a child of www.example.com, so the sign-in link on the
        # customer's own homepage was discarded as a third party.
        ("www.example.com", "https://accounts.example.com/login", True),
        # THE DOT IS WHAT MAKES THIS SAFE.
        ("example.com", "https://notexample.com/login", False),
        ("www.example.com", "https://wwwexample.com/login", False),
        # The reason this function exists at all.
        ("example.com", "https://accounts.google.com/o/oauth2/auth", False),
        ("example.com", "https://login.microsoftonline.com/common", False),
        # Userinfo cannot smuggle a host past it: the host is what follows the @.
        ("example.com", "https://example.com@evil.com/", False),
        ("example.com", "https://evil.com@example.com/", True),
        # Non-navigational schemes have no host at all.
        ("example.com", "mailto:security@example.com", False),
        ("example.com", "tel:+15550100", False),
        ("example.com", "javascript:void(0)", False),
        ("example.com", "", False),
        # Case and port are not part of the identity.
        ("example.com", "https://EXAMPLE.COM/login", True),
        ("EXAMPLE.COM", SITE + "/login", True),
        ("example.com", "https://example.com:8443/login", True),
    ]
    for base, url, want in HOSTS:
        check(f"{base} -> {url or '(empty)'}", _same_site(base, url), want)

    print("\n--- 6. COOKIES FROM THE REDIRECT HOPS TOO -----------------")

    # A session cookie is very often set by the redirect rather than by the final 200.
    request = httpx.Request("GET", PAGE_URL)
    hop = httpx.Response(
        302,
        headers=[("set-cookie", "csrftoken=abc; Path=/"), ("set-cookie", "lang=en")],
        request=request,
    )
    final = httpx.Response(
        200, text="<p>Hi</p>",
        headers=[("set-cookie", "sessionid=xyz; HttpOnly")],
        request=request, history=[hop],
    )
    check("every Set-Cookie survives, hops first",
          _collect_cookies(final),
          ["csrftoken=abc; Path=/", "lang=en", "sessionid=xyz; HttpOnly"])

    p = _parse_page(final)
    check("the parsed page carries them", len(p.set_cookies), 3)
    check("...while dict(headers) would have kept one", len(p.headers.get("set-cookie", "").split(",")) >= 1, True)

    print("\n--- 7. WHAT COUNTS AS A LOGIN PAGE ------------------------")

    check("None is not a login page", _is_login_page(None), False)
    check("a 200 with no password field is not one",
          _is_login_page(parse("<h1>Log in</h1><p>Coming soon</p>")), False)
    check("a 404 carrying a login form is not one",
          _is_login_page(parse(LOGIN_FORM, status=404)), False)
    check("a 500 carrying a login form is not one",
          _is_login_page(parse(LOGIN_FORM, status=500)), False)
    check("a 200 with a password field is one",
          _is_login_page(parse(LOGIN_FORM)), True)
    check("a React screen with no <form> at all is one",
          _is_login_page(parse("<div><input type='email' name='email'>"
                               "<input type='password' name='password'>"
                               "<button>Sign in</button></div>")), True)

    print("\n--- 8. CANDIDATES -----------------------------------------")

    home = parse(
        "<a href='/users/sign_in'>Members area</a>"
        "<a href='/portal'>Sign in</a>"
        "<a href='https://accounts.google.com/o/oauth2/auth'>Sign in with Google</a>"
        "<a href='/login#form'>Log in</a>"
        "<a href='/portal'>Sign in</a>"
        "<a href='/pricing'>Pricing</a>",
        url=SITE + "/",
    )
    got = _candidates(SITE, "example.com", home, LOGIN_HINT, ("/login", "/signin"))
    check("links first, off-site dropped, fragment stripped, deduplicated",
          got,
          [SITE + "/users/sign_in", SITE + "/portal", SITE + "/login", SITE + "/signin"])
    check("the OAuth provider never enters the list",
          any("google" in c for c in got), False)
    check("a page with nothing on it still gets the guessed paths",
          _candidates(SITE, "example.com", None, LOGIN_HINT, ("/login",)), [SITE + "/login"])

    # The separator a real sign-in href uses. Written for link TEXT, the pattern allowed
    # only a space - so Rails' /users/sign_in and the common /sign-in matched nothing,
    # and a login living off the guessed paths was reachable by neither route.
    for href in ("/users/sign_in", "/sign-in", "/log-in", "/signin", "/auth/login",
                 "Sign In", "Log in", "My Account"):
        check(f"login hint matches {href!r}", bool(LOGIN_HINT.search(href)), True)
    for href in ("/users/sign_up", "/sign-up", "Create an account", "Get started"):
        check(f"signup hint matches {href!r}", bool(SIGNUP_HINT.search(href)), True)
    # And the other direction, because a hint that matches everything is not a hint.
    for href in ("/pricing", "/blog/design-notes", "/api/v1/users", "Contact us",
                 "/docs/authentication-guide"):
        check(f"login hint does NOT match {href!r}", bool(LOGIN_HINT.search(href)), False)
    check("a signup link is not read as a login link",
          bool(LOGIN_HINT.search("/users/sign_up")), False)

    # The host rule reaches candidates through the same door, so the www case shows up
    # as an outcome rather than as a boolean.
    home = parse("<a href='https://accounts.example.com/login'>Sign in</a>", url="https://www.example.com/")
    got = _candidates("https://www.example.com", "www.example.com", home, LOGIN_HINT, ())
    check("with a www base, the subdomain sign-in link is kept",
          got, ["https://accounts.example.com/login"])

    print("\n--- 9. IT NEVER RAISES ------------------------------------")

    for label, body in [
        ("an empty body", ""),
        ("a truncated tag", "<form action='/x"),
        ("an unbalanced close", "</form></a></template>"),
        ("binary served as html", "\x00\x01\x02<<>>&#x"),
        ("a form inside a form", "<form action='/a'><form action='/b'>"
                                 "<input type='password' name='p'></form></form>"),
        ("a template that never closes", "<template>" + LOGIN_FORM),
    ]:
        try:
            parse(body)
            ok = True
        except Exception as exc:
            ok = f"{type(exc).__name__}"
        check(f"{label} parses without raising", ok, True)

    # A template left open swallows the rest of the document rather than leaking an
    # unreachable form - the safe direction of the two.
    check("an unclosed template yields no form", parse("<template>" + LOGIN_FORM).forms, [])

    print("\n--- 10. SIGNUP FORMS ARE TOLD APART -----------------------")

    p = parse("<form action='/register' method='post'>"
              "<input type='email' name='email'>"
              "<input type='password' name='password'>"
              "<input type='password' name='password_confirmation'>"
              "</form>")
    check("two password boxes read as a signup", p.forms[0].looks_like_signup(), True)

    p = parse("<form action='/register' method='post'>"
              "<input type='email' name='email'>"
              "<input type='password' name='password'>"
              "<input type='password' name='confirm'>"
              "</form>")
    check("a 'confirm' password box reads as a signup", p.forms[0].looks_like_signup(), True)

    check("a login form does not", parse(LOGIN_FORM).forms[0].looks_like_signup(), False)

    # A login form carrying a "verify" CHECKBOX is still a login form: the confirm hint
    # only counts on a password field.
    p = parse("<form action='/session' method='post'>"
              "<input type='email' name='email'>"
              "<input type='password' name='password'>"
              "<input type='checkbox' name='verify_device'>"
              "</form>")
    check("a 'verify' checkbox does not make it a signup", p.forms[0].looks_like_signup(), False)

    print("\n--- 11. FIELD TYPING, WHICH _field_names RESTS ON ---------")

    p = parse("<form action='/session' method='post'>"
              "<input name='login_id'>"
              "<input TYPE='HIDDEN' NAME='csrf' value='n42'>"
              "<input type='text' id='emailAddress'>"
              "<select name='tenant'><option>a</option></select>"
              "<textarea name='notes'></textarea>"
              "<input type='PASSWORD' name='password'>"
              "</form>")
    f = {x.name: x for x in p.forms[0].fields}
    check("an input with no type is a text box", f["login_id"].type, "text")
    check("TYPE='HIDDEN' is lowercased", f["csrf"].type, "hidden")
    check("...and its attributes are readable", f["csrf"].attrs.get("value"), "n42")
    check("a nameless input falls back to its id", f["emailAddress"].name, "emailAddress")
    check("a select carries its tag as its type", f["tenant"].type, "select")
    check("a textarea likewise", f["notes"].type, "textarea")
    check("type='PASSWORD' is still a password", f["password"].type, "password")
    check("...and the form knows it", p.forms[0].has_password(), True)

    # A password box outside any form is carried separately - a weaker signal, but the
    # only one a React login screen gives.
    p = parse("<div><input type='password' name='password'></div>")
    check("a loose password field is recorded", len(p.loose_password_fields), 1)
    check("...but it is not a form", p.forms, [])
    p = parse("<div><input type='text' name='email'></div>")
    check("a loose TEXT field is not recorded", p.loose_password_fields, [])

    print("\n--- 12. A SIGNUP FORM IS NEVER THE LOGIN FORM -------------")

    # The one property in this file whose wrong answer does something to the CLIENT'S
    # site rather than to our report. _session.py posts the supplied username and
    # password at whatever login_form() returns; aimed at a registration form that is an
    # attempt to create an account on a production system. "The first form with a
    # password box" was enough to hit it, because a SaaS page that is both homepage and
    # login page puts the "Create your account" panel above the fold and the sign-in
    # form below it. Form.looks_like_signup() already existed for the password-policy
    # check; this one simply had never asked.

    SIGNUP = ("<form action='/register' method='post'>"
              "<input type='email' name='new_email'>"
              "<input type='password' name='password'>"
              "<input type='password' name='password_confirmation'>"
              "</form>")
    NEWSLETTER = "<form action='/subscribe'><input type='email' name='e'></form>"
    CHANGE_PW = ("<form action='/password' method='post'>"
                 "<input type='password' name='current'>"
                 "<input type='password' name='new'>"
                 "<input type='password' name='confirm'></form>")

    def login_action(body):
        """Where a scan would POST the client's credentials for this page."""
        form = ScanTarget(url=SITE, login=parse(body, url=SITE + "/")).login_form()
        return form.submit_url if form else None

    # Every one of these used to answer /register.
    check("the signup panel above the sign-in form does not win",
          login_action(SIGNUP + LOGIN_FORM), SITE + "/session")
    check("...nor with a decoy form ahead of both",
          login_action(NEWSLETTER + SIGNUP + LOGIN_FORM), SITE + "/session")
    check("a change-password widget is not the login form either",
          login_action(CHANGE_PW + LOGIN_FORM), SITE + "/session")
    check("the sign-in form first is still the sign-in form",
          login_action(LOGIN_FORM + SIGNUP), SITE + "/session")
    check("an ordinary login page is unaffected",
          login_action(LOGIN_FORM), SITE + "/session")

    # AND NONE RATHER THAN THE SIGNUP FORM when that is all the page has. The caller
    # already handles None: it posts the conventional field names at the login page's
    # own URL, which is what a JavaScript login screen needs anyway. So the honest
    # answer costs nothing, and the tempting one is a write to someone's database.
    check("a page with only a registration form yields no login form",
          login_action(SIGNUP), None)
    check("...and a loose signup form does not become one",
          login_action(NEWSLETTER + SIGNUP), None)
    check("a page with no password form at all yields none",
          login_action(NEWSLETTER), None)
    check("no login page at all yields none", ScanTarget(url=SITE).login_form(), None)

    # The mirror image, so the two cannot drift into agreeing. A signup page very often
    # carries an "already have an account?" sign-in form as well, and the password-policy
    # check reading that one would judge the site on a form that enforces no policy.
    def signup_action(body):
        form = ScanTarget(url=SITE, signup=parse(body, url=SITE + "/")).signup_form()
        return form.submit_url if form else None

    check("a sign-in form on the signup page does not win",
          signup_action(LOGIN_FORM + SIGNUP), SITE + "/register")
    check("...and an ordinary signup page is unaffected",
          signup_action(SIGNUP), SITE + "/register")
    # Unlike login_form, the fallback here IS the first form: nothing is posted to this
    # one, it is read. A signup form we cannot recognise is still better evidence of the
    # site's password policy than no form at all.
    check("an unrecognised signup form is still read",
          signup_action(LOGIN_FORM), SITE + "/session")
    check("no signup page at all yields none", ScanTarget(url=SITE).signup_form(), None)

    print(f"\n{PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAIL_COUNT > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()
