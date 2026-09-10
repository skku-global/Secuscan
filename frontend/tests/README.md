# SecuScan browser tests

Three Playwright scripts that drive a real browser against the running app. They
cover the half the Python suites cannot reach: whether the pages render, whether
the buttons are actually wired, and whether the themes hold up.

## Before you run anything

**Both servers have to be up**, in two terminals:

```
cd backend   && python -m uvicorn main:app --host 127.0.0.1 --port 8000
cd frontend  && npm run dev            # http://localhost:5173
```

The scripts hardcode `localhost:5173`, which is safe because `vite.config.js` sets
`strictPort` — Vite either gets 5173 or refuses to start, rather than drifting to
5174 and serving from an origin that Google Sign-In and CORS do not recognise.

**They drive installed Microsoft Edge**, via `channel: 'msedge'`. That is why
`npm install` does not need Playwright's bundled browsers, and why this repo was
installed with `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` — roughly half a gigabyte of
Chromium, Firefox and WebKit that nothing here would ever launch. If you drop the
`channel` option from a script, run `npx playwright install chromium` first, or you
get an executable-not-found error that does not mention the missing download.

## Running them, in the order they expect

`checkout-e2e.mjs` **creates** an account. The other two **need one that already
exists**, passed as the first argument — so run it first and reuse the address it
prints on its last line.

```
node tests/checkout-e2e.mjs                       # prints: email used: e2e<stamp>@example.com
node tests/themes.mjs         e2e<stamp>@example.com
node tests/coupling-check.mjs e2e<stamp>@example.com
```

All three share one hardcoded password constant (`PASS` / `PASS=` at the top of each
file). It is a throwaway development credential for accounts these scripts create on
a development database — which is the only kind of database any of this should be
pointed at, for the same reason the backend live suites carry that warning.

## What each one is for

**`checkout-e2e.mjs` — the one with a verdict.** Walks landing → pick a plan →
signup via "Create one" → checkout → receipt → Settings billing panel → cancel, and
asserts along the way: that Settings resolves past its loading gate, shows the
purchased plan, shows the card as brand and last4 only, lists billing history, and
reflects the cancellation. It collects `pageerror` and `console.error` throughout —
which is the real prize, since a React page can render something plausible while
throwing — and **exits non-zero** if any assert or page error fired.

**`themes.mjs` — rendering across the three themes.** Logs in, then loads the
checkout page under `navy`, `white`, `system` (dark) and `navy` at 390px, screenshots
each, and checks the one thing that is easy to break and invisible in a screenshot
you skim: that the page never scrolls sideways.

**`coupling-check.mjs` — one failure must not take out its neighbour.** Aborts
`/2fa/status` only, then asks whether the billing panel still renders and its
controls are still present. The bug it exists to catch is a Settings page where one
failed request blanks a section that had nothing to do with it.

**`_shots.mjs`** decides where the PNGs go: `tests/screenshots/`, overridable with
`SECUSCAN_SHOT_DIR` for CI artefacts. That directory is gitignored — screenshots are
evidence you read once and regenerate, not source. The scripts originally wrote to a
hardcoded `C:/tmp` path, which is the habit that left this whole suite living in a
temp directory.

## Only the first one has a meaningful exit code

Same split as `backend/tests/`, for the same reason. `checkout-e2e.mjs` asserts, so
a non-zero exit means a bug. `themes.mjs` and `coupling-check.mjs` print for a human
to read and never call `process.exit`, so they always exit 0 — their output and their
screenshots are the result, and treating their exit code as a verdict would invent a
pass out of nothing.

There is deliberately no runner tying the three together. A runner implies one
verdict, and two of these do not have one.
