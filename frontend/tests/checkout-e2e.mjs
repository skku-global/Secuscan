import { chromium } from 'playwright'
import { shot as shotPath } from './_shots.mjs'

const WEB = 'http://localhost:5173'
const stamp = Date.now()
const EMAIL = `e2e${stamp}@example.com`
const PASS = 'Tr0ubadour-Vault-91!'
const NAME = 'Resume Tester'

const errors = []      // uncaught exceptions + console errors: the real prize
const failedReqs = []
const steps = []
let stepN = 0

const browser = await chromium.launch({ channel: 'msedge' })
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } })

page.on('pageerror', (e) => errors.push(`[pageerror] ${e.message}`))
page.on('console', (m) => {
  if (m.type() === 'error') errors.push(`[console.error] ${m.text()}`)
})
page.on('requestfailed', (r) =>
  failedReqs.push(`${r.method()} ${r.url()} :: ${r.failure()?.errorText}`))

async function shot(label) {
  stepN += 1
  const file = shotPath(`${String(stepN).padStart(2, '0')}-${label}`)
  await page.screenshot({ path: file, fullPage: true })
  steps.push(`${stepN}. ${label} -> ${page.url()}`)
  console.log(`--- step ${stepN}: ${label}\n    url: ${page.url()}`)
  return file
}

function ok(cond, msg) {
  console.log(`    ${cond ? 'PASS' : 'FAIL'}  ${msg}`)
  if (!cond) errors.push(`[assert] ${msg}`)
  return cond
}

// 1. Landing, pick Starter as a signed-out visitor
await page.goto(WEB, { waitUntil: 'networkidle' })
await shot('landing')
await page.getByRole('link', { name: 'Start with Starter' })
  .or(page.getByRole('button', { name: 'Start with Starter' })).first().click()
await page.waitForLoadState('networkidle')
await shot('after-pick-starter')
const wall = page.url()
ok(/\/login|\/signup|\/checkout/.test(wall), `Starter CTA led somewhere sane: ${wall}`)

// 2. If we hit the sign-in wall, cross to signup via "Create one" — the exact
//    path the plan used to die on.
if (/\/login/.test(wall)) {
  await page.getByRole('link', { name: /create one/i }).first().click()
  await page.waitForLoadState('networkidle')
  await shot('signup-via-create-one')
}

// 3. Sign up
if (/\/signup/.test(page.url())) {
  await page.fill('#name', NAME)
  await page.fill('#signup-email', EMAIL)
  await page.fill('#signup-password', PASS)
  await shot('signup-filled')
  await page.getByRole('button', { name: 'Create account', exact: true }).click()
  await page.waitForLoadState('networkidle')
  await page.waitForTimeout(1200)
  await shot('after-signup')
}

// THE load-bearing assertion: the chosen plan survived the sign-in wall.
const afterSignup = page.url()
ok(/\/checkout\/starter/.test(afterSignup),
   `plan survived signup (expected /checkout/starter, got ${afterSignup})`)

// 4. Pay with the mock card
if (!/\/checkout/.test(page.url())) {
  await page.goto(`${WEB}/checkout/starter`, { waitUntil: 'networkidle' })
  await shot('checkout-direct')
}
const bodyText = await page.locator('#main').innerText().catch(() => '')
ok(/starter/i.test(bodyText), 'checkout page names the Starter plan')
ok(!/\$?\s*0\.00/.test(bodyText.split('\n')[0] ?? ''), 'checkout shows a real figure')

await page.fill('#co-name', NAME)
await page.fill('#co-number', '4242424242424242')
await page.fill('#co-expiry', '12/34')
await page.fill('#co-cvc', '123')
await shot('checkout-filled')
await page.locator('button[type=submit]').first().click()
await page.waitForTimeout(2500)
await page.waitForLoadState('networkidle')
await shot('after-pay')
const receipt = await page.locator('#main').innerText().catch(() => '')
ok(/receipt|thank|paid|success|starter/i.test(receipt), 'landed on something receipt-shaped')

// 5. Settings billing panel — never rendered before today
await page.goto(`${WEB}/settings`, { waitUntil: 'networkidle' })
await page.waitForTimeout(1500)
await shot('settings-billing')
const set = await page.locator('#main').innerText().catch(() => '')
ok(!/Loading your account/i.test(set), 'settings resolved past the loading gate')
ok(/Starter/i.test(set), 'settings shows the purchased plan')
ok(/4242|Visa|ending/i.test(set), 'settings shows the card (brand/last4 only)')
ok(/receipt|history|invoice/i.test(set), 'settings shows billing history')

// 6. Cancel
const cancelBtn = page.getByRole('button', { name: /cancel/i }).first()
if (await cancelBtn.count()) {
  await cancelBtn.click()
  await page.waitForTimeout(600)
  await shot('cancel-panel-open')
  const confirm = page.getByRole('button', { name: /cancel|confirm|yes/i })
  const n = await confirm.count()
  await confirm.nth(n > 1 ? n - 1 : 0).click()
  await page.waitForTimeout(2000)
  await shot('after-cancel')
  const after = await page.locator('#main').innerText().catch(() => '')
  ok(/cancel|ends|until/i.test(after), 'cancellation reflected in the panel')
} else {
  ok(false, 'no cancel button found in the billing panel')
}

console.log('\n===== STEPS =====')
steps.forEach((s) => console.log(s))
console.log('\n===== PAGE ERRORS / FAILED ASSERTS =====')
console.log(errors.length ? errors.join('\n') : '(none)')
console.log('\n===== FAILED REQUESTS =====')
console.log(failedReqs.length ? failedReqs.join('\n') : '(none)')
console.log(`\nemail used: ${EMAIL}`)

await browser.close()
process.exit(errors.length ? 1 : 0)
