import { chromium } from 'playwright'
import { shot } from './_shots.mjs'
const WEB='http://localhost:5173'
const EMAIL=process.argv[2], PASS='Tr0ubadour-Vault-91!'
const b=await chromium.launch({channel:'msedge'})
const p=await b.newPage({viewport:{width:1280,height:900}})
await p.goto(`${WEB}/login`,{waitUntil:'networkidle'})
await p.fill('#email',EMAIL)
await p.fill('#password',PASS)
p.on('console',m=>{if(m.type()==='error')console.log('[console.error]',m.text())})
p.on('pageerror',e=>console.log('[pageerror]',e.message))
await p.getByRole('button',{name:'Sign in',exact:true}).click()
await p.waitForTimeout(2500)
console.log('logged in ->',p.url())
const le=await p.locator('.auth-error').innerText().catch(()=>'(no .auth-error)')
console.log('login error box:',le)
// Now fail ONLY /2fa/status and see what happens to billing.
await p.route('**/2fa/status',(r)=>r.abort('failed'))
await p.goto(`${WEB}/settings`,{waitUntil:'networkidle'})
await p.waitForTimeout(1800)
await p.screenshot({path:shot('coupling-2fa-down'),fullPage:true})
const t=await p.locator('#main').innerText().catch(()=>'')
console.log('--- page text ---'); console.log(t.slice(0,700))
console.log('\nbilling visible with /2fa/status down?', /Plan and billing/i.test(t))
console.log('cancel/keep control present?', /Keep my plan|Cancel/i.test(t))
await b.close()
