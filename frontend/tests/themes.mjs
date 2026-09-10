import { chromium } from 'playwright'
import { shot } from './_shots.mjs'
const WEB='http://localhost:5173'
const EMAIL=process.argv[2], PASS='Tr0ubadour-Vault-91!'
const b=await chromium.launch({channel:'msedge'})
const errs=[]
for (const [theme, vp] of [['navy',{width:1280,height:900}],['white',{width:1280,height:900}],
                           ['system',{width:1280,height:900}],['navy',{width:390,height:844}]]) {
  const p=await b.newPage({viewport:vp, colorScheme: theme==='system'?'dark':'light'})
  p.on('pageerror',e=>errs.push(`[${theme}] ${e.message}`))
  await p.goto(`${WEB}/login`,{waitUntil:'networkidle'})
  await p.fill('#email',EMAIL); await p.fill('#password',PASS)
  await p.getByRole('button',{name:'Sign in',exact:true}).click()
  await p.waitForTimeout(1800)
  await p.evaluate((t)=>{ if(t==='system') document.documentElement.removeAttribute('data-theme')
                          else document.documentElement.setAttribute('data-theme',t) }, theme)
  await p.goto(`${WEB}/checkout/business`,{waitUntil:'networkidle'})
  await p.evaluate((t)=>{ if(t==='system') document.documentElement.removeAttribute('data-theme')
                          else document.documentElement.setAttribute('data-theme',t) }, theme)
  await p.waitForTimeout(900)
  const tag=`${theme}-${vp.width}`
  await p.screenshot({path:shot(`theme-${tag}`),fullPage:true})
  // horizontal overflow check: the body must never scroll sideways
  const over=await p.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+1)
  console.log(`${tag.padEnd(14)} overflow-x: ${over?'FAIL (page scrolls sideways)':'none'}`)
  await p.close()
}
console.log('\npage errors:', errs.length?errs.join('\n'):'(none)')
await b.close()
