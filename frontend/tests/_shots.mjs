/* Where the browser scripts put their screenshots.

   WHY THIS EXISTS: these three scripts were written as scratch and wrote their PNGs
   to a hardcoded C:/tmp path, which is exactly the habit that left the whole suite
   living in a temp directory. Screenshots are evidence - you read them to decide
   whether a render regressed - so they belong next to the script that produced them,
   in a directory that is ignored by version control rather than one that gets wiped.

   Override with SECUSCAN_SHOT_DIR to point somewhere else (CI artefacts, say). */

import { mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))

export const OUT = process.env.SECUSCAN_SHOT_DIR
  ? resolve(process.env.SECUSCAN_SHOT_DIR)
  : join(HERE, 'screenshots')

mkdirSync(OUT, { recursive: true })

/** Absolute path for one screenshot, e.g. shot('03-signup') -> <OUT>/03-signup.png */
export function shot(name) {
  return join(OUT, name.endsWith('.png') ? name : `${name}.png`)
}
