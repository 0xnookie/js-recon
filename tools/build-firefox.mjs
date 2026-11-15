// Builds the Firefox version of the extension into dist/firefox/ (and optionally a .zip / .xpi):
//   node tools/build-firefox.mjs                     → dist/firefox/
//   node tools/build-firefox.mjs --zip out.zip       → also a ZIP for addons.mozilla.org / about:debugging
//
// The code is shared; only the manifest differs. Firefox runs MV3 background code as an event page
// (background.scripts, not service_worker), needs a gecko id, and opens options via options_ui.
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ZipWriter } from '../src/zip.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const OUT = join(ROOT, 'dist', 'firefox');
const SHIP = ['manifest.json', 'icons', 'fonts', 'src', 'ui', 'LICENSE'];
export const GECKO_ID = 'js-recon@0xnookie';
export const MIN_FIREFOX = '128.0'; // MV3 host permissions at install, scripting world MAIN, storage.session

/** Chrome manifest → Firefox manifest (pure, tested). */
export function firefoxManifest(m) {
  const f = structuredClone(m);
  f.background = { scripts: [m.background.service_worker], type: m.background.type || 'module' };
  delete f.minimum_chrome_version;
  if (f.options_page) {
    f.options_ui = { page: f.options_page, open_in_tab: true };
    delete f.options_page;
  }
  f.browser_specific_settings = { gecko: { id: GECKO_ID, strict_min_version: MIN_FIREFOX } };
  return f;
}

function files(dir, out = []) {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) files(p, out);
    else if (!/^(?:\.DS_Store|Thumbs\.db|desktop\.ini)$/.test(n)) out.push(p);
  }
  return out;
}

export async function build({ zip = null } = {}) {
  rmSync(OUT, { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });
  for (const p of SHIP) cpSync(join(ROOT, p), join(OUT, p), { recursive: true });
  const manifest = firefoxManifest(JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8')));
  writeFileSync(join(OUT, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  if (zip) {
    const z = new ZipWriter();
    for (const p of files(OUT).sort()) await z.add(relative(OUT, p).split(sep).join('/'), new Uint8Array(readFileSync(p)));
    writeFileSync(zip, Buffer.from(await z.blob().arrayBuffer()));
  }
  return { dir: OUT, version: manifest.version, zip };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1].replace(/\//g, sep)) {
  const i = process.argv.indexOf('--zip');
  const r = await build({ zip: i > 0 ? process.argv[i + 1] : null });
  console.log(`Firefox build ${r.version} → ${relative(ROOT, r.dir)}${r.zip ? ` and ${r.zip}` : ''}`);
}
