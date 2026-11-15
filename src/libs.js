// Known-vulnerable JavaScript libraries: finds library versions in scanned code (banner comments,
// version constants), in script URLs and file names, and matches them against the advisories in
// src/vulndb.js (generated from the retire.js repository). Offline, no network.
// Pure: no chrome.* APIs, so it can be unit-tested with Node.

import { VULNDB, VULNDB_DATE } from './vulndb.js';
import { SEV_RANK } from './util.js';

const VERSION = '[0-9][0-9.a-z_\\-]+';
const MAX_PER_PATTERN = 4; // a bundle rarely carries more than a couple of copies of one library
const MAX_SPAN = 4096; // a content pattern's match must not span more than this (".*" on minified code)

/**
 * Text that every match of `src` must contain (the longest run of plain characters outside groups,
 * classes and optional parts), so most patterns are skipped with one indexOf on code that can't match.
 * '' when the pattern has a top-level alternation or no usable run.
 */
export function requiredLiteral(src) {
  let best = '';
  let run = '';
  let depth = 0;
  const end = () => {
    if (run.length > best.length) best = run;
    run = '';
  };
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '§') {
      // §§version§§
      end();
      i = src.indexOf('§§', i + 2) + 1 || src.length;
      continue;
    }
    if (c === '\\') {
      const n = src[i + 1];
      i++;
      if (n && /[^A-Za-z0-9]/.test(n)) {
        if (depth === 0) run += n;
      } else end(); // \s \d \w \b \1 …
      continue;
    }
    if (c === '[') {
      end();
      while (i < src.length && src[i] !== ']') i += src[i] === '\\' ? 2 : 1;
      continue;
    }
    if (c === '(') {
      end();
      depth++;
      continue;
    }
    if (c === ')') {
      depth = Math.max(0, depth - 1);
      end();
      continue;
    }
    if (c === '|') {
      if (depth === 0) return '';
      end();
      continue;
    }
    if (c === '?' || c === '*' || c === '{') {
      run = run.slice(0, -1); // the previous character is optional
      end();
      if (c === '{') while (i < src.length && src[i] !== '}') i++;
      continue;
    }
    if (c === '+' || c === '.' || c === '^' || c === '$') {
      end();
      continue;
    }
    if (depth === 0) run += c;
    else end();
  }
  end();
  return best.length >= 3 ? best : '';
}

let compiled = null;
function compile() {
  const make = (src) => {
    try {
      return { re: new RegExp(src.replace(/§§version§§/g, VERSION), 'g'), lit: requiredLiteral(src) };
    } catch {
      return null;
    }
  };
  compiled = VULNDB.map((lib) => ({
    name: lib.name,
    vulns: lib.vulns,
    content: lib.content.map(make).filter(Boolean),
    uri: lib.uri.map(make).filter(Boolean),
    file: lib.file.map(make).filter(Boolean),
  }));
  return compiled;
}

/** Version as found ("3.4.1.min" from a file name, "2.0.0-" …) → clean version, or null. */
export function cleanVersion(v) {
  v = String(v || '').replace(/[._-]+min$/i, '').replace(/[._-]+$/, '');
  return /^\d+(?:\.\d+)*(?:[.-]?[0-9a-z_]+)*$/i.test(v) && v.length <= 40 ? v : null;
}

const part = (n) => (n === undefined || n === '' ? 0 : /^\d+$/.test(n) ? Number(n) : n);

/** retire.js ordering: numeric parts compare as numbers, a pre-release tag sorts below the release. */
export function isAtOrAbove(a, b) {
  const x = String(a).split(/[.-]/);
  const y = String(b).split(/[.-]/);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = part(x[i]);
    const q = part(y[i]);
    if (typeof p !== typeof q) return typeof p === 'number';
    if (p > q) return true;
    if (p < q) return false;
  }
  return true;
}

/** Advisories in `lib` that cover `version`: [{ ids, severity, summary, atOrAbove, below, link }]. */
export function vulnsFor(libName, version) {
  const lib = (compiled || compile()).find((l) => l.name === libName);
  if (!lib || !version) return [];
  const out = [];
  for (const [atOrAbove, below, severity, ids, summary, link] of lib.vulns) {
    if (atOrAbove && atOrAbove !== '0' && !isAtOrAbove(version, atOrAbove)) continue;
    if (isAtOrAbove(version, below)) continue;
    out.push({ ids, severity, summary, atOrAbove, below, link });
  }
  return out;
}

function scan(list, text, max = MAX_PER_PATTERN) {
  const hits = [];
  for (const { re, lit } of list) {
    if (lit && !text.includes(lit)) continue;
    re.lastIndex = 0;
    let m;
    let n = 0;
    while ((m = re.exec(text)) && n < max) {
      if (m[0] === '') {
        re.lastIndex++;
        continue;
      }
      n++;
      if (m[0].length > MAX_SPAN) continue;
      const v = cleanVersion(m[1]);
      if (v) hits.push({ version: v, index: m.index + Math.max(0, m[0].indexOf(m[1])), length: m[1].length });
    }
  }
  return hits;
}

/**
 * Libraries in a piece of code (and its URL): [{ name, version, via, index, length }], one per
 * library + version. `via` is 'content', 'url' or 'file name'.
 */
export function detectLibraries(code, url = '') {
  const libs = compiled || compile();
  const out = new Map();
  const add = (name, hit, via) => {
    const k = name + ' ' + hit.version;
    if (!out.has(k)) out.set(k, { name, version: hit.version, via, index: hit.index ?? -1, length: hit.length || 0 });
  };
  let path = '';
  let file = '';
  if (url && /^https?:/i.test(url)) {
    try {
      const u = new URL(url);
      path = u.pathname + u.search;
      file = decodeURIComponent(u.pathname.split('/').pop() || '');
    } catch {
      /* not a URL */
    }
  }
  for (const lib of libs) {
    if (typeof code === 'string' && code) for (const hit of scan(lib.content, code)) add(lib.name, hit, 'content');
    if (path) for (const hit of scan(lib.uri, path, 1)) add(lib.name, { version: hit.version }, 'url');
    if (file) for (const hit of scan(lib.file, file, 1)) add(lib.name, { version: hit.version }, 'file name');
  }
  return [...out.values()];
}

const VIA = { content: 'version string in the code', url: 'script URL', 'file name': 'script file name' };

const VULN_DESC =
  'A library version with published advisories. Check whether the app uses the affected feature with attacker-influenced input (the Sinks tab shows tainted flows) before reporting: an outdated library alone is usually informational.';
const LIB_DESC = `Library version found in the code. No advisory in the bundled retire.js data (${VULNDB_DATE}) covers this version.`;

/** Upgrading to this fixes every advisory in `vulns` (the highest "below" bound). */
export function fixedIn(vulns) {
  let best = '';
  for (const v of vulns) if (!best || !isAtOrAbove(best, v.below)) best = v.below;
  return best;
}

/** Line, column and a short context snippet (like the analyzer's) for a match at `index`. */
function locate(code, index, length, radius = 70) {
  let line = 1;
  let start = 0;
  for (let i = code.indexOf('\n'); i !== -1 && i < index; i = code.indexOf('\n', i + 1)) {
    line++;
    start = i + 1;
  }
  const squash = (x) => x.replace(/\s+/g, ' ');
  const s = Math.max(0, index - radius);
  const e = Math.min(code.length, index + length + radius);
  const ctx = [(s > 0 ? '…' : '') + squash(code.slice(s, index)), squash(code.slice(index, index + length)), squash(code.slice(index + length, e)) + (e < code.length ? '…' : '')];
  return { line, col: index - start + 1, ctx };
}

/**
 * Library findings for the analyzer pipeline (category deps, meta.kind 'library' so they don't mix
 * with npm package names).
 */
export function libraryFindings(code, url = '') {
  const results = [];
  for (const d of detectLibraries(code, url)) {
    const vulns = vulnsFor(d.name, d.version);
    let severity = 'info';
    for (const v of vulns) if ((SEV_RANK[v.severity] || 0) > (SEV_RANK[severity] || 0)) severity = v.severity;
    const ids = [...new Set(vulns.flatMap((v) => v.ids))];
    const meta = { kind: 'library', library: d.name, version: d.version, found: VIA[d.via] || d.via };
    if (vulns.length) {
      // retire.js marks "every version of this line" (AngularJS 1.x, end of life) with a below of 1.999
      const fixed = fixedIn(vulns);
      const eol = /(?:^|\.)9{3,}(?:\.|$)/.test(fixed);
      Object.assign(meta, { advisories: vulns.length, 'fixed in': eol ? 'no fixed release (end of life)' : fixed });
      if (eol) meta.eol = true;
      if (ids.length) meta.ids = ids.slice(0, 12).join(', ') + (ids.length > 12 ? ` +${ids.length - 12}` : '');
      meta.vulns = vulns
        .sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0))
        .slice(0, 40)
        .map((v) => [v.ids.join(', '), v.severity, v.summary, `${v.atOrAbove && v.atOrAbove !== '0' ? '≥ ' + v.atOrAbove + ', ' : ''}< ${v.below}`, v.link]);
    }
    let line = 0;
    let col = 0;
    let ctx;
    if (d.via === 'content' && d.index >= 0) ({ line, col, ctx } = locate(code, d.index, d.length));
    results.push({
      rule: vulns.length ? 'vulnerable-library' : 'library-version',
      label: vulns.length ? 'Vulnerable library' : 'Library',
      category: 'deps',
      severity,
      value: `${d.name} ${d.version}`,
      tags: [vulns.length ? 'vulnerable' : 'library'],
      meta,
      desc: vulns.length ? VULN_DESC : LIB_DESC,
      line,
      col,
      ...(ctx ? { ctx } : {}),
    });
  }
  return results;
}

/** `/*! For license information please see main.js.LICENSE.txt *\/` → the absolute URL, or null. */
export function licenseFileRef(code, scriptUrl) {
  const m = /\/\*!? *For license information please see ([^\s*]{1,200}?\.LICENSE\.txt) *\*\//.exec(String(code || '').slice(0, 4096)) ||
    /\/\*!? *For license information please see ([^\s*]{1,200}?\.LICENSE\.txt) *\*\//.exec(String(code || '').slice(-4096));
  if (!m) return null;
  try {
    const u = new URL(m[1], scriptUrl);
    return /^https?:$/.test(u.protocol) ? u.href : null;
  } catch {
    return null;
  }
}

export { VULNDB_DATE };
