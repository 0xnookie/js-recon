// Bug-bounty program scope: reads what you paste from a program page (HackerOne CSV export, Burp
// project options JSON, or the plain text of a HackerOne / Bugcrowd / Intigriti / YesWeHack scope
// table) and decides whether a host or URL is in scope.
// Pure: no chrome.* APIs, so it can be unit-tested with Node.
//
// Patterns:
//   *.acme.com            every subdomain of acme.com, at any depth (not acme.com itself)
//   acme.com              exactly that host
//   api-*.acme.com        "*" inside a label matches within that label
//   app.acme.com:8443     only that port
//   https://acme.com/api  the host, and for URL checks only paths under /api
//   10.0.0.0/24, 1.2.3.4  IPv4 addresses and ranges
// Out of scope always wins over in scope. A host on neither list is "unlisted": when a scope is set,
// active checks treat it as out of scope (programs only allow what they list).

const FILE_EXT = /\.(?:js|mjs|json|map|html?|php|aspx?|jsp|txt|md|csv|xml|ya?ml|png|jpe?g|gif|svg|webp|ico|css|pdf|zip|exe|apk|ipa|dmg|msi|docx?|xlsx?)$/i;
const HOST_RE = /^(?:\*\.)?(?:[a-z0-9*](?:[a-z0-9*-]{0,61}[a-z0-9*])?\.)+[a-z][a-z0-9-]{1,23}\.?$/;
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/;

/**
 * One scope line → normalised pattern string ("*.acme.com", "acme.com:8443", "acme.com/api",
 * "10.0.0.0/24"), or null when the line holds no host (app store ids, "Other", prose …).
 */
export function normalizePattern(raw) {
  let s = String(raw || '').trim().toLowerCase();
  if (!s) return null;
  s = s.replace(/^[`'"(<\[]+|[`'")>\],;]+$/g, '');
  const ip = IPV4_RE.exec(s);
  if (ip) {
    if (ip.slice(1, 5).some((o) => Number(o) > 255) || (ip[5] && Number(ip[5]) > 32)) return null;
    return s;
  }
  let path = '';
  let port = '';
  const scheme = /^(?:[a-z][a-z0-9+.-]*:)?\/\//.exec(s);
  if (scheme) s = s.slice(scheme[0].length);
  const slash = s.indexOf('/');
  if (slash >= 0) {
    path = s.slice(slash).replace(/[?#].*$/, '').replace(/\*+$/, '').replace(/\/+$/, '');
    s = s.slice(0, slash);
  }
  s = s.replace(/^[^@]*@/, ''); // user@host
  const p = /:(\d{1,5}|\*)$/.exec(s);
  if (p) {
    port = p[1] === '*' ? '' : p[1];
    s = s.slice(0, -p[0].length);
  }
  if (s.startsWith('.')) s = '*' + s; // ".acme.com" (Burp / cookie style) = every subdomain
  s = s.replace(/\.$/, '');
  if (!HOST_RE.test(s) || /\*\*/.test(s)) return null;
  if (!scheme && !path && FILE_EXT.test(s)) return null; // "config.json", "app.js"
  if (!scheme && /^(?:com|org|net)\.[^.]+\.[^.]+/.test(s)) return null; // app ids: com.acme.android
  if (port && (Number(port) < 1 || Number(port) > 65535)) return null;
  return s + (port ? ':' + port : '') + (path && path !== '/' ? path : '');
}

const OUT_HEAD = /^\s*(?:#+\s*)?(?:out[\s-]*of[\s-]*scope|not\s+in\s+scope|exclusions?|excluded(?:\s+targets?)?|ineligible|non-?eligible|no\s+bounty|do\s+not\s+test)\b/i;
const IN_HEAD = /^\s*(?:#+\s*)?(?:in[\s-]*scope|targets?|eligible|scope|assets?)\b(?!.*\bout\b)/i;
const TOKEN_RE = /(?:[a-z][a-z0-9+.-]*:\/\/)?(?:\*\.|\.)?(?:[a-z0-9*](?:[a-z0-9*-]{0,61}[a-z0-9*])?\.)+[a-z][a-z0-9-]{1,23}(?::(?:\d{1,5}|\*))?(?:\/[^\s"'<>,;|)]*)?|\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/gi;

/** Minimal RFC 4180 CSV reader (quoted fields, "" escapes, newlines inside quotes). */
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') (field += '"'), i++;
      else if (c === '"') q = false;
      else field += c;
    } else if (c === '"') q = true;
    else if (c === ',') row.push(field), (field = '');
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else field += c;
  }
  if (field || row.length) row.push(field), rows.push(row);
  return rows.filter((r) => r.some((x) => x.trim()));
}

const truthy = (v) => /^(?:true|yes|1|y)$/i.test(String(v).trim());

/** HackerOne "Download CSV" of a program's scope. */
function fromHackerOneCsv(text) {
  const rows = parseCsv(text);
  const head = rows.shift().map((h) => h.trim().toLowerCase());
  const col = (n) => head.indexOf(n);
  const id = col('identifier');
  const type = col('asset_type');
  const sub = col('eligible_for_submission');
  const out = { in: [], out: [], skipped: [] };
  for (const r of rows) {
    const t = (r[type] || '').toUpperCase();
    if (type >= 0 && t && !/^(?:URL|WILDCARD|DOMAIN|CIDR|IP_ADDRESS|API|OTHER)$/.test(t)) {
      out.skipped.push(r[id]);
      continue;
    }
    for (const part of String(r[id] || '').split(/[\s,]+/)) {
      const p = normalizePattern(part);
      if (!p) {
        if (part.trim()) out.skipped.push(part.trim());
        continue;
      }
      (sub >= 0 && !truthy(r[sub]) ? out.out : out.in).push(p);
    }
  }
  return out;
}

/** Burp "project options" / scope JSON: include / exclude entries with a host regex or a URL prefix. */
function fromBurpJson(obj) {
  const scope = obj?.target?.scope || obj?.scope || obj;
  const out = { in: [], out: [], skipped: [] };
  const conv = (e) => {
    if (e?.enabled === false) return null;
    if (e?.prefix) return normalizePattern(e.prefix);
    let h = String(e?.host || '');
    if (!h) return null;
    h = h
      .replace(/^\^/, '')
      .replace(/\$$/, '')
      .replace(/^\(\.\*\\?\.\)\?/, '') // ^(.*\.)?acme\.com$ → acme.com + subdomains
      .replace(/^\.\*\\\./, '*.')
      .replace(/^\[\^.\]\*\\\./, '*.')
      .replace(/\\\./g, '.');
    const both = /^\^?\(\.\*\\?\.\)\?/.test(String(e.host));
    let path = String(e.file || '').replace(/^\^/, '').replace(/\.\*\$?$/, '').replace(/\$$/, '');
    if (/[\\^$()[\]|+?]/.test(path)) path = '';
    const port = /^\^?(\d{1,5})\$?$/.exec(String(e.port || ''))?.[1];
    const p = normalizePattern(h + (port ? ':' + port : '') + (path || ''));
    if (!p) return null;
    return both && !p.startsWith('*.') ? [p, '*.' + p] : p;
  };
  for (const [list, key] of [[scope.include, 'in'], [scope.exclude, 'out']]) {
    for (const e of list || []) {
      const p = conv(e);
      if (p) out[key].push(...[].concat(p));
      else if (e?.host || e?.prefix) out.skipped.push(String(e.host || e.prefix));
    }
  }
  return out;
}

/** Plain text copied from a scope page: "In scope" / "Out of scope" headings switch the section. */
function fromText(text) {
  const out = { in: [], out: [], skipped: [] };
  let section = 'in';
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (OUT_HEAD.test(line)) section = 'out';
    else if (IN_HEAD.test(line)) section = 'in';
    let target = section;
    let body = line;
    // "- blog.acme.com" / "!blog.acme.com" force out of scope; "+ x" forces in
    const mark = /^([!+-])\s*(?=\S)/.exec(line);
    if (mark && !/^-{2,}/.test(line)) {
      target = mark[1] === '+' ? 'in' : 'out';
      body = line.slice(mark[0].length);
    }
    for (const m of body.matchAll(TOKEN_RE)) {
      if (/[@\w-]/.test(body[m.index - 1] || '')) continue; // e-mail addresses, the tail of a longer word
      const p = normalizePattern(m[0]);
      if (p) out[target].push(p);
    }
  }
  return out;
}

/**
 * Parses a pasted scope. Returns { in: [patterns], out: [patterns], skipped: [lines], format }.
 * Formats: HackerOne CSV, Burp JSON, plain text (one per line, headings or -/! prefixes for out).
 */
export function parseScope(text) {
  const s = String(text || '').trim();
  let r;
  let format = 'text';
  if (/^[{[]/.test(s)) {
    try {
      r = fromBurpJson(JSON.parse(s));
      format = 'burp';
    } catch {
      r = null;
    }
  }
  if (!r && /^﻿?"?identifier"?\s*,/i.test(s)) {
    r = fromHackerOneCsv(s.replace(/^﻿/, ''));
    format = 'hackerone-csv';
  }
  if (!r) r = fromText(s);
  const uniq = (a) => [...new Set(a)];
  const out = uniq(r.out);
  return { in: uniq(r.in).filter((p) => !out.includes(p)), out, skipped: uniq(r.skipped).slice(0, 50), format };
}

// ── matching ──

const reCache = new Map();
function hostRe(pattern) {
  let re = reCache.get(pattern);
  if (!re) {
    const esc = (x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    let src;
    if (pattern.startsWith('*.') && !pattern.slice(2).includes('*')) src = '(?:[^.]+\\.)+' + esc(pattern.slice(2));
    else src = pattern.split('*').map(esc).join('[^.]*');
    re = new RegExp('^' + src + '$');
    if (reCache.size > 2000) reCache.clear();
    reCache.set(pattern, re);
  }
  return re;
}

const ipNum = (s) => s.split('.').reduce((n, o) => n * 256 + Number(o), 0);

function splitPattern(p) {
  const ip = IPV4_RE.exec(p);
  if (ip) return { ip: true, net: ipNum(ip.slice(1, 5).join('.')), bits: ip[5] ? Number(ip[5]) : 32, port: '', path: '' };
  const slash = p.indexOf('/');
  const hp = slash >= 0 ? p.slice(0, slash) : p;
  const path = slash >= 0 ? p.slice(slash) : '';
  const m = /^(.*?)(?::(\d+))?$/.exec(hp);
  return { host: m[1], port: m[2] || '', path };
}

function hostHit(e, hostname, port) {
  if (e.port && port && e.port !== port) return false;
  if (e.port && !port && e.port !== '443' && e.port !== '80') return false;
  if (e.ip) {
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) return false;
    const mask = e.bits === 0 ? 0 : (~0 << (32 - e.bits)) >>> 0;
    return ((ipNum(hostname) & mask) >>> 0) === ((e.net & mask) >>> 0);
  }
  return hostRe(e.host).test(hostname);
}

/** Compiled scope: { in: [entry], out: [entry] } from the settings lists. */
export function compileScope(inList = [], outList = []) {
  const prep = (list) => (list || []).map((p) => normalizePattern(p)).filter(Boolean).map(splitPattern);
  return { in: prep(inList), out: prep(outList) };
}

export const hasScope = (s) => !!s && s.in.length + s.out.length > 0;

function hostParts(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  const m = /^(.*?)(?::(\d+))?$/.exec(h);
  return { hostname: m[1], port: m[2] || '' };
}

/**
 * 'in' | 'out' | 'unlisted' for a host ("app.acme.com" or "app.acme.com:8443"), or null when no
 * scope is set. An out-of-scope entry limited to a path doesn't exclude the whole host.
 */
export function hostScope(scope, host) {
  if (!hasScope(scope)) return null;
  const { hostname, port } = hostParts(host);
  if (!hostname) return 'unlisted';
  if (scope.out.some((e) => !e.path && hostHit(e, hostname, port))) return 'out';
  return scope.in.some((e) => hostHit(e, hostname, port)) ? 'in' : 'unlisted';
}

const underPath = (path, prefix) => !prefix || path === prefix || path.startsWith(prefix.endsWith('/') ? prefix : prefix + '/') || path.startsWith(prefix + '?');

/** 'in' | 'out' | 'unlisted' for a URL (path-limited entries count here), or null without a scope. */
export function urlScope(scope, url) {
  if (!hasScope(scope)) return null;
  let u;
  try {
    u = new URL(url);
  } catch {
    return 'unlisted';
  }
  const hostname = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const port = u.port;
  const path = u.pathname.toLowerCase();
  if (scope.out.some((e) => hostHit(e, hostname, port) && underPath(path, e.path))) return 'out';
  return scope.in.some((e) => hostHit(e, hostname, port) && underPath(path, e.path)) ? 'in' : 'unlisted';
}
