// JS Recon command-line engine: the extension's analysis (src/*.js) driven from Node.
// Fetches pages and scripts (with injectable fetch, for tests), follows source maps, lazy chunks
// and .LICENSE.txt files, and merges findings per host the way the extension's service worker does.

import { createHash } from 'node:crypto';
import { analyze, mergeBody } from '../src/analyzer.js';
import { buildRules, makeSubdomainRule, packageRoot } from '../src/rules.js';
import { libraryFindings, licenseFileRef } from '../src/libs.js';
import { mergeFlag } from '../src/flags.js';
import { sourceMapRef, decodeDataUri, parseSourceMap, mapEntries, cleanSourcePath } from '../src/sourcemap.js';
import { findChunks } from '../src/chunks.js';
import { siteOf, hostMatches, SEV_RANK } from '../src/util.js';
import { DEFAULT_IGNORED_SCRIPT_HOSTS } from '../src/settings.js';

const MAX_SOURCES = 8;
const TAG_MERGE = new Set(['endpoints', 'urls', 'params', 'api', 'subdomains', 'flags']);
const SCRIPT_RE = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
const SRC_RE = /\bsrc\s*=\s*["']?([^"'\s>]+)/i;

export const DEFAULTS = {
  maps: true, // follow sourceMappingURL
  chunks: true, // fetch lazy chunks listed by the bundler runtime
  chunkLimit: 400, // per host
  libraries: true, // library versions → advisories (and .LICENSE.txt files)
  nodeModules: false, // scan node_modules sources inside source maps (libraries are always checked)
  firstParty: false, // only fetch scripts from the page's own registrable domain
  maxBytes: 15 * 1048576,
  concurrency: 6,
  timeoutMs: 30000,
  headers: {},
  ignoreHosts: DEFAULT_IGNORED_SCRIPT_HOSTS,
};

const sha1 = (t) => createHash('sha1').update(t).digest('hex');
const looksLikeHtml = (text, type) => /text\/html/i.test(type || '') || /^\s*<(?:!doctype|html|head|body)\b/i.test(text.slice(0, 300));

/** Merges analyzer results into a host's findings (the service worker's mergeFindings, minus storage). */
export function mergeInto(host, results, src) {
  for (const r of results) {
    const kind = r.meta?.kind && r.meta.kind !== 'query' ? r.meta.kind + ':' : '';
    const key = r.category + '|' + kind + r.value;
    let f = host.findings[key];
    if (!f) {
      f = host.findings[key] = { key, rule: r.rule, label: r.label, category: r.category, severity: r.severity, value: r.value, tags: [...(r.tags || [])], sources: [], hits: 0 };
      if (r.meta) f.meta = { ...r.meta };
      if (r.desc) f.desc = r.desc;
      if (r.confidence) Object.assign(f, { confidence: r.confidence, entropy: r.entropy });
    } else {
      if ((SEV_RANK[r.severity] || 0) > (SEV_RANK[f.severity] || 0)) {
        Object.assign(f, { severity: r.severity, label: r.label, rule: r.rule });
        if (r.meta) f.meta = { ...f.meta, ...r.meta };
        if (r.desc) f.desc = r.desc;
      }
      if (TAG_MERGE.has(r.category)) for (const t of r.tags || []) if (!f.tags.includes(t)) f.tags.push(t);
      if (r.category === 'api' && r.meta?.body) mergeBody(f, r);
      if (r.category === 'flags') mergeFlag(f, r);
    }
    f.hits += r.hits || 1;
    if (f.sources.length < MAX_SOURCES && !f.sources.some((s) => s.file === src.file && s.sub === src.sub && s.line === r.line)) {
      const s = { file: src.file, line: r.line, col: r.col };
      if (src.sub) s.sub = src.sub;
      if (r.ctx && f.sources.length === 0) s.ctx = r.ctx;
      f.sources.push(s);
    }
  }
}

/** Inline scripts and external script URLs of an HTML page. */
export function pageScripts(html, baseUrl) {
  const inline = [];
  const urls = [];
  for (const m of html.matchAll(SCRIPT_RE)) {
    const attrs = m[1];
    const src = SRC_RE.exec(attrs)?.[1];
    if (src) {
      try {
        const u = new URL(src.replace(/&amp;/g, '&'), baseUrl);
        if (/^https?:$/.test(u.protocol)) urls.push(u.href);
      } catch {
        /* bad URL */
      }
    } else if (m[2].trim() && !/\btype\s*=\s*["']?(?:text\/(?:template|html|x-template)|importmap)/i.test(attrs)) inline.push(m[2]);
  }
  return { inline, urls: [...new Set(urls)] };
}

/**
 * Scans `targets` (page or script URLs) and `texts` ([{ id, text, url? }] for local files).
 * Returns { hosts: { [host]: { host, origin, files, findings, chunkUrls } }, errors: [...] }.
 */
export async function scan({ targets = [], texts = [], host: forcedHost = null, options = {}, fetchImpl = globalThis.fetch, onProgress = null } = {}) {
  const o = { ...DEFAULTS, ...options };
  const baseRules = buildRules(o.ruleSettings || {});
  const ruleCache = new Map();
  const rulesFor = (host) => {
    const site = siteOf(String(host).replace(/:\d+$/, ''));
    if (!site.includes('.') || /^[\d.]+$/.test(site)) return baseRules;
    if (!ruleCache.has(site)) ruleCache.set(site, [...baseRules, makeSubdomainRule(site)]);
    return ruleCache.get(site);
  };
  const hosts = {};
  const errors = [];
  const seenUrls = new Set();
  const seenHashes = new Set();
  const hostData = (name, origin) => (hosts[name] ||= { host: name, origin: origin || 'https://' + name, files: {}, findings: {}, chunkUrls: {}, chunksFetched: 0 });

  const queue = [];
  let active = 0;
  let done = 0;
  let resolveAll;
  const finished = new Promise((r) => (resolveAll = r));
  const push = (job) => {
    if (job.kind !== 'text' && o.ignoreUrl?.(job.url)) return; // excluded by the program scope
    if (seenUrls.has(job.kind + ' ' + job.url)) return;
    seenUrls.add(job.kind + ' ' + job.url);
    queue.push(job);
    pump();
  };
  const pump = () => {
    while (active < o.concurrency && queue.length) {
      const job = queue.shift();
      active++;
      run(job)
        .catch((e) => errors.push({ url: job.url, error: String(e?.message || e) }))
        .finally(() => {
          active--;
          done++;
          onProgress?.(done, done + queue.length + active);
          if (!active && !queue.length) resolveAll();
          else pump();
        });
    }
  };

  // -H headers (session cookies, tokens) only go to the targets' own sites (registrable domains), never to
  // scripts, source maps or license files hosted elsewhere. Redirects are followed by hand, so every hop
  // gets the same check, and a hop the program scope excludes is never requested.
  const targetSites = new Set();
  const urlSite = (url) => {
    try {
      return siteOf(new URL(url).hostname);
    } catch {
      return null;
    }
  };
  const MAX_REDIRECTS = 10;

  async function get(url) {
    let current = url;
    let res;
    for (let hop = 0; ; hop++) {
      const extra = targetSites.has(urlSite(current)) ? o.headers : {};
      res = await fetchImpl(current, { headers: { 'user-agent': 'js-recon-cli', ...extra }, redirect: 'manual', signal: AbortSignal.timeout(o.timeoutMs) });
      const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
      if (!location) break;
      if (hop >= MAX_REDIRECTS) throw new Error('too many redirects');
      current = new URL(location, current).href;
      if (!/^https?:$/.test(new URL(current).protocol)) throw new Error('redirected to a non-HTTP URL');
      if (o.ignoreUrl?.(current)) throw new Error('redirected out of scope');
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const len = Number(res.headers.get('content-length') || 0);
    if (len > o.maxBytes) throw new Error(`too large (${(len / 1048576).toFixed(1)} MB)`);
    const text = await res.text();
    if (text.length > o.maxBytes) throw new Error(`too large (${(text.length / 1048576).toFixed(1)} MB)`);
    return { text, type: res.headers.get('content-type') || '', finalUrl: current, headers: res.headers };
  }

  const allowedScript = (url, pageHost) => {
    let h;
    try {
      h = new URL(url).host;
    } catch {
      return false;
    }
    if (hostMatches(h, o.ignoreHosts)) return false;
    if (o.firstParty && siteOf(h.replace(/:\d+$/, '')) !== siteOf(pageHost.replace(/:\d+$/, ''))) return false;
    return true;
  };

  function scanCode(data, text, file, url) {
    const results = analyze(text, rulesFor(data.host));
    if (o.libraries) results.push(...libraryFindings(text, url || ''));
    mergeInto(data, results, { file });
    return results.length;
  }

  function processMap(data, mapId, map) {
    const deps = new Set();
    let scanned = 0;
    for (const e of mapEntries(map)) {
      for (const x of e.path.matchAll(/(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)/g)) {
        const n = packageRoot(x[1]);
        if (n) deps.add(n);
      }
      if (typeof e.content !== 'string' || !e.content || e.content.length > o.maxBytes) continue;
      const sub = cleanSourcePath(e.path);
      if (o.libraries) mergeInto(data, libraryFindings(e.content, ''), { file: mapId, sub });
      if (!o.nodeModules && /(?:^|\/)node_modules\//.test(e.path)) continue;
      mergeInto(data, analyze(e.content, rulesFor(data.host)), { file: mapId, sub });
      scanned++;
    }
    if (deps.size) mergeInto(data, [...deps].map((n) => ({ rule: 'dep-sourcemap', label: 'npm dependency', category: 'deps', severity: 'info', value: n, tags: [], meta: { evidence: ['source map'] }, line: 0, col: 0 })), { file: mapId });
    data.files[mapId] = { url: mapId, kind: 'sourcemap', status: 'done', scanned };
  }

  function afterScript(job, data, text, finalUrl, headers) {
    const ref = o.maps ? sourceMapRef(text, headers) : null;
    if (ref?.startsWith('data:')) {
      const map = parseSourceMap(decodeDataUri(ref) || '');
      if (map) processMap(data, `${job.url} [inline source map]`, map);
    } else if (ref) {
      try {
        push({ kind: 'map', url: new URL(ref, finalUrl).href, host: data.host });
      } catch {
        /* bad ref */
      }
    }
    if (o.libraries) {
      const lic = licenseFileRef(text, finalUrl);
      if (lic) push({ kind: 'license', url: lic, host: data.host });
    }
    if (o.chunks && /^https?:/i.test(finalUrl)) {
      for (const f of findChunks(text, finalUrl)) {
        for (const u of f.urls) {
          data.chunkUrls[u] = f.kind;
          if (data.chunksFetched >= o.chunkLimit || !allowedScript(u, data.host)) continue;
          data.chunksFetched++;
          push({ kind: 'script', url: u, host: data.host, chunk: true });
        }
      }
    }
  }

  async function run(job) {
    const data = hostData(job.host, job.origin);
    if (job.kind === 'text') {
      if (job.map) {
        const map = parseSourceMap(job.text);
        if (map) processMap(data, job.url, map);
        return;
      }
      data.files[job.url] = { url: job.url, kind: 'file', status: 'done', size: job.text.length, count: scanCode(data, job.text, job.url, job.srcUrl) };
      return;
    }
    let res;
    try {
      res = await get(job.url);
    } catch (e) {
      if (!job.chunk && job.kind !== 'license') data.files[job.url] = { url: job.url, kind: job.kind, status: 'error', error: String(e.message || e) };
      return;
    }
    if (job.kind === 'license') {
      if (looksLikeHtml(res.text, res.type)) return;
      mergeInto(data, libraryFindings(res.text, ''), { file: job.url });
      data.files[job.url] = { url: job.url, kind: 'license', status: 'done' };
      return;
    }
    if (job.kind === 'map') {
      const map = parseSourceMap(res.text);
      if (map) processMap(data, job.url, map);
      else data.files[job.url] = { url: job.url, kind: 'sourcemap', status: 'error', error: 'not a source map' };
      return;
    }
    if (looksLikeHtml(res.text, res.type)) {
      if (job.kind !== 'page') {
        data.files[job.url] = { url: job.url, kind: job.kind, status: 'error', error: 'got HTML instead of JavaScript' };
        return;
      }
      // a page: its DOM, inline scripts and every script it loads
      const { inline, urls } = pageScripts(res.text, res.finalUrl);
      data.files[job.url] = { url: job.url, kind: 'html', status: 'done', count: scanCode(data, res.text, job.url, '') };
      inline.forEach((code, i) => {
        const id = `inline:${job.url}#${i + 1}`;
        const h = sha1(code);
        if (seenHashes.has(h)) return;
        seenHashes.add(h);
        data.files[id] = { url: id, kind: 'inline', status: 'done', count: scanCode(data, code, id, '') };
        afterScript({ url: id }, data, code, res.finalUrl, null);
      });
      for (const u of urls) if (allowedScript(u, data.host)) push({ kind: 'script', url: u, host: data.host });
      return;
    }
    const h = sha1(res.text);
    if (seenHashes.has(h)) {
      data.files[job.url] = { url: job.url, kind: job.chunk ? 'chunk' : 'script', status: 'dup' };
      return;
    }
    seenHashes.add(h);
    data.files[job.url] = { url: job.url, kind: job.chunk ? 'chunk' : 'script', status: 'done', size: res.text.length, count: scanCode(data, res.text, job.url, job.url) };
    afterScript(job, data, res.text, res.finalUrl, res.headers);
  }

  let started = false;
  for (const t of targets) {
    let u;
    try {
      u = new URL(t);
    } catch {
      errors.push({ url: t, error: 'not a URL' });
      continue;
    }
    started = true;
    targetSites.add(siteOf(u.hostname));
    const host = forcedHost || u.host;
    hostData(host, u.origin);
    push({ kind: /\.m?js(?:[?#]|$)/i.test(u.pathname) ? 'script' : /\.map(?:[?#]|$)/i.test(u.pathname) ? 'map' : 'page', url: u.href, host, origin: u.origin });
  }
  for (const t of texts) {
    started = true;
    const host = forcedHost || (t.url ? new URL(t.url).host : 'local');
    push({ kind: 'text', url: t.id, text: t.text, srcUrl: t.url, map: !!t.map, host });
  }
  if (started && (queue.length || active)) await finished;
  return { hosts, errors };
}

/** Flattened findings of every host, filtered and sorted (severity, then category). */
export function collect(result, { only = null, minSeverity = 'info' } = {}) {
  const min = SEV_RANK[minSeverity] ?? 0;
  const out = [];
  for (const h of Object.values(result.hosts)) {
    for (const f of Object.values(h.findings)) {
      if (only && !only.includes(f.category)) continue;
      if ((SEV_RANK[f.severity] || 0) < min) continue;
      out.push({ host: h.host, ...f });
    }
  }
  return out.sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || a.category.localeCompare(b.category) || a.value.localeCompare(b.value));
}
