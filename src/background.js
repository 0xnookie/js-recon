// Service worker: observes script loads, fetches and analyzes JavaScript, stores findings per host,
// verifies discovered npm dependencies (dependency confusion).

import { analyze } from './analyzer.js';
import { buildRules, makeSubdomainRule, packageRoot, classifyLink, INTERESTING_RE } from './rules.js';
import { DEFAULT_SETTINGS, getSettings } from './settings.js';
import { SEV_RANK, sha1, siteOf, hostMatches, hostOf, truncate } from './util.js';
import { sourceMapRef, decodeDataUri, parseSourceMap, mapEntries, cleanSourcePath, probeCandidates } from './sourcemap.js';
import { findChunks } from './chunks.js';
import { analyzeHeaders } from './headers.js';

const KEY = (host) => 'host:' + host;
const MAX_SOURCES = 8;
const LIGHT_CATEGORIES = new Set(['endpoints', 'urls', 'params', 'api', 'subdomains', 'deps']);
const JS_URL_RE = /\.m?js(?:[?#]|$)/i;
const SCRIPT_KINDS = new Set(['script', 'crawled', 'chunk', 'manual']);
const MAX_CHUNK_URLS = 5000; // discovered chunk URLs kept per host (for exports)

// ───────────────────────── settings / rules ─────────────────────────

let state = null;
let readyPromise = null;

function applySettings(settings) {
  state = { settings, rules: buildRules(settings), hostRules: new Map() };
  readyPromise = Promise.resolve(state);
  return state;
}

function ready() {
  if (!readyPromise) readyPromise = getSettings().then(applySettings);
  return readyPromise;
}

/** Global rules plus a subdomain rule for the host's registrable domain. */
function rulesFor(host) {
  const site = siteOf(String(host).replace(/:\d+$/, ''));
  if (!site || !site.includes('.') || /^[\d.]+$/.test(site)) return state.rules;
  let r = state.hostRules.get(site);
  if (!r) state.hostRules.set(site, (r = [...state.rules, makeSubdomainRule(site)]));
  return r;
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (changes.settings) applySettings({ ...DEFAULT_SETTINGS, ...(changes.settings.newValue || {}) });
  for (const k of Object.keys(changes)) {
    if (k.startsWith('host:') && changes[k].newValue === undefined) hostCache.delete(k.slice(5));
  }
});

// ───────────────────────── host storage ─────────────────────────

const hostCache = new Map(); // host -> Promise<data>

function newHostData(host, origin) {
  const now = Date.now();
  return { host, origin: origin || 'https://' + host, created: now, updated: now, files: {}, findings: {}, hashes: {}, crawled: 0 };
}

function getHost(host, origin) {
  let p = hostCache.get(host);
  if (!p) {
    p = chrome.storage.local.get(KEY(host)).then((r) => {
      const data = r[KEY(host)] || newHostData(host, origin);
      if (!data.origin && origin) data.origin = origin;
      return data;
    });
    hostCache.set(host, p);
  }
  return p;
}

function summarize(data) {
  const counts = {};
  let critical = 0;
  let high = 0;
  let medium = 0;
  for (const f of Object.values(data.findings)) {
    counts[f.category] = (counts[f.category] || 0) + 1;
    if (f.severity === 'critical') critical++;
    else if (f.category === 'secrets') {
      if (f.severity === 'high') high++;
      else if (f.severity === 'medium') medium++;
    }
  }
  return { origin: data.origin, updated: data.updated, files: Object.keys(data.files).length, counts, critical, high, medium };
}

let writeChain = Promise.resolve();
const dirty = new Set();
let flushTimer = null;

function serial(fn) {
  writeChain = writeChain.then(fn).catch((e) => console.warn('[JS Recon] storage error', e));
  return writeChain;
}

function markDirty(host) {
  dirty.add(host);
  if (!flushTimer) flushTimer = setTimeout(flush, 600);
}

function flush() {
  flushTimer = null;
  const hosts = [...dirty];
  dirty.clear();
  return serial(async () => {
    const { index = {} } = await chrome.storage.local.get('index');
    const payload = {};
    for (const h of hosts) {
      const p = hostCache.get(h);
      if (!p) continue;
      const data = await p;
      data.updated = Date.now();
      payload[KEY(h)] = data;
      index[h] = summarize(data);
    }
    payload.index = index;
    await chrome.storage.local.set(payload);
  });
}

function clearData(host) {
  return serial(async () => {
    if (host) {
      hostCache.delete(host);
      dirty.delete(host);
      const { index = {} } = await chrome.storage.local.get('index');
      delete index[host];
      await chrome.storage.local.remove(KEY(host));
      await chrome.storage.local.set({ index });
    } else {
      hostCache.clear();
      dirty.clear();
      const all = await chrome.storage.local.get(null);
      await chrome.storage.local.remove(Object.keys(all).filter((k) => k.startsWith('host:') || k === 'index'));
    }
  }).then(() => refreshAllBadges());
}

// ───────────────────────── findings ─────────────────────────

function mergeFindings(data, results, src) {
  const alerts = [];
  for (const r of results) {
    // params of other kinds (cookie, header, storage …) get their own key; query params keep the old one
    const kind = r.meta?.kind && r.meta.kind !== 'query' ? r.meta.kind + ':' : '';
    const key = r.category + '|' + kind + r.value;
    let f = data.findings[key];
    if (!f) {
      f = data.findings[key] = {
        key,
        rule: r.rule,
        label: r.label,
        category: r.category,
        severity: r.severity,
        value: r.value,
        tags: r.tags || [],
        sources: [],
        hits: 0,
        first: Date.now(),
      };
      if (r.meta) f.meta = { ...r.meta };
      if (r.desc) f.desc = r.desc;
      if (r.confidence) Object.assign(f, { confidence: r.confidence, entropy: r.entropy });
      if (r.severity === 'high' || r.severity === 'critical') alerts.push(f);
    } else if ((SEV_RANK[r.severity] || 0) > (SEV_RANK[f.severity] || 0)) {
      f.severity = r.severity;
      f.label = r.label;
      f.rule = r.rule;
      if (r.meta) f.meta = { ...f.meta, ...r.meta };
      if (r.desc) f.desc = r.desc;
      if (r.confidence) Object.assign(f, { confidence: r.confidence, entropy: r.entropy });
    }
    if (r.category === 'deps' && r.meta?.evidence) {
      const ev = new Set([...(f.meta?.evidence || []), ...r.meta.evidence]);
      if (ev.size !== (f.meta?.evidence || []).length) {
        f.meta = { ...f.meta, evidence: [...ev] };
        if (f.meta.npm && npmCache?.[f.value]) applyNpm(f, npmCache[f.value]);
      }
    }
    f.hits += r.hits || 1;
    if (f.sources.length < MAX_SOURCES && !f.sources.some((s) => s.file === src.file && s.sub === src.sub && s.line === r.line)) {
      const s = { file: src.file, line: r.line, col: r.col };
      if (src.sub) s.sub = src.sub;
      if (r.ctx && (f.sources.length === 0 || !LIGHT_CATEGORIES.has(r.category))) s.ctx = r.ctx;
      f.sources.push(s);
    }
  }
  if (alerts.length) notify(data.host, alerts);
  return results.length;
}

function notify(host, list) {
  if (!state?.settings.notify) return;
  const first = list[0];
  try {
    chrome.notifications.create('jsrecon-' + Date.now(), {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/icon128.png'),
      title: `JS Recon: ${list.length} ${first.severity} finding${list.length > 1 ? 's' : ''}`,
      message: `${host}\n${first.label}: ${truncate(first.value, 60)}`,
      priority: 1,
    });
  } catch {
    /* notifications unavailable */
  }
}

// ───────────────────────── badge ─────────────────────────

const badgeTimers = new Map();

function scheduleBadge(host) {
  if (badgeTimers.has(host)) return;
  badgeTimers.set(
    host,
    setTimeout(async () => {
      badgeTimers.delete(host);
      const tabs = await chrome.tabs.query({});
      for (const t of tabs) if (hostOf(t.url || '') === host) setBadge(t.id, host);
    }, 800),
  );
}

async function setBadge(tabId, host) {
  let s = null;
  if (host) {
    const p = hostCache.get(host);
    if (p) s = summarize(await p);
    else s = (await chrome.storage.local.get('index')).index?.[host];
  }
  const hot = (s?.critical || 0) + (s?.high || 0);
  const n = hot + (s?.medium || 0);
  try {
    await chrome.action.setBadgeText({ tabId, text: n ? (n > 999 ? '999+' : String(n)) : '' });
    if (n) await chrome.action.setBadgeBackgroundColor({ tabId, color: hot ? '#e5484d' : '#f5a524' });
  } catch {
    /* tab closed */
  }
}

async function refreshAllBadges() {
  const tabs = await chrome.tabs.query({});
  for (const t of tabs) setBadge(t.id, hostOf(t.url || ''));
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === 'complete' || info.url) setBadge(tabId, hostOf(tab.url || ''));
});

// ───────────────────────── fetching ─────────────────────────

async function fetchText(url, { force = false, maxBytes } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 30000);
  try {
    const res = await fetch(url, {
      credentials: 'include',
      cache: force ? 'no-cache' : 'force-cache',
      redirect: 'follow',
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const len = Number(res.headers.get('content-length') || 0);
    if (maxBytes && len > maxBytes) throw new Error(`Too large (${(len / 1048576).toFixed(1)} MB)`);
    const text = await res.text();
    if (maxBytes && text.length > maxBytes) throw new Error(`Too large (${(text.length / 1048576).toFixed(1)} MB)`);
    return { text, headers: res.headers, finalUrl: res.url || url, contentType: res.headers.get('content-type') || '' };
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Timeout');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

const looksLikeHtml = (res) => /text\/html/i.test(res.contentType) && /^\s*</.test(res.text.slice(0, 200));

// ───────────────────────── job queue ─────────────────────────

const queue = [];
const pending = new Map(); // jobKey -> host
let running = 0;

function enqueue(job) {
  const k = job.host + '\n' + job.kind + '\n' + job.id;
  if (pending.has(k)) return;
  pending.set(k, job.host);
  queue.push(job);
  pump();
}

function pump() {
  const max = state?.settings.concurrency || 4;
  while (running < max && queue.length) {
    const job = queue.shift();
    running++;
    runJob(job)
      .catch((e) => console.warn('[JS Recon] job failed', job.url || job.id, e))
      .finally(() => {
        running--;
        pending.delete(job.host + '\n' + job.kind + '\n' + job.id);
        pump();
      });
  }
}

async function runJob(job) {
  await ready();
  if (job.kind === 'external') return scanExternal(job);
  if (job.kind === 'sourcemap') return scanSourceMap(job);
  if (job.kind === 'text') return scanText(job);
  if (job.kind === 'npm') return checkDependency(job);
}

// ───────────────────────── scanners ─────────────────────────

async function scanExternal(job) {
  const { host, url } = job;
  const s = state.settings;
  const data = await getHost(host, job.origin);
  const prev = data.files[url];
  if (prev && !job.force && (prev.status === 'done' || prev.status === 'dup' || prev.status === 'error')) return;

  const file = { url, kind: job.chunk ? 'chunk' : job.crawled ? 'crawled' : job.manual ? 'manual' : 'script', page: job.pageUrl, status: 'scanning', ts: Date.now() };
  data.files[url] = file;
  markDirty(host);

  let res;
  try {
    res = await fetchText(url, { force: job.force, maxBytes: s.maxFileSizeMB * 1048576 });
    if (looksLikeHtml(res)) throw new Error('Got HTML instead of JavaScript');
  } catch (e) {
    if (job.crawled || job.chunk) delete data.files[url]; // guessed URLs: don't list failures
    else Object.assign(file, { status: 'error', error: String(e.message || e) });
    markDirty(host);
    return;
  }

  file.size = res.text.length;
  const hash = await sha1(res.text);
  file.hash = hash;
  const dupOf = data.hashes[hash];
  if (dupOf && dupOf !== url && !job.force) {
    Object.assign(file, { status: 'dup', dupOf });
    markDirty(host);
    return;
  }
  data.hashes[hash] = url;

  const results = analyze(res.text, rulesFor(host));
  file.count = mergeFindings(data, results, { file: url });
  file.status = 'done';
  markDirty(host);
  scheduleBadge(host);
  queueDependencyChecks(host, data, job.force);

  if (s.fetchSourceMaps || s.probeSourceMaps) handleSourceMapRef(job, res, data);
  if (s.crawlJs && (job.depth || 0) < 2) crawlReferences(job, results, data);
  discoverChunks(job, res.text, res.finalUrl || url, data);
}

async function scanText(job) {
  const { host } = job;
  const data = await getHost(host, job.origin);
  const hash = job.hash || (await sha1(job.text));
  const id = job.id || `${job.textKind}:${hash.slice(0, 16)}`;
  if (!job.force && (data.files[id]?.status === 'done' || data.hashes[hash])) return;
  data.hashes[hash] = id;
  const results = analyze(job.text, rulesFor(host));
  data.files[id] = {
    url: id,
    kind: job.textKind,
    label: job.label,
    page: job.pageUrl,
    status: 'done',
    size: job.text.length,
    ts: Date.now(),
    count: mergeFindings(data, results, { file: id }),
  };
  markDirty(host);
  scheduleBadge(host);
  queueDependencyChecks(host, data, job.force);
  if (job.textKind === 'inline') discoverChunks(job, job.text, job.docUrl || job.pageUrl, data);
  if (job.textKind === 'inline' && state.settings.fetchSourceMaps) {
    const ref = sourceMapRef(job.text);
    if (ref?.startsWith('data:')) {
      const map = parseSourceMap(decodeDataUri(ref) || '');
      if (map) processSourceMap(data, `${id} [inline source map]`, map, id, ref.length);
    }
  }
}

// ── source maps ──

function handleSourceMapRef(job, res, data) {
  const s = state.settings;
  const ref = sourceMapRef(res.text, res.headers);
  if (ref && ref.startsWith('data:')) {
    if (!s.fetchSourceMaps) return;
    const map = parseSourceMap(decodeDataUri(ref) || '');
    if (map) processSourceMap(data, `${job.url} [inline source map]`, map, job.url, ref.length);
    return;
  }
  let mapUrl = null;
  if (ref) {
    try {
      mapUrl = new URL(ref, res.finalUrl || job.url).href;
    } catch {
      /* ignore */
    }
  }
  if (mapUrl) {
    mergeFindings(data, [{ rule: 'sourcemap-ref', label: 'Source map reference', category: 'intel', severity: 'low', value: mapUrl, tags: [], line: 0, col: 0 }], { file: job.url });
    if (s.fetchSourceMaps) {
      enqueue({ kind: 'sourcemap', host: job.host, origin: job.origin, id: mapUrl, url: mapUrl, from: job.url, force: job.force });
    }
  } else if (s.probeSourceMaps && /^https?:/i.test(job.url)) {
    const candidates = probeCandidates(job.url);
    enqueue({ kind: 'sourcemap', host: job.host, origin: job.origin, id: candidates[0], url: candidates[0], candidates, from: job.url, probe: true, force: job.force });
  }
}

async function scanSourceMap(job) {
  const data = await getHost(job.host, job.origin);
  const urls = job.candidates || [job.url];
  if (!job.force && urls.some((u) => data.files[u] && data.files[u].status !== 'scanning')) return;
  const maxBytes = state.settings.maxFileSizeMB * 4 * 1048576;
  let lastError = null;
  for (const url of urls) {
    let res;
    try {
      res = await fetchText(url, { force: job.force, maxBytes });
    } catch (e) {
      lastError = String(e.message || e);
      continue;
    }
    const map = parseSourceMap(res.text);
    if (!map) {
      lastError = 'Not a valid source map';
      continue;
    }
    processSourceMap(data, url, map, job.from, res.text.length, job.probe);
    return;
  }
  if (!job.probe) {
    data.files[job.url] = { url: job.url, kind: 'sourcemap', status: 'error', error: lastError || 'Failed', from: job.from, ts: Date.now() };
    markDirty(job.host);
  }
}

function processSourceMap(data, mapId, map, from, size, probed = false) {
  const entries = mapEntries(map);
  const skipNM = state.settings.skipNodeModules;
  const maxLen = state.settings.maxFileSizeMB * 1048576;
  const rules = rulesFor(data.host);
  let count = 0;
  let scanned = 0;
  let withContent = 0;
  const deps = new Set();
  for (const e of entries) {
    const re = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)/g;
    let x;
    while ((x = re.exec(e.path))) {
      const n = packageRoot(x[1]);
      if (n) deps.add(n);
    }
    if (typeof e.content !== 'string' || !e.content) continue;
    withContent++;
    if (skipNM && /(?:^|\/)node_modules\//.test(e.path)) continue;
    if (e.content.length > maxLen) continue;
    count += mergeFindings(data, analyze(e.content, rules), { file: mapId, sub: cleanSourcePath(e.path) });
    scanned++;
  }
  if (deps.size) {
    count += mergeFindings(
      data,
      [...deps].map((n) => ({ rule: 'dep-sourcemap', label: 'npm dependency', category: 'deps', severity: 'info', value: n, tags: [], meta: { evidence: ['source map'] }, line: 0, col: 0 })),
      { file: mapId },
    );
  }
  data.files[mapId] = {
    url: mapId,
    kind: 'sourcemap',
    status: 'done',
    from,
    probed,
    ts: Date.now(),
    size,
    count,
    sources: entries.slice(0, 5000).map((e) => cleanSourcePath(e.path)),
    sourcesTotal: entries.length,
    withContent,
    scanned,
  };
  const exposed = withContent > 0;
  mergeFindings(
    data,
    [{
      rule: 'sourcemap-exposed',
      label: exposed ? 'Source map exposes original source code' : 'Source map (paths only)',
      category: 'intel',
      severity: exposed ? 'medium' : 'low',
      value: mapId,
      tags: probed ? ['guessed'] : [],
      meta: { sources: entries.length, withContent },
      line: 0,
      col: 0,
    }],
    { file: from || mapId },
  );
  markDirty(data.host);
  scheduleBadge(data.host);
  queueDependencyChecks(data.host, data);
}

function crawlReferences(job, results, data) {
  const s = state.settings;
  const pageSite = siteOf(job.host);
  const candidates = new Set();
  for (const r of results) {
    if ((r.category !== 'endpoints' && r.category !== 'urls') || !JS_URL_RE.test(r.value)) continue;
    if (r.value.includes('${') || r.tags.includes('noise')) continue;
    for (const base of [job.url, job.origin + '/']) {
      try {
        const u = new URL(r.value, base);
        if ((u.protocol === 'https:' || u.protocol === 'http:') && siteOf(u.hostname) === pageSite) {
          candidates.add(u.href.replace(/#.*$/, ''));
        }
      } catch {
        /* ignore */
      }
    }
  }
  for (const u of candidates) {
    if (data.files[u]) continue;
    if ((data.crawled || 0) >= s.crawlLimit) break;
    if (hostMatches(hostOf(u), s.ignoreScriptHosts)) continue;
    data.crawled = (data.crawled || 0) + 1;
    enqueue({ kind: 'external', host: job.host, origin: job.origin, id: u, url: u, pageUrl: job.pageUrl, depth: (job.depth || 0) + 1, crawled: true });
  }
}

// ── lazy chunks ──

const CHUNK_KIND = { webpack: 'webpack chunk map', next: 'Next.js chunks', vite: 'Vite preload list', esm: 'ES module dynamic imports' };

/** Finds every chunk the bundler can load, records them and fetches the ones not seen yet. */
function discoverChunks(job, code, baseUrl, data) {
  let found;
  try {
    found = findChunks(code, baseUrl);
  } catch {
    return;
  }
  if (!found.length) return;
  const s = state.settings;
  data.chunkUrls ||= {};
  const results = [];
  const fresh = [];
  for (const f of found) {
    for (const u of f.urls) {
      if (!(u in data.chunkUrls) && Object.keys(data.chunkUrls).length < MAX_CHUNK_URLS) data.chunkUrls[u] = f.kind;
      if (!data.files[u]) fresh.push(u);
    }
    for (const r of f.routes || []) {
      const l = classifyLink(r);
      if (l) results.push({ rule: 'next-route', label: 'Route (Next.js build manifest)', category: 'endpoints', severity: 'info', value: r, tags: [...l.tags, 'route'], line: 0, col: 0 });
    }
    const total = Object.values(data.chunkUrls).filter((k) => k === f.kind).length;
    results.push({
      rule: 'chunk-list',
      label: 'Lazy-loaded chunks',
      category: 'intel',
      severity: 'info',
      value: CHUNK_KIND[f.kind] || f.kind,
      tags: [],
      meta: { chunks: total, publicPath: f.publicPath || undefined },
      line: 0,
      col: 0,
    });
  }
  mergeFindings(data, results, { file: job.url || job.id });
  // keep the chunk count current (mergeFindings only sets meta the first time)
  for (const r of results) if (r.rule === 'chunk-list') data.findings['intel|' + r.value].meta = r.meta;
  markDirty(job.host);
  if (!s.fetchChunks) return;
  const scope = { host: job.host };
  // screens that look sensitive first: admin, settings, billing …
  fresh.sort((a, b) => INTERESTING_RE.test(b) - INTERESTING_RE.test(a));
  for (const u of new Set(fresh)) {
    if ((data.chunksFetched || 0) >= s.chunkLimit) break;
    if (!scriptAllowed(u, scope, s)) continue;
    data.chunksFetched = (data.chunksFetched || 0) + 1;
    enqueue({ kind: 'external', host: job.host, origin: job.origin, id: u, url: u, pageUrl: job.pageUrl, chunk: true });
  }
}

// ───────────────────────── dependency confusion (npm) ─────────────────────────

const NPM_TTL = 3 * 24 * 3600 * 1000;
const MAX_DEP_CHECKS_PER_HOST = 1500;
let npmCache = null; // { name: { status, latest?, scope?, checked } , "@scope": { status, checked } }
const npmInflight = new Map();
let npmSaveTimer = null;

async function loadNpmCache() {
  if (!npmCache) npmCache = (await chrome.storage.local.get('npmcache')).npmcache || {};
  return npmCache;
}

function saveNpmCache() {
  clearTimeout(npmSaveTimer);
  npmSaveTimer = setTimeout(() => serial(() => chrome.storage.local.set({ npmcache: npmCache })), 1500);
}

const npmFetch = (path) =>
  fetch('https://registry.npmjs.org/' + path, {
    credentials: 'omit',
    cache: 'no-store',
    headers: { accept: 'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8' },
  });

async function lookupScope(scope) {
  const cache = await loadNpmCache();
  const key = '@' + scope;
  const c = cache[key];
  if (c && Date.now() - c.checked < NPM_TTL) return c.status;
  let status = 'unknown';
  try {
    const org = await npmFetch(`-/org/${encodeURIComponent(scope)}/package`);
    if (org.ok) status = 'claimed';
    else if (org.status === 404) {
      const user = await npmFetch(`-/user/${encodeURIComponent(scope)}/package`);
      if (user.ok) status = 'claimed';
      else if (user.status === 404) status = 'unclaimed';
    }
  } catch {
    /* network error → unknown */
  }
  if (status !== 'unknown') {
    cache[key] = { status, checked: Date.now() };
    saveNpmCache();
  }
  return status;
}

async function lookupPackage(name) {
  const cache = await loadNpmCache();
  const c = cache[name];
  if (c && Date.now() - c.checked < NPM_TTL) return c;
  if (npmInflight.has(name)) return npmInflight.get(name);
  const p = (async () => {
    const r = { status: 'unknown', checked: Date.now() };
    try {
      const res = await npmFetch(name.replace('/', '%2F'));
      if (res.ok) {
        const j = await res.json().catch(() => ({}));
        r.status = Object.keys(j.versions || {}).length ? 'exists' : 'unpublished';
        if (j['dist-tags']?.latest) r.latest = j['dist-tags'].latest;
      } else if (res.status === 404) {
        r.status = 'missing';
        if (name.startsWith('@')) r.scope = await lookupScope(name.slice(1, name.indexOf('/')));
      } else {
        r.error = 'HTTP ' + res.status;
      }
    } catch (e) {
      r.error = String(e.message || e);
    }
    if (r.status !== 'unknown') {
      cache[name] = r;
      saveNpmCache();
    }
    return r;
  })();
  npmInflight.set(name, p);
  try {
    return await p;
  } finally {
    npmInflight.delete(name);
  }
}

const DEP_CONFUSION_DESC =
  'This package name is referenced by the application but is not registered on the public npm registry. If any build resolves it from registry.npmjs.org, an attacker could publish a package with this name (dependency confusion). Confirm how the project resolves dependencies before reporting.';
const ALIAS_NOTE = ' Only seen in an import statement — it may be a bundler/TypeScript path alias rather than a package.';

/** Updates a deps finding from a registry lookup result. */
function applyNpm(f, r) {
  if (!r) return;
  const evidence = f.meta?.evidence || [];
  const strong = evidence.some((e) => e !== 'import');
  const scoped = f.value.startsWith('@');
  const scope = scoped ? f.value.slice(0, f.value.indexOf('/')) : null;
  f.meta = { ...(f.meta || {}), npm: r.status };
  if (r.latest) f.meta.latest = r.latest;
  if (r.scope) f.meta.scopeStatus = r.scope;
  let severity = 'info';
  let label = 'npm dependency';
  let desc = null;
  let tag = 'unverified';
  if (r.status === 'exists') {
    tag = 'on-npm';
    if (/security/i.test(r.latest || '')) {
      severity = 'low';
      label = 'npm security placeholder package';
      desc = 'The public package is an npm security holding package — this name was most likely reported as a dependency-confusion issue before.';
    }
  } else if (r.status === 'unpublished') {
    severity = 'high';
    label = 'npm package unpublished';
    tag = 'unpublished';
    desc = 'The package exists on npm but has no published versions (unpublished). Check whether the name can be re-registered.';
  } else if (r.status === 'missing') {
    if (!scoped) {
      severity = strong ? 'critical' : 'high';
      label = 'Dependency confusion: package not on npm';
      tag = 'not-on-npm';
      desc = DEP_CONFUSION_DESC + (strong ? '' : ALIAS_NOTE);
    } else if (r.scope === 'unclaimed') {
      severity = strong ? 'critical' : 'high';
      label = `Dependency confusion: npm scope ${scope} is unclaimed`;
      tag = 'scope-unclaimed';
      desc = `Neither an npm organization nor a user named "${scope.slice(1)}" exists, so anyone could claim the scope and publish ${f.value}. ` + DEP_CONFUSION_DESC + (strong ? '' : ALIAS_NOTE);
    } else if (r.scope === 'claimed') {
      severity = 'low';
      label = 'Private scoped package (scope is claimed)';
      tag = 'private-scope';
      desc = `The ${scope} scope exists on npm, so third parties cannot publish into it.`;
    } else {
      severity = 'medium';
      label = 'Scoped package not on npm (scope status unknown)';
      tag = 'not-on-npm';
      desc = `Verify manually whether https://www.npmjs.com/org/${scope.slice(1)} exists.`;
    }
  } else {
    label = 'npm dependency (lookup failed)';
  }
  f.severity = severity;
  f.label = label;
  f.tags = [tag];
  if (desc) f.desc = desc;
  else delete f.desc;
}

function queueDependencyChecks(host, data, recheck = false) {
  if (!state.settings.checkNpm) return;
  let n = 0;
  for (const f of Object.values(data.findings)) {
    if (f.category !== 'deps') continue;
    if (f.meta?.npm && !(recheck && f.meta.npm === 'unknown')) continue;
    if (++n > MAX_DEP_CHECKS_PER_HOST) break;
    enqueue({ kind: 'npm', host, id: f.value, name: f.value });
  }
}

async function checkDependency(job) {
  if (!state.settings.checkNpm) return;
  const r = await lookupPackage(job.name);
  const data = await getHost(job.host);
  const f = data.findings['deps|' + job.name];
  if (!f) return;
  const before = f.severity;
  applyNpm(f, r);
  markDirty(job.host);
  scheduleBadge(job.host);
  if (f.severity === 'critical' && before !== 'critical') notify(job.host, [f]);
}

// ───────────────────────── scope ─────────────────────────

function scopeFor(pageUrl, s) {
  let u;
  try {
    u = new URL(pageUrl);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (hostMatches(u.hostname, s.denyHosts)) return null;
  if (s.scopeMode === 'allowlist' && !hostMatches(u.hostname, s.allowHosts)) return null;
  return { host: u.host, origin: u.origin };
}

function scriptAllowed(scriptUrl, scope, s) {
  if (!/^https?:/i.test(scriptUrl)) return false;
  const sh = hostOf(scriptUrl);
  if (hostMatches(sh, s.ignoreScriptHosts)) return false;
  if (s.firstPartyOnly && siteOf(sh) !== siteOf(scope.host)) return false;
  return true;
}

async function tabUrl(tabId) {
  try {
    const t = await chrome.tabs.get(tabId);
    return t.url || t.pendingUrl || '';
  } catch {
    return '';
  }
}

// ───────────────────────── passive capture ─────────────────────────

async function onScriptLoaded(details) {
  if (details.tabId < 0) return; // our own fetches and extension contexts
  if (details.statusCode && details.statusCode >= 400) return;
  if (details.type !== 'script' && !JS_URL_RE.test(details.url)) return;
  const { settings } = await ready();
  if (!settings.enabled) return;
  const pageUrl = await tabUrl(details.tabId);
  const scope = scopeFor(pageUrl, settings);
  if (!scope || !scriptAllowed(details.url, scope, settings)) return;
  enqueue({ kind: 'external', host: scope.host, origin: scope.origin, id: details.url, url: details.url, pageUrl });
}

chrome.webRequest.onCompleted.addListener(
  (d) => void onScriptLoaded(d).catch(() => {}),
  { urls: ['http://*/*', 'https://*/*'], types: ['script', 'xmlhttprequest', 'other'] },
);

// ── response headers of the target's own servers ──

const HEADER_TYPES = new Set(['main_frame', 'sub_frame', 'xmlhttprequest', 'websocket']);
const headerSeen = new Set();

async function onResponseHeaders(d) {
  if (d.tabId < 0 || !HEADER_TYPES.has(d.type) || !d.responseHeaders?.length) return;
  const { settings } = await ready();
  if (!settings.enabled || !settings.captureHeaders) return;
  const pageUrl = d.type === 'main_frame' ? d.url : await tabUrl(d.tabId);
  const scope = scopeFor(pageUrl, settings);
  if (!scope) return;
  let u;
  try {
    u = new URL(d.url);
  } catch {
    return;
  }
  // only the target's own servers: third-party APIs and CDNs would describe someone else's stack
  if (siteOf(u.hostname) !== siteOf(scope.host.replace(/:\d+$/, ''))) return;
  const results = analyzeHeaders(d.responseHeaders, { url: d.url, pageOrigin: scope.origin, statusCode: d.statusCode });
  if (!results.length) return;
  const sig = [scope.host, u.origin, ...results.map((r) => r.category + '|' + r.value).sort()].join('\n');
  if (headerSeen.has(sig)) return;
  if (headerSeen.size > 5000) headerSeen.clear();
  headerSeen.add(sig);
  const data = await getHost(scope.host, scope.origin);
  const id = 'headers:' + u.origin;
  mergeFindings(data, results, { file: id, sub: `${u.host}${u.pathname} — response headers` });
  data.files[id] = {
    url: id,
    kind: 'headers',
    label: `${u.host} — response headers`,
    page: pageUrl,
    status: 'done',
    ts: Date.now(),
    count: Object.values(data.findings).filter((f) => f.sources.some((x) => x.file === id)).length,
  };
  markDirty(scope.host);
  scheduleBadge(scope.host);
}

chrome.webRequest.onCompleted.addListener(
  (d) => void onResponseHeaders(d).catch(() => {}),
  { urls: ['http://*/*', 'https://*/*'], types: [...HEADER_TYPES] },
  ['responseHeaders', 'extraHeaders'],
);

async function onPageCollect(msg, sender) {
  const { settings } = await ready();
  if (!settings.enabled && !msg.force) return { ok: false };
  // findings are filed under the tab's (top page's) host, like the scripts the page loads
  const pageUrl = sender.tab?.url || msg.pageUrl;
  const scope = scopeFor(pageUrl, settings);
  if (!scope) return { ok: false, reason: 'out of scope' };
  const isFrame = !!msg.frame || (sender.frameId ?? 0) > 0;
  // iframes are treated like scripts: ignored hosts (ads, analytics, video) and "first-party only" apply
  if (isFrame && !scriptAllowed(msg.pageUrl, scope, settings)) return { ok: false, reason: 'frame skipped' };
  const base = { host: scope.host, origin: scope.origin, pageUrl, docUrl: msg.pageUrl || pageUrl };
  for (const url of msg.scripts || []) {
    if (scriptAllowed(url, scope, settings)) enqueue({ ...base, kind: 'external', id: url, url, force: msg.force });
  }
  let where = pageUrl;
  try {
    where = new URL(pageUrl).pathname;
    if (isFrame) {
      const f = new URL(msg.pageUrl);
      where += ` › frame ${f.host === scope.host ? '' : f.host}${f.pathname}`;
    }
  } catch {
    /* ignore */
  }
  const texts = [];
  if (settings.scanInline || msg.force) {
    (msg.inline || []).forEach((text, i) => text && texts.push({ textKind: 'inline', text, label: `${where} — inline script #${i + 1}` }));
  }
  if (msg.html && (settings.scanHtml || msg.force)) texts.push({ textKind: 'html', text: msg.html, label: `${where} — ${isFrame ? 'frame' : 'page'} DOM` });
  for (const t of texts) {
    const hash = await sha1(t.text);
    enqueue({ ...base, ...t, kind: 'text', id: `${t.textKind}:${hash.slice(0, 16)}`, hash, force: msg.force });
  }
  return { ok: true };
}

// ───────────────────────── messages from UI ─────────────────────────

async function rescan({ tabId, host }) {
  await ready();
  if (host) {
    const data = await getHost(host);
    for (const f of Object.values(data.files)) {
      if (SCRIPT_KINDS.has(f.kind)) {
        enqueue({ kind: 'external', host, origin: data.origin, id: f.url, url: f.url, pageUrl: f.page, force: true, crawled: f.kind === 'crawled', manual: f.kind === 'manual' });
      } else if (f.kind === 'sourcemap' && /^https?:/i.test(f.url)) {
        enqueue({ kind: 'sourcemap', host, origin: data.origin, id: f.url, url: f.url, from: f.from, force: true });
      }
    }
    queueDependencyChecks(host, data, true);
  }
  if (tabId != null) {
    try {
      await chrome.tabs.sendMessage(tabId, { type: 'collect', force: true });
    } catch {
      try {
        await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, files: ['src/content.js'] });
        await chrome.tabs.sendMessage(tabId, { type: 'collect', force: true });
      } catch (e) {
        return { ok: false, error: 'Cannot access this page: ' + (e.message || e) };
      }
    }
  }
  return { ok: true };
}

async function scanUrls({ host, urls }) {
  await ready();
  let n = 0;
  for (const raw of urls || []) {
    let u;
    try {
      u = new URL(raw.trim());
    } catch {
      continue;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
    const h = host || u.host;
    const origin = host ? undefined : u.origin;
    if (/\.map(?:[?#]|$)/i.test(u.pathname)) {
      enqueue({ kind: 'sourcemap', host: h, origin, id: u.href, url: u.href, force: true });
    } else {
      enqueue({ kind: 'external', host: h, origin, id: u.href, url: u.href, pageUrl: u.href, force: true, manual: true });
    }
    n++;
  }
  return { ok: true, queued: n };
}

async function scanPastedText({ host, text, label }) {
  await ready();
  const h = (host || 'manual').trim();
  const hash = await sha1(text);
  enqueue({ kind: 'text', textKind: 'manual', host: h, id: 'manual:' + hash.slice(0, 16), text, label: label || 'Pasted code', force: true });
  return { ok: true };
}

function status({ host }) {
  let q = 0;
  for (const h of pending.values()) if (!host || h === host) q++;
  return { pending: q, running, queued: queue.length };
}

const HANDLERS = {
  'page-collect': onPageCollect,
  rescan,
  'scan-urls': scanUrls,
  'scan-text': scanPastedText,
  status,
  clear: ({ host }) => clearData(host).then(() => ({ ok: true })),
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const handler = HANDLERS[msg?.type];
  if (!handler) return false;
  Promise.resolve()
    .then(() => handler(msg, sender))
    .then(sendResponse, (e) => sendResponse({ ok: false, error: String(e?.message || e) }));
  return true;
});

chrome.runtime.onInstalled.addListener(() => {
  ready();
});
