// Service worker: observes script loads, fetches and analyzes JavaScript, stores findings per host,
// verifies discovered npm dependencies (dependency confusion).

import { analyze } from './analyzer.js';
import { buildRules, makeSubdomainRule, packageRoot, classifyLink, INTERESTING_RE, inputFinding, apiEndpoint, analyzeMessageHandler, POSTMESSAGE_DESC } from './rules.js';
import { observedRequest, normalizePath, orderCaptures, scriptFamily } from './requests.js';
import { replayCandidates } from './exporters.js';
import { DEFAULT_SETTINGS, getSettings } from './settings.js';
import { SEV_RANK, sha1, siteOf, hostMatches, hostOf, truncate } from './util.js';
import { sourceMapRef, decodeDataUri, parseSourceMap, mapEntries, cleanSourcePath, probeCandidates } from './sourcemap.js';
import { findChunks } from './chunks.js';
import { analyzeHeaders } from './headers.js';

const KEY = (host) => 'host:' + host;
const MAX_SOURCES = 8;
const LIGHT_CATEGORIES = new Set(['endpoints', 'urls', 'params', 'api', 'subdomains', 'deps']);
const TAG_MERGE = new Set(['endpoints', 'urls', 'params', 'api', 'subdomains']);
const JS_URL_RE = /\.m?js(?:[?#]|$)/i;
const SCRIPT_KINDS = new Set(['script', 'crawled', 'chunk', 'manual']);
const MAX_CHUNK_URLS = 5000; // discovered chunk URLs kept per host (for exports)

// ───────────────────────── settings / rules ─────────────────────────

let state = null;
let readyPromise = null;

function applySettings(settings) {
  state = { settings, rules: buildRules(settings), hostRules: new Map() };
  readyPromise = Promise.resolve(state);
  syncRuntimeScript(settings);
  return state;
}

// ── runtime hooks (opt-in): src/runtime.js is registered into the page's own world only while enabled ──

const RUNTIME_SCRIPT_ID = 'jsrecon-runtime';
let runtimeSync = Promise.resolve();
let runtimeSig = null;

const matchPatterns = (hosts) =>
  (hosts || []).flatMap((h) => {
    const host = String(h).trim().toLowerCase().replace(/:\d+$/, '').replace(/^\*?\.+/, '').replace(/^\*\./, '');
    return /^[a-z0-9.-]+$/.test(host) ? [`*://${host}/*`, `*://*.${host}/*`] : [];
  });

function syncRuntimeScript(s) {
  const api = chrome.scripting;
  if (!api?.registerContentScripts) return runtimeSync;
  const want = s.enabled && s.runtimeHooks;
  const sig = JSON.stringify([want, s.scopeMode, s.allowHosts, s.denyHosts]);
  if (sig === runtimeSig) return runtimeSync;
  runtimeSig = sig;
  runtimeSync = runtimeSync.then(async () => {
    try {
      const existing = await api.getRegisteredContentScripts({ ids: [RUNTIME_SCRIPT_ID] });
      if (existing.length) await api.unregisterContentScripts({ ids: [RUNTIME_SCRIPT_ID] });
      if (!want) return;
      // only where we'd scan anyway: the allow-list (if used), never the deny-list
      const matches = s.scopeMode === 'allowlist' ? matchPatterns(s.allowHosts) : ['http://*/*', 'https://*/*'];
      if (!matches.length) return;
      const excludeMatches = matchPatterns(s.denyHosts);
      await api.registerContentScripts([
        { id: RUNTIME_SCRIPT_ID, js: ['src/runtime.js'], matches, ...(excludeMatches.length ? { excludeMatches } : {}), runAt: 'document_start', allFrames: true, world: 'MAIN', persistAcrossSessions: true },
      ]);
    } catch (e) {
      console.warn('[JS Recon] runtime hooks', e);
    }
  });
  return runtimeSync;
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
      src.newKeys?.push(key);
    } else if ((SEV_RANK[r.severity] || 0) > (SEV_RANK[f.severity] || 0)) {
      f.severity = r.severity;
      f.label = r.label;
      f.rule = r.rule;
      if (r.meta) f.meta = { ...f.meta, ...r.meta };
      if (r.desc) f.desc = r.desc;
      if (r.confidence) Object.assign(f, { confidence: r.confidence, entropy: r.entropy });
    }
    // inputs, endpoints and hosts seen by several sources keep all their tags (e.g. "cors" + "observed")
    if (TAG_MERGE.has(r.category)) for (const t of r.tags || []) if (!f.tags.includes(t)) f.tags = [...f.tags, t];
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
  if (info.url) activeCollected.delete(tabId); // navigated: let active-tab mode re-scan it when focused
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
  if (job.kind === 'wayback') return scanWayback(job);
  if (job.kind === 'replay') return replayRequest(job);
  if (job.kind === 'probe') return probeRequest(job);
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

  // change tracking: the same script (family) with new content means the app was redeployed
  const family = job.manual ? null : scriptFamily(url);
  const before = family ? data.families?.[family] : null;
  if (family) (data.families ||= {})[family] = { url, hash, ts: Date.now() };

  const results = analyze(res.text, rulesFor(host));
  const newKeys = [];
  file.count = mergeFindings(data, results, { file: url, newKeys });
  file.status = 'done';
  if (before && before.hash !== hash) recordChange(data, { family, from: before.url, to: url, newKeys });
  else if (!before && family) attachToRecentChange(data, newKeys); // new files of the same deploy
  markDirty(host);
  scheduleBadge(host);
  queueDependencyChecks(host, data, job.force);

  if (s.fetchSourceMaps || s.probeSourceMaps) handleSourceMapRef(job, res, data);
  if (s.crawlJs && (job.depth || 0) < 2) crawlReferences(job, results, data);
  discoverChunks(job, res.text, res.finalUrl || url, data);
}

// ── change alerts ──

const CHANGE_WINDOW = 10 * 60 * 1000; // new files within 10 minutes of a change belong to the same deploy
const MAX_CHANGES = 30;

const shortName = (u) => {
  try {
    return new URL(u).pathname.split('/').filter(Boolean).pop() || u;
  } catch {
    return u;
  }
};

const CHANGE_DESC =
  'The app was redeployed: scripts were replaced by new versions. Findings that first appeared with them are marked "new"; use the New filter (or the banner) to see only them.';

/**
 * A script was replaced by a new version. Every file that changes within CHANGE_WINDOW belongs to the
 * same deploy, so one deploy is one change entry and one Intel finding, however many chunks it touched.
 */
function recordChange(data, { family, from, to, newKeys }) {
  const now = Date.now();
  let change = data.changes?.[0];
  if (!change || now - change.at > CHANGE_WINDOW) {
    change = { at: now, family, from, to, files: 0, added: [] };
    data.changes = [change, ...(data.changes || [])].slice(0, MAX_CHANGES);
    const value = `${shortName(from)} → ${shortName(to)}`;
    change.findingKey = 'intel|' + value;
    mergeFindings(data, [{ rule: 'bundle-changed', label: 'Bundle changed', category: 'intel', severity: 'info', value, tags: [], line: 0, col: 0, desc: CHANGE_DESC }], { file: to });
    scheduleChangeNotification(data.host, change);
  }
  change.files = (change.files || 0) + 1;
  addToChange(data, change, newKeys);
}

/** Marks findings as new in `change` and keeps its Intel summary current. */
function addToChange(data, change, newKeys) {
  for (const k of newKeys) if (data.findings[k]) data.findings[k].changedAt = change.at;
  change.added = [...new Set([...change.added, ...newKeys])].slice(0, 1000);
  const f = data.findings[change.findingKey];
  if (!f) return;
  f.meta = { at: new Date(change.at).toISOString(), 'files changed': change.files, new: changeSummary(data, change) };
  f.severity = change.added.length ? 'low' : 'info';
}

function changeSummary(data, change) {
  const counts = {};
  for (const k of change.added) {
    const c = data.findings[k]?.category;
    if (c) counts[c] = (counts[c] || 0) + 1;
  }
  return Object.entries(counts).map(([c, n]) => `${n} ${c}`).join(', ') || 'no new findings';
}

/** One notification per deploy, sent once the changed files have had time to be scanned. */
function scheduleChangeNotification(host, change) {
  if (!state.settings.notify) return;
  setTimeout(async () => {
    const data = await getHost(host);
    const c = data.changes?.find((x) => x.at === change.at);
    if (!c?.added.length) return;
    try {
      chrome.notifications.create('jsrecon-change-' + c.at, {
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icons/icon128.png'),
        title: `JS Recon: ${host} was redeployed`,
        message: `${c.files} file${c.files === 1 ? '' : 's'} changed · new: ${changeSummary(data, c)}`,
        priority: 1,
      });
    } catch {
      /* notifications unavailable */
    }
  }, 20000);
}

/** A script seen for the first time shortly after a change most likely came with that deploy. */
function attachToRecentChange(data, newKeys) {
  const recent = data.changes?.[0];
  if (!recent || !newKeys.length || Date.now() - recent.at > CHANGE_WINDOW) return;
  addToChange(data, recent, newKeys);
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

// ── "send to proxy" (active, only on request): GET discovered URLs so they show up in the site map of
// an intercepting proxy (Burp, Caido, ZAP) the browser is configured to use. Same site only, no
// placeholders, nothing that sounds like it changes state; redirects are not followed.

const MAX_REPLAY = 500;

async function replayToProxy({ host, urls }) {
  await ready();
  if (!host || !Array.isArray(urls)) return { ok: false, error: 'Nothing to send' };
  const { urls: list, skipped } = replayCandidates(urls.slice(0, 10000).map(String), siteOf, host);
  const send = list.slice(0, MAX_REPLAY);
  for (const u of send) enqueue({ kind: 'replay', host, id: u, url: u });
  return { ok: true, queued: send.length, skipped: { ...skipped, limit: list.length - send.length } };
}

async function replayRequest(job) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 20000);
  try {
    await fetch(job.url, { method: 'GET', credentials: 'include', cache: 'no-store', redirect: 'manual', signal: ctrl.signal });
  } catch {
    /* the proxy has seen it either way */
  } finally {
    clearTimeout(timer);
  }
}

// ── endpoint liveness (opt-in, same-site): the same safe GET candidates as "send to proxy",
// but the response status is recorded so you can tell apart live (200), protected (401/403),
// wrong-method (405), redirecting (3xx) and dead (404) endpoints. Never cross-site, GET only.

const MAX_PROBE = 300;

async function probeEndpoints({ host, urls }) {
  await ready();
  if (!host || !Array.isArray(urls)) return { ok: false, error: 'Nothing to probe' };
  const { urls: list, skipped } = replayCandidates(urls.slice(0, 10000).map(String), siteOf, host);
  const send = list.slice(0, MAX_PROBE);
  if (!send.length) return { ok: true, queued: 0, skipped: { ...skipped, limit: list.length - send.length } };
  const data = await getHost(host);
  data.probes ||= {};
  for (const u of send) {
    data.probes[u] = { status: 'pending', at: Date.now() };
    enqueue({ kind: 'probe', host, id: u, url: u });
  }
  markDirty(host);
  return { ok: true, queued: send.length, skipped: { ...skipped, limit: list.length - send.length } };
}

async function probeRequest(job) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 20000);
  let rec;
  try {
    const res = await fetch(job.url, { method: 'GET', credentials: 'include', cache: 'no-store', redirect: 'manual', signal: ctrl.signal });
    rec = res.type === 'opaqueredirect' ? { status: 0, redirect: true } : { status: res.status };
  } catch (e) {
    rec = { status: 0, error: e && e.name === 'AbortError' ? 'timeout' : 'error' };
  } finally {
    clearTimeout(timer);
  }
  const data = await getHost(job.host);
  data.probes ||= {};
  data.probes[job.url] = { ...rec, at: Date.now() };
  markDirty(job.host);
}

// ── Wayback Machine: historical JS and source maps (manual button, or automatic when enabled) ──
// Talks to web.archive.org only (never to the target) and sends it the host name.

const WAYBACK_CDX = 'https://web.archive.org/cdx/search/cdx';
const isMapUrl = (u) => /\.map(?:[?#]|$)/i.test(u);

async function fetchArchive(url, maxBytes) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 60000);
  try {
    const res = await fetch(url, { credentials: 'omit', cache: 'force-cache', redirect: 'follow', signal: ctrl.signal });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const text = await res.text();
    if (maxBytes && text.length > maxBytes) throw new Error('Too large');
    return text;
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Timeout');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function waybackLookup({ host, limit }) {
  await ready();
  if (!host) return { ok: false, error: 'No host' };
  const s = state.settings;
  const data = await getHost(host);
  const max = Math.max(1, Math.min(2000, Number(limit) || s.waybackLimit || 100));
  const q = new URLSearchParams({ url: `${host.replace(/:\d+$/, '')}/*`, output: 'json', fl: 'timestamp,original', collapse: 'urlkey', limit: '20000' });
  q.append('filter', 'statuscode:200');
  q.append('filter', 'original:.*\\.(?:m?js|map)(?:\\?.*)?$');
  let rows;
  try {
    rows = JSON.parse((await fetchArchive(`${WAYBACK_CDX}?${q}`)) || '[]');
  } catch (e) {
    const msg = String(e.message || e);
    const error = `Wayback Machine: ${/HTTP (?:429|5\d\d)|Timeout/.test(msg) ? msg + ' (archive.org is busy, try again later)' : msg}`;
    data.wayback = { checked: Date.now(), error }; // the automatic lookup retries after an hour
    markDirty(host);
    return { ok: false, error };
  }
  const ordered = orderCaptures(rows);
  const captures = ordered;
  let queued = 0;
  for (const c of ordered) {
    if (queued >= max) break;
    const id = `https://web.archive.org/web/${c.timestamp}id_/${c.original}`;
    if (data.files[id] || data.files[c.original]?.status === 'done') continue; // already scanned (live or archived)
    queued++;
    enqueue({ kind: 'wayback', host, origin: data.origin, id, url: id, original: c.original, timestamp: c.timestamp });
  }
  data.wayback = { checked: Date.now(), captures: captures.length, queued };
  markDirty(host);
  return { ok: true, captures: captures.length, queued };
}

async function scanWayback(job) {
  const data = await getHost(job.host, job.origin);
  if (data.files[job.id]?.status === 'done') return;
  const s = state.settings;
  const ts = job.timestamp;
  const label = `${job.original} (archived ${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)})`;
  let text;
  try {
    text = await fetchArchive(job.url, s.maxFileSizeMB * 4 * 1048576);
  } catch {
    return; // missing captures are common; don't list them
  }
  if (/^\s*</.test(text.slice(0, 200))) return; // archive error page instead of the file
  const hash = await sha1(text);
  if (data.hashes[hash]) return; // identical to a file already scanned
  data.hashes[hash] = job.id;
  if (isMapUrl(job.original)) {
    const map = parseSourceMap(text);
    if (map) {
      processSourceMap(data, job.id, map, job.original, text.length);
      data.files[job.id].label = label;
    }
    return;
  }
  const results = analyze(text, rulesFor(job.host));
  data.files[job.id] = { url: job.id, kind: 'wayback', label, page: job.original, status: 'done', size: text.length, hash, ts: Date.now(), count: mergeFindings(data, results, { file: job.id }) };
  markDirty(job.host);
  scheduleBadge(job.host);
  queueDependencyChecks(job.host, data);
  // its source map, as archived around the same time
  const ref = s.fetchSourceMaps && sourceMapRef(text);
  if (ref && !ref.startsWith('data:')) {
    try {
      const mapUrl = new URL(ref, job.original).href;
      const id = `https://web.archive.org/web/${ts}id_/${mapUrl}`;
      if (!data.files[id]) enqueue({ kind: 'wayback', host: job.host, origin: job.origin, id, url: id, original: mapUrl, timestamp: ts });
    } catch {
      /* ignore */
    }
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

// "Active tab" scope: only the tab the user is actually looking at is scanned, not every open
// background tab. We track the frontmost tab of each window; a page is in scope only if its tab is
// one of them. tabId < 0 (our own fetches) and forced collects (explicit Rescan) bypass this check.
const activeByWindow = new Map(); // windowId → tabId of its active tab
const activeCollected = new Set(); // tabIds already collected since becoming active (avoids re-scan storms)

function isActiveTab(tabId) {
  if (tabId == null || tabId < 0) return false;
  for (const id of activeByWindow.values()) if (id === tabId) return true;
  return false;
}

async function initActiveTabs() {
  try {
    for (const t of await chrome.tabs.query({ active: true })) {
      if (t.windowId != null && t.id != null) activeByWindow.set(t.windowId, t.id);
    }
  } catch {
    /* ignore */
  }
}
initActiveTabs();

chrome.tabs.onActivated.addListener(async ({ tabId, windowId }) => {
  activeByWindow.set(windowId, tabId);
  // In active-tab mode, a background tab was skipped while it loaded; scan it now that it's in front.
  if (activeCollected.has(tabId)) return;
  try {
    const { settings } = await ready();
    if (!settings.enabled || settings.scopeMode !== 'active') return;
    activeCollected.add(tabId);
    chrome.tabs.sendMessage(tabId, { type: 'collect', force: true }).catch(() => {});
  } catch {
    /* ignore */
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  activeCollected.delete(tabId);
  for (const [w, id] of activeByWindow) if (id === tabId) activeByWindow.delete(w);
});
chrome.windows?.onRemoved?.addListener((windowId) => activeByWindow.delete(windowId));

function scopeFor(pageUrl, s, tabId) {
  let u;
  try {
    u = new URL(pageUrl);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (hostMatches(u.hostname, s.denyHosts)) return null;
  if (s.scopeMode === 'allowlist' && !hostMatches(u.hostname, s.allowHosts)) return null;
  if (s.scopeMode === 'active' && tabId != null && tabId >= 0 && !isActiveTab(tabId)) return null;
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
  const scope = scopeFor(pageUrl, settings, details.tabId);
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
  const scope = scopeFor(pageUrl, settings, d.tabId);
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
    count: fileCount(data, id),
  };
  markDirty(scope.host);
  scheduleBadge(scope.host);
}

/** Number of findings with a source in the given pseudo-file (headers, observed requests, runtime). */
const fileCount = (data, id) => Object.values(data.findings).filter((f) => f.sources.some((x) => x.file === id)).length;

// ── requests the page makes (fetch / XHR / WebSocket): method, path, parameter and header names ──

const OBSERVED_TYPES = new Set(['xmlhttprequest', 'websocket']);
const observedSeen = new Set();
const tabUrls = new Map(); // tabId → { url, t }

async function tabUrlCached(tabId) {
  const c = tabUrls.get(tabId);
  if (c && Date.now() - c.t < 3000) return c.url;
  const url = await tabUrl(tabId);
  if (tabUrls.size > 200) tabUrls.clear();
  tabUrls.set(tabId, { url, t: Date.now() });
  return url;
}

async function onRequestSent(d) {
  if (d.tabId < 0 || !OBSERVED_TYPES.has(d.type)) return;
  const { settings } = await ready();
  if (!settings.enabled || !settings.observeRequests) return;
  const pageUrl = await tabUrlCached(d.tabId);
  const scope = scopeFor(pageUrl, settings, d.tabId);
  if (!scope || !scriptAllowed(d.url.replace(/^ws/i, 'http'), scope, settings)) return; // ignored hosts / first-party only
  const results = observedRequest({ method: d.method, url: d.url, type: d.type, pageOrigin: scope.origin, requestHeaders: d.requestHeaders });
  if (!results.length) return;
  const sig = [scope.host, ...results.map((r) => `${r.category}|${r.meta?.kind || ''}|${r.value}`).sort()].join('\n');
  if (observedSeen.has(sig)) return;
  if (observedSeen.size > 10000) observedSeen.clear();
  observedSeen.add(sig);
  const data = await getHost(scope.host, scope.origin);
  const id = 'observed:' + scope.host;
  let sub = d.url;
  try {
    const u = new URL(d.url);
    sub = `${d.method || 'GET'} ${u.host}${normalizePath(u.pathname)}`;
  } catch {
    /* keep */
  }
  mergeFindings(data, results, { file: id, sub });
  data.files[id] = { url: id, kind: 'observed', label: `${scope.host} — observed requests`, page: pageUrl, status: 'done', ts: Date.now(), count: fileCount(data, id) };
  markDirty(scope.host);
}

chrome.webRequest.onBeforeSendHeaders?.addListener(
  (d) => void onRequestSent(d).catch(() => {}),
  { urls: ['http://*/*', 'https://*/*', 'ws://*/*', 'wss://*/*'], types: [...OBSERVED_TYPES] },
  ['requestHeaders', 'extraHeaders'],
);

// ── runtime hooks: names the page's code read / wrote, body fields, message handlers ──

const RUNTIME_LIMITS = { params: 500, storage: 300, cookies: 200, attrs: 300, bodies: 300, handlers: 50 };

async function onRuntimeCollect(msg, sender) {
  const { settings } = await ready();
  if (!settings.enabled || !settings.runtimeHooks) return { ok: false };
  const pageUrl = sender.tab?.url || msg.pageUrl;
  const scope = scopeFor(pageUrl, settings, sender.tab?.id);
  if (!scope) return { ok: false };
  const isFrame = !!msg.frame || (sender.frameId ?? 0) > 0;
  if (isFrame && !scriptAllowed(msg.pageUrl, scope, settings)) return { ok: false };
  const d = msg.data && typeof msg.data === 'object' ? msg.data : {};
  const list = (k) => (Array.isArray(d[k]) ? d[k].slice(0, RUNTIME_LIMITS[k]) : []);
  const base = { line: 0, col: 0, hits: 1, severity: 'info' };
  const out = [];
  const input = (rule, label, kind, name, tags = [], example) => {
    const f = inputFinding(kind, String(name ?? ''), ['runtime', ...tags]);
    if (!f) return;
    if (example) f.meta.example = example;
    out.push({ ...base, rule, label, category: 'params', ...f });
  };
  for (const n of list('params')) input('rt-param', 'Query parameter read (runtime)', 'query', n);
  for (const s of list('storage')) if (s && typeof s === 'object') input('rt-storage', 'Web storage key (runtime)', 'storage', s.key, s.area === 'session' ? ['session'] : []);
  for (const n of list('cookies')) input('rt-cookie', 'Cookie written (runtime)', 'cookie', n);
  for (const n of list('attrs')) input('rt-data', 'data-* attribute read (runtime)', 'data', n);
  for (const b of list('bodies')) {
    if (!b || typeof b !== 'object' || !Array.isArray(b.keys) || typeof b.path !== 'string') continue;
    const path = normalizePath(b.path);
    for (const k of b.keys.slice(0, 100)) input('rt-body', 'Request body field (runtime)', 'body', k, [], `${b.method} ${path}`);
    const api = apiEndpoint(String(b.method || 'POST'), path);
    if (api) out.push({ ...base, rule: 'rt-request', label: 'API call (runtime)', category: 'api', value: api.value, tags: [...api.tags, 'runtime'], meta: { ...api.meta, body: b.keys.slice(0, 30).join(', ') } });
  }
  for (const src of list('handlers')) {
    if (typeof src !== 'string') continue;
    const a = analyzeMessageHandler(src);
    const flat = src.replace(/\s+/g, ' ');
    out.push({ ...base, rule: 'rt-postmessage', label: a.label, category: 'intel', severity: a.severity, value: a.value, tags: ['runtime'], meta: a.meta, desc: POSTMESSAGE_DESC, ctx: ['', flat.slice(0, 400), flat.length > 400 ? '…' : ''] });
  }
  if (!out.length) return { ok: true };
  let u;
  try {
    u = new URL(msg.pageUrl || pageUrl);
  } catch {
    return { ok: false };
  }
  const data = await getHost(scope.host, scope.origin);
  const id = 'runtime:' + u.origin;
  mergeFindings(data, out, { file: id, sub: `${u.host}${u.pathname} — runtime` });
  data.files[id] = { url: id, kind: 'runtime', label: `${u.host} — runtime hooks`, page: pageUrl, status: 'done', ts: Date.now(), count: fileCount(data, id) };
  markDirty(scope.host);
  scheduleBadge(scope.host);
  return { ok: true, findings: out.length };
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
  const scope = scopeFor(pageUrl, settings, msg.force ? -1 : sender.tab?.id);
  if (!scope) return { ok: false, reason: 'out of scope' };
  const isFrame = !!msg.frame || (sender.frameId ?? 0) > 0;
  // iframes are treated like scripts: ignored hosts (ads, analytics, video) and "first-party only" apply
  if (isFrame && !scriptAllowed(msg.pageUrl, scope, settings)) return { ok: false, reason: 'frame skipped' };
  if (!isFrame && settings.waybackAuto) {
    const data = await getHost(scope.host, scope.origin);
    const failed = data.wayback?.error && Date.now() - data.wayback.checked > 3600000;
    if (!data.wayback || failed) {
      data.wayback = { checked: Date.now(), pending: true }; // once per host (failed lookups: retried after an hour)
      waybackLookup({ host: scope.host }).catch(() => {});
    }
  }
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
  'runtime-collect': onRuntimeCollect,
  wayback: waybackLookup,
  replay: replayToProxy,
  probe: probeEndpoints,
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
