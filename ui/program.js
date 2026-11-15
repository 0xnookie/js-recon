// Program view: every scanned host the program's scope covers, merged into one data object that the
// popup renders like a single host. Relative endpoints and API paths are made absolute first, so
// /api/users of app.acme.com and of api.acme.com stay apart. Each merged finding remembers which
// hosts (and which of their keys) it came from, so triage can be written back to every one of them.
// Pure: no chrome.* APIs, so it can be unit-tested with Node.

import { SEV_RANK, siteOf } from '../src/util.js';

export const PROGRAM = '@program';
const MAX_SOURCES = 8;

/** The popup's resolveUrl, against a given origin. */
export function absoluteUrl(v, origin) {
  if (/^(?:https?|wss?):\/\//i.test(v)) return v;
  if (v.startsWith('//')) return 'https:' + v;
  if (!origin || v.startsWith('${')) return v;
  try {
    return new URL(v.startsWith('/') || v.startsWith('.') ? v : '/' + v, origin + '/').href.replace(/%7B/g, '{').replace(/%7D/g, '}');
  } catch {
    return v;
  }
}

/** A host's finding with its endpoint / API path made absolute (key adjusted to the new value). */
function absolutized(f, origin) {
  let value = f.value;
  let meta = f.meta;
  if (f.category === 'endpoints') value = absoluteUrl(f.value, origin);
  else if (f.category === 'api' && !f.meta?.graphql) {
    const method = f.meta?.method || f.value.split(' ')[0];
    const path = f.meta?.path || f.value.slice(method.length + 1);
    const abs = absoluteUrl(path, origin);
    value = `${method} ${abs}`;
    meta = { ...f.meta, method, path: abs };
  }
  if (value === f.value) return f;
  const key = f.key.endsWith(f.value) ? f.key.slice(0, f.key.length - f.value.length) + value : f.category + '|' + value;
  return { ...f, key, value, meta };
}

/**
 * hosts: [{ host, data }] (data = the stored host:<host> object). Returns a data object shaped like a
 * host's, with `program: true`, `hosts` (names) and, on merged findings, `hosts` + `origKeys`.
 */
export function mergeHosts(list) {
  const out = {
    host: PROGRAM,
    program: true,
    hosts: [],
    origin: '',
    created: Date.now(),
    updated: 0,
    files: {},
    findings: {},
    hostChecks: {},
    wildcards: {}, // registrable site → its latest wildcard-DNS check
    probes: {},
    chunkUrls: {},
    triage: {},
    changes: [],
  };
  const statuses = new Map(); // merged key → Set of statuses ('' = untriaged) across its hosts
  const notes = new Map(); // merged key → Set of the notes its hosts carry
  for (const { host, data } of list) {
    if (!data) continue;
    out.hosts.push(host);
    out.updated = Math.max(out.updated, data.updated || 0);
    Object.assign(out.files, data.files || {});
    Object.assign(out.probes, data.probes || {});
    Object.assign(out.chunkUrls, data.chunkUrls || {});
    for (const [h, c] of Object.entries(data.hostChecks || {})) {
      const prev = out.hostChecks[h];
      if (!prev || (c.at || 0) > (prev.at || 0)) out.hostChecks[h] = c;
    }
    if (data.hostWildcard) {
      const site = siteOf(host.replace(/:\d+$/, ''));
      const prev = out.wildcards[site];
      if (!prev || (data.hostWildcard.at || 0) > (prev.at || 0)) out.wildcards[site] = data.hostWildcard;
    }
    const t = data.triage || {};
    // derived rows (params, domains) carry the popup's own keys: newest answer wins
    for (const [k, v] of Object.entries(t)) {
      if (!/^(?:param|domain)\|/.test(k)) continue;
      if (!out.triage[k] || (v.at || 0) > (out.triage[k].at || 0)) out.triage[k] = v;
    }
    for (const raw of Object.values(data.findings || {})) {
      const f = absolutized(raw, data.origin || 'https://' + host);
      const st = t[raw.key]?.s || '';
      if (t[raw.key]?.n) {
        if (!notes.has(f.key)) notes.set(f.key, new Set());
        notes.get(f.key).add(t[raw.key].n);
      }
      let m = out.findings[f.key];
      if (!m) {
        m = out.findings[f.key] = { ...f, tags: [...(f.tags || [])], sources: [...(f.sources || [])].slice(0, MAX_SOURCES), hosts: [host], origKeys: [[host, raw.key]] };
        delete m.changedAt;
        statuses.set(f.key, new Set([st]));
        continue;
      }
      if (!m.hosts.includes(host)) m.hosts.push(host);
      m.origKeys.push([host, raw.key]);
      statuses.get(f.key).add(st);
      m.hits = (m.hits || 0) + (f.hits || 0);
      m.first = Math.min(m.first || Infinity, f.first || Infinity);
      for (const tag of f.tags || []) if (!m.tags.includes(tag)) m.tags.push(tag);
      for (const s of f.sources || []) if (m.sources.length < MAX_SOURCES) m.sources.push(s);
      if ((SEV_RANK[f.severity] || 0) > (SEV_RANK[m.severity] || 0)) Object.assign(m, { severity: f.severity, label: f.label, rule: f.rule, meta: f.meta, desc: f.desc });
    }
  }
  // a merged finding counts as triaged only when every host agrees; one unreviewed copy keeps it open
  for (const [k, set] of statuses) {
    if (set.size === 1) {
      const s = [...set][0];
      if (s) out.triage[k] = { s, at: 0 };
    }
  }
  // notes from every host, joined
  for (const [k, set] of notes) out.triage[k] = { ...(out.triage[k] || {}), n: [...set].join(' | ') };
  out.hosts.sort();
  return out;
}

/**
 * Program-wide subdomain checks: the subdomains grouped by registrable site, each sent through one
 * scanned host of that site (the worker files the results under it). [{ host, site, hosts }]
 */
export function siteGroups(subdomains, scannedHosts) {
  const home = new Map();
  for (const h of [...scannedHosts].sort()) {
    const site = siteOf(h.replace(/:\d+$/, ''));
    if (!home.has(site)) home.set(site, h);
  }
  const groups = new Map();
  for (const d of subdomains) {
    const site = siteOf(String(d).replace(/:\d+$/, ''));
    if (!home.has(site)) continue;
    if (!groups.has(site)) groups.set(site, { host: home.get(site), site, hosts: [] });
    groups.get(site).hosts.push(d);
  }
  return [...groups.values()];
}

/** Host → keys to write when the user triages merged items (derived rows go to every host). */
export function triageTargets(items, hosts) {
  const byHost = new Map();
  const add = (h, k) => {
    if (!byHost.has(h)) byHost.set(h, new Set());
    byHost.get(h).add(k);
  };
  for (const f of items) {
    if (f.origKeys?.length) for (const [h, k] of f.origKeys) add(h, k);
    else for (const h of hosts) add(h, f.key);
  }
  return [...byHost].map(([host, keys]) => ({ host, keys: [...keys] }));
}
