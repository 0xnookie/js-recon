import { SEV_RANK, CONFIDENCE_RANK, decodeJwt, siteOf, hostOf, formatBytes, truncate } from '../src/util.js';
import { DEV_HOST_RE, CLOUD_HOST_RE, interestingParam } from '../src/rules.js';
import { getSettings, saveSettings } from '../src/settings.js';
import { sourcesZip, dumpHosts, canRebuild } from './dump.js';
import { searchHost } from './search.js';
import { ZipWriter } from '../src/zip.js';
import { buildOpenApi, buildPostman, buildSarif, replayCandidates } from '../src/exporters.js';
import { parseDefinition, schemaSketch } from '../src/graphql.js';
import { rateHost, hostAlive } from '../src/hosts.js';
import { compileScope, hasScope, hostScope, urlScope } from '../src/scope.js';
import { VULNDB_DATE } from '../src/libs.js';
import { PROGRAM, mergeHosts, triageTargets, siteGroups } from './program.js';

const params = new URLSearchParams(location.search);
const FULL = params.get('view') === 'full';
document.body.classList.toggle('full', FULL);
document.body.classList.toggle('popup', !FULL);

const TABS = [
  { id: 'secrets', label: 'Secrets' },
  { id: 'api', label: 'API' },
  { id: 'endpoints', label: 'Endpoints' },
  { id: 'urls', label: 'URLs' },
  { id: 'domains', label: 'Domains' },
  { id: 'cloud', label: 'Cloud' },
  { id: 'params', label: 'Params' },
  { id: 'deps', label: 'Deps' },
  { id: 'intel', label: 'Intel' },
  { id: 'routes', label: 'Routes', optional: true },
  { id: 'flags', label: 'Flags', optional: true },
  { id: 'sinks', label: 'Sinks', optional: true },
  { id: 'files', label: 'Files' },
];

const store = {
  get(k, d) {
    try {
      const v = localStorage.getItem('jsrecon.' + k);
      return v == null ? d : JSON.parse(v);
    } catch {
      return d;
    }
  },
  set(k, v) {
    try {
      localStorage.setItem('jsrecon.' + k, JSON.stringify(v));
    } catch {
      /* ignore */
    }
  },
};

const ui = {
  host: params.get('host'),
  tabHost: null,
  tabId: null,
  data: null,
  model: null,
  index: {},
  settings: null,
  tab: store.get('tab', 'secrets'),
  q: '',
  sev: 'all',
  hideNoise: store.get('hideNoise', true),
  hideTentative: store.get('hideTentative', false),
  onlyInteresting: false,
  onlyNew: false,
  onlyInScope: false,
  triage: store.get('triage', 'all'), // all | todo | reviewed | reported | fp
  scope: compileScope(),
  absolute: store.get('absolute', false),
  limit: 400,
  expanded: new Set(),
  visible: [],
};
if (!TABS.some((t) => t.id === ui.tab)) ui.tab = 'secrets';

const $ = (s) => document.querySelector(s);

function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? '' : v);
    }
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) e.append(c instanceof Node ? c : String(c));
  return e;
}

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), 1800);
}

async function copy(text, what = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = h('textarea', {}, text);
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  toast(what);
}

function downloadBlob(name, blob) {
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

const download = (name, text, type = 'text/plain') => downloadBlob(name, new Blob([text], { type }));
const safeName = (s) => String(s || 'export').replace(/[^\w.-]+/g, '_');
const isHttp = (u) => /^https?:\/\//i.test(u);
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
const stamp = () => new Date().toISOString().slice(0, 10);

// ───────────────────────── model ─────────────────────────

function resolveUrl(v) {
  if (/^(?:https?|wss?):\/\//i.test(v)) return v;
  if (v.startsWith('//')) return 'https:' + v;
  const origin = ui.data?.origin || (ui.host ? 'https://' + ui.host : '');
  if (!origin || v.startsWith('${')) return v;
  try {
    return new URL(v.startsWith('/') || v.startsWith('.') ? v : '/' + v, origin + '/').href.replace(/%7B/g, '{').replace(/%7D/g, '}');
  } catch {
    return v;
  }
}

const apiParts = (f) => {
  const method = f.meta?.method || f.value.split(' ')[0];
  return { method, path: f.meta?.path || f.value.slice(method.length + 1) };
};

/** Body field names of an API finding (meta.body is "a, b", from the request code or the runtime hooks). */
const bodyFields = (meta) => String(meta?.body || '').split(', ').filter(Boolean);

// What to test first: sensitive names, object IDs (IDOR), state-changing methods, known inputs, seen live
const API_WEIGHT = { interesting: 4, idor: 3, write: 2, observed: 1, runtime: 1 };
function apiPriority(f) {
  let s = 0;
  for (const t of f.tags || []) s += API_WEIGHT[t] || 0;
  if (f.meta?.body || apiParts(f).path.includes('?')) s += 1;
  return s;
}

// Params tab groups: everything on the client side a tester can set
const PARAM_KINDS = {
  query: 'Query parameters',
  body: 'Request body fields',
  data: 'data-* attributes',
  form: 'Form fields',
  header: 'Request headers',
  cookie: 'Cookies',
  storage: 'Web storage keys',
};
const PARAM_KIND_ORDER = Object.keys(PARAM_KINDS);
const PARAM_DESC = {
  query: 'Read from the page URL or sent in requests. Try it on the page and on the API endpoints.',
  body: 'Top-level JSON / form field the page sends: read from the request code (JSON.stringify, FormData, $.ajax data …) or recorded by the runtime hooks. The examples show the endpoints. "idor" marks object IDs: change them to another user\'s. Good candidates for mass assignment: add fields the UI never sends.',
  data: 'Read from a data-* attribute, usually on the embedding element (widget container or <script> tag). An embedder controls it.',
  form: 'Submitted by a form. Hidden fields are worth tampering with.',
  header: 'Request header set or read by the code. Custom headers often switch behaviour on the server.',
  cookie: 'Cookie read or written by the code.',
  storage: 'localStorage / sessionStorage key. Debug and feature switches often live here.',
};

const isProgram = () => ui.host === PROGRAM;
/** Name used in reports and file names: the host, or "program" for the merged in-scope view. */
const hostLabel = () => (isProgram() ? 'program' : ui.host);
const scoped = () => hasScope(ui.scope);

function buildModel(data) {
  const m = { secrets: [], api: [], endpoints: [], urls: [], domains: [], cloud: [], params: [], deps: [], intel: [], sinks: [], routes: [], flags: [], files: [], graphql: [] };
  if (!data) return m;
  const pageSite = siteOf((ui.host || '').replace(/:\d+$/, ''));
  // the target's own sites: this host's, or in the program view every merged host's
  const ownSites = new Set(data.program ? data.hosts.map((x) => siteOf(x.replace(/:\d+$/, ''))) : [pageSite]);
  const params = new Map();
  const domains = new Map();
  const addParam = (name, example, f, kind = 'query') => {
    if (kind === 'query' && !/^[A-Za-z_$][\w.[\]$-]{0,60}$/.test(name)) return;
    const key = `param|${kind}|${name}`;
    let p = params.get(key);
    if (!p) {
      const tags = interestingParam(name) ? ['interesting'] : [];
      params.set(key, (p = { key, value: name, kind, label: PARAM_KINDS[kind] || kind, desc: PARAM_DESC[kind], count: 0, tags, examples: [], sources: [], meta: {} }));
    }
    p.count++;
    if (f) {
      for (const t of f.tags || []) if (!p.tags.includes(t)) p.tags.push(t);
      if (f.meta?.key) p.meta['config key'] = f.meta.key;
      example ||= f.meta?.example;
    }
    for (const x of [example, ...(f?.meta?.examples || [])]) if (x && p.examples.length < 5 && !p.examples.includes(x)) p.examples.push(x);
    if (f && p.sources.length < 5) p.sources.push(...f.sources.slice(0, 5 - p.sources.length));
  };
  const addDomain = (host, example, extraTags = [], hits = 1, f = null) => {
    let d = domains.get(host);
    if (!d) {
      const hostname = host.replace(/:\d+$/, '');
      const site = siteOf(hostname);
      const tags = [ownSites.has(site) ? 'same-site' : 'third-party'];
      // only look at the subdomain labels: "staging.acme.io" yes, "acme.test" no
      if (hostname !== site && DEV_HOST_RE.test(hostname.slice(0, -site.length - 1))) tags.push('interesting');
      if (CLOUD_HOST_RE.test(host.replace(/:\d+$/, ''))) tags.push('cloud');
      domains.set(host, (d = { key: 'domain|' + host, value: host, count: 0, tags, examples: [], sources: [] }));
    }
    for (const t of extraTags) if (!d.tags.includes(t)) d.tags.push(t);
    d.count += hits;
    if (example && d.examples.length < 5 && !d.examples.includes(example)) d.examples.push(example);
    if (f && d.sources.length < 5) d.sources.push(...f.sources.slice(0, 5 - d.sources.length));
  };

  // findings that first appeared with the latest bundle change are "new"
  const latestChange = data.changes?.[0]?.at;
  for (const f of Object.values(data.findings)) {
    if (latestChange && f.changedAt === latestChange && !f.tags?.includes('new')) f.tags = [...(f.tags || []), 'new'];
  }
  for (const f of Object.values(data.findings)) {
    if (f.category === 'params') {
      addParam(f.value, null, f, f.meta?.kind || 'query');
      continue;
    }
    if (f.category === 'subdomains') {
      // seen in code, or only in CSP / CORS headers, certificate logs (ct) or the page's own traffic (observed)
      const inCode = !f.sources?.length || f.sources.some((s) => !/^(?:headers|ct|observed):/.test(s.file));
      addDomain(f.value, null, inCode ? ['in-code', ...(f.tags || [])] : f.tags || [], f.hits || 1, f);
      continue;
    }
    (m[f.category] || m.intel).push(f);
    if (f.category === 'endpoints' || f.category === 'urls' || f.category === 'api') {
      const v = f.category === 'api' ? apiParts(f).path : f.value;
      const q = v.split('#')[0].split('?')[1];
      if (q) for (const part of q.split('&')) addParam(decodeURIComponentSafe(part.split('=')[0]), v);
    }
    if (f.category === 'urls' && !f.tags?.includes('noise')) {
      const host = urlHost(f.value);
      if (host) addDomain(host, f.value);
    }
  }
  const kindRank = (p) => PARAM_KIND_ORDER.indexOf(p.kind) >>> 0; // unknown kinds last
  const paramRank = (p) => (p.tags.includes('interesting') ? 2 : 0) + (p.tags.includes('idor') ? 1 : 0);
  m.params = [...params.values()].sort(
    (a, b) => kindRank(a) - kindRank(b) || paramRank(b) - paramRank(a) || b.count - a.count || a.value.localeCompare(b.value),
  );
  // the target's own subdomains: what answered (our check or the page's traffic) and how worth testing they are
  const checks = data.hostChecks || {};
  // wildcard DNS is per registrable site: the host's own check, or each site's in the program view
  const wildFor = (site) => {
    const w = data.program ? data.wildcards?.[site] : data.hostWildcard;
    return w?.status ? w : null;
  };
  for (const d of domains.values()) {
    if (!d.tags.includes('same-site') || d.value.includes('*')) continue;
    d.check = checks[d.value.toLowerCase()] || null;
    // a check the worker never finished (restarted mid-run) shouldn't say "checking…" forever
    if (d.check?.pending && Date.now() - (d.check.at || 0) > 5 * 60000) {
      const { pending, ...rest } = d.check;
      d.check = rest.seen ? rest : null;
    }
    const site = siteOf(d.value.replace(/:\d+$/, ''));
    d.rating = rateHost(d.value, site, d.check, wildFor(site));
    if (d.rating.wildcard) d.tags.push('wildcard');
    else if (hostAlive(d.check)) d.tags.push('live');
    if (d.check?.takeover && !d.rating.wildcard) d.tags.push('takeover');
  }
  // program scope (Settings → Program scope): out-of-scope and unlisted hosts are marked and greyed
  if (scoped()) {
    for (const d of domains.values()) {
      d.scope = d.value.includes('*') ? null : hostScope(ui.scope, d.value);
      if (d.scope === 'out') d.tags.push('out-of-scope');
      else if (d.scope === 'unlisted' && d.tags.includes('same-site')) d.tags.push('not-in-scope');
    }
  }
  const has = (x, t) => (x.tags.includes(t) ? 1 : 0);
  m.domains = [...domains.values()].sort(
    (a, b) =>
      has(b, 'same-site') - has(a, 'same-site') ||
      (b.rating?.score || 0) - (a.rating?.score || 0) ||
      has(b, 'live') - has(a, 'live') ||
      has(b, 'interesting') - has(a, 'interesting') ||
      a.value.localeCompare(b.value),
  );
  const bySev = (a, b) =>
    (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) ||
    (CONFIDENCE_RANK[b.confidence] ?? 1) - (CONFIDENCE_RANK[a.confidence] ?? 1) ||
    a.label.localeCompare(b.label) ||
    a.value.localeCompare(b.value);
  m.secrets.sort(bySev);
  m.intel.sort(bySev);
  m.cloud.sort(bySev);
  m.deps.sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || a.value.localeCompare(b.value));
  m.sinks.sort((a, b) => a.label.localeCompare(b.label));
  const byInteresting = (a, b) => (b.tags?.includes('interesting') - a.tags?.includes('interesting')) || a.value.localeCompare(b.value);
  m.endpoints.sort(byInteresting);
  m.urls.sort(byInteresting);
  m.api.sort((a, b) => apiPriority(b) - apiPriority(a) || apiParts(a).path.localeCompare(apiParts(b).path) || a.value.localeCompare(b.value));
  // flags: switched off first (the unreleased features), then interesting names, then by name
  const flagRank = (f) => (f.tags?.includes('off') ? 2 : 0) + (f.tags?.includes('interesting') ? 1 : 0);
  m.flags.sort((a, b) => flagRank(b) - flagRank(a) || a.value.localeCompare(b.value));
  m.routes.sort(
    (a, b) =>
      (b.tags?.includes('interesting') - a.tags?.includes('interesting')) ||
      (b.tags?.includes('guarded') - a.tags?.includes('guarded')) ||
      a.value.localeCompare(b.value),
  );
  m.files = Object.values(data.files).sort((a, b) => (b.ts || 0) - (a.ts || 0));
  // what the user has already looked at (reviewed / reported / false positive), by row key
  const triage = data.triage || {};
  for (const [tab, list] of Object.entries(m)) {
    if (tab === 'files') continue;
    for (const f of list) {
      f.triage = triage[f.key]?.s || null;
      f.note = triage[f.key]?.n || '';
    }
  }
  return m;
}

function decodeURIComponentSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function urlHost(v) {
  try {
    const u = new URL(v.startsWith('//') ? 'https:' + v : v);
    return u.hostname.includes('${') ? null : u.host;
  } catch {
    return null;
  }
}

function makeMatcher(q) {
  if (!q) return () => true;
  const lit = /^\/(.+)\/([a-z]*)$/.exec(q);
  if (lit) {
    try {
      const re = new RegExp(lit[1], lit[2].replace('g', '') || 'i');
      return (s) => re.test(s);
    } catch {
      /* fall through to substring */
    }
  }
  const needle = q.toLowerCase();
  return (s) => s.toLowerCase().includes(needle);
}

const SEV_TABS = new Set(['secrets', 'intel', 'cloud', 'deps']);
const NOISE_TABS = new Set(['endpoints', 'urls', 'intel', 'params']);
const INTERESTING_TABS = new Set(['endpoints', 'urls', 'domains', 'api', 'params', 'routes', 'flags']);

/** The Status filter: everything, only what is left to review, or one triage status. */
function triagePass(f, tab = ui.tab) {
  if (tab === 'files' || ui.triage === 'all') return true;
  if (ui.triage === 'todo') return !f.triage;
  return f.triage === ui.triage;
}

function filtered(tab) {
  const items = ui.model[tab] || [];
  const match = makeMatcher(ui.q.trim());
  const minSev = ui.sev === 'all' ? -1 : SEV_RANK[ui.sev];
  return items.filter((f) => {
    if (!triagePass(f, tab)) return false;
    if (SEV_TABS.has(tab) && (SEV_RANK[f.severity] || 0) < minSev) return false;
    if (tab === 'secrets' && ui.hideTentative && (f.confidence === 'tentative' || f.tags?.includes('example'))) return false;
    if (ui.hideNoise && NOISE_TABS.has(tab) && f.tags?.some((t) => t === 'noise' || t === 'static')) return false;
    if (ui.onlyInteresting && INTERESTING_TABS.has(tab) && !f.tags?.some((t) => t === 'interesting' || t === 'idor') && !f.rating?.level) return false;
    if (ui.onlyLive && tab === 'domains' && !f.tags?.includes('live')) return false;
    if (ui.onlyInScope && tab === 'domains' && scoped() && f.scope !== 'in') return false;
    if (ui.onlyNew && tab !== 'files' && !f.tags?.includes('new')) return false;
    if (tab === 'files') return match(f.url + ' ' + (f.label || '') + ' ' + (f.error || ''));
    return match(f.value + ' ' + (f.label || '') + ' ' + (f.examples || []).join(' ') + ' ' + (f.tags || []).join(' ') + ' ' + (f.note || ''));
  });
}

// ───────────────────────── rendering ─────────────────────────

function fileName(id) {
  const fi = ui.data?.files?.[id];
  if (fi?.label) return fi.label;
  if (/^(?:inline|html|manual):/.test(id)) return id;
  try {
    const u = new URL(id.replace(/ \[inline source map\]$/, ''));
    const base = u.pathname.split('/').filter(Boolean).pop() || u.host;
    return base + (id.endsWith('[inline source map]') ? ' (inline map)' : '');
  } catch {
    return id;
  }
}

function srcLabel(s) {
  const loc = s.line ? `:${s.line}${s.col ? ':' + s.col : ''}` : '';
  return s.sub ? `${s.sub}${loc}` : `${fileName(s.file)}${loc}`;
}

function fileLink(s) {
  const text = srcLabel(s);
  const title = s.sub ? `${s.sub} (via ${s.file})` : s.file;
  const target = s.file.replace(/ \[inline source map\]$/, '');
  return isHttp(target)
    ? h('a', { class: 'file', href: target, target: '_blank', rel: 'noreferrer', title }, text)
    : h('span', { class: 'file', title }, text);
}

function srcSummary(f) {
  if (!f.sources?.length) return null;
  const more = f.sources.length > 1 ? ` +${f.sources.length - 1}` : '';
  return h('span', { class: 'src', title: f.sources.map(srcLabel).join('\n') }, truncate(srcLabel(f.sources[0]), 42) + more);
}

const HIDDEN_CHIPS = new Set(['js', 'write', 'live']); // "live" is shown as the status chip
const CHIP_TITLES = {
  idor: 'Sends an object ID (path segment, body field or query parameter): try another user\'s ID (IDOR / BOLA)',
  interesting: 'Name suggests a sensitive function (admin, upload, token, payment …)',
  ct: 'Found in certificate-transparency logs (crt.sh)',
  observed: 'Seen in the browser\'s real traffic',
  takeover: 'Answers with a hosting provider\'s "no such site / bucket" page: possible subdomain takeover',
  wildcard: 'Answers exactly like a made-up subdomain (wildcard DNS): probably not a real host',
  'in-code': 'Found in the JavaScript / HTML',
  'out-of-scope': 'Excluded by the program scope (Settings → Program scope): no active checks are sent to it',
  'not-in-scope': 'Not listed in the program scope (Settings → Program scope): no active checks are sent to it',
  vulnerable: 'A library version with published advisories (retire.js data)',
  off: 'Switched off (or false) for this page: the feature behind it may already exist on the server',
  on: 'Switched on for this page',
  'in-house': 'Evaluated by the app\'s own flag helper, not a known SDK',
  'config-object': 'From a features: { … } object in the code or page config',
  library: 'Library version found; no known advisory for it',
};

// ── triage: reviewed / reported / false positive, stored per host (survives rescans and redeploys) ──

const TRIAGE = {
  reviewed: { label: 'reviewed', title: 'Looked at, nothing to report' },
  reported: { label: 'reported', title: 'Reported (or being written up)' },
  fp: { label: 'false positive', title: 'Not a real issue' },
};

/** Writes a status (or null to clear it) for these rows, updating the view at once. */
async function setTriage(items, status) {
  items = items.filter((f) => f?.key);
  if (!items.length || !ui.data) return;
  const t = (ui.data.triage ||= {});
  for (const f of items) {
    const e = { ...(t[f.key] || {}) };
    if (status) Object.assign(e, { s: status, at: Date.now() });
    else delete e.s;
    if (e.s || e.n) t[f.key] = e;
    else delete t[f.key];
    f.triage = status || null;
  }
  render();
  await sendTriage(items, { status: status || null }, 'Could not save the status, try again');
}

/** Sends a triage change to the worker (every host the rows came from, in the program view). */
async function sendTriage(items, change, error) {
  const targets = isProgram() ? triageTargets(items, ui.data.hosts) : [{ host: ui.host, keys: items.map((f) => f.key) }];
  let failed = 0;
  for (const { host, keys } of targets) {
    try {
      const r = await chrome.runtime.sendMessage({ type: 'triage', host, keys, ...change });
      if (!r?.ok) failed++;
    } catch {
      failed++;
    }
  }
  if (failed) toast(error);
}

/** A free-text note on a row ('' removes it), e.g. "reported as H1 #123456". */
async function setNote(f, note) {
  note = String(note || '').replace(/\s+/g, ' ').trim().slice(0, 500);
  if (!ui.data || note === (f.note || '')) return;
  const t = (ui.data.triage ||= {});
  const e = { ...(t[f.key] || {}) };
  if (note) Object.assign(e, { n: note, nat: Date.now() });
  else delete e.n, delete e.nat;
  if (e.s || e.n) t[f.key] = e;
  else delete t[f.key];
  f.note = note;
  // let a click that moved the focus out of the field (e.g. on "Reported") land before the list is rebuilt
  setTimeout(() => !editingNote() && render(), 300);
  await sendTriage([f], { note }, 'Could not save the note, try again');
  if (note) toast('Note saved');
}

function triageChip(f) {
  const t = TRIAGE[f.triage];
  return t ? h('span', { class: `chip triage t-${f.triage}`, title: t.title }, t.label) : null;
}

/** The status buttons at the top of an expanded row. */
function triageBar(f) {
  const b = (status, label, title) =>
    h('button', { class: `mini${f.triage === status ? ' primary' : ''}`, title, onclick: (e) => (e.stopPropagation(), setTriage([f], f.triage === status ? null : status)) }, label);
  return h(
    'div',
    { class: 'triage-bar' },
    h('span', { class: 'muted small' }, 'Status'),
    b('reviewed', 'Reviewed', 'Looked at it: hide it with Status → To review'),
    b('reported', 'Reported', 'Reported, or being written up'),
    b('fp', 'False positive', 'Not a real issue: left out of the reports and SARIF'),
    f.triage ? h('button', { class: 'mini', onclick: (e) => (e.stopPropagation(), setTriage([f], null)) }, 'Clear') : null,
    noteInput(f),
  );
}

function noteInput(f) {
  const input = h('input', {
    type: 'text',
    class: 'note-input',
    value: f.note || '',
    maxlength: '500',
    spellcheck: 'false',
    placeholder: 'Note — e.g. reported as H1 #123456, tested 12 Nov: 403',
    title: 'A note for this row: kept per host, shown on the row, included in the reports. Enter or leaving the field saves it.',
  });
  input.addEventListener('click', (e) => e.stopPropagation());
  input.addEventListener('keydown', (e) => {
    e.stopPropagation();
    if (e.key === 'Enter') input.blur();
    if (e.key === 'Escape') {
      input.value = f.note || '';
      input.blur();
    }
  });
  input.addEventListener('change', () => setNote(f, input.value));
  return input;
}

/** Adds the status chip and the quick "mark reviewed" button to a rendered row. */
function decorateTriage(row, f) {
  const head = row.querySelector(':scope > .row-head');
  if (!head) return row;
  if (f.triage) row.classList.add('triaged', 't-' + f.triage);
  const chip = triageChip(f);
  const spacer = head.querySelector(':scope > .spacer');
  if (chip) head.insertBefore(chip, spacer || null);
  if (f.note) head.insertBefore(h('span', { class: 'row-note', title: `Note: ${f.note}` }, truncate(f.note, 60)), spacer || null);
  const quick = f.triage
    ? btn('↺', 'Clear the status', () => setTriage([f], null), 'triage-quick')
    : btn('✓', 'Mark reviewed (looked at it, nothing to report)', () => setTriage([f], 'reviewed'), 'triage-quick');
  const last = head.lastElementChild;
  head.insertBefore(quick, last?.tagName === 'BUTTON' ? last : null);
  return row;
}
function chips(tags) {
  return (tags || []).filter((t) => !HIDDEN_CHIPS.has(t)).map((t) => h('span', { class: `chip ${t}`, title: CHIP_TITLES[t] || '' }, t.replace(/-/g, ' ')));
}

function btn(label, title, fn, cls = '') {
  return h('button', { class: `mini ${cls}`, title, onclick: (e) => (e.stopPropagation(), fn()) }, label);
}

function ctxBlock(ctx) {
  return h('pre', { class: 'ctx mono' }, ctx[0], h('mark', {}, ctx[1]), ctx[2]);
}

function metaBlock(meta) {
  const rows = Object.entries(meta).filter(([, v]) => v != null && v !== '' && !(Array.isArray(v) && !v.length));
  if (!rows.length) return null;
  return h('dl', { class: 'meta' }, rows.map(([k, v]) => [h('dt', {}, k), h('dd', { class: 'mono' }, Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v) : String(v))]));
}

function detailFor(f) {
  const d = h('div', { class: 'detail' });
  if (f.desc) d.append(h('div', { class: 'desc' }, f.desc));
  const meta = { ...(f.meta || {}) };
  if (f.confidence) Object.assign(meta, { confidence: f.confidence, entropy: `${f.entropy} bits/char (Shannon)` });
  delete meta.method;
  delete meta.path;
  delete meta.graphql;
  delete meta.vulns;
  if (meta.kind === 'library') {
    // name and version are the row's value already
    for (const k of ['kind', 'library', 'version', 'eol']) delete meta[k];
  }
  if (f.hosts?.length) meta.hosts = f.hosts;
  const doc = meta.document;
  delete meta.document;
  if (f.meta?.graphql) meta.endpoint = graphqlEndpoint();
  const mb = metaBlock(meta);
  if (mb) d.append(mb);
  if (doc) d.append(h('pre', { class: 'json mono' }, doc));
  if (/^eyJ/.test(f.value)) {
    const j = decodeJwt(f.value);
    if (j) d.append(h('pre', { class: 'json mono' }, JSON.stringify(j, null, 2)));
  }
  if (f.examples?.length) d.append(h('div', { class: 'examples' }, f.examples.map((x) => h('div', { class: 'mono' }, x))));
  for (const s of f.sources || []) d.append(h('div', { class: 'source' }, fileLink(s), s.ctx ? ctxBlock(s.ctx) : null));
  if (f.hits > (f.sources?.length || 0)) d.append(h('div', { class: 'muted small' }, `${f.hits} occurrences in total`));
  return d;
}

function expandable(row, key, buildDetail) {
  // rows that can be triaged get the status buttons on top of their detail
  const build = () => {
    const d = buildDetail();
    const f = ui.itemsByKey?.get(key);
    if (f && d) d.prepend(triageBar(f));
    return d;
  };
  const open = ui.expanded.has(key);
  row.classList.toggle('open', open);
  if (open) row.append(build());
  row.addEventListener('click', (e) => {
    if (e.target.closest('a,button,.detail') || getSelection().toString()) return;
    if (ui.expanded.has(key)) {
      ui.expanded.delete(key);
      row.classList.remove('open');
      row.querySelector(':scope > .detail')?.remove();
    } else {
      ui.expanded.add(key);
      row.classList.add('open');
      row.append(build());
    }
  });
  return row;
}

const head = (...kids) => h('div', { class: 'row-head' }, ...kids);

function findingRow(f) {
  const conf = f.confidence ? h('span', { class: `chip conf ${f.confidence}`, title: `Shannon entropy ${f.entropy} bits/char` }, f.confidence) : null;
  const row = h(
    'div',
    { class: `row finding sev-${f.severity}` },
    head(h('span', { class: `pill ${f.severity}` }, f.severity), h('span', { class: 'label' }, f.label), conf, chips(f.tags), h('span', { class: 'spacer' }), srcSummary(f), btn('Copy', 'Copy value', () => copy(f.value))),
    h('div', { class: 'value mono', title: f.value }, f.value),
  );
  return expandable(row, f.key, () => detailFor(f));
}

/** Single-line variant used under group headers (Intel, Cloud, Sinks), where the label is the header. */
function compactFindingRow(f) {
  const row = h(
    'div',
    { class: `row link sev-${f.severity}` },
    head(h('span', { class: `pill ${f.severity}` }, f.severity), h('span', { class: 'value mono', title: f.value }, f.value), chips(f.tags), h('span', { class: 'spacer' }), srcSummary(f), btn('Copy', 'Copy value', () => copy(f.value))),
  );
  return expandable(row, f.key, () => detailFor(f));
}

function linkRow(f) {
  const shown = ui.absolute && f.category === 'endpoints' ? resolveUrl(f.value) : f.value;
  const openUrl = resolveUrl(f.value);
  const row = h(
    'div',
    { class: 'row link' },
    head(
      h('span', { class: 'value mono', title: shown }, shown),
      chips(f.tags),
      probeChip(openUrl),
      h('span', { class: 'spacer' }),
      srcSummary(f),
      isHttp(openUrl) && !openUrl.includes('${') ? btn('Open', openUrl, () => chrome.tabs.create({ url: openUrl, active: false })) : null,
      btn('Copy', 'Copy', () => copy(shown)),
    ),
  );
  return expandable(row, f.key, () => detailFor(f));
}

/** curl with the body the page sends: recovered sample payload, else the field names, else {} */
function curlFor(method, url, meta = {}) {
  const base = `curl -i -s -k -X ${method} ${shq(url)}`;
  const fields = bodyFields(meta);
  if (!['POST', 'PUT', 'PATCH'].includes(method) && !fields.length) return base;
  const enc = meta.encoding || 'json';
  if (enc === 'multipart') {
    const pairs = meta.sample ? meta.sample.split('&') : fields.map((n) => `${encodeURIComponent(n)}=`);
    // --form-string, not -F: a value starting with @ or < would make curl read a local file
    return `${base} ${pairs.map((p) => '--form-string ' + shq(decodeURIComponentSafe(p))).join(' ')}`;
  }
  if (enc === 'form') {
    const body = meta.sample || fields.map((n) => `${encodeURIComponent(n)}=`).join('&');
    return `${base} -H 'Content-Type: application/x-www-form-urlencoded' --data-raw ${shq(body)}`;
  }
  const body = meta.sample || JSON.stringify(Object.fromEntries(fields.map((n) => [n, ''])));
  return `${base} -H 'Content-Type: application/json' --data-raw ${shq(body)}`;
}

/** The GraphQL endpoint the app uses: a discovered URL / endpoint containing "graphql", else /graphql. */
function graphqlEndpoint() {
  const m = ui.model;
  const cands = [...(m?.endpoints || []), ...(m?.urls || [])].map((f) => f.value).filter((v) => /graphql|\/gql(?:[/?#]|$)/i.test(v) && !v.includes('${'));
  const own = cands.find((v) => resolveUrl(v).startsWith(ui.data?.origin || '\u0000'));
  return resolveUrl(own || cands[0] || '/graphql');
}

const GQL_LABEL = { QUERY: 'QUERY', MUTATION: 'MUTATION', SUBSCRIPTION: 'SUB' };

function graphqlRow(f) {
  const { method } = apiParts(f);
  const m = method.toLowerCase();
  const curl = () => {
    const body = JSON.stringify({ operationName: f.meta.path, query: f.meta.document || '', variables: {} });
    return `curl -i -s -k -X POST ${shq(graphqlEndpoint())} -H 'Content-Type: application/json' --data-raw ${shq(body)}`;
  };
  const row = h(
    'div',
    { class: `row link api m-${m}` },
    head(
      h('span', { class: `method gql m-${m}`, title: method.toLowerCase() }, GQL_LABEL[method] || method),
      h('span', { class: 'value mono', title: f.meta?.fields || '' }, f.meta.path),
      f.meta?.fields ? h('span', { class: 'gql-fields mono' }, `{ ${truncate(f.meta.fields, 60)} }`) : null,
      chips(f.tags),
      h('span', { class: 'spacer' }),
      srcSummary(f),
      f.meta?.document ? btn('curl', 'Copy as curl command (POST to the GraphQL endpoint)', () => copy(curl(), 'curl command copied')) : null,
      btn('Copy', 'Copy the operation', () => copy(f.meta?.document || f.value)),
    ),
  );
  return expandable(row, f.key, () => detailFor(f));
}

function apiRow(f) {
  if (f.meta?.graphql) return graphqlRow(f);
  const { method, path } = apiParts(f);
  const abs = resolveUrl(path);
  const shown = ui.absolute ? abs : path;
  const canCurl = isHttp(abs) && !abs.includes('${');
  const fields = bodyFields(f.meta);
  const m = method.toLowerCase();
  const row = h(
    'div',
    { class: `row link api m-${m}` },
    head(
      h('span', { class: `method m-${m}` }, method),
      h('span', { class: 'value mono', title: shown }, shown),
      fields.length ? h('span', { class: 'gql-fields mono', title: `Body (${f.meta?.encoding || 'json'}): ${fields.join(', ')}` }, `{ ${truncate(fields.join(', '), 60)} }`) : null,
      chips(f.tags),
      method === 'GET' ? probeChip(abs) : null,
      h('span', { class: 'spacer' }),
      srcSummary(f),
      canCurl ? btn('curl', fields.length ? 'Copy as curl command, with the request body the page sends' : 'Copy as curl command', () => copy(curlFor(method, abs, f.meta), 'curl command copied')) : null,
      btn('Copy', 'Copy "METHOD URL"', () => copy(`${method} ${shown}`)),
    ),
  );
  return expandable(row, f.key, () => detailFor(f));
}

function routeRow(f) {
  const openUrl = /^\//.test(f.value) && !/[:*]/.test(f.value) ? resolveUrl(f.value) : null;
  const sub = f.meta?.component || f.meta?.name || (f.meta?.module ? `→ ${f.meta.module}` : f.meta?.redirectTo ? `→ ${f.meta.redirectTo}` : '');
  const row = h(
    'div',
    { class: `row link${f.tags?.includes('guarded') ? ' sev-low' : ''}` },
    head(
      h('span', { class: 'value mono', title: f.value }, f.value),
      sub ? h('span', { class: 'src mono', title: f.meta?.guard ? `guard: ${f.meta.guard}` : '' }, sub) : null,
      chips(f.tags),
      openUrl ? probeChip(openUrl) : null,
      h('span', { class: 'spacer' }),
      srcSummary(f),
      openUrl && isHttp(openUrl) ? btn('Open', openUrl, () => chrome.tabs.create({ url: openUrl, active: false })) : null,
      btn('Copy', 'Copy the route path', () => copy(f.value)),
    ),
  );
  return expandable(row, f.key, () => detailFor(f));
}

const DEP_STATUS = { 'on-npm': 'on npm', 'not-on-npm': 'NOT on npm', 'scope-unclaimed': 'scope unclaimed', 'private-scope': 'private scope', unpublished: 'unpublished', unverified: 'unverified' };

/** A library version (retire.js data): advisories, fix version, and where the version was found. */
function libRow(f) {
  const n = f.meta?.advisories || 0;
  const row = h(
    'div',
    { class: `row link sev-${f.severity}` },
    head(
      h('span', { class: `pill ${f.severity}` }, f.severity),
      h('span', { class: 'value mono', title: f.value }, f.value),
      n
        ? h('span', { class: 'chip vulnerable', title: f.meta.ids || '' }, `${n} advisor${n === 1 ? 'y' : 'ies'}`)
        : h('span', { class: 'chip library', title: CHIP_TITLES.library }, 'no known vulns'),
      n && f.meta['fixed in']
        ? h('span', { class: 'src', title: f.meta.eol ? 'Some advisories cover every release of this line: no version of it fixes them' : 'Upgrading to this version fixes every listed advisory' }, f.meta.eol ? 'end of life, no fix' : `fixed in ${f.meta['fixed in']}`)
        : null,
      h('span', { class: 'spacer' }),
      srcSummary(f),
      btn('Copy', 'Copy "library version"', () => copy(f.value)),
    ),
  );
  return expandable(row, f.key, () => libDetail(f));
}

const SINK_LIBS = { jquery: /jquery/, DOMPurify: /./, angularjs: /angular|template/i, handlebars: /template|handlebars/i };

function libDetail(f) {
  const d = detailFor(f);
  const vulns = f.meta?.vulns || [];
  if (vulns.length) {
    const list = h('div', { class: 'advisories' });
    for (const [ids, sev, summary, range, link] of vulns) {
      list.append(
        h(
          'div',
          { class: 'advisory' },
          h('span', { class: `pill ${sev}` }, sev),
          h('div', { class: 'advisory-body' }, h('div', {}, summary || ids || 'Advisory'), h('div', { class: 'muted small mono' }, [ids, range].filter(Boolean).join(' · '))),
          isHttp(link) ? h('a', { class: 'mini-link', href: link, target: '_blank', rel: 'noreferrer', title: link }, 'details') : null,
        ),
      );
    }
    d.insertBefore(list, d.querySelector(':scope > .source') || null);
  }
  // tainted sinks on the same host make an outdated sanitiser / templating / DOM library more interesting
  const lib = f.meta?.library;
  const re = SINK_LIBS[lib];
  const sinks = re ? (ui.model?.sinks || []).filter((s) => s.tags?.includes('tainted') || /taint/.test(s.rule || '')).filter((s) => re.test(s.rule + ' ' + s.label)) : [];
  if (vulns.length && sinks.length) d.prepend(h('div', { class: 'desc' }, `The Sinks tab has ${sinks.length} tainted flow${sinks.length === 1 ? '' : 's'} on this host that may reach ${lib}: start there.`));
  d.append(h('div', { class: 'muted small' }, `Advisory data: retire.js repository, ${VULNDB_DATE}.`));
  return d;
}

function depRow(f) {
  if (f.meta?.kind === 'library') return libRow(f);
  const tag = f.tags?.[0] || 'unverified';
  const row = h(
    'div',
    { class: `row link sev-${f.severity}` },
    head(
      h('span', { class: `pill ${f.severity}` }, f.severity),
      h('span', { class: 'value mono', title: f.label }, f.value),
      h('span', { class: `chip dep ${tag}`, title: f.label }, DEP_STATUS[tag] || tag),
      f.meta?.latest ? h('span', { class: 'src' }, 'v' + f.meta.latest) : null,
      h('span', { class: 'spacer' }),
      h('span', { class: 'src', title: 'Evidence' }, (f.meta?.evidence || []).join(', ')),
      btn('npm', 'Open on npmjs.com', () => chrome.tabs.create({ url: 'https://www.npmjs.com/package/' + f.value, active: false })),
      btn('Copy', 'Copy package name', () => copy(f.value)),
    ),
  );
  return expandable(row, f.key, () => detailFor(f));
}

/** A feature flag: its key, the SDK, the state delivered to the page and / or the default in the code. */
function flagRow(f) {
  const st = f.meta?.state;
  const def = f.meta?.default;
  const stateText = st != null && st !== 'listed' ? `= ${truncate(st, 24)}` : def != null ? `default ${truncate(def, 20)}` : '';
  const row = h(
    'div',
    { class: `row link${f.tags?.includes('off') ? ' sev-low' : ''}` },
    head(
      h('span', { class: 'value mono', title: f.value }, f.value),
      stateText ? h('span', { class: 'src mono flag-state', title: st != null ? 'Value delivered to this page' : 'Fallback value in the code' }, stateText) : null,
      chips(f.tags),
      h('span', { class: 'spacer' }),
      srcSummary(f),
      btn('Copy', 'Copy the flag key', () => copy(f.value)),
    ),
  );
  return expandable(row, f.key, () => detailFor(f));
}

const VALUE_TITLE = { high: 'High-value target', medium: 'Worth a look' };

function domainRow(d) {
  const r = d.rating;
  const c = d.check;
  const openUrl = `${c?.scheme || c?.seen?.scheme || 'https'}://${d.value}`;
  const row = h(
    'div',
    { class: `row link${r?.level === 'high' ? ' sev-high' : ''}${d.scope === 'out' || (d.scope === 'unlisted' && d.tags.includes('same-site')) ? ' oos' : ''}` },
    head(
      r?.level ? h('span', { class: `pill ${r.level}`, title: `${VALUE_TITLE[r.level]}:\n${r.reasons.join('\n')}` }, r.level) : null,
      h('span', { class: 'value mono', title: d.value }, d.value),
      hostChip(d),
      c?.title && !r?.wildcard ? h('span', { class: 'src host-title', title: c.title }, truncate(c.title, 48)) : null,
      chips(d.tags),
      h('span', { class: 'spacer' }),
      h('span', { class: 'src' }, `${d.count}×`),
      d.value.includes('*') ? null : btn('Open', openUrl, () => chrome.tabs.create({ url: openUrl, active: false })),
      btn('Copy', 'Copy', () => copy(d.value)),
    ),
  );
  return expandable(row, d.key, () => domainDetail(d));
}

/** Status of a subdomain: our check (GET /) or, failing that, what the page loaded from it. */
function hostChip(d) {
  const c = d.check;
  if (!c || d.rating?.wildcard) return null;
  if (c.pending && !c.seen) return h('span', { class: 'chip probe pending', title: 'Checking…' }, '…');
  const s = c.status || c.seen?.status || 0;
  if (!s) return h('span', { class: 'chip probe gone', title: c.error === 'timeout' ? 'Timed out' : 'No HTTP(S) answer: no DNS record, connection refused or a TLS error' }, 'dead');
  const via = c.status ? `GET ${c.scheme || 'https'}://${d.value}/` : 'loaded by the page';
  const title = [`${s} · ${via}`, c.url ? `→ ${c.url}` : '', c.server ? `server: ${c.server}` : ''].filter(Boolean).join('\n');
  return h('span', { class: `chip probe ${statusClass(s)}`, title }, String(s) + (c.url ? ' →' : ''));
}

const TAKEOVER_DESC = (host, svc) =>
  `${host} answers with the page ${svc} shows for a site / bucket that no longer exists. If its DNS CNAME still points at ${svc}, anyone could claim that resource and serve content on this subdomain (subdomain takeover). Confirm with: dig CNAME ${host.replace(/:\d+$/, '')}`;

function domainDetail(d) {
  const c = d.check || {};
  const meta = {};
  if (d.rating?.reasons?.length) meta.why = d.rating.reasons;
  if (c.status != null && !c.pending) meta.status = c.status ? `${c.status} (${c.scheme || 'https'})` : c.error || 'no response';
  if (c.seen) meta['loaded by the page'] = `${c.seen.status} (${c.seen.type})`;
  Object.assign(meta, { 'final URL': c.url, title: c.title, product: c.product, server: c.server, 'x-powered-by': c.poweredBy, 'content-type': c.type });
  if (c.at && c.status != null && !c.pending) meta.checked = new Date(c.at).toLocaleString();
  if (d.scope) meta['program scope'] = { in: 'in scope', out: 'out of scope', unlisted: 'not listed (treated as out of scope)' }[d.scope];
  let desc = null;
  const wildName = (ui.data?.program ? ui.data.wildcards?.[siteOf(d.value.replace(/:\d+$/, ''))] : ui.data?.hostWildcard)?.name;
  if (d.rating?.wildcard) desc = `A made-up subdomain (${wildName}) answers the same way, so DNS has a wildcard record: this name is probably not a real host.`;
  else if (c.takeover) desc = TAKEOVER_DESC(d.value, c.takeover);
  return detailFor({ ...d, meta, desc });
}

function paramRow(p) {
  const row = h(
    'div',
    { class: 'row link' },
    head(h('span', { class: 'value mono' }, p.value), chips(p.tags), h('span', { class: 'spacer' }), h('span', { class: 'src' }, `${p.count}×`), btn('Copy', 'Copy', () => copy(p.value))),
  );
  return expandable(row, p.key, () => detailFor(p));
}

const KIND_LABEL = { script: 'script', crawled: 'crawled', chunk: 'chunk', manual: 'manual', inline: 'inline', html: 'DOM', sourcemap: 'map', headers: 'headers', observed: 'traffic', runtime: 'runtime', wayback: 'wayback', ct: 'crt.sh', license: 'licenses' };

async function downloadSources(f) {
  toast('Rebuilding sources…');
  try {
    const { blob, files } = await sourcesZip(ui.host, f, { nodeModules: false });
    downloadBlob(`jsrecon-sources-${safeName(ui.host)}-${safeName(fileName(f.url))}.zip`, blob);
    toast(`${files} source files`);
  } catch (e) {
    toast(String(e.message || e));
  }
}

function fileRow(f) {
  const name = f.label || f.url;
  const status =
    f.status === 'error' ? h('span', { class: 'chip error', title: f.error }, truncate(f.error || 'error', 40))
    : f.status === 'dup' ? h('span', { class: 'chip noise', title: 'Same content as ' + f.dupOf }, 'duplicate')
    : f.status === 'scanning' ? h('span', { class: 'chip' }, 'scanning…')
    : null;
  const isMap = f.kind === 'sourcemap' && f.status === 'done';
  const row = h(
    'div',
    { class: 'row link' },
    head(
      h('span', { class: 'pill kind' }, KIND_LABEL[f.kind] || f.kind),
      isHttp(f.url) ? h('a', { class: 'value mono', href: f.url, target: '_blank', rel: 'noreferrer', title: f.url }, name) : h('span', { class: 'value mono', title: name }, name),
      f.probed ? h('span', { class: 'chip interesting', title: 'Found by guessing the .map location' }, 'guessed') : null,
      status,
      h('span', { class: 'spacer' }),
      isMap && f.sourcesTotal != null ? h('span', { class: 'src' }, `${f.sourcesTotal} sources`) : null,
      f.size != null ? h('span', { class: 'src' }, formatBytes(f.size)) : null,
      f.count != null ? h('span', { class: 'src', title: 'Findings in this file' }, `${f.count} hits`) : null,
      canRebuild(f) ? btn('Sources .zip', 'Rebuild the original source tree from this map', () => downloadSources(f)) : null,
    ),
  );
  if (isMap && f.sources?.length) {
    return expandable(row, 'file|' + f.url, () =>
      h(
        'div',
        { class: 'detail' },
        h('div', { class: 'muted small' }, `${f.sourcesTotal} original files, ${f.withContent} with embedded source, ${f.scanned} scanned`),
        h('div', { class: 'examples' }, f.sources.map((s) => h('div', { class: 'mono' }, s))),
        h('div', { class: 'panel-row' }, btn('Copy paths', 'Copy all source paths', () => copy(f.sources.join('\n'))), canRebuild(f) ? btn('Download sources .zip', '', () => downloadSources(f)) : null),
      ),
    );
  }
  return row;
}

const ROW = {
  secrets: findingRow,
  api: apiRow,
  intel: compactFindingRow,
  cloud: compactFindingRow,
  sinks: compactFindingRow,
  flags: flagRow,
  deps: depRow,
  endpoints: linkRow,
  urls: linkRow,
  domains: domainRow,
  params: paramRow,
  routes: routeRow,
  files: fileRow,
};
const GROUPED = new Set(['intel', 'cloud', 'sinks', 'params']);

const EMPTY = {
  secrets: 'No secrets found (yet). Keep browsing the app — lazy-loaded chunks are scanned as they load.',
  api: 'No API calls with an HTTP method found yet (fetch, axios, $.ajax, XHR …).',
  endpoints: 'No endpoints found.',
  urls: 'No URLs found.',
  domains: 'No domains or subdomains found.',
  cloud: 'No cloud assets found.',
  params: 'No parameters found.',
  deps: 'No dependencies found. npm package names come from source maps, node_modules paths, imports and package.json blobs; library versions (checked against known advisories) from banners, version strings, script URLs and .LICENSE.txt files.',
  intel: 'Nothing here yet.',
  sinks: 'No tainted DOM sinks found. Taint flows (a URL source reaching innerHTML / eval / navigation) run by default; the broader single-pattern sink rules can be enabled in Settings.',
  routes: 'No client-side routes found (React Router, Vue Router, Angular …).',
  flags: 'No feature flags found (LaunchDarkly, GrowthBook, Unleash, Optimizely, Flagsmith, Statsig, Split, ConfigCat, PostHog or features: { … } config objects).',
  files: 'No files scanned yet.',
};

// 1234 → "1.2k" so the tab strip stays compact; the exact number is in the tooltip
const shortCount = (n) => (n < 1000 ? String(n) : n < 10000 ? (n / 1000).toFixed(1).replace(/\.0$/, '') + 'k' : Math.round(n / 1000) + 'k');

// The tab strip scrolls horizontally when it is wider than the window: the mouse wheel scrolls it,
// arrow buttons appear over faded edges, and the active tab is kept in view.
let tabsShownFor = null;
function updateTabScroll() {
  const nav = $('#tabs');
  const max = nav.scrollWidth - nav.clientWidth;
  const bar = $('#tabsBar');
  bar.classList.toggle('can-left', nav.scrollLeft > 1);
  bar.classList.toggle('can-right', nav.scrollLeft < max - 1);
}

function revealActiveTab(smooth) {
  const nav = $('#tabs');
  const tab = nav.querySelector('.tab.active');
  if (!tab || nav.scrollWidth <= nav.clientWidth) return;
  const edge = 40; // room for the arrow button and fade
  let left = nav.scrollLeft;
  if (tab.offsetLeft - edge < left) left = tab.offsetLeft - edge;
  else if (tab.offsetLeft + tab.offsetWidth + edge > left + nav.clientWidth) left = tab.offsetLeft + tab.offsetWidth + edge - nav.clientWidth;
  if (left !== nav.scrollLeft) nav.scrollTo({ left: Math.max(0, left), behavior: smooth ? 'smooth' : 'instant' });
}

function bindTabScroll() {
  const nav = $('#tabs');
  nav.addEventListener(
    'wheel',
    (e) => {
      if (nav.scrollWidth <= nav.clientWidth || Math.abs(e.deltaX) > Math.abs(e.deltaY)) return;
      e.preventDefault();
      nav.scrollLeft += e.deltaY;
    },
    { passive: false },
  );
  nav.addEventListener('scroll', updateTabScroll, { passive: true });
  new ResizeObserver(() => (updateTabScroll(), revealActiveTab(false))).observe(nav);
  for (const b of document.querySelectorAll('.tab-scroll')) {
    b.addEventListener('click', () => nav.scrollBy({ left: Number(b.dataset.dir) * Math.round(nav.clientWidth * 0.6), behavior: 'smooth' }));
  }
}

function renderTabs() {
  const nav = $('#tabs');
  const scrollLeft = nav.scrollLeft;
  nav.replaceChildren();
  for (const t of TABS) {
    const items = (ui.model[t.id] || []).filter((f) => triagePass(f, t.id)); // "To review" counts what's left
    const n = items.length;
    if (t.optional && !n && ui.tab !== t.id) continue;
    let cls = n ? 'count' : 'count zero';
    if (t.id === 'secrets' || t.id === 'deps' || t.id === 'cloud' || t.id === 'sinks') {
      if (items.some((f) => f.severity === 'critical')) cls += ' crit';
      else if (items.some((f) => f.severity === 'high')) cls += ' hot';
      else if (items.some((f) => f.severity === 'medium')) cls += ' warm';
    }
    nav.append(
      h(
        'button',
        {
          class: `tab${ui.tab === t.id ? ' active' : ''}`,
          onclick: () => {
            ui.tab = t.id;
            ui.limit = 400;
            store.set('tab', t.id);
            render();
          },
        },
        t.label,
        h('span', { class: cls, title: n >= 1000 ? `${n}` : null }, shortCount(n)),
      ),
    );
  }
  nav.scrollLeft = scrollLeft;
  // bring the active tab into view when it changes (not on every live re-render, which would fight the user)
  if (tabsShownFor !== ui.tab) {
    revealActiveTab(tabsShownFor !== null);
    tabsShownFor = ui.tab;
  }
  updateTabScroll();
}

function renderToolbar() {
  const t = ui.tab;
  $('#sevFilter').hidden = !SEV_TABS.has(t);
  $('#tentativeWrap').hidden = t !== 'secrets';
  $('#noiseWrap').hidden = !NOISE_TABS.has(t);
  $('#interestingWrap').hidden = !INTERESTING_TABS.has(t);
  $('#absWrap').hidden = t !== 'endpoints' && t !== 'api';
  $('#liveWrap').hidden = t !== 'domains';
  $('#inScopeWrap').hidden = t !== 'domains' || !scoped();
  $('#newWrap').hidden = !ui.data?.changes?.length || t === 'files';
  $('#triageFilter').hidden = t === 'files';
  $('#triageFilter').value = ui.triage;
}

// ── bulk triage: two clicks mark every row shown (or clear their status when a status is filtered) ──

let triageArmed = 0;
function renderTriageButton() {
  const b = $('#btnTriage');
  const n = ui.tab === 'files' ? 0 : ui.visible.length;
  b.hidden = !n;
  if (!n) return;
  const clearing = ui.triage !== 'all' && ui.triage !== 'todo';
  const armed = Date.now() - triageArmed < 6000;
  b.classList.toggle('primary', armed);
  // the popup shows this button as an icon; only the armed state gets a (short) label there
  b.querySelector('.lbl').textContent = armed ? `${clearing ? 'Clear' : 'Mark'} ${n}?${FULL ? ' Click again' : ''}` : clearing ? 'Clear status' : 'Mark reviewed';
  b.title = clearing ? `Clear the status of the ${n} rows shown` : `Mark the ${n} rows shown as reviewed (two clicks)`;
}

async function bulkTriage() {
  const items = ui.tab === 'files' ? [] : [...ui.visible];
  if (!items.length) return;
  if (Date.now() - triageArmed > 6000) {
    triageArmed = Date.now();
    renderTriageButton();
    setTimeout(() => {
      if (triageArmed && Date.now() - triageArmed >= 6000) renderTriageButton();
    }, 6100);
    return;
  }
  triageArmed = 0;
  const clearing = ui.triage !== 'all' && ui.triage !== 'todo';
  await setTriage(items, clearing ? null : 'reviewed');
  toast(`${clearing ? 'Cleared' : 'Marked'} ${items.length} row${items.length === 1 ? '' : 's'}${clearing ? '' : ' reviewed'}`);
}

/** "Changed 2 h ago: main.4f2a.js → main.9b8c.js · 12 new" with a button for the New filter. */
function renderChangeBanner() {
  const el = $('#changeBanner');
  const c = ui.data?.changes?.[0];
  if (!c || Date.now() - c.at > 14 * 86400000) {
    el.hidden = true;
    return;
  }
  const mins = Math.round((Date.now() - c.at) / 60000);
  const ago = mins < 60 ? `${mins} min ago` : mins < 2880 ? `${Math.round(mins / 60)} h ago` : `${Math.round(mins / 1440)} days ago`;
  const name = (u) => {
    try {
      return new URL(u).pathname.split('/').pop();
    } catch {
      return u;
    }
  };
  el.replaceChildren(
    h('span', {}, h('b', {}, 'Bundle changed '), `${ago}: `, h('span', { class: 'mono' }, `${name(c.from)} → ${name(c.to)}`), ` · ${c.added.length} new finding${c.added.length === 1 ? '' : 's'}`),
    h('span', { class: 'spacer' }),
    c.added.length
      ? btn(ui.onlyNew ? 'Show all' : 'Show new', 'Only findings that first appeared in the new version', () => {
          ui.onlyNew = !ui.onlyNew;
          $('#onlyNew').checked = ui.onlyNew;
          render();
        })
      : null,
  );
  el.hidden = false;
}

// ── program scope: is the host shown in scope? ──

const SCOPE_CHIP = {
  in: ['in scope', 'scope-in', 'Listed in the program scope: active checks may be sent to it'],
  out: ['out of scope', 'scope-out', 'Excluded by the program scope: active checks are never sent to it'],
  unlisted: ['not in scope', 'scope-unlisted', 'Not listed in the program scope: treated as out of scope for active checks'],
};

/** 'in' / 'out' / 'unlisted' for the host shown, or null (no scope set, or the program view). */
const shownScope = () => (scoped() && ui.host && !isProgram() ? hostScope(ui.scope, ui.host) : null);

function renderScopeChip() {
  const el = $('#scopeChip');
  const st = shownScope();
  // in scope is the normal case: a green status dot says it; out of scope / not listed get a chip
  $('#status').classList.toggle('in-scope', st === 'in');
  el.hidden = !st || st === 'in';
  if (el.hidden) return;
  const [text, cls, title] = SCOPE_CHIP[st];
  el.className = `chip ${cls}`;
  el.textContent = text;
  el.title = `${title} (Settings → Program scope)`;
}

// ── "Ask first": the site in this tab waits for the user's OK before anything is scanned ──

async function refreshAsk() {
  ui.ask = null;
  if (FULL || ui.tabId == null || !ui.tabUrl) return;
  try {
    const r = await chrome.runtime.sendMessage({ type: 'scope', tabId: ui.tabId, url: ui.tabUrl });
    if (r?.state === 'ask') ui.ask = r;
  } catch {
    /* worker starting */
  }
}

const askingHere = () => !!ui.ask && ui.host === ui.tabHost;

/** The three answers; `kind` 'btn' for the full-size empty-state card, 'mini' for the banner. */
function askButtons(kind) {
  const name = ui.ask.hostname;
  const make = (label, title, choice, primary) =>
    kind === 'btn' ? h('button', { class: `btn${primary ? ' primary' : ''}`, title, onclick: () => decide(choice) }, label) : btn(label, title, () => decide(choice), primary ? 'primary' : '');
  return [
    make('Scan this tab', `Scan ${name} in this tab while it stays on the site. Other tabs and later visits ask again.`, 'tab', true),
    make('Always scan this site', `Add ${name} to the allow-list (Settings → Scope) and scan it in every tab without asking`, 'always'),
    make('Never for this site', `Add ${name} to the deny-list (Settings → Scope)`, 'never'),
  ];
}

/** "in scope" / "out of scope" for the site waiting for an OK, when a program scope is set. */
function askScopeChip() {
  const st = ui.ask?.program;
  if (!st) return null;
  const [text, cls, title] = SCOPE_CHIP[st];
  return h('span', { class: `chip ${cls}`, title }, text);
}

function renderAskBanner() {
  const el = $('#askBanner');
  const show = askingHere() && !!ui.data;
  el.hidden = !show;
  if (show) {
    el.replaceChildren(
      h('span', {}, h('b', {}, `Not scanning ${ui.ask.host} in this tab.`), ' Findings below are from an earlier scan.'),
      askScopeChip(),
      h('span', { class: 'spacer' }),
      ...askButtons('mini'),
    );
  }
}

async function decide(choice) {
  const host = ui.ask?.host || ui.tabHost;
  let r = null;
  try {
    r = await chrome.runtime.sendMessage({ type: 'approve', tabId: ui.tabId, url: ui.tabUrl, choice });
  } catch {
    /* worker starting */
  }
  if (!r?.ok) return toast(r?.error || 'Could not reach the extension, try again');
  ui.ask = null;
  toast(choice === 'never' ? `Won't scan ${host} (undo in Settings → Scope)` : choice === 'always' ? `Scanning ${host} (added to the allow-list)` : `Scanning ${host} in this tab`);
  render();
  pollStatus();
}

function emptyState(title, text) {
  return h('div', { class: 'empty' }, h('div', { class: 'empty-mark' }, '{ }'), title ? h('b', {}, title) : null, text ? h('p', {}, text) : null);
}

function render() {
  if (!ui.model) ui.model = buildModel(ui.data);
  renderTabs();
  renderToolbar();
  renderChangeBanner();
  renderAskBanner();
  renderDomainBar();
  renderScopeChip();
  const list = $('#list');
  const scroll = list.scrollTop;
  list.replaceChildren();
  ui.visible = [];
  ui.itemsByKey = new Map();
  renderTriageButton();

  if (!ui.host) {
    list.append(emptyState('No website in this tab', 'Open a site to scan it, or pick a previously scanned host above.'));
    $('#count').textContent = '';
    return;
  }
  if (!ui.data) {
    if (isProgram()) {
      list.append(emptyState('No in-scope host scanned yet', 'Browse the program\'s sites: every scanned host that Settings → Program scope covers is merged here.'));
      $('#count').textContent = '';
      return;
    }
    if (askingHere()) {
      const card = emptyState(`Scan ${ui.ask.host}?`, 'JS Recon asks before scanning a site. Nothing has been fetched from it yet.');
      const sc = askScopeChip();
      if (sc) card.append(sc);
      card.append(h('div', { class: 'ask-actions' }, ...askButtons('btn')));
      list.append(card);
    } else list.append(emptyState(`Nothing scanned for ${ui.host} yet`, 'Reload the page or press Rescan. Scripts are captured as the page loads them.'));
    $('#count').textContent = '';
    return;
  }

  const items = filtered(ui.tab);
  ui.visible = items;
  if (ui.tab !== 'files') for (const f of items) if (f.key) ui.itemsByKey.set(f.key, f);
  renderTriageButton();
  const total = (ui.model[ui.tab] || []).length;
  $('#count').textContent = items.length === total ? `${total}` : `${items.length} / ${total}`;
  if (!items.length) {
    const allDone = total && ui.triage === 'todo' && (ui.model[ui.tab] || []).every((f) => f.triage);
    list.append(
      allDone ? emptyState('All reviewed', 'Every row in this tab has a status. Set Status to “Any status” to see them again.')
      : total ? emptyState('No matches', 'Nothing matches the current filters.')
      : emptyState(null, EMPTY[ui.tab]),
    );
    return;
  }
  const make = ROW[ui.tab];
  const frag = document.createDocumentFragment();
  let last = null;
  for (const f of items.slice(0, ui.limit)) {
    if (GROUPED.has(ui.tab) && f.label !== last) frag.append(h('div', { class: 'group' }, f.label));
    last = f.label;
    const row = make(f);
    frag.append(ui.tab === 'files' ? row : decorateTriage(row, f));
  }
  if (items.length > ui.limit) {
    frag.append(h('button', { class: 'btn more', onclick: () => ((ui.limit = Infinity), render()) }, `Show all ${items.length} (${items.length - ui.limit} more)`));
  }
  list.append(frag);
  list.scrollTop = scroll;
}

let renderTimer = null;
/** True while the user types a note: re-rendering would throw the field (and the text) away. */
const editingNote = () => document.activeElement?.classList?.contains('note-input');

function scheduleRender() {
  clearTimeout(renderTimer);
  renderTimer = setTimeout(() => {
    if (editingNote()) return scheduleRender();
    ui.model = buildModel(ui.data);
    render();
  }, 250);
}

// ───────────────────────── header ─────────────────────────

function renderHostSelect() {
  const sel = $('#hostSelect');
  const hosts = Object.entries(ui.index).sort((a, b) => (b[1].updated || 0) - (a[1].updated || 0));
  for (const o of [...sel.options]) o.remove(); // keep the <button><selectedcontent> used by customizable selects
  const label = (host, s) => {
    const sec = s ? (s.critical || 0) + (s.high || 0) + (s.medium || 0) : 0;
    return sec ? `${host}  ·  ${sec} finding${sec > 1 ? 's' : ''}` : host;
  };
  // with a program scope: one entry that merges every scanned in-scope host
  const inScope = scoped() ? hosts.filter(([host]) => hostScope(ui.scope, host) === 'in').length : 0;
  if (inScope || isProgram()) sel.append(h('option', { value: PROGRAM }, `All in-scope hosts (${inScope})`));
  if (ui.tabHost && !ui.index[ui.tabHost]) sel.append(h('option', { value: ui.tabHost }, `${ui.tabHost} (current tab)`));
  if (ui.host && ui.host !== ui.tabHost && !ui.index[ui.host]) sel.append(h('option', { value: ui.host }, ui.host));
  for (const [host, s] of hosts) sel.append(h('option', { value: host }, label(host, s)));
  if (!sel.options.length) sel.append(h('option', { value: '' }, 'No hosts scanned yet'));
  sel.value = ui.host || '';
  renderDumpHosts();
}

/** Every scanned host the program scope covers, merged (see ui/program.js). */
async function loadProgram() {
  const all = await chrome.storage.local.get(null);
  const list = Object.keys(all)
    .filter((k) => k.startsWith('host:') && hostScope(ui.scope, k.slice(5)) === 'in')
    .map((k) => ({ host: k.slice(5), data: all[k] }));
  return list.length ? mergeHosts(list) : null;
}

async function loadHost(host) {
  ui.host = host || null;
  ui.expanded.clear();
  ui.limit = 400;
  if (host === PROGRAM) ui.data = await loadProgram();
  else if (host) {
    const r = await chrome.storage.local.get('host:' + host);
    ui.data = r['host:' + host] || null;
  } else ui.data = null;
  ui.model = buildModel(ui.data);
  document.body.classList.toggle('program', isProgram());
  if (FULL) {
    const u = new URL(location.href);
    if (host) u.searchParams.set('host', host);
    history.replaceState(null, '', u);
    document.title = isProgram() ? 'JS Recon — all in-scope hosts' : host ? `JS Recon — ${host}` : 'JS Recon';
    $('#manualHost').placeholder = isProgram() ? '(derived from URL)' : host || '(derived from URL)';
  }
  render();
  pollStatus();
}

/** Per-host actions (rescan, live checks, crt.sh, Wayback …) need one host, not the merged view. */
function needsOneHost() {
  if (!isProgram()) return false;
  toast('Pick a single host for this: the program view merges several');
  return true;
}

let programTimer = null;
function scheduleProgramReload() {
  clearTimeout(programTimer);
  programTimer = setTimeout(async () => {
    if (!isProgram()) return;
    if (editingNote()) return scheduleProgramReload();
    ui.data = await loadProgram();
    ui.model = buildModel(ui.data);
    render();
  }, 1200);
}

async function pollStatus() {
  let st = null;
  try {
    st = await chrome.runtime.sendMessage({ type: 'status', host: ui.host });
  } catch {
    /* worker starting */
  }
  const el = $('#status');
  el.classList.toggle('in-scope', shownScope() === 'in');
  if (isProgram()) {
    el.classList.remove('busy');
    el.textContent = ui.data ? `${ui.data.hosts.length} hosts · ${Object.keys(ui.data.files).length} files` : 'No in-scope host scanned yet';
  } else if (st?.pending) {
    el.classList.add('busy');
    el.textContent = `Scanning · ${st.pending} queued`;
  } else if (ui.data) {
    el.classList.remove('busy');
    const s = Math.round((Date.now() - (ui.data.updated || Date.now())) / 1000);
    el.textContent = `${Object.keys(ui.data.files).length} files · ${s < 60 ? s + 's' : Math.round(s / 60) + 'm'} ago`;
  } else el.textContent = '';
  el.title = el.textContent + (el.classList.contains('in-scope') ? ' · in the program scope' : '');
}

function renderPause() {
  const on = ui.settings?.enabled !== false;
  const b = $('#btnPause');
  b.classList.toggle('paused', !on);
  b.classList.toggle('warn', !on);
  b.title = on ? 'Pause passive scanning' : 'Resume passive scanning';
  $('#pausedBanner').hidden = on;
}

// ───────────────────────── dump panel ─────────────────────────

const dumpSelection = new Set(params.get('dump') ? [params.get('host')].filter(Boolean) : []);

function renderDumpHosts() {
  const box = $('#dumpHosts');
  if (!box || !FULL) return;
  box.replaceChildren();
  const hosts = Object.entries(ui.index).sort((a, b) => a[0].localeCompare(b[0]));
  if (!hosts.length) box.append(h('div', { class: 'muted' }, 'No hosts scanned yet.'));
  for (const [host, s] of hosts) {
    const cb = h('input', { type: 'checkbox', checked: dumpSelection.has(host) });
    cb.addEventListener('change', () => (cb.checked ? dumpSelection.add(host) : dumpSelection.delete(host)));
    box.append(h('label', { class: 'chk host-item' }, cb, h('span', { class: 'mono' }, host), h('span', { class: 'muted small' }, `${s.files} files`)));
  }
}

async function runDump() {
  const hosts = [...dumpSelection].filter((h) => ui.index[h]);
  if (!hosts.length) return ($('#dumpMsg').textContent = 'Select at least one host.');
  const opts = { js: $('#dumpJs').checked, maps: $('#dumpMaps').checked, sources: $('#dumpSources').checked, nodeModules: $('#dumpNodeModules').checked };
  const go = $('#btnDumpGo');
  go.disabled = true;
  try {
    const r = await dumpHosts(hosts, opts, (done, total) => ($('#dumpMsg').textContent = `Fetching ${done} / ${total}…`));
    const name = hosts.length === 1 ? `jsrecon-dump-${safeName(hosts[0])}-${stamp()}.zip` : `jsrecon-dump-${hosts.length}-hosts-${stamp()}.zip`;
    downloadBlob(name, r.blob);
    $('#dumpMsg').textContent = `${r.files} files, ${formatBytes(r.bytes)} uncompressed${r.errors ? ` · ${r.errors} failed (see _errors.txt)` : ''}`;
  } catch (e) {
    $('#dumpMsg').textContent = 'Failed: ' + (e.message || e);
  } finally {
    go.disabled = false;
  }
}

function openDump() {
  if (!FULL) {
    chrome.tabs.create({ url: chrome.runtime.getURL(`ui/popup.html?view=full&dump=1${ui.host ? '&host=' + encodeURIComponent(ui.host) : ''}`) });
    window.close();
    return;
  }
  if (ui.host && ui.index[ui.host] && !dumpSelection.size) dumpSelection.add(ui.host);
  renderDumpHosts();
  $('#dump').hidden = false;
  $('#manual').hidden = true;
  $('#searchFiles').hidden = true;
}

// ───────────────────────── content search ─────────────────────────

function openSearch() {
  if (needsOneHost()) return;
  if (!FULL) {
    chrome.tabs.create({ url: chrome.runtime.getURL(`ui/popup.html?view=full&find=1${ui.host ? '&host=' + encodeURIComponent(ui.host) : ''}`) });
    window.close();
    return;
  }
  $('#searchFiles').hidden = false;
  $('#manual').hidden = true;
  $('#dump').hidden = true;
  $('#searchQuery').focus();
}

function renderSearchResults(res, label) {
  const box = $('#searchResults');
  box.replaceChildren();
  if (!res.matches.length) {
    box.append(h('div', { class: 'muted' }, `No matches for ${label}.`));
    return;
  }
  const groups = new Map();
  for (const m of res.matches) {
    if (!groups.has(m.source)) groups.set(m.source, { url: m.url, kind: m.kind, items: [] });
    groups.get(m.source).items.push(m);
  }
  for (const [source, g] of groups) {
    const head = h(
      'div',
      { class: 'search-file' },
      h('span', { class: 'mono src' }, source),
      h('span', { class: 'muted small' }, `${g.items.length} match${g.items.length === 1 ? '' : 'es'}`),
      g.kind === 'file' && isHttp(g.url) ? btn('open', 'Open this file in a tab', () => chrome.tabs.create({ url: g.url })) : null,
    );
    const hits = g.items.map((m) =>
      h('div', { class: 'search-hit' }, h('span', { class: 'search-loc muted small' }, `${m.line}:${m.col}`), h('code', { class: 'mono' }, m.pre, h('mark', {}, m.hit), m.post)),
    );
    box.append(h('div', { class: 'search-group' }, head, ...hits));
  }
  if (res.truncated) box.append(h('div', { class: 'muted small pad' }, 'Results truncated — refine your query.'));
}

async function runSearch() {
  const raw = $('#searchQuery').value.trim();
  const msg = $('#searchMsg');
  if (!raw) return void (msg.textContent = 'Enter a string or /regex/.');
  if (!ui.host) return void (msg.textContent = 'Open a site first.');
  // /pattern/ or /pattern/i in the box is a shortcut for the Regex checkbox (the trailing i sets case-insensitive)
  let query = raw;
  let regex = $('#searchRegex').checked;
  let caseSensitive = $('#searchCase').checked;
  const slash = /^\/(.+)\/([a-z]*)$/.exec(raw);
  if (slash) {
    query = slash[1];
    regex = true;
    if (/i/.test(slash[2])) caseSensitive = false;
  }
  const opts = { regex, caseSensitive, includeNodeModules: $('#searchNodeModules').checked };
  const go = $('#btnSearchGo');
  go.disabled = true;
  $('#searchResults').replaceChildren();
  msg.textContent = 'Searching…';
  try {
    const res = await searchHost(ui.host, query, opts, (done, total) => (msg.textContent = `Searching ${done} / ${total} files…`));
    renderSearchResults(res, regex ? `/${query}/` : `“${query}”`);
    msg.textContent = `${res.matches.length}${res.truncated ? '+' : ''} match${res.matches.length === 1 ? '' : 'es'} in ${res.files} file${res.files === 1 ? '' : 's'}${res.errors ? ` · ${res.errors} unreadable` : ''}`;
  } catch (e) {
    msg.textContent = 'Failed: ' + (e.message || e);
  } finally {
    go.disabled = false;
  }
}

// ───────────────────────── exports ─────────────────────────

function exportJson(data) {
  return {
    host: data.program ? 'program' : data.host,
    ...(data.program ? { programHosts: data.hosts } : {}),
    origin: data.origin,
    updated: new Date(data.updated).toISOString(),
    files: Object.values(data.files),
    findings: Object.values(data.findings),
    chunks: Object.keys(data.chunkUrls || {}),
    hosts: data.hostChecks || {},
    wildcard: data.hostWildcard || null,
    triage: data.triage || {},
  };
}

/** "LaunchDarkly · state false · default false" for the reports. */
function flagSummary(f) {
  const m = f.meta || {};
  return [m.provider, m.state != null && m.state !== 'listed' ? `state ${m.state}` : null, m.default != null ? `default ${m.default}` : null].filter(Boolean).join(' · ');
}

/** Rows marked false positive stay out of the reports and SARIF. */
const reportable = (list) => list.filter((f) => f.triage !== 'fp');
const triageNote = (f) => (f.triage === 'reported' ? ' [reported]' : f.triage === 'reviewed' ? ' [reviewed]' : '') + (f.note ? ` — note: ${f.note}` : '');

/** "jquery 3.4.1 · 6 advisories · fixed in 3.5.0 · CVE-…" / npm package line, for the reports. */
function depLine(f) {
  if (f.meta?.kind !== 'library') return `${f.value}\t${f.label}${f.meta?.latest ? '\tv' + f.meta.latest : ''}`;
  const n = f.meta.advisories || 0;
  const fix = f.meta.eol ? 'end of life, no fixed release' : `fixed in ${f.meta['fixed in']}`;
  return n ? `${f.value}\t${n} advisor${n === 1 ? 'y' : 'ies'}, ${fix}${f.meta.ids ? '\t' + f.meta.ids : ''}` : `${f.value}\tno known advisories`;
}

/** Same-site subdomains with a high / medium rating, best first. */
const valuedHosts = () => ui.model.domains.filter((d) => d.rating?.level);

/** "200 https" / "dead" / "" for the reports. */
function hostStatus(d) {
  const c = d.check;
  if (!c || d.rating?.wildcard) return d.rating?.wildcard ? 'wildcard' : '';
  if (c.pending && !c.seen) return 'checking';
  const s = c.status || c.seen?.status;
  return s ? `${s}${c.url ? ' → ' + c.url : ''}` : c.status === 0 ? 'dead' : '';
}

/** https://host of every live, non-wildcard subdomain (for httpx / nuclei / aquatone). */
function liveHostUrls() {
  return ui.model.domains
    .filter((d) => d.tags.includes('live') && !d.tags.includes('wildcard'))
    .map((d) => `${d.check?.scheme || d.check?.seen?.scheme || 'https'}://${d.value}`);
}

function textReport() {
  const m = ui.model;
  const out = [`# JS Recon — ${isProgram() ? `all in-scope hosts (${ui.data.hosts.join(', ')})` : ui.host}`, `# ${new Date().toISOString()}`, ''];
  const section = (title, lines) => {
    if (!lines.length) return;
    out.push(`## ${title} (${lines.length})`, ...lines, '');
  };
  section('Secrets', reportable(m.secrets).map((f) => `[${f.severity.toUpperCase()}${f.confidence ? '/' + f.confidence : ''}] ${f.label}: ${f.value}  (${f.sources.map(srcLabel).join(', ')})${triageNote(f)}`));
  const bodyNote = (f) => (f.meta?.body ? `  {${f.meta.body}}` : '') + (f.tags?.includes('idor') ? '  [idor]' : '');
  section('API endpoints', m.api.map((f) => (f.meta?.graphql ? `${apiParts(f).method} ${apiParts(f).path} (GraphQL)` : `${apiParts(f).method} ${resolveUrl(apiParts(f).path)}${bodyNote(f)}`)));
  section('Endpoints', m.endpoints.filter((f) => !f.tags.includes('noise')).map((f) => f.value));
  section('URLs', m.urls.filter((f) => !f.tags.includes('noise')).map((f) => f.value));
  section('High-value targets', valuedHosts().map((d) => `[${d.rating.level.toUpperCase()}] ${d.value}\t${hostStatus(d)}\t${d.rating.reasons.join('; ')}`));
  section('Domains', m.domains.map((d) => `${d.value}\t${d.tags.join(',')}${hostStatus(d) ? '\t' + hostStatus(d) : ''}`));
  section('Cloud', reportable(m.cloud).map((f) => `[${f.severity}] ${f.label}: ${f.value}${triageNote(f)}`));
  section('Parameters', m.params.map((p) => (p.kind === 'query' ? p.value : `${p.value}\t(${p.kind})`)));
  section('Dependencies', reportable(m.deps).map((f) => `[${f.severity.toUpperCase()}] ${depLine(f)}${triageNote(f)}`));
  section('Intel', reportable(m.intel).map((f) => `[${f.severity}] ${f.label}: ${f.value}${triageNote(f)}`));
  section('Routes', m.routes.map((f) => `${f.value}${f.tags.length ? '\t[' + f.tags.join(',') + ']' : ''}${f.meta?.component ? '\t→ ' + f.meta.component : ''}`));
  section('Feature flags', reportable(m.flags).map((f) => `${f.value}\t${flagSummary(f)}${triageNote(f)}`));
  section('Sinks', reportable(m.sinks).map((f) => `${f.label}: ${f.value}  (${f.sources.map(srcLabel).join(', ')})${triageNote(f)}`));
  section('Lazy chunks (from the bundler runtime)', Object.keys(ui.data?.chunkUrls || {}).sort());
  section('Files', m.files.map((f) => `${f.kind}\t${f.url}${f.error ? '\t' + f.error : ''}`));
  return out.join('\n');
}

/** Markdown version of the report — pastes cleanly into tickets, PRs and wikis. */
function mdReport() {
  const m = ui.model;
  const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
  const tagsOf = (f) => (f.tags?.length ? ` _(${f.tags.join(', ')})_` : '');
  const out = [`# JS Recon — ${isProgram() ? 'all in-scope hosts' : ui.host}`, '', ...(isProgram() ? [`_Hosts: ${ui.data.hosts.join(', ')}_`, ''] : []), `_Generated ${new Date().toISOString()}_`, ''];
  const section = (title, rows) => {
    if (rows.length) out.push(`## ${title} (${rows.length})`, '', ...rows, '');
  };
  section('Secrets', reportable(m.secrets).map((f) => `- **[${f.severity}${f.confidence ? '/' + f.confidence : ''}]** ${esc(f.label)}: \`${esc(f.value)}\`${tagsOf(f)}${triageNote(f)}`));
  section('DOM-XSS sinks', reportable(m.sinks).map((f) => `- ${esc(f.label)}: \`${esc(f.value)}\`${triageNote(f)}`));
  section('API endpoints', m.api.map((f) =>
    `- \`${apiParts(f).method} ${esc(f.meta?.graphql ? apiParts(f).path + ' (GraphQL)' : resolveUrl(apiParts(f).path))}\`` +
    (f.meta?.body && !f.meta?.graphql ? ` — body: ${bodyFields(f.meta).map((n) => `\`${esc(n)}\``).join(', ')}` : '') +
    (f.tags?.includes('idor') ? ' _(idor)_' : '')));
  section('Routes', m.routes.map((f) => `- \`${esc(f.value)}\`${tagsOf(f)}`));
  section('Feature flags', reportable(m.flags).map((f) => `- \`${esc(f.value)}\` — ${esc(flagSummary(f))}${triageNote(f)}`));
  section('Cloud', reportable(m.cloud).map((f) => `- **[${f.severity}]** ${esc(f.label)}: \`${esc(f.value)}\`${triageNote(f)}`));
  section('Dependencies', reportable(m.deps).map((f) => `- **[${f.severity}]** \`${esc(f.value)}\` — ${esc(f.meta?.kind === 'library' ? depLine(f).split('\t').slice(1).join(' · ') : f.label)}${triageNote(f)}`));
  section('Intel', reportable(m.intel).map((f) => `- **[${f.severity}]** ${esc(f.label)}: ${esc(f.value)}${triageNote(f)}`));
  section('High-value targets', valuedHosts().map((d) => `- **[${d.rating.level}]** \`${esc(d.value)}\`${hostStatus(d) ? ` — ${esc(hostStatus(d))}` : ''} — ${esc(d.rating.reasons.join('; '))}`));
  section('Domains', m.domains.map((d) => `- \`${esc(d.value)}\`${hostStatus(d) ? ` ${esc(hostStatus(d))}` : ''}${tagsOf(d)}`));
  return out.join('\n');
}

/** Normalised findings (security tabs only) with resolved source locations, for the SARIF export. */
function sarifModel() {
  const m = ui.model;
  const loc = (f) =>
    (f.sources || [])
      .map((s) => ({ uri: String(s.file || '').replace(/ \[inline source map\]$/, ''), line: s.line, col: s.col }))
      .filter((l) => l.uri);
  const findings = [];
  for (const tab of ['secrets', 'sinks', 'intel', 'cloud', 'deps']) {
    for (const f of reportable(m[tab] || [])) {
      findings.push({ rule: f.rule || tab, label: f.label || tab, severity: f.severity || 'info', value: f.value, category: f.category || tab, desc: f.desc, locations: loc(f) });
    }
  }
  return { host: hostLabel(), version: chrome.runtime.getManifest().version, findings };
}

/** Endpoint + API paths of the current host (relative or absolute, noise and static files excluded). */
function endpointPaths() {
  return [
    ...ui.model.endpoints.filter((f) => !f.tags.some((t) => t === 'noise' || t === 'static')).map((f) => f.value),
    ...ui.model.api.filter((f) => !f.meta?.graphql).map((f) => apiParts(f).path),
  ];
}

/** Model for the OpenAPI / Postman exporters (src/exporters.js). */
function exportModel() {
  const m = ui.model;
  const fieldsBy = {};
  for (const p of m.params.filter((x) => x.kind === 'body')) {
    for (const ex of p.examples) if (!(fieldsBy[ex] ||= []).includes(p.value)) fieldsBy[ex].push(p.value);
  }
  const auth = m.params.filter((p) => p.kind === 'header' && /^authorization$/i.test(p.value));
  return {
    host: ui.host,
    origin: ui.data.origin,
    endpoints: m.api.filter((f) => !f.meta?.graphql).map((f) => {
      const p = apiParts(f);
      const body = [...new Set([...bodyFields(f.meta), ...(fieldsBy[`${p.method} ${p.path}`] || [])])];
      return { ...p, tags: f.tags, body, sample: f.meta?.sample, encoding: f.meta?.encoding };
    }),
    bodyFields: fieldsBy,
    headers: m.params.filter((p) => p.kind === 'header').map((p) => p.value),
    bearer: auth.length > 0 && !auth.some((p) => p.examples.some((e) => /^basic/i.test(e))),
    graphql: { endpoint: graphqlEndpoint(), operations: m.api.filter((f) => f.meta?.graphql && f.meta.document).map((f) => ({ kind: f.meta.method.toLowerCase(), name: f.meta.path, document: f.meta.document })) },
  };
}

function exportGraphql() {
  const ops = ui.model.api.filter((f) => f.meta?.graphql && f.meta.document);
  const frags = ui.model.graphql.filter((f) => f.meta?.document);
  if (!ops.length) return toast('No GraphQL operations found');
  const defs = [...ops, ...frags].map((f) => parseDefinition(f.meta.document)).filter(Boolean);
  const text = [
    `# ${hostLabel()} · GraphQL endpoint: ${graphqlEndpoint()}`,
    '',
    schemaSketch(defs),
    '# ─── Operations and fragments found in the client ───',
    '',
    ...[...ops, ...frags].map((f) => f.meta.document + '\n'),
  ].join('\n');
  download(`jsrecon-${safeName(hostLabel())}-${stamp()}.graphql`, text);
  toast(`${ops.length} operations, ${frags.length} fragments`);
}

/** Concrete GET URLs of this host (the background filters again before sending anything). */
function replayUrls() {
  const keep = (f) => !f.tags.some((t) => t === 'noise' || t === 'static' || t === 'js');
  const urls = [
    ...ui.model.endpoints.filter(keep).map((f) => f.value),
    ...ui.model.urls.filter(keep).map((f) => f.value),
    ...ui.model.api.filter((f) => !f.meta?.graphql && apiParts(f).method === 'GET').map((f) => apiParts(f).path),
  ]
    .map(resolveUrl)
    .filter(isHttp);
  return inScopeUrls(replayCandidates(urls, siteOf, ui.host));
}

/** With a program scope, only URLs it covers are sent (the worker checks again). */
function inScopeUrls(r) {
  if (!scoped()) return r;
  const urls = r.urls.filter((u) => urlScope(ui.scope, u) === 'in');
  return { urls, skipped: { ...r.skipped, scope: r.urls.length - urls.length } };
}

let replayArmed = 0;
const REPLAY_LABEL = 'Send GET URLs to proxy… ';

/** Two clicks: the first shows how many requests would be sent, the second sends them. */
async function runReplay() {
  if (needsOneHost()) return;
  if (!ui.data) return toast('Nothing to send');
  const { urls, skipped } = replayUrls();
  const item = $('#replayItem');
  if (!urls.length) {
    $('#exportMenu').open = false;
    return toast(skipped.scope ? `No in-scope GET URLs (${skipped.scope} out of scope)` : 'No concrete GET URLs for this host');
  }
  if (Date.now() - replayArmed > 6000) {
    replayArmed = Date.now();
    item.firstChild.textContent = `Send ${urls.length} GET request${urls.length > 1 ? 's' : ''}? Click again `;
    setTimeout(() => {
      if (replayArmed && Date.now() - replayArmed >= 6000) item.firstChild.textContent = REPLAY_LABEL;
    }, 6100);
    return;
  }
  replayArmed = 0;
  item.firstChild.textContent = REPLAY_LABEL;
  $('#exportMenu').open = false;
  const r = await chrome.runtime.sendMessage({ type: 'replay', host: ui.host, urls });
  if (!r?.ok) return toast(r?.error || 'Failed');
  const skip = skipped.unsafe + skipped.template;
  const oos = skipped.scope || 0;
  toast(`Sending ${r.queued} GET requests${skip ? ` · skipped ${skip} (placeholders / state-changing)` : ''}${oos ? ` · ${oos} out of scope` : ''}`);
  pollStatus();
}

const absoluteUrls = () => [...new Set(endpointPaths().map(resolveUrl).filter((u) => isHttp(u) && !u.includes('${')))].sort();

// ── endpoint liveness (opt-in, same-site) ──
function probeUrls() {
  const urls = [...absoluteUrls(), ...routePaths().map(resolveUrl)].filter(isHttp);
  return inScopeUrls(replayCandidates(urls, siteOf, ui.host));
}

let probeArmed = 0;
const PROBE_LABEL = 'Check which endpoints are live… ';

/** Two clicks, same safe same-site GET candidates as the proxy sender, but the status is recorded. */
async function runProbe() {
  if (needsOneHost()) return;
  if (!ui.data) return toast('Nothing to probe');
  const { urls, skipped } = probeUrls();
  const item = $('#probeItem');
  if (!urls.length) {
    $('#exportMenu').open = false;
    return toast(skipped.scope ? `No in-scope GET URLs (${skipped.scope} out of scope)` : 'No concrete same-site GET URLs for this host');
  }
  if (Date.now() - probeArmed > 6000) {
    probeArmed = Date.now();
    item.firstChild.textContent = `Send ${urls.length} same-site GET${urls.length > 1 ? 's' : ''} and read status? Click again `;
    setTimeout(() => {
      if (probeArmed && Date.now() - probeArmed >= 6000) item.firstChild.textContent = PROBE_LABEL;
    }, 6100);
    return;
  }
  probeArmed = 0;
  item.firstChild.textContent = PROBE_LABEL;
  $('#exportMenu').open = false;
  const r = await chrome.runtime.sendMessage({ type: 'probe', host: ui.host, urls });
  if (!r?.ok) return toast(r?.error || 'Failed');
  const skip = skipped.unsafe + skipped.template + (skipped.scope || 0) + (r.skipped?.limit || 0);
  toast(`Probing ${r.queued} same-site endpoint${r.queued === 1 ? '' : 's'}${skip ? ` · skipped ${skip}` : ''}`);
  pollStatus();
}

// ── subdomains: certificate transparency (crt.sh) and live check (opt-in, two clicks) ──

/** Same-site subdomains in the Domains tab, high-value names first (the check is capped). */
function subdomainTargets() {
  return ui.model.domains.filter((d) => d.tags.includes('same-site') && !d.value.includes('*') && (!scoped() || d.scope === 'in')).map((d) => d.value);
}

let hostsArmed = 0;
let ctBusy = false;

function renderDomainBar() {
  const el = $('#domainBar');
  const show = ui.tab === 'domains' && !!ui.data;
  el.hidden = !show;
  if (!show) return;
  const own = ui.model.domains.filter((d) => d.tags.includes('same-site') && !d.value.includes('*'));
  const n = (pred) => own.filter(pred).length;
  const live = n((d) => d.tags.includes('live'));
  const high = n((d) => d.rating?.level === 'high');
  const medium = n((d) => d.rating?.level === 'medium');
  const pending = n((d) => d.check?.pending);
  const wild = n((d) => d.tags.includes('wildcard'));
  const inScope = scoped() ? n((d) => d.scope === 'in') : null;
  const armed = Date.now() - hostsArmed < 6000;
  const total = Math.min(subdomainTargets().length, 500);
  el.replaceChildren(
    h(
      'span',
      { title: 'Subdomains of the target\'s registrable domain found in code, headers, traffic and certificate logs' },
      h('b', {}, `${own.length} subdomain${own.length === 1 ? '' : 's'}`),
      ` · ${live} live`,
      high ? ` · ${high} high value` : '',
      medium ? ` · ${medium} medium` : '',
      wild ? ` · ${wild} wildcard` : '',
      inScope != null ? ` · ${inScope} in scope` : '',
      pending ? ` · checking ${pending}…` : '',
    ),
    h('span', { class: 'spacer' }),
    btn(ctBusy ? 'Asking crt.sh…' : 'Find more (crt.sh)', `Look up subdomains in certificate-transparency logs${isProgram() ? ', for every in-scope site' : ''}. Sends the domain name to crt.sh, nothing to the target.`, runCt),
    total
      ? btn(
          armed ? `GET / on ${total} host${total === 1 ? '' : 's'}? Click again` : 'Check live…',
          `Sends one GET / (HTTPS, then HTTP, no cookies) to each subdomain of this site${scoped() ? ' that the program scope lists' : ''}, max 500, and a made-up one to detect wildcard DNS. Records status, title, server and takeover signatures. Deny-listed hosts are skipped. Active: sends requests to the target.`,
          runHostProbe,
          armed ? 'primary' : '',
        )
      : null,
  );
}

async function runCt() {
  if (!ui.host || ctBusy) return;
  // the program view asks crt.sh once per registrable site, through one scanned host of each
  const hosts = isProgram() ? siteGroups(ui.data.hosts, ui.data.hosts).map((g) => g.host) : [ui.host];
  ctBusy = true;
  renderDomainBar();
  let names = 0;
  let added = 0;
  const errors = [];
  for (const host of hosts) {
    let r = null;
    try {
      r = await chrome.runtime.sendMessage({ type: 'subdomains-ct', host });
    } catch {
      /* worker restarting */
    }
    if (r?.ok) (names += r.names || 0), (added += r.added || 0);
    else errors.push(r?.error || `crt.sh lookup failed for ${host}`);
  }
  ctBusy = false;
  renderDomainBar();
  if (errors.length === hosts.length) return toast(errors[0]);
  const sites = hosts.length > 1 ? ` for ${hosts.length - errors.length} sites` : '';
  toast((names ? `${names} names in certificate logs${sites} · ${added} new` : 'No certificates logged for this domain') + (errors.length ? ` · ${errors.length} failed` : ''));
}

/** Two clicks: the first shows how many hosts would be contacted, the second sends the requests. */
async function runHostProbe() {
  const hosts = subdomainTargets();
  if (!hosts.length) return toast(scoped() ? 'No in-scope subdomains of this site yet' : 'No subdomains of this site yet');
  if (Date.now() - hostsArmed > 6000) {
    hostsArmed = Date.now();
    renderDomainBar();
    setTimeout(() => {
      if (hostsArmed && Date.now() - hostsArmed >= 6000) renderDomainBar();
    }, 6100);
    return;
  }
  hostsArmed = 0;
  // one request per registrable site; in the program view each goes through a scanned host of that site
  const groups = isProgram() ? siteGroups(hosts, ui.data.hosts) : [{ host: ui.host, hosts }];
  let queued = 0;
  let skip = 0;
  let error = null;
  for (const g of groups) {
    let r = null;
    try {
      r = await chrome.runtime.sendMessage({ type: 'probe-hosts', host: g.host, hosts: g.hosts });
    } catch {
      /* worker restarting */
    }
    if (!r?.ok) {
      error ||= r?.error || 'Failed';
      continue;
    }
    queued += r.queued || 0;
    skip += (r.skipped?.denied || 0) + (r.skipped?.limit || 0) + (r.skipped?.scope || 0);
  }
  renderDomainBar();
  if (!queued && error) return toast(error);
  const sites = groups.length > 1 ? ` on ${groups.length} sites` : '';
  toast(`Checking ${queued} host${queued === 1 ? '' : 's'}${sites}${skip ? ` · skipped ${skip} (deny-list / scope / limit)` : ''}`);
  pollStatus();
}

const statusClass = (s) => (s >= 200 && s < 300 ? 'ok' : s === 401 || s === 403 ? 'auth' : s === 404 || s === 410 ? 'gone' : s >= 500 ? 'err' : 'other');

// status code → a short labelled chip on endpoint / API / route rows
function probeChip(absUrl) {
  if (!ui.data?.probes || !absUrl) return null;
  let key = absUrl;
  try {
    key = new URL(absUrl).href;
  } catch {
    /* use as-is */
  }
  const p = ui.data.probes[key] || ui.data.probes[absUrl];
  if (!p) return null;
  if (p.status === 'pending') return h('span', { class: 'chip probe pending', title: 'Probing…' }, '…');
  if (p.redirect) return h('span', { class: 'chip probe redir', title: 'Redirects (often to login)' }, '3xx');
  const s = p.status;
  if (!s) return h('span', { class: 'chip probe err', title: p.error || 'No response' }, 'ERR');
  const cls = statusClass(s);
  const title = s === 401 || s === 403 ? 'Exists but protected — worth testing' : s === 405 ? 'Exists (method not allowed for GET)' : s >= 200 && s < 300 ? 'Live' : '';
  return h('span', { class: `chip probe ${cls}`, title }, String(s));
}

// Concrete client-side route paths (no :params or wildcards) → a path wordlist of real SPA pages.
function routePaths() {
  return [
    ...new Set(
      ui.model.routes
        .map((f) => f.value)
        .filter((v) => v && v !== '*' && v !== '**' && !v.includes('${') && !v.includes(':') && !v.includes('*'))
        .map((v) => (v.startsWith('/') ? v : '/' + v))
        .filter((v) => v.length > 1),
    ),
  ].sort();
}

const WORDLIST_FILES = [
  ['params.txt', 'query + body + form names (Arjun, x8, ffuf, Param Miner)'],
  ['query-params.txt', 'parameters read from / sent in the URL'],
  ['body-fields.txt', 'JSON / form fields the page sends (runtime hooks)'],
  ['form-fields.txt', 'names of form inputs'],
  ['data-attributes.txt', 'data-* attributes the code reads'],
  ['headers.txt', 'custom request headers'],
  ['cookies.txt', 'cookie names'],
  ['storage-keys.txt', 'localStorage / sessionStorage keys'],
  ['paths.txt', 'endpoint and API paths'],
  ['routes.txt', 'client-side router paths (SPA pages)'],
  ['path-segments.txt', 'single path segments for directory brute force'],
  ['urls.txt', 'absolute URLs (httpx, nuclei, katana)'],
  ['subdomains.txt', 'same-site hostnames (dnsx, httpx)'],
  ['live-hosts.txt', 'subdomains that answered, as URLs (httpx, nuclei)'],
  ['high-value-hosts.txt', 'subdomains rated high / medium value, best first'],
];

/** One ZIP of plain wordlists for ffuf, Arjun, x8, Param Miner … built from everything found for this host. */
async function exportWordlists() {
  const m = ui.model;
  const uniq = (a) => [...new Set(a.filter(Boolean))].sort((x, y) => x.localeCompare(y));
  const byKind = (k) => m.params.filter((p) => p.kind === k).map((p) => p.value);
  const paths = uniq(
    endpointPaths()
      .map((v) => {
        try {
          return /^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(v) ? new URL(v, 'https://x.invalid').pathname : v;
        } catch {
          return v;
        }
      })
      .map((v) => v.split(/[?#]/)[0])
      .filter((p) => p.startsWith('/') && p.length > 1 && !p.includes('${')),
  );
  const lists = {
    'params.txt': uniq([...byKind('query'), ...byKind('body'), ...byKind('form')]),
    'query-params.txt': uniq(byKind('query')),
    'body-fields.txt': uniq(byKind('body')),
    'form-fields.txt': uniq(byKind('form')),
    'data-attributes.txt': uniq(byKind('data')),
    'headers.txt': uniq(byKind('header')),
    'cookies.txt': uniq(byKind('cookie')),
    'storage-keys.txt': uniq(byKind('storage')),
    'paths.txt': paths,
    'routes.txt': routePaths(),
    'path-segments.txt': uniq([...paths, ...routePaths()].flatMap((p) => p.split('/')).filter((s) => /^[\w.~-]{1,80}$/.test(s))),
    'urls.txt': absoluteUrls(),
    'subdomains.txt': uniq(m.domains.filter((d) => d.tags.includes('same-site') && !d.value.includes('*')).map((d) => d.value.replace(/:\d+$/, ''))),
    'live-hosts.txt': uniq(liveHostUrls()),
    'high-value-hosts.txt': [...new Set(valuedHosts().map((d) => d.value))],
  };
  const zip = new ZipWriter();
  const written = [];
  for (const [name, desc] of WORDLIST_FILES) {
    const lines = lists[name];
    if (!lines.length) continue;
    await zip.add(name, lines.join('\n') + '\n');
    written.push(`${name.padEnd(22)}${String(lines.length).padStart(6)}  ${desc}`);
  }
  if (!written.length) return toast('Nothing to export');
  const h = isProgram() ? ui.data.hosts[0] || 'TARGET' : ui.host;
  const readme = [
    `JS Recon wordlists for ${isProgram() ? `all in-scope hosts (${ui.data.hosts.join(', ')})` : h} (${new Date().toISOString().slice(0, 16).replace('T', ' ')})`,
    '',
    ...written,
    '',
    'Examples',
    `  arjun -u https://${h}/ENDPOINT -w params.txt`,
    `  x8 -u "https://${h}/ENDPOINT" -w params.txt`,
    `  ffuf -u "https://${h}/ENDPOINT?FUZZ=1" -w params.txt -mc all -ac`,
    `  ffuf -u "https://${h}/FUZZ" -w paths.txt -mc all -ac`,
    `  ffuf -u "https://${h}/api/FUZZ" -w path-segments.txt -mc all -ac`,
    `  ffuf -u "https://${h}/ENDPOINT" -H "FUZZ: 1" -w headers.txt -mc all -ac`,
    '  httpx -l urls.txt -sc -title        dnsx -l subdomains.txt -resp',
    '  nuclei -l live-hosts.txt             httpx -l high-value-hosts.txt -sc -title -td',
    '  Burp Param Miner: Settings → "use custom wordlist" → params.txt (or headers.txt for header guessing)',
    '',
  ].join('\n');
  await zip.add('README.txt', readme);
  downloadBlob(`jsrecon-${safeName(hostLabel())}-wordlists-${stamp()}.zip`, zip.blob());
  toast(`${written.length} wordlists`);
}

/** Historical JS and source maps of this host from the Wayback Machine (sends the host name to web.archive.org). */
async function runWayback() {
  $('#exportMenu').open = false;
  if (needsOneHost()) return;
  if (!ui.host) return toast('Open a site first');
  toast('Asking the Wayback Machine…');
  const r = await chrome.runtime.sendMessage({ type: 'wayback', host: ui.host });
  if (!r?.ok) return toast(r?.error || 'Wayback lookup failed');
  toast(r.captures ? `${r.captures} archived JS / map files · scanning ${r.queued}` : 'No archived JS files for this host');
  pollStatus();
}

async function doExport(kind) {
  if (kind === 'replay') return runReplay(); // keeps the menu open for the confirmation click
  if (kind === 'probe') return runProbe(); // two-click confirm, menu stays open
  $('#exportMenu').open = false;
  if (kind === 'dump') return openDump();
  if (kind === 'find') return openSearch();
  if (kind === 'wayback') return runWayback();
  if (kind === 'all') {
    const all = await chrome.storage.local.get(null);
    const hosts = Object.keys(all).filter((k) => k.startsWith('host:')).map((k) => exportJson(all[k]));
    return download(`jsrecon-all-${stamp()}.json`, JSON.stringify(hosts, null, 2), 'application/json');
  }
  if (!ui.data) return toast('Nothing to export');
  const base = `jsrecon-${safeName(hostLabel())}`;
  if (kind === 'json') download(`${base}-${stamp()}.json`, JSON.stringify(exportJson(ui.data), null, 2), 'application/json');
  if (kind === 'txt') download(`${base}-${stamp()}.txt`, textReport());
  if (kind === 'md') download(`${base}-${stamp()}.md`, mdReport(), 'text/markdown');
  if (kind === 'sarif') download(`${base}-${stamp()}.sarif`, JSON.stringify(buildSarif(sarifModel()), null, 2), 'application/json');
  if (kind === 'urls') download(`${base}-urls-${stamp()}.txt`, absoluteUrls().join('\n'));
  if (kind === 'wordlists') await exportWordlists();
  if (kind === 'graphql') exportGraphql();
  if (kind === 'openapi') download(`${base}-openapi-${stamp()}.json`, JSON.stringify(buildOpenApi(exportModel()), null, 2), 'application/json');
  if (kind === 'postman') download(`${base}-${stamp()}.postman_collection.json`, JSON.stringify(buildPostman(exportModel()), null, 2), 'application/json');
  if (kind === 'api') download(`${base}-api-${stamp()}.txt`, ui.model.api.filter((f) => !f.meta?.graphql).map((f) => `${apiParts(f).method} ${resolveUrl(apiParts(f).path)}`).join('\n'));
}

function copyVisible() {
  const items = ui.visible;
  if (!items.length) return toast('Nothing to copy');
  let lines;
  if (ui.tab === 'secrets') lines = items.map((f) => `${f.label}\t${f.value}`);
  else if (ui.tab === 'endpoints') lines = items.map((f) => (ui.absolute ? resolveUrl(f.value) : f.value));
  else if (ui.tab === 'api') lines = items.map((f) => `${apiParts(f).method} ${ui.absolute ? resolveUrl(apiParts(f).path) : apiParts(f).path}`);
  else if (ui.tab === 'files') lines = items.map((f) => f.url);
  else lines = items.map((f) => f.value);
  lines = [...new Set(lines)];
  copy(lines.join('\n'), `Copied ${lines.length} line${lines.length > 1 ? 's' : ''}`);
}

// ───────────────────────── wiring ─────────────────────────

function bindCheckbox(id, key, persist = true) {
  const el = $(id);
  el.checked = !!ui[key];
  el.addEventListener('change', () => {
    ui[key] = el.checked;
    if (persist) store.set(key, el.checked);
    render();
  });
}

function bind() {
  bindTabScroll();
  $('#hostSelect').addEventListener('change', (e) => loadHost(e.target.value));
  $('#search').addEventListener('input', (e) => {
    ui.q = e.target.value;
    ui.limit = 400;
    render();
  });
  $('#sevFilter').addEventListener('change', (e) => ((ui.sev = e.target.value), render()));
  bindCheckbox('#hideNoise', 'hideNoise');
  bindCheckbox('#hideTentative', 'hideTentative');
  bindCheckbox('#onlyInteresting', 'onlyInteresting', false);
  bindCheckbox('#onlyNew', 'onlyNew', false);
  bindCheckbox('#absolute', 'absolute');
  bindCheckbox('#onlyLive', 'onlyLive', false);
  bindCheckbox('#onlyInScope', 'onlyInScope', false);
  $('#btnCopy').addEventListener('click', copyVisible);
  $('#btnTriage').addEventListener('click', bulkTriage);
  $('#triageFilter').addEventListener('change', (e) => {
    ui.triage = e.target.value;
    store.set('triage', ui.triage);
    ui.limit = 400;
    triageArmed = 0;
    render();
  });

  $('#btnPause').addEventListener('click', async () => {
    ui.settings = await saveSettings({ enabled: !(ui.settings?.enabled !== false) });
    renderPause();
  });

  $('#btnRescan').addEventListener('click', async () => {
    if (!ui.host || needsOneHost()) return;
    if (askingHere()) return decide('tab'); // pressing Rescan on an unapproved tab is the OK for this tab
    const tabId = ui.tabHost === ui.host ? ui.tabId : null;
    const r = await chrome.runtime.sendMessage({ type: 'rescan', host: ui.host, tabId });
    toast(r?.ok ? 'Rescan queued' : r?.error || 'Rescan failed');
    pollStatus();
  });

  const clearBtn = $('#btnClear');
  clearBtn.addEventListener('click', async () => {
    if (!ui.host || needsOneHost()) return;
    if (!clearBtn.classList.contains('confirm')) {
      clearBtn.classList.add('confirm');
      setTimeout(() => clearBtn.classList.remove('confirm'), 3000);
      return;
    }
    clearBtn.classList.remove('confirm');
    await chrome.runtime.sendMessage({ type: 'clear', host: ui.host });
    await loadHost(ui.host);
    toast('Cleared');
  });

  for (const b of document.querySelectorAll('[data-export]')) b.addEventListener('click', () => doExport(b.dataset.export));
  document.addEventListener('click', (e) => {
    if (!e.target.closest('#exportMenu')) $('#exportMenu').open = false;
  });

  $('#btnFull').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL(`ui/popup.html?view=full${ui.host ? '&host=' + encodeURIComponent(ui.host) : ''}`) });
    window.close();
  });
  $('#btnOptions').addEventListener('click', () => chrome.runtime.openOptionsPage());

  $('#btnManual').addEventListener('click', () => {
    const m = $('#manual');
    m.hidden = !m.hidden;
    $('#dump').hidden = true;
    $('#searchFiles').hidden = true;
    if (!m.hidden) $('#manualInput').focus();
  });
  $('#btnDump').addEventListener('click', () => {
    $('#searchFiles').hidden = true;
    $('#dump').hidden ? openDump() : ($('#dump').hidden = true);
  });
  $('#btnSearchFiles').addEventListener('click', () => ($('#searchFiles').hidden ? openSearch() : ($('#searchFiles').hidden = true)));
  $('#btnSearchGo').addEventListener('click', runSearch);
  $('#searchQuery').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runSearch();
  });
  $('#btnWayback').addEventListener('click', runWayback);
  $('#dumpAll').addEventListener('click', () => {
    Object.keys(ui.index).forEach((x) => dumpSelection.add(x));
    renderDumpHosts();
  });
  $('#dumpNone').addEventListener('click', () => {
    dumpSelection.clear();
    renderDumpHosts();
  });
  $('#btnDumpGo').addEventListener('click', runDump);

  $('#btnScanUrls').addEventListener('click', async () => {
    const urls = $('#manualInput').value.split(/\s+/).filter((u) => isHttp(u));
    if (!urls.length) return ($('#manualMsg').textContent = 'No http(s) URLs found.');
    const host = $('#manualHost').value.trim() || null;
    const r = await chrome.runtime.sendMessage({ type: 'scan-urls', host, urls });
    $('#manualMsg').textContent = `Queued ${r?.queued ?? 0} URL(s).`;
    const target = host || hostOf(urls[0]);
    if (target && target !== ui.host) setTimeout(() => loadHost(target).then(refreshIndex), 800);
  });
  $('#btnScanCode').addEventListener('click', async () => {
    const text = $('#manualInput').value;
    if (!text.trim()) return;
    const host = $('#manualHost').value.trim() || (isProgram() ? null : ui.host) || 'manual';
    await chrome.runtime.sendMessage({ type: 'scan-text', host, text, label: `Pasted code (${formatBytes(text.length)})` });
    $('#manualMsg').textContent = `Scanned into “${host}”.`;
    if (host !== ui.host) setTimeout(() => loadHost(host).then(refreshIndex), 800);
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (isProgram()) {
      if (Object.keys(changes).some((k) => k.startsWith('host:') && hostScope(ui.scope, k.slice(5)) === 'in')) scheduleProgramReload();
    } else if (ui.host && changes['host:' + ui.host]) {
      ui.data = changes['host:' + ui.host].newValue || null;
      scheduleRender();
    }
    if (changes.index) {
      ui.index = changes.index.newValue || {};
      renderHostSelect();
    }
    if (changes.settings) {
      ui.settings = { ...ui.settings, ...(changes.settings.newValue || {}) };
      ui.scope = compileScope(ui.settings.scopeIn, ui.settings.scopeOut);
      ui.model = buildModel(ui.data);
      renderHostSelect();
      if (isProgram()) scheduleProgramReload();
      renderPause();
      refreshAsk().then(render);
    }
  });
}

async function refreshIndex() {
  ui.index = (await chrome.storage.local.get('index')).index || {};
  renderHostSelect();
}

async function init() {
  bind();
  ui.settings = await getSettings();
  ui.scope = compileScope(ui.settings.scopeIn, ui.settings.scopeOut);
  renderPause();
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && !FULL && /^https?:/i.test(tab.url || '')) {
      ui.tabHost = hostOf(tab.url);
      ui.tabId = tab.id;
      ui.tabUrl = tab.url;
    }
  } catch {
    /* ignore */
  }
  await refreshAsk();
  await refreshIndex();
  if (!ui.host) {
    ui.host = ui.tabHost || (FULL ? Object.entries(ui.index).sort((a, b) => (b[1].updated || 0) - (a[1].updated || 0))[0]?.[0] : null) || null;
  }
  renderHostSelect();
  await loadHost(ui.host);
  if (FULL && params.get('dump')) openDump();
  if (FULL && params.get('find')) openSearch();
  pollStatus();
  setInterval(pollStatus, 1000);
  if (!FULL) $('#search').focus();
}

init();
