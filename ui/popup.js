import { SEV_RANK, CONFIDENCE_RANK, decodeJwt, siteOf, hostOf, formatBytes, truncate } from '../src/util.js';
import { DEV_HOST_RE, CLOUD_HOST_RE, interestingParam } from '../src/rules.js';
import { getSettings, saveSettings } from '../src/settings.js';
import { sourcesZip, dumpHosts, canRebuild } from './dump.js';
import { ZipWriter } from '../src/zip.js';
import { buildOpenApi, buildPostman, buildSarif, replayCandidates } from '../src/exporters.js';
import { parseDefinition, schemaSketch } from '../src/graphql.js';

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
  body: 'Top-level JSON / form field the page sends (recorded by the runtime hooks). The example shows the endpoint. Good candidates for mass assignment: add fields the UI never sends.',
  data: 'Read from a data-* attribute, usually on the embedding element (widget container or <script> tag). An embedder controls it.',
  form: 'Submitted by a form. Hidden fields are worth tampering with.',
  header: 'Request header set or read by the code. Custom headers often switch behaviour on the server.',
  cookie: 'Cookie read or written by the code.',
  storage: 'localStorage / sessionStorage key. Debug and feature switches often live here.',
};

function buildModel(data) {
  const m = { secrets: [], api: [], endpoints: [], urls: [], domains: [], cloud: [], params: [], deps: [], intel: [], sinks: [], routes: [], files: [], graphql: [] };
  if (!data) return m;
  const pageSite = siteOf((ui.host || '').replace(/:\d+$/, ''));
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
    if (example && p.examples.length < 5 && !p.examples.includes(example)) p.examples.push(example);
    if (f && p.sources.length < 5) p.sources.push(...f.sources.slice(0, 5 - p.sources.length));
  };
  const addDomain = (host, example, extraTags = [], hits = 1, f = null) => {
    let d = domains.get(host);
    if (!d) {
      const hostname = host.replace(/:\d+$/, '');
      const site = siteOf(hostname);
      const tags = [site === pageSite ? 'same-site' : 'third-party'];
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
      // hosts from CSP / CORS headers keep their own tag; the rest were found in code
      const fromHeaders = f.tags?.some((t) => t === 'csp' || t === 'cors');
      addDomain(f.value, null, fromHeaders ? f.tags : ['in-code', ...(f.tags || [])], f.hits || 1, f);
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
  m.params = [...params.values()].sort(
    (a, b) => kindRank(a) - kindRank(b) || b.tags.includes('interesting') - a.tags.includes('interesting') || b.count - a.count || a.value.localeCompare(b.value),
  );
  const has = (x, t) => (x.tags.includes(t) ? 1 : 0);
  m.domains = [...domains.values()].sort(
    (a, b) => has(b, 'same-site') - has(a, 'same-site') || has(b, 'interesting') - has(a, 'interesting') || a.value.localeCompare(b.value),
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
  m.api.sort((a, b) => (b.tags?.includes('interesting') - a.tags?.includes('interesting')) || apiParts(a).path.localeCompare(apiParts(b).path) || a.value.localeCompare(b.value));
  m.routes.sort(
    (a, b) =>
      (b.tags?.includes('interesting') - a.tags?.includes('interesting')) ||
      (b.tags?.includes('guarded') - a.tags?.includes('guarded')) ||
      a.value.localeCompare(b.value),
  );
  m.files = Object.values(data.files).sort((a, b) => (b.ts || 0) - (a.ts || 0));
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
const INTERESTING_TABS = new Set(['endpoints', 'urls', 'domains', 'api', 'params', 'routes']);

function filtered(tab) {
  const items = ui.model[tab] || [];
  const match = makeMatcher(ui.q.trim());
  const minSev = ui.sev === 'all' ? -1 : SEV_RANK[ui.sev];
  return items.filter((f) => {
    if (SEV_TABS.has(tab) && (SEV_RANK[f.severity] || 0) < minSev) return false;
    if (tab === 'secrets' && ui.hideTentative && (f.confidence === 'tentative' || f.tags?.includes('example'))) return false;
    if (ui.hideNoise && NOISE_TABS.has(tab) && f.tags?.some((t) => t === 'noise' || t === 'static')) return false;
    if (ui.onlyInteresting && INTERESTING_TABS.has(tab) && !f.tags?.includes('interesting')) return false;
    if (ui.onlyNew && tab !== 'files' && !f.tags?.includes('new')) return false;
    if (tab === 'files') return match(f.url + ' ' + (f.label || '') + ' ' + (f.error || ''));
    return match(f.value + ' ' + (f.label || '') + ' ' + (f.examples || []).join(' ') + ' ' + (f.tags || []).join(' '));
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

const HIDDEN_CHIPS = new Set(['js', 'write']);
function chips(tags) {
  return (tags || []).filter((t) => !HIDDEN_CHIPS.has(t)).map((t) => h('span', { class: `chip ${t}` }, t.replace(/-/g, ' ')));
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

function expandable(row, key, build) {
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

function curlFor(method, url) {
  return `curl -i -s -k -X ${method} ${shq(url)}${['POST', 'PUT', 'PATCH'].includes(method) ? " -H 'Content-Type: application/json' -d '{}'" : ''}`;
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
  const m = method.toLowerCase();
  const row = h(
    'div',
    { class: `row link api m-${m}` },
    head(
      h('span', { class: `method m-${m}` }, method),
      h('span', { class: 'value mono', title: shown }, shown),
      chips(f.tags),
      method === 'GET' ? probeChip(abs) : null,
      h('span', { class: 'spacer' }),
      srcSummary(f),
      canCurl ? btn('curl', 'Copy as curl command', () => copy(curlFor(method, abs), 'curl command copied')) : null,
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

function depRow(f) {
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

function domainRow(d) {
  const row = h(
    'div',
    { class: 'row link' },
    head(
      h('span', { class: 'value mono' }, d.value),
      chips(d.tags),
      h('span', { class: 'spacer' }),
      h('span', { class: 'src' }, `${d.count}×`),
      d.value.includes('*') ? null : btn('Open', 'https://' + d.value, () => chrome.tabs.create({ url: 'https://' + d.value, active: false })),
      btn('Copy', 'Copy', () => copy(d.value)),
    ),
  );
  return expandable(row, d.key, () => detailFor(d));
}

function paramRow(p) {
  const row = h(
    'div',
    { class: 'row link' },
    head(h('span', { class: 'value mono' }, p.value), chips(p.tags), h('span', { class: 'spacer' }), h('span', { class: 'src' }, `${p.count}×`), btn('Copy', 'Copy', () => copy(p.value))),
  );
  return expandable(row, p.key, () => detailFor(p));
}

const KIND_LABEL = { script: 'script', crawled: 'crawled', chunk: 'chunk', manual: 'manual', inline: 'inline', html: 'DOM', sourcemap: 'map', headers: 'headers', observed: 'traffic', runtime: 'runtime', wayback: 'wayback' };

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
  deps: 'No npm dependencies found. They are extracted from source maps, node_modules paths, imports and package.json blobs.',
  intel: 'Nothing here yet.',
  sinks: 'No tainted DOM sinks found. Taint flows (a URL source reaching innerHTML / eval / navigation) run by default; the broader single-pattern sink rules can be enabled in Settings.',
  routes: 'No client-side routes found (React Router, Vue Router, Angular …).',
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
    const items = ui.model[t.id] || [];
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
  $('#newWrap').hidden = !ui.data?.changes?.length || t === 'files';
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

function emptyState(title, text) {
  return h('div', { class: 'empty' }, h('div', { class: 'empty-mark' }, '{ }'), title ? h('b', {}, title) : null, text ? h('p', {}, text) : null);
}

function render() {
  if (!ui.model) ui.model = buildModel(ui.data);
  renderTabs();
  renderToolbar();
  renderChangeBanner();
  const list = $('#list');
  const scroll = list.scrollTop;
  list.replaceChildren();

  if (!ui.host) {
    list.append(emptyState('No website in this tab', 'Open a site to scan it, or pick a previously scanned host above.'));
    $('#count').textContent = '';
    return;
  }
  if (!ui.data) {
    list.append(emptyState(`Nothing scanned for ${ui.host} yet`, 'Reload the page or press Rescan. Scripts are captured as the page loads them.'));
    $('#count').textContent = '';
    return;
  }

  const items = filtered(ui.tab);
  ui.visible = items;
  const total = (ui.model[ui.tab] || []).length;
  $('#count').textContent = items.length === total ? `${total}` : `${items.length} / ${total}`;
  if (!items.length) {
    list.append(total ? emptyState('No matches', 'Nothing matches the current filters.') : emptyState(null, EMPTY[ui.tab]));
    return;
  }
  const make = ROW[ui.tab];
  const frag = document.createDocumentFragment();
  let last = null;
  for (const f of items.slice(0, ui.limit)) {
    if (GROUPED.has(ui.tab) && f.label !== last) frag.append(h('div', { class: 'group' }, f.label));
    last = f.label;
    frag.append(make(f));
  }
  if (items.length > ui.limit) {
    frag.append(h('button', { class: 'btn more', onclick: () => ((ui.limit = Infinity), render()) }, `Show all ${items.length} (${items.length - ui.limit} more)`));
  }
  list.append(frag);
  list.scrollTop = scroll;
}

let renderTimer = null;
function scheduleRender() {
  clearTimeout(renderTimer);
  renderTimer = setTimeout(() => {
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
  if (ui.tabHost && !ui.index[ui.tabHost]) sel.append(h('option', { value: ui.tabHost }, `${ui.tabHost} (current tab)`));
  if (ui.host && ui.host !== ui.tabHost && !ui.index[ui.host]) sel.append(h('option', { value: ui.host }, ui.host));
  for (const [host, s] of hosts) sel.append(h('option', { value: host }, label(host, s)));
  if (!sel.options.length) sel.append(h('option', { value: '' }, 'No hosts scanned yet'));
  sel.value = ui.host || '';
  renderDumpHosts();
}

async function loadHost(host) {
  ui.host = host || null;
  ui.expanded.clear();
  ui.limit = 400;
  if (host) {
    const r = await chrome.storage.local.get('host:' + host);
    ui.data = r['host:' + host] || null;
  } else ui.data = null;
  ui.model = buildModel(ui.data);
  if (FULL) {
    const u = new URL(location.href);
    if (host) u.searchParams.set('host', host);
    history.replaceState(null, '', u);
    document.title = host ? `JS Recon — ${host}` : 'JS Recon';
    $('#manualHost').placeholder = host || '(derived from URL)';
  }
  render();
}

async function pollStatus() {
  let st = null;
  try {
    st = await chrome.runtime.sendMessage({ type: 'status', host: ui.host });
  } catch {
    /* worker starting */
  }
  const el = $('#status');
  if (st?.pending) {
    el.className = 'status busy';
    el.textContent = `Scanning · ${st.pending} queued`;
  } else if (ui.data) {
    el.className = 'status';
    const s = Math.round((Date.now() - (ui.data.updated || Date.now())) / 1000);
    el.textContent = `${Object.keys(ui.data.files).length} files · ${s < 60 ? s + 's' : Math.round(s / 60) + 'm'} ago`;
  } else el.textContent = '';
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
}

// ───────────────────────── exports ─────────────────────────

function exportJson(data) {
  return {
    host: data.host,
    origin: data.origin,
    updated: new Date(data.updated).toISOString(),
    files: Object.values(data.files),
    findings: Object.values(data.findings),
    chunks: Object.keys(data.chunkUrls || {}),
  };
}

function textReport() {
  const m = ui.model;
  const out = [`# JS Recon — ${ui.host}`, `# ${new Date().toISOString()}`, ''];
  const section = (title, lines) => {
    if (!lines.length) return;
    out.push(`## ${title} (${lines.length})`, ...lines, '');
  };
  section('Secrets', m.secrets.map((f) => `[${f.severity.toUpperCase()}${f.confidence ? '/' + f.confidence : ''}] ${f.label}: ${f.value}  (${f.sources.map(srcLabel).join(', ')})`));
  section('API endpoints', m.api.map((f) => (f.meta?.graphql ? `${apiParts(f).method} ${apiParts(f).path} (GraphQL)` : `${apiParts(f).method} ${resolveUrl(apiParts(f).path)}`)));
  section('Endpoints', m.endpoints.filter((f) => !f.tags.includes('noise')).map((f) => f.value));
  section('URLs', m.urls.filter((f) => !f.tags.includes('noise')).map((f) => f.value));
  section('Domains', m.domains.map((d) => `${d.value}\t${d.tags.join(',')}`));
  section('Cloud', m.cloud.map((f) => `[${f.severity}] ${f.label}: ${f.value}`));
  section('Parameters', m.params.map((p) => (p.kind === 'query' ? p.value : `${p.value}\t(${p.kind})`)));
  section('Dependencies', m.deps.map((f) => `[${f.severity.toUpperCase()}] ${f.value}\t${f.label}${f.meta?.latest ? '\tv' + f.meta.latest : ''}`));
  section('Intel', m.intel.map((f) => `[${f.severity}] ${f.label}: ${f.value}`));
  section('Routes', m.routes.map((f) => `${f.value}${f.tags.length ? '\t[' + f.tags.join(',') + ']' : ''}${f.meta?.component ? '\t→ ' + f.meta.component : ''}`));
  section('Sinks', m.sinks.map((f) => `${f.label}: ${f.value}  (${f.sources.map(srcLabel).join(', ')})`));
  section('Lazy chunks (from the bundler runtime)', Object.keys(ui.data?.chunkUrls || {}).sort());
  section('Files', m.files.map((f) => `${f.kind}\t${f.url}${f.error ? '\t' + f.error : ''}`));
  return out.join('\n');
}

/** Markdown version of the report — pastes cleanly into tickets, PRs and wikis. */
function mdReport() {
  const m = ui.model;
  const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
  const tagsOf = (f) => (f.tags?.length ? ` _(${f.tags.join(', ')})_` : '');
  const out = [`# JS Recon — ${ui.host}`, '', `_Generated ${new Date().toISOString()}_`, ''];
  const section = (title, rows) => {
    if (rows.length) out.push(`## ${title} (${rows.length})`, '', ...rows, '');
  };
  section('Secrets', m.secrets.map((f) => `- **[${f.severity}${f.confidence ? '/' + f.confidence : ''}]** ${esc(f.label)}: \`${esc(f.value)}\`${tagsOf(f)}`));
  section('DOM-XSS sinks', m.sinks.map((f) => `- ${esc(f.label)}: \`${esc(f.value)}\``));
  section('API endpoints', m.api.map((f) => `- \`${apiParts(f).method} ${esc(f.meta?.graphql ? apiParts(f).path + ' (GraphQL)' : resolveUrl(apiParts(f).path))}\``));
  section('Routes', m.routes.map((f) => `- \`${esc(f.value)}\`${tagsOf(f)}`));
  section('Cloud', m.cloud.map((f) => `- **[${f.severity}]** ${esc(f.label)}: \`${esc(f.value)}\``));
  section('Dependencies', m.deps.map((f) => `- **[${f.severity}]** \`${esc(f.value)}\` — ${esc(f.label)}`));
  section('Intel', m.intel.map((f) => `- **[${f.severity}]** ${esc(f.label)}: ${esc(f.value)}`));
  section('Domains', m.domains.map((d) => `- \`${esc(d.value)}\`${tagsOf(d)}`));
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
    for (const f of m[tab] || []) {
      findings.push({ rule: f.rule || tab, label: f.label || tab, severity: f.severity || 'info', value: f.value, category: f.category || tab, desc: f.desc, locations: loc(f) });
    }
  }
  return { host: ui.host, version: chrome.runtime.getManifest().version, findings };
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
  const bodyFields = {};
  for (const p of m.params.filter((x) => x.kind === 'body')) {
    for (const ex of p.examples) if (!(bodyFields[ex] ||= []).includes(p.value)) bodyFields[ex].push(p.value);
  }
  const auth = m.params.filter((p) => p.kind === 'header' && /^authorization$/i.test(p.value));
  return {
    host: ui.host,
    origin: ui.data.origin,
    endpoints: m.api.filter((f) => !f.meta?.graphql).map((f) => ({ ...apiParts(f), tags: f.tags })),
    bodyFields,
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
    `# ${ui.host} · GraphQL endpoint: ${graphqlEndpoint()}`,
    '',
    schemaSketch(defs),
    '# ─── Operations and fragments found in the client ───',
    '',
    ...[...ops, ...frags].map((f) => f.meta.document + '\n'),
  ].join('\n');
  download(`jsrecon-${safeName(ui.host)}-${stamp()}.graphql`, text);
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
  return replayCandidates(urls, siteOf, ui.host);
}

let replayArmed = 0;
const REPLAY_LABEL = 'Send GET URLs to proxy… ';

/** Two clicks: the first shows how many requests would be sent, the second sends them. */
async function runReplay() {
  if (!ui.data) return toast('Nothing to send');
  const { urls, skipped } = replayUrls();
  const item = $('#replayItem');
  if (!urls.length) {
    $('#exportMenu').open = false;
    return toast('No concrete GET URLs for this host');
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
  toast(`Sending ${r.queued} GET requests${skip ? ` · skipped ${skip} (placeholders / state-changing)` : ''}`);
  pollStatus();
}

const absoluteUrls = () => [...new Set(endpointPaths().map(resolveUrl).filter((u) => isHttp(u) && !u.includes('${')))].sort();

// ── endpoint liveness (opt-in, same-site) ──
function probeUrls() {
  const urls = [...absoluteUrls(), ...routePaths().map(resolveUrl)].filter(isHttp);
  return replayCandidates(urls, siteOf, ui.host);
}

let probeArmed = 0;
const PROBE_LABEL = 'Check which endpoints are live… ';

/** Two clicks, same safe same-site GET candidates as the proxy sender, but the status is recorded. */
async function runProbe() {
  if (!ui.data) return toast('Nothing to probe');
  const { urls, skipped } = probeUrls();
  const item = $('#probeItem');
  if (!urls.length) {
    $('#exportMenu').open = false;
    return toast('No concrete same-site GET URLs for this host');
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
  const skip = skipped.unsafe + skipped.template + (r.skipped?.limit || 0);
  toast(`Probing ${r.queued} same-site endpoint${r.queued === 1 ? '' : 's'}${skip ? ` · skipped ${skip}` : ''}`);
  pollStatus();
}

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
  const cls = s >= 200 && s < 300 ? 'ok' : s === 401 || s === 403 ? 'auth' : s === 404 || s === 410 ? 'gone' : s >= 500 ? 'err' : 'other';
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
  const h = ui.host;
  const readme = [
    `JS Recon wordlists for ${h} (${new Date().toISOString().slice(0, 16).replace('T', ' ')})`,
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
    '  Burp Param Miner: Settings → "use custom wordlist" → params.txt (or headers.txt for header guessing)',
    '',
  ].join('\n');
  await zip.add('README.txt', readme);
  downloadBlob(`jsrecon-${safeName(h)}-wordlists-${stamp()}.zip`, zip.blob());
  toast(`${written.length} wordlists`);
}

/** Historical JS and source maps of this host from the Wayback Machine (sends the host name to web.archive.org). */
async function runWayback() {
  $('#exportMenu').open = false;
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
  if (kind === 'wayback') return runWayback();
  if (kind === 'all') {
    const all = await chrome.storage.local.get(null);
    const hosts = Object.keys(all).filter((k) => k.startsWith('host:')).map((k) => exportJson(all[k]));
    return download(`jsrecon-all-${stamp()}.json`, JSON.stringify(hosts, null, 2), 'application/json');
  }
  if (!ui.data) return toast('Nothing to export');
  const base = `jsrecon-${safeName(ui.host)}`;
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
  $('#btnCopy').addEventListener('click', copyVisible);

  $('#btnPause').addEventListener('click', async () => {
    ui.settings = await saveSettings({ enabled: !(ui.settings?.enabled !== false) });
    renderPause();
  });

  $('#btnRescan').addEventListener('click', async () => {
    if (!ui.host) return;
    const tabId = ui.tabHost === ui.host ? ui.tabId : null;
    const r = await chrome.runtime.sendMessage({ type: 'rescan', host: ui.host, tabId });
    toast(r?.ok ? 'Rescan queued' : r?.error || 'Rescan failed');
    pollStatus();
  });

  const clearBtn = $('#btnClear');
  clearBtn.addEventListener('click', async () => {
    if (!ui.host) return;
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
    if (!m.hidden) $('#manualInput').focus();
  });
  $('#btnDump').addEventListener('click', () => ($('#dump').hidden ? openDump() : ($('#dump').hidden = true)));
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
    const host = $('#manualHost').value.trim() || ui.host || 'manual';
    await chrome.runtime.sendMessage({ type: 'scan-text', host, text, label: `Pasted code (${formatBytes(text.length)})` });
    $('#manualMsg').textContent = `Scanned into “${host}”.`;
    if (host !== ui.host) setTimeout(() => loadHost(host).then(refreshIndex), 800);
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (ui.host && changes['host:' + ui.host]) {
      ui.data = changes['host:' + ui.host].newValue || null;
      scheduleRender();
    }
    if (changes.index) {
      ui.index = changes.index.newValue || {};
      renderHostSelect();
    }
    if (changes.settings) {
      ui.settings = { ...ui.settings, ...(changes.settings.newValue || {}) };
      renderPause();
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
  renderPause();
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && !FULL && /^https?:/i.test(tab.url || '')) {
      ui.tabHost = hostOf(tab.url);
      ui.tabId = tab.id;
    }
  } catch {
    /* ignore */
  }
  await refreshIndex();
  if (!ui.host) {
    ui.host = ui.tabHost || (FULL ? Object.entries(ui.index).sort((a, b) => (b[1].updated || 0) - (a[1].updated || 0))[0]?.[0] : null) || null;
  }
  renderHostSelect();
  await loadHost(ui.host);
  if (FULL && params.get('dump')) openDump();
  pollStatus();
  setInterval(pollStatus, 1000);
  if (!FULL) $('#search').focus();
}

init();
