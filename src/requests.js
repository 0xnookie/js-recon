// Requests the page really makes (fetch / XHR / WebSocket), as seen by chrome.webRequest.
// Pure: no chrome.* APIs, so it can be unit-tested with Node.
//
// Values are never stored: only the method, the normalised path, query parameter names and
// custom request header names (plus the scheme of an Authorization header, e.g. "Bearer").

import { apiEndpoint, inputFinding, classifyLink, STATIC_RE, INTERESTING_RE } from './rules.js';

const STD_REQUEST_HEADERS = new Set([
  'accept', 'accept-encoding', 'accept-language', 'cache-control', 'connection', 'content-length', 'content-type',
  'cookie', 'host', 'origin', 'pragma', 'referer', 'user-agent', 'if-none-match', 'if-modified-since', 'if-match',
  'if-unmodified-since', 'if-range', 'range', 'dnt', 'upgrade-insecure-requests', 'priority', 'te', 'keep-alive', 'upgrade',
  'purpose', 'x-client-data', 'device-memory', 'downlink', 'dpr', 'ect', 'rtt', 'viewport-width', 'save-data',
]);

/** "/api/users/123/orders/9f1c…" → "/api/users/{id}/orders/{uuid}" so one endpoint isn't listed per object. */
export function normalizePath(pathname) {
  return String(pathname)
    .split('/')
    .map((seg) => {
      if (!seg) return seg;
      if (/^\d+$/.test(seg)) return '{id}';
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return '{uuid}';
      if (/^[0-9a-f]{8,}$/i.test(seg) && /\d/.test(seg) && /[a-f]/i.test(seg)) return '{id}'; // hex ids / hashes
      if (/^[0-9a-f]{24}$/i.test(seg) || /^[0-9a-f]{32,}$/i.test(seg)) return '{id}';
      if (seg.length >= 20 && /^[A-Za-z0-9_-]+$/.test(seg) && /\d/.test(seg) && /[A-Za-z]/.test(seg) && !/[_-][a-z]{3,}[_-]/i.test(seg)) return '{token}';
      return seg;
    })
    .join('/');
}

// well-known libraries: archived copies of these rarely tell you anything about the target
const LIBRARY_FILE_RE =
  /\/(?:jquery(?:[.-][\w.-]*)?|bootstrap|polyfills?|vendors?|react(?:-dom)?|lodash|underscore|moment|angular|vue|d3|leaflet|three|proj4|mapbox-gl|ol|highcharts|echarts|plotly|tinymce|ckeditor|codemirror|monaco|ace|require|modernizr|core-js|zone|swagger-ui[\w-]*|pdf(?:\.worker)?|popper|select2|datatables|chart)(?:[.-][\w.-]*)?\.(?:min\.)?m?js(?:[?#]|$)/i;

/** Same script across versions / instances: chart/<uuid>/iframe.js, index.<hash>.js, main.4f2a91c.chunk.js */
export function scriptFamily(url) {
  try {
    const x = new URL(url);
    return x.host + normalizePath(x.pathname).replace(/[.-][\w-]{6,20}(?=\.(?:m?js|map)$)/, '').replace(/\.[0-9a-f]{6,}(?=\.)/i, '');
  } catch {
    return url;
  }
}

/**
 * Wayback CDX rows ([["timestamp","original"], …]) → captures in the order to fetch them:
 * source maps and sensitive-looking names first, then the newest, and one file per script family
 * before older versions, so near-identical copies don't use up the whole budget.
 */
export function orderCaptures(rows) {
  const captures = (Array.isArray(rows) ? rows.slice(1) : [])
    .filter((r) => Array.isArray(r) && /^\d{14}$/.test(r[0]) && /^https?:\/\//i.test(r[1] || ''))
    .map(([timestamp, original]) => ({ timestamp, original }));
  const score = (c) =>
    (/\.map(?:[?#]|$)/i.test(c.original) ? 2 : 0) + (INTERESTING_RE.test(c.original) ? 1 : 0) - (LIBRARY_FILE_RE.test(c.original) ? 3 : 0);
  captures.sort((a, b) => score(b) - score(a) || b.timestamp.localeCompare(a.timestamp));
  const roundRobin = (list) => {
    const groups = new Map();
    for (const c of list) {
      const k = scriptFamily(c.original);
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(c);
    }
    const out = [];
    for (let round = 0; out.length < list.length; round++) {
      const before = out.length;
      for (const g of groups.values()) if (g[round]) out.push(g[round]);
      if (out.length === before) break;
    }
    return out;
  };
  // application code (one per family, then older versions), libraries after all of it
  const isLib = (c) => LIBRARY_FILE_RE.test(c.original);
  return [...roundRobin(captures.filter((c) => !isLib(c))), ...roundRobin(captures.filter(isLib))];
}

/**
 * @param {{method: string, url: string, type?: string, pageOrigin?: string, requestHeaders?: Array<{name, value}>}} req
 * @returns {Array} findings in analyzer.js shape (empty if the request isn't interesting)
 */
export function observedRequest(req) {
  let u;
  try {
    u = new URL(req.url);
  } catch {
    return [];
  }
  const out = [];
  const base = { line: 0, col: 0, hits: 1 };
  if (req.type === 'websocket' || u.protocol === 'ws:' || u.protocol === 'wss:') {
    const l = classifyLink(u.origin.replace(/^http/, 'ws') + normalizePath(u.pathname));
    if (l) out.push({ ...base, rule: 'observed-websocket', label: 'WebSocket (observed)', category: 'urls', severity: 'info', value: l.value, tags: [...l.tags, 'observed'] });
  } else if (/^https?:$/.test(u.protocol) && !STATIC_RE.test(u.pathname) && !/\.m?js$/i.test(u.pathname)) {
    const names = [...new Set([...u.searchParams.keys()])].filter((n) => n.length <= 60);
    const path = normalizePath(u.pathname) + (names.length ? '?' + names.map((n) => `${n}=`).join('&') : '');
    const sameOrigin = req.pageOrigin && u.origin === req.pageOrigin;
    const api = apiEndpoint(req.method || 'GET', sameOrigin ? path : u.origin + path);
    if (api) out.push({ ...base, rule: 'observed-request', label: 'API call (observed)', category: 'api', severity: 'info', value: api.value, tags: [...api.tags, 'observed'], meta: api.meta });
    for (const n of names) {
      const f = inputFinding('query', n, ['observed']);
      if (f) out.push({ ...base, rule: 'observed-param', label: 'Query parameter (observed)', category: 'params', severity: 'info', ...f });
    }
  }
  for (const h of req.requestHeaders || []) {
    const lower = String(h.name).toLowerCase();
    if (STD_REQUEST_HEADERS.has(lower) || lower.startsWith('sec-') || lower.startsWith(':')) continue;
    const f = inputFinding('header', h.name, ['observed']);
    if (!f) continue;
    if (lower === 'authorization') f.meta.example = String(h.value || '').split(/\s+/)[0] + ' …';
    out.push({ ...base, rule: 'observed-header', label: 'Request header (observed)', category: 'params', severity: 'info', ...f });
  }
  return out;
}
