// Detection rules.
//
// Each rule: { id, label, category, severity, re (global RegExp), group?, post?, enabled?, desc?, generic? }
//   group    – capture group that holds the value (default: whole match)
//   post     – (value, match, { code, index }) => false/null to drop, true to keep,
//              an object { value?, label?, severity?, category?, tags?, meta? } to keep with overrides,
//              or an array of such objects to emit several findings from one match.
//   generic  – context-based secret rule ("key = value"); gets a lower confidence ceiling.
//
// Rules are evaluated in order and de-duplicated per (category, value), so specific
// rules must come before generic ones. All quantifiers are bounded or anchored to keep
// scans of multi-megabyte bundles linear.

import { entropy, decodeJwt, SEV_RANK } from './util.js';

export const CATEGORY_LABELS = {
  secrets: 'Secrets',
  api: 'API endpoints',
  endpoints: 'Endpoints',
  urls: 'URLs',
  subdomains: 'Subdomains',
  cloud: 'Cloud',
  params: 'Parameters',
  deps: 'Dependencies',
  intel: 'Intel',
  sinks: 'DOM sinks',
};

const S = 'secrets';
const I = 'intel';
const C = 'cloud';
const A = 'api';
const D = 'deps';

// ───────────────────────────── helpers ─────────────────────────────

const PLACEHOLDER_RE =
  /example|sample|dummy|placeholder|changeme|change[_-]me|your[_-]|insert[_-]|replace[_-]?me|x{5}|\*{4}|<[^>]*>|\$\{|\{\{|%s|process\.env|import\.meta/i;
const RESERVED_WORDS = new Set([
  'true', 'false', 'null', 'none', 'nil', 'undefined', 'string', 'number', 'object', 'boolean',
  'function', 'required', 'optional', 'hidden', 'password', 'text', 'secret', 'token', 'bearer',
  'basic', 'login', 'signin', 'signup', 'submit', 'reset', 'forgot', 'current', 'confirm', 'change',
]);

export function notPlaceholder(v) {
  return !PLACEHOLDER_RE.test(v) && !/^(.)\1+$/.test(v);
}

/**
 * Heuristic filter for values captured by context-based ("key = value") rules.
 * `human` lowers the entropy bar for human-chosen values (passwords repeat characters more than tokens do).
 */
export function isLikelySecret(v, human = false) {
  if (!v || v.length < 8 || v.length > 256) return false;
  if (!notPlaceholder(v)) return false;
  if (RESERVED_WORDS.has(v.toLowerCase())) return false;
  if (/[\s()[\]{}<>\\|,;'"`]/.test(v)) return false;
  if (/^\^/.test(v)) return false; // regex
  if (/^[a-z]+$/i.test(v)) return false; // single word
  if (/^[a-z]+(?:[-_.:][a-z]+)+$/i.test(v)) return false; // i18n keys, css classes, event names
  if (/^[a-z]+(?:[A-Z][a-z]+)+\d{0,2}$/.test(v)) return false; // camelCase identifiers
  if (/^[A-Z][A-Z_]+$/.test(v)) return false; // CONSTANT_NAMES
  if (/^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(v) || /^[./#?@$&=]/.test(v)) return false; // urls, paths, selectors
  if (/^[\d.:_-]+$/.test(v)) return false; // numbers, versions, dates
  if (/^[a-z_\-/]+$/i.test(v)) return false; // path-like words
  if (/^(?:text|application|image)\//i.test(v)) return false;
  const threshold = human ? Math.min(3.0, Math.log2(v.length) * 0.8) : Math.min(3.5, Math.log2(v.length) * 0.85);
  return entropy(v) >= threshold;
}

/**
 * Confidence for a secret finding, based on Shannon entropy of the value.
 * Format-specific rules start at "certain"; context-based ("generic") rules top out at "firm".
 */
export function secretConfidence(value, generic) {
  const e = entropy(value);
  if (generic) return { entropy: e, confidence: e >= 4.0 ? 'firm' : 'tentative' };
  return { entropy: e, confidence: e >= 3.5 ? 'certain' : e >= 2.8 ? 'firm' : 'tentative' };
}

function ctxValue(v, m, ctx) {
  return { value: ctx.code.slice(ctx.index, ctx.index + 90).replace(/\s+/g, ' ').trim() };
}

function classifyJwt(v) {
  const d = decodeJwt(v);
  if (!d || !d.payload || typeof d.payload !== 'object') return null;
  const p = d.payload;
  const meta = {};
  for (const k of ['alg', 'kid', 'typ']) if (d.header[k] != null) meta[k] = d.header[k];
  for (const k of ['iss', 'sub', 'aud', 'role', 'scope', 'email', 'exp', 'iat']) if (p[k] != null) meta[k] = p[k];
  if (typeof p.exp === 'number') meta.expires = new Date(p.exp * 1000).toISOString();
  if (p.role === 'service_role') return { severity: 'high', label: 'Supabase service_role JWT', meta };
  if (p.role === 'anon' && /supabase/i.test(String(p.iss || ''))) {
    return { severity: 'info', category: I, label: 'Supabase anon key (JWT)', meta };
  }
  if (String(d.header.alg).toLowerCase() === 'none') return { label: 'JWT (alg: none)', meta };
  return { meta };
}

const DB_SCHEMES = /^(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqps?|mssql|sqlserver|couchdb|neo4j(?:\+s)?|clickhouse|jdbc:[a-z0-9]+):/i;
const WEAK_CRED_RE = /^(?:user(?:name)?|pass(?:word)?|pwd|secret|admin|root|login|test|guest|demo|xxx+|\*+|\$\{.*|\{\{.*|<.*|%.*|:?[a-z]+_?(?:user|pass(?:word)?))$/i;

function credsInUrl(v) {
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^:@/]+):([^@/]+)@([^/?#]+)/i.exec(v);
  if (!m) return null;
  if (DB_SCHEMES.test(v)) return null; // handled by db-connection
  const [, , user, pass, host] = m;
  if (/sentry/i.test(host) || /^[a-f0-9]{32}$/i.test(user)) return null;
  if (WEAK_CRED_RE.test(pass) || !notPlaceholder(pass) || !notPlaceholder(user)) return null;
  return { meta: { user, host } };
}

function dbConn(v) {
  const m = /^[^:]+(?::[a-z0-9]+)?:\/\/(?:([^:@/\s]*):([^@/\s]+)@)?([^/?#\s]+)/i.exec(v);
  if (!m) return null;
  const [, user, pass, host] = m;
  if (pass && notPlaceholder(pass) && !WEAK_CRED_RE.test(pass)) {
    return { meta: { user, host } };
  }
  return { category: I, severity: 'low', label: 'Database host', meta: { host } };
}

function basicAuth(v) {
  try {
    const decoded = atob(v);
    if (!/^[\x20-\x7e]+:[\x20-\x7e]*$/.test(decoded)) return null;
    const [, pass] = decoded.split(':');
    if (!pass || WEAK_CRED_RE.test(pass)) return null;
    return { meta: { decoded } };
  } catch {
    return null;
  }
}

// ── endpoints / urls ──

const MIME_RE = /^(?:application|text|image|audio|video|font|multipart|model|message|chemical|x-[\w-]+)\/[\w.+*-]+(?:\s*;.*)?$/i;
const DATE_FMT_RE = /^[YyMDdHhmsSaAZzEeWwGgQqKkLlc]{1,4}(?:[/.:\- ][YyMDdHhmsSaAZzEeWwGgQqKkLlc]{1,4}){1,5}$/;
export const STATIC_RE =
  /\.(?:png|jpe?g|gif|svg|ico|cur|webp|avif|bmp|tiff?|css|s[ac]ss|less|styl|woff2?|ttf|otf|eot|mp[34]|webm|ogg|ogv|wav|flac|aac|m4[av]|mov|avi|mkv|pdf|swf|psd|map)(?:[?#]|$)/i;
const NOISE_PATH_RE =
  /node_modules\/|(?:^|\/)(?:webpack|@babel|@swc|core-js|regenerator-runtime|@vite|vite|@emotion|@mui|lodash|moment|react-dom)\/|^webpack:|^\.\/node_modules|\.(?:tsx?|jsx|vue|svelte|coffee|elm|flow)(?:[?#]|$)/i;
export const INTERESTING_RE =
  /(?:^|[/._?&=-])(?:admin\w*|administrator|internal|private|debug|staging|sandbox|graphql|graphiql|gql|swagger(?:-ui)?|api-docs|apidocs|openapi|redoc|actuator|heapdump|jolokia|metrics|prometheus|config(?:uration)?|settings|env|backup|bak|dump|export|upload\w*|token|oauth\d?|sso|saml|jwt|reset|password|passwd|secret|apikey|api_key|credential\w*|webhook\w*|callback|redirect\w*|return_?url|proxy|console|manage\w*|phpinfo|server-status|\.git|\.svn|\.env|wp-admin|wp-json|xmlrpc|cgi-bin|impersonat\w*|sudo|superuser|role\w*|permission\w*|invite|billing|payment\w*|refund|transfer|wallet|kyc|mfa|2fa|otp)(?:$|[/._?#&=-])|[a-z0-9](?:admin|internal|debug)(?:$|[/._?#&=-])/i;

/** Hostnames that look like non-production / internal infrastructure. */
export const DEV_HOST_RE =
  /(?:^|[.-])(?:dev|develop|development|stg|stage|staging|test|testing|qa|uat|int|internal|intranet|corp|preprod|pre-prod|sandbox|beta|demo|local|localhost|admin|vpn|jenkins|gitlab|jira|confluence|grafana|kibana|sonar|nexus|artifactory|argocd|vault)\d*(?:[.-]|$)/i;

/** Hostnames of cloud / hosting providers. */
export const CLOUD_HOST_RE =
  /(?:amazonaws\.com(?:\.cn)?|cloudfront\.net|on\.aws|azure\w*\.(?:net|com)|windows\.net|azurecr\.io|azurestaticapps\.net|cloudapp\.net|trafficmanager\.net|googleapis\.com|appspot\.com|firebase(?:io|app)?\.com|firebasedatabase\.app|firebasestorage\.app|run\.app|cloudfunctions\.net|oraclecloud(?:apps)?\.com|aliyuncs\.com|rackcdn\.com|clouddrive\.com|dream\.io|dreamhosters\.com|digitaloceanspaces\.com|ondigitalocean\.app|wasabisys\.com|backblazeb2\.com|r2\.dev|r2\.cloudflarestorage\.com|linodeobjects\.com|appdomain\.cloud|herokuapp\.com|vercel\.app|netlify\.app|pages\.dev|workers\.dev|supabase\.co|onrender\.com|fly\.dev|railway\.app)$/i;

// Hosts that only show up as documentation/namespace links in bundled libraries.
const NOISE_HOSTS = [
  'w3.org', 'schema.org', 'xmlns.com', 'purl.org', 'ogp.me', 'apache.org', 'opensource.org',
  'reactjs.org', 'react.dev', 'fb.me', 'facebook.github.io', 'momentjs.com', 'lodash.com',
  'underscorejs.org', 'jquery.org', 'jquery.com', 'mozilla.org', 'tc39.es', 'whatwg.org',
  'ietf.org', 'npms.io', 'npmjs.org', 'npmjs.com', 'feross.org', 'babeljs.io', 'mths.be',
  'getbootstrap.com', 'angular.io', 'angular.dev', 'vuejs.org', 'svelte.dev', 'nextjs.org',
  'vitejs.dev', 'webpack.js.org', 'creativecommons.org', 'gnu.org', 'json-schema.org',
  'swagger.io', 'ecma-international.org', 'unicode.org', 'adobe.com/xap', 'ns.adobe.com',
  'github.com/zloirock', 'github.com/facebook', 'github.com/mui', 'github.com/emotion-js',
  'github.com/reduxjs', 'redux.js.org', 'mui.com', 'emotion.sh', 'tailwindcss.com',
  'polyfill.io', 'sentry.io/for', 'docs.sentry.io', 'goo.gl', 'example.com', 'example.org',
  'example.net', 'localhost.example',
];

function isNoiseUrl(hostname, path) {
  const hp = hostname + (path || '');
  for (const n of NOISE_HOSTS) {
    if (n.includes('/')) {
      if (hp.startsWith(n) || hp.startsWith('www.' + n)) return true;
    } else if (hostname === n || hostname.endsWith('.' + n)) {
      return true;
    }
  }
  return false;
}

export function classifyLink(raw) {
  const v = String(raw).trim();
  if (v.length < 3 || v.length > 2048) return null;
  if (!/[a-z]/i.test(v) || /[\s<>\\]/.test(v)) return null;
  if (MIME_RE.test(v) || DATE_FMT_RE.test(v)) return null;
  if (/^\.{0,2}\/+$/.test(v)) return null;
  const tags = [];
  const abs = /^(?:([a-z][a-z0-9+.-]{0,15}):)?\/\/([^/?#]+)(.*)$/i.exec(v);
  if (abs) {
    const scheme = (abs[1] || '').toLowerCase();
    const path = abs[3] || '';
    const hostname = abs[2].replace(/^[^@]*@/, '').toLowerCase().replace(/:\d+$/, '');
    if (!hostname.includes('${')) {
      const isIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
      const named = /^[a-z0-9.-]+$/.test(hostname) && /\.[a-z][a-z0-9-]{1,62}$/.test(hostname);
      const single = scheme && /^[a-z][a-z0-9-]{0,62}$/.test(hostname); // http://jenkins:8080
      if (!(isIp || named || single || hostname === 'localhost' || /^\[[0-9a-f:.]+\]$/.test(hostname))) return null;
    }
    if (isNoiseUrl(hostname, path)) tags.push('noise');
    else if (STATIC_RE.test(path)) tags.push('static');
    if (INTERESTING_RE.test(path)) tags.push('interesting');
    if (/\.m?js(?:[?#]|$)/i.test(path)) tags.push('js');
    return { category: 'urls', value: v, tags };
  }
  if (/^[a-z][a-z0-9+.-]{1,15}:/i.test(v)) return null; // other schemes (mailto:, data:, about: …)
  if (NOISE_PATH_RE.test(v)) tags.push('noise');
  else if (STATIC_RE.test(v)) tags.push('static');
  if (INTERESTING_RE.test(v)) tags.push('interesting');
  if (/\.m?js(?:[?#]|$)/i.test(v)) tags.push('js');
  return { category: 'endpoints', value: v, tags };
}

// "api.acme.io/v1" without a scheme: accept country-code TLDs and common generic ones, not file extensions.
const EXT_NOT_TLD = new Set(['js', 'ts', 'md', 'py', 'rb', 'sh', 'go', 'rs', 'cs', 'gz', 'db', 'so', 'cc', 'hh', 'kt', 'vm', 'pm', 'mm']);
const GENERIC_TLDS = new Set([
  'com', 'net', 'org', 'io', 'dev', 'app', 'ai', 'info', 'biz', 'gov', 'edu', 'mil', 'int', 'cloud', 'tech', 'xyz',
  'online', 'site', 'shop', 'store', 'page', 'link', 'live', 'services', 'systems', 'solutions', 'digital', 'network',
  'software', 'group', 'global', 'agency', 'media', 'news', 'wiki', 'local', 'internal', 'corp', 'lan', 'intranet', 'test',
]);

function schemelessUrl(v, m) {
  const tld = m[3].toLowerCase();
  if (tld.length === 2 ? EXT_NOT_TLD.has(tld) : !GENERIC_TLDS.has(tld)) return null;
  return classifyLink('//' + v);
}

// Based on LinkFinder's regex, extended with template literals and `${base}/path` strings.
const LINK_RE =
  /(["'`])((?:[a-zA-Z][a-zA-Z0-9+.-]{0,15}:)?\/\/[^"'`\s/<>]{1,255}(?:\/[^"'`\s<>]{0,2000})?|(?:\/|\.\.\/|\.\/)[^"'`><,;|*()%$^/\\[\]\s][^"'`><,;|()\s]{1,2000}|\$\{[\w.$]{1,80}\}\/[^"'`\s<>]{1,2000}|[a-zA-Z0-9_\-/]{1,300}\/[a-zA-Z0-9_\-/.]{1,300}\.(?:[a-zA-Z]{1,4}|action)(?:[?#][^"'`\s]{0,2000})?|[a-zA-Z0-9_\-/]{1,300}\/[a-zA-Z0-9_\-/]{3,300}(?:[?#][^"'`\s]{0,2000})?|[a-zA-Z0-9_-]{1,200}\.(?:php\d?|aspx?|ashx|asmx|jsp|jspx|json|action|do|html?|js|mjs|txt|xml|cgi|pl|cfm|svc|wsdl|ya?ml|env|bak|sql|conf|config|ini|log)(?:[?#][^"'`\s]{0,2000})?)\1/g;

// ── API endpoints (method-aware) ──

const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);
const API_PATH_START = /^(?:(?:https?|wss?):\/\/|\/\/|\/|\.\.?\/|\$\{|[A-Za-z0-9_-]+\/)/;

function apiPath(raw) {
  const p = String(raw || '').trim();
  if (p.length < 2 || p.length > 1000 || /\s/.test(p)) return null;
  if (!API_PATH_START.test(p) || !/[a-z]/i.test(p) || !p.includes('/')) return null;
  if (p.startsWith('${') && !/^\$\{[^}]{1,80}\}\//.test(p)) return null; // only `${base}/path`, not `${a}:b`
  if (MIME_RE.test(p) || STATIC_RE.test(p) || DATE_FMT_RE.test(p) || NOISE_PATH_RE.test(p)) return null;
  if (/^\/\/\s|^\/\*/.test(p)) return null;
  return p;
}

/** Builds an API finding ("POST /api/x") or null. `prefix` is a variable concatenated before the path. */
export function apiEndpoint(method, path, prefix) {
  const M = String(method || '').toUpperCase();
  if (!HTTP_METHODS.has(M)) return null;
  const p = apiPath(path);
  if (!p) return null;
  const full = prefix && !/^(?:[a-z]+:)?\/\//i.test(p) ? `\${${prefix}}${p.startsWith('/') ? '' : '/'}${p}` : p;
  const tags = [];
  if (INTERESTING_RE.test(p)) tags.push('interesting');
  if (!['GET', 'HEAD', 'OPTIONS'].includes(M)) tags.push('write');
  return { value: `${M} ${full}`, tags, meta: { method: M, path: full } };
}

const METHOD_IN_OPTS_RE = /\bmethod\s*:\s*(["'`])([A-Za-z]{3,7})\1/;
const URL_KEY_RE = /\burl\s*:\s*(?:([A-Za-z_$][\w.$]{0,60})\s*\+\s*)?(["'`])([^"'`\s]{1,1000})\2/g;

/** Looks for `method: "X"` in the options object that follows a call's URL argument. */
function methodAfter(code, from) {
  let win = code.slice(from, from + 500);
  const stop = win.search(/;|\bfetch\(/);
  if (stop > -1) win = win.slice(0, stop);
  const m = METHOD_IN_OPTS_RE.exec(win);
  return m ? m[2] : null;
}

function apiFromCall(v, m) {
  const fn = m[1];
  if (/\.(?:get|post|put|delete|patch|head|options|getJSON|del)$/i.test(fn)) return null; // handled by api-call
  const fetchLike = /(?:^|\.)fetch$|(?:^|\.)Request$|^\$fetch$|^ofetch$|^ky$/i.test(fn);
  if (!fetchLike && !m[5]) return null;
  const end = m.index + m[0].length;
  const method = methodAfter(this.code, end) || (fetchLike ? 'GET' : null);
  return method ? apiEndpoint(method, m[4], m[2]) : null;
}

/** Text of the object literal that contains `index` (brace matching, max `max` chars each way). */
function enclosingObject(code, index, max = 600) {
  let depth = 0;
  let start = -1;
  for (let i = index - 1; i >= Math.max(0, index - max); i--) {
    const c = code[i];
    if (c === '}') depth++;
    else if (c === '{') {
      if (depth === 0) {
        start = i;
        break;
      }
      depth--;
    }
  }
  if (start < 0) return null;
  depth = 0;
  for (let i = index; i < Math.min(code.length, index + max); i++) {
    const c = code[i];
    if (c === '{') depth++;
    else if (c === '}') {
      if (depth === 0) return code.slice(start, i + 1);
      depth--;
    }
  }
  return null;
}

function apiFromConfig(v, m, ctx) {
  const obj = enclosingObject(ctx.code, ctx.index);
  if (!obj) return null;
  URL_KEY_RE.lastIndex = 0;
  const u = URL_KEY_RE.exec(obj);
  return u ? apiEndpoint(m[2] || m[4], u[3], u[1]) : null;
}

// ── dependencies (npm) ──

const NODE_BUILTINS = new Set([
  'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console', 'constants', 'crypto', 'dgram',
  'diagnostics_channel', 'dns', 'domain', 'events', 'fs', 'http', 'http2', 'https', 'inspector', 'module',
  'net', 'os', 'path', 'perf_hooks', 'process', 'punycode', 'querystring', 'readline', 'repl', 'stream',
  'string_decoder', 'sys', 'timers', 'tls', 'trace_events', 'tty', 'url', 'util', 'v8', 'vm', 'wasi',
  'worker_threads', 'zlib',
]);
const NPM_NAME_RE = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;

/** "@scope/pkg/sub/file.js" → "@scope/pkg", "lodash/fp" → "lodash"; null for relative paths, builtins, URLs. */
export function packageRoot(spec) {
  const s = String(spec || '').trim();
  if (!s || /^[./~#]/.test(s) || /^[a-z][a-z0-9+.-]*:/i.test(s)) return null;
  const parts = s.split('/');
  if (s.startsWith('@') && parts.length < 2) return null;
  const name = s.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  if (name.length > 214 || !NPM_NAME_RE.test(name) || NODE_BUILTINS.has(name)) return null;
  return name;
}

const depFinding = (name, evidence) => ({ value: name, meta: { evidence: [evidence] } });

function depsFromPackageJson(block) {
  const out = [];
  const re = /"([^"\s]{1,214})"\s*:\s*"[^"]{0,200}"/g;
  let m;
  while ((m = re.exec(block))) {
    const name = packageRoot(m[1]);
    if (name && name === m[1]) out.push(depFinding(name, 'package.json'));
  }
  return out.length ? out : null;
}

// ── parameters and other client-side inputs ──
// Every "params" finding carries meta.kind: query | data | form | header | cookie | storage.

const PARAM_NAME_RE = /^[A-Za-z_$][\w.[\]$-]{0,60}$/;
const KEY_NAME_RE = /^(?=[^a-z]*[a-z])[\w.:@/$[\]-]{1,80}$/i; // storage keys / cookie names: "persist:root", "@app/token"
const HEADER_NAME_RE = /^[A-Za-z][A-Za-z0-9-]{1,60}$/;
// type names, OpenAPI "in" values and literals that show up as the value of a *Param key
const NOT_A_NAME = new Set([
  'string', 'number', 'integer', 'boolean', 'object', 'array', 'query', 'path', 'header', 'headers', 'body',
  'formdata', 'cookie', 'true', 'false', 'null', 'undefined', 'none', 'default', 'function',
]);
const STD_HEADERS = new Set([
  'accept', 'accept-language', 'accept-encoding', 'content-type', 'content-length', 'content-encoding',
  'content-language', 'content-disposition', 'cache-control', 'pragma', 'expires', 'if-none-match',
  'if-modified-since', 'last-modified', 'etag', 'user-agent', 'connection', 'host', 'date', 'range', 'vary',
  'location', 'link', 'retry-after', 'upgrade', 'origin', 'referer', 'dnt',
]);
// words that make a parameter worth a closer look (open redirect, SSRF, LFI, debug switches, auth …)
const PARAM_WORD_RE =
  /^(?:debug|test|testing|dev|devmode|admin|internal|preview|beta|alpha|feature|features|flag|flags|mock|bypass|force|override|staging|sandbox|trace|verbose|redirect|redir|return|returnurl|returnto|callback|continue|dest|destination|next|goto|target|endpoint|proxy|template|tpl|file|filename|filepath|path|dir|folder|cmd|command|exec|eval|sql|token|secret|apikey|jwt|role|roles|impersonate|sudo|env|environment|url|uri|host|domain|webhook|html|script|jsonp|include)$/i;

// data-* attributes owned by UI frameworks (Bootstrap, React, Vue, Alpine, Turbo, test ids)
const LIB_DATA_ATTR_RE =
  /^data-(?:bs-|toggle$|target$|dismiss$|placement$|original-title$|reactroot$|react-|v-|has-alpine|x-|turbo|turbolinks|testid$|test-?id$|cy$|qa$|tooltip$)/;

const paramWords = (name) =>
  String(name)
    .replace(/^data-/, '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[\s_.\-[\]$:/@]+/)
    .filter(Boolean);

export function interestingParam(name) {
  return paramWords(name).some((w) => PARAM_WORD_RE.test(w));
}

/** "initialMessage" → "data-initial-message" (the attribute behind element.dataset.initialMessage). */
export const dataAttr = (n) => (/^data-/i.test(n) ? n.toLowerCase() : 'data-' + n.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase()));

/** Builds a params finding of the given kind, or null if `name` doesn't look like one. */
export function inputFinding(kind, name, tags = []) {
  const n = String(name ?? '').trim();
  if (!n) return null;
  if (kind === 'header') {
    if (!HEADER_NAME_RE.test(n) || STD_HEADERS.has(n.toLowerCase())) return null;
  } else if (kind === 'storage' || kind === 'cookie') {
    if (!KEY_NAME_RE.test(n)) return null;
  } else if (!PARAM_NAME_RE.test(n)) {
    return null;
  }
  const value = kind === 'data' ? dataAttr(n) : n;
  const t = [...tags];
  if (kind === 'data' && LIB_DATA_ATTR_RE.test(value)) t.push('noise');
  else if (interestingParam(value) && !t.includes('interesting')) t.push('interesting');
  return { value, tags: t, meta: { kind } };
}

// Variables holding a URLSearchParams: `l=new URLSearchParams(location.search)`, `p=url.searchParams`,
// `[q]=useSearchParams()`. Minified bundles read parameters through these (`l.get("x")`).
const SEARCH_PARAMS_VAR_RE =
  /\b([A-Za-z_$][\w$]{0,40})\s*=\s*(?:new\s+URLSearchParams\b|new\s+URL\([^;]{0,200}?\)\.searchParams\b(?!\s*\.)|[\w$.]{0,80}\.searchParams\b(?!\s*\.)|(?:\(0,\s*)?[\w$.]{0,60}\buse(?:Search|Query)Params\)?\s*\()|\[\s*([A-Za-z_$][\w$]{0,40})\s*(?:,[^\]]{0,60})?\]\s*=\s*(?:\(0,\s*)?[\w$.]{0,60}\buse(?:Search|Query)Params\b/g;
let spCache = { code: null, vars: null };

function searchParamVars(code) {
  if (spCache.code === code) return spCache.vars;
  const vars = new Map();
  if (/searchparams|usequeryparams/i.test(code)) {
    SEARCH_PARAMS_VAR_RE.lastIndex = 0;
    let m;
    while ((m = SEARCH_PARAMS_VAR_RE.exec(code))) {
      const v = m[1] || m[2];
      if (!vars.has(v)) vars.set(v, []);
      vars.get(v).push(m.index);
    }
  }
  spCache = { code, vars };
  return vars;
}

function paramFromVar(v, m, ctx) {
  const at = searchParamVars(ctx.code).get(m[1]);
  // the assignment must come shortly before the read (minifiers reuse short names across functions)
  return at && at.some((i) => i < ctx.index && ctx.index - i < 20000) ? inputFinding('query', v) : null;
}

/** `initial_message_url_param: "initial-message"`, `cookieName: "sid"`, `csrfHeaderName: "X-CSRF"` … */
function paramFromConfig(v, m) {
  const key = m[1];
  let kind = 'query';
  if (/cookie/i.test(key)) kind = 'cookie';
  else if (/header/i.test(key)) kind = 'header';
  else if (/storage/i.test(key)) kind = 'storage';
  else if (/dataset|data[_-]?attr|attribute/i.test(key)) kind = 'data';
  if (NOT_A_NAME.has(v.toLowerCase())) return null; // paramType: "string", in: "query" …
  const f = inputFinding(kind, v, ['config']);
  if (f) f.meta.key = key;
  return f;
}

/** Top-level keys of the object literal starting at code[from] (string-aware brace matching). */
function topLevelKeys(code, from, max = 200000) {
  if (code[from] !== '{') return null;
  const keys = [];
  let depth = 0;
  let expectKey = false;
  const end = Math.min(code.length, from + max);
  for (let i = from; i < end; i++) {
    const c = code[i];
    if (c === '"' || c === "'" || c === '`') {
      const start = i;
      for (i++; i < end && code[i] !== c; i++) if (code[i] === '\\') i++;
      if (depth === 1 && expectKey && /^\s*:/.test(code.slice(i + 1, i + 40))) keys.push(code.slice(start + 1, i));
      expectKey = false;
      continue;
    }
    if (c === '{' || c === '[' || c === '(') {
      depth++;
      expectKey = depth === 1;
    } else if (c === '}' || c === ']' || c === ')') {
      if (--depth === 0) return keys;
    } else if (c === ',' && depth === 1) {
      expectKey = true;
    } else if (depth === 1 && expectKey && /[A-Za-z_$]/.test(c)) {
      const k = /^[A-Za-z_$][\w$]*(?=\s*:)/.exec(code.slice(i, i + 80));
      if (k) {
        keys.push(k[0]);
        i += k[0].length - 1;
      }
      expectKey = false;
    }
  }
  return keys;
}

const IGNORED_GLOBALS = /^(?:on\w+|location|name|status|opener|parent|top|self|__REACT_DEVTOOLS\w*|webpack\w*|__webpack\w*|dataLayer|_gaq|ga|gtag)$/;

/** `window.APP_CONFIG = {…}` — server-injected configuration, usually the richest object on the page. */
function globalConfig(v, m, ctx) {
  const name = m[1] || m[2];
  if (IGNORED_GLOBALS.test(name)) return null;
  const at = ctx.index + v.length;
  const keys = topLevelKeys(ctx.code, at);
  if (keys && !keys.length) return null; // `window.x = {}`
  const meta = keys ? { keys: keys.slice(0, 40).join(', ') + (keys.length > 40 ? ` … (+${keys.length - 40})` : '') } : undefined;
  return { value: `window.${name}`, meta };
}

/** `features: { feedback: false, handover: !1 }` → which features are switched off client-side. */
function featureFlags(v, m) {
  const on = [];
  const off = [];
  for (const p of m[2].matchAll(/(?:^|,)\s*(["'`]?)([A-Za-z_$][\w.$-]{0,60})\1\s*:\s*(true|false|!0|!1)\s*(?=,|$)/g)) {
    (p[3] === 'true' || p[3] === '!0' ? on : off).push(p[2]);
  }
  if (!on.length && !off.length) return null;
  const list = [...off.map((k) => `${k}=off`), ...on.map((k) => `${k}=on`)].join(', ');
  return {
    value: `${m[1]}: ${list}`.slice(0, 300),
    severity: off.length ? 'low' : 'info',
    meta: { disabled: off.join(', ') || '—', enabled: on.join(', ') || '—' },
  };
}

// ── postMessage handlers ──

export const POSTMESSAGE_DESC =
  'Any website can send messages to this window (by opening it, or framing it if framing is allowed). Without a strict origin check, message data reaching an HTML, code or navigation sink is DOM XSS; reaching storage, requests or replies to "*" can leak or tamper with data.';

const PM_SINKS = [
  [/\.(?:inner|outer)HTML\s*\+?=(?!=)|\.insertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(|dangerouslySetInnerHTML|\.html\s*\(\s*[^)\s]/, 'HTML injection'],
  [/\b(?:eval|Function)\s*\(|\bset(?:Timeout|Interval)\s*\(\s*[\w$.]*data\b/, 'code execution'],
  [/\blocation(?:\.href)?\s*=(?!=)|\blocation\.(?:assign|replace)\s*\(|\bwindow\.open\s*\(/, 'navigation'],
  [/(?<!location)\.(?:src|href|action)\s*=(?!=)|\.setAttribute\(\s*["'`](?:src|href|action|srcdoc)["'`]/, 'URL / attribute assignment'],
  [/\b(?:local|session)Storage\.setItem\s*\(|\bdocument\.cookie\s*=(?!=)/, 'storage write'],
  [/\bfetch\s*\(|XMLHttpRequest|\.ajax\s*\(|\baxios\b/, 'network request'],
  [/\.postMessage\s*\([^;]{0,300}?,\s*["'`]\*["'`]/, 'replies to "*"'],
];
const DANGEROUS_SINKS = new Set(['HTML injection', 'code execution', 'navigation', 'URL / attribute assignment']);

/** Text of the block starting at code[open] === "{" (string-aware brace matching). */
function braceBlock(code, open, max = 30000) {
  let depth = 0;
  const end = Math.min(code.length, open + max);
  for (let i = open; i < end; i++) {
    const c = code[i];
    if (c === '"' || c === "'" || c === '`') {
      for (i++; i < end && code[i] !== c; i++) if (code[i] === '\\') i++;
    } else if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return code.slice(open, i + 1);
  }
  return null;
}

/** Source of the handler passed at code[at…]: inline function / arrow, or a named function defined elsewhere. */
function handlerSource(code, at) {
  const head = code.slice(at, at + 300);
  const fn = /^(?:async\s+)?(?:function\b[^(]{0,80}\([^)]{0,200}\)|\(?[\w$,\s]{0,80}\)?\s*=>)\s*/.exec(head);
  if (fn) {
    const i = at + fn[0].length;
    if (code[i] === '{') return code.slice(at, i) + (braceBlock(code, i) || '');
    return code.slice(at, at + 600).split(/\)\s*[,;]|\n/)[0]; // expression-bodied arrow
  }
  const ref = /^(?:this\.)?(?:[\w$]+\.)*([\w$]{3,60})(?:\.bind\([^)]{0,80}\))?\s*[,)]/.exec(head);
  if (!ref) return null;
  const n = ref[1].replace(/\$/g, '\\$');
  const def = new RegExp(
    `(?:function\\s+${n}\\s*\\([^)]{0,200}\\)\\s*|[\\s,{;.]${n}\\s*[:=]\\s*(?:async\\s+)?(?:function\\b[^(]{0,80}\\([^)]{0,200}\\)|\\(?[\\w$,\\s]{0,80}\\)?\\s*=>)\\s*|[\\s,{;}]${n}\\s*\\([^)]{0,200}\\)\\s*)\\{`,
  ).exec(code);
  if (!def) return null;
  const open = def.index + def[0].length - 1;
  return def[0].trim() + (braceBlock(code, open)?.slice(1) || '');
}

/**
 * Classifies a message handler's source: how the sender's origin is checked, which message types it
 * handles and which sinks the data can reach. Used for handlers in code and handlers captured at runtime.
 */
export function analyzeMessageHandler(src) {
  const s = String(src || '');
  let origin = 'not checked';
  if (/\.origin\s*[!=]==?|[!=]==?\s*[\w$.]*\.origin\b|(?:allowed|trusted|valid|white|allow)\w*(?:Origins?|Hosts?|List)\w*\s*\.\s*(?:includes|has|indexOf)\s*\(\s*[\w$.]*\.origin|\.source\s*[!=]==?|[!=]==?\s*[\w$.]*\.source\b/i.test(s)) origin = 'checked';
  else if (/\.test\(\s*[\w$.]*\.origin\s*\)|\.origin\s*\.\s*match\s*\(/.test(s)) origin = 'regex (check the anchoring)';
  else if (/\.origin\s*\.\s*(?:indexOf|includes|startsWith|endsWith|search)\s*\(|\.origin\s*\)\s*\.\s*(?:indexOf|includes)|(?:indexOf|includes)\s*\(\s*[\w$.]*\.origin\s*\)/.test(s)) origin = 'weak (substring match)';
  const types = new Set();
  for (const m of s.matchAll(/\.(?:type|action|event|cmd|command|method|name|kind|op|messageType|eventName|topic)\s*[!=]==?\s*["'`]([\w:./@-]{1,60})["'`]/g)) types.add(m[1]);
  for (const m of s.matchAll(/["'`]([\w:./@-]{1,60})["'`]\s*[!=]==?\s*[\w$.]*\.(?:type|action|event|cmd|command|method|name|kind|op)\b/g)) types.add(m[1]);
  for (const m of s.matchAll(/\bcase\s*["'`]([\w:./@-]{1,60})["'`]\s*:/g)) types.add(m[1]);
  const sinks = PM_SINKS.filter(([re]) => re.test(s)).map(([, name]) => name);
  const dangerous = sinks.some((x) => DANGEROUS_SINKS.has(x));
  const unsafe = origin !== 'checked';
  const severity = unsafe ? (dangerous ? 'medium' : 'low') : 'info';
  const label = unsafe ? (origin === 'not checked' ? 'postMessage handler without origin check' : 'postMessage handler with a weak origin check') : 'postMessage handler';
  const t = [...types].slice(0, 12);
  const value = `origin: ${origin} · types: ${t.length ? t.join(', ') : 'any'}${sinks.length ? ' · sinks: ' + sinks.join(', ') : ''}`;
  return { value, severity, label, meta: { origin, types: t.join(', ') || '(not filtered)', sinks: sinks.join(', ') || '—' } };
}

function postMessageFinding(code, at) {
  const src = handlerSource(code, at);
  if (!src) return { value: 'handler defined elsewhere (not resolved)', label: 'postMessage handler', severity: 'info' };
  return analyzeMessageHandler(src);
}

// ── misc intel ──

const FILE_TLD_RE = /^(?:png|jpe?g|gif|svg|webp|ico|js|mjs|cjs|css|map|json|html?|txt|xml|woff2?|ttf|eot|mp[34]|tsx?|jsx|vue|scss|less|min|gz|zip)$/i;

function classifyEmail(v, m, ctx) {
  const prev = ctx.code[ctx.index - 1];
  if (prev === '/' || prev === ':') return null; // credentials inside a URL
  const domain = v.slice(v.indexOf('@') + 1).toLowerCase();
  const tld = domain.slice(domain.lastIndexOf('.') + 1);
  if (FILE_TLD_RE.test(tld)) return null;
  if (/^\d+x\./.test(domain)) return null; // icon@2x.png
  const tags = [];
  if (/(?:^|\.)(?:example|domain|email|test|yourdomain|company|sentry)\.(?:com|org|net|io)$/.test(domain)) {
    tags.push('noise');
  }
  return { value: v.toLowerCase(), tags };
}

function classifyIp(v, m, ctx) {
  const o = v.split('.').map(Number);
  if (o[0] === 0 || o[0] === 255 || o.every((x) => x === 0)) return null;
  const before = ctx.code.slice(Math.max(0, ctx.index - 16), ctx.index);
  if (/(?:version|ver|v)["'`\s:=]{0,3}$/i.test(before)) return null;
  if (o[0] === 10 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168) || (o[0] === 169 && o[1] === 254)) {
    return { label: 'Internal IP Address', severity: 'low' };
  }
  if (o[0] === 127) return { label: 'Loopback IP Address' };
  if (o[0] >= 224) return null; // multicast / reserved
  return true;
}

function htmlComment(v) {
  const t = v.replace(/\s+/g, ' ').trim();
  if (t.length < 4 || /^(?:\[|\]|\/?\$|#|\/?ko\b|v-if|-->|<!)/i.test(t) || /^\[if /i.test(t)) return null;
  if (!/[a-z]{3}/i.test(t)) return null;
  return { value: t.slice(0, 300) };
}

const lower = (v) => ({ value: v.toLowerCase() });

const rule = (id, label, category, severity, re, extra = {}) => ({ id, label, category, severity, re, ...extra });

// ───────────────────────────── rules ─────────────────────────────

export const RULES = [
  // ── Cloud provider credentials ──
  rule('aws-access-key', 'AWS Access Key ID', S, 'high', /\b(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}\b/g, { post: notPlaceholder }),
  rule('aws-secret-key', 'AWS Secret Access Key', S, 'high',
    /(?:(?:aws|amazon)[\w.-]{0,20}?(?:secret|sk)[\w.-]{0,20}?|secret_?access_?key)["'`]?\s*[:=]{1,3}\s*["'`]([A-Za-z0-9/+]{40})["'`]/gi,
    { group: 1, generic: true, post: (v) => notPlaceholder(v) && entropy(v) > 3.5 }),
  rule('aws-mws', 'Amazon MWS Auth Token', S, 'high', /\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g),
  rule('aws-cognito-identity-pool', 'AWS Cognito Identity Pool ID', S, 'medium',
    /\b(?:us|eu|ap|ca|sa|me|af|il|mx)-(?:gov-)?[a-z]{2,12}-\d:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g,
    { desc: 'Try cognito-identity get-id / get-credentials-for-identity to obtain unauthenticated AWS credentials.' }),
  rule('gcp-oauth-secret', 'Google OAuth Client Secret', S, 'high', /\bGOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])/g),
  rule('gcp-api-key', 'Google API Key', S, 'medium', /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g,
    { desc: 'Check which Google APIs accept it (Maps, Places, Gemini, Firebase…) — e.g. with gmapsapiscanner or keyhacks.' }),
  rule('gcp-oauth-token', 'Google OAuth Access Token', S, 'high', /\bya29\.[0-9A-Za-z_-]{20,}/g),
  rule('gcp-service-account', 'GCP Service Account Key (JSON)', S, 'high', /["']type["']\s*:\s*["']service_account["']/g),
  rule('firebase-fcm', 'Firebase Cloud Messaging Server Key', S, 'high', /\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{134}/g),
  rule('azure-storage-conn', 'Azure Storage Connection String', S, 'high',
    /DefaultEndpointsProtocol=https?;AccountName=[^;"'`\s]{1,100};AccountKey=[A-Za-z0-9+/=]{86,88}/g),
  rule('azure-sas', 'Azure SAS Token', S, 'high', /[?&]sv=\d{4}-\d{2}-\d{2}[^"'`\s<>]{0,400}?[?&]sig=[A-Za-z0-9%+/=]{20,}/g),
  rule('alibaba-access-key', 'Alibaba Cloud AccessKey ID', S, 'high', /\bLTAI[A-Za-z0-9]{12,20}\b/g),
  rule('digitalocean', 'DigitalOcean Token', S, 'high', /\bdo[opr]_v1_[a-f0-9]{64}\b/g),
  rule('heroku', 'Heroku API Key', S, 'high',
    /\bheroku[\w.-]{0,20}["'`]?\s*[:=]{1,3}\s*["'`]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["'`]/gi, { group: 1, generic: true }),
  rule('heroku-new', 'Heroku API Key', S, 'high', /\bHRKU-[0-9A-Za-z_-]{60}/g),

  // ── Source control / CI / dev tooling ──
  rule('github-token', 'GitHub Token', S, 'high', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/g),
  rule('github-pat-fine', 'GitHub Fine-grained PAT', S, 'high', /\bgithub_pat_[A-Za-z0-9_]{82}\b/g),
  rule('gitlab-token', 'GitLab Token', S, 'high', /\bgl(?:pat|ptt|rt|dt|ft|soat|cbt|imt|agent|oas)-[A-Za-z0-9_-]{20,}/g),
  rule('npm-token', 'npm Access Token', S, 'high', /\bnpm_[A-Za-z0-9]{36}\b/g),
  rule('pypi-token', 'PyPI Token', S, 'high', /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g),
  rule('atlassian', 'Atlassian API Token', S, 'high', /\bATATT3[A-Za-z0-9_\-=]{180,}/g),
  rule('postman', 'Postman API Key', S, 'high', /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/g),
  rule('linear', 'Linear API Key', S, 'high', /\blin_api_[A-Za-z0-9]{40}\b/g),
  rule('vault', 'HashiCorp Vault Token', S, 'high', /\bhv[sb]\.[A-Za-z0-9_-]{90,}/g),
  rule('doppler', 'Doppler Token', S, 'high', /\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44}\b/g),
  rule('grafana', 'Grafana Token', S, 'high', /\b(?:glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}|glc_[A-Za-z0-9+/]{32,400}={0,2})/g),
  rule('newrelic-key', 'New Relic User API Key', S, 'high', /\bNRAK-[A-Z0-9]{27}\b/g),
  rule('datadog-key', 'Datadog API/App Key', S, 'high',
    /(?:datadog|\bdd)[_-]?(?:api|app(?:lication)?)[_-]?key["'`]?\s*[:=]{1,3}\s*["'`]([a-f0-9]{32,40})["'`]/gi, { group: 1, generic: true }),
  rule('dynatrace', 'Dynatrace Token', S, 'high', /\bdt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b/g),
  rule('contentful', 'Contentful Management Token', S, 'high', /\bCFPAT-[A-Za-z0-9_-]{43}\b/g),

  // ── Messaging / webhooks ──
  rule('slack-token', 'Slack Token', S, 'high', /\bxox[abposre]-[0-9A-Za-z-]{10,250}/g),
  rule('slack-app-token', 'Slack App Token', S, 'high', /\bxapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+\b/g),
  rule('slack-webhook', 'Slack Webhook', S, 'high', /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+/_-]{20,}/g),
  rule('discord-webhook', 'Discord Webhook', S, 'high', /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g),
  rule('teams-webhook', 'Microsoft Teams Webhook', S, 'high', /https:\/\/[a-z0-9-]{1,63}\.webhook\.office\.com\/webhookb2\/[^\s"'`<>]{10,}/g),
  rule('telegram-bot', 'Telegram Bot Token', S, 'high', /\b\d{8,10}:AA[0-9A-Za-z_-]{33}(?![0-9A-Za-z_-])/g),
  rule('discord-bot-token', 'Discord Bot Token', S, 'medium', /\b[MNO][A-Za-z\d_-]{23,25}\.[\w-]{6}\.[\w-]{27,38}\b/g),
  rule('twilio-key', 'Twilio API Key', S, 'medium', /\bSK[0-9a-fA-F]{32}\b/g),
  rule('sendgrid', 'SendGrid API Key', S, 'high', /\bSG\.[\w-]{22}\.[\w-]{43}(?![\w-])/g),
  rule('mailgun', 'Mailgun API Key', S, 'medium', /\bkey-[0-9a-zA-Z]{32}\b/g),
  rule('mailchimp', 'Mailchimp API Key', S, 'high', /\b[0-9a-f]{32}-us\d{1,2}\b/g),

  // ── Payments / commerce ──
  rule('stripe-secret', 'Stripe Secret Key', S, 'high', /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,247}\b/g),
  rule('stripe-webhook-secret', 'Stripe Webhook Secret', S, 'high', /\bwhsec_[a-zA-Z0-9]{32,}\b/g),
  rule('stripe-test', 'Stripe Test Secret Key', S, 'low', /\b(?:sk|rk)_test_[0-9a-zA-Z]{24,247}\b/g),
  rule('square', 'Square Token', S, 'high', /\bsq0(?:atp|csp)-[0-9A-Za-z_-]{22,43}(?![0-9A-Za-z_-])/g),
  rule('braintree', 'Braintree Access Token', S, 'high', /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g),
  rule('shopify', 'Shopify Token', S, 'high', /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g),

  // ── AI providers ──
  rule('openai', 'OpenAI API Key', S, 'high', /\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})/g),
  rule('anthropic', 'Anthropic API Key', S, 'high', /\bsk-ant-(?:api|admin|sid)\d{2}-[A-Za-z0-9_-]{80,}/g),
  rule('huggingface', 'Hugging Face Token', S, 'high', /\bhf_[A-Za-z0-9]{34,40}\b/g),
  rule('groq', 'Groq API Key', S, 'high', /\bgsk_[A-Za-z0-9]{52}\b/g),
  rule('replicate', 'Replicate API Token', S, 'high', /\br8_[A-Za-z0-9]{37}\b/g),

  // ── Social / SaaS ──
  rule('facebook-token', 'Facebook Access Token', S, 'medium', /\bEAA[A-Z][A-Za-z0-9]{80,}/g),
  rule('twitter-bearer', 'Twitter/X Bearer Token', S, 'high', /\bA{21}[A-Za-z0-9%]{30,}/g),
  rule('mapbox-secret', 'Mapbox Secret Token', S, 'high', /\bsk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g),
  rule('algolia', 'Algolia API Key', S, 'medium',
    /algoliasearch\s*\(\s*["'`]([A-Z0-9]{10})["'`]\s*,\s*["'`]([a-f0-9]{32})["'`]/g,
    { group: 2, post: (v, m) => ({ meta: { appId: m[1] } }), desc: 'Check the key ACL: GET https://<appId>-dsn.algolia.net/1/keys/<key>' }),
  rule('algolia-context', 'Algolia API Key', S, 'medium',
    /algolia[\w.-]{0,30}?(?:key|token)["'`]?\s*[:=]{1,3}\s*["'`]([a-f0-9]{32})["'`]/gi, { group: 1, generic: true }),
  rule('cloudinary', 'Cloudinary URL', S, 'high', /\bcloudinary:\/\/\d{15}:[A-Za-z0-9_-]+@[a-z0-9-]+/g),
  rule('airtable', 'Airtable Token', S, 'high', /\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b/g),
  rule('notion', 'Notion Integration Token', S, 'high', /\b(?:secret_[A-Za-z0-9]{43}|ntn_\d{11}[A-Za-z0-9]{35})\b/g),

  // ── Crypto material / credentials ──
  rule('private-key', 'Private Key', S, 'high',
    /-----BEGIN[ A-Z]{0,24}PRIVATE KEY(?: BLOCK)?-----(?:\\[rn]|\s|["'`+,]){0,16}(?:[A-Za-z0-9+/=]{32,}|Proc-Type:)/g,
    { post: (v) => ({ value: v.length > 120 ? v.slice(0, 120) + '…' : v }) }),
  rule('bcrypt-hash', 'Password Hash (bcrypt)', S, 'medium', /\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}/g),
  rule('jwt', 'JSON Web Token', S, 'medium', /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, { post: classifyJwt }),
  rule('db-connection', 'Database Connection String', S, 'high',
    /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqps?|mssql|sqlserver|couchdb|neo4j(?:\+s)?|clickhouse|jdbc:[a-z0-9]{2,12}):\/\/[^\s"'`<>]{3,300}/gi,
    { post: dbConn }),
  rule('sentry-dsn', 'Sentry DSN', I, 'low', /https?:\/\/[a-f0-9]{32}(?::[a-f0-9]{32})?@[a-z0-9.-]{1,120}(?::\d+)?\/\d+/g,
    { post: (v) => (/:[a-f0-9]{32}@/.test(v) ? { severity: 'medium', category: S, label: 'Sentry DSN (with secret)' } : true) }),
  rule('basic-auth-url', 'Credentials in URL', S, 'high',
    /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s/:@"'`<>]{1,64}:[^\s/:@"'`<>]{1,128}@[a-z0-9.-]{1,253}/gi, { post: credsInUrl }),
  rule('bearer-token', 'Hardcoded Bearer Token', S, 'high', /["'`]Bearer\s+([A-Za-z0-9._~+/-]{20,}=*)["'`]/g,
    { group: 1, generic: true, post: (v) => isLikelySecret(v) }),
  rule('basic-auth-header', 'Hardcoded Basic Auth', S, 'high', /["'`]Basic\s+([A-Za-z0-9+/]{8,}={0,2})["'`]/g,
    { group: 1, generic: true, post: basicAuth }),
  rule('generic-secret', 'Hardcoded secret', S, 'medium',
    /\b([A-Za-z0-9_-]{0,30}?(?:api[_-]?key|api[_-]?secret|app[_-]?secret|app[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?key(?:[_-]?id)?|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key|consumer[_-]?(?:key|secret)|master[_-]?key|encryption[_-]?key|signing[_-]?key|passw(?:or)?d|pwd|secret|token))["'`]?\s*[:=]{1,3}\s*["'`]([^"'`\s]{8,256})["'`]/gi,
    {
      group: 2,
      generic: true,
      post: (v, m) => (isLikelySecret(v, /pass|pwd/i.test(m[1])) ? { label: `Hardcoded ${m[1]}`, meta: { key: m[1] } } : null),
      desc: 'Context-based match ("key = value") filtered by Shannon entropy. Expect some false positives.',
    }),

  // ── Cloud assets: AWS ──
  rule('s3-bucket', 'AWS S3 Bucket', C, 'low',
    /\b[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3(?:[.-](?:dualstack\.)?[a-z0-9-]{1,30})?\.amazonaws\.com(?:\.cn)?\b|\bs3(?:[.-][a-z0-9-]{1,30})?\.amazonaws\.com(?:\.cn)?\/[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]|\bs3:\/\/[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]/g,
    { desc: 'Test listing / upload: aws s3 ls s3://<bucket> --no-sign-request' }),
  rule('aws-api-gateway', 'AWS API Gateway', C, 'low', /\b[a-z0-9]{10}\.execute-api\.[a-z0-9-]{1,30}\.amazonaws\.com\b/g),
  rule('aws-lambda-url', 'AWS Lambda Function URL', C, 'low', /\b[a-z0-9]{32}\.lambda-url\.[a-z0-9-]{1,30}\.on\.aws\b/g),
  rule('aws-appsync', 'AWS AppSync API', C, 'low', /\b[a-z0-9]{26}\.appsync-api\.[a-z0-9-]{1,30}\.amazonaws\.com\b/g),
  rule('aws-rds', 'AWS RDS / ElastiCache Host', C, 'low', /\b[a-z0-9][a-z0-9.-]{0,120}\.(?:rds|cache)\.amazonaws\.com\b/g),
  rule('aws-elb', 'AWS Load Balancer', C, 'info', /\b[a-z0-9][a-z0-9.-]{0,120}\.elb\.amazonaws\.com(?:\.cn)?\b/g),
  rule('cloudfront', 'AWS CloudFront Distribution', C, 'info', /\b[a-z0-9]{12,14}\.cloudfront\.net\b/g),
  rule('aws-other', 'AWS Endpoint', C, 'info', /\b[a-z0-9][a-z0-9.-]{0,120}\.amazonaws\.com(?:\.cn)?\b/g),
  rule('aws-cognito-user-pool', 'AWS Cognito User Pool ID', C, 'low', /\b(?:us|eu|ap|ca|sa|me|af|il|mx)-(?:gov-)?[a-z]{2,12}-\d_[A-Za-z0-9]{9}\b/g),
  rule('aws-arn', 'AWS ARN', C, 'info', /\barn:aws[a-z-]{0,10}:[a-z0-9-]{1,40}:[a-z0-9-]{0,30}:\d{12}:[A-Za-z0-9_/:.+=@-]{1,200}/g),

  // ── Cloud assets: Google / Firebase ──
  rule('gcs-bucket', 'Google Cloud Storage Bucket', C, 'low',
    /\bstorage\.(?:googleapis|cloud\.google)\.com\/[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]|\b[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]\.storage\.googleapis\.com\b|\bgs:\/\/[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]/g),
  rule('firebase-db', 'Firebase Realtime Database', C, 'medium',
    /\b[a-z0-9][a-z0-9.-]{0,120}\.(?:firebaseio\.com|firebasedatabase\.app)\b/g,
    { desc: 'Test for open read access: https://<db>/.json' }),
  rule('firebase-storage', 'Firebase Storage Bucket', C, 'low',
    /\bfirebasestorage\.googleapis\.com\/v0\/b\/[a-z0-9._-]{3,222}|\b[a-z0-9][a-z0-9.-]{0,120}\.(?:appspot\.com|firebasestorage\.app)\b/g),
  rule('firebase-app', 'Firebase Project', C, 'info', /\b[a-z0-9-]{1,63}\.firebaseapp\.com\b/g),
  rule('gcp-serverless', 'Google Cloud Functions / Run', C, 'info', /\b[a-z0-9-]{1,63}\.(?:cloudfunctions\.net|a\.run\.app)\b/g),

  // ── Cloud assets: Azure ──
  rule('azure-storage', 'Azure Storage Account', C, 'low', /\b[a-z0-9]{3,24}\.(?:blob|file|queue|table|dfs|web)\.core\.windows\.net\b/g),
  rule('azure-resource', 'Azure Resource', C, 'info',
    /\b[a-z0-9-]{2,63}\.(?:azurewebsites\.net|azure-api\.net|database\.windows\.net|servicebus\.windows\.net|vault\.azure\.net|azurecr\.io|cloudapp\.azure\.com|cloudapp\.net|trafficmanager\.net|azurefd\.net|azureedge\.net|search\.windows\.net|documents\.azure\.com|redis\.cache\.windows\.net|azurestaticapps\.net)\b/g),

  // ── Cloud assets: other providers ──
  rule('do-spaces', 'DigitalOcean Space', C, 'low', /\b[a-z0-9][a-z0-9.-]{0,120}\.digitaloceanspaces\.com\b/g),
  rule('oracle-bucket', 'Oracle Object Storage Bucket', C, 'low',
    /\bobjectstorage\.[a-z0-9-]{1,30}\.oraclecloud\.com\/n\/[A-Za-z0-9_.-]{1,100}\/b\/[A-Za-z0-9_.-]{1,100}/g),
  rule('oracle-cloud', 'Oracle Cloud', C, 'info', /\b[a-z0-9][a-z0-9.-]{0,120}\.oraclecloud(?:apps)?\.com\b/g),
  rule('alibaba', 'Alibaba Cloud', C, 'info', /\b[a-z0-9][a-z0-9.-]{0,120}\.aliyuncs\.com\b/g, {
    post: (v) => (/\.oss(?:-[a-z0-9-]+)?\.aliyuncs\.com$/.test(v) && !/^oss-/.test(v) ? { label: 'Alibaba OSS Bucket', severity: 'low' } : true),
  }),
  rule('rackspace', 'Rackspace Cloud Files', C, 'low', /\b[a-z0-9][a-z0-9.-]{0,120}\.(?:rackcdn\.com|clouddrive\.com)\b/g),
  rule('dreamhost', 'DreamHost DreamObjects', C, 'low', /\b[a-z0-9][a-z0-9.-]{0,120}\.(?:dream\.io|dreamhosters\.com)\b/g),
  rule('object-storage-other', 'Object Storage', C, 'low',
    /\b[a-z0-9][a-z0-9.-]{0,120}\.(?:wasabisys\.com|backblazeb2\.com|r2\.cloudflarestorage\.com|r2\.dev|linodeobjects\.com|cloud-object-storage\.appdomain\.cloud)\b/g),
  rule('supabase', 'Supabase Project', C, 'low', /\b[a-z0-9]{20}\.supabase\.(?:co|in)\b/g),
  rule('paas-host', 'PaaS / Serverless Host', C, 'info',
    /\b[a-z0-9][a-z0-9-]{0,62}\.(?:herokuapp\.com|vercel\.app|netlify\.app|pages\.dev|workers\.dev|onrender\.com|fly\.dev|railway\.app|ondigitalocean\.app)\b/g),

  // ── Public / client-side identifiers (intel) ──
  rule('gcp-oauth-client', 'Google OAuth Client ID', I, 'info', /\b\d{6,}-[0-9a-z_]{32}\.apps\.googleusercontent\.com\b/g),
  rule('twilio-sid', 'Twilio Account SID', I, 'low', /\bAC[a-f0-9]{32}\b/g),
  rule('stripe-publishable', 'Stripe Publishable Key', I, 'info', /\bpk_live_[0-9a-zA-Z]{24,247}\b/g),
  rule('mapbox-public', 'Mapbox Public Token', I, 'info', /\bpk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g),
  rule('newrelic-browser', 'New Relic Browser Key', I, 'info', /\bNRJS-[a-f0-9]{19}\b/g),
  rule('datadog-client-token', 'Datadog Client Token', I, 'info', /\bpub[a-f0-9]{32}\b/g),
  rule('razorpay', 'Razorpay Key ID', I, 'low', /\brzp_live_[A-Za-z0-9]{14}\b/g),

  // ── Recon intel ──
  rule('ip', 'IP Address', I, 'info',
    /(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w.])/g, { post: classifyIp }),
  rule('email', 'Email Address', I, 'info', /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,6}\.[A-Za-z]{2,24}\b/g,
    { post: classifyEmail }),
  rule('graphql-op', 'GraphQL Operation', I, 'info', /\b(query|mutation|subscription)\s+([A-Za-z_]\w{1,80})\s*[({]/g,
    { post: (v, m) => ({ value: `${m[1]} ${m[2]}` }) }),
  rule('dev-comment', 'Developer Comment', I, 'info',
    /(?:\/\/|\/\*+|<!--)[ \t]*(?:TODO|FIXME|HACK|XXX|BUG|SECURITY|TEMP|DEPRECATED)\b[^\n]{0,160}/g,
    { post: (v) => ({ value: v.replace(/\s*(?:\*\/|-->)[\s\S]*$/, '').trim() }) }),
  rule('html-comment', 'HTML Comment', I, 'info', /<!--([\s\S]{4,600}?)-->/g, { group: 1, post: htmlComment }),
  // window message handlers only (not WebSocket / MessagePort / Worker): origin check, message types, sinks
  rule('postmessage-listener', 'postMessage handler', I, 'info',
    /(?:\b(?:window|self|top|globalThis)\s*\.\s*|(?<![\w$.]))addEventListener\(\s*["'`]message["'`]\s*,\s*|\b(?:window|self)\s*\.\s*onmessage\s*=(?!=)\s*/g,
    { post: (v, m, ctx) => postMessageFinding(ctx.code, ctx.index + v.length), desc: POSTMESSAGE_DESC }),
  rule('postmessage-wildcard', 'postMessage with "*" targetOrigin', I, 'low',
    /\.postMessage\([^;]{0,300}?,\s*["'`]\*["'`]\s*\)/g, { post: ctxValue }),

  rule('global-config', 'Injected config object', I, 'info',
    /\bwindow\s*(?:\.\s*([A-Za-z_$][\w$]{2,60})|\[\s*["'`]([A-Za-z_$][\w$]{2,60})["'`]\s*\])\s*=\s*(?=\{|JSON\.parse\()/g,
    { post: globalConfig, desc: 'Configuration the server injects into the page. Its keys are often accepted as parameters or overrides.' }),
  rule('feature-flags', 'Feature flags', I, 'info',
    /["'`]?\b(features|featureFlags|feature_flags|featureToggles|feature_toggles|flags|toggles|experiments)["'`]?\s*:\s*\{([^{}]{3,3000})\}/g,
    { post: featureFlags, desc: 'Features switched off on the client often still exist on the server. Look for their endpoints and try enabling them.' }),

  // ── Parameters and other client-side inputs (meta.kind says which) ──
  rule('param-read', 'Query parameter read', 'params', 'info',
    /\b(?:searchParams|URLSearchParams\([^)]{0,80}\)|query|params|queryParams|queryParamMap|paramMap)\.(?:get|getAll|has)\(\s*["'`]([A-Za-z_$][\w.[\]$-]{0,60})["'`]/g,
    { group: 1, post: (v) => inputFinding('query', v) }),
  // l=new URLSearchParams(location.search); … l.get("debug")
  rule('param-var', 'Query parameter read', 'params', 'info',
    /\b([A-Za-z_$][\w$]{0,40})\.(?:get|getAll|has)\(\s*(["'`])([A-Za-z_$][\w.[\]$-]{0,60})\2\s*\)/g,
    { group: 3, post: paramFromVar }),
  // this.$route.query.redirect, router.query.id, route.query["next"]
  rule('param-router', 'Query parameter read', 'params', 'info',
    /(?:\$route|\broute|\brouter|\bRoute\(\)|\bRouter\(\))\.query(?:\.([A-Za-z_$][\w$]{0,60})(?![\w$(])|\[\s*(["'`])([^"'`\s]{1,60})\2\s*\])/g,
    { post: (v, m) => inputFinding('query', m[1] || m[3]) }),
  // getParameterByName("x"), getUrlParam("x"), getQueryVariable("x")
  rule('param-getter', 'Query parameter read', 'params', 'info',
    /\b(?:get(?:Url|URL|Query|Search|Request)?Param(?:eter)?(?:ByName|Value|FromUrl)?|getQuery(?:Variable|String|Value)|getUrlVars?|urlParam|queryParam|readParam)\(\s*(["'`])([A-Za-z_$][\w.[\]$-]{0,60})\1(?=\s*[,)])/g,
    { group: 2, post: (v) => inputFinding('query', v) }),
  // an opening quote only: in `string`?x=… (minified ternary) the backtick closes a literal
  rule('param-string', 'Query parameter', 'params', 'info', /(?<![\w$])["'`][?&]([A-Za-z_][\w.[\]-]{0,40})=/g,
    { group: 1, post: (v) => inputFinding('query', v) }),
  // /[?&]token=([^&]*)/
  rule('param-regex', 'Query parameter (regex)', 'params', 'info', /\[(?:\\{0,2}[?&#]){2,3}\]\)?([A-Za-z_][\w.-]{0,40})=/g,
    { group: 1, post: (v) => inputFinding('query', v) }),
  // initial_message_url_param: "initial-message", redirectParam: "next", cookieName || "sid"
  rule('param-config', 'Parameter name in config', 'params', 'info',
    /["'`]?\b((?:[A-Za-z_$][\w$-]{0,60}?)?(?:param(?:eter)?(?:[_-]?(?:name|key))?|cookie[_-]?(?:name|key)|header[_-]?(?:name|key)|storage[_-]?key))["'`]?\s*(?::|=(?!=)|\|\|)\s*["'`]([^"'`\s]{1,80})["'`]/gi,
    { group: 2, post: paramFromConfig }),
  rule('data-attr', 'data-* attribute read', 'params', 'info',
    /\.dataset\.([A-Za-z_$][\w$]{0,60})\b|\.dataset\[\s*(["'`])([\w-]{1,60})\2\s*\]|\b(?:get|has)Attribute\(\s*(["'`])(data-[\w-]{1,60})\4(?=\s*[,)])/g,
    { post: (v, m) => inputFinding('data', m[1] || m[3] || m[5]) }),
  rule('storage-key', 'Web storage key', 'params', 'info',
    /\b(local|session)Storage\s*(?:\.\s*(?:getItem|setItem|removeItem)\(\s*(["'`])([^"'`\s]{1,80})\2(?=\s*[,)])|\[\s*(["'`])([^"'`\s]{1,80})\4\s*\])/g,
    { post: (v, m) => inputFinding('storage', m[3] || m[5], m[1] === 'session' ? ['session'] : []) }),
  rule('cookie-name', 'Cookie', 'params', 'info',
    /\bdocument\.cookie\s*=\s*(["'`])([^"'`\s=;]{1,60})=|(?:\b(?:get|read|set|remove|delete|has|erase)_?[Cc]ookie(?:Value)?|\bCookies?\.(?:get|set|remove)|\bcookies\(\)\.(?:get|set|has|delete)|\$\.(?:cookie|removeCookie))\(\s*(["'`])([^"'`\s=;,]{1,80})\3(?=\s*[,)])/g,
    { post: (v, m) => inputFinding('cookie', m[2] || m[4]) }),
  rule('request-header', 'Request header', 'params', 'info',
    /\b(?:setRequestHeader|[Hh]eaders?\.(?:set|append|get|has))\(\s*(["'`])([A-Za-z][\w-]{1,60})\1|(["'`])(X-[A-Za-z][\w-]{1,60})\3/g,
    { post: (v, m) => inputFinding('header', m[2] || m[4]) }),
  rule('request-header-obj', 'Request header', 'params', 'info', /\bheaders\s*:\s*\{([^{}]{1,800})\}/g, {
    group: 1,
    post: (v) => {
      const out = [];
      for (const k of v.matchAll(/(?:^|,)\s*(["'`]?)([A-Za-z][\w-]{1,60})\1\s*:/g)) {
        // header-like keys only: quoted, hyphenated or capitalised (not `enumerable`, `get` …)
        if (!k[1] && !/-|^[A-Z]/.test(k[2])) continue;
        const f = inputFinding('header', k[2]);
        if (f) out.push(f);
      }
      return out;
    },
  }),
  // <input type="hidden" name="csrf" value="…">
  rule('form-field', 'Form field', 'params', 'info', /<(?:input|select|textarea|button)\b[^<>]{0,600}>/gi, {
    post: (v) => {
      const name = /\bname\s*=\s*(["']?)([^"'\s>]{1,80})\1/i.exec(v);
      if (!name) return null;
      const hidden = /\btype\s*=\s*["']?hidden\b/i.test(v);
      const f = inputFinding('form', name[2], hidden ? ['hidden'] : []);
      const val = hidden && /\bvalue\s*=\s*(["'])([^"']{1,200})\1/i.exec(v);
      if (f && val) f.meta.example = val[2];
      return f;
    },
  }),

  // ── API endpoints with HTTP method ──
  // axios.post("/x"), http.get<T>(`${base}/x`), $.post(url), router.delete("/x"), api.patch(base + "/x")
  rule('api-call', 'API call', A, 'info',
    /\.(get|post|put|delete|patch|head|options|getJSON|del)\s*(?:<[^<>()]{0,80}>)?\s*\(\s*(?:([A-Za-z_$][\w.$]{0,60})\s*\+\s*)?(["'`])([^"'`\s]{1,1000})\3/g,
    { group: 4, post: (v, m) => apiEndpoint(m[1] === 'getJSON' ? 'GET' : m[1] === 'del' ? 'DELETE' : m[1], m[4], m[2]) }),
  // fetch("/x", { method: "POST" }), new Request(...), request("/x", { method: "PUT" })
  rule('api-fetch', 'API call', A, 'info',
    /\b([\w$.]{1,60})\(\s*(?:([A-Za-z_$][\w.$]{0,60})\s*\+\s*)?(["'`])([^"'`\s]{1,1000})\3(\s*,\s*\{)?/g,
    { group: 4, post(v, m, ctx) { return apiFromCall.call(ctx, v, m); } }),
  // xhr.open("POST", "/x"), new HttpRequest("PUT", "/x")
  rule('api-xhr', 'API call', A, 'info',
    /(?:\.open|\bHttpRequest)\(\s*(["'`])([A-Za-z]{3,7})\1\s*,\s*(?:([A-Za-z_$][\w.$]{0,60})\s*\+\s*)?(["'`])([^"'`\s]{1,1000})\4/g,
    { group: 5, post: (v, m) => apiEndpoint(m[2], m[5], m[3]) }),
  // $.ajax({ type: "POST", url: "/x" }), axios({ method: "put", url: "/x" })
  rule('api-config', 'API call', A, 'info',
    /\bmethod\s*:\s*(["'`])(get|post|put|delete|patch|GET|POST|PUT|DELETE|PATCH)\1|\btype\s*:\s*(["'`])(GET|POST|PUT|DELETE|PATCH)\3/g,
    { post: apiFromConfig }),

  // ── Endpoints & URLs ──
  rule('link', 'Endpoint', 'endpoints', 'info', LINK_RE, { group: 2, post: classifyLink }),
  rule('url-bare', 'URL', 'urls', 'info', /\b(?:https?|wss?):\/\/[^\s"'`<>()\\{}|^[\]]{3,2000}/g,
    { post: (v) => classifyLink(v.replace(/[.,;:!?$]+$/, '')) }),
  // "api.acme.io/v1/users" (no scheme) → //api.acme.io/v1/users
  rule('url-schemeless', 'URL', 'urls', 'info',
    /(["'`])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,8}([a-z]{2,24})(?::\d{2,5})?\/[^"'`\s<>]{0,2000})\1/g,
    { group: 2, post: schemelessUrl }),

  // ── Dependencies (for dependency-confusion checks) ──
  rule('dep-node-modules', 'npm dependency', D, 'info',
    /node_modules\/((?:@[a-z0-9][a-z0-9._~-]{0,100}\/)?[a-z0-9][a-z0-9._~-]{0,213})(?=\/)/g,
    { group: 1, post: (v) => { const n = packageRoot(v); return n ? depFinding(n, 'node_modules path') : null; } }),
  rule('dep-import', 'npm dependency', D, 'info',
    /\b(?:require|import)\s*\(\s*(["'`])([^"'`\s]{1,214})\1\s*\)|\b(?:import|export)\b[^;"'`()]{0,200}?\bfrom\s*(["'])([^"'`\s]{1,214})\3|\bimport\s+(["'])([^"'`\s]{1,214})\5/g,
    { post: (v, m) => { const n = packageRoot(m[2] || m[4] || m[6]); return n ? depFinding(n, 'import') : null; } }),
  rule('dep-package-json', 'npm dependency', D, 'info',
    /"(?:dependencies|devDependencies|peerDependencies|optionalDependencies)"\s*:\s*\{([^{}]{1,20000})\}/g,
    { group: 1, post: depsFromPackageJson }),

  // ── DOM XSS sinks (off by default – noisy) ──
  rule('sink-innerhtml', 'innerHTML / outerHTML assignment', 'sinks', 'info', /\.(?:inner|outer)HTML\s*\+?=(?!=)/g, { enabled: false, post: ctxValue }),
  rule('sink-insertadjacent', 'insertAdjacentHTML', 'sinks', 'info', /\.insertAdjacentHTML\s*\(/g, { enabled: false, post: ctxValue }),
  rule('sink-docwrite', 'document.write', 'sinks', 'info', /\bdocument\.write(?:ln)?\s*\(/g, { enabled: false, post: ctxValue }),
  rule('sink-eval', 'eval / Function / string timer', 'sinks', 'info',
    /\b(?:eval|Function)\s*\(|\bset(?:Timeout|Interval)\s*\(\s*["'`]/g, { enabled: false, post: ctxValue }),
  rule('sink-react', 'dangerouslySetInnerHTML', 'sinks', 'info', /dangerouslySetInnerHTML/g, { enabled: false, post: ctxValue }),
  rule('sink-location', 'location assignment', 'sinks', 'info',
    /\b(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=(?!=)/g, { enabled: false, post: ctxValue }),
  rule('sink-jquery', 'jQuery HTML sink', 'sinks', 'info',
    /\$\([^)]{0,80}\)\.(?:html|append|prepend|after|before|replaceWith|wrap)\(\s*[^)\s'"`]/g, { enabled: false, post: ctxValue }),
  rule('source-dom', 'DOM XSS source', 'sinks', 'info',
    /\b(?:location\.(?:hash|search)|document\.(?:URL|documentURI|referrer)|window\.name)\b/g, { enabled: false, post: ctxValue }),
];

// ───────────────────────────── per-host rules ─────────────────────────────

/** Rule that finds subdomains of `site` (e.g. "acme.com") anywhere in the code, not only inside URLs. */
export function makeSubdomainRule(site) {
  const esc = site.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return {
    id: 'subdomain',
    label: 'Subdomain',
    category: 'subdomains',
    severity: 'info',
    re: new RegExp(`(?<![a-z0-9-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.){1,8}${esc}(?![a-z0-9-]|\\.[a-z0-9])`, 'gi'),
    post(v, m, ctx) {
      let h = v.toLowerCase();
      // drop the escape residue of "\napi.acme.com" or "%2Fapi.acme.com"
      if (ctx.code[ctx.index - 1] === '\\') h = h.slice(1);
      else if (/^[0-9a-f]{2}/.test(h) && ctx.code[ctx.index - 1] === '%') h = h.slice(2);
      if (!h.endsWith('.' + site) || h.startsWith('.') || h.startsWith('-')) return null;
      const tags = [];
      if (DEV_HOST_RE.test(h.slice(0, -site.length - 1))) tags.push('interesting');
      if (CLOUD_HOST_RE.test(h)) tags.push('cloud');
      return { value: h, tags };
    },
  };
}

// ───────────────────────────── custom rules ─────────────────────────────

/**
 * One rule per line:  Name | severity | regex      (regex may be written as /pattern/flags)
 * Lines starting with # are comments. If the regex has a capture group, group 1 is the value.
 */
export function parseCustomRules(text) {
  const rules = [];
  const errors = [];
  String(text || '').split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    const p1 = line.indexOf('|');
    const p2 = p1 < 0 ? -1 : line.indexOf('|', p1 + 1);
    if (p1 < 0 || p2 < 0) {
      errors.push(`Line ${i + 1}: expected "Name | severity | regex"`);
      return;
    }
    const name = line.slice(0, p1).trim();
    const severity = line.slice(p1 + 1, p2).trim().toLowerCase();
    const src = line.slice(p2 + 1).trim();
    if (!name) return errors.push(`Line ${i + 1}: missing name`);
    if (!(severity in SEV_RANK)) return errors.push(`Line ${i + 1}: severity must be critical, high, medium, low or info`);
    let pattern = src;
    let flags = 'g';
    const lit = /^\/(.+)\/([dgimsuy]*)$/s.exec(src);
    if (lit) {
      pattern = lit[1];
      flags = [...new Set((lit[2] + 'g').split(''))].join('');
    }
    try {
      const re = new RegExp(pattern, flags);
      if (new RegExp(pattern, flags.replace('g', '')).test('')) {
        errors.push(`Line ${i + 1}: regex matches the empty string`);
        return;
      }
      const groups = new RegExp(pattern + '|', flags.replace('g', '')).exec('').length - 1;
      rules.push({
        id: `custom-${i + 1}`,
        label: name,
        category: severity === 'info' ? I : S,
        severity,
        re,
        group: groups > 0 ? 1 : 0,
        custom: true,
      });
    } catch (e) {
      errors.push(`Line ${i + 1}: ${e.message}`);
    }
  });
  return { rules, errors };
}

/** Compile the active rule list for the given settings. Custom rules run first. */
export function buildRules(settings = {}) {
  const overrides = settings.ruleOverrides || {};
  const builtin = RULES.filter((r) => (r.id in overrides ? !!overrides[r.id] : r.enabled !== false));
  const { rules: custom } = parseCustomRules(settings.customRules);
  return [...custom, ...builtin];
}
