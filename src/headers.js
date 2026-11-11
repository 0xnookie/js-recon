// Response-header analysis. Pure: no chrome.* APIs, so it can be unit-tested with Node.
//
// The service worker passes the headers of the target's own responses (pages, frames, XHR/fetch).
// Results have the same shape as analyzer.js findings, so they merge into the same store.
//
//   Access-Control-Allow-Headers  → request headers the API accepts (Params tab, kind "header")
//   Content-Security-Policy       → every host the app talks to (Domains) + weak script-src (Intel)
//   Access-Control-Allow-Origin   → trusted origins (Domains) + "null" origin (Intel)
//   Set-Cookie                    → cookie names (Params tab, kind "cookie")
//   Server, X-Powered-By, …       → technology / version banners (Intel)
//   unusual X-… headers           → custom response headers (Intel)
//   Report-To, NEL, Link          → reporting / preconnect URLs (URLs)

import { inputFinding, classifyLink } from './rules.js';

const STANDARD = new Set([
  'accept-ranges', 'access-control-allow-credentials', 'access-control-allow-headers', 'access-control-allow-methods',
  'access-control-allow-origin', 'access-control-expose-headers', 'access-control-max-age', 'age', 'allow', 'alt-svc',
  'cache-control', 'clear-site-data', 'connection', 'content-disposition', 'content-encoding', 'content-language',
  'content-length', 'content-location', 'content-range', 'content-security-policy', 'content-security-policy-report-only',
  'content-type', 'cross-origin-embedder-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy', 'date',
  'etag', 'expect-ct', 'expires', 'keep-alive', 'last-modified', 'link', 'location', 'nel', 'origin-agent-cluster',
  'permissions-policy', 'pragma', 'referrer-policy', 'report-to', 'reporting-endpoints', 'retry-after', 'server',
  'server-timing', 'set-cookie', 'strict-transport-security', 'timing-allow-origin', 'trailer', 'transfer-encoding',
  'upgrade', 'vary', 'via', 'www-authenticate', 'x-content-type-options', 'x-dns-prefetch-control', 'x-frame-options',
  'x-xss-protection', 'x-permitted-cross-domain-policies', 'x-download-options', 'x-ua-compatible', 'feature-policy',
  'document-policy', 'accept-ch', 'critical-ch', 'priority', 'x-robots-tag', 'status', 'p3p', 'x-request-id',
  'x-correlation-id', 'x-trace-id', 'traceparent', 'tracestate', 'x-cache', 'x-cache-hits', 'x-timer', 'x-content-duration',
  'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset', 'ratelimit-limit', 'ratelimit-remaining',
  'ratelimit-reset', 'ratelimit-policy', 'speculation-rules', 'supports-loading-mode', 'observe-browsing-topics',
]);

// Banners whose value is stable and tells you what runs on the server
const BANNERS = new Set([
  'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'via', 'x-backend-server',
  'x-served-by', 'x-upstream', 'x-server', 'x-app-version', 'x-version', 'x-api-version', 'x-amz-bucket-region',
  'x-redirect-by', 'x-drupal-cache', 'x-litespeed-cache', 'x-turbo-charged-by', 'x-framework', 'x-runtime-version',
]);

// Presence of these headers identifies the platform (their values change on every request)
const PLATFORMS = [
  [/^cf-(?:ray|cache-status)$/, 'Cloudflare'],
  [/^x-amz-cf-(?:id|pop)$/, 'Amazon CloudFront'],
  [/^x-amz-(?:request-id|id-2)$/, 'Amazon S3'],
  [/^x-amzn-(?:requestid|trace-id)$|^x-amz-apigw-id$/, 'AWS API Gateway / Lambda'],
  [/^x-azure-ref$|^x-fd-healthprobe$/, 'Azure Front Door'],
  [/^x-ms-request-id$|^x-ms-version$/, 'Azure'],
  [/^x-goog-|^x-guploader-uploadid$|^x-cloud-trace-context$/, 'Google Cloud'],
  [/^x-vercel-/, 'Vercel'],
  [/^x-nf-request-id$/, 'Netlify'],
  [/^fly-request-id$/, 'Fly.io'],
  [/^x-github-request-id$/, 'GitHub (github.com / Pages)'],
  [/^x-fastly-|^fastly-/, 'Fastly'],
  [/^x-akamai-|^akamai-/, 'Akamai'],
  [/^x-envoy-/, 'Envoy proxy'],
  [/^x-kong-/, 'Kong API gateway'],
  [/^x-varnish$/, 'Varnish'],
  [/^x-drupal-/, 'Drupal'],
  [/^x-pingback$/, 'WordPress (xmlrpc.php)'],
  [/^x-shopify-|^x-shopid$/, 'Shopify'],
  [/^x-wix-/, 'Wix'],
  [/^x-jenkins|^x-hudson/, 'Jenkins'],
  [/^x-gitlab-/, 'GitLab'],
  [/^x-litespeed-/, 'LiteSpeed'],
  [/^x-sucuri-/, 'Sucuri WAF'],
  [/^x-iinfo$|^x-cdn$/, 'Imperva / Incapsula'],
  [/^x-heroku-|^heroku-/, 'Heroku'],
  [/^x-render-origin-server$/, 'Render'],
  [/^x-railway-/, 'Railway'],
  [/^x-matched-path$|^x-nextjs-/, 'Next.js'],
  [/^x-nuxt-/, 'Nuxt'],
];

// custom response headers that hint at internals worth a closer look
const JUICY_HEADER_RE = /debug|trace|internal|backend|upstream|origin|real-?ip|forwarded|env|stage|staging|node|pod|host|instance|cluster|version|build|commit|branch|user|role|tenant|admin/i;

// script-src hosts that serve JSONP or arbitrary user content (classic CSP bypass gadgets)
const CSP_BYPASS_HOSTS =
  /^(?:\*\.)?(?:googleapis\.com|ajax\.googleapis\.com|www\.google\.com|google\.com|accounts\.google\.com|gstatic\.com|cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|raw\.githubusercontent\.com|github\.io|githubusercontent\.com|herokuapp\.com|appspot\.com|firebaseapp\.com|cloudfront\.net|amazonaws\.com|azurewebsites\.net|blob\.core\.windows\.net|vercel\.app|netlify\.app|pages\.dev|workers\.dev|yandex\.st|bootstrapcdn\.com|code\.jquery\.com)$/i;

const SESSION_COOKIE_RE = /sess|sid$|^sid|auth|token|jwt|login|remember|csrf|xsrf/i;

const ctx = (name, value) => ['', `${name}: ${String(value).replace(/\s+/g, ' ').slice(0, 400)}`, ''];

function finding(rule, label, category, severity, value, extra = {}) {
  return { rule, label, category, severity, value, tags: extra.tags || [], meta: extra.meta, desc: extra.desc, line: 0, col: 0, ctx: extra.ctx, hits: 1 };
}

/** "https://*.acme.com:443/path" → "*.acme.com"; null for keywords, schemes and nonces. */
function cspHost(token) {
  const t = token.trim();
  if (!t || /^'/.test(t) || /^[a-z][a-z0-9+.-]*:$/i.test(t) || t === '*') return null;
  const m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?(\*\.)?([a-z0-9.-]+\.[a-z]{2,63}|localhost)(?::(?:\d+|\*))?(?:\/.*)?$/i.exec(t);
  return m ? ((m[1] || '') + m[2]).toLowerCase() : null;
}

function parseCsp(policy) {
  const dirs = new Map();
  for (const part of policy.split(';')) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name && !dirs.has(name.toLowerCase())) dirs.set(name.toLowerCase(), vals);
  }
  return dirs;
}

function analyzeCsp(name, policy, out) {
  const report = name.endsWith('report-only');
  const dirs = parseCsp(policy);
  const hosts = new Map(); // host → directives
  for (const [dir, vals] of dirs) {
    if (dir === 'report-uri') {
      for (const v of vals) {
        const l = classifyLink(v);
        if (l) out.push(finding('csp-report-uri', 'CSP report endpoint', l.category, 'info', v, { tags: [...l.tags, 'csp'], ctx: ctx(name, policy) }));
      }
      continue;
    }
    for (const v of vals) {
      const h = cspHost(v);
      if (!h) continue;
      if (!hosts.has(h)) hosts.set(h, new Set());
      hosts.get(h).add(dir);
    }
  }
  for (const [h, set] of hosts) {
    out.push(finding('csp-host', 'Host in Content-Security-Policy', 'subdomains', 'info', h, { tags: ['csp'], meta: { directives: [...set].join(', ') }, ctx: ctx(name, policy) }));
  }
  // weaknesses only matter for an enforced policy
  if (report) return;
  const script = dirs.get('script-src-elem') || dirs.get('script-src') || dirs.get('default-src');
  if (!script) return;
  const vals = script.map((v) => v.toLowerCase());
  const nonceOrHash = vals.some((v) => /^'(?:nonce|sha256|sha384|sha512)-/.test(v));
  const strictDynamic = vals.includes("'strict-dynamic'");
  const weak = [];
  if (vals.includes("'unsafe-inline'") && !nonceOrHash) weak.push("'unsafe-inline'");
  if (vals.includes("'unsafe-eval'")) weak.push("'unsafe-eval'");
  if (!strictDynamic) {
    for (const v of vals) if (v === '*' || v === 'https:' || v === 'http:' || v === 'data:') weak.push(v);
    const gadgets = vals.map(cspHost).filter((h) => h && CSP_BYPASS_HOSTS.test(h));
    if (gadgets.length) weak.push(...gadgets);
  }
  if (!weak.length) return;
  out.push(
    finding('csp-weak', 'Weak Content-Security-Policy (script-src)', 'intel', 'low', `script-src allows ${weak.join(' ')}`, {
      ctx: ctx(name, policy),
      desc: "Scripts can still be injected despite the CSP: inline scripts / eval, any host, or hosts that serve JSONP or user content (CSP bypass gadgets). Matters as soon as you find an HTML injection.",
    }),
  );
}

/**
 * @param {Array<{name: string, value?: string}>} headers  as delivered by chrome.webRequest
 * @param {{url: string, pageOrigin?: string, statusCode?: number}} info
 * @returns {Array} findings in analyzer.js shape
 */
export function analyzeHeaders(headers, info = {}) {
  const out = [];
  const list = (headers || []).filter((h) => h && h.name).map((h) => ({ name: h.name, lower: h.name.toLowerCase(), value: String(h.value ?? '') }));
  const get = (n) => list.find((h) => h.lower === n)?.value;
  const platforms = new Set();

  for (const { name, lower, value } of list) {
    if (lower === 'access-control-allow-headers') {
      for (const hn of value.split(',').map((s) => s.trim()).filter((s) => s && s !== '*')) {
        const f = inputFinding('header', hn, ['cors']);
        if (f) out.push(finding('cors-allow-headers', 'Request header (CORS)', 'params', 'info', f.value, { tags: f.tags, meta: f.meta, ctx: ctx(name, value) }));
      }
    } else if (lower === 'access-control-expose-headers') {
      const custom = value.split(',').map((s) => s.trim()).filter((s) => s && s !== '*' && !STANDARD.has(s.toLowerCase()));
      if (custom.length) out.push(finding('cors-expose-headers', 'CORS exposed response headers', 'intel', 'info', custom.sort().join(', '), { ctx: ctx(name, value) }));
    } else if (lower === 'access-control-allow-origin') {
      const creds = /^true$/i.test(get('access-control-allow-credentials') || '');
      if (value.trim() === 'null') {
        out.push(finding('cors-null-origin', 'CORS trusts the "null" origin', 'intel', creds ? 'medium' : 'low', `Access-Control-Allow-Origin: null${creds ? ' (with credentials)' : ''}`, {
          ctx: ctx(name, value),
          desc: 'Sandboxed iframes and data: URLs send "Origin: null", so any website can read these responses' + (creds ? ' with the victim’s cookies.' : '.'),
        }));
      } else {
        const m = /^https?:\/\/([^/:]+)/i.exec(value.trim());
        if (m && (!info.pageOrigin || !info.pageOrigin.includes('//' + m[1]))) {
          out.push(finding('cors-origin', 'Trusted origin (CORS)', 'subdomains', 'info', m[1].toLowerCase(), { tags: ['cors'], meta: { credentials: creds }, ctx: ctx(name, value) }));
        }
      }
    } else if (lower === 'access-control-allow-methods') {
      const methods = value.toUpperCase().split(',').map((s) => s.trim()).filter(Boolean);
      if (methods.some((x) => ['PUT', 'DELETE', 'PATCH'].includes(x))) {
        out.push(finding('cors-methods', 'CORS allows write methods', 'intel', 'info', methods.join(', '), { ctx: ctx(name, value) }));
      }
    } else if (lower === 'content-security-policy' || lower === 'content-security-policy-report-only') {
      analyzeCsp(lower, value, out);
    } else if (lower === 'set-cookie') {
      const [pair, ...attrs] = value.split(';');
      const cname = pair.split('=')[0].trim();
      const flags = attrs.map((a) => a.trim()).filter((a) => !/^(?:expires|max-age|domain)=/i.test(a));
      const tags = ['set-cookie'];
      if (SESSION_COOKIE_RE.test(cname) && !flags.some((a) => /^httponly$/i.test(a))) tags.push('no-httponly');
      const f = inputFinding('cookie', cname, tags);
      if (f) out.push(finding('set-cookie', 'Cookie (Set-Cookie)', 'params', 'info', f.value, { tags: f.tags, meta: { ...f.meta, example: flags.join('; ') || '(no attributes)' }, ctx: ctx(name, `${cname}=…; ${flags.join('; ')}`) }));
    } else if (lower === 'www-authenticate') {
      out.push(finding('www-authenticate', 'HTTP authentication', 'intel', 'low', value.slice(0, 200), { ctx: ctx(name, value) }));
    } else if (lower === 'report-to' || lower === 'nel' || lower === 'reporting-endpoints' || lower === 'link') {
      for (const u of value.match(/https?:\/\/[^\s"'<>,;]+/g) || []) {
        const l = classifyLink(u);
        if (l) out.push(finding('header-url', `URL in ${name} header`, l.category, 'info', u, { tags: l.tags, ctx: ctx(name, value) }));
      }
    } else if (BANNERS.has(lower)) {
      const versioned = /\d+\.\d+/.test(value);
      out.push(finding('tech-banner', versioned ? 'Version disclosed in header' : 'Technology header', 'intel', versioned ? 'low' : 'info', `${name}: ${value.slice(0, 160)}`, { ctx: ctx(name, value) }));
    } else {
      const p = PLATFORMS.find(([re]) => re.test(lower));
      if (p) {
        if (!platforms.has(p[1])) {
          platforms.add(p[1]);
          out.push(finding('tech-platform', 'Platform (from headers)', 'intel', 'info', p[1], { meta: { header: name }, ctx: ctx(name, value) }));
        }
      } else if (!STANDARD.has(lower) && !/^(?:sec-|x-content-|x-xss-|x-frame-|accept-)/.test(lower)) {
        const juicy = JUICY_HEADER_RE.test(lower);
        out.push(finding('custom-header', 'Custom response header', 'intel', juicy ? 'low' : 'info', name, { meta: { example: value.slice(0, 200) }, ctx: ctx(name, value) }));
      }
    }
  }
  return out;
}
