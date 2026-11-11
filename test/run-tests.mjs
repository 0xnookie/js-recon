// Run with: node test/run-tests.mjs
// Exercises the analyzer + rules with synthetic (fake) secrets, negative cases and a perf check.
import { analyze } from '../src/analyzer.js';
import { buildRules, RULES, parseCustomRules, classifyLink, makeSubdomainRule } from '../src/rules.js';
import { ZipWriter, zipPath } from '../src/zip.js';
import { buildMatcher, findMatches } from '../ui/search.js';
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

// Extract a .zip for the ZIP-writer round-trip test. bsdtar (Windows, macOS, local PowerShell)
// reads zip directly; GNU tar on Linux does not, so fall back to unzip (present on CI runners).
function extractZip(zipFile, outDir) {
  try {
    execFileSync('tar', ['-xf', zipFile, '-C', outDir], { stdio: 'pipe' });
    if (readFileSync(join(outDir, 'acme.io/static/js/main.js'), 'utf8')) return;
  } catch {
    /* fall through to unzip */
  }
  execFileSync('unzip', ['-qq', '-o', zipFile, '-d', outDir], { stdio: 'pipe' });
}

const rules = buildRules({});
const rep = (c, n) => c.repeat(n);
let seed = 0x9e3779b9;
const rand = () => {
  // mulberry32 – deterministic so test output is stable
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const rnd = (n, alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') => {
  let s = '';
  for (let i = 0; i < n; i++) s += alphabet[Math.floor(rand() * alphabet.length)];
  return s;
};
const hex = (n) => rnd(n, '0123456789abcdef');
const b64url = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

const fake = {
  aws: 'AKIA' + rnd(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'),
  awsSecret: rnd(40, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+'),
  google: 'AIza' + rnd(35),
  github: 'ghp_' + rnd(36),
  slack: 'xoxb-' + '123456789012-' + rnd(24),
  stripe: 'sk_live_' + rnd(24),
  stripePk: 'pk_live_' + rnd(24),
  sendgrid: 'SG.' + rnd(22) + '.' + rnd(43),
  openai: 'sk-proj-' + rnd(48),
  jwt: b64url({ alg: 'HS256', typ: 'JWT' }) + '.' + b64url({ sub: '42', role: 'service_role', iss: 'supabase' }) + '.' + rnd(43),
  jwtAnon: b64url({ alg: 'HS256', typ: 'JWT' }) + '.' + b64url({ ref: 'abc', role: 'anon', iss: 'supabase' }) + '.' + rnd(43),
  cognito: 'us-east-1:' + hex(8) + '-' + hex(4) + '-' + hex(4) + '-' + hex(4) + '-' + hex(12),
  generic: 'Zq8' + rnd(29),
  pass: 'Tr0ub4dor&3x!',
  telegram: '1234567890:AA' + rnd(33),
};

const fixture = `
/*! app bundle */
const config = {
  aws: { accessKeyId: "${fake.aws}", secretAccessKey: "${fake.awsSecret}" },
  firebase: { apiKey: "${fake.google}", authDomain: "acme-prod.firebaseapp.com", databaseURL: "https://acme-prod.firebaseio.com", storageBucket: "acme-prod.appspot.com" },
  identityPoolId: "${fake.cognito}",
  userPoolId: "us-east-1_AbCdEfGhI",
};
const gh = '${fake.github}';
const slack = "${fake.slack}";
const stripe = { secret: "${fake.stripe}", publishable: "${fake.stripePk}" };
const sg = "${fake.sendgrid}";
const oa = \`${fake.openai}\`;
const supa = "${fake.jwt}";
const supaAnon = "${fake.jwtAnon}";
const tg = "${fake.telegram}";
const db = "mongodb://admin:S3cr3tP4ss@10.0.12.5:27017/prod";
const dbNoCreds = "postgres://db.internal.acme.local:5432/app";
const creds = "https://deploy:Hx9#kq2Lp@ci.acme.io/hook";
const header = { Authorization: "Bearer ${fake.generic}" };
const clientSecret = "${fake.generic}";
var adminPassword = "${fake.pass}";
const pem = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA${rnd(60)}\\n-----END RSA PRIVATE KEY-----";
const docs = "Paste your key here (starts with -----BEGIN PRIVATE KEY-----)";
fetch("/api/v2/users?id=1&debug=true");
axios.post('/internal/admin/impersonate', data);
const u = \`/api/orders/\${id}/refund\`;
const b = \`\${API_BASE}/v1/payments\`;
const full = "https://api.acme.io/graphql";
const ws = "wss://realtime.acme.io/socket";
const s3 = "https://acme-uploads.s3.amazonaws.com/avatars/";
const local = "http://localhost:8080/debug";
const params = new URLSearchParams(location.search).get("redirect_uri");
const q = "?returnTo=" + x;
const email = "security@acme.io";
const ip = "192.168.1.20";
const ver = "v1.2.3.4";
const gql = gql\`query GetUserProfile($id: ID!) { user(id: $id) { email } }\`;
window.addEventListener("message", (e) => { document.body.innerHTML = e.data; });
parent.postMessage(token, "*");
// TODO: remove hardcoded staging creds before release
//# sourceMappingURL=app.min.js.map
`;

const negatives = `
const mime = "application/json"; const t2 = "text/html; charset=utf-8";
const fmt = "MM/DD/YYYY"; const f2 = "dd/MM/yyyy HH:mm";
const pw = { password: "Password", label: "password-field", token: "csrf-token", secret: "secretKey" };
const ns = "http://www.w3.org/2000/svg";
const k = { apiKey: "YOUR_API_KEY_HERE", token: "xxxxxxxxxxxxxxxx", secret: "\${process.env.SECRET}" };
const awsDoc = "${'AKIAIOSFODNN7' + 'EXAMPLE'}";
const img = "icon@2x.png";
const pkg = "core-js@3.6.5";
const blob = "data:image/png;base64,${rep('QUJDRA', 400)}";
const re = "^(?=.*[A-Z])(?=.*\\\\d).{8,}$";
const v = { version: "1.0.0.0" };
`;

let failures = 0;
const check = (cond, msg) => {
  if (!cond) {
    failures++;
    console.log('  ✗ ' + msg);
  } else console.log('  ✓ ' + msg);
};

console.log('Rule compilation');
check(RULES.length > 80, `${RULES.length} built-in rules`);
for (const r of RULES) {
  if (!r.re.global) check(false, `${r.id} must be global`);
}

console.log('\nPositive fixture');
const res = analyze(fixture, rules);
const find = (pred) => res.find(pred);
const byValue = (v) => res.find((f) => f.value === v);
const expect = (value, ruleId, sev) => {
  const f = byValue(value);
  check(f && (!ruleId || f.rule === ruleId) && (!sev || f.severity === sev), `${ruleId} ${sev || ''} → ${value.slice(0, 40)}${f ? '' : '  (NOT FOUND)'}${f && f.rule !== ruleId ? ' (got ' + f.rule + ')' : ''}`);
};
expect(fake.aws, 'aws-access-key', 'high');
expect(fake.awsSecret, 'aws-secret-key', 'high');
expect(fake.google, 'gcp-api-key', 'medium');
expect(fake.cognito, 'aws-cognito-identity-pool', 'medium');
expect('us-east-1_AbCdEfGhI', 'aws-cognito-user-pool');
expect(fake.github, 'github-token', 'high');
expect(fake.slack, 'slack-token', 'high');
expect(fake.stripe, 'stripe-secret', 'high');
expect(fake.stripePk, 'stripe-publishable', 'info');
expect(fake.sendgrid, 'sendgrid', 'high');
expect(fake.openai, 'openai', 'high');
expect(fake.jwt, 'jwt', 'high');
expect(fake.jwtAnon, 'jwt', 'info');
expect(fake.telegram, 'telegram-bot', 'high');
expect(fake.generic, 'bearer-token', 'high');
expect(fake.pass, 'generic-secret', 'medium');
expect('mongodb://admin:S3cr3tP4ss@10.0.12.5:27017/prod', 'db-connection', 'high');
expect('postgres://db.internal.acme.local:5432/app', 'db-connection', 'low');
expect('https://deploy:Hx9#kq2Lp@ci.acme.io', 'basic-auth-url', 'high');
check(res.filter((f) => f.rule === 'private-key').length === 1, 'private key with body found, bare header in docs ignored');
expect('acme-prod.firebaseio.com', 'firebase-db');
expect('acme-prod.appspot.com', 'firebase-storage');
expect('acme-uploads.s3.amazonaws.com', 's3-bucket');
expect('/api/v2/users?id=1&debug=true', 'link');
expect('/internal/admin/impersonate', 'link');
expect('/api/orders/${id}/refund', 'link');
expect('${API_BASE}/v1/payments', 'link');
expect('https://api.acme.io/graphql', 'link');
expect('wss://realtime.acme.io/socket', 'link');
expect('http://localhost:8080/debug', 'link');
expect('redirect_uri', 'param-read');
expect('returnTo', 'param-string');
expect('security@acme.io', 'email');
expect('192.168.1.20', 'ip', 'low');
expect('QUERY GetUserProfile', 'graphql-op');
check(find((f) => f.rule === 'postmessage-listener'), 'postMessage listener');
check(find((f) => f.rule === 'postmessage-wildcard'), 'postMessage "*"');
check(find((f) => f.rule === 'dev-comment' && /TODO: remove hardcoded/.test(f.value)), 'TODO comment');
check(find((f) => f.value === '/internal/admin/impersonate')?.tags.includes('interesting'), 'interesting tag on admin endpoint');
check(!find((f) => f.value === '1.2.3.4'), 'version string not reported as IP');
const ep = byValue('/api/v2/users?id=1&debug=true');
check(ep && ep.line > 1 && ep.ctx[1] === ep.value, `location + context (line ${ep?.line}, col ${ep?.col})`);
check(!find((f) => f.category === 'sinks'), 'sink rules disabled by default');

console.log('\nNegative fixture');
const neg = analyze(negatives, rules);
const noise = neg.filter((f) => !(f.tags || []).includes('noise'));
const bad = noise.filter((f) => f.category === 'secrets' || ['application/json', 'MM/DD/YYYY', 'dd/MM/yyyy HH:mm'].includes(f.value));
check(bad.length === 0, 'no false-positive secrets / mime / date formats' + (bad.length ? ': ' + bad.map((f) => `${f.rule}=${f.value}`).join(', ') : ''));
check(!neg.find((f) => f.category === 'intel' && f.rule === 'email'), 'no emails from icon@2x.png / core-js@3.6.5');
check(!neg.find((f) => f.rule === 'ip'), 'version "1.0.0.0" not reported as IP');
check(neg.find((f) => f.value.startsWith('http://www.w3.org'))?.tags.includes('noise'), 'w3.org namespace tagged as noise');

console.log('\nInputs: parameters, data-* attributes, headers, cookies, storage, forms');
{
  // shaped like real widgets / SPAs: config-declared names, minified URLSearchParams variables …
  const code = `
window.UTW_INJECTED_PARAMS = {"type": "widget", "server_urls": {"admin": "chat.acme.test/botadmin"}, "features": {"feedback": false, "handover": false, "search": true},
  "override_params": {"chat_endpoint_url_param": "chat-endpoint", "initial_message_url_param": "initial-message", "initial_message_dataset_param": "initialMessage"}};
var a=document.currentScript.dataset,l=new URLSearchParams(window.location.search),s=l.get(P.override_params.initial_message_url_param);
function q(){var n=new URLSearchParams(window.location.search);return n.get("ut_force_test")||n.has("ut_quit_test")}
var m=new Map;m.get("notAParam");
var r=this.$route.query.redirect, i=router.query["invite_code"], h=getParameterByName("lang");
var re=/[?&]access_token=([^&#]*)/; ro(u.cookieName||"_bot_user_id");document.cookie="session_hint="+v+";path=/";Cookies.get("csrftoken");
localStorage.getItem("ut_force_test");sessionStorage.setItem("returnTo",x);el.dataset.params;el.getAttribute("data-tenant-id");
xhr.setRequestHeader("X-Debug-Mode","1");fetch(u,{headers:{"X-Api-Version":"2",Authorization:t,"Content-Type":"application/json"}});
Object.defineProperty(o,"headers",{headers:{enumerable:!0,get:f}});
var form='<input type="hidden" name="__csrf" value="abc123"><input name="q"><select name="role">';
var schema = {paramType: "string", in: "query"};
`;
  const res = analyze(code, rules);
  const inp = (kind, value) => res.find((f) => f.category === 'params' && f.meta?.kind === kind && f.value === value);
  const has = (kind, value, rule) => {
    const f = inp(kind, value);
    check(f && (!rule || f.rule === rule), `${kind} → ${value}${f ? ` (${f.rule})` : '  (NOT FOUND)'}`);
    return f;
  };
  has('query', 'chat-endpoint', 'param-config');
  check(inp('query', 'chat-endpoint')?.tags.includes('interesting'), '"endpoint" parameter tagged interesting');
  has('query', 'initial-message', 'param-config');
  has('data', 'data-initial-message', 'param-config');
  has('query', 'ut_force_test', 'param-var');
  has('query', 'ut_quit_test', 'param-var');
  check(!inp('query', 'notAParam'), 'Map.get() is not a parameter read');
  has('query', 'redirect', 'param-router');
  has('query', 'invite_code', 'param-router');
  has('query', 'lang', 'param-getter');
  has('query', 'access_token', 'param-regex');
  has('cookie', '_bot_user_id', 'param-config');
  has('cookie', 'session_hint', 'cookie-name');
  has('cookie', 'csrftoken', 'cookie-name');
  has('storage', 'ut_force_test', 'storage-key');
  check(has('storage', 'returnTo', 'storage-key')?.tags.includes('session'), 'sessionStorage key tagged "session"');
  has('data', 'data-params', 'data-attr');
  has('data', 'data-tenant-id', 'data-attr');
  has('header', 'X-Debug-Mode', 'request-header');
  has('header', 'X-Api-Version');
  has('header', 'Authorization', 'request-header-obj');
  check(!inp('header', 'Content-Type'), 'standard headers (Content-Type) skipped');
  check(!inp('header', 'enumerable'), 'property descriptors are not headers');
  check(has('form', '__csrf', 'form-field')?.tags.includes('hidden'), 'hidden form field tagged "hidden"');
  has('form', 'q', 'form-field');
  check(!res.some((f) => f.category === 'params' && ['string', 'query'].includes(f.value)), 'type names in schemas are not parameters');
  const ternary = analyze('typeof n==`string`?NR[e]=n.charAt(0):x;var o=i===`x`?r===`end`?1:2:3;e.type===`GEOGCS`?e.projName=`longlat`:0', rules);
  check(!ternary.some((f) => f.category === 'params'), 'minified ternaries after a template literal are not "?param=" strings');
  const concat = analyze('localStorage.getItem("jsr_" + k); Cookies.get("pre" + x); el.getAttribute("data-" + n); getUrlParam("ab" + c);', rules);
  check(!concat.some((f) => f.category === 'params'), 'string fragments of a concatenation are not names');
  const cfg = res.find((f) => f.rule === 'global-config');
  check(cfg?.value === 'window.UTW_INJECTED_PARAMS' && /override_params/.test(cfg.meta?.keys), `injected config object with keys (${cfg?.meta?.keys})`);
  const ff = res.find((f) => f.rule === 'feature-flags');
  check(ff && ff.severity === 'low' && ff.meta.disabled === 'feedback, handover' && ff.meta.enabled === 'search', `feature flags: ${ff?.value}`);
  const adm = res.find((f) => f.value === '//chat.acme.test/botadmin');
  check(adm?.category === 'urls' && adm.tags.includes('interesting'), 'scheme-less "host/path" URL, admin path tagged interesting');
  check(!analyze('import x from "lodash.debounce/index"; const f = "main.chunk.js/x"; const p = "react.dom/client";', rules).some((f) => f.rule === 'url-schemeless'),
    'package names and file names are not scheme-less URLs');
}

console.log('\nResponse headers');
{
  const { analyzeHeaders } = await import('../src/headers.js');
  const H = (o) => Object.entries(o).flatMap(([name, v]) => [].concat(v).map((value) => ({ name, value })));
  const res = analyzeHeaders(
    H({
      Server: 'Magistrat der Stadt Wien - Web Gateway',
      'X-Powered-By': 'PHP/7.4.3',
      'X-STDPORTAL-TXID': '140106$fm8uh@wien',
      'X-Backend-Node': 'app-07.internal',
      'CF-Ray': '8f2a1b3c4d5e6f70-VIE',
      'Access-Control-Allow-Headers': 'Accept,Authorization,Content-Type,X-Csrftoken,User-Id,User-Label,Ut-External-Options',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Origin': 'https://admin.acme.test',
      'Access-Control-Allow-Credentials': 'true',
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; connect-src 'self' wss: api.acme.test https://*.ingest.sentry.io; frame-ancestors 'self' *.acme.test; report-uri https://csp.acme.test/report",
      'Set-Cookie': ['sessionid=abc123; Path=/; Secure; SameSite=Lax', 'theme=dark; Path=/', 'csrftoken=x; Secure; HttpOnly'],
      'Content-Type': 'text/html',
      Date: 'Wed, 11 Nov 2026 13:01:06 GMT',
    }),
    { url: 'https://app.acme.test/', pageOrigin: 'https://app.acme.test' },
  );
  const get = (rule, value) => res.find((f) => f.rule === rule && (value === undefined || f.value === value));
  for (const hn of ['User-Id', 'User-Label', 'Ut-External-Options', 'X-Csrftoken', 'Authorization']) {
    check(get('cors-allow-headers', hn)?.meta.kind === 'header', `CORS-allowed request header → ${hn}`);
  }
  check(!get('cors-allow-headers', 'Content-Type') && !get('cors-allow-headers', 'Accept'), 'standard headers skipped');
  check(get('cors-origin', 'admin.acme.test')?.category === 'subdomains', 'trusted CORS origin → domain');
  check(get('cors-methods')?.value.includes('DELETE'), 'CORS write methods');
  for (const h of ['cdnjs.cloudflare.com', 'api.acme.test', '*.ingest.sentry.io', '*.acme.test']) check(get('csp-host', h)?.category === 'subdomains', `CSP host → ${h}`);
  check(get('csp-report-uri', 'https://csp.acme.test/report'), 'CSP report-uri → URL');
  const weak = get('csp-weak');
  check(weak && /'unsafe-inline'/.test(weak.value) && /cdnjs/.test(weak.value), `weak CSP: ${weak?.value}`);
  check(get('set-cookie', 'sessionid')?.tags.includes('no-httponly'), 'session cookie without HttpOnly flagged');
  check(get('set-cookie', 'theme') && !get('set-cookie', 'theme').tags.includes('no-httponly'), 'non-session cookie not flagged');
  check(get('set-cookie', 'csrftoken') && !get('set-cookie', 'csrftoken').tags.includes('no-httponly'), 'HttpOnly cookie not flagged');
  check(get('tech-banner', 'X-Powered-By: PHP/7.4.3')?.severity === 'low', 'version banner → low');
  check(get('tech-banner', 'Server: Magistrat der Stadt Wien - Web Gateway')?.severity === 'info', 'server banner without version → info');
  check(get('tech-platform', 'Cloudflare'), 'platform from cf-ray');
  check(get('custom-header', 'X-STDPORTAL-TXID')?.meta.example === '140106$fm8uh@wien', 'custom response header (name as value, example kept)');
  check(get('custom-header', 'X-Backend-Node')?.severity === 'low', 'internal-looking custom header → low');
  check(!res.some((f) => /^(?:Date|Content-Type)$/i.test(f.value)), 'standard headers ignored');
  const nonce = analyzeHeaders(H({ 'Content-Security-Policy': "script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic'" }), {});
  check(!nonce.some((f) => f.rule === 'csp-weak'), "'unsafe-inline' with a nonce / strict-dynamic is not weak");
  const nullo = analyzeHeaders(H({ 'Access-Control-Allow-Origin': 'null', 'Access-Control-Allow-Credentials': 'true' }), {});
  check(nullo.find((f) => f.rule === 'cors-null-origin')?.severity === 'medium', 'ACAO: null with credentials → medium');
}

console.log('\nLazy chunk discovery');
{
  const { findChunks } = await import('../src/chunks.js');
  const urlsOf = (code, base) => findChunks(code, base).flatMap((r) => r.urls);
  // webpack 5 (CRA): names map + hash map, public path "/"
  const wp5 = `!function(){var n={};n.p="/";n.u=e=>"static/js/"+({35:"admin",78:"settings"}[e]||e)+"."+{35:"1f2e3d4c",78:"9a8b7c6d",112:"0b1c2d3e"}[e]+".chunk.js",n.miniCssF=e=>"static/css/"+e+"."+{35:"aa11"}[e]+".chunk.css"}();`;
  const u5 = urlsOf(wp5, 'https://app.acme.test/static/js/runtime.js');
  check(u5.includes('https://app.acme.test/static/js/admin.1f2e3d4c.chunk.js') && u5.includes('https://app.acme.test/static/js/112.0b1c2d3e.chunk.js') && u5.length === 3,
    `webpack 5 chunk map → ${u5.length} chunks (named + numbered)`);
  // webpack 4: jsonpScriptSrc with the public path variable, relative to the page
  const wp4 = `function a(e){return u.p+"static/js/"+({}[e]||e)+"."+{0:"8d7e6f5a",1:"4b3c2d1e"}[e]+".chunk.js"}u.p="/app/";`;
  const u4 = urlsOf(wp4, 'https://acme.test/index.html');
  check(u4.includes('https://acme.test/app/static/js/0.8d7e6f5a.chunk.js') && u4.length === 2, `webpack 4 jsonpScriptSrc → ${u4.join(', ')}`);
  // Next.js webpack runtime with a ternary special case and grouped maps
  const nx = `d.p="/_next/",d.u=function(e){return 2272===e?"static/chunks/2272-ab12cd34.js":"static/chunks/"+(({4511:"admin-panel"})[e]||e)+"."+({4511:"0f9e8d7c",6060:"1a2b3c4d"})[e]+".js"}`;
  const un = urlsOf(nx, 'https://shop.acme.test/_next/static/chunks/webpack-1.js');
  check(['https://shop.acme.test/_next/static/chunks/2272-ab12cd34.js', 'https://shop.acme.test/_next/static/chunks/admin-panel.0f9e8d7c.js', 'https://shop.acme.test/_next/static/chunks/6060.1a2b3c4d.js'].every((x) => un.includes(x)),
    `Next.js runtime → ${un.length} chunks incl. ternary special case`);
  // Next.js build manifest → routes
  const bm = `self.__BUILD_MANIFEST=function(s){return{__rewrites:{afterFiles:[]},"/":[s,"static/chunks/pages/index-11aa.js"],"/admin/users/[id]":["static/chunks/pages/admin/users/[id]-22bb.js"],sortedPages:["/","/_app","/_error","/admin/users/[id]"]}}("static/chunks/1-33cc.js");`;
  const rb = findChunks(bm, 'https://shop.acme.test/_next/static/abc123/_buildManifest.js').find((r) => r.kind === 'next');
  check(rb?.routes.includes('/admin/users/[id]') && !rb.routes.includes('/_app'), `Next.js build manifest → routes ${rb?.routes.join(' ')}`);
  check(rb?.urls.includes('https://shop.acme.test/_next/static/chunks/pages/admin/users/[id]-22bb.js'), 'Next.js build manifest → page chunks');
  // Vite preload list + ESM dynamic imports (incl. template literals)
  const vite = `const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/Admin-1a2b3c.js","assets/Admin-1a2b3c.css","assets/Billing-4d5e6f.js"])))=>i.map(i=>d[i]);const r=()=>import(\`./Report-7g8h9i.js\`);`;
  const uv = urlsOf(vite, 'https://acme.test/base/assets/index-0a1b.js');
  check(uv.includes('https://acme.test/base/assets/Admin-1a2b3c.js') && uv.includes('https://acme.test/base/assets/Billing-4d5e6f.js') && uv.includes('https://acme.test/base/assets/Report-7g8h9i.js') && !uv.some((x) => x.endsWith('.css')),
    `Vite preload list + dynamic import → ${uv.length} chunks`);
  // negatives: string building that isn't a chunk map
  const neg = urlsOf(`var s="/assets/"+name+".js";var t=cfg["x"]+"/"+y+".min.js";var o={a:"b"}[k]+"";`, 'https://acme.test/a.js');
  check(neg.length === 0, 'ordinary "+.js" string building is not a chunk map');
  check(findChunks(wp5, 'chrome-extension://x/a.js').length === 0, 'non-http base ignored');
}

console.log('\npostMessage handlers');
{
  const pm = analyze(
    `
window.addEventListener("message", function(e){ if (e.data.type === "render") document.getElementById("o").innerHTML = e.data.html; });
window.addEventListener("message", (e) => { if (e.origin !== "https://app.acme.test") return; switch (e.data.action) { case "resize": f(); break; case "navigate": location.href = e.data.url; } });
window.addEventListener('message', this.handleMessage.bind(this));
class W { handleMessage(ev) { if (ev.origin.indexOf("acme.test") > -1) { localStorage.setItem("token", ev.data.token) } } }
this._ws.addEventListener("message", this._onSocket); channel.port2.onmessage = function(){ tick() }; worker.addEventListener("message", g);
`,
    rules,
  ).filter((f) => f.rule === 'postmessage-listener');
  const by = (re) => pm.find((f) => re.test(f.value));
  const unsafe = by(/types: render/);
  check(unsafe?.severity === 'medium' && /not checked/.test(unsafe.value) && /HTML injection/.test(unsafe.value), `no origin check + innerHTML → medium (${unsafe?.value})`);
  const safe = by(/types: resize, navigate/);
  check(safe?.severity === 'info' && safe.meta.origin === 'checked' && safe.meta.sinks === 'navigation', `strict origin check, types + sinks listed (${safe?.value})`);
  const weak = by(/weak/);
  check(weak?.severity === 'low' && /storage write/.test(weak.value), `named handler resolved through .bind(this), substring origin check → weak (${weak?.value})`);
  check(pm.length === 3, `WebSocket / MessagePort / Worker listeners ignored (${pm.length} handlers)`);
}

console.log('\nObserved requests');
{
  const { observedRequest, normalizePath } = await import('../src/requests.js');
  check(normalizePath('/api/users/123/orders/550e8400-e29b-41d4-a716-446655440000') === '/api/users/{id}/orders/{uuid}', 'ids and uuids normalised');
  check(normalizePath('/api/v2/files/5f8d0d55b54764421b7156c9/eyJhbGciOiJIUzI1NiJ9abc123') === '/api/v2/files/{id}/{token}', 'object ids and tokens normalised');
  check(normalizePath('/api/feature-flags/new_checkout_flow') === '/api/feature-flags/new_checkout_flow', 'readable segments kept');
  const res = observedRequest({
    method: 'POST',
    url: 'https://app.acme.test/api/v1/orders/42/refund?reason=dup&notify=1',
    type: 'xmlhttprequest',
    pageOrigin: 'https://app.acme.test',
    requestHeaders: [
      { name: 'Content-Type', value: 'application/json' },
      { name: 'X-Tenant-Id', value: 'acme' },
      { name: 'Authorization', value: 'Bearer eyJhbGciOi.secret.value' },
      { name: 'sec-ch-ua', value: '"Edge"' },
    ],
  });
  const api = res.find((f) => f.category === 'api');
  check(api?.value === 'POST /api/v1/orders/{id}/refund?reason=&notify=' && api.tags.includes('observed') && api.tags.includes('interesting'), `observed API call → ${api?.value}`);
  check(res.some((f) => f.meta?.kind === 'query' && f.value === 'reason'), 'query parameter names from observed request');
  check(res.some((f) => f.meta?.kind === 'header' && f.value === 'X-Tenant-Id'), 'custom request header name');
  const auth = res.find((f) => f.value === 'Authorization');
  check(auth?.meta.example === 'Bearer …' && !JSON.stringify(res).includes('secret.value'), 'Authorization: scheme only, the token is never stored');
  check(!res.some((f) => /content-type|sec-ch-ua/i.test(f.value)), 'standard and sec-* headers skipped');
  const cross = observedRequest({ method: 'GET', url: 'https://api.acme-cloud.io/v2/me', type: 'xmlhttprequest', pageOrigin: 'https://app.acme.test' });
  check(cross.find((f) => f.category === 'api')?.value === 'GET https://api.acme-cloud.io/v2/me', 'cross-origin calls keep their origin');
  check(!observedRequest({ method: 'GET', url: 'https://app.acme.test/static/logo.svg', pageOrigin: 'https://app.acme.test' }).length, 'static files ignored');
  const ws = observedRequest({ method: 'GET', url: 'wss://realtime.acme.test/socket/123', type: 'websocket' });
  check(ws[0]?.value === 'wss://realtime.acme.test/socket/{id}' && ws[0].tags.includes('observed'), `WebSocket → ${ws[0]?.value}`);
}

console.log('\nWayback capture order');
{
  const { orderCaptures } = await import('../src/requests.js');
  const order = orderCaptures([
    ['timestamp', 'original'],
    ['20260101000000', 'https://acme.test/chart/aaaa1111/iframe.js?revision=1'],
    ['20260102000000', 'https://acme.test/chart/bbbb2222/iframe.js?revision=2'],
    ['20260103000000', 'https://acme.test/chart/cccc3333/iframe.js?revision=3'],
    ['20250101000000', 'https://acme.test/js/jquery.min.js'],
    ['20240101000000', 'https://acme.test/static/js/main.4f2a91c.js'],
    ['20230101000000', 'https://acme.test/static/js/main.9b8c7d6.js'],
    ['20220101000000', 'https://acme.test/static/js/main.4f2a91c.js.map'],
    ['20210101000000', 'https://acme.test/admin/app.js'],
    ['bad', 'https://acme.test/x.js'],
  ]).map((c) => c.original.replace('https://acme.test', ''));
  check(order[0].endsWith('.map') && order[1] === '/admin/app.js', `source maps, then sensitive names first (${order.slice(0, 2).join(', ')})`);
  check(order.slice(0, 4).filter((u) => u.startsWith('/chart/')).length === 1, 'one copy per script family before older versions');
  check(order.at(-1) === '/js/jquery.min.js', 'well-known libraries last');
  check(order.length === 8, 'malformed rows dropped');
}

console.log('\nGraphQL');
{
  const { parseDefinition, schemaSketch } = await import('../src/graphql.js');
  const tick = '`';
  const code = [
    `const USER = gql${tick}fragment UserFields on User { id email isAdmin createdAt team { id name } }${tick};`,
    `const Q = gql${tick}query GetUser($id: ID!) { user(id: $id) { ...UserFields orders(first: 10) { totalCount } } } \${USER}${tick};`,
    'var doc={kind:"Document",loc:{start:0,end:120,source:{body:"mutation UpdateUserRole($userId: ID!, $role: Role!) {\\n  updateUserRole(userId: $userId, role: $role) {\\n    user { id role }\\n    errors { message }\\n  }\\n}\\n"}}};',
    'const relay = {params:{operationKind:"subscription",name:"onMessage",text:"subscription OnMessage($room: String!) {\\n  messageAdded(room: $room) { id author { ... on Admin { level } ... on Customer { tier } } }\\n}"}};',
    'const notGql = "query string(a) {"; function query(x){ return x } var subscription = foo; const q = { query: "x" };',
  ].join('\n');
  const res = analyze(code, rules);
  const ops = res.filter((f) => f.rule === 'graphql-op');
  const get = (v) => ops.find((f) => f.value === v);
  check(ops.length === 3, `3 operations (${ops.map((f) => f.value).join(', ')}), JS look-alikes ignored`);
  check(get('QUERY GetUser')?.meta.variables === '$id: ID!' && get('QUERY GetUser').meta.fields === 'user', 'gql template: variables and root fields');
  const mut = get('MUTATION UpdateUserRole');
  check(mut?.category === 'api' && mut.tags.includes('write') && mut.tags.includes('interesting') && /updateUserRole\(userId: \$userId/.test(mut.meta.document), 'Apollo JSON-escaped document → MUTATION, write + interesting, document unescaped');
  check(get('SUBSCRIPTION OnMessage')?.meta.fields === 'messageAdded', 'Relay text → SUBSCRIPTION');
  const frag = res.find((f) => f.rule === 'graphql-fragment');
  check(frag?.category === 'graphql' && frag.value === 'fragment UserFields on User', 'fragment (feeds the schema sketch)');
  const sdl = schemaSketch([...ops, frag].map((f) => parseDefinition(f.meta.document)));
  check(/type Query \{\n {2}user\(id: ID!\): User\n\}/.test(sdl), 'schema: Query.user(id: ID!): User (type from the fragment)');
  check(/updateUserRole\(userId: ID!, role: Role!\): UpdateUserRole/.test(sdl), 'schema: mutation arguments typed from the variables');
  check(/type User \{[^}]*email: String[^}]*isAdmin: Boolean[^}]*orders\(first: Int\): Orders[^}]*role: String/s.test(sdl), 'schema: object fields merged from fragment and operations, scalars guessed');
  check(/union Author = Admin \| Customer/.test(sdl) && /message: String/.test(sdl), 'schema: union from inline fragments; "message" is not an Int');
  check(/#\s+Role/.test(sdl), 'schema: input / enum types listed');
}

console.log('\nOpenAPI / Postman exports');
{
  const { buildOpenApi, buildPostman, splitEndpoint, replayCandidates } = await import('../src/exporters.js');
  const { siteOf } = await import('../src/util.js');
  check(JSON.stringify(splitEndpoint('${API_BASE}/v1/users/:id?fields=&page=', 'https://app.acme.test')) === JSON.stringify({ origin: 'https://app.acme.test', path: '/v1/users/{id}', query: ['fields', 'page'], templated: true }), 'splitEndpoint: base variable, :id, query names');
  check(splitEndpoint('https://api.acme.test/v2/orders/${orderId}/refund', 'https://app.acme.test').path === '/v2/orders/{orderId}/refund', 'splitEndpoint: ${x} becomes {x}, other origin kept');
  const model = {
    host: 'app.acme.test',
    origin: 'https://app.acme.test',
    endpoints: [
      { method: 'GET', path: '/api/v1/users/{id}?fields=', tags: ['observed'] },
      { method: 'POST', path: '/api/v1/users/{id}/role', tags: ['write', 'interesting'] },
      { method: 'GET', path: 'https://api.acme.test/v2/me', tags: [] },
    ],
    bodyFields: { 'POST /api/v1/users/{id}/role': ['role', 'isAdmin'] },
    headers: ['X-Tenant-Id', 'Authorization'],
    bearer: true,
    graphql: { endpoint: 'https://app.acme.test/graphql', operations: [{ kind: 'query', name: 'GetUser', document: 'query GetUser { me { id } }' }] },
  };
  const oa = buildOpenApi(model);
  const getUser = oa.paths['/api/v1/users/{id}']?.get;
  check(oa.openapi === '3.0.3' && getUser && getUser.parameters.some((p) => p.in === 'path' && p.name === 'id' && p.required) && getUser.parameters.some((p) => p.in === 'query' && p.name === 'fields'), 'OpenAPI: path and query parameters');
  check(Object.keys(oa.paths['/api/v1/users/{id}/role'].post.requestBody.content['application/json'].schema.properties).join() === 'role,isAdmin', 'OpenAPI: request body from runtime-captured fields');
  check(oa.paths['/v2/me']?.servers?.[0].url === 'https://api.acme.test', 'OpenAPI: other origin as a path-level server');
  check(oa.components.parameters.header_X_Tenant_Id && oa.security?.[0].bearerAuth, 'OpenAPI: custom headers and bearer auth');
  check(oa.paths['/graphql']?.post.requestBody.content['application/json'].examples.query_GetUser.value.query === 'query GetUser { me { id } }', 'OpenAPI: GraphQL operations as request examples');
  const pm = buildPostman(model);
  const role = pm.item.find((i) => i.name === 'POST /api/v1/users/{id}/role');
  check(pm.info.schema.includes('v2.1.0') && role?.request.url.raw === '{{baseUrl}}/api/v1/users/:id/role' && JSON.parse(role.request.body.raw).isAdmin === '', 'Postman: :id path variable, {{baseUrl}}, JSON body');
  check(pm.item.find((i) => i.name === 'GraphQL')?.item[0].request.body.mode === 'graphql' && pm.auth?.type === 'bearer', 'Postman: GraphQL folder and bearer auth');
  const r = replayCandidates(
    ['https://app.acme.test/api/v1/reports', 'https://app.acme.test/logout', 'https://app.acme.test/api/users/{id}', 'https://evil.example/x', 'https://cdn.acme.test/api/v1/config?x=1', 'https://app.acme.test/api/v1/reports'],
    siteOf,
    'app.acme.test',
  );
  check(JSON.stringify(r.urls) === JSON.stringify(['https://app.acme.test/api/v1/reports', 'https://cdn.acme.test/api/v1/config?x=1']) && r.skipped.unsafe === 1 && r.skipped.template === 1 && r.skipped.offsite === 1,
    'send to proxy: same site only, no placeholders, nothing that sounds state-changing, de-duplicated');
}

console.log('\nclassifyLink');
check(classifyLink('text/javascript') === null, 'mime rejected');
check(classifyLink('//cdn.acme.io/x.js')?.category === 'urls', 'protocol-relative → urls');
check(classifyLink('static/js/main.chunk.js')?.tags.includes('js'), 'js tag');
check(classifyLink('/assets/logo.svg')?.tags.includes('static'), 'static tag');
check(classifyLink('./node_modules/react/index.js')?.tags.includes('noise'), 'node_modules noise');

console.log('\nCustom rules');
const cr = parseCustomRules('# comment\nInternal key | high | /ACME-[A-Z0-9]{12}/\nBad | high | (\nNo sev | x | abc\nGroup | low | token=([a-z]{6})');
check(cr.rules.length === 2 && cr.errors.length === 2, `2 valid, 2 errors (${cr.errors.join('; ')})`);
const cres = analyze('const k = "ACME-ABCDEF123456"; x("token=abcdef")', buildRules({ customRules: 'Internal key | high | /ACME-[A-Z0-9]{12}/\nGroup | low | token=([a-z]{6})' }));
check(cres.find((f) => f.value === 'ACME-ABCDEF123456' && f.severity === 'high'), 'custom rule match');
check(cres.find((f) => f.value === 'abcdef' && f.severity === 'low'), 'custom rule capture group');

console.log('\nAPI endpoints (method-aware)');
const apiCode = `
n.a.post("/api/v1/login",e);this.http.get<User[]>(\`\${this.base}/users\`);$.getJSON("/api/v1/feed");
api.patch(BASE_URL + "/accounts/me", body);router.delete("/admin/users/:id");
fetch("/api/v1/me");fetch("/api/v1/orders",{headers:{a:1},method:"PUT",body:x});request("/api/v1/export",{method:"post"});
xhr.open("DELETE","/api/v1/tokens/"+id);$.ajax({url:"/legacy/save.php",type:"POST",data:d});
axios({method:"patch",url:"/api/v2/profile"});map.get("someKey");headers.get("content-type");t.get("a.b.c");
cache.get("/static/img/logo.png");`;
const apiRes = analyze(apiCode, rules).filter((f) => f.category === 'api').map((f) => f.value);
for (const v of [
  'POST /api/v1/login', 'GET ${this.base}/users', 'GET /api/v1/feed', 'PATCH ${BASE_URL}/accounts/me', 'DELETE /admin/users/:id',
  'GET /api/v1/me', 'PUT /api/v1/orders', 'POST /api/v1/export', 'DELETE /api/v1/tokens/', 'POST /legacy/save.php', 'PATCH /api/v2/profile',
]) check(apiRes.includes(v), `api: ${v}`);
check(apiRes.length === 11, `no API false positives (got ${apiRes.length}: ${apiRes.filter((v) => !/\/api|admin|legacy|users/.test(v)).join(', ')})`);
check(analyze('axios.delete("/api/x")', rules).find((f) => f.category === 'api')?.tags.includes('write'), 'state-changing method tagged "write"');

console.log('\nClient-side routes');
const routeCode = `
const r = createBrowserRouter([
  { path: "/", element: <Home/> },
  { path: "/admin", element: <RequireAuth><AdminPanel/></RequireAuth> },
  { path: "/users/:id", element: <User/> },
  { path: "/settings/billing", lazy: () => import("./routes/Billing") },
]);
const vue = [
  { path: "/login", name: "login", component: Login },
  { path: "/account", name: "account", component: Account, meta: { requiresAuth: true }, beforeEnter: authGuard },
];
const ng = [
  { path: "internal", loadChildren: () => import("./internal/internal.module"), canActivate: [AuthGuard] },
  { path: "public", component: PublicComponent },
  { path: "**", redirectTo: "/404" },
];
const noise = { output: { path: path.resolve(__dirname, "dist") } };
const icon = { path: "M12 2L2 7l10 5z" };
const file = { path: "/etc/passwd" };
const asset = { path: "assets/logo.svg" };`;
const routes = analyze(routeCode, rules).filter((f) => f.category === 'routes');
const routeVals = routes.map((f) => f.value);
for (const v of ['/', '/admin', '/users/:id', '/settings/billing', '/login', '/account', 'internal', 'public', '**'])
  check(routeVals.includes(v), `route: ${v}`);
const routeByVal = (v) => routes.find((f) => f.value === v);
check(routeByVal('/admin')?.tags.includes('guarded') && routeByVal('/admin')?.tags.includes('interesting'), '/admin guarded + interesting');
check(routeByVal('/account')?.meta?.guard === 'beforeEnter', '/account guard = beforeEnter');
check(routeByVal('internal')?.tags.includes('lazy') && routeByVal('internal')?.tags.includes('guarded'), 'Angular lazy + guarded route');
check(routeByVal('/settings/billing')?.meta?.module === './routes/Billing', 'lazy import path captured');
check(routeByVal('**')?.meta?.redirectTo === '/404', 'wildcard redirect target');
check(routeByVal('/users/:id')?.meta?.component === 'User', 'route component captured');
check(!routeVals.includes('/etc/passwd') && !routeVals.some((v) => v.startsWith('M12')) && !routeVals.includes('assets/logo.svg'),
  `no route false positives (got: ${routeVals.join(', ')})`);

console.log('\nDOM-XSS taint flows');
const taintPos = `
  el.innerHTML = "<b>" + location.hash.slice(1) + "</b>";
  node.insertAdjacentHTML("beforeend", document.referrer);
  document.write(decodeURIComponent(location.search));
  eval(new URLSearchParams(location.search).get("cb"));
  window.location = location.hash;
  frame.setAttribute("src", location.href);
  iframe.srcdoc = window.name;
  const x = <div dangerouslySetInnerHTML={{ __html: location.search }} />;`;
const taintNeg = `
  el.innerHTML = "<b>" + user.name + "</b>";
  el.textContent = location.hash;
  img.src = CDN + location.pathname;
  setTimeout(function(){ render(); }, 250);
  const u = location.href; logger.info(u);`;
const taint = analyze(taintPos, rules).filter((f) => f.category === 'sinks' && f.tags.includes('tainted'));
const taintVals = taint.map((f) => f.value);
for (const v of ['location.hash → innerHTML', 'document.referrer → insertAdjacentHTML', 'location.search → document.write', 'location.search → eval / Function', 'location.hash → location', 'location.href → setAttribute', 'window.name → srcdoc', 'location.search → dangerouslySetInnerHTML'])
  check(taintVals.includes(v), `taint: ${v}`);
check(taint.find((f) => f.value === 'location.hash → innerHTML')?.severity === 'high', 'HTML sink is high severity');
const taintFP = analyze(taintNeg, rules).filter((f) => f.category === 'sinks' && f.tags.includes('tainted'));
check(taintFP.length === 0, `no taint false positives (got: ${taintFP.map((f) => f.value).join(', ')})`);

console.log('\nOffline enrichment (AWS account ID, example triage)');
{
  const { awsAccountId, exampleSignals, looksLikeExample } = await import('../src/enrich.js');
  // Verified key ID → account number vectors (keyhog-scanner / aws_account_id_from_key_id).
  for (const [key, acct] of [
    ['ASIAY34FZKBOKMUTVV7A', '609629065308'],
    ['AKIASP2TPHJSQH3FJXYZ', '171436882533'],
    ['AKIA2222222222222222', '744830457525'],
  ]) check(awsAccountId(key) === acct, `AWS ${key} → account ${acct} (offline)`);
  check(awsAccountId('not-a-key') === null, 'non-key → null');
  check(awsAccountId('AKIA0000000000000001') === null, 'invalid base32 chars (0/1) → null');

  const akia = analyze('const cfg = { accessKeyId: "AKIASP2TPHJSQH3FJXYZ" };', rules).find((f) => f.rule === 'aws-access-key');
  check(akia?.meta?.account === '171436882533', 'AWS key finding carries decoded account id');
  check(akia?.meta?.['key type'] === 'long-term (IAM user)', 'AWS key finding carries key type');
  check(!(akia?.tags || []).includes('example'), 'real-looking AWS key not flagged example');

  const asia = analyze('x = "ASIAY34FZKBOKMUTVV7A"', rules).find((f) => f.rule === 'aws-access-key');
  check(asia?.tags?.includes('temporary'), 'ASIA key tagged temporary (STS)');

  const demo = analyze('const k = "AKIA2222222222222222";', rules).find((f) => f.rule === 'aws-access-key');
  check(demo?.tags?.includes('example'), 'structurally-synthetic AWS key tagged example');
  check(demo?.meta?.account === '744830457525', 'example key still decodes its account');

  check(looksLikeExample('abcdefghijklmnop'), 'sequential run → example');
  check(looksLikeExample('token_deadbeef_cafebabe'), 'demo marker → example');
  check(looksLikeExample('aaaaa_secret_value'), 'repeated run → example');
  check(exampleSignals('ghp_R3dStr1keQw9pLmZx7bN2vK4tH8cF6dA1eU0').length === 0, 'genuine high-entropy token not flagged');
  check(!looksLikeExample('k9Qm2vX7bR4tLp8aZ6cH3dNj5sYg1wF0'), 'realistic high-entropy value not flagged');

  const gcpSa = `const creds = {
    "type": "service_account",
    "project_id": "acme-prod-9f2a",
    "private_key_id": "a1b2c3d4e5f6",
    "client_email": "svc@acme-prod-9f2a.iam.gserviceaccount.com",
    "client_id": "109876543210"
  };`;
  const sa = analyze(gcpSa, rules).find((f) => f.rule === 'gcp-service-account');
  check(sa?.meta?.project === 'acme-prod-9f2a', 'GCP service account → project id (offline)');
  check(sa?.meta?.['service account'] === 'svc@acme-prod-9f2a.iam.gserviceaccount.com', 'GCP service account → email');

  const fbCode = `const firebaseConfig = {
    apiKey: "AIzaSyD9x2Qm7bR4tLp8aZ6cH3dNj5sYg1wF0kQ",
    authDomain: "acme-app.firebaseapp.com",
    projectId: "acme-app",
    messagingSenderId: "123456789012",
    appId: "1:123456789012:web:abcdef"
  };`;
  const fk = analyze(fbCode, rules).find((f) => f.rule === 'gcp-api-key');
  check(fk?.tags?.includes('firebase'), 'Google API key near Firebase config tagged firebase');
  check(fk?.meta?.project === 'acme-app', 'Firebase key → project id (offline)');
  const bareKey = analyze('const k = "AIzaSyD9x2Qm7bR4tLp8aZ6cH3dNj5sYg1wF0kQ";', rules).find((f) => f.rule === 'gcp-api-key');
  check(bareKey && !bareKey.tags?.includes('firebase'), 'Google API key with no Firebase config not tagged firebase');
}

console.log('\nJWT expiry triage (offline)');
{
  const { jwtExpiryTag } = await import('../src/rules.js');
  const nowS = Math.floor(Date.now() / 1000);
  check(jwtExpiryTag(nowS - 3600) === 'expired', 'past exp → expired');
  check(jwtExpiryTag(nowS + 3 * 24 * 3600) === 'expires-soon', 'exp in 3 days → expires-soon');
  check(jwtExpiryTag(nowS + 60 * 24 * 3600) === null, 'exp far future → no tag');
  check(jwtExpiryTag(undefined) === null && jwtExpiryTag('x') === null, 'missing / non-numeric exp → no tag');
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const expiredTok = `${b64u({ alg: 'HS256', typ: 'JWT' })}.${b64u({ sub: '123', exp: nowS - 100 })}.sig`;
  const jf = analyze(`const t = "${expiredTok}";`, rules).find((f) => f.rule === 'jwt');
  check(jf?.tags?.includes('expired'), 'expired JWT finding tagged expired');
  const liveTok = `${b64u({ alg: 'HS256', typ: 'JWT' })}.${b64u({ sub: '123', exp: nowS + 90 * 24 * 3600 })}.sig`;
  const jf2 = analyze(`const t = "${liveTok}";`, rules).find((f) => f.rule === 'jwt');
  check(jf2 && !jf2.tags?.includes('expired') && !jf2.tags?.includes('expires-soon'), 'long-lived JWT not tagged expired');
}

console.log('\nNew provider token rules');
{
  const H = (n) => 'a1b2c3d4e5f60718293a4b5c6d7e8f90'.repeat(4).slice(0, n);
  const A = (n) => 'k9Qm2vX7bR4tLp8aZ6cH3dNj5sYg1wF0kQ2bN7cJ4dP6'.repeat(3).slice(0, n);
  // Provider prefixes are split across concatenation so no complete token is a literal here
  // (keeps GitHub secret-scanning push protection from flagging the test file).
  const toks = {
    openrouter: 'sk-' + 'or-v1-' + H(64),
    perplexity: 'pp' + 'lx-' + A(48),
    tailscale: 'tskey' + '-auth-' + 'k9Qm2vX7bR4t' + '-' + 'Lp8aZ6cH3dNj5sYg1wF0kQ',
    planetscale: 'pscale' + '_tkn_' + A(34),
    databricks: 'da' + 'pi' + H(32),
    'terraform-cloud': 'k9Qm2vX7bR4tLp' + '.atlasv1.' + A(64),
    figma: 'fig' + 'd_' + A(44),
    'sentry-auth': 'sntr' + 'ys_' + A(60),
  };
  const blob = Object.values(toks).map((t) => `x="${t}";`).join(' ');
  const found = new Set(analyze(blob, rules).map((f) => f.rule));
  for (const id of Object.keys(toks)) check(found.has(id), `new rule: ${id}`);
}

console.log('\nSARIF export');
{
  const { buildSarif } = await import('../src/exporters.js');
  const sarif = buildSarif({
    host: 'acme.test',
    version: '1.5.0',
    findings: [
      { rule: 'aws-access-key', label: 'AWS Access Key ID', severity: 'high', value: 'AKIA-x', category: 'secrets', desc: 'd', locations: [{ uri: 'https://acme.test/app.js', line: 12, col: 4 }] },
      { rule: 'aws-access-key', label: 'AWS Access Key ID', severity: 'high', value: 'AKIA-y', category: 'secrets', locations: [] },
      { rule: 'taint-innerhtml', label: 'DOM XSS', severity: 'medium', value: 'x -> innerHTML', category: 'sinks', locations: [{ uri: 'https://acme.test/b.js', line: 3 }] },
    ],
  });
  check(sarif.version === '2.1.0' && sarif.$schema.includes('sarif-2.1.0'), 'SARIF 2.1.0 envelope');
  const run = sarif.runs[0];
  check(run.tool.driver.name === 'JS Recon' && run.tool.driver.version === '1.5.0', 'tool driver name + version');
  check(run.tool.driver.rules.length === 2, 'rules de-duplicated by id');
  check(run.tool.driver.rules[0].defaultConfiguration.level === 'error', 'rule default level from severity');
  check(run.results.length === 3, 'one result per finding');
  check(run.results[0].level === 'error' && run.results[2].level === 'warning', 'severity → SARIF level');
  const reg = run.results[0].locations[0].physicalLocation.region;
  check(reg.startLine === 12 && reg.startColumn === 4, 'location line + column preserved');
  check(!run.results[1].locations, 'finding without a location omits locations');
  check(run.results[2].locations[0].physicalLocation.region.startColumn === undefined, 'line without column is fine');
}

console.log('\nCloud providers');
const cloudCode = `
"https://objectstorage.us-ashburn-1.oraclecloud.com/n/acmetenant/b/backups/o/db.tar"
"acme-assets.oss-cn-hangzhou.aliyuncs.com" "ecs.aliyuncs.com" "LTAI5tQx8mR2nP4kW9vY3zB1"
"https://c1234567.ssl.cf1.rackcdn.com/x.png" "https://storage101.dfw1.clouddrive.com/v1/x"
"acme-media.objects-us-east-1.dream.io" "acme.nyc3.digitaloceanspaces.com" "d1a2b3c4d5e6f7.cloudfront.net"
"https://firebasestorage.googleapis.com/v0/b/acme-prod.appspot.com/o/a.png" "pub-abc123.r2.dev"
"https://acme-api.herokuapp.com" "acmestorage.blob.core.windows.net" "cognito-idp.us-east-1.amazonaws.com"`;
const cl = analyze(cloudCode, rules);
const cloudLabel = (v) => cl.find((f) => f.value === v && (f.category === 'cloud' || f.category === 'secrets'))?.label;
check(cloudLabel('objectstorage.us-ashburn-1.oraclecloud.com/n/acmetenant/b/backups') === 'Oracle Object Storage Bucket', 'Oracle bucket');
check(cloudLabel('acme-assets.oss-cn-hangzhou.aliyuncs.com') === 'Alibaba OSS Bucket', 'Alibaba OSS bucket');
check(cloudLabel('ecs.aliyuncs.com') === 'Alibaba Cloud', 'Alibaba endpoint');
check(cloudLabel('LTAI5tQx8mR2nP4kW9vY3zB1') === 'Alibaba Cloud AccessKey ID', 'Alibaba access key');
check(cloudLabel('c1234567.ssl.cf1.rackcdn.com') === 'Rackspace Cloud Files', 'Rackspace CDN');
check(cloudLabel('storage101.dfw1.clouddrive.com') === 'Rackspace Cloud Files', 'Rackspace Cloud Files');
check(cloudLabel('acme-media.objects-us-east-1.dream.io') === 'DreamHost DreamObjects', 'DreamHost DreamObjects');
check(cloudLabel('acme.nyc3.digitaloceanspaces.com') === 'DigitalOcean Space', 'DigitalOcean Space');
check(cloudLabel('d1a2b3c4d5e6f7.cloudfront.net') === 'AWS CloudFront Distribution', 'CloudFront');
check(cloudLabel('firebasestorage.googleapis.com/v0/b/acme-prod.appspot.com') === 'Firebase Storage Bucket', 'Firebase storage URL');
check(cloudLabel('pub-abc123.r2.dev') === 'Object Storage', 'Cloudflare R2');
check(cloudLabel('acme-api.herokuapp.com') === 'PaaS / Serverless Host', 'Heroku app');
check(cloudLabel('acmestorage.blob.core.windows.net') === 'Azure Storage Account', 'Azure blob');
check(cloudLabel('cognito-idp.us-east-1.amazonaws.com') === 'AWS Endpoint', 'generic AWS endpoint');

console.log('\nDependencies');
const depCode = `
__webpack_require__(/*! @acme/ui */ "./node_modules/@acme/ui/dist/index.js");"./node_modules/.pnpm/axios@1.6.0/node_modules/axios/lib/x.js"
import Button from "@acme/ui/Button"; import "./styles.css"; const fs = require("fs"); const x = require("internal-billing-sdk/client");
export * from 'shared-utils'; import("lazy-mod"); const y = require("node:path");
{"name":"acme-web","dependencies":{"react":"^18.2.0","acme-private-lib":"1.0.0","@acme/core":"workspace:*"}}`;
const deps = analyze(depCode, rules).filter((f) => f.category === 'deps');
const dv = (n) => deps.find((f) => f.value === n);
check(dv('@acme/ui')?.meta.evidence.includes('node_modules path'), '@acme/ui from node_modules path');
check(dv('axios') && !dv('.pnpm'), 'pnpm store path → axios');
check(dv('internal-billing-sdk')?.meta.evidence[0] === 'import', 'require("internal-billing-sdk/client") → root package');
check(dv('shared-utils') && dv('lazy-mod'), 'export-from and dynamic import');
check(!dv('fs') && !dv('node:path') && !dv('path'), 'node builtins ignored');
check(dv('acme-private-lib')?.meta.evidence[0] === 'package.json' && dv('@acme/core'), 'package.json dependencies');

console.log('\nConfidence & subdomains');
const lowKey = 'sk_live_' + 'ab'.repeat(12);
const conf = analyze(`const a = "${'sk_live_' + rnd(24)}"; const b = "${lowKey}"; const c = { password: "summer2024!" };`, rules);
check(conf.find((f) => f.rule === 'stripe-secret' && f.value.length > 30 && f.confidence === 'certain'), 'high-entropy key → certain');
check(conf.find((f) => f.value === lowKey)?.confidence === 'tentative', 'low-entropy key → tentative');
check(conf.find((f) => f.value === 'summer2024!')?.confidence === 'tentative', 'generic password → tentative');
const sub = analyze('a="api.acme.io";b="https://staging-admin.acme.io/x";c="acme.io.evil.com";d="notacme.io";e="\\ncdn.acme.io";g="mail@corp.acme.io"', [makeSubdomainRule('acme.io')]).map((f) => f.value);
check(sub.includes('api.acme.io') && sub.includes('staging-admin.acme.io') && sub.includes('cdn.acme.io') && sub.includes('corp.acme.io'), `subdomains: ${sub.join(', ')}`);
check(!sub.some((s) => /evil|notacme|ncdn/.test(s)), 'no look-alike / escaped hosts');
check(analyze('x="staging-admin.acme.io"', [makeSubdomainRule('acme.io')])[0]?.tags.includes('interesting'), 'dev/staging subdomain tagged interesting');
check(parseCustomRules('Crit | critical | foo\\d+').rules[0]?.severity === 'critical', 'custom rule with critical severity');

console.log('\nZIP writer');
const zip = new ZipWriter();
const zipText = 'console.log("hello");\n'.repeat(500);
await zip.add('acme.io/static/js/main.js', zipText);
await zip.add('acme.io/static/js/main.js', 'dup name');
await zip.add(zipPath('acme.io/../evil/<x>:y.js'), 'sanitised');
await zip.add('acme.io/ünïcode.txt', 'utf8');
const zbuf = Buffer.from(await zip.blob().arrayBuffer());
const tmp = mkdtempSync(join(tmpdir(), 'jsrecon-zip-'));
writeFileSync(join(tmp, 't.zip'), zbuf);
mkdirSync(join(tmp, 'out'));
extractZip(join(tmp, 't.zip'), join(tmp, 'out'));
check(readFileSync(join(tmp, 'out/acme.io/static/js/main.js'), 'utf8') === zipText, `deflated entry round-trips (${zipText.length} → ${zbuf.length} bytes zip)`);
check(readFileSync(join(tmp, 'out/acme.io/static/js/main~2.js'), 'utf8') === 'dup name', 'duplicate names made unique');
check(readFileSync(join(tmp, 'out/acme.io/_/evil/_x__y.js'), 'utf8') === 'sanitised', 'path traversal and invalid chars sanitised');
check(readFileSync(join(tmp, 'out/acme.io/ünïcode.txt'), 'utf8') === 'utf8', 'UTF-8 file names');
rmSync(tmp, { recursive: true, force: true });

console.log('\nContent search (grep helpers)');
{
  const text = 'const x = createServerReference("ACTION_ID_abc123");\nvar y = ACTION_ID_def456;\n';
  const lit = findMatches(text, buildMatcher('ACTION_ID_'));
  check(lit.length === 2, `literal finds both ACTION_ID_ occurrences (${lit.length})`);
  check(lit[0].line === 1 && lit[1].line === 2, 'line numbers tracked across newlines');
  check(lit[0].hit === 'ACTION_ID_' && lit[0].post.startsWith('abc123'), 'snippet keeps hit + trailing context');

  const dots = findMatches('a.b axb a.b', buildMatcher('a.b'));
  check(dots.length === 2, `literal "a.b" matches the dots, not the wildcard (${dots.length})`);

  check(findMatches('Foo FOO foo', buildMatcher('foo', { regex: true })).length === 3, 'regex is case-insensitive by default');
  check(findMatches('Foo FOO foo', buildMatcher('foo', { regex: true, caseSensitive: true })).length === 1, 'case-sensitive matches exactly one');

  const mini = rep('x', 200) + 'NEEDLE' + rep('y', 200);
  const one = findMatches(mini, buildMatcher('NEEDLE'));
  check(one.length === 1 && one[0].line === 1, 'minified single line reports line 1');
  check(one[0].pre.startsWith('…') && one[0].post.endsWith('…') && one[0].pre.length < 70, 'long line clamped to a ±context window');

  check(Array.isArray(findMatches('abcabc', buildMatcher('x*', { regex: true }), 10)), 'zero-width regex terminates');
  check(findMatches('a a a a a a', buildMatcher('a'), 3).length === 3, 'per-file match limit is honoured');

  let threw = false;
  try {
    buildMatcher('(', { regex: true });
  } catch {
    threw = true;
  }
  check(threw, 'invalid regex is rejected');
}

console.log('\nPerformance');
let big = '';
const chunk = fixture + negatives + 'function a(e,t){return e.map(function(n){return n.id+"/"+t})}var o={a:1,b:"/x/y",c:[1,2,3]};'.repeat(50);
while (big.length < 6 * 1024 * 1024) big += chunk.replace(/\n/g, ';');
big += '"' + 'a/'.repeat(20000) + '"'; // long path-like literal (backtracking stress)
big += rep('Zm9vYmFy', 2000); // long base64 run
const t0 = performance.now();
const pr = analyze(big, buildRules({ ruleOverrides: Object.fromEntries(RULES.filter((r) => r.category === 'sinks').map((r) => [r.id, true])) }));
const ms = performance.now() - t0;
check(ms < 8000, `6 MB single-line bundle, all rules incl. sinks: ${ms.toFixed(0)} ms, ${pr.length} unique findings`);

console.log(failures ? `\n${failures} check(s) failed` : '\nAll checks passed');
process.exit(failures ? 1 : 0);
