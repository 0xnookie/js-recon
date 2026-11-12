// Integration test for the service worker with a mocked chrome.* API and fetch.
// Run with: node test/sw-harness.mjs
const PAGE = 'https://app.acme.test/dashboard';
const fakeStripe = 'sk_live_' + 'Q7wPz2Lk9VbX4mN8rT1yH6cJ';
const fakeGoogle = 'AIza' + 'SyB7xQ2pL9mN4vK8rT1wH6cJ3dF5gZ0aE1i';

const FILES = {
  'https://app.acme.test/static/main.abc.js': {
    body: `!function(){var k="${fakeGoogle}";fetch("/api/v1/me");var c="static/js/admin.chunk.js";}();\n//# sourceMappingURL=main.abc.js.map`,
  },
  'https://app.acme.test/static/main.abc.js.map': {
    body: JSON.stringify({
      version: 3,
      sources: [
        'webpack://app/./src/api/payments.ts',
        'webpack://app/./node_modules/react/index.js',
        'webpack://app/./node_modules/acme-internal-utils/index.js',
        'webpack://app/./node_modules/@acme-corp/design-system/index.js',
        'webpack://app/./node_modules/@babel/runtime/helpers/x.js',
      ],
      sourcesContent: [
        `import { track } from "@acme-priv/telemetry";\nconst STRIPE_KEY = "${fakeStripe}";\nexport const refund = (id) => fetch(\`/api/internal/refunds/\${id}\`, { method: "POST" });\nconst api = "https://api.acme.test/v2";`,
        'module.exports = "/should/not/appear"',
        null,
        null,
        null,
      ],
    }),
    type: 'application/json',
  },
  // probed (no sourceMappingURL) – the map lives at <script>.map
  'https://app.acme.test/static/legacy.js': { body: 'axios.delete("/api/v1/sessions/all")' },
  'https://app.acme.test/static/legacy.js.map': {
    body: JSON.stringify({ version: 3, sources: ['src/legacy.js'], sourcesContent: ['const pw = { password: "Pr0d!Passw0rd#2024" };'] }),
    type: 'application/json',
  },
  // npm registry
  'https://registry.npmjs.org/react': { body: JSON.stringify({ 'dist-tags': { latest: '18.3.1' }, versions: { '18.3.1': {} } }), type: 'application/json' },
  'https://registry.npmjs.org/@babel%2Fruntime': { body: JSON.stringify({ 'dist-tags': { latest: '7.25.0' }, versions: { '7.25.0': {} } }), type: 'application/json' },
  'https://registry.npmjs.org/-/org/acme-corp/package': { body: '{}', type: 'application/json' }, // scope exists
  'https://registry.npmjs.org/-/org/acme-priv/package': { status: 404, body: '{}' },
  'https://registry.npmjs.org/-/user/acme-priv/package': { status: 404, body: '{}' },
  'https://app.acme.test/static/js/admin.chunk.js': { body: 'x.get("/api/admin/users/delete")' },
  'https://app.acme.test/static/vendor.js': { body: 'var a=1;' },
  'https://app.acme.test/static/vendor-copy.js': { body: 'var a=1;' },
  'https://app.acme.test/static/missing.js': { status: 404, body: 'nope' },
  'https://app.acme.test/static/spa-fallback.js': { body: '<!doctype html><html></html>', type: 'text/html' },
  'https://www.google-analytics.com/analytics.js': { body: 'should never be fetched' },
};

const fetched = [];
globalThis.fetch = async (url) => {
  fetched.push(url);
  const f = FILES[url] || Object.values(FILES).find((x) => x.match?.test(url));
  if (!f) return new Response('not found', { status: 404 });
  return new Response(f.body, { status: f.status || 200, headers: { 'content-type': f.type || 'application/javascript' } });
};

// ── chrome mock ──
const mem = {};
const memSession = {};
const listeners = { storage: [], webRequest: [], sendHeaders: [], message: [], tabsUpdated: [], tabsActivated: [], tabsRemoved: [], installed: [] };
const registered = new Map(); // dynamically registered content scripts
const clone = (v) => (v === undefined ? undefined : structuredClone(v));
const badges = {};
const titles = {};
globalThis.chrome = {
  storage: {
    local: {
      async get(keys) {
        if (keys == null) return clone(mem);
        const out = {};
        for (const k of [].concat(keys)) if (k in mem) out[k] = clone(mem[k]);
        return out;
      },
      async set(obj) {
        const changes = {};
        for (const [k, v] of Object.entries(obj)) {
          changes[k] = { oldValue: mem[k], newValue: clone(v) };
          mem[k] = clone(v);
        }
        listeners.storage.forEach((l) => l(changes, 'local'));
      },
      async remove(keys) {
        const changes = {};
        for (const k of [].concat(keys)) {
          changes[k] = { oldValue: mem[k], newValue: undefined };
          delete mem[k];
        }
        listeners.storage.forEach((l) => l(changes, 'local'));
      },
    },
    session: {
      async get(keys) {
        const out = {};
        for (const k of [].concat(keys)) if (k in memSession) out[k] = clone(memSession[k]);
        return out;
      },
      async set(obj) {
        for (const [k, v] of Object.entries(obj)) memSession[k] = clone(v);
      },
    },
    onChanged: { addListener: (l) => listeners.storage.push(l) },
  },
  webRequest: {
    onCompleted: { addListener: (l) => listeners.webRequest.push(l) },
    onBeforeSendHeaders: { addListener: (l) => listeners.sendHeaders.push(l) },
  },
  tabs: {
    get: async (id) => ({ id, windowId: 1, url: PAGE }),
    query: async () => [{ id: 7, windowId: 1, url: PAGE }],
    sendMessage: async () => {
      throw new Error('no receiver');
    },
    onUpdated: { addListener: (l) => listeners.tabsUpdated.push(l) },
    onActivated: { addListener: (l) => listeners.tabsActivated.push(l) },
    onRemoved: { addListener: (l) => listeners.tabsRemoved.push(l) },
  },
  windows: { onRemoved: { addListener: () => {} } },
  scripting: {
    executeScript: async () => [],
    getRegisteredContentScripts: async ({ ids } = {}) => [...registered.values()].filter((s) => !ids || ids.includes(s.id)),
    registerContentScripts: async (list) => list.forEach((s) => registered.set(s.id, s)),
    unregisterContentScripts: async ({ ids }) => ids.forEach((id) => registered.delete(id)),
  },
  action: {
    setBadgeText: async ({ tabId, text }) => (badges[tabId] = text),
    setBadgeBackgroundColor: async () => {},
    setTitle: async ({ tabId, title }) => (titles[tabId] = title),
  },
  runtime: {
    onMessage: { addListener: (l) => listeners.message.push(l) },
    onInstalled: { addListener: (l) => listeners.installed.push(l) },
    getURL: (p) => 'chrome-extension://x/' + p,
  },
  notifications: { create: () => {} },
};

const send = (msg, sender = { tab: { id: 7, url: PAGE } }) =>
  new Promise((resolve) => listeners.message.forEach((l) => l(msg, sender, resolve)));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function drain() {
  for (let i = 0; i < 100; i++) {
    const st = await send({ type: 'status' });
    if (!st.pending) break;
    await sleep(50);
  }
  await sleep(900); // debounced storage flush + badge
}

let failures = 0;
const check = (cond, msg) => {
  console.log((cond ? '  ✓ ' : '  ✗ ') + msg);
  if (!cond) failures++;
};

// enable crawling for this run; scope 'all' so the capture tests below aren't gated to one active tab
mem.settings = { crawlJs: true, scopeMode: 'all' };
await import('../src/background.js');

console.log('Passive capture via webRequest');
const fire = (url, type = 'script', tabId = 7) => listeners.webRequest.forEach((l) => l({ url, type, tabId, statusCode: 200 }));
fire('https://app.acme.test/static/main.abc.js');
fire('https://app.acme.test/static/vendor.js');
fire('https://app.acme.test/static/vendor-copy.js');
fire('https://app.acme.test/static/missing.js');
fire('https://app.acme.test/static/spa-fallback.js');
fire('https://www.google-analytics.com/analytics.js');
fire('https://app.acme.test/api/data.json', 'xmlhttprequest'); // not JS → ignored
fire('https://app.acme.test/static/main.abc.js', 'script', -1); // extension's own request → ignored
await drain();

const data = mem['host:app.acme.test'];
check(!!data, 'host data stored under host:app.acme.test');
const F = Object.values(data.findings);
const has = (pred) => F.some(pred);
check(has((f) => f.value === fakeGoogle && f.rule === 'gcp-api-key'), 'Google API key from main bundle');
check(has((f) => f.value === '/api/v1/me'), 'endpoint from main bundle');
check(has((f) => f.value === fakeStripe && f.sources[0].sub === 'src/api/payments.ts'), 'Stripe key from source map original source (with source path)');
check(has((f) => f.value === '/api/internal/refunds/${id}'), 'endpoint from source map');
check(!has((f) => f.value === '/should/not/appear'), 'node_modules sources skipped');
check(has((f) => f.rule === 'sourcemap-exposed' && f.severity === 'medium'), 'source map exposure reported');
check(has((f) => f.value === '/api/admin/users/delete'), 'crawled lazy chunk scanned');
check(data.files['https://app.acme.test/static/js/admin.chunk.js']?.kind === 'crawled', 'crawled file recorded');
check(
  [data.files['https://app.acme.test/static/vendor.js']?.status, data.files['https://app.acme.test/static/vendor-copy.js']?.status].sort().join() === 'done,dup',
  'identical content de-duplicated',
);
check(data.files['https://app.acme.test/static/missing.js']?.error === 'HTTP 404', '404 recorded as error');
check(/HTML/.test(data.files['https://app.acme.test/static/spa-fallback.js']?.error || ''), 'SPA HTML fallback rejected');
check(!fetched.includes('https://www.google-analytics.com/analytics.js'), 'ignored script host not fetched');
check(!fetched.includes('https://app.acme.test/api/data.json'), 'non-JS XHR not fetched');
check(fetched.filter((u) => u === 'https://app.acme.test/static/main.abc.js').length === 1, 'main bundle fetched once');
const idx = mem.index?.['app.acme.test'] || {};
check(idx.high === 1 && idx.medium >= 1 && idx.critical === 1,`index summary (critical=${idx.critical}, high=${idx.high}, medium=${idx.medium})`);
check(badges[7] === String(idx.critical + idx.high + idx.medium), `badge shows ${badges[7]} (critical + high + medium)`);

console.log('\nDependency confusion (npm registry)');
const dep = (n) => data.findings['deps|' + n];
check(dep('react')?.meta?.npm === 'exists' && dep('react').severity === 'info' && dep('react').meta.latest === '18.3.1', 'react → exists on npm (info, latest 18.3.1)');
check(dep('acme-internal-utils')?.severity === 'critical' && dep('acme-internal-utils').tags.includes('not-on-npm'), 'acme-internal-utils → critical, not on npm');
check(dep('@acme-corp/design-system')?.severity === 'low' && dep('@acme-corp/design-system').meta.scopeStatus === 'claimed', '@acme-corp/design-system → scope claimed (low)');
check(dep('@acme-priv/telemetry')?.severity === 'high' && /scope @acme-priv is unclaimed/.test(dep('@acme-priv/telemetry').label), '@acme-priv/telemetry (import only) → scope unclaimed, high (alias caveat)');
check(dep('@babel/runtime')?.meta?.npm === 'exists', '@babel/runtime → exists');
check(fetched.filter((u) => u === 'https://registry.npmjs.org/react').length === 1, 'registry lookups cached');

console.log('\nAPI endpoints / subdomains / confidence');
check(data.findings['api|POST /api/internal/refunds/${id}'], 'POST endpoint from fetch(…, { method: "POST" }) in source map');
check(Object.values(data.findings).some((f) => f.category === 'subdomains' && f.value === 'api.acme.test'), 'subdomain api.acme.test found');
const stripe = Object.values(data.findings).find((f) => f.value === fakeStripe);
check(stripe?.confidence === 'certain' && stripe.entropy > 3.5, `secret confidence (${stripe?.confidence}, entropy ${stripe?.entropy})`);

console.log('\nActive source-map probing');
await chrome.storage.local.set({ settings: { ...mem.settings, probeSourceMaps: true } });
fire('https://app.acme.test/static/legacy.js');
await drain();
const d1 = mem['host:app.acme.test'];
check(d1.files['https://app.acme.test/static/legacy.js.map']?.probed === true, 'guessed <script>.map location and parsed it');
check(Object.values(d1.findings).some((f) => f.value === 'Pr0d!Passw0rd#2024' && f.sources[0].sub === 'src/legacy.js'), 'secret found in probed map');
check(d1.findings['api|DELETE /api/v1/sessions/all'], 'DELETE endpoint from axios.delete');
check(!fetched.includes('https://app.acme.test/static/legacy.map'), 'stopped probing after the first candidate succeeded');
await chrome.storage.local.set({ settings: { ...mem.settings, probeSourceMaps: false } });

console.log('\nContent-script collection');
const inlineMap = Buffer.from(JSON.stringify({ version: 3, sources: ['src/inline-boot.ts'], sourcesContent: ['const bootToken = "ghp_' + 'Ab3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5' + '";'] })).toString('base64');
const inline = 'window.__CONFIG__ = {"apiBase":"https:\\/\\/api.acme.test\\/v2","sentry":"https://' + 'a'.repeat(32) + '@o1.ingest.sentry.io/42"}\n//# sourceMappingURL=data:application/json;base64,' + inlineMap;
await send({ type: 'page-collect', pageUrl: PAGE, scripts: ['https://app.acme.test/static/main.abc.js'], inline: [inline], html: '<html><!-- TODO remove debug panel --><a href="/admin/panel">x</a></html>' });
await drain();
const d2 = mem['host:app.acme.test'];
const F2 = Object.values(d2.findings);
check(F2.some((f) => f.value === 'https://api.acme.test/v2'), 'JSON-escaped URL from inline script');
check(F2.some((f) => f.rule === 'sentry-dsn'), 'Sentry DSN from inline script');
check(F2.some((f) => f.value === '/admin/panel' && f.tags.includes('interesting')), 'link from DOM');
check(F2.some((f) => f.rule === 'html-comment' || f.rule === 'dev-comment'), 'HTML comment from DOM');
check(F2.some((f) => f.rule === 'github-token' && f.sources[0].sub === 'src/inline-boot.ts'), 'inline base64 source map in inline script parsed');
check(fetched.filter((u) => u === 'https://app.acme.test/static/main.abc.js').length === 1, 'already-scanned script not re-fetched');

// iframes: an embedded widget's inline config is scanned and filed under the top page's host
const frameSender = (url) => ({ tab: { id: 7, url: PAGE }, frameId: 3, url });
const widgetUrl = 'https://chat.acme.test/widget/index/';
const widget = 'window.WIDGET_PARAMS = {"override_params": {"initial_message_url_param": "initial-message", "initial_message_dataset_param": "initialMessage"}, "features": {"handover": false}};';
await send({ type: 'page-collect', pageUrl: widgetUrl, frame: true, scripts: [], inline: [widget], html: null }, frameSender(widgetUrl));
await send({ type: 'page-collect', pageUrl: 'https://ads.doubleclick.net/frame', frame: true, scripts: [], inline: ['var trackerParam = "ad_should_not_appear";'], html: null }, frameSender('https://ads.doubleclick.net/frame'));
await drain();
const F3 = mem['host:app.acme.test'].findings;
check(F3['params|initial-message']?.meta?.kind === 'query', 'iframe inline script: URL parameter named in config');
check(F3['params|data:data-initial-message'], 'iframe inline script: data-* attribute named in config');
const frameFile = mem['host:app.acme.test'].files[F3['params|initial-message']?.sources[0].file];
check(frameFile?.label === '/dashboard › frame chat.acme.test/widget/index/ — inline script #1', `iframe source labelled with the frame (${frameFile?.label})`);
check(Object.values(F3).some((f) => f.rule === 'feature-flags' && f.meta.disabled === 'handover'), 'feature flags from iframe config');
check(!Object.values(F3).some((f) => f.value === 'ad_should_not_appear'), 'ignored-host iframe (ads) skipped');

console.log('\nLazy chunks from the webpack runtime');
FILES['https://app.acme.test/static/js/runtime.js'] = { body: '!function(){n.p="/";n.u=e=>"static/js/"+({35:"admin"}[e]||e)+"."+{35:"1f2e3d4c",78:"9a8b7c6d"}[e]+".chunk.js"}();' };
FILES['https://app.acme.test/static/js/admin.1f2e3d4c.chunk.js'] = { body: 'axios.post("/api/internal/users/promote",d);' };
FILES['https://app.acme.test/static/js/78.9a8b7c6d.chunk.js'] = { body: 'fetch("/api/v1/reports/export");' };
fire('https://app.acme.test/static/js/runtime.js');
await drain();
const d4 = mem['host:app.acme.test'];
check(d4.files['https://app.acme.test/static/js/admin.1f2e3d4c.chunk.js']?.kind === 'chunk', 'never-loaded admin chunk fetched (kind "chunk")');
check(d4.findings['api|POST /api/internal/users/promote'], 'API endpoint found inside the lazy chunk');
check(d4.findings['intel|webpack chunk map']?.meta.chunks === 2, `chunk-map finding (${d4.findings['intel|webpack chunk map']?.meta.chunks} chunks)`);
check(Object.keys(d4.chunkUrls || {}).length === 2 && d4.chunksFetched === 2, 'discovered chunk URLs stored for export');

console.log('\nResponse headers');
const respond = (url, type, headers) =>
  listeners.webRequest.forEach((l) => l({ url, type, tabId: 7, statusCode: 200, responseHeaders: Object.entries(headers).map(([name, value]) => ({ name, value })) }));
respond(PAGE, 'main_frame', {
  Server: 'nginx/1.18.0',
  'Access-Control-Allow-Headers': 'Content-Type, X-Tenant-Id',
  'Content-Security-Policy': "default-src 'self'; connect-src 'self' api.acme.test wss://realtime.acme.test",
  'Set-Cookie': 'sessionid=abc; Path=/; Secure',
});
respond('https://api.thirdparty.io/v1/track', 'xmlhttprequest', { Server: 'thirdparty-gw/2.0', 'Access-Control-Allow-Headers': 'X-Should-Not-Appear' });
await drain();
const d5 = mem['host:app.acme.test'];
check(d5.findings['params|header:X-Tenant-Id']?.rule === 'cors-allow-headers', 'request header from Access-Control-Allow-Headers');
check(d5.findings['subdomains|realtime.acme.test']?.tags.includes('csp'), 'host from the CSP');
check(d5.findings['params|cookie:sessionid']?.tags.includes('no-httponly'), 'Set-Cookie name, session cookie without HttpOnly flagged');
check(d5.findings['intel|Server: nginx/1.18.0']?.severity === 'low', 'version banner');
check(d5.files['headers:https://app.acme.test']?.kind === 'headers', 'headers listed as a source in Files');
check(!JSON.stringify(d5.findings).includes('X-Should-Not-Appear') && !JSON.stringify(d5.findings).includes('thirdparty-gw'), "third-party API's headers ignored");

console.log('\nObserved requests');
const sendHeaders = (d) => listeners.sendHeaders.forEach((l) => l({ tabId: 7, ...d }));
sendHeaders({
  method: 'PATCH',
  url: 'https://app.acme.test/api/v1/users/42?fields=role',
  type: 'xmlhttprequest',
  requestHeaders: [{ name: 'X-Tenant-Id', value: 'acme' }, { name: 'Authorization', value: 'Bearer abc.def.ghi' }],
});
sendHeaders({ method: 'GET', url: 'https://www.google-analytics.com/collect?v=1', type: 'xmlhttprequest' });
await drain();
const d6 = mem['host:app.acme.test'];
check(d6.findings['api|PATCH /api/v1/users/{id}?fields=']?.tags.includes('observed'), 'observed API call with method and normalised path');
check(d6.findings['params|header:X-Tenant-Id']?.tags.includes('observed'), 'observed custom request header');
check(!JSON.stringify(d6.findings).includes('abc.def.ghi'), 'Authorization value not stored');
check(!JSON.stringify(d6.findings).includes('google-analytics'), 'ignored hosts (analytics) skipped');
check(d6.files['observed:app.acme.test']?.kind === 'observed', 'observed requests listed in Files');

console.log('\nRuntime hooks');
check(!registered.size, 'not registered by default');
await chrome.storage.local.set({ settings: { ...mem.settings, runtimeHooks: true, scopeMode: 'allowlist', allowHosts: ['acme.test'], denyHosts: ['admin.acme.test'] } });
await sleep(50);
const rs = registered.get('jsrecon-runtime');
check(rs?.world === 'MAIN' && rs.runAt === 'document_start' && rs.allFrames && rs.js[0] === 'src/runtime.js', 'registered in the page world at document_start, all frames');
check(JSON.stringify(rs?.matches) === JSON.stringify(['*://acme.test/*', '*://*.acme.test/*']) && rs.excludeMatches.includes('*://admin.acme.test/*'), 'limited to the allow-list, deny-list excluded');
const handlerSrc = 'function(e){ if (e.data.cmd === "login") document.body.innerHTML = e.data.html }';
const rr = await send({
  type: 'runtime-collect',
  pageUrl: PAGE,
  data: {
    params: ['ut_force_test', 'next'],
    storage: [{ key: 'featureFlags', area: 'local' }, { key: 'returnTo', area: 'session' }],
    cookies: ['session_hint'],
    attrs: ['data-tenant'],
    bodies: [{ method: 'POST', path: '/api/v1/users/42/role', keys: ['role', 'isAdmin'] }],
    handlers: [handlerSrc],
  },
});
await drain();
const d7 = mem['host:app.acme.test'];
check(rr?.ok && d7.findings['params|ut_force_test']?.tags.includes('runtime'), 'query parameter read at runtime');
check(d7.findings['params|storage:returnTo']?.tags.includes('session'), 'sessionStorage key at runtime');
check(d7.findings['params|cookie:session_hint'] && d7.findings['params|data:data-tenant'], 'cookie written and data-* attribute read at runtime');
check(d7.findings['params|body:isAdmin']?.meta.example === 'POST /api/v1/users/{id}/role', 'request body field with its endpoint');
check(d7.findings['api|POST /api/v1/users/{id}/role']?.meta.body === 'role, isAdmin', 'API call from a request body');
const rpm = Object.values(d7.findings).find((f) => f.rule === 'rt-postmessage');
check(rpm?.severity === 'medium' && /login/.test(rpm.value), `message handler captured at runtime: ${rpm?.value}`);
check(d7.files['runtime:https://app.acme.test']?.kind === 'runtime', 'runtime data listed in Files');
await chrome.storage.local.set({ settings: { ...mem.settings, runtimeHooks: false, scopeMode: 'all', allowHosts: [], denyHosts: [] } });
await sleep(50);
check(!registered.size, 'unregistered when switched off');
const rOff = await send({ type: 'runtime-collect', pageUrl: PAGE, data: { params: ['should_not_appear'] } });
check(!rOff?.ok, 'runtime data ignored while the option is off');

console.log('\nWayback Machine');
FILES.cdx = {
  match: /^https:\/\/web\.archive\.org\/cdx\/search\/cdx\?/,
  type: 'application/json',
  body: JSON.stringify([
    ['timestamp', 'original'],
    ['20230105120000', 'https://app.acme.test/static/js/admin-old.js'],
    ['20210101000000', 'https://app.acme.test/static/main.abc.js'],
    ['20240303000000', 'https://app.acme.test/chart/3333/iframe.js?revision=3'],
    ['20240302000000', 'https://app.acme.test/chart/2222/iframe.js?revision=2'],
    ['20200101000000', 'https://app.acme.test/static/js/legacy-2020.js'],
  ]),
};
FILES['https://web.archive.org/web/20240303000000id_/https://app.acme.test/chart/3333/iframe.js?revision=3'] = { body: 'var chart = "/api/charts/3333";' };
FILES['https://web.archive.org/web/20200101000000id_/https://app.acme.test/static/js/legacy-2020.js'] = { body: 'var legacy = "/api/v0/export.php";' };
FILES['https://web.archive.org/web/20230105120000id_/https://app.acme.test/static/js/admin-old.js'] = { body: 'axios.delete("/api/internal/tenants/all");\n//# sourceMappingURL=admin-old.js.map' };
FILES['https://web.archive.org/web/20230105120000id_/https://app.acme.test/static/js/admin-old.js.map'] = {
  type: 'application/json',
  body: JSON.stringify({ version: 3, sources: ['src/admin/tenants.ts'], sourcesContent: ['export const purge = () => fetch("/api/internal/purge", { method: "POST" });'] }),
};
const wb = await send({ type: 'wayback', host: 'app.acme.test', limit: 3 });
await drain();
const d8 = mem['host:app.acme.test'];
check(wb?.ok && wb.captures === 5 && wb.queued === 3, `CDX lookup: ${wb?.captures} captures, ${wb?.queued} queued`);
check(!fetched.some((u) => u.includes('main.abc.js') && u.includes('web.archive.org')), 'live, already scanned file not fetched again from the archive');
check(fetched.some((u) => u.includes('legacy-2020.js')) && !fetched.some((u) => u.includes('chart/2222')), 'one file per distinct script before older versions (chart/<id>/iframe.js once)');
const arch = d8.files['https://web.archive.org/web/20230105120000id_/https://app.acme.test/static/js/admin-old.js'];
check(arch?.kind === 'wayback' && arch.label === 'https://app.acme.test/static/js/admin-old.js (archived 2023-01-05)', `archived bundle scanned (${arch?.label})`);
check(d8.findings['api|DELETE /api/internal/tenants/all'], 'endpoint from the archived bundle');
const archMap = d8.files['https://web.archive.org/web/20230105120000id_/https://app.acme.test/static/js/admin-old.js.map'];
check(archMap?.kind === 'sourcemap' && /archived/.test(archMap.label) && d8.findings['api|POST /api/internal/purge'], 'its archived source map followed and scanned');

console.log('\nSend to proxy');
const beforeReplay = fetched.length;
const rp = await send({ type: 'replay', host: 'app.acme.test', urls: ['https://app.acme.test/api/v1/reports', 'https://app.acme.test/logout', 'https://app.acme.test/api/users/{id}', 'https://evil.example/x'] });
await drain();
const replayed = fetched.slice(beforeReplay);
check(rp?.ok && rp.queued === 1 && JSON.stringify(replayed) === JSON.stringify(['https://app.acme.test/api/v1/reports']), `only the concrete, harmless same-site GET sent (${replayed.join(', ')})`);

console.log('\nEndpoint liveness');
FILES['https://app.acme.test/api/live'] = { body: 'ok' };
FILES['https://app.acme.test/api/admin'] = { body: 'forbidden', status: 403 };
const pb = await send({
  type: 'probe',
  host: 'app.acme.test',
  urls: [
    'https://app.acme.test/api/live', // 200
    'https://app.acme.test/api/admin', // 403
    'https://app.acme.test/api/missing', // 404 (not in FILES)
    'https://app.acme.test/logout', // unsafe → skipped
    'https://app.acme.test/api/{id}', // placeholder → skipped
    'https://evil.example/x', // offsite → skipped
  ],
});
await drain();
const probes = mem['host:app.acme.test'].probes || {};
check(pb?.ok && pb.queued === 3, `probe queued only the 3 safe same-site GETs (queued ${pb?.queued})`);
check(probes['https://app.acme.test/api/live']?.status === 200, 'live endpoint → 200');
check(probes['https://app.acme.test/api/admin']?.status === 403, 'protected endpoint → 403');
check(probes['https://app.acme.test/api/missing']?.status === 404, 'missing endpoint → 404');
check(!probes['https://app.acme.test/logout'] && !probes['https://evil.example/x'], 'unsafe and offsite endpoints not probed');

const cdxBackup = FILES.cdx;
FILES.cdx = { ...cdxBackup, status: 503, body: '<html>Internet Archive: Temporarily Offline</html>', type: 'text/html' };
const wbDown = await send({ type: 'wayback', host: 'app.acme.test' });
check(!wbDown.ok && /503.*try again later/.test(wbDown.error) && mem['host:app.acme.test'] && (await send({ type: 'status' })), `archive.org outage reported (${wbDown.error})`);
FILES.cdx = cdxBackup;

console.log('\nScope');
await chrome.storage.local.set({ settings: { ...mem.settings, denyHosts: ['acme.test'] } });
const before = fetched.length;
FILES['https://app.acme.test/static/new.js'] = { body: 'x' };
fire('https://app.acme.test/static/new.js');
await drain();
check(fetched.length === before, 'deny-listed page host not scanned');
await chrome.storage.local.set({ settings: { ...mem.settings, denyHosts: [] } });

// active-tab mode: only the frontmost tab (7, window 1) is scanned; a background tab (99) is skipped
await chrome.storage.local.set({ settings: { ...mem.settings, scopeMode: 'active' } });
listeners.tabsActivated.forEach((l) => l({ tabId: 7, windowId: 1 }));
const beforeActive = fetched.length;
FILES['https://app.acme.test/static/bg-tab.js'] = { body: 'x' };
fire('https://app.acme.test/static/bg-tab.js', 'script', 99);
await drain();
check(fetched.length === beforeActive, 'background tab not scanned in active-tab mode');
FILES['https://app.acme.test/static/active-tab.js'] = { body: 'x' };
fire('https://app.acme.test/static/active-tab.js', 'script', 7);
await drain();
check(fetched.length === beforeActive + 1, 'active tab scanned in active-tab mode');

// ask-first mode (the default): nothing is fetched until the user OKs the site in the popup
console.log('\nAsk before scanning');
await chrome.storage.local.set({ settings: { ...mem.settings, scopeMode: 'ask', allowHosts: [], denyHosts: [] } });
const tabUpdate = (tabId, url) => listeners.tabsUpdated.forEach((l) => l(tabId, { url, status: 'complete' }, { id: tabId, url }));
tabUpdate(7, PAGE);
await sleep(50);
check(badges[7] === '?' && /not scanning app\.acme\.test/.test(titles[7] || ''), `unapproved tab shows a "?" badge (${badges[7]}: ${titles[7]})`);
check((await send({ type: 'scope' })).state === 'ask', 'scope state for the tab: ask');
const pcAsk = await send({ type: 'page-collect', pageUrl: PAGE, scripts: ['https://app.acme.test/static/ask-1.js'], inline: [], html: '<html></html>' });
const beforeAsk = fetched.length;
FILES['https://app.acme.test/static/ask-1.js'] = { body: 'var a="/api/ask/one";' };
FILES['https://app.acme.test/static/ask-2.js'] = { body: 'var b="/api/ask/two";' };
fire('https://app.acme.test/static/ask-1.js', 'script', 7);
await drain();
check(pcAsk.ok === false && fetched.length === beforeAsk, 'nothing collected or fetched before the user answers');

check((await send({ type: 'approve', tabId: 7, url: PAGE, choice: 'tab' })).ok, '"Scan this tab" accepted');
await sleep(50);
check(memSession.approvedTabs?.[7] === 'app.acme.test', 'one-off approval kept in session storage (survives worker restarts)');
check((await send({ type: 'scope' })).state === 'scan' && badges[7] !== '?', 'approved tab: state scan, "?" badge cleared');
fire('https://app.acme.test/static/ask-1.js', 'script', 7);
fire('https://app.acme.test/static/ask-2.js', 'script', 8);
await drain();
check(fetched.includes('https://app.acme.test/static/ask-1.js') && !fetched.includes('https://app.acme.test/static/ask-2.js'), 'approved tab scanned; another tab on the same site still waits');
tabUpdate(7, 'https://other.example/');
check(!memSession.approvedTabs?.[7], 'approval dropped when the tab navigates to another host');

check((await send({ type: 'approve', tabId: 8, url: PAGE, choice: 'always' })).ok && mem.settings.allowHosts.includes('app.acme.test'), '"Always scan this site" adds the host to the allow-list');
fire('https://app.acme.test/static/ask-2.js', 'script', 8);
await drain();
check(fetched.includes('https://app.acme.test/static/ask-2.js'), 'allow-listed site scanned in any tab without asking');
await chrome.storage.local.set({ settings: { ...mem.settings, runtimeHooks: true } });
await sleep(50);
check(JSON.stringify(registered.get('jsrecon-runtime')?.matches) === JSON.stringify(['*://app.acme.test/*', '*://*.app.acme.test/*']), 'runtime hooks registered only for allow-listed sites in ask mode');
await chrome.storage.local.set({ settings: { ...mem.settings, runtimeHooks: false } });

const adsPage = 'https://ads.other.example/x';
check((await send({ type: 'approve', tabId: 9, url: adsPage, choice: 'never' })).ok && mem.settings.denyHosts.includes('ads.other.example'), '"Never" adds the host to the deny-list');
check((await send({ type: 'scope' }, { tab: { id: 9, url: adsPage } })).state === 'off', 'deny-listed site: no prompt');

// upgrading: installs still holding the old default scope move to ask-first once
const upgrade = async (previousVersion) => {
  for (const l of listeners.installed) await l({ reason: 'update', previousVersion });
};
await chrome.storage.local.set({ settings: { ...mem.settings, scopeMode: 'all' } });
await upgrade('1.7.0');
check(mem.settings.scopeMode === 'ask', 'update from 1.7.0: "every open tab" → ask first');
await chrome.storage.local.set({ settings: { ...mem.settings, scopeMode: 'allowlist' } });
await upgrade('1.6.0');
check(mem.settings.scopeMode === 'allowlist', 'update: explicit allow-list setup left alone');
await chrome.storage.local.set({ settings: { ...mem.settings, scopeMode: 'active' } });
await upgrade('1.8.0');
check(mem.settings.scopeMode === 'active', 'no migration when already on 1.8.0');
await chrome.storage.local.set({ settings: { ...mem.settings, allowHosts: [], denyHosts: [] } });
await chrome.storage.local.set({ settings: { ...mem.settings, scopeMode: 'all' } });

console.log('\nStatic file dumper & source reconstruction');
{
  const { dumpHosts, sourcesZip } = await import('../ui/dump.js');
  const { readZip } = await import('./zip-read.mjs');
  // Read the archive in-process: no dependency on the host's tar/unzip (GNU tar can't read zip).
  const unzip = async (blob) => {
    const entries = readZip(Buffer.from(await blob.arrayBuffer()));
    return { text: (n) => entries.get(n)?.data.toString('utf8'), has: (n) => entries.has(n), names: [...entries.keys()] };
  };
  let progress = 0;
  const r = await dumpHosts(['app.acme.test'], { js: true, maps: true, sources: true, nodeModules: false }, (d) => (progress = d));
  const z = await unzip(r.blob);
  const base = 'app.acme.test/';
  check(z.text(base + 'files/app.acme.test/static/main.abc.js') === FILES['https://app.acme.test/static/main.abc.js'].body, 'JS file dumped byte-for-byte');
  check(z.has(base + 'files/app.acme.test/static/main.abc.js.map'), '.map file dumped');
  check(z.text(base + 'sources/main.abc.js.map/src/api/payments.ts')?.includes('STRIPE_KEY'), 'original source rebuilt from map (src/api/payments.ts)');
  check(!z.names.some((n) => n.startsWith(base + 'sources/main.abc.js.map/node_modules/')), 'node_modules sources excluded by default');
  check(!z.has(base + 'files/app.acme.test/static/missing.js'), 'failed files skipped');
  const idx = JSON.parse(z.text('_index.json'));
  check(idx.files.length >= 5 && progress > 0, `_index.json lists ${idx.files.length} entries, ${r.files} files, ${r.errors} errors`);

  const mapFile = mem['host:app.acme.test'].files['https://app.acme.test/static/main.abc.js.map'];
  const one = await sourcesZip('app.acme.test', mapFile);
  const z2 = await unzip(one.blob);
  check(one.files === 1 && z2.has('app.acme.test/main.abc.js.map/src/api/payments.ts'), 'single-map "Sources .zip"');
}

console.log('\nRescan & clear');
const n = fetched.length;
await send({ type: 'rescan', host: 'app.acme.test', tabId: 7 });
await drain();
check(fetched.length > n, `rescan re-fetched ${fetched.length - n} files`);
await send({ type: 'clear', host: 'app.acme.test' });
await sleep(100);
check(!mem['host:app.acme.test'] && !mem.index['app.acme.test'], 'clear removed host data and index entry');

console.log('\nManual scan');
await send({ type: 'scan-text', host: 'manual', text: `const t = "${fakeStripe}";` });
await drain();
check(Object.values(mem['host:manual']?.findings || {}).some((f) => f.value === fakeStripe), 'pasted code scanned into "manual"');

// on a freshly cleared host, so earlier fixtures can't look like an older version of these scripts
console.log('\nChange alerts');
FILES['https://app.acme.test/static/js/main.1111aaaa.js'] = { body: 'fetch("/api/v1/profile");var a="/api/v1/settings";' };
FILES['https://app.acme.test/static/js/main.2222bbbb.js'] = { body: 'fetch("/api/v1/profile");var a="/api/v1/settings";axios.post("/api/v2/admin/export",d);' };
FILES['https://app.acme.test/static/js/vendor.4444dddd.js'] = { body: 'var v="/api/v1/health";' };
FILES['https://app.acme.test/static/js/vendor.5555eeee.js'] = { body: 'var v="/api/v1/health";var w="/api/v1/metrics";' };
FILES['https://app.acme.test/static/js/new-feature.3333cccc.chunk.js'] = { body: 'var p="/api/v2/beta/feature-x";' };
fire('https://app.acme.test/static/js/main.1111aaaa.js');
fire('https://app.acme.test/static/js/vendor.4444dddd.js');
await drain();
check(!mem['host:app.acme.test'].changes?.length, 'first version: no change recorded');
fire('https://app.acme.test/static/js/main.2222bbbb.js');
await drain();
fire('https://app.acme.test/static/js/vendor.5555eeee.js');
fire('https://app.acme.test/static/js/new-feature.3333cccc.chunk.js');
await drain();
const d9 = mem['host:app.acme.test'];
const ch = d9.changes?.[0];
check(ch && ch.from.endsWith('main.1111aaaa.js') && ch.to.endsWith('main.2222bbbb.js'), `deploy detected (${ch?.from?.split('/').pop()} → ${ch?.to?.split('/').pop()})`);
check(d9.findings['api|POST /api/v2/admin/export']?.changedAt === ch?.at && d9.findings['endpoints|/api/v1/profile']?.changedAt === undefined, 'only what is new in the new version is marked new');
check(d9.findings['endpoints|/api/v2/beta/feature-x']?.changedAt === ch?.at && d9.findings['endpoints|/api/v1/metrics']?.changedAt === ch?.at, 'other changed and new files of the same deploy attached to it');
const chf = d9.findings['intel|main.1111aaaa.js → main.2222bbbb.js'];
check(d9.changes.length === 1 && chf?.rule === 'bundle-changed' && chf.meta['files changed'] === 2, `one change and one Intel finding per deploy (${chf?.meta?.['files changed']} files, new: ${chf?.meta?.new})`);

console.log(failures ? `\n${failures} check(s) failed` : '\nAll checks passed');
process.exit(failures ? 1 : 0);
