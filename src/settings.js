// Extension settings (stored in chrome.storage.local under "settings").

export const DEFAULT_IGNORED_SCRIPT_HOSTS = [
  'google-analytics.com', 'googletagmanager.com', 'googlesyndication.com', 'googleadservices.com',
  'doubleclick.net', 'adservice.google.com', 'gstatic.com', 'recaptcha.net', 'youtube.com', 'ytimg.com',
  'facebook.net', 'connect.facebook.net', 'fbcdn.net', 'twitter.com', 'twimg.com', 'licdn.com',
  'linkedin.com', 'snap.licdn.com', 'bing.com', 'clarity.ms', 'tiktok.com', 'pinimg.com',
  'hotjar.com', 'segment.com', 'segment.io', 'mixpanel.com', 'amplitude.com', 'fullstory.com',
  'heap.io', 'heapanalytics.com', 'mouseflow.com', 'crazyegg.com', 'quantserve.com',
  'scorecardresearch.com', 'criteo.com', 'criteo.net', 'taboola.com', 'outbrain.com',
  'adsrvr.org', 'adnxs.com', 'rubiconproject.com', 'pubmatic.com', 'amazon-adsystem.com',
  'cookielaw.org', 'onetrust.com', 'cookiebot.com', 'consensu.org', 'trustarc.com',
  'intercom.io', 'intercomcdn.com', 'hs-scripts.com', 'hs-analytics.net', 'hsforms.net',
  'hscollectedforms.net', 'hs-banner.com', 'zdassets.com', 'zendesk.com', 'driftt.com',
  'optimizely.com', 'newrelic.com', 'nr-data.net', 'sentry-cdn.com', 'datadoghq-browser-agent.com',
  'cloudflareinsights.com', 'polyfill-fastly.io',
];

export const DEFAULT_SETTINGS = {
  enabled: true, // passive scanning of every page you visit
  scanInline: true, // inline <script> blocks
  scanHtml: true, // the rendered DOM (HTML comments, data attributes, links …)
  fetchSourceMaps: true, // follow sourceMappingURL and scan the original sources
  probeSourceMaps: false, // also try <script>.map when no sourceMappingURL is present
  skipNodeModules: true, // skip node_modules/* sources inside source maps
  crawlJs: false, // fetch same-site .js files referenced inside scanned JS (lazy chunks)
  crawlLimit: 150, // max crawled files per host
  fetchChunks: true, // fetch the lazy chunks the bundler runtime knows about (webpack, Next.js, Vite, ESM)
  chunkLimit: 400, // max chunk files fetched per host
  captureHeaders: true, // analyse response headers of the target's own servers (CORS, CSP, cookies, banners)
  observeRequests: true, // record the fetch / XHR / WebSocket calls pages make (method, path, parameter and header names)
  runtimeHooks: false, // opt-in: hook the page's own world to record parameter / storage / cookie names, body fields, message handlers
  waybackAuto: false, // opt-in: look up historical JS on the Wayback Machine for every new host
  waybackLimit: 100, // archived files fetched per lookup
  firstPartyOnly: false, // only scan scripts from the same site as the page
  maxFileSizeMB: 15,
  concurrency: 4,
  checkNpm: true, // verify discovered package names against registry.npmjs.org (dependency confusion)
  notify: false, // desktop notification on new critical / high-severity findings
  // 'ask' (nothing is scanned until you OK the site from the popup) | 'active' (only the tab in front)
  // | 'all' (every open tab) | 'allowlist'
  scopeMode: 'ask',
  allowHosts: [],
  denyHosts: [],
  ignoreScriptHosts: DEFAULT_IGNORED_SCRIPT_HOSTS,
  ruleOverrides: {}, // { ruleId: true|false }
  customRules: '',
};

export async function getSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

export async function saveSettings(patch) {
  const current = await getSettings();
  const next = { ...current, ...patch };
  await chrome.storage.local.set({ settings: next });
  return next;
}
