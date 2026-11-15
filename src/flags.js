// Feature flags: the flag keys a client asks its feature-flag SDK about (LaunchDarkly, GrowthBook,
// Unleash, Optimizely, Flagsmith, Statsig, Split, ConfigCat, PostHog, and in-house helpers), with
// the fallback value the code passes, plus flag states from bootstrap / config payloads embedded in
// the bundle or the page (LaunchDarkly flag state, GrowthBook features, Unleash toggles, Flagsmith
// flags, Optimizely datafiles). Switched-off flags often guard features that already exist on the
// server: their endpoints, routes and parameters are worth trying.
// Pure: no chrome.* APIs, so it can be unit-tested with Node.

const F = 'flags';

const PROVIDERS = {
  launchdarkly: ['LaunchDarkly', /launchdarkly|\bLDClient\b|clientSideID|ldclient/i],
  growthbook: ['GrowthBook', /growthbook/i],
  unleash: ['Unleash', /unleash/i],
  optimizely: ['Optimizely', /optimizely/i],
  flagsmith: ['Flagsmith', /flagsmith/i],
  statsig: ['Statsig', /statsig/i],
  split: ['Split', /splitio|split\.io|SplitFactory|getTreatment/i],
  configcat: ['ConfigCat', /configcat/i],
  posthog: ['PostHog', /posthog/i],
};

// method → [providers it belongs to, needs one of their markers in the same file?]
// Specific names count on their own; generic ones (isEnabled, getValue, decide …) only next to the SDK.
const METHODS = {
  variation: [['launchdarkly'], false, true], // [.., .., needs a default argument]
  variationDetail: [['launchdarkly'], false, true],
  boolVariation: [['launchdarkly'], false],
  stringVariation: [['launchdarkly'], false],
  jsonVariation: [['launchdarkly'], false],
  useFeatureIsOn: [['growthbook'], false],
  useFeatureValue: [['growthbook'], false],
  getFeatureValue: [['growthbook'], false],
  evalFeature: [['growthbook'], false],
  isOn: [['growthbook'], true],
  isOff: [['growthbook'], true],
  useFlag: [['unleash'], false],
  useVariant: [['unleash'], false],
  getVariant: [['unleash'], true],
  isEnabled: [['unleash'], true],
  useDecision: [['optimizely'], false],
  decide: [['optimizely'], true],
  getFeatureVariable: [['optimizely'], false],
  getFeatureVariableBoolean: [['optimizely'], false],
  getFeatureVariableString: [['optimizely'], false],
  hasFeature: [['flagsmith'], false],
  getValue: [['flagsmith', 'configcat'], true],
  checkGate: [['statsig'], false],
  useGate: [['statsig'], false],
  useFeatureGate: [['statsig'], false],
  getFeatureGate: [['statsig'], false],
  getExperiment: [['statsig'], false],
  useExperiment: [['statsig'], false],
  getLayer: [['statsig'], false],
  useLayer: [['statsig'], false],
  getDynamicConfig: [['statsig'], false],
  useDynamicConfig: [['statsig'], false],
  getTreatment: [['split'], false],
  getTreatmentWithConfig: [['split'], false],
  getValueAsync: [['configcat'], false],
  getValueDetailsAsync: [['configcat'], false],
  getFeatureFlag: [['posthog'], false],
  getFeatureFlagPayload: [['posthog'], false],
  useFeatureFlagEnabled: [['posthog'], false],
  useFeatureFlagVariantKey: [['posthog'], false],
  useFeatureFlagPayload: [['posthog'], false],
  isFeatureEnabled: [['optimizely', 'posthog'], false, false, 'in-house'],
  useFeatureFlag: [['configcat'], false, false, 'in-house'],
  isFeatureOn: [[], false, false, 'in-house'],
  isFlagEnabled: [[], false, false, 'in-house'],
  featureEnabled: [[], false, false, 'in-house'],
  isFeatureActive: [[], false, false, 'in-house'],
  hasFeatureFlag: [[], false, false, 'in-house'],
};

const KEY = String.raw`[A-Za-z0-9_][\w.:/-]{1,99}`;
const LIT = String.raw`true|false|!0|!1|null|-?\d+(?:\.\d+)?|"[^"\\\n]{0,80}"|'[^'\\\n]{0,80}'`;

const CALL_RE = new RegExp(
  String.raw`(?:\.|\b)(${Object.keys(METHODS).join('|')})\s*\)?\s*\(\s*(["'\x60])(${KEY})\2\s*(?:,\s*(${LIT})\s*)?[,)]`,
  'g',
);

/** Words in a flag name that point at unreleased, internal or privileged features. */
const FLAG_WORDS = new Set(
  ('admin internal staff employee employees beta alpha preview experimental experiment unreleased debug dev test sandbox staging ' +
    'new next v2 v3 legacy kill killswitch bypass override impersonate impersonation superuser unlimited premium enterprise paid ' +
    'billing payment payments export import upload uploads api graphql webhook webhooks sso saml mfa 2fa auth permission permissions role roles')
    .split(' '),
);

/** "enableNewCheckout" / "new-checkout_v2" → true when one of its words is in FLAG_WORDS. */
export function interestingFlag(key) {
  return String(key)
    .split(/[._:/\s-]+|(?<=[a-z0-9])(?=[A-Z])/)
    .some((w) => FLAG_WORDS.has(w.toLowerCase()));
}

let lastCode = null;
let lastMarkers = null;
/** Which SDKs the text mentions (computed once per analysed text). */
function markers(code) {
  if (code !== lastCode) {
    lastCode = code;
    lastMarkers = new Set(Object.entries(PROVIDERS).filter(([, [, re]]) => re.test(code)).map(([k]) => k));
  }
  return lastMarkers;
}

/** "!1" → "false", "'x'" → "x". */
export function literal(v) {
  if (v == null) return undefined;
  if (v === '!0') return 'true';
  if (v === '!1') return 'false';
  if (/^["']/.test(v)) return v.slice(1, -1);
  return v;
}

const stateTag = (v) => (v === 'false' || v === 'off' || v === 'control' ? 'off' : v === 'true' || v === 'on' ? 'on' : null);

function flagFinding(key, provider, extra = {}) {
  const tags = [provider.toLowerCase().replace(/[^a-z0-9]+/g, '-')];
  if (extra.state) {
    const t = stateTag(extra.state);
    if (t) tags.push(t);
  }
  if (interestingFlag(key)) tags.push('interesting');
  const meta = { provider, ...extra.meta };
  if (extra.state != null) meta.state = extra.state;
  return {
    value: key,
    category: F,
    label: 'Feature flag',
    // a flag that is off for this user / environment is the lead: the feature behind it is unreleased
    severity: extra.state != null && stateTag(extra.state) === 'off' ? 'low' : 'info',
    tags,
    meta,
  };
}

/** post() for SDK call sites: `ld.variation("new-checkout", false)`, `(0,o.useFeatureIsOn)("x")` … */
export function flagCall(v, m, ctx) {
  const [, method, , key, def] = m;
  const spec = METHODS[method];
  if (!spec || /^(?:https?|\/\/)/.test(key) || /\.(?:js|css|json|png|svg|html?)$/i.test(key)) return null;
  const [cands, needsMarker, needsDefault, fallback] = spec;
  if (needsDefault && def == null) return null;
  const seen = markers(ctx.code);
  let provider = cands.find((c) => seen.has(c));
  if (!provider) {
    if (needsMarker) return null;
    provider = cands.length === 1 ? cands[0] : null;
  }
  const name = provider ? PROVIDERS[provider][0] : fallback || 'in-house';
  const meta = { call: `${method}("${key}"${def != null ? ', ' + def : ''})` };
  const d = literal(def);
  if (d != null) meta.default = d;
  return flagFinding(key, name, { meta });
}

/** post() factory for embedded flag states: group 1 = key, group 2 = state literal. */
const statePost = (provider, what) => (v, m) => {
  const key = m[1];
  if (!key || key.length > 100) return null;
  const state = m[2] ? literal(m[2]) : 'listed';
  return flagFinding(key, provider, { state, meta: { source: what } });
};

const Q = String.raw`["']`;
const STATE = String.raw`(true|false|!0|!1|null|-?\d+(?:\.\d+)?|"[^"\\\n]{0,80}")`;

const FLAG_DESC =
  'A feature-flag key the client evaluates. Features behind a flag that is off (or defaults to off) often already exist on the server: look for their endpoints, routes and parameters in the other tabs and try them. "state" is the value delivered to this page; "default" is the fallback in the code.';

export const FLAG_RULES = [
  // LaunchDarkly bootstrap / allFlagsState: "flag-key":{"value":false,"variation":1,"version":7,…}
  {
    id: 'flag-state-launchdarkly',
    label: 'Feature flag',
    category: F,
    severity: 'info',
    re: new RegExp(String.raw`${Q}(${KEY})${Q}\s*:\s*\{\s*${Q}value${Q}\s*:\s*${STATE}\s*,\s*${Q}(?:variation|version|trackEvents|flagVersion|reason|variationIndex)${Q}`, 'g'),
    post: statePost('LaunchDarkly', 'flag state (bootstrap)'),
    desc: FLAG_DESC,
  },
  // GrowthBook features payload: "feature-key":{"defaultValue":false,"rules":[…]}
  {
    id: 'flag-state-growthbook',
    label: 'Feature flag',
    category: F,
    severity: 'info',
    re: new RegExp(String.raw`${Q}(${KEY})${Q}\s*:\s*\{\s*${Q}defaultValue${Q}\s*:\s*${STATE}`, 'g'),
    post: statePost('GrowthBook', 'features payload (defaultValue)'),
    desc: FLAG_DESC,
  },
  // Unleash toggles: {"name":"x","enabled":false,"variant":{…}}
  {
    id: 'flag-state-unleash',
    label: 'Feature flag',
    category: F,
    severity: 'info',
    re: new RegExp(String.raw`\{\s*${Q}name${Q}\s*:\s*${Q}(${KEY})${Q}\s*,\s*${Q}enabled${Q}\s*:\s*(true|false|!0|!1)\s*,\s*${Q}(?:variant|impressionData|impression_data)${Q}`, 'g'),
    post: statePost('Unleash', 'toggles (bootstrap)'),
    desc: FLAG_DESC,
  },
  // Flagsmith SDK state: "key":{"id":12,"enabled":false,"value":null}
  {
    id: 'flag-state-flagsmith',
    label: 'Feature flag',
    category: F,
    severity: 'info',
    re: new RegExp(String.raw`${Q}(${KEY})${Q}\s*:\s*\{\s*${Q}id${Q}\s*:\s*\d+\s*,\s*${Q}enabled${Q}\s*:\s*(true|false|!0|!1)\s*,\s*${Q}value${Q}`, 'g'),
    post: statePost('Flagsmith', 'flags (SDK state)'),
    desc: FLAG_DESC,
  },
  // Optimizely datafile: {"experimentIds":[…],"id":"123","key":"new_checkout","rolloutId":"456",…}
  {
    id: 'flag-optimizely-datafile',
    label: 'Feature flag',
    category: F,
    severity: 'info',
    re: new RegExp(String.raw`${Q}id${Q}\s*:\s*${Q}\d+${Q}\s*,\s*${Q}key${Q}\s*:\s*${Q}(${KEY})${Q}\s*,\s*${Q}rolloutId${Q}()`, 'g'),
    post: statePost('Optimizely', 'datafile'),
    desc: FLAG_DESC,
  },
  { id: 'flag-sdk-call', label: 'Feature flag', category: F, severity: 'info', re: CALL_RE, post: flagCall, desc: FLAG_DESC },
];

/** Per-key flags from a plain `features: { a: false, b: true }` object (the Intel "Feature flags" rule). */
export function objectFlags(pairs) {
  return pairs.map(([key, on]) => flagFinding(key, 'config object', { state: on ? 'true' : 'false', meta: { source: 'config object' } }));
}

const SEV = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const VAGUE = new Set(['in-house', 'config object']);

/**
 * The same flag seen again (another rule in the same file, or another file): keep the most telling
 * state, the call site and default, the real provider over "in-house", and every tag.
 */
export function mergeFlag(f, r) {
  if (!r?.meta) return f;
  const keepProvider = f.meta?.provider && !VAGUE.has(f.meta.provider) ? f.meta.provider : null;
  f.meta = { ...(f.meta || {}), ...r.meta };
  if (keepProvider) f.meta.provider = keepProvider;
  if ((SEV[r.severity] || 0) > (SEV[f.severity] || 0)) f.severity = r.severity;
  for (const t of r.tags || []) if (!f.tags.includes(t)) f.tags = [...f.tags, t];
  if (f.tags.includes('in-house') && f.meta.provider && !VAGUE.has(f.meta.provider)) f.tags = f.tags.filter((t) => t !== 'in-house');
  return f;
}
