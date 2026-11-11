// Client-side route maps: React Router, Vue Router and Angular route tables, plus any
// framework whose routes are plain `{ path: '…', component/element/children }` objects or
// `<Route path="…">` JSX. Pure (no chrome.* APIs) so it unit-tests under Node.
//
// These are the application's own pages — including the ones never linked from the UI
// (/admin, /internal, debug consoles). A route behind a guard (canActivate, beforeEnter,
// requiresAuth, a <RequireAuth> wrapper) is flagged, because a protected page is usually
// the one worth testing.

// Something in the route's object/element that proves it really is a route and not some
// other `path:` config (webpack output.path, a file path, an SVG `path`, …).
const ROUTE_SIGNAL =
  /\b(?:element|component|components|Component|loadComponent|loadChildren|lazy|loader|shouldRevalidate|ErrorBoundary|errorElement|canActivate|canActivateChild|canLoad|canMatch|beforeEnter|beforeEnterGuards|redirectTo|redirect|alias|useRoutes|createBrowserRouter|createHashRouter|createMemoryRouter|createRoutesFromElements|RouterModule|outlet|pathMatch|caseSensitive|handle)\b|<Routes?\b/;

const GUARD_RE =
  /\b(?:canActivate|canActivateChild|canLoad|canMatch|beforeEnter|requiresAuth|requireAuth|requiresLogin|requireLogin|authGuard|AuthGuard|PrivateRoute|ProtectedRoute|RequireAuth|RequireRole|requireRole|ensureAuthenticated|isAuthenticated|loginRequired|roleGuard|RoleGuard|permissionGuard|withAuth)\b/;

const LAZY_RE = /\bloadChildren\b|\bloadComponent\b|\blazy\s*[:=]|React\.lazy|\bimport\s*\(/;
const REDIRECT_RE = /\bredirectTo\b|\bredirect\s*:/;

// Route paths whose names suggest privileged or otherwise sensitive areas.
const INTERESTING_RE =
  /(?:^|[/_:-])(?:admin|administrator|superuser|root|sudo|owner|staff|internal|intranet|private|secret|hidden|debug|dev|devtools|test|testing|staging|sandbox|preview|beta|console|dashboard|manage|management|moderat|operator|backoffice|back-office|control|settings?|config|setup|billing|payment|invoice|subscription|wallet|finance|account|user|users|member|customer|tenant|org|organization|workspace|team|role|permission|impersonat|audit|report|export|import|invite|onboard|integration|api-?keys?|credential|token|security|sso|saml|oauth|webhook|feature-?flags?)(?:$|[/_:-])/i;

const SKIP_EXT = /\.(?:js|mjs|cjs|ts|tsx|jsx|css|scss|less|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|otf|json|map|wasm|mp[34]|webm|pdf|txt|md|xml|html?)$/i;

function looksLikePath(v) {
  if (v.length > 200) return false;
  if (/^(?:https?:)?\/\//i.test(v)) return false; // absolute URL, handled by the URL rules
  if (/[\s<>"'`\\]/.test(v)) return false; // SVG data, sentences, template noise
  if (SKIP_EXT.test(v)) return false; // asset / module path
  if (/^#/.test(v)) return false; // in-page anchor
  if (/^\//.test(v)) return true; // /admin, /users/:id, /
  if (/^\*{1,2}$/.test(v)) return true; // wildcard
  if (/^\.{1,2}\//.test(v)) return true; // ./x, ../x
  // bare / relative segment: admin, users/:id, :id, settings/general
  return /^[:*]?[A-Za-z0-9_~.-]+(?:\/[:*]?[A-Za-z0-9_~.-]+)*\/?$/.test(v);
}

/** Smallest text window that belongs to this route: bounded by the neighbouring `path` keys. */
function routeWindow(code, index, valueLen) {
  const PATH_KEY = /\bpath\s*[:=]/g;
  let left = Math.max(0, index - 320);
  let right = Math.min(code.length, index + valueLen + 440);
  // don't reach past the previous route's path key
  const before = code.slice(left, index);
  let lastKey = -1;
  PATH_KEY.lastIndex = 0;
  let mm;
  while ((mm = PATH_KEY.exec(before)) !== null) lastKey = mm.index + mm[0].length;
  if (lastKey >= 0) left += lastKey;
  // …or into the next route's
  const after = code.slice(index + valueLen, right);
  PATH_KEY.lastIndex = 0;
  const next = PATH_KEY.exec(after);
  if (next) right = index + valueLen + next.index;
  return code.slice(left, right);
}

const RE_COMPONENT = /\bcomponent\s*:\s*([A-Za-z_$][\w$.]{0,60})/;
const RE_LOAD = /\b(?:loadComponent|loadChildren|lazy)\s*:[^,}]*?import\(\s*["'`]([^"'`]{1,120})["'`]|=>\s*import\(\s*["'`]([^"'`]{1,120})["'`]/;
const RE_ELEMENT = /\belement\s*[:=]\s*\{?\s*<\s*([A-Za-z_$][\w$.]{0,60})/;
const RE_NAME = /\bname\s*:\s*["'`]([^"'`]{1,60})["'`]/;
const RE_REDIRTO = /\bredirectTo\s*:\s*["'`]([^"'`]{0,200})["'`]/;

/**
 * value = a string a `path` key/attribute pointed at; index = where it starts in `code`.
 * Returns an analyzer finding override ({ value, tags, meta }) for category 'routes', or null.
 */
export function routeInfo(value, code, index) {
  if (!looksLikePath(value)) return null;
  const win = routeWindow(code, index, value.length);
  if (!ROUTE_SIGNAL.test(win)) return null;

  const tags = [];
  const guard = GUARD_RE.test(win);
  if (guard) tags.push('guarded');
  if (LAZY_RE.test(win)) tags.push('lazy');
  if (REDIRECT_RE.test(win)) tags.push('redirect');
  if (INTERESTING_RE.test(value)) tags.push('interesting');

  const meta = {};
  const comp = RE_COMPONENT.exec(win) || RE_ELEMENT.exec(win);
  if (comp) meta.component = comp[1];
  const load = RE_LOAD.exec(win);
  if (load) meta.module = load[1] || load[2];
  const name = RE_NAME.exec(win);
  if (name) meta.name = name[1];
  const to = RE_REDIRTO.exec(win);
  if (to) meta.redirectTo = to[1];
  const g = /\b(canActivate|canActivateChild|canLoad|canMatch|beforeEnter)\b/.exec(win);
  if (g) meta.guard = g[1];

  // A guarded or clearly privileged route is worth a nudge above plain info.
  const severity = guard && tags.includes('interesting') ? 'low' : 'info';
  return { value, tags, meta, severity };
}

/** Standalone scan (used by tests); the extension drives this through the rule engine instead. */
export function findRoutes(code) {
  const re = /\bpath\s*[:=]\s*\{?\s*(["'`])((?:\\.|(?!\1)[^\\\r\n]){0,200}?)\1/g;
  const out = [];
  let m;
  while ((m = re.exec(code)) !== null) {
    const value = m[2];
    const at = m.index + m[0].lastIndexOf(value);
    const info = routeInfo(value, code, at);
    if (info) out.push(info);
  }
  return out;
}
