// Passwords the generic "key = value" rule misses:
//   - short keys: pass, pw, passphrase, passcode (userPass, DB_PASS, smtpPw …)
//   - credential pairs: { username: "admin", password: "admin" } — short / simple passwords count
//     when a username sits next to them
//   - client-side checks: if (pass === "letmein")
//   - values behind a variable (const p = "…"; login({ password: p })) or atob("…")
//   - btoa("user:pass") Basic-auth credentials
//   - password inputs with a prefilled value (HTML, and JSX type: "password", defaultValue: "…")
// Pure: no chrome.* APIs. The helpers from rules.js are passed in (makePasswordRules) to avoid an
// import cycle.

const S = 'secrets';
const PW_WORDS = new Set(['pass', 'password', 'passwd', 'passphrase', 'passcode', 'pwd', 'pw']);
const SHORT_KEYS = new Set(['pass', 'passphrase', 'passcode', 'pw']); // the generic rule covers password / passwd / pwd
const NOT_PASSWORDS = new Set([
  'new-password', 'current-password', 'one-time-code', 'off', 'on', 'hidden', 'text', 'input', 'field', 'show', 'hide',
  'required', 'invalid', 'error', 'empty', 'mismatch', 'weak', 'strong', 'medium', 'reset', 'change', 'forgot', 'confirm',
  'username', 'user', 'email', 'login', 'pass', 'pwd', 'pw', 'passwd', 'passphrase', 'secret', 'none', 'default',
]);
const NOT_USERS = new Set(['username', 'user', 'email', 'e-mail', 'login', 'name', 'account', 'id', 'userid', 'user_id', 'uid', 'required', 'invalid', 'text', 'string', 'none']);
const IDENT_STOP = new Set(['true', 'false', 'null', 'undefined', 'this', 'void', 'new', 'typeof', 'function', 'return', 'await', 'async', 'class', 'in', 'of', 'instanceof']);

/** "userPass" / "DB_PASS" / "smtp-password" → the password word it ends with, or null. */
export function passwordWord(key) {
  const words = String(key || '')
    .split(/[_\-$.]+|(?<=[a-z0-9])(?=[A-Z])/)
    .filter(Boolean);
  const last = words.at(-1)?.toLowerCase();
  return PW_WORDS.has(last) ? last : null;
}

/** Something a person could have typed as a password (not a label, message key, constant or URL). */
export function plausiblePassword(v, notPlaceholder, reserved) {
  if (!v || v.length < 3 || v.length > 128) return false;
  if (/\s/.test(v) || /\$\{|\{\{|%[sd]|^\*+$|^•+$/.test(v)) return false;
  const low = v.toLowerCase();
  if (NOT_PASSWORDS.has(low) || reserved.has(low) || !notPlaceholder(v)) return false;
  if (/pass(?:word|wd)?|pwd/i.test(v) && /^[A-Za-z_.:-]+$/.test(v)) return false; // passwordTooShort, auth.password.label
  if (/^[a-z]+(?:[._:][a-z0-9]+)+$/i.test(v) && !/\d/.test(v)) return false; // i18n keys
  if (/^[a-z]+(?:[A-Z][a-z]+)+$/.test(v)) return false; // camelCaseIdentifier
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)) return false; // ACTION_TYPES
  if (/^(?:[a-z][a-z0-9+.-]*:)?\/\/|^[./#?]/.test(v)) return false; // URLs, paths, selectors
  if (/^(?:text|application|image)\//i.test(v)) return false;
  return true;
}

function plausibleUser(v, notPlaceholder, reserved) {
  if (!v || v.length < 2 || v.length > 64 || /\s|\$\{|\{\{/.test(v)) return false;
  const low = v.toLowerCase();
  if (NOT_USERS.has(low) || reserved.has(low) || !notPlaceholder(v)) return false;
  if (/^[a-z]+(?:\.[a-z]+)+$/.test(v)) return false; // i18n keys (svc_report and e-mail addresses are fine)
  return true;
}

const USER_RE = /["'`]?\b(user(?:_?name)?|username|login|e?-?mail|account|usr|admin_?user|user_?id)["'`]?\s*[:=]\s*(["'`])([^"'`\s\\]{1,64})\2/gi;

/** The username literal closest to `index` within the same neighbourhood (an object literal, a call). */
function nearbyUser(code, index, len, ok) {
  const from = Math.max(0, index - 200);
  const win = code.slice(from, Math.min(code.length, index + len + 200));
  let best = null;
  for (const m of win.matchAll(USER_RE)) {
    if (!ok(m[3])) continue;
    // same object / call only: a statement boundary between them means they belong to different things
    const a = from + m.index;
    const between = a < index ? code.slice(a + m[0].length, index) : code.slice(index + len, a);
    if (between.includes(';')) continue;
    const d = Math.abs(a - index);
    if (!best || d < best.d) best = { user: m[3], d };
  }
  return best?.user || null;
}

/** `name` in `var a=1,name="x"` / `let name = "x"` / `name="x"` before `index` (the last one wins). */
export function variableValue(code, index, name, maxBack = 3000) {
  const from = Math.max(0, index - maxBack);
  const before = code.slice(from, index);
  const esc = name.replace(/\$/g, '\\$');
  const re = new RegExp(`(?:^|[^\\w$.])${esc}\\s*=\\s*(["'\`])((?:(?!\\1)[^\\\\\\n]){1,128})\\1`, 'g');
  let last = null;
  for (const m of before.matchAll(re)) last = m[2];
  return last;
}

function decodeB64(s) {
  try {
    const t = atob(s);
    return /^[\x20-\x7e]+$/.test(t) ? t : null;
  } catch {
    return null;
  }
}

/**
 * Builds the password rules; `h` = { isLikelySecret, notPlaceholder, RESERVED_WORDS } from rules.js.
 * They run before the generic secret rule, so when both match a value the richer finding (a
 * credential pair, a client-side check) is kept.
 */
export function makePasswordRules(h) {
  const okPw = (v) => plausiblePassword(v, h.notPlaceholder, h.RESERVED_WORDS);
  const okUser = (v) => plausibleUser(v, h.notPlaceholder, h.RESERVED_WORDS);

  // key, operator, then a quoted literal, atob("…") or an identifier
  const KEY_RE =
    /\b([A-Za-z0-9_$-]{0,30}?(?:pass(?:word|wd|phrase|code)?|pwd|pw))(?:\.value|\.val\(\))?["'`]?\s*(:|={1,3})\s*(?:(["'`])((?:(?!\3)[^\\\n]){1,128})\3|atob\(\s*(["'`])([A-Za-z0-9+/=]{4,200})\5\s*\)|([A-Za-z_$][\w$]{0,40})\b(?!\s*[(.[`]))/gi;

  function keyPost(v, m, ctx) {
    const [, key, op, , lit, , b64, ident] = m;
    const word = passwordWord(key);
    if (!word) return null;
    let value = lit;
    const meta = { key };
    let confidence = null;
    if (b64 != null) {
      value = decodeB64(b64);
      meta.encoded = 'base64 (atob)';
    } else if (ident != null) {
      if (IDENT_STOP.has(ident)) return null;
      value = variableValue(ctx.code, ctx.index, ident);
      if (value == null) return null;
      meta.via = `variable ${ident}`;
      confidence = 'tentative'; // minified scopes reuse short names
    }
    if (!value || !okPw(value)) return null;
    const compare = op.startsWith('==');
    const user = compare ? null : nearbyUser(ctx.code, ctx.index, v.length, okUser);
    if (compare) {
      return { value, label: 'Client-side password check', severity: 'high', confidence: confidence || 'firm', meta: { ...meta, check: `${key} ${op} "${value}"` } };
    }
    if (user) {
      return { value, label: 'Hardcoded credentials', severity: 'high', confidence: confidence || 'firm', meta: { ...meta, username: user } };
    }
    // no username, no comparison: short keys need a strong value; password / passwd / pwd literals are
    // the generic rule's job, but values it can't see (variables, atob) are reported here
    if (!SHORT_KEYS.has(word) && lit != null) return null;
    if (!h.isLikelySecret(value, true)) return null;
    return { value, label: `Hardcoded ${key}`, severity: 'medium', ...(confidence ? { confidence } : {}), meta };
  }

  function btoaPost(v, m) {
    const [, , user, pass] = m;
    if (!okUser(user) || !okPw(pass)) return null;
    return { value: `${user}:${pass}`, confidence: 'firm', meta: { username: user, encoded: 'btoa → Basic auth' } };
  }

  function inputPost(v, m) {
    const tag = m[0];
    const val = /\b(?:value|defaultValue)\s*[=:]\s*(["'])([^"'\n]{1,128})\1/.exec(tag)?.[2];
    if (!val || !okPw(val)) return null;
    return { value: val, confidence: 'firm', meta: { field: tag.slice(0, 160) } };
  }

  return [
    {
      id: 'password-context',
      label: 'Hardcoded password',
      category: S,
      severity: 'medium',
      re: KEY_RE,
      generic: true,
      post: keyPost,
      desc: 'A password next to its key: a credential pair (a username alongside it), a client-side check (if (pass === "…")), a short key (pass, pw, passphrase) or a value behind a variable or atob(). Try the credentials on the login forms and APIs of the target.',
    },
    {
      id: 'basic-auth-btoa',
      label: 'Hardcoded Basic auth (btoa)',
      category: S,
      severity: 'high',
      re: /\bbtoa\(\s*(["'`])([^"'`:\s\\]{1,64}):([^"'`\s\\]{1,128})\1\s*\)/g,
      post: btoaPost,
      desc: 'Credentials encoded for an Authorization: Basic header in the client.',
    },
    {
      id: 'password-field-value',
      label: 'Prefilled password field',
      category: S,
      severity: 'high',
      re: /<input\b[^>]{0,300}?\btype\s*=\s*["']?password\b[^>]{0,300}>|\btype\s*:\s*["']password["'][^{}]{0,200}?\b(?:defaultValue|value)\s*:\s*["'][^"'\n]{1,128}["']/gi,
      post: inputPost,
      desc: 'A password input that ships with a value: anyone viewing the page source can read it.',
    },
  ];
}
