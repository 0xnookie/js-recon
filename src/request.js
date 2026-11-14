// Request shape recovery for API calls found in code: what a variable holding the URL was set to,
// and which fields the request body (or params object) carries.
//
//   let url = "action.php"; xhr.open("POST", url); xhr.send(JSON.stringify({ id: 1 }))
//     → url "action.php", body fields [id] (JSON, sample {"id":1})
//
// Pure: no chrome.* APIs and no imports, so it can be unit-tested with Node. Everything here is a
// bounded, string-aware scan of the surrounding source — not a JavaScript parser — so every
// function gives up (returns null) rather than guess when the code doesn't have the expected shape.

const IDENT_RE = /^[A-Za-z_$][\w$]*/;
const MAX_FIELDS = 40;
// how far back an assignment to a variable is searched for (short / descriptive names)
const LOOKBACK = 4000;
const LOOKBACK_NAMED = 30000;

const esc = (s) => s.replace(/[$]/g, '\\$');

function skipWs(code, i) {
  while (i < code.length && /\s/.test(code[i])) i++;
  return i;
}

/** Index just past the string / template literal that starts at code[i]. */
function skipString(code, i) {
  const q = code[i];
  const end = Math.min(code.length, i + 20000);
  for (i++; i < end; i++) {
    const c = code[i];
    if (c === '\\') i++;
    else if (c === q) return i + 1;
    else if (q === '`' && c === '$' && code[i + 1] === '{') i = skipBalanced(code, i + 1) - 1;
  }
  return end;
}

/** Index just past the bracket group that starts at code[i] ( ({[ ). */
function skipBalanced(code, i) {
  let depth = 0;
  const end = Math.min(code.length, i + 20000);
  for (; i < end; i++) {
    const c = code[i];
    if (c === '"' || c === "'" || c === '`') {
      i = skipString(code, i) - 1;
    } else if (c === '(' || c === '[' || c === '{') {
      depth++;
    } else if (c === ')' || c === ']' || c === '}') {
      if (--depth === 0) return i + 1;
    }
  }
  return end;
}

/** A line break ends a statement (ASI) unless an operator on either side continues the expression. */
function newlineEnds(code, i) {
  let p = i - 1;
  while (p >= 0 && /[ \t\r]/.test(code[p])) p--;
  const n = skipWs(code, i);
  return !/[+\-*/%,([{:?=&|<>!]/.test(code[p] || '') && !/[+\-*/%.,)\]}?:=&|<>]/.test(code[n] || '');
}

/** Index of the `,` / `;` / closing bracket (or statement-ending line break) after the expression at code[i]. */
function exprEnd(code, i, max = 4000) {
  const end = Math.min(code.length, i + max);
  for (; i < end; i++) {
    const c = code[i];
    if (c === '"' || c === "'" || c === '`') i = skipString(code, i) - 1;
    else if (c === '(' || c === '[' || c === '{') i = skipBalanced(code, i) - 1;
    else if (c === ',' || c === ';' || c === ')' || c === ']' || c === '}') return i;
    else if (c === '\n' && newlineEnds(code, i)) return i;
  }
  return end;
}

/** The string literal at code[i] → { value, end, template }; template literals keep `${…}` as written. */
export function stringAt(code, i) {
  const q = code[i];
  if (q !== '"' && q !== "'" && q !== '`') return null;
  const end = skipString(code, i);
  if (end > code.length || code[end - 1] !== q) return null;
  const raw = code.slice(i + 1, end - 1);
  const value = q === '`' ? raw : raw.replace(/\\(.)/g, '$1');
  return { value, end, template: q === '`' && raw.includes('${') };
}

/** A literal value (number, string, boolean, null) at code[i], for sample payloads; undefined otherwise. */
function literalAt(code, i) {
  const s = stringAt(code, i);
  if (s && !s.template) return /^\s*[,})\]]/.test(code.slice(s.end, s.end + 20)) ? s.value.slice(0, 80) : undefined;
  const m = /^(-?\d+(?:\.\d+)?|true|false|null|!0|!1)\s*(?=[,})\]])/.exec(code.slice(i, i + 40));
  if (!m) return undefined;
  const t = m[1];
  return t === 'true' || t === '!0' ? true : t === 'false' || t === '!1' ? false : t === 'null' ? null : Number(t);
}

/**
 * Where `name` was last assigned before `before`: `let url = …`, `url = …`, `var a = 1, url = …`.
 * Returns the index of the assigned expression, or -1.
 */
export function assignmentBefore(code, name, before, max) {
  if (!IDENT_RE.test(name) || name.length > 60) return -1;
  const list = assignments(code).get(name);
  if (!list) return -1;
  // minified one/two-letter names are reused everywhere: only look close by; descriptive names
  // (CART_URL, endpoint) are often module-level constants further up
  const limit = Math.max(0, before - (max ?? (name.length > 2 ? LOOKBACK_NAMED : LOOKBACK)));
  let lo = 0;
  let hi = list.length; // first index with list[i] >= before
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (list[mid] < before) lo = mid + 1;
    else hi = mid;
  }
  // nearest first; skip assignments whose block closed before `before` (another function's variable)
  for (let k = lo - 1; k >= 0 && list[k] >= limit; k--) {
    const at = skipWs(code, list[k]);
    if (at < before && sameScope(code, at, before)) return at;
  }
  return -1;
}

// name → offsets just past `name =` for every simple assignment in the file; built once per file
let assignCache = { code: null, map: null };
function assignments(code) {
  if (assignCache.code === code) return assignCache.map;
  const map = new Map();
  const re = /(?<![\w$.])([A-Za-z_$][\w$]{0,59})[ \t]*=(?![=>])/g;
  let m;
  while ((m = re.exec(code))) {
    let list = map.get(m[1]);
    if (!list) map.set(m[1], (list = []));
    list.push(m.index + m[0].length);
  }
  assignCache = { code, map };
  return map;
}

/** No block that is open at `from` gets closed before `to` (string-aware brace count). */
function sameScope(code, from, to) {
  let depth = 0;
  for (let i = from; i < to; i++) {
    const c = code[i];
    if (c === '"' || c === "'" || c === '`') i = skipString(code, i) - 1;
    else if (c === '{') depth++;
    else if (c === '}' && --depth < 0) return false;
  }
  return true;
}

/**
 * A URL argument at code[i]: "lit", `tmpl`, base + "lit", "lit" + id, or a variable holding one of these.
 * → { path, prefix?, end, dynamicTail } — dynamicTail: something is concatenated after the literal ("/x/" + id).
 */
export function urlExprAt(code, i, depth = 0) {
  i = skipWs(code, i);
  let prefix;
  const s = stringAt(code, i);
  let lit = s;
  if (!s) {
    const id = /^([A-Za-z_$][\w.$]{0,60})\s*(\+\s*)?/.exec(code.slice(i, i + 80));
    if (!id) return null;
    if (id[2]) {
      lit = stringAt(code, i + id[0].length);
      if (!lit) return null;
      prefix = id[1];
    } else {
      // a variable holding the URL
      if (depth > 1 || id[1].includes('.')) return null;
      const at = assignmentBefore(code, id[1], i);
      if (at < 0) return null;
      const r = urlExprAt(code, at, depth + 1);
      return r && { ...r, end: i + id[1].length, via: id[1] };
    }
  }
  const after = code.slice(lit.end, lit.end + 60);
  const dynamicTail = /^\s*\+\s*[A-Za-z_$(]/.test(after);
  return { path: lit.value, prefix, end: lit.end, dynamicTail };
}

/** Field names (and literal sample values) of the object literal at code[from]. */
export function objectFields(code, from, max = 6000) {
  if (code[from] !== '{') return null;
  const fields = [];
  let partial = false;
  const end = Math.min(code.length, from + max);
  let i = from + 1;
  while (i < end && fields.length < MAX_FIELDS) {
    i = skipWs(code, i);
    const c = code[i];
    if (c === '}') return { fields, partial, end: i + 1 };
    if (c === ',') {
      i++;
      continue;
    }
    let name = null;
    if (c === '"' || c === "'") {
      const s = stringAt(code, i);
      if (!s) break;
      name = s.value;
      i = s.end;
    } else if (code.startsWith('...', i)) {
      partial = true; // spread: fields we can't see
      i = exprEnd(code, i + 3);
      continue;
    } else if (c === '[') {
      partial = true; // computed key
      i = skipBalanced(code, i);
    } else {
      const k = /^(?:[A-Za-z_$][\w$]*|\d+)/.exec(code.slice(i, i + 100));
      if (!k) break;
      name = k[0];
      i += name.length;
      if (/^(?:get|set|async)$/.test(name) && /^\s+[A-Za-z_$]/.test(code.slice(i, i + 3))) break; // accessor / async method
    }
    i = skipWs(code, i);
    if (code[i] === ':') {
      i = skipWs(code, i + 1);
      if (name != null) fields.push({ name, sample: literalAt(code, i) });
      i = exprEnd(code, i);
      if (code[i] !== ',' && code[i] !== '}') break;
    } else if (code[i] === '(') {
      // method shorthand: x() { … }
      i = skipWs(code, skipBalanced(code, i));
      if (code[i] !== '{') break;
      i = skipBalanced(code, i);
    } else if (name != null && (code[i] === ',' || code[i] === '}')) {
      fields.push({ name, sample: undefined }); // shorthand { id }
    } else {
      break;
    }
  }
  return fields.length || partial ? { fields, partial: true, end: i } : null;
}

/** "a=1&b=" + x + "&c=" → [a, b, c] — names from the string literals of a concatenation. */
function formStringFields(code, i) {
  const end = exprEnd(code, i);
  const parts = [];
  for (let j = i; j < end; ) {
    const s = stringAt(code, j);
    if (s) {
      parts.push(s.value);
      j = s.end;
    } else {
      parts.push('\u0000'); // a dynamic piece
      j++;
    }
  }
  const text = parts.join('').replace(/\u0000+/g, '\u0000');
  if (!/^[?&]?[A-Za-z_][\w.[\]-]{0,60}=/.test(text)) return null;
  const fields = [];
  for (const p of text.replace(/^[?&]/, '').split('&')) {
    const m = /^([A-Za-z_][\w.[\]-]{0,60})=([^\u0000]*)(\u0000)?/.exec(p);
    if (m && !fields.some((f) => f.name === m[1])) fields.push({ name: m[1], sample: m[3] ? undefined : decodeSafe(m[2]).slice(0, 80) });
  }
  return fields.length ? { fields, encoding: 'form' } : null;
}

function decodeSafe(s) {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    return s;
  }
}

/** fd.append("k", …), p.set("k", …), o.k = …, o["k"] = … between `from` and `to`. */
function builtFields(code, name, from, to) {
  const fields = [];
  const re = new RegExp(
    `(?<![\\w$.])${esc(name)}\\s*(?:\\.\\s*(?:append|set)\\(\\s*(["'\`])([^"'\`\\s]{1,80})\\1|\\.\\s*([A-Za-z_$][\\w$]{0,60})\\s*=(?![=>])|\\[\\s*(["'\`])([^"'\`\\s]{1,80})\\4\\s*\\]\\s*=(?![=>]))`,
    'g',
  );
  const win = code.slice(from, to);
  let m;
  while ((m = re.exec(win)) && fields.length < MAX_FIELDS) {
    const n = m[2] || m[3] || m[5];
    if (n && !fields.some((f) => f.name === n)) fields.push({ name: n, sample: m[3] || m[5] ? literalAt(code, skipWs(code, from + m.index + m[0].length)) : undefined });
  }
  return fields;
}

/**
 * The request body expression at code[i] → { fields: [{name, sample}], encoding, partial } or null.
 * encoding: "json" | "form" | "multipart" | null (an object literal whose encoding depends on the library).
 */
export function bodyAt(code, i, depth = 0) {
  i = skipWs(code, i);
  const head = code.slice(i, i + 40);
  let m;
  if ((m = /^JSON\s*\.\s*stringify\s*\(\s*/.exec(head))) {
    const inner = bodyAt(code, i + m[0].length, depth + 1);
    return inner ? { ...inner, encoding: 'json' } : { fields: [], encoding: 'json', partial: true };
  }
  if ((m = /^(?:new\s+URLSearchParams|(?:\$|jQuery)\s*\.\s*param)\s*\(\s*/.exec(head))) {
    const inner = code[i + m[0].length] === ')' ? null : bodyAt(code, i + m[0].length, depth + 1);
    return { fields: inner?.fields || [], encoding: 'form', partial: !inner };
  }
  if (/^new\s+FormData\s*\(/.test(head)) return { fields: [], encoding: 'multipart', partial: !/^new\s+FormData\s*\(\s*\)/.test(head) };
  if (code[i] === '{') {
    const o = objectFields(code, i);
    return o && { fields: o.fields, encoding: null, partial: o.partial };
  }
  const s = stringAt(code, i);
  if (s) {
    const t = s.value.trim();
    if (/^\{\s*"/.test(t)) {
      const keys = [...t.matchAll(/[{,]\s*"([^"\\]{1,80})"\s*:/g)].map((k) => ({ name: k[1], sample: undefined }));
      return keys.length ? { fields: keys, encoding: 'json', partial: false } : null;
    }
    return formStringFields(code, i);
  }
  // a variable holding the body (or a FormData / URLSearchParams built up before the call)
  const id = /^([A-Za-z_$][\w$]{0,60})(?![\w$.(])/.exec(head);
  if (!id || depth > 1) return null;
  const at = assignmentBefore(code, id[1], i);
  if (at < 0) return null;
  const base = bodyAt(code, at, depth + 1);
  const added = builtFields(code, id[1], at, i);
  if (!base && !added.length) return null;
  const fields = [...(base?.fields || [])];
  for (const f of added) if (!fields.some((x) => x.name === f.name)) fields.push(f);
  return { fields, encoding: base?.encoding ?? null, partial: base ? base.partial && !added.length : false };
}

/**
 * A top-level key of the object literal at code[from] whose name matches `keyRe`
 * → { name, at } (at: start of its value) or { name, shorthand: true } for `{ data }`; null if absent.
 */
export function objectKeyAt(code, from, keyRe, max = 6000) {
  if (code[from] !== '{') return null;
  const end = Math.min(code.length, skipBalanced(code, from), from + max);
  let i = from + 1;
  while (i < end) {
    i = skipWs(code, i);
    if (code[i] === ',') {
      i++;
      continue;
    }
    if (code[i] === '}') return null;
    let name = null;
    const s = stringAt(code, i);
    if (s) {
      name = s.value;
      i = s.end;
    } else {
      const k = IDENT_RE.exec(code.slice(i, i + 80));
      if (k) {
        name = k[0];
        i += name.length;
      } else if (code.startsWith('...', i)) {
        i = exprEnd(code, i + 3);
        continue;
      } else if (code[i] === '[') {
        i = skipBalanced(code, i);
      } else {
        return null;
      }
    }
    i = skipWs(code, i);
    if (code[i] === ':') {
      i = skipWs(code, i + 1);
      if (name != null && keyRe.test(name)) return { name, at: i };
      i = exprEnd(code, i);
    } else if (name != null && (code[i] === ',' || code[i] === '}')) {
      if (keyRe.test(name)) return { name, shorthand: true };
    } else {
      i = exprEnd(code, i);
    }
    if (i <= from) return null;
  }
  return null;
}

/** The body / params value of a key in an options object ({ body: … }, { data }, { params: {…} }). */
export function keyBody(code, objStart, keyRe) {
  const k = objectKeyAt(code, objStart, keyRe);
  if (!k) return null;
  if (!k.shorthand) return bodyAt(code, k.at);
  const at = assignmentBefore(code, k.name, objStart);
  return at < 0 ? null : bodyAt(code, at, 1);
}

/** A string-valued key of the object literal at code[objStart] (`method: "POST"`), or null. */
export function keyString(code, objStart, keyRe) {
  const k = objectKeyAt(code, objStart, keyRe);
  return k && !k.shorthand ? stringAt(code, k.at)?.value ?? null : null;
}

/** Start index of the next top-level argument after the expression at code[i] (`, <here>`), or -1. */
export function nextArg(code, i) {
  const e = exprEnd(code, i);
  return code[e] === ',' ? skipWs(code, e + 1) : -1;
}

export { skipWs, skipBalanced, exprEnd };

// ── what makes a request worth testing first ──

/** Field / path-variable names that carry an object reference: id, userId, order_id, uuid, accountID … */
export const ID_NAME_RE = /(?:[a-z0-9_-](?:Id|ID|Ids|IDs|Uuid|UUID|Guid|GUID)|[_-](?:id|ids|uuid|guid|pk))$/;
const BARE_ID_RE = /^(?:id|ids|uuid|guid|uid|oid|pk)$/i;

export const isIdName = (n) => BARE_ID_RE.test(String(n || '')) || ID_NAME_RE.test(String(n || ''));

/** "/api/users/{id}/x", "/u/:userId", "${base}/o/${order.id}" → true */
export function pathHasId(path) {
  const p = String(path || '');
  for (const m of p.matchAll(/\{([^{}]{1,60})\}|\/:([A-Za-z_]\w{0,60})|\$\{([^{}]{1,80})\}/g)) {
    if (m[3] && p.startsWith('${' + m[3] + '}')) continue; // base URL variable, not a path segment
    const name = (m[1] || m[2] || m[3]).split(/[.\s]/).pop();
    if (isIdName(name) || /^(?:token|slug|uuid|hash)$/i.test(name)) return true;
  }
  return false;
}

/** Sample payload for curl / reports: {"id":1} or id=1&qty= */
export function samplePayload(fields, encoding) {
  if (!fields?.length) return undefined;
  if (encoding === 'form' || encoding === 'multipart') {
    return fields.map((f) => `${encodeURIComponent(f.name)}=${f.sample == null ? '' : encodeURIComponent(String(f.sample))}`).join('&');
  }
  return JSON.stringify(Object.fromEntries(fields.map((f) => [f.name, f.sample === undefined ? '' : f.sample])));
}
