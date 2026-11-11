// Lazy-chunk discovery. Pure: no chrome.* APIs, so it can be unit-tested with Node.
//
// Single-page apps only download the code for the screens you open. The bundler runtime, however,
// knows the file name of every chunk, so admin panels and other screens you never visited can be
// fetched and scanned:
//
//   webpack 4/5 (CRA, Vue CLI, Angular, Next.js …)
//       n.u = e => "static/js/" + ({35:"admin"}[e] || e) + "." + {35:"1f2e3d4c", 78:"9a8b7c6d"}[e] + ".chunk.js"
//     → the expression is evaluated for every chunk id in its maps, then resolved against
//       the public path (n.p = "/") or the runtime script's directory.
//   Next.js     self.__BUILD_MANIFEST = { "/admin": ["static/chunks/pages/admin-….js"], sortedPages: [...] }
//     → every page route plus its chunks.
//   Vite        __vite__mapDeps … m.f = ["assets/Admin-….js", …]   and   import("./Admin-….js")

const MAX_EXPR = 400000; // chunk maps of very large apps run to a few hundred KB

// ── tiny expression evaluator for the chunk-filename expression ──
// Grammar:  or := sum ("||" sum)* ;  sum := term ("+" term)* ;
//           term := (string | number | ident(.ident)* | "(" or ")" | object) ("[" or "]")*
// Evaluated with { [indexVar]: chunkId }. Other identifiers (the public path n.p …) evaluate to "".

const UNDEF = Symbol('undefined');

class Parser {
  constructor(src, varName) {
    this.s = src;
    this.i = 0;
    this.v = varName;
    this.maps = [];
  }
  ws() {
    while (this.i < this.s.length && /\s/.test(this.s[this.i])) this.i++;
  }
  peek(t) {
    this.ws();
    return this.s.startsWith(t, this.i);
  }
  eat(t) {
    if (!this.peek(t)) throw new Error(`expected ${t} at ${this.i}`);
    this.i += t.length;
  }
  string() {
    const q = this.s[this.i];
    let out = '';
    for (this.i++; this.i < this.s.length && this.s[this.i] !== q; this.i++) {
      if (this.s[this.i] === '\\') this.i++;
      out += this.s[this.i];
    }
    this.i++;
    return out;
  }
  object() {
    this.eat('{');
    const map = new Map();
    while (!this.peek('}')) {
      this.ws();
      let key;
      const c = this.s[this.i];
      if (c === '"' || c === "'") key = this.string();
      else {
        const m = /^[\w$.-]+/.exec(this.s.slice(this.i, this.i + 300));
        if (!m) throw new Error('bad key');
        key = m[0];
        this.i += key.length;
      }
      this.eat(':');
      this.ws();
      const vc = this.s[this.i];
      let val;
      if (vc === '"' || vc === "'") val = this.string();
      else {
        const m = /^[\w$.-]+/.exec(this.s.slice(this.i, this.i + 300));
        if (!m) throw new Error('bad value');
        val = m[0];
        this.i += val.length;
      }
      map.set(key, val);
      this.ws();
      if (this.s[this.i] === ',') this.i++;
    }
    this.eat('}');
    this.maps.push(map);
    return { t: 'map', map };
  }
  term() {
    this.ws();
    const c = this.s[this.i];
    let node;
    if (c === '"' || c === "'") node = { t: 'str', v: this.string() };
    else if (c === '(') {
      this.i++;
      node = this.or();
      this.eat(')');
    } else if (c === '{') node = this.object();
    else {
      const m = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*|^\d+/.exec(this.s.slice(this.i, this.i + 200));
      if (!m) throw new Error(`unexpected ${c} at ${this.i}`);
      this.i += m[0].length;
      node = /^\d/.test(m[0]) ? { t: 'str', v: m[0] } : { t: 'id', v: m[0] };
    }
    while (this.peek('[')) {
      this.eat('[');
      const idx = this.or();
      this.eat(']');
      node = { t: 'index', obj: node, idx };
    }
    return node;
  }
  sum() {
    const parts = [this.term()];
    while (this.peek('+') && !this.peek('++')) {
      this.eat('+');
      parts.push(this.term());
    }
    return parts.length === 1 ? parts[0] : { t: 'sum', parts };
  }
  or() {
    const alts = [this.sum()];
    while (this.peek('||')) {
      this.eat('||');
      alts.push(this.sum());
    }
    return alts.length === 1 ? alts[0] : { t: 'or', alts };
  }
}

function evaluate(node, env) {
  switch (node.t) {
    case 'str':
      return node.v;
    case 'id':
      return node.v in env ? env[node.v] : '';
    case 'map':
      return node.map;
    case 'index': {
      const obj = evaluate(node.obj, env);
      const k = evaluate(node.idx, env);
      if (obj instanceof Map) return obj.has(String(k)) ? obj.get(String(k)) : UNDEF;
      return UNDEF;
    }
    case 'sum': {
      let s = '';
      for (const p of node.parts) {
        const v = evaluate(p, env);
        if (v === UNDEF || v instanceof Map) return UNDEF;
        s += v;
      }
      return s;
    }
    case 'or': {
      for (const a of node.alts) {
        const v = evaluate(a, env);
        if (v !== UNDEF && v !== '') return v;
      }
      return UNDEF;
    }
    default:
      return UNDEF;
  }
}

/** Walk left from `end` over `term + term + …` and return where the expression starts. */
function expressionStart(code, end) {
  const min = Math.max(0, end - MAX_EXPR);
  let i = end;
  const skipWs = () => {
    while (i > min && /\s/.test(code[i])) i--;
  };
  const matchBack = (open, close) => {
    let depth = 0;
    for (; i >= min; i--) {
      const c = code[i];
      if (c === '"' || c === "'") {
        for (i--; i >= min && !(code[i] === c && code[i - 1] !== '\\'); i--);
        continue;
      }
      if (c === close) depth++;
      else if (c === open && --depth === 0) return true;
    }
    return false;
  };
  for (;;) {
    skipWs();
    const c = code[i];
    if (c === '"' || c === "'") {
      for (i--; i >= min && !(code[i] === c && code[i - 1] !== '\\'); i--);
    } else {
      // optional index suffixes:  …}[e]  …)[e]
      while (code[i] === ']') {
        if (!matchBack('[', ']')) return -1;
        i--;
        skipWs();
      }
      if (code[i] === '}') {
        if (!matchBack('{', '}')) return -1;
      } else if (code[i] === ')') {
        if (!matchBack('(', ')')) return -1;
      } else if (/[\w$.]/.test(code[i])) {
        while (i > min && /[\w$.]/.test(code[i - 1])) i--;
      } else return -1;
    }
    const termStart = i;
    i--;
    skipWs();
    if (code[i] === '+' && code[i - 1] !== '+') {
      i--;
      continue;
    }
    return termStart;
  }
}

const PUBLIC_PATH_RE = /\b[A-Za-z_$][\w$]*\.p\s*=\s*(["'])([^"'\s]{0,300})\1/;
// end of a chunk-filename expression:  + ".chunk.js"
const JS_SUFFIX_RE = /\+\s*(["'])((?:\.[\w-]+)*\.m?js)\1/g;

function webpackChunks(code, baseUrl) {
  if (!/\}\s*\)?\s*\[\s*[A-Za-z_$][\w$]*\s*\]/.test(code)) return null; // no "{…}[e]" lookup anywhere
  const urls = new Set();
  let publicPath = null;
  const pp = PUBLIC_PATH_RE.exec(code);
  if (pp) publicPath = pp[2];
  JS_SUFFIX_RE.lastIndex = 0;
  let m;
  let exprs = 0;
  let attempts = 0;
  while ((m = JS_SUFFIX_RE.exec(code)) && exprs < 20 && attempts++ < 300) {
    const end = m.index + m[0].length;
    // look back for the expression start from the char before the final "+"
    const start = expressionStart(code, m.index - 1);
    if (start < 0 || m.index - start > MAX_EXPR) continue;
    const src = code.slice(start, end);
    const idx = /\}\s*\)?\s*\[\s*([A-Za-z_$][\w$]*)\s*\]/.exec(src);
    if (!idx) continue;
    let ast;
    const p = new Parser(src, idx[1]);
    try {
      ast = p.or();
      p.ws();
      if (p.i < src.length) continue; // didn't consume the whole expression
    } catch {
      continue;
    }
    const ids = new Set();
    for (const map of p.maps) for (const k of map.keys()) ids.add(k);
    if (ids.size < 1) continue;
    exprs++;
    for (const id of ids) {
      const rel = evaluate(ast, { [idx[1]]: id });
      if (rel === UNDEF || typeof rel !== 'string' || !/\.m?js$/.test(rel)) continue;
      urls.add(rel);
    }
  }
  if (!urls.size) return null;
  // special cases webpack emits for some ids:  e===123?"static/chunks/123-abc.js":…   if("ncx"===e)return"ncx-abc.js"
  for (const s of code.matchAll(/===\s*[A-Za-z_$][\w$]*\s*(?:\?|\)\s*return)\s*(["'])([\w./-]+\.m?js)\1/g)) urls.add(s[2]);
  const base = publicPath != null && publicPath !== 'auto' ? resolve(publicPath, baseUrl) : baseUrl;
  return { kind: 'webpack', publicPath: publicPath ?? '(auto)', urls: [...urls].map((u) => resolve(u, base)).filter(Boolean) };
}

function resolve(u, base) {
  try {
    return new URL(u, base).href;
  } catch {
    return null;
  }
}

const NEXT_CHUNK_RE = /(?:\/_next\/)?static\/(?:immutable\/)?chunks\/[\w./~@%+[\]-]+?\.m?js(?![\w.])/g;

/**
 * Next.js: chunk paths ("static/chunks/…js") appear in the build manifest, the webpack/Turbopack
 * runtime and the inline flight data of app-router pages. self.__BUILD_MANIFEST (pages router)
 * also lists every route.
 */
function nextChunks(code, baseUrl) {
  const manifestAt = code.indexOf('__BUILD_MANIFEST');
  if (manifestAt < 0 && !/static\/(?:immutable\/)?chunks\//.test(code)) return null;
  // chunk paths are relative to the /_next/ directory
  const base = /^(.*?\/_next\/)/.exec(baseUrl || '')?.[1] || resolve('/_next/', baseUrl);
  const urls = new Set();
  for (const s of code.matchAll(NEXT_CHUNK_RE)) urls.add(s[0].startsWith('/') ? resolve(s[0], baseUrl) : resolve(s[0], base));
  const routes = new Set();
  if (manifestAt >= 0) {
    const body = code.slice(manifestAt, manifestAt + MAX_EXPR);
    const sorted = /sortedPages\s*:\s*\[([^\]]{0,200000})\]/.exec(body);
    if (sorted) for (const r of sorted[1].matchAll(/(["'])(\/[^"']*)\1/g)) routes.add(r[2]);
    for (const r of body.matchAll(/(["'])(\/[^"'\s]{0,300})\1\s*:\s*\[/g)) routes.add(r[2]);
  }
  const ssg = code.indexOf('__SSG_MANIFEST');
  if (ssg >= 0) for (const r of code.slice(ssg, ssg + 200000).matchAll(/(["'])(\/[^"'\s]{0,300})\1/g)) routes.add(r[2]);
  for (const r of [...routes]) if (/^\/_(?:app|error|document)$/.test(r)) routes.delete(r);
  if (!urls.size && !routes.size) return null;
  return { kind: 'next', publicPath: base, urls: [...urls].filter(Boolean), routes: [...routes] };
}

/** Vite: the preload dependency list (__vite__mapDeps) and literal dynamic imports. */
function esmChunks(code, baseUrl) {
  const urls = new Set();
  let kind = null;
  const deps = /__vite__mapDeps[\s\S]{0,200}?\.f\s*=\s*\[([^\]]{1,300000})\]/.exec(code);
  if (deps) {
    kind = 'vite';
    // deps are relative to the app base; the entry usually lives in <base>assets/
    const base = /^(.*?\/)assets\//.exec(baseUrl || '')?.[1] || resolve('/', baseUrl);
    for (const s of deps[1].matchAll(/(["'])([^"']+\.m?js)\1/g)) urls.add(resolve(s[2], base));
  }
  for (const s of code.matchAll(/\bimport\(\s*(["'`])(\.{1,2}\/[^"'`\s$]{1,300}\.m?js)\1\s*\)/g)) {
    kind ||= 'esm';
    urls.add(resolve(s[2], baseUrl));
  }
  return urls.size ? { kind, publicPath: null, urls: [...urls].filter(Boolean) } : null;
}

/**
 * @param {string} code      a scanned script (or inline script)
 * @param {string} baseUrl   the script's URL (or the page URL for inline scripts)
 * @returns {Array<{kind, publicPath, urls, routes?}>}
 */
export function findChunks(code, baseUrl) {
  if (typeof code !== 'string' || !code || !/^https?:/i.test(baseUrl || '')) return [];
  const out = [];
  for (const fn of [nextChunks, webpackChunks, esmChunks]) {
    try {
      const r = fn(code, baseUrl);
      if (r) out.push(r);
    } catch {
      /* malformed input – ignore */
    }
  }
  return out;
}
