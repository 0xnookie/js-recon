// GraphQL documents in client code → operations, fragments and an inferred schema sketch.
// Pure: no chrome.* APIs, so it can be unit-tested with Node.
//
// Documents show up as gql`…` template literals, JSON-escaped strings (Apollo's loc.source.body,
// Relay's `text`) or plain strings. Only what the client selects is visible, so the schema is a
// sketch: root fields with their arguments, object types with the fields the client reads, and the
// names of input / enum types used as variable types.

const BUILTIN = new Set(['ID', 'String', 'Int', 'Float', 'Boolean']);

/**
 * Raw text of the definition whose header starts at code[at] ("query X(…) { … }"), up to the end of
 * its top-level selection set. null if no selection set follows (then it isn't GraphQL).
 */
export function definitionText(code, at, max = 30000) {
  const end = Math.min(code.length, at + max);
  let i = at;
  let paren = 0;
  for (; i < end; i++) {
    const c = code[i];
    if (c === '(') paren++;
    else if (c === ')') paren--;
    else if (c === '{' && paren === 0) break;
    else if (c === ';' || c === '`' || (c === '}' && paren === 0)) return null;
  }
  if (i >= end) return null;
  let depth = 0;
  for (; i < end; i++) {
    const c = code[i];
    if (c === '$' && code[i + 1] === '{') {
      // template-literal interpolation ${Fragment}: skip it entirely
      let d = 0;
      for (i++; i < end; i++) {
        if (code[i] === '{') d++;
        else if (code[i] === '}' && --d === 0) break;
      }
      continue;
    }
    if (c === '"') {
      for (i++; i < end && code[i] !== '"'; i++) if (code[i] === '\\' && code[i + 1] !== '"') i++;
      continue;
    }
    if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return code.slice(at, i + 1);
  }
  return null;
}

/** JS-escaped document text → plain GraphQL. */
export function cleanDocument(text) {
  return String(text)
    .replace(/\$\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}/g, '') // ${…} interpolations
    .replace(/\\r\\n|\\n|\\r/g, '\n')
    .replace(/\\t/g, '  ')
    .replace(/\\"/g, '"')
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/[ \t]+\n/g, '\n')
    .trim();
}

// ── tokenizer / parser for executable definitions ──

const TOKEN_RE = /\s+|,|#[^\n]*|(\.\.\.)|([{}()[\]:=!$@|&])|("(?:[^"\\]|\\.)*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([A-Za-z_]\w*)/y;

function tokenize(src) {
  const toks = [];
  let i = 0;
  while (i < src.length) {
    TOKEN_RE.lastIndex = i;
    const m = TOKEN_RE.exec(src);
    if (!m) {
      i++;
      continue;
    }
    i = TOKEN_RE.lastIndex;
    if (m[1]) toks.push({ t: 'spread', v: '...' });
    else if (m[2]) toks.push({ t: 'p', v: m[2] });
    else if (m[3]) toks.push({ t: 'str', v: m[3] });
    else if (m[4]) toks.push({ t: 'num', v: m[4] });
    else if (m[5]) toks.push({ t: 'name', v: m[5] });
  }
  return toks;
}

/** Parses one operation or fragment. Returns null if the text isn't a valid definition. */
export function parseDefinition(text) {
  const toks = tokenize(text);
  let p = 0;
  const peek = (v) => toks[p] && (v === undefined || toks[p].v === v);
  const next = () => toks[p++];
  const expect = (v) => {
    if (!peek(v)) throw new Error(`expected ${v}`);
    return next();
  };
  const name = () => {
    const t = next();
    if (!t || t.t !== 'name') throw new Error('expected name');
    return t.v;
  };
  const type = () => {
    let s;
    if (peek('[')) {
      next();
      s = `[${type()}]`;
      expect(']');
    } else s = name();
    if (peek('!')) {
      next();
      s += '!';
    }
    return s;
  };
  const value = () => {
    const t = next();
    if (!t) throw new Error('eof');
    if (t.v === '$') return { var: name() };
    if (t.t === 'str') return { str: true };
    if (t.t === 'num') return { num: true, float: /[.eE]/.test(t.v) };
    if (t.v === 'true' || t.v === 'false') return { bool: true };
    if (t.v === 'null') return { null: true };
    if (t.v === '[') {
      const items = [];
      while (!peek(']')) items.push(value());
      next();
      return { list: items };
    }
    if (t.v === '{') {
      const fields = {};
      while (!peek('}')) {
        const k = name();
        expect(':');
        fields[k] = value();
      }
      next();
      return { obj: fields };
    }
    if (t.t === 'name') return { enum: t.v };
    throw new Error('bad value');
  };
  const args = () => {
    const out = [];
    if (!peek('(')) return out;
    next();
    while (!peek(')')) {
      const n = name();
      expect(':');
      out.push({ name: n, value: value() });
    }
    next();
    return out;
  };
  const directives = () => {
    while (peek('@')) {
      next();
      name();
      args();
    }
  };
  const selectionSet = () => {
    expect('{');
    const sel = [];
    while (!peek('}')) {
      if (peek('...')) {
        next();
        if (peek('on')) {
          next();
          const on = name();
          directives();
          sel.push({ inline: on, selections: selectionSet() });
        } else if (peek('{') || peek('@')) {
          directives();
          sel.push({ inline: null, selections: selectionSet() });
        } else {
          sel.push({ spread: name() });
          directives();
        }
        continue;
      }
      let n = name();
      let alias = null;
      if (peek(':')) {
        next();
        alias = n;
        n = name();
      }
      const a = args();
      directives();
      sel.push({ name: n, alias, args: a, selections: peek('{') ? selectionSet() : [] });
    }
    next();
    return sel;
  };
  try {
    const kw = name();
    if (kw === 'fragment') {
      const n = name();
      expect('on');
      const on = name();
      directives();
      return { kind: 'fragment', name: n, on, variables: [], selections: selectionSet() };
    }
    if (!['query', 'mutation', 'subscription'].includes(kw)) return null;
    const n = name();
    const variables = [];
    if (peek('(')) {
      next();
      while (!peek(')')) {
        expect('$');
        const v = name();
        expect(':');
        const t = type();
        if (peek('=')) {
          next();
          value();
        }
        directives();
        variables.push({ name: v, type: t });
      }
      next();
    }
    directives();
    const selections = selectionSet();
    return selections.length ? { kind: kw, name: n, variables, selections } : null;
  } catch {
    return null;
  }
}

/** Finding data for a definition found at code[at]: { def, document } or null. */
export function graphqlAt(code, at) {
  const raw = definitionText(code, at);
  if (!raw) return null;
  const document = cleanDocument(raw);
  const def = parseDefinition(document);
  return def ? { def, document } : null;
}

// ── schema sketch ──

const pascal = (s) => s.charAt(0).toUpperCase() + s.slice(1);
const baseType = (t) => String(t).replace(/[[\]!]/g, '');

function leafType(field) {
  if (/^(?:id|uuid)$|[a-z](?:Id|ID|Uuid)$|_id$/.test(field)) return 'ID';
  if (/^(?:is|has|can|should|was|did|allow)[A-Z_]|^(?:enabled|active|deleted|verified|visible|locked|admin|disabled|archived)$/.test(field)) return 'Boolean';
  // whole names, or camelCase suffixes ("totalCount", not "message" for "age")
  if (/^(?:count|total|page|limit|offset|size|quantity|position|index|age|year|rank|level|version)$|[a-z](?:Count|Total|Size|Index|Position|Quantity|Number)$/.test(field)) return 'Int';
  if (/^(?:price|amount|balance|rate|ratio|score|latitude|longitude|lat|lng)$|[a-z](?:Price|Amount|Balance|Rate|Ratio|Score)$/.test(field)) return 'Float';
  return 'String';
}

function argType(v, vars) {
  if (v.var) return vars.get(v.var) || 'String';
  if (v.num) return v.float ? 'Float' : 'Int';
  if (v.bool) return 'Boolean';
  if (v.list) return v.list.length ? `[${argType(v.list[0], vars)}]` : '[String]';
  if (v.obj) return 'JSON';
  return 'String';
}

/**
 * @param {Array} defs parsed operations and fragments (parseDefinition results)
 * @returns {string} SDL-like schema sketch
 */
export function schemaSketch(defs) {
  const fragments = new Map(defs.filter((d) => d.kind === 'fragment').map((d) => [d.name, d]));
  const types = new Map(); // type → Map(field → { type, args: Map })
  const variableTypes = new Set();
  const ROOT = { query: 'Query', mutation: 'Mutation', subscription: 'Subscription' };
  const ensure = (t) => {
    if (!types.has(t)) types.set(t, new Map());
    return types.get(t);
  };
  const unions = new Map(); // abstract type → Set(member types) from several inline fragments
  const targetType = (field) => {
    const on = new Set();
    for (const s of field.selections) {
      if (s.inline) on.add(s.inline);
      else if (s.spread && fragments.get(s.spread)) on.add(fragments.get(s.spread).on);
    }
    if (on.size === 1) return [...on][0];
    const name = pascal(field.name);
    if (on.size > 1) {
      if (!unions.has(name)) unions.set(name, new Set());
      for (const t of on) unions.get(name).add(t);
    }
    return name;
  };
  const visit = (typeName, selections, vars, seen) => {
    const fields = ensure(typeName);
    for (const s of selections) {
      if (s.inline !== undefined) {
        visit(s.inline || typeName, s.selections, vars, seen);
        continue;
      }
      if (s.spread) {
        const fr = fragments.get(s.spread);
        if (fr && !seen.has(fr.name)) visit(fr.on, fr.selections, vars, new Set([...seen, fr.name]));
        continue;
      }
      if (s.name.startsWith('__')) continue;
      const f = fields.get(s.name) || { type: null, args: new Map() };
      for (const a of s.args) f.args.set(a.name, argType(a.value, vars));
      if (s.selections.length) {
        if (!f.type || BUILTIN.has(baseType(f.type))) f.type = targetType(s);
        visit(baseType(f.type), s.selections, vars, seen);
      } else if (!f.type) f.type = leafType(s.name);
      fields.set(s.name, f);
    }
  };
  let ops = 0;
  for (const d of defs) {
    const vars = new Map(d.variables.map((v) => [v.name, v.type]));
    for (const v of d.variables) if (!BUILTIN.has(baseType(v.type))) variableTypes.add(baseType(v.type));
    if (d.kind === 'fragment') visit(d.on, d.selections, vars, new Set([d.name]));
    else {
      ops++;
      visit(ROOT[d.kind], d.selections, vars, new Set());
    }
  }
  const order = [...types.keys()].sort((a, b) => {
    const r = (t) => ['Query', 'Mutation', 'Subscription'].indexOf(t);
    return (r(a) < 0 ? 9 : r(a)) - (r(b) < 0 ? 9 : r(b)) || a.localeCompare(b);
  });
  const out = [
    `# Schema sketch inferred by JS Recon from ${ops} operation${ops === 1 ? '' : 's'} and ${fragments.size} fragment${fragments.size === 1 ? '' : 's'}.`,
    '# Only the fields the client selects are listed. Scalar types are guesses from field names;',
    '# object type names come from fragments and inline fragments, otherwise from the field name.',
    '',
  ];
  // abstract types: an interface when the client also selects fields on it directly, else a union
  for (const [u, members] of [...unions].sort((a, b) => a[0].localeCompare(b[0]))) {
    if (!types.get(u)?.size) out.push(`union ${u} = ${[...members].sort().join(' | ')}   # or an interface`, '');
  }
  for (const t of order) {
    const fields = types.get(t);
    if (!fields.size) continue;
    out.push(unions.has(t) ? `interface ${t} {   # implemented by ${[...unions.get(t)].sort().join(', ')}` : `type ${t} {`);
    for (const [name, f] of [...fields].sort((a, b) => a[0].localeCompare(b[0]))) {
      const a = [...f.args].map(([k, v]) => `${k}: ${v}`).join(', ');
      out.push(`  ${name}${a ? `(${a})` : ''}: ${f.type}`);
    }
    out.push('}', '');
  }
  const used = [...variableTypes].filter((t) => !types.has(t)).sort();
  if (used.length) {
    out.push('# Input objects / enums used as variable types (their fields are not visible in the client):');
    for (const t of used) out.push(`#   ${t}`);
    out.push('');
  }
  return out.join('\n');
}
