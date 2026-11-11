// DOM-XSS taint flows: a URL / attacker-influenced source reaching a dangerous sink inside the
// same expression or statement. Pure (no chrome.* APIs) so it unit-tests under Node.
//
// This is deliberately conservative — it reports a flow only when a recognised source
// (location.hash/search/href, document.URL/referrer, window.name, URLSearchParams, a URL-param
// getter) appears in the very value that is written to the sink. That keeps it precise enough to
// run by default, unlike the raw single-pattern sink rules. postMessage data flows are handled
// separately by the postMessage analyzer.

const SOURCES = [
  [/\blocation\s*\.\s*hash\b/, 'location.hash'],
  [/\blocation\s*\.\s*search\b/, 'location.search'],
  [/\blocation\s*\.\s*href\b/, 'location.href'],
  [/\blocation\s*\.\s*pathname\b/, 'location.pathname'],
  [/\bdocument\s*\.\s*URL\b/, 'document.URL'],
  [/\bdocument\s*\.\s*documentURI\b/, 'document.documentURI'],
  [/\bdocument\s*\.\s*referrer\b/, 'document.referrer'],
  [/\bdocument\s*\.\s*location\b/, 'document.location'],
  [/\bwindow\s*\.\s*name\b/, 'window.name'],
  [/\bnew\s+URLSearchParams\b|\bURLSearchParams\s*\(|\.searchParams\b/, 'URLSearchParams'],
  [/\b(?:getUrlParam|getQueryParam|getParameterByName|getUrlParameter)\s*\(/, 'URL-param getter'],
];

function findSource(text) {
  for (const [re, name] of SOURCES) if (re.test(text)) return name;
  return null;
}

/** Read a balanced, string-aware expression from `start` to a top-level statement break. */
function readExpr(code, start, max = 500) {
  let depth = 0;
  const end = Math.min(code.length, start + max);
  let i = start;
  for (; i < end; i++) {
    const c = code[i];
    if (c === '"' || c === "'" || c === '`') {
      for (i++; i < end && code[i] !== c; i++) if (code[i] === '\\') i++;
    } else if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) break;
      depth--;
    } else if (depth === 0 && (c === ';' || c === '\n' || c === ',')) break;
  }
  return code.slice(start, i);
}

/** Read the argument list of a call whose "(" is at `open`. */
function readArgs(code, open, max = 500) {
  let depth = 0;
  const end = Math.min(code.length, open + max);
  for (let i = open; i < end; i++) {
    const c = code[i];
    if (c === '"' || c === "'" || c === '`') {
      for (i++; i < end && code[i] !== c; i++) if (code[i] === '\\') i++;
    } else if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return code.slice(open + 1, i);
  }
  return code.slice(open + 1, end);
}

/**
 * Given a sink match at [index, index+len) and its mode, extract the value the sink receives and
 * check whether a taint source flows into it.
 * @returns {{source, value}|null}
 */
export function taintAt(code, index, len, mode) {
  const matchEnd = index + len;
  let value = '';
  if (mode === 'assign') {
    const eq = code.indexOf('=', index);
    if (eq < 0 || eq >= matchEnd) return null;
    value = readExpr(code, eq + 1);
  } else if (mode === 'call') {
    const open = code.lastIndexOf('(', matchEnd);
    if (open < 0) return null;
    value = readArgs(code, open);
  } else if (mode === 'jsx') {
    // dangerouslySetInnerHTML={{ __html: <expr> }} — read the object/expression that follows
    const br = code.indexOf('{', matchEnd);
    if (br < 0 || br - matchEnd > 40) return null;
    value = readExpr(code, br);
  }
  value = value.trim();
  if (!value) return null;
  const source = findSource(value);
  if (!source) return null;
  return { source, value: value.slice(0, 200) };
}
