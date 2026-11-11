// Source-map helpers shared by the service worker (scanning) and the UI (source reconstruction).

/** Finds the source map reference of a JS file (SourceMap header or trailing sourceMappingURL comment). */
export function sourceMapRef(text, headers) {
  const h = headers?.get?.('sourcemap') || headers?.get?.('x-sourcemap');
  if (h) return h.trim();
  const at = text.lastIndexOf('sourceMappingURL=');
  if (at === -1 || !/[#@]\s*$/.test(text.slice(Math.max(0, at - 4), at))) return null;
  const m = /^sourceMappingURL=([^\s'"`*]+)/.exec(text.slice(at, at + 50_000_000));
  return m ? m[1] : null;
}

export function decodeDataUri(uri) {
  const comma = uri.indexOf(',');
  if (comma < 0) return null;
  const meta = uri.slice(5, comma);
  const body = uri.slice(comma + 1);
  try {
    if (/;base64/i.test(meta)) {
      const bin = atob(body);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder().decode(bytes);
    }
    return decodeURIComponent(body);
  } catch {
    return null;
  }
}

export function parseSourceMap(text) {
  if (!text) return null;
  let t = text.trimStart();
  if (t.startsWith(")]}'")) t = t.slice(t.indexOf('\n') + 1);
  if (!t.startsWith('{')) return null;
  try {
    const j = JSON.parse(t);
    if (j && (Array.isArray(j.sources) || Array.isArray(j.sections))) return j;
  } catch {
    /* not JSON */
  }
  return null;
}

/** Flattens a (possibly indexed) source map into [{ path, content }]. */
export function mapEntries(map) {
  const out = [];
  const collect = (m) => {
    const root = m.sourceRoot ? String(m.sourceRoot).replace(/\/?$/, '/') : '';
    (m.sources || []).forEach((src, i) => out.push({ path: root + (src ?? ''), content: m.sourcesContent?.[i] ?? null }));
  };
  if (Array.isArray(map.sections)) map.sections.forEach((sec) => sec.map && collect(sec.map));
  else collect(map);
  return out;
}

export const cleanSourcePath = (p) =>
  String(p)
    .replace(/^webpack:\/\/[^/]*\//, '')
    .replace(/^[a-z][a-z0-9+.-]*:\/\/\/?/i, '')
    .replace(/^(?:\.\.?\/)+/, '')
    .replace(/^\/+/, '');

/** Candidate locations to probe when a script has no sourceMappingURL. */
export function probeCandidates(url) {
  const base = url.replace(/[?#].*$/, '');
  const out = [base + '.map'];
  if (/\.m?js$/i.test(base)) out.push(base.replace(/\.(m?js)$/i, '.map'));
  return out;
}
