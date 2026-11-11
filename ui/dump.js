// Source reconstruction from source maps and the static-file dumper (runs in the extension page).

import { ZipWriter, zipPath } from '../src/zip.js';
import { parseSourceMap, mapEntries, cleanSourcePath, sourceMapRef, decodeDataUri } from '../src/sourcemap.js';

const SCRIPT_KINDS = new Set(['script', 'crawled', 'chunk', 'manual']);
const INLINE_MAP_SUFFIX = ' [inline source map]';
const isHttp = (u) => /^https?:\/\//i.test(u);

async function fetchBytes(url) {
  const res = await fetch(url, { credentials: 'include', cache: 'force-cache' });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return new Uint8Array(await res.arrayBuffer());
}

function shortHash(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(36);
}

/** https://cdn.acme.io/static/main.js?v=3 → cdn.acme.io/static/main.q1x2y3.js */
export function urlToPath(url) {
  const u = new URL(url);
  let p = decodeURIComponentSafe(u.pathname);
  if (p.endsWith('/')) p += 'index';
  if (u.search) {
    const tag = 'q' + shortHash(u.search);
    const m = /^(.*?)(\.[A-Za-z0-9]{1,8})$/.exec(p);
    p = m ? `${m[1]}.${tag}${m[2]}` : `${p}.${tag}`;
  }
  return zipPath(u.host + p);
}

function decodeURIComponentSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/** Folder name for a source map's reconstructed sources. */
export function mapFolder(id) {
  const inline = id.endsWith(INLINE_MAP_SUFFIX);
  const raw = inline ? id.slice(0, -INLINE_MAP_SUFFIX.length) : id;
  let base = raw;
  try {
    base = new URL(raw).pathname.split('/').filter(Boolean).pop() || raw;
  } catch {
    /* inline:… ids */
  }
  return zipPath(base.replace(/[/:]/g, '_') + (inline ? '.inline-map' : ''));
}

/**
 * Whether the sources of a stored source-map entry can be rebuilt later: the map (or the JS file that embeds it)
 * must be fetchable. Maps embedded in inline <script> blocks are scanned but their text is not stored.
 */
export function canRebuild(file) {
  return file.kind === 'sourcemap' && file.status === 'done' && file.withContent > 0 && isHttp(file.url.replace(INLINE_MAP_SUFFIX, ''));
}

/** Loads the source map behind a stored "sourcemap" file entry (remote .map, or inline data: URI in a JS file). */
export async function loadSourceMap(file) {
  if (file.url.endsWith(INLINE_MAP_SUFFIX)) {
    const jsUrl = file.url.slice(0, -INLINE_MAP_SUFFIX.length);
    if (!isHttp(jsUrl)) throw new Error('This map was embedded in an inline <script>, which is not stored');
    const text = new TextDecoder().decode(await fetchBytes(jsUrl));
    const ref = sourceMapRef(text);
    const map = ref?.startsWith('data:') ? parseSourceMap(decodeDataUri(ref)) : null;
    if (!map) throw new Error('Inline source map is no longer present in ' + jsUrl);
    return map;
  }
  const map = parseSourceMap(new TextDecoder().decode(await fetchBytes(file.url)));
  if (!map) throw new Error('Not a valid source map');
  return map;
}

async function addSources(zip, base, map, { nodeModules = false } = {}) {
  let n = 0;
  for (const e of mapEntries(map)) {
    if (typeof e.content !== 'string') continue;
    const p = cleanSourcePath(e.path) || `source-${n}`;
    if (!nodeModules && /(?:^|\/)node_modules\//.test(p)) continue;
    await zip.add(zipPath(`${base}/${p}`), e.content);
    n++;
  }
  return n;
}

/** ZIP with the original source tree of one source map. */
export async function sourcesZip(host, file, opts = {}) {
  const zip = new ZipWriter();
  const map = await loadSourceMap(file);
  const n = await addSources(zip, `${zipPath(host)}/${mapFolder(file.url)}`, map, opts);
  if (!n) throw new Error('The source map has no embedded sources (sourcesContent)');
  return { blob: zip.blob(), files: n };
}

/**
 * Dumps the static files of several hosts into one ZIP:
 *   <host>/files/<origin host>/<path>     every scanned JS file (and .map files)
 *   <host>/sources/<map name>/<src path>  original sources rebuilt from source maps
 */
export async function dumpHosts(hosts, opts, onProgress) {
  const zip = new ZipWriter();
  const errors = [];
  const index = [];
  const tasks = [];
  for (const host of hosts) {
    const data = (await chrome.storage.local.get('host:' + host))['host:' + host];
    if (!data) continue;
    for (const f of Object.values(data.files)) {
      if (f.status === 'error' || f.status === 'scanning') continue;
      if (opts.js && SCRIPT_KINDS.has(f.kind) && isHttp(f.url) && f.status !== 'dup') tasks.push({ type: 'file', host, url: f.url });
      if (f.kind === 'sourcemap') {
        if (opts.maps && isHttp(f.url)) tasks.push({ type: 'file', host, url: f.url });
        if (opts.sources && canRebuild(f)) tasks.push({ type: 'sources', host, file: f });
      }
    }
  }
  let done = 0;
  onProgress?.(0, tasks.length);
  const run = async (t) => {
    try {
      if (t.type === 'file') {
        const bytes = await fetchBytes(t.url);
        const path = await zip.add(`${zipPath(t.host)}/files/${urlToPath(t.url)}`, bytes);
        index.push({ host: t.host, url: t.url, path, size: bytes.length });
      } else {
        const map = await loadSourceMap(t.file);
        const base = `${zipPath(t.host)}/sources/${mapFolder(t.file.url)}`;
        const n = await addSources(zip, base, map, opts);
        index.push({ host: t.host, sourcemap: t.file.url, path: base, files: n });
      }
    } catch (e) {
      errors.push(`${t.url || t.file.url}\t${e.message || e}`);
    }
    onProgress?.(++done, tasks.length);
  };
  const pending = [...tasks];
  await Promise.all(Array.from({ length: 4 }, async () => {
    while (pending.length) await run(pending.shift());
  }));
  await zip.add('_index.json', JSON.stringify({ created: new Date().toISOString(), hosts, files: index }, null, 2));
  if (errors.length) await zip.add('_errors.txt', errors.join('\n'));
  return { blob: zip.blob(), files: zip.count - 1 - (errors.length ? 1 : 0), bytes: zip.bytes, errors: errors.length };
}
