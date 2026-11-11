// Content search: grep the raw text of every scanned JS file (and the sources rebuilt from source maps)
// of one host for a literal string or a regular expression. Bodies are not stored — they are scanned and
// discarded — so this re-fetches them (normally straight from the HTTP cache) at search time. Runs in the
// extension page, like the dumper. Use it to hunt for things the detection rules don't have a pattern for,
// e.g. Next.js server-action refs (`ACTION_ID_…`), feature flags, internal hostnames, build constants.

import { mapEntries, cleanSourcePath } from '../src/sourcemap.js';
import { loadSourceMap, canRebuild, mapFolder } from './dump.js';

const SCRIPT_KINDS = new Set(['script', 'crawled', 'chunk', 'manual', 'wayback']);
const isHttp = (u) => /^https?:\/\//i.test(u);

const PER_FILE = 50; // max matches kept per file / source
const TOTAL = 1000; // max matches overall
const CONCURRENCY = 5;
const CTX = 60; // characters of context shown on each side of a match

// ── pure matching helpers (unit-tested) ──

/** A global RegExp for `query`. `regex:false` treats the query as a literal string. Throws on a bad pattern. */
export function buildMatcher(query, { regex = false, caseSensitive = false } = {}) {
  const flags = 'g' + (caseSensitive ? '' : 'i');
  const src = regex ? query : query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(src, flags);
}

function newlineIndex(text) {
  const nl = [];
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) nl.push(i);
  return nl;
}

/** Line (1-based), column and the bounds of the line that contains `idx`. */
function lineAt(nl, idx, len) {
  let lo = 0;
  let hi = nl.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (nl[mid] < idx) lo = mid + 1;
    else hi = mid;
  }
  const lineStart = lo === 0 ? 0 : nl[lo - 1] + 1;
  const lineEnd = lo < nl.length ? nl[lo] : len;
  return { line: lo + 1, col: idx - lineStart + 1, lineStart, lineEnd };
}

/**
 * Every match of `re` in `text`, up to `limit`, as { line, col, pre, hit, post }. The snippet is clamped to
 * the line that holds the match and to ±ctx characters, with an ellipsis where it was cut — so a minified
 * one-line bundle yields a readable window rather than the whole file.
 */
export function findMatches(text, re, limit = PER_FILE, ctx = CTX) {
  if (!re.global) re = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  const nl = newlineIndex(text);
  const out = [];
  re.lastIndex = 0;
  let m;
  while (out.length < limit && (m = re.exec(text))) {
    const hit = m[0];
    if (hit === '') {
      re.lastIndex++; // zero-width match: step forward so we don't loop forever
      continue;
    }
    const idx = m.index;
    const { line, col, lineStart, lineEnd } = lineAt(nl, idx, text.length);
    const from = Math.max(lineStart, idx - ctx);
    const to = Math.min(lineEnd, idx + hit.length + ctx);
    out.push({
      line,
      col,
      pre: (from > lineStart ? '…' : '') + text.slice(from, idx),
      hit,
      post: text.slice(idx + hit.length, to) + (to < lineEnd ? '…' : ''),
    });
  }
  return out;
}

// ── orchestration (fetches, needs chrome + the page's fetch) ──

const textCache = new Map(); // url → Promise<string>, so repeat searches in one session don't re-fetch

async function fetchText(url) {
  let p = textCache.get(url);
  if (!p) {
    if (textCache.size > 600) textCache.clear();
    p = (async () => {
      const res = await fetch(url, { credentials: 'include', cache: 'force-cache' });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.text();
    })();
    textCache.set(url, p);
  }
  return p;
}

/**
 * Searches one host's scanned JS files and reconstructed sources.
 * @returns { matches, files, errors, truncated } — matches are { source, url, kind, srcPath?, line, col, pre, hit, post }.
 */
export async function searchHost(host, query, opts = {}, onProgress) {
  const re = buildMatcher(query, opts); // validates the pattern up front
  const data = (await chrome.storage.local.get('host:' + host))['host:' + host];
  const result = { matches: [], files: 0, errors: 0, truncated: false };
  if (!data) return result;

  const tasks = [];
  for (const f of Object.values(data.files)) {
    if (f.status === 'error' || f.status === 'scanning') continue;
    if (SCRIPT_KINDS.has(f.kind) && isHttp(f.url) && f.status !== 'dup') tasks.push({ kind: 'file', url: f.url, label: f.label || f.url });
    if (opts.sources !== false && f.kind === 'sourcemap' && canRebuild(f)) tasks.push({ kind: 'sources', file: f });
  }
  result.files = tasks.length;
  onProgress?.(0, tasks.length);

  const push = (arr) => {
    for (const mm of arr) {
      if (result.matches.length >= TOTAL) {
        result.truncated = true;
        return;
      }
      result.matches.push(mm);
    }
  };

  let done = 0;
  const run = async (t) => {
    try {
      if (result.matches.length >= TOTAL) {
        result.truncated = true;
      } else if (t.kind === 'file') {
        const text = await fetchText(t.url);
        push(findMatches(text, re).map((mm) => ({ source: t.label, url: t.url, kind: 'file', ...mm })));
      } else {
        const map = await loadSourceMap(t.file);
        const folder = mapFolder(t.file.url);
        for (const e of mapEntries(map)) {
          if (typeof e.content !== 'string') continue;
          const srcPath = cleanSourcePath(e.path) || 'source';
          if (!opts.includeNodeModules && /(?:^|\/)node_modules\//.test(srcPath)) continue;
          push(findMatches(e.content, re).map((mm) => ({ source: `${folder}/${srcPath}`, url: t.file.url, kind: 'source', srcPath, ...mm })));
          if (result.truncated) break;
        }
      }
    } catch {
      result.errors++;
    }
    onProgress?.(++done, tasks.length);
  };

  const pending = [...tasks];
  await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
    while (pending.length) await run(pending.shift());
  }));
  return result;
}
