// Runs the rule set over a piece of JavaScript / HTML and returns de-duplicated findings
// with location and a short context snippet. Pure function: no chrome.* APIs, so it can be
// unit-tested with Node.

import { secretConfidence } from './rules.js';
import { exampleSignals } from './enrich.js';

const DATA_URI_BLOB_RE = /(data:[\w/+.-]{1,100};base64,)([A-Za-z0-9+/=]{512,})/g;
const LONG_BLOB_RE = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{3000,}={0,2}/g;

/**
 * Normalises the input for matching:
 *  - un-escapes JSON-style "\/" and "/" so escaped URLs are found
 *  - blanks out large base64 blobs (inline images, fonts, wasm) which only produce false positives
 */
export function prepare(code) {
  let text = code;
  if (text.includes('\\/') || /\\u002f/i.test(text)) text = text.replace(/\\\/|\\u002[fF]/g, '/');
  if (text.length > 512) {
    text = text
      .replace(DATA_URI_BLOB_RE, (m, prefix, blob) => prefix + ' '.repeat(blob.length))
      .replace(LONG_BLOB_RE, (m) => ' '.repeat(m.length));
  }
  return text;
}

function lineStarts(text) {
  const starts = [0];
  let i = -1;
  while ((i = text.indexOf('\n', i + 1)) !== -1) starts.push(i + 1);
  return starts;
}

function position(starts, index) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, col: index - starts[lo] + 1 };
}

const squash = (s) => s.replace(/\s+/g, ' ');

function context(text, index, len, radius) {
  const s = Math.max(0, index - radius);
  const e = Math.min(text.length, index + len + radius);
  return [
    (s > 0 ? '…' : '') + squash(text.slice(s, index)),
    squash(text.slice(index, index + Math.min(len, 400))),
    squash(text.slice(index + len, e)) + (e < text.length ? '…' : ''),
  ];
}

/**
 * @param {string} code
 * @param {Array} rules compiled rules (see rules.js)
 * @param {{maxPerRule?: number, radius?: number, timeBudgetMs?: number}} opts
 * @returns {Array<{rule,label,category,severity,value,tags,meta,line,col,ctx,hits}>}
 */
export function analyze(code, rules, opts = {}) {
  if (typeof code !== 'string' || !code) return [];
  const maxPerRule = opts.maxPerRule ?? 2500;
  const radius = opts.radius ?? 70;
  const deadline = Date.now() + (opts.timeBudgetMs ?? 20000);
  const text = prepare(code);
  let starts = null;
  const found = new Map();

  for (const rule of rules) {
    if (Date.now() > deadline) break;
    const re = rule.re;
    re.lastIndex = 0;
    let n = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m[0] === '') {
        re.lastIndex++;
        continue;
      }
      const raw = rule.group ? m[rule.group] : m[0];
      if (!raw) continue;
      const index = m.index + Math.max(0, rule.group ? m[0].indexOf(raw) : 0);
      let outs = [null];
      if (rule.post) {
        let r;
        try {
          r = rule.post(raw, m, { code: text, index });
        } catch {
          r = null;
        }
        if (!r || (Array.isArray(r) && !r.length)) continue;
        if (Array.isArray(r)) outs = r;
        else if (typeof r === 'object') outs = [r];
      }
      for (const extra of outs) {
        const value = extra?.value || raw;
        const category = extra?.category || rule.category;
        const key = category + '\u0000' + (extra?.meta?.kind || '') + '\u0000' + value;
        const prev = found.get(key);
        if (prev) {
          prev.hits++;
          continue;
        }
        if (!starts) starts = lineStarts(text);
        const { line, col } = position(starts, index);
        const finding = {
          rule: rule.id,
          label: extra?.label || rule.label,
          category,
          severity: extra?.severity || rule.severity,
          value,
          tags: extra?.tags || [],
          line,
          col,
          ctx: context(text, index, raw.length, radius),
          hits: 1,
        };
        if (extra?.meta) finding.meta = extra.meta;
        if (rule.desc) finding.desc = rule.desc;
        if (category === 'secrets') {
          const { entropy, confidence } = secretConfidence(value, rule.generic);
          finding.entropy = Math.round(entropy * 100) / 100;
          finding.confidence = confidence;
          // Offline triage: flag values that look like demo / example credentials (never dropped,
          // only tagged, so the user can deprioritise them without losing the hit).
          const signals = exampleSignals(value);
          if (signals.length) {
            if (!finding.tags.includes('example')) finding.tags = [...finding.tags, 'example'];
            if (!finding.meta?.example) finding.meta = { ...(finding.meta || {}), example: signals.join('; ') };
          }
        }
        found.set(key, finding);
        n++;
      }
      if (n >= maxPerRule) break;
    }
  }
  return [...found.values()];
}
