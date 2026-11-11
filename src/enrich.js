// Offline enrichment for secret findings. Pure, no network: everything here is computed
// locally from the matched value. Nothing is ever sent to the issuing service — validating a
// discovered credential against a live third party is intentionally out of scope (that would be
// credential-testing against someone else's account). See the project's enrichment note.

// ───────────────────────────── AWS access keys ─────────────────────────────
//
// An AWS access key ID encodes the owning account number: drop the 4-char prefix, base32-decode
// the rest, take the first 6 bytes as a big-endian integer and compute (n & 0x7fffffffff80) >> 7.
// This is a local calculation — no call to AWS. (Truffle Security / Tal Be'ery; WithSecure.)
// Old-generation key IDs beginning AKIAI… / AKIAJ… don't carry a decodable account and return null.

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // RFC 4648

const KEY_TYPE = {
  AKIA: 'long-term (IAM user)',
  ASIA: 'temporary (STS)',
  ABIA: 'STS bearer token',
  ACCA: 'context-specific',
  A3T: 'long-term (IAM user)',
};

/** Account number that owns an AWS access key ID, computed locally, or null if it can't be decoded. */
export function awsAccountId(keyId) {
  if (typeof keyId !== 'string' || !/^[A-Z0-9]{20}$/.test(keyId)) return null;
  // The 10 base32 chars after the prefix hold the first 50 bits; the account lives in the top 48.
  const body = keyId.slice(4, 14);
  let acc = 0n;
  for (const ch of body) {
    const idx = B32.indexOf(ch);
    if (idx < 0) return null; // 0/1/8/9 etc. — not valid base32, so not a real key ID
    acc = (acc << 5n) | BigInt(idx);
  }
  const z = acc >> 2n; // top 48 bits = first 6 bytes, big-endian
  const e = (z & 0x7fffffffff80n) >> 7n;
  return e.toString();
}

export function awsKeyType(keyId) {
  const p4 = String(keyId).slice(0, 4);
  return KEY_TYPE[p4] || KEY_TYPE[String(keyId).slice(0, 3)] || null;
}

/**
 * Post-processor for the AWS Access Key ID rule. Drops obvious placeholders, otherwise keeps the
 * finding and attaches the owning account number and key type (both computed offline).
 */
export function enrichAwsKey(raw) {
  if (!notPlaceholder(raw)) return null;
  const meta = {};
  const tags = [];
  const type = awsKeyType(raw);
  if (type) meta['key type'] = type;
  const account = awsAccountId(raw);
  if (account) {
    meta.account = account;
    tags.push('acct-known');
  }
  if (/^ASIA/.test(raw)) {
    tags.push('temporary'); // STS creds expire — usually lower value than a long-term key
  }
  // Structural example/demo triage is applied uniformly to every secret in analyzer.js.
  return { meta, tags };
}

// ─────────────────────── structural live-vs-example triage ──────────────────────
//
// A conservative, offline heuristic: does a value look like a demo / placeholder credential even
// though it passed the word-level placeholder filter? Returns reasons (empty array = looks real).
// Deliberately strict so it never tags a genuine high-entropy secret.

// Demo markers not already covered by rules.js PLACEHOLDER_RE (example/sample/dummy/your_/xxxxx/…).
const DEMO_WORD_RE =
  /deadbeef|cafebabe|badc0ffee|0{6,}|f{6,}|1234567890|123456789|qwerty|foobar|lorem|notreal|donotuse|replacethis|yourkeyhere|testkey|faketoken/i;

/** Longest run of consecutively ascending or descending character codes (abcdef, 987654…). */
function longestMonotonicRun(s) {
  let best = 1;
  let up = 1;
  let down = 1;
  for (let i = 1; i < s.length; i++) {
    const d = s.charCodeAt(i) - s.charCodeAt(i - 1);
    up = d === 1 ? up + 1 : 1;
    down = d === -1 ? down + 1 : 1;
    best = Math.max(best, up, down);
  }
  return best;
}

/**
 * Structural reasons a secret value looks like an example / non-production credential.
 * @returns {string[]} empty when the value looks like a real secret.
 */
export function exampleSignals(value) {
  const v = String(value || '');
  const out = [];
  if (!v || v.length < 8) return out;
  const word = DEMO_WORD_RE.exec(v);
  if (word) out.push(`demo marker "${word[0]}"`);
  if (/(.)\1{4,}/.test(v)) out.push('repeated character run');
  if (longestMonotonicRun(v) >= 6) out.push('sequential character run');
  const distinct = new Set(v).size;
  if (v.length >= 16 && distinct <= 4) out.push(`only ${distinct} distinct characters`);
  return out;
}

/** True when a secret value is structurally a demo / example rather than a live credential. */
export function looksLikeExample(value) {
  return exampleSignals(value).length > 0;
}

// Local copy of the rules.js placeholder test, kept here so enrich.js stays dependency-free.
const PLACEHOLDER_RE =
  /example|sample|dummy|placeholder|changeme|change[_-]me|your[_-]|insert[_-]|replace[_-]?me|x{5}|\*{4}|<[^>]*>|\$\{|\{\{|%s|process\.env|import\.meta/i;

function notPlaceholder(v) {
  return !PLACEHOLDER_RE.test(v) && !/^(.)\1+$/.test(v);
}
