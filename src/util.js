// Shared helpers (used by the service worker, the analyzer and the UI pages).

export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const CONFIDENCE_RANK = { certain: 2, firm: 1, tentative: 0 };

/** Shannon entropy in bits per character. */
export function entropy(s) {
  if (!s) return 0;
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let e = 0;
  const n = s.length;
  for (const c of freq.values()) {
    const p = c / n;
    e -= p * Math.log2(p);
  }
  return e;
}

export function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
}

/**
 * "example.com" and "*.example.com" both match example.com and every subdomain.
 */
export function hostMatches(host, patterns) {
  if (!host || !patterns || !patterns.length) return false;
  host = host.toLowerCase().replace(/:\d+$/, '');
  for (let p of patterns) {
    p = String(p).trim().toLowerCase().replace(/^\*?\.+/, '').replace(/^\*\./, '');
    if (!p) continue;
    if (host === p || host.endsWith('.' + p)) return true;
  }
  return false;
}

const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'plc.uk',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.in', 'net.in', 'org.in', 'gov.in',
  'co.nz', 'org.nz', 'co.za', 'org.za', 'co.kr', 'or.kr', 'co.il', 'co.id', 'co.th',
  'com.mx', 'com.tr', 'com.sg', 'com.hk', 'com.ar', 'com.tw', 'com.my', 'com.vn',
  'com.ph', 'com.pk', 'com.ua', 'com.pl', 'com.co', 'com.eg', 'com.sa', 'com.ng',
]);

/** Approximate registrable domain ("eTLD+1") without shipping the public suffix list. */
export function siteOf(host) {
  if (!host) return '';
  host = host.toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
  if (/^[\d.]+$/.test(host) || host.startsWith('[')) return host;
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const last2 = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(last2)) return parts.slice(-3).join('.');
  return last2;
}

export async function sha1(text) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  let out = '';
  for (const b of new Uint8Array(buf)) out += b.toString(16).padStart(2, '0');
  return out;
}

export function b64urlDecode(s) {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

export function decodeJwt(token) {
  const parts = String(token).split('.');
  if (parts.length < 2) return null;
  try {
    const header = JSON.parse(b64urlDecode(parts[0]));
    const payload = JSON.parse(b64urlDecode(parts[1]));
    if (!header || typeof header !== 'object') return null;
    return { header, payload };
  } catch {
    return null;
  }
}

export function formatBytes(n) {
  if (n == null) return '';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(1) + ' MB';
}

export function truncate(s, n) {
  s = String(s ?? '');
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}
