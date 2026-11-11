// Usage: node test/fp-sweep.mjs <dir> — scans every .js file under <dir> and prints secret/intel
// findings, to eyeball false positives on real-world code.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { analyze } from '../src/analyzer.js';
import { buildRules } from '../src/rules.js';

const root = process.argv[2];
if (!root) {
  console.error('usage: node test/fp-sweep.mjs <dir>');
  process.exit(2);
}
const rules = buildRules({});
const files = [];
(function walk(d) {
  for (const n of readdirSync(d)) {
    const p = join(d, n);
    const st = statSync(p);
    if (st.isDirectory()) walk(p);
    else if (/\.(?:m?js|cjs)$/.test(n) && st.size < 5e6) files.push(p);
  }
})(root);

let bytes = 0;
const counts = {};
const shown = [];
const t0 = performance.now();
for (const f of files) {
  const code = readFileSync(f, 'utf8');
  bytes += code.length;
  for (const r of analyze(code, rules)) {
    counts[r.category] = (counts[r.category] || 0) + 1;
    if (r.category === 'secrets' || (r.category === 'intel' && r.severity !== 'info')) shown.push(`${r.severity.padEnd(6)} ${r.rule.padEnd(22)} ${r.value.slice(0, 70)}  (${f.slice(root.length)}:${r.line})`);
  }
}
console.log(`${files.length} files, ${(bytes / 1048576).toFixed(1)} MB in ${(performance.now() - t0).toFixed(0)} ms`);
console.log('counts by category:', counts);
console.log(shown.slice(0, 80).join('\n'));
if (shown.length > 80) console.log(`… ${shown.length - 80} more`);
