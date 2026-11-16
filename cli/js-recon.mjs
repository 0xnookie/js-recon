#!/usr/bin/env node
// JS Recon on the command line: the extension's analysis for scripted recon pipelines.
//   js-recon https://app.example.com/                 page → its scripts, source maps, lazy chunks
//   js-recon -l urls.txt --json report.json           many targets, JSON report
//   cat urls.txt | js-recon -l - --sarif out.sarif    from a pipeline (katana / gau / waybackurls …)
//   js-recon ./dump/ --host app.example.com           local files (e.g. the extension's Dump ZIP)
import { readFileSync, readdirSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { join, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan, collect } from './scan.mjs';
import { buildSarif } from '../src/exporters.js';
import { parseScope, compileScope, urlScope, hasScope } from '../src/scope.js';
import { SEV_RANK } from '../src/util.js';

const VERSION = JSON.parse(readFileSync(fileURLToPath(new URL('../manifest.json', import.meta.url)), 'utf8')).version;
const CATEGORIES = ['secrets', 'api', 'endpoints', 'urls', 'subdomains', 'cloud', 'params', 'deps', 'intel', 'flags', 'routes', 'sinks', 'graphql'];
const SECURITY = new Set(['secrets', 'sinks', 'deps', 'flags', 'cloud', 'intel']);

const HELP = `JS Recon ${VERSION} — JavaScript recon from the command line

Usage: js-recon [options] <url | file | directory> ...

Targets
  <url>                   a page (its inline and external scripts are scanned) or a .js / .map URL
  <file | directory>      local .js .mjs .cjs .map .html files (no network)
  -l, --list <file>       targets from a file, one per line ("-" = stdin)
  --host <name>           file local findings under this host (default: local)

Fetching
  -H, --header "K: V"     extra request header, repeatable (e.g. -H "Cookie: session=…"); only sent to
                          the targets' own sites (registrable domain), never to scripts hosted elsewhere
  --scope <file>          program scope (HackerOne CSV, Burp JSON or scope text, as in the extension):
                          targets outside it are skipped, excluded hosts are never fetched
  --first-party           only fetch scripts from the target's own registrable domain
  --no-maps               don't follow source maps
  --no-chunks             don't fetch lazy chunks from the bundler runtime
  --chunk-limit <n>       lazy chunks per host (default 400)
  --no-libraries          skip library versions / advisories (and .LICENSE.txt files)
  --node-modules          also scan node_modules sources inside source maps
  --concurrency <n>       parallel requests (default 6)
  --timeout <seconds>     per request (default 30)

Output
  --json [file]           full JSON report (stdout if no file)
  --sarif <file>          SARIF 2.1.0 (secrets, sinks, deps, flags, cloud, intel)
  --only <cats>           comma-separated: ${CATEGORIES.join(', ')}
  --min-severity <level>  info | low | medium | high | critical (default info)
  --all                   list every finding in the text output (default: security findings + API)
  --fail-on <level>       exit code 1 if a finding is at or above this severity (CI)
  -q, --quiet             no progress on stderr
  -v, --version · -h, --help
`;

function parseArgs(argv) {
  const a = { targets: [], headers: {}, only: null, minSeverity: 'info', options: {}, json: null, sarif: null, all: false, quiet: false, list: [], failOn: null };
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${x} needs a value`);
      return argv[++i];
    };
    if (x === '-h' || x === '--help') a.help = true;
    else if (x === '-v' || x === '--version') a.version = true;
    else if (x === '-l' || x === '--list') a.list.push(next());
    else if (x === '-H' || x === '--header') {
      const h = next();
      const c = h.indexOf(':');
      if (c < 1) throw new Error(`bad header "${h}" (expected "Name: value")`);
      a.headers[h.slice(0, c).trim()] = h.slice(c + 1).trim();
    } else if (x === '--host') a.host = next();
    else if (x === '--scope') a.scope = next();
    else if (x === '--first-party') a.options.firstParty = true;
    else if (x === '--no-maps') a.options.maps = false;
    else if (x === '--no-chunks') a.options.chunks = false;
    else if (x === '--no-libraries') a.options.libraries = false;
    else if (x === '--node-modules') a.options.nodeModules = true;
    else if (x === '--chunk-limit') a.options.chunkLimit = Number(next());
    else if (x === '--concurrency') a.options.concurrency = Math.max(1, Number(next()) || 6);
    else if (x === '--timeout') a.options.timeoutMs = Math.max(1, Number(next()) || 30) * 1000;
    else if (x === '--json') a.json = argv[i + 1] && !argv[i + 1].startsWith('-') && !/^https?:/i.test(argv[i + 1]) && /\.json$/i.test(argv[i + 1]) ? argv[++i] : '-';
    else if (x === '--sarif') a.sarif = next();
    else if (x === '--only') a.only = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (x === '--min-severity') a.minSeverity = next();
    else if (x === '--fail-on') a.failOn = next();
    else if (x === '--all') a.all = true;
    else if (x === '-q' || x === '--quiet') a.quiet = true;
    else if (x.startsWith('-') && x !== '-') throw new Error(`unknown option ${x}`);
    else a.targets.push(x);
  }
  for (const lvl of [a.minSeverity, a.failOn].filter(Boolean)) if (!(lvl in SEV_RANK)) throw new Error(`unknown severity "${lvl}"`);
  for (const c of a.only || []) if (!CATEGORIES.includes(c)) throw new Error(`unknown category "${c}"`);
  return a;
}

const LOCAL_EXT = new Set(['.js', '.mjs', '.cjs', '.map', '.html', '.htm', '.jsx', '.ts', '.tsx']);

function localTexts(path, maxBytes, out = []) {
  const st = statSync(path);
  if (st.isDirectory()) {
    for (const n of readdirSync(path)) if (n !== 'node_modules' && !n.startsWith('.')) localTexts(join(path, n), maxBytes, out);
  } else if (LOCAL_EXT.has(extname(path).toLowerCase()) && st.size <= maxBytes) {
    out.push({ id: path, text: readFileSync(path, 'utf8'), map: extname(path).toLowerCase() === '.map' });
  }
  return out;
}

const readStdin = () => new Promise((resolve) => {
  let s = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (d) => (s += d)).on('end', () => resolve(s));
});

function where(f) {
  const s = f.sources?.[0];
  if (!s) return '';
  const name = s.sub || String(s.file).replace(/^https?:\/\/[^/]+/, '');
  return `${name}${s.line ? ':' + s.line : ''}`;
}

function textReport(result, findings, all) {
  const out = [];
  for (const h of Object.values(result.hosts)) {
    const mine = findings.filter((f) => f.host === h.host);
    const files = Object.values(h.files);
    const counts = {};
    for (const f of mine) counts[f.category] = (counts[f.category] || 0) + 1;
    out.push(`\n== ${h.host} — ${files.filter((f) => f.status === 'done').length} files${files.some((f) => f.status === 'error') ? `, ${files.filter((f) => f.status === 'error').length} failed` : ''}`);
    out.push('   ' + (Object.entries(counts).map(([c, n]) => `${c} ${n}`).join(' · ') || 'no findings'));
    for (const cat of CATEGORIES) {
      const list = mine.filter((f) => f.category === cat);
      if (!list.length || (!all && !SECURITY.has(cat) && cat !== 'api')) continue;
      const shown = all ? list : cat === 'intel' || cat === 'flags' ? list.filter((f) => (SEV_RANK[f.severity] || 0) >= 1 || f.tags?.includes('interesting')) : list;
      if (!shown.length) continue;
      out.push(`\n-- ${cat} (${shown.length}${shown.length < list.length ? ` of ${list.length}` : ''})`);
      for (const f of shown.slice(0, all ? Infinity : 200)) {
        const extra =
          cat === 'deps' && f.meta?.kind === 'library' ? (f.meta.advisories ? `  ${f.meta.advisories} advisories, ${f.meta.eol ? 'end of life' : 'fixed in ' + f.meta['fixed in']}` : '')
          : cat === 'flags' ? `  ${[f.meta?.provider, f.meta?.state != null ? 'state ' + f.meta.state : '', f.meta?.default != null ? 'default ' + f.meta.default : ''].filter(Boolean).join(' · ')}`
          : f.meta?.username ? `  (user ${f.meta.username})` : '';
        const label = cat === 'api' || cat === 'endpoints' || cat === 'urls' || cat === 'subdomains' ? '' : `${f.label}: `;
        out.push(`[${f.severity.toUpperCase().padEnd(8)}] ${label}${f.value}${extra}${where(f) ? '   ← ' + where(f) : ''}`);
      }
      if (!all && shown.length > 200) out.push(`… ${shown.length - 200} more (--all or --json)`);
    }
  }
  if (result.errors.length) out.push(`\n${result.errors.length} error(s):`, ...result.errors.slice(0, 20).map((e) => `  ${e.url}: ${e.error}`));
  return out.join('\n');
}

async function main() {
  let a;
  try {
    a = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(`js-recon: ${e.message}\n(js-recon --help for usage)`);
    process.exit(2);
  }
  if (a.help) return void process.stdout.write(HELP);
  if (a.version) return void console.log(VERSION);

  const urls = [];
  const texts = [];
  const raw = [...a.targets];
  for (const l of a.list) raw.push(...(l === '-' ? await readStdin() : readFileSync(l, 'utf8')).split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#')));
  const maxBytes = a.options.maxBytes || 15 * 1048576;
  for (const t of raw) {
    if (/^https?:\/\//i.test(t)) urls.push(t);
    else if (existsSync(t)) texts.push(...localTexts(t, maxBytes));
    else if (/^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:\/|$)/i.test(t)) urls.push('https://' + t);
    else console.error(`js-recon: skipping "${t}" (not a URL or a file)`);
  }

  let targets = urls;
  if (a.scope) {
    const p = parseScope(readFileSync(a.scope, 'utf8'));
    const sc = compileScope(p.in, p.out);
    if (!hasScope(sc)) throw new Error(`no hosts found in ${a.scope}`);
    targets = urls.filter((u) => urlScope(sc, u) === 'in');
    if (targets.length < urls.length && !a.quiet) console.error(`js-recon: ${urls.length - targets.length} target(s) outside the scope skipped`);
    a.options.ignoreUrl = (u) => urlScope(sc, u) === 'out';
  }
  if (!targets.length && !texts.length) {
    console.error('js-recon: nothing to scan (js-recon --help for usage)');
    process.exit(2);
  }

  const progress = !a.quiet && process.stderr.isTTY ? (d, t) => process.stderr.write(`\r  ${d} / ${t} files…`) : null;
  const result = await scan({ targets, texts, host: a.host || null, options: { ...a.options, headers: a.headers }, onProgress: progress });
  if (progress) process.stderr.write('\r\x1b[K');

  const findings = collect(result, { only: a.only, minSeverity: a.minSeverity });
  if (a.sarif) {
    const sec = findings.filter((f) => SECURITY.has(f.category));
    const model = {
      host: Object.keys(result.hosts).join(', '),
      version: VERSION,
      findings: sec.map((f) => ({ rule: f.rule, label: f.label, severity: f.severity, value: f.value, category: f.category, desc: f.desc, locations: (f.sources || []).map((s) => ({ uri: String(s.file).replace(/ \[inline source map\]$/, ''), line: s.line, col: s.col })) })),
    };
    writeFileSync(a.sarif, JSON.stringify(buildSarif(model), null, 2));
    if (!a.quiet) console.error(`js-recon: SARIF written to ${a.sarif} (${sec.length} results)`);
  }
  if (a.json) {
    const report = {
      tool: 'js-recon',
      version: VERSION,
      generated: new Date().toISOString(),
      hosts: Object.values(result.hosts).map((h) => ({ host: h.host, origin: h.origin, files: Object.values(h.files), chunks: Object.keys(h.chunkUrls) })),
      findings,
      errors: result.errors,
    };
    const text = JSON.stringify(report, null, 2);
    if (a.json === '-') process.stdout.write(text + '\n');
    else {
      writeFileSync(a.json, text);
      if (!a.quiet) console.error(`js-recon: JSON written to ${a.json} (${findings.length} findings)`);
    }
  }
  if (a.json !== '-') console.log(textReport(result, findings, a.all));
  if (a.failOn && findings.some((f) => (SEV_RANK[f.severity] || 0) >= SEV_RANK[a.failOn])) process.exit(1);
}

main().catch((e) => {
  console.error(`js-recon: ${e.message || e}`);
  process.exit(2);
});
