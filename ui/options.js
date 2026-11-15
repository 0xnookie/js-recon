import { RULES, CATEGORY_LABELS, parseCustomRules } from '../src/rules.js';
import { DEFAULT_SETTINGS, DEFAULT_IGNORED_SCRIPT_HOSTS, getSettings, saveSettings } from '../src/settings.js';
import { formatBytes } from '../src/util.js';
import { parseScope, compileScope, hasScope, hostScope, urlScope } from '../src/scope.js';

const $ = (s) => document.querySelector(s);
let settings = null;

function flashSaved() {
  const el = $('#saved');
  el.classList.add('show');
  clearTimeout(flashSaved.t);
  flashSaved.t = setTimeout(() => el.classList.remove('show'), 1200);
}

async function save(patch) {
  settings = await saveSettings(patch);
  flashSaved();
}

const toList = (text) => [...new Set(text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean))];

function bindFields() {
  for (const el of document.querySelectorAll('[data-key]')) {
    const key = el.dataset.key;
    if (el.type === 'checkbox') {
      el.checked = !!settings[key];
      el.addEventListener('change', () => save({ [key]: el.checked }));
    } else if (el.type === 'number') {
      el.value = settings[key];
      el.addEventListener('change', () => {
        const min = Number(el.min || 1);
        const max = Number(el.max || 1e9);
        const v = Math.min(max, Math.max(min, Math.round(Number(el.value) || DEFAULT_SETTINGS[key])));
        el.value = v;
        save({ [key]: v });
      });
    } else if (el.hasAttribute('data-list')) {
      el.value = (settings[key] || []).join('\n');
      let t = null;
      el.addEventListener('input', () => {
        clearTimeout(t);
        t = setTimeout(() => save({ [key]: toList(el.value) }), 500);
      });
    }
  }
  for (const r of document.querySelectorAll('input[name="scopeMode"]')) {
    r.checked = settings.scopeMode === r.value;
    r.addEventListener('change', () => r.checked && save({ scopeMode: r.value }));
  }
  $('#resetIgnore').addEventListener('click', () => {
    $('[data-key="ignoreScriptHosts"]').value = DEFAULT_IGNORED_SCRIPT_HOSTS.join('\n');
    save({ ignoreScriptHosts: [...DEFAULT_IGNORED_SCRIPT_HOSTS] });
  });
}

// ── program scope ──

const SCOPE_WORDS = { in: 'in scope', out: 'out of scope', unlisted: 'not listed: treated as out of scope' };

function testScope() {
  const raw = $('#scopeTestInput').value.trim();
  const el = $('#scopeTestResult');
  const scope = compileScope(settings.scopeIn, settings.scopeOut);
  if (!raw) return void (el.textContent = '');
  if (!hasScope(scope)) return void (el.textContent = 'No scope set: active checks use the target\'s own registrable domain.');
  const st = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? urlScope(scope, raw) : hostScope(scope, raw.replace(/\/.*$/, ''));
  el.replaceChildren();
  const chip = document.createElement('span');
  chip.className = `chip scope-${st}`;
  chip.textContent = SCOPE_WORDS[st];
  el.append(chip);
}

function setScopeLists(inList, outList) {
  $('[data-key="scopeIn"]').value = inList.join('\n');
  $('[data-key="scopeOut"]').value = outList.join('\n');
  return save({ scopeIn: inList, scopeOut: outList }).then(testScope);
}

function bindScope() {
  const importScope = async (replace) => {
    const text = $('#scopePaste').value;
    const r = parseScope(text);
    const msg = $('#scopeMsg');
    if (!r.in.length && !r.out.length) return void (msg.textContent = 'No hosts found in the pasted text.');
    const outList = [...new Set([...(replace ? [] : settings.scopeOut || []), ...r.out])];
    const inList = [...new Set([...(replace ? [] : settings.scopeIn || []), ...r.in])].filter((p) => !outList.includes(p));
    await setScopeLists(inList, outList);
    const fmt = { 'hackerone-csv': 'HackerOne CSV', burp: 'Burp JSON', text: 'text' }[r.format];
    msg.textContent = `${replace ? 'Scope set' : 'Added'}: ${r.in.length} in scope, ${r.out.length} out of scope (${fmt})${r.skipped.length ? ` · skipped ${r.skipped.length} non-web assets: ${r.skipped.slice(0, 4).join(', ')}${r.skipped.length > 4 ? '…' : ''}` : ''}`;
    $('#scopePaste').value = '';
  };
  $('#scopeImport').addEventListener('click', () => importScope(false));
  $('#scopeReplace').addEventListener('click', () => importScope(true));
  const clear = $('#scopeClear');
  clear.addEventListener('click', async () => {
    if (!clear.classList.contains('confirm')) {
      clear.classList.add('confirm');
      clear.textContent = 'Click again to clear';
      setTimeout(() => (clear.classList.remove('confirm'), (clear.textContent = 'Clear scope')), 4000);
      return;
    }
    clear.classList.remove('confirm');
    clear.textContent = 'Clear scope';
    await setScopeLists([], []);
    $('#scopeMsg').textContent = 'Scope cleared.';
  });
  $('#scopeTestInput').addEventListener('input', testScope);
  for (const k of ['scopeIn', 'scopeOut']) $(`[data-key="${k}"]`).addEventListener('input', () => setTimeout(testScope, 600));
}

function ruleEnabled(r) {
  const o = settings.ruleOverrides || {};
  return r.id in o ? !!o[r.id] : r.enabled !== false;
}

function renderRules() {
  const root = $('#rules');
  root.replaceChildren();
  const byCat = {};
  for (const r of RULES) (byCat[r.category] ||= []).push(r);
  for (const [cat, rules] of Object.entries(byCat)) {
    const title = document.createElement('div');
    title.className = 'rule-cat';
    title.textContent = `${CATEGORY_LABELS[cat] || cat} (${rules.length})`;
    const grid = document.createElement('div');
    grid.className = 'rule-grid';
    for (const r of rules) {
      const label = document.createElement('label');
      label.className = 'rule-item';
      label.title = `${r.id}${r.desc ? ' — ' + r.desc : ''}\n${r.re.source.slice(0, 300)}`;
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = ruleEnabled(r);
      cb.addEventListener('change', () => {
        const overrides = { ...(settings.ruleOverrides || {}) };
        if (cb.checked === (r.enabled !== false)) delete overrides[r.id];
        else overrides[r.id] = cb.checked;
        save({ ruleOverrides: overrides });
      });
      const pill = document.createElement('span');
      pill.className = `pill ${r.severity}`;
      pill.textContent = r.severity;
      const name = document.createElement('span');
      name.className = 'name';
      name.textContent = r.label;
      label.append(cb, pill, name);
      grid.append(label);
    }
    root.append(title, grid);
  }
}

function bindRules() {
  $('#rulesAll').addEventListener('click', async () => {
    await save({ ruleOverrides: Object.fromEntries(RULES.filter((r) => r.enabled === false).map((r) => [r.id, true])) });
    renderRules();
  });
  $('#rulesDefault').addEventListener('click', async () => {
    await save({ ruleOverrides: {} });
    renderRules();
  });
}

function bindCustom() {
  const ta = $('#customRules');
  ta.value = settings.customRules || '';
  const validate = () => {
    const { rules, errors } = parseCustomRules(ta.value);
    $('#customErrors').textContent = errors.join('\n');
    $('#customStatus').textContent = `${rules.length} valid rule${rules.length === 1 ? '' : 's'}`;
    return errors;
  };
  validate();
  ta.addEventListener('input', validate);
  $('#saveCustom').addEventListener('click', async () => {
    const errors = validate();
    if (errors.length) {
      $('#customStatus').textContent = 'Fix the errors below first.';
      return;
    }
    await save({ customRules: ta.value });
  });
}

async function renderUsage() {
  const all = await chrome.storage.local.get(null);
  const hosts = Object.keys(all).filter((k) => k.startsWith('host:'));
  let findings = 0;
  let files = 0;
  for (const k of hosts) {
    findings += Object.keys(all[k].findings || {}).length;
    files += Object.keys(all[k].files || {}).length;
  }
  let bytes = 0;
  try {
    bytes = await chrome.storage.local.getBytesInUse(null);
  } catch {
    /* ignore */
  }
  $('#usage').textContent = `${hosts.length} hosts · ${files} files scanned · ${findings} unique findings · ${formatBytes(bytes)} stored`;
}

function bindData() {
  $('#exportAll').addEventListener('click', async () => {
    const all = await chrome.storage.local.get(null);
    const hosts = Object.keys(all)
      .filter((k) => k.startsWith('host:'))
      .map((k) => ({ ...all[k], files: Object.values(all[k].files), findings: Object.values(all[k].findings), hashes: undefined }));
    const url = URL.createObjectURL(new Blob([JSON.stringify(hosts, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `jsrecon-all-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  });
  const btn = $('#clearAll');
  btn.addEventListener('click', async () => {
    if (!btn.classList.contains('confirm')) {
      btn.classList.add('confirm');
      btn.textContent = 'Click again to delete everything';
      setTimeout(() => (btn.classList.remove('confirm'), (btn.textContent = 'Delete all findings')), 4000);
      return;
    }
    btn.classList.remove('confirm');
    btn.textContent = 'Delete all findings';
    await chrome.runtime.sendMessage({ type: 'clear' });
    renderUsage();
  });
}

async function init() {
  settings = await getSettings();
  bindFields();
  bindScope();
  renderRules();
  bindRules();
  bindCustom();
  bindData();
  renderUsage();
}

init();
