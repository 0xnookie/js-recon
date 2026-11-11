import { RULES, CATEGORY_LABELS, parseCustomRules } from '../src/rules.js';
import { DEFAULT_SETTINGS, DEFAULT_IGNORED_SCRIPT_HOSTS, getSettings, saveSettings } from '../src/settings.js';
import { formatBytes } from '../src/util.js';

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
  renderRules();
  bindRules();
  bindCustom();
  bindData();
  renderUsage();
}

init();
