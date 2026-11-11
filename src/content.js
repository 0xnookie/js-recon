// Content script: reports script URLs, inline scripts and (optionally) the rendered DOM to the
// service worker. External scripts are also captured via webRequest; this covers scripts that were
// loaded before the extension was active, and inline code that never hits the network.
(() => {
  // Skip if a live instance is already running (re-injection on "Rescan"). An instance left over
  // from before an extension reload reports itself as dead, so we take over.
  const alive = window.__jsReconAlive;
  if (typeof alive === 'function' && alive()) return;
  window.__jsReconAlive = () => {
    try {
      return !!chrome.runtime?.id;
    } catch {
      return false;
    }
  };

  // Also runs in iframes (embedded widgets keep their config in inline scripts). The service worker
  // decides whether a frame is in scope, because a cross-origin frame can't see the top page's URL.
  const IS_FRAME = window !== window.top;
  const MAX_INLINE = 3 * 1024 * 1024;
  const MAX_HTML = 5 * 1024 * 1024;
  const JS_RE = /\.m?js(?:[?#]|$)/i;
  const sent = new WeakSet();

  // Runtime hooks (opt-in; src/runtime.js runs in the page's own world) post batches of names here.
  // The page could fire this event itself, so the service worker treats the data as page-supplied.
  document.addEventListener('jsrecon:runtime', (e) => {
    const d = e.detail;
    if (typeof d !== 'string' || d.length > 2000000) return;
    let data;
    try {
      data = JSON.parse(d);
    } catch {
      return;
    }
    if (!data || typeof data !== 'object') return;
    try {
      chrome.runtime.sendMessage({ type: 'runtime-collect', pageUrl: location.href, frame: IS_FRAME, data }).catch(() => {});
    } catch {
      /* extension reloaded */
    }
  });
  document.dispatchEvent(new CustomEvent('jsrecon:ready'));

  function hostMatches(host, patterns) {
    host = host.toLowerCase();
    return (patterns || []).some((p) => {
      p = String(p).trim().toLowerCase().replace(/^\*?\.+/, '').replace(/^\*\./, '');
      return p && (host === p || host.endsWith('.' + p));
    });
  }

  async function getSettings() {
    try {
      const { settings = {} } = await chrome.storage.local.get('settings');
      return { enabled: true, scanInline: true, scanHtml: true, scopeMode: 'all', allowHosts: [], denyHosts: [], ...settings };
    } catch {
      return null; // extension was reloaded; this content script is orphaned
    }
  }

  function inScope(s) {
    const h = location.hostname;
    if (hostMatches(h, s.denyHosts)) return false;
    if (s.scopeMode === 'allowlist' && !hostMatches(h, s.allowHosts)) return false;
    return true;
  }

  function scriptUrls() {
    const urls = new Set();
    for (const s of document.scripts) if (s.src) urls.add(s.src);
    for (const l of document.querySelectorAll('link[rel="modulepreload"][href], link[rel="preload"][as="script"][href], link[rel="prefetch"][href]')) {
      if (l.rel !== 'prefetch' || JS_RE.test(l.href)) urls.add(l.href);
    }
    try {
      for (const e of performance.getEntriesByType('resource')) {
        if (e.initiatorType === 'script' || JS_RE.test(e.name)) urls.add(e.name);
      }
    } catch {
      /* ignore */
    }
    return [...urls].filter((u) => /^https?:/i.test(u));
  }

  function inlineScripts(force) {
    const out = [];
    for (const s of document.scripts) {
      if (s.src || (!force && sent.has(s))) continue;
      sent.add(s);
      const t = s.textContent;
      if (t && t.trim().length > 20 && t.length <= MAX_INLINE) out.push(t);
    }
    return out;
  }

  async function collect({ force = false, html = true } = {}) {
    const s = await getSettings();
    if (!s || (!force && (!s.enabled || (!IS_FRAME && !inScope(s))))) return;
    const msg = {
      type: 'page-collect',
      pageUrl: location.href,
      frame: IS_FRAME,
      scripts: scriptUrls(),
      inline: force || s.scanInline ? inlineScripts(force) : [],
      html: null,
      force,
    };
    if (html && (force || s.scanHtml)) {
      const h = document.documentElement ? document.documentElement.outerHTML : '';
      msg.html = h.length > MAX_HTML ? h.slice(0, MAX_HTML) : h;
    }
    try {
      await chrome.runtime.sendMessage(msg);
    } catch {
      /* service worker restarting or extension reloaded */
    }
  }

  // Inline scripts injected later (SPAs, tag managers, JSONP …)
  let timer = null;
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const n of m.addedNodes) {
        if (n.nodeName === 'SCRIPT' && !n.src) {
          clearTimeout(timer);
          timer = setTimeout(() => collect({ html: false }), 1500);
          return;
        }
      }
    }
  });

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.type === 'collect') {
      collect({ force: !!msg.force }).then(() => sendResponse({ ok: true }));
      return true;
    }
    return false;
  });

  collect();
  if (document.documentElement) observer.observe(document.documentElement, { childList: true, subtree: true });
})();
