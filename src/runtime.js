// Runtime hooks (opt-in, Settings → Runtime hooks). Registered by the service worker with
// chrome.scripting.registerContentScripts({ world: 'MAIN', runAt: 'document_start' }), so it runs in
// the page's own JavaScript context before the page's scripts.
//
// Records only NAMES, never values:
//   URLSearchParams.get/getAll/has            → query parameter names the code reads
//   Storage getItem/setItem/removeItem        → localStorage / sessionStorage keys
//   document.cookie = "name=…"                → cookie names the code writes
//   Element.getAttribute/hasAttribute("data-…") → data-* attributes
//   fetch / XMLHttpRequest bodies             → top-level JSON / form field names per endpoint
//   addEventListener("message") / onmessage   → the handler's source, for the postMessage analysis
//
// Hooks are Proxies around the native functions (same name, same toString) and never throw into the page.
// Batches go to the isolated content script (content.js) as a JSON string in a DOM event.
(() => {
  const FLAG = Symbol.for('jsrecon.runtime');
  if (window[FLAG]) return;
  Object.defineProperty(window, FLAG, { value: true });

  const EVT = 'jsrecon:runtime';
  const MAX_ITEMS = 3000;
  const seen = new Set();
  let pending = { params: [], storage: [], cookies: [], attrs: [], bodies: [], handlers: [] };
  let count = 0;
  let ready = false;
  let timer = 0;

  const flush = () => {
    timer = 0;
    const p = pending;
    pending = { params: [], storage: [], cookies: [], attrs: [], bodies: [], handlers: [] };
    try {
      document.dispatchEvent(new CustomEvent(EVT, { detail: JSON.stringify(p) }));
    } catch {
      /* document gone */
    }
  };
  const schedule = () => {
    if (ready && !timer) timer = setTimeout(flush, 1500);
  };
  const add = (kind, key, item = key) => {
    if (count >= MAX_ITEMS || typeof key !== 'string' || !key || key.length > 300) return;
    const k = kind + '\u0000' + key;
    if (seen.has(k)) return;
    seen.add(k);
    count++;
    pending[kind].push(item);
    schedule();
  };
  // the content script announces itself; until then everything is buffered
  document.addEventListener('jsrecon:ready', () => {
    ready = true;
    const any = Object.values(pending).some((a) => a.length);
    if (any) schedule();
  });

  const hook = (obj, name, before) => {
    try {
      const orig = obj[name];
      if (typeof orig !== 'function') return;
      obj[name] = new Proxy(orig, {
        apply(target, self, args) {
          try {
            before(self, args);
          } catch {
            /* never break the page */
          }
          return Reflect.apply(target, self, args);
        },
      });
    } catch {
      /* frozen / non-writable */
    }
  };

  // ── URL parameters ──
  for (const m of ['get', 'getAll', 'has']) hook(URLSearchParams.prototype, m, (_s, a) => add('params', String(a[0])));

  // ── web storage ──
  let session = null;
  try {
    session = window.sessionStorage;
  } catch {
    /* sandboxed */
  }
  for (const m of ['getItem', 'setItem', 'removeItem']) {
    hook(Storage.prototype, m, (self, a) => {
      const area = self === session ? 'session' : 'local';
      add('storage', area + ':' + String(a[0]), { key: String(a[0]), area });
    });
  }

  // ── cookies written by the code ──
  try {
    const d = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (d && d.set) {
      Object.defineProperty(Document.prototype, 'cookie', {
        configurable: true,
        enumerable: d.enumerable,
        get: d.get,
        set: new Proxy(d.set, {
          apply(target, self, args) {
            try {
              add('cookies', String(args[0]).split(';')[0].split('=')[0].trim());
            } catch {
              /* ignore */
            }
            return Reflect.apply(target, self, args);
          },
        }),
      });
    }
  } catch {
    /* ignore */
  }

  // ── data-* attributes ──
  const dataAttr = (_s, a) => {
    const n = a[0];
    if (typeof n === 'string' && n.length > 5 && n.charCodeAt(0) === 100 && n.startsWith('data-')) add('attrs', n.toLowerCase());
  };
  hook(Element.prototype, 'getAttribute', dataAttr);
  hook(Element.prototype, 'hasAttribute', dataAttr);

  // ── request body field names ──
  const bodyKeys = (body) => {
    if (body == null) return null;
    if (typeof body === 'string') {
      const t = body.trim();
      if (t.startsWith('{')) {
        try {
          const o = JSON.parse(t);
          return o && typeof o === 'object' && !Array.isArray(o) ? Object.keys(o) : null;
        } catch {
          return null;
        }
      }
      if (/^[\w.[\]%-]+=/.test(t)) return [...new URLSearchParams(t).keys()];
      return null;
    }
    if (body instanceof URLSearchParams || (typeof FormData !== 'undefined' && body instanceof FormData)) return [...new Set(body.keys())];
    return null;
  };
  const recordBody = (method, url, body) => {
    const keys = bodyKeys(body);
    if (!keys || !keys.length) return;
    let path = String(url);
    try {
      const u = new URL(path, location.href);
      path = (u.origin === location.origin ? '' : u.origin) + u.pathname;
    } catch {
      /* keep as is */
    }
    const m = String(method || 'POST').toUpperCase();
    add('bodies', m + ' ' + path + ' ' + keys.join(','), { method: m, path, keys: keys.slice(0, 100).map(String) });
  };
  hook(window, 'fetch', (_s, a) => {
    const input = a[0];
    const init = a[1] || {};
    const url = typeof input === 'string' || input instanceof URL ? String(input) : input && input.url;
    if (url && init.body != null) recordBody(init.method || (input && input.method) || 'GET', url, init.body);
  });
  const xhrInfo = new WeakMap();
  hook(XMLHttpRequest.prototype, 'open', (self, a) => xhrInfo.set(self, { method: a[0], url: a[1] }));
  hook(XMLHttpRequest.prototype, 'send', (self, a) => {
    const i = xhrInfo.get(self);
    if (i && a[0] != null) recordBody(i.method, i.url, a[0]);
  });

  // ── postMessage handlers ──
  const handlerSource = (fn) => {
    let f = fn;
    if (f && typeof f === 'object' && typeof f.handleEvent === 'function') f = f.handleEvent;
    if (typeof f !== 'function') return;
    let src;
    try {
      src = Function.prototype.toString.call(f);
    } catch {
      return;
    }
    if (!src || /\{\s*\[native code\]\s*\}$/.test(src)) return;
    add('handlers', src.slice(0, 200), src.slice(0, 30000));
  };
  hook(EventTarget.prototype, 'addEventListener', (self, a) => {
    if (a[0] === 'message' && self === window) handlerSource(a[1]);
  });
  try {
    const d = Object.getOwnPropertyDescriptor(window, 'onmessage') || Object.getOwnPropertyDescriptor(Window.prototype, 'onmessage');
    if (d && d.set && d.configurable) {
      Object.defineProperty(window, 'onmessage', {
        configurable: true,
        enumerable: d.enumerable,
        get: d.get,
        set: new Proxy(d.set, {
          apply(target, self, args) {
            try {
              handlerSource(args[0]);
            } catch {
              /* ignore */
            }
            return Reflect.apply(target, self, args);
          },
        }),
      });
    }
  } catch {
    /* ignore */
  }
})();
