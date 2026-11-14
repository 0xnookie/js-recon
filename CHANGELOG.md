# Changelog

All notable changes to **JS Recon** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.0] — 2026-11-14

### Added
- **Request bodies of API calls, read from the code.** The fields a request sends are
  recovered statically from `JSON.stringify({…})`, object literals, `FormData.append()`,
  `URLSearchParams`, `"a=1&b=" + x` strings and variables holding any of these, for
  `xhr.send()`, `fetch(…, { body })`, `axios.post(url, data)`, `$.post` /
  `$.ajax({ data })`, `new HttpRequest(m, url, body)` and `ky` / `got` (`{ json }`). API rows
  show them inline (`POST action.php { id }`), the detail shows the encoding and a sample
  payload, and every field is listed under Params → Request body fields with the endpoints
  it is sent to. axios / Angular `params` and jQuery GET data become query parameters.
- **URLs held in variables.** `let url = "action.php"; xhr.open("POST", url)`,
  `fetch(endpoint, opts)`, `axios.post(u, data)`, `$.ajax({ url: saveUrl })` and `{ url }`
  are resolved to the nearest assignment in the same scope (another function's variable or a
  parameter is never used), including options objects kept in a variable.
- **Bare server scripts as API endpoints**: `action.php`, `Save.aspx`, `login.do`, `.jsp`,
  `.cgi`, `.ashx` … are now method-aware API rows instead of plain links only.
- **`idor` tag** for endpoints and body fields that carry an object ID: `id`, `userId`,
  `order_id`, `uuid`, `/users/{id}`, `/u/:userId`, `"/tokens/" + id` (not static-asset paths).

### Changed
- **The API tab is sorted by what to test first**: sensitive names, IDOR candidates,
  state-changing methods, endpoints with known inputs, then calls seen live. *Interesting*
  also keeps *idor* rows; Params ranks *idor* fields after *interesting* ones.
- **curl sends the real request body**: `--data-raw '{"id":1}'` as JSON, form-encoded or
  multipart (`--form-string`, so values are never read as local files), as the page sends it.
- **OpenAPI / Postman exports** use the body fields from the code too, with example values,
  number / boolean types and the page's media type (JSON, form, multipart); Postman writes
  urlencoded / form-data bodies. Text and Markdown reports list each endpoint's body fields.

## [1.8.0] — 2026-11-12

### Changed
- **Ask before scanning a site (new default scope).** Opening a tab no longer starts a
  scan: nothing is fetched, observed or hooked on a site until you OK it. A tab that is
  waiting shows a **?** on the toolbar icon, and the popup offers **Scan this tab**
  (one-off, while the tab stays on that host; kept across service-worker restarts, not
  browser restarts), **Always scan this site** (adds it to the allow-list) or **Never**
  (adds it to the deny-list). Pressing Rescan on a waiting tab counts as "Scan this tab".
  In this mode runtime hooks are registered for allow-listed sites only and injected
  into a tab when you approve it.
- **Updating moves "Only the active tab" and "Every open tab" to the new mode once.**
  Settings are stored whole, so installs that ever saved them kept an old default
  (1.6.0 changed the default without migrating, leaving such installs on "Every open
  tab"). An allow-list setup is left alone; pick another mode in Settings → Scope.

### Fixed
- CI: the ZIP round-trip tests read archives in-process instead of shelling out to
  `tar` / `unzip`. Ubuntu 24.04's `unzip` ignores the UTF-8 name flag, which failed every
  CI and release run since the workflows were added.

## [1.7.0] — 2026-11-11

### Added
- **Content search** — grep the raw text of every scanned JS file and the sources rebuilt
  from source maps for a host, for a literal string or `/regex/`. Finds what the detection
  rules have no pattern for (Next.js `ACTION_ID_` server-action refs, feature flags,
  internal hosts, build constants). Results group by file with line / column and a
  highlighted, windowed snippet. Reached from the dashboard's **Search files** button or
  the **Search file contents…** export-menu item. Bodies aren't stored, so it re-fetches
  (normally from the HTTP cache); inline scripts and page DOM are not covered.

## [1.6.0] — 2026-11-11

### Changed
- **Scope now defaults to the active tab only.** Instead of passively scanning every
  open tab, JS Recon scans just the page you are looking at; the frontmost tab of each
  window is tracked and background tabs are left alone until you switch to them.
  Switching to a background tab scans it once. "Every open tab" and the allow-list
  remain as options, and the deny-list applies in every mode.

### Fixed
- Icon-only buttons (delete, pause, play, dashboard, settings) now center their glyph in
  the 28×28 box — a leading-icon padding rule was overriding the icon-button layout and
  pushing the glyphs to the right.

## [1.5.0] — 2026-11-11

### Added
- **JWT expiry triage** — `exp` is decoded offline to flag `expired` / `expires-soon` tokens.
- **More offline enrichment** — GCP service-account JSON → project / email / key id, and
  Firebase config near an API key → project (`firebase` tag).
- **Eight new secret rules** (76 secret / 162 total): OpenRouter, Perplexity, Tailscale,
  PlanetScale, Databricks, Terraform Cloud, Figma, Sentry auth token.
- **New exports** — SARIF 2.1.0 (CI code-scanning) and a Markdown report (tickets / PRs).

### Changed
- The Secrets "Hide tentative" toggle is now **"Hide low-value"** and also hides
  example / demo-looking values.

## [1.4.0] — 2026-11-11

### Added
- **Offline secret enrichment** — the owning AWS account number and key type are decoded
  locally from an access-key ID (no request to AWS), and every secret is checked for
  structural example / demo signals (sequential or repeated runs, low character diversity,
  demo markers) and tagged `example` rather than dropped.

## [1.3.0] — 2026-11-11

### Added
- **Routes** tab — client-side route maps extracted from React Router, Vue and Angular,
  with guarded routes flagged.
- **DOM-XSS taint flows** — a URL source reaching a sink within one expression is reported
  in the Sinks tab.
- **Endpoint liveness** — an opt-in, two-click check that records the HTTP status of the
  safe same-site GET candidates so live, protected, redirecting and dead endpoints are
  distinguishable.
- **GitHub Actions** CI and tagged-release workflows.

## [1.2.0] — 2026-11-11

### Added
- Change alerts across bundle deploys, a GraphQL schema sketch, OpenAPI 3 and Postman
  collection exports, and "send GET URLs to proxy".

## [1.1.0] — 2026-11-11

### Added
- Observed traffic (fetch / XHR / WebSocket method, path, parameter and header names),
  opt-in runtime hooks, postMessage handler analysis, wordlist export, and Wayback Machine
  lookups for historical JS.

## [1.0.0] — 2026-11-11

### Added
- Initial release: passive scanning of the JavaScript, inline scripts, page DOM and
  response headers of the pages you visit, surfacing endpoints, API keys, secrets, source
  maps, cloud assets and other recon data, with per-host findings and report exports.

[1.9.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.9.0
[1.8.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.8.0
[1.7.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.7.0
[1.6.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.6.0
[1.5.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.5.0
[1.4.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.4.0
[1.3.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.3.0
[1.2.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.2.0
[1.1.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.1.0
[1.0.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.0.0
