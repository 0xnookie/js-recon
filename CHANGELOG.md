# Changelog

All notable changes to **JS Recon** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.6.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.6.0
[1.5.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.5.0
[1.4.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.4.0
[1.3.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.3.0
[1.2.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.2.0
[1.1.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.1.0
[1.0.0]: https://github.com/0xnookie/js-recon/releases/tag/v1.0.0
