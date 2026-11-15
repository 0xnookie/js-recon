// Subdomains of the target: certificate-transparency parsing, the response fingerprint of a live host
// (title, product, subdomain-takeover signatures, wildcard DNS) and a "high value target" rating.
// Pure functions, no chrome.* — used by the service worker and the UI, unit-tested in Node.

const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/;

/** "Host" as listed in the Domains tab ("api.acme.com" or "api.acme.com:8443") → lower-case hostname[:port], or null. */
export function normalizeHost(raw) {
  const v = String(raw || '').trim().toLowerCase().replace(/\.$/, '');
  const m = /^([^:/\s]+)(?::(\d{1,5}))?$/.exec(v);
  if (!m || !HOST_RE.test(m[1])) return null;
  if (m[2] && (Number(m[2]) < 1 || Number(m[2]) > 65535)) return null;
  return m[2] ? `${m[1]}:${m[2]}` : m[1];
}

// ── certificate transparency (crt.sh JSON) ──

/**
 * Hostnames under `site` from a crt.sh `output=json` response. Wildcard names ("*.dev.acme.com") count as
 * their parent ("dev.acme.com"); e-mail addresses and other domains in the same certificate are dropped.
 */
export function parseCtNames(json, site, max = 5000) {
  let rows = json;
  if (typeof json === 'string') {
    try {
      rows = JSON.parse(json || '[]');
    } catch {
      return [];
    }
  }
  if (!Array.isArray(rows)) return [];
  site = String(site).toLowerCase();
  const out = new Set();
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    for (const raw of `${r.name_value || ''}\n${r.common_name || ''}`.split(/\s+/)) {
      const n = raw.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
      if (!n || n.includes('@') || n.includes('*')) continue;
      if (n !== site && !n.endsWith('.' + site)) continue;
      if (!HOST_RE.test(n)) continue;
      out.add(n);
      if (out.size >= max) return [...out].sort();
    }
  }
  return [...out].sort();
}

// ── which hosts may be checked ──

/**
 * Hosts of the target's own registrable domain that can be checked: valid names, no wildcards, never a
 * deny-listed host. `siteOf` and `isDenied` are passed in so this stays free of settings / chrome.*.
 */
export function hostCandidates(hosts, site, siteOf, isDenied = () => false) {
  const out = [];
  const skipped = { invalid: 0, offsite: 0, denied: 0 };
  for (const raw of new Set(hosts || [])) {
    const h = normalizeHost(raw);
    if (!h) {
      skipped.invalid++;
      continue;
    }
    const name = h.replace(/:\d+$/, '');
    if (siteOf(name) !== site) {
      skipped.offsite++;
      continue;
    }
    if (isDenied(name)) {
      skipped.denied++;
      continue;
    }
    if (!out.includes(h)) out.push(h);
  }
  return { hosts: out, skipped };
}

// ── what answered: title, product, takeover signature ──

// Error pages of hosting providers when a CNAME points at a resource that no longer exists. The host is
// a takeover candidate only if its CNAME still points at that provider (check with `dig CNAME host`).
const TAKEOVER = [
  [/<Code>NoSuchBucket<\/Code>|The specified bucket does not exist/i, 'AWS S3 / GCS bucket'],
  [/There isn['’]t a GitHub Pages site here/i, 'GitHub Pages'],
  [/herokucdn\.com\/error-pages\/no-such-app|<title>No such app<\/title>/i, 'Heroku'],
  [/Sorry, this shop is currently unavailable/i, 'Shopify'],
  [/Whatever you were looking for doesn['’]t currently exist at this address/i, 'Tumblr'],
  [/Do you want to register \*\.wordpress\.com/i, 'WordPress.com'],
  [/The thing you were looking for is no longer here, or never was/i, 'Ghost'],
  [/<title>project not found<\/title>|project not found<\/h1>/i, 'Surge.sh'],
  [/<title>Repository not found<\/title>|Repository not found<\/h1>/i, 'Bitbucket'],
  [/The gods are wise, but do not know of the site which you seek/i, 'Pantheon'],
  [/Fastly error: unknown domain/i, 'Fastly'],
  [/Help Center Closed/i, 'Zendesk'],
  [/Project doesnt exist\.\.\. yet!/i, 'Readme.io'],
  [/No settings were found for this company:/i, 'Help Scout'],
  [/We could not find what you['’]re looking for\.\s*<\/h1>/i, 'Helpjuice'],
  [/This UserVoice subdomain is currently available/i, 'UserVoice'],
  [/It looks like you may have taken a wrong turn somewhere\. Don['’]t worry\.\.\.it happens to all of us/i, 'LaunchRock'],
  [/Sorry, couldn['’]t find the status page/i, 'Pingdom'],
  [/is not a registered InCloud YouTrack/i, 'YouTrack'],
  [/There is no such company\. Did you enter the right URL\?/i, 'Canny'],
  [/Oops - We didn['’]t find your site\./i, 'Teamwork'],
  [/No Site For Domain/i, 'Kinsta'],
  [/ERR_NGROK_3200|Tunnel [\w.-]+\.ngrok(?:-free)?\.(?:io|app|dev) not found/i, 'ngrok'],
  [/If you['’]re moving your domain away from Cargo you must make this configuration/i, 'Cargo'],
  [/Sorry, this page is no longer available\.<\/h1>/i, 'Agile CRM'],
  [/Please renew your subscription<\/h1>/i, 'Tilda'],
];

// [pattern on title + start of body, product, weight, what it is]
const PRODUCTS = [
  [/<title>\s*Index of \//i, 'Directory listing', 3, 'directory listing'],
  [/"tagline"\s*:\s*"You Know, for Search"/, 'Elasticsearch', 4, 'open Elasticsearch API'],
  [/DisallowedHost at|You're seeing this error because you have <code>DEBUG = True<\/code>/i, 'Django (debug)', 4, 'debug mode'],
  [/Whitelabel Error Page/i, 'Spring Boot', 1, 'Spring Boot (try /actuator)'],
  [/Whoops(?:!|,) (?:There was an error|looks like something went wrong)/i, 'Laravel', 2, 'Laravel (debug page?)'],
  [/Dashboard \[Jenkins\]|<title>[^<]*\[Jenkins\]|X-Jenkins/i, 'Jenkins', 4, 'Jenkins'],
  [/<title>[^<]*GitLab/i, 'GitLab', 3, 'GitLab'],
  [/<title>[^<]*Grafana/i, 'Grafana', 3, 'Grafana'],
  [/<title>[^<]*Kibana|kbn-injected-metadata/i, 'Kibana', 3, 'Kibana'],
  [/<title>[^<]*Prometheus/i, 'Prometheus', 3, 'Prometheus'],
  [/<title>[^<]*phpMyAdmin/i, 'phpMyAdmin', 4, 'phpMyAdmin'],
  [/<title>[^<]*Adminer/i, 'Adminer', 4, 'Adminer'],
  [/<title>[^<]*SonarQube/i, 'SonarQube', 3, 'SonarQube'],
  [/<title>[^<]*Argo CD/i, 'Argo CD', 3, 'Argo CD'],
  [/<title>[^<]*Harbor/i, 'Harbor', 3, 'Harbor registry'],
  [/<title>[^<]*Nexus Repository/i, 'Nexus', 3, 'Nexus repository'],
  [/<title>[^<]*(?:Artifactory|JFrog)/i, 'Artifactory', 3, 'Artifactory'],
  [/<title>[^<]*(?:Jira|System Dashboard - )/i, 'Jira', 2, 'Jira'],
  [/<title>[^<]*Confluence/i, 'Confluence', 2, 'Confluence'],
  [/<title>[^<]*Kubernetes Dashboard/i, 'Kubernetes Dashboard', 4, 'Kubernetes dashboard'],
  [/<title>[^<]*Portainer/i, 'Portainer', 4, 'Portainer'],
  [/<title>[^<]*Rancher/i, 'Rancher', 4, 'Rancher'],
  [/<title>[^<]*RabbitMQ Management/i, 'RabbitMQ', 3, 'RabbitMQ management'],
  [/<title>[^<]*Consul by HashiCorp/i, 'Consul', 3, 'Consul'],
  [/<title>[^<]*Vault/i, 'Vault', 2, 'HashiCorp Vault'],
  [/<title>[^<]*Traefik/i, 'Traefik', 3, 'Traefik dashboard'],
  [/<title>[^<]*Swagger UI|swagger-ui/i, 'Swagger UI', 2, 'API docs (Swagger UI)'],
  [/<title>[^<]*Keycloak|kc-form-login|\/resources\/[\w.-]+\/login\/keycloak/i, 'Keycloak', 2, 'Keycloak'],
  [/<title>[^<]*Outlook(?: Web App)?|\/owa\/auth\//i, 'Outlook Web App', 2, 'Outlook Web App'],
  [/<title>[^<]*(?:Citrix Gateway|NetScaler)/i, 'Citrix Gateway', 3, 'Citrix Gateway'],
  [/<title>[^<]*GlobalProtect/i, 'GlobalProtect', 3, 'GlobalProtect VPN'],
  [/<title>[^<]*(?:Pulse Connect Secure|Ivanti Connect Secure)/i, 'Ivanti Connect Secure', 3, 'Ivanti / Pulse VPN'],
  [/<title>[^<]*FortiGate|\/remote\/login|fgt_lang/i, 'FortiGate', 3, 'FortiGate SSL VPN'],
  [/<title>[^<]*(?:SSL VPN Service|Cisco ASDM)|webvpn/i, 'Cisco ASA', 3, 'Cisco VPN'],
  [/<title>[^<]*Apache Tomcat/i, 'Tomcat', 2, 'Apache Tomcat (manager?)'],
  [/<title>[^<]*Webmin/i, 'Webmin', 3, 'Webmin'],
  [/<title>[^<]*(?:cPanel|WHM)/i, 'cPanel', 2, 'cPanel'],
  [/<title>[^<]*Plesk/i, 'Plesk', 2, 'Plesk'],
  [/<title>[^<]*(?:Welcome to nginx!|IIS Windows Server|Apache2 \w+ Default Page|Test Page for the Apache)/i, 'Default page', 2, 'default server page (forgotten host?)'],
  [/<title>[^<]*(?:WordPress|Log In &lsaquo;)|wp-content\//i, 'WordPress', 1, 'WordPress'],
  [/<title>[^<]*(?:Login|Log in|Sign in|Sign-in|Anmelden)\b/i, 'Login page', 1, 'login page'],
];

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#39': "'", lsaquo: '‹', rsaquo: '›', middot: '·', raquo: '»', laquo: '«', ndash: '–', mdash: '—' };

function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+\d*);/gi, (m, e) => {
    const k = e.toLowerCase();
    if (k.startsWith('#x')) return String.fromCodePoint(parseInt(k.slice(2), 16) || 32);
    if (k.startsWith('#') && k !== '#39') return String.fromCodePoint(Number(k.slice(1)) || 32);
    return ENTITIES[k] ?? m;
  });
}

/** Title, recognised product and takeover signature of a host's response body (first ~256 KB). */
export function describeResponse(body, headers = {}) {
  const text = String(body || '');
  const out = {};
  const t = /<title[^>]*>([^<]{0,300})/i.exec(text);
  if (t) {
    const title = decodeEntities(t[1]).replace(/\s+/g, ' ').trim();
    if (title) out.title = title.slice(0, 120);
  }
  for (const [re, name] of TAKEOVER) {
    if (re.test(text)) {
      out.takeover = name;
      break;
    }
  }
  const head = text.slice(0, 65536) + (headers['x-jenkins'] ? ' X-Jenkins' : '');
  for (const [re, name] of PRODUCTS) {
    if (re.test(head)) {
      out.product = name;
      break;
    }
  }
  return out;
}

// ── wildcard DNS: a made-up name answering means every name answers ──

/** True when a host's response looks like the answer to a random, non-existent subdomain. */
export function sameAsWildcard(rec, wild) {
  if (!rec || !wild || !rec.status || !wild.status) return false;
  if (rec.status !== wild.status) return false;
  if ((rec.title || '') !== (wild.title || '')) return false;
  if (rec.takeover !== wild.takeover) return false;
  const a = rec.length || 0;
  const b = wild.length || 0;
  return Math.abs(a - b) <= Math.max(64, b * 0.05);
}

/** A host is live when it answered our check, or the browser loaded something from it. */
export const hostAlive = (rec) => !!rec && ((rec.status || 0) > 0 || (rec.seen?.status || 0) > 0);

// ── high value targets ──

// [category, weight, words matched as whole labels / label parts, words also matched anywhere]
const HVT = [
  ['non-production', 3, ['dev', 'develop', 'development', 'stg', 'stage', 'staging', 'test', 'testing', 'qa', 'uat', 'preprod', 'pre', 'sandbox', 'sbx', 'beta', 'alpha', 'demo', 'int', 'integration', 'local', 'perf', 'canary', 'nonprod', 'tmp', 'temp', 'poc'], ['staging', 'preprod', 'sandbox']],
  ['admin / internal', 3, ['admin', 'administrator', 'internal', 'intranet', 'corp', 'corporate', 'backoffice', 'private', 'manage', 'management', 'manager', 'mgmt', 'console', 'ops', 'staff', 'employee', 'employees', 'hr', 'it', 'helpdesk', 'cms', 'cpanel', 'whm', 'webmin', 'plesk', 'panel', 'sharepoint', 'wiki'], ['admin', 'internal', 'intranet', 'backoffice']],
  ['CI/CD / source code', 4, ['jenkins', 'ci', 'cd', 'build', 'builds', 'gitlab', 'git', 'github', 'ghe', 'bitbucket', 'svn', 'drone', 'teamcity', 'bamboo', 'travis', 'circleci', 'concourse', 'spinnaker', 'argo', 'argocd', 'sonar', 'sonarqube', 'nexus', 'artifactory', 'jfrog', 'harbor', 'registry', 'docker', 'npm', 'pypi', 'maven', 'gerrit', 'deploy'], ['jenkins', 'gitlab', 'bitbucket', 'artifactory', 'sonarqube', 'teamcity', 'argocd']],
  ['monitoring / logs', 3, ['grafana', 'kibana', 'prometheus', 'elastic', 'elasticsearch', 'opensearch', 'splunk', 'sentry', 'log', 'logs', 'logging', 'metrics', 'zabbix', 'nagios', 'graylog', 'jaeger', 'zipkin', 'monitor', 'monitoring', 'alertmanager', 'alerts', 'apm', 'tracing', 'netdata'], ['grafana', 'kibana', 'prometheus', 'zabbix', 'nagios', 'graylog']],
  ['data store / infrastructure', 4, ['db', 'database', 'sql', 'mysql', 'mariadb', 'postgres', 'postgresql', 'pg', 'mongo', 'mongodb', 'redis', 'phpmyadmin', 'pma', 'adminer', 'kafka', 'rabbit', 'rabbitmq', 'mq', 'solr', 'couchdb', 'cassandra', 'memcache', 'memcached', 'minio', 'backup', 'backups', 'ftp', 'sftp', 'nfs', 'vault', 'consul', 'k8s', 'kube', 'kubernetes', 'rancher', 'portainer', 'openshift', 'traefik', 'haproxy', 'etcd', 'hadoop', 'airflow', 'jupyter', 'notebook', 'superset', 'metabase', 'redash'], ['phpmyadmin', 'kubernetes', 'portainer', 'jupyter', 'airflow']],
  ['remote access / mail', 3, ['vpn', 'sslvpn', 'remote', 'citrix', 'rdp', 'rdweb', 'rds', 'vdi', 'horizon', 'owa', 'webmail', 'mail', 'exchange', 'autodiscover', 'ssh', 'bastion', 'jump', 'jumphost', 'globalprotect', 'fortigate', 'forti', 'pulse', 'anyconnect', 'access'], ['sslvpn', 'webmail', 'citrix']],
  ['origin server (CDN / WAF bypass)', 3, ['origin', 'direct', 'nocdn', 'bypass'], ['origin']],
  ['partner / extranet', 2, ['portal', 'extranet', 'partner', 'partners', 'vendor', 'vendors', 'supplier', 'suppliers', 'b2b', 'reseller', 'resellers'], ['extranet']],
  ['authentication', 2, ['sso', 'auth', 'login', 'signin', 'oauth', 'oauth2', 'oidc', 'idp', 'adfs', 'okta', 'keycloak', 'cas', 'identity', 'id', 'iam', 'saml', 'mfa', '2fa', 'accounts', 'account'], ['keycloak']],
  ['legacy', 2, ['old', 'legacy', 'deprecated', 'archive', 'archived', 'classic', 'prev', 'previous', 'v1', 'bak', 'orig'], ['legacy', 'deprecated']],
  ['payments', 2, ['pay', 'payment', 'payments', 'billing', 'checkout', 'invoice', 'invoices', 'wallet', 'finance'], ['payment', 'billing', 'checkout']],
  ['API', 1, ['api', 'apis', 'graphql', 'gql', 'gateway', 'gw', 'rest', 'rpc', 'grpc', 'ws', 'wss', 'socket', 'backend', 'service', 'services', 'svc', 'swagger'], ['graphql', 'swagger']],
  ['file upload / storage', 1, ['upload', 'uploads', 'files', 'storage', 'share'], ['upload']],
];

// identity providers: an app that sends you there is usually internal / staff-only
const SSO_HOST_RE =
  /(?:^|\.)(?:login\.microsoftonline\.com|login\.microsoft\.com|login\.windows\.net|b2clogin\.com|okta\.com|oktapreview\.com|okta-emea\.com|auth0\.com|onelogin\.com|accounts\.google\.com|pingidentity\.com|pingone\.(?:com|eu)|duosecurity\.com|jumpcloud\.com|cloudflareaccess\.com)$/i;
const SSO_PATH_RE = /\/(?:adfs\/ls|saml2?\/|sso\/|cas\/login|realms\/[^/]+\/protocol\/openid-connect)/i;

function redirectHost(url) {
  if (!url) return null;
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Labels of the part before the registrable domain, split on "." and "-", trailing digits dropped (dev2 → dev). */
function hostTokens(hostname, site) {
  const sub = hostname === site ? '' : hostname.slice(0, -(site.length + 1));
  if (!sub) return { sub, tokens: [] };
  const tokens = new Set();
  for (const label of sub.split('.')) {
    tokens.add(label);
    for (const part of label.split(/[-_]/)) {
      if (!part) continue;
      tokens.add(part);
      tokens.add(part.replace(/\d+$/, ''));
    }
  }
  tokens.delete('');
  return { sub, tokens: [...tokens] };
}

/**
 * How worth testing a subdomain of the target is: the job its name suggests (CI/CD, admin, staging, VPN …)
 * plus what it answered (401/403, a recognised product, a takeover signature).
 * → { score, level: 'high' | 'medium' | null, reasons: [...] }
 */
export function rateHost(host, site, rec = null, wild = null) {
  const hostname = String(host).toLowerCase().replace(/:\d+$/, '');
  const reasons = [];
  let score = 0;
  if (rec && wild && sameAsWildcard(rec, wild)) return { score: 0, level: null, reasons: ['answers like a wildcard DNS record'], wildcard: true };

  const { sub, tokens } = hostTokens(hostname, site);
  const seen = new Set();
  let best = 0;
  let extra = 0;
  for (const [cat, weight, words, anywhere] of HVT) {
    // "anywhere" words still have to start or end a label part: phpmyadmin, adminpanel, apistaging — not badminton
    const hit = tokens.find((t) => words.includes(t)) || anywhere.find((w) => tokens.some((t) => t.length > w.length && (t.startsWith(w) || t.endsWith(w))));
    if (!hit || seen.has(cat)) continue;
    seen.add(cat);
    reasons.push(`${cat} (${hit})`);
    // the strongest category counts in full, every further one adds a point
    if (weight > best) {
      extra += best ? 1 : 0;
      best = weight;
    } else extra += 1;
  }
  score += best + Math.min(extra, 2);
  if (/(?:^|[.-])\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}(?:[.-]|$)|(?:^|\.)ip-\d/.test(sub)) {
    score += 1;
    reasons.push('IP-like name (single server)');
  }

  if (rec) {
    if (rec.takeover) {
      score += 6;
      reasons.unshift(`possible subdomain takeover (${rec.takeover})`);
    }
    if (rec.product) {
      const p = PRODUCTS.find((x) => x[1] === rec.product);
      if (p) {
        score += p[2];
        reasons.push(`answers as ${p[3]}`);
      }
    }
    const to = redirectHost(rec.url);
    if (to && to !== hostname) {
      if (SSO_HOST_RE.test(to) || SSO_PATH_RE.test(rec.url)) {
        score += 2;
        reasons.push(`behind SSO (→ ${to})`);
      } else reasons.push(`redirects to ${to}`);
    }
    const st = rec.status || 0;
    if (st === 401 || st === 403) {
      score += 1;
      reasons.push(`protected (${st})`);
    } else if (st >= 500) {
      score += 1;
      reasons.push(`server error (${st})`);
    }
    if (rec.status === 0 && !rec.seen && !rec.pending) {
      // no answer over HTTP(S): keep the name-based reasons but don't call it a top target
      if (score >= 4) score = 3;
      if (reasons.length) reasons.push('no HTTP response');
    }
  }
  const level = score >= 4 ? 'high' : score >= 2 ? 'medium' : null;
  return { score, level, reasons };
}
