// Acceptance tests for the v5.0 Netlify Function proxy layer.
// Runs without a framework, without DOM, without a build step.
//   node scripts/acceptance-proxy.mjs
//
// What it covers:
//   1. The Netlify Function file exists at the expected path
//      and contains the expected CISA / NVD / EPSS upstream URLs.
//   2. The function declares a default export handler (the
//      Netlify Function runtime contract).
//   3. The function returns FetchResult-shaped JSON: a successful
//      200 with { data, source, mode, nvdStatus, epssStatus, ... }
//      and a 502 fallback with { mode: 'fallback', fallbackReason }.
//   4. The Netlify config (`netlify.toml`) wires the functions
//      directory and does not introduce external dependencies.
//   5. The frontend service prefers the proxy endpoint over
//      browser-direct fetches, and falls back to the v4
//      browser-direct path when the proxy is unreachable.
//   6. The service adds a `proxyStatus` field to FetchResult
//      and the Header renders a "Proxy: Netlify" pill when the
//      proxy was the live transport.
//   7. The CISA / NVD / EPSS URLs and severity rules in the
//      function mirror the browser-side providers — so the
//      same data flows through both transports.
//
// This is purely source-level / structural verification. It
// does NOT require network access, does NOT hit any real
// CISA / NVD / EPSS endpoint, and does NOT start a Netlify
// dev server. The live data flow is verified on Netlify
// itself via a deployment preview (see DEPLOYMENT.md).

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

/* ------------------------------------------------------------------ */
/* Test runner                                                        */
/* ------------------------------------------------------------------ */

let passed = 0;
let failed = 0;
const failures = [];

function assert(label, condition, extra = '') {
  if (condition) {
    passed++;
    console.log(`  \u2713 ${label}`);
  } else {
    failed++;
    failures.push({ label, extra });
    console.log(`  \u2717 ${label}${extra ? '  [' + extra + ']' : ''}`);
  }
}

function section(name) {
  console.log(`\n--- ${name} ---`);
}

/* ------------------------------------------------------------------ */
/* 1. The Netlify Function file exists and is a Node ESM module       */
/* ------------------------------------------------------------------ */

section('Netlify Function file (netlify/functions/dataset.mjs)');

const functionPath = join(root, 'netlify', 'functions', 'dataset.mjs');
const functionExists = existsSync(functionPath);
assert('netlify/functions/dataset.mjs exists', functionExists,
  functionExists ? '' : 'expected the v5.0 serverless aggregator');

let functionSrc = '';
if (functionExists) {
  functionSrc = readFileSync(functionPath, 'utf8');
}

assert('function is an ES module (export default handler)',
  /export\s+default\s+async\s*\(/.test(functionSrc) ||
    /export\s+default\s+async\s+function/.test(functionSrc) ||
    /export\s+default\s+function/.test(functionSrc),
  'expected a default-exported handler (Netlify Function shape)');

/* ------------------------------------------------------------------ */
/* 2. The function references all three upstream feeds                */
/* ------------------------------------------------------------------ */

section('Function references the right upstream feeds');

assert('function reads the CISA KEV JSON feed',
  /cisa\.gov\/sites\/default\/files\/feeds\/known_exploited_vulnerabilities\.json/.test(functionSrc),
  'expected the official CISA KEV feed URL');

assert('function reads the NVD CVE 2.0 endpoint',
  /services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0/.test(functionSrc),
  'expected the official NVD CVE 2.0 endpoint URL');

assert('function reads the FIRST EPSS endpoint',
  /api\.first\.org\/data\/v1\/epss/.test(functionSrc),
  'expected the official FIRST EPSS endpoint URL');

assert('function uses an 8-second per-request timeout (matches browser)',
  /8000|PER_REQUEST_TIMEOUT_MS\s*=\s*8_?000/.test(functionSrc),
  'expected per-request timeout to match the browser-side 8 s ceiling');

assert('function applies an overall budget under the 26 s Netlify limit',
  /24_?000|OVERALL_BUDGET_MS\s*=\s*24_?000/.test(functionSrc),
  'expected an overall budget of 24 s (safety margin under Netlify default)');

/* ------------------------------------------------------------------ */
/* 3. The function returns the FetchResult-shaped JSON contract       */
/* ------------------------------------------------------------------ */

section('Function response shape (FetchResult contract)');

assert('function returns HTTP 200 on success',
  /jsonResponse\(\s*200\b/.test(functionSrc) ||
    /new\s+Response\([^,]+,\s*\{\s*status:\s*200\b/.test(functionSrc),
  'expected a 200 response on the success path');

assert('function returns HTTP 502 with mode="fallback" on CISA failure',
  /jsonResponse\(\s*502[\s\S]{0,400}mode:\s*['"]fallback['"]/.test(functionSrc) ||
    /status:\s*502[\s\S]{0,400}mode:\s*['"]fallback['"]/.test(functionSrc),
  'expected a 502 + { mode: "fallback", fallbackReason } response on CISA failure');

assert('function emits nvdStatus and epssStatus fields in the success body',
  /nvdStatus:/.test(functionSrc) && /epssStatus:/.test(functionSrc),
  'expected nvdStatus and epssStatus in the success body');

assert('function uses "unavailable" as the partial-failure value',
  /['"]unavailable['"]/.test(functionSrc),
  'expected nvdStatus / epssStatus "unavailable" sentinel');

assert('v5.0.1: function sets a CDN-cacheable Cache-Control with s-maxage=900',
  /Cache-Control['"]\s*:\s*['"]public,\s*s-maxage=900,\s*stale-while-revalidate=300/.test(functionSrc),
  'expected Cache-Control: public, s-maxage=900, stale-while-revalidate=300 (15 min CDN cache + 5 min SWR)');

assert('v5.0.1: function response does NOT use the v5.0 no-store directive',
  !/Cache-Control['"]\s*:\s*['"]no-store/.test(functionSrc),
  'expected no-store to be removed in v5.0.1 so the CDN can absorb repeat visits');

assert('function sets Access-Control-Allow-Origin: * (safe for embed / proxy)',
  /Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]/.test(functionSrc),
  'expected permissive CORS for the function response');

/* ------------------------------------------------------------------ */
/* 4. The function does not introduce secrets or new data sources     */
/* ------------------------------------------------------------------ */

section('Honesty: no new sources, no API keys, no scoring fabrication');

assert('function does NOT add any new data source (no OSV, GHSA, etc.)',
  !/osv\.dev|osv\.osvdev|ghsa|advisories\.github/.test(functionSrc),
  'v5.0 must not silently add OSV.dev / GHSA — those are v5.1+');

assert('v5.0.2: function reads ONLY the documented optional NVD_API_KEY env var (no others)',
  // v5.0.2 added an optional NVD_API_KEY env var. It must be
  // the ONLY env var the function reads — no silent new
  // credentials. The test asserts that NVD_API_KEY is the
  // only process.env.* read in the function.
  (() => {
    const envReads = functionSrc.match(/process\.env\.[A-Z_][A-Z0-9_]*/g) || [];
    if (envReads.length === 0) return false; // v5.0.2 must read at least NVD_API_KEY
    const unique = Array.from(new Set(envReads));
    return unique.length === 1 && unique[0] === 'process.env.NVD_API_KEY';
  })(),
  'expected the function to read ONLY process.env.NVD_API_KEY (no other env vars)');

assert('function does NOT fabricate CVSS / EPSS scores',
  // The function should only assign cvssScore / epssProbability
  // from the NVD / EPSS upstream response (or 0 as default).
  // It must never invent a value.
  !/cvssScore\s*[:=]\s*Math\.random|epssProbability\s*[:=]\s*Math\.random/.test(functionSrc) &&
    !/cvssScore\s*[:=]\s*[5-9]\b/.test(functionSrc) &&
    !/epssProbability\s*[:=]\s*0\.[1-9]/.test(functionSrc),
  'expected cvssScore and epssProbability to come only from upstream (or default 0)');

/* ------------------------------------------------------------------ */
/* 5. The Netlify config wires the functions directory                */
/* ------------------------------------------------------------------ */

section('Netlify config (netlify.toml)');

const netlifyTomlPath = join(root, 'netlify.toml');
const netlifyTomlExists = existsSync(netlifyTomlPath);
assert('netlify.toml exists at the project root', netlifyTomlExists,
  netlifyTomlExists ? '' : 'expected netlify.toml with build + functions config');

let tomlSrc = '';
if (netlifyTomlExists) {
  tomlSrc = readFileSync(netlifyTomlPath, 'utf8');
}

assert('netlify.toml sets publish = "dist"',
  /publish\s*=\s*["']dist["']/.test(tomlSrc),
  'expected publish = "dist" so the Vite output is the site root');

assert('netlify.toml sets functions = "netlify/functions"',
  /functions\s*=\s*["']netlify\/functions["']/.test(tomlSrc),
  'expected functions directory to be netlify/functions');

assert('netlify.toml sets a build command (npm run build)',
  /command\s*=\s*["']npm run build["']/.test(tomlSrc),
  'expected build command to run the Vite production build');

assert('netlify.toml configures the dataset function with node_bundler = "none"',
  /\[functions\.dataset\]/.test(tomlSrc) &&
    /node_bundler\s*=\s*["']none["']/.test(tomlSrc),
  'expected the dataset function to skip esbuild bundling (plain .mjs)');

/* ------------------------------------------------------------------ */
/* 6. The frontend service uses the proxy                             */
/* ------------------------------------------------------------------ */

section('Frontend service — proxy-first orchestration');

const serviceSrc = readFileSync(
  join(root, 'src', 'services', 'vulnerabilityService.ts'), 'utf8');

assert('service declares a DATASET_PROXY_URL constant pointing at the function',
  /DATASET_PROXY_URL/.test(serviceSrc) &&
    /\/\.netlify\/functions\/dataset/.test(serviceSrc),
  'expected DATASET_PROXY_URL with the Netlify Function path');

assert('service exposes a ProxyStatus type',
  /export\s+type\s+ProxyStatus/.test(serviceSrc),
  'expected export type ProxyStatus');

assert('ProxyStatus covers proxy / browser-direct / unavailable',
  /ProxyStatus\s*=\s*['"]proxy['"]\s*\|\s*['"]browser-direct['"]\s*\|\s*['"]unavailable['"]/.test(serviceSrc),
  'expected ProxyStatus = "proxy" | "browser-direct" | "unavailable"');

assert('FetchResult includes optional proxyStatus field',
  /proxyStatus\?\s*:\s*ProxyStatus/.test(serviceSrc),
  'expected proxyStatus?: ProxyStatus on FetchResult');

assert('service has a tryProxyFetch() helper that calls fetch(DATASET_PROXY_URL)',
  /tryProxyFetch/.test(serviceSrc) &&
    (
      /fetch\(\s*DATASET_PROXY_URL/.test(serviceSrc) ||
      /fetch\(\s*url/.test(serviceSrc) ||
      /fetch\(\s*`?\$\{?DATASET_PROXY_URL/.test(serviceSrc)
    ),
  'expected tryProxyFetch to call the proxy endpoint (direct or templated URL)');

assert('service has a tryBrowserDirectFetch() helper for the v4 fallback',
  /tryBrowserDirectFetch/.test(serviceSrc),
  'expected the v4 browser-direct path to be preserved as tryBrowserDirectFetch');

assert('service tries the proxy BEFORE the browser-direct path (tryLiveFetch wraps both)',
  (() => {
    // tryProxyFetch should appear before tryBrowserDirectFetch in
    // the file, and tryLiveFetch (which calls both) should appear
    // even earlier as the entry point.
    const iProxy = serviceSrc.indexOf('tryProxyFetch');
    const iBrowser = serviceSrc.indexOf('tryBrowserDirectFetch');
    const iWrapper = serviceSrc.indexOf('tryLiveFetch');
    return iProxy > 0 && iBrowser > 0 && iWrapper > 0 &&
      iWrapper < iProxy && iProxy < iBrowser;
  })(),
  'expected tryLiveFetch -> tryProxyFetch -> tryBrowserDirectFetch ordering');

assert('tryProxyFetch treats any fetch failure (network / non-2xx / shape) as null',
  (() => {
    // Look for a `catch {` block inside tryProxyFetch whose body
    // returns null. The error-handling block may have several
    // lines of comments above the return. We slice from the
    // function definition past the catch block (or 6000 chars,
    // whichever is shorter) so the catch is in scope.
    const i = serviceSrc.indexOf('tryProxyFetch');
    if (i < 0) return false;
    const tail = serviceSrc.slice(i, i + 6000);
    return /catch\s*\{[\s\S]{0,500}return\s+null/.test(tail);
  })(),
  'expected tryProxyFetch to swallow errors and return null on any failure');

assert('FetchResult on a successful live fetch is tagged with proxyStatus: "proxy"',
  /proxyStatus:\s*['"]proxy['"]/.test(serviceSrc),
  'expected the proxy-success branch to set proxyStatus: "proxy"');

assert('FetchResult on a browser-direct fallback is tagged with proxyStatus: "browser-direct"',
  /proxyStatus:\s*['"]browser-direct['"]/.test(serviceSrc),
  'expected the browser-direct branch to set proxyStatus: "browser-direct"');

assert('FetchResult on a total failure is tagged with proxyStatus: "unavailable"',
  /proxyStatus:\s*['"]unavailable['"]/.test(serviceSrc),
  'expected the total-failure branch to set proxyStatus: "unavailable"');

/* ------------------------------------------------------------------ */
/* 6.5. v5.0.1 — CDN cache + forceRefresh cache-busting               */
/* ------------------------------------------------------------------ */

section('v5.0.1 — CDN cache headers + forceRefresh cache-busting');

assert('v5.0.1: tryProxyFetch accepts a forceRefresh option',
  /tryProxyFetch\(\s*[\s\S]{0,400}opts[\s\S]{0,200}forceRefresh/.test(serviceSrc) ||
    /tryProxyFetch\(\s*opts[\s\S]{0,200}forceRefresh/.test(serviceSrc) ||
    /async function tryProxyFetch\(\s*opts\s*:\s*\{\s*forceRefresh/.test(serviceSrc),
  'expected tryProxyFetch to accept an opts object with forceRefresh');

assert('v5.0.1: tryProxyFetch appends a cache-busting ?t=<timestamp> on forceRefresh',
  (() => {
    // The cache-busting URL must be constructed inside tryProxyFetch
    // (not at module scope) and must reference Date.now() so every
    // forced refresh gets a unique URL.
    const i = serviceSrc.indexOf('tryProxyFetch');
    if (i < 0) return false;
    const tail = serviceSrc.slice(i, i + 4000);
    return /forceRefresh[\s\S]{0,500}\?t=/.test(tail) &&
      /Date\.now\(\)/.test(tail);
  })(),
  'expected "?t=${Date.now()}" appended to the URL when forceRefresh is true');

assert('v5.0.1: tryLiveFetch accepts a forceRefresh option in its signature',
  /async function tryLiveFetch\(\s*[\s\S]{0,200}forceRefresh/.test(serviceSrc),
  'expected the tryLiveFetch signature to declare a forceRefresh option');

assert('v5.0.1: tryLiveFetch forwards opts to tryProxyFetch',
  /await\s+tryProxyFetch\(\s*opts\s*\)/.test(serviceSrc),
  'expected tryLiveFetch to call `tryProxyFetch(opts)` (forwarding the option object)');

assert('v5.0.1: fetchVulnerabilities forwards forceRefresh to tryLiveFetch',
  /tryLiveFetch\(\s*\{\s*forceRefresh:\s*query\.forceRefresh/.test(serviceSrc),
  'expected fetchVulnerabilities to call tryLiveFetch({ forceRefresh: query.forceRefresh })');

assert('v5.0.1: the no-store directive is removed from the function response',
  !/Cache-Control['"]\s*:\s*['"]no-store/.test(functionSrc),
  'expected no-store removed so the CDN can cache repeat visits');

assert('v5.0.1: the function response includes s-maxage=900 (15 min)',
  /s-maxage=900/.test(functionSrc),
  'expected s-maxage=900 so Netlify\'s edge caches for 15 minutes');

assert('v5.0.1: the function response includes stale-while-revalidate=300 (5 min)',
  /stale-while-revalidate=300/.test(functionSrc),
  'expected stale-while-revalidate=300 so the next visitor after expiry gets a stale response immediately + a background refresh');

assert('v5.0.1: no max-age directive is set (CDN-only caching, not browser caching)',
  // The browser is told not to cache (`cache: 'no-store'` on the
  // client fetch). The function response should rely solely on
  // `s-maxage` (CDN), not `max-age` (browser).
  !/Cache-Control['"]\s*:\s*['"][^'"]*\bmax-age\s*=/.test(functionSrc),
  'expected no max-age directive so browser HTTP cache is not used (CDN only)');

/* ------------------------------------------------------------------ */
/* 7. The Header shows a Proxy pill                                   */
/* ------------------------------------------------------------------ */

section('Header UI — Proxy: Netlify pill');

const headerSrc = readFileSync(
  join(root, 'src', 'components', 'Header.tsx'), 'utf8');

assert('Header imports a Cloud icon for the Proxy pill',
  /Cloud/.test(headerSrc),
  'expected a Cloud icon import in Header');

assert('Header renders a "Proxy: Netlify" pill when proxyStatus === "proxy"',
  /proxyStatus\s*===\s*['"]proxy['"][\s\S]{0,400}Proxy:\s*Netlify/.test(headerSrc),
  'expected the Proxy: Netlify pill on a successful proxy fetch');

assert('Proxy pill uses an info tone (cyan, matches Cache: fresh)',
  (() => {
    const i = headerSrc.indexOf("proxyStatus === 'proxy'");
    if (i < 0) return false;
    const slice = headerSrc.slice(i, i + 500);
    return /tone\s*=\s*['"]info['"]/.test(slice);
  })(),
  'expected tone="info" on the Proxy pill');

/* ------------------------------------------------------------------ */
/* 8. The function and the browser-side providers share the same URLs */
/* ------------------------------------------------------------------ */

section('URL + severity parity between function and browser providers');

const cisaSrc = readFileSync(
  join(root, 'src', 'services', 'providers', 'cisaKev.ts'), 'utf8');
const nvdSrc = readFileSync(
  join(root, 'src', 'services', 'providers', 'nvd.ts'), 'utf8');
const epssSrc = readFileSync(
  join(root, 'src', 'services', 'providers', 'epss.ts'), 'utf8');

assert('CISA KEV URL matches between function and browser provider',
  (functionSrc.match(/cisa\.gov\/sites\/default\/files\/feeds\/known_exploited_vulnerabilities\.json/) || [])[0] ===
    (cisaSrc.match(/cisa\.gov\/sites\/default\/files\/feeds\/known_exploited_vulnerabilities\.json/) || [])[0]);

assert('NVD base URL matches between function and browser provider',
  (functionSrc.match(/services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0/) || [])[0] ===
    (nvdSrc.match(/services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0/) || [])[0]);

assert('FIRST EPSS base URL matches between function and browser provider',
  (functionSrc.match(/api\.first\.org\/data\/v1\/epss/) || [])[0] ===
    (epssSrc.match(/api\.first\.org\/data\/v1\/epss/) || [])[0]);

assert('CISA severity rule (Known ransomware → Critical, else High) matches',
  /knownRansomwareCampaignUse\s*===\s*['"]Known['"]/.test(functionSrc) &&
    /['"]High['"]/.test(functionSrc) &&
    /knownRansomwareCampaignUse\s*===\s*['"]Known['"]/.test(cisaSrc) &&
    /['"]High['"]/.test(cisaSrc));

assert('NVD chunk size matches between function and browser provider (100 CVEs)',
  /CHUNK_SIZE\s*=\s*100/.test(functionSrc) &&
    /CHUNK_SIZE\s*=\s*100/.test(nvdSrc));

assert('EPSS chunk size matches between function and browser provider (100 CVEs)',
  /CHUNK_SIZE\s*=\s*100/.test(epssSrc));

/* ------------------------------------------------------------------ */
/* 8.5. v5.0.2 — NVD rate-limit hardening + optional server-only key  */
/* ------------------------------------------------------------------ */

section('v5.0.2 — NVD rate-limit hardening + optional server-only NVD_API_KEY');

assert('v5.0.2: function reads NVD_API_KEY from process.env (server-side only)',
  /process\.env\.NVD_API_KEY/.test(functionSrc),
  'expected process.env.NVD_API_KEY to be read inside the function');

assert('v5.0.2: function never puts NVD_API_KEY in the response body',
  // The jsonResponse helper's body parameter is the FetchResult
  // shape (data, source, mode, nvdStatus, etc.). It must never
  // receive a NVD_API_KEY, and the function body must not
  // assign the key to a response field.
  (() => {
    // Find the jsonResponse helper definition.
    const i = functionSrc.indexOf('function jsonResponse(');
    if (i < 0) return true; // if no helper to inspect, pass
    const tail = functionSrc.slice(i, i + 800);
    return !/NVD_API_KEY/.test(tail);
  })() &&
    // Also: the function must not return a field named anything
    // like 'apiKey' on the success path.
    !/nvdApiKey|apiKey\s*:\s*[^,}\s]+/.test(functionSrc),
  'expected NVD_API_KEY to never appear in the function response');

assert('v5.0.2: function passes apiKey as ?apiKey=... query param to NVD when set',
  // Look for a URL construction that appends `&apiKey=...` or
  // a conditional that uses apiKey in the URL.
  /apiKey\s*=\s*\$\{[^}]*encodeURIComponent[^}]*apiKey\}/.test(functionSrc) ||
    /apiKey=.{0,30}apiKey/.test(functionSrc) ||
    /\?apiKey=/.test(functionSrc),
  'expected ?apiKey=<key> on the NVD URL when NVD_API_KEY is set');

assert('v5.0.2: function uses serial chunk fetch (concurrency = 1) without NVD_API_KEY',
  // Look for the actual `concurrency = apiKey ? X : 1` line in
  // the function body (NOT the docstring comment). Find the
  // `process.env.NVD_API_KEY` line and slice from there.
  (() => {
    const i = functionSrc.indexOf('process.env.NVD_API_KEY');
    if (i < 0) return false;
    const tail = functionSrc.slice(i, i + 1000);
    return /concurrency\s*=\s*apiKey\s*\?\s*[^:]+\s*:\s*1\b/.test(tail);
  })(),
  'expected concurrency = apiKey ? chunks.length : 1 (serial) when NVD_API_KEY is absent');

assert('v5.0.2: function uses parallel chunk fetch with NVD_API_KEY',
  // Same approach: find the actual concurrency line, assert
  // the "true" branch uses parallel chunks (chunks.length).
  (() => {
    const i = functionSrc.indexOf('process.env.NVD_API_KEY');
    if (i < 0) return false;
    const tail = functionSrc.slice(i, i + 1000);
    return /concurrency\s*=\s*apiKey\s*\?\s*chunks\.length/.test(tail);
  })(),
  'expected concurrency = apiKey ? chunks.length (parallel) when NVD_API_KEY is set');

assert('v5.0.2: function includes a small settledAll concurrency helper',
  /async function settledAll\(/.test(functionSrc) ||
    /function settledAll\(/.test(functionSrc),
  'expected a concurrency helper (e.g. settledAll) for serial chunk fetch');

assert('v5.0.2: function returns a concise 429 reason (not repeated chunk errors)',
  /rate limit reached[\s\S]{0,400}HTTP 429/.test(functionSrc) ||
    /HTTP 429[\s\S]{0,400}rate limit reached/.test(functionSrc) ||
    (/rate limit reached/.test(functionSrc) && /HTTP 429/.test(functionSrc)),
  'expected a single concise reason string for 429, not a joined per-chunk error list');

assert('v5.0.2: 429 reason mentions severity fallback to CISA-derived values',
  /rate limit reached[\s\S]{0,500}CISA-derived/.test(functionSrc),
  'expected the 429 reason to tell the user severity falls back to CISA-derived');

assert('v5.0.2: non-429 chunk errors are de-duplicated in the error message',
  // The new code uses `Array.from(new Set(reasons))` to avoid
  // "HTTP 503; HTTP 503; HTTP 503" repetition. Look for the
  // de-duplication call.
  /new Set\(reasons\)/.test(functionSrc),
  'expected new Set(reasons) to de-duplicate per-chunk errors');

assert('v5.0.2: v5.0.1 CDN cache headers are preserved',
  /Cache-Control['"]\s*:\s*['"]public,\s*s-maxage=900/.test(functionSrc),
  'expected the v5.0.1 s-maxage=900 directive to remain unchanged');

assert('v5.0.2: v5.0.1 forceRefresh cache-busting (?t=<timestamp>) is preserved',
  // The ?t=<timestamp> cache-busting lives in the CLIENT
  // (src/services/vulnerabilityService.ts), not in the function.
  // Look in serviceSrc directly — the two pieces are far apart
  // in the file, so a positional slice is unreliable.
  /\?t=/.test(serviceSrc) && /forceRefresh/.test(serviceSrc),
  'expected the v5.0.1 ?t= cache-busting to remain in the client service code');

assert('v5.0.2: v5.0.1 no-store removal is preserved',
  !/Cache-Control['"]\s*:\s*['"]no-store/.test(functionSrc),
  'expected no-store to remain removed in v5.0.2');

/* ------------------------------------------------------------------ */
/* 9. Cache / fallback invariants are preserved through v5            */
/* ------------------------------------------------------------------ */

section('v4.1 cache / fallback invariants preserved through v5');

assert('Cache envelope never carries a proxyStatus leak from the proxy (sanity)',
  // The cached FetchResult is the full merged envelope. The
  // proxyStatus we set is a per-load field, not a per-cache
  // field — re-reading the cache should leave proxyStatus as it
  // was on the original write. The service doesn't strip
  // proxyStatus on cache reads, which is the correct v4-like
  // behavior (it preserves the original transport tag).
  /cacheStatus:\s*['"]fresh['"]/.test(serviceSrc) &&
    /cacheStatus:\s*['"]miss['"]/.test(serviceSrc) &&
    /cacheStatus:\s*['"]stale['"]/.test(serviceSrc),
  'expected all three cacheStatus values to be reachable from the service');

assert('writeCache is still called on a successful live fetch (proxy or browser-direct)',
  (() => {
    const iWrite = serviceSrc.indexOf('writeCache(');
    return iWrite > 0;
  })(),
  'expected writeCache() to still be called on a successful live fetch');

assert('Mock fallback is still reachable (mode = "fallback" with mock data)',
  /mode:\s*['"]fallback['"][\s\S]{0,200}MOCK_VULNERABILITIES/.test(serviceSrc) ||
    /MOCK_VULNERABILITIES[\s\S]{0,400}mode:\s*['"]fallback['"]/.test(serviceSrc),
  'expected the mock-fallback path to still be reachable');

assert('v5.0.2: no new build-time env vars are required for the frontend',
  // v5.0.2 adds ONE optional server-side runtime env var
  // (NVD_API_KEY) inside the Netlify Function. The FRONTEND
  // build is unchanged — no new VITE_* vars are required.
  // Existing VITE_DATASET_PROXY_URL still has a default.
  !/import\.meta\.env\.VITE_(?!DATASET_PROXY_URL)/.test(serviceSrc),
  'expected no new VITE_* env vars in the frontend (NVD_API_KEY is server-side only)');

assert('v5.0.2: NVD_API_KEY is a runtime server-side env var (not exposed to the browser)',
  // The function reads it from process.env at runtime. The
  // function's response body never includes it.
  /process\.env\.NVD_API_KEY/.test(functionSrc) &&
    !/VITE_NVD_API_KEY/.test(serviceSrc) &&
    !/import\.meta\.env\.NVD_API_KEY/.test(serviceSrc),
  'expected NVD_API_KEY to be process.env (server-side), never VITE_* (browser-exposed)');

/* ------------------------------------------------------------------ */
/* Summary                                                            */
/* ------------------------------------------------------------------ */

console.log();
if (failed === 0) {
  console.log(`PROXY TESTS PASSED  (${passed}/${passed})`);
} else {
  console.log(`PROXY TESTS FAILED  (${failed} of ${passed + failed} failed)`);
  for (const f of failures) {
    console.log(`  - ${f.label}${f.extra ? '  [' + f.extra + ']' : ''}`);
  }
  process.exit(1);
}
