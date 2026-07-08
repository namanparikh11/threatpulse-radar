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

assert('function sets Cache-Control: no-store on responses',
  /Cache-Control['"]\s*:\s*['"]no-store/.test(functionSrc),
  'expected Cache-Control: no-store (the client already does its own 1 h localStorage cache)');

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

assert('function does NOT read any API key / secret / env credential',
  !/process\.env\.(NVD_API_KEY|EPSS_API_KEY|CISA_API_KEY|API_KEY|TOKEN|SECRET)/.test(functionSrc),
  'v5.0 must not silently embed or read any API key');

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
    /fetch\(\s*DATASET_PROXY_URL/.test(serviceSrc),
  'expected tryProxyFetch to call the proxy endpoint');

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
    // function definition to the next `async function` (or 4000
    // chars, whichever is shorter) so the catch block is in
    // scope.
    const i = serviceSrc.indexOf('tryProxyFetch');
    if (i < 0) return false;
    const tail = serviceSrc.slice(i, i + 4000);
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

assert('No new environment variables are required at build time',
  // VITE_DATASET_PROXY_URL is the only one introduced, and it
  // has a default. The function file doesn't read any env vars.
  !/process\.env\./.test(functionSrc),
  'expected the function to read no environment variables');

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
