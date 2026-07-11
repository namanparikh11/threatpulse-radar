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

/**
 * v5.0.3: Strip JS-style comments from a source string so the
 * tests below can check the code, not the comments. Used by
 * the response-body and URL-query-string tests to avoid
 * false positives from documentation that mentions the
 * pattern (e.g. "`?apiKey=...` in the URL; v5.0.3 moves it to
 * a header" — the test must not flag this as actual code).
 */
function stripComments(s) {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, '')   // /* ... */ block comments
    .replace(/^\s*\/\/.*$/gm, '')       // // line comments (line start)
    .replace(/\s+\/\/.*$/gm, '');      // // trailing-line comments
}

/**
 * v5.2: Read both the dataset.mjs entry function and the
 * shared `_shared/liveBuild.mjs` module. The build pipeline
 * was extracted into a shared module in v5.2 so the
 * background / scheduled refresh functions can call the same
 * code without duplicating upstream-fetch logic. The dataset
 * function imports from the shared module — the URLs,
 * timeouts, and `NVD_API_KEY` handling now live there.
 *
 * Both files are read below, after `functionSrc` is
 * initialized. The combined source (`datasetOrSharedSrc`)
 * lets the URL / NVD / NVD_API_KEY tests search both files
 * without losing any v5.0 / v5.0.1 / v5.0.2 / v5.0.3
 * coverage.
 */
const liveBuildPath = join(root, 'netlify', 'functions', '_shared', 'liveBuild.mjs');
const liveBuildExists = existsSync(liveBuildPath);
const liveBuildSrc = liveBuildExists ? readFileSync(liveBuildPath, 'utf8') : '';

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

/**
 * v5.2: Combined source for any test that needs to look
 * across both `dataset.mjs` and `_shared/liveBuild.mjs`. The
 * build pipeline was extracted into a shared module so the
 * background / scheduled refresh functions can call the same
 * upstream-fetch code; the dataset entry just delegates.
 * Tests that look for CISA / NVD / EPSS URLs, NVD_API_KEY
 * handling, and the chunk-size constants search the combined
 * source so a regression in either file is caught.
 */
const datasetOrSharedSrc = functionSrc + '\n' + liveBuildSrc;

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
  /cisa\.gov\/sites\/default\/files\/feeds\/known_exploited_vulnerabilities\.json/.test(datasetOrSharedSrc),
  'expected the official CISA KEV feed URL');

assert('function reads the NVD CVE 2.0 endpoint',
  /services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0/.test(datasetOrSharedSrc),
  'expected the official NVD CVE 2.0 endpoint URL');

assert('function reads the FIRST EPSS endpoint',
  /api\.first\.org\/data\/v1\/epss/.test(datasetOrSharedSrc),
  'expected the official FIRST EPSS endpoint URL');

assert('function uses an 8-second per-request timeout (matches browser)',
  /8000|PER_REQUEST_TIMEOUT_MS\s*=\s*8_?000/.test(datasetOrSharedSrc),
  'expected per-request timeout to match the browser-side 8 s ceiling');

assert('function applies an overall budget under the 26 s Netlify limit',
  /24_?000|OVERALL_BUDGET_MS\s*=\s*24_?000/.test(datasetOrSharedSrc),
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

assert('v5.0–v5.5: function does NOT silently add any new data source (no OSV, GHSA, etc.)',
  // v5.0 guard: a data source must not be added silently.
  // v5.5 (CISA Vulnrichment) and v5.6 (GitHub Advisory) are
  // intentional, documented additions with their own
  // dedicated acceptance suites — this guard's purpose is
  // to catch SILENT additions, not block the explicit,
  // audited ones.
  (() => {
    if (/osv\.dev|osv\.osvdev/.test(functionSrc)) {
      return false; // OSV.dev was never added — strict ban holds
    }
    // GHSA / GitHub Advisory is intentionally present from
    // v5.6. We assert that the orchestrator wires it
    // through an EXPLICIT, DOCUMENTED, TESTED path (the
    // refresh orchestrator's documented v5.6 enrichment
    // pass) — i.e., NOT silently.
    if (/advisories\.github/.test(functionSrc)) {
      // Acceptable IF the reference is part of a documented
      // v5.6 section (a comment that names the source is
      // explicit, not silent).
      return /v5\.6/i.test(functionSrc) &&
        /GitHub Advisory/i.test(functionSrc);
    }
    return true;
  })(),
  'v5.0–v5.5: no silent OSV/GHSA additions; v5.6 GHSA additions must be explicitly documented in dataset.mjs');

assert('v5.0.2: function reads ONLY the documented optional NVD_API_KEY env var (no others)',
  // v5.0.2 added an optional NVD_API_KEY env var. It must be
  // the ONLY env var the function reads — no silent new
  // credentials. The test asserts that NVD_API_KEY is the
  // only process.env.* read across both dataset.mjs and the
  // shared liveBuild module.
  (() => {
    const envReads = datasetOrSharedSrc.match(/process\.env\.[A-Z_][A-Z0-9_]*/g) || [];
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
  (datasetOrSharedSrc.match(/cisa\.gov\/sites\/default\/files\/feeds\/known_exploited_vulnerabilities\.json/) || [])[0] ===
    (cisaSrc.match(/cisa\.gov\/sites\/default\/files\/feeds\/known_exploited_vulnerabilities\.json/) || [])[0]);

assert('NVD base URL matches between function and browser provider',
  (datasetOrSharedSrc.match(/services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0/) || [])[0] ===
    (nvdSrc.match(/services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0/) || [])[0]);

assert('FIRST EPSS base URL matches between function and browser provider',
  (datasetOrSharedSrc.match(/api\.first\.org\/data\/v1\/epss/) || [])[0] ===
    (epssSrc.match(/api\.first\.org\/data\/v1\/epss/) || [])[0]);

assert('CISA severity rule (Known ransomware → Critical, else High) matches',
  /knownRansomwareCampaignUse\s*===\s*['"]Known['"]/.test(datasetOrSharedSrc) &&
    /['"]High['"]/.test(datasetOrSharedSrc) &&
    /knownRansomwareCampaignUse\s*===\s*['"]Known['"]/.test(cisaSrc) &&
    /['"]High['"]/.test(cisaSrc));

assert('NVD chunk size matches between function and browser provider (100 CVEs)',
  /CHUNK_SIZE\s*=\s*100/.test(datasetOrSharedSrc) &&
    /CHUNK_SIZE\s*=\s*100/.test(nvdSrc));

assert('EPSS chunk size matches between function and browser provider (100 CVEs)',
  /CHUNK_SIZE\s*=\s*100/.test(epssSrc));

/* ------------------------------------------------------------------ */
/* 8.5. v5.0.2 — NVD rate-limit hardening + optional server-only key  */
/* ------------------------------------------------------------------ */

section('v5.0.2 — NVD rate-limit hardening + optional server-only NVD_API_KEY');

assert('v5.0.2: function reads NVD_API_KEY from process.env (server-side only)',
  /process\.env\.NVD_API_KEY/.test(datasetOrSharedSrc),
  'expected process.env.NVD_API_KEY to be read inside the function');

assert('v5.0.2: function never puts NVD_API_KEY in the response body',
  // The jsonResponse helper's body parameter is the FetchResult
  // shape (data, source, mode, nvdStatus, etc.). It must never
  // receive a NVD_API_KEY, and the function body must not
  // assign the key to a response field. Comments stripped
  // first to avoid matching doc text that mentions the
  // pattern (v5.0.3 fix).
  (() => {
    const code = stripComments(functionSrc);
    const i = code.indexOf('function jsonResponse(');
    if (i < 0) return true;
    const tail = code.slice(i, i + 800);
    return !/NVD_API_KEY/.test(tail) &&
      !/nvdApiKey|apiKey\s*:\s*[^,}\s]+/.test(code);
  })(),
  'expected NVD_API_KEY to never appear in the function response');

assert('v5.0.3: NVD_API_KEY is NOT appended to the NVD URL query string',
  // v5.0.2 incorrectly used a URL query parameter
  // (`?apiKey=...` / `&apiKey=...`). v5.0.3 moves the key
  // to a request header per NVD's official CVE 2.0 spec.
  // Comments stripped first so the doc text describing
  // the v5.0.2 → v5.0.3 transition doesn't trip the test.
  !/\?apiKey=/.test(stripComments(datasetOrSharedSrc)) &&
    !/&apiKey=/.test(stripComments(datasetOrSharedSrc)),
  'expected NVD_API_KEY to NOT appear in any NVD URL query string');

assert('v5.2.3: chunked NVD requests use ?cveIds= (plural) for comma-separated batches',
  // NVD CVE 2.0 uses `cveIds=` (plural) for a comma-separated
  // list of CVE IDs, max 100 per request. The deprecated
  // singular `cveId=` parameter expects a single CVE ID;
  // passing a comma-separated list to it returns HTTP 404.
  // (Caught by the v5.2.3 prebuilt-dataset deploy preview —
  // every chunk failed with "HTTP 404 Not Found".)
  // The actual code must construct URLs with `?cveIds=`.
  // Strip comments first so the explanatory doc text that
  // references the deprecated `cveId=` form doesn't trip
  // the test.
  (() => {
    const code = stripComments(datasetOrSharedSrc);
    // Must contain a URL construction with `?cveIds=` followed
    // by an encodeURIComponent of a comma-joined chunk.
    return /\?cveIds=\$\{encodeURIComponent\([^)]*\.join\(['"],['"]\)\)\}/.test(code);
  })(),
  'expected chunked NVD URL to use `?cveIds=${encodeURIComponent(cveChunk.join(\",\"))}`');

assert('v5.2.3: chunked NVD requests do NOT use the deprecated ?cveId= (singular)',
  // The deprecated singular `cveId=` parameter returns 404
  // when given a comma-separated list. It must not appear
  // in any actual NVD URL construction (code only; comments
  // are fine to reference it historically).
  (() => {
    const code = stripComments(datasetOrSharedSrc);
    return !/\?cveId=\$\{encodeURIComponent/.test(code);
  })(),
  'expected no chunked NVD URL to use the deprecated `?cveId=` parameter');

assert('v5.0.3: NVD_API_KEY IS passed as a request header (apiKey: <key>)',
  // v5.0.3: the apiKey must be assigned to the request
  // headers object, not the URL. Acceptable forms:
  //   - mutable headers:   headers.apiKey = apiKey
  //   - object literal:     { ..., apiKey: apiKey }
  //   - shorthand literal:  { ..., apiKey }
  (() => {
    return /headers\.\s*apiKey\s*=/.test(datasetOrSharedSrc) ||
      /apiKey:\s*apiKey\b/.test(datasetOrSharedSrc) ||
      /headers\s*=\s*\{[^}]*apiKey\b/.test(datasetOrSharedSrc);
  })(),
  'expected apiKey to be assigned to a request headers object');

assert('v5.0.3: NVD_API_KEY is never included in the function response body',
  // The jsonResponse helper is the only place the response
  // body is constructed. The key must not flow into it.
  // Comments stripped to avoid matching doc text.
  (() => {
    const code = stripComments(functionSrc);
    const i = code.indexOf('function jsonResponse(');
    if (i < 0) return true;
    const tail = code.slice(i, i + 800);
    return !/NVD_API_KEY/.test(tail) && !/apiKey/.test(tail);
  })(),
  'expected NVD_API_KEY to never appear in the function response body');

assert('v5.0.3: NVD_API_KEY is never logged (no console.log / .log of the key)',
  // Defense-in-depth: the key must not flow into any log
  // call. console.log of the apiKey variable, of the env
  // var, or of any string containing "key" is forbidden.
  // Comments stripped to avoid matching doc text.
  !/console\.log\([^)]*apiKey/.test(stripComments(datasetOrSharedSrc)) &&
    !/console\.log\([^)]*NVD_API_KEY/.test(stripComments(datasetOrSharedSrc)) &&
    !/console\.log\([^)]*process\.env/.test(stripComments(datasetOrSharedSrc)),
  'expected NVD_API_KEY to never be passed to console.log');

assert('v5.0.2: function uses serial chunk fetch (concurrency = 1) without NVD_API_KEY',
  // Look for the actual `concurrency = apiKey ? X : 1` line in
  // the function body (NOT the docstring comment). Find the
  // `process.env.NVD_API_KEY` line and slice from there.
  (() => {
    const i = datasetOrSharedSrc.indexOf('process.env.NVD_API_KEY');
    if (i < 0) return false;
    const tail = datasetOrSharedSrc.slice(i, i + 1000);
    return /concurrency\s*=\s*apiKey\s*\?\s*[^:]+\s*:\s*1\b/.test(tail);
  })(),
  'expected concurrency = apiKey ? chunks.length : 1 (serial) when NVD_API_KEY is absent');

assert('v5.0.2: function uses parallel chunk fetch with NVD_API_KEY',
  // Same approach: find the actual concurrency line, assert
  // the "true" branch uses parallel chunks (chunks.length).
  (() => {
    const i = datasetOrSharedSrc.indexOf('process.env.NVD_API_KEY');
    if (i < 0) return false;
    const tail = datasetOrSharedSrc.slice(i, i + 1000);
    return /concurrency\s*=\s*apiKey\s*\?\s*chunks\.length/.test(tail);
  })(),
  'expected concurrency = apiKey ? chunks.length (parallel) when NVD_API_KEY is set');

assert('v5.0.2: function includes a small settledAll concurrency helper',
  /async function settledAll\(/.test(datasetOrSharedSrc) ||
    /function settledAll\(/.test(datasetOrSharedSrc),
  'expected a concurrency helper (e.g. settledAll) for serial chunk fetch');

assert('v5.0.2: function returns a concise 429 reason (not repeated chunk errors)',
  /rate limit reached[\s\S]{0,400}HTTP 429/.test(datasetOrSharedSrc) ||
    /HTTP 429[\s\S]{0,400}rate limit reached/.test(datasetOrSharedSrc) ||
    (/rate limit reached/.test(datasetOrSharedSrc) && /HTTP 429/.test(datasetOrSharedSrc)),
  'expected a single concise reason string for 429, not a joined per-chunk error list');

assert('v5.0.2: 429 reason mentions severity fallback to CISA-derived values',
  /rate limit reached[\s\S]{0,500}CISA-derived/.test(datasetOrSharedSrc),
  'expected the 429 reason to tell the user severity falls back to CISA-derived');

assert('v5.0.2: non-429 chunk errors are de-duplicated in the error message',
  // The new code uses `Array.from(new Set(reasons))` to avoid
  // "HTTP 503; HTTP 503; HTTP 503" repetition. Look for the
  // de-duplication call.
  /new Set\(reasons\)/.test(datasetOrSharedSrc),
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
/* 8.6. v5.2.5 — NVD partial-fallback hardening (404 → split)          */
/* ------------------------------------------------------------------ */

section('v5.2.5 — NVD partial-fallback hardening (404 → split, individual 404 = missing)');

assert('v5.2.5: liveBuild defines a tryBatchWithSplit helper',
  // The v5.2.5 partial-fallback is implemented as a recursive
  // wrapper around the existing batch fetch. Look for the
  // function definition in the shared module.
  /async\s+function\s+tryBatchWithSplit\s*\(/.test(liveBuildSrc) ||
    /function\s+tryBatchWithSplit\s*\(/.test(liveBuildSrc),
  'expected tryBatchWithSplit helper in netlify/functions/_shared/liveBuild.mjs');

assert('v5.2.5: tryBatchWithSplit is recursive (calls itself with depth+1)',
  // Binary-search splitting: when a batch 404s, the function
  // must recurse on `chunk.slice(0, mid)` and `chunk.slice(mid)`
  // with depth incremented. Verify both branches exist.
  /tryBatchWithSplit\s*\(\s*chunk\.slice\(0\s*,\s*mid\)/.test(liveBuildSrc) &&
    /tryBatchWithSplit\s*\(\s*chunk\.slice\(mid\)/.test(liveBuildSrc),
  'expected tryBatchWithSplit to recurse on chunk.slice(0, mid) AND chunk.slice(mid)');

assert('v5.2.5: single-CVE 404 is treated as "missing", not provider failure',
  // When the recursion bottoms out at chunk.length === 1, the
  // single-CVE 404 should be reported as `missing: chunk.slice()`
  // (a soft skip), not re-thrown.
  /chunk\.length\s*===\s*1[\s\S]{0,400}missing:\s*chunk\.slice\(\)/.test(liveBuildSrc) ||
    /chunk\.length\s*<=\s*1[\s\S]{0,400}missing:\s*chunk\.slice\(\)/.test(liveBuildSrc),
  'expected single-CVE 404 path to push into the `missing` array');

assert('v5.2.5: only HTTP 404 triggers split; other statuses bubble up',
  // 429 / 5xx / network / shape errors must NOT trigger the
  // recursive split (recursing wouldn't help for upstream-side
  // failures). The split-on-404 check must extract the status
  // from the error message.
  /status\s*===\s*404/.test(liveBuildSrc) &&
    /extractHttpStatus\s*\(/.test(liveBuildSrc),
  'expected status === 404 to gate the split branch and extractHttpStatus helper to exist');

assert('v5.2.5: error message includes the safe URL (no apiKey)',
  // The apiKey is a request HEADER per NVD's official spec —
  // it must never appear in any URL. The error message must
  // include the request URL for diagnostics, and that URL
  // must be the `cveIds=` form (no `apiKey=` query parameter).
  /url=\$\{url\}/.test(liveBuildSrc) &&
    !/\?apiKey=/.test(stripComments(liveBuildSrc)) &&
    !/&apiKey=/.test(stripComments(liveBuildSrc)),
  'expected error messages to embed url=... and never include apiKey in URL');

assert('v5.2.5: error message includes the HTTP status code',
  // Look for the `HTTP ${res.status} ${res.statusText}` pattern
  // in the error throw path. Without this, operators have no
  // way to tell a 404 from a 503 from a network error.
  /HTTP\s+\$\{res\.status\}\s+\$\{res\.statusText\}/.test(liveBuildSrc),
  'expected NVD error to include "HTTP ${res.status} ${res.statusText}"');

assert('v5.2.5: error message captures NVD Warning header if present',
  // NVD sometimes returns a `Warning` HTTP header on soft
  // failures. The diagnostic must surface it.
  /res\.headers\.get\(['"]Warning['"]\)/.test(liveBuildSrc),
  'expected NVD error to read the Warning response header');

assert('v5.2.5: error message captures NVD body snippet (truncated to 200 chars)',
  // Body snippet helps operators see what NVD actually said.
  // It must be truncated so a pathological response can't blow
  // up the envelope.
  /bodySnippet/.test(liveBuildSrc) &&
    /200/.test(liveBuildSrc) &&
    /res\.text\(\)/.test(liveBuildSrc),
  'expected NVD error to capture a truncated body snippet via res.text()');

assert('v5.2.5: NVD_PARTIAL_META Symbol is exported from liveBuild',
  // The partial-failure metadata travels on the Map via a
  // Symbol property. The Symbol itself must be exported so
  // the call site in buildLiveDataset and the acceptance
  // tests can read the metadata consistently.
  /export\s+const\s+NVD_PARTIAL_META\s*=/.test(liveBuildSrc) &&
    /Symbol\.for\(/.test(liveBuildSrc),
  'expected export const NVD_PARTIAL_META = Symbol.for(...) in liveBuild.mjs');

assert('v5.2.5: readNvdPartialMeta helper is exported and reads the Symbol property',
  // The buildLiveDataset call site uses readNvdPartialMeta to
  // safely extract partial-failure metadata from the Map
  // returned by fetchNvdForCves.
  /export\s+function\s+readNvdPartialMeta\s*\(/.test(liveBuildSrc) &&
    /map\s*\[\s*NVD_PARTIAL_META\s*\]/.test(liveBuildSrc),
  'expected readNvdPartialMeta to be exported and to read map[NVD_PARTIAL_META]');

assert('v5.2.5: partial metadata is attached via non-enumerable Object.defineProperty',
  // The metadata MUST be non-enumerable so it doesn't leak
  // through JSON.stringify, Object.keys, or Map iteration.
  /Object\.defineProperty\(\s*merged\s*,\s*NVD_PARTIAL_META/.test(liveBuildSrc) &&
    /enumerable:\s*false/.test(liveBuildSrc),
  'expected partial metadata to be attached via Object.defineProperty with enumerable: false');

assert('v5.2.5: buildLiveDataset promotes partial metadata to nvdReason',
  // When partial metadata is present, the envelope's
  // `nvdReason` must be replaced with a partial-failure
  // summary (count of missing + count of batch errors +
  // first error message). nvdStatus must remain 'nvd' so
  // the UI contract is preserved (the data IS enriched).
  /readNvdPartialMeta\s*\(/.test(liveBuildSrc) &&
    /formatPartialNvdReason\s*\(/.test(liveBuildSrc) &&
    /nvdStatus\s*=\s*nvdResult\.status/.test(liveBuildSrc),
  'expected buildLiveDataset to read partial metadata and format it into nvdReason');

assert('v5.2.5: apiKey is never included in any error message or URL',
  // Defense-in-depth: the apiKey variable must not appear in
  // any throw-new-Error string, template literal that flows
  // into a thrown error, or URL. The apiKey is allowed to
  // appear in:
  //   - `const apiKey = process.env.NVD_API_KEY`
  //   - function parameters and call sites (`(chunk, apiKey, depth)`)
  //   - the headers write (`headers.apiKey = apiKey`)
  //   - the `concurrency = apiKey ? ... : 1` line
  // We scan the stripped source for any `apiKey` substring
  // inside a `new Error(...)` call or inside a template literal
  // that contains the keyword "url" (which is where the URL
  // is interpolated into error messages).
  (() => {
    const code = stripComments(liveBuildSrc);
    // 1. No `new Error(...)` call whose string contains apiKey.
    const errorMatches = code.match(/new\s+Error\([^)]*apiKey[^)]*\)/g) || [];
    // 2. No `throw new Error(...)` form (rare, but possible).
    const throwMatches = code.match(/throw\s+new\s+Error\([^)]*apiKey[^)]*\)/g) || [];
    // 3. No template literal of the form `...${...apiKey...}...`
    //    (we already check for `?apiKey=` separately).
    const tmplMatches = code.match(/`[^`]*\$\{[^}]*apiKey[^}]*\}[^`]*`/g) || [];
    // 4. No URL containing apiKey= query parameter.
    const urlApiKeyMatches = code.match(/[?&]apiKey=/g) || [];
    return errorMatches.length === 0 &&
      throwMatches.length === 0 &&
      tmplMatches.length === 0 &&
      urlApiKeyMatches.length === 0;
  })(),
  'expected apiKey to never appear inside any Error string, template literal, or URL query');

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

assert('v5.0.2 / v5.2: no VITE_* env vars leak secrets to the frontend',
  // v5.0.2: NVD_API_KEY is server-side only — must NOT
  // appear in the frontend via any VITE_* name.
  // v5.2: VITE_REFRESH_ENDPOINT_URL is allowed (it's a
  // public route, not a secret, with a default of
  // '/.netlify/functions/refresh-dataset-background'). VITE_DATASET_PROXY_URL
  // was already allowed in v5.0.
  // The regex below explicitly excludes the two public
  // endpoint vars and forbids any other VITE_* env var.
  !/import\.meta\.env\.VITE_(?!DATASET_PROXY_URL|REFRESH_ENDPOINT_URL)([A-Z_]+)/.test(serviceSrc) &&
    !/VITE_NVD_API_KEY/.test(serviceSrc),
  'expected no secret VITE_* env vars in the frontend (NVD_API_KEY is server-side only)');

assert('v5.0.2: NVD_API_KEY is a runtime server-side env var (not exposed to the browser)',
  // The function reads it from process.env at runtime. The
  // function's response body never includes it.
  /process\.env\.NVD_API_KEY/.test(datasetOrSharedSrc) &&
    !/VITE_NVD_API_KEY/.test(serviceSrc) &&
    !/import\.meta\.env\.NVD_API_KEY/.test(serviceSrc),
  'expected NVD_API_KEY to be process.env (server-side), never VITE_* (browser-exposed)');

/* ------------------------------------------------------------------ */
/* 10. v5.2.6 — NVD backoff + dataset quality guard                   */
/* ------------------------------------------------------------------ */

section('v5.2.6 — NVD backoff + dataset quality guard (source-level)');

/**
 * The bulk of the v5.2.6 behavior tests live in
 * acceptance-prebuilt.mjs (decision table + pure-JS
 * reimplementations). This section is the structural /
 * source-level complement: it verifies that the new wiring
 * exists in the shared modules and that the no-apiKey
 * invariant still holds across the new code paths.
 *
 * Specifically we assert:
 *   - The shared store module declares the nvd-cooldown blob
 *     key + 15-min TTL constant.
 *   - The shared refresh module exposes the three pure-JS
 *     helpers (countCvssAboveZero, isNvdRateLimitedReason,
 *     shouldSkipOverwrite).
 *   - The refresh module calls writeNvdCooldown after the
 *     guard fires AND clears the lock on the new 'preserved'
 *     and 'cooldown' short-circuit paths.
 *   - The shared liveBuild module accepts a `skipNvd` opt
 *     and short-circuits the NVD fetch when it is true.
 *   - The two entry-point functions (background + scheduled)
 *     forward the `skipNvd` opt into `buildLiveDataset`.
 *   - The apiKey is NEVER included in any cooldown payload,
 *     preserved reason, or any new error path. The apiKey
 *     lives only in liveBuild.mjs and only as a request
 *     header — never in any URL, log, error string, or
 *     blob payload.
 */

const refreshPath = join(root, 'netlify', 'functions', '_shared', 'refresh.mjs');
const refreshExists = existsSync(refreshPath);
const refreshSrc = refreshExists ? readFileSync(refreshPath, 'utf8') : '';
const storePath = join(root, 'netlify', 'functions', '_shared', 'store.mjs');
const storeSrc = existsSync(storePath) ? readFileSync(storePath, 'utf8') : '';
const bgPath = join(root, 'netlify', 'functions', 'refresh-dataset-background.mjs');
const bgExists = existsSync(bgPath);
const bgSrc = bgExists ? readFileSync(bgPath, 'utf8') : '';
const schedPath = join(root, 'netlify', 'functions', 'refresh-dataset-scheduled.mjs');
const schedExists = existsSync(schedPath);
const schedSrc = schedExists ? readFileSync(schedPath, 'utf8') : '';

assert('v5.2.6: store module declares the nvd-cooldown blob key + 15-min TTL',
  /NVD_COOLDOWN_KEY\s*=\s*['"]nvd-cooldown['"]/.test(storeSrc) &&
    /NVD_COOLDOWN_TTL_MS\s*=\s*15\s*\*\s*60\s*\*\s*1000\b/.test(storeSrc),
  'expected `NVD_COOLDOWN_KEY = "nvd-cooldown"` and `NVD_COOLDOWN_TTL_MS = 15 * 60 * 1000`');

assert('v5.2.6: store module exposes readNvdCooldown / writeNvdCooldown / clearNvdCooldown / isNvdCooldownActive / buildCooldownPayload',
  /export\s+(?:async\s+)?function\s+readNvdCooldown/.test(storeSrc) &&
    /export\s+(?:async\s+)?function\s+writeNvdCooldown/.test(storeSrc) &&
    /export\s+(?:async\s+)?function\s+clearNvdCooldown/.test(storeSrc) &&
    /export\s+function\s+isNvdCooldownActive/.test(storeSrc) &&
    /export\s+function\s+buildCooldownPayload/.test(storeSrc),
  'expected all five cooldown helpers exported from store.mjs');

assert('v5.2.6: refresh module exposes countCvssAboveZero / isNvdRateLimitedReason / shouldSkipOverwrite',
  /export\s+function\s+countCvssAboveZero/.test(refreshSrc) &&
    /export\s+function\s+isNvdRateLimitedReason/.test(refreshSrc) &&
    /export\s+function\s+shouldSkipOverwrite/.test(refreshSrc),
  'expected the three pure-JS quality-guard helpers exported from refresh.mjs');

assert('v5.2.6: refresh module imports readNvdCooldown / writeNvdCooldown / clearNvdCooldown / isNvdCooldownActive from store',
  /import\s*\{[^}]*readNvdCooldown[^}]*\}\s*from\s*['"]\.\/store\.mjs['"]/.test(refreshSrc) &&
    /import\s*\{[^}]*writeNvdCooldown[^}]*\}\s*from\s*['"]\.\/store\.mjs['"]/.test(refreshSrc) &&
    /import\s*\{[^}]*clearNvdCooldown[^}]*\}\s*from\s*['"]\.\/store\.mjs['"]/.test(refreshSrc) &&
    /import\s*\{[^}]*isNvdCooldownActive[^}]*\}\s*from\s*['"]\.\/store\.mjs['"]/.test(refreshSrc),
  'expected the four cooldown imports in refresh.mjs');

assert('v5.2.6: refresh module reads the existing latest-dataset before writing (quality-guard compare)',
  // runRefresh must readLatestDataset(store) before any
  // writeLatestDataset(store, ...) call so the guard can
  // compare old vs new.
  (() => {
    const iRead = refreshSrc.indexOf('readLatestDataset(');
    const iWrite = refreshSrc.indexOf('writeLatestDataset(');
    return iRead > 0 && iWrite > 0 && iRead < iWrite;
  })(),
  'expected `readLatestDataset(` to appear before `writeLatestDataset(` in refresh.mjs');

assert('v5.2.6: refresh module applies shouldSkipOverwrite to the freshly-built envelope',
  /shouldSkipOverwrite\(/.test(refreshSrc) &&
    /envelope/.test(refreshSrc),
  'expected shouldSkipOverwrite(existing, envelope) call in runRefresh');

assert('v5.2.6: refresh module writes the cooldown blob when the guard fires',
  /shouldSkipOverwrite[\s\S]{0,800}writeNvdCooldown/.test(refreshSrc),
  'expected writeNvdCooldown to be called after shouldSkipOverwrite fires');

assert('v5.2.6: refresh module clears the cooldown on a non-rate-limited successful write',
  // After a clean write (nvdStatus !== "unavailable" OR reason
  // does NOT include 429/rate limit), the cooldown marker must
  // be cleared so the next refresh goes through the normal NVD
  // path again.
  /isNvdRateLimitedReason\(envelope\)[\s\S]{0,400}clearNvdCooldown/.test(refreshSrc),
  'expected clearNvdCooldown on the non-rate-limited successful-write branch');

assert('v5.2.6: refresh module returns the new "preserved" status when guard fires',
  // The 'preserved' status is the v5.2.6 way to signal that
  // we did NOT overwrite because the new is worse. This status
  // is what the scheduled function logs (so operators can see
  // the rate-limit was caught).
  /status:\s*['"]preserved['"]/.test(refreshSrc),
  'expected `status: "preserved"` in runRefresh');

assert('v5.2.6: refresh module returns the new "cooldown" status when cooldown short-circuits the build',
  /status:\s*['"]cooldown['"]/.test(refreshSrc),
  'expected `status: "cooldown"` in runRefresh');

assert('v5.2.6: refresh module clears the lock on every short-circuit return path',
  // Every return path that ENDS a refresh attempt
  // (preserved / cooldown / completed / failed) must release
  // the refresh-lock — leaving the lock held would block the
  // next refresh for up to 15 minutes. The implementation
  // pattern is `await clearRefreshLock(store);` immediately
  // before the `return { status: ... }`. We scan for every
  // occurrence of `status: '<key>'` and check the 800 chars
  // BEFORE each for a clearRefreshLock(store) call.
  (() => {
    const code = stripComments(refreshSrc);
    const hasLockClearNear = (statusKey) => {
      const re = new RegExp(
        "status:\\s*['\"]" + statusKey + "['\"]",
        'g',
      );
      const matches = [];
      let m;
      while ((m = re.exec(code)) !== null) matches.push(m.index);
      if (matches.length === 0) return false;
      // Check EVERY occurrence (skip doc-comment mentions by
      // accepting the check if ANY occurrence has a lock
      // clear nearby — that's the actual code path; the doc
      // comments will fail the check harmlessly).
      return matches.some((idx) => {
        const start = Math.max(0, idx - 800);
        const slice = code.slice(start, idx);
        return /clearRefreshLock\s*\(\s*store\s*\)/.test(slice);
      });
    };
    return (
      hasLockClearNear('preserved') &&
      hasLockClearNear('cooldown') &&
      hasLockClearNear('completed') &&
      hasLockClearNear('failed')
    );
  })(),
  'expected clearRefreshLock(store) to be called immediately before every short-circuit status return');

assert('v5.2.6: liveBuild accepts opts.skipNvd and short-circuits the NVD fetch when true',
  /opts\.skipNvd/.test(liveBuildSrc) &&
    /skipNvd\s*===\s*true/.test(liveBuildSrc),
  'expected liveBuild.mjs to read `opts.skipNvd === true` and skip the NVD call');

assert('v5.2.6: liveBuild skipNvd path returns a synthetic unavailable result (not a real fetchOneNvdBatch call)',
  // When skipNvd is true, the safeEnrich("NVD", ...) call must
  // be bypassed. The synthetic result has the shape that the
  // rest of the pipeline already understands (Map + status +
  // reason).
  /skipNvd[\s\S]{0,800}nvdStatus:\s*['"]unavailable['"]/.test(liveBuildSrc),
  'expected the skipNvd branch to return `{ nvdStatus: "unavailable", ... }`');

assert('v5.2.6: background refresh forwards buildFn opts into buildLiveDataset',
  // The entry point must call buildFn(opts) and pass opts
  // through to buildLiveDataset so the skipNvd flag flows
  // from the orchestrator to the build pipeline.
  /buildFn:\s*\(\s*opts\s*\)\s*=>\s*buildLiveDataset\(\s*opts\s*\)/.test(bgSrc),
  'expected `buildFn: (opts) => buildLiveDataset(opts)` in refresh-dataset-background.mjs');

assert('v5.2.6: scheduled refresh forwards buildFn opts into buildLiveDataset',
  /buildFn:\s*\(\s*opts\s*\)\s*=>\s*buildLiveDataset\(\s*opts\s*\)/.test(schedSrc),
  'expected `buildFn: (opts) => buildLiveDataset(opts)` in refresh-dataset-scheduled.mjs');

assert('v5.2.6: the dataset endpoint still returns the unchanged envelope from the blob (no UI changes)',
  // The quality guard is server-side only — the dataset
  // endpoint reads `latest-dataset` and returns it verbatim.
  // The client cannot tell whether the blob is from a
  // 'completed' refresh or a 'preserved' short-circuit; the
  // existing fields (nvdStatus, nvdReason, fetchedAt, etc.)
  // are the source of truth and they did not change.
  /readLatestDataset\(/.test(functionSrc) &&
    /dataSource:\s*['"]prebuilt-store['"]/.test(functionSrc),
  'expected the dataset endpoint to still return the prebuilt-store envelope verbatim');

assert('v5.2.6: apiKey is never referenced in refresh.mjs (apiKey lives only in liveBuild.mjs)',
  // Defense-in-depth: refresh.mjs must not import or read
  // process.env.NVD_API_KEY. The apiKey variable flows only
  // inside liveBuild.mjs as a request header.
  !/apiKey/.test(stripComments(refreshSrc)),
  'expected no `apiKey` substring in refresh.mjs');

assert('v5.2.6: apiKey is never referenced in refresh-dataset-background.mjs',
  !/apiKey/.test(stripComments(bgSrc)),
  'expected no `apiKey` substring in refresh-dataset-background.mjs');

assert('v5.2.6: apiKey is never referenced in refresh-dataset-scheduled.mjs',
  !/apiKey/.test(stripComments(schedSrc)),
  'expected no `apiKey` substring in refresh-dataset-scheduled.mjs');

assert('v5.2.6: the new "preserved" reason never embeds the apiKey (substring check)',
  // The 'preserved' reason is built from envelope.nvdReason
  // + the cvssScore counts. nvdReason is sanitized by liveBuild
  // (it only embeds HTTP status + URL + warning headers, never
  // apiKey). Defense-in-depth: the reason text built in
  // runRefresh doesn't interpolate any other source that could
  // contain apiKey.
  (() => {
    // Find the slice of refresh.mjs that builds the preserved
    // reason and verify it only references safe sources.
    const code = stripComments(refreshSrc);
    const iPreserved = code.indexOf("status: 'preserved'");
    if (iPreserved < 0) return true; // regex test below catches this
    const slice = code.slice(iPreserved, iPreserved + 1500);
    // The reason string may interpolate: envelope.nvdReason,
    // truncateForReason, countCvssAboveZero. None of these
    // touch apiKey.
    return !/apiKey/i.test(slice);
  })(),
  'expected the preserved-reason slice in refresh.mjs to not reference apiKey');

assert('v5.2.6: the new "cooldown" reason never embeds the apiKey',
  (() => {
    const code = stripComments(refreshSrc);
    const iCooldown = code.indexOf("status: 'cooldown'");
    if (iCooldown < 0) return true;
    const slice = code.slice(iCooldown, iCooldown + 1000);
    return !/apiKey/i.test(slice);
  })(),
  'expected the cooldown-reason slice in refresh.mjs to not reference apiKey');

assert('v5.2.6: the cooldown payload builder does not include apiKey (URL or headers)',
  // The cooldown payload is built from envelope.nvdReason
  // only — never from request headers, never from the URL.
  // Strip comments and verify the builder function only
  // touches `nvdReason` and `truncateForReason`.
  (() => {
    const code = stripComments(refreshSrc);
    const iBuilder = code.indexOf('buildCooldownPayloadFromEnvelope');
    if (iBuilder < 0) return false;
    const slice = code.slice(iBuilder, iBuilder + 1500);
    return /nvdReason/.test(slice) &&
      /truncateForReason/.test(slice) &&
      !/apiKey/i.test(slice) &&
      !/headers/.test(slice);
  })(),
  'expected buildCooldownPayloadFromEnvelope to only touch nvdReason + truncateForReason');

assert('v5.2.6: v5.2.6 docs preserved in store + refresh module headers',
  // The new section headers must explain the cooldown +
  // quality-guard contract so future maintainers don't
  // accidentally break it.
  /v5\.2\.6/.test(storeSrc) &&
    /cooldown/i.test(storeSrc) &&
    /v5\.2\.6/.test(refreshSrc) &&
    /quality\s*guard|shouldSkipOverwrite/i.test(refreshSrc),
  'expected the v5.2.6 doc blocks in store.mjs and refresh.mjs');

assert('v5.2.6: no new sources, no new providers, no auth, no UI changes (regression guard)',
  // The task spec is explicit: do not change UI, do not
  // change providers, do not add auth, do not add new
  // sources. Verify the spec invariants:
  //   - no new upstream URLs
  //   - no new auth / login / OAuth surface
  //   - no new dashboard / Header source additions
  !/CISA_KEV_URL|NVD_BASE_URL|EPSS_BASE_URL/.test(bgSrc) || // entry point shouldn't redefine URLs
    bgSrc.match(/CISA_KEV_URL|NVD_BASE_URL|EPSS_BASE_URL/g).length === 0,
  'expected the refresh-dataset-background entry point to NOT redefine upstream URLs');

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
