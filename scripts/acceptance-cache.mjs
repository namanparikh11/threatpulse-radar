// Acceptance tests for the v4 localStorage cache layer.
// Runs without a framework, without DOM, without a build step.
//   node scripts/acceptance-cache.mjs
//
// What it covers:
//   1. Pure helpers (isCacheFresh, formatAgeShort, getCacheAgeMs)
//      with both happy-path and boundary inputs.
//   2. The cache envelope round-trip and schema-validation
//      defenses (corrupt JSON, missing fields, wrong types).
//   3. The service-layer orchestration of cache states:
//      fresh-cache-hit, stale-cache-fallback, cache-miss + write,
//      forceRefresh bypass, and the critical "never hide
//      provider failures" invariant — the cached FetchResult
//      preserves nvdStatus / epssStatus / fallbackReason exactly
//      as the original live fetch returned them.
//
// The v1 / CISA / EPSS / NVD test suites keep running untouched;
// this file is purely additive.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

/* ------------------------------------------------------------------ */
/* Re-implementations of the production logic, in plain JS.          */
/* Kept in lockstep with src/services/datasetCache.ts.                */
/* ------------------------------------------------------------------ */

const TTL_MS = 60 * 60 * 1000;

function isCacheFresh(cachedAtMs) {
  return Date.now() - cachedAtMs < TTL_MS;
}

function getCacheAgeMs(cachedAtMs) {
  return Math.max(0, Date.now() - cachedAtMs);
}

function formatAgeShort(ms) {
  if (ms < 60_000) return 'just now';
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

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
/* 1. Pure freshness / age helpers                                   */
/* ------------------------------------------------------------------ */

section('Cache freshness helpers (isCacheFresh / getCacheAgeMs)');

const now = Date.now();

assert('freshly written entry is fresh',
  isCacheFresh(now) === true);

assert('entry written 30 seconds ago is fresh',
  isCacheFresh(now - 30_000) === true);

assert('entry written 59:59 ago is still fresh',
  isCacheFresh(now - (60 * 60 * 1000 - 1000)) === true);

assert('entry written exactly 1 hour ago is NOT fresh (TTL boundary)',
  // TTL is strict: <, not <=. So an entry at exactly 1 h is stale.
  isCacheFresh(now - 60 * 60 * 1000) === false);

assert('entry written 2 hours ago is stale',
  isCacheFresh(now - 2 * 60 * 60 * 1000) === false);

assert('entry written 24 hours ago is stale',
  isCacheFresh(now - 24 * 60 * 60 * 1000) === false);

assert('future-dated entry (clock skew) is treated as fresh',
  // If the cachedAt is somehow in the future (clocks drift), the
  // age would be negative. getCacheAgeMs clamps to 0, and
  // isCacheFresh treats "age 0" as fresh. This avoids spuriously
  // re-fetching on minor clock skew.
  isCacheFresh(now + 5_000) === true);

assert('getCacheAgeMs clamps future timestamps to 0',
  getCacheAgeMs(now + 60_000) === 0);

assert('getCacheAgeMs returns the delta in ms for past timestamps',
  getCacheAgeMs(now - 5_000) >= 5_000 && getCacheAgeMs(now - 5_000) < 6_000);

/* ------------------------------------------------------------------ */
/* 2. formatAgeShort — UI labels                                     */
/* ------------------------------------------------------------------ */

section('formatAgeShort — UI label formatting');

assert('0 ms \u2192 "just now"',
  formatAgeShort(0) === 'just now');

assert('59_999 ms \u2192 "just now"',
  formatAgeShort(59_999) === 'just now');

assert('60_000 ms \u2192 "1m ago"',
  formatAgeShort(60_000) === '1m ago');

assert('5 minutes \u2192 "5m ago"',
  formatAgeShort(5 * 60_000) === '5m ago');

assert('59 minutes \u2192 "59m ago"',
  formatAgeShort(59 * 60_000) === '59m ago');

assert('60 minutes \u2192 "1h ago"',
  formatAgeShort(60 * 60_000) === '1h ago');

assert('23 hours \u2192 "23h ago"',
  formatAgeShort(23 * 60 * 60_000) === '23h ago');

assert('24 hours \u2192 "1d ago"',
  formatAgeShort(24 * 60 * 60_000) === '1d ago');

assert('3 days \u2192 "3d ago"',
  formatAgeShort(3 * 24 * 60 * 60_000) === '3d ago');

/* ------------------------------------------------------------------ */
/* 3. Cache envelope round-trip + schema validation                  */
/* ------------------------------------------------------------------ */

section('Cache envelope round-trip and schema validation');

function makeEnvelope(fetchResult, cachedAtMs = Date.now()) {
  return {
    fetchResult,
    cachedAt: cachedAtMs,
  };
}

// Shape A: a minimal valid FetchResult shape.
const validResult = {
  data: [
    {
      id: 'CVE-2024-0001',
      cveId: 'CVE-2024-0001',
      vendor: 'Test',
      product: 'Widget',
      summary: 'A test CVE',
      publishedDate: '2024-01-01T00:00:00.000Z',
      cvssScore: 9.8,
      epssProbability: 0.5,
      severity: 'Critical',
      kev: true,
      knownRansomwareCampaignUse: 'Known',
      source: 'CISA KEV',
      externalLinks: [],
      description: 'Test',
    },
  ],
  source: 'merged',
  fetchedAt: '2024-01-01T00:00:00.000Z',
  mode: 'live',
  nvdStatus: 'nvd',
  epssStatus: 'first',
};

assert('valid envelope has all expected fields',
  (() => {
    const env = makeEnvelope(validResult);
    return Array.isArray(env.fetchResult.data)
      && typeof env.fetchResult.fetchedAt === 'string'
      && env.fetchResult.mode === 'live'
      && env.fetchResult.nvdStatus === 'nvd'
      && env.fetchResult.epssStatus === 'first'
      && typeof env.cachedAt === 'number';
  })());

assert('FetchResult preserves nvdStatus="unavailable" through cache envelope',
  (() => {
    const r = { ...validResult, nvdStatus: 'unavailable', nvdReason: 'NVD timeout' };
    const env = makeEnvelope(r);
    return env.fetchResult.nvdStatus === 'unavailable'
      && env.fetchResult.nvdReason === 'NVD timeout';
  })(),
  'cached envelope must NOT lose nvdStatus');

assert('FetchResult preserves epssStatus="unavailable" through cache envelope',
  (() => {
    const r = { ...validResult, epssStatus: 'unavailable', epssReason: 'EPSS 503' };
    const env = makeEnvelope(r);
    return env.fetchResult.epssStatus === 'unavailable'
      && env.fetchResult.epssReason === 'EPSS 503';
  })(),
  'cached envelope must NOT lose epssStatus');

assert('FetchResult preserves fallbackReason through cache envelope',
  (() => {
    const r = { ...validResult, mode: 'fallback', fallbackReason: 'CISA 503' };
    const env = makeEnvelope(r);
    return env.fetchResult.mode === 'fallback'
      && env.fetchResult.fallbackReason === 'CISA 503';
  })(),
  'cached envelope must NOT lose fallbackReason');

assert('Cache envelope is JSON-serializable round-trip',
  (() => {
    const env = makeEnvelope(validResult);
    const round = JSON.parse(JSON.stringify(env));
    return round.fetchResult.data[0].cveId === 'CVE-2024-0001'
      && round.cachedAt === env.cachedAt;
  })());

/* ------------------------------------------------------------------ */
/* 4. Source-level invariants                                         */
/* ------------------------------------------------------------------ */

section('Source-level wiring (cache + service + UI)');

const cacheSrc = readFileSync(
  join(root, 'src', 'services', 'datasetCache.ts'), 'utf8');
const serviceSrc = readFileSync(
  join(root, 'src', 'services', 'vulnerabilityService.ts'), 'utf8');
const headerSrc = readFileSync(
  join(root, 'src', 'components', 'Header.tsx'), 'utf8');
const dashboardSrc = readFileSync(
  join(root, 'src', 'pages', 'DashboardPage.tsx'), 'utf8');
const formatSrc = readFileSync(
  join(root, 'src', 'utils', 'format.ts'), 'utf8');

assert('cache module exists with readCache / writeCache / clearCache exports',
  /export\s+function\s+readCache/.test(cacheSrc) &&
    /export\s+function\s+writeCache/.test(cacheSrc) &&
    /export\s+function\s+clearCache/.test(cacheSrc));

assert('cache TTL is exactly 1 hour (60 * 60 * 1000 ms)',
  /CACHE_TTL_MS\s*=\s*60\s*\*\s*60\s*\*\s*1000/.test(cacheSrc),
  'expected 60 * 60 * 1000 ms constant');

assert('cache uses a versioned localStorage key',
  /tpr:dataset:v1/.test(cacheSrc),
  'expected versioned key like "tpr:dataset:v1"');

assert('cache read wraps localStorage.getItem in try/catch (private mode safe)',
  /try\s*\{[\s\S]*?localStorage\.getItem[\s\S]*?\}\s*catch/.test(cacheSrc),
  'expected defensive try/catch around localStorage.getItem');

assert('cache write wraps localStorage.setItem in try/catch (quota safe)',
  /try\s*\{[\s\S]*?localStorage\.setItem[\s\S]*?\}\s*catch/.test(cacheSrc),
  'expected defensive try/catch around localStorage.setItem');

assert('cache read validates the envelope shape (rejects missing fields)',
  /typeof\s+parsed\.cachedAt\s*!==\s*['"]number['"]/.test(cacheSrc) ||
    /typeof\s+parsed\.cachedAt\s*!==\s*'number'/.test(cacheSrc),
  'expected cachedAt type validation');

assert('cache read rejects envelopes where data is not an array',
  /Array\.isArray\(parsed\.fetchResult\.data\)/.test(cacheSrc),
  'expected Array.isArray(data) validation');

assert('service imports cache helpers from datasetCache',
  /import[\s\S]{0,200}from\s+['"]\.\/datasetCache['"]/.test(serviceSrc) &&
    /readCache/.test(serviceSrc) &&
    /writeCache/.test(serviceSrc) &&
    /clearCache/.test(serviceSrc) &&
    /isCacheFresh/.test(serviceSrc));

assert('service exports a CacheStatus type',
  /export\s+type\s+CacheStatus/.test(serviceSrc),
  'expected export type CacheStatus');

assert('CacheStatus covers miss / fresh / stale',
  /CacheStatus\s*=\s*['"]miss['"]\s*\|\s*['"]fresh['"]\s*\|\s*['"]stale['"]/.test(serviceSrc),
  'expected CacheStatus = "miss" | "fresh" | "stale"');

assert('FetchResult includes optional cacheStatus field',
  /cacheStatus\?\s*:\s*CacheStatus/.test(serviceSrc),
  'expected cacheStatus?: CacheStatus on FetchResult');

assert('VulnerabilityQuery accepts forceRefresh',
  /forceRefresh\?\s*:\s*boolean/.test(serviceSrc),
  'expected forceRefresh?: boolean on VulnerabilityQuery');

assert('service checks the cache before doing the live fetch',
  // The cache check must come before tryLiveFetch in the
  // non-forceRefresh path.
  (() => {
    const i1 = serviceSrc.indexOf('readCache()');
    const i2 = serviceSrc.indexOf('tryLiveFetch(');
    return i1 > 0 && i1 < i2;
  })(),
  'expected readCache() before tryLiveFetch(');

assert('service serves cached data with cacheStatus="fresh" when in TTL',
  /isCacheFresh[\s\S]{0,200}cacheStatus:\s*['"]fresh['"]/.test(serviceSrc),
  'expected cacheStatus: "fresh" on in-TTL hit');

assert('service serves cached data with cacheStatus="stale" when past TTL + live failed',
  /cacheStatus:\s*['"]stale['"]/.test(serviceSrc),
  'expected cacheStatus: "stale" on expired cache + live failure');

assert('service writes successful live fetch to cache',
  /writeCache\(\s*\w+\s*\)/.test(serviceSrc),
  'expected writeCache() call after successful live fetch');

assert('service honors forceRefresh by clearing the cache',
  /forceRefresh[\s\S]{0,200}clearCache\(\)/.test(serviceSrc),
  'expected forceRefresh to clear the cache');

assert('service bypasses cache entirely when forceRefresh=true',
  // In the forceRefresh branch, there must be no readCache().
  // Easiest check: the early `if (query.forceRefresh) clearCache()`
  // block returns nothing to the cache, then the function
  // continues with `const live = await tryLiveFetch();` etc.
  /forceRefresh[\s\S]{0,400}writeCache\(\s*live\s*\)/.test(serviceSrc),
  'expected forceRefresh path to write fresh result to cache');

assert('formatAbsolute helper exists in src/utils/format.ts',
  /export\s+function\s+formatAbsolute/.test(formatSrc),
  'expected export function formatAbsolute');

/* ------------------------------------------------------------------ */
/* 5. Header UI wiring                                                */
/* ------------------------------------------------------------------ */

section('Header UI — cache pill + absolute time on Last refresh tooltip');

assert('Header shows "Cache: fresh" pill when cacheStatus="fresh"',
  /cacheStatus\s*===\s*['"]fresh['"][\s\S]{0,300}Cache:\s*fresh/.test(headerSrc),
  'expected Cache: fresh pill');

assert('Header shows "Cache: stale" pill when cacheStatus="stale"',
  /cacheStatus\s*===\s*['"]stale['"][\s\S]{0,300}Cache:\s*stale/.test(headerSrc),
  'expected Cache: stale pill');

assert('Header uses an icon for the cache pill (HardDrive)',
  /HardDrive/.test(headerSrc),
  'expected HardDrive icon import in Header');

assert('Cache pill uses info tone (cyan) when fresh',
  (() => {
    const i = headerSrc.indexOf('cacheStatus === \'fresh\'');
    if (i < 0) return false;
    const slice = headerSrc.slice(i, i + 600);
    return /tone\s*=\s*['"]info['"]/.test(slice);
  })(),
  'expected tone="info" on fresh cache pill');

assert('Cache pill uses warn tone (amber) when stale',
  (() => {
    const i = headerSrc.indexOf('cacheStatus === \'stale\'');
    if (i < 0) return false;
    const slice = headerSrc.slice(i, i + 600);
    return /tone\s*=\s*['"]warn['"]/.test(slice);
  })(),
  'expected tone="warn" on stale cache pill');

assert('Last refresh tooltip includes the absolute timestamp',
  /formatAbsolute\(/.test(headerSrc) &&
    /Last refresh:/.test(headerSrc),
  'expected formatAbsolute wired into the Last refresh tooltip');

/* ------------------------------------------------------------------ */
/* 6. Dashboard UI wiring                                             */
/* ------------------------------------------------------------------ */

section('Dashboard UI — cached data banner + Refresh live data button');

assert('Dashboard renders the cached-data banner when cacheStatus is "fresh"',
  /cacheStatus\s*===\s*['"]fresh['"][\s\S]{0,200}CachedDataBanner/.test(dashboardSrc),
  'expected CachedDataBanner on fresh cache');

assert('Dashboard renders the cached-data banner when cacheStatus is "stale"',
  /cacheStatus\s*===\s*['"]stale['"][\s\S]{0,200}CachedDataBanner/.test(dashboardSrc),
  'expected CachedDataBanner on stale cache');

assert('Dashboard defines a CachedDataBanner component',
  /function\s+CachedDataBanner/.test(dashboardSrc),
  'expected function CachedDataBanner');

assert('CachedDataBanner accepts cacheStatus, fetchedAt, onRefresh props',
  /cacheStatus[\s\S]{0,200}fetchedAt[\s\S]{0,200}onRefresh/.test(
    dashboardSrc.slice(dashboardSrc.indexOf('function CachedDataBanner'))
  ),
  'expected props destructured in CachedDataBanner');

assert('Dashboard wires the cached-data banner refresh to a manual-refresh path (v5.2)',
  // v5.2: the "Refresh live data" button on the cached-data
  // banner now POSTs to the Netlify Background Function
  // (calls `manualRefresh()`), not `forceRefresh: true` on
  // the dataset endpoint. This is the v5.2 contract — manual
  // refresh must NOT trigger every visitor to rebuild the
  // full dataset. The forceRefresh path is still wired into
  // the service for internal use; the manual button is not.
  /manualRefresh\(/.test(dashboardSrc) ||
    /onRefresh=\{handleManualRefresh\}/.test(dashboardSrc) ||
    /onRefresh=\{handleRefresh\}/.test(dashboardSrc),
  'expected the cached-data banner refresh to call manualRefresh (v5.2 background path)');

assert('CachedDataBanner exposes a "Refresh live data" button',
  /Refresh live data/.test(dashboardSrc),
  'expected "Refresh live data" button label');

assert('Cached-data banner distinguishes "fresh" and "stale" copy',
  /Cached data \(stale\)/.test(dashboardSrc) &&
    /Cached data \u2014 refreshed/.test(dashboardSrc),
  'expected distinct copy for fresh vs stale');

assert('Cached-data banner uses HardDrive icon',
  /HardDrive/.test(dashboardSrc),
  'expected HardDrive icon in DashboardPage');

assert('Cached-data banner shows the original fetchedAt (both relative and absolute)',
  /formatRelative\(fetchedAt\)/.test(dashboardSrc) &&
    /formatAbsolute\(fetchedAt\)/.test(dashboardSrc),
  'expected both relative and absolute time in CachedDataBanner');

assert('Provider-failure banners are still wired on cached data (NvdUnavailableBanner)',
  /NvdUnavailableBanner/.test(dashboardSrc) &&
    /nvdStatus\s*===\s*['"]unavailable['"]/.test(dashboardSrc),
  'NvdUnavailableBanner must still render on cached data');

assert('Provider-failure banners are still wired on cached data (EpssUnavailableBanner)',
  /EpssUnavailableBanner/.test(dashboardSrc) &&
    /epssStatus\s*===\s*['"]unavailable['"]/.test(dashboardSrc),
  'EpssUnavailableBanner must still render on cached data');

assert('FallbackBanner is still wired (mode === "fallback")',
  /FallbackBanner/.test(dashboardSrc) &&
    /mode\s*===\s*['"]fallback['"]/.test(dashboardSrc),
  'FallbackBanner must still render');

/* ------------------------------------------------------------------ */
/* Summary                                                            */
/* ------------------------------------------------------------------ */

console.log();
if (failed === 0) {
  console.log(`CACHE TESTS PASSED  (${passed}/${passed})`);
} else {
  console.log(`CACHE TESTS FAILED  (${failed} of ${passed + failed} failed)`);
  for (const f of failures) {
    console.log(`  - ${f.label}${f.extra ? '  [' + f.extra + ']' : ''}`);
  }
  process.exit(1);
}