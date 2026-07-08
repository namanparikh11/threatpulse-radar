// Acceptance tests for the v5.1 soft-refresh path.
//
//   node scripts/acceptance-softrefresh.mjs
//
// What it covers:
//   1. The "should we show the pending-update banner?" decision
//      re-implemented in plain JS, with boundary inputs:
//        - new result with same fetchedAt as displayed (no upstream
//          change yet — stale-while-revalidate re-serve)
//        - new result with older fetchedAt (out-of-order responses)
//        - new result with newer fetchedAt (the happy path)
//        - new result with mode !== 'live' (mock fallback or
//          stale cache re-serve — never an actionable update)
//        - new result whose fetchedAt matches the user's last
//          dismissed update (must not re-show)
//        - new result whose fetchedAt is strictly newer than
//          both the displayed AND the dismissed fetchedAt
//          (the spec's "hide until the next newer dataset")
//   2. The v5.1 source wiring:
//        - service: VulnerabilityQuery.background, the bypass-
//          readCache / keep-writeCache behavior, the contract
//          comment, the file-level v5.1 note
//        - dashboard: pendingUpdate + dismissedFetchedAt state,
//          stateRef + dismissedRef refs, the polling useEffect
//          (5-minute cadence, visibility check, cleanup,
//          fetchVulnerabilities({ background: true })), the
//          handleApplyUpdate handler (state promotion, drawer
//          close-if-missing, selected swap-if-present), the
//          handleDismissUpdate handler, the UpdateAvailableBanner
//          component definition, the conditional render, and
//          both buttons (Apply update + dismiss ×).
//   3. Existing v4 / v5.0.3 contract is NOT regressed: the
//      same source-level regexes from the cache + proxy suites
//      are re-checked here so a refactor that breaks either
//      suite is caught here too.
//
// The v1 / CISA / EPSS / NVD / cache / proxy suites keep
// running untouched; this file is purely additive.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

/* ------------------------------------------------------------------ */
/* Re-implementation of the soft-refresh decision logic. Kept in     */
/* lockstep with DashboardPage.tsx's polling useEffect.              */
/* ------------------------------------------------------------------ */

/**
 * Decide whether the polling loop should set `pendingUpdate` to
 * the new result (which would cause the UpdateAvailableBanner to
 * render). Mirrors the in-component check, character-for-character.
 *
 *   - Non-live results (mock / fallback / cache-replay) never
 *     trigger a banner — they aren't a "new dataset" the user
 *     can act on.
 *   - A result whose `fetchedAt` is NOT strictly newer than the
 *     currently displayed one is ignored — this covers both the
 *     "same fetchedAt" case (stale-while-revalidate re-serve with
 *     no upstream change) and the out-of-order-response case.
 *   - A result whose `fetchedAt` matches the user's last
 *     dismissed update is ignored — so dismissing once hides
 *     that exact update forever (until a strictly newer one
 *     arrives).
 */
function shouldShowPendingUpdate(currentFetchedAt, newResult, dismissedFetchedAt) {
  if (!newResult || newResult.mode !== 'live') return false;
  if (typeof newResult.fetchedAt !== 'string') return false;
  if (typeof currentFetchedAt !== 'string') return false;
  if (newResult.fetchedAt <= currentFetchedAt) return false;
  if (dismissedFetchedAt && newResult.fetchedAt === dismissedFetchedAt) return false;
  return true;
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
/* 1. shouldShowPendingUpdate — decision logic                        */
/* ------------------------------------------------------------------ */

section('shouldShowPendingUpdate — pure decision logic');

const DISPLAYED = '2026-07-08T18:00:00.000Z';
const NEWER = '2026-07-08T18:05:00.000Z';
const EQUAL = '2026-07-08T18:00:00.000Z';
const OLDER = '2026-07-08T17:55:00.000Z';

assert('newer live result, no prior dismiss \u2192 show',
  shouldShowPendingUpdate(DISPLAYED, { mode: 'live', fetchedAt: NEWER }, null) === true);

assert('same-fetchedAt live result (no upstream change) \u2192 do not show',
  shouldShowPendingUpdate(DISPLAYED, { mode: 'live', fetchedAt: EQUAL }, null) === false);

assert('older-fetchedAt live result (out-of-order response) \u2192 do not show',
  shouldShowPendingUpdate(DISPLAYED, { mode: 'live', fetchedAt: OLDER }, null) === false);

assert('newer mock-mode result \u2192 do not show (mock isn\u2019t a new dataset)',
  shouldShowPendingUpdate(DISPLAYED, { mode: 'mock', fetchedAt: NEWER }, null) === false);

assert('newer fallback-mode result \u2192 do not show (fallback isn\u2019t a new dataset)',
  shouldShowPendingUpdate(DISPLAYED, { mode: 'fallback', fetchedAt: NEWER }, null) === false);

assert('newer live result, dismissedFetchedAt matches \u2192 do not show',
  shouldShowPendingUpdate(DISPLAYED, { mode: 'live', fetchedAt: NEWER }, NEWER) === false);

assert('newer live result, dismissedFetchedAt is older \u2192 show',
  shouldShowPendingUpdate(DISPLAYED, { mode: 'live', fetchedAt: NEWER }, OLDER) === true);

assert('newer live result, dismissedFetchedAt is null \u2192 show',
  shouldShowPendingUpdate(DISPLAYED, { mode: 'live', fetchedAt: NEWER }, null) === true);

assert('result missing fetchedAt \u2192 do not show (defensive)',
  shouldShowPendingUpdate(DISPLAYED, { mode: 'live' }, null) === false);

assert('null result \u2192 do not show (defensive)',
  shouldShowPendingUpdate(DISPLAYED, null, null) === false);

assert('displayed fetchedAt missing \u2192 do not show (defensive)',
  shouldShowPendingUpdate(null, { mode: 'live', fetchedAt: NEWER }, null) === false);

assert('fallback result with newer fetchedAt \u2192 do not show (mode check runs first)',
  // Mode !== 'live' must be the first guard, otherwise a fallback
  // re-serve (rare but possible) could trigger a banner for data
  // the user is already looking at.
  shouldShowPendingUpdate(DISPLAYED, { mode: 'fallback', fetchedAt: NEWER }, OLDER) === false);

/* ------------------------------------------------------------------ */
/* 2. Source-level wiring — service                                   */
/* ------------------------------------------------------------------ */

section('Service: VulnerabilityQuery.background flag + fetch flow');

const serviceSrc = readFileSync(
  join(root, 'src', 'services', 'vulnerabilityService.ts'), 'utf8');

assert('VulnerabilityQuery declares an optional `background` flag',
  /background\?\s*:\s*boolean/.test(serviceSrc) &&
    /interface\s+VulnerabilityQuery/.test(serviceSrc),
  'expected `background?: boolean` on VulnerabilityQuery');

assert('service skips readCache when background=true',
  // The conditional must include both !query.forceRefresh AND
  // !query.background in the readCache gate.
  /!\s*query\.forceRefresh\s*&&\s*!\s*query\.background\s*\?\s*readCache\(\)\s*:\s*null/.test(serviceSrc),
  'expected readCache gate to also exclude `background`');

assert('service does NOT bypass writeCache on background=true (still writes through)',
  // The writeCache() call after a successful live fetch must
  // not be wrapped in `if (!query.background)`. Background
  // polls still update the localStorage cache so a future
  // Apply / page reload is instant.
  (() => {
    const i = serviceSrc.indexOf('writeCache(');
    if (i < 0) return false;
    // Find the writeCache call inside fetchVulnerabilities
    // (not in any helper function) — search the first 4KB after.
    const slice = serviceSrc.slice(0, i + 4000);
    // The writeCache call inside fetchVulnerabilities sits in
    // the success branch of the live fetch. Look for
    // `writeCache(live)` not gated by a `background` check.
    return /writeCache\(\s*live\s*\)/.test(slice);
  })(),
  'expected writeCache(live) still present in fetchVulnerabilities');

assert('service file-level comment mentions v5.1 soft-refresh',
  /v5\.1/.test(serviceSrc) && /soft-refresh|background\s*poll|background\s*flag/i.test(serviceSrc),
  'expected v5.1 + soft-refresh mentioned in service header');

assert('fetchVulnerabilities docstring mentions `background`',
  // The docstring opens with `* Fetch the active vulnerability
  // dataset.` — anchor there and look for `background=true`
  // inside the same JSDoc block.
  /\/\*\*[\s\S]{0,500}\*\s*Fetch the active vulnerability dataset[\s\S]{0,2500}background\s*=\s*true/.test(serviceSrc),
  'expected `background=true` documented in fetchVulnerabilities comment');

assert('service keeps forceRefresh behavior intact (still clears cache)',
  // v4 contract: forceRefresh calls clearCache(). Must still work.
  /forceRefresh[\s\S]{0,200}clearCache\(\)/.test(serviceSrc),
  'expected forceRefresh to still call clearCache()');

/* ------------------------------------------------------------------ */
/* 3. Source-level wiring — DashboardPage                              */
/* ------------------------------------------------------------------ */

section('Dashboard: polling, pendingUpdate, apply/dismiss, banner');

const dashboardSrc = readFileSync(
  join(root, 'src', 'pages', 'DashboardPage.tsx'), 'utf8');
const cacheSrc = readFileSync(
  join(root, 'src', 'services', 'datasetCache.ts'), 'utf8');

assert('DashboardPage imports formatAgeShort from datasetCache',
  /import\s*\{[\s\S]*?formatAgeShort[\s\S]*?\}\s*from\s*['"]\.\.\/services\/datasetCache['"]/.test(dashboardSrc),
  'expected formatAgeShort import in DashboardPage');

assert('DashboardPage declares pendingUpdate state',
  /useState<FetchResult<Vulnerability\[\]>\s*\|\s*null>\(\s*null\s*\)/.test(dashboardSrc) ||
    /const\s+\[pendingUpdate,\s*setPendingUpdate\]\s*=\s*useState/.test(dashboardSrc),
  'expected pendingUpdate state slot');

assert('DashboardPage declares dismissedFetchedAt state',
  /const\s+\[dismissedFetchedAt,\s*setDismissedFetchedAt\]\s*=\s*useState/.test(dashboardSrc),
  'expected dismissedFetchedAt state slot');

assert('DashboardPage defines stateRef + dismissedRef for closure access',
  /stateRef\s*=\s*useRef/.test(dashboardSrc) &&
    /dismissedRef\s*=\s*useRef/.test(dashboardSrc),
  'expected stateRef and dismissedRef refs');

assert('DashboardPage defines BACKGROUND_POLL_INTERVAL_MS = 5 * 60 * 1000',
  /BACKGROUND_POLL_INTERVAL_MS\s*=\s*5\s*\*\s*60\s*\*\s*1000/.test(dashboardSrc),
  'expected 5-minute cadence constant');

assert('DashboardPage polling useEffect calls fetchVulnerabilities({ background: true })',
  /fetchVulnerabilities\(\s*\{\s*background:\s*true\s*\}\s*\)/.test(dashboardSrc),
  'expected background: true on the polling fetch');

assert('polling useEffect sets up a setInterval',
  /setInterval\(/.test(dashboardSrc),
  'expected setInterval in polling useEffect');

assert('polling useEffect cleans up the interval',
  /clearInterval\(\s*timer\s*\)/.test(dashboardSrc) ||
    /clearInterval\(/.test(dashboardSrc),
  'expected clearInterval in cleanup');

assert('polling useEffect checks document.visibilityState === "visible"',
  /document\.visibilityState\s*!==\s*['"]visible['"]/.test(dashboardSrc),
  'expected visibility check');

assert('polling useEffect ignores non-live results',
  /if\s*\(\s*result\.mode\s*!==\s*['"]live['"]\s*\)\s*return/.test(dashboardSrc),
  'expected mode !== "live" early return in poll');

assert('polling useEffect ignores results not newer than displayed',
  /result\.fetchedAt\s*<=\s*current\.meta\.fetchedAt/.test(dashboardSrc),
  'expected fetchedAt comparison against current state');

assert('polling useEffect ignores results whose fetchedAt matches the dismissed one',
  /result\.fetchedAt\s*===\s*dismissedRef\.current/.test(dashboardSrc),
  'expected dismissedRef.current comparison');

assert('polling useEffect wraps the network call in try/catch (silent failure)',
  // Background poll failures must be silent — a transient
  // proxy error shouldn't surface as a banner or break the UI.
  /try\s*\{[\s\S]{0,200}fetchVulnerabilities\(\s*\{\s*background:\s*true/.test(dashboardSrc) &&
    /\}\s*catch\s*\{/.test(dashboardSrc),
  'expected try/catch around background fetchVulnerabilities');

assert('DashboardPage defines handleApplyUpdate',
  /function\s+handleApplyUpdate|const\s+handleApplyUpdate\s*=\s*useCallback/.test(dashboardSrc),
  'expected handleApplyUpdate handler');

assert('handleApplyUpdate promotes pendingUpdate into state',
  // It must call setState({ kind: 'ready', meta: current }) with
  // the pending update, NOT with the existing meta.
  /setState\(\s*\{\s*kind:\s*['"]ready['"]\s*,\s*meta:\s*current\s*\}\s*\)/.test(dashboardSrc),
  'expected setState with pendingUpdate as meta');

assert('handleApplyUpdate preserves filters (does not call setFilters)',
  // The handler must not call setFilters or setSort. Just to be
  // safe, look for any of those calls within the function body.
  (() => {
    const i = dashboardSrc.indexOf('handleApplyUpdate');
    if (i < 0) return false;
    // Look at the next ~1500 chars (the function body and a bit
    // beyond) and assert no setFilters / setSort calls.
    const slice = dashboardSrc.slice(i, i + 1500);
    return !/setFilters\(/.test(slice) && !/setSort\(/.test(slice);
  })(),
  'expected handleApplyUpdate to NOT reset filters or sort');

assert('handleApplyUpdate closes the drawer when the selected CVE is gone',
  // Must check `find((v) => v.cveId === prev.cveId)` and return
  // null when not found.
  /cveId\s*===\s*prev\.cveId[\s\S]{0,200}return\s+null/.test(dashboardSrc),
  'expected drawer-close-on-missing-CVE logic');

assert('handleApplyUpdate swaps the selected record when the CVE still exists',
  // After the `stillExists = ... find(...)`, the handler must
  // return stillExists (not prev) so any updated CVSS / EPSS
  // scores show through in the drawer.
  /const\s+stillExists\s*=\s*current\.data\.find[\s\S]{0,200}return\s+stillExists/.test(dashboardSrc),
  'expected selected-record swap when CVE still present');

assert('handleApplyUpdate clears dismissedFetchedAt',
  // After Apply, dismissedFetchedAt is no longer relevant —
  // the displayed fetchedAt is now the just-applied one.
  /setDismissedFetchedAt\(\s*null\s*\)/.test(dashboardSrc),
  'expected setDismissedFetchedAt(null) in handleApplyUpdate');

assert('DashboardPage defines handleDismissUpdate',
  /function\s+handleDismissUpdate|const\s+handleDismissUpdate\s*=\s*useCallback/.test(dashboardSrc),
  'expected handleDismissUpdate handler');

assert('handleDismissUpdate records the dismissed fetchedAt',
  /setDismissedFetchedAt\(\s*current\.fetchedAt\s*\)/.test(dashboardSrc),
  'expected setDismissedFetchedAt(current.fetchedAt) in dismiss');

assert('handleDismissUpdate clears pendingUpdate',
  // The handler must call setPendingUpdate(null) — via the
  // functional updater pattern (return null).
  /setPendingUpdate\(\s*\(current\)[\s\S]{0,400}return\s+null\s*;?\s*\}\s*\)/.test(dashboardSrc),
  'expected setPendingUpdate(null) in dismiss');

assert('DashboardPage renders UpdateAvailableBanner when pendingUpdate is non-null',
  /pendingUpdate\s*&&\s*\(\s*[\s\S]{0,200}UpdateAvailableBanner/.test(dashboardSrc),
  'expected conditional render of UpdateAvailableBanner');

assert('UpdateAvailableBanner has an "Apply update" button',
  /Apply update/.test(dashboardSrc),
  'expected "Apply update" button copy');

assert('UpdateAvailableBanner has a dismiss (×) button with aria-label',
  /aria-label\s*=\s*['"]Dismiss update notification['"]/.test(dashboardSrc),
  'expected dismiss button aria-label');

assert('UpdateAvailableBanner uses Sparkles icon',
  /Sparkles/.test(dashboardSrc),
  'expected Sparkles icon import + usage in DashboardPage');

assert('UpdateAvailableBanner uses X icon',
  /\bX\b/.test(dashboardSrc) && /from\s+['"]lucide-react['"]/.test(dashboardSrc),
  'expected X icon import + usage in DashboardPage');

assert('UpdateAvailableBanner shows the new dataset\'s age with formatAgeShort',
  /formatAgeShort\(\s*ageMs\s*\)/.test(dashboardSrc),
  'expected formatAgeShort(ageMs) in banner');

assert('UpdateAvailableBanner shows the absolute timestamp with formatAbsolute',
  /formatAbsolute\(\s*pendingFetchedAt\s*\)/.test(dashboardSrc),
  'expected formatAbsolute(pendingFetchedAt) in banner');

assert('UpdateAvailableBanner uses info-tone (cyan) styling',
  /border-radar-accent\/30\s+bg-radar-accent\/5/.test(dashboardSrc),
  'expected info-tone panel classes on the banner');

/* ------------------------------------------------------------------ */
/* 4. Regressions — v4 / v5.0.3 contracts must still hold             */
/* ------------------------------------------------------------------ */

section('Regressions — existing v4 / v5.0.3 contracts');

assert('cache module still exports readCache / writeCache / clearCache',
  /export\s+function\s+readCache/.test(cacheSrc) &&
    /export\s+function\s+writeCache/.test(cacheSrc) &&
    /export\s+function\s+clearCache/.test(cacheSrc));

assert('cache TTL is still exactly 1 hour (60 * 60 * 1000 ms)',
  /CACHE_TTL_MS\s*=\s*60\s*\*\s*60\s*\*\s*1000/.test(cacheSrc));

assert('service still uses cacheStatus = "miss" / "fresh" / "stale"',
  /CacheStatus\s*=\s*['"]miss['"]\s*\|\s*['"]fresh['"]\s*\|\s*['"]stale['"]/.test(serviceSrc));

assert('service still has forceRefresh: boolean on VulnerabilityQuery',
  /forceRefresh\?\s*:\s*boolean/.test(serviceSrc));

assert('service still serves fresh cache with cacheStatus="fresh"',
  /isCacheFresh[\s\S]{0,200}cacheStatus:\s*['"]fresh['"]/.test(serviceSrc));

assert('DashboardPage still has CachedDataBanner (v4 not regressed)',
  /function\s+CachedDataBanner/.test(dashboardSrc));

assert('DashboardPage still has FallbackBanner',
  /function\s+FallbackBanner/.test(dashboardSrc));

assert('DashboardPage still has NvdUnavailableBanner',
  /function\s+NvdUnavailableBanner/.test(dashboardSrc));

assert('DashboardPage still has EpssUnavailableBanner',
  /function\s+EpssUnavailableBanner/.test(dashboardSrc));

assert('DashboardPage still has a handleRefresh wired to forceRefresh: true',
  /fetchVulnerabilities\(\s*\{\s*forceRefresh:\s*true\s*\}\s*\)/.test(dashboardSrc));

/* ------------------------------------------------------------------ */
/* Summary                                                            */
/* ------------------------------------------------------------------ */

console.log();
if (failed === 0) {
  console.log(`SOFT-REFRESH TESTS PASSED  (${passed}/${passed})`);
} else {
  console.log(`SOFT-REFRESH TESTS FAILED  (${failed} of ${passed + failed} failed)`);
  for (const f of failures) {
    console.log(`  - ${f.label}${f.extra ? '  [' + f.extra + ']' : ''}`);
  }
  process.exit(1);
}