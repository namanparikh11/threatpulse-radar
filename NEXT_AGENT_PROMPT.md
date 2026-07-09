# NEXT_AGENT_PROMPT

> Drop this into a fresh MiniMax Code session when you're ready to take
> ThreatPulse Radar to the next milestone. It is intentionally compact:
> enough context to act, no fluff.

---

## You are working on ThreatPulse Radar

**What it is.** A polished, dark-themed, frontend-only cybersecurity
vulnerability-intelligence dashboard for **defensive** security
portfolio use. Now in v5.2.6, with a v5.3 launch-documentation
polish queued on `v5-3-launch-polish`.

**Stack.** React 18 + Vite 5 + TypeScript 5 (strict) + Tailwind CSS 3 +
Recharts 2 + Lucide React + three Node 20 ESM Netlify Functions
(`netlify/functions/dataset.mjs`,
`netlify/functions/refresh-dataset-background.mjs`,
`netlify/functions/refresh-dataset-scheduled.mjs`) sharing three
modules in `netlify/functions/_shared/` (`store.mjs`, `refresh.mjs`,
`liveBuild.mjs`). The read endpoint serves a v5.0.1 CDN-cacheable
response (now serving from the v5.2 prebuilt Blob when present),
the v5.0.2 NVD rate-limit path and v5.0.3 request-header NVD
API key transport are preserved, the v5.1 soft-refresh
polling + banner mechanism serves as the only path through which
v5.2 background-refresh results reach the UI, and v5.2.6 adds the
NVD backoff + dataset quality guard so a 429-induced downgrade
cannot overwrite a better existing blob. The new `@netlify/blobs`
runtime dependency is zipped alongside the function code on deploy.

**Status.** v1 (mock data) through v5.2.6 (NVD backoff + dataset
quality guard) are done; v5.3 is documentation-only (README polish,
queued on `v5-3-launch-polish`).
- `node node_modules/typescript/bin/tsc -b ; node node_modules/vite/bin/vite.js build` → 0 errors, ~7 s.
- `node scripts/acceptance-cisa.mjs` → **28/28**.
- `node scripts/acceptance-epss.mjs` → **39/39**.
- `node scripts/acceptance-nvd.mjs` → **57/57** (v3.0 / v3.0.1
  NVD upstream tests + v5.2.4 batch URL fixes).
- `node scripts/acceptance-cache.mjs` → **60/60**.
- `node scripts/acceptance-softrefresh.mjs` → **58/58**.
- `node scripts/acceptance-proxy.mjs` → **110/110** (v5.0 +
  v5.0.1 CDN cache + v5.0.2 NVD rate-limit hardening +
  v5.0.3 NVD_API_KEY request-header transport + v5.2.5 NVD
  partial-fallback hardening + v5.2.6 NVD backoff + dataset
  quality guard source-level checks).
- `node scripts/acceptance-prebuilt.mjs` → **148/148** (v5.2
  prebuilt-dataset store + v5.2.6 quality-guard decision table:
  `nvd-cooldown` blob key + 15-min TTL + cooldown read / write /
  clear helpers + pure-JS cooldown-active check +
  `countCvssAboveZero` + `isNvdRateLimitedReason` +
  `shouldSkipOverwrite` + 8 quality-guard scenarios + cooldown
  short-circuit + `skipNvd` opt + source-level wiring + no-`apiKey`
  invariants).
- Total: **500/500** acceptance tests.
- 60 unique mock records (offline fallback) + the live CISA KEV
  feed (default) + live NVD CVSS enrichment + live FIRST EPSS
  enrichment, all server-aggregated by the v5.0 Netlify
  Function and prebuilt into a shared Netlify Blobs
  `latest-dataset` entry on a 30-min cron.
- Returning visitors hit the v5.2 prebuilt blob first —
  no upstream build runs on their request. The v4
  localStorage cache still wraps the read path with a 1 h
  TTL; both layers compose. A "Cache: fresh" / "Cache:
  stale" pill in the header and a "Cached data" banner
  above the stats make it obvious when data is from
  `localStorage`; a "Dataset store: latest available"
  pill makes it obvious when the read came from the
  shared blob.
- v5.1 silently polls the proxy every 5 minutes (only while
  the tab is visible) and surfaces a small "New dataset
  available." banner with an Apply update button when a
  newer upstream dataset is detected. Filters / search /
  sort / selected detail view are preserved across the
  apply; the drawer auto-closes only if the selected CVE
  is no longer in the new dataset.
- v5.2 manual "Refresh live data" button POSTs to the
  Netlify Background Function — the visible dataset is
  preserved; the v5.1 banner is the only way the data is
  swapped. A "Refresh running in background" pill appears
  immediately and auto-clears when the build completes.
- v5.2.6 quality guard: if a later refresh hits NVD HTTP 429
  and the new build has fewer CVSS-positive records than the
  existing prebuilt blob, the new build is discarded
  (`status: "preserved"`) and the existing blob continues to
  serve visitors. A 15-min `nvd-cooldown` marker is set so the
  next refresh short-circuits the doomed NVD fetch
  (`status: "cooldown"`).
- Filter / search / sort pipeline in `useVulnerabilityFilter`
  works identically on every data path.
- Severity sort verified: `desc` = Critical, High, Medium,
  Low. `asc` = Low, Medium, High, Critical.
- Hero is the final public-portfolio cut (no version
  numbers, no top status strip, no live radar animation).
- Deployment target: **Netlify** (`netlify.toml`). The
  Hostinger static-hosting fallback (`dist/.htaccess`)
  is preserved for the v4.1 browser-direct demo if the
  function is not available, but the supported path is
  Netlify.
- `main` is clean (v5.2.6 was merged via PR). The current
  branch is `v5-3-launch-polish` with uncommitted source changes
  (README rewrite + internal-doc header updates). The `origin`
  remote is configured (private repo at
  `https://github.com/namanparikh11/threatpulse-radar.git`) but
  nothing has been pushed. Do not push without an explicit ask.

## Read first

Open these files in this order before touching anything:

1. `PROJECT_HANDOFF.md` — the full project status, what was
   done in each pass, what's out of scope, the recommended
   next milestone.
2. `README.md` — the public-facing project description (v5.1
   reflects the Netlify Function proxy + CDN cache + NVD
   rate-limit hardening + soft refresh).
3. `DEPLOYMENT.md` — the Netlify deployment guide (v5.0
   onward). Section 0 for the v5.0 Netlify workflow,
   section 0.7 for the v5.0.1 CDN cache, section 0.8 for
   the v5.0.2 / v5.0.3 `NVD_API_KEY` configuration.

## Hard rules for this session

These are non-negotiable. The next agent (you) must not:

- ❌ Add more real APIs. CISA KEV, NVD, and FIRST EPSS are
  the full enrichment chain. New sources go through a fresh
  ask — they need a new provider, a new orchestration path,
  and a new status field on `FetchResult`.
- ❌ Add new features (auth, persistence beyond the cache,
  watchlists, CSV export, per-vendor sidebar, deep-linking).
  Out of scope unless the user explicitly asks.
- ❌ Redesign the header. The pass-4 layout is final; the v2
  / v2.5 / v3 / v4 / v5 passes only changed labels and
  added pills / banners, not structure.
- ❌ Touch the filter / search / sort pipeline. The 15 v1
  acceptance tests + 28 CISA tests + 39 EPSS tests + 53 NVD
  tests + 60 cache tests + 71 proxy tests + 58 soft-refresh
  tests + 98 prebuilt tests must keep passing. Do not weaken
  them. The severity sort comparator in
  `src/utils/analytics.ts` (`compareByField`'s
  `case 'severity':`) was corrected in pass 8 to put Critical
  first when descending; do not revert it.
- ❌ Touch `src/data/mockVulnerabilities.ts`,
  `src/hooks/useVulnerabilityFilter.ts`, or
  `src/hooks/useDebouncedValue.ts` unless the user explicitly
  asks.
- ❌ Bump major versions of React / Vite / Recharts.
- ❌ Add a backend, a database, or any kind of server beyond
  the existing three Netlify Functions + the shared
  `_shared/{store,refresh,liveBuild}.mjs` modules. The
  prebuilt Blob store is the only server-side state.
- ❌ Add additional scheduled functions or change the v5.2
  cron cadence (currently `*/30 * * * *`).
- ❌ Remove `base: './'` from `vite.config.ts` or the
  `public/.htaccess` file.
- ❌ Change `DATA_MODE` away from `'live'` in
  `src/services/vulnerabilityService.ts` without an explicit
  ask.
- ❌ Revert the severity sort comparator, the CISA / NVD /
  EPSS enrichment, or the `nvdStatus` / `epssStatus`
  side-channels.
- ❌ Revert the v4 cache layer. The cache envelope
  deliberately preserves `nvdStatus` / `epssStatus` /
  `fallbackReason` so the cache never hides provider
  failures; do not "optimize" by dropping them.
- ❌ Revert the v5.0.3 NVD_API_KEY request-header transport.
  The key is read from `process.env.NVD_API_KEY` inside the
  function only and sent as `headers.apiKey = apiKey`. Never
  as a URL query parameter. Never to the browser. A
  `VITE_NVD_API_KEY` is explicitly forbidden by the
  v4.1 / v5.0 docs contract.
- ❌ Revert the v5.1 soft-refresh path. The polling effect
  in `DashboardPage` uses `fetchVulnerabilities({ background:
  true })` which skips the localStorage cache read but still
  writes through. The polling cadence is 5 minutes. The
  banner is shown only when the new result's `mode ===
  'live'` AND its `fetchedAt` is strictly newer than the
  displayed one AND its `fetchedAt` does not match the
  user's last-dismissed update. None of these guards may be
  removed.
- ❌ Auto-apply a background poll result. The user must
  always click "Apply update" — soft refresh is
  informational, never automatic.
- ❌ Revert the v5.2 prebuilt store. The read endpoint must
  read `latest-dataset` BEFORE running the live build. The
  blob must NEVER be overwritten with a mock fallback. The
  refresh-lock TTL must stay at 15 minutes. The scheduled
  function must stay at `*/30 * * * *`. The manual button
  must POST to the background endpoint — it must NOT
  call `fetchVulnerabilities({ forceRefresh: true })` on
  the read endpoint.
- ❌ Auto-replace the visible dataset on a manual refresh.
  The v5.2 contract is: the manual button POSTs to the
  background endpoint, the visible data is preserved, and
  the v5.1 banner is the only way the data is swapped.
- ❌ Add new VITE_* env vars beyond `VITE_DATASET_PROXY_URL`
  and `VITE_REFRESH_ENDPOINT_URL` (both are public routes,
  not secrets).
- ❌ Push to `origin` without an explicit ask.

If a request seems to violate these, push back once, then
ask before acting. The user values this scope.

## Recommended next milestone (v4.5 / v5.2): UX-on-top-of-frozen-data

The v5.1 data + cache + soft-refresh layers are
feature-complete for a portfolio piece. The next session's
job is whatever the user explicitly asks for, but
reasonable options include:

1. **Saved filter presets** — e.g. "Internet-facing + KEV",
   "Last 7 days + High/Critical", "Microsoft + EPSS > 50%".
   A small `presets.ts` in `src/data/` or `src/utils/` with
   named `VulnerabilityFilters` objects, plus a dropdown in
   `FiltersPanel.tsx` that applies them. No data-layer
   change needed. Watch out: don't store these in the same
   `localStorage` namespace as the dataset cache.
2. **CSV / JSON export of the current filtered view** — use
   a `Blob` + `URL.createObjectURL`. Trivial; ~30 lines.
3. **Per-vendor watchlists** — a separate `watchlist`
   `localStorage` key + a small "Watchlist" view that
   filters the dataset to the user's saved vendors. No
   data-layer change.
4. **New data sources** — OSV.dev / GHSA / other
   aggregators. These need a new provider, a new
   orchestration path, and a new status field on
   `FetchResult`. The function has room (the
   `OVERALL_BUDGET_MS` is 24 s under Netlify's 26 s default
   async limit; adding a fourth provider would likely
   require bumping the function to a paid Netlify plan or
   serializing more aggressively).

The user gets to pick. The frozen-scope contract from the
"Hard rules" section above is the same regardless of which
one they choose.

## Acceptance for the next session

When work is done, report:

1. `npm.cmd run build` result (must be 0 errors, 0 warnings).
2. `node scripts/acceptance.mjs` result (must be **15/15**).
3. `node scripts/acceptance-cisa.mjs` result (must be **28/28**).
4. `node scripts/acceptance-epss.mjs` result (must be **39/39**).
5. `node scripts/acceptance-nvd.mjs` result (must be **53/53**).
6. `node scripts/acceptance-cache.mjs` result (must be **60/60**).
7. `node scripts/acceptance-proxy.mjs` result (must be **71/71**).
8. `node scripts/acceptance-softrefresh.mjs` result (must be **58/58**).
9. `node scripts/acceptance-prebuilt.mjs` result (must be **98/98**).
10. New tests (if any) result (must be `N/N`).
11. List of files added / modified.
12. A short note on whether `dist/` is still drop-in
    deployable to Netlify (it should be — `netlify.toml`
    registers the new functions, the read endpoint still
    serves a CDN-cacheable response).

## Things that are already correct (don't redo them)

- Tailwind palette (`tailwind.config.js`).
- Strict TypeScript (`tsconfig.app.json`).
- Manual chunk splitting for `react` / `charts` / `icons`
  in `vite.config.ts` — bundle is well-split.
- The 6 stats cards, 4 charts, vulnerability table, filter
  panel, detail drawer, empty/loading/error states.
- The pass-4 hero: logo, title, subtitle, badges, status
  pills (now with dynamic source / mode / NVD / EPSS /
  Cache / Proxy labels).
- `useVulnerabilityFilter` + `useDebouncedValue` +
  `SearchStatus` custom-hook pipeline.
- The 60 unique mock records with stable `id`s (offline
  fallback, not primary source).
- The CISA KEV provider with `AbortController` timeout.
- The FIRST EPSS provider with chunked batched fetch,
  parsing, and a pure `enrichWithEpss` function.
- The NVD CVE 2.0 provider with v3.1 → v3.0 → v2 score
  preference, chunked batched fetch, and a pure
  `enrichWithNvd` function that overrides both
  `cvssScore` and `severity` when NVD has data.
- The `FetchResult.mode` state machine:
  `'live' | 'mock' | 'fallback'`.
- The `FetchResult.epssStatus` side-channel:
  `'first' | 'unavailable'`.
- The `FetchResult.nvdStatus` side-channel:
  `'nvd' | 'unavailable'`.
- The `FetchResult.cacheStatus` side-channel (v4):
  `'miss' | 'fresh' | 'stale'`. `undefined` in mock mode.
- The `FetchResult.proxyStatus` side-channel (v5.0):
  `'proxy' | 'browser-direct' | 'unavailable'`.
  `undefined` in mock mode or stale-cache-only serves.
- The `public/.htaccess` SPA fallback + cache + security
  headers.
- The v1 acceptance suite (`scripts/acceptance.mjs`).
- The v2 CISA acceptance suite
  (`scripts/acceptance-cisa.mjs`).
- The v2.5 EPSS acceptance suite
  (`scripts/acceptance-epss.mjs`).
- The v3 NVD acceptance suite
  (`scripts/acceptance-nvd.mjs`).
- The v3.1 honesty fixes in `Header.tsx` (the
  `describeSource` function reads `nvdStatus` *and*
  `epssStatus` before building the source label) and the
  `LoadingState` copy that names the three live
  providers. Both are guarded by tests in
  `scripts/acceptance-nvd.mjs`.
- The v4 transparent cache: `src/services/datasetCache.ts`
  (versioned localStorage key `tpr:dataset:v1`, 1-hour
  TTL, defensive try/catch around all storage access), the
  `CachedDataBanner` component in `DashboardPage.tsx`
  (above the provider-failure banners), the "Cache:
  fresh" / "Cache: stale" pills in `Header.tsx`, the
  absolute-time tooltip on "Last refresh" via
  `formatAbsolute()`, and the manual "Refresh live data"
  button wired to
  `fetchVulnerabilities({ forceRefresh: true })`. All of
  these are guarded by tests in
  `scripts/acceptance-cache.mjs`.
- The v5.0 Netlify Function proxy: `netlify/functions/
  dataset.mjs` (CISA → NVD → EPSS in parallel, AbortController
  timeouts, OVERALL_BUDGET_MS = 24 s, no-store on
  outbound upstream fetches, CORS-permissive response,
  `jsonResponse` helper). The `Proxy: Netlify` pill in
  `Header.tsx`. The `tryProxyFetch` →
  `tryBrowserDirectFetch` → mock-fallback orchestration
  in `src/services/vulnerabilityService.ts`. All guarded
  by tests in `scripts/acceptance-proxy.mjs`.
- The v5.0.1 CDN-cacheable function response
  (`Cache-Control: public, s-maxage=900,
  stale-while-revalidate=300`), `fetchedAt` set inside the
  function body so the "Last refresh" pill stays honest,
  and the `?t=<timestamp>` cache-busting query string
  forwarded by `forceRefresh: true`.
- The v5.0.2 NVD rate-limit hardening: `concurrency = 1`
  when no `NVD_API_KEY` is set, `concurrency = chunks.length`
  when the key is set, the `settledAll` helper, and the
  concise 429 reason (`'NVD rate limit reached (HTTP 429).
  NVD CVSS enrichment is unavailable; severity falls back
  to CISA-derived values for this refresh.'`).
- The v5.0.3 NVD_API_KEY transport fix: key passed as
  `headers.apiKey = apiKey` per NVD's CVE 2.0 spec, never
  as a URL query parameter. Server-side only.
- The v5.1 soft-refresh path: the `background?: boolean`
  flag on `VulnerabilityQuery`, the polling
  `useEffect` in `DashboardPage` (5-minute cadence,
  visibility-gated, silent try/catch on failure), the
  `pendingUpdate` / `dismissedFetchedAt` state slots, the
  `stateRef` / `dismissedRef` refs, the `handleApplyUpdate`
  handler (state promotion with filters / sort / search
  preserved, drawer close-if-missing-CVE + selected-swap-
  if-present), the `handleDismissUpdate` handler, and the
  `UpdateAvailableBanner` component (info-tone, Sparkles
  icon, Apply update + × buttons, formatAgeShort +
  formatAbsolute labels). All guarded by tests in
  `scripts/acceptance-softrefresh.mjs`.
- The v5.2 prebuilt-dataset store: the
  `netlify/functions/_shared/store.mjs` module
  (`getDatasetStore`, `readLatestDataset`,
  `writeLatestDataset`, `readRefreshLock`,
  `isRefreshLocked`, `tryAcquireRefreshLock`,
  `clearRefreshLock`; constants `STORE_NAME =
  "tpr-dataset"`, `LATEST_DATASET_KEY =
  "latest-dataset"`, `REFRESH_LOCK_KEY = "refresh-lock"`,
  `REFRESH_LOCK_TTL_MS = 15 * 60 * 1000`), the
  `netlify/functions/_shared/refresh.mjs` module
  (`runRefresh` orchestrator: lock-check → acquire →
  build → write-on-success → release), the
  `netlify/functions/_shared/liveBuild.mjs` module
  (the CISA → NVD → EPSS pipeline extracted from the
  v5.0 / v5.0.1 / v5.0.2 / v5.0.3 dataset function —
  byte-identical upstream URLs, NVD_API_KEY header
  transport, 429 reason), the `dataset.mjs` blob-first
  read with the bootstrap path on a cold deploy
  (returns `dataSource: "prebuilt-store"` on a hit,
  `dataSource: "live-build"` on the bootstrap), the
  `refresh-dataset-background.mjs` Netlify Background
  Function (POSTed by the manual button, returns 202
  immediately, runs the build via `context.waitUntil`),
  the `refresh-dataset-scheduled.mjs` scheduled
  function (`*/30 * * * *` cron, same orchestrator),
  the `netlify.toml` cron registration, the
  `REFRESH_ENDPOINT_URL` constant + `manualRefresh()`
  function in `vulnerabilityService.ts`, the new
  `RefreshStatus` + `RefreshResult` + `PrebuiltDataSource`
  types, the new `dataSource` + `refreshInProgress`
  fields on `FetchResult`, the three new Header pills
  ("Dataset store: latest available" /
  "Dataset store: bootstrapping" / "Refresh running in
  background"), the "Last dataset build" tooltip
  wording, the `RefreshInProgressBanner` component in
  `DashboardPage.tsx` (info tone, Loader2 spinner,
  three messages: started / in-progress / failed,
  dismissible via ×), and the rewired manual button
  (`handleManualRefresh` calls `manualRefresh()`, NOT
  `fetchVulnerabilities({ forceRefresh: true })`). All
  guarded by tests in `scripts/acceptance-prebuilt.mjs`.

## Style notes

- Match the existing code style: Tailwind utility
  classes, 4-space-indent in TS, semicolons (existing
  code uses them — keep them), function declarations
  for components (`export default function X()`).
- Keep the tone of the existing `README.md` and
  `PROJECT_HANDOFF.md`: factual, no marketing fluff,
  explicit about what is and isn't included.
- Don't introduce new dependencies unless absolutely
  required. CISA, NVD, and EPSS can all be fetched with
  plain `fetch`; the current `package.json` is
  intentionally lean.
- The CISA KEV, NVD, and EPSS providers are the model
  for any new provider — copy their shape: an
  `AbortController` timeout, a typed raw-record
  interface, a `normalize*` function (where applicable),
  and a top-level `fetch*` function that throws on
  shape mismatch.
- For any new `localStorage` key, follow the v4 cache
  module's pattern: a versioned suffix (e.g. `:v1`),
  defensive try/catch around all access, schema
  validation on read, and silent no-op on quota /
  disabled-storage errors.

Good luck. v5.1 ships clean; the next milestone is
whatever the user explicitly picks.