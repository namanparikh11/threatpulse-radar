# PROJECT_HANDOFF

> End-of-session handover for **ThreatPulse Radar** v5.2.
> Last verified: this session (Pass 19 — prebuilt dataset
> store: shared Netlify Blobs `latest-dataset` envelope
> + 15-min `refresh-lock` + scheduled cron every 30 min +
> manual background-refresh endpoint; UI honesty via new
> "Dataset store: latest available" and "Refresh running
> in background" pills; the v5.1 soft-refresh banner is
> preserved end-to-end as the only way new data is
> surfaced to the user).
> Build clean. Acceptance tests green
> (**15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS + 53/53 v3 NVD +
> 60/60 v4 cache + 71/71 v5.0/v5.0.1/v5.0.2/v5.0.3 proxy +
> 58/58 v5.1 soft-refresh + 98/98 v5.2 prebuilt = 422/422**).
> Tree has uncommitted source changes on `main`.

---

## 1. Project status

**ThreatPulse Radar** is a frontend-only cybersecurity
vulnerability-intelligence dashboard built for **defensive** security
portfolio use. v3 is feature-complete at this milestone: the dashboard
fetches the public **CISA Known Exploited Vulnerabilities** feed at
runtime, enriches with NVD CVSS + FIRST EPSS, and falls back to the
curated mock dataset if the upstream fetch fails. v4 layers a
transparent 1-hour localStorage cache on top so a returning visitor
doesn't pay the 30–60 s NVD first-load on every page visit. v5.0
adds a single read-only Netlify Function that aggregates the same
three feeds server-side, so the browser no longer depends on direct
access to the third-party origins for the happy path. v5.0.1 adds
a CDN-cacheable function response (`Cache-Control: s-maxage=900,
stale-while-revalidate=300`) so repeat visitors in a region get
sub-100 ms responses within a 15 min window, while the
"Last refresh" pill and the "Refresh live data" button remain
source-honest. v5.0.2 adds NVD rate-limit hardening (serial chunks
when no key, parallel when `NVD_API_KEY` is set) and a concise
429 reason so the dashboard's `NvdUnavailableBanner` reads
cleanly when NVD rate-limits. v5.0.3 fixes the NVD API key
transport: the key is now passed as request header
`apiKey: <key>` per NVD's official CVE 2.0 spec (v5.0.2
incorrectly appended it to the URL query string). The key
is still server-side only. v5.1 adds soft refresh: a
silent 5-minute background poll detects newer upstream
data and surfaces a small "New dataset available.
Updated 2 min ago." banner with an explicit Apply update
button. Filters, search, sort, and the open detail view
are preserved across the apply; the drawer auto-closes
only if the selected CVE is no longer in the new dataset.
v5.2 layers a shared Netlify Blobs prebuilt dataset
store in front of the read endpoint: normal visitors
read the latest successfully-built dataset immediately,
without paying the upstream build on every page load.
The build is triggered by a Netlify scheduled function
(every 30 min) and by a manual Netlify Background
Function (POSTed by the dashboard's "Refresh live data"
button). Both writers share a 15-minute `refresh-lock`
blob so concurrent rebuilds are prevented. The store is
never overwritten with a mock fallback; only a
successful live build writes to it. The UI honesty
contract adds "Dataset store: latest available" +
"Refresh running in background" pills; the v5.1 banner
remains the only way new data is surfaced.

- **Stack:** React 18 + Vite 5 + TypeScript 5 (strict) + Tailwind CSS 3 +
  Recharts 2 + Lucide React icons + three Node 20 ESM Netlify
  Functions (`dataset.mjs`, `refresh-dataset-background.mjs`,
  `refresh-dataset-scheduled.mjs`) sharing three modules in
  `netlify/functions/_shared/` (`store.mjs`, `refresh.mjs`,
  `liveBuild.mjs`). The read endpoint serves a v5.0.1 CDN-cacheable
  response (now serving from the v5.2 prebuilt Blob when present),
  the v5.0.2 NVD rate-limit path and v5.0.3 request-header NVD
  API key transport are preserved, and the v5.1 soft-refresh
  polling + banner mechanism now also serves as the only path
  through which v5.2 background-refresh results reach the UI.
- **Backend:** three serverless functions plus a managed
  [Netlify Blobs](https://docs.netlify.com/build/data-and-storage/netlify-blobs/)
  store. The read endpoint is read-only and idempotent; the
  background and scheduled functions own the write path and
  share a 15-minute refresh-lock blob. **Auth:** none.
  **Database:** none (Blobs is a managed key/value store, not
  a database). **Payments:** none. **Exploit code:** none.
  **Live public-feed access:** the browser prefers the
  prebuilt Blob envelope served by the Netlify Function
  (CDN-cached) and falls back to the v4 browser-direct path
  on transport failure, then to the local mock dataset on
  total failure. **API keys:** one optional server-side env
  var (`NVD_API_KEY`, Netlify function scope only) for
  higher NVD throughput; never exposed to the browser; the
  app works identically without it.
- **Build:** `npm.cmd run build` passes clean (≈5.8 s this pass, 0 errors, 0 warnings). The v5.2 changes add ~3 kB to the main JS chunk (new manualRefresh handler + state slots + banner component + Loader2 icon). The CSS chunk gains ~0.5 kB for the new pill / banner styles. The icons chunk gains the new `Loader2` lucide-react icon.
- **Acceptance suites:** **15/15 v1** mock-data tests + **28/28 v2 CISA
  KEV tests** + **39/39 v2.5 EPSS tests** + **53/53 v3 NVD tests** +
  **60/60 v4 cache tests** + **71/71 v5.0/v5.0.1/v5.0.2/v5.0.3 proxy tests**
  + **58/58 v5.1 soft-refresh tests**
  + **98/98 v5.2 prebuilt-dataset tests**
  (`node scripts/acceptance.mjs && node scripts/acceptance-cisa.mjs && node scripts/acceptance-epss.mjs && node scripts/acceptance-nvd.mjs && node scripts/acceptance-cache.mjs && node scripts/acceptance-proxy.mjs && node scripts/acceptance-softrefresh.mjs && node scripts/acceptance-prebuilt.mjs`).
- **Repo:** `main` branch has uncommitted source changes from this
  session (Pass 19). An `origin` remote is configured at
  `https://github.com/namanparikh11/threatpulse-radar.git` (added in
  pass 5); nothing has been pushed since. Do not push without an
  explicit ask.
- **Deployment:** v5.2 is the Netlify deployment target (see
  [`DEPLOYMENT.md`](./DEPLOYMENT.md) section 0 for the v5.0
  Netlify workflow, section 0.7 for the v5.0.1 CDN-cache
  behavior, section 0.8 for the v5.0.2 / v5.0.3
  `NVD_API_KEY` configuration, and section 0.9 for the
  v5.2 prebuilt-dataset store + scheduled function +
  manual refresh endpoint + refresh lock).
  hosting (or any Apache-based `public_html` host). See
  [`DEPLOYMENT.md`](./DEPLOYMENT.md) for the guide.

---

## 2. What was completed in this session

The v1 dashboard was built across four implementation passes, then
two follow-up passes refreshed the handoff and completed the
Hostinger deployment prep, then v2 wired up CISA KEV live-data
integration, v2.1 fixed a pre-existing severity sort bug, v2.5
added FIRST EPSS enrichment, and v3 added NVD CVSS enrichment:

### Pass 1 — initial build
- Scaffolded Vite + React + TS project manually.
- Set up Tailwind with a dark cybersecurity palette (`tailwind.config.js`).
- Created 60-record mock dataset of realistic (fictional) CVEs spanning
  Microsoft, Cisco, Fortinet, Ivanti, Apache, Atlassian, Apple, Google,
  VMware, Linux, Open Source, Check Point, D-Link, JetBrains, ConnectWise,
  Fortra, etc.
- Built the full dashboard: stats cards, 4 charts, vulnerability table,
  filter panel, detail drawer, empty/loading/error states.
- Wrote `README.md` and the first `PROJECT_HANDOFF.md`.

### Pass 2 — filter / search / sort overhaul
- Diagnosed and fixed the bug where the table kept its own internal sort
  state that desynced from the page-level sort.
- Replaced the old sort with a unified `SortState = { field, direction }`.
- Expanded the search haystack to include `severity` and `source`.
- Added 12 explicit sort options to the dropdown.
- Built `useVulnerabilityFilter` custom hook as the single source of truth
  for the filter → sort pipeline.
- Added `useDebouncedValue` + `SearchStatus` (the "Searching current
  dataset…" / "X of Y results" indicator).
- Removed 3 duplicate CVE IDs (21626, 21893, 22245) and gave every
  record a unique `id`.
- Wrote `scripts/acceptance.mjs` — runnable test that exercises the
  filter / sort / data pipeline against the real mock data.

### Pass 3 — hero / header redesign (rich)
- Replaced the small sticky header with a premium hero: large logo, big
  bold title, full product subtitle, two badges, three color-coded
  status pills, dot-grid + soft-glow background, responsive layout.
- Added a thin top status strip with "Operational" + "Build v1.0".

### Pass 4 — final header refinement (public-portfolio cut)
- Removed the top status strip and the "Build v1.0 · local" line.
- No version numbers anywhere in the visible hero.
- The hero now contains *only*: logo, title, subtitle, 2 badges, 3 status
  pills. Quiet, professional, ship-ready.

### Pass 5 — handoff refresh
- Re-ran `npm.cmd run build`: 0 errors, 0 warnings, 5.72 s, identical
  output hashes to pass 4 (no source drift).
- Confirmed working tree is clean on `main` (commit `0097ee7` +
  earlier), `up to date with origin/main`.
- Added the GitHub `origin` remote (private repo, nothing pushed).
- Refreshed `PROJECT_HANDOFF.md` (this file) and `NEXT_AGENT_PROMPT.md`
  to capture the verified state and the still-pending deployment-prep
  task. No source code, hooks, or config were changed.

### Pass 6 — Hostinger deployment prep
- `vite.config.ts` — added `base: './'` so the built `index.html`
  references assets with **relative** URLs. Works for both subdomain
  and subpath deployment on Hostinger.
- `public/.htaccess` — new file, copied into `dist/` at build time.
  Provides: (1) SPA fallback rewrite, (2) 1-year cache for hashed
  assets + 0-second cache for the entry `index.html`,
  (3) standard security headers. CSP and HSTS are present but
  commented out (uncomment on HTTPS only).
- `DEPLOYMENT.md` — new file. The drop-in guide for Hostinger
  static hosting: which files to upload, where, how to handle
  subdomain vs subpath vs custom domain, the rationale for
  `base: './'`, and full troubleshooting (blank page, assets not
  loading, wrong folder, browser cache, mixed content, perms).
- Acceptance suite re-run: **13/13 still passing**.
- Build re-run: 0 errors, 0 warnings, 5.59 s. New `dist/index.html`
  now references assets as `./assets/...` and `./radar.svg`
  (relative).
- `dist/` is now drop-in deployable to Hostinger static hosting.

### Pass 7 — CISA KEV live-data integration
- New `src/services/providers/cisaKev.ts` — fetches the public
  [CISA KEV feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
  with an 8 s `AbortController` timeout, and normalizes every
  record into the existing `Vulnerability` shape. CISA doesn't
  provide CVSS or EPSS, so those default to `0` and the
  description carries a transparent note. Severity is derived
  from `knownRansomwareCampaignUse`: `Known` → `Critical`,
  otherwise `High`.
- `vulnerabilityService.ts` — replaced the v1 `USE_MOCK` boolean
  with a `DATA_MODE: 'live' | 'mock'` constant and added a
  `FetchMode = 'live' | 'mock' | 'fallback'` to `FetchResult`. In
  `'live'` mode, the service tries the CISA fetch and falls back
  to the mock dataset with `mode: 'fallback'` + a
  `fallbackReason` on any failure.
- `Header.tsx` — same layout, dynamic labels. The header now shows
  one of: `Live CISA KEV Mode` (cyan badge) /
  `Mock Data Mode` (amber badge) / `Fallback Mode` (amber
  badge), and the source pill reads `Source: CISA KEV` /
  `Source: mock` / `Source: mock (fallback)`.
- `DashboardPage.tsx` — new `<FallbackBanner />` above the stats
  when `mode === 'fallback'`. Shows the failure reason and a
  "Retry live fetch" button.
- `scripts/acceptance-cisa.mjs` — new 27-test acceptance suite for
  the CISA integration. The v1 13-test script is untouched and
  still passes.
- `README.md`, `NEXT_AGENT_PROMPT.md` — updated to reflect v2.
- Build re-run: 0 errors, 0 warnings, 4.57 s. Asset hashes
  changed (CISA code is now in the bundle).
- Acceptance: **13/13 v1 + 27/27 v2 CISA = 40/40**.

### Pass 8 — severity sort direction fix
- `src/utils/analytics.ts` — one-line change in `compareByField`'s
  `case 'severity':` branch. The comparator was `(rank_a - rank_b)`
  (natural "ascending": Low first) which then got flipped by the
  `direction` factor to put High before Critical for `desc` — the
  opposite of what the dropdown label "Severity: high to low"
  promises. Flipped to `(rank_b - rank_a)` so the natural order
  is "most severe first" and the existing factor logic produces
  the correct `desc` and `asc` results. **No other code paths
  changed.**
- `scripts/acceptance.mjs` — JS mirror updated in lockstep; added
  2 new tests (`Severity high-to-low: Critical, High, Medium, Low`
  and `Severity low-to-high: Low, Medium, High, Critical`). v1
  suite is now 15/15.
- `scripts/acceptance-cisa.mjs` — JS mirror updated; the previously
  deliberately-weak "sort runs deterministically" test is now
  replaced with two strong tests asserting the correct order on
  CISA records (`desc` puts Critical first, `asc` puts Critical
  last). v2 CISA suite is now 28/28.
- Build re-run: 0 errors, 0 warnings, 5.25 s. App-chunk hash
  changed (`CFc8jTCu` → `BZKj2KNS`); all other chunks unchanged
  — confirms this was a true one-line change.
- Acceptance: **15/15 v1 + 28/28 v2 CISA = 43/43**.

### Pass 9 — FIRST EPSS enrichment
- New `src/services/providers/epss.ts` — fetches EPSS scores for
  the CISA CVE IDs in batched requests of 100 each (parallel),
  with an 8 s `AbortController` timeout per request. Exposes
  `fetchEpssForCves(cveIds) → Map<cveId, { epss, percentile }>`
  and a pure `enrichWithEpss(records, map)` that fills
  `epssProbability` without mutating the input. CVEs absent from
  the FIRST response keep `epssProbability: 0` (no fabrication).
- `vulnerabilityService.ts` — orchestrates CISA → EPSS. On CISA
  success, fetches EPSS and enriches. On EPSS failure, returns
  the CISA data with `epssStatus: 'unavailable'` and a
  `fallbackReason`. `FetchResult` gains two optional fields:
  `epssStatus?: 'first' | 'unavailable'` and
  `fallbackReason?: string`. On full success, `source: 'merged'`,
  `mode: 'live'`, `epssStatus: 'first'`. On CISA failure,
  unchanged v2 behavior: `mode: 'fallback'`, mock data.
- `Header.tsx` — when `epssStatus === 'first'`, source pill
  reads "Source: CISA KEV + FIRST EPSS" and a new cyan
  `EPSS: FIRST` pill appears. When `epssStatus === 'unavailable'`,
  source pill stays "Source: CISA KEV" and a warn-tone
  `EPSS: unavailable` pill appears with the reason in its
  tooltip. Header layout unchanged otherwise.
- `DashboardPage.tsx` — new `<EpssUnavailableBanner />` shown
  above the stats when `mode === 'live'` and
  `epssStatus === 'unavailable'`. Smaller and softer than the
  full CISA fallback banner; no retry button (next page load
  retries automatically).
- `scripts/acceptance-epss.mjs` — new 39-test acceptance suite for
  the EPSS integration. The v1 15-test script and the v2 28-test
  CISA script are untouched and still pass.
- `README.md`, `NEXT_AGENT_PROMPT.md` — updated to reflect v2.5.
- Build re-run: 0 errors, 0 warnings, 4.23 s. App chunk grew
  by ~3 kB raw / ~1 kB gzipped (EPSS provider + UI bits).
- Acceptance: **15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS = 82/82**.

### Pass 10 — NVD CVSS enrichment
- New `src/services/providers/nvd.ts` — fetches the official
  [NVD CVE 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0)
  feed for the CISA CVE IDs in batched requests of 100 each
  (parallel), with an 8 s `AbortController` timeout per request.
  Exposes `fetchNvdForCves(cveIds) → Map<cveId, { cvssScore, severity }>`
  and a pure `enrichWithNvd(records, map)` that fills
  `cvssScore` and `severity` without mutating the input. CVEs
  absent from NVD's response keep `cvssScore: 0` (no fabrication).
  Score extraction prefers v3.1, then v3.0, then v2; severity
  comes from NVD's `baseSeverity` when present, otherwise from
  `baseScore` (>=9 Critical, >=7 High, >=4 Medium, else Low).
- `vulnerabilityService.ts` — orchestrates the full live chain:
  `CISA → (ok) → NVD → (ok) → FIRST EPSS → enrich → merged`.
  CISA still gates everything. Each secondary provider has its
  own status field; one failing does NOT degrade the whole page.
  `FetchResult` gains `nvdStatus?: 'nvd' | 'unavailable'` and
  `nvdReason?: string` (parallel to the existing EPSS fields).
- `Header.tsx` — new `NVD: enriched` (cyan) / `NVD: unavailable`
  (amber) pills. Source label now reads "Source: CISA KEV + NVD
  + FIRST EPSS" when NVD loaded, falls back to "… + FIRST EPSS"
  when NVD unavailable. Header layout unchanged otherwise.
- `DashboardPage.tsx` — new `<NvdUnavailableBanner />` above the
  stats when `mode === 'live'` and `nvdStatus === 'unavailable'`.
  Same soft style as `EpssUnavailableBanner`; no retry button.
  Footer text updated to mention CISA + NVD + EPSS.
- `cisaKev.ts` — the per-record description note was updated.
  The old note "…populated when NVD / FIRST EPSS are wired in"
  is now stale (they are), so the note now honestly states
  "…may enrich them from NVD and FIRST EPSS when those services
  are reachable" — true regardless of whether enrichment
  actually happens on a given load.
- `scripts/acceptance-nvd.mjs` — new 52-test acceptance suite
  for the NVD integration. v1 / CISA / EPSS scripts unchanged
  and still pass. Test count total: **134/134** across 4 suites.
- `README.md`, `NEXT_AGENT_PROMPT.md` — updated to reflect v3.
- Build re-run: 0 errors, 0 warnings, ~6.1 s. App chunk grew by
  ~3.7 kB raw / ~0.7 kB gzipped (NVD provider + UI bits).
- Acceptance: **15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS + 52/52 v3 NVD = 134/134**.

### Pass 11 — v3 QA / portfolio-demo hardening
- **QA review** — read every component, the service flow end-to-end,
  the chart components, the filter hook, and the styling. Two
  real issues found, both honesty-related.
- **Fix #1: honest source label in `Header.tsx`.** The
  `describeSource` function only checked `nvdStatus` and
  always said "CISA KEV + NVD + FIRST EPSS" when NVD loaded —
  even when EPSS didn't. The function now builds the label
  from both `nvdStatus` and `epssStatus` (only mentions a
  provider if its pill isn't amber). The amber "unavailable"
  pills remain — the label is now consistent with them.
- **Fix #2: honest `LoadingState` message.** The first-load
  copy was "Loading threat intelligence…" which undersells
  the multi-source fetch. NVD's 5-req/30s rate limit means the
  first live load can take 30–60 s. The message now reads:
  "Loading CISA KEV · NVD CVSS · FIRST EPSS — may take up to a
  minute on first load…". First-time portfolio visitors now
  know what's happening.
- **Test for the honesty fix.** `scripts/acceptance-nvd.mjs`
  grew by 1 test (now 53/53). It reads the `Header.tsx` source,
  locates the `describeSource` function body, and asserts that
  `epssStatus` is checked (so future regressions to the v2
  behavior of always-claiming-EPSS-loaded are caught).
- **`PORTFOLIO_WRITEUP.md`** — new file. ~3 pages, written
  for a recruiter or technical interviewer who has 5–30
  minutes. Covers: what the project is, why it exists, five
  engineering decisions worth talking about in an
  interview, and an honest list of trade-offs.
- **No new features.** No new dependencies. No UI redesign.
  No data architecture changes (the two fixes are
  presentation-layer / copy fixes only).
- **README review:** confirmed the README reflects v3.0
  correctly. Did not modify — the README was already updated
  in the v3 pass and is current.
- Build re-run: 0 errors, 0 warnings, 6.34 s. App chunk hash
  changed (presentation changes only); all other chunks
  identical.
- Acceptance: **15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS + 53/53 v3 NVD = 135/135**.

### Pass 12 — v4 transparent cache layer ← *current*
- **Motivation.** A portfolio visitor who comes back to the page
  within an hour currently pays the full 30–60 s NVD first-load
  again. That's a real friction point on a public demo. The
  user-visible gap was also a "Last refreshed" pill in the
  header that showed only a relative time, and no clear answer
  to "is what I'm looking at live data, partial enrichment,
  fallback mock, or cached?"
- **`src/services/datasetCache.ts`** — new module. Versioned
  localStorage key (`tpr:dataset:v1`), 1-hour TTL
  (`CACHE_TTL_MS = 60 * 60 * 1000`), defensive try/catch around
  all `localStorage` access (private mode / quota / disabled
  storage can never crash the dashboard). Helpers:
  `readCache()`, `writeCache()`, `clearCache()`,
  `isCacheFresh(cachedAt)`, `getCacheAgeMs(cachedAt)`,
  `formatAgeShort(ms)`. Cache envelope = full `FetchResult`
  so provider-status fields survive the round-trip.
- **`vulnerabilityService.ts`** refactor + cache wiring.
  - New `CacheStatus = 'miss' | 'fresh' | 'stale'` type, new
    optional `cacheStatus?: CacheStatus` on `FetchResult`, new
    `forceRefresh?: boolean` on `VulnerabilityQuery`.
  - Extracted the live fetch into a helper `tryLiveFetch()` that
    returns `null` on CISA failure (the only gating upstream).
    The cached fall-through and the cache-miss path both call
    it, eliminating the duplicated fallback-handling code that
    existed in v3.
  - Three cache states, three observable behaviors:
    - `fresh` — cache hit, in TTL. Returns immediately, no
      live fetch.
    - `stale` — cache hit, past TTL, live fetch failed. Returns
      the cached FetchResult with `cacheStatus: 'stale'`. The
      header pill turns amber and the dashboard banner explains
      "live fetch failed; showing last-known real data".
    - `miss` — cache miss (or `forceRefresh: true`). Runs the
      live path; on success writes through to the cache.
  - Mock-mode path is unchanged (no cache, no upstream).
- **`Header.tsx`** — new "Cache: fresh" (cyan) and "Cache: stale"
  (amber) pills parallel to the existing NVD / EPSS pills. The
  "Last refresh" tooltip now shows the absolute timestamp via a
  new `formatAbsolute()` helper in `src/utils/format.ts`, so a
  hover on "Last refresh: 5m ago" reveals the full ISO date.
- **`DashboardPage.tsx`** — new `CachedDataBanner` rendered
  above the provider-failure banners whenever
  `cacheStatus === 'fresh'` or `'stale'`. It shows both the
  relative and absolute time of the original upstream fetch and
  exposes a "Refresh live data" button wired to a new
  `handleRefresh()` that calls
  `fetchVulnerabilities({ forceRefresh: true })`. The banner
  copy distinguishes fresh vs stale, and the cached
  `FetchResult`'s `nvdStatus`/`epssStatus`/`fallbackReason`
  fields are preserved so the existing provider-failure banners
  keep rendering on cached data — the cache never hides
  failures.
- **`scripts/acceptance-cache.mjs`** — new 60-test acceptance
  suite covering: pure-helper edge cases (TTL boundary, clock-
  skew tolerance, `formatAgeShort` boundaries), envelope
  round-trip + JSON serialization + provider-failure
  preservation, and source-level wiring for every public surface
  (cache module, service imports, `CacheStatus` type, cache-
  before-fetch ordering, fresh/stale code paths, `forceRefresh`
  bypass, header pill rendering, dashboard banner + Refresh
  button, absolute-time tooltip, provider-failure-banner
  preservation on cached data).
- **Test fix.** `scripts/acceptance-cisa.mjs`'s source-level
  regex for the fallback path was looking for an inline
  `catch → mode:'fallback'` pattern, which the
  `tryLiveFetch()` refactor moved into a helper. Updated the
  regex to accept either pattern (inline catch OR
  helper-returns-null + caller constructs `mode: 'fallback'`).
  Behavior unchanged; assertion now refactor-tolerant.
- **Docs.** README "Features" / "Data sources" / "Project
  structure" / "Roadmap" all updated to reflect v4. Version
  badge bumped to `v4.0-22d3ee`. This handoff is updated.
- **No new dependencies.** Bundle delta: app chunk +0.4 kB
  raw (negligible). No CSS change.
- Build re-run: 0 errors, 0 warnings, 7.51 s. All chunks
  rebuild cleanly.
- Acceptance: **15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS +
  53/53 v3 NVD + 60/60 v4 cache = 195/195**.

### Pass 13 — v4.1 public-demo honesty hardening ← *current*
- **Motivation.** The v4 pass shipped a working live dashboard,
  but the README / portfolio writeup / deployment guide were
  slightly *too optimistic* about CORS — they claimed "all
  three APIs serve permissive CORS" as if that were a
  guarantee. For a static public deployment that's not true:
  any third-party feed can tighten its CORS policy, rate-limit
  anonymous browser traffic, return 4xx from a particular
  region, or simply be down. v4.1 makes the public-demo
  documentation source-honest about that, without changing a
  single line of app code.
- **README.md**
  - Version badge bumped from `v4.0` to `v4.1`.
  - "Tech stack → Data sources" paragraph rewritten: the
    "all three APIs serve permissive CORS" claim is removed
    entirely. The new paragraph states that ThreatPulse
    Radar reads public feeds directly from the browser
    *when available*, that third-party feeds may block
    direct browser requests in a static public demo (CORS,
    rate limits, geo, outages), and that the UI shows the
    failure transparently and falls back only according to
    the documented rules. Explicitly notes that no API
    keys, secrets, or tokens are ever embedded in the
    frontend bundle. Points readers to the new V4.1
    section.
  - **New section: "🌐 V4.1 public-demo honesty"** between
    "Data sources" and "Roadmap". Six numbered points:
    (1) the dashboard is frontend-only and defensive-only,
    (2) the static public demo may show fallback / mock mode
    when a feed blocks direct browser requests, and this is
    expected for v4.1, (3) the UI is intentionally transparent
    about it (header pills, source label, partial-failure
    pills, cache pill + banner), (4) the app never hides
    provider failures, (5) no API keys are ever embedded in
    the frontend bundle, (6) a future v5 could add a thin
    backend or serverless proxy — v4.1 explicitly does *not*
    add it.
  - Roadmap v4 entry expanded into two: v4 (cache) and v4.1
    (public-demo honesty hardening — this release).
- **PORTFOLIO_WRITEUP.md**
  - **New engineering-decision item: "7. V4.1 — The public
    demo is source-honest about static deployment and CORS"**
    added after the cache section. Same six points as the
    README, framed for a recruiter / technical interviewer
    audience.
  - "What I would do differently next time" updated: the
    old "future pass could plumb an NVD API key for a 10×
    rate-limit bump" line is removed (that path is closed in
    v4.1) and replaced with a v5 backend / serverless-proxy
    framing. The "no API keys in the frontend bundle"
    stance is stated explicitly.
- **DEPLOYMENT.md**
  - **New section 10: "V4.1 public-demo honesty (what
    visitors will actually see)"** added at the end. Walks
    through the three honest degradation paths (CISA
    unreachable, NVD / EPSS unreachable, cached data) and
    restates the no-API-keys-in-bundle and v5-backend
    rules. The existing deployment strategy in sections
    1–9 is **unchanged**.
- **PROJECT_HANDOFF.md (this file)**
  - Header bumped from v4.0 to v4.1.
  - This Pass 13 entry added after Pass 12.
  - Milestone table updated with a v4.1 row (see section 9
    below).
- **No app code changed.** No new dependencies. No UI
  changes. No data-flow changes. No new features. No backend
  or serverless function added. No API keys introduced. No
  deployment strategy overwritten. The cache, the providers,
  the header, the dashboard page, the filter / sort pipeline,
  and the `acceptance-*.mjs` test suites are all untouched.
- **Build re-run**: 0 errors, 0 warnings. (Docs are not in
  the build, but the build was re-run to confirm no source
  drift was introduced.)
- **Acceptance**: **195/195** still green (the test suites
  were not modified and were not re-run, since no source
  files changed).

### Pass 14 — v5.0 Netlify Function live proxy ← *current*

- **Motivation.** The v4.1 docs are source-honest about a
  real problem the public demo hits: a static deployment
  depends on the upstream feeds (CISA, NVD, FIRST EPSS)
  continuing to allow direct browser requests. CORS, rate
  limits, geo restrictions, and upstream outages can each
  put the dashboard into fallback / mock mode. v5.0 adds a
  thin serverless proxy so the browser only ever hits the
  project's own origin. CISA + NVD + EPSS are aggregated
  server-side; the function returns a single CORS-safe
  JSON envelope.

- **Architecture.**
  ```
  Browser ──► /.netlify/functions/dataset (Netlify Function)
                                          │
                                          ├── CISA KEV
                                          ├── NVD CVE 2.0
                                          └── FIRST EPSS
        (proxy failure only)
        ──► browser-direct CISA / NVD / EPSS (v4 path)
        (total failure only)
        ──► local mock dataset (Fallback Mode)
  ```

- **`netlify/functions/dataset.mjs`** — new file. A
  self-contained Node 20 ESM module (no imports from
  `src/`, no dependencies). Re-implements the CISA → NVD
  → EPSS pipeline with the same field shapes and
  normalization rules as the browser-side providers in
  `src/services/providers/`. Returns a JSON envelope
  identical in shape to the client-side `FetchResult`:
  - `200` on success with
    `{ data, source: 'merged', mode: 'live', fetchedAt,
       nvdStatus, nvdReason, epssStatus, epssReason }`.
    Partial NVD or EPSS failure still returns 200 with
    `nvdStatus: 'unavailable'` / `epssStatus: 'unavailable'`.
  - `502` when CISA itself failed, with
    `{ mode: 'fallback', fallbackReason }`. The client
    treats this as a proxy failure and falls through to
    browser-direct.
  - 8 s per-request timeout (matches the browser-side
    providers), 24 s overall budget (safety margin under
    Netlify's 26 s default async-function limit).
  - `Cache-Control: no-store` on responses (the dashboard
    already has its own 1 h localStorage cache).
  - `Access-Control-Allow-Origin: *` for the rare
    iframe-embed case.
  - **No API keys, no env vars, no persistent state.**

- **`netlify.toml`** — new file. Wires the function
  directory, the Vite build, the static publish, and the
  `node_bundler = "none"` setting that lets the function
  run as plain ESM without an esbuild step. Also adds
  per-asset cache headers and standard security headers
  for the static `dist/` (mirrors the Hostinger
  `.htaccess` rules for parity).

- **`src/services/vulnerabilityService.ts`** — extended.
  - New `ProxyStatus = 'proxy' | 'browser-direct' |
    'unavailable'` type. New optional `proxyStatus?` field
    on `FetchResult`. The field is set on every live
    fetch (proxy, browser-direct, or total-failure) so
    the UI is always honest about which transport carried
    the data.
  - New `tryProxyFetch()` calls
    `fetch(DATASET_PROXY_URL)`. On any failure (network,
    non-2xx, shape mismatch, timeout) it returns `null`.
  - The existing `tryLiveFetch()` is now a wrapper that
    tries `tryProxyFetch()` first and falls back to
    `tryBrowserDirectFetch()` (the v4 path, renamed for
    clarity) on proxy failure. The v4 cache test
    invariant (the test regex still matches `tryLiveFetch`
    as a function name in the source) is preserved.
  - `DATASET_PROXY_URL` defaults to
    `/.netlify/functions/dataset`; can be overridden by
    `VITE_DATASET_PROXY_URL` at build time for local
    `netlify dev` or alternate deployments.
  - The mock-fallback path now sets
    `proxyStatus: 'unavailable'` so the UI can distinguish
    "no live data attempted" from "live data attempted
    but every transport failed".

- **`src/components/Header.tsx`** — small additive change.
  A new cyan "Proxy: Netlify" pill (with a Cloud icon)
  appears in the header status column when
  `proxyStatus === 'proxy'`. No new pill is rendered
  when the proxy is unavailable or the browser-direct
  path was used — the source label and the existing
  Fallback banner already cover those cases.

- **`src/vite-env.d.ts`** — new file. Adds the
  `/// <reference types="vite/client" />` triple-slash
  so `import.meta.env.VITE_DATASET_PROXY_URL` is
  TypeScript-typed. This was the only TS error during
  the v5.0 build; no other type changes.

- **`scripts/acceptance-proxy.mjs`** — new 45-test
  suite. Covers:
  - the Netlify Function file exists and is a Node ESM
    module with the right upstream URLs and timeouts;
  - the function returns the FetchResult-shaped JSON
    contract (200 on success, 502 on CISA fail);
  - the function does NOT add new sources, read any
    API key, or fabricate CVSS / EPSS scores;
  - `netlify.toml` wires the functions directory with
    `node_bundler = "none"`;
  - the frontend service exposes `ProxyStatus`, sets
    `proxyStatus` on every live-fetch branch, and
    prefers the proxy before browser-direct;
  - the Header renders the "Proxy: Netlify" pill in
    info tone (cyan);
  - the URLs and severity rules in the function
    *mirror* the browser-side providers — so the
    two transports are guaranteed to produce
    interchangeable data;
  - all v4 cache / fallback invariants are preserved
    through v5 (no leaks, no missing pieces).

- **Acceptance**:
  **15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS +
  53/53 v3 NVD + 60/60 v4 cache + 45/45 v5 proxy =
  240/240**.

- **Build**: 0 errors, 0 warnings, 7.68 s. Bundle
  deltas vs v4.1: `index-*.js` app chunk +0.96 kB
  (proxy orchestration), `icons-*.js` +0.29 kB (Cloud
  icon), `index-*.css` +0.28 kB (pill styles). All
  other chunks unchanged. No new dependencies in
  `package.json`.

- **Docs.** README "Features" / "Tech stack" / "Project
  structure" / "Roadmap" all updated to reflect v5.0.
  A new "⚡ V5.0 live proxy mode" section added between
  the v4.1 honesty section and the Roadmap, with the
  full architecture, the proxy-first orchestration rules,
  the v4 invariants that are preserved, the explicit
  "v5.0 does *not* add" list, and the local-dev note
  about `netlify dev`. `DEPLOYMENT.md` is now
  Netlify-first (sections 0.1–0.6 document the v5.0
  deploy end-to-end; the existing Hostinger sections
  1–9 are preserved as a fallback). The "Run it
  locally" section in the README now documents
  `netlify dev` alongside `npm run dev`.

- **No new dependencies** added to `package.json`.
  The function uses only Node 20 built-ins
  (`fetch`, `AbortController`, `Response`).
  `netlify-cli` is documented as a dev dependency for
  local testing but is not required to build or run
  the dashboard.

- **What v5.0 does *not* add (deliberate, per the
  v4.1 docs contract):**
  - No API keys, secrets, or tokens are read or
    shipped.
  - No new data sources. OSV.dev / GHSA / other
    aggregators remain a v5.1+ milestone.
  - No scheduled / background functions. The dataset
    function runs on demand per request.
  - No database, no auth, no login. The function is
    read-only and idempotent.
  - No UI redesign. The v4.1 header, dashboard,
    table, filters, and detail drawer are unchanged.
    The only new visible element is the small
    "Proxy: Netlify" pill in the header.
  - No offensive / exploit functionality. The
    v1 / v2 / v3 defensive-only contract is preserved.

### Pass 15 — v5.0.1 performance hardening ← *current*

- **Motivation.** The v5.0 function returned
  `Cache-Control: no-store` on every response. Netlify's
  edge cache respected that and re-ran the full
  CISA → NVD → EPSS pipeline on every request — even if
  the same visitor reloaded five times in a minute. On a
  busy public demo that meant dozens of unnecessary
  upstream fetches per minute per region, and a cold first
  load for every visitor in every region. v5.0.1 adds a
  short, safe, source-honest CDN cache so the second-and-
  onwards visitors within a 15 min window get a sub-100 ms
  response.

- **Root cause (confirmed by reading the code).**
  - localStorage cache **is** being written under
    `tpr:dataset:v1` (`writeCache(live)` at the end of a
    successful live fetch).
  - Second reload within 1 h **does** render from
    localStorage cache (`if (cached && isCacheFresh(...))`
    is the first branch in `fetchVulnerabilities`).
  - The function **was** using
    `Cache-Control: no-store`. **This was the root cause**
    of repeated slow loads.

- **`netlify/functions/dataset.mjs`** — one line of
  effective change. The `jsonResponse` helper now returns
  `Cache-Control: public, s-maxage=900, stale-while-revalidate=300`
  instead of `Cache-Control: no-store`. Detailed comment
  block added explaining:
  - `s-maxage=900` → 15 min CDN cache (repeat visitors
    within the window get <100 ms responses).
  - `stale-while-revalidate=300` → after the 15 min
    mark, the cache is "stale" for another 5 minutes;
    Netlify serves the stale response immediately AND
    triggers a background refresh. This avoids the
    "thundering herd" problem.
  - No `max-age` directive — the browser is not told to
    cache the JSON locally (the client uses
    `cache: 'no-store'` on its fetch anyway). The
    `s-maxage` directive is what Netlify's edge honors.
  - The function's `fetchedAt` is set inside the function
    body at the moment it actually runs, NOT when the
    CDN serves the response. The "Last refresh" pill
    therefore shows the time since the *real* upstream
    fetch, even on CDN-cached responses.

- **`src/services/vulnerabilityService.ts`** — minimal
  additive change. `tryProxyFetch` now accepts an
  `opts: { forceRefresh?: boolean }` parameter; when
  `forceRefresh` is true, the URL gets a unique
  `?t=${Date.now()}` query string. The CDN treats this
  as a different URL and re-runs the function, honoring
  the "Refresh live data" button's contract. `tryLiveFetch`
  and `fetchVulnerabilities` thread the option through.
  No new types, no new env vars, no UI changes.

- **Honesty contract (preserved):**
  - The function's `fetchedAt` is set inside the function
    body. The dashboard's "Last refresh" pill
    (`formatRelative(meta.fetchedAt)`) shows the time
    since the actual upstream fetch, NOT the time the
    CDN served the response. **A CDN-cached response is
    never advertised as a fresh fetch.**
  - The "Refresh live data" button appends a unique
    `?t=<timestamp>` query string when `forceRefresh: true`
    is passed. The CDN treats this as a different URL and
    does NOT hit its cache — a manual refresh always
    re-runs the function. The button's name remains
    honest.
  - The localStorage cache (v4) is unchanged. The two
    layers compose: a 15 min CDN cache + a 1 h
    localStorage cache + the in-memory `cacheStatus`
    pill. No layer hides the others.
  - The provider-status banners (NVD unavailable, EPSS
    unavailable, Fallback Mode) survive every layer and
    are still rendered on cached data. The cache
    envelope preserves the full `FetchResult`.

- **Test fix in `scripts/acceptance-nvd.mjs`.** Two NVD
  tests (`header source label mentions NVD when
  nvdStatus="nvd"` and `Header source label reflects
  BOTH nvdStatus and epssStatus`) were using
  `indexOf('\n}\n', fnStart)` to find the closing brace
  of `describeSource` in `Header.tsx`. This was failing
  on Windows where `Header.tsx` has CRLF line endings
  (the indexOf never matched `\n}\n` because the actual
  bytes are `}\r\n`). Replaced with a regex match
  (`/\n\s*\}\s*\n/`) that works on both LF and CRLF. No
  production code changed.

- **`scripts/acceptance-proxy.mjs`** — 9 new
  v5.0.1-specific assertions added (proxy suite is now
  55/55, up from 45/45 in v5.0). New section
  "v5.0.1 — CDN cache headers + forceRefresh cache-busting":
  - function sets CDN-cacheable Cache-Control with
    `s-maxage=900` and `stale-while-revalidate=300`
  - function response does NOT use the v5.0 no-store
    directive
  - `tryProxyFetch` accepts a `forceRefresh` option
  - `tryProxyFetch` appends a cache-busting
    `?t=<timestamp>` on `forceRefresh`
  - `tryLiveFetch` accepts `forceRefresh` in its
    signature
  - `tryLiveFetch` forwards `opts` to `tryProxyFetch`
  - `fetchVulnerabilities` forwards `forceRefresh` to
    `tryLiveFetch`
  - no `max-age` directive is set (CDN-only caching,
    not browser caching)
  - existing `tryProxyFetch` test for catch-null behavior
    still passes (slice size increased from 4000 to 6000
    chars to accommodate the longer v5.0.1 function body)

- **Build**: 0 errors, 0 warnings, 5.80 s. App chunk
  hash changed (`CRAMVlaT` → `CIyVmlOq`); all other
  chunks are byte-identical to v5.0. App chunk grew by
  0.08 kB raw / 0.02 kB gzipped for the cache-busting
  logic. No CSS or icon change.

- **Acceptance**:
  **15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS +
  53/53 v3 NVD + 60/60 v4 cache + 55/55 v5/v5.0.1
  proxy = 250/250**.

- **No new dependencies.** No `package.json` change.
  The function uses only Node 20 built-ins. The client
  uses only the existing stack.

- **What v5.0.1 does *not* add (deliberate, per the
  v4.1 / v5.0 docs contract):**
  - No new data sources. OSV.dev / GHSA / other
    aggregators remain a v5.1+ milestone.
  - No API keys, secrets, or tokens are read or shipped.
  - No new environment variables.
  - No scheduled / background functions. The
    `stale-while-revalidate` directive is a CDN-layer
    mechanism, not a function scheduled job.
  - No UI redesign.
  - No offensive / exploit functionality.
  - No new fake freshness claims. A CDN-cached
    response is not advertised as a fresh fetch.

### Pass 16 — v5.0.2 NVD rate-limit hardening ← *current*

- **Motivation.** NVD's anonymous public endpoint allows
  only 5 requests / 30 s. The v5.0 / v5.0.1 function fired
  all 10 NVD chunks (one per 100 CVEs) in parallel via
  `Promise.allSettled` — guaranteed to hit HTTP 429 on the
  first hit in every region. The function then produced a
  long repeated error string ("HTTP 429 Too Many Requests;
  HTTP 429 Too Many Requests; ...") which the
  `NvdUnavailableBanner` displayed verbatim, spilling past
  the banner boundary and making the public demo look
  broken. v5.0.2 fixes both: it serializes chunks when no
  API key is present, and it returns a single concise
  reason when NVD rate-limits.

- **`netlify/functions/dataset.mjs`** — three small changes
  in the NVD path only:
  1. New `settledAll(tasks, concurrency)` helper — a
     small Promise.allSettled-shaped runner with a hard
     concurrency limit. Used by `fetchNvdForCves` to run
     chunks serially (`concurrency = 1`) or in parallel
     (`concurrency = chunks.length`) without duplicating
     the allSettled wiring.
  2. `fetchNvdForCves` now reads
     `process.env.NVD_API_KEY` at function runtime. If
     the key is present, the function uses parallel
     chunks; if absent, the function uses serial
     chunks. The key is passed into `fetchOneNvdChunk`
     and sent to NVD as a request header `apiKey: <key>`
     (v5.0.3 — NVD's official CVE 2.0 spec uses the
     `apiKey` request header, not a URL query parameter).
     The key is **never** sent in the response
     body, **never** logged, **never** exposed to the
     browser.
  3. `fetchOneNvdChunk` accepts an optional `apiKey`
     parameter. If set, it sets `headers.apiKey = apiKey` on
     the request to NVD. The URL is unchanged; only the
     headers object gains the key when present.
  4. The `fetchNvdForCves` "all chunks failed" error
     path now detects 429 specifically: if every failed
     chunk is `HTTP 429`, the function throws a single
     concise reason ("NVD rate limit reached (HTTP 429).
     NVD CVSS enrichment is unavailable; severity falls
     back to CISA-derived values for this refresh.")
     instead of joining N repeated chunk errors. For
     non-429 failures, the chunk errors are de-duplicated
     via `Array.from(new Set(reasons))` so the banner
     doesn't show "HTTP 503; HTTP 503; HTTP 503" either.

- **Frontend is unchanged.** No new env var, no new
  provider, no UI change, no FetchResult shape change,
  no new pill / banner / cache layer. The v4
  `NvdUnavailableBanner` in `DashboardPage.tsx`
  continues to render the function's `nvdReason` field
  verbatim. The concise reason string is what the user
  sees.

- **Honesty guarantees (preserved):**
  - The function's `fetchedAt` is still set inside the
    function body. The dashboard's "Last refresh" pill
    reflects when the function *actually* ran. The
    v5.0.1 `?t=<timestamp>` cache-buster on "Refresh
    live data" still forces a real function run.
  - The function response never contains the API key.
    Asserted by `acceptance-proxy.mjs` (the new
    `v5.0.2: function never puts NVD_API_KEY in the
    response body` test reads the `jsonResponse` helper
    and asserts no `NVD_API_KEY` substring is present).
  - Provider-status banners are preserved on cached
    data and on key-less deployments. A 429 with no key
    renders as "NVD: unavailable" with the concise
    reason; a successful NVD call with a key renders as
    "NVD: enriched" with no rate-limit copy.
  - The dashboard never claims NVD is enriched when it
    is unavailable — the `nvdStatus` field is the source
    of truth, and the banner only renders when
    `nvdStatus === 'unavailable'`.

- **`scripts/acceptance-proxy.mjs`** — 13 new
  v5.0.2-specific assertions added (proxy suite is now
  68/68, up from 55/55 in v5.0.1). New section
  "v5.0.2 — NVD rate-limit hardening + optional server-
  only NVD_API_KEY":
  - function reads `NVD_API_KEY` from `process.env`
    (server-side only)
  - function never puts `NVD_API_KEY` in the response
    body
  - function passes apiKey as a request header
    (`apiKey: <key>`) to NVD when set (v5.0.3 — was a
    URL query parameter in v5.0.2)
  - function uses serial chunk fetch (concurrency = 1)
    without `NVD_API_KEY`
  - function uses parallel chunk fetch with
    `NVD_API_KEY`
  - function includes a small `settledAll` concurrency
    helper
  - function returns a concise 429 reason (not repeated
    chunk errors)
  - 429 reason mentions severity fallback to
    CISA-derived values
  - non-429 chunk errors are de-duplicated in the error
    message
  - v5.0.1 CDN cache headers are preserved
  - v5.0.1 `forceRefresh` cache-busting (`?t=<timestamp>`)
    is preserved (in the client service, not the
    function)
  - v5.0.1 `no-store` removal is preserved
  - no new build-time env vars are required for the
    frontend
  - `NVD_API_KEY` is a runtime server-side env var
    (not exposed to the browser)

  - **Two v5.0-era tests updated** (the spirit of the
    tests is preserved, but the strict v5.0 "no env
    vars" assertion is replaced with a v5.0.2 "only
    NVD_API_KEY, server-side, optional" assertion):
    - "function does NOT read any API key / secret /
      env credential" → "v5.0.2: function reads ONLY
      the documented optional NVD_API_KEY env var (no
      others)"
    - "No new environment variables are required at
      build time" → "v5.0.2: no new build-time env
      vars are required for the frontend" + a new
      test asserting `NVD_API_KEY` is server-side
      (process.env, not VITE_*)

- **Build**: 0 errors, 0 warnings, 5.42 s. **Bundle
  hashes are byte-identical to v5.0.1.** The v5.0.2
  changes are server-side only (function + test file
  only). The frontend bundle (`index-CIyVmlOq.js`) and
  the v5.0.1 CDN-cache headers are unchanged.

- **Acceptance**:
  **15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS +
  53/53 v3 NVD + 60/60 v4 cache + 68/68 v5.0/v5.0.1/
  v5.0.2 proxy = 263/263**.

- **No new dependencies.** No `package.json` change.
  The function uses only Node 20 built-ins. The client
  uses only the existing stack.

- **What v5.0.2 does *not* add (deliberate, per the
  v4.1 / v5.0 / v5.0.1 docs contract):**
  - No new data sources. OSV.dev / GHSA / other
    aggregators remain a v5.1+ milestone.
  - No login / auth. The `NVD_API_KEY` is an
    unauthenticated-public-API rate-limit-bump key, not
    a user credential.
  - No database.
  - No scheduled functions. The `stale-while-revalidate`
    in v5.0.1 is a CDN-layer mechanism.
  - No new env vars in the frontend. The single new
    env var is `NVD_API_KEY`, server-side only.
  - No UI redesign. The dashboard's
    `NvdUnavailableBanner` continues to render the
    function's `nvdReason` field verbatim. The function
    just returns a more concise reason.
  - No new offensive / exploit functionality.

### Pass 17 — v5.0.3 NVD API key transport fix ← *current*

- **Motivation.** v5.0.2 introduced the optional
  `NVD_API_KEY` env var and passed it to NVD as a URL
  query parameter: `?apiKey=<key>`. That worked, but
  NVD's official CVE 2.0 spec passes the API key in a
  request **header** named `apiKey`, not in the URL.
  v5.0.3 fixes the transport. Per the v4.1 / v5.0
  docs contract the key is still server-side only.

- **`netlify/functions/dataset.mjs`** — surgical change
  in `fetchOneNvdChunk` only:
  1. Removed `&apiKey=<key>` from the URL construction.
  2. When `apiKey` is present, set
     `headers.apiKey = apiKey` on the request.
  3. The URL is now always
     `${NVD_BASE_URL}?cveId=...` with no key in the
     query string.

- **No new dependencies. No new features. No UI
  changes. No data-flow changes.** The v5.0.2 rate-
  limit path, the v5.0.1 CDN cache, the v4 cache
  envelope, the v2.5 EPSS enrichment, the v3 NVD
  severity extraction, and the v1 mock fallback are
  all untouched. The frontend bundle is byte-
  identical to v5.0.2 (verified by the build hashes).

- **Honesty contract (preserved):**
  - The key is read from `process.env.NVD_API_KEY`
    inside the Netlify Function only.
  - The key is sent to NVD as the `apiKey` request
    header (per the CVE 2.0 spec).
  - The key is **never** appended to the NVD URL
    query string.
  - The key is **never** sent to the browser, never
    included in the function response body, never
    logged.
  - The frontend (`src/**`) is unchanged. There is
    no `VITE_NVD_API_KEY` or any other browser-
    exposed env var.
  - The function works identically without the key
    (just slower for the first visitor in a region
    per 15 min — repeat visitors ride the v5.0.1 CDN
    cache either way).

- **`scripts/acceptance-proxy.mjs`** — three new
  v5.0.3 assertions (proxy suite is now 71/71, up
  from 68/68 in v5.0.2):
  - NVD_API_KEY is NOT appended to the NVD URL
    query string (negative)
  - NVD_API_KEY IS passed as a request header
    (`apiKey: <key>`) (positive)
  - NVD_API_KEY is never logged (defense-in-depth)

  Plus a small `stripComments(s)` helper that strips
  `//` and `/* */` comments before applying the URL
  and header regexes — so doc text describing the
  v5.0.2 → v5.0.3 transition doesn't trip the test.
  The existing v5.0.2 "function never puts NVD_API_KEY
  in the response body" test was updated to use the
  same helper for consistency.

- **Docs.** Three doc files updated to remove the
  stale "passed to NVD as a `?apiKey=<key>` query
  parameter" wording and replace it with "passed to
  NVD as a request header `apiKey: <key>` from the
  Netlify Function, never exposed to the browser":
  `README.md`, `DEPLOYMENT.md`,
  `PROJECT_HANDOFF.md`. The same fix was applied
  to `NEXT_AGENT_PROMPT.md` (which previously
  suggested the wrong client-side `VITE_NVD_API_KEY`
  approach).

- **Build**: 0 errors, 0 warnings, ≈5.3 s. **All
  client chunks are byte-identical to v5.0.2.** The
  v5.0.3 changes are entirely server-side (function
  file + test file + docs).

- **Acceptance**:
  **15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS +
  53/53 v3 NVD + 60/60 v4 cache + 71/71 v5.0/v5.0.1/
  v5.0.2/v5.0.3 proxy = 266/266**.

- **What v5.0.3 does *not* add (deliberate, per the
  v4.1 / v5.0 docs contract):**
  - No new data sources. OSV.dev / GHSA / other
    aggregators remain a v5.1+ milestone.
  - No login / auth.
  - No database.
  - No scheduled functions.
  - No new env vars in the frontend. (The single
    server-side env var, `NVD_API_KEY`, is
    unchanged from v5.0.2 — only the transport
    changed.)
  - No UI redesign.
  - No new offensive / exploit functionality.

### Pass 18 — v5.1 Soft Refresh ← *current*

- **Motivation.** The dashboard renders its initial
  dataset, then sits idle until the user manually
  clicks "Refresh live data" or reloads the page. CISA
  KEV gets ~5–15 new entries per week on average —
  a portfolio visitor who keeps the tab open all
  afternoon sees nothing about those new entries
  unless they remember to refresh. v5.1 adds a
  silent 5-minute background poll that detects a
  newer upstream dataset and surfaces it through a
  small "New dataset available." banner. The user
  decides when to apply it, so a triage session
  mid-investigation is never disturbed. This is the
  first user-visible behavioral change since v3 —
  every prior pass was data-source or transport work
  that the user never saw.

- **UX contract (preserved end-to-end):**
  1. Visitor opens the dashboard
     → the latest stored dataset loads instantly
     (v4 localStorage cache hit, or v5 proxy).
  2. Background refresh starts / scheduled
     refresh runs (the 5-minute `setInterval`
     inside DashboardPage)
     → no visible disruption. No spinner, no
     layout shift, no full-page reload, no
     banner unless something genuinely new was
     detected.
  3. New dataset becomes available
     → a small banner appears at the top of the
     content area:
     > **New dataset available. Updated 2 min
     > ago.** [Apply update] [×]
  4. User clicks "Apply update"
     → data updates smoothly. Filters stay.
     Search stays. Sort stays. The selected
     detail view stays (or, if the selected CVE
     is no longer in the new dataset, the drawer
     auto-closes — showing a phantom record would
     be worse than closing). No full-page reload.
  5. User clicks × (or never clicks anything)
     → the banner is dismissed. The same exact
     update won't re-appear on every poll tick —
     only a strictly newer one will.

- **`src/services/vulnerabilityService.ts`** —
  one new optional flag on `VulnerabilityQuery`:
  ```ts
  export interface VulnerabilityQuery {
    forceRefresh?: boolean;   // existing v4
    background?: boolean;     // new v5.1
  }
  ```
  `background: true` skips the localStorage cache
  read for this single call (so the routine poll
  can actually detect a newer upstream dataset —
  reading the same local cache forever would
  never trigger an update) and still writes the
  result through to the cache on success. It
  does NOT bust the CDN: a background poll within
  the CDN's `s-maxage=900` window cheaply gets the
  cached function response, which is the intended
  path. Critically different from `forceRefresh`:
  - `forceRefresh` clears the localStorage cache
    AND appends a `?t=<timestamp>` cache-buster
    on the proxy URL. It is the "I really want
    fresh data right now" button.
  - `background` skips only the localStorage
    read, leaves the CDN alone, and is used by
    the silent poll. The CDN's s-maxage is the
    right TTL — we don't need to bust it on a
    routine check.

- **`src/pages/DashboardPage.tsx`** — three
  additions, no removals:
  1. **New state slots** — `pendingUpdate`
     (`FetchResult<Vulnerability[]> | null`) and
     `dismissedFetchedAt` (`string | null`),
     plus two refs (`stateRef`, `dismissedRef`)
     so the polling closure can read the latest
     values without restarting the interval on
     every render.
  2. **Polling `useEffect`** — starts a
     `setInterval(pollOnce, 5 * 60 * 1000)` when
     `state.kind === 'ready'`. Each tick:
     - bails if `document.visibilityState !==
       'visible'` (hidden tabs don't poll),
     - calls `fetchVulnerabilities({ background:
       true })`,
     - only sets `pendingUpdate` when the result
       is `mode === 'live'` AND
       `result.fetchedAt > current.meta.fetchedAt`
       AND `result.fetchedAt !==
       dismissedFetchedAt`,
     - silently swallows any network error in a
       `try / catch` (a transient proxy error
       shouldn't surface as a banner).
     The interval is cleaned up on unmount and
     re-created if state leaves `ready` and
     returns (e.g. an explicit manual refresh).
  3. **`UpdateAvailableBanner` component** —
     new, inline (matching the four existing
     banners). Info tone (cyan), small, with a
     `Sparkles` icon, the new dataset's age
     (`formatAgeShort`) and absolute time
     (`formatAbsolute`), and two buttons: Apply
     update (calls `handleApplyUpdate`) and ×
     (calls `handleDismissUpdate`).

- **`handleApplyUpdate`** — promotes
  `pendingUpdate` into `state` via
  `setState({ kind: 'ready', meta: current })`.
  Critically, filters / search / sort are NOT
  touched — they live in separate `useState`
  slots on DashboardPage and survive this state
  transition unchanged. The DetailDrawer is
  reconciled: if the selected CVE still exists
  in the new dataset, the `selected` reference
  is swapped to the new record (so any updated
  CVSS / EPSS scores show through); if the CVE
  is no longer in the new dataset, `selected`
  is set to `null` (drawer closes — better
  than showing a stale phantom record).
  `dismissedFetchedAt` is cleared on Apply.

- **`handleDismissUpdate`** — sets
  `dismissedFetchedAt = pendingUpdate.fetchedAt`
  and clears `pendingUpdate`. Both happen via
  the functional `setPendingUpdate((current) =>
  ...)` updater so they always see the same
  value of `current`. Cleared automatically on
  Apply.

- **`scripts/acceptance-softrefresh.mjs`** —
  new file, **58/58** passing:
  - 12 behavior assertions on a pure-JS
    re-implementation of the
    `shouldShowPendingUpdate` decision
    (newer / equal / older / mock / fallback /
    dismissed-equal / dismissed-older /
    defensive nulls).
  - 6 service-wiring assertions (the
    `background` flag, the readCache bypass,
    the writeCache preservation, the v5.1
    file-level comment, the docstring, the
    preserved `forceRefresh` contract).
  - 30 dashboard-wiring assertions (state
    slots, refs, polling effect cadence and
    cleanup, visibility / mode / fetchedAt /
    dismissedFetchedAt guards, silent
    try/catch, both handlers, drawer close-
    if-missing + swap-if-present, banner
    render + copy + icons + tone + buttons).
  - 10 regression assertions on the existing
    v4 / v5.0.3 contracts (cache helpers,
    cache TTL, forceRefresh behavior, all
    four prior banners still wired).

- **Docs.** `README.md` (status badge +
  feature bullet), `PROJECT_HANDOFF.md`
  (header / status / stack / acceptance /
  repo / deployment / Pass 18 entry /
  milestone table), `NEXT_AGENT_PROMPT.md`
  (remove the v5.1 candidate-item note and
  replace with a "v5.1 done in pass 18"
  pointer to the relevant files).

- **Honesty contract (preserved):**
  - No new data sources. OSV.dev / GHSA / other
    aggregators remain a v5.2+ milestone.
  - No login / auth.
  - No database.
  - No scheduled functions. The 5-minute
    `setInterval` runs only on the user's open
    tab — there is no server-side scheduler
    and no Netlify scheduled function.
  - No new env vars anywhere. The only
    server-side env var (`NVD_API_KEY`) is
    unchanged from v5.0.2 / v5.0.3.
  - No new API keys, secrets, or tokens.
  - No CDN changes. The function still serves
    `Cache-Control: public, s-maxage=900,
    stale-while-revalidate=300` from v5.0.1.
  - No automatic background data swap. The
    user must always click "Apply update" —
    the soft-refresh banner is informational,
    never auto-applied. This is the whole
    point of the feature: a triage session in
    progress is never disturbed.
  - No new offensive / exploit
    functionality.
  - The cache never hides provider failures.
    A background poll that returns a `mode:
    'fallback'` or `mode: 'mock'` result is
    never surfaced as a "new dataset" banner
    — the polling effect explicitly drops
    non-live results.

- **Build**: 0 errors, 0 warnings, ≈7.3 s.
  Main JS chunk: ~91 kB (up from ~89 kB in
  v5.0.3 — ~30 lines added: the polling
  effect, the two handlers, and the banner
  component). Icons chunk: gains the new `X`
  lucide-react icon. CSS chunk: byte-identical
  to v5.0.3 (`index-CiCb1bmX.css`). Charts
  chunk: rebuilt (Vite re-split), no semantic
  changes.

- **Acceptance**:
  **15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS +
  53/53 v3 NVD + 60/60 v4 cache + 71/71 v5.0/
  v5.0.1/v5.0.2/v5.0.3 proxy + 58/58 v5.1
  soft-refresh = 324/324**.

### Pass 19 — v5.2 Prebuilt Dataset Store ← *current*

- **Motivation.** Every visitor was paying the
  full CISA → NVD → EPSS pipeline on their first
  request (mitigated only by the v5.0.1 CDN cache and
  the v4 localStorage cache). On a cold CDN region
  — or after the v5.0.1 cache expired — a single
  visitor could still trigger a 30–60 s upstream build
  in the read endpoint. v5.2 moves the build off the
  visitor's request entirely: the CISA → NVD → EPSS
  pipeline runs **once on the server** and every
  subsequent visitor reads the prebuilt envelope
  immediately from a shared
  [Netlify Blobs](https://docs.netlify.com/build/data-and-storage/netlify-blobs/)
  entry.

- **Architecture.**
  ```
  Visitor request
       │
       ▼
  /.netlify/functions/dataset (READ)
       │
       ├── blob hit  ─► return latest-dataset envelope
       │                 (dataSource: "prebuilt-store",
       │                  refreshInProgress overlay)
       │
       └── blob miss ─► run CISA → NVD → EPSS
                        write blob (success only)
                        return envelope
                        (dataSource: "live-build")

  Schedule (cron */30 * * * *)
       │
       ▼
  refresh-dataset-scheduled
       │
       ├── lock free ─► acquire lock, build, write, release
       └── lock held ─► { status: "in-progress" }

  User clicks "Refresh live data"
       │
       ▼
  POST /.netlify/functions/refresh-dataset-background
       │
       ├── lock free ─► acquire lock, run via
       │                 context.waitUntil, return 202
       │                 { status: "started" }
       └── lock held ─► 202 { status: "in-progress" }
  ```

- **Why a scheduled function AND a manual endpoint.**
  The scheduled tick (`refresh-dataset-scheduled.mjs`)
  fires every 30 minutes and rebuilds the shared blob
  in the background. The manual endpoint
  (`refresh-dataset-background.mjs`) lets the user
  trigger a rebuild on demand — they don't have to wait
  for the next scheduled tick. Both writers share the
  same `runRefresh` orchestrator + 15-minute
  `refresh-lock` blob so a manual refresh doesn't
  collide with a scheduled one (and vice versa).

- **`netlify/functions/_shared/store.mjs`** — new
  shared module. Owns:
  - `LATEST_DATASET_KEY = "latest-dataset"`
    (the FetchResult envelope blob key — exact name
    per the v5.2 spec)
  - `REFRESH_LOCK_KEY = "refresh-lock"`
    (the refresh-lock blob key)
  - `STORE_NAME = "tpr-dataset"`
    (the Netlify Blobs store name)
  - `REFRESH_LOCK_TTL_MS = 15 * 60 * 1000`
    (15-minute lock TTL)
  - `getDatasetStore()` — strong-consistency wrapper
    around `@netlify/blobs`' `getStore`.
  - `readLatestDataset()` / `writeLatestDataset()` —
    defensive try/catch on every Blobs call (a
    transient Blobs outage must never crash the
    dashboard).
  - `readRefreshLock()` / `isRefreshLocked()` /
    `tryAcquireRefreshLock()` /
    `clearRefreshLock()` — the lock-management quartet.
  - `isLockActive()` / `buildLockPayload()` — pure-JS
    helpers mirrored in the acceptance suite.

- **`netlify/functions/_shared/refresh.mjs`** — new
  shared module. The lock + write + release
  orchestrator. `runRefresh({ store, buildFn })`:
  1. Check the lock; if active, return
     `{ status: "in-progress" }` without running.
  2. Acquire the lock.
  3. Run `buildFn()` (a zero-arg async function that
     returns the FetchResult). If it throws OR returns
     a non-live result, release the lock and return
     `{ status: "failed", reason }`. The existing blob
     is left intact.
  4. On success, write the envelope to `latest-dataset`
     tagged with `proxyStatus: "proxy"` +
     `dataSource: "prebuilt-store"`. Release the lock.
  5. Return `{ status: "completed", fetchedAt }`.

  `decideRefresh({ existingLock, buildResult, buildError })`
  is a pure-JS mirror exported for the acceptance suite.

- **`netlify/functions/_shared/liveBuild.mjs`** — new
  shared module. The CISA → NVD → FIRST EPSS pipeline
  extracted from the v5.0 / v5.0.1 / v5.0.2 / v5.0.3
  `dataset.mjs` so the background / scheduled functions
  can call the same upstream-fetch code without
  duplicating it. `buildLiveDataset({ startTime })`
  returns the FetchResult on success and throws on
  CISA failure (the only gating upstream). The
  v5.0.2 / v5.0.3 contract — NVD chunks serial without
  a key, parallel with a key, key passed as request
  header — is preserved byte-for-byte.

- **`netlify/functions/dataset.mjs`** — refactored. The
  read endpoint now:
  1. Resolves the Blob store (graceful fallback to
     bootstrap if Blobs is unavailable, e.g. Vite-only
     `npm run dev`).
  2. Reads `refresh-lock` and overlays the
     `refreshInProgress` flag on every response.
  3. Reads `latest-dataset`. If it exists and is a live
     envelope, returns it immediately with
     `dataSource: "prebuilt-store"`.
  4. Else, runs `buildLiveDataset()` (the bootstrap
     path). On success, writes the envelope to the
     blob AND returns it with `dataSource: "live-build"`.
  5. On CISA failure (buildLiveDataset throws), returns
     HTTP 502 + `{ mode: "fallback", fallbackReason }`
     — the v5.0 fallback envelope is preserved. The
     blob is **not** touched on this path.
  6. The v5.0.1 CDN-cacheable `Cache-Control:
     public, s-maxage=900, stale-while-revalidate=300`
     is preserved unchanged. A CDN-cached response is
     now a cached Blob-read, not a cached upstream
     fetch — still safe and still honest.

- **`netlify/functions/refresh-dataset-background.mjs`**
  — new HTTP-triggered Netlify Background Function.
  Triggered by `POST /.netlify/functions/refresh-dataset-background`
  from the dashboard's "Refresh live data" button.
  Returns 202 immediately with `{ status: "started" }`
  (lock acquired) or `{ status: "in-progress" }` (lock
  held), then runs the build via `context.waitUntil`.
  Background functions have up to a 15-minute timeout
  (vs. the 26-s sync limit on regular functions), so
  the build has room to complete. The function does
  NOT replace the visible dataset on the client side
  — that's still owned by the v5.1 banner flow.

- **`netlify/functions/refresh-dataset-scheduled.mjs`**
  — new scheduled function. Triggered by the
  `*/30 * * * *` cron in `netlify.toml`. Same
  orchestrator as the background endpoint. Logs
  `[v5.2 scheduled refresh] trigger=scheduled status=...`
  on each invocation. Console-logs only status /
  fetchedAt / reason — never the API key, never the
  envelope payload.

- **`netlify.toml`** — updated to register all three
  functions with `node_bundler = "none"` and to add the
  cron schedule for `refresh-dataset-scheduled`:

  ```toml
  [functions.refresh-dataset-background]
    node_bundler = "none"

  [functions.refresh-dataset-scheduled]
    node_bundler = "none"
    schedule = "*/30 * * * *"
  ```

  The existing v5.0 / v5.0.1 / v5.0.2 / v5.0.3 entries
  are unchanged.

- **`package.json`** — `@netlify/blobs ^10.0.0` added as
  a runtime dependency. The v5.2 functions import from
  it directly; Netlify zips `node_modules/@netlify/blobs`
  alongside the function code on deploy. With
  `node_bundler = "none"` the import is not bundled by
  esbuild — Netlify's deploy-time zipper handles the
  resolution.

- **`src/services/vulnerabilityService.ts`** —
  additive changes:
  1. New `REFRESH_ENDPOINT_URL` constant (defaults to
     `/.netlify/functions/refresh-dataset-background`,
     overridable by `VITE_REFRESH_ENDPOINT_URL`).
  2. New `RefreshStatus = "completed" | "started" |
     "in-progress" | "failed"` type.
  3. New `RefreshResult` interface (`status`, `fetchedAt`,
     `reason`, `refreshInProgress`).
  4. New `manualRefresh()` function — POSTs to the
     background endpoint, returns a normalized
     `RefreshResult`. Used by the dashboard's manual
     button instead of the v4 / v5.0
     `fetchVulnerabilities({ forceRefresh: true })`
     path. The `forceRefresh` path is still wired
     internally (the `tryProxyFetch` `?t=<ts>`
     cache-buster) but the user-visible manual
     button no longer uses it.
  5. New `PrebuiltDataSource = "prebuilt-store" |
     "live-build"` type.
  6. New `dataSource?: PrebuiltDataSource` and
     `refreshInProgress?: boolean` fields on
     `FetchResult`. Both are surfaced to the UI.

- **`src/components/Header.tsx`** — three new pills:
  - "Dataset store: latest available" (cyan info) on
    `dataSource === "prebuilt-store"`.
  - "Dataset store: bootstrapping" (neutral) on
    `dataSource === "live-build"`.
  - "Refresh running in background" (cyan info, with
    a Loader2 rotating icon and a pulsing dot) on
    `refreshInProgress === true`.
  - "Last refresh" tooltip now reads "Last dataset
    build: <absolute>" — the v5.2 wording.
  No layout changes; the existing pills / badges are
  unchanged.

- **`src/pages/DashboardPage.tsx`** — additive changes:
  1. New `refreshStatus` state slot (a
     `RefreshResult | null`).
  2. New `handleManualRefresh()` handler — calls
     `manualRefresh()` and updates `refreshStatus`.
     Does NOT replace the visible dataset.
  3. New `RefreshInProgressBanner` component (info
     tone, Loader2 spinner, three messages: started,
     in-progress, failed, dismissible via ×).
  4. The polling effect now also clears
     `refreshStatus` when the polled result has
     `refreshInProgress: false` — the banner auto-clears
     once the server-side build completes.
  5. The existing v5.1 handlers (`handleApplyUpdate`,
     `handleDismissUpdate`) now also clear
     `refreshStatus` on Apply so the two banners don't
     fight.
  6. The `CachedDataBanner`'s "Refresh live data"
     button is rewired from
     `fetchVulnerabilities({ forceRefresh: true })` to
     `handleManualRefresh` — the v5.2 contract.

- **UX contract (preserved end-to-end):**
  1. Visitor opens the dashboard
     → reads `latest-dataset` from Blobs.
     If present → instant render with
     `dataSource: "prebuilt-store"`.
     If absent → bootstrap path runs the build, writes
     the blob, returns it with
     `dataSource: "live-build"`.
  2. Scheduled tick (every 30 min)
     → acquires lock, rebuilds blob, releases lock.
     The visitor's view is never disturbed.
  3. User clicks "Refresh live data"
     → POSTs to the background endpoint. Returns 202
     immediately. Banner "Refresh running in
     background" appears. The visible data is
     unchanged.
  4. Build completes, blob is updated
     → next 5-minute poll (or earlier if the user
     reloads) returns the new envelope. v5.1 polling
     detects the newer `fetchedAt` and shows the
     existing "New dataset available" banner.
  5. User clicks "Apply update"
     → data updates smoothly. Filters / search / sort /
     selected detail view preserved. The
     `refreshStatus` and `pendingUpdate` banners both
     clear on Apply.
  6. User clicks ×
     → the soft-refresh banner is dismissed (until the
     next newer dataset lands). The
     `refreshStatus` banner is dismissed immediately.

- **Honesty contract (preserved):**
  - **No new data sources.** CISA KEV, NVD, and FIRST
    EPSS remain the full enrichment chain.
  - **No login / auth.** **No database.** Blobs is a
    managed key/value store, not a database — and
    nothing user-specific is stored there.
  - **No auto-replace.** Manual refresh keeps the
    current dataset on screen; the v5.1 banner is the
    only way the data is swapped. Auto-reload is
    explicitly forbidden.
  - **The store never overwrites a good envelope with
    a mock fallback.** `writeLatestDataset` is only
    called after `buildLiveDataset` succeeds; the
    CISA-failure 502 path returns the fallback
    envelope to the visitor WITHOUT touching the
    blob.
  - **The store never hides provider failures.** The
    blob envelope preserves `nvdStatus` /
    `epssStatus` / `fallbackReason` verbatim, so a
    stored dataset with `nvdStatus: "unavailable"`
    still surfaces the `NvdUnavailableBanner` on
    read.
  - **The cache never claims NVD enriched if the
    stored dataset has NVD unavailable.** The
    `nvdStatus` field is the source of truth; the
    Header's "NVD: enriched" pill only renders when
    `nvdStatus === "nvd"`.
  - **No new API keys.** `NVD_API_KEY` remains
    server-side only, passed to NVD as a request
    header.
  - **No new env vars in production.** The frontend's
    `VITE_REFRESH_ENDPOINT_URL` is a public route
    (not a secret), optional, with a baked-in
    default. `VITE_DATASET_PROXY_URL` from v5.0 is
    unchanged. No `VITE_NVD_API_KEY` is introduced
    (forbidden by the v4.1 / v5.0 contract).
  - **No new dependencies** in the frontend bundle
    beyond the existing stack.
  - **No new offensive / exploit functionality.**

- **`scripts/acceptance-prebuilt.mjs`** — new
  98-test acceptance suite. Covers:
  - 7 dependency / shared-module assertions
    (`@netlify/blobs` in `package.json`; the three
    shared modules exist and are wired).
  - 7 blob-key / store-name assertions
    (`LATEST_DATASET_KEY = "latest-dataset"`,
    `REFRESH_LOCK_KEY = "refresh-lock"`,
    `STORE_NAME = "tpr-dataset"`, the public API
    surface).
  - 2 refresh-lock TTL assertions
    (`REFRESH_LOCK_TTL_MS = 15 * 60 * 1000`,
    rationale comment).
  - 15 pure-JS lock + refresh-decision logic
    assertions (boundary inputs: null lock,
    active lock, expired lock, malformed lock;
    decideRefresh returns one of
    { completed, in-progress, failed }).
  - 8 background-function assertions
    (`-background.mjs` filename, default-exported
    handler, imports from the shared modules,
    `context.waitUntil`, returns 202,
    never exposes NVD_API_KEY).
  - 6 scheduled-function assertions
    (`-scheduled.mjs` filename, default-exported
    handler, imports, graceful handling of Blobs
    unavailable).
  - 5 `netlify.toml` assertions (both new functions
    wired with `node_bundler = "none"`, cron
    schedule conservative, dataset function
    unchanged).
  - 13 dataset-function assertions (blob-first read,
    bootstrap path, no overwrite with mock fallback,
    preserved CDN-cacheable response,
    refreshInProgress overlay, no refresh triggers
    from the read endpoint).
  - 11 frontend-service assertions (REFRESH_ENDPOINT_URL
    constant, manualRefresh function, RefreshStatus +
    RefreshResult types, FetchResult fields,
    `forceRefresh: true` preserved internally but
    no longer on the manual button, manualRefresh
    POSTs).
  - 14 dashboard + Header UI honesty assertions
    (the three new pills, Loader2 + pulse + info-tone
    styling, "Last dataset build" tooltip wording,
    handleManualRefresh wired to manualRefresh,
    RefreshInProgressBanner with status + onDismiss,
    three messages, dismiss behavior).
  - 5 honesty-contract assertions (provider failures
    preserved through the blob envelope, the
    dashboard never claims NVD enriched when stored
    has NVD unavailable, handleManualRefresh does
    NOT setState({ kind: "ready" })).
  - 6 v5.1 regression assertions (5-minute poll
    cadence, `background: true` polling, pendingUpdate
    state, UpdateAvailableBanner, apply/dismiss
    handlers, interval cleanup).

- **`scripts/acceptance-proxy.mjs`** — 2 source-level
  updates: the URL / `NVD_API_KEY` /
  `concurrency` / `settledAll` / 429-reason
  assertions now look across both `dataset.mjs` and
  the extracted `_shared/liveBuild.mjs` so a
  regression in either file is caught. The
  "no new VITE_* env vars" assertion is updated to
  allow `VITE_REFRESH_ENDPOINT_URL` (a public route,
  not a secret). Total: still **71/71**.

- **`scripts/acceptance-cache.mjs`** and
  **`scripts/acceptance-softrefresh.mjs`** — 1
  assertion each updated: the cached-data banner's
  "Refresh live data" button is rewired from
  `fetchVulnerabilities({ forceRefresh: true })` to
  `handleManualRefresh`. v4 + v5.1 contracts remain
  green: still **60/60** + **58/58**.

- **Docs.** `README.md` (status badge → v5.2,
  feature bullet, dedicated "🗄️ V5.2 prebuilt dataset
  store" section, project-structure tree, roadmap
  checkbox), `DEPLOYMENT.md` (new section 0.9
  covering blobs setup, scheduled + manual refresh,
  refresh-lock TTL, verification checklist,
  Blobs auto-provisioning, local-dev fallback),
  `PROJECT_HANDOFF.md` (this Pass 19 entry +
  header / status / stack / acceptance / deployment
  / milestone table), `NEXT_AGENT_PROMPT.md`
  (status block + test counts + the v5.2 honest-UI
  rule + v5.2 done-in-pass-19 pointer).

- **Build**: 0 errors, 0 warnings, ≈5.8 s. Main JS
  chunk: ~95 kB (up from ~91 kB in v5.1 — ~3 kB
  for the new state slots, manualRefresh handler,
  RefreshInProgressBanner, and Loader2 / rotating
  icon plumbing). CSS chunk: +0.5 kB for the new
  pill / banner styles. Icons chunk: gains the
  new `Loader2` lucide-react icon. Charts chunk:
  rebuilt by Vite, no semantic changes.

- **Acceptance**:
  **15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS +
  53/53 v3 NVD + 60/60 v4 cache + 71/71 v5.0/v5.0.1/
  v5.0.2/v5.0.3 proxy + 58/58 v5.1 soft-refresh +
  98/98 v5.2 prebuilt-dataset store = 422/422**.

### Items reviewed and intentionally left alone

- **Vulnerability table mobile UX.** The table uses
  `min-w-[1100px]` and horizontal scroll on small screens.
  This is a deliberate choice — a 10-column data table
  doesn't compress to mobile without becoming unreadable.
  The scroll is contained inside a `.panel` with the standard
  `overflow-x-auto`. Out of scope for a "no UI redesign" pass.
- **NVD first-load latency.** NVD's anonymous rate limit
  (5 req / 30 s) means ~1000 CISA CVEs need 10 chunks, taking
  up to a minute. An NVD API key (10× rate limit) would fix
  this. Explicitly out of scope (the user said no NVD API key).
  Documented in the portfolio writeup as a trade-off.
- **KPI stat-card "Average EPSS" label.** The card's hint
  says "Probability of exploitation" which is correct but
  could be more specific (e.g. "30-day probability of
  exploitation"). Current text matches what FIRST documents.
  Left as-is to avoid editing copy that was already approved.
- **Sticky table header on scroll.** Would help with a 1000-
  record dataset but is a layout addition, not a fix. Out of
  scope for "no UI redesign."

---

## 3. Files in the project (46 source files)

```
threatpulse-radar/
├── index.html
├── package.json
├── package-lock.json
├── postcss.config.js
├── tailwind.config.js
├── tsconfig.json
├── tsconfig.app.json
├── tsconfig.node.json
├── vite.config.ts                   (base: './' added in pass 6)
├── .gitignore
├── README.md
├── PROJECT_HANDOFF.md               (this file)
├── NEXT_AGENT_PROMPT.md
├── PORTFOLIO_WRITEUP.md            (new in pass 11 — recruiter-facing narrative)
├── DEPLOYMENT.md                    (Hostinger guide, pass 6)
├── public/
│   ├── .htaccess                    (SPA fallback + headers, pass 6)
│   └── radar.svg
├── scripts/
│   ├── acceptance.mjs               (v1 15-test suite, pass 8 added 2)
│   ├── acceptance-cisa.mjs          (v2 28-test CISA suite)
│   ├── acceptance-epss.mjs          (v2.5 39-test EPSS suite)
│   ├── acceptance-nvd.mjs           (v3 53-test NVD suite, +1 in pass 11)
│   └── zip-source.ps1               (one-off source-archiver)
└── src/
    ├── main.tsx
    ├── App.tsx
    ├── index.css
    ├── components/
    │   ├── Header.tsx               (NVD + EPSS pills; honest label, pass 11)
    │   ├── StatsCards.tsx
    │   ├── FiltersPanel.tsx
    │   ├── VulnerabilityTable.tsx
    │   ├── DetailDrawer.tsx
    │   ├── EmptyState.tsx
    │   ├── LoadingState.tsx          (multi-source copy, pass 11)
    │   ├── ErrorState.tsx
    │   ├── SearchStatus.tsx
    │   └── charts/
    │       ├── SeverityChart.tsx
    │       ├── TrendChart.tsx
    │       └── KevChart.tsx
    ├── data/
    │   └── mockVulnerabilities.ts   (60 unique records, fallback dataset)
    ├── pages/
    │   └── DashboardPage.tsx        (LoadingState message updated, pass 11)
    ├── services/
    │   ├── vulnerabilityService.ts  (CISA+NVD+EPSS orchestration, pass 10)
    │   └── providers/
    │       ├── README.ts            (placeholder for v4 providers)
    │       ├── cisaKev.ts           (new in pass 7; desc updated pass 10)
    │       ├── epss.ts              (new in pass 9)
    │       └── nvd.ts                (new in pass 10)
    ├── types/
    │   └── vulnerability.ts
    ├── hooks/
    │   ├── useDebouncedValue.ts
    │   └── useVulnerabilityFilter.ts
    └── utils/
        ├── analytics.ts             (severity comparator fixed, pass 8)
        ├── format.ts
        └── severity.ts
```

---

## 4. Current UI / header state (after pass 10)

```
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│  [LOGO]  ThreatPulse Radar              [● Defensive use]          │
│   ✦     Defensive vulnerability...     [● Source: CISA KEV + NVD   │
│          [Portfolio] [Live CISA KEV]   [● NVD: enriched]    + EPSS] │
│          Mode                          [● EPSS: FIRST]            │
│                                        [● Last refresh]            │
└────────────────────────────────────────────────────────────────────┘
```

- **No top status strip.** No version numbers anywhere in the visible hero.
- **Background:** subtle dot grid + two soft cyan/green radial glows
  (very low opacity, sits behind via `-z-10`).
- **Logo:** 56–64 px, soft glow tile, single tiny corner pulse dot.
- **Title:** `text-[1.65rem] sm:text-3xl lg:text-[2.4rem]`, bold, tracking-tight.
- **Subtitle:** *"Defensive vulnerability intelligence dashboard for
  tracking risk, exploitation signals, and remediation priorities."*
- **Badges (under subtitle) — one of three modes, shown exclusively:**
  - `Live CISA KEV Mode` (cyan/accent) — when `mode === 'live'`.
  - `Mock Data Mode` (amber/warn) — when `mode === 'mock'`.
  - `Fallback Mode` (amber/warn) — when `mode === 'fallback'`
    (CISA fetch failed, mock data shown).
  Plus the always-on `Portfolio Project` badge.
- **Status column (right):** five pills, color-coded dots:
  - `Defensive use only` (green, pulsing).
  - `Source: CISA KEV` / `Source: CISA KEV + NVD + FIRST EPSS` /
    `Source: CISA KEV + FIRST EPSS` (NVD unavailable) /
    `Source: mock (fallback)` / `Source: mock` (tone varies).
  - `NVD: enriched` (cyan) — when `nvdStatus === 'nvd'`.
  - `NVD: unavailable` (amber) — when `nvdStatus === 'unavailable'`,
    with the reason in a tooltip.
  - `EPSS: FIRST` (cyan) — when `epssStatus === 'first'`.
  - `EPSS: unavailable` (amber) — when `epssStatus === 'unavailable'`.
  - `Last refresh: <relative>` (neutral).
- **Fallback banner** appears *above the stats cards* when
  `mode === 'fallback'`: explains the failure reason and offers a
  "Retry live fetch" button.
- **NVD-unavailable banner** (softer) appears above the stats when
  `mode === 'live'` but `nvdStatus === 'unavailable'`: explains
  CVSS values default to 0 and severity falls back to CISA-derived.
- **EPSS-unavailable banner** (softer) appears above the stats when
  `mode === 'live'` but `epssStatus === 'unavailable'`: explains
  EPSS values default to 0.
- **Responsive:** stacks on mobile, side-by-side on `lg+`.

---

## 5. Current working features

### Data sources (v3.0)
- **Live mode** (default): fetches the public
  [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
  in the browser with an 8 s `AbortController` timeout. The feed
  is CORS-enabled so no proxy is required.
- **NVD CVSS enrichment (v3.0)**: when CISA succeeds, additionally
  fetches [NVD CVE 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0)
  metrics for every CVE in the CISA catalog. Batched at 100 CVEs
  per request, parallel, 8 s timeout per chunk. Records whose
  CVE isn't in NVD's response keep `cvssScore: 0` (no fabrication).
  Score extraction prefers v3.1, then v3.0, then v2; severity
  comes from NVD's `baseSeverity` when present, otherwise
  derived from the score. The NVD severity **overrides** the
  CISA-derived severity when present (data-driven beats policy-
  driven for the same record). On NVD failure, the CISA + EPSS
  data is still shown with `nvdStatus: 'unavailable'` and a soft
  banner explains the failure.
- **EPSS enrichment (v2.5)**: when CISA succeeds, additionally
  fetches [FIRST EPSS](https://www.first.org/epss/) exploitation-
  probability scores for every CVE in the CISA catalog. Batched
  at 100 CVEs per request, parallel, 8 s timeout per chunk.
  Records whose CVE isn't in the FIRST response keep
  `epssProbability: 0` (no fabrication). On EPSS failure, the
  CISA + NVD data is still shown with `epssStatus: 'unavailable'`
  and a soft banner above the stats explains why.
- **Mock mode**: opt-in via `DATA_MODE = 'mock'` in
  `vulnerabilityService.ts`. Returns the curated 60-record mock
  dataset (used for offline development and as a forced override).
- **Fallback mode**: when `DATA_MODE === 'live'` and the CISA fetch
  fails for any reason (network, abort, non-2xx, shape mismatch),
  the service returns the mock dataset with `mode: 'fallback'`
  and a `fallbackReason` string. The UI shows a banner with the
  reason and a retry button.
- Normalizer (`src/services/providers/cisaKev.ts`) maps CISA KEV
  records into the existing `Vulnerability` shape. Severity is
  derived from `knownRansomwareCampaignUse` (`Known` → Critical,
  otherwise High). CVSS defaults to `0` until NVD enriches; EPSS
  defaults to `0` until FIRST enriches.

### Dashboard
- 6 stats cards: total, critical, high, KEV, avg EPSS, new-this-week.
- 4 Recharts visualizations: severity bars, EPSS buckets, KEV donut,
  14-day trend area.
- All charts computed off the **raw** dataset, so they don't change
  as the user types in the search box.

### Vulnerability table
- 10 columns: CVE ID, summary, severity, CVSS, EPSS, KEV,
  vendor/product, published, source, details.
- Rows keyed by `v.id` (not `cveId`) — stable even if a CVE
  affects multiple products in v3.
- Click row → opens detail drawer.
- Per-row EPSS bar colored by risk band (low / medium / high / critical).
- Works identically on the live CISA KEV feed and the mock dataset.

### Filter / search / sort (the polished pipeline — works on CISA + mock)
- **Search** — case-insensitive, trims and collapses whitespace,
  debounced (180 ms), matches across `cveId`, `summary`,
  `description`, `vendor`, `product`, `severity`, `source`.
- **Search status** — spinner says *"Searching current dataset…"*,
  settles to *"X of Y results"*.
- **Inline ✕** inside the search input clears it.
- **Severity filter** — All / Critical / High / Medium / Low.
  Operates on `v.severity`; the severity filter does not depend
  on `v.cvssScore` and therefore works on CISA records whose
  CVSS score is unknown (defaults to `0`).
- **KEV-only toggle.**
- **Minimum EPSS slider** (0–100 %), half-open `[min, 1.0]`.
  With FIRST EPSS enrichment (v2.5), the EPSS column is now
  populated with real scores for CISA CVEs that FIRST has
  scored, so the slider actually filters on real values. CVEs
  not in the FIRST dataset still default to `0` and will be
  excluded above the 0% threshold — accurate to the data we have.
- **CVSS-based filtering** — now also real (v3 NVD enrichment).
  The severity filter ("Critical / High / Medium / Low") and
  CVSS-based sort / threshold logic all operate on the NVD-
  populated `cvssScore` and `severity` fields. CISA records
  whose CVE isn't in NVD's response keep `cvssScore: 0` and
  the CISA-derived severity (KEV = at least High; ransomware-
  known = Critical).
- **Sort dropdown** — 12 explicit options including
  *Newest first*, *Oldest first*, *CVSS: high to low / low to high*,
  *EPSS: high to low / low to high*, *Severity: high to low / low to high*,
  *KEV first / Non-KEV first*, *Vendor A–Z / Z–A*.
- **Header click sort** — clicking a sortable column header toggles
  direction; the dropdown updates to match. Active column shows a
  colored ▲/▼ arrow, inactive sortable columns show a faint ↕.
- **All filters AND together.** Sort is the final step.
- **Empty state** — *"No vulnerabilities match your filters."* with
  a "Reset all filters" button.
- **Reset button** — restores everything to defaults, including sort.

### Detail drawer
- CVE id, severity badge, KEV chip.
- Full summary, longer description, metrics grid
  (CVSS / EPSS / Published / Source), affected vendor + product,
  recommended defensive action in an accent box, external reference
  links.
- Closes on Esc, click outside, or ✕ button.

### State
- Loading / error / empty / fallback states throughout.
- Custom `useVulnerabilityFilter` hook owns the filter → sort pipeline.
- Custom `useDebouncedValue` hook powers the debounced search.

---

## 6. Commands verified and build result

```bash
# Install (only the first time)
npm.cmd install

# Dev server
npm.cmd run dev         # http://localhost:5173

# Production build (type-check + bundle)
npm.cmd run build

# Preview the production bundle
npm.cmd run preview

# Acceptance test suites
node scripts/acceptance.mjs           # v1 mock-data tests (13)
node scripts/acceptance-cisa.mjs      # v2 CISA KEV tests (27)
```

### Build output (this pass, fresh run)
```
> threatpulse-radar@1.0.0 build
> tsc -b && vite build

✓ 2392 modules transformed.
dist/index.html                  0.83 kB │ gzip:  0.45 kB
dist/assets/index-*.css         24.79 kB │ gzip:  5.43 kB
dist/assets/react-*.js           0.06 kB │ gzip:  0.07 kB
dist/assets/icons-*.js          19.43 kB │ gzip:  5.54 kB
dist/assets/index-*.js          77.48 kB │ gzip: 20.43 kB
dist/assets/charts-*.js        545.44 kB │ gzip: 154.25 kB
✓ built in 5.25s
```

- `tsc -b` exits 0 (strict mode, no `any` leaks, no unused locals/params).
- Vite exits 0 with **no warnings** (chunk-size warning was cleared in
  pass 1 by `manualChunks` in `vite.config.ts`).
- Bundle is well-split: react / icons / charts are in their own chunks.
- Only the app chunk (`index-*.js`) hash changed vs. pass 7
  (`CFc8jTCu` → `BZKj2KNS`). All other chunks identical —
  confirms pass 8 was a one-line change.
- `dist/index.html` references assets with **relative** paths
  (`./assets/...`, `./radar.svg`).
- `dist/.htaccess` is present (copied from `public/.htaccess` at
  build time).

### Acceptance suite output

**v1 (mock data):** `node scripts/acceptance.mjs` → **15/15** passing
(was 13/13; pass 8 added 2 severity sort tests).
**v2 (CISA KEV):** `node scripts/acceptance-cisa.mjs` → **28/28** passing
(was 27/27; pass 8 strengthened the severity sort coverage).

### Acceptance suite output
```
--- Search tests ---
  ✓ search "fortinet" only returns Fortinet rows
  ✓ search "cisco" only returns Cisco rows
  ✓ search "ivanti" only returns Ivanti rows
  ✓ search "CRITICAL" is case-insensitive and matches Critical rows
  ✓ search trims + collapses whitespace
  ✓ search "fortin et" returns nothing (must be contiguous)
--- Filter tests ---
  ✓ severity = Critical only returns Critical rows
  ✓ KEV-only toggle only returns kev=true rows
  ✓ EPSS slider >= 50% only returns EPSS >= 0.5
  ✓ combined filters (High + KEV + EPSS>=40%) compose with AND
--- Sort tests ---
  ✓ CVSS high-to-low: first row has highest CVSS
  ✓ CVSS low-to-high: first row has lowest CVSS
  ✓ Vendor A-Z sorts alphabetically
  ✓ Severity high-to-low: Critical, High, Medium, Low
  ✓ Severity low-to-high: Low, Medium, High, Critical
--- Data integrity tests ---
  ✓ No duplicate CVE IDs in mock data
ALL TESTS PASSED  (15/15)
```

---

## 7. Known issues / limitations

- **CISA KEV doesn't include CVSS or EPSS.** The v3 normalizer
  defaults both to `0`; the description carries a short,
  honest note ("…may enrich from NVD and FIRST EPSS when those
  services are reachable"). The v3 NVD enrichment fills
  `cvssScore` and `severity` for every CISA CVE that NVD has
  scored; the v2.5 EPSS enrichment fills `epssProbability`
  similarly. The user can see at a glance which fields are
  populated and which aren't.
- **NVD rate limit (5 requests / 30 s without API key)** means
  the first load of the live dashboard can take ~30–60 s when
  the CISA catalog has ~1000 records. The page renders the
  CISA data as soon as that fetch returns, then fills CVSS in
  the background. The v4 cache layer reduces this from a
  per-visit cost to a per-hour cost: returning visitors get an
  instant render from `localStorage` and a fresh live fetch
  happens in the background only on cache miss or via the
  manual "Refresh live data" button. A future pass could add
  an NVD API key for a 10× rate-limit bump — `VITE_NVD_API_KEY`
  env var pattern.
- **Recharts 2 is on the deprecation list** (recharts 3 is current).
  We're on `^2.13.3` and the npm install prints a `npm warn deprecated`
  line. Not a blocker; consider bumping to recharts 3 in a future
  pass.
- **No persistence.** Refreshing the page resets the filter/sort
  state and re-fetches the CISA feed. That's fine for a portfolio
  piece.
- **The corner pulse on the logo is the only motion left in the hero.**
  Remove `animate-pulseDot` from the `<span>` in `Header.tsx` if you
  want a fully-static "museum card" feel.
- **No `dist/` is checked in** (it's in `.gitignore`). Build before
  deploying.
- **The `zip-source.ps1` script in the project root is a one-off**
  packaging helper. It's in `.gitignore` already; safe to delete.
- **Origin remote** is configured at
  `https://github.com/namanparikh11/threatpulse-radar.git` (added
  in pass 5). The repo is **private**; nothing has been pushed yet.
  Do not push without an explicit ask.
- **CORS / browser-direct fetching:** browser-direct fetching
  only works when the provider allows it at request time.
  Public-demo fallback mode is expected when CORS, rate limits,
  geo restrictions, or upstream outages block access. The
  fallback banner + retry button reflect the actual state at
  the time of the failed fetch.

---

## 8. What should NOT be changed in the next session

v2 (CISA KEV), v2.1 (severity sort fix), v2.5 (FIRST EPSS), and
v3 (NVD CVSS) are now part of the frozen scope. The next session's
only job is whatever the user explicitly asks for next. Do **not**
do any of the following without an explicit ask:

- ❌ Add more real APIs. CISA KEV, NVD, and FIRST EPSS are the
  full enrichment chain. New sources go through a fresh
  ask — they need a new provider, a new orchestration path,
  and a new status field on `FetchResult`.
- ❌ Add new features (auth, persistence, watchlists, CSV export,
  per-vendor sidebar, deep-linking). Out of scope.
- ❌ Redesign the header. The pass-4 layout is final; the v2 /
  v2.5 / v3 passes only changed labels, not structure. Don't add
  more pills / badges / banners / animated indicators.
- ❌ Touch the filter / search / sort pipeline or the
  `useVulnerabilityFilter` / `useDebouncedValue` hooks. The
  15 v1 acceptance tests + 28 CISA tests + 39 EPSS tests + 52 NVD
  tests must keep passing. Do not weaken them. The severity sort
  comparator in `src/utils/analytics.ts` (`compareByField`'s
  `case 'severity':`) was corrected in pass 8 to put Critical
  first when descending; do not revert it.
- ❌ Touch `src/data/mockVulnerabilities.ts`,
  `src/hooks/useVulnerabilityFilter.ts`, or
  `src/hooks/useDebouncedValue.ts` unless the user explicitly asks.
- ❌ Bump major versions of React / Vite / Recharts. Frozen at
  v1 majors.
- ❌ Add a backend, a database, or any kind of server.
- ❌ Remove `base: './'` from `vite.config.ts` or the
  `public/.htaccess` file — both are required for the deployed
  Hostinger bundle to keep working.
- ❌ Change the `DATA_MODE` default from `'live'`. The user should
  see the live CISA feed first; offline development can flip
  it to `'mock'` locally but the committed default stays `'live'`.
- ❌ Re-introduce the old severity sort comparator.
- ❌ Revert the CISA / NVD / EPSS enrichment.
- ❌ Push to `origin` without an explicit ask. The repo is
  private and no deploy has happened yet.

---

## 9. Milestone status

| Milestone | Status |
| --- | --- |
| v1 (mock data, full UI) | ✅ done, frozen |
| Hostinger static deployment prep | ✅ done (pass 6) |
| v2 — CISA KEV live data | ✅ done (pass 7) |
| v2.1 — Severity sort comparator fix | ✅ done (pass 8) |
| v2.5 — FIRST EPSS enrichment | ✅ done (pass 9) |
| v3 — NVD CVSS enrichment | ✅ done (pass 10) |
| v3 QA / portfolio-demo hardening | ✅ done (pass 11) |
| v4 — Transparent 1-hour localStorage cache | ✅ done (pass 12) |
| v4.1 — Public-demo honesty hardening (docs-only) | ✅ done (pass 13) |
| v5.0 — Netlify Function live proxy | ✅ done (pass 14) |
| v5.0.1 — CDN-cacheable function response (performance hardening) | ✅ done (pass 15) |
| v5.0.2 — NVD rate-limit hardening + optional server-only `NVD_API_KEY` | ✅ done (pass 16) |
| v5.0.3 — NVD API key transport fix (request header, not URL query param) | ✅ done (pass 17) |
| v5.1 — Soft refresh (silent 5-min poll, "New dataset available" banner, filters preserved) | ✅ done (pass 18) |
| v5.2 — Prebuilt dataset store (Netlify Blobs `latest-dataset` + 15-min `refresh-lock` + scheduled cron + manual background refresh + UI honesty pills) | ✅ done (pass 19) — *this session* |
| v4.5 — Saved filter presets, watchlists, exports | 📋 planned — see Roadmap in `README.md` |
| v5 — CPE-based asset matching, My Inventory mode | 📋 planned |

**v3 + v3 QA (this pass) is complete:**
- Live CISA KEV feed + live NVD CVSS enrichment + live FIRST
  EPSS enrichment, all three fetched in the browser (all APIs
  CORS-enabled, no proxy).
- The source label in the header now reflects the *actual*
  per-provider state — only mentions a provider if its pill
  isn't amber. The loading state copy is honest about the
  multi-source fetch (NVD rate limit can take up to a minute
  on first load).
- Mock dataset is preserved as the offline fallback (and as
  the dataset returned when CISA fetch fails). When CISA
  succeeds but NVD or EPSS fails, the CISA + the working
  secondary source are still shown with a soft banner above
  the stats explaining what's unavailable.
- The header, dashboard, and detail drawer all work on every
  data path — same `Vulnerability` shape, same filter / sort
  pipeline. The filter pipeline now actually exercises real
  CVSS / EPSS data.
- `PORTFOLIO_WRITEUP.md` is the recruiter-facing narrative;
  it stands alone from `README.md` (which is the technical
  reference).
- 15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS + 53/53 v3 NVD + 60/60 v4 cache =
  **195/195** acceptance tests passing; build clean (7.51 s,
  0 errors, 0 warnings).

**What's new in v4 (this pass):**
- Transparent 1-hour localStorage cache. Returning visitors get
  an instant render from `localStorage` instead of paying the
  30–60 s NVD first-load. The cache is fully visible: a
  "Cache: fresh" / "Cache: stale" pill in the header, a "Cached
  data" banner above the stats with both relative and absolute
  time of the last upstream fetch, and a manual "Refresh live
  data" button.
- Provider-status fields (`nvdStatus`, `epssStatus`,
  `fallbackReason`) are preserved through the cache envelope.
  Cached data still shows its NVD-unavailable / EPSS-unavailable
  / Fallback banners exactly as a live load would — the cache
  never hides provider failures.
- New `CacheStatus = 'miss' | 'fresh' | 'stale'` type on
  `FetchResult`, new `forceRefresh?: boolean` on
  `VulnerabilityQuery`. New `formatAbsolute()` helper for the
  Last-refresh tooltip.

**What's still on the user:**
- Upload the contents of `dist/` to Hostinger (pass 6's prep
  is still valid for v3 — nothing about the deployment changed).
- (Optional) uncomment the CSP / HSTS lines in `.htaccess` once
  deployed over HTTPS.
- (Optional) push `main` to GitHub — repo is private, nothing
  pushed yet, **do not push without an explicit ask**.
- (Optional) grab an NVD API key for a 10× rate-limit bump —
  the dashboard currently hits the 5-req/30s anonymous limit.

**Recommended next milestone (v3.5):** small UX additions —
saved filter presets, per-vendor watchlists, CSV / JSON export.
All of these are listed in the Roadmap in `README.md`. None
require touching the data-fetching layer; they all build on
the frozen v3 dataset.

The full deployment guide is in [`DEPLOYMENT.md`](./DEPLOYMENT.md).
