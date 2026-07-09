# ThreatPulse Radar

> A modern cybersecurity **vulnerability-intelligence dashboard** built for
> **defensive** security teams. Track CVEs, KEV status, CVSS scores, EPSS
> probability, and severity across your stack in a single, focused
> command-center view.

![status](https://img.shields.io/badge/status-v5.2-22d3ee?style=flat-square)
![stack](https://img.shields.io/badge/stack-React%20%2B%20Vite%20%2B%20TS-0d1424?style=flat-square)
![use](https://img.shields.io/badge/use-defensive%20only-f43f5e?style=flat-square)

---

## ⚠️ Defensive-only purpose

ThreatPulse Radar is built **exclusively for defensive security work** —
vulnerability prioritization, patch planning, exposure awareness, and
security posture reporting.

It contains **no exploit code, no offensive tooling, and no weaponized
payloads**. All "recommended action" copy is plain-language defensive
guidance (e.g. _"apply the latest vendor patch, rotate credentials,
review access logs"_).

---

## ✨ Features

- **Live CISA KEV data, with mock fallback** — by default the dashboard
  fetches the public [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  feed at runtime. If the fetch fails (offline, CORS, slow network),
  the dashboard automatically falls back to the curated mock dataset so
  the user is never left with a blank screen. The current data source
  and mode are shown in the header.
- **FIRST EPSS enrichment (v2.5)** — when CISA loads successfully, the
  dashboard additionally fetches [FIRST EPSS](https://www.first.org/epss/)
  exploitation-probability scores for every CVE in the catalog and
  fills the `EPSS` column with real values. A CISA record whose CVE is
  not yet scored by FIRST keeps `0.0` — no fabricated scores. If FIRST
  is unreachable, the CISA data is still shown and a soft banner
  explains that EPSS values default to 0.
- **NVD CVSS enrichment (v3.0)** — when CISA loads successfully, the
  dashboard additionally fetches [NVD CVE 2.0](https://nvd.nist.gov/)
  metrics for every CVE in the catalog and fills the `CVSS` and
  `Severity` columns with real values (v3.1 → v3.0 → v2 preference).
  The NVD severity takes precedence over the CISA-derived severity
  when present. A CISA record whose CVE isn't in the NVD response
  keeps `0.0` / the CISA default — no fabricated scores. If NVD is
  unreachable, the CISA + EPSS data is still shown and a soft banner
  explains that CVSS values default to 0.
- **Dashboard overview** — at-a-glance cards for total, critical, high,
  KEV-listed, average EPSS, and new-this-week vulnerabilities.
- **Vulnerability table** with columns for CVE ID, summary, severity,
  CVSS, EPSS, KEV status, vendor, product, published date, and source.
- **Filtering & search** (works identically on live CISA KEV data and
  on the mock dataset — same code path, same UI):
  - Full-text search across CVE ID, vendor, product, and summary
  - Severity filter (Critical / High / Medium / Low / All)
  - KEV-only toggle
  - Minimum EPSS probability slider
  - Sort by newest, CVSS, EPSS, or KEV status
- **Detail drawer** with full description, metrics, affected product,
  recommended defensive action, and external source links.
- **Charts** powered by Recharts:
  - Severity distribution
  - EPSS risk distribution
  - 14-day vulnerability trend
  - KEV vs non-KEV comparison
- **Dark cybersecurity command-center theme** — neon cyan / amber accents,
  readable, professional, desktop-first responsive.
- **Empty / loading / error states** throughout (including a banner
  that surfaces the live-fetch failure reason when fallback kicks in).
- **Transparent 1-hour localStorage cache (v4.0)** — a returning
  visitor sees their previously-fetched dataset instantly instead of
  waiting through the 30–60 s NVD first-load on every visit. The
  cache is fully visible: a "Cache: fresh" / "Cache: stale" pill in
  the header, a "Cached data" banner above the stats that shows both
  the relative and absolute time of the last upstream fetch, and a
  one-click "Refresh live data" button that forces a bypass-cache
  re-fetch. Provider-status banners (NVD / EPSS unavailable,
  Fallback Mode) are still rendered on cached data — the cache
  preserves the original FetchResult fields, so it never hides
  failures.
- **Netlify Function proxy (v5.0)** — the browser prefers
  `/.netlify/functions/dataset`, a single CORS-safe serverless
  endpoint that aggregates CISA KEV + NVD CVSS + FIRST EPSS
  server-side. The browser never hits the upstream feeds
  directly on the happy path, so the public demo no longer
  depends on browser-direct CORS, anonymous rate limits, or
  geo restrictions for those feeds. If the function is
  unreachable, the client falls back to the v4 browser-direct
  pipeline automatically; if both transports fail, the
  existing mock fallback kicks in. A small "Proxy: Netlify"
  pill in the header makes the live transport visible. **No
  API keys, secrets, or tokens are ever embedded in the
  frontend or in the function** — both transports use the
  same anonymous public endpoints. See
  [V5.0 live proxy mode](#-v50-live-proxy-mode) for the full
  architecture.
- **CDN-cacheable function response (v5.0.1)** — the
  function's `Cache-Control` is now
  `public, s-maxage=900, stale-while-revalidate=300`. The
  Netlify edge cache absorbs repeat visitors within a 15 min
  window (and serves a slightly-stale response for an
  additional 5 min while a fresh fetch runs in the
  background). First production load still hits the full
  upstream pipeline once, but second-and-onwards visitors
  within the window get a sub-100 ms response from the CDN.
  The "Refresh live data" button still bypasses the cache
  (via a unique `?t=<timestamp>` query string) so the
  button's name remains honest. The "Last refresh" pill
  reflects the time the function *actually* ran, not the
  time the CDN served the response — freshness copy is
  preserved. See
  [V5.0.1 performance hardening](#-v501-performance-hardening)
  for the full cache-strategy contract.
- **NVD rate-limit hardening + optional server-only
  `NVD_API_KEY` (v5.0.2)** — NVD's anonymous public
  endpoint allows only 5 requests / 30 s, so without a
  key the function serializes NVD chunks (concurrency = 1)
  to avoid HTTP 429. When all chunks return 429, the
  function returns a single concise reason ("NVD rate
  limit reached (HTTP 429). NVD CVSS enrichment is
  unavailable; severity falls back to CISA-derived values
  for this refresh.") instead of repeating the chunk
  error N times — the dashboard's
  `NvdUnavailableBanner` reads cleanly. **An optional
  `NVD_API_KEY` env var is supported server-side only.**
  When set in the Netlify function's environment, NVD
allows 50 req / 30 s, the function parallelizes chunks,
   and the key is never exposed to the browser. The app
   works identically without the key (just slower for
   the first visitor in a region per 15 min). See
   [V5.0.2 NVD rate-limit hardening](#-v502-nvd-rate-limit-hardening)
   for the full rate-limit story.
- **Soft refresh with explicit user consent (v5.1)** — the
  dashboard silently polls the proxy every 5 minutes
  (only while the tab is visible) and detects when a
  newer upstream dataset has landed. A small banner
  appears at the top of the content area:
  > **New dataset available. Updated 2 min ago.** [Apply update] [×]
  Clicking **Apply update** swaps the data in place —
  filters, search, sort, and the open detail view all
  stay exactly as they were. The drawer auto-closes
  only if the selected CVE is no longer in the new
  dataset. The × dismisses the banner until the *next*
  newer dataset arrives (so the same update doesn't
  re-appear on every poll tick). The soft-refresh path
  is entirely client-side: a `setInterval` in
  `DashboardPage` calls `fetchVulnerabilities({
  background: true })`, which skips the localStorage
  cache read but still writes the new result through.
  No deployment-config changes, no new env vars, no
  scheduled functions, no automatic data swap. See
  [V5.1 soft refresh](#-v51-soft-refresh) for the full
  UX contract.
- **Prebuilt dataset store (v5.2)** — the live CISA →
  NVD → EPSS build runs once on the server and the
  result is written to a shared [Netlify Blobs](https://docs.netlify.com/build/data-and-storage/netlify-blobs/)
  entry named `latest-dataset`. Subsequent visitors read
  the prebuilt blob on the first request and never wait
  for a fresh upstream fetch — the dashboard renders the
  latest successfully-built dataset immediately. A new
  cyan "Dataset store: latest available" pill in the
  header makes the storage layer visible. The build is
  triggered by a Netlify scheduled function every 30
  minutes (`*/30 * * * *` cron) and by a Netlify
  Background Function at
  `/.netlify/functions/refresh-dataset-background` that
  the dashboard's "Refresh live data" button POSTs to.
  Both writers use a shared `refresh-lock` blob (15-min
  TTL) so concurrent refreshes are prevented. The
  prebuilt blob is NEVER overwritten with a mock
  fallback; only a successful live build writes to it.
  The manual button keeps the current dataset on screen
  and uses the v5.1 "New dataset available" banner when
  the new blob is detected on the next poll tick — no
  auto-reload, no auto-replace. The v5.1 + v5.2 UI
  honesty contract is preserved end-to-end. See
  [V5.2 prebuilt dataset store](#-v52-prebuilt-dataset-store)
  for the full architecture, the lock semantics, the
  scheduled cadence, and the manual-refresh UX.
- **Service layer** designed to plug in additional real APIs (NVD,
  FIRST EPSS) without touching UI code.

---

## 🧱 Tech stack

| Layer        | Choice                                          |
| ------------ | ----------------------------------------------- |
| Framework    | [React 18](https://react.dev)                   |
| Build tool   | [Vite 5](https://vitejs.dev)                    |
| Language     | TypeScript (strict)                             |
| Styling      | [Tailwind CSS 3](https://tailwindcss.com)       |
| Charts       | [Recharts 2](https://recharts.org)              |
| Icons        | [Lucide React](https://lucide.dev)              |

No login. No database. No payments. No exploit code.
V5.0 adds a single read-only serverless function
(`netlify/functions/dataset`) that aggregates the public
feeds. V5.2 layers a shared [Netlify Blobs](https://docs.netlify.com/build/data-and-storage/netlify-blobs/)
entry (`latest-dataset`) in front of it so visitors
read a prebuilt envelope instead of paying the upstream
pipeline on every page load. V5.2 also adds two more
functions — `refresh-dataset-background.mjs` (manual
refresh) and `refresh-dataset-scheduled.mjs` (cron,
every 30 min) — plus a shared `refresh-lock` blob with
a 15-minute TTL. None of these is a backend in the
traditional sense (no persistent state, no auth, no
business logic, no credentials, no scheduled jobs
beyond the v5.2 cron).

**Data sources:** the dashboard is **defensive-only**.
V5.2 reads public vulnerability feeds via a single
serverless endpoint (`/.netlify/functions/dataset`) by
default, with a transparent browser-direct fallback when
the function is unreachable. The proxy aggregates the
same three feeds that v4 fetched directly from the
browser (CISA KEV, NVD CVE 2.0, FIRST EPSS) — it does
*not* add new sources, and it uses the same anonymous
public endpoints. **No API keys, secrets, or tokens are
ever embedded in the frontend bundle or in the
function.** See [V5.2 prebuilt dataset store](#-v52-prebuilt-dataset-store)
for the full architecture and
[V4.1 public-demo honesty](#-v41-public-demo-honesty) for
the fallback / transparency contract that v5.0 / v5.2
inherits. No new data sources planned for v5.x — see
the [Roadmap](#-roadmap).

---

## 📁 Project structure

```
threatpulse-radar/
├── index.html
├── netlify.toml                       # v5.0 Netlify config (build + functions)
├── package.json
├── tailwind.config.js
├── postcss.config.js
├── tsconfig.json
├── tsconfig.app.json
├── tsconfig.node.json
├── vite.config.ts
├── public/
│   ├── .htaccess                     # SPA fallback, cache, security headers (Hostinger)
│   └── radar.svg
├── netlify/
│   └── functions/
│       ├── dataset.mjs               # v5.0 read endpoint (v5.2: blob-first)
│       ├── refresh-dataset-background.mjs   # v5.2 manual refresh (BG fn)
│       ├── refresh-dataset-scheduled.mjs    # v5.2 cron refresh (every 30 min)
│       └── _shared/
│           ├── store.mjs             # v5.2 Netlify Blobs + lock helpers
│           ├── refresh.mjs           # v5.2 lock + write orchestrator
│           └── liveBuild.mjs         # v5.2 shared CISA→NVD→EPSS pipeline
└── src/
    ├── main.tsx                       # entry
    ├── App.tsx                        # thin shell
    ├── index.css                      # Tailwind + global polish
    ├── vite-env.d.ts                  # import.meta.env typing for v5.0
    ├── components/                    # presentational + container pieces
    │   ├── Header.tsx                 # + "Proxy: Netlify" pill (v5.0)
    │   ├── StatsCards.tsx
    │   ├── FiltersPanel.tsx
    │   ├── VulnerabilityTable.tsx
    │   ├── DetailDrawer.tsx
    │   ├── EmptyState.tsx
    │   ├── LoadingState.tsx
    │   ├── ErrorState.tsx
    │   ├── SearchStatus.tsx
    │   └── charts/
    │       ├── SeverityChart.tsx
    │       ├── TrendChart.tsx
    │       └── KevChart.tsx
    ├── data/
    │   └── mockVulnerabilities.ts     # 60 fictional CVEs (v1 mock + fallback)
    ├── pages/
    │   └── DashboardPage.tsx          # single-screen dashboard
    ├── services/
    │   ├── vulnerabilityService.ts    # v5.0: proxy-first orchestration
    │   │                              # v5.2: + manualRefresh() + dataSource / refreshInProgress fields
    │   ├── datasetCache.ts            # v4 localStorage cache layer
    │   └── providers/
    │       ├── README.ts              # reserved for v4 providers
    │       ├── cisaKev.ts             # CISA KEV fetch + normalize
    │       ├── epss.ts                # FIRST EPSS batched fetch + enrich
    │       └── nvd.ts                 # NVD CVE 2.0 batched fetch + enrich
    ├── types/
    │   └── vulnerability.ts           # shared domain types
    ├── hooks/
    │   ├── useDebouncedValue.ts
    │   └── useVulnerabilityFilter.ts
    └── utils/
        ├── analytics.ts               # filter, sort, aggregate
        ├── format.ts                  # date / score formatters
        └── severity.ts                # color + ordering helpers
```

---

## 🔌 Data sources

The service layer (`src/services/vulnerabilityService.ts`) returns
`Promise<FetchResult<Vulnerability[]>>` with a `(source, mode)` pair
that describes where the data came from. The same `Vulnerability` shape
is used everywhere, so the filter / sort / chart pipeline doesn't
care which source is active.

| Source                  | Status   | Provides                                          | Endpoint |
| ----------------------- | -------- | ------------------------------------------------- | -------- |
| **CISA KEV** (v2)       | ✅ Live  | Known-exploited boolean, due dates, ransomware-use | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| **NVD CVE 2.0** (v3)    | ✅ Live enrichment | CVSS base score + severity (v3.1 → v3.0 → v2) for each CISA CVE | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=…` |
| **FIRST EPSS** (v2.5)   | ✅ Live enrichment | Exploitation probability (0–1) for each CISA CVE | `https://api.first.org/data/v1/epss?cve=…` |
| **Mock dataset** (v1)   | ✅ Live  | 60 fictional CVEs spanning 16 vendors              | `src/data/mockVulnerabilities.ts` (in-bundle) |

**How the CISA KEV integration works (v2):**

- The browser fetches CISA KEV directly (CISA serves the feed with
  permissive CORS).
- The fetch has an 8 s `AbortController` timeout — a slow CISA
  response can't hang the dashboard.
- Records are normalized into the same `Vulnerability` shape used
  for the mock data. CISA KEV doesn't carry CVSS or EPSS scores,
  so those default to `0` and the description carries a short note
  explaining why. Severity is derived from
  `knownRansomwareCampaignUse`: `Known` → `Critical`, otherwise
  `High` (KEV by construction is at least High).
- On any failure (network, abort, non-2xx, shape mismatch) the
  service returns the mock dataset with `mode: 'fallback'` and a
  `fallbackReason` string. The header shows a "Fallback Mode"
  badge, the source pill turns amber, and a banner above the
  stats explains what happened and offers a "Retry live fetch"
  button.
- The service constant `DATA_MODE` in
  `src/services/vulnerabilityService.ts` can be flipped to `'mock'`
  to force the local dataset (useful for offline development).

**How the v4 transparent cache works:**

- The full `FetchResult` (including `nvdStatus`, `epssStatus`, and
  `fallbackReason`) is written to `localStorage` under the
  versioned key `tpr:dataset:v1` after every successful live
  fetch. The 1-hour TTL is encoded as `60 * 60 * 1000 ms`.
- On subsequent loads, the service checks the cache first. A
  fresh hit (< 1 h) returns the cached result with
  `cacheStatus: 'fresh'` — no live fetch needed, instant render.
- A stale hit (> 1 h) is returned only as a last-resort fallback
  when the live fetch just failed, with `cacheStatus: 'stale'`.
  The header pill turns amber and the dashboard banner tells the
  user the data is older than the TTL.
- All `localStorage` access is wrapped in try/catch, so private
  mode / disabled storage / quota exceeded never crashes the
  dashboard. The cache is an optimization, not a requirement.
- The "Refresh live data" button in the cached-data banner calls
  `fetchVulnerabilities({ forceRefresh: true })`, which clears the
  cache and runs the full live path again. Failures during a
  forced refresh are surfaced through the same fallback banner
  path as on first load — never silently masked.
- Critically: provider-status fields (`nvdStatus`,
  `epssStatus`, `fallbackReason`) are preserved through the
  cache. If the original live fetch had NVD or EPSS unavailable,
  those banners still render on cached data. **The cache never
  hides provider failures.**

---

## 🌐 V4.1 public-demo honesty

A static public deployment of a "live" data dashboard has a real
honesty problem: third-party feeds can block or rate-limit
direct browser requests at any time (CORS, geo-blocking,
anonymous rate limits, upstream outages), and the easy response
is to silently swap in a pre-baked dataset so the page never
goes blank. **The v4.1 stance is the opposite: the failure
mode is shown, not hidden.**

**1. The dashboard is frontend-only and defensive-only.** No
backend, no serverless function, no proxy, no database, no
auth, no payments. All three feeds (CISA KEV, NVD, FIRST EPSS)
are fetched directly from the visitor's browser at runtime.
There is nothing to configure on the server beyond the static
files in `dist/`.

**2. The static public demo may show fallback / mock mode
when a public data feed blocks direct browser requests.** This
is expected for v4.1, not exceptional. Browser-direct access
to a public feed depends on CORS, anonymous rate limits, geo
restrictions, and upstream availability — a static public
deployment cannot *guarantee* any of those. A provider can
tighten its CORS policy, rate-limit anonymous browser
traffic, return 4xx from a particular region, or simply be
down. In every one of those cases, the public demo degrades
honestly:

- The header shows an **amber "Fallback Mode"** badge and a
  "Source: mock (fallback)" pill.
- A **"Live CISA KEV feed unavailable — showing mock data"**
  banner appears above the stats with the failure reason and
  a "Retry live fetch" button.
- The 60-record curated mock dataset is rendered. The
  dashboard is fully functional against it: filtering,
  sorting, search, charts, and the detail drawer all work
  identically.

For *partial* upstream failures (CISA succeeded, but NVD or
EPSS didn't), the same pattern applies at the per-provider
level: the working providers' data is shown, an amber
"unavailable" pill appears in the header, and a soft banner
above the stats explains the partial outage.

**3. The UI is intentionally transparent about this.** Three
mechanisms in v4 / v4.1 make provenance visible at all times:

- The header source pill reads `Source: CISA KEV + NVD +
  FIRST EPSS` only when every named provider actually
  contributed data; otherwise it downgrades to the
  providers that did (e.g. `Source: CISA KEV + FIRST EPSS`
  when NVD failed), and to `Source: mock (fallback)` when
  CISA itself failed.
- The per-provider pills (`NVD: enriched` / `NVD:
  unavailable`, `EPSS: FIRST` / `EPSS: unavailable`) turn
  amber with the failure reason in their tooltip on any
  partial failure.
- The v4 cache pill (`Cache: fresh` / `Cache: stale`) plus
  the "Cached data" banner above the stats make it clear
  when the data is being served from `localStorage` and
  what the original upstream fetch time was.

**4. The app never hides provider failures.** The v4 cache
envelope preserves the full `FetchResult` (including
`nvdStatus`, `epssStatus`, and `fallbackReason`), so cached
data is rendered with the same provider-failure banners that
the original live load produced. The cache is an
optimization, not a way to make failures invisible.

**5. No API keys are ever embedded in the frontend bundle.**
A static `dist/` is a public artifact the moment the site is
deployed — any key shipped in it is a public credential. The
NVD API key path is intentionally not implemented in v4.1;
the 5-req/30s anonymous rate limit is a price worth paying
for not shipping a public secret. (The README previously
mentioned "a future pass could plumb an NVD API key" — that
option is closed in v4.1.)

**6. A future v5 could introduce a thin backend or
serverless proxy** that aggregates CISA + NVD + FIRST EPSS
server-side and exposes a single CORS-safe JSON endpoint.
The v4.1 service layer is designed so a backend can be
added as a new `provider` without touching UI code or
breaking the existing fallback path. **v4.1 does *not* add
the backend** — that is an explicit v5 milestone, listed
under the [Roadmap](#-roadmap) below.

---

## ⚡ V5.0 live proxy mode

V5.0 ships the v4.1 v5 milestone. The architecture is:

```
Browser ──► /.netlify/functions/dataset ──► CISA KEV
                                          NVD CVE 2.0
                                          FIRST EPSS
        (only on proxy failure)
        ──► browser-direct CISA / NVD / EPSS
        (only on total failure)
        ──► local mock dataset (Fallback Mode)
```

The function lives at `netlify/functions/dataset.mjs`. It
is a self-contained Node 20 ESM module (no imports from
`src/`, no dependencies) that re-implements the CISA → NVD
→ EPSS pipeline with the same field shapes and
normalization rules as the browser-side providers in
`src/services/providers/`. It returns a JSON envelope
identical in shape to the client-side `FetchResult`:

- **HTTP 200** on success:
  `{ data, source: 'merged', mode: 'live', fetchedAt,
     nvdStatus, nvdReason, epssStatus, epssReason }`. A
  partial NVD or EPSS failure still returns 200 with
  `nvdStatus: 'unavailable'` / `epssStatus: 'unavailable'`.
- **HTTP 502** when CISA itself failed:
  `{ mode: 'fallback', fallbackReason }`. The client treats
  this as a proxy failure and falls through to browser-direct.

The frontend (`src/services/vulnerabilityService.ts`)
prefers the proxy on every fetch:

1. **Proxy success** → return with `proxyStatus: 'proxy'`.
   The header shows a small cyan "Proxy: Netlify" pill so
   the user can see which transport carried the data.
2. **Proxy failure** → fall back to the v4
   `tryBrowserDirectFetch` (the existing CISA → NVD → EPSS
   pipeline). If that succeeds, return with
   `proxyStatus: 'browser-direct'`.
3. **Both transports failed** → return the local mock
   dataset with `mode: 'fallback'`,
   `fallbackReason` explaining the total failure, and
   `proxyStatus: 'unavailable'`.

**All v4 invariants are preserved:**

- The localStorage cache still wraps the live path. A
  successful proxy fetch is cached; a successful
  browser-direct fetch is cached; a mock fallback is never
  cached. A stale cache hit on a total transport failure
  still surfaces the original provider-status banners.
- The per-provider status fields (`nvdStatus`, `epssStatus`)
  and the `fallbackReason` survive every transport swap and
  every cache round-trip. The cache never hides failures.
- The header pills, banners, and source labels are
  source-honest. The user can see at a glance whether
  they're looking at proxy-fetched, browser-direct,
  cached, or mock-fallback data.

**What v5.0 does *not* add (the line that matters):**

- **No API keys** in the frontend or in the function. The
  proxy uses the same anonymous public endpoints the
  browser used in v4 — there is no credential to leak.
- **No new data sources.** OSV.dev, GitHub Advisory
  Database, and other aggregators remain a v5.1+
  milestone, not a v5.0 feature.
- **No scheduled / background functions.** The dataset
  function runs on demand per request.
- **No database, no auth, no login.** The function is
  read-only and idempotent.
- **No UI redesign.** The v4.1 header, dashboard, table,
  filters, and detail drawer are unchanged. The only new
  visible element is the small "Proxy: Netlify" pill in
  the header, shown only when the proxy was the live
  transport.

**Local development note:** `npm run dev` runs the Vite
dev server, which does *not* serve Netlify Functions. The
proxy endpoint will 404 on `http://localhost:5173` unless
you run `netlify dev` (which proxies Functions through the
Vite dev server). On `netlify dev`, both transports work.
On `npm run dev` only, the proxy returns null and the
client transparently falls back to the browser-direct
path — the dashboard still works, the proxyStatus field
reads `browser-direct`. See
[`DEPLOYMENT.md`](./DEPLOYMENT.md) for the full local-dev
and Netlify-deploy workflows.

---

## ⚡ V5.0.1 performance hardening

V5.0.1 is a patch release on top of v5.0. It does **not**
add features, change data sources, change the UI, or
change the data flow. The single goal: make repeat
production loads fast without ever misleading the user
about how fresh the data is.

### The problem v5.0 left on the table

The v5.0 function returned `Cache-Control: no-store` on
every response. Netlify's edge cache respected that and
re-ran the full CISA → NVD → EPSS pipeline on every
single request — even if the same visitor reloaded five
times in a minute. On a busy public demo that meant
dozens of unnecessary upstream fetches per minute per
region, and a cold first load for every visitor in every
region.

### The v5.0.1 fix

The function's response is now
`Cache-Control: public, s-maxage=900, stale-while-revalidate=300`.
That single header change does three things:

- **`s-maxage=900`** — Netlify's edge cache holds the
  response for **15 minutes**. Within that window, every
  visitor in the same region gets the cached response
  in <100 ms. No upstream fetch, no function run, no
  cold start.
- **`stale-while-revalidate=300`** — after the 15 min
  mark, the cache is "stale" for another **5 minutes**.
  Netlify serves the stale response immediately AND
  triggers a background function invocation to refresh
  the cache. This avoids the "thundering herd" problem
  where many visitors all wait on a slow function at
  once.
- **No `max-age` directive** — the browser is not told
  to cache the JSON locally (the client uses
  `cache: 'no-store'` on its fetch anyway). The
  `s-maxage` directive is what Netlify's edge honors.
  The `max-age` directive would have told the browser
  to cache the response across reloads, which would
  shadow the localStorage cache and the per-load
  honesty contract.

### How freshness stays honest

Three guarantees keep the dashboard source-honest under
the new caching:

1. **The function's `fetchedAt` is set inside the
   function body**, at `new Date().toISOString()` on the
   moment the function actually runs. When the CDN
   serves a cached response, the `fetchedAt` is from
   the *original* function run, not the CDN serve
   time. The "Last refresh" pill (`formatRelative(meta.fetchedAt)`)
   therefore shows the time since the real upstream
   fetch, even on a CDN-cached response.
2. **The "Refresh live data" button appends a unique
   `?t=<timestamp>` query string** when `forceRefresh: true`
   is passed. The CDN treats this as a different URL and
   does *not* hit its cache — the function actually re-runs.
   The button's name remains honest: a manual refresh
   always fetches fresh upstream data.
3. **The localStorage cache (v4) is unchanged.** It
   still wraps the live path with a 1 h TTL. The two
   layers compose: a 15 min CDN cache + a 1 h
   localStorage cache + the in-memory `cacheStatus`
   pill. No layer hides the others.

### What you should observe in production

- **First visitor in a region** (cold CDN cache):
  the full CISA → NVD → EPSS pipeline runs once,
  taking 5–15 s. Subsequent visitors in the same
  region within 15 min get the cached response.
- **Visitor at minute 16** (cache just expired):
  Netlify serves the stale response immediately AND
  triggers a background refresh. The next visitor
  after the refresh hits the fresh cache.
- **Visitor at minute 21+** (cache fully expired):
  the next request waits for a fresh function
  invocation. Cold.
- **Visitor who clicks "Refresh live data"** at any
  time: the `?t=<timestamp>` cache-buster forces a
  real function run. The "Last refresh" pill ticks
  to "just now".

### What v5.0.1 does *not* add

- **No new data sources.** OSV.dev, GHSA, etc. are
  still v5.1+ milestones.
- **No new dependencies.** Plain Node 20 ESM in the
  function, plain React in the client.
- **No new environment variables.** The
  `VITE_DATASET_PROXY_URL` client-side env var
  default is unchanged.
- **No UI changes.** Same header, same pills, same
  banners, same dashboard layout.
- **No scheduled / background functions.** The
  `stale-while-revalidate` directive is a CDN-layer
  mechanism, not a function scheduled job. The
  function still runs on demand.
- **No new fake freshness claims.** A CDN-cached
  response is not advertised as a fresh fetch; the
  "Last refresh" pill reflects the actual function
  run time, not the CDN serve time.

### Test count

**15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS +
53/53 v3 NVD + 60/60 v4 cache + 55/55 v5.0/v5.0.1
proxy = 250/250.**

---

## 🛡️ V5.0.2 NVD rate-limit hardening

V5.0.2 is a small reliability/UX patch on top of v5.0.1.
It does **not** add new sources, change the UI, or change
the data flow. Two related changes that solve a real
friction point on the public demo.

### The problem v5.0.1 left on the table

NVD's anonymous public endpoint allows only
**5 requests / 30 s** per source IP. The v5.0 function
was firing all 10 NVD chunks (one per 100 CVEs) in
parallel via `Promise.allSettled` — guaranteed to hit
HTTP 429 on the first hit in every region. The function
then produced a long repeated error string like

```
HTTP 429 Too Many Requests; HTTP 429 Too Many Requests;
HTTP 429 Too Many Requests; HTTP 429 Too Many Requests;
HTTP 429 Too Many Requests; HTTP 429 Too Many Requests;
HTTP 429 Too Many Requests; HTTP 429 Too Many Requests;
HTTP 429 Too Many Requests; HTTP 429 Too Many Requests
```

…which the dashboard's `NvdUnavailableBanner`
displayed verbatim, spilling past the banner boundary and
making the public demo look broken.

### The v5.0.2 fix

**1. Optional `NVD_API_KEY` env var, server-side only.**
When the Netlify function has `process.env.NVD_API_KEY`
set, NVD allows 50 req / 30 s, and the function
parallelizes NVD chunks. When the var is absent (the
default), the function **serializes NVD chunks
(concurrency = 1)** to stay under the anonymous limit.

```
without NVD_API_KEY:    CISA → [NVD chunk 1 → NVD chunk 2 → ... → NVD chunk 10] → EPSS
with NVD_API_KEY:       CISA → [NVD chunk 1, 2, 3, ..., 10]  → EPSS
```

The key is:

- read from `process.env.NVD_API_KEY` **inside the
  Netlify Function only** (server-side);
- passed to NVD as a request header `apiKey: <key>` from
  the Netlify Function, never exposed to the browser
  (v5.0.3 — NVD's official CVE 2.0 spec uses the `apiKey`
  request header, not a URL query parameter);
- **never** sent to the browser, **never** included in
  the function response body, **never** logged;
- **optional** — the function works identically without
  it (just slower for the first visitor in a region per
  15 min — repeat visitors ride the v5.0.1 CDN cache
  either way).

The frontend (`src/**`) is unchanged. No `VITE_NVD_API_KEY`
or any other build-time env var is added. **There is no
API key in the frontend bundle.**

**2. Concise 429 reason.** If every failed chunk is
HTTP 429, the function throws a single short reason
instead of joining N repeated chunk errors:

```
NVD rate limit reached (HTTP 429). NVD CVSS enrichment is
unavailable; severity falls back to CISA-derived values
for this refresh.
```

The dashboard's `NvdUnavailableBanner` reads this
reason verbatim. The banner now renders cleanly as:

> **NVD CVSS enrichment unavailable — scores default to 0.**
>
> CISA KEV data is current. NVD could not be reached:
> NVD rate limit reached (HTTP 429). NVD CVSS enrichment
> is unavailable; severity falls back to CISA-derived
> values for this refresh. Severity and CVSS sorting
> will fall back to the CISA-derived values (KEV records
> default to "High"; ransomware-known records to
> "Critical").

For non-429 failures (timeout, 5xx, network error), the
function de-duplicates per-chunk error messages via
`Array.from(new Set(reasons))` so the banner doesn't
show "HTTP 503; HTTP 503; HTTP 503" either.

### Honesty guarantees (preserved)

- The function's `fetchedAt` is still set inside the
  function body. The dashboard's "Last refresh" pill
  reflects when the function *actually* ran, even on a
  CDN-cached response. The `?t=<timestamp>` cache-buster
  on the "Refresh live data" button still forces a real
  function run.
- The function response never contains the API key
  (asserted by `acceptance-proxy.mjs`: the key is read
  from `process.env`, passed to NVD's URL, and never
  flows into the JSON body).
- Provider-status banners are preserved on cached data
  and on key-less deployments: a 429 with no key renders
  as "NVD: unavailable" with the concise reason; a
  successful NVD call with a key renders as "NVD:
  enriched" with no rate-limit copy.
- The dashboard never claims NVD is enriched when it
  is unavailable — the `nvdStatus` field is the
  source of truth, and the banner only renders when
  `nvdStatus === 'unavailable'`.

### Configuring `NVD_API_KEY` on Netlify

```
# In the Netlify site dashboard:
#   Site settings → Environment variables → Add variable
#   Key:   NVD_API_KEY
#   Value: <your NVD API key>
#   Scopes: Functions (NOT "Build" — the function reads it at runtime, not at build time)
```

The function picks the key up at the next invocation.
No rebuild is required. The key is never sent to the
browser, never logged, never stored anywhere else.

### Test count

**15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS +
53/53 v3 NVD + 60/60 v4 cache + 71/71 v5.0/v5.0.1/v5.0.2/v5.0.3
proxy + 58/58 v5.1 soft-refresh = 324/324.**

---

## 🔄 V5.1 soft refresh

> The dashboard now silently polls the proxy for newer
> upstream data and lets *you* decide when to swap it in.
> A triage session mid-investigation is never disturbed.

### The UX contract

1. **Visitor opens the dashboard** — the latest stored
   dataset loads instantly (v4 localStorage cache hit,
   or v5 proxy).
2. **Background refresh starts / scheduled refresh runs**
   — a `setInterval` inside `DashboardPage` calls
   `fetchVulnerabilities({ background: true })` every
   5 minutes, but only while the tab is visible. No
   spinner, no layout shift, no full-page reload.
3. **New dataset becomes available** — a small banner
   appears at the top of the content area:

   > **New dataset available. Updated 2 min ago.** [Apply update] [×]

4. **User clicks "Apply update"** — the data updates
   smoothly in place:
   - Filters stay.
   - Search stays.
   - Sort stays.
   - Selected detail view stays (or, if the selected
     CVE is no longer in the new dataset, the drawer
     auto-closes).
   - No full-page reload.
5. **User clicks × (or never clicks anything)** — the
   banner is dismissed. The same exact update won't
   re-appear on every poll tick — only a strictly newer
   one will.

### How detection works

The dashboard polls with a new optional flag:

```ts
fetchVulnerabilities({ background: true })
```

`background: true` skips the localStorage cache read
for this single call (so a routine poll can actually
detect a newer upstream dataset — reading the same
local cache forever would never trigger an update)
and still writes the result through to the cache on
success. It does **not** bust the CDN: a background
poll within the CDN's `s-maxage=900` window cheaply
gets the cached function response, which is the
intended path.

The polling effect then compares the result's
`fetchedAt` to the currently displayed one. A banner
is shown only when:

- the result is `mode === 'live'` (a mock fallback or
  stale cache re-serve is never surfaced — that
  isn't a "new dataset"),
- `result.fetchedAt > displayed.fetchedAt`, AND
- `result.fetchedAt !== dismissedFetchedAt` (so a
  stale-while-revalidate re-serve of the same exact
  update doesn't re-show the banner).

### Why explicit user consent

The whole point of v5.1 is that the user is never
disturbed mid-task. Auto-applying a new dataset while
the user is mid-row in the table, or has carefully
scoped filters / a search query, would clobber their
context. The banner sits at the top of the content
area, doesn't auto-dismiss, and only goes away on
Apply or × click. The poll is silent otherwise.

### Honesty guarantees (preserved)

- **No new data sources.** OSV.dev / GHSA / other
  aggregators remain a v5.2+ milestone.
- **No login / auth.** No database. **No scheduled
  functions.** The 5-minute `setInterval` runs only
  on the user's open tab — there is no server-side
  scheduler and no Netlify scheduled function.
- **No new env vars.** The only server-side env var
  (`NVD_API_KEY`) is unchanged from v5.0.2 / v5.0.3.
- **No new API keys, secrets, or tokens.**
- **No CDN changes.** The function still serves
  `Cache-Control: public, s-maxage=900,
  stale-while-revalidate=300` from v5.0.1.
- **No automatic background data swap.** The user
  must always click "Apply update" — the soft-refresh
  banner is informational, never auto-applied.
- **The cache never hides provider failures.** A
  background poll that returns `mode: 'fallback'` or
  `mode: 'mock'` is never surfaced as a "new
  dataset" banner.
- **No new offensive / exploit functionality.**

### Test count

**58/58 v5.1 soft-refresh tests.** 12 pure-JS
behavior assertions on the `shouldShowPendingUpdate`
decision (newer / equal / older / mock / fallback /
dismissed-equal / dismissed-older / defensive nulls).
6 service-wiring assertions. 30 dashboard-wiring
assertions. 10 regression assertions on the existing
v4 / v5.0.3 contracts. Run with:

```bash
node scripts/acceptance-softrefresh.mjs
```

---

## 🗄️ V5.2 prebuilt dataset store

> The CISA → NVD → EPSS build now runs **once on the
> server** and every visitor reads the prebuilt envelope
> from Netlify Blobs. No more waiting for the upstream
> pipeline on every page load.

### Architecture

```
                            Netlify Blobs (store: tpr-dataset)
                           ┌──────────────────────────────┐
                           │ latest-dataset  (FetchResult)│  ← written only
                           │ refresh-lock    (TTL 15 min) │    after a
                           └──────────────────────────────┘    SUCCESSFUL
                                      ▲              ▲          live build
                                      │              │
   Visitor request                     │              │
   ─────────────────────────────────►  │              │
                                       │              │
   Browser ──► /.netlify/functions/dataset (READ)
                  │ blob hit? ──► return latest-dataset  ◄──────┐
                  │ blob miss? ──► build CISA→NVD→EPSS ───────┤
                  │                  write blob (success only)  │
                  │                  return envelope           │
                                                           │
   Scheduled tick (every 30 min) ──► refresh-dataset-scheduled
                                                           │
   User clicks "Refresh live data" ──► refresh-dataset-background
```

The browser calls **only** the read endpoint
(`/.netlify/functions/dataset`) on every page load. The
read endpoint checks `latest-dataset` first; if the
blob exists, the visitor gets it immediately (with
`dataSource: "prebuilt-store"`). If no blob exists yet
(cold deploy, first visitor), the read endpoint runs the
existing CISA → NVD → EPSS build on this request, writes
the result to the blob, and returns it with
`dataSource: "live-build"`. The next visitor hits the
fast path.

### Refresh lock — preventing duplicate builds

A shared `refresh-lock` blob in the same store holds
`{ startedAt, expiresAt }` with a 15-minute TTL. Every
refresh attempts to acquire the lock:

- Lock acquired → run the build, write the blob, release
  the lock.
- Lock already held (and not expired) → return
  `{ status: "in-progress", refreshInProgress: true }`
  without doing any work.

The 15-minute TTL is long enough for the longest
realistic build (no NVD API key → ~60 s of serial chunks)
and short enough that a hung refresh doesn't block the
next scheduled tick forever.

### Scheduled refresh (every 30 min)

The `refresh-dataset-scheduled.mjs` function is wired in
`netlify.toml`:

```toml
[functions.refresh-dataset-scheduled]
  node_bundler = "none"
  schedule = "*/30 * * * *"
```

The schedule is conservative — every 30 minutes on the
hour and half-hour. The function acquires the lock,
runs the build, writes the blob, releases the lock.
If the manual button has already kicked off a refresh,
the scheduled tick returns `in-progress` without doing
anything.

### Manual refresh — keeping the user in control

The dashboard's "Refresh live data" button no longer
calls `fetchVulnerabilities({ forceRefresh: true })` on
the read endpoint. Instead it POSTs to:

```
POST /.netlify/functions/refresh-dataset-background
```

This is a Netlify **Background Function** (filename
suffix `-background.mjs`) with up to a 15-minute
timeout. It returns a 202 immediately, runs the actual
build via `context.waitUntil`, and updates the shared
blob. The dashboard **does not** replace the visible
dataset on this call — the existing v5.1 polling
detects the new blob on the next tick and surfaces the
"New dataset available" banner. The user clicks Apply.

While the rebuild is in flight, the header shows:

> **🔄 Refresh running in background** (cyan, pulsing)

…and the dashboard's `RefreshInProgressBanner` appears
above the cache banner. Both clear automatically when the
next poll returns `refreshInProgress: false` (the
server-side build is done).

### UI honesty contract

The v5.2 layer adds three honest signals and preserves
the v5.0 / v5.0.1 / v5.0.3 contract:

| Field / pill | When shown | Tells the user |
| --- | --- | --- |
| `dataSource: "prebuilt-store"` → "Dataset store: latest available" pill | The current FetchResult came from the shared blob | "You're reading from the prebuilt store; no live build ran on this request." |
| `dataSource: "live-build"` → "Dataset store: bootstrapping" pill | This request ran the full pipeline because no blob existed | "No prebuilt dataset yet — the build ran live and was written to the store. Next visitor will hit the fast path." |
| `refreshInProgress: true` → "Refresh running in background" pill | The `refresh-lock` blob is active | "A scheduled or manual refresh is rebuilding the shared dataset. Your current view is unchanged." |
| `nvdStatus` / `epssStatus` from the blob | Always preserved through the blob envelope | "Provider-failure banners are still rendered on stored data — the store never hides failures." |
| "Last refresh: <relative>" pill | The existing pill, unchanged | "Last dataset build: <absolute>" — the tooltip now uses the v5.2 wording. |

The store is **never** overwritten with a mock fallback.
If a refresh build fails, the existing blob is left
intact and the failure reason is logged server-side.

### Honesty guarantees (preserved)

- **No new data sources.** OSV.dev / GHSA / other
  aggregators remain a v5.3+ milestone.
- **No login / auth.** **No database.** The Blobs store
  is a managed key/value store, not a database.
- **No auto-replace.** Manual refresh keeps the current
  dataset on screen; the v5.1 banner is the only way the
  data is swapped.
- **No new API keys.** `NVD_API_KEY` remains server-side
  only.
- **The cache never hides provider failures.** A stored
  envelope with `nvdStatus: "unavailable"` still surfaces
  the `NvdUnavailableBanner` — the blob preserves the
  full FetchResult verbatim.
- **No new frontend env vars.** `VITE_REFRESH_ENDPOINT_URL`
  is a public route, optional, with a default.
- **No offensive / exploit functionality.**

### Test count

**98/98 v5.2 prebuilt-dataset tests.** 7 dependency /
shared-module assertions, 7 blob-key / store-name
assertions, 2 refresh-lock TTL assertions, 15 pure-JS
lock + refresh-decision logic assertions, 8 background-
function assertions, 6 scheduled-function assertions, 5
`netlify.toml` configuration assertions, 13 dataset-
function blob-first / bootstrap / no-overwrite assertions,
11 frontend-service `manualRefresh` + new-types assertions,
14 dashboard + Header UI honesty assertions, 5 contract
honesty assertions, and 6 v5.1 regression assertions.
Run with:

```bash
node scripts/acceptance-prebuilt.mjs
```

---

## 🛣️ Roadmap

- [x] v1 — Polished frontend, mock data, full filtering & visualization
- [x] v2 — **CISA KEV live data with automatic mock fallback**
- [x] v2.1 — Severity sort comparator fix
- [x] v2.5 — **FIRST EPSS enrichment**
- [x] v3 — **NVD CVE 2.0 CVSS enrichment**
- [x] v4 — **Transparent 1-hour localStorage cache** — a
  "Cache: fresh" / "Cache: stale" pill in the header, a
  "Cached data" banner above the stats, and a manual
  "Refresh live data" button. Provider failures are never
  hidden.
- [x] v4.1 — **Public-demo honesty hardening** — docs
  updated to be source-honest about static deployment
  and browser CORS. The public demo is intentionally
  transparent when any provider is unreachable; no API
  keys are ever embedded in the frontend bundle. See
  [V4.1 public-demo honesty](#-v41-public-demo-honesty)
  for the full stance.
- [x] v5.0 — **Netlify Function live proxy** — a single
  serverless endpoint at `/.netlify/functions/dataset`
  aggregates CISA KEV + NVD CVSS + FIRST EPSS server-side.
  The browser prefers the proxy and falls back to
  browser-direct on transport failure. No API keys, no
  new sources, no UI redesign. See
  [V5.0 live proxy mode](#-v50-live-proxy-mode) for the
  full architecture.
- [x] v5.0.1 — **CDN-cacheable function response
  (performance hardening)** — the function's
  `Cache-Control` is now
  `public, s-maxage=900, stale-while-revalidate=300`,
  so Netlify's edge cache absorbs repeat visitors within
  a 15 min window. "Refresh live data" still forces a
  real function run via a cache-busting `?t=<timestamp>`
  query string. `fetchedAt` remains honest (set inside
  the function body, not by the CDN). See
  [V5.0.1 performance hardening](#-v501-performance-hardening)
  for the full cache-strategy contract.
- [x] v5.0.2 — **NVD rate-limit hardening + optional
  server-only `NVD_API_KEY`** — without a key, NVD
  chunks fetch serially (concurrency = 1) to stay
  under the 5-req/30s anonymous limit; with a key,
  chunks fetch in parallel. The function returns a
  single concise 429 reason instead of N repeated
  chunk errors. The key is `process.env.NVD_API_KEY`,
  server-side only, never sent to the browser. The
  app works identically without the key. See
  [V5.0.2 NVD rate-limit hardening](#-v502-nvd-rate-limit-hardening)
  for the full rate-limit story.
- [x] v5.0.3 — **NVD API key transport fix** — the
  optional `NVD_API_KEY` is now passed to NVD as
  the `apiKey` request header per NVD's official
  CVE 2.0 spec, not as a URL query parameter.
  Same honesty contract as v5.0.2: server-side
  only, never exposed to the browser.
- [x] v5.1 — **Soft refresh with explicit user
  consent** — silent 5-minute background poll
  detects a newer upstream dataset and surfaces
  a "New dataset available. Updated 2 min ago."
  banner with an Apply update button. Filters /
  search / sort / selected detail view are
  preserved across the apply. Drawer auto-closes
  only if the selected CVE is no longer in the
  new dataset. × dismisses the banner until the
  next newer dataset. No new env vars, no
  scheduled functions, no automatic data swap.
  See [V5.1 soft refresh](#-v51-soft-refresh) for
  the full UX contract.
- [x] v5.2 — **Prebuilt dataset store with
  scheduled + manual refresh (this release)** —
  the CISA → NVD → EPSS build now runs **once
  on the server** and every visitor reads a
  shared `latest-dataset` Netlify Blobs entry.
  A scheduled function (`*/30 * * * *` cron,
  every 30 min) and a Netlify Background
  Function (manual refresh) share a 15-min
  `refresh-lock` blob so concurrent rebuilds are
  prevented. The dashboard's "Refresh live data"
  button POSTs to the background endpoint; the
  current dataset stays on screen; the v5.1
  polling detects the new blob on the next tick
  and surfaces the "New dataset available"
  banner. New "Dataset store: latest available"
  + "Refresh running in background" pills make
  the storage + lock state visible. No new data
  sources, no auth, no database, no auto-replace.
  See [V5.2 prebuilt dataset store](#-v52-prebuilt-dataset-store)
  for the full architecture.
- [ ] v4.5 — Saved filter presets (e.g. _"Internet-facing + KEV"_)
- [ ] v4.5 — Per-vendor watchlists and email/Slack digest
- [ ] v4.5 — CSV / JSON export of filtered results
- [ ] v5 — CPE-based asset matching: "which of _my_ products are exposed?"
- [ ] v5 — Local-only "My Inventory" mode with optional read-only API

---

## 🏃 Run it locally

Prerequisites: **Node.js 18+** (tested on Node 24). For the
v5.0 Netlify Function proxy: **Netlify CLI** (`npm i -g netlify-cli`).

```bash
# 1. Install dependencies
npm install

# 2a. Plain Vite dev server (no Netlify Function).
#     The dashboard works, but the proxy endpoint will 404.
#     The client transparently falls back to browser-direct
#     fetches (proxyStatus === 'browser-direct').
npm run dev
# -> http://localhost:5173

# 2b. Netlify dev (Vite + Netlify Functions together).
#     Use this to test the v5.0 proxy end-to-end locally.
npx netlify dev
# -> http://localhost:8888

# 3. Production build (type-check + bundle)
npm run build

# 4. Preview the production build
npm run preview
```

> The first build is the one that verifies everything compiles cleanly.
> `npm run build` runs `tsc -b && vite build` and will fail on any
> type error.

---

## 🧭 Design notes

- **State management** is intentionally just `useState` + `useMemo`. The
  dataset is small enough (50–hundreds of CVEs) that client-side filtering
  is instant, and adding Redux / Zustand would add weight without value
  at this scale.
- **Filter logic** lives in `src/utils/analytics.ts` as pure functions —
  easy to unit-test, no React dependencies.
- **Severity / color** is centralized in `src/utils/severity.ts` so the
  table badges, chart bars, and detail drawer never drift out of sync.
- **Mock data** is intentionally vendor-diverse (Microsoft, Cisco,
  Fortinet, Ivanti, Apache, Atlassian, Linux, Apple, Google, VMware, …)
  to make the dashboard look like a real SOC view, not a toy.

---

## 📄 License & use

This project is for **defensive security work only**. Do not use any
information surfaced here to develop, distribute, or execute offensive
tooling. The mock CVEs are fictional and provided for visualization
purposes; always refer to upstream advisories before taking action.

---

_Made with care by your friendly neighborhood defensive security
dashboard._
