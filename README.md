# ThreatPulse Radar

> A modern cybersecurity **vulnerability-intelligence dashboard** built for
> **defensive** security teams. Track CVEs, KEV status, CVSS scores, EPSS
> probability, and severity across your stack in a single, focused
> command-center view.

![status](https://img.shields.io/badge/status-v4.0-22d3ee?style=flat-square)
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

No backend. No login. No database. No payments. No exploit code.

**Data sources:** the dashboard is frontend-only. CISA KEV, NVD, and
FIRST EPSS are all fetched directly from the browser (all three APIs
serve permissive CORS); if a fetch fails, the curated mock dataset
is shown and a banner explains why. No new data sources planned
for v3.x — see the [Roadmap](#-roadmap).

---

## 📁 Project structure

```
threatpulse-radar/
├── index.html
├── package.json
├── tailwind.config.js
├── postcss.config.js
├── tsconfig.json
├── tsconfig.app.json
├── tsconfig.node.json
├── vite.config.ts
├── public/
│   ├── .htaccess                     # SPA fallback, cache, security headers
│   └── radar.svg
└── src/
    ├── main.tsx                       # entry
    ├── App.tsx                        # thin shell
    ├── index.css                      # Tailwind + global polish
    ├── components/                    # presentational + container pieces
    │   ├── Header.tsx
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
    │   ├── vulnerabilityService.ts    # live/mock/fallback mode switcher
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

## 🛣️ Roadmap

- [x] v1 — Polished frontend, mock data, full filtering & visualization
- [x] v2 — **CISA KEV live data with automatic mock fallback**
- [x] v2.1 — Severity sort comparator fix
- [x] v2.5 — **FIRST EPSS enrichment**
- [x] v3 — **NVD CVE 2.0 CVSS enrichment**
- [x] v4 — **Transparent 1-hour localStorage cache** (this release)
  — a "Cache: fresh" / "Cache: stale" pill in the header, a
  "Cached data" banner above the stats, and a manual
  "Refresh live data" button. Provider failures are never hidden.
- [ ] v4.5 — Saved filter presets (e.g. _"Internet-facing + KEV"_)
- [ ] v4.5 — Per-vendor watchlists and email/Slack digest
- [ ] v4.5 — CSV / JSON export of filtered results
- [ ] v5 — CPE-based asset matching: "which of _my_ products are exposed?"
- [ ] v5 — Local-only "My Inventory" mode with optional read-only API

---

## 🏃 Run it locally

Prerequisites: **Node.js 18+** (tested on Node 24).

```bash
# 1. Install dependencies
npm install

# 2. Start the dev server
npm run dev
# -> http://localhost:5173

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
