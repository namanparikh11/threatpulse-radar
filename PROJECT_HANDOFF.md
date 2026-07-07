# PROJECT_HANDOFF

> End-of-session handover for **ThreatPulse Radar** v3.0.
> Last verified: this session (NVD CVSS enrichment pass).
> Build clean. Acceptance tests green
> (**15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS + 52/52 v3 NVD = 134/134**).
> Tree has uncommitted source changes on `main`.

---

## 1. Project status

**ThreatPulse Radar** is a frontend-only cybersecurity
vulnerability-intelligence dashboard built for **defensive** security
portfolio use. v2 is feature-complete at this milestone: the dashboard
now fetches the public **CISA Known Exploited Vulnerabilities** feed at
runtime and falls back to the curated mock dataset if the fetch fails.

- **Stack:** React 18 + Vite 5 + TypeScript 5 (strict) + Tailwind CSS 3 +
  Recharts 2 + Lucide React icons.
- **Backend:** none. **Auth:** none. **Database:** none. **Payments:** none.
  **Exploit code:** none. CISA KEV is fetched directly from the browser
  (the CISA feed is CORS-enabled) — no proxy, no server.
- **Build:** `npm.cmd run build` passes clean (4.57 s this pass, 0 errors, 0 warnings).
- **Acceptance suites:** **15/15 v1** mock-data tests + **28/28 v2 CISA
  KEV tests** + **39/39 v2.5 EPSS tests** + **52/52 v3 NVD tests**
  (`node scripts/acceptance.mjs && node scripts/acceptance-cisa.mjs && node scripts/acceptance-epss.mjs && node scripts/acceptance-nvd.mjs`).
- **Repo:** `main` branch has uncommitted source changes from this
  session (Pass 7). An `origin` remote is configured at
  `https://github.com/namanparikh11/threatpulse-radar.git` (added in
  pass 5); nothing has been pushed since. Do not push without an
  explicit ask.
- **Deployment:** `dist/` is drop-in deployable to Hostinger static
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

### Pass 10 — NVD CVSS enrichment ← *current*
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

---

## 3. Files in the project (45 source files)

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
├── DEPLOYMENT.md                    (Hostinger guide, pass 6)
├── public/
│   ├── .htaccess                    (SPA fallback + headers, pass 6)
│   └── radar.svg
├── scripts/
│   ├── acceptance.mjs               (v1 15-test suite, pass 8 added 2)
│   ├── acceptance-cisa.mjs          (v2 28-test CISA suite)
│   ├── acceptance-epss.mjs          (v2.5 39-test EPSS suite)
│   ├── acceptance-nvd.mjs           (v3 52-test NVD suite, new)
│   └── zip-source.ps1               (one-off source-archiver)
└── src/
    ├── main.tsx
    ├── App.tsx
    ├── index.css
    ├── components/
    │   ├── Header.tsx               (NVD + EPSS pills, pass 10)
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
    │   └── mockVulnerabilities.ts   (60 unique records, fallback dataset)
    ├── pages/
    │   └── DashboardPage.tsx        (NvdUnavailableBanner, pass 10)
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
  the background. A future pass could add an NVD API key for
  a 10× rate-limit bump — `VITE_NVD_API_KEY` env var pattern.
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
- **CORS:** the CISA KEV feed is served with
  `Access-Control-Allow-Origin: *`, which is what makes the
  browser-direct fetch work. If CISA ever changes that policy,
  the dashboard will fall back to mock mode on every load and
  show the fallback banner. The retry button will keep failing
  until CISA restores the CORS header.

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
| v3 — NVD CVSS enrichment | ✅ done (pass 10) — *this session* |
| v3.5 — Saved filter presets, watchlists, exports | 📋 planned — see Roadmap in `README.md` |
| v4 — CPE-based asset matching, My Inventory mode | 📋 planned |

**v3 (this pass) is complete:**
- Live CISA KEV feed + live NVD CVSS enrichment + live FIRST
  EPSS enrichment, all three fetched in the browser (all APIs
  CORS-enabled, no proxy).
- Mock dataset is preserved as the offline fallback (and as
  the dataset returned when CISA fetch fails). When CISA
  succeeds but NVD or EPSS fails, the CISA + the working
  secondary source are still shown with a soft banner above
  the stats explaining what's unavailable.
- The header, dashboard, and detail drawer all work on every
  data path — same `Vulnerability` shape, same filter / sort
  pipeline. The filter pipeline now actually exercises real
  CVSS / EPSS data.
- 15/15 v1 + 28/28 v2 CISA + 39/39 v2.5 EPSS + 52/52 v3 NVD =
  **134/134** acceptance tests passing; build clean (6.12 s,
  0 errors, 0 warnings).

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
