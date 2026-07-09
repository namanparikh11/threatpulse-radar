# ThreatPulse Radar

> A modern cybersecurity **vulnerability-intelligence dashboard** built for
> **defensive** security work. Track CVEs, KEV status, CVSS scores, EPSS
> probability, and severity across your stack in one focused
> command-center view.

![status](https://img.shields.io/badge/status-v5.3-22d3ee?style=flat-square)
![stack](https://img.shields.io/badge/stack-React%20%2B%20Vite%20%2B%20TS-0d1424?style=flat-square)
![use](https://img.shields.io/badge/use-defensive%20only-f43f5e?style=flat-square)

**Live demo:** [https://threatpulse-radar.netlify.app](https://threatpulse-radar.netlify.app)

---

## Defensive-only scope

ThreatPulse Radar is built **exclusively for defensive security work** —
vulnerability prioritization, patch planning, exposure awareness, and
security posture reporting.

It contains **no exploit code, no offensive tooling, and no weaponized
payloads**. Every "recommended action" in the dashboard is
plain-language defensive guidance ("apply the latest vendor patch,
rotate credentials, review access logs").

This is not an enterprise vulnerability management platform. It is not a
real-time zero-day detector. It does not "guarantee" NVD enrichment —
NVD's anonymous endpoint is rate-limited and can return errors; the
dashboard surfaces those honestly rather than papering over them.

---

## What it does

ThreatPulse Radar joins three public defensive-intelligence feeds into a
single filterable dashboard:

| Feed | Provides | Source |
| --- | --- | --- |
| **CISA KEV** | "This CVE is being actively exploited in the wild" | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **NVD CVE 2.0** | CVSS base score + severity (v3.1 → v3.0 → v2) | [NVD](https://nvd.nist.gov/) |
| **FIRST EPSS** | Probability of exploitation in the next 30 days | [FIRST EPSS](https://www.first.org/epss/) |

The result is a one-page command center:

- **6 stat cards** — total, critical, high, KEV-listed, average EPSS, new-this-week
- **4 charts** — severity distribution, EPSS risk distribution, 14-day trend, KEV vs non-KEV
- **Filterable table** — search by CVE ID / vendor / product / summary,
  severity filter, KEV-only toggle, minimum EPSS slider, sort by
  newest / CVSS / EPSS / KEV
- **Detail drawer** — full description, metrics, recommended defensive
  action, external links to CISA KEV + NVD
- **Dark cybersecurity command-center theme** — neon cyan / amber
  accents, desktop-first responsive

The same `Vulnerability` shape is used end-to-end, so the filter / sort
/ chart pipeline doesn't care which upstream provider contributed which
record.

---

## Architecture

```
                         Visitor's browser
                                │
                                ▼
   ┌─────────────────────────────────────────────────────────┐
   │  GET /.netlify/functions/dataset   (Netlify Function)    │
   │                                                         │
   │   1. Try `latest-dataset` blob (prebuilt envelope)      │
   │      ├─ hit  → return immediately                        │
   │      └─ miss → build live (bootstrap path)              │
   │                                                         │
   │   Response tagged with:                                 │
   │     dataSource: "prebuilt-store" | "live-build"          │
   │     refreshInProgress: <bool>  (from refresh-lock blob) │
   └─────────────────────────────────────────────────────────┘
            │                                  ▲
            │ writes                           │ acquires
            ▼                                  │ refresh-lock
   ┌──────────────────────────┐         ┌──────┴──────────────┐
   │   Netlify Blobs store    │         │  refresh-lock blob  │
   │   (name: tpr-dataset)    │◄────────┤  (TTL: 15 min)      │
   │   ┌────────────────────┐ │         └──────▲──────────────┘
   │   │ latest-dataset     │ │                │ acquires
   │   │  (FetchResult)     │ │   ┌────────────┴───────────────┐
   │   └────────────────────┘ │   │                            │
   └──────────────────────────┘   │                            │
            ▲                     │                            │
            │                     ▼                            ▼
   ┌────────┴─────────┐   ┌────────────────────┐   ┌────────────────────┐
   │  Cron scheduled  │   │  Background fn     │   │  Browser manual    │
   │  (every 30 min)  │   │  (manual refresh   │   │  "Refresh live     │
   │  reads + writes  │   │   from dashboard)  │   │   data" button     │
   │  the prebuilt    │   │  reads + writes    │   │  POSTs to the      │
   │  envelope        │   │  the prebuilt      │   │  background fn     │
   └──────────────────┘   │  envelope          │   └────────────────────┘
            │              └────────────────────┘
            │ build                       build
            ▼                              ▼
   ┌──────────────────────────────────────────────────────┐
   │  Shared build pipeline:                              │
   │    CISA KEV  →  NVD CVE 2.0  →  FIRST EPSS           │
   │                                                      │
   │  • Optional NVD_API_KEY (server-side only) raises    │
   │    NVD's rate-limit allowance from 5 to 50 req / 30s │
   │  • Rate-limited (429) builds are blocked from        │
   │    overwriting a better existing prebuilt blob       │
   │  • 15-min NVD cooldown marker avoids hammering a     │
   │    known-flaky NVD                                   │
   └──────────────────────────────────────────────────────┘
```

**Three properties this architecture guarantees:**

1. **The build runs once on the server**, not per visitor. The prebuilt
   blob is the source of truth for normal traffic; cron + manual
   refresh keep it fresh.
2. **A bad refresh never overwrites a better one.** If NVD rate-limits
   (HTTP 429), the quality guard compares the new build against the
   existing blob and preserves the better envelope.
3. **The browser never blocks on the upstream pipeline.** The first
   visitor after a cold deploy pays the bootstrap cost once; everyone
   after reads the prebuilt blob.

---

## Reliability & honesty

The codebase's stance: **failures are visible, never hidden.**

### Source labels in the header

Every response is tagged with the actual transport and providers that
contributed:

- **Source:** `CISA KEV + NVD + FIRST EPSS` — all three providers
  contributed data
- **Source:** `CISA KEV + FIRST EPSS` — NVD unavailable, dashboard
  still works (CVSS falls back to CISA-derived severity)
- **Source:** `CISA KEV` — NVD and EPSS both unavailable
- **Proxy:** `Netlify` (cyan pill) — data came from the serverless
  endpoint, not browser-direct
- **Dataset store:** `latest available` / `bootstrapping` /
  `refresh running in background` — visible state of the prebuilt
  blob + refresh lock

### Per-provider status pills

`NVD` and `EPSS` each have their own status pill that turns amber with a
human-readable reason when that specific provider fails. A 429 surfaces
as `NVD: unavailable — rate limit reached (HTTP 429)`. A network
timeout surfaces as `EPSS: unavailable — request timed out`. The
remaining providers' data still renders; the failure is announced, not
swallowed.

### No fabricated scores

A CISA record whose CVE is not yet in NVD keeps `cvssScore: 0` and the
CISA-derived severity (KEV records default to `High`; ransomware-known
records to `Critical`). A CISA record whose CVE is not scored by FIRST
keeps `epssProbability: 0`. **The dashboard never invents enrichment
data** — when a provider fails, the field is zero and a banner explains
why.

### NVD rate-limit guard

If NVD returns HTTP 429 (its anonymous endpoint allows only 5 req / 30s):

- The orchestrator detects the rate-limit reason
- It compares the new build against the existing prebuilt blob
- If the existing blob is better (more CVSS-positive records, NVD
  enriched), the new build is **discarded** and the existing blob
  continues to serve visitors
- A 15-minute cooldown marker is set so the next refresh
  short-circuits the doomed NVD fetch
- When the cooldown expires, normal refresh behavior resumes

### Manual refresh never blocks the user

Clicking "Refresh live data" POSTs to a Netlify Background Function
that returns `202 Accepted` immediately. The current dataset stays on
screen. When the new blob is ready, the v5.1 polling effect detects it
and surfaces a "New dataset available. Updated 2 min ago." banner with
explicit **Apply update** / × controls — filters, search, sort, and the
open detail view are preserved across the apply.

### API key stays server-side

The optional `NVD_API_KEY` is read from `process.env` inside the
Netlify Function only, passed to NVD as a request header
(`apiKey: <key>`), and **never** appears in the function response body,
in any URL, in any log, or in the frontend bundle. The key is optional
— the dashboard works identically without it (just slower for the
first visitor in a region per 15 min; repeat visitors ride the CDN
cache).

### No mock fallback in the prebuilt store

The prebuilt `latest-dataset` blob is written **only** by a successful
live build. Mock data never replaces real upstream data. The dashboard
ships a 60-record curated mock dataset for offline development and as a
last-resort browser fallback when *every* transport path fails; it is
never silently mixed into live results, and the header pill turns amber
the moment it is in use.

---

## Tech stack

| Layer | Choice |
| --- | --- |
| Framework | [React 18](https://react.dev) |
| Build tool | [Vite 5](https://vitejs.dev) |
| Language | TypeScript (strict) |
| Styling | [Tailwind CSS 3](https://tailwindcss.com) |
| Charts | [Recharts 2](https://recharts.org) |
| Icons | [Lucide React](https://lucide.dev) |
| Backend | [Netlify Functions](https://docs.netlify.com/build/functions/overview/) (Node 20 ESM) |
| Storage | [Netlify Blobs](https://docs.netlify.com/build/data-and-storage/netlify-blobs/) |

No login. No database. No payments. No exploit code. No offensive
features. The Netlify Function is read-only and idempotent; the Blobs
store is a managed key/value store used as a prebuilt-envelope cache.

---

## Project structure

```
threatpulse-radar/
├── index.html
├── netlify.toml                       # Netlify build + functions + cron
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
├── netlify/
│   └── functions/
│       ├── dataset.mjs               # read endpoint (blob-first, else bootstrap)
│       ├── refresh-dataset-background.mjs   # manual refresh (BG fn, 15-min timeout)
│       ├── refresh-dataset-scheduled.mjs    # cron refresh (every 30 min)
│       └── _shared/
│           ├── store.mjs             # Netlify Blobs + lock + cooldown helpers
│           ├── refresh.mjs           # lock + write orchestrator + quality guard
│           └── liveBuild.mjs         # shared CISA → NVD → EPSS pipeline
└── src/
    ├── main.tsx                       # entry
    ├── App.tsx                        # thin shell
    ├── index.css                      # Tailwind + global polish
    ├── vite-env.d.ts                  # import.meta.env typing
    ├── components/                    # presentational + container pieces
    │   ├── Header.tsx                 # + source / provider / cache pills
    │   ├── StatsCards.tsx
    │   ├── FiltersPanel.tsx
    │   ├── VulnerabilityTable.tsx
    │   ├── DetailDrawer.tsx
    │   ├── EmptyState.tsx
    │   ├── LoadingState.tsx
    │   ├── ErrorState.tsx
    │   ├── SearchStatus.tsx
    │   ├── CachedDataBanner.tsx       # v4 cache banner + refresh button
    │   ├── UpdateAvailableBanner.tsx  # v5.1 "New dataset available" banner
    │   ├── RefreshInProgressBanner.tsx # v5.2 background-refresh indicator
    │   ├── NvdUnavailableBanner.tsx
    │   ├── EpssUnavailableBanner.tsx
    │   ├── FallbackBanner.tsx
    │   └── charts/
    │       ├── SeverityChart.tsx
    │       ├── TrendChart.tsx
    │       └── KevChart.tsx
    ├── data/
    │   └── mockVulnerabilities.ts     # 60 fictional CVEs (offline fallback)
    ├── pages/
    │   └── DashboardPage.tsx          # single-screen dashboard
    ├── services/
    │   ├── vulnerabilityService.ts    # proxy-first orchestration
    │   ├── datasetCache.ts            # 1-hour localStorage cache layer
    │   └── providers/
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

## Run it locally

Prerequisites: **Node.js 18+** (tested on Node 24). For the Netlify
Function proxy: **Netlify CLI** (`npm i -g netlify-cli`).

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
#     Use this to test the v5.2 prebuilt-store path end-to-end.
npx netlify dev
# -> http://localhost:8888

# 3. Production build (type-check + bundle)
npm run build

# 4. Preview the production build
npm run preview
```

> `npm run build` runs `tsc -b && vite build` and fails on any type
> error.

The full deployment guide (Netlify configuration, env vars, scheduled
functions, custom domain, troubleshooting) lives in
[`DEPLOYMENT.md`](./DEPLOYMENT.md).

---

## Portfolio notes

**Built by [Naman Parikh](https://github.com/namanparikh11).**

This is a **defensive** vulnerability-intelligence project, built as
both a real triage tool and a public-facing portfolio piece for
security / frontend engineering interviews. The engineering decisions
in it are the artifact — not the feature list.

What I would point to in a review:

- **Per-provider status side-channels.** CISA, NVD, and FIRST are
  three independent services with three independent failure modes.
  The `FetchResult` shape has separate `nvdStatus` and `epssStatus`
  fields so partial outages degrade honestly instead of misrepresenting
  the data.
- **Prebuilt blob + quality guard.** A shared `latest-dataset`
  Netlify Blobs entry decouples the upstream pipeline from per-request
  latency. The orchestrator refuses to overwrite a better envelope
  with a rate-limited downgrade — a real-world reliability bug
  (NVD HTTP 429 silently worsening the cached data) that most
  tutorials skip.
- **No API keys in the frontend bundle.** `NVD_API_KEY` is read from
  `process.env` inside the Netlify Function only, passed as a request
  header, never exposed. The app works identically without it.
- **Transparent freshness.** "Last refresh" reflects when the
  function actually ran, not when the CDN served the response. The
  "Refresh live data" button uses a `?t=<timestamp>` cache-buster so
  its name stays honest.
- **Explicit user consent on soft refresh.** The v5.1 polling
  surfaces newer upstream data behind an Apply-update banner; filters
  and the open detail view are preserved. The user is never disturbed
  mid-task.

The codebase is intentionally small, strict-mode TypeScript end-to-end,
and lives under a defensive-only license. See
[`PORTFOLIO_WRITEUP.md`](./PORTFOLIO_WRITEUP.md) for the longer
narrative.

---

## License & use

This project is for **defensive security work only**. Do not use any
information surfaced here to develop, distribute, or execute offensive
tooling. The mock CVEs in `src/data/mockVulnerabilities.ts` are
fictional and provided for visualization purposes; always refer to
upstream advisories before taking action.

The NVD, CISA KEV, and FIRST EPSS feeds are public services operated by
their respective organizations. ThreatPulse Radar is not affiliated
with NIST, CISA, or FIRST.

---

_Made with care by your friendly neighborhood defensive security
dashboard._