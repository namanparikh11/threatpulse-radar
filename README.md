# ThreatPulse Radar

> A modern cybersecurity **vulnerability-intelligence dashboard** built for
> **defensive** security teams. Track CVEs, KEV status, EPSS probability, and
> severity across your stack in a single, focused command-center view.

![status](https://img.shields.io/badge/status-v1.0-22d3ee?style=flat-square)
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

- **Dashboard overview** — at-a-glance cards for total, critical, high,
  KEV-listed, average EPSS, and new-this-week vulnerabilities.
- **Vulnerability table** with columns for CVE ID, summary, severity,
  CVSS, EPSS, KEV status, vendor, product, published date, and source.
- **Filtering & search**
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
- **Empty / loading / error states** throughout.
- **Service layer** designed to plug in real APIs without touching UI code.

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
    │   └── charts/
    │       ├── SeverityChart.tsx
    │       ├── TrendChart.tsx
    │       └── KevChart.tsx
    ├── data/
    │   └── mockVulnerabilities.ts     # 50+ realistic CVEs
    ├── pages/
    │   └── DashboardPage.tsx          # single-screen dashboard
    ├── services/
    │   ├── vulnerabilityService.ts    # async, pluggable data source
    │   └── providers/
    │       └── README.ts              # v2 client stubs live here
    ├── types/
    │   └── vulnerability.ts           # shared domain types
    └── utils/
        ├── analytics.ts               # filter, sort, aggregate
        ├── format.ts                  # date / score formatters
        └── severity.ts                # color + ordering helpers
```

---

## 🚧 Planned data sources (v2)

The service layer (`src/services/vulnerabilityService.ts`) already returns
`Promise<FetchResult<Vulnerability[]>>` so adding real APIs is a
one-file change. Planned providers:

| Source                 | Provides                                        | Endpoint                                   |
| ---------------------- | ----------------------------------------------- | ------------------------------------------ |
| **CISA KEV**           | Known-exploited boolean, due dates              | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| **NVD CVE 2.0**        | CVSS, description, CPE (vendor/product), dates  | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| **FIRST EPSS**         | Exploitation probability (0–1)                  | `https://api.first.org/data/v1/epss`       |

The mock dataset (`src/data/mockVulnerabilities.ts`) intentionally mirrors
the merged shape these providers will produce.

---

## 🛣️ Roadmap

- [x] v1 — Polished frontend, mock data, full filtering & visualization
- [ ] v2 — Wire up NVD + CISA KEV + FIRST EPSS (with caching + rate-limit
      handling)
- [ ] v2 — Saved filter presets (e.g. _"Internet-facing + KEV"_)
- [ ] v2 — Per-vendor watchlists and email/Slack digest
- [ ] v2 — CSV / JSON export of filtered results
- [ ] v3 — CPE-based asset matching: "which of _my_ products are exposed?"
- [ ] v3 — Local-only "My Inventory" mode with optional read-only API

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
