# NEXT_AGENT_PROMPT

> Drop this into a fresh MiniMax Code session when you're ready to take
> ThreatPulse Radar to the next milestone. It is intentionally compact:
> enough context to act, no fluff.

---

## You are working on ThreatPulse Radar

**What it is.** A polished, dark-themed, frontend-only cybersecurity
vulnerability-intelligence dashboard for **defensive** security
portfolio use. Now in v2.5.

**Stack.** React 18 + Vite 5 + TypeScript 5 (strict) + Tailwind CSS 3 +
Recharts 2 + Lucide React.

**Status.** v2.5 (FIRST EPSS enrichment) is feature-complete and
ships clean.
- `npm.cmd run build` → 0 errors, 0 warnings, ~4.2 s.
- `node scripts/acceptance.mjs` → **15/15** (v1 mock-data tests,
  including severity sort).
- `node scripts/acceptance-cisa.mjs` → **28/28** (v2 CISA tests).
- `node scripts/acceptance-epss.mjs` → **39/39** (v2.5 EPSS tests).
- Total: **82/82** acceptance tests.
- 60 unique mock records + the live CISA KEV feed (default) +
  live FIRST EPSS enrichment of every CISA CVE.
- Filter / search / sort pipeline in `useVulnerabilityFilter` works
  identically on every data path.
- Severity sort verified: `desc` = Critical, High, Medium, Low.
  `asc` = Low, Medium, High, Critical.
- Hero is the final public-portfolio cut (no version numbers, no
  top status strip, no live radar animation).
- `dist/` is drop-in deployable to Hostinger static hosting.
- `main` has **uncommitted** source changes from the CISA + EPSS
  passes. The `origin` remote is configured (private repo) but
  nothing has been pushed. Do not push without an explicit ask.

## Read first

Open these files in this order before touching anything:

1. `PROJECT_HANDOFF.md` — the full project status, what was done in
   each pass, what's out of scope, the recommended next milestone.
2. `README.md` — the public-facing project description (v2.5 reflects
   CISA KEV + FIRST EPSS live data).
3. `DEPLOYMENT.md` — the Hostinger static-hosting guide (still valid
   for v2.5; nothing about the deployment changed).

## Hard rules for this session

These are non-negotiable. The next agent (you) must not:

- ❌ Add more real APIs (NVD). FIRST EPSS is the only secondary
  source for v2.5; NVD is the planned v3 milestone. The
  `vulnerabilityService` type union still allows `'nvd' | 'epss'`
  but those branches are unused — do not implement them without
  an explicit ask.
- ❌ Add new features (auth, persistence, watchlists, CSV export,
  per-vendor sidebar, deep-linking). Out of scope.
- ❌ Redesign the header. The pass-4 layout is final; the v2 / v2.5
  passes only changed labels, not structure. Don't add more pills /
  badges / banners / animated indicators.
- ❌ Touch the filter / search / sort pipeline. The 15 v1
  acceptance tests + 28 CISA tests + 39 EPSS tests must keep
  passing. Do not weaken them. The severity sort comparator in
  `src/utils/analytics.ts` (`compareByField`'s `case 'severity':`)
  was corrected in pass 8 to put Critical first when descending;
  do not revert it.
- ❌ Touch `src/data/mockVulnerabilities.ts`,
  `src/hooks/useVulnerabilityFilter.ts`, or
  `src/hooks/useDebouncedValue.ts` unless the user explicitly asks.
- ❌ Bump major versions of React / Vite / Recharts.
- ❌ Add a backend, a database, or any kind of server.
- ❌ Remove `base: './'` from `vite.config.ts` or the
  `public/.htaccess` file.
- ❌ Change `DATA_MODE` away from `'live'` in
  `src/services/vulnerabilityService.ts` without an explicit ask.
- ❌ Revert the severity sort comparator, the CISA enrichment, or
  the EPSS enrichment.
- ❌ Push to `origin` without an explicit ask.

If a request seems to violate these, push back once, then ask before
acting. The user values this scope.

## Recommended next milestone (v3): NVD provider for CVSS backfill

v2.5's EPSS enrichment fills `epssProbability` from FIRST. The
remaining hole is `cvssScore` — CISA doesn't carry it, NVD does.
v3 should backfill the CVSS column by joining on `cveId`.

The pattern follows the EPSS enrichment exactly:

1. **NVD provider** — `src/services/providers/nvd.ts`. Fetch
   recent CVEs from `https://services.nvd.nist.gov/rest/json/cves/2.0`
   (paginated, rate-limited — 5 requests / 30 s without an API
   key, 50 / 30 s with one). NVD is paginated, not batched by
   `?cve=`, so you'll likely need a separate fetch-per-CVE or
   a small in-memory cache. Normalize to a `{ cveId, cvssScore }`
   map (and a `description` / `cpe` map if you want to fill
   those too).

2. **Service orchestration** — extend
   `vulnerabilityService.ts` so the live path is:
   `CISA → (ok) → NVD → (ok) → FIRST EPSS → enrich → merged`.
   CISA still gates everything: if CISA fails, fall back to
   mock. If CISA succeeds but NVD fails, keep going with EPSS
   (and the same for the inverse). NVD gets its own status
   field, e.g. `nvdStatus: 'nvd' | 'unavailable'`, parallel to
   the existing `epssStatus`.

3. **Per-record note** — currently the CISA normalizer's
   `description` says "CVSS and EPSS scores are not provided by
   the CISA KEV feed; they are populated when NVD / FIRST EPSS
   are wired in." That note is now stale for EPSS (it's wired
   in). Either remove the EPSS half of the note, or refactor
   the description to be context-aware. Pick one — confirm
   with the user.

4. **Acceptance tests** — add `scripts/acceptance-nvd.mjs`
   parallel to the existing three suites. Test the NVD response
   parser, the enrich step, and the orchestration. Keep the
   15 v1 + 28 CISA + 39 EPSS tests passing.

5. **Header** — when `source === 'merged'`, the source pill
   already reads "Source: CISA KEV + FIRST EPSS". When NVD
   joins, the user can decide whether to say "+ NVD" or
   "merged (CISA + NVD + EPSS)". Confirm with the user.

6. **No UI redesign.** v2.5 header structure carries through.
   The `EpssUnavailableBanner` may need a sibling
   `NvdUnavailableBanner`; the same pattern applies.

## Acceptance for the v3 session

When v3 is done, report:

1. `npm.cmd run build` result (must be 0 errors, 0 warnings).
2. `node scripts/acceptance.mjs` result (must be **15/15**).
3. `node scripts/acceptance-cisa.mjs` result (must be **28/28**).
4. `node scripts/acceptance-epss.mjs` result (must be **39/39**).
5. `node scripts/acceptance-nvd.mjs` result (must be `N/N` —
   your new tests).
6. List of files added / modified.
7. A short note on whether `dist/` is still drop-in deployable
   to Hostinger (it should be — `base: './'` and
   `public/.htaccess` are unchanged).

## Things that are already correct (don't redo them)

- Tailwind palette (`tailwind.config.js`).
- Strict TypeScript (`tsconfig.app.json`).
- Manual chunk splitting for `react` / `charts` / `icons` in
  `vite.config.ts` — bundle is well-split.
- The 6 stats cards, 4 charts, vulnerability table, filter panel,
  detail drawer, empty/loading/error states.
- The pass-4 hero: logo, title, subtitle, badges, status pills
  (now with dynamic source / mode / EPSS labels).
- `useVulnerabilityFilter` + `useDebouncedValue` + `SearchStatus`
  custom-hook pipeline.
- The 60 unique mock records with stable `id`s (now used as
  fallback data, not the primary source).
- The CISA KEV provider with `AbortController` timeout.
- The FIRST EPSS provider with chunked batched fetch, parsing,
  and a pure `enrichWithEpss` function.
- The `FetchResult.mode` state machine: `'live' | 'mock' | 'fallback'`.
- The `FetchResult.epssStatus` side-channel:
  `'first' | 'unavailable'`.
- The `public/.htaccess` SPA fallback + cache + security headers.
- The v1 acceptance suite (`scripts/acceptance.mjs`).
- The v2 CISA acceptance suite (`scripts/acceptance-cisa.mjs`).
- The v2.5 EPSS acceptance suite (`scripts/acceptance-epss.mjs`).

## Style notes

- Match the existing code style: Tailwind utility classes,
  4-space-indent in TS, semicolons (existing code uses them —
  keep them), function declarations for components
  (`export default function X()`).
- Keep the tone of the existing `README.md` and `PROJECT_HANDOFF.md`:
  factual, no marketing fluff, explicit about what is and isn't
  included.
- Don't introduce new dependencies unless absolutely required.
  CISA, NVD, and EPSS can all be fetched with plain `fetch`; the
  current `package.json` is intentionally lean.
- The CISA KEV and EPSS providers are the model for new providers
  — copy their shape: an `AbortController` timeout, a typed raw-
  record interface, a `normalize*` function (where applicable),
  and a top-level `fetch*` function that throws on shape mismatch.

Good luck. v2.5 ships clean; v3 is the next logical step.
