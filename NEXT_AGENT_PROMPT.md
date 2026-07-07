# NEXT_AGENT_PROMPT

> Drop this into a fresh MiniMax Code session when you're ready to take
> ThreatPulse Radar to the next milestone. It is intentionally compact:
> enough context to act, no fluff.

---

## You are working on ThreatPulse Radar

**What it is.** A polished, dark-themed, frontend-only cybersecurity
vulnerability-intelligence dashboard for **defensive** security
portfolio use. Now in v3.0.

**Stack.** React 18 + Vite 5 + TypeScript 5 (strict) + Tailwind CSS 3 +
Recharts 2 + Lucide React.

**Status.** v3.0 (NVD CVSS enrichment) is feature-complete and ships
clean. v3.1 (QA / portfolio-demo hardening) is also done.
- `npm.cmd run build` → 0 errors, 0 warnings, ~6.3 s.
- `node scripts/acceptance.mjs` → **15/15** (v1 mock-data tests,
  including severity sort).
- `node scripts/acceptance-cisa.mjs` → **28/28** (v2 CISA tests).
- `node scripts/acceptance-epss.mjs` → **39/39** (v2.5 EPSS tests).
- `node scripts/acceptance-nvd.mjs` → **53/53** (v3 NVD tests,
  +1 from the v3.1 honesty fix).
- Total: **135/135** acceptance tests.
- 60 unique mock records + the live CISA KEV feed (default) +
  live NVD CVSS enrichment + live FIRST EPSS enrichment.
- Filter / search / sort pipeline in `useVulnerabilityFilter` works
  identically on every data path.
- Severity sort verified: `desc` = Critical, High, Medium, Low.
  `asc` = Low, Medium, High, Critical.
- Hero is the final public-portfolio cut (no version numbers, no
  top status strip, no live radar animation).
- `dist/` is drop-in deployable to Hostinger static hosting.
- `main` has **uncommitted** source changes from the CISA + EPSS
  + NVD + QA passes. The `origin` remote is configured (private
  repo) but nothing has been pushed. Do not push without an
  explicit ask.

## Read first

Open these files in this order before touching anything:

1. `PROJECT_HANDOFF.md` — the full project status, what was done in
   each pass, what's out of scope, the recommended next milestone.
2. `README.md` — the public-facing project description (v3 reflects
   CISA KEV + NVD + FIRST EPSS live data).
3. `DEPLOYMENT.md` — the Hostinger static-hosting guide (still valid
   for v3; nothing about the deployment changed).

## Hard rules for this session

These are non-negotiable. The next agent (you) must not:

- ❌ Add more real APIs. CISA KEV, NVD, and FIRST EPSS are the full
  enrichment chain. New sources go through a fresh ask — they
  need a new provider, a new orchestration path, and a new status
  field on `FetchResult`.
- ❌ Add new features (auth, persistence, watchlists, CSV export,
  per-vendor sidebar, deep-linking). Out of scope.
- ❌ Redesign the header. The pass-4 layout is final; the v2 /
  v2.5 / v3 passes only changed labels, not structure. Don't add
  more pills / badges / banners / animated indicators.
- ❌ Touch the filter / search / sort pipeline. The 15 v1
  acceptance tests + 28 CISA tests + 39 EPSS tests + 53 NVD tests
  must keep passing. Do not weaken them. The severity sort
  comparator in `src/utils/analytics.ts` (`compareByField`'s
  `case 'severity':`) was corrected in pass 8 to put Critical
  first when descending; do not revert it.
- ❌ Touch `src/data/mockVulnerabilities.ts`,
  `src/hooks/useVulnerabilityFilter.ts`, or
  `src/hooks/useDebouncedValue.ts` unless the user explicitly asks.
- ❌ Bump major versions of React / Vite / Recharts.
- ❌ Add a backend, a database, or any kind of server.
- ❌ Remove `base: './'` from `vite.config.ts` or the
  `public/.htaccess` file.
- ❌ Change `DATA_MODE` away from `'live'` in
  `src/services/vulnerabilityService.ts` without an explicit ask.
- ❌ Revert the severity sort comparator, the CISA / NVD / EPSS
  enrichment, or the `nvdStatus` / `epssStatus` side-channels.
- ❌ Push to `origin` without an explicit ask.

If a request seems to violate these, push back once, then ask before
acting. The user values this scope.

## Recommended next milestone (v3.5): UX-on-top-of-frozen-data

The v3 data layer is now feature-complete for a portfolio piece.
The next session's job is whatever the user explicitly asks for,
but reasonable options include:

1. **Saved filter presets** — e.g. "Internet-facing + KEV",
   "Last 7 days + High/Critical", "Microsoft + EPSS > 50%". A
   small `presets.ts` in `src/data/` or `src/utils/` with
   named `VulnerabilityFilters` objects, plus a dropdown in
   `FiltersPanel.tsx` that applies them. No data-layer change
   needed.
2. **CSV / JSON export of the current filtered view** — use a
   `Blob` + `URL.createObjectURL`. Trivial; ~30 lines.
3. **Per-vendor watchlists** — a `watchlist` localStorage key
   + a small "Watchlist" view that filters the dataset to the
   user's saved vendors. No data-layer change.
4. **NVD API key support** — read `VITE_NVD_API_KEY` from
   `import.meta.env`, pass through to NVD's `apiKey` query
   param for a 10× rate-limit bump. ~10 lines in `nvd.ts`.

The user gets to pick. The frozen-scope contract from section 8
above is the same regardless of which one they choose.

## Acceptance for the v3.5 session

When v3.5 work is done, report:

1. `npm.cmd run build` result (must be 0 errors, 0 warnings).
2. `node scripts/acceptance.mjs` result (must be **15/15**).
3. `node scripts/acceptance-cisa.mjs` result (must be **28/28**).
4. `node scripts/acceptance-epss.mjs` result (must be **39/39**).
5. `node scripts/acceptance-nvd.mjs` result (must be **53/53**).
6. New tests (if any) result (must be `N/N`).
7. List of files added / modified.
8. A short note on whether `dist/` is still drop-in deployable
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
  (now with dynamic source / mode / NVD / EPSS labels).
- `useVulnerabilityFilter` + `useDebouncedValue` + `SearchStatus`
  custom-hook pipeline.
- The 60 unique mock records with stable `id`s (now used as
  fallback data, not the primary source).
- The CISA KEV provider with `AbortController` timeout.
- The FIRST EPSS provider with chunked batched fetch, parsing,
  and a pure `enrichWithEpss` function.
- The NVD CVE 2.0 provider with v3.1 → v3.0 → v2 score preference,
  chunked batched fetch, and a pure `enrichWithNvd` function
  that overrides both `cvssScore` and `severity` when NVD has
  data.
- The `FetchResult.mode` state machine: `'live' | 'mock' | 'fallback'`.
- The `FetchResult.epssStatus` side-channel:
  `'first' | 'unavailable'`.
- The `FetchResult.nvdStatus` side-channel:
  `'nvd' | 'unavailable'`.
- The `public/.htaccess` SPA fallback + cache + security headers.
- The v1 acceptance suite (`scripts/acceptance.mjs`).
- The v2 CISA acceptance suite (`scripts/acceptance-cisa.mjs`).
- The v2.5 EPSS acceptance suite (`scripts/acceptance-epss.mjs`).
- The v3 NVD acceptance suite (`scripts/acceptance-nvd.mjs`).
- The v3.1 honesty fixes in `Header.tsx` (the `describeSource`
  function reads `nvdStatus` *and* `epssStatus` before building
  the source label) and the `LoadingState` copy that names
  the three live providers. Both are guarded by tests in
  `scripts/acceptance-nvd.mjs`.

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
- The CISA KEV, NVD, and EPSS providers are the model for any
  new provider — copy their shape: an `AbortController` timeout,
  a typed raw-record interface, a `normalize*` function (where
  applicable), and a top-level `fetch*` function that throws on
  shape mismatch.

Good luck. v3 ships clean; v3.5 (or whatever the user picks next)
is the next logical step.
