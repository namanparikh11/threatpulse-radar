# NEXT_AGENT_PROMPT

> Drop this into a fresh MiniMax Code session when you're ready to take
> ThreatPulse Radar to the next milestone. It is intentionally compact:
> enough context to act, no fluff.

---

## You are working on ThreatPulse Radar

**What it is.** A polished, dark-themed, frontend-only cybersecurity
vulnerability-intelligence dashboard for **defensive** security
portfolio use. Now in v2.

**Stack.** React 18 + Vite 5 + TypeScript 5 (strict) + Tailwind CSS 3 +
Recharts 2 + Lucide React.

**Status.** v2.0 (CISA KEV) is feature-complete and ships clean.
- `npm.cmd run build` → 0 errors, 0 warnings, ~5.3 s.
- `node scripts/acceptance.mjs` → **15/15** (v1 mock-data tests,
  including severity sort).
- `node scripts/acceptance-cisa.mjs` → **28/28** (v2 CISA tests,
  including severity sort on CISA records).
- 60 unique mock records + the live CISA KEV feed (default).
- Filter / search / sort pipeline in `useVulnerabilityFilter` works
  identically on either source.
- Severity sort verified: `desc` = Critical, High, Medium, Low.
  `asc` = Low, Medium, High, Critical. (Pre-existing comparator
  bug fixed in pass 8; do not revert.)
- Hero is the final public-portfolio cut (no version numbers, no
  top status strip, no live radar animation).
- `dist/` is drop-in deployable to Hostinger static hosting.
- `main` has **uncommitted** source changes from the CISA + sort
  fix passes. The `origin` remote is configured (private repo)
  but nothing has been pushed. Do not push without an explicit ask.

## Read first

Open these files in this order before touching anything:

1. `PROJECT_HANDOFF.md` — the full project status, what was done in
   each pass, what's out of scope, the recommended next milestone.
2. `README.md` — the public-facing project description (v2 reflects
   CISA KEV live data).
3. `DEPLOYMENT.md` — the Hostinger static-hosting guide (still valid
   for v2; nothing about the deployment changed).

## Hard rules for this session

These are non-negotiable. The next agent (you) must not:

- ❌ Add more real APIs (NVD / FIRST EPSS). CISA KEV is the only live
  source for v2; the others are planned for v2.5 (the next milestone).
  The merge + NVD + EPSS plumbing is in the type system; do not
  implement it without an explicit ask.
- ❌ Add new features (auth, persistence, watchlists, CSV export,
  per-vendor sidebar, deep-linking). Out of scope.
- ❌ Redesign the header. The pass-4 layout is final; the v2 pass only
  changed labels, not structure. Don't add more pills / badges /
  banners / animated indicators.
- ❌ Touch the filter / search / sort pipeline. The 15 v1 acceptance
  tests + the 28 CISA tests must keep passing. Do not weaken them.
  The severity sort comparator in `src/utils/analytics.ts`
  (`compareByField`'s `case 'severity':`) was corrected in pass 8
  to put Critical first when descending; do not revert it.
- ❌ Touch `src/data/mockVulnerabilities.ts`,
  `src/hooks/useVulnerabilityFilter.ts`, or
  `src/hooks/useDebouncedValue.ts` unless the user explicitly asks.
- ❌ Bump major versions of React / Vite / Recharts.
- ❌ Add a backend, a database, or any kind of server.
- ❌ Remove `base: './'` from `vite.config.ts` or the
  `public/.htaccess` file.
- ❌ Change `DATA_MODE` away from `'live'` in
  `src/services/vulnerabilityService.ts` without an explicit ask.
- ❌ Push to `origin` without an explicit ask.

If a request seems to violate these, push back once, then ask before
acting. The user values this scope.

## Recommended next milestone (v2.5): NVD + FIRST EPSS providers

The v2 normalizer leaves `cvssScore: 0` and `epssProbability: 0`
on CISA records because CISA doesn't provide them. v2.5 should
backfill those values by joining on `cveId`.

Specifically:

1. **NVD provider** — `src/services/providers/nvd.ts`. Fetch
   recent CVEs from `https://services.nvd.nist.gov/rest/json/cves/2.0`
   (paginated, rate-limited — 5 requests / 30 s without an API
   key, 50 / 30 s with one). Normalize to a `Vulnerability` subset
   that has the full CVSS, description, and CPE fields. Returned
   separately from CISA so the service can join them.

2. **FIRST EPSS provider** — `src/services/providers/epss.ts`.
   Fetch from `https://api.first.org/data/v1/epss?cve=...`. Returns
   a small `{ cve, epss, percentile }` per CVE. Used to fill
   `epssProbability` on the CISA records.

3. **Service layer merge** — `vulnerabilityService.ts` runs the
   CISA fetch, then the NVD fetch, then the EPSS fetch in
   parallel. Joins on `cveId` so each final `Vulnerability` has
   the union of the three sources' fields. Return with
   `source: 'merged'`. `mode` stays `'live'` if all three succeed;
   partial failures should still return what's available, with
   a new `partialDegradation` field if the user wants the
   header to surface it.

4. **Acceptance tests** — extend `scripts/acceptance-cisa.mjs`
   (or add `scripts/acceptance-merge.mjs`) with tests that the
   merge step correctly backfills CISA records' `cvssScore` and
   `epssProbability` from NVD / EPSS. Keep the 13 v1 + 27 v2
   tests passing.

5. **Header / mode** — when `source === 'merged'`, the source
   pill should read `Source: CISA KEV + NVD + EPSS` (or
   similar). The mode badge stays `Live CISA KEV Mode` or becomes
   `Live Multi-Source Mode` — confirm with the user.

6. **No UI redesign.** The v2 header structure carries through.

## Things that are already correct (don't redo them)

- Tailwind palette (`tailwind.config.js`).
- Strict TypeScript (`tsconfig.app.json`).
- Manual chunk splitting for `react` / `charts` / `icons` in
  `vite.config.ts` — bundle is well-split.
- The 6 stats cards, 4 charts, vulnerability table, filter panel,
  detail drawer, empty/loading/error states.
- The pass-4 hero: logo, title, subtitle, badges, 3 status pills
  (now with dynamic source / mode labels).
- `useVulnerabilityFilter` + `useDebouncedValue` + `SearchStatus`
  custom-hook pipeline.
- The 60 unique mock records with stable `id`s (now used as
  fallback data, not the primary source).
- The CISA KEV provider with `AbortController` timeout and
  transparent defaults for missing CVSS / EPSS.
- The corrected severity sort comparator
  (`(rank_b - rank_a)` in `compareByField`'s `case 'severity':`).
  Tested by both acceptance suites.
- The `FetchResult.mode` state machine: `'live' | 'mock' | 'fallback'`.
- The `public/.htaccess` SPA fallback + cache + security headers.
- The v1 acceptance suite (`scripts/acceptance.mjs`).
- The v2 CISA acceptance suite (`scripts/acceptance-cisa.mjs`).

## Acceptance for the v2.5 session

When the v2.5 work is done, report:

1. `npm.cmd run build` result (must be 0 errors, 0 warnings).
2. `node scripts/acceptance.mjs` result (must be **15/15**).
3. `node scripts/acceptance-cisa.mjs` result (must be **28/28**).
4. New acceptance suite (whatever you call it) result (must be
   `N/N` — your new tests).
5. List of files added / modified.
6. A short note on whether `dist/` is still drop-in deployable
   to Hostinger (it should be — `base: './'` and `public/.htaccess`
   are unchanged).

## Style notes

- Match the existing code style: Tailwind utility classes,
  4-space-indent in TS, semicolons (existing code uses them —
  keep them), function declarations for components
  (`export default function X()`).
- Keep the tone of the existing `README.md` and `PROJECT_HANDOFF.md`:
  factual, no marketing fluff, explicit about what is and isn't
  included.
- Don't introduce new dependencies unless absolutely required.
  NVD can be fetched with plain `fetch`; EPSS too. The current
  `package.json` is intentionally lean.
- The CISA KEV provider is the model for new providers — copy its
  shape: an `AbortController` timeout, a typed raw-record
  interface, a `normalize*` function, and a top-level `fetch*`
  function that throws on shape mismatch.

Good luck. v2 ships clean; v2.5 is the next logical step.
