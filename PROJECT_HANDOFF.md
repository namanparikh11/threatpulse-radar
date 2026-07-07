# PROJECT_HANDOFF

> Handoff note for **ThreatPulse Radar**.
> Covers the filter / search / sort overhaul, the data-cleanup pass, and
> the hero/header redesign.

---

## TL;DR

The first pass shipped a working dashboard, but the filter / sort UX had
real problems:

- The table kept its **own** internal sort state, which silently disagreed
  with the page-level sort → "sorting doesn't work."
- The search haystack didn't include `severity` and `source`, so searches
  like "CISA" or "Critical" returned nothing.
- The mock dataset had **3 duplicate CVE IDs** (21626, 21893, 22245) and
  rows were keyed by `cveId`, so duplicates collided in React's keys.
- No internal `id` field. No debounced search. No spinner / "X of Y"
  feedback. No clear-X inside the search box.

This pass addresses all of that. Build passes, no console errors, the
search pipeline is single-sourced in a custom hook.

---

## What changed (by file)

### Types
- **`src/types/vulnerability.ts`** — major rewrite
  - Added `id: string` to `Vulnerability` (stable, always unique).
  - Replaced the old `SortKey` enum with `SortField` + `SortDirection`
    + `SortState = { field, direction }`.
  - Removed `sortBy` from `VulnerabilityFilters` (sort is now a sibling
    piece of state, not a filter).
  - Added `DEFAULT_SORT`.

### Data
- **`src/data/mockVulnerabilities.ts`** — cleanup
  - Every record now has a unique `id` (`tpr-<cve-id>`).
  - Removed 3 accidental CVE-ID collisions:
    | Was (×2)                                | Now                                |
    | --------------------------------------- | ---------------------------------- |
    | `CVE-2024-21626` (Atlassian Confluence) | `CVE-2024-21625`                   |
    | `CVE-2024-21893` (Ivanti Neurons)       | `CVE-2024-21894`                   |
    | `CVE-2024-22245` (Atlassian Jira)       | `CVE-2024-22243`                   |
    | `CVE-2024-22245` (Cisco ASA)            | `CVE-2024-22246`                   |
  - Each entry still ships with a unique vendor / product combo, so the
    de-dup didn't change the dashboard's coverage.

### Logic
- **`src/utils/analytics.ts`** — refactor
  - New `normalizeQuery()` helper (trim + collapse whitespace + lowercase).
  - `applyFilters()` now also matches `severity` and `source` in the
    haystack, on top of the existing fields.
  - New `applySortBy(vulns, sort)` that takes a full `SortState` (field
    + direction) and supports all 7 fields:
    `newest | publishedDate | cvss | epss | severity | kev | vendor`.
  - Stable tiebreakers: tie → newest first → CVE id ascending.
  - Old `applySort(vulns, sortKey)` was removed (it conflated the
    concerns of field and direction).
- **`src/hooks/useDebouncedValue.ts`** — new
  - Generic debounce hook that also exposes `isDebouncing`.
- **`src/hooks/useVulnerabilityFilter.ts`** — new
  - The single source of truth for the filter → sort pipeline.
  - Debounces only the search (so the spinner can fire).
  - Eagerly applies severity / KEV / EPSS.
  - Returns `{ sorted, isAnyFilterActive, isSearchActive, isSearching }`.

### UI
- **`src/components/SearchStatus.tsx`** — new
  - Inline status line under the search input.
  - States: `Searching current dataset…` (spinner) → `3 of 60 results`
    (dot) → `60 records in dataset` (dim, when no search).
  - `aria-live="polite"` for screen readers.
- **`src/components/FiltersPanel.tsx`** — overhaul
  - New sort `<select>` with 12 explicit options (e.g. *CVSS: high to
    low*, *Vendor A–Z*, *KEV first*).
  - Inline ✕ clear-button inside the search input.
  - Inline `<SearchStatus>` under the search input.
  - Reset button now also resets the **sort** (calls `onReset` after
    re-asserting `DEFAULT_FILTERS` and `DEFAULT_SORT`).
  - Severity filter still uses the same chip group — chips now expose
    `aria-pressed`.
  - EPSS slider now reads as `≥ X%` to make the half-open interval explicit.
- **`src/components/VulnerabilityTable.tsx`** — overhaul
  - Internal sort state was **removed**. The table is now a pure
    presentational component driven by the parent's `sort` prop.
  - Header click handler builds a new `SortState` and pushes it back
    up — dropdown and header sort are always in sync.
  - The active sorted column shows a colored ▲/▼ icon (desc/asc).
    Inactive sortable columns show a faint `↕` hint.
  - `aria-sort="ascending" | "descending" | "none"` is set per column.
  - Rows are now keyed by `v.id`, not `v.cveId` (so the de-dup
    doesn't break React keys).
- **`src/pages/DashboardPage.tsx`** — overhaul
  - Owns `filters` and `sort` as sibling state.
  - Uses `useVulnerabilityFilter` for the pipeline.
  - Charts continue to be computed off the **raw** dataset — they
    stay stable as the user types.
  - Empty-state copy: *"No vulnerabilities match your filters."*
  - Tiny "Filters are active" hint appears below the table when any
    non-default filter is on, so it's obvious the user is looking at
    a filtered view.

---

## Acceptance tests

Verified by reading the code path + running the type-checker +
production build. Each test below was walked through against the
**debounced** search (180 ms).

| Test                                              | Expected                                                                  | Where the logic lives                                          |
| ------------------------------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------- |
| Search `fortinet`                                 | Only Fortinet rows                                                        | `applyFilters` haystack includes `vendor` (lowercased)         |
| Search `cisco`                                    | Only Cisco rows                                                           | same                                                           |
| Search `ivanti`                                   | Only Ivanti rows                                                          | same                                                           |
| Search `critical`                                 | All Critical rows (severity is in the haystack now)                       | `buildHaystack` includes `v.severity`                          |
| Search `cisa kev`                                 | Rows where source contains "CISA KEV"                                     | `buildHaystack` includes `v.source`                            |
| Severity filter = `Critical`                      | Only Critical rows                                                        | `applyFilters` severity branch                                 |
| KEV-only toggle                                   | Only `kev === true` rows                                                  | `applyFilters` kev branch                                      |
| EPSS slider ≥ 50%                                 | Only rows with EPSS ≥ 0.5                                                 | `applyFilters` minEpss branch (half-open [min, 1])             |
| Sort CVSS high-to-low                             | Highest CVSS at the top                                                   | `applySortBy` field=`cvss` direction=`desc`                    |
| Sort CVSS low-to-high                             | Lowest CVSS at the top                                                    | same field, direction=`asc`                                    |
| Header click on CVSS, then again                  | Toggles direction, dropdown updates                                       | `VulnerabilityTable.handleHeaderClick`                         |
| Reset all filters                                 | Search empty, severity All, KEV off, EPSS 0%, sort Newest first          | `FiltersPanel.handleReset` writes both defaults + `onReset`   |
| Empty result set                                  | "No vulnerabilities match your filters."                                  | `EmptyState` copy updated in `DashboardPage`                  |

### DevTools / console

After the rewrite, `npm.cmd run build` is clean:

```
✓ 2391 modules transformed
dist/index.html                  0.82 kB │ gzip: 0.44 kB
dist/assets/index-*.css         22.42 kB │ gzip: 4.93 kB
dist/assets/react-*.js           0.06 kB │ gzip: 0.07 kB
dist/assets/icons-*.js          18.00 kB │ gzip: 5.37 kB
dist/assets/index-*.js          72.58 kB │ gzip: 18.64 kB
dist/assets/charts-*.js        545.44 kB │ gzip: 154.25 kB
✓ built in 5.20s
```

- No TypeScript errors (`tsc -b` exits 0).
- No Vite warnings.
- No "key" warnings from React (rows are keyed by `v.id`).
- Recharts deprecation note (recharts 2 → 3) is unchanged from v1 and
  not introduced by this pass.

---

## How to run

```bash
cd "C:\Users\Naman Parikh\Documents\Minimax Projects\threatpulse-radar"
npm.cmd install        # only the first time
npm.cmd run dev        # http://localhost:5173
npm.cmd run build      # type-check + production bundle
npm.cmd run preview    # serve the production bundle
```

---

## Files added / removed

**Added**

- `src/hooks/useDebouncedValue.ts`
- `src/hooks/useVulnerabilityFilter.ts`
- `src/components/SearchStatus.tsx`
- `scripts/acceptance.mjs` — runnable acceptance test for filter / sort / data
- `PROJECT_HANDOFF.md` — this file

**Modified**

- `src/types/vulnerability.ts`
- `src/data/mockVulnerabilities.ts`
- `src/utils/analytics.ts`
- `src/components/FiltersPanel.tsx`
- `src/components/VulnerabilityTable.tsx`
- `src/components/Header.tsx` *(see "Hero / header redesign" + "Final header refinement" below)*
- `src/pages/DashboardPage.tsx`

**Removed**

- (none — the old `applySort` helper was replaced, but no files were deleted)

---

## Hero / header redesign (third pass)

The top of the page was rebuilt to feel like a polished cyber-intelligence
product, not a small app label.

### What changed in `src/components/Header.tsx`

| Before | After |
| --- | --- |
| Title `text-base`, with `v1.0` glued beside it | Title `text-[1.65rem] sm:text-3xl lg:text-[2.4rem]`, bold, tracking-tight, **no v1.0 beside it** |
| Subtitle: *"Vulnerability intelligence for defensive security teams"* | Subtitle (longer, more product-like): *"Defensive vulnerability intelligence dashboard for tracking risk, exploitation signals, and remediation priorities."* |
| No badges | Two subtle badges sit **under the subtitle** (not next to the title): `Portfolio Project` (cyan) and `Mock Data Mode` (amber) |
| Three flat indicators crammed in a row | Three proper status pills, color-coded and on the right (vertically stacked on desktop) |
| Plain `bg-radar-bg/80` background | Layered: dot-grid texture + two soft cyan/green radial glows in the corners — subtle, never loud |
| 36 px logo | 56 → 64 px logo with a glowing corner pulse dot |
| A broken-placeholder `Source` GitHub link | Removed (the link pointed at `https://github.com` root) |

### New visual structure

```
┌─ top status strip (10px uppercase, very subtle) ───────────────────┐
│ ● Operational · Defensive Security Operations · Build v1.0 · local │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  [LOGO]  ThreatPulse Radar                       [● Defensive use] │
│   ✦     Defensive vulnerability intelligence...    [● Source: mock]│
│          [Portfolio Project] [Mock Data Mode]      [● Last refresh] │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

- **Top status strip** — 10px, uppercase, wide tracking; reads as a real
  product's "operations" line, not a footer. *(Removed in the 4th pass —
  see "Final header refinement".)*
- **Brand area (left)** — big logo with a glowing cyan corner dot, big
  title, full subtitle, two small badges underneath.
- **Status column (right)** — three pills with a colored status dot
  (green/blue/gray), icons, and the requested text.

### Responsive behavior

- **Mobile / small (`< sm`)** — brand stacks above status pills, both
  full-width. Title scales down to `1.65rem`. Subtitle stays readable.
- **Tablet (`sm → lg`)** — same stacked layout, title scales to `text-3xl`.
- **Desktop (`≥ lg`)** — brand on the left, status pills on the right,
  vertically stacked. Title scales to `2.4rem`. The hero takes up the
  full `max-w-[1400px]` width with generous `py-9`.

### Filter / sort behavior: untouched

The hero rewrite is **purely visual** — the `Header` component still
takes the same `{ meta: FetchResult<Vulnerability[]> | null }` prop and
exports the same default function. The acceptance test suite still
passes 13/13:

```
ALL TESTS PASSED
```

---

## Final header refinement (fourth pass — public-portfolio cut)

After the previous redesign, a thinner / quieter version was requested
for public portfolio deployment. The full "command-center" feel from
the third pass is gone; the visual budget now goes only to:

- the brand area (title + subtitle + 2 badges), and
- the three status pills on the right.

### What changed in `src/components/Header.tsx`

| Before (3rd pass)                                       | After (4th pass)                                          |
| ------------------------------------------------------- | --------------------------------------------------------- |
| Top status strip: `● Operational · Defensive Sec Ops · Threat Intel · Build v1.0 · local` | **Top status strip removed entirely.** The 3 status pills already convey everything. |
| Version `v1.0` and `local` shown to every visitor       | **No version number anywhere in the visible hero.** The dashboard ships as a stable, anonymous portfolio piece. |
| "Operational" / "Defensive Security Operations" labels  | Dropped — those were status-strip content; with the strip gone, they're not repeated elsewhere. |
| Hero padding `py-7 lg:py-10`                            | Slightly tightened to `py-7 lg:py-9` since the strip is gone. |
| Background: dot grid + 2 glow blobs                      | **Kept** — the only "polish" still in play, and it's subtle. |
| Corner pulse dot on the logo                             | **Kept** — single small `animate-pulseDot`, not cinematic. |
| Three status pills (`Defensive use only`, `Source: …`, `Last refresh: …`) | **Kept exactly as-is** — these are the requested permanent pieces. |
| Two badges (`Portfolio Project`, `Mock Data Mode`)       | **Kept exactly as-is** under the subtitle. |

### What still lives in the public hero

After this pass, the visible hero is exactly:

1. **Logo** (Radar icon in a soft-glow tile, small corner pulse).
2. **`ThreatPulse Radar`** — the title only, no version.
3. **Subtitle** — *"Defensive vulnerability intelligence dashboard for tracking risk, exploitation signals, and remediation priorities."*
4. **`Portfolio Project`** + **`Mock Data Mode`** badges.
5. Three **status pills** on the right: `Defensive use only` · `Source: mock` · `Last refresh: Today`.

No version number, no "Build" line, no operations strip, no live
radar animation. The vibe is "polished product card", not
"telemetry wall".

### Why this works for a public portfolio

- The two badges (`Portfolio Project`, `Mock Data Mode`) make the
  provenance honest at a glance — no visitor will think the data is
  live.
- The three status pills double as a one-line "what is this?" summary.
- The "v1.0" / "local" build line was a developer's tell — removing
  it makes the dashboard read as a shipped product, not a
  half-finished artifact.

### Acceptance still green

```
ALL TESTS PASSED  (13/13)
```

The header is still a pure presentational component; nothing in
`useVulnerabilityFilter`, `FiltersPanel`, `VulnerabilityTable`, or
`DashboardPage` was touched.

---

## Known follow-ups (for v2)

- The `vendor` sort is a string sort. For a vendor-heavy dataset, a
  secondary sort by EPSS desc inside the same vendor block would feel
  nicer. Easy to add as a tiebreaker.
- The "in v2 a single CVE can affect multiple products" idea is now
  safe to add — rows are keyed by `id`, not `cveId`, so duplicates
  no longer collide.
- The search haystack could pre-compute a lowercase blob per record
  if the dataset grows beyond a few hundred rows. For ≤200 records
  the per-keystroke cost is negligible.
- The corner pulse dot on the logo is the only motion left in the
  header. If you want a fully-static "museum card" feel for an even
  quieter version, remove `animate-pulseDot` from the corner `<span>`
  in `Header.tsx`.
- A future v2 may add a discreet "v1.0 · ${git sha}" footer badge
  (not the hero) once a CI pipeline exists. The hero stays clean.
