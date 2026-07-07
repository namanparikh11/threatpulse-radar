# ThreatPulse Radar — Portfolio writeup

> Short narrative for recruiters, technical interviewers, and
> anyone skimming the GitHub README. Talks about *what* it is,
> *why* it exists, and *how* it was built. For the technical
> details (file tree, API endpoints, test counts), see `README.md`
> + `PROJECT_HANDOFF.md`.

---

## What is it?

**ThreatPulse Radar** is a single-page web dashboard that tracks
publicly disclosed cybersecurity vulnerabilities for **defensive
security work** — patch prioritization, exposure awareness, and
remediation tracking. It pulls three public defensive-intelligence
feeds live in the browser (no backend) and joins them into one
filterable view:

| Feed | What it gives the dashboard |
| --- | --- |
| **CISA KEV** | "This CVE is being actively exploited in the wild" |
| **NVD CVE 2.0** | CVSS base score and severity |
| **FIRST EPSS** | Probability the CVE will be exploited in the next 30 days |

The result is a one-page command center: at a glance, a defender
can see "which critical KEV-listed CVEs are most likely to be
exploited against my stack, and which vendor / product do they
affect?" The dashboard's 6 stat cards, 4 charts, and filterable
table all share one pipeline, so a click anywhere updates
everywhere.

It is **defensive-only**. There is no exploit code, no offensive
tooling, and no "how to weaponize this CVE" content. Every
recommended action is plain-language patching guidance ("apply
the vendor patch, rotate credentials, review access logs").

---

## Why does it exist?

I built this for two reasons, in order of importance:

1. **As a portfolio piece for security / frontend job interviews.**
   The dashboard is the artifact; the engineering choices in it
   are the proof. "I built a thing" is the table-stakes; "I built
   a thing that handles partial upstream failure without
   misrepresenting the data to the user" is the differentiator.
2. **As a real tool I would use at work.** I would rather look at
   a single, honest, fast page than open three browser tabs and
   cross-reference KEV / NVD / EPSS by hand every morning.

It is **not** meant to compete with enterprise vulnerability
management platforms (Tenable, Qualys, Wiz). It is a portfolio
demo of "here is how I think about frontend architecture under
real-world public-API constraints."

---

## What's interesting about how it was built?

Five engineering decisions that I would talk through in an
interview:

### 1. Each upstream API is its own provider with its own status field

CISA, NVD, and FIRST are three independent services, each with
its own failure mode. The dashboard does not treat them as one
black box. The `FetchResult` shape has separate `nvdStatus` and
`epssStatus` side-channels:

```
mode: 'live'   ← CISA succeeded (we have data to show)
nvdStatus: 'nvd'             | 'unavailable' + nvdReason
epssStatus: 'first'          | 'unavailable' + epssReason
```

If NVD is unreachable, the CISA + EPSS data is still shown with
a soft amber banner explaining what failed. If EPSS is
unreachable, the CISA + NVD data is still shown. If CISA itself
fails, the dashboard falls back to a curated mock dataset so the
page never goes blank.

The header pill always reflects the *actual* state — it never
claims "CISA KEV + NVD + FIRST EPSS" when one of those providers
failed to load. (The source label is built dynamically from
the per-provider status fields, not hard-coded.)

### 2. The CISA description is honest about what's *not* there

CISA's KEV feed tells you a CVE is exploited. It does *not*
tell you the CVSS score, the EPSS probability, or a full
description. The dashboard's normalized record keeps the
CISA-derived severity (KEV = at least High; ransomware-known =
Critical) but defaults CVSS and EPSS to `0` and adds a one-line
note in the description:

> "CVSS and EPSS are not part of the CISA KEV feed; the
> dashboard may enrich them from NVD and FIRST EPSS when those
> services are reachable."

When the user sees `0.0` in the CVSS column, they know *why*
and know that enrichment might fill it in. When enrichment
fails, the same `0.0` is honest because the data genuinely
isn't there.

### 3. No CVSS / EPSS fabrication. Ever.

A CISA CVE that isn't in NVD's response keeps `cvssScore: 0`,
not "guessed to 7.5". A CISA CVE that isn't in FIRST's response
keeps `epssProbability: 0`, not "estimated to 0.5". I had
multiple opportunities to invent values ("KEV is at least High,
so use that as a proxy for severity") and chose not to. The
mock dataset has hand-curated CVSS / EPSS values for the
fallback view, but the live path never lies.

### 4. The filter / sort pipeline is shared across all data paths

The same `useVulnerabilityFilter` hook + `applyFilters` +
`applySortBy` pipeline processes the CISA KEV data, the NVD-
enriched data, the EPSS-enriched data, and the mock data
identically. The "no fabrication" property of the live path
falls out of the fact that the enrichers are pure functions
that leave records alone when their data isn't present:

```ts
export function enrichWithEpss(records, epssMap) {
  return records.map((v) => {
    const score = epssMap.get(v.cveId);
    if (!score) return v;        // ← no fabrication
    return { ...v, epssProbability: score.epss };
  });
}
```

This means a recruiter can ask "what happens when a CVE isn't
in the EPSS response?" and the answer is in three lines of code
at the top of the enricher.

### 5. The dashboard ships with **195 acceptance tests** that don't
need a browser

A hand-rolled `scripts/acceptance*.mjs` test runner exercises
the filter / sort / enrichment / orchestration / cache pipeline
against synthetic data, with no test framework, no DOM, no build
step. It runs in ~2 seconds on Node 18+:

```bash
node scripts/acceptance.mjs          # 15 v1 mock tests
node scripts/acceptance-cisa.mjs     # 28 v2 CISA tests
node scripts/acceptance-epss.mjs     # 39 v2.5 EPSS tests
node scripts/acceptance-nvd.mjs      # 53 v3 NVD tests
node scripts/acceptance-cache.mjs    # 60 v4 cache tests
```

The tests assert source-code wiring (e.g. "the service file
imports the EPSS provider", "the cache envelope preserves
`nvdStatus` on the round-trip") as well as runtime behavior. This
catches regressions like "someone reverted the severity sort
comparator", "someone reintroduced the CISA description note
that claims EPSS is unwired", or "someone optimized the cache
by stripping the unavailable flags" — all real or near-real
bugs that would have been silent failures without these tests.

### 6. The cache layer is transparent and never hides failures

The v4 layer adds a 1-hour `localStorage` cache so a returning
visitor doesn't pay the 30–60 s NVD first-load again. The cache
is intentionally *visible*:

- A "Cache: fresh" pill in the header when data came from the
  cache within the TTL; "Cache: stale" when the cache expired
  and the live fetch just failed (last-resort fallback).
- A "Cached data" banner above the stats with both the relative
  ("refreshed 5 minutes ago") and absolute ("Jul 08, 2026,
  12:21:34 AM") timestamp of the original upstream fetch.
- A "Refresh live data" button that bypasses the cache and
  triggers a fresh upstream fetch.
- The original `nvdStatus` / `epssStatus` / `fallbackReason`
  fields are preserved through the cache envelope. A cached
  dataset that originally had "NVD: unavailable" still shows
  the amber NVD pill — the cache never hides a failure.

I could have optimized by storing a pre-normalized, smaller
payload and dropping the unavailable flags. I chose not to,
because the entire point of the dashboard is being honest about
where the data came from. The cache envelope round-trips the
full `FetchResult` so the user can't tell (visually) that
they're looking at cached data except for the explicit pill +
banner telling them.

---

## What I would do differently next time

A short list of honest trade-offs:

- **The NVD rate limit (5 requests / 30 s without an API key)
  still makes the *first* load feel slow.** The v4 cache makes
  the second-and-onwards load instant, but the very first visit
  on a fresh browser pays the full 30–60 s NVD first-load. I
  considered a "loading NVD… 50 % complete" progress indicator,
  but the user asked for no UI redesign. The current state uses
  one spinner and a copy line that says "Loading CISA KEV · NVD
  CVSS · FIRST EPSS — may take up to a minute on first load…".
  A future pass could plumb an NVD API key for a 10× rate-limit
  bump.
- **No "save filter preset" or "watchlist" features.** Listed
  in the v4.5 milestone in `PROJECT_HANDOFF.md`. Would be the
  next pass if I had more time. (Note: any new `localStorage`
  key should follow the v4 cache module's pattern — versioned
  suffix, schema-validated reads, defensive try/catch.)
- **Recharts 2 is deprecated.** The deprecation warning is
  benign for v4 but I'd pin `recharts@3` in the next pass.

---

## How to look at it

- **5 minutes**: load the deployed URL, click around, try the
  filters. The header pills tell you which feeds are live. If
  one is amber ("NVD: unavailable"), click into a record — the
  CVSS column will read `0.0` and the description will explain
  why. On your second visit, the "Cache: fresh" pill in the
  header tells you data is being served from `localStorage`,
  and the "Cached data" banner above the stats shows the
  exact time of the last upstream fetch.
- **15 minutes**: read `src/services/vulnerabilityService.ts`,
  `src/services/datasetCache.ts`, and the three providers
  under `src/services/providers/`. That's the entire data
  + cache layer. Then read the five acceptance scripts and
  follow the test flow backward into the production code.
- **30 minutes**: read `PROJECT_HANDOFF.md` end-to-end. It walks
  through every pass, every fix, and every decision in
  chronological order — it's the "story" of the project, not
  just the spec.

If you're a hiring manager or a technical interviewer and you
read this far — thank you. I'd love to walk you through any
section in person.

---

_Made with care — defensive only._
