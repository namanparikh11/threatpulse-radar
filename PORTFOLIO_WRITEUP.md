# ThreatPulse Radar — Portfolio writeup

> Short narrative for recruiters, technical interviewers, and
> anyone skimming the GitHub README. Talks about *what* it is,
> *why* it exists, and *how* it was built. For the technical
> details (file tree, API endpoints, test counts), see `README.md`.

---

## What is it?

**ThreatPulse Radar** is a single-page web dashboard that tracks
publicly disclosed cybersecurity vulnerabilities for **defensive
security work** — patch prioritization, exposure awareness, and
remediation tracking. It pulls five public defensive-intelligence
feeds live (server-side, via a Netlify Function) and joins them
into one filterable view:

| Feed | What it gives the dashboard |
| --- | --- |
| **CISA KEV** | "This CVE is being actively exploited in the wild" |
| **NVD CVE 2.0** | CVSS base score and severity |
| **FIRST EPSS** | Probability the CVE will be exploited in the next 30 days |
| **CISA Vulnrichment** | CISA SSVC decision context (Exploitation, Automatable, Technical impact) |
| **GitHub Advisory Database** | Reviewed GHSA, affected package, vulnerable range, first patched version |

The result is a one-page command center: at a glance, a defender
can see "which critical KEV-listed CVEs are most likely to be
exploited against my stack, and which vendor / product do they
affect?" The dashboard's 6 stat cards, 4 charts, and filterable
table all share one pipeline, so a click anywhere updates
everywhere. The Vulnrichment SSVC context appears only in the
vulnerability details drawer (not as a main-table column) so the
five signals stay independent — the dashboard never combines them
into a proprietary composite score.

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

### 5. The dashboard ships with **874 acceptance tests** that don't
need a browser

A hand-rolled `scripts/acceptance-*.mjs` test runner exercises
the filter / sort / enrichment / orchestration / cache / proxy /
soft-refresh / prebuilt / last-known-good / CISA Vulnrichment /
GitHub Advisory pipeline against synthetic data, with no test
framework, no DOM, no build step. It runs in seconds on Node 18+:

```bash
node scripts/acceptance-cisa.mjs               # 28 CISA KEV tests
node scripts/acceptance-epss.mjs               # 39 FIRST EPSS tests
node scripts/acceptance-nvd.mjs                # 57 NVD CVSS tests
node scripts/acceptance-cache.mjs              # 60 v4 cache tests
node scripts/acceptance-proxy.mjs              # 110 v5.0 proxy tests
node scripts/acceptance-softrefresh.mjs        # 58 v5.1 soft-refresh tests
node scripts/acceptance-prebuilt.mjs           # 148 v5.2 prebuilt-blob tests
node scripts/acceptance-lastknowngood.mjs      # 76 v5.4.2 last-known-good tests
node scripts/acceptance-vulnrichment.mjs       # 125 v5.5 CISA Vulnrichment tests
node scripts/acceptance-github-advisory.mjs    # 173 v5.6 GitHub Advisory tests
```

The tests assert source-code wiring (e.g. "the service file
imports the EPSS provider", "the cache envelope preserves
`nvdStatus` on the round-trip", "the public response strips
`lastVulnrichmentRefresh`") as well as runtime behavior. This
catches regressions like "someone reverted the severity sort
comparator", "someone reintroduced the CISA description note
that claims EPSS is unwired", "someone optimized the cache by
stripping the unavailable flags", or "someone reintroduced a
main-table column for SSVC" — all real or near-real bugs that
would have been silent failures without these tests.

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

### 7. V4.1 — The public demo is source-honest about static deployment and CORS

A static public deployment of a "live" data dashboard has a real
honesty problem: third-party feeds can block or rate-limit
direct browser requests at any time (CORS, geo-blocking,
anonymous rate limits, upstream outages), and the easy response
is to silently swap in a pre-baked dataset so the page never
goes blank. **The v4.1 stance is the opposite: the failure mode
is shown, not hidden.** This is what the public demo at the
deployed URL is actually showing you, on purpose:

- The header pills, the source label, and the banners above
  the stats are the source of truth. If CISA is unreachable,
  the header shows "Fallback Mode" and a "Source: mock
  (fallback)" pill in amber. The mock dataset is shown, but
  the page never *claims* it's live data.
- For *partial* upstream failures (CISA succeeded, NVD or
  EPSS did not), the same pattern applies per-provider: the
  working providers' data is shown, the failing providers'
  pills turn amber, and a soft banner explains the partial
  outage. A degraded view is never dressed up as a full view.
- The v4 localStorage cache envelope preserves the original
  `nvdStatus` / `epssStatus` / `fallbackReason` fields, so
  cached data is rendered with the same provider-failure
  banners that the original live load produced. The cache is
  an optimization, not a way to make failures invisible.

Two consequences of that stance that are worth calling out in
an interview:

1. **No API keys are ever embedded in the frontend bundle.**
   A static `dist/` is a public artifact the moment the site
   is deployed — any key shipped in it is a public credential,
   and rotating a leaked key is more disruptive than accepting
   the 5-req/30s NVD anonymous rate limit. Embedding a key
   would also have made the "the dashboard never claims data
   it doesn't have" property less honest, because the key
   itself would be unverifiable from the public bundle. I
   chose the slower path on purpose.
2. **A future v5 could add a thin backend or serverless
   proxy** that aggregates CISA + NVD + FIRST EPSS
   server-side and exposes a single CORS-safe JSON endpoint.
   The v4.1 service layer is designed so a backend can be
   added as a new `provider` without touching UI code or
   breaking the existing fallback path. **v4.1 does *not*
   add the backend** — that is an explicit v5 milestone,
   not a quietly-laid track. The dashboard as deployed
   today is strictly frontend-only.

### 8. V5.x — The server-side prebuilt-blob design (incremental, partial, honest)

The v5.x backend is a thin Netlify Function that runs the
CISA → NVD → EPSS build on a cron, writes the result to a
shared Netlify Blobs entry, and serves the prebuilt envelope
to every subsequent visitor. Four design choices in the
backend are worth pointing to:

- **Last-known-good preservation (v5.4.2).** If the live
  build fails (CISA unreachable, NVD rate-limited, network
  error), the orchestrator does **not** overwrite the
  existing prebuilt blob with a degraded envelope. Visitors
  keep seeing the last successful build, the header pill
  explains the partial outage, and the next cron tick
  retries. A bad refresh is never allowed to worsen the
  public dataset.
- **Incremental enrichment with negative caching (v5.5).**
  CISA's Vulnrichment repository publishes SSVC decision
  context for selected CVEs, but not for all of them. The
  refresh runs a **separate incremental post-step** that
  selects at most 50 missing-or-stale CVEs per cycle and
  enriches them at concurrency 5, sorted by KEV `dateAdded`
  descending. An HTTP 404 ("no CISA Vulnrichment assessment
  available") is recorded as a lightweight
  `{ ssvc: null, status: "missing", cachedAt, checkedAt }`
  negative-cache marker instead of being re-fetched every
  cycle — so the backfill queue keeps moving instead of
  looping over the same CVEs. A 404 is also explicitly
  prevented from overwriting an existing positive SSVC
  record, so a transient upstream inconsistency cannot
  delete real data.
- **Honest partial coverage (v5.5).** The public envelope
  carries `vulnrichmentStatus: "available" | "partial" |
  "unavailable"` and `vulnrichmentCoverage: { enriched,
  total }`, computed from the actual cache state at read
  time. The status is never `available` while the
  incremental backfill is still in progress — the
  `enriched` count is compared to the total, and the
  status is derived honestly. Visitors see exactly how
  many CVEs in the current dataset have a CISA Vulnrichment
  assessment, and the SSVC fields appear in the details
  drawer for those that do. The five signals (KEV, NVD,
  EPSS, SSVC, GitHub Advisory) stay independent; the
  dashboard never combines them into a proprietary
  composite score.
- **Reviewed package-remediation enrichment (v5.6).** The
  GitHub Advisory Database publishes reviewed, vulnerability-
  scoped advisories. The refresh runs a **second separate
  incremental post-step** that filters the upstream endpoint
  by CVE and by the reviewed advisory type, then selects at
  most 25 missing-or-stale CVEs per cycle (50 when the
  optional server-side `GITHUB_TOKEN` is configured) and
  enriches them at concurrency 4. Withdrawn and unreviewed
  advisories are dropped at the filter; only reviewed,
  non-withdrawn entries are stored. The same read-time merge
  pattern is used as for Vulnrichment: records are stored
  in their own Netlify Blobs store (`tpr-github-advisory`),
  attached to records at serve time, and never written to
  the main `latest-dataset` blob. As a result, a GitHub
  Advisory update can never rewrite the main blob's
  `fetchedAt`, and the v5.1 "newer dataset available"
  banner can never fire spuriously from a remediation
  refresh. Empty / 404 results are negatively cached as
  `{ advisory: null, status: "missing", cachedAt,
  checkedAt }`; a 404 is explicitly prevented from
  overwriting an existing positive advisory record, and
  provider failures (5xx, network errors, rate-limit
  responses) preserve the positive cached entry. The
  public envelope carries
  `githubAdvisoryStatus: "available" | "partial" |
  "unavailable"` and `githubAdvisoryCoverage: { enriched,
  total }`, computed honestly from the actual cache state.
  When a reviewed advisory does not list a patched version
  — for example because the upstream record omits the field
  or the package is unmaintained — the drawer renders the
  field as **"First patched version unavailable"**. The
  dashboard never infers a missing patched version as
  **"No fix exists"**; that would be a fabricated claim
  that a defender could act on. The optional
  `GITHUB_TOKEN` is read from `process.env` inside the
  Netlify Function only, passed to the upstream as an
  `Authorization: Bearer <token>` header, and **never**
  appears in the function response body, in any URL, in
  any log, or in the frontend bundle. The dashboard works
  identically without it (slower incremental backfill,
  repeat visitors ride the CDN cache for the main envelope
  either way).

The result: a backend that runs cheaply (one cron tick every
30 min, two enrichment passes per refresh), degrades honestly
(partial outages are labeled, never hidden), and is
incremental (the 1,600+ CVEs in CISA KEV are not re-fetched
in a single cycle). The visitor never sees a raw provider
error, a transient failure reason, or any of the internal
operator-only fields written to the blob.

---

## What I would do differently next time

A short list of honest trade-offs:

- **The NVD rate limit (5 requests / 30 s on the anonymous
  endpoint) still makes the *first* load feel slow.** The v4
  cache makes the second-and-onwards load instant, but the
  very first visit on a fresh browser pays the full 30–60 s
  NVD first-load. I considered a "loading NVD… 50 % complete"
  progress indicator, but the user asked for no UI redesign.
  The current state uses one spinner and a copy line that says
  "Loading CISA KEV · NVD CVSS · FIRST EPSS — may take up to a
  minute on first load…". A v5 backend or serverless proxy
  could absorb the NVD rate limit server-side and serve a
  single CORS-safe JSON to the browser, which would fix the
  first-load latency *and* remove the CORS-failure surface
  for the public demo. Embedding an NVD API key in the
  frontend bundle is not on the table — a static `dist/` is
  a public artifact, and shipping a key is shipping a public
  credential.
- **No "save filter preset" or "watchlist" features.** Would be
  the next pass if I had more time. (Note: any new `localStorage`
  key should follow the v4 cache module's pattern — versioned
  suffix, schema-validated reads, defensive try/catch.)
- **Recharts 2 is on a deprecation track upstream.** The
  current pinned version is `^2.13.3` and the deprecation
  warning is benign for the production build, but a future
  pass would pin `recharts@3` and audit any breaking
  changes in the chart components.

---

## V6.0 — Canonical baseline (private data plane)

V6.0 introduces a private data plane alongside the public
V5.7 dashboard. The full vulnerability dataset is published
as a content-addressed, versioned, atomic baseline; consumers
authenticate to a separate Netlify site to read it.

The interesting engineering problems:

- **The bootstrap state is a journal, not a log.** The
  orchestrator's per-ecosystem cursor and bounded
  recent-ids ring let a run that is killed by the 15-minute
  Background Function ceiling resume from the last
  persisted position. The state lives in a single Blob
  (`osv-bootstrap-state`); it is a journal of progress,
  not a record of every record processed.
- **The latest pointer is the only mutable write.** Every
  other artifact (version manifests, content-addressed
  shards, deltas) is immutable. A reader that sees the new
  pointer can also find the new version manifest and
  delta; a reader that sees the old pointer still sees a
  consistent previous version. The publisher's atomicity
  is one `manifests/latest.json` write.
- **The delta's `targetManifestHash` matches the new
  manifest's `canonicalContentHash` exactly.** A previous
  two-pass build produced a mismatch because `deltaHash`
  was inside the manifest's content hash. The fix moves
  `deltaHash` to a metadata field, attached AFTER the
  canonical content hash is computed. Consumers verify
  the delta and the manifest against each other; the
  hash discipline is the same on both sides.
- **The credential is HMAC, not a JWT.** The pepper
  (`THREATPULSE_CREDENTIAL_PEPPER`) lives only in the
  gateway's environment. The stored digest is the raw
  HMAC-SHA256 output, no `sha256:` prefix, no extra
  wrapping. The keyId character set is `A-Za-z0-9-`
  (deliberately excludes `_` to keep the credential
  unambiguously parseable). The constant-time
  comparison hashes both sides to SHA-256 BEFORE the
  `timingSafeEqual` call, so a wrong-length input cannot
  be used as a side channel.
- **The consumer is intentionally small.** It is a
  reference implementation, not a feature-complete sync
  engine. A real product would add retries, exponential
  backoff, concurrent fetches, and an observability
  surface. The reference keeps the surface area small so
  the integration story is obvious.

What V6.0 is explicit about NOT doing:
- No anonymous public function reads the canonical
  baseline. The only public surface is the V5.7 dashboard.
- No real-time push. Consumers pull on their own schedule.
- No STIX 2.1 interop (a future-version concern).
- No per-credential hard quotas (deferred until an atomic
  counter store exists).

The full V6.0 architecture summary is in
[`docs/v6-architecture.md`](docs/v6-architecture.md).

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
  under `src/services/providers/`. For the v5.x backend,
  skim `netlify/functions/_shared/refresh.mjs`,
  `liveBuild.mjs`, `store.mjs`, `vulnrichment.mjs`,
  `vulnrichmentRefresh.mjs`, `githubAdvisory.mjs`, and
  `githubAdvisoryRefresh.mjs` — the entire build +
  enrichment pipeline is in those seven files. Then read
  the ten acceptance scripts and follow the test flow
  backward into the production code.
- **30 minutes**: skim the git history (or run
  `git log --oneline --graph`). The version-by-version commit
  messages tell the same "story" — what shipped, what was
  fixed, what was audited — without needing a separate
  internal doc.

If you're a hiring manager or a technical interviewer and you
read this far — thank you. I'd love to walk you through any
section in person.

---

_Made with care — defensive only._
