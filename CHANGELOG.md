# Changelog

Public version history for **ThreatPulse Radar**. Newest
entry first. Entries are concise; for design notes and the
audit findings behind each release, see
[`README.md`](./README.md),
[`PORTFOLIO_WRITEUP.md`](./PORTFOLIO_WRITEUP.md), and
[`PUBLIC_RELEASE_CHECKLIST.md`](./PUBLIC_RELEASE_CHECKLIST.md).

## V6.0 — Canonical baseline (private data plane)

V6.0 introduces a **canonical baseline**: a content-addressed,
versioned, atomic-publication snapshot of the full
vulnerability / advisory / package / relationship / tombstone
data plane, derived from OSV. The baseline is **private** —
the V5.7 public dashboard is unchanged.

### What this release adds

- **A new OSV ingestion pipeline.** The public site now
  ships a Scheduled Function (hourly cron) and a Background
  Function (15-minute ceiling) that read OSV's per-ecosystem
  `modified_id.csv` and the per-vuln JSON, normalize to five
  canonical entity types (vulnerability, advisory, package,
  relationship, tombstone), partition into 256 buckets per
  entity type, and publish a new version manifest atomically.
  The pipeline is resumable across Background Function
  invocations via a Blob-backed bootstrap state.
- **A new private sync gateway.** A separate Netlify site
  exposes five authenticated routes at `/private/v1/*`
  (manifest, manifest/{version}, delta, shard, snapshot,
  sources) that authenticated consumers call to read the
  baseline. Authentication is HMAC-SHA256 of the credential
  keyed by a server-side pepper. The credential format is
  `tpr_<keyId>_<randomSecret>`.
- **A reference consumer client.** A small Node.js ESM
  module (`client/consumer-client.mjs`) that authenticates,
  fetches the manifest, verifies its hash, and pulls only
  the shards the local store doesn't already have. The
  default store is a filesystem path; SQLite and Postgres
  adapters are documented in `client/contracts.md`.
- **A new V6.0 documentation set.** `docs/v6-architecture.md`,
  `docs/credentials.md`, `docs/deployment.md`,
  `docs/ecosystems.md`. Plus V6.0 sections in
  `README.md`, `PORTFOLIO_WRITEUP.md`,
  `PUBLIC_RELEASE_CHECKLIST.md`, and this changelog.

### What this release explicitly does NOT add

- No new anonymous function on the public site. The
  baseline is private.
- No real-time push to consumers. Consumers pull.
- No STIX 2.1 interop. The manifest schema is the V6.0
  schema.
- No per-credential hard quotas. Per-IP/per-domain rate
  limits only.
- No change to the V5.7 public dashboard surface.

### Topology

The V6.0 architecture has three Netlify environments:

1. The **public ThreatPulse Radar site** (the V5.7 site
   plus the V6.0 OSV ingestion pipeline). Owns the
   `tpr-baseline` Blob store.
2. The **private sync gateway** (a separate Netlify site).
   Reads the public site's `tpr-baseline` store via
   cross-site env vars. Holds the credential pepper.
3. The **consumer** (a third-party product). Authenticates
   to the gateway with the HMAC credential and pulls the
   baseline.

### Operational entries

- `THREATPULSE_REFRESH_TRIGGER_SECRET` (public site) —
  shared secret used by the scheduled function to invoke
  the background function. Long random string.
- `THREATPULSE_BASELINE_SITE_ID` and
  `THREATPULSE_BLOBS_ACCESS_TOKEN` (private gateway) —
  cross-site access to the public site's `tpr-baseline`
  store.
- `THREATPULSE_CREDENTIAL_PEPPER` (private gateway) —
  the HMAC pepper. Server-side only. Identical to the
  value used by the operator script when issuing
  credentials.
- `THREATPULSE_OSV_ECOSYSTEMS` (public site, optional) —
  JSON override of `config/osv-ecosystems.json`.

### V6.0 invariants (and the test names that verify them)

- **No empty shards.** `applyChangesToBucket` returns an
  empty array for a fully-removed bucket; the orchestrator
  omits that bucket from the new manifest. Tested by
  "empty bucket → null descriptor" in
  `acceptance-canonical-baseline.mjs`.
- **Unchanged shards are reused.** A bucket whose content
  hash matches the previous bucket's hash keeps its
  previous objectKey. Tested by "unchanged content reuses
  previous shard key" in
  `acceptance-canonical-baseline.mjs`.
- **Failed publication leaves `manifests/latest.json`
  unchanged.** A write failure between the version
  manifest write and the latest pointer write does NOT
  cause a torn read. Tested by "failed publication leaves
  latest unchanged" in
  `acceptance-canonical-baseline.mjs`.
- **Old manifests retain valid immutable shard
  references.** A consumer that pins a previous version
  can still fetch its shards indefinitely (the objectKeys
  are content-addressed and never deleted). Tested by
  "manifest/{version} route" in
  `acceptance-private-gateway.mjs`.
- **Equal-timestamp OSV updates are not skipped.** The
  orchestrator re-processes IDs that reappear in
  `modified_id.csv`; the bucket-merge dedup makes the
  re-emit safe. Tested by "equal-timestamp re-emit
  invariant" in `acceptance-osv-ingestion.mjs`.
- **Corrupt shard or delta is rejected.** A consumer
  that receives a bad shard (mismatched sha256) will not
  commit it. The `verifyManifest` function rejects any
  manifest whose computed `canonicalContentHash` does
  not match the embedded value. Tested by "verifyManifest:
  tampered manifest" in
  `acceptance-consumer-client.mjs`.
- **Provider and private API credentials cannot enter
  frontend bundles.** No code path from the public site's
  client code touches the credential pepper, the trigger
  secret, or the cross-site access token. The trigger
  secret, pepper, and access token live in Netlify
  environment variables, not in any code committed to
  this repository.
- **Visitors cannot invoke the background refresh.** The
  background function rejects any request without the
  trigger secret header. Tested by "visitors cannot
  trigger refresh" in `acceptance-scheduler.mjs`.
- **Working tree is clean after the final logical
  commit.** Each logical commit's working tree is empty
  before the next one starts. `git status --short` returns
  no output after the V6.0 implementation is complete.

### Test summary

The V6.0 implementation adds 6 new behavior suites with
441 total assertions:

| Suite | Assertions |
| --- | --- |
| `acceptance-canonical-hashing` | 26 |
| `acceptance-osv-ingestion` | 94 |
| `acceptance-canonical-baseline` | 127 |
| `acceptance-scheduler` | 50 |
| `acceptance-private-gateway` | 90 |
| `acceptance-consumer-client` | 54 |
| **Total V6.0** | **441** |

All 11 existing V5.x acceptance scripts pass unchanged.

### Files added or modified

- **New shared modules**:
  `netlify/functions/_shared/{canonicalBaseline,baselinePublish,osvBackground,triggerAuth,credentials}.mjs`
- **New functions**:
  `netlify/functions/{refresh-baseline-scheduled,refresh-baseline-background,private-sync-gateway}.mjs`
- **New client**:
  `client/{consumer-client.mjs,contracts.md}`
- **New docs**: `docs/{v6-architecture,credentials,deployment,ecosystems}.md`
- **New JSON Schemas**: `schemas/{baseline,delta,manifest,source-registry}-v1.schema.json`
- **New config**: `config/osv-ecosystems.json`
- **Modified**: `netlify.toml` (V6.0 cron), `README.md`,
  `PORTFOLIO_WRITEUP.md`, `PUBLIC_RELEASE_CHECKLIST.md`,
  `CHANGELOG.md`, `.gitignore` (transient build dirs).

### Why this is a major version

V6.0 changes the data-plane architecture, not the dashboard
surface. The dashboard is unchanged. The internal split
between "the publisher" and "the consumer" is the new
contract. Any downstream product that wants to use the
baseline integrates via the consumer client (or its own
implementation of the same contract). The V5.x public
dashboard continues to work as before — the V6.0 changes
are additive on the public site and entirely new on the
private gateway.

## V5.7 — Transparent remediation views and export

- README, portfolio writeup, public-release checklist, and
  changelog refreshed to describe the v5.7 reviewed
  remediation drawer, the "Affected package" tab, the
  vendor / product facet, the "First patched version"
  rendering, the safe-link behavior, and the export.
- The V5.7 surface is the last major addition before V6.0.
  See the V5.6 entry for the GitHub Advisory capability
  that feeds the v5.7 drawer.

## V5.6.1 — GitHub Advisory release documentation

- README, portfolio writeup, public-release checklist, and
  changelog refreshed to describe the v5.6 reviewed
  GitHub Advisory capability accurately: fifth source
  listed, five-provider architecture diagram, drawer-only
  "Package remediation context" section, neutral
  missing-patch semantics ("First patched version
  unavailable", never "No fix exists"), safe GHSA link
  behavior, server-side-only `GITHUB_TOKEN` contract,
  and explicit no-real-time / no-proprietary-score /
  no-header-pill / no-table-column claims.
- Public-release checklist adds a v5.6 GitHub Advisory
  public-surface audit finding (no token leak, no raw
  rate-limit metadata, no raw provider error bodies, no
  internal cache markers, separate `tpr-github-advisory`
  blob store, drawer-only presentation) and a
  production-verification step for
  `githubAdvisoryStatus` / `githubAdvisoryCoverage` /
  Package remediation context / safe GHSA links.
- Portfolio writeup updates the assertion total from
  701 to **874** and adds a fourth design-choice bullet
  to the v5.x section describing the v5.6 reviewed
  package-remediation enrichment, the optional
  `GITHUB_TOKEN`, the read-time merge without
  `fetchedAt` rewrite, and the null-patched-version
  rendering rule.
- No application, Netlify Function, refresh, UI, or test
  changes.

## V5.6 — GitHub Advisory remediation context

- Fifth defensive-intelligence feed: the public **GitHub
  Advisory Database**, surfaced as reviewed package-
  remediation context (GHSA identifier, advisory severity,
  GitHub-reviewed date, source label, and up to 5
  normalized package entries — ecosystem, name, vulnerable
  range, first patched version) in the vulnerability
  details drawer.
- Server-side incremental enrichment: the endpoint is
  filtered by CVE and by the reviewed advisory type, and
  at most 25 missing / stale CVEs are enriched per
  background run without a token (50 with the optional
  server-side `GITHUB_TOKEN`), running at concurrency 4
  as a separate post-step in the same refresh cycle.
  Only reviewed, non-withdrawn advisories are stored;
  withdrawn and unreviewed entries are dropped at the
  filter.
- Separate Netlify Blobs store
  (`tpr-github-advisory`, key `cache`) holds reviewed
  advisory records and lightweight negative-cache
  markers for empty / 404 ("no reviewed GitHub Advisory")
  responses, so the backfill queue keeps moving instead
  of looping. An empty / 404 result never overwrites an
  existing positive advisory record; provider failures
  (5xx, network errors, rate-limit responses) preserve
  positive cached entries.
- A null patched version on a reviewed advisory is
  rendered as **"First patched version unavailable"** —
  the dashboard never infers a missing patched version
  as **"No fix exists"**.
- Package remediation context is drawer-only: no main-
  table column, no header pill, no combined score. The
  public envelope's `githubAdvisoryStatus` /
  `githubAdvisoryCoverage` reflect the actual cache
  state; the dashboard never claims `available` while
  backfill is still in progress. External GHSA links
  open in a new tab with `rel="noopener noreferrer"`
  and point only to the public
  `https://github.com/advisories/<GHSA-ID>` URL.
- Internal-only fields — negative-cache markers, raw
  rate-limit headers (`x-ratelimit-*`, `Retry-After`),
  raw provider error bodies, cache keys, and stack
  traces — are stripped from the public response. The
  optional `GITHUB_TOKEN` is read from `process.env`
  inside the Netlify Function only, passed to the
  upstream as an `Authorization: Bearer <token>` header,
  and never appears in the function response body, in
  any URL, in any log, or in the frontend bundle. The
  frontend bundle never references the `api.github.com`
  upstream.
- New acceptance suite:
  `scripts/acceptance-github-advisory.mjs`
  (173 assertions).

## V5.5.1 — Vulnrichment launch polish (documentation only)

- README, portfolio writeup, and public-release checklist
  refreshed to describe the v5.5 CISA Vulnrichment /
  SSVC capability accurately: fourth source listed, four-
  provider architecture diagram, honest-partial-coverage
  language, no real-time or proprietary-score claims.
- Public-release checklist adds a Vulnrichment
  public-surface audit finding (no internal metadata, no
  raw provider errors, separate blob store) and a
  production-verification step for `vulnrichmentStatus` /
  `vulnrichmentCoverage`.
- No application, Netlify Function, refresh, UI, or test
  changes.

## V5.5 — CISA Vulnrichment / SSVC

- Fourth defensive-intelligence feed: CISA's public
  **Vulnrichment** repository, surfaced as CISA-ADP **SSVC**
  decision context (Exploitation, Automatable, Technical
  impact) in the vulnerability details drawer.
- Server-side incremental enrichment: at most 50
  missing / stale CVEs enriched per background refresh
  (concurrency 5, KEV-newest first), running as a
  separate post-step in the same refresh cycle.
- Separate Netlify Blobs store (`tpr-vulnrichment`,
  key `cache`) holds SSVC records and lightweight
  negative-cache markers for HTTP 404 ("no CISA
  Vulnrichment assessment available") responses, so the
  backfill queue keeps moving instead of looping.
- A 404 never overwrites an existing positive SSVC record.
  The public envelope's `vulnrichmentStatus` /
  `vulnrichmentCoverage` reflect the actual cache state;
  the dashboard never claims `available` while backfill
  is still in progress.
- Internal-only fields (`lastVulnrichmentRefresh`,
  `lastRefreshFailure`, `lastRefreshAttemptAt`) are
  stripped from the public response. The frontend bundle
  never references the `raw.githubusercontent.com`
  upstream.
- New acceptance suite: `scripts/acceptance-vulnrichment.mjs`
  (125 assertions).

## V5.4.3 — Automatic refresh UI cleanup

- Removed the misleading "Refresh live data" button from
  the dashboard. The button name implied a manual action
  the user could take, but the same path was already run
  on the v5.1 polling tick and the v5.4.2 last-known-good
  guard made manual intervention less meaningful. The
  header "Last refresh" pill and the "New dataset
  available" banner remain as the user-visible signals.
- No code, Netlify Function, or refresh-behavior changes
  — this is a UI-only cleanup.

## V5.4.2 — Last-known-good dataset preservation

- The refresh orchestrator preserves the existing
  prebuilt `latest-dataset` blob when the live build
  fails (CISA unreachable, NVD rate-limited, network
  error). A bad refresh is never allowed to worsen the
  public dataset. The visitor keeps seeing the last
  successful build, the header pill explains the partial
  outage, and the next cron tick retries.
- The existing v5.2.6 NVD cooldown short-circuit is
  preserved on the same path; the new behavior is purely
  additive.
- New acceptance suite: `scripts/acceptance-lastknowngood.mjs`
  (76 assertions).

---

_For the full version-by-version commit history, run
`git log --oneline --graph` from the project root._
