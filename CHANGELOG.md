# Changelog

Public version history for **ThreatPulse Radar**. Newest
entry first. Entries are concise; for design notes and the
audit findings behind each release, see
[`README.md`](./README.md),
[`PORTFOLIO_WRITEUP.md`](./PORTFOLIO_WRITEUP.md), and
[`PUBLIC_RELEASE_CHECKLIST.md`](./PUBLIC_RELEASE_CHECKLIST.md).

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
