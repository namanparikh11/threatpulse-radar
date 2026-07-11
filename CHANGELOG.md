# Changelog

Public version history for **ThreatPulse Radar**. Newest
entry first. Entries are concise; for design notes and the
audit findings behind each release, see
[`README.md`](./README.md),
[`PORTFOLIO_WRITEUP.md`](./PORTFOLIO_WRITEUP.md), and
[`PUBLIC_RELEASE_CHECKLIST.md`](./PUBLIC_RELEASE_CHECKLIST.md).

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
