# V6.1 — Source Transparency

The Source Health panel makes the public dashboard
honest about which data sources contribute to the
current dataset and how healthy each one is. Six sources
are tracked: CISA KEV, NVD, FIRST EPSS, CISA
Vulnrichment (SSVC), GitHub Advisory Database, and OSV.

## Five derived states (mutually exclusive)

The state field is derived at request time from the
persisted observations. No state field is persisted in
the public response.

| State | Rule | Surfaced copy |
| --- | --- | --- |
| `unknown` | No successful observation AND no definitive hard failure | "No data yet — first deploy or fresh bootstrap." |
| `fresh` | Usable successful observation, age < threshold, complete coverage, no degrade | (no chip; green dot only) |
| `partial` | Fresh + incomplete coverage OR fresh + soft-partial OR fresh + recent hard failure | "Partial" chip + sanitized warning |
| `stale` | Usable successful observation, age ≥ threshold | "Stale" chip |
| `unavailable` | No usable successful observation AND a definitive hard failure was recorded | "Unavailable" chip + sanitized warning |

A recent hard failure after a usable observation does
NOT erase usability. The state is `partial` (with a
sanitized warning), not `unavailable`. The `unavailable`
state is reserved for the case where no successful
observation exists AND a hard failure has been recorded.

## Thresholds (based on actual repo refresh schedules)

| Source | Schedule | Threshold | Rationale |
| --- | --- | --- | --- |
| CISA KEV | `*/30 * * * *` | 90 min | 3× the 30-min schedule. |
| NVD | `*/30 * * * *` | 90 min | Same shape. |
| FIRST EPSS | `*/30 * * * *` | 90 min | Same shape. |
| CISA Vulnrichment | incremental | 14 d | 2× the 7-day backfill window. |
| GitHub Advisory | incremental | 14 d | 2× the 7-day backfill window. |
| OSV | `0 * * * *` (hourly) | 180 min | 3× the hourly schedule. |

## What the panel does NOT expose

- API keys, env-var values, internal Blob keys, lock
  metadata, stack traces.
- Provider rate-limit headers, raw error bodies, internal
  cache markers, or any field that would help an attacker
  fingerprint the operator's environment.
- Consumer credentials, private-gateway details, or
  anything that does not appear in the public
  source-registry blob.

## Authentication modes (public enum, no env-var names)

- `none` — public, no credential required (CISA KEV,
  Vulnrichment, OSV, FIRST EPSS).
- `optional-server-side` — the operator may supply a
  token; the public function uses it if present (NVD,
  GitHub Advisory).
- `required-server-side` — reserved for future sources
  that require a token for any access. Not currently
  used.

## Official-source links (validated `https://`)

| Source | Provenance URL |
| --- | --- |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| NVD | https://nvd.nist.gov/ |
| FIRST EPSS | https://www.first.org/epss/ |
| CISA Vulnrichment | https://github.com/cisagov/vulnrichment |
| GitHub Advisory | https://github.com/advisories |
| OSV | https://osv.dev/ |

The Source Health card renders each link as a
`<a target="_blank" rel="noopener noreferrer">` element.
The URLs are part of the static source-registry blob;
they are NOT fetched at render time.

## Honest empty states

When the V6.1 public-intelligence bundle is not yet
published, the Source Health panel renders the
"Source health unavailable. The V6.1 public intelligence
bundle is not yet published. Source health will appear
here once the first dataset-bound bundle is available."
copy. No fabricated `OK` state, no invented timestamps.
