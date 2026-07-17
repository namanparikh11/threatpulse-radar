# V6.8 — Release Candidate Consolidation

ThreatPulse Radar **V6.8** is a release-candidate
consolidation milestone. It contains the complete
V6.1–V6.8 product, with a focus on stabilizing,
measuring, lazy-loading, and documenting the existing
surfaces rather than introducing a new major subsystem.

V6.8 is honest about what it is and what it is not. It
is a single controlled release of a defensive
cybersecurity intelligence product. It is **not**
enterprise-certified, legally admissible, complete,
or independently audited.

## Product capability map

### Public intelligence (V6.1)
- CISA KEV, NVD CVSS, FIRST EPSS, GitHub Advisory, and
  OSV public projection.
- Bounded data cache with the v5.2 dataset-store pill
  and the v5.1 background poll / "New dataset
  available" banner.
- Source health, change intelligence, public
  filters, Defender Views presets.

### Local workspace (V6.4)
- Local-only CVE triage with notes, tags, and
  user-assigned priority / triage status.
- Bulk actions, change-since-review marker, and a
  local export / import with SHA-256 integrity.

### Local environment (V6.6)
- Asset registry + supported SBOM import (CycloneDX
  1.4 / 1.5 / 1.6 JSON, SPDX 2.3 JSON, ThreatPulse
  inventory JSON, bounded CSV).
- Six documented correlation states.
- Eight review statuses. Export / import with
  SHA-256 integrity.

### Local remediation (V6.7)
- Nine-state plan lifecycle, ten remediation types,
  five priorities, six validation statuses.
- Local task list, evidence records, and append-only
  hash-chained activity ledger.
- Local file fingerprint via Web Worker / Web Crypto.
- Export / import with SHA-256 integrity; atomic
  ledger conflict detection.

### Reports (V6.5)
- Five report templates and five redaction modes.
- Markdown, HTML, print, and JSON export.
- Verifier, compare, and history dialogs.
- Optional additive `localEnvironmentSummary` (V6.6)
  and `localRemediationSummary` (V6.7) — counts only,
  never including owner / plan / task / evidence /
  fingerprint / blocker / validation / actor content.

## Public vs local-only data boundary

| Surface | Public? | Local-only? |
| --- | --- | --- |
| Vulnerability corpus | yes | no |
| Source health | yes | no |
| Public change summary | yes | no |
| Workspace entries (notes / tags / triage) | no | yes |
| Environment assets / SBOMs / correlations | no | yes |
| Remediation plans / tasks / evidence | no | yes |
| Local evidence fingerprints | no | yes (counts only) |
| Local report content (private notes, owner labels) | no | yes |
| Report history summary | no | yes |
| Activity ledger | no | yes (tamper-evident local only) |

The public dashboard never carries any of the
local-only fields. Default public reports do not
carry any environment or remediation content.

## Supported providers (read-only)

- **CISA KEV** — authoritative known-exploited list.
- **NVD CVE 2.0** — CVSS enrichment.
- **FIRST EPSS** — exploitation probability.
- **GitHub Advisory** — package remediation context.
- **OSV** — public package vulnerability projections.

The dashboard never calls package or provider APIs
from the browser. All provider calls go through the
Netlify gateway.

## Supported local import formats

| Dataset | Format | Notes |
| --- | --- | --- |
| Environment | CycloneDX 1.4 / 1.5 / 1.6 JSON | bounded |
| Environment | SPDX 2.3 JSON | bounded |
| Environment | ThreatPulse inventory JSON | bounded |
| Environment | CSV | bounded, schema-validated |
| Remediation | threatpulse-local-remediation v1.0.0 | SHA-256 integrity |
| Workspace | threatpulse-workspace v1.0.0 | SHA-256 integrity |

## Supported version evaluators (V6.6)

- npm
- crates / cargo
- packagist / composer
- generic-exact (default for ecosystems without a
  dedicated evaluator)

PyPI, Maven, Go, and NuGet fall through to the
generic-exact evaluator. Pre-release versions are
never matched against `>=X` ranges.

## Workspace capabilities

- Local-only watch, triage, priority, tag, note.
- Multi-tab sync via `BroadcastChannel`.
- Bulk actions and a "Changed since review" filter.
- Export and re-import with SHA-256 integrity.

## Reporting capabilities

- Five templates:
  - defender-daily-briefing
  - selected-cve
  - change-briefing
  - asset-environment-rollup
  - workspace-summary
- Five redaction modes (none, exclude-private-notes,
  exclude-all-user-text, identifiers-only,
  full-export).
- Markdown, HTML, print, and JSON export.
- Verifier dialog (re-verify the integrity
  checksum) and compare dialog (compare two saved
  reports).
- History dialog (summary-only records).

## Environment correlation limitations

- Correlations are computed from package identity
  + version range. They are not exploitability
  signals.
- Six documented correlation states; each is
  honestly labelled.
- A "no-supported-match" or "version-not-evaluable"
  result is **not** the same as "safe".

## Remediation / evidence limitations

- All plan / task / evidence / ledger data is local.
- The hash chain detects local tampering; it does
  **not** prove authorship, identity, timestamp
  authority, or legal authenticity.
- A "passed-locally" validation is a workflow
  record, not an external verification.
- A "completed locally" plan status is a workflow
  record, not an external fix.

## Browser persistence limitations

- IndexedDB is the only persistent layer.
- Quota may be exceeded on large imports.
- Safari private mode and some enterprise policies
  block IndexedDB entirely; the in-memory adapter
  exposes this fact via the Local Data Control
  Centre.
- `localStorage` is used only for the report
  history enabled flag (summary-only).

## Backup requirements

A complete backup requires **three** separate local
exports (and a fourth optional report-history clear):

1. Local workspace (JSON, SHA-256 integrity).
2. Local environment (JSON, SHA-256 integrity).
3. Local remediation (JSON bundle, SHA-256 integrity).

Each dataset's clear action is independent. The
Local Data Control Centre surfaces an export-first
recommendation before every clear action.

## Netlify deployment architecture

- 5 public Netlify functions: `dataset`,
  `refresh-baseline-background`,
  `refresh-baseline-scheduled`,
  `refresh-dataset-background`,
  `refresh-dataset-scheduled`.
- 1 gateway function: `private-sync-gateway`.
- The client code is statically hosted; no server
  state is required for the public dashboard.
- The gateway exposes only private, owner-specific
  sync storage for the hostinger portability path;
  no public payload is ever proxied through it.

## Hostinger portability architecture

- Filesystem-backed public-intelligence storage.
- Portable HTTP server (`ac2b180`) + CLI jobs
  (`feb2742`).
- Cron locks via the V6.3 portable cron lock helper.
- Backup / restore via the V6.2 filesystem tooling.
- Deployment manifest generator (V6.3).

## Known dependency advisories and mitigations

- `xz-utils` 5.6.0 and below are not in the
  fingerprint path; the V6.6 environment import
  evaluator lists `xz-utils 5.6.1+` as the supported
  range.
- All browser-reachable hashing is `crypto.subtle`
  only; no `node:crypto` chunk is emitted by the
  Vite build.
- The Vite build graph was audited in V6.6
  (`6d5fd39`) to remove the `sha256Node` chunk and
  to harden the test cleanup path.

## Known deferred work

- v2.0 remediation templates (V7.x roadmap).
- Multi-org workspace collaboration.
- Server-side persistence of the report history
  (out of scope for the local-only product).
- Public corpus extension beyond CISA KEV / NVD /
  FIRST EPSS / GitHub Advisory / OSV.
- Real-time push (the V6.0 architecture is pull-only
  by design).
- An optional server-side "trends" view (out of
  scope; the dashboard is local-first).

## Release verification checklist

- [x] 36 acceptance suites pass with exit code 0.
- [x] `npm.cmd run build` is clean.
- [x] No `sha256Node` or `fingerprintNode` chunk in
  the Vite build output.
- [x] No `node:crypto` reference in the browser
  output.
- [x] No forced `process.exit(0)` in any acceptance
  source.
- [x] `git diff --check` is clean.
- [x] `git status --short` is empty after a clean
  build.
- [x] 5 public Netlify function entries.
- [x] 1 gateway function entry.
- [x] `CSV_COLUMNS` = 21.
- [x] `client/` and `netlify/gateway/` are
  byte-identical to `32a8a63`.
- [x] `docs/v6-8-release-candidate.md` is the
  canonical release-candidate description.

## Rollback and checkpoint information

The V6.8 branch is built on the V6.7 checkpoint
(`9912044`). The V6.6 checkpoint is `6d5fd39`. The
V6.5 checkpoint is `4165c87`. The V6.4 checkpoint is
`70a228c`. The V6.3 checkpoint is `15364e5`. The V6.2
checkpoint is `52f8c57`. The V6.1 / V6.0 baseline is
`32a8a63`. Each checkpoint is a published branch in
the repository; rolling back to any checkpoint is a
single `git checkout <branch>` operation.

## What V6.8 is NOT

- Not enterprise-certified.
- Not legally admissible.
- Not "complete" in the sense that no further
  product work is needed.
- Not independently audited by a third party.
- Not a real-time push system.
- Not a multi-tenant SaaS.
- Not a substitute for a vulnerability management
  platform.
- Not a substitute for a security audit.

V6.8 is a single controlled release of a defensive
cybersecurity intelligence product that runs in a
single browser session and depends on public, free
data sources.
