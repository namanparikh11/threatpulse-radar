# ThreatPulse Radar

> A modern cybersecurity **vulnerability-intelligence dashboard** built for
> **defensive** security work. Track CVEs, KEV status, CVSS scores, EPSS
> probability, SSVC decision context, and reviewed package-remediation
> guidance across your stack in one focused command-center view.

![status](https://img.shields.io/badge/status-v6.8-22d3ee?style=flat-square)
![stack](https://img.shields.io/badge/stack-React%20%2B%20Vite%20%2B%20TS-0d1424?style=flat-square)
![use](https://img.shields.io/badge/use-defensive%20only-f43f5e?style=flat-square)

**Live demo:** [https://threatpulse-radar.netlify.app](https://threatpulse-radar.netlify.app)

---

## Defensive-only scope

ThreatPulse Radar is built **exclusively for defensive security work** —
vulnerability prioritization, patch planning, exposure awareness, and
security posture reporting.

It contains **no exploit code, no offensive tooling, and no weaponized
payloads**. Every "recommended action" in the dashboard is
plain-language defensive guidance ("apply the latest vendor patch,
rotate credentials, review access logs").

This is not an enterprise vulnerability management platform. It is not a
real-time zero-day detector. It does not "guarantee" NVD enrichment —
NVD's anonymous endpoint is rate-limited and can return errors; the
dashboard surfaces those honestly rather than papering over them.

---

## What it does

ThreatPulse Radar joins five public defensive-intelligence feeds into a
single filterable dashboard:

| Feed | Provides | Source |
| --- | --- | --- |
| **CISA KEV** | "This CVE is being actively exploited in the wild" | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **NVD CVE 2.0** | CVSS base score + severity (v3.1 → v3.0 → v2) | [NVD](https://nvd.nist.gov/) |
| **FIRST EPSS** | Probability of exploitation in the next 30 days | [FIRST EPSS](https://www.first.org/epss/) |
| **CISA Vulnrichment** | CISA SSVC decision context — Exploitation, Automatable, Technical impact | [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment) |
| **GitHub Advisory Database** | Reviewed GHSA, affected package, vulnerable range, first patched version | [GitHub Advisory Database](https://github.com/advisories) |

The result is a one-page command center:

- **6 stat cards** — total, critical, high, KEV-listed, average EPSS, new-this-week
- **4 charts** — severity distribution, EPSS risk distribution, 14-day trend, KEV vs non-KEV
- **Filterable table** — search by CVE ID / vendor / product / summary,
  severity filter, KEV-only toggle, minimum EPSS slider, sort by
  newest / CVSS / EPSS / KEV
- **Detail drawer** — full description, metrics, recommended defensive
  action, external links to CISA KEV + NVD, the CISA SSVC decision
  context for that CVE (when available), and — for CVEs that have a
  reviewed GitHub Advisory — the **Package remediation context**
  (GHSA ID, advisory severity, reviewed date, affected npm package,
  vulnerable range, first patched version)
- **Dark cybersecurity command-center theme** — neon cyan / amber
  accents, desktop-first responsive

The same `Vulnerability` shape is used end-to-end, so the filter / sort
/ chart pipeline doesn't care which upstream provider contributed which
record.

### CISA Vulnrichment / SSVC — what it adds, and what it does not

The fourth feed is CISA's public **Vulnrichment** repository, which
publishes CISA-ADP **SSVC (Stakeholder-Specific Vulnerability
Categorization)** decision context for selected CVEs. Three
fields are surfaced in the dashboard:

- **Exploitation** — `none` / `poc` / `active` (whether exploitation
  is observed in the wild, has proof-of-concept code, or is
  actively used)
- **Automatable** — `yes` / `no` (whether exploitation can be
  automated)
- **Technical impact** — `partial` / `total` (the scope of the
  technical impact if exploited)

Coverage is **incremental and partial**. Not every CVE in the
dashboard has a CISA Vulnrichment assessment; the backend fetches at
most 50 missing-or-stale CVEs per background run, and a CVE for
which the upstream returns HTTP 404 ("no CISA Vulnrichment
assessment available") is recorded as a lightweight negative-cache
marker so the backfill continues with the rest of the queue rather
than looping over the same CVEs every cycle. The public dataset
envelope carries two derived metadata fields — `vulnrichmentStatus:
"available" | "partial" | "unavailable"` and
`vulnrichmentCoverage: { enriched, total }` — that reflect the
actual cache state at read time. The dashboard never claims
`available` while backfill is still in progress, and the SSVC
fields themselves stay drawer-only (see below).

SSVC is shown **only in the vulnerability details drawer**, as a
"**CISA decision context**" section. It is intentionally **not** a
main-table column and is **not** combined with NVD / EPSS / KEV
into a proprietary "ThreatPulse score" — the five signals stay
independent so a defender can weigh them separately. If a CVE has
no Vulnrichment record, the drawer renders the empty-state copy
"No CISA Vulnrichment assessment available."

### GitHub Advisory Database — what it adds, and what it does not

The fifth feed is the public **GitHub Advisory Database**, which
publishes reviewed, vulnerability-scoped advisories. When a CVE has
a matching reviewed GitHub Advisory, the drawer surfaces a
"**Package remediation context**" section with:

- **GHSA identifier** and a safe external link to the advisory
- **Advisory severity** (the GitHub-reviewed severity)
- **GitHub-reviewed date**
- **Source:** GitHub Advisory Database
- **Affected packages** (up to 5 normalized package entries per
  advisory) — ecosystem, package name, **vulnerable range**,
  and **first patched version** when one is known
- If the advisory does not list a patched version, the field is
  rendered as **"First patched version unavailable"** — never
  inferred as **"No fix exists"**

Coverage is **incremental and partial**. Not every CVE in the
dashboard has a matching reviewed advisory; the backend fetches
at most 25 CVEs per background run without a token (50 with a
token) at concurrency 4, and a CVE for which the upstream
returns an empty result is recorded as a lightweight
negative-cache marker so the backfill continues with the rest
of the queue rather than looping over the same CVEs every
cycle. The public dataset envelope carries two derived
metadata fields — `githubAdvisoryStatus: "available" | "partial"
| "unavailable"` and `githubAdvisoryCoverage: { enriched,
total }` — that reflect the actual cache state at read time.
The dashboard never claims `available` while backfill is still
in progress, and the package-remediation fields themselves stay
drawer-only (see below).

The package-remediation context is shown **only in the
vulnerability details drawer**, as a "**Package remediation
context**" section. It is intentionally **not** a main-table
column, is **not** a header pill, and is **not** combined with
the other four signals into a proprietary composite score. If
a CVE has no reviewed advisory, the drawer simply omits the
section — missing coverage is neutral, not alarming.

---

## Architecture

```
                         Visitor's browser
                                │
                                ▼
   ┌─────────────────────────────────────────────────────────┐
   │  GET /.netlify/functions/dataset   (Netlify Function)    │
   │                                                         │
   │   1. Try `latest-dataset` blob (prebuilt envelope)      │
   │      ├─ hit  → return immediately                        │
   │      └─ miss → build live (bootstrap path)              │
   │   2. Read-time merge into each record:                  │
   │      • SSVC from `tpr-vulnrichment` blob                │
   │      • Package remediation from `tpr-github-advisory`   │
   │                                                         │
   │   Response tagged with:                                 │
   │     dataSource: "prebuilt-store" | "live-build"          │
   │     refreshInProgress: <bool>  (from refresh-lock blob) │
   │     vulnrichmentStatus: "available" | "partial" |        │
   │                          "unavailable"                  │
   │     vulnrichmentCoverage: { enriched, total }           │
   │     githubAdvisoryStatus: "available" | "partial" |     │
   │                           "unavailable"                 │
   │     githubAdvisoryCoverage: { enriched, total }         │
   └─────────────────────────────────────────────────────────┘
            │                                  ▲
            │ writes                           │ acquires
            ▼                                  │ refresh-lock
   ┌──────────────────────────┐         ┌──────┴──────────────┐
   │   Netlify Blobs store    │         │  refresh-lock blob  │
   │   (name: tpr-dataset)    │◄────────┤  (TTL: 15 min)      │
   │   ┌────────────────────┐ │         └──────▲──────────────┘
   │   │ latest-dataset     │ │                │ acquires
   │   │  (FetchResult)     │ │   ┌────────────┴───────────────┐
   │   └────────────────────┘ │   │                            │
   └──────────────────────────┘   │                            │
            ▲                     │                            │
            │                     ▼                            ▼
   ┌────────┴─────────┐   ┌────────────────────┐   ┌────────────────────┐
   │  Cron scheduled  │   │  Background fn     │   │  Browser manual    │
   │  (every 30 min)  │   │  (manual refresh   │   │  "Refresh live     │
   │  reads + writes  │   │   from dashboard)  │   │   data" button     │
   │  the prebuilt    │   │  reads + writes    │   │  POSTs to the      │
   │  envelope        │   │  the prebuilt      │   │  background fn     │
   └──────────────────┘   │  envelope          │   └────────────────────┘
            │              └────────────────────┘
            │ build                       build
            ▼                              ▼
   ┌──────────────────────────────────────────────────────┐
   │  Shared build pipeline (main envelope):              │
   │    CISA KEV  →  NVD CVE 2.0  →  FIRST EPSS           │
   │                                                      │
   │  • Optional NVD_API_KEY (server-side only) raises    │
   │    NVD's rate-limit allowance from 5 to 50 req / 30s │
   │  • Rate-limited (429) builds are blocked from        │
   │    overwriting a better existing prebuilt blob       │
   │  • 15-min NVD cooldown marker avoids hammering a     │
   │    known-flaky NVD                                   │
   └──────────────────────────────────────────────────────┘
                       │
                       │ after a successful main build, two
                       │ incremental enrichment passes run in
                       │ the same refresh (v5.5 + v5.6):
                       ▼
   ┌──────────────────────────────────────────────────────┐
   │  CISA Vulnrichment enrichment (server-side, post-step):│
   │    • Incremental: only CVEs missing or > 7 d stale   │
   │    • Capped at 50 CVEs per refresh run               │
   │    • Concurrency 5; KEV-newest first                  │
   │    • HTTP 404 → negative-cache marker                 │
   │      (so the same CVE is not re-selected every run)  │
   │    • A 404 never overwrites a positive SSVC record   │
   │    • Public `vulnrichmentStatus` /                   │
   │      `vulnrichmentCoverage` are computed at read-time │
   └──────────────────────────────────────────────────────┘
                       │
                       │ writes
                       ▼
   ┌──────────────────────────┐
   │  Netlify Blobs store     │
   │  (name: tpr-vulnrichment)│   ◄── separate from the main
   │  ┌────────────────────┐  │       dataset blob; the visitor
   │  │ cache              │  │       read path never writes here
   │  │  (SSVC records +   │  │
   │  │   negative-cache   │  │
   │  │   markers)         │  │
   │  └────────────────────┘  │
   └──────────────────────────┘

   ┌──────────────────────────────────────────────────────┐
   │  GitHub Advisory enrichment (server-side, post-step):│
   │    • Endpoint filters by CVE + reviewed advisory type│
   │    • Incremental: only CVEs missing or with a        │
   │      positive record older than 7 d                   │
   │    • Capped at 25 CVEs/run without GITHUB_TOKEN,    │
   │      50 CVEs/run with GITHUB_TOKEN                   │
   │    • Concurrency 4; only reviewed, non-withdrawn     │
   │      advisories; npm-ecosystem package entries only  │
   │    • Empty result → negative-cache marker             │
   │      (so the same CVE is not re-selected every run)  │
   │    • An empty / 404 result never overwrites a        │
   │      positive advisory; provider failures preserve  │
   │      positive cached entries                         │
   │    • Public `githubAdvisoryStatus` /                  │
   │      `githubAdvisoryCoverage` are computed at read-time│
   └──────────────────────────────────────────────────────┘
                       │
                       │ writes
                       ▼
   ┌──────────────────────────┐
   │  Netlify Blobs store     │
   │  (name: tpr-github-      │   ◄── separate from both the main
   │   advisory)              │       dataset blob and the
   │  ┌────────────────────┐  │       Vulnrichment blob; the
   │  │ cache              │  │       visitor read path never
   │  │  (GHSA records +   │  │       writes here
   │  │   negative-cache   │  │
   │  │   markers)         │  │
   │  └────────────────────┘  │
   └──────────────────────────┘
```

**Five properties this architecture guarantees:**

1. **The build runs once on the server**, not per visitor. The prebuilt
   blob is the source of truth for normal traffic; cron + manual
   refresh keep it fresh.
2. **A bad refresh never overwrites a better one.** If NVD rate-limits
   (HTTP 429), the quality guard compares the new build against the
   existing blob and preserves the better envelope.
3. **The browser never blocks on the upstream pipeline.** The first
   visitor after a cold deploy pays the bootstrap cost once; everyone
   after reads the prebuilt blob.
4. **Vulnrichment is incremental, partial, and never pollutes the
   main blob.** SSVC is stored in its own Netlify Blobs store
   (`tpr-vulnrichment`) and merged into the public response at read
   time. The prebuilt `latest-dataset` blob's `fetchedAt` is never
   rewritten by a Vulnrichment update, so the v5.1 "newer dataset
   available" banner can never fire spuriously. Up to 50 missing /
   stale CVEs are enriched per background run; CVEs that return
   HTTP 404 receive a lightweight negative-cache marker so the
   backfill queue keeps moving instead of looping.
5. **Package remediation is incremental, partial, and never
   pollutes the main blob.** Reviewed GitHub Advisories are stored
   in their own Netlify Blobs store (`tpr-github-advisory`) and
   merged into the public response at read time. The prebuilt
   `latest-dataset` blob's `fetchedAt` is never rewritten by a
   GitHub Advisory update, so the v5.1 "newer dataset available"
   banner can never fire spuriously. The endpoint is filtered by
   CVE and by the reviewed advisory type, and only reviewed,
   non-withdrawn advisories are kept. Up to 25 CVEs per run are
   processed without a token (50 with a token) at concurrency 4;
    empty / 404 results are negatively cached, an empty result
    never overwrites a positive advisory, and a null patched
    version is rendered as "First patched version unavailable"
    (never inferred as "No fix exists").

---

## V6.0 — Canonical baseline (private)

V6.0 adds a **canonical baseline**: a content-addressed,
versioned, atomic-publication snapshot of the full
vulnerability / advisory / package / relationship / tombstone
data plane, derived from OSV. The baseline is **private** —
the public V5.7 dashboard above is unchanged. The new
surface is split across THREE Netlify environments:

1. **The public site** (this one) — the OSV ingestion
   pipeline writes the canonical baseline to a new
   `tpr-baseline` Blob store. A thin Scheduled Function
   fires hourly; a Background Function runs the actual
   work.
2. **A private sync gateway** (a separate Netlify site) —
   exposes five authenticated routes at `/private/v1/*`
   that authenticated consumers call to read the baseline.
3. **The consumer** — a reference Node.js client
   ([`client/consumer-client.mjs`](client/consumer-client.mjs))
   and the SQLite/Postgres adapter contract
   ([`client/contracts.md`](client/contracts.md)).

The gateway requires an HMAC-SHA256 credential
(`tpr_<keyId>_<randomSecret>`) issued by the operator.
Visitors cannot trigger refreshes or read the baseline —
the only public surface is the V5.7 dashboard.

What V6.0 is NOT:
- It is NOT a real-time push system. Consumers pull.
- It is NOT a multi-product "shared baseline service".
- It is NOT a public read API.
- It is NOT a STIX 2.1 interop layer.
- It is NOT a per-client quota system (per-credential hard
  quotas are deferred until an atomic counter store
  exists).

V6.0 documentation:
- [`docs/v6-architecture.md`](docs/v6-architecture.md) —
  the read-once architecture summary.
- [`docs/credentials.md`](docs/credentials.md) — how to
  issue, rotate, and revoke credentials.
- [`docs/deployment.md`](docs/deployment.md) — production
  deploy of the public site, the private gateway, and the
  consumer.
- [`docs/ecosystems.md`](docs/ecosystems.md) — the OSV
  ecosystem allowlist and how to change it.
- [`schemas/`](schemas/) — the JSON Schemas for the
  baseline, the manifest, the delta, and the source
  registry.

---

## V6.4 — Local defender workspace (additive)

V6.4 adds a fully-local defender workspace to the dashboard.
A defender can watch CVEs, assign a local triage status and
priority, add local tags, write a private note, and identify
watched CVEs that changed since the last review. Everything
lives on the user's device in IndexedDB (with a session-memory
fallback); nothing is uploaded.

Privacy invariants (proved by `scripts/acceptance-v64-workspace.mjs`):

- No workspace field appears in the public dataset, the
  Netlify function entries, the private gateway payloads,
  the dashboard URL, the public CSV, or any analytics
  endpoint.
- The export filename is static (`threatpulse-workspace.json`).
- The export is deterministic (sorted by `cveId`, fixed
  field order, sha256 checksum).

V6.4 documentation: [`docs/v6-4-local-workspace.md`](docs/v6-4-local-workspace.md).

---

## V6.5 — Local briefings and reports (additive)

V6.5 adds fully-local, defensible report exports generated from
public intelligence + V6.1 change intelligence + V6.4 local
workspace entries. Five report types, five redaction modes,
strict JSON schema with SHA-256 integrity, verification +
comparison + history. All generation, preview, export, verify,
compare, and history live inside the browser. Nothing is
uploaded.

V6.5 documentation: [`docs/v6-5-local-briefings-and-reports.md`](docs/v6-5-local-briefings-and-reports.md).

---

## V6.6 — Local asset, SBOM, and exposure mapping (additive)

V6.6 adds a local-only environment relevance layer. The operator
can register local assets, import supported SBOM / software-inventory
files (CycloneDX 1.4 / 1.5 / 1.6 JSON, SPDX 2.3 JSON, ThreatPulse
inventory JSON, bounded CSV), identify components, correlate with
public OSV + GitHub Advisory package data, distinguish reliable
affected-range matches from ambiguous identity-only matches,
review / dismiss local correlations, filter the public
vulnerability table by local relevance, and view potentially
affected local assets from the CVE detail drawer.

**All asset / SBOM / package / mapping / user-review data is
local browser data. Nothing is uploaded.** The system NEVER
claims a correlation proves exploitability, compromise, or
practical exploitability.

Six correlation states (none mean "this CVE was exploited
against you"):

- `affected-range-match` — range evaluator said the imported
  version falls inside the declared affected range
- `exact-version-match` — the imported version is in the
  provider's `versions[]` list
- `identity-only-potential` — identity matched but no version
  / range was available to evaluate
- `no-supported-match` — identity matched but the imported
  version did NOT fall inside the declared range (NOT
  evidence of safety)
- `version-not-evaluable` — range syntax was unsupported
- `public-data-unavailable` — public intelligence status
  was not `available` when correlation ran

Eight review statuses (`unreviewed`, `confirmed-relevant`,
`dismissed`, `needs-validation`, `remediation-planned`,
`remediation-in-progress`, `remediated` (local workflow
statement only — NOT externally verified), `accepted-risk`).

Three storage adapters (`IndexedDBEnvironmentAdapter` /
`InMemoryEnvironmentAdapter` / `UnavailableEnvironmentAdapter`)
with multi-tab BroadcastChannel sync and atomic inventory
promotion. Worker dispatch (separate `parseInventory.worker`
+ `correlate.worker` chunks) with main-thread synchronous
fallback for older browsers and the test runner.

V6.5 reports gain an OPTIONAL additive `localEnvironmentSummary`
field (counts only — no asset names, paths, owner labels, or
review notes). Default V6.5 reports carry no environment data.

Privacy invariants (proved by `scripts/acceptance-v66-local-environment.mjs`):

- No network call carries asset / SBOM / note / tag / report
  data
- No asset / note / tag / private field enters a URL
- No production console output contains private fields
- No public CSV field is added (`CSV_COLUMNS` still 21)
- No public API envelope is mutated
- No public-intelligence fixture is mutated
- Local-relevance filter state is never serialized to the URL
- Raw SBOM payloads are never retained (only minimal documented
  component fields)
- Prototype-pollution keys are rejected by every validator

V6.6 documentation: [`docs/v6-6-local-environment.md`](docs/v6-6-local-environment.md).

---

## V6.7 — Local remediation plans, evidence, and activity ledger (additive)

V6.7 adds a fully-local remediation workflow layer on top of V6.4
workspace, V6.5 reports, and V6.6 environment. The operator can
create a local plan for a CVE, correlation, asset, or component;
decompose the plan into ordered tasks with local owner labels and
due dates; attach nine kinds of evidence; fingerprint a local
evidence file with a Web Worker that never uploads the bytes; walk
the plan through the documented nine-state lifecycle machine;
record a local validation result; reopen a completed or
accepted-risk plan without silently mutating its history; export
and re-import integrity-checked plan bundles; and inspect a
per-plan append-only hash-chained activity ledger.

All plan, task, evidence, owner, due-date, validation, and
ledger data is local browser data. Nothing is uploaded. The
system never claims a recorded completion is an external
verification, that a matching fingerprint proves authorship or
authenticity, or that the local ledger has any legal or
identity-significance.

V6.5 reports gain an OPTIONAL additive `localRemediationSummary`
field (counts only — no owner labels, plan / task / evidence
content, fingerprints, blocker reasons, validation notes, or
actor labels). Default V6.5 reports carry no remediation data.

Privacy invariants (proved by `scripts/acceptance-v67-local-remediation.mjs`):
- No fetch, XHR, `sendBeacon`, `history.pushState` /
  `replaceState`, or production console output of plan / task /
  evidence / owner / fingerprint / validation / actor content.
- File bytes are never stored; only the SHA-256, file name,
  size, MIME, and optional `lastModified` are recorded.
- No `node:crypto` in any browser-reachable module.
- No `sha256Node` or `fingerprintNode` chunk in the Vite build.
- The `threatpulse-local-remediation` bundle v1.0.0 has a
  SHA-256 integrity checksum, prototype-pollution rejection,
  atomic ledger conflict detection, and a 25 MiB size cap.
- Hash chain detects modified, missing, reordered, and inserted
  events; does **not** prove authorship, identity, timestamp
  authority, or legal authenticity.

V6.7 documentation: [`docs/v6-7-local-remediation-evidence.md`](docs/v6-7-local-remediation-evidence.md).

---

## V6.8 controlled deployment preparation (additive)

A separate `release/v6-8-deployment-preparation` branch
carries the V6.8 release-preparation tooling without
modifying the V6.8 product. The branch adds:

- A machine-readable [`deploy/v6-8-release-manifest.json`](deploy/v6-8-release-manifest.json)
  (names only, no secret values).
- A read-only release preflight
  ([`scripts/verify-v68-release.mjs`](scripts/verify-v68-release.mjs)).
- A local smoke test
  ([`scripts/smoke-v68-local.mjs`](scripts/smoke-v68-local.mjs)).
- A dry-run-by-default production smoke test
  ([`scripts/smoke-v68-production.mjs`](scripts/smoke-v68-production.mjs)).
- A release-preparation acceptance suite
  ([`scripts/acceptance-v68-deployment-preparation.mjs`](scripts/acceptance-v68-deployment-preparation.mjs)).
- A phased deployment runbook
  ([`docs/v6-8-controlled-deployment-runbook.md`](docs/v6-8-controlled-deployment-runbook.md)).
- A rollback plan
  ([`docs/v6-8-rollback-plan.md`](docs/v6-8-rollback-plan.md)).
- A production observation plan
  ([`docs/v6-8-production-observation-plan.md`](docs/v6-8-production-observation-plan.md)).
- An environment-variable checklist (names only)
  ([`docs/v6-8-environment-checklist.md`](docs/v6-8-environment-checklist.md)).
- A deployment-cost controls document
  ([`docs/v6-8-deployment-cost-controls.md`](docs/v6-8-deployment-cost-controls.md)).

The preparation branch is honest about what it is. The
release is **not** enterprise-certified, legally
admissible, complete, or independently audited. **The
preparation tooling does not perform any deployment,
merge, credential, environment-variable, DNS, or
paid-service change.** Every action gated by the runbook
requires explicit operator authorization in the
Netlify UI.

**Preparation-branch commit history (5 commits on top
of the V6.8 RC `0480a9f`):** the three planned
logical commits (`6531ada` manifest + preflight +
smokes, `0698d12` runbooks, `5dda6f7` acceptance
suite + docs) plus two bounded verification
corrections (`43ea1ca` loosen the V6.8
release-candidate suite count to `>= 36` for
forward-compat, `557023f` allow the V6.8
release-candidate acceptance suite in the
deployment-preparation branch's product-source
diff). The V6.8 release-candidate baseline carried
36 acceptance suites; the deployment-preparation
branch carries 37 (the V6.8 deployment-preparation
acceptance suite).

## Hostinger managed scheduler ENOENT hotfix (additive)

A separate `hostinger/v6-8-managed-scheduler-execpath`
branch fixes a deployment-time ENOENT observed on
the Hostinger Business managed-Node temporary
deployment. Every scheduled child process is now
spawned with `process.execPath` (the absolute path
of the currently running Node executable) instead
of the bare string `node`. The bare string failed
because the managed-Node runtime's PATH is not
propagated to `child_process.spawn`; the absolute
path of the running executable is always present.
The fix preserves every V6.6+ invariant:
no shell is used, no provider/storage/canonicalization
logic is duplicated, no public HTTP route is added,
no third-party scheduler is introduced, and the
existing standalone `hostinger/cron-*.mjs` entrypoints
remain importable. The total acceptance suite count
remains 37.

## Hostinger filesystem intelligence-store parity (additive)

A separate `hostinger/v6-8-filesystem-intelligence-stores`
branch fixes three observed deployment findings on
the Hostinger Business managed-Node deployment:

  1. `lastVulnrichmentRefresh.status = failed`
     ("Failed to write Vulnrichment cache blob.")
  2. `lastGitHubAdvisoryRefresh.status = failed`
     ("Failed to write GitHub Advisory cache blob.")
  3. `lastV61DatasetBoundRefresh.status = skipped`
     ("public-intelligence-store-unavailable")

All three had the same root cause: the four
`get*Store` helpers hardcoded the `'netlify'`
adapter, so every cache write and every
public-intelligence read returned an unusable handle
on a Hostinger runtime that has no Netlify Blobs
context. The fix routes the four helpers through
`THREATPULSE_STORAGE_BACKEND` exactly the same way
`server/config.mjs` and `jobs/_lib.mjs#resolveStorage`
already do. The Netlify path is preserved unchanged
for backward compatibility.

When the backend is `'filesystem'`, every Blob
namespace lives under the same
`$THREATPULSE_DATA_ROOT`:

- `tpr-dataset/` — primary dataset envelope
- `tpr-vulnrichment/` — CISA Vulnrichment / SSVC cache
- `tpr-github-advisory/` — GitHub Advisory cache
- `tpr-public-intelligence/` — V6.1 public-intelligence
  OSV + dataset versioned artifacts, `latest.json`
  pointers, publication locks, change-summaries

Every filesystem write uses a temp file + rename
(atomic, last-known-good preserved on failure). The
V6.1 size budgets and the NVD 429 partial-enrichment
behavior are preserved unchanged. The total
acceptance suite count remains 37.

## Hostinger Business managed-Node scheduler (additive)

A separate `hostinger/v6-8-managed-scheduler`
branch adds an opt-in in-process scheduler for
Hostinger Business managed-Node deployments that
do not expose an OS-level cron. The scheduler is
disabled by default and reuses the existing
`hostinger/cron-*.mjs` job implementations and the
existing `hostinger/locks.mjs` mkdir-based locks.
No provider, storage, publication, or
canonicalization logic is duplicated; the standalone
cron entrypoints remain available for VPS
deployments.

- Enable with `THREATPULSE_MANAGED_SCHEDULER=1`
  (literal value; any other value keeps the
  scheduler disabled).
- Optional one-shot bootstrap on a missing dataset
  with `THREATPULSE_MANAGED_SCHEDULER_BOOTSTRAP=1`.
- Schedules (UTC): dataset refresh on minute 0 and
  30, baseline refresh at :10, dataset publish at
  :20 and :50, public-intel GC at :25, state
  verify at 06:30 daily, backup at 02:40 daily.
- The scheduler adds no public HTTP trigger route.
  A process restart is safe; the scheduler starts
  again from the next calculated UTC occurrence,
  the bootstrap is retried when the dataset is
  missing, and the existing locks prevent
  duplicate active jobs.
- The total acceptance suite count remains 37 —
  the existing `scripts/acceptance-v63-hostinger.mjs`
  is extended with 77 new tests for the managed
  scheduler.

The exact variable names are listed in
[`docs/v6-8-environment-checklist.md`](docs/v6-8-environment-checklist.md).
No values are documented; only the variable names.

## V6.8 — Release candidate consolidation (additive)

V6.8 is a release-candidate consolidation milestone. It
contains the complete V6.1–V6.8 product and focuses on
stabilizing, measuring, lazy-loading, and documenting the
existing surfaces rather than introducing a new major
subsystem.

**This release is honest about what it is and what it
is not. It is a single controlled release of a defensive
cybersecurity intelligence product. It is NOT
enterprise-certified, legally admissible, complete, or
independently audited.**

What V6.8 adds on top of V6.7:

- A sanitized **release diagnostics** helper that
  reports storage availability, schema versions,
  record counts, and pending-write state — without
  ever including private content.
- A reusable **`ErrorBoundary`** wrapping every
  major local surface (workspace, reports,
  environment, remediation, local data centre) so
  a failure on one surface cannot crash the public
  dashboard.
- A consolidated **Local Data Control Centre** that
  summarizes every local dataset and exposes
  per-dataset export and clear actions. Each
  destructive action is gated by an accessible
  confirmation dialog; datasets are independent.
- A compact **first-run guide** with a dismissable
  surface that explains the local-only storage
  boundary and the first useful action.
- **Lazy-loaded** report / environment / remediation
  panels; the V6.8 main bundle is measurably
  smaller than the V6.7 main bundle.
- An end-to-end **release-candidate acceptance
  suite** (`scripts/acceptance-v68-release-candidate.mjs`)
  covering the five documented journeys, local data
  separation, migration + recovery, privacy
  instrumentation, and structural invariants.

V6.8 documentation: [`docs/v6-8-release-candidate.md`](docs/v6-8-release-candidate.md).

---
## Reliability & honesty

The codebase's stance: **failures are visible, never hidden.**

### Source labels in the header

Every response is tagged with the actual transport and providers that
contributed:

- **Source:** `CISA KEV + NVD + FIRST EPSS` — all three providers
  contributed data
- **Source:** `CISA KEV + FIRST EPSS` — NVD unavailable, dashboard
  still works (CVSS falls back to CISA-derived severity)
- **Source:** `CISA KEV` — NVD and EPSS both unavailable
- **Proxy:** `Netlify` (cyan pill) — data came from the serverless
  endpoint, not browser-direct
- **Dataset store:** `latest available` / `bootstrapping` /
  `refresh running in background` — visible state of the prebuilt
  blob + refresh lock

Vulnrichment is intentionally **not** surfaced as a separate
header pill. The two public dataset metadata fields
(`vulnrichmentStatus: "available" | "partial" | "unavailable"`
and `vulnrichmentCoverage: { enriched, total }`) are computed
at read time and shipped in the function response body, but
there is no badge in the current header for them — a defender
who wants the current coverage value can read it from
DevTools → Network → the `/.netlify/functions/dataset`
response. The SSVC decision context itself is shown only in
the vulnerability details drawer (see the section above).

### Per-provider status pills

`NVD` and `EPSS` each have their own status pill that turns amber with a
human-readable reason when that specific provider fails. A 429 surfaces
as `NVD: unavailable — rate limit reached (HTTP 429)`. A network
timeout surfaces as `EPSS: unavailable — request timed out`. The
remaining providers' data still renders; the failure is announced, not
swallowed.

### No fabricated scores

A CISA record whose CVE is not yet in NVD keeps `cvssScore: 0` and the
CISA-derived severity (KEV records default to `High`; ransomware-known
records to `Critical`). A CISA record whose CVE is not scored by FIRST
keeps `epssProbability: 0`. **The dashboard never invents enrichment
data** — when a provider fails, the field is zero and a banner explains
why.

### NVD rate-limit guard

If NVD returns HTTP 429 (its anonymous endpoint allows only 5 req / 30s):

- The orchestrator detects the rate-limit reason
- It compares the new build against the existing prebuilt blob
- If the existing blob is better (more CVSS-positive records, NVD
  enriched), the new build is **discarded** and the existing blob
  continues to serve visitors
- A 15-minute cooldown marker is set so the next refresh
  short-circuits the doomed NVD fetch
- When the cooldown expires, normal refresh behavior resumes

### CISA Vulnrichment / SSVC reliability

The Vulnrichment enrichment is incremental, partial, and isolated
from the main dataset blob:

- **Separate Netlify Blobs store.** SSVC records live in their own
  store (`tpr-vulnrichment`, key `cache`). The visitor's read path
  merges them into records at serve time and never writes to this
  store. The prebuilt `latest-dataset` blob's `fetchedAt` is never
  rewritten by a Vulnrichment update, so the v5.1 "newer dataset
  available" banner can never fire spuriously.
- **Incremental and capped.** Each refresh selects at most 50
  CVEs that are missing from the cache or older than the 7-day
  staleness window, runs at concurrency 5, and sorts by KEV
  `dateAdded` descending so the most-recently-added KEV entries
  are enriched first. The full dataset is never refetched in a
  single cycle.
- **HTTP 404 is "no assessment", not a failure.** When the
  upstream repository has no record for a CVE (HTTP 404), the
  refresh writes a lightweight negative-cache marker
  (`{ ssvc: null, status: "missing", cachedAt, checkedAt }`)
  instead of re-fetching the same CVE on every cycle. A stale
  negative entry (older than the 7-day window) is re-selected
  so a newly published CISA assessment eventually replaces it.
- **A 404 never overwrites a positive record.** If the cache
  already holds a positive SSVC record for a CVE, a later 404
  leaves the positive record untouched — losing real data on a
  transient upstream inconsistency is worse than keeping a
  possibly-stale one.
- **`vulnrichmentCoverage.enriched` counts only positive SSVC
  records.** The 404 markers are not counted as enriched; the
  public envelope's `available` / `partial` / `unavailable`
  status is derived from the honest `{ enriched, total }` ratio
  and never claims `available` while backfill is still incomplete.
- **No internal metadata reaches the visitor.** The
  per-cycle operator fields (`lastVulnrichmentRefresh`,
  `lastRefreshFailure`, `lastRefreshAttemptAt`) are written to
  the prebuilt blob for operators to inspect, but they are
  stripped from the public response before the dataset endpoint
  returns. The frontend bundle never references the
  `raw.githubusercontent.com` upstream — the browser has no
  way to call Vulnrichment directly, and a malicious visitor
  cannot reconstruct a 404 reason or transient failure from
  the response body.

### GitHub Advisory reliability

The GitHub Advisory enrichment is incremental, partial, and isolated
from both the main dataset blob and the Vulnrichment blob:

- **Separate Netlify Blobs store.** Reviewed advisory records live
  in their own store (`tpr-github-advisory`, key `cache`). The
  visitor's read path merges them into records at serve time and
  never writes to this store. The prebuilt `latest-dataset`
  blob's `fetchedAt` is never rewritten by a GitHub Advisory
  update, so the v5.1 "newer dataset available" banner can
  never fire spuriously.
- **Endpoint filtered by CVE and reviewed advisory type.** The
  request filters for reviewed, non-withdrawn advisories that
  match the target CVE. Only reviewed entries that survive the
  filter are stored. Withdrawn and unreviewed entries are
  intentionally dropped, not surfaced with a partial
  provenance disclaimer — the dashboard never claims a
  "review" it cannot verify.
- **Incremental and capped.** Each refresh selects at most 25
  CVEs that are missing from the cache or whose positive
  advisory record is older than the 7-day staleness window.
  The cap doubles to 50 CVEs per run when the optional
  `GITHUB_TOKEN` is set server-side. Requests run at
  concurrency 4; the full dataset is never refetched in a
  single cycle.
- **Empty result is "no reviewed advisory", not a failure.**
  When the upstream returns no reviewed advisory for a CVE
  (empty result), the refresh writes a lightweight
  negative-cache marker (`{ advisory: null, status: "missing",
  cachedAt, checkedAt }`) instead of re-fetching the same
  CVE on every cycle. A stale negative entry (older than the
  7-day window) is re-selected so a newly reviewed advisory
  eventually replaces it.
- **An empty / 404 result never overwrites a positive
  record.** If the cache already holds a positive advisory
  for a CVE, a later empty or 404 response leaves the
  positive record untouched — losing real data on a
  transient upstream inconsistency is worse than keeping a
  possibly-stale one. Provider failures (5xx, network errors,
  rate-limit responses) also preserve the positive cached
  entry; the failure is recorded in the internal operator
  envelope but never surfaces in the public response.
- **`githubAdvisoryCoverage.enriched` counts only positive
  records.** The empty / 404 markers are not counted as
  enriched; the public envelope's `available` / `partial` /
  `unavailable` status is derived from the honest
  `{ enriched, total }` ratio and never claims `available`
  while backfill is still incomplete.
- **Null patched version means "unavailable", not "no fix".**
  When a reviewed advisory does not list a patched version
  (e.g. the upstream record omits the field, or the package
  is unmaintained), the drawer renders the field as
  **"First patched version unavailable"**. The dashboard
  never infers a missing patched version as
  **"No fix exists"** — that would be a fabricated claim
  that a defender could act on.
- **No internal metadata reaches the visitor.** The
  negative-cache markers, raw rate-limit headers
  (`x-ratelimit-*`, `Retry-After`), raw provider error
  bodies, cache keys, and stack traces all stay internal.
  The optional `GITHUB_TOKEN` is read from `process.env`
  inside the Netlify Function only, passed as an
  `Authorization: Bearer <token>` header, and **never**
  appears in the function response body, in any URL, in
  any log, or in the frontend bundle. The
  `githubAdvisoryStatus` /
  `githubAdvisoryCoverage` fields are the only public
  surface; the frontend bundle never references the
  `api.github.com` upstream directly — the browser has
  no way to call the GitHub Advisory API itself, and a
  malicious visitor cannot reconstruct a token, a
  rate-limit value, or a transient provider error from
  the response body.

### Manual refresh never blocks the user

Clicking "Refresh live data" POSTs to a Netlify Background Function
that returns `202 Accepted` immediately. The current dataset stays on
screen. When the new blob is ready, the v5.1 polling effect detects it
and surfaces a "New dataset available. Updated 2 min ago." banner with
explicit **Apply update** / × controls — filters, search, sort, and the
open detail view are preserved across the apply.

### API keys stay server-side

The optional `NVD_API_KEY` is read from `process.env` inside the
Netlify Function only, passed to NVD as a request header
(`apiKey: <key>`), and **never** appears in the function response body,
in any URL, in any log, or in the frontend bundle. The key is optional
— the dashboard works identically without it (just slower for the
first visitor in a region per 15 min; repeat visitors ride the CDN
cache).

The optional `GITHUB_TOKEN` follows the same contract: it is read
from `process.env` inside the Netlify Function only, passed to the
GitHub Advisory API as an `Authorization: Bearer <token>` header,
and **never** appears in the function response body, in any URL,
in any log, or in the frontend bundle. Setting it raises the
incremental-enrichment cap from 25 to 50 CVEs per background run
and tightens the upstream rate-limit allowance; the dashboard
works identically without it (slower incremental backfill,
repeat visitors ride the CDN cache for the main envelope either
way).

### No mock fallback in the prebuilt store

The prebuilt `latest-dataset` blob is written **only** by a successful
live build. Mock data never replaces real upstream data. The dashboard
ships a 60-record curated mock dataset for offline development and as a
last-resort browser fallback when *every* transport path fails; it is
never silently mixed into live results, and the header pill turns amber
the moment it is in use.

---

## Tech stack

| Layer | Choice |
| --- | --- |
| Framework | [React 18](https://react.dev) |
| Build tool | [Vite 5](https://vitejs.dev) |
| Language | TypeScript (strict) |
| Styling | [Tailwind CSS 3](https://tailwindcss.com) |
| Charts | [Recharts 2](https://recharts.org) |
| Icons | [Lucide React](https://lucide.dev) |
| Backend | [Netlify Functions](https://docs.netlify.com/build/functions/overview/) (Node 20 ESM) |
| Storage | [Netlify Blobs](https://docs.netlify.com/build/data-and-storage/netlify-blobs/) |

No login. No database. No payments. No exploit code. No offensive
features. The Netlify Function is read-only and idempotent; the Blobs
store is a managed key/value store used as a prebuilt-envelope cache.

---

## Project structure

```
threatpulse-radar/
├── index.html
├── netlify.toml                       # Netlify build + functions + cron
├── package.json
├── tailwind.config.js
├── postcss.config.js
├── tsconfig.json
├── tsconfig.app.json
├── tsconfig.node.json
├── vite.config.ts
├── public/
│   ├── .htaccess                     # SPA fallback, cache, security headers
│   └── radar.svg
├── netlify/
│   └── functions/
│       ├── dataset.mjs               # read endpoint (blob-first, else bootstrap)
│       ├── refresh-dataset-background.mjs   # manual refresh (BG fn, 15-min timeout)
│       ├── refresh-dataset-scheduled.mjs    # cron refresh (every 30 min)
│       └── _shared/
│           ├── store.mjs             # Netlify Blobs + lock + cooldown helpers
│           ├── refresh.mjs           # lock + write orchestrator + quality guard
│           ├── liveBuild.mjs         # shared CISA → NVD → EPSS pipeline
│           ├── vulnrichment.mjs      # CISA Vulnrichment path / parser / coverage (v5.5)
│           ├── vulnrichmentRefresh.mjs # CISA Vulnrichment incremental orchestrator (v5.5)
│           ├── githubAdvisory.mjs    # GitHub Advisory path / parser / coverage (v5.6)
│           └── githubAdvisoryRefresh.mjs # GitHub Advisory incremental orchestrator (v5.6)
└── src/
    ├── main.tsx                       # entry
    ├── App.tsx                        # thin shell
    ├── index.css                      # Tailwind + global polish
    ├── vite-env.d.ts                  # import.meta.env typing
    ├── components/                    # presentational + container pieces
    │   ├── Header.tsx                 # + source / provider / cache pills
    │   ├── StatsCards.tsx
    │   ├── FiltersPanel.tsx
    │   ├── VulnerabilityTable.tsx
    │   ├── DetailDrawer.tsx
    │   ├── EmptyState.tsx
    │   ├── LoadingState.tsx
    │   ├── ErrorState.tsx
    │   ├── SearchStatus.tsx
    │   ├── CachedDataBanner.tsx       # v4 cache banner + refresh button
    │   ├── UpdateAvailableBanner.tsx  # v5.1 "New dataset available" banner
    │   ├── RefreshInProgressBanner.tsx # v5.2 background-refresh indicator
    │   ├── NvdUnavailableBanner.tsx
    │   ├── EpssUnavailableBanner.tsx
    │   ├── FallbackBanner.tsx
    │   └── charts/
    │       ├── SeverityChart.tsx
    │       ├── TrendChart.tsx
    │       └── KevChart.tsx
    ├── data/
    │   └── mockVulnerabilities.ts     # 60 fictional CVEs (offline fallback)
    ├── pages/
    │   └── DashboardPage.tsx          # single-screen dashboard
    ├── services/
    │   ├── vulnerabilityService.ts    # proxy-first orchestration
    │   ├── datasetCache.ts            # 1-hour localStorage cache layer
    │   └── providers/
    │       ├── cisaKev.ts             # CISA KEV fetch + normalize
    │       ├── epss.ts                # FIRST EPSS batched fetch + enrich
    │       └── nvd.ts                 # NVD CVE 2.0 batched fetch + enrich
    ├── types/
    │   └── vulnerability.ts           # shared domain types
    ├── hooks/
    │   ├── useDebouncedValue.ts
    │   └── useVulnerabilityFilter.ts
    └── utils/
        ├── analytics.ts               # filter, sort, aggregate
        ├── format.ts                  # date / score formatters
        └── severity.ts                # color + ordering helpers
```

---

## Run it locally

Prerequisites: **Node.js 18+** (tested on Node 24). For the Netlify
Function proxy: **Netlify CLI** (`npm i -g netlify-cli`).

```bash
# 1. Install dependencies
npm install

# 2a. Plain Vite dev server (no Netlify Function).
#     The dashboard works, but the proxy endpoint will 404.
#     The client transparently falls back to browser-direct
#     fetches (proxyStatus === 'browser-direct').
npm run dev
# -> http://localhost:5173

# 2b. Netlify dev (Vite + Netlify Functions together).
#     Use this to test the v5.2 prebuilt-store path end-to-end.
npx netlify dev
# -> http://localhost:8888

# 3. Production build (type-check + bundle)
npm run build

# 4. Preview the production build
npm run preview
```

> `npm run build` runs `tsc -b && vite build` and fails on any type
> error.

The full deployment guide (Netlify configuration, env vars, scheduled
functions, custom domain, troubleshooting) lives in
[`DEPLOYMENT.md`](./DEPLOYMENT.md).

---

## Portfolio notes

**Built by [Naman Parikh](https://github.com/namanparikh11).**

This is a **defensive** vulnerability-intelligence project, built as
both a real triage tool and a public-facing portfolio piece for
security / frontend engineering interviews. The engineering decisions
in it are the artifact — not the feature list.

What I would point to in a review:

- **Per-provider status side-channels.** CISA, NVD, FIRST, CISA
  Vulnrichment, and the GitHub Advisory Database are five
  independent services with five independent failure modes. The
  `FetchResult` shape has separate `nvdStatus`, `epssStatus`,
  `vulnrichmentStatus` + `vulnrichmentCoverage`, and
  `githubAdvisoryStatus` + `githubAdvisoryCoverage` fields so
  partial outages degrade honestly instead of misrepresenting the
  data.
- **Prebuilt blob + quality guard.** A shared `latest-dataset`
  Netlify Blobs entry decouples the upstream pipeline from per-request
  latency. The orchestrator refuses to overwrite a better envelope
  with a rate-limited downgrade — a real-world reliability bug
  (NVD HTTP 429 silently worsening the cached data) that most
  tutorials skip.
- **Incremental, partial enrichment with negative caching.** The
  v5.5 CISA Vulnrichment and v5.6 GitHub Advisory passes are
  separate post-steps that each enrich only the CVEs that are
  missing from the cache or older than the staleness window.
  Vulnrichment is capped at 50 missing/stale CVEs per
  background run; the GitHub Advisory pass is capped at 25
  CVEs per run without a token, 50 with a token. HTTP 404 and
  empty results are written as lightweight negative-cache
  markers so the backfill queue keeps moving instead of looping
  over the same CVEs every cycle. Coverage is reported honestly
  as `{ enriched, total }` — the dashboard never claims
  `available` while backfill is still incomplete.
- **No API keys in the frontend bundle.** `NVD_API_KEY` is read from
  `process.env` inside the Netlify Function only, passed as a request
  header, never exposed. The app works identically without it.
- **Transparent freshness.** "Last refresh" reflects when the
  function actually ran, not when the CDN served the response. The
  "Refresh live data" button uses a `?t=<timestamp>` cache-buster so
  its name stays honest.
- **Explicit user consent on soft refresh.** The v5.1 polling
  surfaces newer upstream data behind an Apply-update banner; filters
  and the open detail view are preserved. The user is never disturbed
  mid-task.

The codebase is intentionally small, strict-mode TypeScript end-to-end,
and lives under a defensive-only license. See
[`PORTFOLIO_WRITEUP.md`](./PORTFOLIO_WRITEUP.md) for the longer
narrative.

---

## License & use

This project is for **defensive security work only**. Do not use any
information surfaced here to develop, distribute, or execute offensive
tooling. The mock CVEs in `src/data/mockVulnerabilities.ts` are
fictional and provided for visualization purposes; always refer to
upstream advisories before taking action.

The NVD, CISA KEV, CISA Vulnrichment, GitHub Advisory Database, and
FIRST EPSS feeds are public services operated by their respective
organizations. ThreatPulse Radar is not affiliated with NIST, CISA,
GitHub, or FIRST.

---

_Made with care by your friendly neighborhood defensive security
dashboard._