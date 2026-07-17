# V6.6 — Local Asset, SBOM, and Exposure Mapping

Local-only environment relevance layer. The operator can register local
assets, import supported SBOM / software-inventory files, identify
components, correlate with public OSV + GitHub Advisory package data,
distinguish reliable affected-range matches from ambiguous
identity-only matches, review / dismiss local correlations, filter the
public vulnerability table by local relevance, and view potentially
affected local assets from the CVE detail drawer.

**All asset / SBOM / package / mapping / user-review data is local
browser data.** Nothing is uploaded. The system NEVER claims a
correlation proves exploitability, compromise, or practical
exploitability.

## What it is

A correlation is a single deterministic record that says "we matched
this locally-imported component (by identity) against this public CVE
(by package identity), and the match came back in this state." The
state is one of six, and none of them mean "this CVE was exploited
against you."

## Six correlation states

| State | Meaning | What it tells the operator |
| --- | --- | --- |
| `affected-range-match` | The provider's range evaluator said the imported version falls inside the declared affected range | The closest match. Still needs human review. |
| `exact-version-match` | The imported version is in the provider's `versions[]` list | Concrete package-version match. Still needs human review. |
| `identity-only-potential` | The package identity matched (purl / ecosystem + name) but no version or range was available to evaluate | Operator must read the CVE page and decide |
| `no-supported-match` | Identity matched but the imported version did NOT fall inside the declared affected range | NOT evidence of safety. The package is on the provider's list; this version is not in the declared range. |
| `version-not-evaluable` | Identity matched but the range syntax was unsupported (PyPI / Maven / Go / NuGet default to exact-only) | Operator must read the CVE page; correlation engine will never invent a match |
| `public-data-unavailable` | The public intelligence status was not `available` when correlation ran | Try again after a refresh. Not a safety claim. |

`no-supported-match` is explicitly NOT treated as "this version is
safe." The package is in the provider's affected-package list; the
imported version simply did not fall inside the declared affected
range. The operator can review / dismiss the correlation but must
never interpret absence as remediation.

## Eight review statuses

| Status | Meaning |
| --- | --- |
| `unreviewed` | Initial state; appears in the correlation queue |
| `confirmed-relevant` | Operator agrees this correlation is relevant; tracking continues |
| `dismissed` | Operator marks this correlation as not relevant; tracking continues (provider evidence is preserved) |
| `needs-validation` | Operator wants a second pair of eyes |
| `remediation-planned` | A patch / upgrade is planned |
| `remediation-in-progress` | The patch / upgrade is being rolled out |
| `remediated` | Local workflow statement only; NOT externally verified |
| `accepted-risk` | Operator has decided to accept the risk |

`remediated` is a local workflow statement. It is NOT a claim that
the patch was applied, NOT a claim that the underlying CVE was
resolved, and NOT independently verified.

## Supported import formats

| Format | Versions | Notes |
| --- | --- | --- |
| CycloneDX JSON | 1.4, 1.5, 1.6 | `bomFormat === 'CycloneDX'`, `specVersion` validated |
| SPDX JSON | 2.3 | `spdxVersion === 'SPDX-2.3'`, packages extracted via `externalRefs[].purl` |
| ThreatPulse inventory JSON | 1.0.0 | Native format; round-trips through export/import |
| CSV (bounded) | n/a | Required columns `asset_name,component_name,component_version`; optional `ecosystem,package_url,cpe,supplier,component_type,source_path` |

Unsupported versions are rejected with explicit reasons
(`unsupported-cyclonedx-version`, `unsupported-spdx-version`).

The raw SBOM payload is NEVER retained. Only the minimal documented
component fields are kept (see "Retained component fields" below).

## Retained component fields

For every imported component, only the following fields are kept:

| Field | Notes |
| --- | --- |
| `componentId` | Deterministic FNV-1a hash of the normalized identity |
| `assetId` | Owning asset |
| `inventoryId` | Owning inventory snapshot |
| `name` | Component name |
| `version` | Component version (null is allowed) |
| `ecosystem` | Normalized (e.g. `crates.io` → `crates`) |
| `namespace` | Purl namespace (e.g. Maven group) |
| `packageUrl` | Purl (without qualifiers / subpath for matching) |
| `cpe` | CPE (preserved but never used as primary correlation key) |
| `supplier` | Bounded string |
| `componentType` | Bounded enum |
| `hashes` | Component hashes (bounded) |
| `sourcePath` | Optional import path |
| `normalizedIdentity` | The identity used for matching (source: `purl` / `explicit` / `name-only`) |
| `createdAt` | ISO timestamp |

The raw SBOM payload, the CycloneDX `metadata.tools[]`, the SPDX
`annotations`, and every other undocumented field is dropped at parse
time and never stored.

## Import limits

- `MAX_IMPORT_BYTES = 25 MiB` per file
- `MAX_COMPONENTS_PER_IMPORT = 50,000` per file
- `WARNING_COMPONENT_COUNT = 10,000` per file (soft warning, not a hard cap)
- `MAX_ASSETS = 5,000` per browser
- `MAX_ASSET_TAGS = 20` per asset
- `MAX_TAG_CHARS = 40` per tag
- `MAX_ASSET_NAME_CHARS = 150`
- `MAX_ASSET_DESCRIPTION_CHARS = 2,000`
- `MAX_OWNER_LABEL_CHARS = 120`
- `MAX_INVENTORY_SNAPSHOTS_PER_ASSET = 5`
- `MAX_CORRELATION_REVIEWS = 100,000`
- `MAX_REVIEW_NOTE_CHARS = 8,000`
- `MAX_COMPONENT_NAME_CHARS = 250`
- `MAX_COMPONENT_VERSION_CHARS = 200`
- `MAX_COMPONENT_PATH_CHARS = 500`
- `MAX_HASH_CHARS = 200`
- `MAX_SUPPLIER_CHARS = 200`

All fields are length-bounded. Non-finite numbers are rejected.
Prototype-pollution keys (`__proto__` / `prototype` / `constructor`)
are rejected by every validator.

## Normalization precedence

`normalizeIdentity(input)` returns the strongest available source:

1. **`purl`** — `parsePurl(input.purl)` returns a typed record
2. **`explicit`** — `ecosystem + namespace + name` provided
3. **`name-only`** — only `name` provided (weakest; cannot resolve
   cross-ecosystem collisions)

`normalizeEcosystem(name)` maps ecosystem aliases:

| Input | Normalized |
| --- | --- |
| `npm` | `npm` |
| `pypi`, `pip` | `pypi` |
| `cargo`, `crates.io` | `crates` |
| `gem`, `rubygems` | `rubygems` |
| `composer`, `packagist` | `packagist` |
| `golang`, `go` | `go` |
| `nuget` | `nuget` |
| `crates` (bare) | **NOT mapped** — must use `cargo` or `crates.io` |

Both sides of a correlation run through the same
`normalizeMatchEcosystem` so `'crates.io'` / `'cargo'` / `'crates'` all
collapse to `'crates'` regardless of which side the operator wrote.

The same provider-side normalization is applied to GHSA ecosystems
(`'rust' / 'cargo' / 'crates.io' / 'crates' → crates`).

## Version evaluator registry

| Ecosystem | Evaluator | Notes |
| --- | --- | --- |
| `npm` | `evaluateNpm` | semver-style ranges: `=`, `>=`, `<=`, `>`, `<`, `^`, `~`, `1.x`, `*` |
| `crates`, `cargo` | `evaluateCrates` | Same syntax as npm; cargo uses comma-AND |
| `packagist`, `composer` | `evaluatePackagist` | Same syntax; `^1.0` is `[1.0.0, 2.0.0)` |
| any other (default) | `evaluateGenericExact` | Exact version equality only |

PyPI, Maven, Go modules, NuGet, and other ecosystems fall through to
the default exact-only evaluator. They NEVER auto-apply npm semver.

Pre-release handling: a pre-release version is "less than" the
corresponding release per the semver spec. So `1.0.0-alpha` does NOT
satisfy `>=1.0.0`. The version is older than the bound.

Compound ranges (e.g. `>=1.0.0, <5.6.1`) use AND semantics — every
sub-expression must hit. A single sub-expression miss returns
`no-supported-match`. An unsupported sub-expression returns
`version-not-evaluable`.

## Provider merge semantics

When OSV and GitHub Advisory both produce a result for the same
`(component, CVE)`, `mergeBest` joins them. The result's
`providerSources` field lists the distinct provider names as an
array, so `providerSources.includes('OSV')` and
`providerSources.includes('GitHub Advisory Database')` are independent
checks. The legacy `provider` string field is kept for single-provider
paths.

## Inventory change detection

`diffInventories(prev, next)` classifies every component identity into
one of four buckets:

- **added** — in `next` but not in `prev`
- **removed** — in `prev` but not in `next`
- **versionChanged** — identity present in both, version differs
- **unchanged** — identity present in both, version identical

A component is identified by its normalized identity
(`ecosystem + namespace + name`) so the detector is robust against
re-imports that shuffle the raw `componentId` values.

The summary explicitly says **"No longer present in the latest
imported inventory"** for removed components. Absence is NEVER
interpreted as remediation.

## Storage adapters

| Adapter | Status | Notes |
| --- | --- | --- |
| `IndexedDBEnvironmentAdapter` | `persistent` | DB `threatpulse-environment` v1, 5 stores: `assets` / `inventories` / `components` / `correlations` / `reviews` / `meta`. BroadcastChannel `threatpulse:environment:events` for multi-tab sync. `onversionchange` handler. |
| `InMemoryEnvironmentAdapter` | `session-only` | Test runner + documented "session-only" fallback. Surfaced prominently in the UI so the operator does not lose work to a refresh. |
| `UnavailableEnvironmentAdapter` | `unavailable` | No-op. Every op returns `{ ok: false, reason: 'unavailable' }`. The UI surfaces a prominent warning. |

`EnvironmentProvider` reports status as one of
`'initializing' | 'persistent' | 'session-only' | 'unavailable' | 'error'`
and exposes `flushPendingWrites` / `hasPendingWrites` so the report
builder can guarantee all local writes land before the snapshot is
captured.

Atomic inventory promotion: `applyInventory` wipes the previous
components for the asset + writes the new inventory + writes the new
components + updates the asset's `latestInventoryId` in a single
read-write transaction. A failure rolls everything back, preserving
the previous inventory + correlation set.

## Export / import / backup

The export payload format is
`threatpulse-local-environment` v1.0.0:

```ts
{
  format: 'threatpulse-local-environment',
  schemaVersion: '1.0.0',
  exportedAt: <ISO>,
  applicationVersion: <string>,
  assets: [...],
  inventories: [...],
  components: [...],
  correlationReviews: [...],
  integrity: { canonicalizationVersion: '1.0.0', checksum: 'sha256:<64 hex>' }
}
```

The checksum is `sha256:` + 64 lowercase hex digits over the
canonical JSON of the payload with the integrity block stripped. The
canonical form is deterministic: sorted keys at every depth, no
whitespace, no `undefined`, throws on non-finite numbers and circular
references.

Import modes:

| Mode | Behavior |
| --- | --- |
| `merge` | Existing records stay; imported records override local copies on `assetId` / `inventoryId` / `componentId` / `correlationId` collision |
| `replace` | `clearAll()` first, then import. Failure of any step leaves the previous state intact. |

A failed integrity check refuses the import. A failed
`validateImportPayload` (prototype pollution, future schema, wrong
format, oversized payload, per-record validation failure) refuses
the import. Atomic rollback on any write failure.

The export NEVER includes credentials, browser / device identifiers,
or analytics ids. The operator-supplied fields (asset name, owner
label, component name, local note) are intentionally included so
the backup is restorable.

The export filename convention is
`threatpulse-environment-{shortId}-{YYYY-MM-DD}.json`. Filenames
never contain private notes, tags, or owner labels.

## Report integration boundary

The V6.5 `ReportSnapshot` schema gained one OPTIONAL additive field
in V6.6:

```ts
{
  ...existing V6.5 fields...,
  localEnvironmentSummary?: {
    relatedAssetCount: <integer>,
    relatedComponentCount: <integer>,
    correlationStateCounts: {
      'affected-range-match': <integer>,
      'exact-version-match': <integer>,
      'identity-only-potential': <integer>,
      'no-supported-match': <integer>,
      'version-not-evaluable': <integer>,
      'public-data-unavailable': <integer>,
    }
  }
}
```

The summary is **counts only**. It NEVER carries asset names,
component paths, owner labels, or review notes. The summary is
absent by default. V6.5 callers that don't opt in see no change.
V6.5 reports without the field continue to verify against the V6.5
integrity.

## Local relevance filter

A new filter on the public vulnerability table restricts the view by
correlation state:

| Filter | Description |
| --- | --- |
| `any` | No local-relevance filtering (default) |
| `potentially-relevant` | Any of `affected-range-match`, `exact-version-match`, `identity-only-potential` |
| `affected-range` | `affected-range-match` only |
| `exact-version` | `exact-version-match` only |
| `identity-only` | `identity-only-potential` only |
| `version-not-evaluable` | `version-not-evaluable` only |
| `no-local-data` | CVE has no local correlation in any state |

The filter is held in a `useState<LocalRelevanceFilter>` in the
dashboard. It is NEVER serialized to the URL, NEVER appears in the
CSV, NEVER appears in Defender Views, and NEVER appears in the
"What Changed" feed. The dashboard explicitly captions the control
"Filters here use only your local imported environment."

## Drawer "Potential local relevance" section

A new section in the detail drawer (after the V6.5 "Local report"
section) shows, for the open CVE:

- Per-state count chips for the local correlations
- A list of matching local assets + components
- The current review status for each correlation
- A Dismiss action (one click; sets `reviewStatus = 'dismissed'`,
  preserves provider evidence)

The section is rendered empty (with a "No local data" caption) when
no local correlation exists for the CVE.

## Worker dispatch

`dispatcher.mjs` wraps the parse and correlation workers:

| Runtime | Behavior |
| --- | --- |
| Browser with `Worker` | Spawn a per-job worker module; `onProgress` / `cancel` / `result` handle |
| Browser without `Worker` (older browsers, hardened enterprise policies) | Synchronous fallback, identical to the worker path |
| Node test runner | Synchronous fallback, identical to the worker path |

`cancel()` bumps a `genRef` so any worker result that arrives after
the cancel is rejected as `cancelled`.

The worker has no network access. The main thread never blocks on a
25 MiB import (chunked progress at 500-component steps).

## Privacy and security proofs

The acceptance suite (`scripts/acceptance-v66-local-environment.mjs`)
instruments `fetch`, `XMLHttpRequest`, `sendBeacon`,
`history.pushState`, `history.replaceState`, and every `console`
method. A sentinel private value is run through the full pipeline
(asset create, inventory import, correlation build, review, export)
and the suite asserts that the sentinel never appears in any captured
channel.

The suite also asserts:

- No external HTML resources (CSP meta with `default-src 'none'`)
- No script tags in the export HTML
- Prototype-pollution keys are rejected by every validator
- Environment size and CVE limits are enforced
- Raw SBOM payloads are never retained
- `localEnvironmentSummary` is OPTIONAL on V6.5 reports
- Local-relevance filter state is never serialized to the URL
- Local assets / notes / tags stay in the browser
- Default V6.5 reports carry no environment fields

## What the local environment is NOT

- NOT a vulnerability scanner (no active probing)
- NOT a patch manager (the `remediated` status is a local workflow statement)
- NOT a package-registry caller (no npmjs.com / crates.io / pypi calls)
- NOT a cloud-synced asset inventory (no accounts, no telemetry)
- NOT a substitute for asset validation, patch testing, or
  professional judgment

Every correlation carries the standard limitations block. Absence
of a correlation is never interpreted as safety. `remediated` is
a local workflow statement, not a security claim.

## Entry points

- **Dashboard** — "My Environment" panel between the change-intel
  panel and Defender Views. Count cards (Assets, Inventories,
  Components, Correlations, Awaiting review), asset list, correlation
  queue, import / export / clear controls
- **Dashboard table** — Local-relevance filter control under the
  search box (with the privacy caption)
- **Detail drawer** — "Potential local relevance" section with
  per-state count chips, matching assets, dismiss action
- **Asset dialog** — create / edit form with closed-enum selects
  for environment, asset type, and "User-assigned local asset
  criticality"
- **Import dialog** — 3-step flow: file picker → dry-run preview
  (format, sourceVersion, component count, rejected, warnings) →
  explicit Apply

## Files

```
src/environment/
  schema.mjs + .d.mts            ASSET_SCHEMA_VERSION, ASSET_LIMITS, ASSET_ENVIRONMENTS, ASSET_TYPES, ASSET_CRITICALITIES, CORRELATION_STATES, REVIEW_STATUSES, SUPPORTED_SBOM_FORMATS, validateAsset/Component/Inventory/Correlation/Review
  schema.d.mts
  migrate.mjs + .d.mts           deterministic V1 migrations
  purl.mjs + .d.mts              conservative Package URL parser, ECOSYSTEM_NORMALIZE, normalizeIdentity
  semver.mjs + .d.mts            parseSemver, compareSemver, semverInRange [lo,hi) exclusive hi
  versionEvaluators.mjs + .d.mts evaluateNpm, evaluateCrates, evaluatePackagist, evaluateGenericExact, pre-release handling
  correlation.mjs + .d.mts       buildCorrelations, matchesIdentity, normalizeMatchEcosystem, normalizeGhsaEcosystem, mergeBest
  inventoryChange.mjs + .d.mts   diffInventories, identityKey
  import.mjs + .d.mts            detectFormat, parseImport, parseCycloneDx 1.4/1.5/1.6, parseSpdx 2.3, parseInventoryJson, parseCsv
  exportImport.mjs + .d.mts      buildExportPayload, stampExportChecksum, validateImportPayload, verifyImportChecksum, applyImportPayload
  hash.mjs + .d.mts              sha256Hex (Web Crypto + Node fallback), computeInventoryChecksum, verifyInventoryChecksum
  InMemoryEnvironmentAdapter.mjs + .d.mts    test runner + session-only fallback
  UnavailableEnvironmentAdapter.mjs + .d.mts no-op
  IndexedDBEnvironmentAdapter.mjs + .d.mts   DB 'threatpulse-environment' v1, 5 stores, BroadcastChannel
  _shim.mjs                                  Node-side IDBKeyRange only
  workers/parseInventory.worker.mjs          pure-JS SHA-256, chunked progress, cancellation
  workers/correlate.worker.mjs               delegates to correlation.mjs with onProgress
  workers/dispatcher.mjs + .d.mts            Worker detection + main-thread fallback; handle with onProgress/cancel/result

src/state/EnvironmentContext.tsx              EnvironmentProvider + useEnvironment; status; flushPendingWrites, hasPendingWrites

src/components/environment/
  EnvironmentPanel.tsx                       Count cards, asset list, correlation queue, clear-all, export/restore
  AssetDialog.tsx                            Create / edit form; "User-assigned local asset criticality" labelled per spec
  InventoryImportDialog.tsx                  3-step flow: file picker → dry-run preview → explicit Apply
  CorrelationQueue.tsx                       Per-state count chips + paged table
  CorrelationReviewDialog.tsx                Status select + note textarea with live MAX_REVIEW_NOTE_CHARS counter
  LocalRelevanceSection.tsx                  Drawer section: per-state count chips, matching local assets/components, Dismiss action
```

Vite emits the two V6.6 workers as separate chunks:
`parseInventory.worker-*.js` (~17.6 kB) and
`correlate.worker-*.js` (~18.2 kB). The main bundle remains
browser-reachable; no `node:crypto` externalization warning.

## Acceptance coverage

`scripts/acceptance-v66-local-environment.mjs` covers:

1. Schema constants and limits (6 envs, 8 types, 5 criticalities,
   6 correlation states, 8 review statuses, all limits)
2. Prototype-pollution rejection (all validators)
3. Future schema rejection (all validators)
4. Non-finite number rejection
5. Migration no-op + unsupported target rejection
6. Package URL parsing (valid / invalid / path-traversal / spaces)
7. Identity normalization precedence (purl > explicit > name-only)
8. Ecosystem alias mapping
9. Semver parse / compare / inRange test vectors
10. Version evaluator test vectors (npm, crates, packagist, generic)
11. Correlation: `affected-range-match` (OSV range hit)
12. Correlation: `no-supported-match` (range miss — fixed version)
13. Correlation: GHSA `affected-range-match`
14. Correlation: `public-data-unavailable` when status != available
15. Correlation: `identity-only-potential` when version missing
16. Correlation: 0 results when no provider data
17. Correlation: deterministic id + CVE-id sort order
18. Correlation: `mergeBest` joins providers without overwriting
19. Inventory change: added / removed / versionChanged
20. CycloneDX 1.4 / 1.5 / 1.6 parse; 1.3 rejected
21. SPDX 2.3 parse; 2.2 rejected
22. ThreatPulse inventory JSON parse
23. CSV parse with the documented columns
24. CSV rejects formula-like values (`=`, `+`, `-`, `@` prefix)
25. CSV dedupes by deterministic componentId
26. Import dry-run does not mutate storage
27. InMemoryEnvironmentAdapter round-trip
28. IndexedDBEnvironmentAdapter shim round-trip
29. `applyInventory` atomic: invalid components leave prior state intact
30. `validateImportPayload` refuses prototype pollution, future
    schema, wrong format
31. `buildExportPayload` + `stampExportChecksum` + `verifyImportChecksum`
    round-trip; tampered payload rejected
32. `applyImportPayload` refuses integrity-failed payload
33. `applyImportPayload` merge + replace via InMemory
34. Export carries no public CSV, no credentials, no device ids
35. `UnavailableEnvironmentAdapter` every op returns unavailable
36. Dispatcher synchronous fallback (no Worker in test runner)
37. Dispatcher cancel rejects pending result
38. PRIVACY: sentinel never appears in any captured runtime channel
39. `computeInventoryChecksum` deterministic + distinguishes inputs
40. `verifyInventoryChecksum` accepts valid, rejects mismatched, no prefix

Plus per-V6.6 invariants: no network call, no URL write, no
console output, no public CSV field added, no public API mutation,
no public-intelligence fixture mutation, no script tag in any
export.
