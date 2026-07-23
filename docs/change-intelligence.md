# V6.1 — Change Intelligence

The "What changed" panel surfaces a deterministic diff
between the previous successful public-intelligence
version and the current one. The panel is panel-local:
its filter does not modify the main `VulnerabilityFilters`,
the Defender Views presets, the main table, or the
CSV export.

## Six panel categories

The panel chip row uses six categories, not seven and
not the V5.7 "added / corrected / withdrawn" mental
model. Each category maps to one or more per-CVE
classifications.

| Category | Classifiers |
| --- | --- |
| Newly tracked | `cve-newly-tracked` |
| No longer tracked | `cve-no-longer-tracked` |
| Fact newly available | `kev-newly-present`, `ssvc-data-newly-available`, `github-advisory-newly-available`, `first-patched-newly-available`, `osv-record-newly-correlated` |
| Fact changed | `severity-class-changed`, `cvss-source-or-version-changed`, `epss-materially-increased`, `epss-materially-decreased`, `ssvc-state-changed`, `osv-record-set-changed`, `affected-package-or-range-changed` |
| Fact no longer present | `kev-no-longer-present`, `github-advisory-no-longer-available`, `first-patched-no-longer-available`, `osv-record-removed`, `withdrawn` |
| Provider status changed | summary-level only (one per source state transition) |

The "Provider status changed" chip does not modify any
filter; clicking it expands and highlights the relevant
Source Health card.

## Comparability gates

A classification axis is computed only when both
snapshots report the corresponding provider as
comparable. The manifest carries `comparableAxes` and
`suppressedAxes` arrays; the UI surfaces the suppression
honestly with the axis name and a sanitized reason
(e.g. "EPSS provider unavailable in current snapshot").
The eight documented axes are: kev, severity-class,
cvss-source, epss, ssvc, github-advisory,
first-patched, osv.

## EPSS threshold

The 0.10 threshold is a transparent product rule. The UI
copy is "EPSS changed by at least 10 percentage points."
The direction is exposed: `epss-materially-increased`
and `epss-materially-decreased` are separate
classifiers. A small floating-point epsilon is used
internally to absorb IEEE-754 arithmetic noise; the
threshold is NOT lowered.

## Precedence rules

- A CVE that enters the tracked universe emits ONLY
  `cve-newly-tracked`. No per-axis classifiers are
  emitted (no `prev` record to compare against).
- A CVE that leaves the tracked universe emits ONLY
  `cve-no-longer-tracked`. No `fact-no-longer-present`
  or `fact-changed` classifiers are emitted.
- All other classifiers may co-occur on the same CVE.

## No fabrication

When no provider axis is comparable in the CURRENT
snapshot (CISA KEV gating failed), the change items
array is empty and `partial: true` is set on the
manifest. The change intelligence step never claims a
change from a failed run. The public envelope's
`publicIntelligenceStatus` is `'unavailable'` until a
successful run publishes a bundle.

## First-bundle (no previous comparable version)

The very first successful public-intelligence bundle
has no previous comparable version. The manifest's
`comparesFreshBase` field is `false`, the
`previousPublicIntelligenceVersion` is `null`, and the
per-CVE `items` array is empty regardless of how many
CVEs are tracked in the current snapshot. The aggregate
`changeSummary` is `{0, 0, 0, 0, 0, 0}` for this
initial bundle. The "What changed" panel renders the
locked copy: "No prior version yet — first comparison
appears after the next scheduled bundle." The change
intelligence step NEVER fabricates a diff against a
non-existent previous version.

## Query modes (current-version-only)

The dataset function exposes:

```
GET /.netlify/functions/dataset?view=changes&version=<v>&category=<c>&limit=25
```

The `version` MUST equal the currently-attached
`publicIntelligenceVersion`. Arbitrary retained-version
browsing is not exposed. The response is sanitized:
400 for malformed parameters, 404 for a missing
category result, 409 for version mismatch, 503 for
missing or corrupt immutable projection.

## Panel-local filter

The chip row is the panel's only filter. It does NOT:

- Modify `VulnerabilityFilters`.
- Modify Defender Views presets.
- Modify the main table.
- Modify the CSV export.
- Affect the public dataset's other panels.

The panel renders the locked copy
"Filters here affect only this panel." immediately
above the chip row.

## Bounded row display

The panel renders at most 25 rows per request, sorted
by `(categoryOrder, classificationOrder, cveId)`. The
disclosure is rendered as
"Showing the 25 most recent changes of N. Filter to see fewer."
when the local filter produces more than 25 matching
items.

## Aggregation

The aggregate `changeSummary` is exposed in the public
envelope:

```ts
{
  newlyTracked, noLongerTracked,
  factNewlyAvailable, factChanged, factNoLongerPresent,
  providerStatusChanged,
  epssMateriallyIncreased, epssMateriallyDecreased
}
```

The full per-CVE `items` array is in the
`changes.json.gz` Blobs (server-side only) and is
fetched by the browser only through the `view=changes`
query mode.
