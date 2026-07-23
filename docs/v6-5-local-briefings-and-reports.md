# V6.5 — Local Briefings and Reports

Local-only defender briefings and defensible report exports generated from
public intelligence + V6.1 change intelligence + V6.4 local workspace entries.
**All report generation, preview, export, verification, comparison, and
history lives inside the browser.** Nothing is uploaded.

## What it is

A report is a JSON bundle the operator can export as Markdown, standalone
HTML, print-optimized HTML (for "Save as PDF"), or strict JSON. The
operator can also verify a JSON report and compare two JSON reports.
History is kept locally in IndexedDB; entries are summary-only and never
include the full report body, private notes, or tags.

## Five report types

| ID | Label | What it does |
| --- | --- | --- |
| `defender-daily-briefing` | Defender Daily Briefing | Newly tracked + changed CVEs (public) and watched CVEs with local status (local) |
| `local-triage-queue` | Local Triage Queue Report | The local queue (provider facts + local status / priority / tags) |
| `selected-cve` | Selected CVE Report | Detailed report for one or more specific CVEs |
| `change-briefing` | Change Briefing | ThreatPulse classifications (public) + local re-review candidates |
| `executive-summary` | Executive Summary | Identifiers + public facts, no local user content |

## Five redaction modes

| ID | Notes | Tags | Status | Body |
| --- | --- | --- | --- | --- |
| `none` | included | included | included | full |
| `exclude-private-notes` | redacted | included | included | full |
| `exclude-local-tags` | included | redacted | included | full |
| `exclude-all-user-text` | redacted | redacted | redacted | full |
| `identifiers-only` | redacted | redacted | redacted | identifiers only |

Redaction is applied during snapshot building so excluded values never
enter the digest input. The checksum reflects the redacted bytes.

## Coherent snapshot

Before generation the builder:

1. Captures compatible public-intelligence metadata
2. Captures selected public CVE records
3. Flushes all pending workspace writes
4. Refuses to proceed if the flush rejects
5. Captures selected workspace entries
6. Freezes the complete input snapshot

Generation then runs only from the frozen snapshot — the public version
cannot change mid-generation.

## Integrity

SHA-256 over canonical report bytes (with the integrity block stripped).
The canonical form is deterministic (sorted keys at every depth, no
whitespace, drops `undefined`, throws on non-finite numbers and
circular references). Checksums are `sha256:<64 hex>`.

The browser uses `crypto.subtle.digest('SHA-256', ...)`; the test runner
falls back to Node `crypto`. The Node `node:` specifier is composed at
runtime so the Vite browser build never produces a `node:crypto`
externalization warning.

## Schema

```ts
{
  format: 'threatpulse-local-report',
  schemaVersion: '1.0.0',
  reportId,
  reportType,
  title,
  generatedAt,
  applicationVersion,
  publicIntelligence: { status, version, projectionSchemaVersion, generatedAt, comparableAxes, suppressedAxes, sourceHealth },
  selection: { cveIds, workspaceFilters, includePrivateNotes, includeLocalTags, includeResolved, includeArchived },
  sections,        // an ordered list of section objects
  provenance,      // a list of public source records
  limitations,     // a list of human-readable limitations
  integrity: { canonicalizationVersion, checksum }
}
```

Limits: `MAX_CVES = 500`, `MAX_BYTES = 20 MiB`, `MAX_TITLE_CHARS = 200`,
`MAX_HISTORY_ENTRIES = 100`.

## Verification

`verifyJson(jsonString)` returns one of:

- `valid` — schema + integrity OK
- `valid-shape` — schema OK, integrity pending (sync helper)
- `unsupported-schema` — future `schemaVersion` is rejected
- `invalid-format` — wrong `format` or wrong payload shape
- `too-large` — payload exceeds `MAX_BYTES` or has too many CVEs
- `corrupt` — JSON parse failed or schema validation failed
- `incomplete` — valid shape but missing/invalid integrity block
- `integrity-failed` — checksum mismatch
- `integrity-unavailable` — Web Crypto is unavailable in this runtime

## Comparison

`compareReports(a, b)` verifies both reports (shape + integrity
recompute) BEFORE computing diffs. When either report is missing or
its integrity fails, comparison is refused. The result is a structured
`DiffResult` covering metadata, public intelligence, selection, CVE
add/remove, per-CVE provider facts, per-CVE local fields (notes only
when BOTH reports explicitly contain them), provenance, and limitations.
The comparison never interprets absence as remediation.

## History

IndexedDB-backed, capped at 100 entries. Each entry contains only:

`reportId, reportType, title, generatedAt, cveCount, publicIntelligenceStatus,
publicIntelligenceVersion, includePrivateNotes, includeLocalTags, includeResolved,
includeArchived, redactionMode, exportFormat, exportStatus, checksum, storedAt`

Full reports, sections, notes, and tags are never stored. The history
can be disabled (the existing entries survive on disk so the operator
can re-enable without losing data).

## Export formats

| Format | Extension | MIME | Notes |
| --- | --- | --- | --- |
| `markdown` | `.md` | `text/markdown;charset=utf-8` | Deterministic pipe-table Markdown; every value escaped |
| `html` | `.html` | `text/html;charset=utf-8` | Standalone self-contained HTML; inline safe CSS; CSP meta policy; no scripts / no remote resources |
| `print` | `.html` | `text/html;charset=utf-8` | Print-optimized HTML; opens in a new tab for the browser's "Save as PDF" command |
| `json` | `.json` | `application/json;charset=utf-8` | Strict JSON bundle; re-validated with `validateReport` before export |

The filename convention is
`threatpulse-report-{type}-{shortId}-{YYYY-MM-DD}.{ext}`.
Filenames never contain private notes, tags, or user names.

## Privacy and security proofs

The acceptance suite instruments `fetch`, `XMLHttpRequest.sendBeacon`,
`history.pushState`, `history.replaceState`, and every `console` method
during build / preview / export / verification / comparison / history
operations. A sentinel private value is run through the full pipeline
and the suite asserts that the sentinel never appears in any captured
channel.

The suite also asserts:

- No external HTML resources (CSP meta with `default-src 'none'`)
- No script tags in standalone HTML
- Prototype-pollution keys (`__proto__`, `prototype`, `constructor`)
  are rejected by `validateReport`
- Report size and CVE limits are enforced
- History excludes full notes
- Pending workspace writes flush before snapshot creation
- Redaction removes values from every representation (sections,
  metadata, JSON, HTML, comments, attributes, filenames, checksum input)

## What the report is NOT

- Not certified
- Not complete
- Not legally admissible
- Not digitally signed
- Not independently verified
- Not a replacement for asset validation, patch testing, or professional judgment

Every report carries a standard limitations block that explains the
public-intelligence + optional local-input model and reminds the
operator that missing enrichment is not evidence of absence.

## Entry points

- **Workspace panel** — "Build report" button combines
  `selectedCveIds` + queue rows
- **Detail drawer** — per-CVE "Build a local report for {cveId}" button
  in the new "Local report" section
- **What changed panel** — "Build a Change Briefing report" button

## Files

```
src/reports/
  schema.mjs              REPORT_SCHEMA_VERSION, REPORT_TYPES, REDACTION_MODES, validateReport
  schema.d.mts
  canonicalize.mjs        canonicalizeReportBytes (integrity-stripped, sorted keys)
  canonicalize.d.mts
  sha256Browser.mjs       Web Crypto only (browser-reachable)
  sha256Node.mjs          Node crypto only (test runner)
  sha256.mjs              public dispatcher
  sha256.d.mts
  integrity.mjs           computeIntegrity, shortChecksum
  integrity.d.mts
  redaction.mjs           modeHidesNote/Tags/Status/Body, fieldKindOf
  redaction.d.mts
  snapshot.mjs            buildReportSnapshot, capture*
  snapshot.d.mts
  templates.mjs           buildReport, buildSections, renderLimitations, renderProvenance
  templates.d.mts
  exporters/markdown.mjs  deterministic pipe-table Markdown
  exporters/html.mjs      standalone self-contained HTML + CSP
  exporters/print.mjs     print-optimized HTML
  exporters/json.mjs      strict JSON bundle
  exporters/index.mjs     public dispatcher
  exporters/index.d.mts
  download.mjs            downloadFile, openHtmlInNewTab, buildReportFilename
  download.d.mts
  verify.mjs              verifyJson, verifyReport, verifyShape
  verify.d.mts
  compare.mjs             compareReports
  compare.d.mts
  history.mjs             addHistoryEntry, listHistoryEntries, removeHistoryEntry, clearHistory, setHistoryEnabled
  history.d.mts

src/components/reports/
  ReportDialogShell.tsx   focus-trap, Escape closes, focus restored on close
  ReportPreview.tsx       React-text-only; renders header + limitations + sections + provenance
  ReportBuilder.tsx       main dialog; form + snapshot + integrity + preview
  ReportHistoryDialog.tsx history list with per-entry delete, clear, disable
  ReportVerifyDialog.tsx  verify or compare JSON files

scripts/acceptance-v65-briefings.mjs   26 tests, 100+ assertions
```

## Compatibility

- V6.1 through V6.4 contracts preserved
- 5 public Netlify function entries
- 1 gateway function entry (byte-identical to `32a8a63`)
- `netlify/gateway/` byte-identical to `32a8a63`
- `client/` byte-identical to `32a8a63`
- `CSV_COLUMNS` = 21
- No accounts, no cloud sync, no browser provider calls, no proprietary
  score, no deployment
- The browser build no longer emits a `node:crypto` externalization
  warning (the Node `node:` specifier is composed at runtime)
