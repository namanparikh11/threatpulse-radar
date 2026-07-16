# V6.4 — Local Defender Workspace and Triage

V6.4 turns ThreatPulse Radar from a read-only public intelligence
dashboard into a useful local defender workspace. Every change is
additive: the public dataset, the Netlify functions, the Hostinger
runtime, and the private gateway are unchanged.

All workspace information lives on the user's device. Nothing is
uploaded to Netlify, Hostinger, the private gateway, CISA, NVD,
FIRST, GitHub, OSV, or any analytics endpoint.

---

## What the workspace is

The workspace is a per-device, IndexedDB-backed (with a
session-memory fallback) triage surface that lets a defender:

- **Watch** selected CVEs.
- **Assign a local triage status** (one of `unreviewed`,
  `reviewing`, `action-required`, `mitigating`, `resolved`,
  `accepted-risk`, `not-applicable`).
- **Assign a local user priority** (one of `none`, `low`,
  `medium`, `high`, `urgent`).
- **Add local tags** (case-insensitive dedup, capped 20 per
  CVE, 40 chars each).
- **Add a private note** (capped 8,000 chars; multi-line
  preserved; control chars stripped).
- **Mark CVEs reviewed** against the current public-intelligence
  view.
- **Identify watched CVEs that changed since review** (compared
  by a deterministic public-safe change signature).
- **Filter and manage a local triage queue** with bounded bulk
  actions.
- **Export and restore the local workspace** as a JSON file
  (deterministic, sha256-checksummed).
- **Clear local data safely** (archived vs full reset, both
  with confirmation).

All of this works without an account.

## What is **never** uploaded

| Field                       | Where it stays           |
| --------------------------- | ------------------------ |
| `watched`                   | Browser IndexedDB        |
| `triageStatus`              | Browser IndexedDB        |
| `userPriority`              | Browser IndexedDB        |
| `tags`                      | Browser IndexedDB        |
| `note`                      | Browser IndexedDB        |
| `archived`                  | Browser IndexedDB        |
| `lastReviewedAt`            | Browser IndexedDB        |
| `lastSeenPublicIntelligenceVersion` | Browser IndexedDB |
| `lastSeenChangeSignature`   | Browser IndexedDB        |
| Search / filter text        | Browser memory only      |
| Import / export payload     | Browser download only    |

A privacy-checked source sweep runs in the V6.4 acceptance
suite (`scripts/acceptance-v64-workspace.mjs`) and verifies
that the `vulnerabilityService`, every Netlify function entry,
and the public-intelligence read paths contain no reference to
any of the workspace fields.

## Storage contract

The browser-side workspace uses a narrow adapter interface
(init / get / put / patch / delete / list / bulkUpdate /
exportWorkspace / validateImport / importWorkspace /
clearArchived / clearWorkspace / getWorkspaceMetadata /
subscribe / close). Three adapters are shipped:

- **`IndexedDBWorkspaceAdapter`** — primary, transactional
  writes, `INDEXEDDB_REASONS` for sanitized errors.
- **`InMemoryWorkspaceAdapter`** — Map-backed, used by tests
  and as a session-only fallback.
- **`UnavailableWorkspaceAdapter`** — read-only stub when
  storage is blocked (private/incognito, quota exceeded,
  blocked-by-user).

### Status fallback chain

`IndexedDB → InMemory (read-only) → Unavailable`. The status
is surfaced as `'initializing' | 'ready' | 'read-only' |
'unavailable' | 'error'`.

## Schema

`schemaVersion: '1.0.0'`, format `threatpulse-local-workspace`.

| Limit                  | Value          |
| ---------------------- | -------------- |
| `NOTE_MAX_CHARS`       | 8,000          |
| `TAGS_PER_CVE`         | 20             |
| `TAG_MAX_CHARS`        | 40             |
| `IMPORT_MAX_BYTES`     | 5 MiB          |
| `IMPORT_MAX_ENTRIES`   | 50,000         |
| `WARNING_ENTRIES`      | 5,000 (soft)   |

Future schema versions are rejected outright. Past versions
are routed through the migration chain. A record with an
unknown `schemaVersion` cannot be imported.

### Prototype-pollution rejection

`__proto__`, `prototype`, and `constructor` keys are rejected
at every entry / payload boundary (entry validation, import
validation, and patch apply). The check uses
`Object.getOwnPropertyNames` to bypass the
`Object.keys`/`__proto__` quirk.

## Export format

```json
{
  "format": "threatpulse-local-workspace",
  "schemaVersion": "1.0.0",
  "exportedAt": "2026-07-16T12:00:00.000Z",
  "applicationVersion": "v6.4",
  "entryCount": 3,
  "entries": [ ... ],
  "checksum": "sha256:<64 hex chars>"
}
```

The export is **deterministic**: entries are sorted by `cveId`
ascending, tags are sorted ascending, and the field order is
fixed. The checksum is a `sha256:`-prefixed hex digest of the
canonical entry list. The download filename is a static
`threatpulse-workspace.json` (no CVE id, no timestamp leak).

## Import modes

- **dry-run** (default): validates the payload only. No writes.
- **merge**: newer `updatedAt` wins per CVE. Existing entries
  without an incoming change are kept.
- **replace**: existing workspace is preserved until the
  complete new workspace has been validated and staged, then
  atomically promoted. Failed promotion leaves the original
  workspace intact.

Import always re-validates synchronously; a failed validation
returns `{ ok: false, reason }` with a sanitized reason string
(e.g. `invalid-format`, `unsupported-schema-version`,
`prototype-pollution:__proto__`, `note-too-long`,
`too-many-tags`, `payload-too-large`, `too-many-entries`).

## Multi-tab synchronization

A `BroadcastChannel('threatpulse-workspace')` is used when
available; a safe in-tab fallback is used otherwise. After a
committed write, a `{ type, cveId?, ts }` message is posted.
Receiving tabs re-fetch the affected record (or the full list
for bulk updates).

### Conflict rules

`updatedAt` is the primary comparison. A deterministic
tie-breaker (`cveId` ascending) breaks ties. A newer
committed update always wins; an older record never silently
replaces a newer one. A conflict surfaces a banner with the
CVE id, the reason, and the remote `updatedAt`; the operator
can "Keep newer" or dismiss.

## Change-aware watchlist

The drawer stamps `lastSeenPublicIntelligenceVersion` and
`lastSeenChangeSignature` when the operator clicks
"Mark reviewed". A subsequent `classifyChange(...)` call
returns:

- `'no-newer'` — the public view is identical to the
  checkpoint.
- `'changed'` — a newer compatible public change was recorded.
- `'newly-tracked'` — the entry has no review checkpoint yet.
- `'no-longer-tracked'` — the CVE is no longer in the public
  dataset.
- `'unavailable'` — change intelligence is missing or the
  version is incompatible.

The change signature is computed from public-safe fields only
(severity, CVSS, EPSS, KEV, SSVC, vulnrichment, GitHub
advisory, OSV record set, withdrawn). Provider record bodies
and SSVC text are NOT copied into IndexedDB.

## Privacy proofs (in `scripts/acceptance-v64-workspace.mjs`)

1. **CSV columns** — 21 columns; no workspace field appears
   in any column.
2. **`vulnerabilityService.ts`** — no workspace field appears
   in any function parameter.
3. **All Netlify function entries** — no `workspace`, `note`,
   `triage`, `priority`, or `watched` reference in any code
   path (comments stripped before the search).
4. **URL** — no `watched`, `triage`, `priority`, `note`,
   `tag`, `archived`, or `workspace` query parameter is ever
   written by the dashboard.
5. **Export filename** — `threatpulse-workspace.json`
   (static, no CVE id, no timestamp).
6. **Banner copy** — the multi-tab conflict banner shows the
   CVE id, the reason, and the remote `updatedAt`; the note
   and tags are never rendered.

## IndexedDB persistence limits

IndexedDB is best-effort. The following failure modes are
handled and behavior-tested:

- IndexedDB blocked by user / browser policy
- Quota exceeded
- Transaction aborted (concurrent tab writes)
- Database deleted externally (next read returns an empty
  list)
- Migration failure
- Malformed import
- Checksum failure
- BroadcastChannel unavailable
- Storage becoming unavailable during autosave

A sanitized human message is shown in each case; the operator
is never shown a stack trace or a raw provider error.

## Private / incognito limitations

- Most modern browsers offer a "session-only" storage mode
  in private windows. The workspace falls back to the
  in-memory adapter (status `read-only`) and the data is lost
  on tab close.
- In some configurations, IndexedDB is fully disabled; the
  workspace falls back to the `Unavailable` adapter and the
  workspace section of the dashboard renders a clear
  "unavailable" state.

## Backup and restore

- **Backup** — `Export` in the panel header downloads a local
  JSON file. The file may contain private notes; the export
  dialog surfaces this in its body copy. No data is uploaded.
- **Restore** — `Import` opens a file picker. The default mode
  is `dry-run`; merge and replace require explicit
  confirmation. Failed promotion leaves the original workspace
  intact.

## User priority vs. provider severity

`userPriority` is documented as a **user-assigned workflow
value**. It never alters CVSS, severity, EPSS, KEV, SSVC, or
any provider fact. The drawer renders it in a distinct tone
and copy ("Local priority") so the operator never confuses
their own triage with the provider's assessment.

## Deletion and recovery

- **Clear archived** — removes only entries with
  `archived: true`. Active (non-archived) entries are kept.
- **Clear workspace** — removes every entry. Gated by a
  typed `RESET` confirmation.
- Both actions are local-only. Public vulnerability data,
  Netlify Blobs, Hostinger storage, and the gateway are
  untouched.
- A cleared workspace is unrecoverable from the application;
  the previous export (if any) is the only source of recovery.

## No cross-device sync

V6.4 does NOT synchronize the workspace across devices. The
private gateway is not used; cloud sync is out of scope.
Operators who need cross-device triage should export on one
device and import on the other.

## No account requirement

V6.4 introduces no authentication, no login, no profile. The
workspace is anonymous and per-device.

## Accessibility

- All controls have accessible labels.
- The multi-tab conflict banner uses `role="alert"` +
  `aria-live="polite"`.
- The save-state indicator (idle / saving / saved / error) is
  announced via `aria-live="polite"`.
- The dialogs trap and restore focus; `Escape` closes them.
- Reduced motion is respected (the "Changed since review"
  pulse is disabled under `prefers-reduced-motion: reduce`).
- Bulk action count and confirmations are surfaced in plain
  text, not just colour.

## Test coverage

`scripts/acceptance-v64-workspace.mjs` covers:

- Schema validation (CVE normalisation, tag dedup, note cap,
  prototype-pollution rejection).
- Migrations (chain lookup, behaviour on unknown versions).
- Change signature (determinism, sha256 prefix, hex format,
  signature change on severity, compat-version logic,
  classifyChange outcomes).
- Adapters (in-memory, unavailable).
- Export / import (deterministic checksum, order-sensitivity,
  dry-run, merge, replace, failed-promotion preservation).
- Queue filters and ordering (all 7 filters, default rank
  ordering, search across cve/note/tag).
- Privacy invariants (CSV, vulnerabilityService, Netlify
  functions, URL, export filename).
- Repository invariants (5 public function entries, 21 CSV
  columns, netlify/gateway present).
- Concurrency (parallel patchEntry → last-write-wins).

Total: 190 assertions.

## Compatibility

| Invariant                                      | Status   |
| ---------------------------------------------- | -------- |
| All 31 prior acceptance suites pass            | yes      |
| Netlify support unchanged                      | yes      |
| Hostinger support unchanged                    | yes      |
| 5 public Netlify function entries              | yes      |
| 1 gateway function entry (byte-identical)      | yes      |
| `netlify/gateway/` byte-identical to V6.1      | yes      |
| `client/` byte-identical to V6.1               | yes      |
| `CSV_COLUMNS` = 21                             | yes      |
| V6.1 dataset/query contracts                   | yes      |
| V6.2 storage portability                       | yes      |
| V6.3 Hostinger runtime behaviour               | yes      |
| No browser provider calls                      | yes      |
| No proprietary score                           | yes      |
| No account system                              | yes      |
| No deployment                                  | yes      |
