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
| `MUTATION_ID_MAX_CHARS` | 96            |

Every workspace record carries two opaque identity fields:

- `revision` — a non-negative integer incremented exactly
  once per committed mutation. A record that pre-dates
  this field is migrated to `revision = 0`.
- `mutationId` — a per-mutation random identifier (NOT a
  device / browser identifier). A migrated record uses
  the deterministic value `"migrated-<cveId>"` so a
  runtime mutation id (a UUID/hex string with no
  `"migrated-"` prefix) cannot collide.

Every successful mutation increments `revision` by
exactly one. A failed transaction does NOT increment
`revision`.

Future schema versions are rejected outright. Past versions
are routed through the migration chain. A record with an
unknown `schemaVersion` cannot be imported.

### Prototype-pollution rejection

`__proto__`, `prototype`, and `constructor` keys are rejected
at every entry / payload boundary (entry validation, import
validation, and patch apply). The check uses
`Object.getOwnPropertyNames` to bypass the
`Object.keys`/`__proto__` quirk.

## Pending-write lifecycle (controlled autosave)

The note editor uses a controlled pending-write lifecycle
that prevents data loss across every operator action. Every
keystroke bumps a generation counter; the debounce timer
captures the current generation and a stale callback is
rejected when its captured generation no longer matches
the current one.

Lifecycle rules:

- The first keystroke sets the save state to `pending`
  ("Unsaved") immediately.
- The debounce timer (600 ms) fires only if the
  generation has not changed since it was scheduled.
- `onBlur` flushes the pending edit before the textarea
  loses focus.
- Changing the selected CVE flushes the previous CVE's
  note before the new CVE mounts its draft state.
- The component unmount path best-effort flushes any
  remaining draft; a `beforeunload` warning fires only
  when an uncommitted write is still in flight.
- Archive / remove-watch actions flush the pending note
  BEFORE issuing the destructive mutation, so a slow
  debounced commit cannot be lost when the operator
  clicks Archive right after typing.
- Import / clear / replace dialogs call
  `flushPendingWrites()` from the context BEFORE
  applying the destructive operation, so the import
  sees the latest committed state and the imported
  data does not race a pending autosave.
- Save success (`Saved`) is shown only after the
  IndexedDB transaction commits AND the verify-by-re-read
  succeeds. A failed transaction leaves the local editor
  contents visible and recoverable.
- The save state is `'pending' | 'saving' | 'saved' |
  'error'`; the error state is sticky until the operator
  changes the draft.

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

Import always re-validates asynchronously (the dry-run
path is async so the canonical SHA-256 can be recomputed
on the browser main thread without blocking). A failed
validation returns `{ ok: false, reason }` with a sanitized
reason string (e.g. `invalid-format`,
`unsupported-schema-version`, `prototype-pollution:__proto__`,
`note-too-long`, `too-many-tags`, `payload-too-large`,
`too-many-entries`, `checksum-mismatch`).

## Async Web Crypto checksums

The export checksum, the import verification, and the
per-CVE change signature are computed via
`crypto.subtle.digest('SHA-256', ...)` when Web Crypto is
available. The main thread is never blocked on a 5 MiB
workspace file.

- **Export** — the export dialog surfaces a "Computing
  checksum… the main thread is not blocked." status while
  the async digest runs.
- **Import** — the import dialog surfaces a "Verifying…
  (checksum)" status while the recomputation runs. A
  tampered file surfaces `checksum-mismatch` and the
  apply button is disabled.
- **Change signature** — the per-CVE change signature
  uses the same async helper via the dashboard
  component (with a sync fallback available for
  Node tests and the small per-render inline call).

When Web Crypto is unavailable AND Node `crypto` is
unavailable, the helper throws a sanitized
`ShaUnavailableError`. No remote hashing service is
used. No `node:crypto` is reachable from the browser
production path.

## Multi-tab synchronization

A `BroadcastChannel('threatpulse-workspace')` is used when
available; a safe in-tab fallback is used otherwise. After a
committed write, a `{ type, cveId?, ts }` message is posted.
Receiving tabs re-fetch the affected record (or the full list
for bulk updates). The message NEVER carries the note or tag
contents; the receiver re-reads them from the local store.

### Conflict rules (v6.4 hardened)

The comparison is a three-level, strictly ordered cascade:

1. `updatedAt` (the primary, millisecond-grained timestamp).
2. `revision` (a non-negative integer incremented exactly
   once per committed mutation; the secondary tie-breaker).
3. `mutationId` (a per-mutation random identifier; the
   final deterministic tie-breaker).

A new committed update always wins. An older record never
silently replaces a newer one. The comparison is **NOT**
based on `cveId` because both records share the same cveId
— using cveId as a tie-breaker cannot resolve same-CVE
conflicts.

A conflict surfaces a banner with the CVE id, the reason,
the remote `revision`, the remote `updatedAt`, and the
remote `mutationId`; the operator can "Keep newer" or
dismiss. The note and tag contents are NEVER rendered in
the banner.

Every workspace record carries `revision` and `mutationId`.
Records that predate this field are migrated deterministically:
`revision = 0` and `mutationId = "migrated-<cveId>"`. The
migration value uses a different prefix from runtime
mutation ids so a real collision is impossible.

## Change-aware watchlist

The drawer stamps `lastSeenPublicIntelligenceVersion`,
`lastSeenChangeSignature`, and
`lastSeenPublicProjectionSchemaVersion` when the operator
clicks "Mark reviewed". A subsequent `classifyChange(...)`
call returns:

- `'no-newer'` — the public view is identical to the
  checkpoint at the same version and projection schema.
- `'changed'` — a newer compatible public change was
  recorded.
- `'newly-tracked'` — the entry has no review checkpoint
  yet.
- `'no-longer-tracked'` — the CVE is no longer in the
  public dataset.
- `'unavailable'` — change intelligence is missing, OR
  the current bundle is not directly comparable to the
  review checkpoint.

### Public-intelligence compatibility (v6.4 hardened)

The V6.1 `publicIntelligenceVersion` is a timestamp + hash
form (`<fs-safe-iso>-<short-hex>`), NOT semver. The
compat check is **EXACT equality** on the version id
and **EXACT equality** on the projection schema version.
Two records produced by different projection schemas
are NEVER treated as compatible. The compat check is
not based on major/minor semantic version numbers.

Compatibility is gated by `publicIntelligenceStatus`:
when the status is not `'available'` (i.e. `'mismatch'`
or `'unavailable'`), the classification is always
`'unavailable'`. The dashboard never fabricates a
"changed since review" claim when the public-intelligence
bundle is not available.

The change signature is computed from public-safe fields
only (severity, CVSS, EPSS, KEV, SSVC, vulnrichment,
GitHub advisory, OSV record set, withdrawn, plus the
projection schema version). Provider record bodies and
SSVC text are NOT copied into IndexedDB.

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
   CVE id, the reason, the remote `revision`, the remote
   `updatedAt`, and the remote `mutationId`; the note and
   tags are never rendered.

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
- Checksum failure (the async dry-run recomputes the
  canonical SHA-256 of the staged entries; a mismatch
  surfaces `checksum-mismatch` before any write)
- BroadcastChannel unavailable
- Storage becoming unavailable during autosave

A sanitized human message is shown in each case; the operator
is never shown a stack trace or a raw provider error.

## Storage fallback modes

The workspace storage status is one of four explicit values:

- **`persistent`** — IndexedDB is available and the
  data is written to disk. This is the default and the
  normal case.
- **`session-only`** — IndexedDB is unavailable, but the
  in-memory adapter is writable for the current tab. The
  panel header surfaces a clear "Session-only mode" badge
  and the data is lost on tab close or reload. The panel
  copy recommends an immediate export.
- **`unavailable`** — neither persistent nor safe session
  storage is available. Every write returns an
  `{ ok: false, reason: 'unavailable' }`; the panel
  renders a "Local workspace is unavailable in this
  browser session" banner.
- **`error`** — unexpected storage failure (e.g. an
  adapter throw that wasn't a known reason). The panel
  surfaces the sanitized error message.

A silent downgrade from `persistent` to `session-only`
after committed persistent data already exists is NOT
permitted. The context tracks whether the session started
as `persistent`; if the IndexedDB adapter subsequently
fails, the panel surfaces an explicit warning: "IndexedDB
became unavailable after a successful open. Recent data
is not persisted. Export a backup." The operator is given
a clear data-loss signal instead of a quiet fallback.

## Private / incognito limitations

- Most modern browsers offer a "session-only" storage mode
  in private windows. The workspace falls back to the
  in-memory adapter (status `session-only`) and the data is
  lost on tab close.
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

- **Schema validation** — CVE normalisation, tag dedup,
  note cap, prototype-pollution rejection (via
  `Object.getOwnPropertyNames`).
- **Migration** — chain lookup, behaviour on unknown
  versions, deterministic `revision = 0` /
  `mutationId = "migrated-<cveId>"` for legacy records.
- **Conflict resolution** — three-level
  `(updatedAt, revision, mutationId)` comparison.
  Same-millisecond records resolve deterministically by
  revision, then by mutationId. Migration records never
  beat a runtime record with `revision >= 1`.
- **Public-intelligence compatibility** — exact
  equality on the V6.1 timestamp+hash version id; no
  semver parsing. Status `'available'` required for
  any change-aware claim. Schema mismatch surfaces
  `'unavailable'`. Missing intelligence surfaces
  `'unavailable'`. Compatible newer change surfaces
  `'changed'`.
- **Web Crypto checksums** — known SHA-256 vector;
  deterministic workspace checksum; corrupt import
  rejected with `checksum-mismatch`; large fixture
  hashing is async; sanitized failure when Web Crypto
  is unavailable; no network call is made.
- **Adapters** — in-memory (with revision/mutationId
  stamping on patch + bulk), unavailable.
- **Export / import** — deterministic checksum, async
  dry-run with checksum verification, merge, replace,
  failed-promotion preservation, prototype-pollution
  rejection.
- **Queue filters and ordering** — all 7 filters, default
  rank ordering, search across CVE id / note / tag.
  The `changed-since-review` filter is unavailable when
  the public-intelligence status is not `'available'`.
- **Privacy invariants (source-level)** — CSV columns,
  `vulnerabilityService.ts` parameters, all 5 Netlify
  function entries (comments stripped), DashboardPage
  URL writes, export filename.
- **Privacy invariants (runtime)** — `fetch`,
  `XMLHttpRequest`, `navigator.sendBeacon`,
  `history.pushState`, `history.replaceState`,
  `console.log/info/debug/warn/error` are instrumented
  during watch / note save / tag save / priority/status
  update / mark reviewed / bulk update / export / import
  dry-run / import merge / clear archived. No network
  call, no URL write, no console output is captured; a
  sentinel private value NEVER appears in any captured
  channel.
- **Repository invariants** — 5 public function
  entries, 21 CSV columns, `netlify/gateway/` present.
- **Concurrency** — parallel `patchEntry` → last-write
  wins with monotonically increasing `revision`.

Total: 219 assertions.

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
