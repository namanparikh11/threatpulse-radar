# V6.7 — Local remediation plans and evidence ledger

ThreatPulse Radar v6.7 adds a **local-only remediation
workflow** that lets a defender connect public CVE
intelligence to a plan, a checklist, evidence, and a
local activity ledger.

Every artifact added in v6.7 is stored only in the
operator's browser. The system has no account, no cloud
sync, no provider callbacks, and no proprietary score.

## What the operator can do

* Create a local remediation plan for a CVE,
  correlation, asset, or component.
* Decompose the plan into ordered tasks with local
  owner labels and due dates.
* Attach evidence records of nine types (local note,
  local file fingerprint, inventory / correlation /
  report reference, validation result, change-ticket
  reference, external reference, other).
* Fingerprint a local evidence file with a Web Worker
  that computes SHA-256 off the main thread. File bytes
  never leave the device and are never stored.
* Walk a plan through the documented lifecycle state
  machine (draft → planned → in-progress → blocked →
  validation-pending → completed / accepted-risk /
  deferred / cancelled). A "validation failed" state
  re-enters `in-progress` rather than mutating the
  history.
* Record a local validation result linked to the
  evidence trail.
* Reopen a completed or accepted-risk plan without
  silently mutating its history.
* Export a plan bundle to `threatpulse-local-remediation`
  v1.0.0 (SHA-256 integrity-checked JSON).
* Import a bundle with dry-run / merge / replace modes
  and atomic ledger conflict detection.
* View a per-plan append-only hash-chained activity
  ledger with chain integrity verification.
* Clear all remediation data in a single action.

## Honest product language

The following are user-authored local workflow states,
**not** provider facts:

* remediation plan status
* task status
* owner label
* due date
* verification result
* accepted-risk decision
* completion state
* validation note
* evidence description

The UI uses wording such as:

* "Local remediation plan"
* "User-assigned owner label"
* "Local validation result"
* "Recorded as completed locally. External validation
  has not been performed by ThreatPulse."
* "Locally recorded evidence"
* "Local workflow status"

The UI never claims the recorded state is:

* a vulnerability fix
* a globally-verified patch
* independently validated
* legally admissible evidence
* digitally signed or externally attested

The activity ledger wording is:

> "The local hash chain can detect changes within this
> exported ledger. It does not prove authorship,
> identity, timestamp authority, or legal authenticity."

## Plan schema (1.0.0)

```json
{
  "schemaVersion": "1.0.0",
  "planId": "plan-...",
  "title": "Upgrade xz-utils to 5.6.2",
  "description": "...",
  "status": "draft|planned|in-progress|blocked|validation-pending|completed|accepted-risk|deferred|cancelled",
  "remediationType": "patch|upgrade|configuration-change|mitigation|compensating-control|remove-component|replace-component|isolate-asset|validate-not-applicable|other",
  "localPriority": "none|low|medium|high|urgent",
  "ownerLabel": "string",
  "dueAt": "ISO timestamp | null",
  "startedAt": "ISO timestamp | null",
  "completedAt": "ISO timestamp | null",
  "validationStatus": "not-started|pending|passed-locally|failed-locally|inconclusive|not-applicable",
  "linkedCveIds": ["CVE-..."],
  "linkedAssetIds": ["..."],
  "linkedComponentIds": ["..."],
  "linkedCorrelationIds": ["..."],
  "linkedInventoryIds": ["..."],
  "tags": ["..."],
  "createdAt": "ISO timestamp",
  "updatedAt": "ISO timestamp",
  "revision": 1,
  "mutationId": "m-...",
  "archived": false
}
```

### Plan bounds (REMEDIATION_LIMITS)

| Field | Cap |
| --- | --- |
| plan title | 200 chars |
| plan description / notes | 8 000 chars |
| owner label | 120 chars |
| tags | 20 items, 40 chars each |
| linked CVEs | 500 |
| linked assets | 500 |
| linked components | 5 000 |
| linked correlations | 5 000 |
| linked inventories | 500 |
| plans per browser | 50 000 (warning at 5 000) |

## Task schema (1.0.0)

```json
{
  "schemaVersion": "1.0.0",
  "taskId": "task-...",
  "planId": "plan-...",
  "title": "...",
  "description": "...",
  "status": "todo|in-progress|blocked|done|skipped",
  "ownerLabel": "...",
  "dueAt": "ISO timestamp | null",
  "completedAt": "ISO timestamp | null",
  "order": 0,
  "blockerReason": "...",
  "createdAt": "...",
  "updatedAt": "...",
  "revision": 1,
  "mutationId": "..."
}
```

* Max 500 tasks per plan.
* `completedAt` is set when the task reaches `done` and
  cleared when the task is reopened.
* Reordering rewrites every task's `order` and appends a
  single `task-updated` event with the task count in
  `targetIds`.

## Evidence schema (1.0.0)

```json
{
  "schemaVersion": "1.0.0",
  "evidenceId": "ev-...",
  "planId": "plan-...",
  "taskId": "task-... | null",
  "evidenceType": "local-note|local-file-fingerprint|inventory-snapshot-reference|correlation-snapshot-reference|report-reference|validation-result|change-ticket-reference|external-reference|other",
  "title": "...",
  "description": "...",
  "capturedAt": "...",
  "sourceLabel": "...",
  "externalUrl": "https://... | null",
  "linkedInventoryId": "...",
  "linkedCorrelationId": "...",
  "linkedReportId": "...",
  "fileFingerprint": {
    "fileName": "...",
    "sizeBytes": 1,
    "mimeType": "...",
    "lastModified": 0,
    "checksum": "sha256:..."
  } | null,
  "validationOutcome": "not-applicable|passed-locally|failed-locally|inconclusive | null",
  "supersedesEvidenceId": "ev-... | null",
  "createdAt": "...",
  "revision": 1,
  "mutationId": "..."
}
```

* Max 2 000 evidence records per plan.
* `externalUrl` is restricted to `https://` / `http://`
  schemes (no `javascript:`, `data:`, `file:`).
* `fileFingerprint.checksum` must match
  `^sha256:[0-9a-f]{64}$`.
* File content is **never** stored. The dialog only
  records the file name, size, MIME, optional
  `lastModified`, and SHA-256.
* Max 25 MiB per fingerprint input.

## Activity ledger schema (1.0.0)

```json
{
  "ledgerSchemaVersion": "1.0.0",
  "eventId": "evt-...",
  "planId": "plan-...",
  "sequence": 0,
  "eventType": "plan-created|plan-updated|status-changed|task-created|task-updated|task-completed|task-reopened|evidence-added|evidence-superseded|validation-recorded|...",
  "occurredAt": "...",
  "actorLabel": "...",
  "summary": "...",
  "targetIds": { "...": "..." },
  "previousEventHash": "sha256:... | null",
  "eventHash": "sha256:..."
}
```

### Hash rule

`eventHash = sha256:` + lowercase hex of canonical JSON
of the event with `eventHash` stripped (replaced with
`sha256:__pending__` for the digest input).

`previousEventHash` is `null` for the genesis event
(sequence 0) and equals the prior event's `eventHash`
otherwise. Sequences are contiguous.

### What the chain detects

* Modified events (event-hash mismatch).
* Missing events (sequence gap).
* Reordered events (previous-hash mismatch).
* Inserted events (sequence gap).

### What the chain does **not** prove

* Authorship or identity.
* A trusted timestamp.
* Legal authenticity.
* That the events were not subsequently rewritten by
  an attacker with write access to the same browser
  profile.

The chain is a **local tamper-evident audit log** that
lets the operator detect a change that happened to their
own local store.

## Lifecycle state machine

| From | Allowed transitions |
| --- | --- |
| `draft` | `planned`, `in-progress`, `deferred`, `cancelled` |
| `planned` | `in-progress`, `blocked`, `deferred`, `cancelled`, `draft` |
| `in-progress` | `blocked`, `validation-pending`, `completed`, `deferred`, `cancelled`, `accepted-risk` |
| `blocked` | `in-progress`, `deferred`, `cancelled`, `draft` |
| `validation-pending` | `in-progress`, `completed`, `deferred`, `cancelled`, `accepted-risk` |
| `completed` | `in-progress`, `accepted-risk` |
| `accepted-risk` | `in-progress`, `deferred`, `cancelled` |
| `deferred` | `in-progress`, `draft`, `planned`, `cancelled` |
| `cancelled` | `draft`, `planned` |

Notes:

* `validation-pending → failed-locally` is **not** a
  direct transition. A failed local validation re-enters
  `in-progress` so the operator can update tasks /
  evidence.
* `completed` may be reopened to `in-progress` or
  `accepted-risk`. The reopen appends a `plan-updated`
  or `status-changed` event; the original completion is
  preserved in the ledger.
* `accepted-risk` is a local workflow statement. The UI
  always surfaces a free-text rationale field. The
  statement does **not** represent external approval,
  compliance, or policy acceptance.
* Overdue is a **derived display state** from
  `dueAt < now` and the current status. It never
  automatically mutates the plan status.

## Local storage

* IndexedDB database `threatpulse-remediation` v1 with
  five stores: `plans`, `tasks`, `evidence`, `ledger`,
  `meta`.
* BroadcastChannel `threatpulse:remediation:events` for
  multi-tab sync (separate from the V6.6
  `threatpulse:environment:events` channel).
* A session-only in-memory adapter is used by the test
  runner and as a documented fallback when IndexedDB
  is unavailable.
* An `UnavailableRemediationAdapter` is exposed as a
  no-op when neither storage option is supported.
* The storage layer never uses `localStorage` for plan /
  task / evidence / ledger data.

## Atomic plan + ledger commit

Every plan, task, and evidence mutation produces a
matching ledger event in the same IndexedDB transaction
via `transaction.createPlanWithGenesisEvent` (atomic
plan + sequence-0 genesis) or
`transaction.appendFollowupEvent` (reads chain tail,
computes next sequence and `previousEventHash`, commits
new event).

A failed transaction appends no event. A
`status-changed` event is emitted when `updatePlan` sees
a `patch.status` different from the current value;
otherwise a `plan-updated` event is emitted.

## Local file fingerprinting

* Implemented as a Web Worker (`fingerprint.worker.mjs`)
  that uses `crypto.subtle.digest("SHA-256", bytes)`
  only. No `node:crypto`, no `sha256Node` chunk in the
  browser build.
* Chunked at 1 MiB with `setTimeout` yields so the
  progress event fires and cancellation can be
  processed.
* Cancellation resolves the pending result with reason
  `cancelled`. Stale results are rejected via a
  generation counter so a slow file cannot overwrite a
  newer fingerprint.
* Max 25 MiB; a `file-too-large` reason is returned
  before any byte is read.
* `verifyOutcome` is one of `matches` / `differs` /
  `cancelled` and is never described as proof of
  authorship or authenticity.

## Export / import format

```json
{
  "format": "threatpulse-local-remediation",
  "schemaVersion": "1.0.0",
  "kind": "plan | full",
  "exportedAt": "ISO timestamp",
  "applicationVersion": "...",
  "planId": "plan-... (kind=plan only)",
  "plans": { "planId": { ... } },
  "tasks": { "planId": { "taskId": { ... } } },
  "evidence": { "planId": { "evidenceId": { ... } } },
  "ledgerEvents": { "planId": [ { ... } ] },
  "checksum": "sha256:..."
}
```

* `checksum` is computed with Web Crypto SHA-256 over
  the canonical JSON of the body (everything except
  `checksum`).
* Import validates:
  * `format`, `schemaVersion`, `kind`, `checksum` shape
  * per-plan / per-task / per-evidence schema validity
  * every per-plan ledger chain via `verifyChain`
  * prototype-pollution keys are rejected
  * size ≤ 25 MiB
  * unsupported `schemaVersion` is rejected
  * same `eventId` with a different `eventHash` is a
    hard import failure (`ledger-conflict`)

## Report integration boundary (V6.5 compatibility)

V6.7 does **not** modify the V6.5 report contract.
A new optional `localRemediationSummary` field is
added to the snapshot and is **excluded by default**.

When the operator opts in (a single checkbox in the
report builder), the snapshot carries counts only:

```json
{
  "schemaVersion": "1.0.0",
  "activePlanCount": 0,
  "draftPlanCount": 0,
  "blockedPlanCount": 0,
  "overduePlanCount": 0,
  "validationPendingCount": 0,
  "completedLocalCount": 0,
  "acceptedRiskCount": 0,
  "archivedPlanCount": 0,
  "brokenLedgerCount": 0
}
```

The summary **never** contains:

* owner labels
* plan descriptions / titles
* task titles / descriptions / blocker reasons
* evidence descriptions / filenames / fingerprints
* validation notes
* actor labels
* complete ledger events

The public CSV (21 columns) is unchanged.

## Failure states handled

* IndexedDB unavailable
* Session-only mode (in-memory adapter with
  `data will not survive a tab close` warning)
* Quota exceeded
* Blocked database
* Database deleted externally
* Transaction aborted
* Multi-tab conflict
* Unsupported status transition
* Pending write failure
* Web Crypto unavailable
* File too large (> 25 MiB)
* Fingerprint cancelled
* Fingerprint mismatch
* Invalid external URL scheme
* Broken ledger chain
* Corrupt remediation import
* Future schema
* Merge conflict (same `eventId` with a different
  `eventHash`)
* Failed atomic promotion
* Selected CVE / asset / component no longer exists
* Public intelligence unavailable
* Inventory snapshot changed
* Validation became stale
* Export download blocked

## Accessibility

* Keyboard operation for every form
* Status not communicated by colour only — every
  status pill carries a text label and a tooltip
* Dialogs trap and restore focus
* Live-region announcements for hashing progress and
  validation errors
* Long identifiers wrap
* `prefers-reduced-motion` respected

## What V6.7 does **not** do

* Touch the network from any UI flow
* Write to the URL or `history`
* Log private values to the console
* Mutate the public dataset
* Call `dangerouslySetInnerHTML`
* Auto-fetch external references
* Auto-preview active content
* Claim local completion is external verification
* Claim local fingerprints prove authorship
* Run `process.exit(0)` (see V6.6 lesson)
* Depend on `node:crypto` from any browser-reachable
  module
* Use `localStorage` for plan / task / evidence / ledger
  data
