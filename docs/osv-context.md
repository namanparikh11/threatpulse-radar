# V6.1 — OSV Context

The OSV section in the DetailDrawer renders the bounded
per-CVE public OSV projection. The data is fetched on
drawer open via the dataset function's `view=osv` query
mode and attached to `vuln.osv`.

## What the section shows

For each OSV record correlated to the selected CVE:

- **OSV id** (linked to the official OSV.dev record).
- **Ecosystem** (e.g. GHSA, PYSEC, GO, RUSTSEC, OSV-DEV).
- **Aliases** (capped at 5 displayed + overflow indicator).
- **Modified** timestamp.
- **Status** (Active or Withdrawn).
- **Affected packages** with provider-native range events
  (ECOSYSTEM, SEMVER, GIT, RANGE) rendered verbatim in a
  `<code>` block. No re-parse, no GitHub-OSV range
  synthesis.
- **First fixed** field. When an OSV range ends in
  `{fixed: 'X.Y.Z'}`, the field shows that version. When
  the range ends in `{last_affected: 'X.Y.Z'}` only, the
  field shows "unavailable (last affected: X.Y.Z)". When
  no fixed event is present, the field shows "unavailable".

## Honest empty state

The locked copy is:

> No OSV record is currently available in this ThreatPulse snapshot.

The copy refers to "this ThreatPulse snapshot" — the
public tracked universe at the current public-
intelligence version. It does NOT claim global absence
("not in OSV" is forbidden). The drawer does NOT say
"no fix" or "not vulnerable".

## Per-record field caps (all per CVE; deterministic)

| Field | Cap | Truncation field |
| --- | --- | --- |
| OSV records per CVE | 8 | `truncation.recordsRemoved` |
| Aliases per record | 10 | `truncation.aliasesRemoved` |
| References per record | 5 | `truncation.referencesRemoved` |
| Affected packages per record | 6 | `truncation.packagesRemoved` |
| Ranges per package | 4 | `truncation.rangesRemoved` |
| Events per range | 8 | `truncation.eventsTruncated` |
| Versions per package | 8 | `truncation.versionsRemoved` |
| Primitive pairs in `ecosystemSpecific` / `databaseSpecific` | 32 | (dropped silently) |

Cap overflow is reported via the `truncation` block.
The drawer surfaces a "Package list truncated. See the
official OSV record for the complete list." sub-line
when a CVE has more than 8 OSV records, more than 5
displayed aliases + overflow, or more than the documented
cap on any other field.

## Determinism

- `records` sorted by `(sourceDatabase, osvId)` ascending.
- Within each record, `aliases` and `references` are
  sorted lex; references are also ordered by
  `ADVISORY > REPORT > FIX > PACKAGE > WEB > ARTICLE > EVIDENCE > other`.
- Within each package, `versions` and `events` are in the
  order OSV provides them.
- Deterministic 16-bucket partition by
  `cveBucketNormalized(cveId)` = first hex char of
  `SHA-256(cveId)`.

## Security

- `osvUrl` is constructed as
  `https://osv.dev/vulnerability/${encodeURIComponent(osvId)}`.
  The `osvId` is validated against
  `/^[A-Za-z0-9._-]{1,128}$/` before URL construction.
- The link is rendered as
  `<a target="_blank" rel="noopener noreferrer">`.
- The browser never fetches `osv.dev`, `api.osv.dev`, or
  `osv-vulnerabilities.storage.googleapis.com` directly.
- The drawer reads only the per-CVE OSV shard by its
  content-addressed key. The shard is read by the
  server-side `view=osv` query mode, never by the
  browser.

## What the section is NOT

- The section does NOT combine GitHub Advisory and OSV
  into a synthetic "package remediation" view. The two
  sources are rendered in separate drawer sections.
- The section does NOT convert GitHub ranges into OSV
  ranges. Each source's range notation is preserved
  verbatim.
- The section does NOT add a new table column, header
  pill, or combined score.
- The section does NOT silently discard truncated
  records; the truncation is reported.

## Drawer ordering

The drawer renders context sections in this order:

1. CISA decision context (SSVC) — existing.
2. Package remediation context (GitHub Advisory) — existing.
3. **OSV package context** — new.
4. External references — existing.
