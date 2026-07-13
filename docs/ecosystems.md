# V6.0 — OSV ecosystem allowlist

The V6.0 OSV ingestion pipeline reads from a fixed set of OSV
ecosystems. The list is the source of truth for what the
canonical baseline contains. This document covers the
ecosystem list, where it lives, how to change it, and the
operational consequences of changing it.

## The default allowlist

The default allowlist lives in
[`config/osv-ecosystems.json`](../../config/osv-ecosystems.json):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "schemaVersion": "1.0.0",
  "ecosystems": [
    "npm", "PyPI", "Go", "Maven", "crates.io",
    "RubyGems", "Packagist", "NuGet", "Hex", "Pub"
  ]
}
```

These are the ten ecosystems that OSV's per-ecosystem GCS
buckets serve. The list is informed by OSV's official
ecosystems list and is meant to be a reasonable default for
"everything most product-security teams care about."

## Where the list lives

The list has two sources of truth, in this order of
precedence:

1. **Server-side env var** (optional override):
   `THREATPULSE_OSV_ECOSYSTEMS` is a JSON string with the
   same shape as the file. When set and well-formed, the env
   var wins.
2. **Source-controlled file** (default):
   `config/osv-ecosystems.json` is the source of truth for
   the version that ships with each deploy.

The orchestrator's `loadEcosystemConfig()` reads in this
order. If the env var is malformed, it falls back to the
file. If the file is missing, it falls back to a single
ecosystem (`npm`) so the build does not crash in a
malformed local dev environment. The fallback is deliberately
limited; an operator who wants more ecosystems must fix the
file or set the env var.

## The configHash

The orchestrator computes a `configHash` — `sha256:<hex>` of
the canonical JSON of the resolved config — and writes it to
the bootstrap state. The hash is included in every
published manifest's `configHash` field, so a consumer can
verify which ecosystems were active when a given version was
built.

A change to the ecosystem list changes the `configHash` and
shows up in the next published version's `configHash`. A
consumer that wants to filter by ecosystem can do so; the
ecosystem is in the package entity's `ecosystem` field.

## How to add an ecosystem

1. Edit `config/osv-ecosystems.json` and add the OSV
   ecosystem name to the `ecosystems` array.
2. Verify the name matches an OSV ecosystem prefix at
   `https://osv-vulnerabilities.storage.googleapis.com/`. The
   per-ecosystem directory is named exactly as the
   ecosystem appears in the allowlist.
3. Commit and deploy. The next run uses the new list.

The OSV ecosystem names are case-sensitive. `npm` is correct;
`NPM` is not. The full official list is at
https://github.com/google/osv.dev/blob/master/osv/ecosystems/ecosystems.txt
and the per-ecosystem GCS layout is documented at
https://google.github.io/osv.dev/post-v1-architecture/.

## How to remove an ecosystem

1. Edit `config/osv-ecosystems.json` and remove the entry.
2. Commit and deploy.

The next run stops fetching records from the removed
ecosystem. Existing records in the canonical baseline stay
in the Blob store (they are content-addressed, so removing
an ecosystem does not delete data). Consumers that
materialize the entire baseline will continue to see the
removed ecosystem's records until the next bootstrap.

If the goal is to actually REMOVE the data, the operator
must manually delete the affected shards from the Blob
store. There is no automated "prune" job in V6.0; the
publisher only adds and updates.

## Server-side override (env var)

The env var `THREATPULSE_OSV_ECOSYSTEMS` accepts the same
JSON shape as the file:

```bash
# Override to just npm and PyPI
export THREATPULSE_OSV_ECOSYSTEMS='{"schemaVersion":"1.0.0","ecosystems":["npm","PyPI"]}'
```

This is useful for:

- A staging environment that wants to test a smaller
  ecosystem list without modifying the file.
- A blue/green deploy where the green environment wants
  to onboard a new ecosystem before the blue.
- A site that wants to pin to a fixed subset and never
  ingest others, regardless of the file.

The env var wins over the file. The file is the source of
truth for the version that ships with the deploy; the env
var is the source of truth for the runtime config.

## Operational consequences of changing the list

Adding an ecosystem **grows the canonical baseline**. The
next run after adding a new ecosystem will fetch the entire
`modified_id.csv` for that ecosystem and start producing
new shards. Bootstrap is multi-run; expect several runs to
fully ingest a large new ecosystem. The bootstrap state
records the per-ecosystem cursor; the next run picks up
where the previous left off.

Removing an ecosystem **stops new ingestion** for that
ecosystem. Existing data stays. To remove the data, delete
the affected shards from the Blob store manually (or wait
for a future "prune" job that does not exist in V6.0).

The `configHash` changes with every edit to the resolved
config. Consumers that filter by `configHash` will see the
change. The change is additive: a consumer that ignores
`configHash` is unaffected.

## Schema

The allowlist is validated against a JSON Schema at
[`schemas/source-registry-v1.schema.json`](../../schemas/source-registry-v1.schema.json)
when the manifest is published. A malformed config is caught
at load time and falls back to the default; a config with
zero ecosystems is also caught (the loader returns null and
the orchestrator exits cleanly with no work to do).

## What is NOT in scope

- **Per-ecosystem rate limits.** All allowlisted ecosystems
  are fetched at the same `concurrency` (default 4). A
  future version may add per-ecosystem priorities.
- **Source fallbacks.** OSV is the only source in V6.0. A
  future version may add PYSEC, RustSec, Go Vuln DB,
  CERT, vendor advisories, and IOC providers.
- **Custom ecosystems.** The allowlist is a literal
  pass-through to the OSV per-ecosystem bucket name. A
  custom upstream would require a new provider module,
  not an ecosystem list change.
- **Differential ingestion.** A future version may add a
  "hot" subset of ecosystems that get more frequent
  refreshes than the rest. V6.0 ingests all ecosystems
  with the same hourly cadence.

## Quick reference

| What | Where |
| --- | --- |
| Default allowlist | `config/osv-ecosystems.json` |
| Runtime override | `THREATPULSE_OSV_ECOSYSTEMS` env var |
| Resolved config hash | written to `osv-bootstrap-state` Blob; also `manifest.configHash` |
| JSON Schema | `schemas/source-registry-v1.schema.json` |
| Loader module | `netlify/functions/_shared/osvEcosystems.mjs` |
| Tests | `scripts/acceptance-osv-ingestion.mjs` (search for "Ecosystem config loader") |

## Frequently asked questions

**Q. The list looks like it has every OSV ecosystem. Why
bother making it configurable?**
A. Some operators want a smaller set for cost or noise
reasons. A "critical-only" team might want just npm and
PyPI. A team in a regulated environment might want to pin
to a specific set and have it in version control.

**Q. Does adding an ecosystem invalidate consumer caches?**
A. No. The new ecosystem's records have new `canonicalId`s,
so they land in new buckets. Existing shards are reused
(unchanged content → same hash → same objectKey). A
consumer that materializes the entire baseline will pick
up the new shards on its next sync; a consumer that
filters by ecosystem list will see the new packages.

**Q. What if I add an ecosystem that doesn't exist in OSV?**
A. The orchestrator fetches `https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/modified_id.csv`
and gets a 404. The provider treats 404 as an empty
ecosystem (no records to process) and the run completes
without error. The bootstrap state's per-ecosystem slot
is initialized but stays empty.

**Q. What if I remove an ecosystem that's currently in the
bootstrap state?**
A. The orchestrator processes ecosystems in the order they
appear in the resolved config. Removed ecosystems are
skipped. The bootstrap state's slot for the removed
ecosystem is preserved (so an operator can see "we used
to process PyPI") until the next markRunStarted
overwrites the per-ecosystem map. The state is a journal;
old entries naturally roll forward.

**Q. Why is the env var name `THREATPULSE_OSV_ECOSYSTEMS`
and not `OSV_ECOSYSTEMS`?**
A. The `THREATPULSE_` prefix namespaces all V6.0+
environment variables so they don't collide with the V5.x
variables on the same Netlify site. The convention is
"any variable starting with `THREATPULSE_` is V6.0+ and
follows the V6.0 conventions."

**Q. Can I read the configHash without running the
publisher?**
A. Yes. The configHash is just `contentHash` of the
canonical config object. From a Node REPL:

```js
import { loadEcosystemConfig } from './netlify/functions/_shared/osvEcosystems.mjs';
const cfg = loadEcosystemConfig();
console.log(cfg.configHash);
// → sha256:abc123…
```

The hash is stable across processes that load the same
config. Two environments that resolve the same effective
allowlist produce the same `configHash`.
