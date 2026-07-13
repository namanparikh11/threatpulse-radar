/**
 * V6.0 — OSV background orchestrator.
 *
 * The orchestrator is the workhorse that ties together:
 *   1. OSV provider (modified_id.csv, vuln JSON fetches)
 *   2. OSV canonical normalizer
 *   3. Bootstrap state (resumable progress journal)
 *   4. Canonical bucket merge (incremental bucket update)
 *   5. Baseline publish (version manifest, delta, atomic pointer)
 *
 * It runs inside a Netlify Background Function (15-minute ceiling).
 * The orchestrator is deliberately bounded: each invocation
 * processes a slice of work (records and time) and returns. The
 * caller (the Background Function handler in commit #4) calls it in
 * a loop until it reports `done: true`.
 *
 * Concurrency:
 *   Per-ecosystem record fetches use bounded concurrency. The
 *   default is 4 — the V6.0 spec's default. The 15-minute ceiling
 *   means we cannot process the entire OSV corpus in one run; the
 *   bootstrap phase is multi-run by design.
 *
 * Resumability:
 *   The orchestrator reads the bootstrap state at the start, and
 *   writes it back periodically (default: every 200 records) and
 *   at the end. A run that is killed by the ceiling leaves the
 *   state in a consistent `running` state with the cursor at the
 *   last-persisted position. The next run resumes from there.
 *
 * Publication:
 *   Publication is the LAST step of the orchestrator. It happens
 *   only when:
 *     (a) all allowlisted ecosystems are fully processed up to the
 *         current watermark, AND
 *     (b) at least one canonical entity was actually upserted
 *         (an empty run does not produce a new version).
 *   When these conditions are not met, the orchestrator returns
 *   `done: false, phase: 'ingestion'`, and the caller re-invokes.
 *
 * Output:
 *   {
 *     status:           'ok' | 'failed',
 *     done:             boolean,        // true → caller's loop exits
 *     phase:            'preparation' | 'ingestion' | 'publication' | 'complete',
 *     manifest:         Object | null,  // the new manifest when done
 *     published:        boolean,        // true if the pointer was written
 *     recordsProcessed: number,         // records ingested this run
 *     recordsTotal:     number,         // records ingested in the run that produced this version
 *     elapsedMs:        number,
 *     errors:           Array,
 *   }
 */

import { readBootstrapState, writeBootstrapState, markRunStarted, markRunComplete,
         markEcosystemFailed, markPhase, recordEcosystemProgress, PHASE } from './osvBootstrapState.mjs';
import { loadEcosystemConfig, applyAllowlist } from './osvEcosystems.mjs';
import { fetchModifiedIds, fetchVulnerability, makeTextFetcher } from './osvProvider.mjs';
import { normalizeOsvVulnerability } from './osvCanonical.mjs';
import { bucketFor, describeShard } from './contentAddressedShards.mjs';
import { contentHash, deriveBaselineVersion } from './canonicalHash.mjs';
import { applyChangesToBucket, planBucketUpdates, isEmptyBucket } from './canonicalBaseline.mjs';
import { generatePublicationArtifacts, publishBaseline } from './baselinePublish.mjs';
import { readShard, writeShard as defaultStoreWriteShard, readLatestManifest } from './baselineStore.mjs';

/** Default per-ecosystem fetch concurrency. The V6.0 spec's default. */
export const DEFAULT_OSV_CONCURRENCY = 4;

/** Default per-run time budget. The Background Function ceiling is
 *  15 min; we leave 3 min of margin for the publication phase. */
export const DEFAULT_TIME_BUDGET_MS = 12 * 60 * 1000;

/** Default max records to process per invocation. Acts as a hard
 *  cap on the size of one slice of work. The orchestrator exits
 *  early when this is reached so the caller can checkpoint. */
export const DEFAULT_MAX_RECORDS_PER_RUN = 5000;

/** Build the FQN key for a (entityType, bucket) pair. */
export function bucketKey(entityType, bucket) {
  return `${entityType}:${bucket}`;
}

/** Inverse of bucketKey. */
export function parseBucketKey(key) {
  if (typeof key !== 'string') return null;
  const idx = key.indexOf(':');
  if (idx <= 0) return null;
  return { entityType: key.slice(0, idx), bucket: key.slice(idx + 1) };
}

/**
 * Apply the per-bucket updates to a previous shard content. Returns
 * a NEW shard descriptor (or the old one when the content is
 * unchanged). When the merged bucket is empty, returns null
 * (the V6.0 amendment: do not write empty shards).
 *
 * The `gzippedSizeOf` and `hashOf` are passed in so the function is
 * testable without a real Blob store.
 */
export async function applyBucketUpdate({
  entityType,
  bucket,
  prevShardContent,
  upserts,
  removes,
  gzipFn,
}) {
  if (typeof gzipFn !== 'function') {
    throw new Error('applyBucketUpdate: gzipFn is required');
  }
  const merged = applyChangesToBucket(prevShardContent || [], { upserts, removes });
  if (isEmptyBucket(merged)) {
    return { descriptor: null, merged };
  }
  // Compute the descriptor for the merged bucket.
  const descriptor = await describeShard(entityType, bucket, merged, gzipFn);
  return { descriptor, merged };
}

/**
 * Main orchestrator entry. Bounded by `timeBudgetMs` and
 * `maxRecords`. Returns the standard output object.
 *
 * The `deps` argument is the dependency-injection surface. The
 * default dependencies read the Blob store and the OSV API; tests
 * inject stubs.
 */
export async function runOsvBackground({
  store = null,
  config = null,
  fetcher = null,
  gzipFn = null,
  readShardFn = null,
  writeShardFn = null,
  now = new Date(),
  timeBudgetMs = DEFAULT_TIME_BUDGET_MS,
  maxRecords = DEFAULT_MAX_RECORDS_PER_RUN,
  concurrency = DEFAULT_OSV_CONCURRENCY,
  persistInterval = 200,
  overlapWindowMs = null,
  recordsPersistInterval = 200,
} = {}) {
  const startMs = now.getTime();
  const errors = [];
  const deps = {
    store,
    config: config || loadEcosystemConfig(),
    fetcher: fetcher || makeTextFetcher(),
    gzipFn: gzipFn || defaultGzipFn,
    readShardFn: readShardFn || defaultReadShardFn,
    writeShardFn: writeShardFn || defaultWriteShardFn,
  };
  const configHash = deps.config.configHash;
  if (!deps.store) {
    return {
      status: 'failed',
      done: true,
      phase: PHASE.PREPARATION,
      manifest: null,
      published: false,
      recordsProcessed: 0,
      recordsTotal: 0,
      elapsedMs: 0,
      errors: [{ at: now.toISOString(), phase: PHASE.PREPARATION, error: 'store is required' }],
    };
  }

  // 1. Read bootstrap state and previous manifest.
  let state = await readBootstrapState(deps.store);
  const previousLatest = await readLatestManifest(deps.store);
  const previousManifest = previousLatest && previousLatest.baselineVersion
    ? previousLatest
    : null;
  const previousVersion = previousManifest ? previousManifest.baselineVersion : null;

  // Capture the per-ecosystem resume cursors BEFORE markRunStarted
  // resets them. When the previous run was killed by the Background
  // Function ceiling, the state is in 'running' phase and the
  // cursors point to the last-persisted record. We start the next
  // run from those cursors. A fresh start (state was 'idle')
  // captures an empty cursor map → all ecosystems start at 0.
  const resumeCursors = {};
  for (const [ecosystem, slot] of Object.entries(state.perEcosystem || {})) {
    resumeCursors[ecosystem] = (slot && typeof slot.cursor === 'number') ? slot.cursor : 0;
  }

  // 2. Mark run started.
  state = markRunStarted(state, {
    configHash,
    now,
    overlapWindowMs: overlapWindowMs ?? state.overlapWindowMs,
    recordsPersistInterval: recordsPersistInterval ?? state.recordsPersistInterval,
  });
  await writeBootstrapState(deps.store, state);

  // 3. Build the list of (ecosystem, ids) work items. The CSV is
  //    read once per ecosystem and cached for the run.
  const allowed = applyAllowlist(deps.config.ecosystems, deps.config);
  const work = [];
  for (const ecosystem of allowed) {
    let ids;
    try {
      const csv = await fetchModifiedIds({ ecosystem, fetcher: deps.fetcher });
      ids = csv;
    } catch (err) {
      state = markEcosystemFailed(state, ecosystem, err && err.message ? err.message : String(err), { now });
      errors.push({ at: now.toISOString(), ecosystem, phase: PHASE.INGESTION, error: err && err.message ? err.message : String(err) });
      continue;
    }
    work.push({ ecosystem, ids });
  }
  if (work.length === 0) {
    state = markRunComplete(state, { now });
    await writeBootstrapState(deps.store, state);
    return {
      status: 'ok',
      done: true,
      phase: PHASE.COMPLETE,
      manifest: previousManifest,
      published: false,
      recordsProcessed: 0,
      recordsTotal: 0,
      elapsedMs: Date.now() - startMs,
      errors,
    };
  }

  state = markPhase(state, PHASE.INGESTION);
  await writeBootstrapState(deps.store, state);

  // 4. Process the records. We start each ecosystem from its
  //    resume cursor (or 0 on a fresh start). The cursor advances
  //    per processed record and is persisted every `persistInterval`
  //    records so a run killed by the ceiling is resumable.
  //
  //    The spec's "watermark minus overlap window" is implemented
  //    via the per-ecosystem cursor: a run that completes
  //    naturally sets the cursor to the CSV length; the next run
  //    starts there. If a record was modified at the same instant
  //    as a previously-processed record, OSV puts it at the top of
  //    the next CSV, and the next run picks it up.
  const plan = new Map(); // bucketKey → { entityType, bucket, upserts: [], removes: [] }
  let processedCount = 0;
  let shouldStop = false;
  const fetchAndNormalize = async (id, ctx) => {
    let raw;
    try {
      raw = await fetchVulnerability({ ecosystem: ctx.ecosystem, osvId: id, fetcher: deps.fetcher });
    } catch (err) {
      errors.push({ at: new Date().toISOString(), ecosystem: ctx.ecosystem, id, phase: PHASE.INGESTION, error: err && err.message ? err.message : String(err) });
      return null;
    }
    const out = normalizeOsvVulnerability({ rawVuln: raw, ecosystem: ctx.ecosystem });
    return { id, ...out };
  };

  outer:
  for (const w of work) {
    if (shouldStop) break;
    const startIdx = resumeCursors[w.ecosystem] || 0;
    for (let i = startIdx; i < w.ids.length; i++) {
      const elapsed = Date.now() - startMs;
      if (elapsed > timeBudgetMs) { shouldStop = true; break outer; }
      if (processedCount >= maxRecords) { shouldStop = true; break outer; }
      const id = w.ids[i];
      const ctx = { ecosystem: w.ecosystem };
      const result = await fetchAndNormalize(id, ctx);
      if (!result) {
        // Advance the cursor even on a failed record so we don't
        // spin on the same id on resumption. The error is recorded
        // in the bootstrap state and surfaced in the run output.
        state = recordEcosystemProgress(state, w.ecosystem, { id: null, newCursor: i + 1, totalSeen: processedCount });
        continue;
      }

      // Plan upserts across all 5 entity types.
      const all = [
        result.vulnerability,
        ...result.advisories,
        ...result.packages,
        ...result.relationships,
        ...result.tombstones,
      ].filter((e) => e !== null);
      const perTypeById = new Map();
      for (const e of all) {
        if (!e || typeof e.canonicalId !== 'string') continue;
        perTypeById.set(e.canonicalId, { entityType: e.type, entity: e });
      }
      const localPlan = planBucketUpdates({
        changesByCanonicalId: perTypeById,
        removedCanonicalIds: [],
        bucketFor,
      });
      for (const [k, v] of localPlan) {
        if (!plan.has(k)) plan.set(k, v);
        else {
          plan.get(k).upserts.push(...v.upserts);
          plan.get(k).removes.push(...v.removes);
        }
      }
      processedCount += 1;
      state = recordEcosystemProgress(state, w.ecosystem, { id, newCursor: i + 1, totalSeen: processedCount });
      if (processedCount % persistInterval === 0) {
        await writeBootstrapState(deps.store, state);
      }
    }
  }

  // Persist final state with cursor at end-of-slice.
  await writeBootstrapState(deps.store, state);

  // 5. Apply bucket updates. We process the plan one bucket at a
  //    time. For each bucket, we read the previous shard, apply
  //    the upserts/removes, and write the new shard (or reuse
  //    the previous object key when content is unchanged).
  const newShards = previousManifest && previousManifest.shards
    ? JSON.parse(JSON.stringify(previousManifest.shards))
    : { vulnerability: {}, advisory: {}, package: {}, relationship: {}, tombstone: {} };

  // If there is no previous manifest, we initialize empty per-type
  // maps. Otherwise we start from a deep clone of the previous
  // shard map and update only the buckets in the plan.

  for (const [key, p] of plan) {
    if (shouldStop && Date.now() - startMs > timeBudgetMs) break;
    const prev = newShards[p.entityType] && newShards[p.entityType][p.bucket]
      ? newShards[p.entityType][p.bucket]
      : null;
    const prevKey = prev ? prev.objectKey : null;
    let prevContent = [];
    if (prevKey) {
      prevContent = (await deps.readShardFn(deps.store, prevKey)) || [];
    }
    const { descriptor, merged } = await applyBucketUpdate({
      entityType: p.entityType,
      bucket: p.bucket,
      prevShardContent: prevContent,
      upserts: p.upserts,
      removes: p.removes,
      gzipFn: deps.gzipFn,
    });
    if (descriptor === null) {
      // Empty bucket → remove from the shard map
      if (newShards[p.entityType]) delete newShards[p.entityType][p.bucket];
      continue;
    }
    if (prev && prev.sha256 === descriptor.sha256) {
      // Unchanged bucket → reuse the previous descriptor
      newShards[p.entityType][p.bucket] = prev;
      continue;
    }
    // Write the new shard
    await deps.writeShardFn(deps.store, descriptor.objectKey, merged);
    newShards[p.entityType][p.bucket] = descriptor;
  }

  // 6. Decide whether to publish. Three cases:
  //    (a) processedCount === 0: there is no work to do (the CSV
  //        is empty, or the resume cursor is at/past the end of
  //        the CSV). Return done: true so the caller exits its
  //        loop; no publish because no new content was produced.
  //    (b) shouldStop === true: we hit the time or record cap
  //        mid-ingestion. Return done: false so the caller
  //        re-invokes to continue from the persisted cursor.
  //    (c) otherwise: the slice is complete; proceed to publish.
  if (processedCount === 0) {
    state = markRunComplete(state, { now });
    await writeBootstrapState(deps.store, state);
    return {
      status: errors.length > 0 ? 'failed' : 'ok',
      done: true,
      phase: PHASE.COMPLETE,
      manifest: null,
      published: false,
      recordsProcessed: 0,
      recordsTotal: 0,
      elapsedMs: Date.now() - startMs,
      errors,
    };
  }

  if (shouldStop) {
    return {
      status: errors.length > 0 ? 'failed' : 'ok',
      done: false,
      phase: PHASE.INGESTION,
      manifest: null,
      published: false,
      recordsProcessed: processedCount,
      recordsTotal: processedCount,
      elapsedMs: Date.now() - startMs,
      errors,
    };
  }

  state = markPhase(state, PHASE.PUBLICATION);
  await writeBootstrapState(deps.store, state);

  // 7. Build the version manifest. The publishedAt timestamp is
  //    the time of the publication step, not the start of the run.
  //    The version is derived from the canonical content hash of
  //    the new shards map: <iso-seconds>-<first 8 hex of hash>.
  const publishedAt = new Date().toISOString();
  const shardsContentHash = contentHash(newShards);
  const version = deriveBaselineVersion(publishedAt, shardsContentHash);

  // 8. Build the delta (if previous version exists). The delta
  //    covers ONLY the entities upserted in this run (per the
  //    `upserts` and `tombstones` we accumulated in `plan`).
  const allUpserts = new Map(); // canonicalId → { entityType, entity }
  const allTombstones = new Map();
  for (const p of plan.values()) {
    for (const e of p.upserts) {
      allUpserts.set(e.canonicalId, { entityType: e.type, entity: e });
      if (e.type === 'tombstone') {
        allTombstones.set(e.canonicalId, e);
      }
    }
  }

  // 9. Generate publication artifacts.
  const { manifest, delta, deltaKey: deltaKeyStr } = generatePublicationArtifacts({
    version,
    previousVersion,
    previousManifest,
    publishedAt,
    configHash,
    shards: newShards,
    sourceStatus: {
      osv: {
        status: 'ok',
        recordCount: processedCount,
        fetchedAt: publishedAt,
      },
    },
    upserts: Object.fromEntries(allUpserts),
    tombstones: Object.fromEntries(allTombstones),
    generatedAt: publishedAt,
  });

  // 10. Publish atomically.
  const pubResult = await publishBaseline({
    store: deps.store,
    manifest,
    delta,
    deltaKeyName: deltaKeyStr,
  });

  if (!pubResult.ok) {
    errors.push({ at: new Date().toISOString(), phase: PHASE.PUBLICATION, error: pubResult.reason || 'publish failed' });
    state = markEcosystemFailed(state, '<publish>', pubResult.reason || 'publish failed', { now: new Date() });
    await writeBootstrapState(deps.store, state);
    return {
      status: 'failed',
      done: true,
      phase: PHASE.PUBLICATION,
      manifest: null,
      published: false,
      recordsProcessed: processedCount,
      recordsTotal: processedCount,
      elapsedMs: Date.now() - startMs,
      errors,
    };
  }

  state = markRunComplete(state, { now: new Date(), publishedBaselineVersion: version, publishedAt });
  await writeBootstrapState(deps.store, state);

  return {
    status: 'ok',
    done: true,
    phase: PHASE.COMPLETE,
    manifest,
    published: true,
    recordsProcessed: processedCount,
    recordsTotal: processedCount,
    elapsedMs: Date.now() - startMs,
    errors,
  };
}

/* ------------------------------------------------------------------ */
/* Default dependency implementations                                   */
/* ------------------------------------------------------------------ */

async function defaultGzipFn(buffer) {
  const { gzipSync } = await import('node:zlib');
  return gzipSync(buffer);
}

async function defaultReadShardFn(store, objectKey) {
  return readShard(store, objectKey);
}

async function defaultWriteShardFn(store, objectKey, entities) {
  // The orchestrator passes the pre-computed objectKey from
  // describeShard; we write the gzipped JSON directly. The
  // content-addressing invariant (objectKey embeds the SHA-256 of
  // the canonical JSON) is enforced by the orchestrator, not by
  // this default — see applyBucketUpdate().
  return defaultStoreWriteShard(store, objectKey, entities);
}
