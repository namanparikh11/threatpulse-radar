/**
 * V6.1 — Production publication chains.
 *
 * Wires the V6.1 public-intelligence publishers into the
 * V5.x / V6.0 refresh pipelines WITHOUT creating new
 * Netlify function entry files, schedules, or
 * Background Functions.
 *
 * Two chains are exposed:
 *
 *   runBaselinePublicationChain
 *     Runs the V6.0 OSV orchestrator and, on a
 *     SUCCESSFUL canonical baseline publication, invokes
 *     the V6.1 OSV public projection. On any structured
 *     failure (size ceiling, projection-unchanged skip,
 *     etc.) the canonical publication is preserved and
 *     the failure is logged as a sanitized warning. On
 *     any successful or unchanged projection, runs
 *     mark-and-sweep GC.
 *
 *   runDatasetPublicationChain
 *     After a successful main dataset write and both
 *     enrichment cache writes, invokes the V6.1
 *     dataset-bound public-intelligence publication.
 *     The chain reads the three envelopes back from
 *     their respective Blob stores and uses the
 *     precomputed per-Blob public hashes to compute the
 *     composite publicStateHash. On a structured skip or
 *     failure, the main refresh's 'completed' status is
 *     preserved and a sanitized warning is logged.
 *
 * Sanitization contract (all log lines):
 *   - Never include stack traces, Blob keys, raw hashes
 *     in user-visible fields, or provider response bodies.
 *   - Use the structured `reason` codes from the
 *     publisher result.
 *   - Field names are stable; values are bounded to
 *     short, descriptive strings.
 *
 * Locking contract:
 *   - Both chains are designed to be called from INSIDE
 *     the existing V6.0 / V5.x publication lock window
 *     (the canonical baseline background function holds
 *     the canonical lock; the dataset refresh holds the
 *     refresh lock).
 *   - The chains do NOT acquire a SECOND lock for the
 *     same resource — the V6.1 publishers do not have a
 *     publication lock in production; they rely on the
 *     outer V6.0 / V5.x lock.
 *   - The chains do not introduce nested lock waits or
 *     background invocations.
 *
 * The chains are pure: every I/O goes through the
 * provided `store` handles. The orchestrator / refresh
 * function and the V6.1 publisher share the same store
 * handles, so no resource contention is introduced.
 */

import { getStore } from '@netlify/blobs';
import { publishOsvProjection } from './osvProjectionPublish.mjs';
import { runOsvGc } from './osvProjectionGc.mjs';
import { publishDatasetBound } from './datasetBoundPublish.mjs';
import { readVulnrichmentCache, readGithubAdvisoryCache, readLatestDataset, writeVulnrichmentCache, writeGithubAdvisoryCache, writeLatestDataset, LATEST_DATASET_KEY, VULNRICHMENT_CACHE_KEY, GITHUB_ADVISORY_CACHE_KEY } from './store.mjs';
import {
  PUBLIC_INTELLIGENCE_STORE_NAME,
  getPublicIntelligenceStore,
  readJson,
  OSV_LATEST_KEY,
  DATASET_LATEST_KEY,
} from './publicIntelligenceStore.mjs';
import { gunzipSync } from 'node:zlib';
import { readShard as defaultReadShard, readLatestManifest } from './baselineStore.mjs';
import { runOsvBackground } from './osvBackground.mjs';
import { computeEnrichmentPublicHash, computeDatasetPublicHash, stripForPublicHash, computePublicHash } from './publicIntelligenceHash.mjs';
import { canonicalizeToString } from './canonicalHash.mjs';

/* ---- Helpers ---- */

const LOG_PREFIX_BASELINE = '[v6.1 baseline chain]';
const LOG_PREFIX_DATASET = '[v6.1 dataset chain]';

/**
 * Read a raw cache envelope from the Blob store,
 * preserving all fields (including the precomputed
 * public hash, if present). The
 * `readVulnrichmentCache` / `readGithubAdvisoryCache`
 * helpers strip the envelope down to `{records,
 * updatedAt, hash}`; the migration path needs the full
 * envelope so it can rewrite it atomically with the new
 * hash while preserving any other operator metadata.
 */
async function readRawEnvelope(store, key) {
  if (!store) return null;
  try {
    const v = await store.get(key, { type: 'json' });
    if (!v || typeof v !== 'object') return null;
    return v;
  } catch {
    return null;
  }
}

/**
 * Validate that an enrichment cache envelope's public
 * content is structurally valid. A valid envelope has
 * a `records` field that is an object. The validation
 * is intentionally cheap and side-effect-free.
 */
function isValidEnrichmentEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') return false;
  if (!envelope.records || typeof envelope.records !== 'object') return false;
  return true;
}

/**
 * Validate that a dataset envelope is structurally
 * valid for a hash upgrade. The envelope must be an
 * object. The pre-V6.1 dataset envelope may carry any
 * shape; we just need to canonicalize the public
 * portion (INTERNAL_BLOB_FIELDS stripped) to compute
 * the hash. No field-presence check is required.
 */
function isValidDatasetEnvelope(envelope) {
  return envelope && typeof envelope === 'object';
}

/**
 * Upgrade a pre-V6.1 enrichment cache envelope to
 * carry its precomputed public hash. Idempotent: when
 * the stored hash is already present, the envelope is
 * returned without a write.
 *
 * Returns:
 *   { envelope, upgraded: boolean, reason?: string }
 *
 * The returned `envelope` is the value that the
 * publisher should consume (i.e. the upgraded one when
 * `upgraded === true`, or the original when no upgrade
 * was necessary). The function NEVER returns a hash
 * that the publisher would compute from a structurally
 * invalid records map.
 */
async function upgradeEnrichmentEnvelopeIfNeeded({ store, key, hashField, writeFn, label }) {
  if (!store) return { envelope: null, upgraded: false, reason: 'store-missing' };
  const raw = await readRawEnvelope(store, key);
  if (!raw) return { envelope: null, upgraded: false, reason: 'no-existing-envelope' };
  if (typeof raw[hashField] === 'string' && raw[hashField].startsWith('sha256:')) {
    return { envelope: raw, upgraded: false, reason: 'already-hash-bearing' };
  }
  if (!isValidEnrichmentEnvelope(raw)) {
    return { envelope: null, upgraded: false, reason: 'invalid-records' };
  }
  // Compute the hash from the public projection of the
  // records map only. The hash is stable across
  // different `updatedAt` timestamps because the hash
  // excludes metadata.
  const newHash = computeEnrichmentPublicHash(raw);
  if (!newHash) {
    return { envelope: null, upgraded: false, reason: 'hash-computation-failed' };
  }
  const upgraded = { ...raw, [hashField]: newHash };
  let writeOk = false;
  try {
    writeOk = await writeFn(store, upgraded);
  } catch {
    writeOk = false;
  }
  if (!writeOk) {
    // Migration write failure leaves the previous
    // (un-upgraded) envelope intact. The publisher will
    // skip because the hash is still missing.
    return { envelope: null, upgraded: false, reason: 'write-failed' };
  }
  return { envelope: upgraded, upgraded: true };
}

/**
 * Upgrade a pre-V6.1 dataset envelope to carry its
 * precomputed public hash. Idempotent.
 */
async function upgradeDatasetEnvelopeIfNeeded({ store, key, writeFn }) {
  if (!store) return { envelope: null, upgraded: false, reason: 'store-missing' };
  const raw = await readRawEnvelope(store, key);
  if (!raw) return { envelope: null, upgraded: false, reason: 'no-existing-envelope' };
  if (typeof raw.datasetPublicHash === 'string' && raw.datasetPublicHash.startsWith('sha256:')) {
    return { envelope: raw, upgraded: false, reason: 'already-hash-bearing' };
  }
  if (!isValidDatasetEnvelope(raw)) {
    return { envelope: null, upgraded: false, reason: 'invalid-envelope' };
  }
  // Compute the public hash from the deterministic
  // public projection of the dataset envelope
  // (INTERNAL_BLOB_FIELDS stripped, then canonical
  // JSON, then SHA-256). This is the same value
  // `refresh.mjs` writes at write time. The strip
  // function is the single source of truth for the
  // internal-fields list, so the upgrade path stays in
  // lockstep with the write-time path.
  const newHash = computeDatasetPublicHash(raw);
  if (!newHash) {
    return { envelope: null, upgraded: false, reason: 'hash-computation-failed' };
  }
  const upgraded = { ...raw, datasetPublicHash: newHash };
  let writeOk = false;
  try {
    writeOk = await writeFn(store, upgraded);
  } catch {
    writeOk = false;
  }
  if (!writeOk) {
    return { envelope: null, upgraded: false, reason: 'write-failed' };
  }
  return { envelope: upgraded, upgraded: true };
}

/**
 * Migrate pre-V6.1 cache envelopes to carry their
 * precomputed public hashes. Called from
 * `runDatasetPublicationChain` BEFORE the publisher.
 * The function NEVER calls the upstream provider; it
 * is a pure envelope-rewrite based on the existing
 * records.
 *
 * The returned envelopes are the ones the publisher
 * must consume (the exact Blobs that the public
 * request path will subsequently serve). When an
 * upgrade fails for a particular envelope, the
 * returned value is `null` and the publisher treats
 * it as a structured skip with a sanitized reason.
 */
export async function upgradeLegacyEnvelopes({ datasetStore, vulnrichmentStore, githubAdvisoryStore } = {}) {
  const result = {
    dataset: { upgraded: false, reason: null, envelope: null },
    vulnrichment: { upgraded: false, reason: null, envelope: null },
    githubAdvisory: { upgraded: false, reason: null, envelope: null },
  };
  // Order: Vulnrichment, GitHub Advisory, dataset.
  // The order is irrelevant functionally (the migration
  // is per-envelope), but this is the order they are
  // used downstream.
  const vuln = await upgradeEnrichmentEnvelopeIfNeeded({
    store: vulnrichmentStore,
    key: VULNRICHMENT_CACHE_KEY,
    hashField: 'vulnrichmentPublicHash',
    writeFn: (s, payload) => writeVulnrichmentCache(s, payload),
    label: 'vulnrichment',
  });
  result.vulnrichment = { upgraded: vuln.upgraded, reason: vuln.reason || null, envelope: vuln.envelope };

  const gh = await upgradeEnrichmentEnvelopeIfNeeded({
    store: githubAdvisoryStore,
    key: GITHUB_ADVISORY_CACHE_KEY,
    hashField: 'githubAdvisoryPublicHash',
    writeFn: (s, payload) => writeGithubAdvisoryCache(s, payload),
    label: 'githubAdvisory',
  });
  result.githubAdvisory = { upgraded: gh.upgraded, reason: gh.reason || null, envelope: gh.envelope };

  const ds = await upgradeDatasetEnvelopeIfNeeded({
    store: datasetStore,
    key: LATEST_DATASET_KEY,
    writeFn: (s, payload) => writeLatestDataset(s, payload),
  });
  result.dataset = { upgraded: ds.upgraded, reason: ds.reason || null, envelope: ds.envelope };

  return result;
}

/**
 * Build a short sanitized summary line for a chain
 * step. Never includes the full hash, the full version
 * id, the full reason, or any provider detail.
 */
function sanitizeSummary(result) {
  if (!result || typeof result !== 'object') return 'no-result';
  if (result.skipped === true) {
    const r = typeof result.reason === 'string' ? result.reason : 'skipped';
    return `skipped:${r}`;
  }
  return 'published';
}

/* ---- Baseline chain ---- */

/**
 * Read the canonical vulnerability entities from the
 * just-published canonical baseline. The function reads
 * the latest manifest and the vulnerability shards
 * referenced by it, then concatenates the entities.
 *
 * This is the only place outside the orchestrator that
 * reads canonical shards. It is intentionally narrow:
 * it only collects the `vulnerability` entity type,
 * which is the only type the V6.1 OSV public
 * projection needs.
 *
 * The function is best-effort: it returns an empty
 * array on any read failure. The caller treats an
 * empty array as a structured skip and logs a
 * sanitized warning.
 */
async function readCanonicalVulnerabilityEntities(store, readShardFn = defaultReadShard) {
  if (!store) return [];
  const latest = await readLatestManifest(store);
  if (!latest || typeof latest !== 'object') return [];
  const shards = latest.shards && latest.shards.vulnerability;
  if (!shards || typeof shards !== 'object') return [];
  const out = [];
  for (const desc of Object.values(shards)) {
    if (!desc || typeof desc.objectKey !== 'string') continue;
    let arr = null;
    try {
      arr = await readShardFn(store, desc.objectKey);
    } catch {
      arr = null;
    }
    if (Array.isArray(arr)) {
      for (const e of arr) {
        if (e && typeof e === 'object' && typeof e.osvId === 'string') {
          out.push(e);
        }
      }
    }
  }
  return out;
}

/**
 * Run the V6.0 OSV orchestrator and, on a successful
 * canonical baseline publication, invoke the V6.1 OSV
 * public projection. On a successful or unchanged
 * projection, run mark-and-sweep GC.
 *
 * Inputs:
 *   - store: the canonical baseline Blob store
 *   - runOrchestrator: a function that performs one
 *     orchestrator iteration (default: `runOsvBackground`).
 *     The function receives the same `store` plus a
 *     `gzipFn` and must return the same shape as
 *     `runOsvBackground`.
 *   - publishOsvProjectionFn: the V6.1 OSV projection
 *     publisher. Default: the production function. The
 *     default can be overridden for tests; the test
 *     override MUST preserve the same return contract
 *     (structured `{skipped, reason, ...}` result).
 *   - runOsvGcFn: the V6.1 mark-and-sweep GC. Default:
 *     the production function. Overridable for tests.
 *   - deps: { gzipFn, readShardFn } — test seams.
 *
 * Returns the orchestrator's return value (so the
 * caller can still use `done`, `published`,
 * `recordsProcessed`, `elapsedMs`, `errors` for its
 * own logging), augmented with `v61OsvProjection`
 * (the V6.1 publishOsvProjection result) and
 * `v61OsvGc` (the V6.1 runOsvGc result).
 */
export async function runBaselinePublicationChain({
  store,
  runOrchestrator = (args) => runOsvBackground(args),
  gzipFn = null,
  readShardFn = null,
  now = new Date(),
  publicIntelligenceStore = null,
  publishOsvProjectionFn = null,
  runOsvGcFn = null,
  logPrefix = LOG_PREFIX_BASELINE,
} = {}) {
  const effectivePublish = publishOsvProjectionFn || publishOsvProjection;
  const effectiveGc = runOsvGcFn || runOsvGc;
  if (!store) {
    return {
      status: 'failed',
      done: true,
      phase: 'preparation',
      manifest: null,
      published: false,
      recordsProcessed: 0,
      recordsTotal: 0,
      elapsedMs: 0,
      errors: [{ at: now.toISOString(), phase: 'preparation', error: 'store is required' }],
      v61OsvProjection: null,
      v61OsvGc: null,
    };
  }
  // 1. Run the V6.0 orchestrator.
  const orchestratorArgs = { store };
  if (gzipFn) orchestratorArgs.gzipFn = gzipFn;
  if (readShardFn) orchestratorArgs.readShardFn = readShardFn;
  const orchestratorResult = await runOrchestrator(orchestratorArgs);

  // 2. Initialize V6.1 sub-result slots so callers always
  //    see a stable shape regardless of which branch ran.
  const augmented = {
    ...orchestratorResult,
    v61OsvProjection: null,
    v61OsvGc: null,
  };

  // 3. Only invoke V6.1 on a SUCCESSFUL canonical
  //    publication. Failed / paused / incomplete / no-work
  //    runs MUST NOT trigger V6.1.
  const canonicalSucceeded =
    orchestratorResult &&
    orchestratorResult.status === 'ok' &&
    orchestratorResult.published === true &&
    orchestratorResult.manifest &&
    typeof orchestratorResult.manifest.baselineVersion === 'string' &&
    typeof orchestratorResult.manifest.canonicalContentHash === 'string';

  if (!canonicalSucceeded) {
    return augmented;
  }

  // 4. Resolve the public-intelligence Blob store. If the
  //    store cannot be resolved (e.g. local dev without
  //    Blobs context), log a sanitized warning and exit
  //    without failing the canonical publication.
  let intelStore = publicIntelligenceStore;
  if (!intelStore) {
    try {
      intelStore = getPublicIntelligenceStore();
    } catch (err) {
      console.warn(`${logPrefix} public-intelligence store unavailable:`, err && err.message ? err.message : String(err));
      return augmented;
    }
  }
  if (!intelStore) {
    console.warn(`${logPrefix} public-intelligence store unavailable: store handle null`);
    return augmented;
  }

  // 5. Read the canonical vulnerability entities from the
  //    just-published baseline.
  const canonicalEntities = await readCanonicalVulnerabilityEntities(store, readShardFn || defaultReadShard);
  if (canonicalEntities.length === 0) {
    console.warn(`${logPrefix} no vulnerability entities in the just-published baseline; skipping OSV projection`);
    return augmented;
  }

  // 6. Invoke the V6.1 OSV public projection.
  let v61Result = null;
  try {
    v61Result = await effectivePublish(intelStore, canonicalEntities, {
      canonicalBaselineVersion: orchestratorResult.manifest.baselineVersion,
      canonicalManifestHash: orchestratorResult.manifest.canonicalContentHash,
      now,
    });
  } catch (err) {
    // Defensive: the publisher contract is to never throw
    // on size-ceiling / common failures, but a defensive
    // catch here preserves the canonical publication.
    console.warn(`${logPrefix} publishOsvProjection threw unexpectedly:`, err && err.message ? err.message : String(err));
    v61Result = { skipped: true, reason: 'projection-threw', error: err && err.message ? err.message : String(err) };
  }
  augmented.v61OsvProjection = v61Result;
  console.log(`${logPrefix} v61=${sanitizeSummary(v61Result)} baselineVersion=${orchestratorResult.manifest.baselineVersion}`);

  // 7. Run mark-and-sweep GC only on a successful or
  //    unchanged projection. A ceiling-rejected or
  //    otherwise-failed projection must NOT trigger GC
  //    because the previous valid projection's shards are
  //    still in use by the previous osv/latest.json.
  const projectionSafeForGc =
    v61Result &&
    (v61Result.skipped === false ||
      (v61Result.skipped === true && v61Result.reason === 'projection-unchanged'));
  if (!projectionSafeForGc) {
    return augmented;
  }
  let gcResult = null;
  try {
    gcResult = await effectiveGc(intelStore);
  } catch (err) {
    console.warn(`${logPrefix} runOsvGc threw unexpectedly:`, err && err.message ? err.message : String(err));
    gcResult = { status: 'failed', error: err && err.message ? err.message : String(err) };
  }
  augmented.v61OsvGc = gcResult;
  if (gcResult && Array.isArray(gcResult.deleted)) {
    console.log(`${logPrefix} gc.retained=${gcResult.retained} gc.deleted=${gcResult.deleted.length}`);
  } else {
    console.log(`${logPrefix} gc.status=${gcResult && gcResult.status}`);
  }

  return augmented;
}

/* ---- Dataset chain ---- */

/**
 * Read the current dataset envelope and both enrichment
 * cache envelopes from their respective Blob stores.
 * Returns a coherent state object suitable for
 * `publishDatasetBound`. Returns `null` if any required
 * envelope is missing.
 */
async function readDatasetBoundInputs({ datasetStore, vulnrichmentStore, githubAdvisoryStore, intelStore }) {
  if (!datasetStore || !vulnrichmentStore || !githubAdvisoryStore) return null;
  const [datasetEnvelope, vulnrichmentCache, githubAdvisoryCache] = await Promise.all([
    readLatestDataset(datasetStore),
    readVulnrichmentCache(vulnrichmentStore),
    readGithubAdvisoryCache(githubAdvisoryStore),
  ]);
  // The dataset envelope is required. The Vulnrichment
  // and GitHub Advisory caches are best-effort
  // (incremental backfill); null caches are allowed and
  // yield a structured skip when their precomputed
  // public hash is also missing.
  if (!datasetEnvelope || typeof datasetEnvelope !== 'object') return null;
  return { datasetEnvelope, vulnrichmentCache, githubAdvisoryCache };
}

/**
 * Read the current OSV projection reference from the
 * public-intelligence store. Returns `null` when no OSV
 * projection has been published yet. The dataset-bound
 * publication can run with `osvProjection: null` (it
 * records the missing axis in `suppressedAxes`), but
 * the publicStateHash will be different.
 */
async function readCurrentOsvProjection(intelStore) {
  if (!intelStore) return null;
  try {
    const latest = await readJson(intelStore, OSV_LATEST_KEY);
    if (!latest || typeof latest !== 'object') return null;
    return {
      osvProjectionVersion: latest.osvProjectionVersion,
      manifestContentHash: latest.manifestContentHash,
      generatedAt: latest.generatedAt,
    };
  } catch {
    return null;
  }
}

/**
 * Run the V6.1 dataset-bound public-intelligence
 * publication chain. The caller is responsible for
 * having completed the main dataset write AND both
 * enrichment cache writes BEFORE invoking this
 * function. The chain:
 *   1. Migrates pre-V6.1 envelopes to carry their
 *      precomputed public hashes (one atomic rewrite
 *      per missing envelope, no upstream provider
 *      request).
 *   2. Reads back the upgraded envelopes (or the
 *      same envelopes when no upgrade was needed).
 *   3. Invokes the V6.1 dataset-bound publication
 *      with the exact upgraded envelopes.
 *
 * Returns a structured result:
 *   - { published: true, publicIntelligenceVersion, ... }
 *   - { skipped: true, reason: '...' }
 *   - { published: false, error: '...' } on unexpected failure
 *
 * The function NEVER throws on a structured skip.
 * The function NEVER calls the upstream provider.
 */
export async function runDatasetPublicationChain({
  datasetStore,
  vulnrichmentStore,
  githubAdvisoryStore,
  intelStore = null,
  now = new Date(),
  logPrefix = LOG_PREFIX_DATASET,
  publishDatasetBoundFn = null,
} = {}) {
  if (!datasetStore) {
    return { skipped: true, reason: 'dataset-store-missing' };
  }
  let store = intelStore;
  if (!store) {
    try {
      store = getPublicIntelligenceStore();
    } catch (err) {
      console.warn(`${logPrefix} public-intelligence store unavailable:`, err && err.message ? err.message : String(err));
      return { skipped: true, reason: 'public-intelligence-store-unavailable' };
    }
  }
  if (!store) {
    return { skipped: true, reason: 'public-intelligence-store-unavailable' };
  }

  // 1. Migrate pre-V6.1 envelopes to carry their
  //    precomputed public hashes. The migration NEVER
  //    calls the upstream provider; it rewrites the
  //    existing envelope atomically with the new hash.
  let migration;
  try {
    migration = await upgradeLegacyEnvelopes({ datasetStore, vulnrichmentStore, githubAdvisoryStore });
  } catch (err) {
    // Defensive: upgradeLegacyEnvelopes is best-effort
    // and NEVER throws. A defensive catch here keeps
    // the main refresh's 'completed' status honest.
    console.warn(`${logPrefix} upgradeLegacyEnvelopes threw unexpectedly:`, err && err.message ? err.message : String(err));
    return { skipped: true, reason: 'migration-threw', error: err && err.message ? err.message : String(err) };
  }
  if (migration.dataset.upgraded) console.log(`${logPrefix} migrated dataset envelope to hash-bearing`);
  if (migration.vulnrichment.upgraded) console.log(`${logPrefix} migrated vulnrichment envelope to hash-bearing`);
  if (migration.githubAdvisory.upgraded) console.log(`${logPrefix} migrated githubAdvisory envelope to hash-bearing`);

  // 2. Re-read the three envelopes from the store. The
  //    migration returns the upgraded envelope object
  //    directly, but re-reading is the safer
  //    single-source-of-truth contract: the published
  //    publicStateHash MUST describe the same three
  //    Blob values that the public request path will
  //    subsequently serve.
  const inputs = await readDatasetBoundInputs({ datasetStore, vulnrichmentStore, githubAdvisoryStore, intelStore: store });
  if (!inputs) {
    return { skipped: true, reason: 'missing-dataset-envelope', migration };
  }
  const { datasetEnvelope, vulnrichmentCache, githubAdvisoryCache } = inputs;

  // 3. Verify the three precomputed public hashes are
  //    present. A missing hash means the envelope was
  //    written by a pre-V6.1 refresh AND the migration
  //    could not upgrade it (e.g. records were
  //    invalid). The function returns a structured
  //    skip — the next successful refresh upgrades
  //    the envelope automatically.
  if (!datasetEnvelope.datasetPublicHash || typeof datasetEnvelope.datasetPublicHash !== 'string') {
    return { skipped: true, reason: 'dataset-public-hash-missing', migration };
  }
  if (!vulnrichmentCache || !vulnrichmentCache.vulnrichmentPublicHash || typeof vulnrichmentCache.vulnrichmentPublicHash !== 'string') {
    return { skipped: true, reason: 'vulnrichment-public-hash-missing', migration };
  }
  if (!githubAdvisoryCache || !githubAdvisoryCache.githubAdvisoryPublicHash || typeof githubAdvisoryCache.githubAdvisoryPublicHash !== 'string') {
    return { skipped: true, reason: 'github-advisory-public-hash-missing', migration };
  }

  // 4. Read the current OSV projection reference.
  const osvProjection = await readCurrentOsvProjection(store);

  // 5. Invoke the V6.1 dataset-bound publication.
  const effectivePublisher = publishDatasetBoundFn || publishDatasetBound;
  let result = null;
  try {
    result = await effectivePublisher(store, {
      datasetEnvelope,
      vulnrichmentCache,
      githubAdvisoryCache,
      osvProjection,
      now,
    });
  } catch (err) {
    // Defensive: the publisher contract is to never
    // throw on common failures, but a defensive catch
    // here preserves the main refresh's 'completed' status.
    console.warn(`${logPrefix} publishDatasetBound threw unexpectedly:`, err && err.message ? err.message : String(err));
    return { skipped: true, reason: 'publish-threw', error: err && err.message ? err.message : String(err) };
  }
  if (!result) {
    return { skipped: true, reason: 'no-result', migration };
  }
  if (result.skipped) {
    console.log(`${logPrefix} skipped reason=${result.reason || 'unspecified'}`);
    return { ...result, migration };
  }
  console.log(`${logPrefix} published version=${result.publicIntelligenceVersion} comparesFreshBase=${result.comparesFreshBase}`);
  return {
    published: true,
    publicIntelligenceVersion: result.publicIntelligenceVersion,
    migration,
    ...result,
  };
}
