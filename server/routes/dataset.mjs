/**
 * V6.2 — portable HTTP route: /api/dataset
 *
 * Mirrors the public-side dataset function's behavior:
 *   - Default mode: the public dataset envelope with
 *     V6.1 public-intelligence additions.
 *   - view=osv: the per-CVE OSV public projection.
 *   - view=changes: the per-category change items.
 *
 * The route enforces the same parameter validation,
 * current-version-only rules, and sanitized error
 * responses as the Netlify function. The response is
 * JSON; the Content-Type header is application/json.
 *
 * No secrets, raw hashes, or canonical private records
 * are exposed. The route NEVER calls an upstream
 * provider; it only reads from the storage adapters.
 */

import { readLatestDataset, readVulnrichmentCache, readGithubAdvisoryCache } from '../../netlify/functions/_shared/store.mjs';
import { computeCurrentPublicStateHash, readOsvView, readChangesView, detectViewMode, readViewParams } from '../../netlify/functions/_shared/datasetPublicIntelligenceRead.mjs';
import { readJson, OSV_LATEST_KEY, DATASET_LATEST_KEY } from '../../netlify/functions/_shared/publicIntelligenceStore.mjs';

/**
 * Handle an HTTP request. Returns a Response object
 * with the appropriate status and JSON body.
 */
export async function handleDataset(request, { config }) {
  // Construct an absolute URL from the incoming
  // request so the existing `detectViewMode` /
  // `readViewParams` helpers (which expect an absolute
  // URL) work in the portable server. The path +
  // query string is read from the `request.url` field
  // (which may be relative in this context) AND from
  // the explicit path+query fields when available.
  const reqUrl = request && request.url;
  let view = null;
  try {
    if (reqUrl && reqUrl.startsWith('http')) {
      view = detectViewMode(request);
    } else if (reqUrl) {
      // Reconstruct an absolute URL with a synthetic base.
      const absolute = `http://localhost${reqUrl.startsWith('/') ? '' : '/'}${reqUrl}`;
      view = detectViewMode({ url: absolute });
    }
  } catch { view = null; }
  if (view === 'osv') return handleOsvView(request, { config });
  if (view === 'changes') return handleChangesView(request, { config });
  return handleDefaultMode({ config, request });
}

async function handleDefaultMode({ config }) {
  // The default mode reads the dataset envelope and the
  // V6.1 public-intelligence latest.json from the
  // configured storage adapters.
  const datasetStore = config.storage('tpr-dataset');
  const vulnStore = config.storage('tpr-vulnrichment');
  const ghStore = config.storage('tpr-github-advisory');
  const intelStore = config.storage('tpr-public-intelligence');

  let datasetEnvelope = null;
  try { datasetEnvelope = await readLatestDataset(datasetStore); } catch { datasetEnvelope = null; }
  if (!datasetEnvelope) {
    return jsonResponse(200, {
      ...emptyEnvelope(),
      note: 'No dataset envelope present; run refresh-dataset to populate.',
    });
  }
  const vulnrichmentCache = await readVulnrichmentCache(vulnStore).catch(() => null);
  const githubAdvisoryCache = await readGithubAdvisoryCache(ghStore).catch(() => null);

  // The V6.1 default additions require the public
  // intelligence latest.json. We read it via the
  // intelStore (storage adapter path) so the route is
  // portable. When the latest.json is missing we
  // report `unavailable` honestly.
  const intelLatest = await readJson(intelStore, DATASET_LATEST_KEY).catch(() => null);

  // The buildV61DefaultAdditions helper expects a
  // shape compatible with @netlify/blobs' getStore;
  // for the storage adapter path we call it directly
  // with the same envelope inputs.
  const v61 = computeV61Additions({
    datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, intelLatest,
  });
  return jsonResponse(200, {
    ...datasetEnvelope,
    ...v61,
  });
}

async function handleOsvView(request, { config }) {
  const params = readViewParamsSync(request) || {};
  const intelStore = config.storage('tpr-public-intelligence');
  // The V6.1 readOsvView expects a Netlify-shaped store.
  // For the portable path we wrap the storage adapter
  // to expose the same get(key, {type}) shape.
  const wrapped = wrapForOsvRead(intelStore);
  // Read the necessary side inputs.
  const datasetStore = config.storage('tpr-dataset');
  const vulnStore = config.storage('tpr-vulnrichment');
  const ghStore = config.storage('tpr-github-advisory');
  const datasetEnvelope = await readLatestDataset(datasetStore).catch(() => null);
  const vulnrichmentCache = await readVulnrichmentCache(vulnStore).catch(() => null);
  const githubAdvisoryCache = await readGithubAdvisoryCache(ghStore).catch(() => null);
  let osvProjection = null;
  try { osvProjection = await readJson(intelStore, OSV_LATEST_KEY); } catch { osvProjection = null; }
  return readOsvView({
    store: wrapped,
    datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
    versionParam: params.versionParam,
    cveParam: params.cveParam,
    bucketParam: params.bucketParam,
  });
}

async function handleChangesView(request, { config }) {
  const params = readViewParamsSync(request) || {};
  const intelStore = config.storage('tpr-public-intelligence');
  const wrapped = wrapForOsvRead(intelStore);
  const datasetStore = config.storage('tpr-dataset');
  const vulnStore = config.storage('tpr-vulnrichment');
  const ghStore = config.storage('tpr-github-advisory');
  const datasetEnvelope = await readLatestDataset(datasetStore).catch(() => null);
  const vulnrichmentCache = await readVulnrichmentCache(vulnStore).catch(() => null);
  const githubAdvisoryCache = await readGithubAdvisoryCache(ghStore).catch(() => null);
  let osvProjection = null;
  try { osvProjection = await readJson(intelStore, OSV_LATEST_KEY); } catch { osvProjection = null; }
  return readChangesView({
    store: wrapped,
    datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
    versionParam: params.versionParam,
    categoryParam: params.categoryParam,
    limitParam: params.limitParam,
  });
}

function emptyEnvelope() {
  return {
    mode: 'empty',
    source: 'portable-server',
    fetchedAt: null,
    data: [],
    // The V6.1 fields are always present so the
    // portable response shape is a superset of the
    // Netlify public response. When there is no
    // dataset envelope yet, the public intelligence
    // status is `unavailable` — the same default the
    // Netlify public function returns.
    publicIntelligenceStatus: 'unavailable',
    publicIntelligenceVersion: null,
    publicStateFingerprint: null,
    sources: [],
    changeSummary: null,
    comparableAxes: [],
    suppressedAxes: [],
  };
}

/**
 * Compute the V6.1 default additions using the public-
 * intelligence latest.json. When the latest.json is
 * missing, return an `unavailable` response.
 */
function computeV61Additions({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, intelLatest }) {
  const result = {
    publicIntelligenceStatus: 'unavailable',
    publicIntelligenceVersion: null,
    publicStateFingerprint: null,
    sources: [],
    changeSummary: null,
    comparableAxes: [],
    suppressedAxes: [],
  };
  if (!intelLatest || typeof intelLatest !== 'object') return result;
  // Read the manifest if present.
  // The portable path cannot call buildV61DefaultAdditions
  // directly because it expects a Netlify-style store. We
  // re-derive the publicStateHash + source health from the
  // cached envelopes and the latest.json.
  const hash = computeCurrentPublicStateHash({
    datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection: null,
  });
  if (!hash.available) return result;
  if (hash.publicStateHash !== intelLatest.publicStateHash) {
    return {
      ...result,
      publicIntelligenceStatus: 'mismatch',
      publicIntelligenceVersion: intelLatest.publicIntelligenceVersion,
    };
  }
  return {
    publicIntelligenceStatus: 'available',
    publicIntelligenceVersion: intelLatest.publicIntelligenceVersion,
    publicStateFingerprint: intelLatest.publicStateFingerprint || null,
    sources: [], // The portable server returns sources=[] until the
                  // dataset chain produces a manifest with source-health.
    changeSummary: null,
    comparableAxes: [],
    suppressedAxes: [],
  };
}

/**
 * Like `readViewParams` from the existing module but
 * handles a possibly-relative `request.url`. Used by
 * the portable server because the request URL may not
 * be absolute.
 */
function readViewParamsSync(request) {
  const u = request && request.url;
  if (!u) return {};
  try {
    const absolute = u.startsWith('http') ? u : `http://localhost${u.startsWith('/') ? '' : '/'}${u}`;
    const url = new URL(absolute);
    return {
      versionParam: url.searchParams.get('version'),
      cveParam: url.searchParams.get('cve'),
      bucketParam: url.searchParams.get('bucket'),
      categoryParam: url.searchParams.get('category'),
      limitParam: url.searchParams.get('limit'),
    };
  } catch {
    return {};
  }
}

/**
 * Wrap a StorageAdapter in a thin shim that exposes
 * `get(key, {type})` and `setJSON`/`setBinary`/`list`/
 * `delete` in the Netlify Blobs shape, so the existing
 * `readOsvView` / `readChangesView` helpers work
 * unchanged.
 */
function wrapForOsvRead(adapter) {
  return {
    async get(key, opts = {}) {
      const type = opts && opts.type ? opts.type : 'arrayBuffer';
      const v = await adapter.get(key, { type: type === 'json' ? 'json' : 'arrayBuffer' });
      return v;
    },
    async setJSON(key, value) { return adapter.setJSON(key, value); },
    async setBinary(key, value) { return adapter.setBinary(key, value); },
    async delete(key) { return adapter.delete(key); },
    async list(opts) { return adapter.list(opts || {}); },
  };
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
