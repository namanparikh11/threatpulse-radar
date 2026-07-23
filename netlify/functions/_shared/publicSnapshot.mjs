/**
 * V6.1 — Per-CVE observation-state public comparison
 * snapshot.
 *
 * The public comparison snapshot is the server-side
 * per-version artifact used to compute change
 * classifications. It carries ONLY the fields needed
 * for deterministic comparison; the full public dataset
 * envelope is not duplicated here.
 *
 * Per-CVE observation states (mutually exclusive):
 *   - 'present'        — positive cache entry / record
 *   - 'checked-absent' — negative cache marker (e.g.
 *                        Vulnrichment 404, GitHub 404/empty)
 *   - 'unknown'        — no cache entry, no negative marker
 *
 * Per-provider comparability flags (set on the snapshot's
 * providerComparability block) determine whether an axis
 * is comparable between two snapshots. A classification
 * axis is computed only when the corresponding provider is
 * comparable in BOTH snapshots.
 *
 * The snapshot is gzipped and stored at:
 *   tpr-public-intelligence/dataset/versions/{v}/public-snapshot.json.gz
 *
 * The browser NEVER parses the snapshot. It is a
 * server-side artifact only.
 */

import { canonicalizeToString, sha256Hex } from './canonicalHash.mjs';
import { OSV_BUCKET_COUNT } from './publicIntelligenceSize.mjs';

/**
 * Build a per-CVE snapshot record from a single public
 * dataset envelope record. The function NEVER mutates
 * the input. It is pure and deterministic.
 */
export function buildSnapshotRecordForCve(cveId, record, caches) {
  if (typeof cveId !== 'string' || cveId.length === 0) return null;
  if (!record || typeof record !== 'object') return null;
  // caches is { vulnrichment: { records: {...} }, githubAdvisory: { records: {...} }, osvProjection: { byCve: {...} } }
  // For V6.1, the per-CVE snapshot only needs the
  // observation states, not the full payload.
  const cve = record.cveId || cveId;
  const kev = deriveKevObservation(record, caches);
  const severity = deriveSeverityObservation(record);
  const nvd = deriveNvdObservation(record);
  const epss = deriveEpssObservation(record);
  const ssvc = deriveSsvcObservation(cve, caches);
  const gh = deriveGithubAdvisoryObservation(cve, caches);
  const osv = deriveOsvObservation(cve, caches);
  const withdrawn = osv.withdrawn === true;
  const affectedSignature = computeAffectedSignature(cve, caches);

  return {
    tracked: true,
    kev,
    severity,
    nvd,
    epssProbability: record.epssProbability ?? null,
    epss,
    ssvcExploitation: ssvc,
    githubAdvisory: gh,
    firstPatchedAvailable: deriveFirstPatchedAvailable(gh),
    osv,
    withdrawn,
    affectedSignature,
  };
}

/**
 * Derive a stable signature of the affected (ecosystem,
 * name, rangeType, sortedEvents) set for a CVE. The hash
 * is used to detect `affected-package-or-range-changed`
 * transitions. It is content-addressed (sha256 of the
 * canonical JSON).
 */
export function computeAffectedSignature(cveId, caches) {
  if (!caches || !caches.osvProjection) return '';
  const ctx = caches.osvProjection.byCve && caches.osvProjection.byCve[cveId];
  if (!ctx || !Array.isArray(ctx.records) || ctx.records.length === 0) return '';
  const sig = [];
  for (const rec of ctx.records) {
    if (!rec || !Array.isArray(rec.affectedPackages)) continue;
    for (const pkg of rec.affectedPackages) {
      if (!Array.isArray(pkg.ranges)) continue;
      for (const r of pkg.ranges) {
        if (!Array.isArray(r.events)) continue;
        const events = r.events.map((e) => {
          const out = [];
          if (e.introduced) out.push('i:' + e.introduced);
          if (e.fixed) out.push('f:' + e.fixed);
          if (e.last_affected) out.push('l:' + e.last_affected);
          if (e.limit) out.push('L:' + e.limit);
          return out.join(',');
        });
        sig.push([rec.osvId, pkg.ecosystem, pkg.name, r.type, events.join(';')].join('|'));
      }
    }
  }
  sig.sort();
  return `sha256:${sha256Hex(canonicalizeToString({ cve: cveId, sig }))}`;
}

function deriveKevObservation(record, caches) {
  if (record.kev === true) return { observation: 'present', present: true, kevDateAdded: record.kevDateAdded ?? null };
  if (record.kev === false) return { observation: 'present', present: false, kevDateAdded: null };
  return { observation: 'unknown', present: false, kevDateAdded: null };
}

function deriveSeverityObservation(record) {
  if (typeof record.severity === 'string' && record.severity.length > 0) {
    return {
      observation: 'present',
      value: record.severity,
      cvssSource: typeof record.cvssSource === 'string' ? record.cvssSource : null,
      cvssVersion: typeof record.cvssVersion === 'string' ? record.cvssVersion : null,
    };
  }
  return { observation: 'unknown', value: null, cvssSource: null, cvssVersion: null };
}

function deriveNvdObservation(record) {
  // NVD is the same as severity in the public dataset;
  // carry the same observation.
  if (typeof record.cvssScore === 'number' && record.cvssScore > 0) {
    return {
      observation: 'present',
      severity: record.severity ?? null,
      cvssSource: typeof record.cvssSource === 'string' ? record.cvssSource : null,
      cvssVersion: typeof record.cvssVersion === 'string' ? record.cvssVersion : null,
    };
  }
  return { observation: 'unknown', severity: null, cvssSource: null, cvssVersion: null };
}

function deriveEpssObservation(record) {
  if (typeof record.epssProbability === 'number' && record.epssProbability > 0) {
    return { observation: 'present', probability: record.epssProbability };
  }
  return { observation: 'unknown', probability: null };
}

function deriveSsvcObservation(cveId, caches) {
  if (!caches || !caches.vulnrichment || !caches.vulnrichment.records) {
    return { observation: 'unknown', exploitation: null };
  }
  const rec = caches.vulnrichment.records[cveId];
  if (!rec) return { observation: 'unknown', exploitation: null };
  if (rec.status === 'missing') {
    return { observation: 'checked-absent', exploitation: null };
  }
  if (rec.ssvc && typeof rec.ssvc.ssvcExploitation === 'string') {
    return { observation: 'present', exploitation: rec.ssvc.ssvcExploitation };
  }
  return { observation: 'unknown', exploitation: null };
}

function deriveGithubAdvisoryObservation(cveId, caches) {
  if (!caches || !caches.githubAdvisory || !caches.githubAdvisory.records) {
    return { observation: 'unknown', ghsaId: null, firstPatchedAvailable: null };
  }
  const rec = caches.githubAdvisory.records[cveId];
  if (!rec) return { observation: 'unknown', ghsaId: null, firstPatchedAvailable: null };
  if (rec.status === 'missing') {
    return { observation: 'checked-absent', ghsaId: null, firstPatchedAvailable: null };
  }
  if (rec.advisory && typeof rec.advisory.ghsaId === 'string') {
    const firstPatched = Array.isArray(rec.advisory.packages)
      ? rec.advisory.packages.some((p) => p.firstPatchedVersion !== null && p.firstPatchedVersion !== undefined)
      : false;
    return { observation: 'present', ghsaId: rec.advisory.ghsaId, firstPatchedAvailable: firstPatched };
  }
  return { observation: 'unknown', ghsaId: null, firstPatchedAvailable: null };
}

function deriveOsvObservation(cveId, caches) {
  if (!caches || !caches.osvProjection || !caches.osvProjection.byCve) {
    return { observation: 'unknown', recordIds: [], affectedSignature: null, withdrawn: null };
  }
  const ctx = caches.osvProjection.byCve[cveId];
  if (!ctx || !Array.isArray(ctx.records) || ctx.records.length === 0) {
    return { observation: 'checked-absent', recordIds: [], affectedSignature: null, withdrawn: false };
  }
  const recordIds = ctx.records.map((r) => r.osvId).filter((s) => typeof s === 'string').sort();
  const withdrawn = ctx.records.some((r) => r.withdrawn === true);
  return {
    observation: 'present',
    recordIds,
    affectedSignature: ctx.records[0] && ctx.records[0]._signature || null,
    withdrawn,
  };
}

function deriveFirstPatchedAvailable(ghObs) {
  if (ghObs && ghObs.observation === 'present') {
    return ghObs.firstPatchedAvailable === true;
  }
  return false;
}

/**
 * Build the full public comparison snapshot from a public
 * dataset envelope and the three enrichment caches.
 */
export function buildPublicSnapshot({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection, now = new Date() } = {}) {
  if (!datasetEnvelope || !Array.isArray(datasetEnvelope.data)) {
    return {
      schemaVersion: '1.0.0',
      publicIntelligenceVersion: '',
      generatedAt: now.toISOString(),
      providerComparability: buildProviderComparability({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection }),
      trackedCveCount: 0,
      byCve: {},
    };
  }
  const caches = {
    vulnrichment: vulnrichmentCache || { records: {} },
    githubAdvisory: githubAdvisoryCache || { records: {} },
    osvProjection: osvProjection || { byCve: {} },
  };
  const byCve = {};
  for (const rec of datasetEnvelope.data) {
    if (!rec || typeof rec.cveId !== 'string') continue;
    const snap = buildSnapshotRecordForCve(rec.cveId, rec, caches);
    if (snap) byCve[rec.cveId] = snap;
  }
  return {
    schemaVersion: '1.0.0',
    publicIntelligenceVersion: datasetEnvelope.publicIntelligenceVersion || '',
    generatedAt: now.toISOString(),
    providerComparability: buildProviderComparability({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection }),
    trackedCveCount: Object.keys(byCve).length,
    byCve,
  };
}

/**
 * Build the providerComparability block for the snapshot.
 * The flags are computed from the public dataset envelope's
 * status fields and the cache states.
 */
export function buildProviderComparability({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection } = {}) {
  const cisaKev = {
    comparable: datasetEnvelope && datasetEnvelope.mode === 'live' ? true : false,
    asOf: datasetEnvelope ? datasetEnvelope.fetchedAt : null,
  };
  const nvd = {
    comparable: datasetEnvelope && datasetEnvelope.nvdStatus === 'nvd' ? true : false,
    asOf: datasetEnvelope ? datasetEnvelope.fetchedAt : null,
  };
  const firstEpss = {
    comparable: datasetEnvelope && datasetEnvelope.epssStatus === 'first' ? true : false,
    asOf: datasetEnvelope ? datasetEnvelope.fetchedAt : null,
  };
  const vulnrichmentStatus = datasetEnvelope ? datasetEnvelope.vulnrichmentStatus : null;
  const ssvc = {
    comparable: vulnrichmentStatus === 'available' ? true : (vulnrichmentStatus === 'partial' ? 'partial' : false),
    asOf: vulnrichmentCache && vulnrichmentCache.updatedAt ? vulnrichmentCache.updatedAt : (datasetEnvelope ? datasetEnvelope.fetchedAt : null),
  };
  const ghStatus = datasetEnvelope ? datasetEnvelope.githubAdvisoryStatus : null;
  const githubAdvisory = {
    comparable: ghStatus === 'available' ? true : (ghStatus === 'partial' ? 'partial' : false),
    asOf: githubAdvisoryCache && githubAdvisoryCache.updatedAt ? githubAdvisoryCache.updatedAt : (datasetEnvelope ? datasetEnvelope.fetchedAt : null),
  };
  const osv = {
    comparable: osvProjection && osvProjection.generatedAt ? true : false,
    asOf: osvProjection ? osvProjection.generatedAt : null,
  };
  return { cisaKev, nvd, firstEpss, ssvc, githubAdvisory, osv };
}
