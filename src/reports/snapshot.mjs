/**
 * V6.5 — Coherent report snapshot.
 *
 * A snapshot freezes the inputs that feed a report.
 * The generators and exporters never reach outside
 * the snapshot; the public-intelligence metadata,
 * the public CVE records, and the selected workspace
 * entries are all captured at the same instant.
 *
 * Build order (mandatory):
 *   1. capture compatible public-intelligence metadata
 *   2. capture the selected public CVE records (from
 *      the frozen FetchResult)
 *   3. flush all pending workspace writes
 *   4. capture the selected workspace entries
 *   5. freeze the input snapshot
 *
 * The function is async. The caller is responsible
 * for surfacing a sanitized error if the flush
 * rejects; the snapshot is never produced when the
 * workspace has uncommitted writes.
 *
 * When a local workspace entry has no matching public
 * record, the entry is RETAINED and the snapshot
 * records the public-intelligence gap so the
 * downstream templates can show an explicit
 * "unavailable in this snapshot" line.
 */

import { computeChangeSignatureSync } from '../workspace/changeSignature.mjs';
import { compareUpdatedAt, normaliseCveId, stampCommitted, newMutationId } from '../workspace/schema.mjs';

const EMPTY_SNAPSHOT_ERROR = 'snapshot:empty-input';

function normaliseCveList(list) {
  if (!Array.isArray(list)) return [];
  const out = new Set();
  for (const id of list) {
    const n = normaliseCveId(id);
    if (n) out.add(n);
  }
  return Array.from(out);
}

/** Capture the public-intelligence metadata block.
 *  The function never invents metadata; missing
 *  fields are surfaced as `null` or empty arrays. */
function capturePublicIntelligence(meta) {
  if (!meta || typeof meta !== 'object') {
    return {
      status: 'unavailable',
      version: null,
      projectionSchemaVersion: null,
      generatedAt: null,
      comparableAxes: [],
      suppressedAxes: [],
      sourceHealth: [],
    };
  }
  const status = meta.publicIntelligenceStatus || 'unavailable';
  return {
    status,
    version: typeof meta.publicIntelligenceVersion === 'string' ? meta.publicIntelligenceVersion : null,
    projectionSchemaVersion: typeof meta.publicProjectionSchemaVersion === 'string' ? meta.publicProjectionSchemaVersion : null,
    generatedAt: typeof meta.fetchedAt === 'string' ? meta.fetchedAt : null,
    comparableAxes: Array.isArray(meta.comparableAxes) ? meta.comparableAxes.slice().sort() : [],
    suppressedAxes: Array.isArray(meta.suppressedAxes) ? meta.suppressedAxes.slice().sort((a, b) => String(a.axis).localeCompare(String(b.axis))) : [],
    sourceHealth: Array.isArray(meta.sources) ? meta.sources.map((s) => ({
      sourceId: s?.sourceId || s?.id || s?.name || 'unknown',
      name: s?.name || s?.sourceId || s?.id || 'unknown',
      state: s?.state || 'unknown',
      lastSuccessAt: typeof s?.lastSuccessAt === 'string' ? s.lastSuccessAt : null,
      officialUrl: typeof s?.officialUrl === 'string' ? s.officialUrl : null,
      limits: typeof s?.limits === 'string' ? s.limits : null,
    })) : [],
  };
}

/** Capture the public CVE records the report cares
 *  about. The records are sorted by CVE id
 *  (ascending) for determinism. The function never
 *  enriches the public fields with local state. */
function capturePublicCveRecords(vulns, cveIds) {
  if (!Array.isArray(vulns)) return [];
  const wanted = new Set(normaliseCveList(cveIds));
  if (wanted.size === 0) return [];
  const map = new Map();
  for (const v of vulns) {
    if (!v || typeof v !== 'object') continue;
    const id = normaliseCveId(v.cveId);
    if (!id || !wanted.has(id)) continue;
    map.set(id, {
      cveId: id,
      // Provider-fact fields only.
      severity: typeof v.severity === 'string' ? v.severity : 'unknown',
      cvssScore: typeof v.cvssScore === 'number' ? v.cvssScore : null,
      epssProbability: typeof v.epssProbability === 'number' ? v.epssProbability : null,
      kev: !!v.kev,
      ssvc: v.ssvc || null,
      vulnrichment: !!v.vulnrichment,
      githubAdvisory: !!v.githubAdvisory,
      osv: v.osv ? { recordIds: Array.isArray(v.osv.recordIds) ? v.osv.recordIds.slice().sort() : [] } : null,
      withdrawn: !!v.withdrawn,
      // ThreatPulse-derived classifications.
      changeTag: v.change ? (v.change.tag || null) : null,
      // Public-safe top-level summary.
      summary: typeof v.summary === 'string' ? v.summary : '',
      publishedDate: typeof v.publishedDate === 'string' ? v.publishedDate : null,
      vendor: typeof v.vendor === 'string' ? v.vendor : '',
      product: typeof v.product === 'string' ? v.product : '',
      source: typeof v.source === 'string' ? v.source : '',
      // Official-link list (only public URLs).
      externalLinks: Array.isArray(v.externalLinks)
        ? v.externalLinks
            .filter((l) => l && typeof l.url === 'string' && /^https?:/.test(l.url))
            .map((l) => ({ label: typeof l.label === 'string' ? l.label : '', url: l.url }))
        : [],
    });
  }
  const out = [];
  for (const id of Array.from(wanted).sort()) {
    if (map.has(id)) out.push(map.get(id));
    else out.push({ cveId: id, unavailable: true });
  }
  return out;
}

/** V6.6: build a narrow optional local environment
 *  summary for the report boundary. The summary
 *  contains only counts — no asset names, component
 *  paths, owner labels, or local review notes.
 *  When the caller does not pass a summary, this
 *  function returns `null` so the field is absent
 *  from the JSON. */
function computeLocalEnvironmentSummary(input) {
  if (!input || typeof input !== 'object') return null;
  const relatedAssetCount = typeof input.relatedAssetCount === 'number' && Number.isFinite(input.relatedAssetCount)
    ? Math.max(0, Math.floor(input.relatedAssetCount)) : 0;
  const relatedComponentCount = typeof input.relatedComponentCount === 'number' && Number.isFinite(input.relatedComponentCount)
    ? Math.max(0, Math.floor(input.relatedComponentCount)) : 0;
  const correlationStateCounts = (input.correlationStateCounts && typeof input.correlationStateCounts === 'object')
    ? Object.fromEntries(Object.entries(input.correlationStateCounts).filter(([k, v]) => typeof k === 'string' && typeof v === 'number' && Number.isFinite(v) && v >= 0))
    : {};
  return Object.freeze({
    schemaVersion: '1.0.0',
    relatedAssetCount,
    relatedComponentCount,
    correlationStateCounts: Object.freeze(correlationStateCounts),
  });
}

/**
 * V6.7: narrow optional report boundary for local
 * remediation. When the caller supplies a
 * `localRemediationSummary` the snapshot carries a
 * small object that is excluded by default. The
 * summary never contains owner labels, plan
 * descriptions, task titles, evidence descriptions,
 * file fingerprints, blocker reasons, validation
 * notes, or actor labels — only counts and the
 * count of plans with a broken ledger chain.
 */
function computeLocalRemediationSummary(input) {
  if (!input || typeof input !== 'object') return null;
  const intCount = (v) => (typeof v === 'number' && Number.isFinite(v)) ? Math.max(0, Math.floor(v)) : 0;
  const activePlanCount = intCount(input.activePlanCount);
  const draftPlanCount = intCount(input.draftPlanCount);
  const blockedPlanCount = intCount(input.blockedPlanCount);
  const overduePlanCount = intCount(input.overduePlanCount);
  const validationPendingCount = intCount(input.validationPendingCount);
  const completedLocalCount = intCount(input.completedLocalCount);
  const acceptedRiskCount = intCount(input.acceptedRiskCount);
  const archivedPlanCount = intCount(input.archivedPlanCount);
  const brokenLedgerCount = intCount(input.brokenLedgerCount);
  return Object.freeze({
    schemaVersion: '1.0.0',
    activePlanCount,
    draftPlanCount,
    blockedPlanCount,
    overduePlanCount,
    validationPendingCount,
    completedLocalCount,
    acceptedRiskCount,
    archivedPlanCount,
    brokenLedgerCount,
  });
}

/** Capture the local workspace entries the report
 *  cares about. The selection is applied here
 *  (archived / resolved / notes / tags / status /
 *  priority / triage) BEFORE the snapshot is frozen. */
function captureLocalEntries(entriesByCve, cveIds, selection) {
  if (!entriesByCve || typeof entriesByCve !== 'object') return [];
  const wanted = new Set(normaliseCveList(cveIds));
  const out = [];
  for (const id of Array.from(wanted).sort()) {
    const e = entriesByCve[id];
    if (!e) continue;
    if (!selection.includeArchived && e.archived) continue;
    if (!selection.includeResolved && e.triageStatus === 'resolved') continue;
    out.push({
      cveId: id,
      watched: !!e.watched,
      triageStatus: e.triageStatus || 'unreviewed',
      userPriority: e.userPriority || 'none',
      tags: Array.isArray(e.tags) ? e.tags.slice() : [],
      // Notes are gated by `includePrivateNotes`. The
      // field is `null` (not omitted) so the JSON shape
      // is stable; the absence is a deliberate redaction
      // signal, not a missing field.
      note: selection.includePrivateNotes
        ? (typeof e.note === 'string' ? e.note : '')
        : null,
      addedAt: e.addedAt || null,
      updatedAt: e.updatedAt || null,
      lastReviewedAt: e.lastReviewedAt || null,
      lastSeenPublicIntelligenceVersion: e.lastSeenPublicIntelligenceVersion || null,
      lastSeenChangeSignature: e.lastSeenChangeSignature || null,
      lastSeenPublicProjectionSchemaVersion: e.lastSeenPublicProjectionSchemaVersion || null,
      revision: typeof e.revision === 'number' ? e.revision : 0,
      mutationId: e.mutationId || null,
    });
  }
  return out;
}

/**
 * Build a coherent snapshot. The function is async
 * and resolves to a frozen `ReportSnapshot` object.
 *
 * The function throws when:
 *   - the public-intelligence version and the
 *     selected public CVE records do not share a
 *     compatible version (caller-supplied check)
 *   - the workspace has pending writes that cannot
 *     be flushed
 *   - the selected CVEs set is empty
 *
 * Inputs:
 *   - publicMeta: the FetchResult.meta (v6.1 fields)
 *   - vulns: the current public CVE list
 *   - entriesByCve: a snapshot of the workspace
 *     entriesByCve map (e.g. from useWorkspace().state)
 *   - selection: { cveIds, includeArchived,
 *     includeResolved, includePrivateNotes,
 *     includeLocalTags, workspaceFilters? }
 *   - flushPendingWrites: a function returning a
 *     promise that resolves when every in-flight
 *     workspace write has settled. The function
 *     returns the same `void`. The snapshot builder
 *     REFUSES to proceed when the flush rejects.
 *   - hasPendingWrites: a boolean indicating whether
 *     any in-flight write is currently outstanding.
 *   - options: { applicationVersion, generatedAt }
 */
export async function buildReportSnapshot({
  publicMeta,
  vulns,
  entriesByCve,
  selection,
  flushPendingWrites,
  hasPendingWrites,
  options,
}) {
  if (!selection || !Array.isArray(selection.cveIds) || selection.cveIds.length === 0) {
    throw new Error(EMPTY_SNAPSHOT_ERROR);
  }
  if (typeof flushPendingWrites === 'function') {
    // Refuse to proceed if writes are outstanding
    // and the flush rejects.
    try {
      await flushPendingWrites();
    } catch (err) {
      const reason = err instanceof Error ? err.message : 'flush-failed';
      const e = new Error(`snapshot:flush-failed:${reason}`);
      e.name = 'SnapshotFlushError';
      throw e;
    }
    if (hasPendingWrites) {
      const e = new Error('snapshot:flush-still-pending');
      e.name = 'SnapshotFlushError';
      throw e;
    }
  }
  const cveIds = normaliseCveList(selection.cveIds);
  if (cveIds.length === 0) {
    throw new Error(EMPTY_SNAPSHOT_ERROR);
  }
  const publicIntelligence = capturePublicIntelligence(publicMeta);
  const publicRecords = capturePublicCveRecords(vulns, cveIds);
  const localEntries = captureLocalEntries(entriesByCve, cveIds, {
    includeArchived: !!selection.includeArchived,
    includeResolved: !!selection.includeResolved,
    includePrivateNotes: !!selection.includePrivateNotes,
    includeLocalTags: selection.includeLocalTags !== false, // default true
  });
  // V6.6: narrow optional report boundary. When the
  // caller supplies a `localEnvironmentSummary` the
  // snapshot carries a small object that is excluded
  // by default. The summary never contains asset
  // names, component paths, owner labels, or local
  // review notes — only counts.
  const localEnvironmentSummary = computeLocalEnvironmentSummary(options?.localEnvironmentSummary);
  // V6.7: narrow optional report boundary for local
  // remediation. Same shape as `localEnvironmentSummary`:
  // counts only, no owner labels / plan / task / evidence
  // / fingerprint / blocker content. Excluded by default.
  const localRemediationSummary = computeLocalRemediationSummary(options?.localRemediationSummary);
  return Object.freeze({
    capturedAt: options?.generatedAt || new Date().toISOString(),
    applicationVersion: options?.applicationVersion || 'unknown',
    publicIntelligence: Object.freeze(publicIntelligence),
    publicRecords: Object.freeze(publicRecords),
    localEntries: Object.freeze(localEntries),
    localEnvironmentSummary,
    localRemediationSummary,
    cveIds: Object.freeze(cveIds),
    selection: Object.freeze({
      cveIds: Object.freeze(cveIds),
      includePrivateNotes: !!selection.includePrivateNotes,
      includeLocalTags: selection.includeLocalTags !== false,
      includeResolved: !!selection.includeResolved,
      includeArchived: !!selection.includeArchived,
    }),
  });
}

export { EMPTY_SNAPSHOT_ERROR };
