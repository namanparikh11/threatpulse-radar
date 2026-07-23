/**
 * V6.4 — Deterministic change signature.
 *
 * Produces a short, stable hash that summarizes the
 * public-intelligence view of a CVE at a given
 * public-intelligence version. The signature is the
 * primary input to "changed since review" detection.
 *
 * The signature is computed from PUBLIC-SAFE fields
 * only. No provider record bodies, no SSVC string
 * content, no notes, no tags. The signature changes
 * when the public view changes, but the underlying
 * record does NOT need to be copied into IndexedDB.
 *
 * Components of the signature (all normalized):
 *   - publicIntelligenceVersion (string)
 *   - publicProjectionSchemaVersion (string)
 *   - severity
 *   - cvssScore
 *   - epssProbability (4-decimal fixed)
 *   - kev (boolean)
 *   - ssvc.exploitation
 *   - ssvc.automatable
 *   - ssvc.technicalImpact
 *   - vulnrichment presence (boolean)
 *   - githubAdvisory presence (boolean)
 *   - osv record set fingerprint (sorted, joined)
 *   - withdrawn (boolean)
 *
 * Each field is concatenated as `key=value` joined by
 * `|`, then hashed with SHA-256. The output is a
 * lowercase hex digest prefixed with `sha256:`.
 *
 * The SHA-256 implementation is the async Web Crypto
 * helper in ./sha256.mjs. A pure-JS sync fallback is
 * used for unit tests; the export and import paths
 * always go through the async API.
 */

import { sha256HexAsync, sha256HexSync } from './sha256.mjs';

function fixed4(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) return '0.0000';
  return n.toFixed(4);
}

function bool01(b) {
  return b ? '1' : '0';
}

/**
 * Compute the change signature for a CVE at a given
 * public-intelligence version. The function accepts a
 * raw `vuln` object and a version string and returns
 * the signature in the form `sha256:<64 hex chars>`.
 *
 * Fields that are absent (e.g. github advisory not
 * present for this CVE) are encoded as empty strings
 * so two views with the same absence signature the
 * same.
 *
 * The function accepts the public-projection schema
 * version as a separate parameter so the signature
 * is bound to the schema that produced it. The
 * signature changes when the public-projection schema
 * changes even if every other field is identical.
 */
export async function computeChangeSignature(vuln, publicIntelligenceVersion, publicProjectionSchemaVersion) {
  if (!vuln || typeof vuln !== 'object') {
    return `sha256:${await sha256HexAsync('__empty__')}`;
  }
  const v = vuln;
  const ssvc = v.ssvc || {};
  const osv = v.osv || {};
  const osvIds = Array.isArray(osv.recordIds) ? osv.recordIds.slice().sort().join(',') : '';
  const parts = [
    `v=${publicIntelligenceVersion || ''}`,
    `schema=${publicProjectionSchemaVersion || ''}`,
    `severity=${v.severity || ''}`,
    `cvss=${fixed4(typeof v.cvssScore === 'number' ? v.cvssScore : 0)}`,
    `epss=${fixed4(typeof v.epssProbability === 'number' ? v.epssProbability : 0)}`,
    `kev=${bool01(!!v.kev)}`,
    `ssvcE=${ssvc.exploitation || ''}`,
    `ssvcA=${ssvc.automatable || ''}`,
    `ssvcT=${ssvc.technicalImpact || ''}`,
    `vr=${bool01(!!v.vulnrichment)}`,
    `gh=${bool01(!!v.githubAdvisory)}`,
    `osv=${osvIds}`,
    `wd=${bool01(!!v.withdrawn)}`,
  ];
  const data = parts.join('|');
  return `sha256:${await sha256HexAsync(data)}`;
}

/** Sync helper for unit tests and small per-CVE
 *  computations where the async path is impractical.
 *  The browser production path always uses
 *  computeChangeSignature. */
export function computeChangeSignatureSync(vuln, publicIntelligenceVersion, publicProjectionSchemaVersion) {
  if (!vuln || typeof vuln !== 'object') {
    return `sha256:${sha256HexSync('__empty__')}`;
  }
  const v = vuln;
  const ssvc = v.ssvc || {};
  const osv = v.osv || {};
  const osvIds = Array.isArray(osv.recordIds) ? osv.recordIds.slice().sort().join(',') : '';
  const parts = [
    `v=${publicIntelligenceVersion || ''}`,
    `schema=${publicProjectionSchemaVersion || ''}`,
    `severity=${v.severity || ''}`,
    `cvss=${fixed4(typeof v.cvssScore === 'number' ? v.cvssScore : 0)}`,
    `epss=${fixed4(typeof v.epssProbability === 'number' ? v.epssProbability : 0)}`,
    `kev=${bool01(!!v.kev)}`,
    `ssvcE=${ssvc.exploitation || ''}`,
    `ssvcA=${ssvc.automatable || ''}`,
    `ssvcT=${ssvc.technicalImpact || ''}`,
    `vr=${bool01(!!v.vulnrichment)}`,
    `gh=${bool01(!!v.githubAdvisory)}`,
    `osv=${osvIds}`,
    `wd=${bool01(!!v.withdrawn)}`,
  ];
  const data = parts.join('|');
  return `sha256:${sha256HexSync(data)}`;
}

/**
 * Determine whether two public-intelligence versions
 * are directly comparable.
 *
 * v6.4 hardened: the V6.1 version id is a timestamp
 * + hash form (`<fs-safe-iso>-<short-hex>`), NOT a
 * semver. The compat check is therefore EXACT
 * equality. Two records with different version ids
 * are NEVER treated as compatible, even when the
 * prefix strings happen to share characters.
 *
 * The "compat" notion we DO need is on the
 * projection schema version, not the dataset
 * version: two records produced by the same
 * projection schema version can be compared
 * directly. The two checks are decoupled; the
 * caller passes the projection schema version
 * separately.
 */
export function publicVersionsEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length === 0 || b.length === 0) return false;
  return a === b;
}

/**
 * Compare the current CVE view (with a current
 * publicIntelligenceVersion) against the workspace
 * record's `lastSeenPublicIntelligenceVersion`,
 * `lastSeenChangeSignature`, and
 * `lastSeenPublicProjectionSchemaVersion`. Returns:
 *   - 'unavailable': missing change intelligence OR
 *     the current bundle is not directly comparable
 *     to the review checkpoint
 *   - 'no-newer': current signature equals the
 *     last-seen signature at the EXACT same
 *     public-intelligence version and projection
 *     schema version
 *   - 'changed': current signature differs from the
 *     last-seen signature at the EXACT same
 *     public-intelligence version and projection
 *     schema version
 *   - 'newly-tracked': the workspace record has no
 *     `lastSeenPublicIntelligenceVersion` yet
 *   - 'no-longer-tracked': the CVE is no longer in
 *     the public dataset (caller supplies this
 *     signal)
 *
 * An older or mismatched bundle (different version
 * or different projection schema) means "Change
 * status unavailable" — never a fabricated change
 * claim.
 */
export function classifyChange({
  currentVersion,
  currentProjectionSchemaVersion,
  currentSignature,
  record,
  presentInPublic = true,
}) {
  if (!record) return 'unavailable';
  if (!presentInPublic) return 'no-longer-tracked';
  if (!record.lastSeenPublicIntelligenceVersion) return 'newly-tracked';
  if (!record.lastSeenChangeSignature) return 'unavailable';
  // Exact-equality compat on the version id
  // (timestamp + short hash, NOT semver).
  if (!publicVersionsEqual(record.lastSeenPublicIntelligenceVersion, currentVersion)) {
    return 'unavailable';
  }
  // Projection schema must match exactly too.
  // A record that was stamped under an older
  // schema is not directly comparable to a
  // current bundle produced under a newer schema.
  if (!publicVersionsEqual(record.lastSeenPublicProjectionSchemaVersion || '', currentProjectionSchemaVersion || '')) {
    return 'unavailable';
  }
  if (currentSignature === record.lastSeenChangeSignature) return 'no-newer';
  return 'changed';
}
