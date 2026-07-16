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
 * The SHA-256 implementation is the pure-JS sync
 * implementation in ./sha256.mjs. The Web Crypto API
 * is async and would force every change-detection
 * comparison through a Promise boundary.
 */

import { sha256Hex } from './sha256.mjs';

const FIELDS = [
  'severity',
  'cvssScore',
  'epssProbability',
  'kev',
  'ssvcExploitation',
  'ssvcAutomatable',
  'ssvcTechnicalImpact',
  'vulnrichment',
  'githubAdvisory',
  'osvRecordIds',
  'withdrawn',
];

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
 */
export function computeChangeSignature(vuln, publicIntelligenceVersion) {
  if (!vuln || typeof vuln !== 'object') {
    return sha256Hex('__empty__');
  }
  const v = vuln;
  const ssvc = v.ssvc || {};
  const osv = v.osv || {};
  const osvIds = Array.isArray(osv.recordIds) ? osv.recordIds.slice().sort().join(',') : '';
  const parts = [
    `v=${publicIntelligenceVersion || ''}`,
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
  return sha256Hex(data);
}

/**
 * Compute a public-intelligence version fingerprint
 * (independent of the workspace record). Used to
 * detect a newer compatible public-intelligence
 * version: a workspace record whose
 * `lastSeenPublicIntelligenceVersion` differs from
 * the current `publicIntelligenceVersion` is a
 * candidate for "changed since review". The actual
 * change is then decided by comparing change
 * signatures on the same version.
 */
export function versionsAreCompatible(a, b) {
  // Two versions are considered compatible when they
  // share a major + minor (e.g. v6-1-... and v6-1-...
  // are compatible; v6-1-... and v6-2-... are not).
  // The format in use is `v<MAJOR>-<MINOR>-<HASH>`.
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ca = a.split('-'); const cb = b.split('-');
  if (ca.length < 2 || cb.length < 2) return false;
  return ca[0] === cb[0] && ca[1] === cb[1];
}

/**
 * Compare the current CVE view (with a current
 * `publicIntelligenceVersion`) against the workspace
 * record's `lastSeenPublicIntelligenceVersion` and
 * `lastSeenChangeSignature`. Returns a label:
 *   - 'unavailable': missing change intelligence OR
 *     versions are not comparable
 *   - 'no-newer': current signature equals the last
 *     seen signature at the SAME compatible version
 *   - 'changed': current signature differs from the
 *     last-seen signature at the SAME compatible
 *     version
 *   - 'newly-tracked': the workspace record has no
 *     `lastSeenPublicIntelligenceVersion` yet
 *   - 'no-longer-tracked': the CVE is no longer in
 *     the public dataset (caller supplies this signal)
 */
export function classifyChange({ currentVersion, currentSignature, record, presentInPublic = true }) {
  if (!record) return 'unavailable';
  if (!presentInPublic) return 'no-longer-tracked';
  if (!record.lastSeenPublicIntelligenceVersion) return 'newly-tracked';
  if (!record.lastSeenChangeSignature) return 'unavailable';
  if (!versionsAreCompatible(record.lastSeenPublicIntelligenceVersion, currentVersion)) {
    return 'unavailable';
  }
  if (currentVersion !== record.lastSeenPublicIntelligenceVersion) {
    return 'unavailable';
  }
  if (currentSignature === record.lastSeenChangeSignature) return 'no-newer';
  return 'changed';
}
