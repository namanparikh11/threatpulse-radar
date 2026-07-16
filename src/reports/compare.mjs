/**
 * V6.5 — Report comparison.
 *
 * Compares two valid report bundles. The comparison
 * pipeline is:
 *
 *   1. verifyShape(a) and verifyShape(b) — both
 *      must pass; an 'unsupported-schema' report
 *      is never compared.
 *   2. Recompute the SHA-256 of both reports
 *      and compare to the embedded integrity block.
 *      If either fails integrity, comparison is
 *      refused (we will not compare a tampered
 *      bundle to a clean one).
 *   3. Compute structured diffs across:
 *        - metadata (title, type, generatedAt, app version)
 *        - publicIntelligence (status / version /
 *          projectionSchemaVersion / sourceHealth)
 *        - selection
 *        - CVE sets (added / removed)
 *        - per-CVE provider facts present (severity,
 *          cvss, epss, kev, ssvc, vulnrichment,
 *          githubAdvisory, osv, withdrawn, changeTag)
 *        - per-CVE ThreatPulse classifications
 *        - per-CVE local status / priority / tags
 *        - per-CVE notes (only when both reports
 *          explicitly contain them)
 *        - provenance rows
 *        - limitations (added / removed)
 *
 *   4. The result is a structured `DiffResult`
 *      object. The comparison NEVER interprets
 *      "absence in the older report" as
 *      "remediated in the newer report".
 *
 * The comparison is pure (no network, no URL, no
 * console) and never mutates either input.
 */

import { canonicalizeReportBytes } from './canonicalize.mjs';
import { digestString, ShaUnavailableError } from './sha256.mjs';
import { verifyShape } from './verify.mjs';

const PROVIDER_FACT_FIELDS = [
  'severity', 'cvssScore', 'epssProbability', 'kev',
  'ssvc', 'vulrichment' /* keep typo-free: 'vulnrichment' is the project name */,
  'vulnrichment',
  'githubAdvisory', 'osv', 'withdrawn', 'publishedDate', 'summary', 'source', 'externalLinks',
];

/** Extract provider-fact rows for a single CVE block. */
function cveBlockRows(block) {
  if (!block || block.kind !== 'cve-block' || !Array.isArray(block.rows)) return {};
  const out = {};
  for (const r of block.rows) {
    if (r && typeof r === 'object' && r.label) out[r.label] = r.value;
  }
  return out;
}

/** Extract all CVE-block rows from a report's sections. */
function extractCveRows(report) {
  const out = {};
  if (!report || !Array.isArray(report.sections)) return out;
  for (const s of report.sections) {
    if (!s || s.kind !== 'cve-list' || !Array.isArray(s.body)) continue;
    for (const b of s.body) {
      if (!b || b.kind !== 'cve-block') continue;
      out[b.cveId] = cveBlockRows(b);
    }
  }
  return out;
}

/** Extract the per-CVE "Local triage status" / "User-assigned local priority"
 *  / "Local tags" / "Watched" / "Local private note" / "ThreatPulse
 *  classification" rows from a report. */
function extractLocalRows(report) {
  const out = {};
  if (!report || !Array.isArray(report.sections)) return out;
  const wanted = new Set([
    'Local triage status (user-authored)',
    'User-assigned local priority',
    'Local tags (user-authored)',
    'Watched',
    'Local private note (user-authored)',
    'Local private note',
    'ThreatPulse classification',
  ]);
  for (const s of report.sections) {
    if (!s || s.kind !== 'cve-list' || !Array.isArray(s.body)) continue;
    for (const b of s.body) {
      if (!b || b.kind !== 'cve-block') continue;
      const entry = {};
      for (const r of (b.rows || [])) {
        if (r && r.label && wanted.has(r.label)) entry[r.label] = r.value;
      }
      out[b.cveId] = entry;
    }
  }
  return out;
}

/** Recompute the integrity of a report. Returns the
 *  expected sha256 prefixed string or `null` when
 *  the runtime cannot compute it. */
async function recomputeIntegrity(report) {
  try {
    const hex = await digestString(canonicalizeReportBytes(report));
    return `sha256:${hex}`;
  } catch (err) {
    if (err instanceof ShaUnavailableError) return null;
    return null;
  }
}

/** Compare two valid report bundles. Returns a
 *  structured `DiffResult` object. */
export async function compareReports(a, b) {
  // Step 1: shape check.
  const aShape = verifyShape(a);
  const bShape = verifyShape(b);
  if (!aShape.ok) {
    return { ok: false, reason: `left-report:${aShape.status}` };
  }
  if (!bShape.ok) {
    return { ok: false, reason: `right-report:${bShape.status}` };
  }
  // Step 2: integrity check.
  const aInteg = await recomputeIntegrity(a);
  const bInteg = await recomputeIntegrity(b);
  if (a.integrity.checksum !== aInteg) {
    return { ok: false, reason: 'left-report-integrity-failed' };
  }
  if (b.integrity.checksum !== bInteg) {
    return { ok: false, reason: 'right-report-integrity-failed' };
  }
  // Step 3: structured diffs.
  const meta = diffMetadata(a, b);
  const pi = diffPublicIntelligence(a, b);
  const sel = diffSelection(a, b);
  const cves = diffCveSets(a, b);
  const aRows = extractCveRows(a);
  const bRows = extractCveRows(b);
  const provider = diffProviderFacts(aRows, bRows, cves.union);
  const localA = extractLocalRows(a);
  const localB = extractLocalRows(b);
  const local = diffLocalFacts(localA, localB, cves.union);
  const provenance = diffProvenance(a, b);
  const limitations = diffLimitations(a, b);
  return {
    ok: true,
    left: { reportId: a.reportId, generatedAt: a.generatedAt, checksum: a.integrity.checksum },
    right: { reportId: b.reportId, generatedAt: b.generatedAt, checksum: b.integrity.checksum },
    metadata: meta,
    publicIntelligence: pi,
    selection: sel,
    cves,
    providerFacts: provider,
    localFacts: local,
    provenance,
    limitations,
  };
}

function diffMetadata(a, b) {
  const keys = ['title', 'reportType', 'generatedAt', 'applicationVersion'];
  const out = { changed: [], added: [], removed: [] };
  for (const k of keys) {
    if (!(k in a) && (k in b)) out.added.push({ key: k, value: b[k] });
    else if ((k in a) && !(k in b)) out.removed.push({ key: k, value: a[k] });
    else if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) {
      out.changed.push({ key: k, left: a[k], right: b[k] });
    }
  }
  return out;
}

function diffPublicIntelligence(a, b) {
  const left = (a && a.publicIntelligence) || {};
  const right = (b && b.publicIntelligence) || {};
  const keys = ['status', 'version', 'projectionSchemaVersion', 'generatedAt', 'comparableAxes', 'suppressedAxes'];
  const out = { changed: [], added: [], removed: [] };
  for (const k of keys) {
    if (!(k in left) && (k in right)) out.added.push({ key: k, value: right[k] });
    else if ((k in left) && !(k in right)) out.removed.push({ key: k, value: left[k] });
    else if (JSON.stringify(left[k]) !== JSON.stringify(right[k])) {
      out.changed.push({ key: k, left: left[k], right: right[k] });
    }
  }
  return out;
}

function diffSelection(a, b) {
  const left = (a && a.selection) || {};
  const right = (b && b.selection) || {};
  const keys = ['cveIds', 'includePrivateNotes', 'includeLocalTags', 'includeResolved', 'includeArchived'];
  const out = { changed: [], added: [], removed: [] };
  for (const k of keys) {
    if (!(k in left) && (k in right)) out.added.push({ key: k, value: right[k] });
    else if ((k in left) && !(k in right)) out.removed.push({ key: k, value: left[k] });
    else if (JSON.stringify(left[k]) !== JSON.stringify(right[k])) {
      out.changed.push({ key: k, left: left[k], right: right[k] });
    }
  }
  return out;
}

function diffCveSets(a, b) {
  const left = new Set(Array.isArray(a?.selection?.cveIds) ? a.selection.cveIds : []);
  const right = new Set(Array.isArray(b?.selection?.cveIds) ? b.selection.cveIds : []);
  const added = [];
  const removed = [];
  const union = [];
  for (const c of right) {
    union.push(c);
    if (!left.has(c)) added.push(c);
  }
  for (const c of left) {
    union.push(c);
    if (!right.has(c)) removed.push(c);
  }
  union.sort();
  added.sort();
  removed.sort();
  return { added, removed, union: Array.from(new Set(union)).sort() };
}

function diffProviderFacts(aRows, bRows, cveIds) {
  const labels = [
    'Severity', 'CVSS', 'EPSS', 'KEV', 'SSVC', 'Vulnrichment',
    'GitHub advisory', 'OSV record ids', 'Withdrawn', 'Published',
    'Summary', 'Vendor / product', 'Source', 'Official link',
    'Public record', 'ThreatPulse classification',
  ];
  const out = [];
  for (const c of cveIds) {
    const a = aRows[c] || {};
    const b = bRows[c] || {};
    const per = [];
    for (const l of labels) {
      const hasA = Object.prototype.hasOwnProperty.call(a, l);
      const hasB = Object.prototype.hasOwnProperty.call(b, l);
      if (!hasA && !hasB) continue;
      if (hasA && !hasB) per.push({ label: l, change: 'removed', right: a[l] });
      else if (!hasA && hasB) per.push({ label: l, change: 'added', right: b[l] });
      else if (JSON.stringify(a[l]) !== JSON.stringify(b[l])) per.push({ label: l, change: 'changed', left: a[l], right: b[l] });
    }
    if (per.length > 0) out.push({ cveId: c, rows: per });
  }
  return out;
}

function diffLocalFacts(localA, localB, cveIds) {
  const labels = [
    'Local triage status (user-authored)',
    'User-assigned local priority',
    'Local tags (user-authored)',
    'Watched',
    'Local private note (user-authored)',
    'Local private note',
  ];
  const out = [];
  for (const c of cveIds) {
    const a = localA[c] || {};
    const b = localB[c] || {};
    const per = [];
    for (const l of labels) {
      const hasA = Object.prototype.hasOwnProperty.call(a, l);
      const hasB = Object.prototype.hasOwnProperty.call(b, l);
      if (!hasA && !hasB) continue;
      if (hasA && !hasB) per.push({ label: l, change: 'removed', right: a[l] });
      else if (!hasA && hasB) per.push({ label: l, change: 'added', right: b[l] });
      else if (JSON.stringify(a[l]) !== JSON.stringify(b[l])) per.push({ label: l, change: 'changed', left: a[l], right: b[l] });
    }
    if (per.length > 0) out.push({ cveId: c, rows: per });
  }
  return out;
}

function diffProvenance(a, b) {
  const left = Array.isArray(a?.provenance) ? a.provenance : [];
  const right = Array.isArray(b?.provenance) ? b.provenance : [];
  const leftKey = new Set(left.map((p) => p?.sourceId || p?.name || ''));
  const rightKey = new Set(right.map((p) => p?.sourceId || p?.name || ''));
  const added = [];
  const removed = [];
  const changed = [];
  for (const p of right) {
    const key = p?.sourceId || p?.name || '';
    if (!leftKey.has(key)) added.push(p);
    else {
      const other = left.find((q) => (q?.sourceId || q?.name || '') === key);
      if (JSON.stringify(other) !== JSON.stringify(p)) changed.push({ left: other, right: p });
    }
  }
  for (const p of left) {
    const key = p?.sourceId || p?.name || '';
    if (!rightKey.has(key)) removed.push(p);
  }
  return { added, removed, changed };
}

function diffLimitations(a, b) {
  const left = new Set(Array.isArray(a?.limitations) ? a.limitations : []);
  const right = new Set(Array.isArray(b?.limitations) ? b.limitations : []);
  const added = [];
  const removed = [];
  for (const l of right) if (!left.has(l)) added.push(l);
  for (const l of left) if (!right.has(l)) removed.push(l);
  return { added, removed };
}

export { PROVIDER_FACT_FIELDS };
