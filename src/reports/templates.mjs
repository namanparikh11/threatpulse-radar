/**
 * V6.5 — Report templates.
 *
 * Each template takes a `ReportSnapshot` and returns a
 * `sections` array. The array is the JSON section
 * payload that the JSON exporter serialises verbatim
 * and the Markdown / HTML exporters walk to render.
 *
 * The five templates correspond to the five
 * documented report types. Each template is pure and
 * deterministic: same snapshot + same options →
 * same output.
 *
 * Every section is annotated with a `kind` so the
 * preview can render an inline metadata pill
 * (provider-fact / ThreatPulse-derived /
 * user-authored / system-metadata /
 * unavailable-or-uncertain). The labels are stable
 * strings the test suite can grep.
 *
 * The templates DO NOT:
 *   - read the network
 *   - read the URL
 *   - log anything
 *   - mutate the snapshot
 *   - call any side-effectful function
 */

import { FIELD_KIND } from './schema.mjs';
import { describeField, modeHidesBody, modeHidesNote, modeHidesStatus, modeHidesTags } from './redaction.mjs';

/** A helper to build a section. */
function section(kind, title, body, extra = {}) {
  return Object.freeze({
    kind,
    title: typeof title === 'string' ? title : '',
    body: Array.isArray(body) ? body.map(Object.freeze) : body,
    ...extra,
  });
}

/** Render the limitations block that every report
 *  carries. The block is deterministic and includes
 *  the standard "this is a local-only, not certified"
 *  preamble. */
export function renderLimitations(snapshot, extra = []) {
  const base = [
    'Reports are generated entirely in this browser. They may contain private notes or internal workflow information. Review the preview before exporting.',
    'This report is not a certification, a legal attestation, or a substitute for asset validation, patch testing, or professional judgment.',
    'Public intelligence may be incomplete, delayed, stale, or unavailable. Missing enrichment is not evidence of absence.',
    'User-assigned local status, priority, and tags are user-authored workflow information. They are not provider severity, exploitation likelihood, or a ThreatPulse risk score.',
    'ThreatPulse classifications (newly tracked, changed, no-longer-tracked) are derived from the public-intelligence version attached at snapshot time and may differ from later upstream snapshots.',
  ];
  if (snapshot.publicIntelligence.status !== 'available') {
    base.unshift(`Public intelligence status is "${snapshot.publicIntelligence.status}" in this snapshot. Some derived signals may be unavailable.`);
  }
  for (const e of extra) base.push(e);
  return base;
}

/** Render the provenance block: one row per
 *  documented public source with name, official URL,
 *  and last-success timestamp. */
export function renderProvenance(snapshot) {
  const rows = [];
  for (const sh of snapshot.publicIntelligence.sourceHealth) {
    rows.push({
      sourceId: sh.sourceId,
      name: sh.name,
      state: sh.state,
      lastSuccessAt: sh.lastSuccessAt,
      officialUrl: sh.officialUrl,
    });
  }
  return rows;
}

/** Render the header section every report shares. */
function renderHeader(snapshot, report) {
  return section('system-metadata', 'Report header', [
    { label: 'Generated at', kind: FIELD_KIND.SYSTEM_METADATA, value: report.generatedAt },
    { label: 'Application version', kind: FIELD_KIND.SYSTEM_METADATA, value: report.applicationVersion },
    { label: 'Report ID', kind: FIELD_KIND.SYSTEM_METADATA, value: report.reportId },
    { label: 'Report type', kind: FIELD_KIND.SYSTEM_METADATA, value: report.reportType },
  ]);
}

function renderPublicIntelligence(snapshot) {
  return section('system-metadata', 'Public intelligence', [
    { label: 'Status', kind: FIELD_KIND.SYSTEM_METADATA, value: snapshot.publicIntelligence.status },
    { label: 'Version', kind: FIELD_KIND.SYSTEM_METADATA, value: snapshot.publicIntelligence.version },
    { label: 'Projection schema version', kind: FIELD_KIND.SYSTEM_METADATA, value: snapshot.publicIntelligence.projectionSchemaVersion },
    { label: 'Generated at', kind: FIELD_KIND.SYSTEM_METADATA, value: snapshot.publicIntelligence.generatedAt },
  ]);
}

function renderProvenanceSection(snapshot) {
  return section('system-metadata', 'Source provenance', renderProvenance(snapshot));
}

/** Render a per-CVE section body. The body is a list
 *  of label/value rows; the labels are the same stable
 *  strings the test suite can grep. */
function renderCveBody(snapshot, options) {
  const { mode, includePrivateNotes, includeLocalTags } = options;
  const hideBody = modeHidesBody(mode);
  const hideNote = modeHidesNote(mode);
  const hideTags = modeHidesTags(mode);
  const hideStatus = modeHidesStatus(mode);
  const localByCve = new Map();
  for (const e of snapshot.localEntries) localByCve.set(e.cveId, e);
  const out = [];
  for (const cve of snapshot.publicRecords) {
    if (hideBody) {
      out.push({ kind: 'cve-identifier-only', cveId: cve.cveId });
      continue;
    }
    const local = localByCve.get(cve.cveId);
    const rows = [];
    if (cve.unavailable) {
      rows.push({ label: 'Public record', kind: FIELD_KIND.UNAVAILABLE, value: 'unavailable in this snapshot' });
    } else {
      rows.push({ label: 'Severity', kind: FIELD_KIND.PROVIDER_FACT, value: cve.severity });
      if (cve.cvssScore !== null) rows.push({ label: 'CVSS', kind: FIELD_KIND.PROVIDER_FACT, value: cve.cvssScore });
      if (cve.epssProbability !== null) rows.push({ label: 'EPSS', kind: FIELD_KIND.PROVIDER_FACT, value: cve.epssProbability });
      rows.push({ label: 'KEV', kind: FIELD_KIND.PROVIDER_FACT, value: cve.kev });
      if (cve.ssvc) rows.push({ label: 'SSVC', kind: FIELD_KIND.PROVIDER_FACT, value: cve.ssvc });
      rows.push({ label: 'Vulnrichment', kind: FIELD_KIND.PROVIDER_FACT, value: cve.vulnrichment });
      rows.push({ label: 'GitHub advisory', kind: FIELD_KIND.PROVIDER_FACT, value: cve.githubAdvisory });
      if (cve.osv) rows.push({ label: 'OSV record ids', kind: FIELD_KIND.PROVIDER_FACT, value: (cve.osv.recordIds || []).join(',') });
      rows.push({ label: 'Withdrawn', kind: FIELD_KIND.PROVIDER_FACT, value: cve.withdrawn });
      if (cve.publishedDate) rows.push({ label: 'Published', kind: FIELD_KIND.PROVIDER_FACT, value: cve.publishedDate });
      if (cve.summary) rows.push({ label: 'Summary', kind: FIELD_KIND.PROVIDER_FACT, value: cve.summary });
      if (cve.vendor || cve.product) rows.push({ label: 'Vendor / product', kind: FIELD_KIND.PROVIDER_FACT, value: `${cve.vendor} / ${cve.product}` });
      if (cve.source) rows.push({ label: 'Source', kind: FIELD_KIND.PROVIDER_FACT, value: cve.source });
      if (Array.isArray(cve.externalLinks) && cve.externalLinks.length > 0) {
        for (const link of cve.externalLinks) {
          rows.push({ label: 'Official link', kind: FIELD_KIND.PROVIDER_FACT, value: link.url });
        }
      }
      if (cve.changeTag) {
        rows.push({ label: 'ThreatPulse classification', kind: FIELD_KIND.THREATPULSE_DERIVED, value: cve.changeTag });
      }
    }
    if (local) {
      if (!hideStatus) {
        rows.push({ label: 'Local triage status (user-authored)', kind: FIELD_KIND.USER_AUTHORED, value: local.triageStatus });
        rows.push({ label: 'User-assigned local priority', kind: FIELD_KIND.USER_AUTHORED, value: local.userPriority });
        rows.push({ label: 'Watched', kind: FIELD_KIND.USER_AUTHORED, value: local.watched });
      }
      if (!hideTags) {
        rows.push({ label: 'Local tags (user-authored)', kind: FIELD_KIND.USER_AUTHORED, value: (local.tags || []).join(', ') });
      }
      if (includePrivateNotes && !hideNote) {
        if (local.note !== null) {
          rows.push({ label: 'Local private note (user-authored)', kind: FIELD_KIND.USER_AUTHORED, value: local.note });
        }
      } else if (!hideNote) {
        rows.push({ label: 'Local private note', kind: FIELD_KIND.USER_AUTHORED, value: '(redacted)' });
      }
    } else {
      rows.push({ label: 'Local workspace entry', kind: FIELD_KIND.UNAVAILABLE, value: 'no entry' });
    }
    out.push({ kind: 'cve-block', cveId: cve.cveId, rows: rows.map(Object.freeze) });
  }
  return out;
}

function cveSection(title, snapshot, options) {
  return section('cve-list', title, renderCveBody(snapshot, options));
}

/** Build the document sections for a given report
 *  type + snapshot + options. The result is an array
 *  of `Section` objects in a stable order. */
export function buildSections(reportType, snapshot, options) {
  const base = [
    renderHeader(snapshot, options.report || {}),
    renderPublicIntelligence(snapshot),
    renderProvenanceSection(snapshot),
  ];
  const head = base;
  const publicOnlyOptions = {
    mode: 'identifiers-only',
    includePrivateNotes: false,
    includeLocalTags: false,
  };
  const fullOptions = {
    mode: options.mode || 'none',
    includePrivateNotes: !!options.includePrivateNotes,
    includeLocalTags: options.includeLocalTags !== false,
  };
  switch (reportType) {
    case 'defender-daily-briefing':
      return head.concat([
        cveSection('Newly tracked and changed CVEs', snapshot, publicOnlyOptions),
        cveSection('Watched CVEs with local status', snapshot, fullOptions),
      ]);
    case 'local-triage-queue':
      return head.concat([
        cveSection('Local triage queue', snapshot, fullOptions),
      ]);
    case 'selected-cve':
      return head.concat([
        cveSection('Selected CVE detail', snapshot, fullOptions),
      ]);
    case 'change-briefing':
      return head.concat([
        cveSection('ThreatPulse change classifications', snapshot, publicOnlyOptions),
        cveSection('Local re-review candidates', snapshot, fullOptions),
      ]);
    case 'executive-summary':
      return head.concat([
        cveSection('Executive summary (identifiers + public facts)', snapshot, publicOnlyOptions),
      ]);
    default:
      return head.concat([
        cveSection('Selected CVEs', snapshot, fullOptions),
      ]);
  }
}

/** Build the full report payload (excluding the
 *  integrity block). The caller adds the integrity
 *  block after computing the SHA-256. */
export function buildReport({ reportId, reportType, title, generatedAt, applicationVersion, snapshot, mode, includePrivateNotes, includeLocalTags }) {
  const safeMode = typeof mode === 'string' && mode ? mode : 'none';
  const report = {
    format: 'threatpulse-local-report',
    schemaVersion: '1.0.0',
    reportId: typeof reportId === 'string' && reportId ? reportId : `rpt-${Date.now()}-${Math.floor(Math.random() * 0xffffff).toString(16)}`,
    reportType,
    title: typeof title === 'string' && title ? title : 'Untitled report',
    generatedAt: typeof generatedAt === 'string' && generatedAt ? generatedAt : new Date().toISOString(),
    applicationVersion: typeof applicationVersion === 'string' && applicationVersion ? applicationVersion : 'unknown',
    publicIntelligence: snapshot.publicIntelligence,
    selection: {
      cveIds: snapshot.cveIds.slice(),
      workspaceFilters: null,
      includePrivateNotes: !!includePrivateNotes,
      includeLocalTags: includeLocalTags !== false,
      includeResolved: !!snapshot.selection.includeResolved,
      includeArchived: !!snapshot.selection.includeArchived,
    },
    sections: buildSections(reportType, snapshot, { mode: safeMode, includePrivateNotes: !!includePrivateNotes, includeLocalTags: includeLocalTags !== false, report: { reportId, reportType, title, generatedAt, applicationVersion } }),
    provenance: renderProvenance(snapshot),
    limitations: renderLimitations(snapshot),
    integrity: { canonicalizationVersion: '1.0.0', checksum: '' },
  };
  return report;
}

export { describeField };
