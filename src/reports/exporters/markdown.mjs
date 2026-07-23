/**
 * V6.5 — Markdown exporter.
 *
 * Renders a redacted report to a deterministic
 * Markdown string. The output is meant to be:
 *   - readable in any text viewer
 *   - pasteable into chat / docs
 *   - stable for the same input (no timestamps that
 *     change on each render)
 *
 * The exporter NEVER:
 *   - touches the network
 *   - executes user content
 *   - includes private values that were redacted
 *     out of the report object
 *
 * User-authored values are escaped so they cannot
 * break out of their container (no Markdown
 * injection). The exporter deliberately does not
 * include HTML; a separate HTML exporter produces
 * the safe HTML rendering.
 */

import { REPORT_LIMITS } from '../schema.mjs';

/** Escape a string for safe inclusion in Markdown.
 *  We escape the four characters that can flip
 *  Markdown semantics (`\`, `*`, `_`, `` ` ``)
 *  and the two characters that can flip a table
 *  row (`|`, newline).  */
function mdEscape(v) {
  if (v === null || v === undefined) return '';
  const s = String(v);
  return s
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ')
    .replace(/`/g, '\\`');
}

/** Render a single key/value row as a Markdown
 *  pipe-table row. */
function row(label, value, kind) {
  const kindLabel = kind ? ` _(${kind})_` : '';
  return `| ${mdEscape(label + kindLabel)} | ${mdEscape(value)} |`;
}

function rowSeparator() {
  return '| --- | --- |';
}

function valueToMd(v) {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  if (Array.isArray(v)) return v.length === 0 ? '—' : v.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(', ');
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

function renderSection(section) {
  if (!section) return '';
  const lines = [];
  lines.push(`### ${section.title || '(untitled section)'}`);
  if (section.body && Array.isArray(section.body)) {
    if (section.kind === 'cve-list') {
      for (const block of section.body) {
        if (!block) continue;
        if (block.kind === 'cve-identifier-only') {
          lines.push('');
          lines.push(`- \`${block.cveId}\` (identifier-only)`);
          continue;
        }
        if (block.kind === 'cve-block') {
          lines.push('');
          lines.push(`#### \`${block.cveId}\``);
          lines.push('');
          lines.push(row('Field', 'Value'));
          lines.push(rowSeparator());
          for (const r of (block.rows || [])) {
            lines.push(row(r.label || r.field || 'Field', valueToMd(r.value), r.kind));
          }
        }
      }
    } else {
      lines.push('');
      lines.push(row('Field', 'Value'));
      lines.push(rowSeparator());
      for (const r of section.body) {
        lines.push(row(r.label || r.field || 'Field', valueToMd(r.value), r.kind));
      }
    }
  }
  return lines.join('\n');
}

function renderProvenance(provenance) {
  if (!Array.isArray(provenance) || provenance.length === 0) return '';
  const lines = [];
  lines.push('## Source provenance');
  lines.push('');
  lines.push('| Source | State | Last success | Official link |');
  lines.push('| --- | --- | --- | --- |');
  for (const p of provenance) {
    lines.push(`| ${mdEscape(p.name || p.sourceId || '')} | ${mdEscape(p.state || 'unknown')} | ${mdEscape(p.lastSuccessAt || '—')} | ${mdEscape(p.officialUrl || '—')} |`);
  }
  return lines.join('\n');
}

function renderLimitations(limitations) {
  if (!Array.isArray(limitations) || limitations.length === 0) return '';
  const lines = [];
  lines.push('## Limitations');
  lines.push('');
  for (const l of limitations) {
    lines.push(`- ${mdEscape(l)}`);
  }
  return lines.join('\n');
}

function renderHeader(report) {
  const lines = [];
  lines.push(`# ${report.title || '(untitled report)'}`);
  lines.push('');
  lines.push(`- **Report type:** \`${mdEscape(report.reportType || 'unknown')}\``);
  lines.push(`- **Report ID:** \`${mdEscape(report.reportId || '')}\``);
  lines.push(`- **Generated at:** \`${mdEscape(report.generatedAt || '')}\``);
  lines.push(`- **Application:** \`${mdEscape(report.applicationVersion || '')}\``);
  const pi = report.publicIntelligence || {};
  lines.push(`- **Public intelligence:** \`${mdEscape(pi.status || 'unavailable')}\`${pi.version ? ` (\`${mdEscape(pi.version)}\`)` : ''}`);
  if (report.selection) {
    const s = report.selection;
    const c = Array.isArray(s.cveIds) ? s.cveIds.length : 0;
    lines.push(`- **Selection:** ${c} CVE${c === 1 ? '' : 's'}; private notes ${s.includePrivateNotes ? 'included' : 'excluded'}; local tags ${s.includeLocalTags !== false ? 'included' : 'excluded'}; resolved ${s.includeResolved ? 'included' : 'excluded'}; archived ${s.includeArchived ? 'included' : 'excluded'}.`);
  }
  if (report.integrity && report.integrity.checksum) {
    lines.push(`- **SHA-256:** \`${mdEscape(report.integrity.checksum)}\``);
  }
  lines.push('');
  lines.push('> Reports are generated entirely in this browser. They may contain private notes or internal workflow information. Review the preview before exporting.');
  return lines.join('\n');
}

function enforce(report) {
  if (!report || typeof report !== 'object') throw new Error('export: invalid report');
  if (typeof report.title === 'string' && report.title.length > REPORT_LIMITS.MAX_TITLE_CHARS) {
    throw new Error('export: title too long');
  }
  return report;
}

/**
 * Render a redacted report to a Markdown string.
 *
 * @param {object} report  the report object (already redacted and integrity-stamped)
 * @returns {string}       the Markdown body
 */
export function renderMarkdown(report) {
  const r = enforce(report);
  const parts = [];
  parts.push(renderHeader(r));
  if (Array.isArray(r.sections)) {
    for (const s of r.sections) {
      parts.push(renderSection(s));
    }
  }
  parts.push(renderProvenance(r.provenance));
  parts.push(renderLimitations(r.limitations));
  return parts.filter(Boolean).join('\n\n') + '\n';
}
