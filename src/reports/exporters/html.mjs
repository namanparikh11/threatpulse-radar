/**
 * V6.5 — Standalone HTML exporter.
 *
 * Renders a redacted report to a self-contained
 * HTML document. The output is safe to email,
 * upload, or open from disk:
 *
 *   - no external scripts
 *   - no external fonts, images, or other resources
 *   - no executable user content (every value is
 *     rendered as escaped text — no `innerHTML`,
 *     no `eval`, no `javascript:` URLs)
 *   - inline safe CSS (single <style> block)
 *   - appropriate CSP meta policy
 *
 * The exporter NEVER:
 *   - touches the network
 *   - mutates the workspace
 *   - mutates the URL / history
 *   - logs to the console
 *
 * The HTML output is suitable for a "Save as PDF"
 * print target as well (the page styles adapt).
 * A separate `print.mjs` exporter adds a print
 * stylesheet optimised for paper output.
 */

import { REPORT_LIMITS } from '../schema.mjs';

const SAFE_CSS = `
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 1.5rem; max-width: 900px; margin-left: auto; margin-right: auto; color: #1f2933; background: #ffffff; }
  h1 { font-size: 1.5rem; margin: 0 0 0.5rem 0; }
  h2 { font-size: 1.15rem; margin: 1.5rem 0 0.5rem 0; border-bottom: 1px solid #d8dde3; padding-bottom: 0.25rem; }
  h3 { font-size: 1rem; margin: 1rem 0 0.5rem 0; }
  h4 { font-size: 0.95rem; margin: 0.75rem 0 0.25rem 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .meta { color: #5c6770; font-size: 0.85rem; margin-bottom: 1.5rem; }
  .meta dt { display: inline; font-weight: 600; }
  .meta dd { display: inline; margin-left: 0.25rem; }
  .meta div { margin-right: 1rem; }
  .preamble { background: #fef6e4; border: 1px solid #f0c674; padding: 0.6rem 0.8rem; border-radius: 6px; margin-bottom: 1.5rem; font-size: 0.85rem; color: #5b4500; }
  table { width: 100%; border-collapse: collapse; margin: 0.5rem 0 1rem 0; font-size: 0.85rem; }
  caption { text-align: left; font-size: 0.75rem; color: #5c6770; padding-bottom: 0.25rem; }
  th, td { border-bottom: 1px solid #eef0f2; padding: 0.35rem 0.5rem; text-align: left; vertical-align: top; }
  th[scope="col"] { background: #f5f6f8; font-weight: 600; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.04em; color: #5c6770; }
  th[scope="row"] { font-weight: 500; color: #3e4c59; width: 33%; }
  td { word-break: break-word; }
  .pill { display: inline-block; font-size: 0.7rem; padding: 0.05rem 0.4rem; border-radius: 4px; border: 1px solid; margin-left: 0.25rem; }
  .pill-provider-fact { border-color: #3b6cf6; background: #e6edff; color: #1c3fae; }
  .pill-threatpulse-derived { border-color: #c08a00; background: #fff3cd; color: #6b4d00; }
  .pill-user-authored { border-color: #97a2ad; background: #eef0f2; color: #1f2933; }
  .pill-system-metadata { border-color: #c4cbd1; background: #f5f6f8; color: #3e4c59; }
  .pill-unavailable-or-uncertain { border-color: #c08a00; background: #fff8e1; color: #6b4d00; }
  .cve-block { border: 1px solid #d8dde3; border-radius: 6px; padding: 0.75rem; margin-bottom: 0.5rem; background: #fbfcfd; }
  .cve-id { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #1c3fae; }
  .checksum { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.75rem; color: #5c6770; }
  .footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #d8dde3; color: #5c6770; font-size: 0.75rem; }
  @media (prefers-color-scheme: dark) {
    body { background: #14181d; color: #e6e9ec; }
    h2 { border-bottom-color: #2a313a; }
    .preamble { background: #2d2615; border-color: #6b5210; color: #f0c674; }
    th[scope="col"] { background: #1d2229; color: #a0a8b0; }
    th, td { border-bottom-color: #2a313a; }
    th[scope="row"] { color: #c0c6cd; }
    .cve-block { background: #181c21; border-color: #2a313a; }
    .pill-user-authored { background: #1d2229; border-color: #2a313a; color: #e6e9ec; }
    .pill-system-metadata { background: #1d2229; border-color: #2a313a; color: #a0a8b0; }
    .footer { border-top-color: #2a313a; }
  }
`;

const CSP = [
  "default-src 'none'",
  "style-src 'unsafe-inline'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

/** Escape for safe inclusion inside an HTML text node. */
function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function valueToHtml(v) {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  if (Array.isArray(v)) return v.length === 0 ? '—' : v.map((x) => esc(typeof x === 'string' ? x : JSON.stringify(x))).join(', ');
  if (typeof v === 'object') return esc(JSON.stringify(v));
  return esc(String(v));
}

function renderPill(kind) {
  if (!kind) return '';
  const map = {
    'provider-fact': 'Provider fact',
    'threatpulse-derived': 'ThreatPulse-derived',
    'user-authored': 'User-authored local field',
    'system-metadata': 'System metadata',
    'unavailable-or-uncertain': 'Unavailable or uncertain',
  };
  return `<span class="pill pill-${esc(kind)}">${esc(map[kind] || kind)}</span>`;
}

function renderRow(r) {
  return `<tr><th scope="row">${esc(r.label || r.field || 'Field')}${renderPill(r.kind)}</th><td>${valueToHtml(r.value)}</td></tr>`;
}

function renderCveBlock(block) {
  if (!block) return '';
  if (block.kind === 'cve-identifier-only') {
    return `<div class="cve-block"><span class="cve-id">${esc(block.cveId)}</span> (identifier-only mode)</div>`;
  }
  const rows = (block.rows || []).map(renderRow).join('');
  return `<div class="cve-block"><h4>${esc(block.cveId)}</h4><table><caption class="sr-only">Fields for ${esc(block.cveId)}</caption><tbody>${rows}</tbody></table></div>`;
}

function renderSection(s) {
  if (!s) return '';
  let body = '';
  if (s.kind === 'cve-list' && Array.isArray(s.body)) {
    body = s.body.map(renderCveBlock).join('');
  } else if (Array.isArray(s.body)) {
    body = `<table><caption class="sr-only">${esc(s.title || 'Section')}</caption><tbody>${s.body.map(renderRow).join('')}</tbody></table>`;
  }
  return `<section><h3>${esc(s.title || '(untitled section)')}${renderPill(s.kind)}</h3>${body}</section>`;
}

function renderProvenance(p) {
  if (!Array.isArray(p) || p.length === 0) return '';
  const rows = p.map((x) => `<tr><td>${esc(x.name || x.sourceId || '')}</td><td>${esc(x.state || 'unknown')}</td><td class="checksum">${esc(x.lastSuccessAt || '—')}</td><td class="checksum">${esc(x.officialUrl || '—')}</td></tr>`).join('');
  return `<h2>Source provenance</h2><table><caption>Public sources used in this report.</caption><thead><tr><th scope="col">Source</th><th scope="col">State</th><th scope="col">Last success</th><th scope="col">Official link</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderLimitations(l) {
  if (!Array.isArray(l) || l.length === 0) return '';
  return `<h2>Limitations</h2><ul>${l.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`;
}

function renderHeader(report) {
  const pi = report.publicIntelligence || {};
  const sel = report.selection || {};
  const integ = report.integrity || {};
  const c = Array.isArray(sel.cveIds) ? sel.cveIds.length : 0;
  return `
    <h1>${esc(report.title || '(untitled report)')}</h1>
    <dl class="meta">
      <div><dt>Report type:</dt><dd>${esc(report.reportType || 'unknown')}</dd></div>
      <div><dt>Report ID:</dt><dd class="checksum">${esc(report.reportId || '')}</dd></div>
      <div><dt>Generated at:</dt><dd class="checksum">${esc(report.generatedAt || '')}</dd></div>
      <div><dt>Application:</dt><dd class="checksum">${esc(report.applicationVersion || '')}</dd></div>
      <div><dt>Public intelligence:</dt><dd class="checksum">${esc(pi.status || 'unavailable')}${pi.version ? ` (${esc(pi.version)})` : ''}</dd></div>
      <div><dt>Selection:</dt><dd>${c} CVE${c === 1 ? '' : 's'}; private notes ${sel.includePrivateNotes ? 'included' : 'excluded'}; local tags ${sel.includeLocalTags !== false ? 'included' : 'excluded'}; resolved ${sel.includeResolved ? 'included' : 'excluded'}; archived ${sel.includeArchived ? 'included' : 'excluded'}</dd></div>
    </dl>
    ${integ.checksum ? `<p class="checksum">SHA-256: ${esc(integ.checksum)}</p>` : ''}
    <div class="preamble">Reports are generated entirely in this browser. They may contain private notes or internal workflow information. Review the preview before exporting.</div>
  `;
}

function enforce(report) {
  if (!report || typeof report !== 'object') throw new Error('export: invalid report');
  if (typeof report.title === 'string' && report.title.length > REPORT_LIMITS.MAX_TITLE_CHARS) {
    throw new Error('export: title too long');
  }
  return report;
}

/**
 * Render a redacted report to a standalone HTML string.
 *
 * @param {object} report  the report object (already redacted and integrity-stamped)
 * @returns {string}       full HTML document
 */
export function renderHtml(report) {
  const r = enforce(report);
  const sections = Array.isArray(r.sections) ? r.sections.map(renderSection).join('\n') : '';
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${esc(CSP)}">
<title>${esc(r.title || 'ThreatPulse report')}</title>
<style>${SAFE_CSS}</style>
</head>
<body>
${renderHeader(r)}
${sections}
${renderProvenance(r.provenance)}
${renderLimitations(r.limitations)}
<footer class="footer">
  <p>Generated locally in the browser. This report is not a certification, a legal attestation, or a substitute for asset validation, patch testing, or professional judgment.</p>
</footer>
</body>
</html>
`;
}
