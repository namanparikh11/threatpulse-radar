/**
 * V6.5 — Exporter dispatcher.
 *
 * Exposes a single `exportReport(report, format)`
 * function that returns `{ filename, mimeType, body }`
 * for a given report + format. The dashboard
 * parent component owns the actual download
 * trigger (`download.mjs`).
 *
 * Supported formats:
 *   - 'markdown'   — `.md`, `text/markdown;charset=utf-8`
 *   - 'html'       — `.html`, `text/html;charset=utf-8`
 *   - 'print'      — `.html`, `text/html;charset=utf-8`
 *   - 'json'       — `.json`, `application/json;charset=utf-8`
 *
 * The dispatcher is pure: same input → same output.
 * It does not touch the network, the URL, the
 * console, or the workspace.
 */

import { renderMarkdown } from './markdown.mjs';
import { renderHtml } from './html.mjs';
import { renderPrintHtml } from './print.mjs';
import { renderJson } from './json.mjs';
import { buildReportFilename } from '../download.mjs';

const FORMAT_MAP = {
  markdown: { ext: 'md',   mime: 'text/markdown;charset=utf-8',          render: renderMarkdown },
  html:     { ext: 'html', mime: 'text/html;charset=utf-8',             render: renderHtml },
  print:    { ext: 'html', mime: 'text/html;charset=utf-8',             render: renderPrintHtml },
  json:     { ext: 'json', mime: 'application/json;charset=utf-8',      render: renderJson },
};

/**
 * Return the supported export format identifiers.
 */
export function listExportFormats() {
  return Object.keys(FORMAT_MAP);
}

/**
 * Return whether a format is supported.
 */
export function isExportFormatSupported(format) {
  return Object.prototype.hasOwnProperty.call(FORMAT_MAP, format);
}

/**
 * Render a report to the named format and return
 * a `{ filename, mimeType, body }` triple. The
 * caller is responsible for the actual download.
 *
 * @param {object} report  the report object (already redacted and integrity-stamped)
 * @param {'markdown'|'html'|'print'|'json'} format
 * @returns {{ filename: string, mimeType: string, body: string }}
 */
export function exportReport(report, format) {
  if (!report || typeof report !== 'object') {
    throw new Error('export: invalid report');
  }
  const entry = FORMAT_MAP[format];
  if (!entry) {
    throw new Error(`export: unsupported format "${format}"`);
  }
  const body = entry.render(report);
  if (typeof body !== 'string' || body.length === 0) {
    throw new Error('export: empty body');
  }
  return {
    filename: buildReportFilename(report, entry.ext),
    mimeType: entry.mime,
    body,
  };
}

export { renderMarkdown, renderHtml, renderPrintHtml, renderJson };
