/**
 * V6.5 — Print-optimized HTML exporter.
 *
 * Produces the same self-contained HTML as the
 * `html.mjs` exporter, with a print stylesheet
 * tuned for A4 / Letter paper output. The output
 * is opened in a new browser tab; the operator
 * uses the browser's "Save as PDF" or print
 * command to produce a local PDF.
 *
 * The print stylesheet:
 *   - removes the on-screen preamble (replaced
 *     by a short footer on the last page)
 *   - sets paper-friendly margins
 *   - forces tables to repeat their header row
 *   - hides interactive elements (none today,
 *     but explicit so future additions do not
 *     leak)
 *
 * The exporter inherits the safety constraints
 * of the standalone HTML exporter (no scripts,
 * no remote resources, CSP meta, etc.).
 */

import { renderHtml } from './html.mjs';

const PRINT_CSS = `
  @page { size: A4; margin: 18mm 14mm; }
  @media print {
    body { padding: 0; max-width: none; background: #ffffff; color: #000000; }
    h1 { font-size: 1.4rem; }
    h2 { font-size: 1.05rem; page-break-after: avoid; }
    h3 { font-size: 0.95rem; page-break-after: avoid; }
    h4 { font-size: 0.85rem; }
    table { page-break-inside: avoid; }
    thead { display: table-header-group; }
    tr { page-break-inside: avoid; }
    .preamble { background: transparent; border: none; padding: 0; color: #000; }
    .footer { color: #444; }
    a { color: inherit; text-decoration: none; }
    .no-print { display: none !important; }
  }
`;

/**
 * Render a redacted report to a print-optimized
 * HTML string.
 *
 * @param {object} report  the report object (already redacted and integrity-stamped)
 * @returns {string}       full HTML document
 */
export function renderPrintHtml(report) {
  const base = renderHtml(report);
  // Inject the print stylesheet after the existing
  // <style> block. The base renderer's CSP allows
  // inline styles, so this is safe.
  return base.replace('</style>', `${PRINT_CSS}</style>`);
}
