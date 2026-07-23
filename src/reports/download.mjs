/**
 * V6.5 — Browser download helper.
 *
 * Wraps the standard Blob + object URL + anchor click
 * pattern. The helper is intentionally tiny and
 * side-effect free outside the download. It NEVER:
 *   - touches the network
 *   - writes to the URL or history
 *   - logs to the console
 *   - includes private values in the filename (the
 *     caller is responsible for the filename)
 *
 * Filenames are expected to be public-safe (no
 * private notes, tags, or user names).
 *
 * Server-side usage is a no-op; the dashboard never
 * calls it server-side.
 */

const REVOKE_DELAY_MS = 1500;

/**
 * Trigger a browser download.
 *
 * @param {string} filename  public-safe filename (no private content)
 * @param {string} body      the file body (already redacted)
 * @param {string} mimeType  e.g. "text/markdown;charset=utf-8"
 */
export function downloadFile(filename, body, mimeType) {
  if (typeof document === 'undefined') return;
  if (typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') return;
  if (typeof body !== 'string' || body.length === 0) return;
  if (typeof filename !== 'string' || filename.length === 0) return;
  const blob = new Blob([body], { type: mimeType || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener noreferrer';
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Defer revocation so the browser has time to start
  // the download. Revoking too early cancels the
  // download in some browsers.
  setTimeout(() => {
    try { URL.revokeObjectURL(url); } catch { /* ignore */ }
  }, REVOKE_DELAY_MS);
}

/**
 * Open a new browser tab/window with the given HTML
 * body. The HTML is provided as a Blob URL so the
 * browser treats it as a same-origin navigation (CSP
 * inside the document still applies). The function
 * never injects private values into the URL.
 *
 * @param {string} html  full HTML document
 * @param {string} [windowName]  optional window name
 */
export function openHtmlInNewTab(html, windowName) {
  if (typeof document === 'undefined') return;
  if (typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') return;
  if (typeof html !== 'string' || html.length === 0) return;
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const win = window.open(url, windowName || '_blank', 'noopener,noreferrer');
  if (!win) {
    // Pop-up blocked. The caller can fall back to a
    // download or surface an error to the operator.
    setTimeout(() => { try { URL.revokeObjectURL(url); } catch { /* ignore */ } }, REVOKE_DELAY_MS);
    return null;
  }
  // Defer revocation so the new tab has time to load
  // the document. The document has its own CSP and
  // the URL is opaque to scripts.
  setTimeout(() => { try { URL.revokeObjectURL(url); } catch { /* ignore */ } }, REVOKE_DELAY_MS * 2);
  return win;
}

/**
 * Build a public-safe filename for a report export.
 *
 * Convention: `threatpulse-report-{type}-{shortId}-{date}.{ext}`
 * - `{type}` is the report type id (kebab-case, e.g.
 *   "defender-daily-briefing").
 * - `{shortId}` is the last 8 chars of the reportId
 *   (alphanumeric, no private content).
 * - `{date}` is YYYY-MM-DD in UTC.
 * - `{ext}` is the file extension (no leading dot).
 *
 * The filename NEVER contains:
 *   - private notes
 *   - tags
 *   - user names
 *   - any field from the report body
 */
export function buildReportFilename(report, ext) {
  if (!report || typeof report !== 'object') return `threatpulse-report.${ext || 'txt'}`;
  const type = typeof report.reportType === 'string' && report.reportType
    ? report.reportType
    : 'report';
  const rid = typeof report.reportId === 'string' ? report.reportId : '';
  const shortId = rid.length >= 8 ? rid.slice(-8) : rid || 'rpt';
  const date = extractDateUtc(report.generatedAt) || utcToday();
  const safeExt = (typeof ext === 'string' && ext.replace(/[^a-z0-9]/gi, '')) || 'txt';
  return `threatpulse-report-${type}-${shortId}-${date}.${safeExt.toLowerCase()}`;
}

function extractDateUtc(iso) {
  if (typeof iso !== 'string') return null;
  const m = iso.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return null;
  return `${m[1]}-${m[2]}-${m[3]}`;
}

function utcToday() {
  const d = new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}
