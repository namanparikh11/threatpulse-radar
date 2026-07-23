/**
 * V6.5 — JSON exporter.
 *
 * Renders a redacted report to a strict JSON
 * bundle. The bundle is exactly the JSON object
 * that `validateReport` accepts and that
 * `verify.mjs` and `compare.mjs` consume.
 *
 * The exporter:
 *   - serialises the report with stable key
 *     ordering (the report object already has
 *     stable key order from `buildReport`)
 *   - re-validates the payload before returning
 *     the bytes
 *   - returns a UTF-8 string with a trailing
 *     newline (POSIX-friendly, friendly to
 *     `diff` tools)
 *
 * The exporter NEVER:
 *   - touches the network
 *   - mutates the workspace
 *   - logs to the console
 *   - includes private values that were
 *     redacted out of the report object
 */

import { REPORT_LIMITS, checkSize, validateReport } from '../schema.mjs';

/**
 * Render a redacted report to a strict JSON string.
 *
 * Throws when the report is not a valid
 * `threatpulse-local-report` payload.
 *
 * @param {object} report  the report object (already redacted and integrity-stamped)
 * @returns {string}       JSON body
 */
export function renderJson(report) {
  const check = validateReport(report);
  if (!check.ok) {
    throw new Error(`export-json: invalid report: ${check.reason}`);
  }
  const body = JSON.stringify(check.report, null, 2);
  const sizeCheck = checkSize(body);
  if (sizeCheck) {
    throw new Error(`export-json: ${sizeCheck}`);
  }
  if (body.length === 0) {
    throw new Error('export-json: empty body');
  }
  return body + '\n';
}

export { REPORT_LIMITS };
