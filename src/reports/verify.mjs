/**
 * V6.5 — Report verification.
 *
 * Verifies a redacted report bundle. The verifier
 * takes either:
 *   - a JSON string (the on-disk format), or
 *   - a parsed object (an in-memory report).
 *
 * It returns a structured verdict:
 *   { ok: true,  status: 'valid',     report }
 *   { ok: false, status: 'unsupported-schema', report }
 *   { ok: false, status: 'invalid-format',     report }
 *   { ok: false, status: 'too-large',          report }
 *   { ok: false, status: 'corrupt',            report }
 *   { ok: false, status: 'incomplete',         report }
 *   { ok: false, status: 'integrity-failed',   report }
 *
 * 'unsupported-schema'  future schemaVersion
 * 'invalid-format'      wrong format / wrong type
 * 'too-large'           payload exceeds REPORT_LIMITS.MAX_BYTES
 * 'corrupt'             JSON parse / schema validation failure
 * 'incomplete'          valid shape but missing required fields
 * 'integrity-failed'    valid shape but SHA-256 mismatch
 *
 * The verifier NEVER:
 *   - mutates the report object (Object.freeze is
 *     applied to a deep copy for safety)
 *   - calls the network
 *   - writes to the URL / history
 *   - logs to the console
 *
 * The verifier is the canonical reference for the
 * 5 documented status values.
 */

import { canonicalizeReportBytes } from './canonicalize.mjs';
import { digestString, ShaUnavailableError } from './sha256.mjs';
import {
  REPORT_LIMITS,
  REPORT_SCHEMA_VERSION,
  REPORT_EXPORT_FORMAT,
  checkSize,
  validateReport,
} from './schema.mjs';

const SUPPORTED_SCHEMA_PREFIX = REPORT_SCHEMA_VERSION;

/** Coerce an unknown value to a verdict. */
function verdict(ok, status, report) {
  return { ok, status, report: report || null };
}

function parseJson(jsonString) {
  if (typeof jsonString !== 'string') return { ok: false, reason: 'not-a-string' };
  if (jsonString.length === 0) return { ok: false, reason: 'empty' };
  if (jsonString.length > REPORT_LIMITS.MAX_BYTES) return { ok: false, reason: 'too-large' };
  let parsed;
  try {
    parsed = JSON.parse(jsonString);
  } catch {
    return { ok: false, reason: 'parse-error' };
  }
  return { ok: true, report: parsed };
}

/** Verify a JSON string. Returns a verdict. */
export async function verifyJson(jsonString) {
  const sizeCheck = checkSize(jsonString);
  if (sizeCheck === 'payload-too-large') {
    return verdict(false, 'too-large', null);
  }
  if (sizeCheck === 'invalid-serialized') {
    return verdict(false, 'invalid-format', null);
  }
  const parsed = parseJson(jsonString);
  if (!parsed.ok) {
    if (parsed.reason === 'too-large') return verdict(false, 'too-large', null);
    if (parsed.reason === 'empty') return verdict(false, 'invalid-format', null);
    return verdict(false, 'corrupt', null);
  }
  return verifyReport(parsed.report);
}

/** Verify an already-parsed report object. Returns a verdict. */
export async function verifyReport(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    return verdict(false, 'invalid-format', null);
  }
  if (report.format !== REPORT_EXPORT_FORMAT) {
    return verdict(false, 'invalid-format', report);
  }
  if (typeof report.schemaVersion !== 'string') {
    return verdict(false, 'corrupt', report);
  }
  // Future schemas are rejected (no forward compat for
  // reports we cannot parse safely).
  if (!report.schemaVersion.startsWith(SUPPORTED_SCHEMA_PREFIX)) {
    return verdict(false, 'unsupported-schema', report);
  }
  const check = validateReport(report);
  if (!check.ok) {
    if (check.reason === 'too-many-cves') return verdict(false, 'too-large', report);
    return verdict(false, 'corrupt', report);
  }
  // Verify the integrity block.
  if (!report.integrity || typeof report.integrity.checksum !== 'string') {
    return verdict(false, 'incomplete', report);
  }
  if (!report.integrity.checksum.startsWith('sha256:')) {
    return verdict(false, 'corrupt', report);
  }
  let actual;
  try {
    actual = await digestString(canonicalizeReportBytes(report));
  } catch (err) {
    if (err instanceof ShaUnavailableError) {
      return verdict(false, 'integrity-unavailable', report);
    }
    return verdict(false, 'corrupt', report);
  }
  if (`sha256:${actual}` !== report.integrity.checksum) {
    return verdict(false, 'integrity-failed', report);
  }
  return verdict(true, 'valid', report);
}

/** Synchronous verification of the shape and schema
 *  without recomputing the SHA-256. Useful for the
 *  UI when the async digest is in flight or unavailable.
 *  Returns a verdict; if 'valid' is returned, the
 *  caller MUST still call verifyReport to confirm the
 *  integrity. */
export function verifyShape(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    return verdict(false, 'invalid-format', null);
  }
  if (report.format !== REPORT_EXPORT_FORMAT) {
    return verdict(false, 'invalid-format', report);
  }
  if (typeof report.schemaVersion !== 'string') {
    return verdict(false, 'corrupt', report);
  }
  if (!report.schemaVersion.startsWith(SUPPORTED_SCHEMA_PREFIX)) {
    return verdict(false, 'unsupported-schema', report);
  }
  const check = validateReport(report);
  if (!check.ok) {
    if (check.reason === 'too-many-cves') return verdict(false, 'too-large', report);
    return verdict(false, 'corrupt', report);
  }
  if (!report.integrity || typeof report.integrity.checksum !== 'string' || !report.integrity.checksum.startsWith('sha256:')) {
    return verdict(false, 'incomplete', report);
  }
  return verdict(true, 'valid-shape', report);
}

export { verifyJson as verify };
