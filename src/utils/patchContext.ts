/**
 * v5.7 — Patch-context classification.
 *
 * A vulnerability's "patch context" describes what we know
 * about a remediation path from the GitHub Advisory review:
 *
 *   - 'unknown'     : no reviewed GitHub Advisory exists for
 *                     this CVE. The absence of an advisory is
 *                     NOT the same as "no fix exists" — the
 *                     dashboard must never equate them.
 *   - 'available'   : a reviewed advisory exists AND at least
 *                     one affected package carries a non-null
 *                     `firstPatchedVersion`. The defender
 *                     can act on the patched version.
 *   - 'unavailable' : a reviewed advisory exists but no
 *                     affected package carries a patched
 *                     version. The dashboard must report this
 *                     as "First patched version unavailable"
 *                     — NEVER as "No fix exists".
 *
 * This module is pure: no React, no I/O, no mutation.
 */

import type { Vulnerability } from '../types/vulnerability';
import {
  allPackagesMissingPatchedVersion,
  hasPatchablePackage,
  hasReviewedGithubAdvisory,
} from './presets';

/**
 * The three documented patch-context states.
 *
 *   - 'unknown'     → no reviewed GitHub Advisory exists
 *   - 'available'   → reviewed advisory + at least one
 *                     package with a non-null patched version
 *   - 'unavailable' → reviewed advisory, but every package
 *                     has a null patched version
 */
export type PatchContext = 'unknown' | 'available' | 'unavailable';

/**
 * The three values the "Patch context" filter exposes in
 * the UI. The filter is `'any' | 'available' | 'unavailable'`
 * — the `'unknown'` state is intentionally NOT a filter
 * value because the spec says "absence of githubAdvisory
 * must not be called 'no patch'." Exposing 'unknown' as a
 * filter would invite exactly that misread. Records in the
 * `'unknown'` state always pass `'any'` but never pass
 * `'available'` or `'unavailable'`.
 */
export type PatchContextFilter = 'any' | 'available' | 'unavailable';

/**
 * Classify a vulnerability's patch context.
 *
 * Returns 'unknown' when the record has no reviewed GitHub
 * Advisory, 'available' when at least one package has a
 * non-null patched version, and 'unavailable' when a
 * reviewed advisory exists but every package's
 * firstPatchedVersion is null.
 *
 * The classification is mutually exclusive and exhaustive
 * for records that have a reviewed advisory. Records
 * without a reviewed advisory are always 'unknown'.
 */
export function classifyPatchContext(v: Vulnerability): PatchContext {
  if (!hasReviewedGithubAdvisory(v)) return 'unknown';
  if (hasPatchablePackage(v)) return 'available';
  if (allPackagesMissingPatchedVersion(v)) return 'unavailable';
  // Defensive fallback: an advisory exists with zero packages
  // or some packages without firstPatchedVersion fields. Treat
  // it as 'unknown' rather than guess.
  return 'unknown';
}

/**
 * Apply a patch-context filter to a vulnerability list.
 *
 *   - 'any'         → pass everything
 *   - 'available'   → keep only records with a concrete patched
 *                     version available
 *   - 'unavailable' → keep only records whose reviewed advisory
 *                     lists no patched version (rendered as
 *                     "First patched version unavailable")
 *
 * Records in the 'unknown' state (no reviewed advisory) are
 * intentionally excluded from the 'available' and
 * 'unavailable' filters so a defender reading the result
 * list never confuses "no advisory" with "no fix."
 */
export function applyPatchContextFilter(
  vulns: Vulnerability[],
  filter: PatchContextFilter
): Vulnerability[] {
  if (filter === 'any') return vulns;
  return vulns.filter((v) => classifyPatchContext(v) === filter);
}
