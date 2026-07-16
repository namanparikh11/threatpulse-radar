/**
 * V6.6 — Conservative semver parser.
 *
 * Supports the standard `MAJOR.MINOR.PATCH` shape
 * plus optional pre-release / build metadata. The
 * parser is small and strict: non-conforming inputs
 * are rejected so the caller can fall back to
 * "version-not-evaluable" without risk of producing
 * a false match.
 *
 * The comparator implements the same subset as the
 * semver.org reference: pre-release identifiers sort
 * BEFORE the corresponding release. Build metadata is
 * ignored for ordering.
 *
 * This module is intentionally NOT a universal
 * version comparator. Maven, Debian, PEP 440, Go
 * pseudo-versions, and similar ecosystems each have
 * their own semantics and must be evaluated by their
 * own registry-aware evaluators (see
 * `versionEvaluators.mjs`).
 */

const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

/** Parse a semver string. Returns the structured
 *  representation or `null` when the input is not
 *  a valid semver. */
export function parseSemver(input) {
  if (typeof input !== 'string') return null;
  const s = input.trim();
  if (s.length === 0 || s.length > 200) return null;
  // Reject v-prefix only if it's the only difference
  // — semver allows `v1.2.3`; we strip and parse.
  const normalised = s.startsWith('v') || s.startsWith('V') ? s.slice(1) : s;
  const m = SEMVER_RE.exec(normalised);
  if (!m) return null;
  return Object.freeze({
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    preRelease: m[4] || null,
    build: m[5] || null,
    raw: input,
  });
}

/** Compare two semver objects. Returns -1, 0, or 1. */
export function compareSemver(a, b) {
  if (!a || !b) return 0;
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  // No pre-release on either
  if (!a.preRelease && !b.preRelease) return 0;
  // Release > pre-release
  if (!a.preRelease) return 1;
  if (!b.preRelease) return -1;
  const aIds = a.preRelease.split('.');
  const bIds = b.preRelease.split('.');
  const len = Math.min(aIds.length, bIds.length);
  for (let i = 0; i < len; i++) {
    const ai = aIds[i];
    const bi = bIds[i];
    const an = /^\d+$/.test(ai);
    const bn = /^\d+$/.test(bi);
    if (an && bn) {
      const an2 = Number(ai);
      const bn2 = Number(bi);
      if (an2 !== bn2) return an2 < bn2 ? -1 : 1;
    } else if (an && !bn) {
      return -1; // numeric < alpha
    } else if (!an && bn) {
      return 1;
    } else if (ai !== bi) {
      return ai < bi ? -1 : 1;
    }
  }
  if (aIds.length !== bIds.length) return aIds.length < bIds.length ? -1 : 1;
  return 0;
}

/** True when `version` falls inside the inclusive
 *  `[lo, hi]` semver range. The range is open when
 *  `lo` or `hi` is `null`. */
export function semverInRange(version, lo, hi) {
  const v = typeof version === 'string' ? parseSemver(version) : version;
  if (!v) return false;
  if (lo) {
    const c = compareSemver(v, lo);
    if (c < 0) return false;
  }
  if (hi) {
    const c = compareSemver(v, hi);
    if (c > 0) return false;
  }
  return true;
}

/** Test vectors used by the acceptance suite. */
export const SEMVER_TEST_VECTORS = Object.freeze([
  // parse
  { op: 'parse', input: '1.2.3', ok: true, major: 1, minor: 2, patch: 3 },
  { op: 'parse', input: '0.0.0', ok: true, major: 0, minor: 0, patch: 0 },
  { op: 'parse', input: 'v1.2.3', ok: true, major: 1, minor: 2, patch: 3 },
  { op: 'parse', input: '1.2.3-rc.1', ok: true, major: 1, minor: 2, patch: 3, preRelease: 'rc.1' },
  { op: 'parse', input: '1.2.3+build.4', ok: true, major: 1, minor: 2, patch: 3, build: 'build.4' },
  { op: 'parse', input: '1.2', ok: false },
  { op: 'parse', input: '1.2.3.4', ok: false },
  { op: 'parse', input: 'a.b.c', ok: false },
  { op: 'parse', input: '', ok: false },
  // compare
  { op: 'compare', a: '1.2.3', b: '1.2.4', c: -1 },
  { op: 'compare', a: '1.2.4', b: '1.2.3', c: 1 },
  { op: 'compare', a: '1.2.3', b: '1.2.3', c: 0 },
  { op: 'compare', a: '1.0.0', b: '2.0.0', c: -1 },
  { op: 'compare', a: '1.0.0-alpha', b: '1.0.0', c: -1 },
  { op: 'compare', a: '1.0.0-alpha.1', b: '1.0.0-alpha.2', c: -1 },
  { op: 'compare', a: '1.0.0-rc.1', b: '1.0.0-rc.1', c: 0 },
  // inRange
  { op: 'inRange', version: '1.2.3', lo: '1.0.0', hi: '2.0.0', out: true },
  { op: 'inRange', version: '0.9.0', lo: '1.0.0', hi: '2.0.0', out: false },
  { op: 'inRange', version: '3.0.0', lo: '1.0.0', hi: '2.0.0', out: false },
  { op: 'inRange', version: '1.0.0-alpha', lo: '1.0.0', hi: null, out: false },
  { op: 'inRange', version: '1.0.0', lo: '1.0.0-alpha', hi: null, out: true },
  { op: 'inRange', version: '1.5.0', lo: null, hi: '2.0.0', out: true },
]);
