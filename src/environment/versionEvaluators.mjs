/**
 * V6.6 — Version evaluator registry.
 *
 * Each evaluator declares the exact set of inputs it
 * supports. Anything outside that set returns
 * `unsupported` so the correlation engine can mark the
 * correlation as `version-not-evaluable` instead of
 * inventing a match.
 *
 * The registry explicitly does NOT pretend to
 * understand every ecosystem. The MVP supports:
 *   - exact version equality (always)
 *   - npm semver-style ranges for npm and crates.io
 *   - composer (Packagist) common constraint syntax
 *
 * PyPI, Maven, Go modules, NuGet, and other ecosystems
 * fall through to "unsupported" until a dedicated
 * evaluator is added. The correlation engine
 * preserves the provider range text in `evidence[]`
 * so the operator can read the original affected
 * range even when the comparator cannot evaluate it.
 *
 * An evaluator returns:
 *   { state: 'affected-range-match' | 'exact-version-match' | 'version-not-evaluable',
 *     evaluatedRange: <provider-native range text> | null,
 *     explanation: <human-readable reason> }
 */

import { parseSemver, semverInRange } from './semver.mjs';

const NPM_RANGE_RE = /^[0-9A-Za-z\.\-\^\~\|\* xX]+$/;
const COMPOSER_RANGE_RE = /^[0-9A-Za-z\.\-\^\~\|\*\ ,xX]+$/;
const CRATES_RANGE_RE = /^[0-9A-Za-z\.\-\^\~\|\*\ ,]+$/;

/** Strip whitespace from a range expression. */
function compact(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/\s+/g, '');
}

/** Check if two strings are exactly equal. */
function exactEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  return a.trim() === b.trim();
}

/** Split a comma-separated range into individual
 *  range expressions. Returns `null` when any
 *  sub-expression is invalid. */
function splitCompound(range, re) {
  if (typeof range !== 'string') return null;
  const parts = range.split(',').map((s) => s.trim()).filter(Boolean);
  if (parts.length === 0) return null;
  for (const p of parts) {
    if (!re.test(p)) return null;
  }
  return parts;
}

/** Evaluate a single npm-style range expression. */
function evaluateNpmRangeExpression(version, expr) {
  // Exact
  if (exactEqual(expr, version)) return { hit: true, kind: 'exact' };
  // Wildcards
  if (expr === '*' || expr === 'x' || expr === 'X' || expr === '') return { hit: true, kind: 'any' };
  if (expr.startsWith('>=') || expr.startsWith('<=') || expr.startsWith('>') || expr.startsWith('<')) {
    const op = expr.slice(0, expr.startsWith('>=') || expr.startsWith('<=') ? 2 : 1);
    const rest = expr.slice(op.length);
    const ref = parseSemver(rest);
    const v = parseSemver(version);
    if (!ref || !v) return { hit: false, kind: 'unsupported' };
    const cmp = v.major - ref.major || v.minor - ref.minor || v.patch - ref.patch;
    if (op === '>=' && cmp >= 0) return { hit: true, kind: 'range' };
    if (op === '<=' && cmp <= 0) return { hit: true, kind: 'range' };
    if (op === '>' && cmp > 0) return { hit: true, kind: 'range' };
    if (op === '<' && cmp < 0) return { hit: true, kind: 'range' };
    return { hit: false, kind: 'range' };
  }
  // Caret / tilde
  const ch = expr.charAt(0);
  if (ch === '^' || ch === '~') {
    const ref = parseSemver(expr.slice(1));
    const v = parseSemver(version);
    if (!ref || !v) return { hit: false, kind: 'unsupported' };
    if (ch === '~') {
      // ~1.2.3 := >=1.2.3 <1.3.0
      const upper = { major: ref.major, minor: ref.minor + 1, patch: 0 };
      return { hit: semverInRange(v, ref, upper), kind: 'range' };
    }
    // ^1.2.3 := >=1.2.3 <2.0.0 (for 1.x)
    // ^0.2.3 := >=0.2.3 <0.3.0 (for 0.x)
    // ^0.0.3 := >=0.0.3 <0.0.4 (for 0.0.x)
    const upper = ref.major > 0
      ? { major: ref.major + 1, minor: 0, patch: 0 }
      : ref.minor > 0
        ? { major: 0, minor: ref.minor + 1, patch: 0 }
        : { major: 0, minor: 0, patch: ref.patch + 1 };
    return { hit: semverInRange(v, ref, upper), kind: 'range' };
  }
  // Range with hyphen: 1.2.3 - 2.3.4
  if (expr.includes(' - ')) {
    const [lo, hi] = expr.split(' - ').map((s) => s.trim());
    const loV = parseSemver(lo);
    const hiV = parseSemver(hi);
    const v = parseSemver(version);
    if (!loV || !hiV || !v) return { hit: false, kind: 'unsupported' };
    return { hit: semverInRange(v, loV, hiV), kind: 'range' };
  }
  // X-ranges: 1.2.x, 1.x
  if (/x$|X$|\*$/.test(expr)) {
    const ref = parseSemver(expr.replace(/[xX*]$/, '0'));
    const v = parseSemver(version);
    if (!ref || !v) return { hit: false, kind: 'unsupported' };
    const upper = expr.startsWith('1.2.') ? { major: ref.major, minor: ref.minor + 1, patch: 0 }
      : expr.startsWith('1.') ? { major: ref.major + 1, minor: 0, patch: 0 }
        : { major: 999999, minor: 0, patch: 0 };
    return { hit: semverInRange(v, ref, upper), kind: 'range' };
  }
  // Fall back to exact
  if (parseSemver(expr)) {
    return { hit: exactEqual(expr, version), kind: 'exact' };
  }
  return { hit: false, kind: 'unsupported' };
}

/** Evaluate an npm package range. */
function evaluateNpm(version, rangeText) {
  if (typeof rangeText !== 'string' || rangeText.length === 0 || rangeText.length > 500) {
    return { state: 'version-not-evaluable', explanation: 'range text empty or too long' };
  }
  const compact_ = compact(rangeText);
  if (!NPM_RANGE_RE.test(compact_)) {
    return { state: 'version-not-evaluable', explanation: 'unsupported range characters' };
  }
  const parts = splitCompound(compact_, NPM_RANGE_RE);
  if (!parts) {
    return { state: 'version-not-evaluable', explanation: 'could not split compound range' };
  }
  // Single exact
  if (parts.length === 1 && exactEqual(parts[0], version)) {
    return { state: 'exact-version-match', evaluatedRange: rangeText, explanation: 'exact version equality' };
  }
  for (const expr of parts) {
    const r = evaluateNpmRangeExpression(version, expr);
    if (r.hit && r.kind === 'exact') {
      return { state: 'exact-version-match', evaluatedRange: rangeText, explanation: 'exact version equality' };
    }
    if (r.hit && r.kind !== 'unsupported') {
      return { state: 'affected-range-match', evaluatedRange: rangeText, explanation: 'semver range match' };
    }
    if (r.kind === 'unsupported') {
      return { state: 'version-not-evaluable', evaluatedRange: rangeText, explanation: 'unsupported sub-expression' };
    }
  }
  return { state: 'no-supported-match', evaluatedRange: rangeText, explanation: 'no range matched' };
}

/** Evaluate a crates.io range. Cargo uses a slightly
 *  different syntax but the common forms overlap with
 *  npm semver. */
function evaluateCrates(version, rangeText) {
  if (typeof rangeText !== 'string' || rangeText.length === 0 || rangeText.length > 500) {
    return { state: 'version-not-evaluable', explanation: 'range text empty or too long' };
  }
  const compact_ = compact(rangeText);
  if (!CRATES_RANGE_RE.test(compact_)) {
    return { state: 'version-not-evaluable', explanation: 'unsupported range characters' };
  }
  // Cargo uses commas as AND and ^ caret for compatible.
  const parts = splitCompound(compact_, CRATES_RANGE_RE);
  if (!parts) return { state: 'version-not-evaluable', explanation: 'could not split compound range' };
  for (const expr of parts) {
    const r = evaluateNpmRangeExpression(version, expr);
    if (r.hit && r.kind === 'exact') {
      return { state: 'exact-version-match', evaluatedRange: rangeText, explanation: 'exact version equality' };
    }
    if (r.hit && r.kind !== 'unsupported') {
      return { state: 'affected-range-match', evaluatedRange: rangeText, explanation: 'semver range match' };
    }
    if (r.kind === 'unsupported') {
      return { state: 'version-not-evaluable', evaluatedRange: rangeText, explanation: 'unsupported sub-expression' };
    }
  }
  return { state: 'no-supported-match', evaluatedRange: rangeText, explanation: 'no range matched' };
}

/** Evaluate a Packagist (Composer) range. */
function evaluatePackagist(version, rangeText) {
  if (typeof rangeText !== 'string' || rangeText.length === 0 || rangeText.length > 500) {
    return { state: 'version-not-evaluable', explanation: 'range text empty or too long' };
  }
  const compact_ = compact(rangeText);
  if (!COMPOSER_RANGE_RE.test(compact_)) {
    return { state: 'version-not-evaluable', explanation: 'unsupported range characters' };
  }
  const parts = splitCompound(compact_, COMPOSER_RANGE_RE);
  if (!parts) return { state: 'version-not-evaluable', explanation: 'could not split compound range' };
  for (const expr of parts) {
    const r = evaluateNpmRangeExpression(version, expr);
    if (r.hit && r.kind === 'exact') {
      return { state: 'exact-version-match', evaluatedRange: rangeText, explanation: 'exact version equality' };
    }
    if (r.hit && r.kind !== 'unsupported') {
      return { state: 'affected-range-match', evaluatedRange: rangeText, explanation: 'semver range match' };
    }
    if (r.kind === 'unsupported') {
      return { state: 'version-not-evaluable', evaluatedRange: rangeText, explanation: 'unsupported sub-expression' };
    }
  }
  return { state: 'no-supported-match', evaluatedRange: rangeText, explanation: 'no range matched' };
}

/** Generic exact-equality evaluator used when no
 *  ecosystem-specific evaluator is registered. */
function evaluateGenericExact(version, rangeText) {
  if (typeof rangeText !== 'string' || rangeText.length === 0) {
    return { state: 'version-not-evaluable', explanation: 'range text empty' };
  }
  // Only treat the range as "exact" if it looks like a
  // single token, not a compound expression.
  if (rangeText.includes(',') || rangeText.includes(' ') || rangeText.includes('||') || rangeText.includes('|')) {
    return { state: 'version-not-evaluable', explanation: 'unsupported range syntax for this ecosystem' };
  }
  if (exactEqual(rangeText, version)) {
    return { state: 'exact-version-match', evaluatedRange: rangeText, explanation: 'exact version equality' };
  }
  return { state: 'no-supported-match', evaluatedRange: rangeText, explanation: 'no exact match' };
}

/** Registry of supported ecosystem evaluators. */
export const VERSION_EVALUATORS = Object.freeze({
  npm: evaluateNpm,
  crates: evaluateCrates,
  cargo: evaluateCrates,
  packagist: evaluatePackagist,
  composer: evaluatePackagist,
  // Fallback for ecosystems without a dedicated
  // evaluator. PyPI, Maven, Go, NuGet, and others
  // hit this path and return exact-only or
  // "unsupported" depending on range text.
  default: evaluateGenericExact,
});

/** Evaluate a version against a range. Returns one of
 *  the four documented states plus the range text
 *  that was evaluated. */
export function evaluateVersion(ecosystem, version, rangeText) {
  if (typeof version !== 'string' || version.length === 0) {
    return { state: 'version-not-evaluable', explanation: 'no imported version' };
  }
  if (typeof rangeText !== 'string' || rangeText.length === 0) {
    return { state: 'version-not-evaluable', explanation: 'no provider range' };
  }
  const fn = VERSION_EVALUATORS[ecosystem] || VERSION_EVALUATORS.default;
  const out = fn(version, rangeText);
  // Always set evaluatedRange to the original text so
  // the operator can see what the provider claimed.
  out.evaluatedRange = rangeText;
  if (!out.explanation) out.explanation = '';
  return out;
}

/** Test vectors used by the acceptance suite. */
export const EVALUATOR_TEST_VECTORS = Object.freeze([
  { ecosystem: 'npm', version: '1.2.3', range: '1.2.3', state: 'exact-version-match' },
  { ecosystem: 'npm', version: '1.2.4', range: '^1.2.3', state: 'affected-range-match' },
  { ecosystem: 'npm', version: '1.2.99', range: '~1.2.3', state: 'affected-range-match' },
  { ecosystem: 'npm', version: '2.0.0', range: '^1.2.3', state: 'no-supported-match' },
  { ecosystem: 'npm', version: '1.0.0', range: '>=1.0.0', state: 'affected-range-match' },
  { ecosystem: 'npm', version: '0.9.0', range: '>=1.0.0', state: 'no-supported-match' },
  { ecosystem: 'npm', version: '1.0.0-alpha', range: '>=1.0.0', state: 'no-supported-match' },
  { ecosystem: 'crates', version: '0.1.5', range: '^0.1.0', state: 'affected-range-match' },
  { ecosystem: 'packagist', version: '2.0.0', range: '^1.0', state: 'affected-range-match' },
  // Generic (unsupported ecosystem): exact only
  { ecosystem: 'pypi', version: '1.0.0', range: '1.0.0', state: 'exact-version-match' },
  { ecosystem: 'pypi', version: '1.0.0', range: '>=1.0.0', state: 'version-not-evaluable' },
  // Missing version
  { ecosystem: 'npm', version: '', range: '^1.0.0', state: 'version-not-evaluable' },
  // Malformed range
  { ecosystem: 'npm', version: '1.0.0', range: '../../../etc/passwd', state: 'version-not-evaluable' },
]);
