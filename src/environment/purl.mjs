/**
 * V6.6 — Package URL (purl) parser / normalizer.
 *
 * Implements a conservative, browser-safe parser for
 * the Package URL specification
 * (https://github.com/package-url/purl-spec). The
 * parser only understands the documented top-level
 * structure:
 *
 *   scheme:type/namespace/name@version?qualifiers#subpath
 *
 * It does NOT understand every ecosystem's namespace
 * conventions. Ecosystem-specific normalisation lives
 * in `normalizeEcosystem` and `normalizeIdentity`.
 *
 * The parser is intentionally small and explicit so
 * the operator gets a clear "unsupported-input"
 * verdict on malformed inputs instead of a silent
 * guess.
 *
 * The parser never throws on user input. It returns
 * `{ ok: false, reason }` for any unparseable
 * package URL.
 */

const PURL_SCHEME = 'pkg:';
const SUPPORTED_TYPES = Object.freeze(new Set([
  'npm', 'pypi', 'cargo', 'gem', 'composer', 'golang', 'nuget', 'maven',
  'deb', 'rpm', 'apk', 'generic',
]));

const ECOSYSTEM_NORMALIZE = Object.freeze({
  'npm': 'npm',
  'pypi': 'pypi',
  'pip': 'pypi',
  'cargo': 'crates',
  'crates.io': 'crates',
  'gem': 'rubygems',
  'rubygems': 'rubygems',
  'composer': 'packagist',
  'packagist': 'packagist',
  'golang': 'go',
  'go': 'go',
  'nuget': 'nuget',
  'maven': 'maven',
});

/** Parse a Package URL. Returns a normalised identity
 *  or `{ ok: false, reason }` on malformed input. */
export function parsePurl(input) {
  if (typeof input !== 'string' || input.length === 0) return { ok: false, reason: 'empty' };
  if (input.length > 500) return { ok: false, reason: 'too-long' };
  if (!input.startsWith(PURL_SCHEME)) return { ok: false, reason: 'missing-scheme' };
  const body = input.slice(PURL_SCHEME.length);
  // Strip subpath
  const hashIdx = body.indexOf('#');
  let rest = body;
  let subpath = null;
  if (hashIdx >= 0) {
    subpath = body.slice(hashIdx + 1);
    rest = body.slice(0, hashIdx);
    if (!isSafeSubpath(subpath)) return { ok: false, reason: 'invalid-subpath' };
  }
  // Strip qualifiers
  const qIdx = rest.indexOf('?');
  let typeNamespaceName = rest;
  let qualifiers = null;
  if (qIdx >= 0) {
    qualifiers = rest.slice(qIdx + 1);
    typeNamespaceName = rest.slice(0, qIdx);
    if (!isSafeQualifiers(qualifiers)) return { ok: false, reason: 'invalid-qualifiers' };
  }
  // Split type from the rest
  const slash = typeNamespaceName.indexOf('/');
  if (slash < 0) return { ok: false, reason: 'missing-type' };
  const type = typeNamespaceName.slice(0, slash);
  const rest2 = typeNamespaceName.slice(slash + 1);
  if (!SUPPORTED_TYPES.has(type)) return { ok: false, reason: 'unsupported-type' };
  if (rest2.length === 0) return { ok: false, reason: 'missing-name' };
  // Split name from version
  const atIdx = rest2.lastIndexOf('@');
  let namespace = null;
  let name = rest2;
  let version = null;
  if (atIdx >= 0) {
    name = rest2.slice(0, atIdx);
    version = rest2.slice(atIdx + 1);
    if (!isSafeVersion(version)) return { ok: false, reason: 'invalid-version' };
  }
  // Split namespace from name
  if (name.includes('/')) {
    const parts = name.split('/');
    if (parts.length > 2) return { ok: false, reason: 'invalid-namespace' };
    const ns = parts[0];
    const nm = parts[1];
    if (!isSafeName(nm)) return { ok: false, reason: 'invalid-name' };
    if (ns.length > 0 && !isSafeNamespace(ns)) return { ok: false, reason: 'invalid-namespace' };
    namespace = ns.length > 0 ? ns : null;
    name = nm;
  } else {
    if (!isSafeName(name)) return { ok: false, reason: 'invalid-name' };
  }
  return {
    ok: true,
    value: deepFreeze({
      purl: input,
      type: String(type),
      namespace: namespace,
      name: String(name),
      version: version,
      qualifiers: qualifiers,
      subpath: subpath,
    }),
  };
}

/** Normalize an ecosystem name to the ThreatPulse
 *  internal form. Returns the canonical ecosystem
 *  string or `null` when the ecosystem is unknown. */
export function normalizeEcosystem(input) {
  if (typeof input !== 'string') return null;
  const lower = input.trim().toLowerCase();
  if (ECOSYSTEM_NORMALIZE[lower]) return ECOSYSTEM_NORMALIZE[lower];
  return null;
}

/** Build a normalised identity object from a parsed
 *  purl, a (ecosystem, namespace, name, version)
 *  tuple, or a raw cpe. The first non-null input
 *  wins. The output is what the correlation engine
 *  uses as the join key with provider context.
 *
 *  Identity precedence (per the spec):
 *    1. valid Package URL
 *    2. explicit ecosystem + namespace + package name
 *    3. raw ecosystem + name only (identity-only)
 *
 *  CPE is intentionally NOT a primary identity source
 *  because there is no documented public provider that
 *  takes a CPE and returns an OSV/GHSA range match
 *  without a translation step. CPE is preserved on the
 *  component record but not used as a correlation key.
 */
export function normalizeIdentity({ purl, ecosystem, namespace, name, version, cpe }) {
  // Path 1: valid purl
  if (typeof purl === 'string' && purl.length > 0) {
    const parsed = parsePurl(purl);
    if (parsed.ok) {
      const v = parsed.value;
      return deepFreeze({
        source: 'purl',
        ecosystem: v.type,
        namespace: v.namespace,
        name: v.name,
        version: v.version,
        cpe: null,
        purl: v.purl,
      });
    }
    // Fall through; an invalid purl is recorded as
    // a raw component but does NOT participate in
    // range correlation.
  }
  // Path 2: explicit ecosystem + namespace + package name
  if (typeof ecosystem === 'string' && ecosystem.length > 0 && typeof name === 'string' && name.length > 0) {
    const eco = normalizeEcosystem(ecosystem);
    if (eco) {
      return deepFreeze({
        source: 'explicit',
        ecosystem: eco,
        namespace: (typeof namespace === 'string' && namespace.length > 0) ? namespace : null,
        name: name,
        version: (typeof version === 'string' && version.length > 0) ? version : null,
        cpe: (typeof cpe === 'string' && cpe.length > 0) ? cpe : null,
        purl: null,
      });
    }
  }
  // Path 3: raw name only — identity-only candidate
  if (typeof name === 'string' && name.length > 0) {
    return deepFreeze({
      source: 'name-only',
      ecosystem: null,
      namespace: null,
      name: name,
      version: (typeof version === 'string' && version.length > 0) ? version : null,
      cpe: (typeof cpe === 'string' && cpe.length > 0) ? cpe : null,
      purl: null,
    });
  }
  return null;
}

export function isValidPurl(input) {
  const r = parsePurl(input);
  return r.ok;
}

export { SUPPORTED_TYPES };

function isSafeName(s) {
  if (typeof s !== 'string' || s.length === 0 || s.length > 250) return false;
  return /^[A-Za-z0-9._+\-]+$/.test(s);
}

function isSafeNamespace(s) {
  if (typeof s !== 'string' || s.length === 0 || s.length > 200) return false;
  return /^[A-Za-z0-9._\-]+$/.test(s);
}

function isSafeVersion(s) {
  if (typeof s !== 'string' || s.length === 0 || s.length > 200) return false;
  return /^[A-Za-z0-9._+\-]+$/.test(s);
}

function isSafeSubpath(s) {
  if (typeof s !== 'string' || s.length > 200) return false;
  return /^[A-Za-z0-9._\-\/]+$/.test(s);
}

function isSafeQualifiers(s) {
  if (typeof s !== 'string' || s.length > 200) return false;
  // Reject anything that smells like an injection.
  if (/[\n\r<>"'`;&|]/.test(s)) return false;
  return true;
}

function deepFreeze(v) {
  if (v === null || v === undefined) return v;
  if (typeof v !== 'object') return v;
  if (Object.isFrozen(v)) return v;
  Object.freeze(v);
  for (const k of Object.keys(v)) deepFreeze(v[k]);
  return v;
}
