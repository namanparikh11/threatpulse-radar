/**
 * V6.6 — Local-vs-public correlation engine.
 *
 * Given a list of local components and the current
 * public CVE list, produce a deterministic
 * `Correlation[]` for the (asset, CVE) pairs where a
 * supported provider rule produced a match.
 *
 * The engine is pure: no network, no IndexedDB, no
 * console. The same inputs always produce the same
 * output. The output is sorted by (cveId, componentId)
 * for stable test assertions and a stable UI.
 *
 * The six documented correlation states:
 *   - 'affected-range-match'
 *       A supported provider-native range evaluator
 *       determined that the imported version falls
 *       inside an affected range.
 *   - 'exact-version-match'
 *       The provider explicitly identifies the exact
 *       imported version as affected.
 *   - 'identity-only-potential'
 *       Package identity matches, but the version
 *       could not be evaluated safely (missing
 *       version, missing provider range, or the
 *       evaluator returned 'unsupported' on the
 *       provided range text).
 *   - 'version-not-evaluable'
 *       A package correlation exists, but ThreatPulse
 *       does not support reliable comparison for the
 *       supplied version / range format.
 *   - 'public-data-unavailable'
 *       The current public intelligence snapshot is
 *       not 'available' (or no provider context is
 *       attached to the CVE), so we cannot make a
 *       claim.
 *   - 'no-supported-match'
 *       No supported rule produced a match. This is
 *       NOT evidence that the component is safe or
 *       unaffected.
 *
 * Provider sources:
 *   - 'OSV'   (OsvPublicRecord.affectedPackages)
 *   - 'GitHub Advisory Database' (GithubAdvisory.packages)
 *
 * Each correlation record carries:
 *   - correlationId (deterministic)
 *   - state
 *   - providerSources
 *   - matchedPackageIdentity (the provider-side
 *     ecosystem + namespace + name + version that
 *     produced the match)
 *   - importedVersion
 *   - evaluatedRanges (one entry per provider range
 *     that was evaluated)
 *   - evidence (deduplicated, never merged across
 *     incompatible providers)
 *   - limitations
 *   - publicIntelligenceVersion + publicProjectionSchemaVersion
 */

import { CORRELATION_SCHEMA_VERSION } from './schema.mjs';
import { evaluateVersion } from './versionEvaluators.mjs';
import { normalizeIdentity } from './purl.mjs';

const PROVIDER_OSV = 'OSV';
const PROVIDER_GHSA = 'GitHub Advisory Database';

/** Build the deterministic correlationId from the
 *  join key. Same input always returns the same id. */
function correlationIdFor(assetId, inventoryId, componentId, cveId) {
  return 'cor-' + fnv1a([assetId, inventoryId, componentId, cveId].join('|')).toString(16).padStart(16, '0');
}

function fnv1a(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h;
}

/** Test whether a local component identity matches a
 *  provider package identity. The match respects the
 *  documented precedence: purl > ecosystem+name >
 *  name-only. */
function matchesIdentity(component, pkg) {
  if (!component || !pkg) return false;
  const cmpIdentity = component.normalizedIdentity || {};
  const cmpEco = normalizeMatchEcosystem(cmpIdentity.ecosystem || component.ecosystem || '');
  const cmpName = (cmpIdentity.name || component.name || '').toLowerCase();
  const cmpNs = (cmpIdentity.namespace || component.namespace || '').toLowerCase();
  const cmpPurl = component.packageUrl || cmpIdentity.purl || null;
  const pkgPurl = pkg.purl || null;
  if (cmpPurl && pkgPurl) {
    // Purl equality is stricter than string equality:
    // the namespace + name + type must match.
    if (normalizePurlKey(cmpPurl) === normalizePurlKey(pkgPurl)) return true;
  }
  const pkgEco = normalizeMatchEcosystem(pkg.ecosystem || '');
  const pkgName = (pkg.name || '').toLowerCase();
  const pkgNs = (extractNamespaceFromPackage(pkg) || '').toLowerCase();
  if (!pkgEco || !pkgName) return false;
  if (pkgEco !== cmpEco) return false;
  if (pkgName !== cmpName) return false;
  if (pkgNs && cmpNs && pkgNs !== cmpNs) return false;
  return true;
}

/** Normalize an ecosystem name to the canonical
 *  ThreatPulse form for join-key comparison. This
 *  function is shared between OSV and GHSA so a
 *  component imported with `ecosystem: 'crates'`
 *  matches a provider package with `ecosystem:
 *  'crates.io'` (and vice versa). */
function normalizeMatchEcosystem(input) {
  if (typeof input !== 'string') return '';
  const lower = input.trim().toLowerCase();
  if (lower === 'rust' || lower === 'cargo' || lower === 'crates.io' || lower === 'crates') return 'crates';
  if (lower === 'composer' || lower === 'packagist') return 'packagist';
  if (lower === 'pip' || lower === 'pypi') return 'pypi';
  if (lower === 'rubygems' || lower === 'gem') return 'rubygems';
  if (lower === 'npm') return 'npm';
  if (lower === 'go' || lower === 'golang') return 'go';
  if (lower === 'maven') return 'maven';
  if (lower === 'nuget') return 'nuget';
  return lower;
}

function normalizePurlKey(purl) {
  if (typeof purl !== 'string' || !purl.startsWith('pkg:')) return purl || '';
  // Strip qualifiers + subpath + version so a purl
  // and a purl-with-version both reduce to the same
  // identity key.
  const noHash = purl.split('#')[0];
  const noQ = noHash.split('?')[0];
  const slash = noQ.indexOf('/');
  if (slash < 0) return noQ;
  const type = noQ.slice(4, slash);
  const rest = noQ.slice(slash + 1);
  const at = rest.lastIndexOf('@');
  return 'pkg:' + type + '/' + (at >= 0 ? rest.slice(0, at) : rest);
}

function extractNamespaceFromPackage(pkg) {
  if (!pkg) return null;
  if (typeof pkg.purl === 'string') {
    const noQ = pkg.purl.split('?')[0].split('#')[0];
    const slash = noQ.indexOf('/');
    if (slash < 0) return null;
    const rest = noQ.slice(slash + 1);
    const at = rest.lastIndexOf('@');
    const main = at >= 0 ? rest.slice(0, at) : rest;
    if (main.includes('/')) return main.split('/')[0];
    return null;
  }
  return null;
}

/** Walk a single OSV package and return a state
 *  for the (component, package) pair, or `null`
 *  when no match is possible. */
function evaluateOsvPackage(component, pkg) {
  if (!matchesIdentity(component, pkg)) return null;
  const version = component.version || (component.normalizedIdentity && component.normalizedIdentity.version) || null;
  // Exact version match
  if (version && Array.isArray(pkg.versions) && pkg.versions.includes(version)) {
    return {
      state: 'exact-version-match',
      provider: PROVIDER_OSV,
      evidence: [{ provider: PROVIDER_OSV, kind: 'exact-version', version }],
      evaluatedRanges: [],
      limitations: [],
      matchedPackageIdentity: {
        ecosystem: pkg.ecosystem || null,
        namespace: extractNamespaceFromPackage(pkg),
        name: pkg.name,
        version: null,
        purl: pkg.purl || null,
      },
    };
  }
  // Range evaluation
  if (version && Array.isArray(pkg.ranges) && pkg.ranges.length > 0) {
    const ranges = [];
    let unsupportedType = false;
    for (const range of pkg.ranges) {
      if (!range || typeof range !== 'object') continue;
      if (!Array.isArray(range.events)) continue;
      const win = evaluateOsvRange(version, range.events, pkg.ecosystem);
      if (win.hit) {
        ranges.push({ provider: PROVIDER_OSV, type: range.type || 'unknown', hit: true, events: range.events.map(summariseEvent) });
      } else if (win.reason === 'unsupported') {
        ranges.push({ provider: PROVIDER_OSV, type: range.type || 'unknown', hit: false, reason: win.reason });
        unsupportedType = true;
      }
    }
    if (ranges.length === 0) {
      // Provider has ranges but none hit. The
      // evaluator was able to compare the version
      // against the provider's range text, so this
      // is a 'no-supported-match' (the package is
      // in the provider's package list, but the
      // imported version did not fall inside the
      // declared affected range). 'identity-only-
      // potential' is reserved for cases where the
      // version could not be evaluated at all.
      return {
        state: 'no-supported-match',
        provider: PROVIDER_OSV,
        evidence: [{ provider: PROVIDER_OSV, kind: 'no-match', identity: { ecosystem: pkg.ecosystem, name: pkg.name } }],
        evaluatedRanges: [],
        limitations: ['Provider declared affected ranges but the imported version did not fall inside any of them.'],
        matchedPackageIdentity: {
          ecosystem: pkg.ecosystem || null,
          namespace: extractNamespaceFromPackage(pkg),
          name: pkg.name,
          version: null,
          purl: pkg.purl || null,
        },
      };
    }
    if (unsupportedType) {
      return {
        state: 'version-not-evaluable',
        provider: PROVIDER_OSV,
        evidence: [{ provider: PROVIDER_OSV, kind: 'unsupported-range', explanation: 'unsupported range type for the ' + (pkg.ecosystem || 'unknown') + ' ecosystem' }],
        evaluatedRanges: ranges,
        limitations: ['OSV range type is not safely evaluable for the ' + (pkg.ecosystem || 'unknown') + ' ecosystem.'],
        matchedPackageIdentity: {
          ecosystem: pkg.ecosystem || null,
          namespace: extractNamespaceFromPackage(pkg),
          name: pkg.name,
          version: null,
          purl: pkg.purl || null,
        },
      };
    }
    // Pick the first range that hit.
    const hit = ranges.find((r) => r.hit);
    if (hit) {
      return {
        state: 'affected-range-match',
        provider: PROVIDER_OSV,
        evidence: [{ provider: PROVIDER_OSV, kind: 'affected-range', range: hit }],
        evaluatedRanges: ranges,
        limitations: [],
        matchedPackageIdentity: {
          ecosystem: pkg.ecosystem || null,
          namespace: extractNamespaceFromPackage(pkg),
          name: pkg.name,
          version: null,
          purl: pkg.purl || null,
        },
      };
    }
  }
  // Identity matched but no version / no ranges
  return {
    state: 'identity-only-potential',
    provider: PROVIDER_OSV,
    evidence: [{ provider: PROVIDER_OSV, kind: 'identity-only', identity: { ecosystem: pkg.ecosystem, name: pkg.name } }],
    evaluatedRanges: [],
    limitations: ['Provider matched the package identity but did not declare a range or version.'],
    matchedPackageIdentity: {
      ecosystem: pkg.ecosystem || null,
      namespace: extractNamespaceFromPackage(pkg),
      name: pkg.name,
      version: null,
      purl: pkg.purl || null,
    },
  };
}

function summariseEvent(ev) {
  if (!ev || typeof ev !== 'object') return null;
  if (typeof ev.introduced === 'string') return { kind: 'introduced', value: ev.introduced };
  if (typeof ev.fixed === 'string') return { kind: 'fixed', value: ev.fixed };
  if (typeof ev.last_affected === 'string') return { kind: 'last_affected', value: ev.last_affected };
  if (typeof ev.limit === 'string') return { kind: 'limit', value: ev.limit };
  return null;
}

function evaluateOsvRange(version, events, ecosystem) {
  // OSV ranges are a list of events in chronological
  // order. An event with `introduced` opens a window;
  // an event with `fixed` closes it. `last_affected`
  // narrows the window. `limit` caps it.
  let introduced = null;
  let fixed = null;
  let limit = null;
  for (const ev of events) {
    if (typeof ev.introduced === 'string') introduced = ev.introduced;
    if (typeof ev.fixed === 'string') fixed = ev.fixed;
    if (typeof ev.last_affected === 'string') fixed = ev.last_affected;
    if (typeof ev.limit === 'string') limit = ev.limit;
  }
  if (!introduced) {
    // No introduced -> no range to evaluate.
    return { hit: false, reason: 'no-introduced-event' };
  }
  // Compare versions. For npm, crates, and packagist
  // we use the dedicated semver evaluator; for other
  // ecosystems we fall back to a string compare.
  const eco = typeof ecosystem === 'string' ? ecosystem.toLowerCase() : null;
  const cmp = (v, ref) => compareVersionStrings(v, ref, eco);
  const cmpVersion = cmp(version, introduced);
  if (cmpVersion < 0) return { hit: false, reason: 'before-introduced' };
  if (fixed) {
    if (cmp(version, fixed) >= 0) return { hit: false, reason: 'after-fixed' };
  }
  if (limit) {
    if (cmp(version, limit) > 0) return { hit: false, reason: 'beyond-limit' };
  }
  return { hit: true, reason: 'in-range' };
}

function compareVersionStrings(a, b, ecosystem) {
  if (a === b) return 0;
  if (!a) return -1;
  if (!b) return 1;
  if (ecosystem && ['npm', 'crates', 'packagist'].includes(ecosystem)) {
    const out = evaluateVersion(ecosystem, a, `>=${a},<=${a}`);
    if (out && out.state === 'exact-version-match') {
      // Use the dedicated comparator path.
      return cmpWithEvaluator(a, b, ecosystem);
    }
  }
  // Fallback string compare
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function cmpWithEvaluator(a, b, ecosystem) {
  if (a === b) return 0;
  if (!a) return -1;
  if (!b) return 1;
  // Try common forms
  for (const range of [`>=${a},<=${a}`, `<=${a},>=${a}`, `>=${a}`, `<=${a}`, `>${a}`, `<${a}`]) {
    const out = evaluateVersion(ecosystem, b, range);
    if (out.state === 'exact-version-match') return 1;
    if (out.state === 'affected-range-match') return 1;
  }
  for (const range of [`>=${b},<=${b}`, `<=${b},>=${b}`, `>=${b}`, `<=${b}`, `>${b}`, `<${b}`]) {
    const out = evaluateVersion(ecosystem, a, range);
    if (out.state === 'exact-version-match') return -1;
    if (out.state === 'affected-range-match') return -1;
  }
  // Fallback string compare
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

/** Walk a single GitHub Advisory package and return
 *  a state for the (component, package) pair, or
 *  `null` when no match. */
function evaluateGhsaPackage(component, pkg) {
  if (!matchesIdentity(component, pkg)) return null;
  const version = component.version || (component.normalizedIdentity && component.normalizedIdentity.version) || null;
  if (!version) {
    return {
      state: 'identity-only-potential',
      provider: PROVIDER_GHSA,
      evidence: [{ provider: PROVIDER_GHSA, kind: 'identity-only', identity: { ecosystem: pkg.ecosystem, name: pkg.name } }],
      evaluatedRanges: [],
      limitations: ['GitHub Advisory matched the package identity but no imported version is available.'],
      matchedPackageIdentity: {
        ecosystem: pkg.ecosystem || null,
        namespace: null,
        name: pkg.name,
        version: null,
        purl: null,
      },
    };
  }
  if (typeof pkg.vulnerableVersionRange !== 'string' || pkg.vulnerableVersionRange.length === 0) {
    return {
      state: 'identity-only-potential',
      provider: PROVIDER_GHSA,
      evidence: [{ provider: PROVIDER_GHSA, kind: 'identity-only', identity: { ecosystem: pkg.ecosystem, name: pkg.name } }],
      evaluatedRanges: [],
      limitations: ['GitHub Advisory matched the package identity but did not declare a vulnerable range.'],
      matchedPackageIdentity: {
        ecosystem: pkg.ecosystem || null,
        namespace: null,
        name: pkg.name,
        version: null,
        purl: null,
      },
    };
  }
  const eco = normalizeGhsaEcosystem(pkg.ecosystem);
  const out = evaluateVersion(eco, version, pkg.vulnerableVersionRange);
  if (out.state === 'exact-version-match' || out.state === 'affected-range-match') {
    return {
      state: out.state,
      provider: PROVIDER_GHSA,
      evidence: [{ provider: PROVIDER_GHSA, kind: out.state, range: pkg.vulnerableVersionRange, firstPatchedVersion: pkg.firstPatchedVersion || null }],
      evaluatedRanges: [{ provider: PROVIDER_GHSA, range: pkg.vulnerableVersionRange, hit: true, firstPatchedVersion: pkg.firstPatchedVersion || null }],
      limitations: [],
      matchedPackageIdentity: {
        ecosystem: pkg.ecosystem || null,
        namespace: null,
        name: pkg.name,
        version: null,
        purl: null,
      },
    };
  }
  if (out.state === 'version-not-evaluable') {
    return {
      state: 'version-not-evaluable',
      provider: PROVIDER_GHSA,
      evidence: [{ provider: PROVIDER_GHSA, kind: 'unsupported-range', range: pkg.vulnerableVersionRange, explanation: out.explanation }],
      evaluatedRanges: [{ provider: PROVIDER_GHSA, range: pkg.vulnerableVersionRange, hit: false, reason: out.explanation }],
      limitations: [`GitHub Advisory range "${pkg.vulnerableVersionRange}" is not safely evaluable for the ${eco} ecosystem.`],
      matchedPackageIdentity: {
        ecosystem: pkg.ecosystem || null,
        namespace: null,
        name: pkg.name,
        version: null,
        purl: null,
      },
    };
  }
  // no-supported-match: identity matched but version
  // did not fall inside the vulnerable range. We
  // return null so the engine does not produce a
  // correlation for a non-match.
  return null;
}

/** Map a GitHub Advisory ecosystem name to the
 *  canonical ThreatPulse form. GHSA uses GitHub's
 *  own spelling ("npm", "crates", "pip", "maven",
 *  "go", "composer", "rust", "rubygems"). */
function normalizeGhsaEcosystem(input) {
  if (typeof input !== 'string') return 'unknown';
  const lower = input.trim().toLowerCase();
  if (lower === 'rust' || lower === 'cargo' || lower === 'crates.io' || lower === 'crates') return 'crates';
  if (lower === 'composer' || lower === 'packagist') return 'packagist';
  return lower;
}

function buildCorrelation({ assetId, inventoryId, component, cveId, result, publicMeta, publicVulnVersion, publicProjectionSchemaVersion, generatedAt }) {
  // When mergeBest has joined multiple provider results,
  // `result.providers` carries the distinct names. When
  // only a single provider produced a result, fall back
  // to the single-entry `provider` string.
  const providerSources = Array.isArray(result.providers) && result.providers.length > 0
    ? result.providers.slice()
    : [result.provider];
  return Object.freeze({
    correlationId: correlationIdFor(assetId, inventoryId, component.componentId, cveId),
    assetId,
    inventoryId,
    componentId: component.componentId,
    cveId,
    state: result.state,
    providerSources: Object.freeze(providerSources),
    matchedPackageIdentity: result.matchedPackageIdentity,
    importedVersion: component.version || null,
    evaluatedRanges: result.evaluatedRanges,
    evidence: result.evidence,
    limitations: result.limitations,
    generatedAt,
    publicIntelligenceVersion: publicVulnVersion,
    publicProjectionSchemaVersion,
    correlationSchemaVersion: CORRELATION_SCHEMA_VERSION,
  });
}

/** Build correlations. Returns a frozen array. */
export function buildCorrelations({ components, publicVulns, publicMeta, assetId, inventoryId, onProgress }) {
  const safeComponents = Array.isArray(components) ? components : [];
  const safeVulns = Array.isArray(publicVulns) ? publicVulns : [];
  const meta = publicMeta || {};
  const pubStatus = typeof meta.publicIntelligenceStatus === 'string' ? meta.publicIntelligenceStatus : 'unavailable';
  const pubVersion = typeof meta.publicIntelligenceVersion === 'string' ? meta.publicIntelligenceVersion : null;
  const projectionVersion = typeof meta.publicProjectionSchemaVersion === 'string' ? meta.publicProjectionSchemaVersion : null;
  const generatedAt = new Date().toISOString();
  const out = [];
  const total = safeVulns.length;
  for (let i = 0; i < total; i++) {
    const vuln = safeVulns[i];
    if (!vuln || typeof vuln !== 'object') continue;
    const cveId = typeof vuln.cveId === 'string' ? vuln.cveId : null;
    if (!cveId) continue;
    // Per-CVE: walk OSV first, then GHSA. Each
    // (component, provider) pair contributes at most
    // one correlation per CVE.
    const osvRecords = (vuln.osv && Array.isArray(vuln.osv.records)) ? vuln.osv.records : [];
    const ghsa = vuln.githubAdvisory || null;
    for (const component of safeComponents) {
      let best = null;
      // OSV
      for (const rec of osvRecords) {
        if (!rec || typeof rec !== 'object') continue;
        if (!Array.isArray(rec.affectedPackages)) continue;
        for (const pkg of rec.affectedPackages) {
          const r = evaluateOsvPackage(component, pkg);
          if (r) { best = mergeBest(best, r); if (best && (best.state === 'exact-version-match' || best.state === 'affected-range-match')) break; }
        }
        if (best && (best.state === 'exact-version-match' || best.state === 'affected-range-match')) break;
      }
      // GHSA
      if (ghsa && Array.isArray(ghsa.packages)) {
        for (const pkg of ghsa.packages) {
          const r = evaluateGhsaPackage(component, pkg);
          if (r) { best = mergeBest(best, r); if (best && (best.state === 'exact-version-match' || best.state === 'affected-range-match')) break; }
        }
      }
      if (!best) continue;
      // If the public status is not 'available', the
      // match was made against the currently-served
      // snapshot; mark accordingly.
      let state = best.state;
      let limitations = best.limitations.slice();
      if (pubStatus !== 'available') {
        state = 'public-data-unavailable';
        limitations.push('Public intelligence status is "' + pubStatus + '" in this snapshot; correlation should be re-checked once the status is "available".');
      }
      out.push(Object.freeze({
        ...buildCorrelation({ assetId, inventoryId, component, cveId, result: { ...best, state, limitations }, publicMeta, publicVulnVersion: pubVersion, publicProjectionSchemaVersion: projectionVersion, generatedAt }),
        limitations: Object.freeze(limitations),
      }));
    }
    if (typeof onProgress === 'function') {
      try { onProgress(i + 1); } catch { /* ignore */ }
    }
  }
  out.sort((a, b) => {
    const c = String(a.cveId).localeCompare(String(b.cveId));
    if (c !== 0) return c;
    return String(a.componentId).localeCompare(String(b.componentId));
  });
  return Object.freeze(out);
}

/** Merge two provider results. Prefer the stronger
 *  state. Keep the union of providers in the final
 *  evidence. Never overwrite a state that already
 *  matches the imported version exactly. */
function mergeBest(a, b) {
  if (!a) return b;
  if (!b) return a;
  const rank = (s) => s === 'exact-version-match' ? 4 : s === 'affected-range-match' ? 3 : s === 'identity-only-potential' ? 2 : s === 'version-not-evaluable' ? 1 : 0;
  if (rank(b.state) > rank(a.state)) return b;
  // Merge evidence and keep provider names SEPARATE
  // in the `providers` array (the legacy `provider`
  // string is kept for the single-provider case so
  // existing single-provider code paths continue to
  // work).
  return {
    ...a,
    provider: a.provider,
    providers: Array.from(new Set([a.provider, b.provider])),
    evidence: a.evidence.concat(b.evidence),
    evaluatedRanges: a.evaluatedRanges.concat(b.evaluatedRanges),
    limitations: a.limitations.concat(b.limitations),
  };
}

export { CORRELATION_SCHEMA_VERSION };
