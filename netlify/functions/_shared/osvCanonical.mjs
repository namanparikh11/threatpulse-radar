/**
 * V6.0 — OSV → canonical entity normalizer.
 *
 * OSV (https://osv.dev/) is the V6.0 source for vulnerabilities,
 * advisories, packages, and relationships. OSV records are extremely
 * rich: a single vulnerability can declare affected packages across
 * multiple ecosystems, with per-package version-range events, severity
 * scores, references, credits, and "withdrawn" / "related" / "aliases"
 * cross-references.
 *
 * This module converts raw OSV JSON into the canonical entity types
 * defined in the V6.0 baseline schema:
 *
 *   - vulnerability     (one per OSV id)
 *   - advisory          (one per OSV id; OSV IS the advisory in this
 *                        version — a future PYSEC or CERT adapter could
 *                        emit distinct advisory entities with their own
 *                        canonicalId)
 *   - package           (one per unique (ecosystem, name) tuple)
 *   - relationship      (vulnerability ↔ package, and
 *                        vulnerability ↔ advisory alias / related /
 *                        upstream links)
 *   - tombstone         (only when a withdrawal is observed — the
 *                        vulnerability is kept in the manifest with
 *                        `withdrawn: true` so consumers can detect
 *                        the transition; the tombstone is a separate
 *                        canonical record that downstream tooling can
 *                        use to invalidate cached results)
 *
 * Provider-native range preservation (V6.0 amendment §8):
 *   OSV "events" arrays (e.g. `[{introduced: '0'}, {fixed: '1.0.0'}]`)
 *   are stored verbatim. We DO NOT re-parse them into a generic
 *   version-range notation. The `type` field of the range is preserved
 *   ("SEMVER", "ECOSYSTEM", "GIT", "RANGE", etc.).
 *
 *   Similarly, GitHub vulnerable range strings (when emitted by a
 *   future GitHub advisory adapter) are preserved verbatim. Different
 *   providers have different range notations; flattening them to a
 *   single dialect would lose information.
 *
 * Determinism:
 *   The output is suitable for canonical hashing. All produced entities
 *   have a string `canonicalId`; arrays of entities are sorted by
 *   canonicalId at the bucket level by the shard helper.
 *
 *   The normalizer does NOT sort the entities it returns. Bucket
 *   assignment is the caller's job (see contentAddressedShards.mjs).
 *
 * Inputs (parameters):
 *   - rawVuln:    the raw OSV JSON object for one vulnerability id
 *   - osvId:      the OSV id (also embedded in `rawVuln.id`)
 *   - ecosystem:  the OSV ecosystem this record was fetched from
 *                 (e.g. "npm", "PyPI", "Maven"). OSV exposes the
 *                 ecosystem per affected package, but the per-ecosystem
 *                 modified_id.csv is the unit of ingestion, so we
 *                 thread the ecosystem through for tagging.
 *
 * Output: { vulnerability, advisories, packages, relationships, tombstones }
 *   Each list may be empty. The caller merges these into the global
 *   canonical entity tables and updates the affected buckets.
 */

const SEVERITY_SCORE_TYPES = new Set(['CVSS_V2', 'CVSS_V3', 'CVSS_V4', 'CVSS_V3.1']);

/**
 * Build the canonical id for a vulnerability. Format: `vuln:{osvId}`.
 * The `vuln:` prefix keeps vulnerability ids from colliding with
 * package or advisory ids of the same string.
 */
export function vulnerabilityCanonicalId(osvId) {
  return `vuln:${osvId}`;
}

/**
 * Build the canonical id for a package.
 * Format: `pkg:{ecosystem}:{nameLower}` (name lowercased per OSV
 * convention for case-insensitive ecosystems like npm).
 */
export function packageCanonicalId(ecosystem, name) {
  return `pkg:${ecosystem}:${name.toLowerCase()}`;
}

/**
 * Build the canonical id for a relationship.
 * Format: `rel:{type}:{sourceId}→{targetId}`.
 */
export function relationshipCanonicalId(type, sourceId, targetId) {
  return `rel:${type}:${sourceId}\u2192${targetId}`;
}

/**
 * Format an ISO timestamp from OSV. OSV emits timestamps as ISO 8601
 * strings ("2021-01-01T00:00:00Z" or with milliseconds). We pass them
 * through. If a non-string is provided we return null.
 */
function toIso(value) {
  if (typeof value !== 'string') return null;
  if (value.length === 0) return null;
  return value;
}

/**
 * Normalize a single OSV severity entry. Returns the score type and
 * the score string exactly as OSV provides it. We do NOT parse the
 * score numerically; that would lose the "CVSS_V3.1" vs "CVSS_V3"
 * distinction. Consumers wanting a numeric score parse the vector
 * themselves.
 */
function normalizeSeverity(severity) {
  if (!severity || typeof severity !== 'object') return null;
  const type = typeof severity.type === 'string' ? severity.type : null;
  const score = typeof severity.score === 'string' ? severity.score : null;
  if (!type || !score) return null;
  if (!SEVERITY_SCORE_TYPES.has(type)) {
    // Unknown score type — preserve as-is so the information is not lost.
    return { type, score, _unknown: true };
  }
  return { type, score };
}

/**
 * Normalize a single OSV affected range. The events array is
 * preserved VERBATIM. We do not re-parse the events; the
 * provider-native range is the source of truth.
 *
 * Returns a `range` object with:
 *   - type:     "SEMVER" | "ECOSYSTEM" | "GIT" | ... (verbatim)
 *   - events:   [{ introduced?, fixed?, last_affected?, limit? }, ...]
 *   - databaseSpecific: optional, preserved verbatim
 *   - repo:     optional, preserved verbatim
 */
function normalizeRange(range) {
  if (!range || typeof range !== 'object') return null;
  const out = {};
  if (typeof range.type === 'string') out.type = range.type;
  if (Array.isArray(range.events)) {
    out.events = range.events.map((e) => {
      if (!e || typeof e !== 'object') return {};
      const ev = {};
      if (typeof e.introduced === 'string') ev.introduced = e.introduced;
      if (typeof e.fixed === 'string') ev.fixed = e.fixed;
      if (typeof e.last_affected === 'string') ev.last_affected = e.last_affected;
      if (typeof e.limit === 'string') ev.limit = e.limit;
      return ev;
    });
  }
  if (range.databaseSpecific && typeof range.databaseSpecific === 'object') {
    out.databaseSpecific = range.databaseSpecific;
  }
  if (typeof range.repo === 'string') out.repo = range.repo;
  return Object.keys(out).length > 0 ? out : null;
}

/**
 * Normalize a single OSV affected entry (a `package` + `ranges` pair
 * inside `affected`). The package object is verbatim except for the
 * canonical-id extraction.
 */
function normalizeAffected(affected, ecosystem) {
  if (!affected || typeof affected !== 'object') return null;
  const pkg = affected.package;
  if (!pkg || typeof pkg !== 'object' || typeof pkg.name !== 'string') return null;
  const rangesIn = Array.isArray(affected.ranges) ? affected.ranges : [];
  const ranges = rangesIn.map(normalizeRange).filter((r) => r !== null);
  return {
    packageEcosystem: ecosystem,
    packageName: pkg.name,
    packagePurl: typeof pkg.purl === 'string' ? pkg.purl : null,
    ranges,
    versions: Array.isArray(affected.versions)
      ? affected.versions.filter((v) => typeof v === 'string')
      : [],
    ecosystemSpecific: affected.ecosystemSpecific && typeof affected.ecosystemSpecific === 'object'
      ? affected.ecosystemSpecific
      : null,
    databaseSpecific: affected.databaseSpecific && typeof affected.databaseSpecific === 'object'
      ? affected.databaseSpecific
      : null,
  };
}

/**
 * Normalize a reference object. Preserves type and url verbatim.
 */
function normalizeReference(ref) {
  if (!ref || typeof ref !== 'object') return null;
  if (typeof ref.url !== 'string' || ref.url.length === 0) return null;
  const out = { url: ref.url };
  if (typeof ref.type === 'string') out.type = ref.type;
  return out;
}

/**
 * Main entry point. Normalize one raw OSV vulnerability JSON object
 * into the five canonical entity types.
 *
 * Returns:
 *   {
 *     vulnerability:  { canonicalId, ... } | null,
 *     advisories:     [advisory, ...]  (0 or 1 for OSV today),
 *     packages:       [package, ...],
 *     relationships:  [relationship, ...],
 *     tombstones:     [tombstone, ...] (0 or 1 when withdrawn),
 *   }
 *
 * The vulnerability is always emitted (when the rawVuln has an id),
 * even when withdrawn, with `withdrawn: true` set. The tombstone is an
 * additional canonical record so consumers can detect the transition
 * without re-deriving it from the vulnerability's withdrawn flag.
 */
export function normalizeOsvVulnerability({ rawVuln, ecosystem }) {
  if (!rawVuln || typeof rawVuln !== 'object' || typeof rawVuln.id !== 'string') {
    return { vulnerability: null, advisories: [], packages: [], relationships: [], tombstones: [] };
  }
  const osvId = rawVuln.id;
  const vId = vulnerabilityCanonicalId(osvId);

  const withdrawn = rawVuln.withdrawn === true;
  const summary = typeof rawVuln.summary === 'string' ? rawVuln.summary : null;
  const details = typeof rawVuln.details === 'string' ? rawVuln.details : null;
  const aliases = Array.isArray(rawVuln.aliases)
    ? rawVuln.aliases.filter((a) => typeof a === 'string')
    : [];
  const related = Array.isArray(rawVuln.related)
    ? rawVuln.related.filter((r) => typeof r === 'string')
    : [];
  const severities = Array.isArray(rawVuln.severity)
    ? rawVuln.severity.map(normalizeSeverity).filter((s) => s !== null)
    : [];
  const references = Array.isArray(rawVuln.references)
    ? rawVuln.references.map(normalizeReference).filter((r) => r !== null)
    : [];

  const affected = Array.isArray(rawVuln.affected) ? rawVuln.affected : [];
  const affectedNormalized = affected
    .map((a) => normalizeAffected(a, ecosystem))
    .filter((a) => a !== null);

  // Build the vulnerability entity. `firstSeen` is the OSV record's
  // `published` timestamp; `lastObserved` is `modified`; the schema
  // allows `modified` to be missing for never-edited records.
  const vulnerability = {
    canonicalId: vId,
    type: 'vulnerability',
    schemaVersion: '1.0.0',
    osvId,
    primaryEcosystem: ecosystem,
    summary,
    details,
    aliases,
    related,
    severities,
    references,
    affectedPackages: affectedNormalized.map((a) => packageCanonicalId(a.packageEcosystem, a.packageName)),
    publishedAt: toIso(rawVuln.published),
    modifiedAt: toIso(rawVuln.modified),
    firstSeen: toIso(rawVuln.published),
    lastObserved: toIso(rawVuln.modified) || toIso(rawVuln.published),
    withdrawn,
    source: 'osv',
  };

  // For OSV the advisory is the same record. We emit an advisory
  // entity with its own canonicalId so a future GitHub/CERT adapter
  // can emit distinct advisory entities that link back to the
  // vulnerability via a relationship.
  const advisories = [{
    canonicalId: `adv:${osvId}`,
    type: 'advisory',
    schemaVersion: '1.0.0',
    osvId,
    ecosystem,
    summary,
    details,
    aliases,
    severities,
    references,
    publishedAt: toIso(rawVuln.published),
    modifiedAt: toIso(rawVuln.modified),
    withdrawn,
    source: 'osv',
    vulnerabilityId: vId,
  }];

  // Packages: one per unique (ecosystem, name) tuple across all
  // affected entries.
  const packageMap = new Map();
  for (const a of affectedNormalized) {
    const pId = packageCanonicalId(a.packageEcosystem, a.packageName);
    if (packageMap.has(pId)) continue;
    packageMap.set(pId, {
      canonicalId: pId,
      type: 'package',
      schemaVersion: '1.0.0',
      ecosystem: a.packageEcosystem,
      name: a.packageName,
      purl: a.packagePurl,
      firstSeen: toIso(rawVuln.published),
      lastObserved: toIso(rawVuln.modified) || toIso(rawVuln.published),
      source: 'osv',
    });
  }
  const packages = [...packageMap.values()];

  // Relationships:
  //   - vuln → package (one per affected)
  //   - vuln → advisory (the OSV-advisory link)
  //   - vuln → vuln-alias (one per alias)
  //   - vuln → vuln-related (one per related)
  const relationships = [];
  for (const a of affectedNormalized) {
    const pId = packageCanonicalId(a.packageEcosystem, a.packageName);
    relationships.push({
      canonicalId: relationshipCanonicalId('affects', vId, pId),
      type: 'relationship',
      schemaVersion: '1.0.0',
      relType: 'affects',
      sourceId: vId,
      targetId: pId,
      rangeCount: a.ranges.length,
      firstSeen: toIso(rawVuln.published),
      lastObserved: toIso(rawVuln.modified) || toIso(rawVuln.published),
      source: 'osv',
    });
  }
  relationships.push({
    canonicalId: relationshipCanonicalId('advisory-of', `adv:${osvId}`, vId),
    type: 'relationship',
    schemaVersion: '1.0.0',
    relType: 'advisory-of',
    sourceId: `adv:${osvId}`,
    targetId: vId,
    firstSeen: toIso(rawVuln.published),
    lastObserved: toIso(rawVuln.modified) || toIso(rawVuln.published),
    source: 'osv',
  });
  for (const alias of aliases) {
    relationships.push({
      canonicalId: relationshipCanonicalId('alias', vId, `vuln:${alias}`),
      type: 'relationship',
      schemaVersion: '1.0.0',
      relType: 'alias',
      sourceId: vId,
      targetId: `vuln:${alias}`,
      firstSeen: toIso(rawVuln.published),
      lastObserved: toIso(rawVuln.modified) || toIso(rawVuln.published),
      source: 'osv',
    });
  }
  for (const rel of related) {
    relationships.push({
      canonicalId: relationshipCanonicalId('related', vId, `vuln:${rel}`),
      type: 'relationship',
      schemaVersion: '1.0.0',
      relType: 'related',
      sourceId: vId,
      targetId: `vuln:${rel}`,
      firstSeen: toIso(rawVuln.published),
      lastObserved: toIso(rawVuln.modified) || toIso(rawVuln.published),
      source: 'osv',
    });
  }

  // Tombstones: only when the record is withdrawn.
  const tombstones = withdrawn
    ? [{
        canonicalId: `tomb:${osvId}`,
        type: 'tombstone',
        schemaVersion: '1.0.0',
        targetId: vId,
        reason: 'withdrawn',
        withdrawnAt: toIso(rawVuln.modified) || toIso(rawVuln.published),
        source: 'osv',
      }]
    : [];

  return { vulnerability, advisories, packages, relationships, tombstones };
}
