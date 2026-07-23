/**
 * V6.1 — Multi-record bounded OSV public projection.
 *
 * The canonical baseline entities (vulnerability, advisory,
 * package, relationship, tombstone) carry more information
 * than the public dashboard needs. The public projection
 * reduces each canonical vulnerability to a deterministic
 * public-safe subset, applies documented field caps, and
 * records honest truncation metadata when caps fire.
 *
 * The projection is content-addressed: a given canonical
 * input produces a deterministic public output. Two OSV
 * projection versions that have identical canonical input
 * produce identical public shards, which allows
 * cross-version shard reuse on disk.
 *
 * Field caps (all per CVE; all deterministic):
 *   - max 8 OSV records per CVE
 *   - max 10 aliases per record
 *   - max 5 references per record
 *   - max 6 affected packages per record
 *   - max 4 ranges per package
 *   - max 8 events per range
 *   - max 8 versions per package
 *   - max 32 primitive key/value pairs in
 *     ecosystemSpecific / databaseSpecific
 *
 * Cap overflow produces explicit truncation metadata; the
 * public drawer surfaces this honestly. Cap overflow NEVER
 * silently discards an entire record — the records that
 * survive are the documented cap.
 */

import { canonicalizeToString, sha256Hex } from './canonicalHash.mjs';
import {
  OSV_RECORDS_PER_CVE_CAP,
  OSV_ALIASES_PER_RECORD_CAP,
  OSV_REFERENCES_PER_RECORD_CAP,
  OSV_PACKAGES_PER_RECORD_CAP,
  OSV_RANGES_PER_PACKAGE_CAP,
  OSV_EVENTS_PER_RANGE_CAP,
  OSV_VERSIONS_PER_PACKAGE_CAP,
  OSV_ECO_SPECIFIC_MAX_PAIRS,
  OSV_BUCKET_COUNT,
} from './publicIntelligenceSize.mjs';
import { cveBucketNormalized } from './publicIntelligenceBucket.mjs';

/**
 * Cap an array to `cap` items; return the truncated slice
 * and the number of items removed. Deterministic: items are
 * taken in the order they appear in the input.
 */
function capArray(arr, cap) {
  if (!Array.isArray(arr)) return { kept: [], removed: 0 };
  if (arr.length <= cap) return { kept: arr, removed: 0 };
  return { kept: arr.slice(0, cap), removed: arr.length - cap };
}

/**
 * Cap a primitive-keyed object to `maxPairs` pairs. Keeps
 * lexicographically-sorted keys (deterministic).
 */
function capObject(obj, maxPairs) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return { kept: obj, removed: 0 };
  }
  const keys = Object.keys(obj).sort();
  if (keys.length <= maxPairs) return { kept: obj, removed: 0 };
  const kept = {};
  for (const k of keys.slice(0, maxPairs)) kept[k] = obj[k];
  return { kept, removed: keys.length - maxPairs };
}

/**
 * Build a public-safe OSV record from a single canonical
 * OSV entity. The canonical entity is the per-OSV-id
 * record produced by `osvCanonical.normalizeOsvVulnerability`
 * and stored in the `vulnerability` entity bucket.
 *
 * `sourceDatabase` is the OSV ecosystem or upstream id
 * prefix (e.g. "GHSA", "PYSEC", "OSV-DEV", "RUSTSEC",
 * "GO"). It is derived from the OSV id convention: GHSA
 * → "GHSA", PYSEC → "PYSEC", GO → "GO", RUSTSEC → "RUSTSEC",
 * everything else → "OSV-DEV".
 */
export function projectCanonicalRecordToPublic(canonical, osvId) {
  if (!canonical || typeof canonical !== 'object') {
    return null;
  }
  const sourceDatabase = sourceDatabaseForOsvId(osvId);

  // Aliases
  const aliasInput = Array.isArray(canonical.aliases) ? canonical.aliases.slice() : [];
  const aliasCapped = capArray(aliasInput, OSV_ALIASES_PER_RECORD_CAP);

  // References (preserve type + url verbatim)
  const refInput = Array.isArray(canonical.references)
    ? canonical.references
        .filter((r) => r && typeof r.url === 'string' && r.url.length > 0)
        .map((r) => {
          const out = { url: r.url };
          if (typeof r.type === 'string') out.type = r.type;
          return out;
        })
    : [];
  // Order: ADVISORY > REPORT > FIX > PACKAGE > WEB > ARTICLE > EVIDENCE > other
  const refOrder = ['ADVISORY', 'REPORT', 'FIX', 'PACKAGE', 'WEB', 'ARTICLE', 'EVIDENCE'];
  const refRank = (r) => {
    const idx = refOrder.indexOf(r.type);
    return idx === -1 ? refOrder.length : idx;
  };
  refInput.sort((a, b) => {
    const ra = refRank(a), rb = refRank(b);
    if (ra !== rb) return ra - rb;
    return a.url < b.url ? -1 : a.url > b.url ? 1 : 0;
  });
  const refCapped = capArray(refInput, OSV_REFERENCES_PER_RECORD_CAP);

  // Severities (preserve type + score verbatim)
  const sevInput = Array.isArray(canonical.severities)
    ? canonical.severities.filter((s) => s && typeof s.type === 'string' && typeof s.score === 'string')
    : [];
  const sevSorted = sevInput.slice().sort((a, b) => {
    if (a.type !== b.type) return a.type < b.type ? -1 : 1;
    return a.score < b.score ? -1 : a.score > b.score ? 1 : 0;
  });

  // Affected packages — preserve provider-native range events verbatim
  const pkgInput = Array.isArray(canonical.affected) ? canonical.affected : [];
  const pkgCapped = capArray(pkgInput, OSV_PACKAGES_PER_RECORD_CAP);

  const packages = pkgCapped.kept.map((p) => {
    const rangesInput = Array.isArray(p.ranges) ? p.ranges : [];
    const rangesCapped = capArray(rangesInput, OSV_RANGES_PER_PACKAGE_CAP);
    const ranges = rangesCapped.kept.map((r) => {
      const eventsInput = Array.isArray(r.events) ? r.events : [];
      const eventsCapped = capArray(eventsInput, OSV_EVENTS_PER_RANGE_CAP);
      const events = eventsCapped.kept.map((e) => {
        const out = {};
        if (typeof e.introduced === 'string') out.introduced = e.introduced;
        if (typeof e.fixed === 'string') out.fixed = e.fixed;
        if (typeof e.last_affected === 'string') out.last_affected = e.last_affected;
        if (typeof e.limit === 'string') out.limit = e.limit;
        return out;
      });
      const out = { type: r.type || 'RANGE', events, databaseSpecific: null, repo: null };
      if (r.databaseSpecific && typeof r.databaseSpecific === 'object' && !Array.isArray(r.databaseSpecific)) {
        const c = capObject(r.databaseSpecific, OSV_ECO_SPECIFIC_MAX_PAIRS);
        out.databaseSpecific = c.kept;
      }
      if (typeof r.repo === 'string') out.repo = r.repo;
      return { range: out, eventsTruncated: eventsCapped.removed };
    });
    const versionsInput = Array.isArray(p.versions) ? p.versions.filter((v) => typeof v === 'string') : [];
    const versionsCapped = capArray(versionsInput, OSV_VERSIONS_PER_PACKAGE_CAP);
    const ecoCapped = p.ecosystemSpecific && typeof p.ecosystemSpecific === 'object' && !Array.isArray(p.ecosystemSpecific)
      ? capObject(p.ecosystemSpecific, OSV_ECO_SPECIFIC_MAX_PAIRS)
      : { kept: null, removed: 0 };
    return {
      ecosystem: p.packageEcosystem || p.ecosystem || '',
      name: p.packageName || p.name || '',
      purl: typeof p.packagePurl === 'string' ? p.packagePurl : (typeof p.purl === 'string' ? p.purl : null),
      ranges: ranges.map((x) => x.range),
      versions: versionsCapped.kept,
      ecosystemSpecific: ecoCapped.kept,
      truncation: {
        versionsRemoved: versionsCapped.removed,
        rangesRemoved: rangesCapped.removed,
        eventsTruncated: ranges.reduce((acc, x) => acc + x.eventsTruncated, 0),
      },
    };
  });

  const record = {
    osvId,
    sourceDatabase,
    aliases: aliasCapped.kept,
    modifiedAt: typeof canonical.modifiedAt === 'string' ? canonical.modifiedAt : null,
    publishedAt: typeof canonical.publishedAt === 'string' ? canonical.publishedAt : null,
    withdrawn: canonical.withdrawn === true,
    references: refCapped.kept,
    severities: sevSorted,
    affectedPackages: packages,
    truncation: {
      aliasesRemoved: aliasCapped.removed,
      referencesRemoved: refCapped.removed,
      packagesRemoved: pkgCapped.removed,
    },
  };

  return record;
}

/**
 * Derive a sourceDatabase label from an OSV id. OSV ids have
 * a documented prefix convention; we use a best-effort map
 * for the common cases and fall back to "OSV-DEV".
 */
function sourceDatabaseForOsvId(osvId) {
  if (typeof osvId !== 'string') return 'OSV-DEV';
  if (osvId.startsWith('GHSA-')) return 'GHSA';
  if (osvId.startsWith('PYSEC-')) return 'PYSEC';
  if (osvId.startsWith('GO-')) return 'GO';
  if (osvId.startsWith('RUSTSEC-')) return 'RUSTSEC';
  if (osvId.startsWith('OSV-')) return 'OSV-DEV';
  if (osvId.startsWith('CVE-')) return 'OSV-DEV';
  if (osvId.startsWith('DSA-') || osvId.startsWith('DLA-')) return 'Debian';
  return 'OSV-DEV';
}

/**
 * Build the public OSV context for a single CVE from a
 * list of canonical vulnerability entities that map to
 * that CVE.
 *
 * The canonical entities may be:
 *   - the canonical vulnerability entity whose `osvId`
 *     matches the CVE id, OR
 *   - canonical vulnerability entities where the CVE is
 *     in the `aliases` list.
 *
 * The output `records` array is capped at
 * OSV_RECORDS_PER_CVE_CAP; the dropped records count is
 * reported in `truncation.recordsRemoved`.
 *
 * Returns `null` when the input is empty / all inputs
 * produce no record.
 */
export function projectCveToOsvPublic(cveId, canonicalEntities) {
  if (typeof cveId !== 'string' || cveId.length === 0) {
    return null;
  }
  if (!Array.isArray(canonicalEntities) || canonicalEntities.length === 0) {
    return null;
  }
  const records = [];
  for (const ent of canonicalEntities) {
    if (!ent || typeof ent !== 'object') continue;
    if (typeof ent.osvId !== 'string') continue;
    const rec = projectCanonicalRecordToPublic(ent, ent.osvId);
    if (rec) records.push(rec);
  }
  // Deterministic ordering: sourceDatabase ascending, then osvId ascending.
  records.sort((a, b) => {
    if (a.sourceDatabase !== b.sourceDatabase) {
      return a.sourceDatabase < b.sourceDatabase ? -1 : 1;
    }
    return a.osvId < b.osvId ? -1 : a.osId > b.osvId ? 1 : a.osvId < b.osvId ? -1 : 1;
  });
  // Dedup by osvId
  const seen = new Set();
  const deduped = [];
  for (const r of records) {
    if (seen.has(r.osvId)) continue;
    seen.add(r.osvId);
    deduped.push(r);
  }
  const capped = capArray(deduped, OSV_RECORDS_PER_CVE_CAP);
  return {
    records: capped.kept,
    truncation: { recordsRemoved: capped.removed },
  };
}

/**
 * Group per-CVE OSV public contexts by their deterministic
 * 16-bucket. Returns an array of 16 bucket objects; each
 * contains the byCve map for that bucket and the bucket's
 * content-addressed key.
 *
 * Each bucket carries a unique `bucket` field (the
 * lowercase hex digit) so that even empty buckets have
 * distinct content hashes. This is required for
 * content-addressed shard reuse: without per-bucket
 * identity, all empty buckets would collide on the same
 * content hash and only the first would be written.
 *
 * The function NEVER mutates the input. It is pure and
 * deterministic: identical input always produces identical
 * output.
 */
export function partitionIntoBuckets(byCvePublic) {
  const buckets = Array.from({ length: OSV_BUCKET_COUNT }, (_, i) => ({
    bucket: i.toString(16),
    byCve: {},
    cveCount: 0,
  }));
  if (!byCvePublic || typeof byCvePublic !== 'object') return buckets;
  // Sort by CVE id for determinism.
  const cveIds = Object.keys(byCvePublic).sort();
  for (const cveId of cveIds) {
    const bucketIdx = parseInt(cveBucketNormalized(cveId), 16);
    const bucket = buckets[bucketIdx];
    bucket.byCve[cveId] = byCvePublic[cveId];
    bucket.cveCount++;
  }
  return buckets;
}

/**
 * Compute the content hash of a single bucket. The hash
 * describes the canonical (uncompressed) bytes of the
 * bucket's public projection. Used for content-addressed
 * shard keys and skip-unchanged detection.
 */
export function bucketContentHash(bucket) {
  if (!bucket || typeof bucket !== 'object') return null;
  return `sha256:${sha256Hex(canonicalizeToString(bucket))}`;
}
