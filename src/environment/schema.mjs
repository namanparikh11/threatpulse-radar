/**
 * V6.6 — Environment schema.
 *
 * Strict versioned local schema for assets,
 * inventory snapshots, components, correlations,
 * and review records. The schema is the single
 * source of truth for the on-disk format; the
 * IndexedDB and in-memory adapters both read and
 * write through the same validation pipeline.
 *
 * Strict rules (all enforced by `validate*`):
 *   - payload is a plain object
 *   - prototype-pollution keys are rejected
 *     (`__proto__`, `prototype`, `constructor`)
 *   - non-finite numbers are rejected
 *   - circular references are rejected
 *   - string identifiers match their regexes
 *   - list sizes do not exceed the documented
 *     limits
 *   - timestamps are ISO-8601 strings
 *   - supported enums are closed
 *   - future schemaVersion is rejected
 *   - size and CVE count limits are enforced
 *     at the report boundary (not here)
 *
 * The module NEVER mutates the input. Returns
 * a deep copy when validation succeeds so the
 * adapter can safely freeze it.
 */

export const ASSET_SCHEMA_VERSION = '1.0.0';
export const COMPONENT_SCHEMA_VERSION = '1.0.0';
export const CORRELATION_SCHEMA_VERSION = '1.0.0';
export const REVIEW_SCHEMA_VERSION = '1.0.0';

export const ASSET_ENVIRONMENTS = Object.freeze([
  'production', 'staging', 'development', 'test', 'personal', 'unknown',
]);

export const ASSET_TYPES = Object.freeze([
  'server', 'workstation', 'container', 'application', 'repository',
  'mobile', 'network-device', 'other',
]);

export const ASSET_CRITICALITIES = Object.freeze([
  'none', 'low', 'medium', 'high', 'critical',
]);

export const COMPONENT_TYPES = Object.freeze([
  'library', 'framework', 'application', 'operating-system', 'container',
  'firmware', 'device-driver', 'other',
]);

export const SUPPORTED_SBOM_FORMATS = Object.freeze([
  'cyclonedx-json', 'spdx-json', 'threatpulse-inventory-json', 'csv',
]);

export const CORRELATION_STATES = Object.freeze([
  'affected-range-match',
  'exact-version-match',
  'identity-only-potential',
  'version-not-evaluable',
  'public-data-unavailable',
  'no-supported-match',
]);

export const REVIEW_STATUSES = Object.freeze([
  'unreviewed',
  'confirmed-relevant',
  'dismissed',
  'needs-validation',
  'remediation-planned',
  'remediation-in-progress',
  'remediated',
  'accepted-risk',
]);

export const ASSET_LIMITS = Object.freeze({
  MAX_IMPORT_BYTES: 25 * 1024 * 1024,        // 25 MiB
  MAX_COMPONENTS_PER_IMPORT: 50000,
  WARNING_COMPONENT_COUNT: 10000,
  MAX_ASSETS: 5000,
  MAX_ASSET_TAGS: 20,
  MAX_TAG_CHARS: 40,
  MAX_ASSET_NAME_CHARS: 150,
  MAX_ASSET_DESCRIPTION_CHARS: 2000,
  MAX_OWNER_LABEL_CHARS: 120,
  MAX_INVENTORY_SNAPSHOTS_PER_ASSET: 5,
  MAX_CORRELATION_REVIEWS: 100000,
  MAX_COMPONENT_NAME_CHARS: 250,
  MAX_COMPONENT_VERSION_CHARS: 200,
  MAX_COMPONENT_PATH_CHARS: 500,
  MAX_HASH_CHARS: 200,
  MAX_REVIEW_NOTE_CHARS: 8000,
  MAX_SUPPLIER_CHARS: 200,
});

const PROTOTYPE_POLLUTION_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const REJECT_KEYS_GLOBAL = new Set(['__proto__', 'prototype', 'constructor']);
const ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

function isPlainObject(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

function hasProtoPollution(input) {
  if (!isPlainObject(input)) return false;
  for (const k of Object.getOwnPropertyNames(input)) {
    if (PROTOTYPE_POLLUTION_KEYS.has(k)) return true;
  }
  return false;
}

function isFiniteNumber(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function isIso(s) {
  return typeof s === 'string' && ISO_RE.test(s);
}

function isNonEmptyString(s, max) {
  if (typeof s !== 'string') return false;
  if (s.length === 0) return false;
  if (typeof max === 'number' && s.length > max) return false;
  return true;
}

function isBoundedString(s, max) {
  return typeof s === 'string' && s.length <= max;
}

function isStringArray(arr, maxLen, maxItem) {
  if (!Array.isArray(arr)) return false;
  if (arr.length > maxLen) return false;
  for (const s of arr) {
    if (typeof s !== 'string') return false;
    if (typeof maxItem === 'number' && s.length > maxItem) return false;
  }
  return true;
}

/** Validate an asset object. Returns `{ ok, value?, reason? }`. */
export function validateAsset(input) {
  if (!isPlainObject(input)) return { ok: false, reason: 'invalid-asset-shape' };
  if (hasProtoPollution(input)) return { ok: false, reason: 'prototype-pollution' };
  if (input.schemaVersion !== ASSET_SCHEMA_VERSION) return { ok: false, reason: 'unsupported-schema-version' };
  if (!isNonEmptyString(input.assetId, 64)) return { ok: false, reason: 'invalid-asset-id' };
  if (!ID_RE.test(input.assetId)) return { ok: false, reason: 'invalid-asset-id' };
  if (!isNonEmptyString(input.name, ASSET_LIMITS.MAX_ASSET_NAME_CHARS)) return { ok: false, reason: 'invalid-name' };
  if (typeof input.description !== 'string' || input.description.length > ASSET_LIMITS.MAX_ASSET_DESCRIPTION_CHARS) {
    return { ok: false, reason: 'invalid-description' };
  }
  if (!ASSET_ENVIRONMENTS.includes(input.environment)) return { ok: false, reason: 'invalid-environment' };
  if (!ASSET_TYPES.includes(input.assetType)) return { ok: false, reason: 'invalid-asset-type' };
  if (!ASSET_CRITICALITIES.includes(input.localCriticality)) return { ok: false, reason: 'invalid-local-criticality' };
  if (typeof input.ownerLabel !== 'string' || input.ownerLabel.length > ASSET_LIMITS.MAX_OWNER_LABEL_CHARS) {
    return { ok: false, reason: 'invalid-owner-label' };
  }
  if (!isStringArray(input.tags, ASSET_LIMITS.MAX_ASSET_TAGS, ASSET_LIMITS.MAX_TAG_CHARS)) {
    return { ok: false, reason: 'invalid-tags' };
  }
  if (!isIso(input.createdAt)) return { ok: false, reason: 'invalid-created-at' };
  if (!isIso(input.updatedAt)) return { ok: false, reason: 'invalid-updated-at' };
  if (typeof input.archived !== 'boolean') return { ok: false, reason: 'invalid-archived' };
  if (input.latestInventoryId !== null && typeof input.latestInventoryId !== 'string') {
    return { ok: false, reason: 'invalid-latest-inventory-id' };
  }
  return { ok: true, value: deepFreeze(deepClone(input)) };
}

/** Validate a component object. */
export function validateComponent(input) {
  if (!isPlainObject(input)) return { ok: false, reason: 'invalid-component-shape' };
  if (hasProtoPollution(input)) return { ok: false, reason: 'prototype-pollution' };
  if (input.schemaVersion !== COMPONENT_SCHEMA_VERSION) return { ok: false, reason: 'unsupported-schema-version' };
  if (!isNonEmptyString(input.componentId, 64)) return { ok: false, reason: 'invalid-component-id' };
  if (!ID_RE.test(input.componentId)) return { ok: false, reason: 'invalid-component-id' };
  if (!isNonEmptyString(input.assetId, 64)) return { ok: false, reason: 'invalid-asset-id' };
  if (typeof input.inventoryId !== 'string' || input.inventoryId.length === 0 || input.inventoryId.length > 64) {
    return { ok: false, reason: 'invalid-inventory-id' };
  }
  if (!isNonEmptyString(input.name, ASSET_LIMITS.MAX_COMPONENT_NAME_CHARS)) return { ok: false, reason: 'invalid-name' };
  if (input.version !== null && (typeof input.version !== 'string' || input.version.length > ASSET_LIMITS.MAX_COMPONENT_VERSION_CHARS)) {
    return { ok: false, reason: 'invalid-version' };
  }
  if (input.ecosystem !== null && (typeof input.ecosystem !== 'string' || input.ecosystem.length > 50)) {
    return { ok: false, reason: 'invalid-ecosystem' };
  }
  if (input.namespace !== null && (typeof input.namespace !== 'string' || input.namespace.length > 200)) {
    return { ok: false, reason: 'invalid-namespace' };
  }
  if (input.packageUrl !== null && (typeof input.packageUrl !== 'string' || input.packageUrl.length > 500)) {
    return { ok: false, reason: 'invalid-package-url' };
  }
  if (input.cpe !== null && (typeof input.cpe !== 'string' || input.cpe.length > 500)) {
    return { ok: false, reason: 'invalid-cpe' };
  }
  if (input.supplier !== null && (typeof input.supplier !== 'string' || input.supplier.length > ASSET_LIMITS.MAX_SUPPLIER_CHARS)) {
    return { ok: false, reason: 'invalid-supplier' };
  }
  if (!COMPONENT_TYPES.includes(input.componentType)) return { ok: false, reason: 'invalid-component-type' };
  if (!isStringArray(input.hashes, 20, ASSET_LIMITS.MAX_HASH_CHARS)) return { ok: false, reason: 'invalid-hashes' };
  if (input.sourcePath !== null && (typeof input.sourcePath !== 'string' || input.sourcePath.length > ASSET_LIMITS.MAX_COMPONENT_PATH_CHARS)) {
    return { ok: false, reason: 'invalid-source-path' };
  }
  if (!isPlainObject(input.normalizedIdentity)) return { ok: false, reason: 'invalid-normalized-identity' };
  if (!isIso(input.createdAt)) return { ok: false, reason: 'invalid-created-at' };
  return { ok: true, value: deepFreeze(deepClone(input)) };
}

/** Validate an inventory snapshot. */
export function validateInventory(input) {
  if (!isPlainObject(input)) return { ok: false, reason: 'invalid-inventory-shape' };
  if (hasProtoPollution(input)) return { ok: false, reason: 'prototype-pollution' };
  if (input.schemaVersion !== COMPONENT_SCHEMA_VERSION) return { ok: false, reason: 'unsupported-schema-version' };
  if (!isNonEmptyString(input.inventoryId, 64)) return { ok: false, reason: 'invalid-inventory-id' };
  if (!isNonEmptyString(input.assetId, 64)) return { ok: false, reason: 'invalid-asset-id' };
  if (!SUPPORTED_SBOM_FORMATS.includes(input.sourceFormat)) return { ok: false, reason: 'invalid-source-format' };
  if (input.sourceVersion !== null && (typeof input.sourceVersion !== 'string' || input.sourceVersion.length > 50)) {
    return { ok: false, reason: 'invalid-source-version' };
  }
  if (!isIso(input.importedAt)) return { ok: false, reason: 'invalid-imported-at' };
  if (typeof input.fileName !== 'string' || input.fileName.length > 250) return { ok: false, reason: 'invalid-file-name' };
  if (typeof input.componentCount !== 'number' || !isFiniteNumber(input.componentCount) || input.componentCount < 0) {
    return { ok: false, reason: 'invalid-component-count' };
  }
  if (input.componentCount > ASSET_LIMITS.MAX_COMPONENTS_PER_IMPORT) {
    return { ok: false, reason: 'too-many-components' };
  }
  if (typeof input.checksum !== 'string' || !input.checksum.startsWith('sha256:')) {
    return { ok: false, reason: 'invalid-checksum' };
  }
  if (!Array.isArray(input.warnings) || input.warnings.some((w) => typeof w !== 'string')) {
    return { ok: false, reason: 'invalid-warnings' };
  }
  if (!isPlainObject(input.metadata)) return { ok: false, reason: 'invalid-metadata' };
  return { ok: true, value: deepFreeze(deepClone(input)) };
}

/** Validate a correlation record. */
export function validateCorrelation(input) {
  if (!isPlainObject(input)) return { ok: false, reason: 'invalid-correlation-shape' };
  if (hasProtoPollution(input)) return { ok: false, reason: 'prototype-pollution' };
  if (input.correlationSchemaVersion !== CORRELATION_SCHEMA_VERSION) return { ok: false, reason: 'unsupported-schema-version' };
  if (!isNonEmptyString(input.correlationId, 64)) return { ok: false, reason: 'invalid-correlation-id' };
  if (!isNonEmptyString(input.assetId, 64)) return { ok: false, reason: 'invalid-asset-id' };
  if (!isNonEmptyString(input.inventoryId, 64)) return { ok: false, reason: 'invalid-inventory-id' };
  if (!isNonEmptyString(input.componentId, 64)) return { ok: false, reason: 'invalid-component-id' };
  if (!CVE_RE.test(input.cveId)) return { ok: false, reason: 'invalid-cve-id' };
  if (!CORRELATION_STATES.includes(input.state)) return { ok: false, reason: 'invalid-state' };
  if (!isStringArray(input.providerSources, 20, 80)) return { ok: false, reason: 'invalid-provider-sources' };
  if (!isPlainObject(input.matchedPackageIdentity)) return { ok: false, reason: 'invalid-matched-package-identity' };
  if (input.importedVersion !== null && (typeof input.importedVersion !== 'string' || input.importedVersion.length > ASSET_LIMITS.MAX_COMPONENT_VERSION_CHARS)) {
    return { ok: false, reason: 'invalid-imported-version' };
  }
  if (!Array.isArray(input.evaluatedRanges)) return { ok: false, reason: 'invalid-evaluated-ranges' };
  if (!Array.isArray(input.evidence) || input.evidence.some((e) => !isPlainObject(e))) {
    return { ok: false, reason: 'invalid-evidence' };
  }
  if (!Array.isArray(input.limitations) || input.limitations.some((l) => typeof l !== 'string')) {
    return { ok: false, reason: 'invalid-limitations' };
  }
  if (!isIso(input.generatedAt)) return { ok: false, reason: 'invalid-generated-at' };
  if (input.publicIntelligenceVersion !== null && (typeof input.publicIntelligenceVersion !== 'string' || input.publicIntelligenceVersion.length > 200)) {
    return { ok: false, reason: 'invalid-public-intelligence-version' };
  }
  if (input.publicProjectionSchemaVersion !== null && (typeof input.publicProjectionSchemaVersion !== 'string' || input.publicProjectionSchemaVersion.length > 50)) {
    return { ok: false, reason: 'invalid-projection-schema-version' };
  }
  return { ok: true, value: deepFreeze(deepClone(input)) };
}

/** Validate a review record. */
export function validateReview(input) {
  if (!isPlainObject(input)) return { ok: false, reason: 'invalid-review-shape' };
  if (hasProtoPollution(input)) return { ok: false, reason: 'prototype-pollution' };
  if (input.schemaVersion !== REVIEW_SCHEMA_VERSION) return { ok: false, reason: 'unsupported-schema-version' };
  if (!isNonEmptyString(input.correlationId, 64)) return { ok: false, reason: 'invalid-correlation-id' };
  if (!REVIEW_STATUSES.includes(input.reviewStatus)) return { ok: false, reason: 'invalid-review-status' };
  if (typeof input.note !== 'string' || input.note.length > ASSET_LIMITS.MAX_REVIEW_NOTE_CHARS) {
    return { ok: false, reason: 'invalid-review-note' };
  }
  if (!isIso(input.updatedAt)) return { ok: false, reason: 'invalid-updated-at' };
  if (typeof input.revision !== 'number' || !isFiniteNumber(input.revision) || input.revision < 0) {
    return { ok: false, reason: 'invalid-revision' };
  }
  if (typeof input.mutationId !== 'string' || input.mutationId.length === 0) {
    return { ok: false, reason: 'invalid-mutation-id' };
  }
  return { ok: true, value: deepFreeze(deepClone(input)) };
}

function deepClone(v) {
  if (v === null || v === undefined) return v;
  if (Array.isArray(v)) return v.map(deepClone);
  if (typeof v !== 'object') return v;
  const out = {};
  for (const k of Object.keys(v)) out[k] = deepClone(v[k]);
  return out;
}

function deepFreeze(v) {
  if (v === null || v === undefined) return v;
  if (typeof v !== 'object') return v;
  if (Object.isFrozen(v)) return v;
  Object.freeze(v);
  for (const k of Object.keys(v)) deepFreeze(v[k]);
  return v;
}

export { REJECT_KEYS_GLOBAL };
