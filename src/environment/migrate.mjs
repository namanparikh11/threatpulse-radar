/**
 * V6.6 — Environment migrations.
 *
 * Deterministic version-to-version migration
 * functions for the local environment schema.
 * Each migration function takes the previous
 * payload shape and returns the next shape.
 *
 * The registry is consulted by the IndexedDB
 * adapter on `onupgradeneeded` and by the
 * import validation pipeline. Migrations are
 * never destructive of unrelated fields.
 *
 * Migration rules:
 *   - each migration is a pure function
 *   - the next version is APPENDED to a
 *     monotonically increasing list
 *   - downgrades are rejected
 *   - future schemas are rejected
 *   - prototype-pollution keys are never
 *     carried forward
 */

import { ASSET_SCHEMA_VERSION, COMPONENT_SCHEMA_VERSION, CORRELATION_SCHEMA_VERSION, REVIEW_SCHEMA_VERSION } from './schema.mjs';

export const SUPPORTED_VERSIONS = Object.freeze([
  '1.0.0',
]);

/** Migrate an asset from `fromVersion` to `toVersion`.
 *  Returns a new payload or `null` when the
 *  migration is not registered. */
export function migrateAsset(input, fromVersion, toVersion) {
  if (fromVersion === toVersion) return { ok: true, value: input };
  if (!SUPPORTED_VERSIONS.includes(toVersion)) return { ok: false, reason: 'unsupported-target-version' };
  if (!SUPPORTED_VERSIONS.includes(fromVersion)) return { ok: false, reason: 'unsupported-source-version' };
  // V1 is the only version registered today.
  if (fromVersion === '1.0.0' && toVersion === '1.0.0') return { ok: true, value: input };
  return { ok: false, reason: 'no-registered-migration' };
}

export function migrateComponent(input, fromVersion, toVersion) {
  if (fromVersion === toVersion) return { ok: true, value: input };
  if (!SUPPORTED_VERSIONS.includes(toVersion)) return { ok: false, reason: 'unsupported-target-version' };
  if (!SUPPORTED_VERSIONS.includes(fromVersion)) return { ok: false, reason: 'unsupported-source-version' };
  if (fromVersion === '1.0.0' && toVersion === '1.0.0') return { ok: true, value: input };
  return { ok: false, reason: 'no-registered-migration' };
}

export function migrateCorrelation(input, fromVersion, toVersion) {
  if (fromVersion === toVersion) return { ok: true, value: input };
  if (!SUPPORTED_VERSIONS.includes(toVersion)) return { ok: false, reason: 'unsupported-target-version' };
  if (!SUPPORTED_VERSIONS.includes(fromVersion)) return { ok: false, reason: 'unsupported-source-version' };
  if (fromVersion === '1.0.0' && toVersion === '1.0.0') return { ok: true, value: input };
  return { ok: false, reason: 'no-registered-migration' };
}

export function migrateReview(input, fromVersion, toVersion) {
  if (fromVersion === toVersion) return { ok: true, value: input };
  if (!SUPPORTED_VERSIONS.includes(toVersion)) return { ok: false, reason: 'unsupported-target-version' };
  if (!SUPPORTED_VERSIONS.includes(fromVersion)) return { ok: false, reason: 'unsupported-source-version' };
  if (fromVersion === '1.0.0' && toVersion === '1.0.0') return { ok: true, value: input };
  return { ok: false, reason: 'no-registered-migration' };
}

export {
  ASSET_SCHEMA_VERSION, COMPONENT_SCHEMA_VERSION, CORRELATION_SCHEMA_VERSION, REVIEW_SCHEMA_VERSION,
};
