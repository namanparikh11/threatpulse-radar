/**
 * V6.4 — Workspace migrations.
 *
 * The migration layer is the only place that knows
 * how to upgrade an older workspace record to the
 * current schema. Migrations are deterministic and
 * behavior-tested.
 *
 * The migration chain is the ordered list of schema
 * versions from the oldest supported to the current.
 * The first entry migrates from that version to the
 * NEXT version on the chain; subsequent versions
 * migrate through the chain in order. The final
 * version is the current schema version
 * (WORKSPACE_SCHEMA_VERSION in schema.mjs).
 *
 * When a record with a schema version that is not on
 * the chain is read, the caller MUST reject the
 * record outright (validateImportPayload already does
 * this via isSupportedSchemaVersion).
 */

import {
  WORKSPACE_SCHEMA_VERSION,
  makeEntry,
  LIMITS,
} from './schema.mjs';

const CHAIN = [WORKSPACE_SCHEMA_VERSION];

/**
 * Migrate a single record (already known to have a
 * known schemaVersion) to the current schema. Returns
 * the migrated record, or throws on unrecoverable
 * shape mismatches. The function is pure: the input
 * is not mutated.
 */
export function migrateRecord(input) {
  if (!input || typeof input !== 'object') {
    throw new Error('migrateRecord: not an object');
  }
  const v = input.schemaVersion;
  if (v === WORKSPACE_SCHEMA_VERSION) {
    // Already current. Pass-through after light
    // normalisation to be safe against an older
    // record shape that lacks some fields.
    return makeEntry(input.cveId, input);
  }
  // Future-proofing: an explicit chain migrator
  // would be inserted here. Today there is only the
  // current version, so this path is unreachable in
  // practice. If a future version is added, an
  // explicit migrator is required.
  throw new Error(`migrateRecord: no migrator for schemaVersion=${v}`);
}

/**
 * Migrate a list of records. Invalid records (any
 * structural failure) are dropped; the function
 * returns the surviving list and the dropped count.
 * The caller is responsible for surfacing the
 * dropped count to the operator.
 */
export function migrateRecords(list) {
  if (!Array.isArray(list)) return { records: [], dropped: 0 };
  const records = [];
  let dropped = 0;
  for (const raw of list) {
    try {
      records.push(migrateRecord(raw));
    } catch {
      dropped++;
    }
  }
  return { records, dropped };
}

/** True when the version is on the current migration chain. */
export function isOnMigrationChain(v) {
  return typeof v === 'string' && CHAIN.includes(v);
}

export const MIGRATION_CHAIN = CHAIN.slice();
