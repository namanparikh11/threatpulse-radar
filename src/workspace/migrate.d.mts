import type { WorkspaceEntry } from './schema.mjs';
export function migrateRecord(input: unknown): WorkspaceEntry;
export function migrateRecords(
  list: unknown
): { records: WorkspaceEntry[]; dropped: number };
export function isOnMigrationChain(v: unknown): boolean;
export const MIGRATION_CHAIN: readonly string[];
