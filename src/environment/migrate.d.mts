/**
 * V6.6 — Environment migrations (types).
 */
export const SUPPORTED_VERSIONS: readonly string[];

export interface MigrationResult { ok: true; value: any }
export interface MigrationError { ok: false; reason: string }

export function migrateAsset(input: any, fromVersion: string, toVersion: string): MigrationResult | MigrationError;
export function migrateComponent(input: any, fromVersion: string, toVersion: string): MigrationResult | MigrationError;
export function migrateCorrelation(input: any, fromVersion: string, toVersion: string): MigrationResult | MigrationError;
export function migrateReview(input: any, fromVersion: string, toVersion: string): MigrationResult | MigrationError;
