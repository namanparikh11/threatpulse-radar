/**
 * V6.7 — Migration type declarations.
 */
export function supportedPlanVersions(): string[];
export function supportedTaskVersions(): string[];
export function supportedEvidenceVersions(): string[];
export function supportedLedgerVersions(): string[];

export function migratePlan(record: any, fromVersion: string, targetVersion: string): { ok: boolean; value?: any; reason?: string; changed?: boolean };
export function migrateTask(record: any, fromVersion: string, targetVersion: string): { ok: boolean; value?: any; reason?: string; changed?: boolean };
export function migrateEvidence(record: any, fromVersion: string, targetVersion: string): { ok: boolean; value?: any; reason?: string; changed?: boolean };
export function migrateLedgerEvent(record: any, fromVersion: string, targetVersion: string): { ok: boolean; value?: any; reason?: string; changed?: boolean };
