/**
 * V6.5 — TypeScript declarations for the report
 * schema. Mirrors the JS surface.
 */

export const REPORT_SCHEMA_VERSION: string;
export const REPORT_EXPORT_FORMAT: string;
export const CANONICALIZATION_VERSION: string;
export const REPORT_LIMITS: {
  readonly MAX_CVES: number;
  readonly MAX_BYTES: number;
  readonly MAX_NOTE_CHARS: number;
  readonly MAX_TAGS_PER_CVE: number;
  readonly MAX_TAG_CHARS: number;
  readonly MAX_TITLE_CHARS: number;
  readonly MAX_HISTORY_ENTRIES: number;
};
export const FIELD_KIND: {
  readonly PROVIDER_FACT: 'provider-fact';
  readonly THREATPULSE_DERIVED: 'threatpulse-derived';
  readonly USER_AUTHORED: 'user-authored';
  readonly SYSTEM_METADATA: 'system-metadata';
  readonly UNAVAILABLE: 'unavailable-or-uncertain';
};
export const REPORT_TYPES: ReadonlyArray<{ id: string; label: string }>;
export const REDACTION_MODES: ReadonlyArray<{ id: string; label: string }>;

export function normaliseCveId(input: unknown): string | null;

export interface ReportValidationFailure {
  ok: false;
  reason: string;
}
export interface ReportValidationSuccess {
  ok: true;
  report: any;
}
export function validateReport(input: unknown): ReportValidationSuccess | ReportValidationFailure;
export function checkSize(serialized: string): string | null;
export function checkCveCount(input: any): string | null;
