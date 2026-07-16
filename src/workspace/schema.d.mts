export const WORKSPACE_SCHEMA_VERSION: string;
export const WORKSPACE_EXPORT_FORMAT: string;
export const TRIAGE_STATUSES: readonly string[];
export const USER_PRIORITIES: readonly string[];
export const LIMITS: {
  readonly NOTE_MAX_CHARS: number;
  readonly TAGS_PER_CVE: number;
  readonly TAG_MAX_CHARS: number;
  readonly IMPORT_MAX_BYTES: number;
  readonly IMPORT_MAX_ENTRIES: number;
  readonly WARNING_ENTRIES: number;
};
export function normaliseCveId(input: unknown): string | null;
export function stripControlChars(s: string): string;
export function normaliseText(
  input: unknown,
  opts?: { max?: number; allowNewlines?: boolean }
): string;
export function normalisePriority(input: unknown): string;
export function normaliseTriageStatus(input: unknown): string;
export function normaliseTags(input: unknown): string[];
export function nowIso(): string;
export interface WorkspaceEntry {
  schemaVersion: string;
  cveId: string;
  watched: boolean;
  triageStatus: string;
  userPriority: string;
  tags: string[];
  note: string;
  addedAt: string;
  updatedAt: string;
  lastReviewedAt: string | null;
  lastSeenPublicIntelligenceVersion: string | null;
  lastSeenChangeSignature: string | null;
  archived: boolean;
}
export function makeEntry(cveId: string, overrides?: Partial<WorkspaceEntry>): WorkspaceEntry;
export function validateEntry(
  input: unknown
):
  | { ok: true; record: WorkspaceEntry }
  | { ok: false; reason: string };
export function validateImportPayload(
  payload: unknown,
  opts?: { maxBytes?: number; maxEntries?: number }
):
  | { ok: true; entries: WorkspaceEntry[]; dropped: { cveId: unknown; reason: string }[] }
  | { ok: false; reason: string; schemaVersion?: string };
export function isSupportedSchemaVersion(v: unknown): boolean;
export function compareUpdatedAt(
  a: { updatedAt: string; cveId: string },
  b: { updatedAt: string; cveId: string }
): -1 | 0 | 1;
export function applyPatch(
  entry: WorkspaceEntry,
  patch: Record<string, unknown>
): WorkspaceEntry;
