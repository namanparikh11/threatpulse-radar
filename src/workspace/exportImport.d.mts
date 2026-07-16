import type { WorkspaceEntry } from './schema.mjs';
export interface ExportPayload {
  format: 'threatpulse-local-workspace';
  schemaVersion: string;
  exportedAt: string;
  applicationVersion: string;
  entryCount: number;
  entries: WorkspaceEntry[];
  checksum: string;
}
export function buildExportPayload(
  entries: WorkspaceEntry[],
  opts?: { applicationVersion?: string }
): ExportPayload;
export function dryRunImport(
  payload: unknown
):
  | { ok: true; entries: WorkspaceEntry[]; dropped: { cveId: unknown; reason: string }[]; stats: { add: number; update: number; leave: number; skip: number; drop: number } }
  | { ok: false; reason: string; schemaVersion?: string };
export function applyMerge(
  adapter: any,
  stagedEntries: WorkspaceEntry[]
): Promise<{ ok: boolean; reason?: string; added?: number; updated?: number; unchanged?: number }>;
export function applyReplace(
  adapter: any,
  stagedEntries: WorkspaceEntry[]
): Promise<{ ok: boolean; reason?: string; written?: number; removed?: number }>;
export function stageEntries(
  payload: unknown
):
  | { ok: true; entries: WorkspaceEntry[]; dropped: { cveId: unknown; reason: string }[] }
  | { ok: false; reason: string; schemaVersion?: string };
