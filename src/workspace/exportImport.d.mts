/**
 * V6.4 — TypeScript declarations for the export /
 * import module. Mirrors the JS surface.
 */

export function buildExportPayload(
  entries: unknown[],
  opts?: { applicationVersion?: string }
): Promise<{
  format: string;
  schemaVersion: string;
  exportedAt: string;
  applicationVersion: string;
  entryCount: number;
  entries: any[];
  checksum: string;
}>;

export function buildExportPayloadSync(
  entries: unknown[],
  opts?: { applicationVersion?: string }
): {
  format: string;
  schemaVersion: string;
  exportedAt: string;
  applicationVersion: string;
  entryCount: number;
  entries: any[];
  checksum: string;
};

export interface DryRunResult {
  ok: true;
  entries: any[];
  dropped: { cveId: unknown; reason: string }[];
  stats: { add: number; update: number; leave: number; skip: number; drop: number };
}
export interface DryRunFailure {
  ok: false;
  reason: string;
  schemaVersion?: string;
}
export function dryRunImport(payload: unknown): Promise<DryRunResult | DryRunFailure>;
export function dryRunImportSync(payload: unknown): DryRunResult | DryRunFailure;

export function applyMerge(
  adapter: any,
  stagedEntries: any[]
): Promise<{ ok: boolean; reason?: string; added?: number; updated?: number; unchanged?: number; removed?: number }>;

export function applyReplace(
  adapter: any,
  stagedEntries: any[]
): Promise<{ ok: boolean; reason?: string; written?: number; removed?: number }>;
