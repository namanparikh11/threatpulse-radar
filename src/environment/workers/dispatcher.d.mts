/**
 * V6.6 — Worker dispatcher (types).
 */
export interface ParseJobHandle {
  cancel(): void;
  onProgress(cb: (p: { processed: number; total: number }) => void): void;
  result(): Promise<{ ok: true; result: any; checksum: string } | { ok: false; reason: string }>;
}

export interface CorrelateJobHandle {
  cancel(): void;
  onProgress(cb: (p: { processed: number; total: number }) => void): void;
  result(): Promise<{ ok: true; correlations: any[] } | { ok: false; reason: string }>;
}

export function startParseJob(args: { text: string; options: any; onProgress?: (p: any) => void }): { handle: ParseJobHandle };
export function startCorrelateJob(args: { components: any[]; publicVulns: any[]; publicMeta: any | null; assetId: string; inventoryId: string; onProgress?: (p: any) => void }): { handle: CorrelateJobHandle };

export const REASONS: Readonly<Record<string, string>>;
