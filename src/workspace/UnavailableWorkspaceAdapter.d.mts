import type { WorkspaceAdapter } from './InMemoryWorkspaceAdapter.mjs';
export declare class UnavailableWorkspaceAdapter implements WorkspaceAdapter {
  constructor(opts?: { reason?: string; backend?: string });
  static readonly REASON: 'unavailable';
  initialize(): Promise<{ ok: boolean; reason?: string }>;
  subscribe(listener: (event: unknown) => void): () => void;
  close(): Promise<void>;
  getEntry(cveId: string): Promise<null>;
  putEntry(entry: import('./schema.mjs').WorkspaceEntry): Promise<{ ok: boolean; reason?: string }>;
  patchEntry(
    cveId: string,
    patch: Record<string, unknown>
  ): Promise<{ ok: boolean; reason?: string }>;
  deleteEntry(cveId: string): Promise<{ ok: boolean; reason?: string }>;
  listEntries(filters?: Record<string, unknown>): Promise<{ ok: boolean; entries: [] }>;
  bulkUpdate(
    cveIds: string[],
    patch: Record<string, unknown>
  ): Promise<{ ok: boolean; updated: 0 }>;
  exportWorkspace(): Promise<{ ok: boolean; entries: []; count: 0 }>;
  validateImport(payload: unknown): Promise<{ ok: boolean }>;
  importWorkspace(
    payload: unknown,
    mode: 'merge' | 'replace'
  ): Promise<{ ok: boolean; reason?: string }>;
  clearArchived(): Promise<{ ok: boolean; removed: 0 }>;
  clearWorkspace(): Promise<{ ok: boolean; removed: 0 }>;
  getWorkspaceMetadata(): Promise<{ ok: boolean; backend: string; count: 0; warning: false }>;
}
export const UNAVAILABLE_REASON: 'unavailable';
