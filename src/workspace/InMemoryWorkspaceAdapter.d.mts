import type { WorkspaceEntry } from './schema.mjs';
export interface WorkspaceAdapter {
  initialize(): Promise<{ ok: boolean; reason?: string; version?: string }>;
  subscribe(listener: (event: unknown) => void): () => void;
  close(): Promise<void>;
  getEntry(cveId: string): Promise<WorkspaceEntry | null>;
  putEntry(entry: WorkspaceEntry): Promise<{ ok: boolean; reason?: string; record?: WorkspaceEntry }>;
  patchEntry(
    cveId: string,
    patch: Record<string, unknown>
  ): Promise<{ ok: boolean; reason?: string; record?: WorkspaceEntry }>;
  deleteEntry(cveId: string): Promise<{ ok: boolean; reason?: string }>;
  listEntries(
    filters?: Record<string, unknown>
  ): Promise<{ ok: boolean; entries?: WorkspaceEntry[]; reason?: string }>;
  bulkUpdate(
    cveIds: string[],
    patch: Record<string, unknown>
  ): Promise<{ ok: boolean; updated?: number; reason?: string }>;
  exportWorkspace(): Promise<{ ok: boolean; entries?: WorkspaceEntry[]; count?: number; reason?: string }>;
  validateImport(payload: unknown): Promise<{ ok: boolean; reason?: string }>;
  importWorkspace(
    payload: unknown,
    mode: 'merge' | 'replace'
  ): Promise<{ ok: boolean; reason?: string; added?: number; updated?: number; unchanged?: number; written?: number; removed?: number }>;
  clearArchived(): Promise<{ ok: boolean; removed?: number; reason?: string }>;
  clearWorkspace(): Promise<{ ok: boolean; removed?: number; reason?: string }>;
  getWorkspaceMetadata(): Promise<{ ok: boolean; backend?: string; count?: number; warning?: boolean; reason?: string }>;
}
export declare class InMemoryWorkspaceAdapter implements WorkspaceAdapter {
  constructor();
  initialize(): Promise<{ ok: boolean; reason?: string; version?: string }>;
  subscribe(listener: (event: unknown) => void): () => void;
  close(): Promise<void>;
  getEntry(cveId: string): Promise<WorkspaceEntry | null>;
  putEntry(entry: WorkspaceEntry): Promise<{ ok: boolean; reason?: string; record?: WorkspaceEntry }>;
  patchEntry(
    cveId: string,
    patch: Record<string, unknown>
  ): Promise<{ ok: boolean; reason?: string; record?: WorkspaceEntry }>;
  deleteEntry(cveId: string): Promise<{ ok: boolean; reason?: string }>;
  listEntries(
    filters?: Record<string, unknown>
  ): Promise<{ ok: boolean; entries?: WorkspaceEntry[]; reason?: string }>;
  bulkUpdate(
    cveIds: string[],
    patch: Record<string, unknown>
  ): Promise<{ ok: boolean; updated?: number; reason?: string }>;
  exportWorkspace(): Promise<{ ok: boolean; entries?: WorkspaceEntry[]; count?: number; reason?: string }>;
  validateImport(payload: unknown): Promise<{ ok: boolean; reason?: string }>;
  importWorkspace(
    payload: unknown,
    mode: 'merge' | 'replace'
  ): Promise<{ ok: boolean; reason?: string; added?: number; updated?: number; unchanged?: number; written?: number; removed?: number }>;
  clearArchived(): Promise<{ ok: boolean; removed?: number; reason?: string }>;
  clearWorkspace(): Promise<{ ok: boolean; removed?: number; reason?: string }>;
  getWorkspaceMetadata(): Promise<{ ok: boolean; backend?: string; count?: number; warning?: boolean; reason?: string }>;
}
export const INMEMORY_STORAGE_VERSION: string;
