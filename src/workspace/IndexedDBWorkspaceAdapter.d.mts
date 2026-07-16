import type { WorkspaceAdapter } from './InMemoryWorkspaceAdapter.mjs';
export declare class IndexedDBWorkspaceAdapter implements WorkspaceAdapter {
  constructor(opts?: { dbName?: string; storeName?: string; metaStoreName?: string });
  static isSupported(): boolean;
  static readonly REASONS: {
    readonly BLOCKED: 'indexeddb-blocked';
    readonly QUOTA: 'quota-exceeded';
    readonly TX_ABORTED: 'transaction-aborted';
    readonly NOT_FOUND: 'not-found';
    readonly INVALID: 'invalid-entry';
    readonly UNKNOWN: 'unknown';
    readonly CLOSED: 'adapter-closed';
    readonly NOT_SUPPORTED: 'indexeddb-not-supported';
  };
  initialize(): Promise<{ ok: boolean; reason?: string; version?: string }>;
  subscribe(listener: (event: unknown) => void): () => void;
  close(): Promise<void>;
  getEntry(cveId: string): Promise<import('./schema.mjs').WorkspaceEntry | null>;
  putEntry(entry: import('./schema.mjs').WorkspaceEntry): Promise<{ ok: boolean; reason?: string; record?: import('./schema.mjs').WorkspaceEntry }>;
  patchEntry(
    cveId: string,
    patch: Record<string, unknown>
  ): Promise<{ ok: boolean; reason?: string; record?: import('./schema.mjs').WorkspaceEntry }>;
  deleteEntry(cveId: string): Promise<{ ok: boolean; reason?: string }>;
  listEntries(
    filters?: Record<string, unknown>
  ): Promise<{ ok: boolean; entries?: import('./schema.mjs').WorkspaceEntry[]; reason?: string }>;
  bulkUpdate(
    cveIds: string[],
    patch: Record<string, unknown>
  ): Promise<{ ok: boolean; updated?: number; reason?: string }>;
  exportWorkspace(): Promise<{ ok: boolean; entries?: import('./schema.mjs').WorkspaceEntry[]; count?: number; reason?: string }>;
  validateImport(payload: unknown): Promise<{ ok: boolean; reason?: string }>;
  importWorkspace(
    payload: unknown,
    mode: 'merge' | 'replace'
  ): Promise<{ ok: boolean; reason?: string; added?: number; updated?: number; unchanged?: number; written?: number; removed?: number }>;
  clearArchived(): Promise<{ ok: boolean; removed?: number; reason?: string }>;
  clearWorkspace(): Promise<{ ok: boolean; removed?: number; reason?: string }>;
  getWorkspaceMetadata(): Promise<{ ok: boolean; backend?: string; count?: number; warning?: boolean; reason?: string }>;
  _deleteDatabase(): Promise<{ ok: boolean; reason?: string; error?: string }>;
}
export const INDEXEDDB_REASONS: {
  readonly BLOCKED: 'indexeddb-blocked';
  readonly QUOTA: 'quota-exceeded';
  readonly TX_ABORTED: 'transaction-aborted';
  readonly NOT_FOUND: 'not-found';
  readonly INVALID: 'invalid-entry';
  readonly UNKNOWN: 'unknown';
  readonly CLOSED: 'adapter-closed';
  readonly NOT_SUPPORTED: 'indexeddb-not-supported';
};
