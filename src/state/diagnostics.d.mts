/**
 * V6.8 — Local storage diagnostics type declarations.
 */
export const DIAGNOSTICS_SCHEMA_VERSION: '1.0.0';
export const STORAGE_KIND: { readonly INDEXEDDB: 'indexeddb'; readonly SESSION: 'session'; readonly UNAVAILABLE: 'unavailable'; readonly UNKNOWN: 'unknown' };

export interface DiagnosticsSnapshot {
  schemaVersion: '1.0.0';
  generatedAt: string;
  storageKind: 'indexeddb' | 'session' | 'unavailable' | 'unknown';
  indexedDBSupported: boolean;
  workspace: any;
  environment: any;
  remediation: any;
}

export interface ContextQuickReport {
  name: string;
  present: boolean;
  status?: string;
  hasPendingWrites?: boolean;
  planCount?: number;
  entryCount?: number;
  assetCount?: number;
}

export function buildDiagnostics(args?: { workspaceCtx?: any; environmentCtx?: any; remediationCtx?: any }): Promise<DiagnosticsSnapshot>;
export function summarizeDiagnostics(diag: any): string;
export function quickReport(args?: { workspaceCtx?: any; environmentCtx?: any; remediationCtx?: any }): {
  workspace: ContextQuickReport;
  environment: ContextQuickReport;
  remediation: ContextQuickReport;
};
