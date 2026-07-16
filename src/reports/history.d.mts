/**
 * V6.5 — Report history (types).
 */
export interface HistoryEntry {
  reportId: string;
  reportType: string;
  title: string;
  generatedAt: string;
  cveCount: number;
  publicIntelligenceStatus: string;
  publicIntelligenceVersion: string | null;
  includePrivateNotes: boolean;
  includeLocalTags: boolean;
  includeResolved: boolean;
  includeArchived: boolean;
  redactionMode: string;
  exportFormat: string;
  exportStatus: string;
  checksum: string;
  storedAt: string;
}

export interface HistoryResult {
  ok: boolean;
  reason?: string;
  entry?: HistoryEntry;
}

export function buildHistoryEntry(report: any, options?: any): HistoryEntry | null;
export function addHistoryEntry(report: any, options?: any): Promise<HistoryResult>;
export function listHistoryEntries(): Promise<HistoryEntry[]>;
export function removeHistoryEntry(reportId: string): Promise<HistoryResult>;
export function clearHistory(): Promise<HistoryResult>;
export function setHistoryEnabled(value: boolean): void;
export function isHistoryEnabled(): boolean;
export function historyAvailable(): boolean;
