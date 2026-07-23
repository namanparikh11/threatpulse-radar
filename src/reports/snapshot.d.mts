/**
 * V6.5 — TypeScript declarations for the snapshot
 * builder. Mirrors the JS surface.
 */

export const EMPTY_SNAPSHOT_ERROR: string;

export interface ReportSelection {
  cveIds: string[];
  includePrivateNotes: boolean;
  includeLocalTags: boolean;
  includeResolved: boolean;
  includeArchived: boolean;
}

export interface ReportSnapshot {
  readonly capturedAt: string;
  readonly applicationVersion: string;
  readonly publicIntelligence: {
    readonly status: 'available' | 'mismatch' | 'unavailable';
    readonly version: string | null;
    readonly projectionSchemaVersion: string | null;
    readonly generatedAt: string | null;
    readonly comparableAxes: string[];
    readonly suppressedAxes: { axis: string; reason: string }[];
    readonly sourceHealth: Array<{
      sourceId: string;
      name: string;
      state: string;
      lastSuccessAt: string | null;
      officialUrl: string | null;
      limits: string | null;
    }>;
  };
  readonly publicRecords: ReadonlyArray<any>;
  readonly localEntries: ReadonlyArray<any>;
  readonly cveIds: ReadonlyArray<string>;
  readonly selection: { readonly [K in keyof ReportSelection]: ReportSelection[K] };
}

export function buildReportSnapshot(args: {
  publicMeta: any;
  vulns: any[];
  entriesByCve: Record<string, any>;
  selection: ReportSelection;
  flushPendingWrites?: () => Promise<void>;
  hasPendingWrites?: boolean;
  options?: { applicationVersion?: string; generatedAt?: string; localEnvironmentSummary?: any; localRemediationSummary?: any };
}): Promise<ReportSnapshot>;
