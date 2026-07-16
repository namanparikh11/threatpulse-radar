/**
 * V6.5 — Report comparison (types).
 */
export interface DiffResult {
  ok: boolean;
  reason?: string;
  left?: { reportId: string; generatedAt: string; checksum: string };
  right?: { reportId: string; generatedAt: string; checksum: string };
  metadata?: { changed: any[]; added: any[]; removed: any[] };
  publicIntelligence?: { changed: any[]; added: any[]; removed: any[] };
  selection?: { changed: any[]; added: any[]; removed: any[] };
  cves?: { added: string[]; removed: string[]; union: string[] };
  providerFacts?: { cveId: string; rows: any[] }[];
  localFacts?: { cveId: string; rows: any[] }[];
  provenance?: { added: any[]; removed: any[]; changed: any[] };
  limitations?: { added: string[]; removed: string[] };
}

export function compareReports(a: any, b: any): Promise<DiffResult>;
