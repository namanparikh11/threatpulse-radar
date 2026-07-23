/**
 * V6.6 — Correlation engine (types).
 */
export interface BuildCorrelationsArgs {
  components: any[];
  publicVulns: any[];
  publicMeta: any | null;
  assetId: string;
  inventoryId: string;
  onProgress?: (processed: number) => void;
}

export function buildCorrelations(args: BuildCorrelationsArgs): readonly any[];
