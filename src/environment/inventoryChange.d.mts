/**
 * V6.6 — Inventory change (types).
 */
export interface InventoryChange {
  added: any[];
  removed: any[];
  versionChanged: any[];
  unchangedCount: number;
  summary: { added: number; removed: number; versionChanged: number; unchanged: number };
  note: string;
}

export function diffInventories(prevComponents: any[], nextComponents: any[]): InventoryChange;
