/**
 * V6.6 — Unavailable environment adapter (types).
 */
export class UnavailableEnvironmentAdapter {
  static readonly REASONS: Readonly<Record<string, string>>;
  static isSupported(): boolean;
  open(): Promise<{ ok: false; reason: string }>;
  close(): void;
  on(listener: (event: any) => void): () => void;
  putAsset(asset: any): Promise<{ ok: false; reason: string }>;
  getAsset(assetId: string): Promise<{ ok: true; value: null }>;
  listAssets(opts?: any): Promise<any[]>;
  deleteAsset(assetId: string): Promise<{ ok: false; reason: string }>;
  applyInventory(args: any): Promise<{ ok: false; reason: string }>;
  listInventorySnapshots(assetId: string): Promise<any[]>;
  getLatestInventory(assetId: string): Promise<any | null>;
  deleteInventorySnapshot(inventoryId: string): Promise<{ ok: false; reason: string }>;
  listComponentsForAsset(assetId: string): Promise<any[]>;
  replaceCorrelationsForInventory(args: any): Promise<{ ok: false; reason: string }>;
  listCorrelationsForInventory(inventoryId: string): Promise<any[]>;
  listCorrelationsForCve(cveId: string): Promise<any[]>;
  putReview(review: any): Promise<{ ok: false; reason: string }>;
  getReview(correlationId: string): Promise<any | null>;
  listReviews(): Promise<any[]>;
  deleteReview(correlationId: string): Promise<{ ok: false; reason: string }>;
  clearAll(): Promise<{ ok: false; reason: string }>;
}
