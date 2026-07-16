/**
 * V6.6 — In-memory environment adapter (types).
 */
import type { AssetInput, ComponentInput, InventoryInput, CorrelationInput, ReviewInput } from './schema.mjs';

export class InMemoryEnvironmentAdapter {
  static readonly REASONS: Readonly<Record<string, string>>;
  static isSupported(): boolean;
  open(): Promise<{ ok: true }>;
  close(): void;
  on(listener: (event: any) => void): () => void;
  putAsset(asset: AssetInput): Promise<{ ok: true } | { ok: false; reason: string }>;
  getAsset(assetId: string): Promise<{ ok: true; value: AssetInput | null }>;
  listAssets(opts?: { includeArchived?: boolean }): Promise<AssetInput[]>;
  deleteAsset(assetId: string): Promise<{ ok: true }>;
  applyInventory(args: { inventory: InventoryInput; components: ComponentInput[] }): Promise<{ ok: true; inventoryId: string; componentCount: number }>;
  listInventorySnapshots(assetId: string): Promise<InventoryInput[]>;
  getLatestInventory(assetId: string): Promise<InventoryInput | null>;
  deleteInventorySnapshot(inventoryId: string): Promise<{ ok: true }>;
  listComponentsForAsset(assetId: string): Promise<ComponentInput[]>;
  replaceCorrelationsForInventory(args: { inventoryId: string; assetId: string; correlations: CorrelationInput[] }): Promise<{ ok: true; count: number }>;
  listCorrelationsForInventory(inventoryId: string): Promise<CorrelationInput[]>;
  listCorrelationsForCve(cveId: string): Promise<CorrelationInput[]>;
  putReview(review: ReviewInput): Promise<{ ok: true }>;
  getReview(correlationId: string): Promise<ReviewInput | null>;
  listReviews(): Promise<ReviewInput[]>;
  deleteReview(correlationId: string): Promise<{ ok: true }>;
  clearAll(): Promise<{ ok: true }>;
}
