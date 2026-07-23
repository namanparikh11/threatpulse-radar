/**
 * V6.6 — IndexedDB environment adapter (types).
 */
import type { AssetInput, ComponentInput, InventoryInput, CorrelationInput, ReviewInput } from './schema.mjs';

export interface ApplyInventoryArgs { inventory: InventoryInput; components: ComponentInput[] }

export class IndexedDBEnvironmentAdapter {
  static readonly REASONS: Readonly<Record<string, string>>;
  static isSupported(): boolean;
  open(): Promise<{ ok: true } | { ok: false; reason: string }>;
  close(): void;
  on(listener: (event: any) => void): () => void;
  putAsset(asset: AssetInput): Promise<{ ok: true } | { ok: false; reason: string }>;
  getAsset(assetId: string): Promise<{ ok: true; value: AssetInput | null } | { ok: false; reason: string }>;
  listAssets(opts?: { includeArchived?: boolean }): Promise<AssetInput[]>;
  deleteAsset(assetId: string): Promise<{ ok: true } | { ok: false; reason: string }>;
  applyInventory(args: ApplyInventoryArgs): Promise<{ ok: true; inventoryId: string; componentCount: number } | { ok: false; reason: string }>;
  listInventorySnapshots(assetId: string): Promise<InventoryInput[]>;
  getLatestInventory(assetId: string): Promise<InventoryInput | null>;
  deleteInventorySnapshot(inventoryId: string): Promise<{ ok: true } | { ok: false; reason: string }>;
  listComponentsForAsset(assetId: string): Promise<ComponentInput[]>;
  replaceCorrelationsForInventory(args: { inventoryId: string; assetId: string; correlations: CorrelationInput[] }): Promise<{ ok: true; count: number } | { ok: false; reason: string }>;
  listCorrelationsForInventory(inventoryId: string): Promise<CorrelationInput[]>;
  listCorrelationsForCve(cveId: string): Promise<CorrelationInput[]>;
  putReview(review: ReviewInput): Promise<{ ok: true } | { ok: false; reason: string }>;
  getReview(correlationId: string): Promise<ReviewInput | null>;
  listReviews(): Promise<ReviewInput[]>;
  deleteReview(correlationId: string): Promise<{ ok: true } | { ok: false; reason: string }>;
  clearAll(): Promise<{ ok: true } | { ok: false; reason: string }>;
}
