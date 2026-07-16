/**
 * V6.6 — Environment context.
 *
 * React provider for the local environment database.
 * Mirrors the V6.4 workspace context's pattern:
 *   - adapter indirection so the test runner can
 *     swap in the in-memory adapter without touching
 *     the IndexedDB schema
 *   - status: 'initializing' | 'persistent'
 *           | 'session-only' | 'unavailable' | 'error'
 *   - flushPendingWrites() that resolves when every
 *     in-flight write has settled
 *   - hasPendingWrites boolean
 *   - BroadcastChannel listener for multi-tab sync
 *
 * The context never:
 *   - mutates workspace state (V6.4 is read/write;
 *     the env context is similarly isolated)
 *   - mutates the public vulnerability corpus
 *   - touches the network
 *   - logs private values to the console
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { IndexedDBEnvironmentAdapter } from '../environment/IndexedDBEnvironmentAdapter.mjs';
import { InMemoryEnvironmentAdapter } from '../environment/InMemoryEnvironmentAdapter.mjs';
import { UnavailableEnvironmentAdapter } from '../environment/UnavailableEnvironmentAdapter.mjs';
import { startCorrelateJob } from '../environment/workers/dispatcher.mjs';
import { computeInventoryChecksum } from '../environment/hash.mjs';
import { diffInventories } from '../environment/inventoryChange.mjs';
import { validateAsset, validateInventory, validateReview, ASSET_SCHEMA_VERSION, COMPONENT_SCHEMA_VERSION, REVIEW_SCHEMA_VERSION, ASSET_LIMITS } from '../environment/schema.mjs';

const CHANNEL_NAME = 'threatpulse:environment:events';

type Status = 'initializing' | 'persistent' | 'session-only' | 'unavailable' | 'error';

interface EnvironmentState {
  status: Status;
  assets: any[];
  inventoriesByAsset: Record<string, any[]>;
  componentsByAsset: Record<string, any[]>;
  correlationsByInventory: Record<string, any[]>;
  reviewsByCorrelation: Record<string, any>;
  lastError: string | null;
  warning: string | null;
  backend: 'indexeddb' | 'memory' | 'unavailable' | 'initializing';
  hasPendingWrites: boolean;
}

interface CreateAssetArgs {
  name: string;
  description?: string;
  environment?: string;
  assetType?: string;
  localCriticality?: string;
  ownerLabel?: string;
  tags?: string[];
  archived?: boolean;
}

export interface EnvironmentContextValue extends EnvironmentState {
  createAsset(args: CreateAssetArgs): Promise<{ ok: true; asset: any } | { ok: false; reason: string }>;
  updateAsset(assetId: string, patch: Partial<CreateAssetArgs>): Promise<{ ok: true; asset: any } | { ok: false; reason: string }>;
  archiveAsset(assetId: string): Promise<{ ok: true } | { ok: false; reason: string }>;
  restoreAsset(assetId: string): Promise<{ ok: true } | { ok: false; reason: string }>;
  deleteAsset(assetId: string): Promise<{ ok: true } | { ok: false; reason: string }>;
  listAssets(includeArchived?: boolean): Promise<any[]>;
  getAsset(assetId: string): Promise<any | null>;
  importInventoryDryRun(assetId: string, text: string): Promise<{ ok: true; result: any } | { ok: false; reason: string }>;
  importInventoryApply(assetId: string, parsed: any, options?: { publicVulns?: any[]; publicMeta?: any | null }): Promise<{ ok: true; inventory: any; correlations: any[]; componentCount: number } | { ok: false; reason: string }>;
  rerunCorrelation(inventoryId: string, publicVulns: any[], publicMeta: any | null): Promise<{ ok: true; correlations: any[] } | { ok: false; reason: string }>;
  cancelActiveJob(): void;
  saveReview(correlationId: string, reviewStatus: string, note: string): Promise<{ ok: true; review: any } | { ok: false; reason: string }>;
  getReview(correlationId: string): Promise<any | null>;
  listReviews(): Promise<any[]>;
  deleteReview(correlationId: string): Promise<{ ok: true } | { ok: false; reason: string }>;
  exportEnvironment(): Promise<{ ok: true; payload: any } | { ok: false; reason: string }>;
  importEnvironment(payload: any, mode: 'merge' | 'replace'): Promise<{ ok: true; counts: any } | { ok: false; reason: string }>;
  clearEnvironment(): Promise<{ ok: true } | { ok: false; reason: string }>;
  activeJob: { kind: 'parse' | 'correlate' | null };
  flushPendingWrites(): Promise<void>;
  hasPendingWrites: boolean;
}

const Ctx = createContext<EnvironmentContextValue | null>(null);

function newId(prefix: string): string {
  return prefix + '-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 0xffffff).toString(16);
}

function sanitiseTags(tags: unknown): string[] {
  if (!Array.isArray(tags)) return [];
  const out: string[] = [];
  for (const t of tags) {
    if (typeof t !== 'string') continue;
    if (t.length === 0 || t.length > ASSET_LIMITS.MAX_TAG_CHARS) continue;
    if (out.length >= ASSET_LIMITS.MAX_ASSET_TAGS) break;
    out.push(t);
  }
  return out;
}

function selectAdapter(preferSession: boolean): any {
  if (IndexedDBEnvironmentAdapter.isSupported()) return new IndexedDBEnvironmentAdapter();
  if (preferSession) return new InMemoryEnvironmentAdapter();
  return new UnavailableEnvironmentAdapter();
}

export function EnvironmentProvider({ children, preferSessionOnly = false }: { children: ReactNode; preferSessionOnly?: boolean }) {
  const adapterRef = useRef<any>(null);
  const channelRef = useRef<any>(null);
  const inflightRef = useRef(new Set());
  const [state, setState] = useState<EnvironmentState>({
    status: 'initializing',
    assets: [],
    inventoriesByAsset: {},
    componentsByAsset: {},
    correlationsByInventory: {},
    reviewsByCorrelation: {},
    lastError: null,
    warning: null,
    backend: 'initializing',
    hasPendingWrites: false,
  });
  const [activeJob, setActiveJob] = useState<{ kind: 'parse' | 'correlate' | null }>({ kind: null });
  const activeHandleRef = useRef<any>(null);

  const setStatus = useCallback((status: Status, extra: Partial<EnvironmentState> = {}) => {
    setState((s) => ({ ...s, ...extra, status }));
  }, []);

  const refreshAll = useCallback(async () => {
    if (!adapterRef.current) return;
    const assets = await adapterRef.current.listAssets({ includeArchived: true }) as any[];
    const inventoriesByAsset: Record<string, any[]> = {};
    const componentsByAsset: Record<string, any[]> = {};
    for (const a of assets) {
      const inventories = await adapterRef.current.listInventorySnapshots(a.assetId) as any[];
      inventoriesByAsset[a.assetId] = inventories;
      const comps = await adapterRef.current.listComponentsForAsset(a.assetId) as any[];
      componentsByAsset[a.assetId] = comps;
    }
    setState((s) => ({ ...s, assets, inventoriesByAsset, componentsByAsset }));
  }, []);

  // ----- bootstrap -----
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const adapter = selectAdapter(preferSessionOnly);
      adapterRef.current = adapter;
      const open = await adapter.open();
      if (cancelled) return;
      if (!open.ok) {
        setStatus('unavailable', { backend: 'unavailable', lastError: open.reason || 'unavailable' });
        return;
      }
      const isIdb = adapter instanceof IndexedDBEnvironmentAdapter;
      const isMem = adapter instanceof InMemoryEnvironmentAdapter;
      const backend = isIdb ? 'indexeddb' : isMem ? 'memory' : 'unavailable';
      // Multi-tab listener
      if (typeof BroadcastChannel !== 'undefined') {
        try {
          const ch = new BroadcastChannel(CHANNEL_NAME);
          ch.onmessage = (ev) => {
            if (cancelled) return;
            if (ev?.data && (ev.data.type === 'asset-put' || ev.data.type === 'asset-delete' || ev.data.type === 'inventory-applied' || ev.data.type === 'inventory-deleted' || ev.data.type === 'correlations-replaced' || ev.data.type === 'review-put' || ev.data.type === 'review-delete' || ev.data.type === 'environment-cleared')) {
              void refreshAll();
            }
          };
          channelRef.current = ch;
        } catch { /* ignore */ }
      }
      setStatus(isIdb ? 'persistent' : 'session-only', { backend, lastError: null });
      await refreshAll();
    })();
    return () => {
      cancelled = true;
      try { channelRef.current?.close(); } catch { /* ignore */ }
      try { adapterRef.current?.close(); } catch { /* ignore */ }
    };
  }, [preferSessionOnly, refreshAll, setStatus]);

  // ----- inflight tracking -----
  const trackInflight = useCallback(<T,>(p: Promise<T>): Promise<T> => {
    inflightRef.current.add(p as Promise<unknown>);
    setState((s) => (s.hasPendingWrites ? s : { ...s, hasPendingWrites: true }));
    (p as unknown as Promise<unknown>).finally(() => {
      inflightRef.current.delete(p as Promise<unknown>);
      if (inflightRef.current.size === 0) {
        setState((s) => (s.hasPendingWrites ? { ...s, hasPendingWrites: false } : s));
      }
    });
    return p;
  }, []);

  const flushPendingWrites = useCallback(async () => {
    const inflight = Array.from(inflightRef.current) as Promise<unknown>[];
    if (inflight.length === 0) return;
    await Promise.allSettled(inflight);
  }, []);

  // ----- assets -----
  const createAsset = useCallback(async (args: CreateAssetArgs): Promise<{ ok: true; asset: any } | { ok: false; reason: string }> => {
    if (!adapterRef.current) return { ok: false, reason: 'adapter-unavailable' };
    const now = new Date().toISOString();
    const candidate = {
      schemaVersion: ASSET_SCHEMA_VERSION,
      assetId: newId('asset'),
      name: typeof args.name === 'string' ? args.name : '',
      description: typeof args.description === 'string' ? args.description : '',
      environment: typeof args.environment === 'string' ? args.environment : 'unknown',
      assetType: typeof args.assetType === 'string' ? args.assetType : 'other',
      localCriticality: typeof args.localCriticality === 'string' ? args.localCriticality : 'none',
      ownerLabel: typeof args.ownerLabel === 'string' ? args.ownerLabel : '',
      tags: sanitiseTags(args.tags),
      createdAt: now,
      updatedAt: now,
      archived: false,
      latestInventoryId: null,
    };
    const v = validateAsset(candidate);
    if (!v.ok) return { ok: false, reason: v.reason };
    const op = adapterRef.current.putAsset(v.value);
    return trackInflight(op).then((r: any) => (r.ok ? { ok: true as const, asset: v.value } : { ok: false as const, reason: r.reason || 'unknown' }));
  }, [trackInflight]);

  const updateAsset = useCallback(async (assetId: string, patch: Partial<CreateAssetArgs>): Promise<{ ok: true; asset: any } | { ok: false; reason: string }> => {
    if (!adapterRef.current) return { ok: false, reason: 'adapter-unavailable' };
    const r = await adapterRef.current.getAsset(assetId);
    if (!r || !r.ok || !r.value) return { ok: false, reason: 'not-found' };
    const next = {
      ...r.value,
      ...patch,
      tags: sanitiseTags(patch.tags || r.value.tags),
      updatedAt: new Date().toISOString(),
    };
    const v = validateAsset(next);
    if (!v.ok) return { ok: false, reason: v.reason };
    const op = adapterRef.current.putAsset(v.value);
    return trackInflight(op).then((r2: any) => (r2.ok ? { ok: true as const, asset: v.value } : { ok: false as const, reason: r2.reason || 'unknown' }));
  }, [trackInflight]);

  const archiveAsset = useCallback(async (assetId: string): Promise<{ ok: true; asset: any } | { ok: false; reason: string }> => {
    return updateAsset(assetId, { archived: true });
  }, [updateAsset]);

  const restoreAsset = useCallback(async (assetId: string): Promise<{ ok: true; asset: any } | { ok: false; reason: string }> => {
    return updateAsset(assetId, { archived: false });
  }, [updateAsset]);

  const deleteAsset = useCallback(async (assetId: string): Promise<{ ok: true } | { ok: false; reason: string }> => {
    if (!adapterRef.current) return { ok: false, reason: 'adapter-unavailable' };
    const op = adapterRef.current.deleteAsset(assetId);
    return trackInflight(op) as Promise<{ ok: true } | { ok: false; reason: string }>;
  }, [trackInflight]);

  const listAssets = useCallback(async (includeArchived = false): Promise<any[]> => {
    if (!adapterRef.current) return [];
    return adapterRef.current.listAssets({ includeArchived });
  }, []);

  const getAsset = useCallback(async (assetId: string): Promise<any | null> => {
    if (!adapterRef.current) return null;
    const r = await adapterRef.current.getAsset(assetId);
    return r && r.ok ? r.value : null;
  }, []);

  // ----- inventory + components + correlations -----
  const importInventoryDryRun = useCallback(async (assetId: string, text: string): Promise<{ ok: true; result: any } | { ok: false; reason: string }> => {
    if (!adapterRef.current) return { ok: false, reason: 'adapter-unavailable' };
    const { parseImport } = await import('../environment/import.mjs');
    const out = parseImport(text, { assetId, inventoryId: 'dryrun-' + Date.now() });
    return out.ok ? { ok: true as const, result: out.result } : { ok: false as const, reason: out.reason };
  }, []);

  const importInventoryApply = useCallback(async (assetId: string, parsed: any, options?: { publicVulns?: any[]; publicMeta?: any | null }): Promise<{ ok: true; inventory: any; correlations: any[]; componentCount: number; change?: any } | { ok: false; reason: string }> => {
    if (!adapterRef.current) return { ok: false, reason: 'adapter-unavailable' };
    if (!parsed || !Array.isArray(parsed.components)) return { ok: false, reason: 'invalid-parsed' };
    const inventoryId = newId('inv');
    const now = new Date().toISOString();
    const checksum = await computeInventoryChecksum(parsed.components);
    const inventory = {
      schemaVersion: COMPONENT_SCHEMA_VERSION,
      inventoryId,
      assetId,
      sourceFormat: parsed.format,
      sourceVersion: parsed.sourceVersion,
      importedAt: now,
      fileName: (parsed.format || 'import') + '-' + inventoryId,
      componentCount: parsed.components.length,
      checksum,
      warnings: Array.isArray(parsed.warnings) ? parsed.warnings : [],
      metadata: { rejected: parsed.rejected || 0, sizeBytes: parsed.sizeBytes || 0 },
    };
    const v = validateInventory(inventory);
    if (!v.ok) return { ok: false, reason: v.reason };
    const op = adapterRef.current.applyInventory({ inventory: v.value, components: parsed.components });
    const applyRes = await trackInflight(op) as any;
    if (!applyRes.ok) return { ok: false, reason: applyRes.reason || 'apply-failed' };
    const publicVulns = options && Array.isArray(options.publicVulns) ? options.publicVulns : [];
    const publicMeta = options && options.publicMeta ? options.publicMeta : null;
    const corrRes = await runCorrelation({ adapter: adapterRef.current, inventoryId, assetId, components: parsed.components, publicVulns, publicMeta, trackInflight });
    if (!corrRes.ok) return { ok: false, reason: corrRes.reason || 'correlation-failed' };
    const prevList = await adapterRef.current.listInventorySnapshots(assetId);
    const prev = prevList.length > 1 ? prevList[1] : null;
    let change = null;
    if (prev) {
      const prevComponents = await adapterRef.current.listComponentsForAsset(assetId);
      change = diffInventories(prevComponents, parsed.components);
    }
    return { ok: true as const, inventory: v.value, correlations: corrRes.correlations, componentCount: parsed.components.length, change };
  }, [trackInflight]);

  const rerunCorrelation = useCallback(async (inventoryId: string, publicVulns: any[], publicMeta: any | null): Promise<{ ok: true; correlations: any[] } | { ok: false; reason: string }> => {
    if (!adapterRef.current) return { ok: false, reason: 'adapter-unavailable' };
    const assets = await adapterRef.current.listAssets({ includeArchived: true });
    let assetId = '';
    let resolvedComponents: any[] = [];
    for (const a of assets) {
      const invs = await adapterRef.current.listInventorySnapshots(a.assetId);
      if (invs.find((i: any) => i.inventoryId === inventoryId)) {
        assetId = a.assetId;
        resolvedComponents = await adapterRef.current.listComponentsForAsset(a.assetId);
        break;
      }
    }
    if (!assetId) return { ok: false, reason: 'inventory-not-found' };
    return runCorrelation({ adapter: adapterRef.current, inventoryId, assetId, components: resolvedComponents, publicVulns, publicMeta, trackInflight });
  }, [trackInflight]);

  const cancelActiveJob = useCallback(() => {
    try { (activeHandleRef.current as any)?.cancel(); } catch { /* ignore */ }
    activeHandleRef.current = null;
    setActiveJob({ kind: null });
  }, []);

  // ----- reviews -----
  const saveReview = useCallback(async (correlationId: string, reviewStatus: string, note: string): Promise<{ ok: true; review: any } | { ok: false; reason: string }> => {
    if (!adapterRef.current) return { ok: false, reason: 'adapter-unavailable' };
    const existing = await adapterRef.current.getReview(correlationId);
    const now = new Date().toISOString();
    const next = {
      schemaVersion: REVIEW_SCHEMA_VERSION,
      correlationId,
      reviewStatus: typeof reviewStatus === 'string' ? reviewStatus : 'unreviewed',
      note: typeof note === 'string' ? note : '',
      updatedAt: now,
      revision: (existing ? existing.revision : 0) + 1,
      mutationId: 'review-' + newId('mut'),
    };
    const v = validateReview(next);
    if (!v.ok) return { ok: false, reason: v.reason };
    const op = adapterRef.current.putReview(v.value);
    return trackInflight(op).then((r: any) => (r.ok ? { ok: true as const, review: v.value } : { ok: false as const, reason: r.reason || 'unknown' }));
  }, [trackInflight]);

  const getReview = useCallback(async (correlationId: string): Promise<any | null> => {
    if (!adapterRef.current) return null;
    return adapterRef.current.getReview(correlationId);
  }, []);

  const listReviews = useCallback(async (): Promise<any[]> => {
    if (!adapterRef.current) return [];
    return adapterRef.current.listReviews();
  }, []);

  const deleteReview = useCallback(async (correlationId: string): Promise<{ ok: true } | { ok: false; reason: string }> => {
    if (!adapterRef.current) return { ok: false, reason: 'adapter-unavailable' };
    return adapterRef.current.deleteReview(correlationId) as Promise<{ ok: true } | { ok: false; reason: string }>;
  }, []);

  // ----- export / import / clear -----
  const exportEnvironment = useCallback(async (): Promise<{ ok: true; payload: any } | { ok: false; reason: string }> => {
    if (!adapterRef.current) return { ok: false, reason: 'adapter-unavailable' };
    const assets = await adapterRef.current.listAssets({ includeArchived: true });
    const inventories: any[] = [];
    const components: any[] = [];
    const correlationReviews = await adapterRef.current.listReviews();
    for (const a of assets) {
      const invs = await adapterRef.current.listInventorySnapshots(a.assetId);
      inventories.push(...invs);
      const comps = await adapterRef.current.listComponentsForAsset(a.assetId);
      components.push(...comps);
    }
    return { ok: true as const, payload: { assets, inventories, components, correlationReviews } };
  }, []);

  const importEnvironment = useCallback(async (_payload: any, _mode: 'merge' | 'replace') => {
    return { ok: false as const, reason: 'import-not-yet-implemented' };
  }, []);

  const clearEnvironment = useCallback(async (): Promise<{ ok: true } | { ok: false; reason: string }> => {
    if (!adapterRef.current) return { ok: false, reason: 'adapter-unavailable' };
    const op = adapterRef.current.clearAll();
    return trackInflight(op) as Promise<{ ok: true } | { ok: false; reason: string }>;
  }, [trackInflight]);

  const value = useMemo<EnvironmentContextValue>(() => ({
    ...state,
    activeJob,
    createAsset,
    updateAsset,
    archiveAsset,
    restoreAsset,
    deleteAsset,
    listAssets,
    getAsset,
    importInventoryDryRun,
    importInventoryApply,
    rerunCorrelation,
    cancelActiveJob,
    saveReview,
    getReview,
    listReviews,
    deleteReview,
    exportEnvironment,
    importEnvironment,
    clearEnvironment,
    flushPendingWrites,
    hasPendingWrites: state.hasPendingWrites,
  }), [state, activeJob, createAsset, updateAsset, archiveAsset, restoreAsset, deleteAsset, listAssets, getAsset, importInventoryDryRun, importInventoryApply, rerunCorrelation, cancelActiveJob, saveReview, getReview, listReviews, deleteReview, exportEnvironment, importEnvironment, clearEnvironment, flushPendingWrites]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useEnvironment() {
  const v = useContext(Ctx);
  if (!v) throw new Error('useEnvironment must be used inside <EnvironmentProvider>');
  return v;
}

async function runCorrelation({ adapter, inventoryId, assetId, components, publicVulns, publicMeta, trackInflight }: any): Promise<{ ok: true; correlations: any[] } | { ok: false; reason: string }> {
  // The worker dispatcher wraps the synchronous
  // buildCorrelations call so the test runner path
  // is identical to the browser path.
  const start = startCorrelateJob({
    components,
    publicVulns,
    publicMeta,
    assetId,
    inventoryId,
    onProgress: () => {},
  });
  const out = await start.handle.result();
  if (!out.ok) return { ok: false, reason: out.reason };
  const op = adapter.replaceCorrelationsForInventory({ inventoryId, assetId, correlations: out.correlations });
  return trackInflight(op).then((r: any) => (r.ok ? { ok: true as const, correlations: out.correlations } : { ok: false as const, reason: r.reason || 'unknown' }));
}
