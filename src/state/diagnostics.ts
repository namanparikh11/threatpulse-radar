/**
 * V6.8 — Local storage diagnostics.
 *
 * A small helper that reports a sanitized snapshot
 * of the local storage state. The diagnostic output
 * is suitable for the on-screen "Local data centre"
 * panel and for the release-candidate acceptance
 * suite. It NEVER includes note text, tag text,
 * asset names, component paths, plan / task /
 * evidence / fingerprint content, blocker reasons,
 * validation notes, owner labels, or actor labels —
 * only counts and metadata.
 *
 * Each adapter may be missing or unsupported in a
 * given browser; the diagnostics surface that fact
 * explicitly so the operator can decide whether to
 * export before clearing.
 */
import { WORKSPACE_SCHEMA_VERSION } from '../workspace/schema.mjs';
import { ASSET_SCHEMA_VERSION } from '../environment/schema.mjs';
import { REMEDIATION_PLAN_SCHEMA_VERSION, REMEDIATION_TASK_SCHEMA_VERSION, REMEDIATION_EVIDENCE_SCHEMA_VERSION, REMEDIATION_LEDGER_SCHEMA_VERSION } from '../remediation/schema.mjs';

const WORKSPACE_DB = 'threatpulse-workspace';
const WORKSPACE_VERSION = 1;
const WORKSPACE_STORE = 'entries';
const ENVIRONMENT_DB = 'threatpulse-environment';
const ENVIRONMENT_VERSION = 1;
const ENVIRONMENT_STORES = ['assets', 'inventories', 'components', 'correlations', 'reviews', 'meta'];
const REMEDIATION_DB = 'threatpulse-remediation';
const REMEDIATION_VERSION = 1;
const REMEDIATION_STORES = ['plans', 'tasks', 'evidence', 'ledger', 'meta'];

export const DIAGNOSTICS_SCHEMA_VERSION = '1.0.0';
export const STORAGE_KIND = {
  INDEXEDDB: 'indexeddb',
  SESSION: 'session',
  UNAVAILABLE: 'unavailable',
  UNKNOWN: 'unknown',
};

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function sanitizeCount(n: unknown): number {
  if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

function isIndexedDBSupported(): boolean {
  return typeof globalThis !== 'undefined' && typeof (globalThis as any).indexedDB !== 'undefined';
}

function safeOpen(name: string, version: number): Promise<{ ok: boolean; db?: any; reason?: string; message?: string }> {
  if (!isIndexedDBSupported()) return Promise.resolve({ ok: false, reason: 'no-indexeddb' });
  return new Promise((resolve) => {
    let req: IDBOpenDBRequest;
    try {
      req = (globalThis as any).indexedDB.open(name, version);
    } catch (err: any) {
      resolve({ ok: false, reason: 'open-threw', message: err && err.message ? err.message : 'unknown' });
      return;
    }
    let settled = false;
    const finish = (v: any) => { if (settled) return; settled = true; resolve(v); };
    req.onsuccess = () => finish({ ok: true, db: req.result });
    req.onerror = () => finish({ ok: false, reason: 'open-failed', message: (req.error as any) && (req.error as any).message ? (req.error as any).message : 'unknown' });
    req.onblocked = () => finish({ ok: false, reason: 'blocked' });
  });
}

function countStore(db: any, storeName: string): Promise<{ ok: boolean; count?: number; reason?: string; message?: string }> {
  return new Promise((resolve) => {
    if (!db.objectStoreNames || !db.objectStoreNames.contains(storeName)) {
      resolve({ ok: false, reason: 'store-missing' });
      return;
    }
    let tx: IDBTransaction;
    try { tx = db.transaction(storeName, 'readonly'); } catch { resolve({ ok: false, reason: 'tx-failed' }); return; }
    let req: IDBRequest;
    try { req = tx.objectStore(storeName).count(); } catch { resolve({ ok: false, reason: 'count-failed' }); return; }
    req.onsuccess = () => resolve({ ok: true, count: sanitizeCount(req.result) });
    req.onerror = () => resolve({ ok: false, reason: 'count-failed', message: (req.error as any) && (req.error as any).message ? (req.error as any).message : 'unknown' });
  });
}

async function reportDatabase(name: string, version: number, stores: string[]) {
  if (!isIndexedDBSupported()) {
    return { database: name, expectedVersion: version, available: false, reason: 'no-indexeddb', stores: {} as Record<string, unknown> };
  }
  const open = await safeOpen(name, version);
  if (!open.ok) {
    return { database: name, expectedVersion: version, available: false, reason: open.reason, message: open.message || null, stores: {} as Record<string, unknown> };
  }
  const db = open.db;
  const actualVersion = db.version || 0;
  const storeResults: Record<string, unknown> = {};
  for (const s of stores) {
    const r = await countStore(db, s);
    storeResults[s] = r.ok ? r.count : { error: r.reason || 'unknown' };
  }
  try { db.close(); } catch { /* noop */ }
  return {
    database: name,
    expectedVersion: version,
    actualVersion,
    available: true,
    versionMatches: actualVersion === version,
    stores: storeResults,
  };
}

function reportFromContext(name: string, ctx: any) {
  if (!ctx) return { name, present: false, reason: 'no-context' };
  const status = ctx.state && ctx.state.status;
  const hasPendingWrites = !!(ctx.state && ctx.state.hasPendingWrites);
  const planCount = ctx.state && Array.isArray(ctx.state.plans) ? ctx.state.plans.length : 0;
  const entryCount = ctx.state && ctx.state.entriesByCve && typeof ctx.state.entriesByCve === 'object' ? Object.keys(ctx.state.entriesByCve).length : 0;
  const assetCount = ctx.state && Array.isArray(ctx.state.assets) ? ctx.state.assets.length : 0;
  return {
    name,
    present: true,
    status: status || 'unknown',
    hasPendingWrites,
    planCount,
    entryCount,
    assetCount,
  };
}

export interface BuildDiagnosticsArgs {
  workspaceCtx?: any;
  environmentCtx?: any;
  remediationCtx?: any;
}

/**
 * Build a sanitized diagnostics snapshot. Safe to
 * call in any browser session; the function never
 * throws and never returns note / tag / owner /
 * fingerprint / plan / task / evidence content.
 */
export async function buildDiagnostics(args: BuildDiagnosticsArgs = {}): Promise<any> {
  const workspaceCtx = args.workspaceCtx;
  const environmentCtx = args.environmentCtx;
  const remediationCtx = args.remediationCtx;
  const out: any = {
    schemaVersion: DIAGNOSTICS_SCHEMA_VERSION,
    generatedAt: new Date().toISOString(),
    storageKind: isIndexedDBSupported() ? STORAGE_KIND.INDEXEDDB : STORAGE_KIND.UNAVAILABLE,
    indexedDBSupported: isIndexedDBSupported(),
    workspace: {
      schemaVersion: WORKSPACE_SCHEMA_VERSION,
      database: WORKSPACE_DB,
      expectedVersion: WORKSPACE_VERSION,
      context: reportFromContext('workspace', workspaceCtx),
    },
    environment: {
      schemaVersion: ASSET_SCHEMA_VERSION,
      database: ENVIRONMENT_DB,
      expectedVersion: ENVIRONMENT_VERSION,
      context: reportFromContext('environment', environmentCtx),
    },
    remediation: {
      planSchemaVersion: REMEDIATION_PLAN_SCHEMA_VERSION,
      taskSchemaVersion: REMEDIATION_TASK_SCHEMA_VERSION,
      evidenceSchemaVersion: REMEDIATION_EVIDENCE_SCHEMA_VERSION,
      ledgerSchemaVersion: REMEDIATION_LEDGER_SCHEMA_VERSION,
      database: REMEDIATION_DB,
      expectedVersion: REMEDIATION_VERSION,
      context: reportFromContext('remediation', remediationCtx),
    },
  };
  if (isIndexedDBSupported()) {
    out.workspace.databaseReport = await reportDatabase(WORKSPACE_DB, WORKSPACE_VERSION, [WORKSPACE_STORE]);
    out.environment.databaseReport = await reportDatabase(ENVIRONMENT_DB, ENVIRONMENT_VERSION, ENVIRONMENT_STORES);
    out.remediation.databaseReport = await reportDatabase(REMEDIATION_DB, REMEDIATION_VERSION, REMEDIATION_STORES);
  }
  return out;
}

/**
 * Render a compact one-line summary suitable for a
 * status pill. Returns "no data" when the local
 * snapshot is empty.
 */
export function summarizeDiagnostics(diag: any): string {
  if (!diag || !isPlainObject(diag as unknown)) return 'no data';
  const d = diag as any;
  const ws = (d.workspace && d.workspace.context && d.workspace.context.entryCount) || 0;
  const env = (d.environment && d.environment.context && d.environment.context.assetCount) || 0;
  const rem = (d.remediation && d.remediation.context && d.remediation.context.planCount) || 0;
  if (ws === 0 && env === 0 && rem === 0) return 'no local data yet';
  const parts: string[] = [];
  if (ws > 0) parts.push(`${ws} workspace entr${ws === 1 ? 'y' : 'ies'}`);
  if (env > 0) parts.push(`${env} asset${env === 1 ? '' : 's'}`);
  if (rem > 0) parts.push(`${rem} plan${rem === 1 ? '' : 's'}`);
  return parts.join(' · ');
}

/**
 * Synchronous, "best effort" report for tests /
 * contexts that cannot await the IndexedDB probe.
 * Returns counts from the React contexts only.
 */
export function quickReport(args: BuildDiagnosticsArgs = {}) {
  return {
    workspace: reportFromContext('workspace', args.workspaceCtx),
    environment: reportFromContext('environment', args.environmentCtx),
    remediation: reportFromContext('remediation', args.remediationCtx),
  };
}
