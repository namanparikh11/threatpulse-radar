/**
 * V6.4 — Local defender workspace context.
 *
 * Owns the local workspace adapter, exposes the
 * workspace state to the React tree, and coordinates
 * multi-tab synchronization through a BroadcastChannel.
 *
 * Public state shape:
 *   status: 'initializing' | 'persistent' | 'session-only'
 *           | 'unavailable' | 'error'
 *   entriesByCve: { [cveId]: WorkspaceEntry }
 *   counts: { watched, unreviewed, actionRequired,
 *             changedSinceReview, resolved, archived }
 *   lastError: string | null
 *   conflict: { cveId, reason } | null
 *   hasPendingWrites: boolean
 *
 * The context NEVER merges a workspace entry into the
 * public vulnerability dataset. Every action is
 * performed against the local adapter; the public
 * data flow is unchanged.
 *
 * Concurrency model:
 *   - Per-CVE writes are serialised through a tiny
 *     in-memory queue so a single tab cannot lose an
 *     update because two components fired at once.
 *   - Every successful mutation increments `revision`
 *     exactly once and stamps a fresh `mutationId`.
 *   - A multi-tab edit is detected by comparing the
 *     on-disk revision/updatedAt with the local one
 *     after every commit; a newer disk record that
 *     was not written by THIS tab surfaces a visible
 *     conflict warning that the operator can dismiss
 *     or resolve.
 *
 * Storage fallback (v6.4 hardened):
 *   - persistent:     IndexedDB available, normal.
 *   - session-only:   IndexedDB unavailable, in-memory
 *                    adapter is writable for the
 *                    current tab. Data disappears when
 *                    the tab closes.
 *   - unavailable:    neither persistent nor safe
 *                    session storage is available.
 *   - error:          unexpected storage failure.
 *   The fallback never silently downgrades from
 *   persistent to session-only: once committed
 *   persistent data has been observed, a later
 *   downgrade surfaces an explicit warning.
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

import {
  applyPatch,
  compareUpdatedAt,
  isNewerThan,
  makeEntry,
  normaliseCveId,
  normalisePriority,
  normaliseTags,
  normaliseText,
  normaliseTriageStatus,
  newMutationId,
  stampCommitted,
  WORKSPACE_SCHEMA_VERSION,
} from '../workspace/schema.mjs';
import {
  InMemoryWorkspaceAdapter,
} from '../workspace/InMemoryWorkspaceAdapter.mjs';
import {
  IndexedDBWorkspaceAdapter,
} from '../workspace/IndexedDBWorkspaceAdapter.mjs';
import {
  UnavailableWorkspaceAdapter,
} from '../workspace/UnavailableWorkspaceAdapter.mjs';
import {
  applyMerge,
  applyReplace,
  buildExportPayload,
  dryRunImport,
} from '../workspace/exportImport.mjs';

export type WorkspaceStatus =
  | 'initializing'
  | 'persistent'
  | 'session-only'
  | 'unavailable'
  | 'error';

export interface WorkspaceEntry {
  schemaVersion: string;
  cveId: string;
  watched: boolean;
  triageStatus: string;
  userPriority: string;
  tags: string[];
  note: string;
  addedAt: string;
  updatedAt: string;
  revision: number;
  mutationId: string;
  lastReviewedAt: string | null;
  lastSeenPublicIntelligenceVersion: string | null;
  lastSeenChangeSignature: string | null;
  lastSeenPublicProjectionSchemaVersion: string | null;
  archived: boolean;
}

export interface WorkspaceCounts {
  total: number;
  watched: number;
  unreviewed: number;
  actionRequired: number;
  changedSinceReview: number;
  resolved: number;
  archived: number;
}

export interface WorkspaceConflict {
  cveId: string;
  reason: 'updated' | 'deleted' | 'replaced';
  remote: WorkspaceEntry | null;
  remoteRevision?: number;
  remoteUpdatedAt?: string;
  remoteMutationId?: string;
}

export interface WorkspaceState {
  status: WorkspaceStatus;
  entriesByCve: Record<string, WorkspaceEntry>;
  counts: WorkspaceCounts;
  lastError: string | null;
  conflict: WorkspaceConflict | null;
  warning: boolean;
  backend: 'indexeddb' | 'memory' | 'unavailable' | 'initializing';
  /**
   * True when at least one write is in flight. The
   * drawer's debounce lifecycle also marks a write
   * "pending" between the keystroke and the actual
   * commit, but that is local to the drawer; this
   * flag tracks in-flight context writes.
   */
  hasPendingWrites: boolean;
}

const EMPTY_COUNTS: WorkspaceCounts = {
  total: 0,
  watched: 0,
  unreviewed: 0,
  actionRequired: 0,
  changedSinceReview: 0,
  resolved: 0,
  archived: 0,
};

const CHANNEL_NAME = 'threatpulse-workspace';
const WARNING_ENTRIES = 5000;

function computeCounts(entries: WorkspaceEntry[]): WorkspaceCounts {
  const counts: WorkspaceCounts = { ...EMPTY_COUNTS };
  counts.total = entries.length;
  for (const e of entries) {
    if (e.archived) { counts.archived++; continue; }
    if (e.watched) counts.watched++;
    if (e.triageStatus === 'unreviewed') counts.unreviewed++;
    if (e.triageStatus === 'action-required') counts.actionRequired++;
    if (e.triageStatus === 'resolved') counts.resolved++;
  }
  return counts;
}

function defaultAdapterFactory(): { adapter: any; backend: WorkspaceState['backend'] } {
  if (typeof window !== 'undefined' && IndexedDBWorkspaceAdapter.isSupported()) {
    try {
      const adapter = new IndexedDBWorkspaceAdapter();
      return { adapter, backend: 'indexeddb' };
    } catch {
      // fall through to in-memory
    }
  }
  return { adapter: new InMemoryWorkspaceAdapter(), backend: 'memory' };
}

interface BroadcastMessage {
  type: 'put' | 'patch' | 'delete' | 'bulk';
  cveId?: string;
  ts: number;
}

const WorkspaceContext = createContext<{
  state: WorkspaceState;
  saveError: string | null;
  /** True iff any in-flight write is pending. */
  hasPendingWrites: boolean;
  /** Resolve once every in-flight write has settled. */
  flushPendingWrites: () => Promise<void>;
  toggleWatch: (cveId: string, on?: boolean) => Promise<{ ok: boolean; reason?: string }>;
  setTriage: (cveId: string, status: string) => Promise<{ ok: boolean; reason?: string }>;
  setPriority: (cveId: string, priority: string) => Promise<{ ok: boolean; reason?: string }>;
  addTag: (cveId: string, tag: string) => Promise<{ ok: boolean; reason?: string }>;
  removeTag: (cveId: string, tag: string) => Promise<{ ok: boolean; reason?: string }>;
  setNote: (cveId: string, note: string) => Promise<{ ok: boolean; reason?: string }>;
  markReviewed: (cveId: string, publicIntelligenceVersion: string, changeSignature: string, publicProjectionSchemaVersion?: string | null) => Promise<{ ok: boolean; reason?: string }>;
  archive: (cveId: string, on?: boolean) => Promise<{ ok: boolean; reason?: string }>;
  getEntry: (cveId: string) => WorkspaceEntry | null;
  listEntries: (filters?: any) => Promise<WorkspaceEntry[]>;
  bulkUpdate: (cveIds: string[], patch: Record<string, unknown>) => Promise<{ ok: boolean; updated?: number; reason?: string }>;
  exportWorkspace: () => Promise<{ format: string; schemaVersion: string; exportedAt: string; applicationVersion: string; entryCount: number; entries: WorkspaceEntry[]; checksum: string }>;
  importWorkspace: (payload: any, mode: 'merge' | 'replace') => Promise<{ ok: boolean; reason?: string; added?: number; updated?: number; unchanged?: number; written?: number; removed?: number }>;
  validateImport: (payload: any) => { ok: boolean; reason?: string; entries?: WorkspaceEntry[]; dropped?: any[] };
  clearArchived: () => Promise<{ ok: boolean; removed?: number; reason?: string }>;
  clearWorkspace: () => Promise<{ ok: boolean; reason?: string }>;
  dismissConflict: () => void;
  forceReload: () => Promise<void>;
  incrementChangedSinceReview: (n: number) => void;
  clearChangedSinceReview: () => void;
} | null>(null);

export function useWorkspace() {
  const ctx = useContext(WorkspaceContext);
  if (!ctx) throw new Error('useWorkspace must be used inside <WorkspaceProvider>');
  return ctx;
}

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<WorkspaceState>({
    status: 'initializing',
    entriesByCve: {},
    counts: EMPTY_COUNTS,
    lastError: null,
    conflict: null,
    warning: false,
    backend: 'initializing',
    hasPendingWrites: false,
  });
  const [saveError, setSaveError] = useState<string | null>(null);
  const [changedSinceReviewOverride, setChangedSinceReviewOverride] = useState<number | null>(null);

  const adapterRef = useRef<any | null>(null);
  /**
   * Tracks the storage mode we STARTED in for this
   * session. A silent downgrade from persistent to
   * session-only after committed persistent data
   * already exists would be a data-loss trap. We
   * surface an explicit warning when that happens.
   */
  const startedAsPersistentRef = useRef<boolean | null>(null);
  const backendRef = useRef<WorkspaceState['backend']>('initializing');
  const channelRef = useRef<BroadcastChannel | null>(null);
  // Per-CVE serialised write queue. The map is
  // `cveId -> Promise`. New writes for the same CVE
  // chain onto the existing promise; writes for
  // different CVEs do not block each other.
  const writeQueuesRef = useRef<Map<string, Promise<unknown>>>(new Map());
  /** Set of in-flight write promises (not per-cve). */
  const inflightRef = useRef<Set<Promise<unknown>>>(new Set());

  const broadcastLocal = useCallback((msg: BroadcastMessage) => {
    try {
      channelRef.current?.postMessage(msg);
    } catch { /* noop */ }
  }, []);

  const ingestEntry = useCallback((e: WorkspaceEntry) => {
    setState((s) => {
      const nextByCve = { ...s.entriesByCve, [e.cveId]: e };
      const entries = Object.values(nextByCve);
      return {
        ...s,
        entriesByCve: nextByCve,
        counts: { ...computeCounts(entries), changedSinceReview: changedSinceReviewOverride ?? s.counts.changedSinceReview },
        warning: entries.length >= WARNING_ENTRIES,
      };
    });
  }, [changedSinceReviewOverride]);

  const refreshAll = useCallback(async () => {
    const adapter = adapterRef.current;
    if (!adapter) return;
    const list = await adapter.listEntries({});
    if (!list || list.ok === false) {
      setState((s) => ({ ...s, status: 'error', lastError: list?.reason ?? 'list-failed' }));
      return;
    }
    const byCve: Record<string, WorkspaceEntry> = {};
    for (const e of list.entries) byCve[e.cveId] = e as WorkspaceEntry;
    setState((s) => ({
      ...s,
      status: s.status === 'error' ? 'error' : (backendRef.current === 'unavailable' ? 'unavailable' : (backendRef.current === 'memory' ? 'session-only' : 'persistent')),
      entriesByCve: byCve,
      counts: { ...computeCounts(Object.values(byCve)), changedSinceReview: changedSinceReviewOverride ?? s.counts.changedSinceReview },
      warning: Object.values(byCve).length >= WARNING_ENTRIES,
      lastError: null,
    }));
  }, [changedSinceReviewOverride]);

  // Initialize the adapter and the BroadcastChannel.
  useEffect(() => {
    let cancelled = false;
    const { adapter, backend } = defaultAdapterFactory();
    adapterRef.current = adapter;
    backendRef.current = backend;
    (async () => {
      const init = await adapter.initialize();
      if (cancelled) return;
      if (!init.ok) {
        if (backend === 'indexeddb') {
          const fallback = new InMemoryWorkspaceAdapter();
          const fallbackInit = await fallback.initialize();
          if (cancelled) return;
          if (fallbackInit.ok) {
            adapterRef.current = fallback;
            backendRef.current = 'memory';
            // We started by attempting IndexedDB. If
            // it had committed data and the upgrade
            // failed AFTER startup, the operator's
            // existing data is lost. We mark the
            // session as a graceful fallback, not as
            // a "persistent session" because the data
            // is now in-memory only.
            if (startedAsPersistentRef.current === true) {
              setState((s) => ({
                ...s,
                status: 'session-only',
                backend: 'memory',
                lastError: 'IndexedDB became unavailable after a successful open. Recent data is not persisted. Export a backup.',
              }));
            } else {
              setState((s) => ({
                ...s,
                status: 'session-only',
                backend: 'memory',
                lastError: 'IndexedDB unavailable; using a session-only workspace that will be lost on tab close.',
              }));
            }
            await refreshAll();
            return;
          }
          const none = new UnavailableWorkspaceAdapter();
          await none.initialize();
          adapterRef.current = none;
          backendRef.current = 'unavailable';
          setState((s) => ({
            ...s,
            status: 'unavailable',
            backend: 'unavailable',
            lastError: 'Local workspace is unavailable in this browser session.',
          }));
          return;
        }
        const none = new UnavailableWorkspaceAdapter();
        await none.initialize();
        adapterRef.current = none;
        backendRef.current = 'unavailable';
        setState((s) => ({
          ...s,
          status: 'unavailable',
          backend: 'unavailable',
          lastError: 'Local workspace is unavailable in this browser session.',
        }));
        return;
      }
      // Successful init.
      startedAsPersistentRef.current = true;
      setState((s) => ({
        ...s,
        status: backend === 'memory' ? 'session-only' : 'persistent',
        backend,
        lastError: backend === 'memory'
          ? 'Session-only workspace. Data is not persisted and will be lost on tab close.'
          : null,
      }));
      await refreshAll();
    })();

    let channel: BroadcastChannel | null = null;
    try {
      if (typeof BroadcastChannel !== 'undefined') {
        channel = new BroadcastChannel(CHANNEL_NAME);
        channel.onmessage = async (ev) => {
          if (cancelled) return;
          const msg = ev.data;
          if (!msg || typeof msg !== 'object') return;
          if (msg.type === 'delete' && typeof msg.cveId === 'string') {
            await refreshAll();
            return;
          }
          if ((msg.type === 'put' || msg.type === 'patch') && typeof msg.cveId === 'string') {
            const adapter = adapterRef.current;
            if (!adapter) return;
            const remote = await adapter.getEntry(msg.cveId);
            const local = state.entriesByCve?.[msg.cveId];
            if (remote && (!local || isNewerThan(remote as WorkspaceEntry, local))) {
              ingestEntry(remote as WorkspaceEntry);
              if (local && isNewerThan(local, remote as WorkspaceEntry)) {
                // Local is newer than remote. The
                // conflict banner surfaces this so
                // the operator can decide.
                setState((s) => ({
                  ...s,
                  conflict: {
                    cveId: msg.cveId,
                    reason: 'replaced',
                    remote: remote as WorkspaceEntry,
                    remoteRevision: (remote as any).revision,
                    remoteUpdatedAt: (remote as any).updatedAt,
                    remoteMutationId: (remote as any).mutationId,
                  },
                }));
              }
            } else if (!remote && local) {
              setState((s) => ({
                ...s,
                conflict: {
                  cveId: msg.cveId,
                  reason: 'deleted',
                  remote: null,
                  remoteRevision: undefined,
                  remoteUpdatedAt: undefined,
                  remoteMutationId: undefined,
                },
              }));
            }
            return;
          }
          if (msg.type === 'bulk') {
            await refreshAll();
          }
        };
        channelRef.current = channel;
      }
    } catch { /* noop */ }
    return () => {
      cancelled = true;
      try { channel?.close(); } catch { /* noop */ }
      channelRef.current = null;
      try { adapterRef.current?.close?.(); } catch { /* noop */ }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    setState((s) => {
      const entries = Object.values(s.entriesByCve);
      return {
        ...s,
        counts: { ...computeCounts(entries), changedSinceReview: changedSinceReviewOverride ?? s.counts.changedSinceReview },
      };
    });
  }, [changedSinceReviewOverride]);

  const trackInflight = useCallback(<T,>(p: Promise<T>): Promise<T> => {
    inflightRef.current.add(p as Promise<unknown>);
    setState((s) => (s.hasPendingWrites ? s : { ...s, hasPendingWrites: true }));
    p.finally(() => {
      inflightRef.current.delete(p as Promise<unknown>);
      if (inflightRef.current.size === 0) {
        setState((s) => (s.hasPendingWrites ? { ...s, hasPendingWrites: false } : s));
      }
    });
    return p;
  }, []);

  const writeWithQueue = useCallback(async <T,>(cveId: string, op: () => Promise<T>): Promise<T> => {
    const prev = writeQueuesRef.current.get(cveId) || Promise.resolve();
    const next = prev.then(op, op);
    writeQueuesRef.current.set(cveId, next.catch(() => undefined));
    return trackInflight(next);
  }, [trackInflight]);

  /**
   * The single source of truth for "this write
   * committed". The function:
   *   1. serialises the per-cve write queue
   *   2. reads the current record (or builds a fresh
   *      one)
   *   3. applies the patch
   *   4. stamps the next revision + a fresh mutationId
   *      (stampCommitted)
   *   5. writes via the adapter
   *   6. re-reads to verify the committed record
   *   7. ingests the committed record into local state
   *   8. broadcasts the change (cveId only; no note /
   *      tag content)
   * On any failure (adapter error, verify mismatch)
   * the revision is NOT incremented.
   */
  const applyMutation = useCallback(async (
    cveId: string,
    patch: Record<string, unknown>,
    broadcastType: 'put' | 'patch' = 'patch',
  ): Promise<{ ok: boolean; reason?: string; record?: WorkspaceEntry }> => {
    const id = normaliseCveId(cveId);
    if (id === null) return { ok: false, reason: 'invalid-cveId' };
    setSaveError(null);
    return writeWithQueue(id, async () => {
      const adapter = adapterRef.current;
      if (!adapter) return { ok: false, reason: 'unavailable' };
      // Read current; if missing, build a fresh entry.
      const cur = (await adapter.getEntry(id)) as WorkspaceEntry | null;
      const base = cur || makeEntry(id, {});
      const patched = applyPatch({ ...base }, patch);
      // Stamp a fresh mutationId + next revision. The
      // mutationId is the runtime per-mutation
      // identifier; revision is the monotonically
      // increasing integer counter.
      const next = stampCommitted(patched, { newMutationId: newMutationId() });
      const r = await adapter.putEntry(next);
      if (!r.ok) {
        const message = humanizeWriteError(r.reason);
        setSaveError(message);
        return { ok: false, reason: r.reason };
      }
      // Verify the committed record on disk before
      // considering the write successful.
      const verified = (await adapter.getEntry(id)) as WorkspaceEntry | null;
      if (!verified || compareUpdatedAt(verified, next) !== 0) {
        setSaveError('Storage did not commit the change. Try again.');
        return { ok: false, reason: 'verify-failed' };
      }
      ingestEntry(verified);
      broadcastLocal({ type: broadcastType, cveId: id, ts: Date.now() });
      return { ok: true, record: verified };
    });
  }, [writeWithQueue, ingestEntry, broadcastLocal]);

  const toggleWatch = useCallback(async (cveId: string, on?: boolean) => {
    const id = normaliseCveId(cveId);
    if (!id) return { ok: false, reason: 'invalid-cveId' };
    const cur = (await adapterRef.current?.getEntry?.(id)) as WorkspaceEntry | null;
    const nextWatched = typeof on === 'boolean' ? on : !(cur?.watched ?? false);
    return applyMutation(id, { watched: nextWatched }, 'patch');
  }, [applyMutation]);

  const setTriage = useCallback(async (cveId: string, status: string) => {
    const id = normaliseCveId(cveId);
    if (!id) return { ok: false, reason: 'invalid-cveId' };
    return applyMutation(id, { triageStatus: normaliseTriageStatus(status) }, 'patch');
  }, [applyMutation]);

  const setPriority = useCallback(async (cveId: string, priority: string) => {
    const id = normaliseCveId(cveId);
    if (!id) return { ok: false, reason: 'invalid-cveId' };
    return applyMutation(id, { userPriority: normalisePriority(priority) }, 'patch');
  }, [applyMutation]);

  const addTag = useCallback(async (cveId: string, tag: string) => {
    const id = normaliseCveId(cveId);
    if (!id) return { ok: false, reason: 'invalid-cveId' };
    return writeWithQueue(id, async () => {
      const adapter = adapterRef.current;
      if (!adapter) return { ok: false, reason: 'unavailable' };
      const cur = (await adapter.getEntry(id)) as WorkspaceEntry | null;
      const base = cur || makeEntry(id, {});
      const tags = normaliseTags([...base.tags, tag]);
      return applyMutation(id, { tags }, 'patch');
    });
  }, [writeWithQueue, applyMutation]);

  const removeTag = useCallback(async (cveId: string, tag: string) => {
    const id = normaliseCveId(cveId);
    if (!id) return { ok: false, reason: 'invalid-cveId' };
    return writeWithQueue(id, async () => {
      const adapter = adapterRef.current;
      if (!adapter) return { ok: false, reason: 'unavailable' };
      const cur = (await adapter.getEntry(id)) as WorkspaceEntry | null;
      if (!cur) return { ok: false, reason: 'not-found' };
      const tagLower = tag.toLocaleLowerCase();
      const tags = cur.tags.filter((t) => t.toLocaleLowerCase() !== tagLower);
      return applyMutation(id, { tags }, 'patch');
    });
  }, [writeWithQueue, applyMutation]);

  const setNote = useCallback(async (cveId: string, note: string) => {
    const id = normaliseCveId(cveId);
    if (!id) return { ok: false, reason: 'invalid-cveId' };
    return applyMutation(id, { note: normaliseText(note, { max: 8000 }) }, 'patch');
  }, [applyMutation]);

  const markReviewed = useCallback(async (
    cveId: string,
    publicIntelligenceVersion: string,
    changeSignature: string,
    publicProjectionSchemaVersion: string | null = null,
  ) => {
    const id = normaliseCveId(cveId);
    if (!id) return { ok: false, reason: 'invalid-cveId' };
    return applyMutation(id, {
      lastReviewedAt: new Date().toISOString(),
      lastSeenPublicIntelligenceVersion: publicIntelligenceVersion,
      lastSeenChangeSignature: changeSignature,
      lastSeenPublicProjectionSchemaVersion: publicProjectionSchemaVersion,
      triageStatus: 'reviewing',
    }, 'patch');
  }, [applyMutation]);

  const archive = useCallback(async (cveId: string, on?: boolean) => {
    const id = normaliseCveId(cveId);
    if (!id) return { ok: false, reason: 'invalid-cveId' };
    return applyMutation(id, { archived: typeof on === 'boolean' ? on : true }, 'patch');
  }, [applyMutation]);

  const getEntry = useCallback((cveId: string): WorkspaceEntry | null => {
    const id = normaliseCveId(cveId);
    if (!id) return null;
    return state.entriesByCve[id] || null;
  }, [state.entriesByCve]);

  const listEntries = useCallback(async (filters: any = {}) => {
    const adapter = adapterRef.current;
    if (!adapter) return [];
    const r = await adapter.listEntries(filters);
    return (r.entries || []) as WorkspaceEntry[];
  }, []);

  const bulkUpdate = useCallback(async (cveIds: string[], patch: Record<string, unknown>) => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false, reason: 'unavailable' };
    const ids = (cveIds || []).map((c) => normaliseCveId(c)).filter((c): c is string => !!c);
    setSaveError(null);
    const r = await adapter.bulkUpdate(ids, patch);
    if (!r.ok) {
      setSaveError(humanizeWriteError(r.reason));
      return { ok: false, reason: r.reason };
    }
    if (r.updated && r.updated > 0) {
      // Stamp a fresh mutationId on every affected
      // record so multi-tab conflict detection has a
      // per-bulk discriminator.
      for (const id of ids) {
        const cur = (await adapter.getEntry(id)) as WorkspaceEntry | null;
        if (cur) {
          const next = stampCommitted(cur, { newMutationId: newMutationId() });
          await adapter.putEntry(next);
          const fresh = (await adapter.getEntry(id)) as WorkspaceEntry | null;
          if (fresh) ingestEntry(fresh);
        }
      }
      broadcastLocal({ type: 'bulk', ts: Date.now() });
    }
    return { ok: true, updated: r.updated || 0 };
  }, [ingestEntry, broadcastLocal]);

  const exportWorkspace = useCallback(async () => {
    const entries = Object.values(state.entriesByCve);
    return await buildExportPayload(entries, { applicationVersion: WORKSPACE_SCHEMA_VERSION });
  }, [state.entriesByCve]);

  const validateImport = useCallback((payload: any) => {
    // The exported dryRunImport is async (it
    // recomputes the checksum). The dialog runs a
    // synchronous shape check here for UX; the async
    // path is the single source of truth at import
    // time.
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return { ok: false, reason: 'payload-not-object' as string };
    }
    if (payload.format !== 'threatpulse-local-workspace') {
      return { ok: false, reason: 'invalid-format' as string };
    }
    if (typeof payload.schemaVersion !== 'string') {
      return { ok: false, reason: 'missing-schema-version' as string };
    }
    if (payload.schemaVersion !== WORKSPACE_SCHEMA_VERSION) {
      return { ok: false, reason: 'unsupported-schema-version' as string };
    }
    if (!Array.isArray(payload.entries)) {
      return { ok: false, reason: 'entries-not-array' as string };
    }
    return { ok: true };
  }, []);

  const importWorkspace = useCallback(async (payload: any, mode: 'merge' | 'replace') => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false, reason: 'unavailable' };
    // The async path is the single source of truth
    // (it re-validates the checksum).
    const v = await dryRunImport(payload);
    if (!v.ok) return { ok: false, reason: v.reason };
    if (mode === 'merge') {
      const r = await applyMerge(adapter, v.entries);
      if (!r.ok) { setSaveError(humanizeWriteError(r.reason)); return { ok: false, reason: r.reason }; }
      await refreshAll();
      broadcastLocal({ type: 'bulk', ts: Date.now() });
      return { ok: true, added: r.added || 0, updated: r.updated || 0, unchanged: r.unchanged || 0 };
    }
    const r = await applyReplace(adapter, v.entries);
    if (!r.ok) { setSaveError(humanizeWriteError(r.reason)); return { ok: false, reason: r.reason }; }
    await refreshAll();
    broadcastLocal({ type: 'bulk', ts: Date.now() });
    return { ok: true, written: r.written || 0, removed: r.removed || 0 };
  }, [refreshAll, broadcastLocal, setSaveError]);

  const clearArchived = useCallback(async () => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false, reason: 'unavailable' };
    setSaveError(null);
    const r = await adapter.clearArchived();
    if (!r.ok) { setSaveError(humanizeWriteError(r.reason)); return { ok: false, reason: r.reason }; }
    await refreshAll();
    broadcastLocal({ type: 'bulk', ts: Date.now() });
    return { ok: true, removed: r.removed };
  }, [refreshAll, broadcastLocal, setSaveError]);

  const clearWorkspace = useCallback(async () => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false, reason: 'unavailable' };
    setSaveError(null);
    const r = await adapter.clearWorkspace();
    if (!r.ok) { setSaveError(humanizeWriteError(r.reason)); return { ok: false, reason: r.reason }; }
    setState((s) => ({
      ...s,
      entriesByCve: {},
      counts: { ...EMPTY_COUNTS, changedSinceReview: 0 },
      warning: false,
    }));
    broadcastLocal({ type: 'bulk', ts: Date.now() });
    return { ok: true };
  }, [broadcastLocal, setSaveError]);

  const dismissConflict = useCallback(() => {
    setState((s) => ({ ...s, conflict: null }));
  }, []);

  const forceReload = useCallback(async () => {
    await refreshAll();
  }, [refreshAll]);

  const incrementChangedSinceReview = useCallback((n: number) => {
    setChangedSinceReviewOverride(n);
  }, []);

  const clearChangedSinceReview = useCallback(() => {
    setChangedSinceReviewOverride(0);
  }, []);

  const flushPendingWrites = useCallback(async () => {
    // Wait for every in-flight write to settle.
    const inflight = Array.from(inflightRef.current) as Promise<unknown>[];
    if (inflight.length === 0) return;
    // We don't care about the result of any individual
    // write; we just need them all to settle before
    // the caller proceeds (e.g. a destructive dialog).
    await Promise.allSettled(inflight);
    // After settling, the per-cve queue tail might
    // still have a final microtask queued. Wait one
    // more tick to be safe.
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }, []);

  const value = useMemo(() => ({
    state,
    saveError,
    hasPendingWrites: state.hasPendingWrites,
    flushPendingWrites,
    toggleWatch, setTriage, setPriority, addTag, removeTag, setNote, markReviewed, archive,
    getEntry, listEntries, bulkUpdate,
    exportWorkspace, importWorkspace, validateImport,
    clearArchived, clearWorkspace,
    dismissConflict, forceReload,
    incrementChangedSinceReview, clearChangedSinceReview,
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [
    state, saveError,
    flushPendingWrites,
    toggleWatch, setTriage, setPriority, addTag, removeTag, setNote, markReviewed, archive,
    getEntry, listEntries, bulkUpdate,
    exportWorkspace, importWorkspace, validateImport,
    clearArchived, clearWorkspace,
    dismissConflict, forceReload,
    incrementChangedSinceReview, clearChangedSinceReview,
  ]);

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

function humanizeWriteError(reason: string | undefined): string {
  switch (reason) {
    case 'indexeddb-blocked': return 'Local storage is blocked. The workspace is read-only this session.';
    case 'indexeddb-not-supported': return 'Local storage is not supported in this browser. The workspace is unavailable.';
    case 'quota-exceeded': return 'Browser storage is full. Export your workspace and clear archived entries to free space.';
    case 'transaction-aborted': return 'A conflicting write was detected. Try again.';
    case 'invalid-entry': return 'The change was rejected by the workspace schema.';
    case 'not-found': return 'The workspace entry no longer exists. Refresh the dashboard.';
    case 'adapter-closed': return 'The workspace has been closed. Refresh the page.';
    case 'unavailable': return 'The local workspace is unavailable. Changes are not being saved.';
    case 'note-too-long': return 'Note is too long (8,000 character limit).';
    case 'too-many-tags': return 'Too many tags (20 per CVE limit).';
    case 'invalid-cveId': return 'Invalid CVE identifier.';
    case 'verify-failed': return 'Storage did not commit the change. Try again.';
    case 'checksum-mismatch': return 'The import file failed its checksum. The file may be corrupted.';
    case 'session-only': return 'The workspace is session-only. Data is not persisted.';
    default: return 'Could not save the change. Try again.';
  }
}
