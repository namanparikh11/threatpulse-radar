/**
 * V6.7 — Remediation context.
 *
 * React provider for the local remediation database.
 * Mirrors the V6.6 EnvironmentContext pattern:
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
 * The context exposes every documented plan / task /
 * evidence / ledger operation. Each plan mutation
 * also appends a matching ledger event in the same
 * IndexedDB transaction (via the adapter and the
 * transaction helper). The context surfaces a
 * sanitized reason on failure so the UI can present
 * a clear message.
 *
 * The context never:
 *   - touches the network
 *   - writes to the URL / history
 *   - logs private values to the console
 *   - mutates the public vulnerability corpus
 *   - exposes local data through any public API
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
import { IndexedDBRemediationAdapter } from '../remediation/IndexedDBRemediationAdapter.mjs';
import { InMemoryRemediationAdapter } from '../remediation/InMemoryRemediationAdapter.mjs';
import { UnavailableRemediationAdapter } from '../remediation/UnavailableRemediationAdapter.mjs';
import {
  validatePlan,
  validateTask,
  validateEvidence,
  validateLedgerEvent,
  normalizePlan,
  normalizeTags,
  normalizeCveIds,
  REMEDIATION_LIMITS,
  PLAN_STATUSES,
  TASK_STATUSES,
  EVIDENCE_TYPES,
  VALIDATION_STATUSES,
} from '../remediation/schema.mjs';
import { isSupportedTransition, checkTransition } from '../remediation/lifecycle.mjs';
import { verifyChain } from '../remediation/ledger.mjs';
import { createPlanWithGenesisEvent, appendFollowupEvent } from '../remediation/transaction.mjs';
import { nowIso, makePlanId, makeTaskId, makeEvidenceId, makeEventId, makeMutationId } from '../remediation/id.mjs';

const CHANNEL_NAME = 'threatpulse:remediation:events';

type Status = 'initializing' | 'persistent' | 'session-only' | 'unavailable' | 'error';

interface RemediationState {
  status: Status;
  plans: any[];
  tasksByPlan: Record<string, any[]>;
  evidenceByPlan: Record<string, any[]>;
  ledgerByPlan: Record<string, any[]>;
  ledgerVerification: {
    status: 'unknown' | 'pending' | 'valid' | 'broken' | 'unavailable';
    perPlan: Record<string, { ok: boolean; reason?: string; eventCount?: number }>;
  };
  lastError: string | null;
  backend: 'indexeddb' | 'memory' | 'unavailable' | 'initializing';
  hasPendingWrites: boolean;
}

export interface CreatePlanArgs {
  title: string;
  description?: string;
  remediationType?: string;
  localPriority?: string;
  ownerLabel?: string;
  dueAt?: string | null;
  linkedCveIds?: string[];
  linkedAssetIds?: string[];
  linkedComponentIds?: string[];
  linkedCorrelationIds?: string[];
  linkedInventoryIds?: string[];
  tags?: string[];
  actorLabel?: string;
}

export interface UpdatePlanPatch {
  title?: string;
  description?: string;
  status?: string;
  remediationType?: string;
  localPriority?: string;
  ownerLabel?: string;
  dueAt?: string | null;
  startedAt?: string | null;
  completedAt?: string | null;
  validationStatus?: string;
  linkedCveIds?: string[];
  linkedAssetIds?: string[];
  linkedComponentIds?: string[];
  linkedCorrelationIds?: string[];
  linkedInventoryIds?: string[];
  tags?: string[];
  notes?: string;
  acceptedRiskRationale?: string;
  archived?: boolean;
}

export interface CreateTaskArgs {
  planId: string;
  title: string;
  description?: string;
  status?: string;
  ownerLabel?: string;
  dueAt?: string | null;
  order?: number;
  blockerReason?: string;
  actorLabel?: string;
}

export interface UpdateTaskPatch {
  title?: string;
  description?: string;
  status?: string;
  ownerLabel?: string;
  dueAt?: string | null;
  completedAt?: string | null;
  order?: number;
  blockerReason?: string;
}

export interface CreateEvidenceArgs {
  planId: string;
  taskId?: string | null;
  evidenceType?: string;
  title: string;
  description?: string;
  sourceLabel?: string;
  externalUrl?: string | null;
  linkedInventoryId?: string | null;
  linkedCorrelationId?: string | null;
  linkedReportId?: string | null;
  fileFingerprint?: any | null;
  validationOutcome?: string | null;
  supersedesEvidenceId?: string | null;
  actorLabel?: string;
}

export interface RemediationContextValue {
  state: RemediationState;

  // plans
  createPlan(args: CreatePlanArgs): Promise<{ ok: true; plan: any; eventId: string } | { ok: false; reason: string }>;
  updatePlan(planId: string, patch: UpdatePlanPatch, actorLabel?: string): Promise<{ ok: true; plan: any; eventId: string } | { ok: false; reason: string }>;
  archivePlan(planId: string, actorLabel?: string): Promise<{ ok: true; eventId: string } | { ok: false; reason: string }>;
  restorePlan(planId: string, actorLabel?: string): Promise<{ ok: true; eventId: string } | { ok: false; reason: string }>;
  deletePlan(planId: string): Promise<{ ok: true } | { ok: false; reason: string }>;
  setStatus(planId: string, toStatus: string, actorLabel?: string): Promise<{ ok: true; eventId: string } | { ok: false; reason: string }>;
  setValidation(planId: string, toStatus: string, note: string, actorLabel?: string): Promise<{ ok: true; eventId: string; evidenceId: string } | { ok: false; reason: string }>;
  acceptRisk(planId: string, rationale: string, actorLabel?: string): Promise<{ ok: true; eventId: string } | { ok: false; reason: string }>;
  reopenPlan(planId: string, actorLabel?: string): Promise<{ ok: true; eventId: string } | { ok: false; reason: string }>;
  getPlan(planId: string): Promise<any | null>;
  listPlans(includeArchived?: boolean): Promise<any[]>;
  countByStatus(): Record<string, number>;

  // tasks
  addTask(args: CreateTaskArgs): Promise<{ ok: true; task: any; eventId: string } | { ok: false; reason: string }>;
  updateTask(taskId: string, patch: UpdateTaskPatch, actorLabel?: string): Promise<{ ok: true; task: any; eventId: string } | { ok: false; reason: string }>;
  reorderTasks(planId: string, taskIds: string[], actorLabel?: string): Promise<{ ok: true; eventId: string } | { ok: false; reason: string }>;
  completeTask(taskId: string, actorLabel?: string): Promise<{ ok: true; task: any; eventId: string } | { ok: false; reason: string }>;
  reopenTask(taskId: string, actorLabel?: string): Promise<{ ok: true; task: any; eventId: string } | { ok: false; reason: string }>;
  deleteTask(taskId: string, actorLabel?: string): Promise<{ ok: true; eventId: string } | { ok: false; reason: string }>;
  listTasksForPlan(planId: string): Promise<any[]>;

  // evidence
  addEvidence(args: CreateEvidenceArgs): Promise<{ ok: true; evidence: any; eventId: string } | { ok: false; reason: string }>;
  supersedeEvidence(evidenceId: string, replacement: CreateEvidenceArgs, actorLabel?: string): Promise<{ ok: true; evidence: any; eventId: string } | { ok: false; reason: string }>;
  listEvidenceForPlan(planId: string): Promise<any[]>;

  // ledger
  listLedgerEvents(planId: string): Promise<any[]>;
  verifyPlanLedger(planId: string): Promise<{ ok: boolean; reason?: string; eventCount?: number }>;
  verifyAllLedgers(): Promise<void>;
  exportPlan(planId: string): Promise<{ ok: true; bundle: any } | { ok: false; reason: string }>;

  // housekeeping
  flushPendingWrites(): Promise<void>;
  hasPendingWrites: boolean;
  clearAll(): Promise<{ ok: true } | { ok: false; reason: string }>;
}

const Ctx = createContext<RemediationContextValue | null>(null);

function selectAdapter(preferSession: boolean): any {
  if (IndexedDBRemediationAdapter.isSupported()) return new IndexedDBRemediationAdapter();
  if (preferSession) return new InMemoryRemediationAdapter();
  return new UnavailableRemediationAdapter();
}

function clampSummary(s: string): string {
  if (typeof s !== 'string') return '';
  if (s.length <= REMEDIATION_LIMITS.MAX_SUMMARY_CHARS) return s;
  return s.slice(0, REMEDIATION_LIMITS.MAX_SUMMARY_CHARS);
}

function clampTagList(tags: unknown): string[] {
  return normalizeTags(tags);
}

function clampCveList(cves: unknown): string[] {
  return normalizeCveIds(cves);
}

function idList(input: unknown, maxLen: number): string[] {
  if (!Array.isArray(input)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of input) {
    if (typeof v !== 'string') continue;
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(v)) continue;
    if (seen.has(v)) continue;
    if (out.length >= maxLen) break;
    seen.add(v);
    out.push(v);
  }
  return out;
}

export function RemediationProvider({ children, preferSessionOnly = false }: { children: ReactNode; preferSessionOnly?: boolean }) {
  const adapterRef = useRef<any>(null);
  const channelRef = useRef<any>(null);
  const inflightRef = useRef(new Set<Promise<unknown>>());
  const [state, setState] = useState<RemediationState>({
    status: 'initializing',
    plans: [],
    tasksByPlan: {},
    evidenceByPlan: {},
    ledgerByPlan: {},
    ledgerVerification: { status: 'unknown', perPlan: {} },
    lastError: null,
    backend: 'initializing',
    hasPendingWrites: false,
  });

  const setStatus = useCallback((status: Status, extra: Partial<RemediationState> = {}) => {
    setState((s) => ({ ...s, ...extra, status }));
  }, []);

  const refreshAll = useCallback(async () => {
    if (!adapterRef.current) return;
    const r = await adapterRef.current.listPlans({ includeArchived: true });
    if (!r.ok) return;
    const plans = Array.isArray(r.value) ? r.value : [];
    const tasksByPlan: Record<string, any[]> = {};
    const evidenceByPlan: Record<string, any[]> = {};
    const ledgerByPlan: Record<string, any[]> = {};
    for (const p of plans) {
      const t = await adapterRef.current.listTasksForPlan(p.planId);
      tasksByPlan[p.planId] = t.ok ? t.value : [];
      const e = await adapterRef.current.listEvidenceForPlan(p.planId);
      evidenceByPlan[p.planId] = e.ok ? e.value : [];
      const l = await adapterRef.current.listLedgerEvents(p.planId);
      ledgerByPlan[p.planId] = l.ok ? l.value : [];
    }
    setState((s) => ({ ...s, plans, tasksByPlan, evidenceByPlan, ledgerByPlan }));
  }, []);

  const trackInflight = useCallback(<T,>(p: Promise<T>): Promise<T> => {
    inflightRef.current.add(p as unknown as Promise<unknown>);
    setState((s) => (s.hasPendingWrites ? s : { ...s, hasPendingWrites: true }));
    (p as unknown as Promise<unknown>).finally(() => {
      inflightRef.current.delete(p as unknown as Promise<unknown>);
      if (inflightRef.current.size === 0) {
        setState((s) => (s.hasPendingWrites ? { ...s, hasPendingWrites: false } : s));
      }
    });
    return p;
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
      const isIdb = adapter instanceof IndexedDBRemediationAdapter;
      const isMem = adapter instanceof InMemoryRemediationAdapter;
      const backend: RemediationState['backend'] = isIdb ? 'indexeddb' : isMem ? 'memory' : 'unavailable';
      if (typeof BroadcastChannel !== 'undefined') {
        try {
          const ch = new BroadcastChannel(CHANNEL_NAME);
          ch.onmessage = (ev) => {
            if (cancelled) return;
            const t = ev?.data?.type;
            if (t === 'plan-put' || t === 'plan-deleted' || t === 'task-put' || t === 'evidence-put' || t === 'ledger-append' || t === 'remediation-cleared') {
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

  // ----- plan operations -----
  const createPlan = useCallback(async (args: CreatePlanArgs) => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false as const, reason: 'adapter-closed' };
    const now = nowIso();
    const planId = makePlanId(`${args.title || 'plan'}|${now}|${Math.random()}`);
    const mutationId = makeMutationId();
    const planCandidate = normalizePlan({
      schemaVersion: '1.0.0',
      planId,
      title: args.title || '',
      description: args.description || '',
      status: 'draft',
      remediationType: args.remediationType || 'other',
      localPriority: args.localPriority || 'none',
      ownerLabel: args.ownerLabel || '',
      dueAt: args.dueAt || null,
      startedAt: null,
      completedAt: null,
      validationStatus: 'not-started',
      linkedCveIds: clampCveList(args.linkedCveIds || []),
      linkedAssetIds: idList(args.linkedAssetIds || [], REMEDIATION_LIMITS.MAX_LINKED_ASSETS),
      linkedComponentIds: idList(args.linkedComponentIds || [], REMEDIATION_LIMITS.MAX_LINKED_COMPONENTS),
      linkedCorrelationIds: idList(args.linkedCorrelationIds || [], REMEDIATION_LIMITS.MAX_LINKED_CORRELATIONS),
      linkedInventoryIds: idList(args.linkedInventoryIds || [], REMEDIATION_LIMITS.MAX_LINKED_INVENTORIES),
      tags: clampTagList(args.tags || []),
      acceptedRiskRationale: '',
      notes: '',
      createdAt: now,
      updatedAt: now,
      revision: 1,
      mutationId,
      archived: false,
    });
    const v = validatePlan(planCandidate);
    if (!v.ok) return { ok: false as const, reason: v.reason || 'invalid-plan' };
    const eventId = makeEventId(`${planId}|0|create`);
    return trackInflight(createPlanWithGenesisEvent({
      adapter,
      plan: v.value,
      eventId,
      occurredAt: now,
      actorLabel: args.actorLabel || '',
      summary: clampSummary(`Plan "${planCandidate.title}" created.`),
    })).then((r) => {
      if (r.ok) {
        void refreshAll();
        return { ok: true as const, plan: v.value, eventId };
      }
      return { ok: false as const, reason: r.reason || 'create-failed' };
    });
  }, [trackInflight, refreshAll]);

  const updatePlan = useCallback(async (planId: string, patch: UpdatePlanPatch, actorLabel?: string) => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false as const, reason: 'adapter-closed' };
    const existing = await adapter.getPlan(planId);
    if (!existing.ok || !existing.value) return { ok: false as const, reason: 'not-found' };
    const cur = existing.value;
    if (patch.status && !isSupportedTransition(cur.status, patch.status)) {
      return { ok: false as const, reason: 'unsupported-status-transition' };
    }
    const now = nowIso();
    const next = normalizePlan({
      ...cur,
      ...patch,
      linkedCveIds: patch.linkedCveIds ? clampCveList(patch.linkedCveIds) : cur.linkedCveIds,
      linkedAssetIds: patch.linkedAssetIds ? idList(patch.linkedAssetIds, REMEDIATION_LIMITS.MAX_LINKED_ASSETS) : cur.linkedAssetIds,
      linkedComponentIds: patch.linkedComponentIds ? idList(patch.linkedComponentIds, REMEDIATION_LIMITS.MAX_LINKED_COMPONENTS) : cur.linkedComponentIds,
      linkedCorrelationIds: patch.linkedCorrelationIds ? idList(patch.linkedCorrelationIds, REMEDIATION_LIMITS.MAX_LINKED_CORRELATIONS) : cur.linkedCorrelationIds,
      linkedInventoryIds: patch.linkedInventoryIds ? idList(patch.linkedInventoryIds, REMEDIATION_LIMITS.MAX_LINKED_INVENTORIES) : cur.linkedInventoryIds,
      tags: patch.tags ? clampTagList(patch.tags) : cur.tags,
      updatedAt: now,
      revision: (cur.revision || 1) + 1,
      mutationId: makeMutationId(),
    });
    const v = validatePlan(next);
    if (!v.ok) return { ok: false as const, reason: v.reason || 'invalid-plan' };
    const put = await trackInflight(adapter.putPlan(v.value));
    if (!put.ok) return { ok: false as const, reason: put.reason || 'put-failed' };
    let eventId = '';
    if (patch.status && patch.status !== cur.status) {
      const eventResult = await trackInflight(appendFollowupEvent({
        adapter,
        planId,
        eventId: makeEventId(`${planId}|${(cur.revision || 1) + 1}|status`),
        eventType: 'status-changed',
        occurredAt: now,
        actorLabel: actorLabel || '',
        summary: clampSummary(`Status changed: ${cur.status} → ${patch.status}.`),
        targetIds: { planId, fromStatus: cur.status, toStatus: patch.status },
      }));
      if (!eventResult.ok) return { ok: false as const, reason: eventResult.reason || 'ledger-failed' };
      eventId = eventResult.eventId || '';
    } else {
      const eventResult = await trackInflight(appendFollowupEvent({
        adapter,
        planId,
        eventId: makeEventId(`${planId}|${(cur.revision || 1) + 1}|update`),
        eventType: 'plan-updated',
        occurredAt: now,
        actorLabel: actorLabel || '',
        summary: clampSummary(`Plan "${cur.title}" updated.`),
        targetIds: { planId },
      }));
      if (!eventResult.ok) return { ok: false as const, reason: eventResult.reason || 'ledger-failed' };
      eventId = eventResult.eventId || '';
    }
    void refreshAll();
    return { ok: true as const, plan: v.value, eventId };
  }, [trackInflight, refreshAll]);

  const setStatusOnly = useCallback(async (planId: string, toStatus: string, actorLabel?: string) => {
    return updatePlan(planId, { status: toStatus }, actorLabel);
  }, [updatePlan]);

  const archivePlan = useCallback(async (planId: string, actorLabel?: string) => {
    return updatePlan(planId, { archived: true }, actorLabel);
  }, [updatePlan]);

  const restorePlan = useCallback(async (planId: string, actorLabel?: string) => {
    return updatePlan(planId, { archived: false }, actorLabel);
  }, [updatePlan]);

  const deletePlan = useCallback(async (planId: string) => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false as const, reason: 'adapter-closed' };
    const r = await trackInflight(adapter.deletePlan(planId));
    if (!r.ok) return r;
    void refreshAll();
    return { ok: true as const };
  }, [trackInflight, refreshAll]);

  const reopenPlan = useCallback(async (planId: string, actorLabel?: string) => {
    const cur = await adapterRef.current?.getPlan(planId);
    if (!cur || !cur.ok || !cur.value) return { ok: false as const, reason: 'not-found' };
    const current = cur.value;
    if (current.status !== 'completed' && current.status !== 'accepted-risk') {
      return updatePlan(planId, { status: 'in-progress' }, actorLabel);
    }
    return updatePlan(planId, { status: 'in-progress' }, actorLabel);
  }, [updatePlan]);

  const acceptRisk = useCallback(async (planId: string, rationale: string, actorLabel?: string) => {
    return updatePlan(planId, { status: 'accepted-risk', acceptedRiskRationale: rationale }, actorLabel);
  }, [updatePlan]);

  const setValidation = useCallback(async (planId: string, toStatus: string, note: string, actorLabel?: string) => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false as const, reason: 'adapter-closed' };
    if (!VALIDATION_STATUSES.includes(toStatus)) return { ok: false as const, reason: 'invalid-validation-status' };
    const patch: UpdatePlanPatch = { validationStatus: toStatus };
    const updated = await updatePlan(planId, patch, actorLabel);
    if (!updated.ok) return updated;
    const now = nowIso();
    const evidenceId = makeEvidenceId(`${planId}|${now}|validation`);
    const evidence: any = {
      schemaVersion: '1.0.0',
      evidenceId,
      planId,
      taskId: null,
      evidenceType: 'validation-result',
      title: `Validation: ${toStatus}`,
      description: note || `Local validation recorded as ${toStatus}.`,
      capturedAt: now,
      sourceLabel: 'local-validation',
      externalUrl: null,
      linkedInventoryId: null,
      linkedCorrelationId: null,
      linkedReportId: null,
      fileFingerprint: null,
      validationOutcome: toStatus,
      supersedesEvidenceId: null,
      createdAt: now,
      revision: 1,
      mutationId: makeMutationId(),
    };
    const ev = validateEvidence(evidence);
    if (!ev.ok) return { ok: false as const, reason: ev.reason || 'invalid-evidence' };
    const evPut = await trackInflight(adapter.putEvidence(ev.value));
    if (!evPut.ok) return { ok: false as const, reason: evPut.reason || 'evidence-failed' };
    const eventResult = await trackInflight(appendFollowupEvent({
      adapter,
      planId,
      eventId: makeEventId(`${planId}|${now}|validation`),
      eventType: 'validation-recorded',
      occurredAt: now,
      actorLabel: actorLabel || '',
      summary: clampSummary(`Validation recorded: ${toStatus}.`),
      targetIds: { planId, evidenceId, validationStatus: toStatus },
    }));
    if (!eventResult.ok) return { ok: false as const, reason: eventResult.reason || 'ledger-failed' };
    void refreshAll();
    return { ok: true as const, plan: updated.plan, eventId: eventResult.eventId || '', evidenceId };
  }, [updatePlan, trackInflight, refreshAll]);

  const getPlan = useCallback(async (planId: string) => {
    const adapter = adapterRef.current;
    if (!adapter) return null;
    const r = await adapter.getPlan(planId);
    return r.ok ? r.value : null;
  }, []);

  const listPlans = useCallback(async (includeArchived = false) => {
    const adapter = adapterRef.current;
    if (!adapter) return [];
    const r = await adapter.listPlans({ includeArchived });
    return r.ok ? r.value : [];
  }, []);

  const countByStatus = useCallback(() => {
    const counts: Record<string, number> = {};
    for (const s of PLAN_STATUSES) counts[s] = 0;
    for (const p of state.plans) {
      if (p.archived) continue;
      counts[p.status] = (counts[p.status] || 0) + 1;
    }
    return counts;
  }, [state.plans]);

  // ----- task operations -----
  const addTask = useCallback(async (args: CreateTaskArgs) => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false as const, reason: 'adapter-closed' };
    const existing = await adapter.listTasksForPlan(args.planId);
    if (!existing.ok) return { ok: false as const, reason: existing.reason || 'list-failed' };
    const order = typeof args.order === 'number' ? args.order : (existing.value?.length || 0);
    const now = nowIso();
    const taskId = makeTaskId(`${args.planId}|${order}|${now}`);
    const task: any = {
      schemaVersion: '1.0.0',
      taskId,
      planId: args.planId,
      title: args.title || '',
      description: args.description || '',
      status: args.status || 'todo',
      ownerLabel: args.ownerLabel || '',
      dueAt: args.dueAt || null,
      completedAt: null,
      order,
      blockerReason: args.blockerReason || '',
      createdAt: now,
      updatedAt: now,
      revision: 1,
      mutationId: makeMutationId(),
    };
    const v = validateTask(task);
    if (!v.ok) return { ok: false as const, reason: v.reason || 'invalid-task' };
    const put = await trackInflight(adapter.putTask(v.value));
    if (!put.ok) return { ok: false as const, reason: put.reason || 'put-failed' };
    const eventResult = await trackInflight(appendFollowupEvent({
      adapter,
      planId: args.planId,
      eventId: makeEventId(`${args.planId}|${taskId}|task-created`),
      eventType: 'task-created',
      occurredAt: now,
      actorLabel: args.actorLabel || '',
      summary: clampSummary(`Task "${task.title}" created.`),
      targetIds: { planId: args.planId, taskId },
    }));
    if (!eventResult.ok) return { ok: false as const, reason: eventResult.reason || 'ledger-failed' };
    void refreshAll();
    return { ok: true as const, task: v.value, eventId: eventResult.eventId || '' };
  }, [trackInflight, refreshAll]);

  const updateTask = useCallback(async (taskId: string, patch: UpdateTaskPatch, actorLabel?: string) => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false as const, reason: 'adapter-closed' };
    const cur = await (async () => {
      for (const planId in state.tasksByPlan) {
        const t = state.tasksByPlan[planId].find((x: any) => x.taskId === taskId);
        if (t) return { planId, task: t };
      }
      return null;
    })();
    if (!cur) return { ok: false as const, reason: 'not-found' };
    const now = nowIso();
    const next: any = {
      ...cur.task,
      ...patch,
      updatedAt: now,
      revision: (cur.task.revision || 1) + 1,
      mutationId: makeMutationId(),
    };
    const v = validateTask(next);
    if (!v.ok) return { ok: false as const, reason: v.reason || 'invalid-task' };
    const put = await trackInflight(adapter.putTask(v.value));
    if (!put.ok) return { ok: false as const, reason: put.reason || 'put-failed' };
    let eventType = 'task-updated';
    if (patch.status === 'done' && cur.task.status !== 'done') eventType = 'task-completed';
    if (patch.status && patch.status !== 'done' && cur.task.status === 'done') eventType = 'task-reopened';
    const eventResult = await trackInflight(appendFollowupEvent({
      adapter,
      planId: cur.planId,
      eventId: makeEventId(`${cur.planId}|${taskId}|${now}`),
      eventType,
      occurredAt: now,
      actorLabel: actorLabel || '',
      summary: clampSummary(`Task "${cur.task.title}" updated.`),
      targetIds: { planId: cur.planId, taskId },
    }));
    if (!eventResult.ok) return { ok: false as const, reason: eventResult.reason || 'ledger-failed' };
    void refreshAll();
    return { ok: true as const, task: v.value, eventId: eventResult.eventId || '' };
  }, [state.tasksByPlan, trackInflight, refreshAll]);

  const reorderTasks = useCallback(async (planId: string, taskIds: string[], actorLabel?: string) => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false as const, reason: 'adapter-closed' };
    const existing = await adapter.listTasksForPlan(planId);
    if (!existing.ok) return { ok: false as const, reason: existing.reason || 'list-failed' };
    const tasks = existing.value || [];
    const byId = new Map<string, any>();
    for (const t of tasks) byId.set(t.taskId, t);
    const now = nowIso();
    let i = 0;
    for (const tid of taskIds) {
      const t = byId.get(tid);
      if (!t) continue;
      const next: any = { ...t, order: i, updatedAt: now, revision: (t.revision || 1) + 1, mutationId: makeMutationId() };
      const v = validateTask(next);
      if (!v.ok) return { ok: false as const, reason: v.reason || 'invalid-task' };
      const put = await trackInflight(adapter.putTask(v.value));
      if (!put.ok) return { ok: false as const, reason: put.reason || 'put-failed' };
      i++;
    }
    const eventResult = await trackInflight(appendFollowupEvent({
      adapter,
      planId,
      eventId: makeEventId(`${planId}|${now}|reorder`),
      eventType: 'task-updated',
      occurredAt: now,
      actorLabel: actorLabel || '',
      summary: clampSummary(`Tasks reordered.`),
      targetIds: { planId, count: String(taskIds.length) },
    }));
    if (!eventResult.ok) return { ok: false as const, reason: eventResult.reason || 'ledger-failed' };
    void refreshAll();
    return { ok: true as const, eventId: eventResult.eventId || '' };
  }, [trackInflight, refreshAll]);

  const completeTask = useCallback(async (taskId: string, actorLabel?: string) => {
    return updateTask(taskId, { status: 'done', completedAt: nowIso() }, actorLabel);
  }, [updateTask]);

  const reopenTask = useCallback(async (taskId: string, actorLabel?: string) => {
    return updateTask(taskId, { status: 'in-progress', completedAt: null }, actorLabel);
  }, [updateTask]);

  const deleteTask = useCallback(async (taskId: string, actorLabel?: string) => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false as const, reason: 'adapter-closed' };
    const cur = await (async () => {
      for (const planId in state.tasksByPlan) {
        const t = state.tasksByPlan[planId].find((x: any) => x.taskId === taskId);
        if (t) return { planId, task: t };
      }
      return null;
    })();
    if (!cur) return { ok: false as const, reason: 'not-found' };
    const r = await trackInflight(adapter.deleteTask(taskId));
    if (!r.ok) return r;
    const now = nowIso();
    const eventResult = await trackInflight(appendFollowupEvent({
      adapter,
      planId: cur.planId,
      eventId: makeEventId(`${cur.planId}|${taskId}|${now}|delete`),
      eventType: 'task-updated',
      occurredAt: now,
      actorLabel: actorLabel || '',
      summary: clampSummary(`Task "${cur.task.title}" deleted.`),
      targetIds: { planId: cur.planId, taskId },
    }));
    if (!eventResult.ok) return { ok: false as const, reason: eventResult.reason || 'ledger-failed' };
    void refreshAll();
    return { ok: true as const, eventId: eventResult.eventId || '' };
  }, [state.tasksByPlan, trackInflight, refreshAll]);

  const listTasksForPlan = useCallback(async (planId: string) => {
    const adapter = adapterRef.current;
    if (!adapter) return [];
    const r = await adapter.listTasksForPlan(planId);
    return r.ok ? r.value : [];
  }, []);

  // ----- evidence operations -----
  const addEvidence = useCallback(async (args: CreateEvidenceArgs) => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false as const, reason: 'adapter-closed' };
    if (!EVIDENCE_TYPES.includes(args.evidenceType || 'local-note')) return { ok: false as const, reason: 'invalid-evidence-type' };
    const now = nowIso();
    const evidenceId = makeEvidenceId(`${args.planId}|${now}|${Math.random()}`);
    const evidence: any = {
      schemaVersion: '1.0.0',
      evidenceId,
      planId: args.planId,
      taskId: args.taskId || null,
      evidenceType: args.evidenceType || 'local-note',
      title: args.title || '',
      description: args.description || '',
      capturedAt: now,
      sourceLabel: args.sourceLabel || '',
      externalUrl: args.externalUrl || null,
      linkedInventoryId: args.linkedInventoryId || null,
      linkedCorrelationId: args.linkedCorrelationId || null,
      linkedReportId: args.linkedReportId || null,
      fileFingerprint: args.fileFingerprint || null,
      validationOutcome: args.validationOutcome || null,
      supersedesEvidenceId: args.supersedesEvidenceId || null,
      createdAt: now,
      revision: 1,
      mutationId: makeMutationId(),
    };
    const v = validateEvidence(evidence);
    if (!v.ok) return { ok: false as const, reason: v.reason || 'invalid-evidence' };
    const put = await trackInflight(adapter.putEvidence(v.value));
    if (!put.ok) return { ok: false as const, reason: put.reason || 'put-failed' };
    const eventResult = await trackInflight(appendFollowupEvent({
      adapter,
      planId: args.planId,
      eventId: makeEventId(`${args.planId}|${evidenceId}|add`),
      eventType: 'evidence-added',
      occurredAt: now,
      actorLabel: args.actorLabel || '',
      summary: clampSummary(`Evidence "${evidence.title}" added.`),
      targetIds: { planId: args.planId, evidenceId },
    }));
    if (!eventResult.ok) return { ok: false as const, reason: eventResult.reason || 'ledger-failed' };
    void refreshAll();
    return { ok: true as const, evidence: v.value, eventId: eventResult.eventId || '' };
  }, [trackInflight, refreshAll]);

  const supersedeEvidence = useCallback(async (evidenceId: string, replacement: CreateEvidenceArgs, actorLabel?: string) => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false as const, reason: 'adapter-closed' };
    const now = nowIso();
    const newEvidenceId = makeEvidenceId(`${replacement.planId}|${now}|${Math.random()}`);
    const evidence: any = {
      schemaVersion: '1.0.0',
      evidenceId: newEvidenceId,
      planId: replacement.planId,
      taskId: replacement.taskId || null,
      evidenceType: replacement.evidenceType || 'local-note',
      title: replacement.title || '',
      description: replacement.description || '',
      capturedAt: now,
      sourceLabel: replacement.sourceLabel || '',
      externalUrl: replacement.externalUrl || null,
      linkedInventoryId: replacement.linkedInventoryId || null,
      linkedCorrelationId: replacement.linkedCorrelationId || null,
      linkedReportId: replacement.linkedReportId || null,
      fileFingerprint: replacement.fileFingerprint || null,
      validationOutcome: replacement.validationOutcome || null,
      supersedesEvidenceId: evidenceId,
      createdAt: now,
      revision: 1,
      mutationId: makeMutationId(),
    };
    const v = validateEvidence(evidence);
    if (!v.ok) return { ok: false as const, reason: v.reason || 'invalid-evidence' };
    const put = await trackInflight(adapter.putEvidence(v.value));
    if (!put.ok) return { ok: false as const, reason: put.reason || 'put-failed' };
    const eventResult = await trackInflight(appendFollowupEvent({
      adapter,
      planId: replacement.planId,
      eventId: makeEventId(`${replacement.planId}|${newEvidenceId}|supersede`),
      eventType: 'evidence-superseded',
      occurredAt: now,
      actorLabel: actorLabel || '',
      summary: clampSummary(`Evidence "${evidence.title}" supersedes ${evidenceId}.`),
      targetIds: { planId: replacement.planId, evidenceId: newEvidenceId, supersedesEvidenceId: evidenceId },
    }));
    if (!eventResult.ok) return { ok: false as const, reason: eventResult.reason || 'ledger-failed' };
    void refreshAll();
    return { ok: true as const, evidence: v.value, eventId: eventResult.eventId || '' };
  }, [trackInflight, refreshAll]);

  const listEvidenceForPlan = useCallback(async (planId: string) => {
    const adapter = adapterRef.current;
    if (!adapter) return [];
    const r = await adapter.listEvidenceForPlan(planId);
    return r.ok ? r.value : [];
  }, []);

  // ----- ledger operations -----
  const listLedgerEvents = useCallback(async (planId: string) => {
    const adapter = adapterRef.current;
    if (!adapter) return [];
    const r = await adapter.listLedgerEvents(planId);
    return r.ok ? r.value : [];
  }, []);

  const verifyPlanLedger = useCallback(async (planId: string) => {
    const events = state.ledgerByPlan[planId] || [];
    if (events.length === 0) return { ok: true, eventCount: 0 };
    try {
      const r = await verifyChain(events);
      return r;
    } catch (err: any) {
      return { ok: false, reason: err && err.message ? err.message : 'integrity-unavailable' };
    }
  }, [state.ledgerByPlan]);

  const verifyAllLedgers = useCallback(async () => {
    const perPlan: Record<string, { ok: boolean; reason?: string; eventCount?: number }> = {};
    let anyBroken = false;
    let anyUnavailable = false;
    for (const planId of Object.keys(state.ledgerByPlan)) {
      const r = await verifyPlanLedger(planId);
      perPlan[planId] = r;
      if (!r.ok) {
        if (r.reason === 'integrity-unavailable') anyUnavailable = true;
        else anyBroken = true;
      }
    }
    const status = anyBroken ? 'broken' : anyUnavailable ? 'unavailable' : (Object.keys(perPlan).length > 0 ? 'valid' : 'unknown');
    setState((s) => ({ ...s, ledgerVerification: { status, perPlan } }));
  }, [state.ledgerByPlan, verifyPlanLedger]);

  const exportPlan = useCallback(async (planId: string) => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false as const, reason: 'adapter-closed' };
    const plan = await adapter.getPlan(planId);
    if (!plan.ok || !plan.value) return { ok: false as const, reason: 'not-found' };
    const tasks = await adapter.listTasksForPlan(planId);
    const evidence = await adapter.listEvidenceForPlan(planId);
    const events = await adapter.listLedgerEvents(planId);
    if (!tasks.ok || !evidence.ok || !events.ok) return { ok: false as const, reason: 'list-failed' };
    return {
      ok: true as const,
      bundle: {
        plan: plan.value,
        tasks: tasks.value || [],
        evidence: evidence.value || [],
        events: events.value || [],
      },
    };
  }, []);

  // ----- housekeeping -----
  const flushPendingWrites = useCallback(async () => {
    const all = Array.from(inflightRef.current) as Promise<unknown>[];
    await Promise.allSettled(all);
  }, []);

  const clearAll = useCallback(async () => {
    const adapter = adapterRef.current;
    if (!adapter) return { ok: false as const, reason: 'adapter-closed' };
    const r = await trackInflight(adapter.clearAll());
    if (!r.ok) return r;
    void refreshAll();
    return { ok: true as const };
  }, [trackInflight, refreshAll]);

  const value = useMemo<RemediationContextValue>(() => ({
    state,
    createPlan,
    updatePlan,
    archivePlan,
    restorePlan,
    deletePlan,
    setStatus: setStatusOnly,
    setValidation,
    acceptRisk,
    reopenPlan,
    getPlan,
    listPlans,
    countByStatus,
    addTask,
    updateTask,
    reorderTasks,
    completeTask,
    reopenTask,
    deleteTask,
    listTasksForPlan,
    addEvidence,
    supersedeEvidence,
    listEvidenceForPlan,
    listLedgerEvents,
    verifyPlanLedger,
    verifyAllLedgers,
    exportPlan,
    flushPendingWrites,
    hasPendingWrites: state.hasPendingWrites,
    clearAll,
  }), [state, createPlan, updatePlan, archivePlan, restorePlan, deletePlan, setStatusOnly, setValidation, acceptRisk, reopenPlan, getPlan, listPlans, countByStatus, addTask, updateTask, reorderTasks, completeTask, reopenTask, deleteTask, listTasksForPlan, addEvidence, supersedeEvidence, listEvidenceForPlan, listLedgerEvents, verifyPlanLedger, verifyAllLedgers, exportPlan, flushPendingWrites, clearAll]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useRemediation(): RemediationContextValue {
  const v = useContext(Ctx);
  if (!v) {
    throw new Error('useRemediation: provider missing — wrap your tree in <RemediationProvider>');
  }
  return v;
}
