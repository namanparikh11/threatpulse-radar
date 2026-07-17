/**
 * V6.7 — IndexedDB remediation adapter type
 * declarations.
 */
import type { PlanInput, TaskInput, EvidenceInput, LedgerEventInput } from './schema.mjs';

export class IndexedDBRemediationAdapter {
  constructor(opts?: { dbName?: string; broadcastChannelName?: string });
  static isSupported(): boolean;
  static get REASONS(): {
    readonly BLOCKED: 'indexeddb-blocked';
    readonly QUOTA: 'quota-exceeded';
    readonly TX_ABORTED: 'transaction-aborted';
    readonly NOT_FOUND: 'not-found';
    readonly INVALID: 'invalid-entry';
    readonly STALE: 'stale-revision';
    readonly CONFLICT: 'ledger-conflict';
    readonly UNKNOWN: 'unknown';
    readonly CLOSED: 'adapter-closed';
    readonly NOT_SUPPORTED: 'indexeddb-not-supported';
  };
  open(): Promise<{ ok: boolean; reason?: string }>;
  close(): void;
  on(listener: (event: any) => void): () => void;
  putPlan(plan: PlanInput): Promise<{ ok: boolean; reason?: string }>;
  getPlan(planId: string): Promise<{ ok: boolean; value: PlanInput | null; reason?: string }>;
  listPlans(opts?: { includeArchived?: boolean }): Promise<{ ok: boolean; value: PlanInput[]; reason?: string }>;
  deletePlan(planId: string): Promise<{ ok: boolean; reason?: string }>;
  putTask(task: TaskInput): Promise<{ ok: boolean; reason?: string }>;
  listTasksForPlan(planId: string): Promise<{ ok: boolean; value: TaskInput[]; reason?: string }>;
  deleteTask(taskId: string): Promise<{ ok: boolean; reason?: string }>;
  putEvidence(evidence: EvidenceInput): Promise<{ ok: boolean; reason?: string }>;
  listEvidenceForPlan(planId: string): Promise<{ ok: boolean; value: EvidenceInput[]; reason?: string }>;
  deleteEvidence(evidenceId: string): Promise<{ ok: boolean; reason?: string }>;
  appendLedgerEvent(event: LedgerEventInput): Promise<{ ok: boolean; reason?: string }>;
  listLedgerEvents(planId: string): Promise<{ ok: boolean; value: LedgerEventInput[]; reason?: string }>;
  clearAll(): Promise<{ ok: boolean; reason?: string }>;
}
