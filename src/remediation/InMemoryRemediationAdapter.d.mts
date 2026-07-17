/**
 * V6.7 — In-memory remediation adapter type
 * declarations.
 */
import type { PlanInput, TaskInput, EvidenceInput, LedgerEventInput } from './schema.mjs';

export class InMemoryRemediationAdapter {
  constructor();
  static isSupported(): boolean;
  static get REASONS(): {
    readonly INVALID: 'invalid-entry';
    readonly NOT_FOUND: 'not-found';
    readonly STALE: 'stale-revision';
    readonly CONFLICT: 'ledger-conflict';
    readonly CLOSED: 'adapter-closed';
    readonly UNKNOWN: 'unknown';
  };
  static get SCHEMA_VERSIONS(): {
    readonly plan: '1.0.0';
    readonly task: '1.0.0';
    readonly evidence: '1.0.0';
    readonly ledger: '1.0.0';
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
  _debugDump(): { plans: string[]; tasks: string[]; evidence: string[]; ledger: [string, number][] };
}
