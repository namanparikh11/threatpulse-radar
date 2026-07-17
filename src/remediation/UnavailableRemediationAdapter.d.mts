/**
 * V6.7 — Unavailable remediation adapter type
 * declarations.
 */
export class UnavailableRemediationAdapter {
  static isSupported(): boolean;
  static get REASONS(): { readonly UNAVAILABLE: 'unavailable' };
  open(): Promise<{ ok: boolean; reason?: string }>;
  close(): void;
  on(listener: (event: any) => void): () => void;
  putPlan(plan: any): Promise<{ ok: boolean; reason?: string }>;
  getPlan(planId: string): Promise<{ ok: boolean; value: any; reason?: string }>;
  listPlans(opts?: { includeArchived?: boolean }): Promise<{ ok: boolean; value: any[]; reason?: string }>;
  deletePlan(planId: string): Promise<{ ok: boolean; reason?: string }>;
  putTask(task: any): Promise<{ ok: boolean; reason?: string }>;
  listTasksForPlan(planId: string): Promise<{ ok: boolean; value: any[]; reason?: string }>;
  deleteTask(taskId: string): Promise<{ ok: boolean; reason?: string }>;
  putEvidence(evidence: any): Promise<{ ok: boolean; reason?: string }>;
  listEvidenceForPlan(planId: string): Promise<{ ok: boolean; value: any[]; reason?: string }>;
  deleteEvidence(evidenceId: string): Promise<{ ok: boolean; reason?: string }>;
  appendLedgerEvent(event: any): Promise<{ ok: boolean; reason?: string }>;
  listLedgerEvents(planId: string): Promise<{ ok: boolean; value: any[]; reason?: string }>;
  clearAll(): Promise<{ ok: boolean; reason?: string }>;
}
