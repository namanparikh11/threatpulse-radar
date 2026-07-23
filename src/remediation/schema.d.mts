/**
 * V6.7 — Remediation schema type declarations.
 */
export const REMEDIATION_PLAN_SCHEMA_VERSION: '1.0.0';
export const REMEDIATION_TASK_SCHEMA_VERSION: '1.0.0';
export const REMEDIATION_EVIDENCE_SCHEMA_VERSION: '1.0.0';
export const REMEDIATION_LEDGER_SCHEMA_VERSION: '1.0.0';

export const PLAN_STATUSES: readonly string[];
export const REMEDIATION_TYPES: readonly string[];
export const LOCAL_PRIORITIES: readonly string[];
export const VALIDATION_STATUSES: readonly string[];
export const TASK_STATUSES: readonly string[];
export const EVIDENCE_TYPES: readonly string[];
export const EVIDENCE_VALIDATION_OUTCOMES: readonly string[];
export const LEDGER_EVENT_TYPES: readonly string[];

export const REMEDIATION_LIMITS: {
  readonly MAX_PLANS: number;
  readonly WARNING_PLAN_COUNT: number;
  readonly MAX_TASKS_PER_PLAN: number;
  readonly MAX_EVIDENCE_PER_PLAN: number;
  readonly MAX_LEDGER_EVENTS_PER_PLAN: number;
  readonly MAX_LEDGER_GAP: number;
  readonly MAX_PLAN_TITLE_CHARS: number;
  readonly MAX_PLAN_DESCRIPTION_CHARS: number;
  readonly MAX_TASK_TITLE_CHARS: number;
  readonly MAX_TASK_DESCRIPTION_CHARS: number;
  readonly MAX_BLOCKER_REASON_CHARS: number;
  readonly MAX_EVIDENCE_TITLE_CHARS: number;
  readonly MAX_EVIDENCE_DESCRIPTION_CHARS: number;
  readonly MAX_SOURCE_LABEL_CHARS: number;
  readonly MAX_OWNER_LABEL_CHARS: number;
  readonly MAX_TAG_CHARS: number;
  readonly MAX_TAGS: number;
  readonly MAX_LINKED_CVES: number;
  readonly MAX_LINKED_ASSETS: number;
  readonly MAX_LINKED_COMPONENTS: number;
  readonly MAX_LINKED_CORRELATIONS: number;
  readonly MAX_LINKED_INVENTORIES: number;
  readonly MAX_LINKED_REPORTS: number;
  readonly MAX_ACTOR_LABEL_CHARS: number;
  readonly MAX_SUMMARY_CHARS: number;
  readonly MAX_RATIONALE_CHARS: number;
  readonly MAX_EXTERNAL_URL_CHARS: number;
  readonly MAX_FILE_FINGERPRINT_BYTES: number;
  readonly MAX_FILE_NAME_CHARS: number;
  readonly MAX_REVISION: number;
};

export interface PlanInput {
  schemaVersion: '1.0.0';
  planId: string;
  title: string;
  description: string;
  status: string;
  remediationType: string;
  localPriority: string;
  ownerLabel: string;
  dueAt: string | null;
  startedAt: string | null;
  completedAt: string | null;
  validationStatus: string;
  linkedCveIds: string[];
  linkedAssetIds: string[];
  linkedComponentIds: string[];
  linkedCorrelationIds: string[];
  linkedInventoryIds: string[];
  tags: string[];
  acceptedRiskRationale: string;
  notes: string;
  createdAt: string;
  updatedAt: string;
  revision: number;
  mutationId: string;
  archived: boolean;
}

export interface TaskInput {
  schemaVersion: '1.0.0';
  taskId: string;
  planId: string;
  title: string;
  description: string;
  status: string;
  ownerLabel: string;
  dueAt: string | null;
  completedAt: string | null;
  order: number;
  blockerReason: string;
  createdAt: string;
  updatedAt: string;
  revision: number;
  mutationId: string;
}

export interface FileFingerprintInput {
  fileName: string;
  sizeBytes: number;
  mimeType: string;
  lastModified: number | null;
  checksum: string;
}

export interface EvidenceInput {
  schemaVersion: '1.0.0';
  evidenceId: string;
  planId: string;
  taskId: string | null;
  evidenceType: string;
  title: string;
  description: string;
  capturedAt: string;
  sourceLabel: string;
  externalUrl: string | null;
  linkedInventoryId: string | null;
  linkedCorrelationId: string | null;
  linkedReportId: string | null;
  fileFingerprint: FileFingerprintInput | null;
  validationOutcome: string | null;
  supersedesEvidenceId: string | null;
  createdAt: string;
  revision: number;
  mutationId: string;
}

export interface LedgerEventInput {
  ledgerSchemaVersion: '1.0.0';
  eventId: string;
  planId: string;
  sequence: number;
  eventType: string;
  occurredAt: string;
  actorLabel: string;
  summary: string;
  targetIds: { [key: string]: string };
  previousEventHash: string | null;
  eventHash: string;
}

export interface ValidationResult {
  ok: boolean;
  value?: any;
  reason?: string;
}

export function validatePlan(input: any): ValidationResult;
export function validateTask(input: any): ValidationResult;
export function validateEvidence(input: any): ValidationResult;
export function validateLedgerEvent(input: any): ValidationResult;
export function normalizeTags(input: unknown): string[];
export function normalizeCveIds(input: unknown): string[];
export function normalizePlan(input: any): PlanInput;
