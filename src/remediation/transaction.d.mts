/**
 * V6.7 — Transaction helper type declarations.
 */
import type { PlanInput, LedgerEventInput } from './schema.mjs';

export function createPlanWithGenesisEvent(args: {
  adapter: any;
  plan: PlanInput;
  eventId: string;
  occurredAt?: string;
  actorLabel?: string;
  summary?: string;
}): Promise<{
  ok: boolean;
  planId?: string;
  eventId?: string;
  sequence?: number;
  reason?: string;
  event?: LedgerEventInput;
  planWritten?: boolean;
}>;

export function appendFollowupEvent(args: {
  adapter: any;
  planId: string;
  eventId: string;
  eventType: string;
  occurredAt?: string;
  actorLabel?: string;
  summary?: string;
  targetIds?: { [key: string]: string };
}): Promise<{
  ok: boolean;
  planId?: string;
  eventId?: string;
  sequence?: number;
  reason?: string;
}>;

export const TRANSACTION_REASONS: {
  readonly INVALID: 'invalid-mutation';
  readonly LEDGER_FULL: 'ledger-full';
  readonly MUTATION_STALE: 'mutation-stale';
  readonly LEDGER_CONFLICT: 'ledger-conflict';
  readonly SCHEMA_MISMATCH: 'schema-mismatch';
};
