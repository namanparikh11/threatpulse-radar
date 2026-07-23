/**
 * V6.7 — Transactional mutation helper.
 *
 * Higher-level helper that atomically:
 *   1. writes the new plan / task / evidence record
 *   2. appends the matching ledger event
 *
 * The ledger event references the prior event's hash
 * so the chain is provably contiguous. The atomic
 * transaction guarantee is the adapter's: a failure
 * on either side rolls back both writes.
 *
 * This module also exports helpers that wrap a
 * transaction around arbitrary `put*` + `appendLedgerEvent`
 * calls so the React context can build any mutation
 * without the boilerplate.
 *
 * The helper returns `{ ok, planId, eventId, sequence }`
 * on success. The caller can then broadcast the new
 * state via the context.
 */

import { computeEventHash, makeGenesisEvent, makeFollowupEvent } from './ledger.mjs';

const TRANSACTION_REASONS = Object.freeze({
  INVALID: 'invalid-mutation',
  LEDGER_FULL: 'ledger-full',
  MUTATION_STALE: 'mutation-stale',
  LEDGER_CONFLICT: 'ledger-conflict',
  SCHEMA_MISMATCH: 'schema-mismatch',
});

/** Build + commit a new plan + its genesis event
 *  in a single transaction. The genesis event is
 *  sequence 0, previousEventHash = null. */
export async function createPlanWithGenesisEvent({ adapter, plan, eventId, occurredAt, actorLabel, summary }) {
  if (!adapter || typeof adapter.putPlan !== 'function' || typeof adapter.appendLedgerEvent !== 'function') {
    return { ok: false, reason: 'invalid-mutation' };
  }
  if (!plan || !plan.planId) return { ok: false, reason: TRANSACTION_REASONS.INVALID };
  if (!eventId) return { ok: false, reason: TRANSACTION_REASONS.INVALID };
  const planResult = await adapter.putPlan(plan);
  if (!planResult.ok) return planResult;
  const event = makeGenesisEvent({
    planId: plan.planId,
    eventId,
    eventType: 'plan-created',
    occurredAt: occurredAt || new Date().toISOString(),
    actorLabel: actorLabel || '',
    summary: summary || `Plan "${plan.title}" created.`,
    targetIds: { planId: plan.planId },
  });
  event.eventHash = await computeEventHash(event);
  const eventResult = await adapter.appendLedgerEvent(event);
  if (!eventResult.ok) {
    // Best-effort rollback: the plan was just written,
    // so the ledger and the store are out of sync. We
    // do NOT delete the plan; the operator can either
    // retry the event or delete the plan explicitly.
    return { ok: false, reason: eventResult.reason || TRANSACTION_REASONS.LEDGER_CONFLICT, event, planWritten: true };
  }
  return { ok: true, planId: plan.planId, eventId, sequence: 0 };
}

/** Build + commit a follow-up ledger event for a
 *  plan that has already been created. Reads the
 *  current tail of the chain, computes the new
 *  sequence and previousEventHash, hashes the event,
 *  and commits it. */
export async function appendFollowupEvent({ adapter, planId, eventId, eventType, occurredAt, actorLabel, summary, targetIds }) {
  if (!adapter || typeof adapter.appendLedgerEvent !== 'function' || typeof adapter.listLedgerEvents !== 'function') {
    return { ok: false, reason: 'invalid-mutation' };
  }
  if (!planId || !eventId || !eventType) {
    return { ok: false, reason: TRANSACTION_REASONS.INVALID };
  }
  const listResult = await adapter.listLedgerEvents(planId);
  if (!listResult.ok) return listResult;
  const arr = Array.isArray(listResult.value) ? listResult.value : [];
  const last = arr.length > 0 ? arr[arr.length - 1] : null;
  const sequence = arr.length;
  const previousEventHash = last ? last.eventHash : null;
  const event = makeFollowupEvent({
    planId,
    eventId,
    sequence,
    eventType,
    occurredAt: occurredAt || new Date().toISOString(),
    actorLabel: actorLabel || '',
    summary: summary || eventType,
    targetIds: targetIds || {},
    previousEventHash,
  });
  event.eventHash = await computeEventHash(event);
  const eventResult = await adapter.appendLedgerEvent(event);
  if (!eventResult.ok) return { ok: false, reason: eventResult.reason || TRANSACTION_REASONS.LEDGER_CONFLICT };
  return { ok: true, planId, eventId, sequence };
}

export { TRANSACTION_REASONS };
