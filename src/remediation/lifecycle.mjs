/**
 * V6.7 — Remediation plan lifecycle.
 *
 * Explicit state machine. The previous V6.4 workspace
 * had no state machine; V6.7 plans follow the documented
 * transitions. The state machine is intentionally
 * permissive about re-entering in-progress from blocked
 * (so a temporary blocker can be cleared) and about
 * re-opening a completed plan, but it never silently
 * mutates a completed plan.
 *
 * The state machine does NOT enforce time-based rules.
 * "Overdue" is a derived display state, not a state
 * transition.
 *
 * The state machine NEVER claims authority over the
 * underlying CVE / component. Completion is a local
 * workflow statement, not a security claim.
 */

import { PLAN_STATUSES } from './schema.mjs';

const TRANSITIONS = Object.freeze({
  draft:                Object.freeze(['planned', 'in-progress', 'deferred', 'cancelled']),
  planned:              Object.freeze(['in-progress', 'blocked', 'deferred', 'cancelled', 'draft']),
  'in-progress':        Object.freeze(['blocked', 'validation-pending', 'completed', 'deferred', 'cancelled', 'accepted-risk']),
  blocked:              Object.freeze(['in-progress', 'deferred', 'cancelled', 'draft']),
  'validation-pending': Object.freeze(['in-progress', 'completed', 'failed-locally', 'deferred', 'cancelled', 'accepted-risk']),
  // 'validation-pending' -> 'failed-locally' is intentionally NOT a plan status.
  // Failed validation re-enters 'in-progress' so the operator can update tasks / evidence.
  // We track the failure as a validation status, not a plan status, to keep the
  // state machine small and the user-facing vocabulary honest.
  completed:            Object.freeze(['in-progress', 'accepted-risk']),
  'accepted-risk':      Object.freeze(['in-progress', 'deferred', 'cancelled']),
  deferred:             Object.freeze(['in-progress', 'draft', 'planned', 'cancelled']),
  cancelled:            Object.freeze(['draft', 'planned']),
});

/** Returns true when the transition from
 *  `from` to `to` is supported by the documented
 *  plan state machine. The same status counts as a
 *  no-op and is allowed. */
export function isSupportedTransition(from, to) {
  if (!PLAN_STATUSES.includes(from) || !PLAN_STATUSES.includes(to)) return false;
  if (from === to) return true;
  const next = TRANSITIONS[from];
  return Array.isArray(next) && next.includes(to);
}

/** Returns `{ ok: true }` when the transition is
 *  supported, otherwise `{ ok: false, reason }`. */
export function checkTransition(from, to) {
  if (!isSupportedTransition(from, to)) {
    return { ok: false, reason: 'unsupported-status-transition' };
  }
  return { ok: true };
}

/** True when the target status is a terminal state
 *  for the user-facing workflow (no further actions
 *  are expected). */
export function isTerminalStatus(status) {
  return status === 'completed' || status === 'cancelled' || status === 'accepted-risk';
}

/** True when the target status represents the
 *  plan being open (i.e. the operator is still
 *  working on it). */
export function isActiveStatus(status) {
  return status === 'draft' || status === 'planned' || status === 'in-progress' || status === 'blocked' || status === 'validation-pending' || status === 'deferred';
}

/** Returns the documented transitions from the
 *  given status. Used by the UI to gate buttons. */
export function allowedTransitionsFrom(from) {
  if (!PLAN_STATUSES.includes(from)) return [];
  return Array.isArray(TRANSITIONS[from]) ? TRANSITIONS[from].slice() : [];
}

/** Returns the next-actionable statuses (excludes
 *  the current status). Convenience for the UI. */
export function actionableTransitionsFrom(from) {
  return allowedTransitionsFrom(from).filter((s) => s !== from);
}

/** A set of reason codes returned by the lifecycle
 *  checker. Exported so the adapter can produce
 *  consistent error reasons. */
export const LIFECYCLE_REASONS = Object.freeze({
  UNSUPPORTED: 'unsupported-status-transition',
  INVALID_STATUS: 'invalid-status',
});
