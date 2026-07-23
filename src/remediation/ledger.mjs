/**
 * V6.7 — Append-only activity ledger.
 *
 * Each plan has its own event chain. The chain is
 * append-only under normal operation. A write that
 * fails the integrity check (sequence gap, previous-
 * event-hash mismatch, schema mismatch) is refused by
 * the adapter, and the corresponding plan mutation is
 * rolled back.
 *
 * The hash chain detects:
 *   - modified events (hash mismatch)
 *   - missing events (sequence gap)
 *   - reordered events (previous-hash mismatch)
 *   - inserted events (sequence gap)
 *
 * The hash chain does NOT prove:
 *   - authorship or identity
 *   - a trusted timestamp
 *   - legal authenticity
 *   - that the events were not subsequently rewritten
 *     by an attacker with write access to the same
 *     browser profile
 *
 * The chain is a local tamper-evident audit log. It
 * lets the operator detect a change that happened to
 * their own local store; it does not let anyone else
 * verify anything.
 */

import { canonicalizeToString } from './canonicalize.mjs';
import { sha256Hex, sha256HexBytes, ShaUnavailableError } from './hash.mjs';

const LEDGER_HASH_VERSION = '1.0.0';

/** Compute the event hash for a single event. The
 *  hash is `sha256:` + lowercase hex digest of the
 *  canonical form of the event, computed with the
 *  `eventHash` field stripped.
 *
 *  If `previousEventHash` is null (the genesis
 *  event), it serializes as null in the canonical
 *  form. Subsequent events must carry the previous
 *  event's `eventHash`. */
export async function computeEventHash(event) {
  if (!event || typeof event !== 'object') throw new Error('ledger: event required');
  const stripped = Object.assign({}, event, { eventHash: 'sha256:__pending__' });
  const canonical = canonicalizeToString(stripped);
  return 'sha256:' + (await sha256Hex(canonical));
}

/** Build the genesis event for a plan. The first
 *  event of a chain has `previousEventHash: null`
 *  and `sequence: 0`. */
export function makeGenesisEvent({ planId, eventId, eventType, occurredAt, actorLabel, summary, targetIds }) {
  return {
    ledgerSchemaVersion: LEDGER_HASH_VERSION,
    eventId,
    planId,
    sequence: 0,
    eventType,
    occurredAt,
    actorLabel,
    summary,
    targetIds: targetIds || {},
    previousEventHash: null,
    eventHash: 'sha256:__pending__', // filled by computeEventHash
  };
}

/** Build a follow-up event. The caller is expected
 *  to set `sequence` and `previousEventHash` from
 *  the last persisted event. */
export function makeFollowupEvent({ planId, eventId, sequence, eventType, occurredAt, actorLabel, summary, targetIds, previousEventHash }) {
  return {
    ledgerSchemaVersion: LEDGER_HASH_VERSION,
    eventId,
    planId,
    sequence,
    eventType,
    occurredAt,
    actorLabel,
    summary,
    targetIds: targetIds || {},
    previousEventHash: previousEventHash || null,
    eventHash: 'sha256:__pending__', // filled by computeEventHash
  };
}

/** Verify an array of events forms a valid
 *  contiguous chain. Returns
 *  `{ ok: true, eventCount }` on success or
 *  `{ ok: false, reason, ... }` on failure. The
 *  `reason` strings are stable and machine-readable. */
export async function verifyChain(events) {
  if (!Array.isArray(events)) return { ok: false, reason: 'invalid-events' };
  let prev = null;
  let prevHash = null;
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (!e || typeof e !== 'object') return { ok: false, reason: 'invalid-event', index: i };
    if (e.sequence !== i) return { ok: false, reason: 'sequence-gap', index: i, expected: i, actual: e.sequence };
    if ((e.previousEventHash || null) !== prevHash) {
      return { ok: false, reason: 'previous-hash-mismatch', index: i };
    }
    const expected = await computeEventHash(e);
    if (e.eventHash !== expected) {
      return { ok: false, reason: 'event-hash-mismatch', index: i, expected, actual: e.eventHash };
    }
    prev = e;
    prevHash = e.eventHash;
  }
  return { ok: true, eventCount: events.length };
}

export { ShaUnavailableError };
