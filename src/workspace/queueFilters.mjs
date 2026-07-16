/**
 * V6.4 — Local workspace queue filtering and ordering.
 *
 * Pure helpers consumed by the React layer to derive a
 * "local queue" from the public vulnerability list and
 * the workspace entries. The functions never write
 * anywhere; they are deterministic and side-effect free.
 *
 * Local queue filters are an OR-within-section model
 * with the documented presets:
 *   - all-watched       : only entries where watched=true
 *   - needs-review      : triageStatus='unreviewed' OR 'reviewing'
 *   - action-required   : triageStatus='action-required'
 *   - changed-since-review : changedSinceReview=true
 *   - high-or-urgent    : userPriority IN ('high','urgent')
 *   - resolved          : triageStatus='resolved'
 *   - archived          : archived=true
 *
 * Default queue ordering (per the V6.4 spec):
 *   1. urgent local priority
 *   2. action-required
 *   3. changed since review
 *   4. high local priority
 *   5. reviewing
 *   6. unreviewed
 *   7. remaining
 *   8. CVE id ascending
 *
 * The helpers are framework-agnostic on purpose so they
 * can be tested in isolation.
 */

import { classifyChange } from './changeSignature.mjs';

export const QUEUE_FILTERS = Object.freeze([
  { id: 'all-watched',           label: 'All watched' },
  { id: 'needs-review',          label: 'Needs review' },
  { id: 'action-required',       label: 'Action required' },
  { id: 'changed-since-review',  label: 'Changed since review' },
  { id: 'high-or-urgent',        label: 'High / urgent local priority' },
  { id: 'resolved',              label: 'Resolved' },
  { id: 'archived',              label: 'Archived' },
]);

export const DEFAULT_QUEUE_FILTER = 'all-watched';

function safeLower(s) {
  return typeof s === 'string' ? s.toLowerCase() : '';
}

/**
 * Decide whether a single (vuln, entry) pair matches a
 * given queue filter. Returns true for match, false
 * otherwise. The `presentInPublic` parameter is the
 * caller-supplied "this CVE is still in the current
 * public dataset" signal; it is used only by the
 * `changed-since-review` filter (a CVE that has dropped
 * out of the public dataset is never "changed since
 * review" in the live sense, but the queue filter still
 * surfaces it so the operator can archive it).
 */
export function matchesQueueFilter({
  vuln,
  entry,
  filter,
  publicIntelligenceVersion,
  currentChangeSignature,
  presentInPublic,
}) {
  const e = entry || null;
  const filterId = filter || 'all-watched';
  switch (filterId) {
    case 'all-watched':
      return !!(e && e.watched && !e.archived);
    case 'needs-review': {
      if (!e || e.archived) return false;
      return e.triageStatus === 'unreviewed' || e.triageStatus === 'reviewing';
    }
    case 'action-required':
      return !!(e && !e.archived && e.triageStatus === 'action-required');
    case 'changed-since-review': {
      if (!e || e.archived) return false;
      const cls = classifyChange({
        currentVersion: publicIntelligenceVersion,
        currentSignature: currentChangeSignature,
        record: e,
        presentInPublic: !!presentInPublic,
      });
      return cls === 'changed' || cls === 'newly-tracked';
    }
    case 'high-or-urgent': {
      if (!e || e.archived) return false;
      return e.userPriority === 'high' || e.userPriority === 'urgent';
    }
    case 'resolved':
      return !!(e && !e.archived && e.triageStatus === 'resolved');
    case 'archived':
      return !!(e && e.archived);
    default:
      return false;
  }
}

/**
 * Free-text search across the workspace-local fields
 * (CVE id, note, tags) plus the public CVE id (already
 * shared with the entry). The query is matched
 * case-insensitively. The function NEVER logs or
 * transmits the search terms.
 */
export function matchesLocalSearch({ vuln, entry, query }) {
  if (!query) return true;
  const q = safeLower(query).trim();
  if (!q) return true;
  // Always allow matching on the public CVE id — the
  // operator wants to find a row they have already
  // triaged in the public table.
  if (vuln && typeof vuln.cveId === 'string' && safeLower(vuln.cveId).includes(q)) {
    return true;
  }
  if (!entry) return false;
  if (safeLower(entry.cveId).includes(q)) return true;
  if (Array.isArray(entry.tags) && entry.tags.some((t) => safeLower(t).includes(q))) return true;
  if (typeof entry.note === 'string' && safeLower(entry.note).includes(q)) return true;
  return false;
}

/**
 * Build the local queue. Returns an array of { vuln,
 * entry, changeClass } objects, sorted by the documented
 * default queue ordering. The queue is determined by the
 * chosen filter AND a free-text query. The result is a
 * pure function of the inputs.
 */
export function buildLocalQueue({
  vulns,
  entriesByCve,
  filter,
  query,
  publicIntelligenceVersion,
  computeSignature,
}) {
  const out = [];
  const byCve = entriesByCve || {};
  for (const v of vulns || []) {
    if (!v || typeof v.cveId !== 'string') continue;
    const e = byCve[v.cveId] || null;
    const presentInPublic = true;
    const sig = typeof computeSignature === 'function'
      ? computeSignature(v, publicIntelligenceVersion)
      : '';
    const matchesFilter = matchesQueueFilter({
      vuln: v, entry: e, filter,
      publicIntelligenceVersion, currentChangeSignature: sig,
      presentInPublic,
    });
    if (!matchesFilter) continue;
    if (!matchesLocalSearch({ vuln: v, entry: e, query })) continue;
    const changeClass = e
      ? classifyChange({
          currentVersion: publicIntelligenceVersion,
          currentSignature: sig,
          record: e,
          presentInPublic,
        })
      : 'unavailable';
    out.push({ vuln: v, entry: e, changeClass });
  }
  out.sort(compareQueueItems);
  return out;
}

const ORDER_RANK = Object.freeze({
  urgent: 0,
  'action-required': 1,
  'changed-since-review': 2,
  high: 3,
  reviewing: 4,
  unreviewed: 5,
  remaining: 6,
});

function rankFor({ entry, changeClass }) {
  if (entry && entry.userPriority === 'urgent') return ORDER_RANK.urgent;
  if (entry && entry.triageStatus === 'action-required') return ORDER_RANK['action-required'];
  if (changeClass === 'changed' || changeClass === 'newly-tracked') {
    return ORDER_RANK['changed-since-review'];
  }
  if (entry && entry.userPriority === 'high') return ORDER_RANK.high;
  if (entry && entry.triageStatus === 'reviewing') return ORDER_RANK.reviewing;
  if (entry && entry.triageStatus === 'unreviewed') return ORDER_RANK.unreviewed;
  return ORDER_RANK.remaining;
}

export function compareQueueItems(a, b) {
  const ra = rankFor(a);
  const rb = rankFor(b);
  if (ra !== rb) return ra - rb;
  // Tie-breaker: CVE id ascending.
  const ca = a.vuln?.cveId || '';
  const cb = b.vuln?.cveId || '';
  if (ca < cb) return -1;
  if (ca > cb) return 1;
  return 0;
}

/**
 * Build the counts shown in the workspace panel header.
 * Each count is the number of entries that would match
 * the corresponding queue filter (without the query).
 *
 * `total` is the total number of workspace entries
 * (including archived). Other counts exclude archived
 * entries unless the filter is "archived".
 */
export function buildCounts({ vulns, entriesByCve, publicIntelligenceVersion, computeSignature }) {
  const byCve = entriesByCve || {};
  const entries = Object.values(byCve);
  let watched = 0, unreviewed = 0, actionRequired = 0, changed = 0, resolved = 0, archived = 0;
  for (const e of entries) {
    if (e.archived) { archived++; continue; }
    if (e.watched) watched++;
    if (e.triageStatus === 'unreviewed') unreviewed++;
    if (e.triageStatus === 'action-required') actionRequired++;
    if (e.triageStatus === 'resolved') resolved++;
    // changed-since-review: find a matching public vuln
    if (vulns && vulns.length > 0) {
      const v = vulns.find((x) => x.cveId === e.cveId);
      if (v) {
        const sig = typeof computeSignature === 'function'
          ? computeSignature(v, publicIntelligenceVersion)
          : '';
        const cls = classifyChange({
          currentVersion: publicIntelligenceVersion,
          currentSignature: sig,
          record: e,
          presentInPublic: true,
        });
        if (cls === 'changed' || cls === 'newly-tracked') changed++;
      }
    }
  }
  return {
    total: entries.length,
    watched,
    unreviewed,
    actionRequired,
    changedSinceReview: changed,
    resolved,
    archived,
  };
}
