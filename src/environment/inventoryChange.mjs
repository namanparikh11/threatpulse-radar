/**
 * V6.6 — Inventory change detector.
 *
 * Compare two inventory snapshots (or two component
 * lists) and return a structured change record. The
 * detector is pure: same inputs always produce the
 * same output.
 *
 * A component is identified by its normalized
 * identity (purl / ecosystem+name+version) so the
 * detector is robust against re-imports that shuffle
 * the raw `componentId` values. When the imported
 * version changes, the detector classifies the
 * change as `versionChanged` (NOT as `removed` +
 * `added`).
 *
 * The detector NEVER claims a removed component was
 * remediated. The summary explicitly says "No
 * longer present in the latest imported inventory".
 */

import { ASSET_LIMITS } from './schema.mjs';

/** Diff two component lists. Returns a structured
 *  `InventoryChange` object. */
export function diffInventories(prevComponents, nextComponents) {
  const prev = Array.isArray(prevComponents) ? prevComponents : [];
  const next = Array.isArray(nextComponents) ? nextComponents : [];
  const prevByKey = new Map();
  const nextByKey = new Map();
  for (const c of prev) {
    const k = identityKey(c);
    if (!k) continue;
    prevByKey.set(k, c);
  }
  for (const c of next) {
    const k = identityKey(c);
    if (!k) continue;
    nextByKey.set(k, c);
  }
  const added = [];
  const removed = [];
  const versionChanged = [];
  const unchanged = [];
  for (const [k, c] of nextByKey) {
    const p = prevByKey.get(k);
    if (!p) {
      added.push(serialize(c));
      continue;
    }
    if ((p.version || null) !== (c.version || null)) {
      versionChanged.push({
        identity: {
          ecosystem: c.normalizedIdentity?.ecosystem || c.ecosystem || null,
          namespace: c.normalizedIdentity?.namespace || c.namespace || null,
          name: c.name,
        },
        previousVersion: p.version || null,
        nextVersion: c.version || null,
      });
    } else {
      unchanged.push(serialize(c));
    }
  }
  for (const [k, c] of prevByKey) {
    if (!nextByKey.has(k)) {
      removed.push(serialize(c));
    }
  }
  added.sort(byIdentityName);
  removed.sort(byIdentityName);
  versionChanged.sort((a, b) => String(a.identity.name).localeCompare(String(b.identity.name)));
  return Object.freeze({
    added: Object.freeze(added),
    removed: Object.freeze(removed),
    versionChanged: Object.freeze(versionChanged),
    unchangedCount: unchanged.length,
    summary: Object.freeze({
      added: added.length,
      removed: removed.length,
      versionChanged: versionChanged.length,
      unchanged: unchanged.length,
    }),
    note: 'A removed component is "No longer present in the latest imported inventory"; absence is not interpreted as remediation.',
  });
}

function identityKey(c) {
  if (!c || typeof c !== 'object') return null;
  const ni = c.normalizedIdentity || {};
  const eco = (ni.ecosystem || c.ecosystem || '').toLowerCase();
  const ns = (ni.namespace || c.namespace || '').toLowerCase();
  const name = (ni.name || c.name || '').toLowerCase();
  if (!eco && !name) return null;
  return [eco, ns, name].join('|');
}

function serialize(c) {
  return {
    name: c.name,
    version: c.version || null,
    ecosystem: c.ecosystem || c.normalizedIdentity?.ecosystem || null,
    namespace: c.namespace || c.normalizedIdentity?.namespace || null,
    packageUrl: c.packageUrl || c.normalizedIdentity?.purl || null,
  };
}

function byIdentityName(a, b) {
  return String(a.name).localeCompare(String(b.name));
}
