/**
 * V6.7 — Node-side shim for IDBKeyRange.
 *
 * The IndexedDB remediation adapter imports
 * IDBKeyRange so it can pass ranges to .getAll() in
 * tests. In the browser `globalThis.IDBKeyRange` is
 * provided by the runtime; in Node we use a small
 * no-op that exposes the `only()` helper used by the
 * adapter.
 */
export const IDBKeyRange = {
  only(value) {
    if (typeof globalThis.IDBKeyRange !== 'undefined') return globalThis.IDBKeyRange.only(value);
    return { value, __only: true };
  },
};
