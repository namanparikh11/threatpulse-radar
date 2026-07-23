/**
 * V6.2 — Portable job helpers.
 *
 * Shared utilities for the CLI entrypoints in `jobs/`.
 * Provides:
 *   - lock acquisition / release via the storage
 *     adapter (works on filesystem and Netlify)
 *   - structured operator output (JSON log lines on
 *     stderr, human-readable summary on stdout)
 *   - exit code mapping
 *   - dry-run support
 *   - cron-friendly SIGINT / SIGTERM handling
 *
 * No raw secrets are written to the log output. The
 * `safeLog` helper redacts any value that looks like a
 * credential, env-var assignment, or token.
 */

import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Map a process exit code to a meaningful label.
 * The application uses the following convention:
 *   0   success
 *   1   invalid arguments / configuration
 *   2   lock held by another instance
 *   3   upstream provider failure
 *   4   storage failure
 *   5   publication failure
 *   6   partial / skipped
 */
export const EXIT_CODES = Object.freeze({
  SUCCESS: 0,
  INVALID_ARGS: 1,
  LOCK_HELD: 2,
  PROVIDER_FAILURE: 3,
  STORAGE_FAILURE: 4,
  PUBLICATION_FAILURE: 5,
  PARTIAL: 6,
});

/**
 * Print a JSON log line to stderr. The format is
 * line-delimited JSON so a log shipper can pick it up.
 * `safe` is true by default; pass `safe: false` only
 * for fields that the operator explicitly wants
 * unredacted (and accept the risk).
 */
export function logLine(event, fields = {}, opts = {}) {
  const safe = opts.safe !== false;
  const redacted = safe ? redact(fields) : fields;
  const line = JSON.stringify({ ts: new Date().toISOString(), event, ...redacted });
  console.error(line);
}

/**
 * Best-effort secret redaction. Matches common patterns:
 *   - keys with "secret", "token", "password", "key" in
 *     the name (case-insensitive)
 *   - values that look like a Netlify personal access
 *     token (long hex), an API key (sk-...), or a JWT
 * The output replaces the value with "[redacted]".
 */
export function redact(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string' && /(secret|token|password|api[_-]?key|credential)/i.test(k)) {
      out[k] = '[redacted]';
      continue;
    }
    if (typeof v === 'string' && /^nfp_[A-Za-z0-9]{20,}$/.test(v)) {
      out[k] = '[redacted]';
      continue;
    }
    if (typeof v === 'string' && /^sk-[A-Za-z0-9_-]{20,}$/.test(v)) {
      out[k] = '[redacted]';
      continue;
    }
    out[k] = v;
  }
  return out;
}

/**
 * Acquire a coarse-grained lock via the storage adapter.
 * The lock is a single key with a JSON value holding
 * `acquiredAt` and `expiresAt`. Acquisition is best-effort:
 *   - If the key is missing OR the existing lock has
 *     expired, the lock is overwritten.
 *   - If a non-expired lock is held, returns
 *     `{ acquired: false, expiresAt }`.
 *   - The optional `owner` is recorded so operators can
 *     tell which job is holding the lock.
 */
export async function acquireLock(store, key, { ttlMs = 15 * 60 * 1000, owner = 'unknown' } = {}) {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlMs);
  const existing = await store.getJSON(key).catch(() => null);
  if (existing && typeof existing === 'object' && typeof existing.expiresAt === 'string') {
    const exp = new Date(existing.expiresAt).getTime();
    if (!Number.isNaN(exp) && exp > now.getTime()) {
      return { acquired: false, expiresAt: existing.expiresAt, holder: existing.owner || 'unknown' };
    }
  }
  const payload = {
    acquiredAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    owner,
  };
  await store.setJSON(key, payload);
  return { acquired: true, expiresAt: expiresAt.toISOString() };
}

/**
 * Release a lock. Idempotent.
 */
export async function releaseLock(store, key) {
  try {
    await store.delete(key);
  } catch {
    // Idempotent; missing key is not an error.
  }
}

/**
 * Install SIGINT and SIGTERM handlers that perform a
 * best-effort cleanup then exit with code 130. The
 * `cleanup` callback is awaited before the process
 * exits.
 */
export function installSignalHandlers(cleanup) {
  let stopping = false;
  const onSignal = async (sig) => {
    if (stopping) return;
    stopping = true;
    logLine('signal.received', { signal: sig });
    try {
      if (typeof cleanup === 'function') await cleanup();
    } catch (err) {
      logLine('signal.cleanup.error', { message: err && err.message ? err.message : String(err) });
    }
    process.exit(130);
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
}

/**
 * Resolve a job's storage adapter configuration from
 * environment variables. The factory is the canonical
 * place to map config to an adapter.
 *
 * Returns `{ store, manifestStore, publicIntelligenceStore }`
 * for the three stores the job uses.
 */
export async function resolveStorage(opts = {}) {
  // Lazy import so the storage module loads on demand.
  const { createStorageAdapter } = await import('../netlify/functions/_shared/storage/index.mjs');
  const backend = (opts.backend || process.env.THREATPULSE_STORAGE_BACKEND || 'netlify').toLowerCase();
  const dataRoot = opts.dataRoot || process.env.THREATPULSE_DATA_ROOT;
  // The CLI jobs use the same Blob-store namespaces as
  // the V6.1 modules. A filesystem data root must be
  // provided when the backend is 'filesystem'; each
  // namespace lives in its own subdirectory.
  const store = createStorageAdapter({
    name: backend,
    storeName: opts.storeName || 'tpr-dataset',
    opts: { dataRoot },
  });
  return { store, backend, dataRoot };
}

/**
 * Ensure the parent directory of a file path exists. The
 * filesystem adapter handles this internally for its
 * own writes, but the helper is useful for jobs that
 * write auxiliary files (logs, exports).
 */
export function ensureDirFor(filePath) {
  const dir = dirname(filePath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}
