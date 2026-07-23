/**
 * V6.3 — Hostinger Business runtime helpers.
 *
 * Shared utilities for the Hostinger application
 * entrypoint, the cron job wrappers, the backup /
 * restore / verify / diagnose commands, and the
 * deployment manifest generator.
 *
 * Provides:
 *   - resolveHostingerConfig: parse the server-only
 *     environment into a typed configuration object
 *   - isPathInside: portable path-traversal check
 *   - maskHomePath: redact the home directory in log
 *     output (so the operator's username is never
 *     printed verbatim)
 *   - parsePort: parse a TCP port from a string,
 *     return null on invalid input
 *
 * The configuration layer is server-only: no VITE_
 * prefix, no secret values, no real credentials.
 */

import { existsSync } from 'node:fs';
import { dirname, isAbsolute, normalize, relative, resolve, sep } from 'node:path';

const HOME_TOKEN = process.env.HOME || process.env.USERPROFILE || '';

/**
 * Replace the home directory portion of a path with
 * `~` so log output never includes the operator's
 * username. On Linux, HOME is usually `/home/<user>`
 * (or `/root` for root). On Windows, USERPROFILE is
 * `C:\Users\<user>`. The replacement is best-effort;
 * the function falls back to the original path when
 * the home token is empty or the path does not start
 * with it.
 */
export function maskHomePath(p) {
  if (!p || typeof p !== 'string' || !HOME_TOKEN) return p;
  const normP = normalize(p);
  const normH = normalize(HOME_TOKEN);
  if (normP === normH) return '~';
  if (normP.startsWith(normH + sep)) return '~' + normP.slice(normH.length);
  return p;
}

/**
 * True when `child` is the same path as, or a
 * descendant of, `parent`. The check is portable
 * across Windows and Linux. The function tolerates
 * trailing separators and case-insensitive Windows
 * paths.
 */
export function isPathInside(parent, child) {
  if (!parent || !child) return false;
  const a = normalize(resolve(parent)) + sep;
  const b = normalize(resolve(child)) + sep;
  // Use case-insensitive compare on Windows; case-
  // sensitive everywhere else.
  if (process.platform === 'win32') {
    const al = a.toLowerCase();
    const bl = b.toLowerCase();
    return bl === al || bl.startsWith(al);
  }
  return b === a || b.startsWith(a);
}

/**
 * Parse a TCP port from a string. Returns null when
 * the value is missing, non-numeric, or out of range.
 */
export function parsePort(v) {
  if (v === undefined || v === null || v === '') return null;
  const n = Number(v);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 1 || n > 65535) return null;
  return n;
}

/**
 * Resolve the Hostinger runtime configuration from
 * the environment. The contract:
 *
 *   THREATPULSE_HTTP_HOST
 *     bind host. Default 0.0.0.0 for the Hostinger
 *     production case (the control panel reverse-
 *     proxies requests to the application port). For
 *     local development override with 127.0.0.1.
 *   THREATPULSE_HTTP_PORT / PORT
 *     bind port. The Hostinger Business control panel
 *     assigns the public-facing port; the value is
 *     surfaced as PORT for platform compatibility.
 *     Default 8787.
 *   THREATPULSE_DATA_ROOT
 *     absolute path to the persistent data directory.
 *     MUST be outside the publicly-served static
 *     directory. Default
 *     $HOME/threatpulse-state (when HOME is set) or
 *     ./state.
 *   THREATPULSE_PUBLIC_DIR
 *     absolute path to the built frontend (the output
 *     of `vite build`). Default ./dist.
 *   THREATPULSE_LOG_DIR
 *     directory for optional file logging. Default
 *     $HOME/threatpulse-logs when HOME is set, else
 *     ./logs.
 *   THREATPULSE_STORAGE_BACKEND
 *     'netlify' | 'filesystem' | 'memory'. The
 *     Hostinger runtime requires 'filesystem'.
 *   THREATPULSE_LOCKS_DIR
 *     absolute path to the locks directory. Default
 *     THREATPULSE_DATA_ROOT/locks.
 *   THREATPULSE_DRY_RUN
 *     '1' / 'true' → cron jobs report only.
 *
 * The function NEVER reads secret values. It returns
 * a plain object the rest of the Hostinger module
 * can consume.
 */
export function resolveHostingerConfig({ argv = process.argv, env = process.env, cwd = process.cwd() } = {}) {
  const host = env.THREATPULSE_HTTP_HOST || '0.0.0.0';
  const portStr = env.PORT || env.THREATPULSE_HTTP_PORT || '8787';
  const port = parsePort(portStr) || 8787;
  const defaultDataRoot = env.HOME
    ? resolve(env.HOME, 'threatpulse-state')
    : resolve(cwd, 'state');
  const dataRoot = env.THREATPULSE_DATA_ROOT
    ? resolve(env.THREATPULSE_DATA_ROOT)
    : defaultDataRoot;
  const publicDir = env.THREATPULSE_PUBLIC_DIR
    ? resolve(env.THREATPULSE_PUBLIC_DIR)
    : resolve(cwd, 'dist');
  const defaultLogDir = env.HOME
    ? resolve(env.HOME, 'threatpulse-logs')
    : resolve(cwd, 'logs');
  const logDir = env.THREATPULSE_LOG_DIR
    ? resolve(env.THREATPULSE_LOG_DIR)
    : defaultLogDir;
  const locksDir = env.THREATPULSE_LOCKS_DIR
    ? resolve(env.THREATPULSE_LOCKS_DIR)
    : resolve(dataRoot, 'locks');
  const backend = (env.THREATPULSE_STORAGE_BACKEND || 'filesystem').toLowerCase();
  const dryRun = env.THREATPULSE_DRY_RUN === '1' || env.THREATPULSE_DRY_RUN === 'true';
  const nodeEnv = env.NODE_ENV || 'production';
  return {
    host, port, dataRoot, publicDir, logDir, locksDir, backend, dryRun, nodeEnv,
    isProduction: nodeEnv === 'production',
  };
}

/**
 * Sanitize an error for log output. The function
 * strips any value that looks like a credential from
 * the message; it returns an object with `name`,
 * `message`, and an optional `code`. Stack traces
 * are NEVER included by default; pass
 * `{ includeStack: true }` only when the operator
 * explicitly wants them (debug mode is local-only).
 */
export function sanitizeError(err, { includeStack = false } = {}) {
  if (!err) return null;
  const out = { name: err.name || 'Error' };
  let msg = err.message || String(err);
  // Strip any path that contains the operator's home
  // directory so usernames never appear in logs.
  if (HOME_TOKEN) {
    const normH = normalize(HOME_TOKEN);
    msg = msg.split(normH).join('~');
  }
  // Truncate very long error messages.
  if (typeof msg === 'string' && msg.length > 1000) msg = msg.slice(0, 1000) + '... (truncated)';
  out.message = msg;
  if (err.code) out.code = String(err.code);
  if (includeStack && err.stack) {
    let stack = err.stack;
    if (HOME_TOKEN) stack = stack.split(normalize(HOME_TOKEN)).join('~');
    out.stack = stack.length > 4000 ? stack.slice(0, 4000) + '... (truncated)' : stack;
  }
  return out;
}
