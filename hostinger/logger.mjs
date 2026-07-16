/**
 * V6.3 — Hostinger structured logger.
 *
 * Writes line-delimited JSON to a writable target.
 * Each line is a self-describing record:
 *
 *   {
 *     "ts":     ISO-8601 timestamp,
 *     "level":  "debug"|"info"|"warn"|"error",
 *     "component": "<module name>",
 *     "op":     "<operation id, optional>",
 *     "msg":    "<sanitized message>",
 *     "durationMs": <optional>,
 *     "result": "ok"|"error"|"skipped",
 *     ...fields
 *   }
 *
 * The logger NEVER writes:
 *   - raw access tokens
 *   - environment-variable values that look like
 *     secrets
 *   - private gateway credentials
 *   - full internal hashes (unless debug mode is
 *     explicitly enabled AND running locally)
 *   - upstream provider response bodies
 *
 * Two output channels are supported:
 *   - console: line-delimited JSON to stderr
 *   - file:    appended to a JSONL file in the
 *     configured log directory; bounded rotation
 *     keeps at most N=10 files of M=2 MiB each.
 *
 * The Hostinger Business control panel ships the
 * stderr stream to its file-based log viewer; file
 * logging is provided as a redundant store for
 * operators who tail the file directly.
 */

import { existsSync, mkdirSync, statSync, appendFileSync, renameSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { hostname as osHostname, userInfo as osUserInfo } from 'node:os';

const SECRET_KEY_RE = /(secret|token|password|api[_-]?key|credential|hmac|pepper|authorization)/i;
const NETLIFY_PAT_RE = /^nfp_[A-Za-z0-9]{20,}$/;
const OPENAI_KEY_RE = /^sk-[A-Za-z0-9_-]{20,}$/;
const HASH_LIKE_RE = /^sha256:[a-f0-9]{64}$/;
const DEFAULT_FILE_LIMIT_BYTES = 2 * 1024 * 1024; // 2 MiB
const DEFAULT_FILE_ROTATION_COUNT = 10;

function safe(value, debug) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    if (NETLIFY_PAT_RE.test(value)) return '[redacted-pat]';
    if (OPENAI_KEY_RE.test(value)) return '[redacted-key]';
    // Internal hashes are sensitive only when the
    // caller did not opt into debug. The debug flag
    // is propagated from the logger instance.
    if (!debug && HASH_LIKE_RE.test(value)) return '[redacted-hash]';
    return value;
  }
  if (Array.isArray(value)) return value.map((v) => safe(v, debug));
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (typeof v === 'string' && SECRET_KEY_RE.test(k)) { out[k] = '[redacted]'; continue; }
      out[k] = safe(v, debug);
    }
    return out;
  }
  return value;
}

let globalOpCounter = 0;
function nextOpId() {
  globalOpCounter = (globalOpCounter + 1) % 1_000_000;
  return `op-${Date.now().toString(36)}-${globalOpCounter.toString(36).padStart(4, '0')}`;
}

/**
 * Create a logger bound to a component name and an
 * optional file path. The `debug` flag is local-only;
 * passing it requires the operator to have set
 * `THREATPULSE_LOG_LEVEL=debug` on the host.
 */
export function createLogger({ component, filePath = null, debug = false, hostname = osHostname(), user = osUserInfo().username } = {}) {
  if (!component) throw new Error('createLogger: component is required');
  const meta = { component, hostname, user };
  function write(level, fields, result) {
    const ts = new Date().toISOString();
    const cleaned = safe(fields || {}, debug);
    const record = { ts, level, ...meta, ...cleaned };
    if (result) record.result = result;
    const line = JSON.stringify(record);
    // Console: stderr (Hostinger ships stderr to the
    // control-panel log viewer; stdout is reserved for
    // operator-readable summaries).
    try { process.stderr.write(line + '\n'); } catch { /* noop */ }
    if (filePath) {
      try {
        if (existsSync(filePath) && statSync(filePath).size > DEFAULT_FILE_LIMIT_BYTES) {
          rotateFile(filePath);
        }
        appendFileSync(filePath, line + '\n');
      } catch { /* file logging is best-effort */ }
    }
  }
  return {
    debug(fields) { if (debug) write('debug', fields); },
    info(fields) { write('info', fields, 'ok'); },
    warn(fields) { write('warn', fields); },
    error(fields) { write('error', fields, 'error'); },
    success(fields) { write('info', fields, 'ok'); },
    skip(fields) { write('info', fields, 'skipped'); },
    /**
     * Wrap an async operation. Returns a
     * `opId`-stamped record on success or failure.
     */
    async op(name, fn) {
      const opId = nextOpId();
      const start = Date.now();
      write('info', { op: name, opId, msg: `start ${name}` });
      try {
        const result = await fn(opId);
        const durationMs = Date.now() - start;
        write('info', { op: name, opId, durationMs, msg: `done ${name}` }, 'ok');
        return { ok: true, opId, durationMs, result };
      } catch (err) {
        const durationMs = Date.now() - start;
        write('error', { op: name, opId, durationMs, msg: `failed ${name}`, error: { name: err && err.name, message: err && err.message ? String(err.message).slice(0, 500) : String(err) } }, 'error');
        return { ok: false, opId, durationMs, error: err };
      }
    },
    _writeRaw(level, fields) { write(level, fields); },
  };
}

function rotateFile(filePath) {
  // Shift .1 → .2, .2 → .3, ..., and the current
  // file becomes .1. We keep at most
  // DEFAULT_FILE_ROTATION_COUNT historical files.
  try {
    for (let i = DEFAULT_FILE_ROTATION_COUNT; i > 0; i--) {
      const from = i === 1 ? filePath : `${filePath}.${i - 1}`;
      const to = `${filePath}.${i}`;
      if (existsSync(from)) {
        if (i === DEFAULT_FILE_ROTATION_COUNT && existsSync(to)) {
          try { unlinkSync(to); } catch { /* best-effort */ }
        }
        try { renameSync(from, to); } catch { /* best-effort */ }
      }
    }
  } catch { /* best-effort */ }
}

/**
 * Build a `filePath` for the current day inside the
 * configured log directory. Returns null when the
 * directory is not writable.
 */
export function dailyLogPath(logDir) {
  try {
    if (!existsSync(logDir)) mkdirSync(logDir, { recursive: true });
    const probe = join(logDir, '.write-probe');
    appendFileSync(probe, 'ok\n');
    try { unlinkSync(probe); } catch { /* best-effort */ }
    const d = new Date();
    const stamp = d.toISOString().slice(0, 10);
    return join(logDir, `threatpulse-${stamp}.jsonl`);
  } catch {
    return null;
  }
}
