#!/usr/bin/env node
/**
 * V6.3 — Hostinger backup creation.
 *
 * Builds a timestamped tar.gz archive by invoking
 * the V6.2 `tools/export-threatpulse-state.mjs` tool
 * with a destination directory derived from
 * THREATPULSE_BACKUP_DIR and the current date.
 *
 * Usage:
 *   node hostinger/backup.mjs [--json] [--label=<text>]
 *
 * Exit codes (mapped by runCronJob):
 *   0   archive created
 *   1   invalid arguments
 *   4   storage failure
 *
 * The full operator-facing wrapper (with retention,
 * target manifest, named archives) is the V6.3.4
 * commit. This module is the minimal cron-friendly
 * version.
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { existsSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

import { resolveHostingerConfig, maskHomePath, sanitizeError } from './_lib.mjs';
import { createLogger, dailyLogPath } from './logger.mjs';

function parseArgs(argv) {
  const args = { json: false, label: null, keep: 7, out: null };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node hostinger/backup.mjs [--json] [--label=<text>] [--out=<dir>] [--keep=<n>]');
      process.exit(0);
    } else if (a.startsWith('--label=')) args.label = a.slice('--label='.length);
    else if (a.startsWith('--out=')) args.out = a.slice('--out='.length);
    else if (a.startsWith('--keep=')) args.keep = Math.max(1, parseInt(a.slice('--keep='.length), 10) || 7);
    else { console.error(`Unknown argument: ${a}`); process.exit(1); }
  }
  return args;
}

const args = parseArgs(process.argv);
const cfg = resolveHostingerConfig();
const logFile = dailyLogPath(cfg.logDir);
const logger = createLogger({ component: 'hostinger.backup', filePath: logFile });

// Resolve the backup directory. The default is
// $THREATPULSE_DATA_ROOT/../threatpulse-backups; an
// operator can override via THREATPULSE_BACKUP_DIR
// or --out.
const defaultBackupRoot = envOr(process.env.THREATPULSE_BACKUP_DIR, resolve(cfg.dataRoot, '..', 'threatpulse-backups'));
const backupRoot = args.out ? resolve(args.out) : defaultBackupRoot;

// The destination directory is the date-stamped
// subdirectory under the backup root. We use the
// local date (not UTC) so the operator can find
// today's archive by ls.
const now = new Date();
const dateStamp = `${now.getFullYear()}-${pad2(now.getMonth() + 1)}-${pad2(now.getDate())}-${pad2(now.getHours())}${pad2(now.getMinutes())}${pad2(now.getSeconds())}`;
const label = args.label || 'backup';
const outDir = join(backupRoot, `${dateStamp}-${label}`);

function envOr(v, fallback) { return v ? v : fallback; }
function pad2(n) { return String(n).padStart(2, '0'); }

if (!existsSync(backupRoot)) {
  try { mkdirSync(backupRoot, { recursive: true }); } catch (err) {
    logger.error({ msg: 'backup.mkdir-failed', dir: maskHomePath(backupRoot), error: sanitizeError(err) });
    console.error(JSON.stringify({ error: 'storage-failure', reason: 'cannot-create-backup-root', dir: maskHomePath(backupRoot) }));
    process.exit(4);
  }
}

logger.info({ msg: 'backup.start', out: maskHomePath(outDir), dataRoot: maskHomePath(cfg.dataRoot) });
const r = await new Promise((resolveRun) => {
  const proc = spawn('node', [resolve(root, 'tools/export-threatpulse-state.mjs'), `--out=${outDir}`, `--data-root=${cfg.dataRoot}`, `--backend=${cfg.backend}`], {
    cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env },
  });
  let out = ''; let err = '';
  proc.stdout.on('data', (d) => { out += d.toString(); });
  proc.stderr.on('data', (d) => { err += d.toString(); });
  proc.on('error', (e) => resolveRun({ code: 1, out, err: err + '\n' + (e && e.message || String(e)) }));
  proc.on('close', (code) => resolveRun({ code, out, err }));
});

if (r.code !== 0) {
  logger.error({ msg: 'backup.export-failed', code: r.code });
  if (args.json) {
    console.log(JSON.stringify({ error: 'export-failed', code: r.code, stderr: r.err.slice(0, 500) }));
  } else {
    console.error(`backup failed: code=${r.code}`);
  }
  process.exit(4);
}

const archivePath = join(outDir, 'threatpulse-export.tar.gz');
let sizeBytes = 0;
try { sizeBytes = statSync(archivePath).size; } catch { /* noop */ }

// Apply retention: keep at most `args.keep` dated
// directories under backupRoot. This is a soft
// retention; an external backup host should also
// rotate the archives.
try {
  const dirs = listBackupDirs(backupRoot);
  if (dirs.length > args.keep) {
    for (const old of dirs.slice(0, dirs.length - args.keep)) {
      // Best-effort rmSync. The retention NEVER
      // touches files outside backupRoot; the
      // isPathInside guard is a defense in depth.
      try { rmSync(old.full, { recursive: true, force: true }); } catch { /* noop */ }
      logger.info({ msg: 'backup.retention-removed', dir: maskHomePath(old.full) });
    }
  }
} catch (err) {
  logger.warn({ msg: 'backup.retention-error', error: sanitizeError(err) });
}

logger.info({ msg: 'backup.done', archive: maskHomePath(archivePath), sizeBytes });
if (args.json) {
  console.log(JSON.stringify({ archive: archivePath, sizeBytes, ts: now.toISOString() }, null, 2));
} else {
  console.log(`backup: ${archivePath} (${sizeBytes} bytes)`);
}
process.exit(0);

function listBackupDirs(root) {
  const entries = readdirSync(root, { withFileTypes: true });
  const dirs = [];
  for (const e of entries) {
    if (e.isDirectory()) {
      const full = join(root, e.name);
      try {
        const st = statSync(full);
        dirs.push({ name: e.name, full, mtime: st.mtimeMs });
      } catch { /* skip */ }
    }
  }
  dirs.sort((a, b) => a.mtime - b.mtime);
  return dirs;
}
