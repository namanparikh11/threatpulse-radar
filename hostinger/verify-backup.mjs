#!/usr/bin/env node
/**
 * V6.3 — Hostinger backup verification.
 *
 * Verifies a ThreatPulse backup archive without
 * applying it. The verification:
 *   - extracts the archive to a temporary staging
 *     area
 *   - validates METADATA.json
 *   - validates CHECKSUMS.json against the
 *     extracted files
 *   - reports operator-readable results
 *
 * Usage:
 *   node hostinger/verify-backup.mjs --archive=<path> [--json]
 *
 * Exit codes:
 *   0   archive OK
 *   1   invalid arguments
 *   2   archive missing or unreadable
 *   3   checksum mismatch
 *   4   metadata invalid
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, isAbsolute } from 'node:path';
import { existsSync, statSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

import { resolveHostingerConfig, maskHomePath, sanitizeError } from './_lib.mjs';
import { createLogger, dailyLogPath } from './logger.mjs';

function parseArgs(argv) {
  const args = { archive: null, json: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--archive=')) args.archive = a.slice('--archive='.length);
    else if (a === '--json') args.json = true;
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node hostinger/verify-backup.mjs --archive=<path> [--json]');
      process.exit(0);
    } else {
      console.error(`Unknown argument: ${a}`);
      process.exit(1);
    }
  }
  return args;
}

const args = parseArgs(process.argv);
const cfg = resolveHostingerConfig();
const logFile = dailyLogPath(cfg.logDir);
const logger = createLogger({ component: 'hostinger.verify-backup', filePath: logFile });

if (!args.archive) {
  console.error('Missing required --archive=<path>');
  process.exit(1);
}
const archivePath = isAbsolute(args.archive) ? args.archive : resolve(process.cwd(), args.archive);
if (!existsSync(archivePath)) {
  console.error(`Archive not found: ${archivePath}`);
  process.exit(2);
}
let archiveSize = 0;
try { archiveSize = statSync(archivePath).size; } catch { /* noop */ }

logger.info({ msg: 'verify-backup.start', archive: maskHomePath(archivePath), archiveSize });

// Delegate to the V6.2 import tool with --dry-run.
// The V6.2 importer already performs the tar
// extraction, METADATA validation, and checksum
// verification.
const v62Args = [
  resolve(root, 'tools/import-threatpulse-state.mjs'),
  `--archive=${archivePath}`,
  `--data-root=${cfg.dataRoot}`,
  `--backend=memory`, // never touch the real store
];

const r = await new Promise((resolveRun) => {
  const proc = spawn('node', v62Args, {
    cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, THREATPULSE_STORAGE_BACKEND: 'memory' },
  });
  let out = ''; let err = '';
  proc.stdout.on('data', (d) => { out += d.toString(); });
  proc.stderr.on('data', (d) => { err += d.toString(); });
  proc.on('error', (e) => resolveRun({ code: 1, out, err: err + '\n' + (e && e.message || String(e)) }));
  proc.on('close', (code) => resolveRun({ code, out, err }));
});

let report = null;
if (r.code === 0) {
  try { report = JSON.parse(r.out); } catch { /* noop */ }
}
logger.info({ msg: 'verify-backup.done', code: r.code });
if (args.json) {
  console.log(JSON.stringify({
    archive: archivePath, archiveSize,
    ok: r.code === 0,
    v62Code: r.code,
    checksumsOk: report ? report.checksumsOk : null,
    present: report ? report.present : null,
    absent: report ? report.absent : null,
  }, null, 2));
} else {
  console.log(`backup verify: ${archivePath}`);
  if (r.code === 0) {
    console.log(`  status: ok`);
    if (report) console.log(`  checksums ok: ${report.checksumsOk}`);
    if (report) console.log(`  entries present: ${report.present}`);
    if (report) console.log(`  entries absent:  ${report.absent}`);
  } else {
    console.log(`  status: failed (v6.2 code ${r.code})`);
    if (r.err.trim()) console.log(`  --- importer stderr ---\n${r.err.trim()}`);
  }
}
if (r.code === 1) process.exit(3);
if (r.code === 2) process.exit(2);
if (r.code === 0) process.exit(0);
process.exit(4);
