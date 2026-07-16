#!/usr/bin/env node
/**
 * V6.3 — Hostinger restore command.
 *
 * Restores a ThreatPulse state archive produced by
 * `npm run backup:hostinger` (or any V6.2 export)
 * into the configured data root.
 *
 * Dry-run by default. The operator must pass
 * `--apply` to actually write. On failure during
 * apply, the previous state is preserved (the
 * V6.2 import already handles this via its
 * staging area).
 *
 * Usage:
 *   node hostinger/restore.mjs --archive=<path> [--dry-run] [--apply]
 *   node hostinger/restore.mjs --archive=<path> --apply --yes
 *
 * Exit codes:
 *   0   dry-run only or successful apply
 *   1   invalid arguments
 *   2   archive missing or unreadable
 *   3   checksum mismatch
 *   4   storage failure
 *   5   refused without --yes confirmation
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, isAbsolute, basename } from 'node:path';
import { existsSync, statSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

import { resolveHostingerConfig, maskHomePath, sanitizeError, isPathInside } from './_lib.mjs';
import { createLogger, dailyLogPath } from './logger.mjs';

function parseArgs(argv) {
  const args = { archive: null, apply: false, dryRun: false, yes: false, json: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--apply') args.apply = true;
    else if (a === '--dry-run') args.dryRun = true;
    else if (a === '--yes') args.yes = true;
    else if (a === '--json') args.json = true;
    else if (a.startsWith('--archive=')) args.archive = a.slice('--archive='.length);
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node hostinger/restore.mjs --archive=<path> [--dry-run|--apply] [--yes] [--json]');
      process.exit(0);
    } else {
      console.error(`Unknown argument: ${a}`);
      process.exit(1);
    }
  }
  if (!args.apply && !args.dryRun) args.dryRun = true; // default dry-run
  return args;
}

const args = parseArgs(process.argv);
const cfg = resolveHostingerConfig();
const logFile = dailyLogPath(cfg.logDir);
const logger = createLogger({ component: 'hostinger.restore', filePath: logFile });

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

// Refuse to restore from an archive that lives
// inside the data root. This protects against an
// operator typo that would target the production
// data path.
if (isPathInside(cfg.dataRoot, archivePath)) {
  console.error('Refusing to restore from an archive inside the data root');
  process.exit(1);
}

if (args.apply && !args.yes) {
  // Destructive operation: require explicit
  // confirmation via --yes. The operator MUST see
  // the target data root printed in red before
  // proceeding.
  console.error('Refusing to apply a restore without --yes. The current data root would be overwritten.');
  console.error(`  data root: ${cfg.dataRoot}`);
  console.error(`  archive:   ${archivePath}`);
  console.error(`Pass --apply --yes to confirm.`);
  process.exit(5);
}

logger.info({ msg: 'restore.start', archive: maskHomePath(archivePath), archiveSize, apply: args.apply, dataRoot: maskHomePath(cfg.dataRoot) });

const v62Args = [
  resolve(root, 'tools/import-threatpulse-state.mjs'),
  `--archive=${archivePath}`,
  `--data-root=${cfg.dataRoot}`,
  `--backend=${cfg.backend}`,
];
if (args.apply) v62Args.push('--apply');

const r = await new Promise((resolveRun) => {
  const proc = spawn('node', v62Args, {
    cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env },
  });
  let out = ''; let err = '';
  proc.stdout.on('data', (d) => { out += d.toString(); });
  proc.stderr.on('data', (d) => { err += d.toString(); });
  proc.on('error', (e) => resolveRun({ code: 1, out, err: err + '\n' + (e && e.message || String(e)) }));
  proc.on('close', (code) => resolveRun({ code, out, err }));
});

logger.info({ msg: 'restore.v62-result', code: r.code });
if (args.json) {
  let parsed = null;
  try { parsed = JSON.parse(r.out); } catch { /* noop */ }
  console.log(JSON.stringify({ dryRun: !args.apply, applied: args.apply, archive: archivePath, archiveSize, v62Result: parsed, v62Code: r.code }, null, 2));
} else {
  console.log(`restore: archive=${archivePath}`);
  console.log(`  applied: ${args.apply}`);
  console.log(`  exit code: ${r.code}`);
  if (r.out.trim()) console.log(`  --- v6.2 importer ---\n${r.out.trim()}`);
}
if (r.code !== 0) {
  // Map V6.2 import exit codes.
  if (r.code === 1) process.exit(3); // checksum mismatch
  if (r.code === 2) process.exit(2); // archive unreadable
  process.exit(4); // storage failure
}
process.exit(0);
