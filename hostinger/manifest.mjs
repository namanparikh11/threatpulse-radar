#!/usr/bin/env node
/**
 * V6.3 — Hostinger deployment manifest generator.
 *
 * Produces a machine-readable JSON manifest AND a
 * human-readable Markdown checklist of every
 * requirement the operator must satisfy to deploy
 * ThreatPulse Radar on a Hostinger Business
 * managed-hosting plan.
 *
 * The manifest contains:
 *   - required Node version
 *   - start command
 *   - build command
 *   - required environment-variable names
 *     (with defaults and a description)
 *   - optional environment-variable names
 *   - expected persistent data directory
 *   - cron command list (one per job)
 *   - health URL, readiness URL
 *   - backup command, restore dry-run command
 *   - rollback procedure
 *   - unsupported assumptions
 *
 * The output NEVER contains secret values.
 *
 * Usage:
 *   node hostinger/manifest.mjs [--json] [--markdown]
 *   node hostinger/manifest.mjs --out=<dir>
 *
 * Exit codes:
 *   0   manifest generated
 *   1   invalid arguments
 *   4   storage failure
 */

import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

import { resolveHostingerConfig, maskHomePath } from './_lib.mjs';

const MIN_NODE_VERSION = '20.0.0';
const RECOMMENDED_NODE_VERSION = '24.0.0';

function parseArgs(argv) {
  const args = { json: false, markdown: false, out: null };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a === '--markdown') args.markdown = true;
    else if (a.startsWith('--out=')) args.out = a.slice('--out='.length);
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node hostinger/manifest.mjs [--json] [--markdown] [--out=<dir>]');
      process.exit(0);
    } else {
      console.error(`Unknown argument: ${a}`);
      process.exit(1);
    }
  }
  if (!args.json && !args.markdown && !args.out) args.json = args.markdown = true;
  return args;
}

const args = parseArgs(process.argv);
const cfg = resolveHostingerConfig();

// The Hostinger Business cron schedule is once per
// minute; the schedule below is staggered so the
// long-running dataset-publish does not collide
// with the dataset-refresh. Every entry's minute
// field is offset by a non-trivial amount so two
// jobs never start in the same minute.
const cronCommands = [
  { name: 'cron:refresh-dataset',  expression: '0,30 * * * *',  desc: 'public dataset refresh (every 30 minutes on the hour + half-hour)' },
  { name: 'cron:refresh-baseline', expression: '10 * * * *',    desc: 'canonical OSV baseline refresh (hourly at :10)' },
  { name: 'cron:publish-dataset',  expression: '20,50 * * * *', desc: 'dataset-bound public-intelligence publication (every 30m at :20 and :50)' },
  { name: 'cron:gc',               expression: '25 * * * *',    desc: 'public-intelligence garbage collection (hourly at :25)' },
  { name: 'cron:verify-state',     expression: '30 6 * * *',     desc: 'state verification (daily at 06:30)' },
  { name: 'cron:backup',           expression: '40 2 * * *',     desc: 'backup creation (daily at 02:40)' },
];

const requiredEnvVars = [
  {
    name: 'PORT', description: 'Hostinger-assigned public port (mirrored from THREATPULSE_HTTP_PORT).',
    defaultValue: '8787',
  },
  {
    name: 'THREATPULSE_DATA_ROOT', description: 'Absolute path to the persistent data root. MUST be outside the public web root.',
    defaultValue: '$HOME/threatpulse-state',
  },
  {
    name: 'THREATPULSE_PUBLIC_DIR', description: 'Absolute path to the built Vite frontend (the output of `npm run build`).',
    defaultValue: './dist',
  },
  {
    name: 'THREATPULSE_STORAGE_BACKEND', description: 'Must be `filesystem` for the Hostinger runtime.',
    defaultValue: 'filesystem',
  },
];

const optionalEnvVars = [
  { name: 'THREATPULSE_HTTP_HOST',  description: 'Bind host.', defaultValue: '0.0.0.0' },
  { name: 'THREATPULSE_HTTP_PORT',  description: 'Bind port when PORT is not set.', defaultValue: '8787' },
  { name: 'THREATPULSE_LOG_DIR',    description: 'Directory for daily JSONL log files.', defaultValue: '$HOME/threatpulse-logs' },
  { name: 'THREATPULSE_LOCKS_DIR',  description: 'Directory for cron-job lock files.', defaultValue: '$THREATPULSE_DATA_ROOT/locks' },
  { name: 'THREATPULSE_BACKUP_DIR', description: 'Directory for backup archives.', defaultValue: '$HOME/threatpulse-backups' },
  { name: 'THREATPULSE_DRY_RUN',    description: '`1` / `true` to make jobs report only without writing.', defaultValue: '0' },
  { name: 'NODE_ENV',               description: 'Should be `production` for the Hostinger runtime.', defaultValue: 'production' },
];

const unsupportedAssumptions = [
  'An always-on process. Hostinger Business cron jobs run on a schedule; the runtime expects deploy restarts.',
  'Sub-minute cron frequency. Hostinger Business cron is once per minute; the V6.3 schedule is once per 5 minutes minimum.',
  'Log shipping. Operators tail the local file logs or the Hostinger control panel log viewer.',
  'Distributed storage. The filesystem adapter stores all state on a single host.',
  'Root access. The application runs as the Hostinger-assigned user; systemd-style supervision is not available.',
  'Real-time background functions. The Netlify Background Function model is replaced by cron jobs.',
];

const rollbackProcedure = [
  '1. Run `npm run verify:backup -- --archive=<most-recent-archive>` to confirm the previous good state is intact.',
  '2. Run `npm run restore:hostinger -- --archive=<most-recent-archive> --apply --yes` to restore.',
  '3. The Hostinger control panel restarts the application on the next health-check miss; no manual restart is required for a restore.',
  '4. Run `npm run cron:verify-state` to confirm the restored state is recognized.',
];

const manifest = {
  schemaVersion: 'manifest-v1',
  generatedAt: new Date().toISOString(),
  application: {
    name: 'threatpulse-radar',
    minNodeVersion: MIN_NODE_VERSION,
    recommendedNodeVersion: RECOMMENDED_NODE_VERSION,
  },
  build: {
    command: 'npm ci --omit=dev && npm run build',
    outputDir: 'dist',
    nodeModulesStrategy: 'omit-dev',
  },
  start: {
    command: 'npm run start:hostinger',
    equivalentDirect: 'node hostinger/app.mjs',
    env: {
      PORT: 'hostinger-assigned',
      THREATPULSE_DATA_ROOT: cfg.dataRoot,
      THREATPULSE_PUBLIC_DIR: cfg.publicDir,
      THREATPULSE_STORAGE_BACKEND: 'filesystem',
    },
  },
  runtime: {
    dataRoot: maskHomePath(cfg.dataRoot),
    publicDir: maskHomePath(cfg.publicDir),
    logDir: maskHomePath(cfg.logDir),
    locksDir: maskHomePath(cfg.locksDir),
  },
  cron: cronCommands,
  requiredEnvVars,
  optionalEnvVars,
  health: {
    url: 'GET /health',
    ready: 'GET /ready',
  },
  backup: {
    command: 'npm run backup:hostinger',
    verifyCommand: 'npm run verify:backup -- --archive=<path>',
    restoreDryRun: 'npm run restore:hostinger -- --archive=<path>',
    restoreApply: 'npm run restore:hostinger -- --archive=<path> --apply --yes',
    retentionDefault: 7,
  },
  rollback: rollbackProcedure,
  unsupportedAssumptions,
  vpsRecommendedConditions: [
    'Representative dataset refresh > 60s (warn).',
    'Filesystem write throughput < 20 MiB/s (warn).',
    'Heap RSS > 70% of heap limit (warn).',
    'Two or more active warnings (recommend).',
  ],
};

function toMarkdown(m) {
  const lines = [];
  lines.push(`# ThreatPulse Radar — Hostinger Business deployment manifest`);
  lines.push('');
  lines.push(`Generated at ${m.generatedAt}.`);
  lines.push('');
  lines.push(`## Requirements`);
  lines.push('');
  lines.push(`- Node.js >= ${m.application.minNodeVersion} (recommended ${m.application.recommendedNodeVersion}).`);
  lines.push(`- npm (bundled with Node.js).`);
  lines.push(`- Hostinger Business Node.js hosting plan with cron enabled.`);
  lines.push(`- Read+write access to: \`${m.runtime.dataRoot}\`, \`${m.runtime.logDir}\`, \`${m.runtime.locksDir}\`, \`${m.runtime.publicDir}\`.`);
  lines.push('');
  lines.push(`## Build`);
  lines.push('');
  lines.push('```');
  lines.push(m.build.command);
  lines.push('```');
  lines.push('');
  lines.push(`Output: \`${m.build.outputDir}/\`.`);
  lines.push('');
  lines.push(`## Start`);
  lines.push('');
  lines.push('```');
  lines.push(`${m.start.command}    # equivalent: ${m.start.equivalentDirect}`);
  lines.push('```');
  lines.push('');
  lines.push(`Required environment:`);
  for (const v of m.requiredEnvVars) lines.push(`- \`${v.name}\` — ${v.description} (default \`${v.defaultValue}\`)`);
  lines.push('');
  lines.push(`Optional environment:`);
  for (const v of m.optionalEnvVars) lines.push(`- \`${v.name}\` — ${v.description} (default \`${v.defaultValue}\`)`);
  lines.push('');
  lines.push(`## Cron schedule`);
  lines.push('');
  lines.push(`| Expression | Command | Description |`);
  lines.push(`| --- | --- | --- |`);
  for (const c of m.cron) {
    const cmd = `npm run ${c.name}`;
    lines.push(`| \`${c.expression}\` | \`${cmd}\` | ${c.desc} |`);
  }
  lines.push('');
  lines.push(`## Health and readiness`);
  lines.push('');
  lines.push(`- \`${m.health.url}\` — liveness, always 200 when the process is running.`);
  lines.push(`- \`${m.health.ready}\` — readiness, 200 when the data root is verified and a dataset envelope is present.`);
  lines.push('');
  lines.push(`## Backup and restore`);
  lines.push('');
  lines.push(`- Create: \`${m.backup.command}\``);
  lines.push(`- Verify: \`${m.backup.verifyCommand}\``);
  lines.push(`- Restore (dry-run, default): \`${m.backup.restoreDryRun}\``);
  lines.push(`- Restore (apply, requires \`--apply --yes\`): \`${m.backup.restoreApply}\``);
  lines.push(`- Default retention: ${m.backup.retentionDefault} archives (overridable via \`--keep=<n>\` on create).`);
  lines.push('');
  lines.push(`## Rollback procedure`);
  lines.push('');
  for (const s of m.rollback) lines.push(`- ${s}`);
  lines.push('');
  lines.push(`## Unsupported assumptions`);
  lines.push('');
  for (const a of m.unsupportedAssumptions) lines.push(`- ${a}`);
  lines.push('');
  lines.push(`## When a VPS is recommended`);
  lines.push('');
  for (const a of m.vpsRecommendedConditions) lines.push(`- ${a}`);
  lines.push('');
  return lines.join('\n');
}

const args2 = args;
if (args2.out) {
  if (!existsSync(args2.out)) mkdirSync(args2.out, { recursive: true });
  writeFileSync(resolve(args2.out, 'deployment-manifest.json'), JSON.stringify(manifest, null, 2));
  writeFileSync(resolve(args2.out, 'deployment-manifest.md'), toMarkdown(manifest));
  console.log(`manifest written to ${args2.out}/`);
  console.log(`  - deployment-manifest.json`);
  console.log(`  - deployment-manifest.md`);
  process.exit(0);
}

if (args2.json) {
  console.log(JSON.stringify(manifest, null, 2));
  if (!args2.markdown) process.exit(0);
}
if (args2.markdown) {
  console.log(toMarkdown(manifest));
}
process.exit(0);
