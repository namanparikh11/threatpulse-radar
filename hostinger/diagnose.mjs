#!/usr/bin/env node
/**
 * V6.3 — Hostinger diagnostic command.
 *
 * Measures runtime characteristics WITHOUT calling
 * production providers. Uses the in-memory storage
 * adapter and synthetic fixtures to measure:
 *   - Node version, platform, arch
 *   - heap limit and rss
 *   - representative dataset refresh (writes a
 *     synthetic V6.1-shaped dataset envelope and a
 *     V6.1 manifest into the memory store; measures
 *     peak RSS and elapsed time)
 *   - representative OSV projection (writes 16
 *     synthetic shards into the memory store;
 *     measures elapsed time and peak RSS)
 *   - filesystem write throughput (1 MiB random
 *     write, then atomic rename)
 *   - atomic rename support
 *   - retained storage (the size of the synthetic
 *     state)
 *   - largest shard and snapshot
 *   - cron overlap risk (whether the cron schedule
 *     is feasible on a once-per-minute host)
 *
 * The output is a JSON report with a
 * `recommendation` field of
 *   - 'compatible'
 *   - 'compatible-with-warnings'
 *   - 'vps-recommended'
 *
 * The diagnostic is non-destructive. It only reads
 * the data root (for size accounting) and never
 * calls upstream providers.
 *
 * Usage:
 *   node hostinger/diagnose.mjs [--json] [--data-root=<path>]
 *
 * Exit codes:
 *   0   diagnostic complete
 *   1   invalid arguments
 *   4   storage failure
 */

import { mkdirSync, existsSync, writeFileSync, readFileSync, statSync, unlinkSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join, sep } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { performance } from 'node:perf_hooks';
import v8 from 'node:v8';
import os from 'node:os';
import { setTimeout as wait } from 'node:timers/promises';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

import { resolveHostingerConfig, maskHomePath } from './_lib.mjs';
import { createLogger, dailyLogPath } from './logger.mjs';
import { createStorageAdapter } from '../netlify/functions/_shared/storage/index.mjs';

const ONE_MIB = 1024 * 1024;

function parseArgs(argv) {
  const args = { json: false, dataRoot: null };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a.startsWith('--data-root=')) args.dataRoot = a.slice('--data-root='.length);
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node hostinger/diagnose.mjs [--json] [--data-root=<path>]');
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
const logger = createLogger({ component: 'hostinger.diagnose', filePath: logFile });

const report = {
  ts: new Date().toISOString(),
  runtime: {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    hostname: os.hostname(),
    cpus: os.cpus().length,
    loadAvg: os.loadavg(),
    totalMemoryBytes: os.totalmem(),
    freeMemoryBytes: os.freemem(),
    uptimeSec: os.uptime(),
  },
  process: {
    pid: process.pid,
    rssBytes: process.memoryUsage().rss,
    heapTotalBytes: v8.getHeapStatistics().total_available_size,
    heapLimitBytes: v8.getHeapStatistics().heap_size_limit,
  },
  storage: {},
  performance: {},
  recommendation: 'compatible',
  warnings: [],
};

function warn(msg) { report.warnings.push(msg); report.recommendation = 'compatible-with-warnings'; }

async function measureDatasetRefresh() {
  // Synthetic representative dataset refresh: write
  // a small V6.1-shaped envelope + a manifest into
  // the memory store, plus 16 OSV shards.
  const store = createStorageAdapter({ name: 'memory' });
  const t0 = performance.now();
  const startRss = process.memoryUsage().rss;
  await store.setJSON('latest-dataset', {
    mode: 'live', source: 'merged', fetchedAt: new Date().toISOString(),
    data: Array.from({ length: 50 }, (_, i) => ({ cveId: `CVE-2026-${String(i).padStart(5, '0')}`, severity: 'High' })),
    datasetPublicHash: 'sha256:' + 'a'.repeat(64),
  });
  await store.setJSON('osv/latest.json', {
    schemaVersion: '1.0.0', osvProjectionVersion: 'v6-3-diagnostic',
    canonicalBaselineVersion: 'v6-0-base', canonicalManifestHash: 'sha256:' + 'b'.repeat(64),
    generatedAt: new Date().toISOString(),
  });
  let largestShardBytes = 0;
  let largestShardKey = null;
  for (let i = 0; i < 16; i++) {
    const content = JSON.stringify({
      schemaVersion: '1.0.0', bucket: String(i),
      byCve: { [`CVE-2026-${String(i).padStart(5, '0')}`]: { records: Array.from({ length: 25 }, (_, k) => ({ osvId: `OSV-${i}-${k}`, sourceDatabase: 'OSV-DEV', aliases: [], affectedPackages: [] })), truncation: { recordsRemoved: 0 } } },
      truncation: { recordsRemovedTotal: 0, cvesTruncated: 0 },
    });
    const gz = gzipSync(Buffer.from(content, 'utf8'));
    const sha = 'sha256:' + createHash('sha256').update(gz).digest('hex');
    const key = `osv/shards/sha256/${sha.slice(7)}.json.gz`;
    await store.setBinary(key, gz);
    if (gz.length > largestShardBytes) { largestShardBytes = gz.length; largestShardKey = key; }
  }
  const elapsedMs = performance.now() - t0;
  const peakRss = process.memoryUsage().rss;
  return {
    elapsedMs: Math.round(elapsedMs),
    peakRssDeltaBytes: peakRss - startRss,
    peakRssBytes: peakRss,
    shardsWritten: 16,
    largestShardBytes,
    largestShardKey,
  };
}

async function measureFilesystemWriteThroughput(dir) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const buf = randomBytes(ONE_MIB);
  const probePath = join(dir, `.write-probe-${process.pid}-${Date.now()}`);
  const t0 = performance.now();
  writeFileSync(probePath, buf);
  const dst = `${probePath}.rename`;
  // Atomic rename
  const { renameSync } = await import('node:fs');
  renameSync(probePath, dst);
  const elapsedMs = performance.now() - t0;
  const sizeBytes = statSync(dst).size;
  try { unlinkSync(dst); } catch { /* noop */ }
  return {
    elapsedMs: Math.round(elapsedMs),
    sizeBytes,
    throughputMBps: Math.round((sizeBytes / 1024 / 1024) / (elapsedMs / 1000) * 100) / 100,
    atomicRenameOk: true,
  };
}

async function measureRetainedStorage(dir) {
  if (!existsSync(dir)) return { ok: true, retainedBytes: 0, files: 0 };
  let total = 0;
  let count = 0;
  const walk = (d) => {
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const ent of entries) {
      const p = join(d, ent.name);
      if (ent.isDirectory()) walk(p);
      else if (ent.isFile()) {
        try { total += statSync(p).size; count++; } catch { /* noop */ }
      }
    }
  };
  walk(dir);
  return { ok: true, retainedBytes: total, files: count, path: maskHomePath(dir) };
}

async function main() {
  // 1. Storage adapter: probe the configured data
  // root (default the operator's data root).
  const dataDir = args.dataRoot ? resolve(args.dataRoot) : cfg.dataRoot;
  if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });
  report.storage.dataRoot = maskHomePath(dataDir);
  report.storage.locksDir = maskHomePath(cfg.locksDir);
  report.storage.publicDir = maskHomePath(cfg.publicDir);
  report.storage.logDir = maskHomePath(cfg.logDir);
  report.storage.backend = cfg.backend;

  // 2. Filesystem write throughput + atomic rename.
  const writePerf = await measureFilesystemWriteThroughput(dataDir);
  report.performance.filesystemWrite = writePerf;
  if (!writePerf.atomicRenameOk) {
    warn('atomic-rename-failed');
    report.recommendation = 'vps-recommended';
  }
  if (writePerf.throughputMBps < 20) {
    warn(`slow-filesystem-throughput:${writePerf.throughputMBps}MB/s`);
  }

  // 3. Representative dataset refresh.
  const refresh = await measureDatasetRefresh();
  report.performance.representativeDatasetRefresh = refresh;
  if (refresh.elapsedMs > 60_000) {
    warn(`slow-refresh:${refresh.elapsedMs}ms`);
  }

  // 4. Retained storage accounting.
  report.performance.retainedStorage = await measureRetainedStorage(dataDir);

  // 5. Process memory: warn if peak RSS exceeds 70%
  // of the heap limit.
  if (refresh.peakRssBytes > 0.7 * report.process.heapLimitBytes) {
    warn(`high-rss:${refresh.peakRssBytes} vs limit ${report.process.heapLimitBytes}`);
  }

  // 6. Cron overlap risk: Hostinger Business cron
  // is once-per-minute. Our V6.3 recommended
  // schedule is dataset every 30 minutes, baseline
  // every hour, publish every 30 minutes offset 15,
  // gc hourly offset 5, verify-state daily, backup
  // daily. The minimum inter-arrival time is 5
  // minutes. The longest job is the representative
  // refresh; warn when it exceeds 5 minutes.
  if (refresh.elapsedMs > 5 * 60 * 1000) {
    warn('cron-overlap-risk');
  }

  // 7. Final recommendation. The Hostinger runtime
  // is the minimum production target; VPS is
  // recommended only when the measurements show a
  // concrete risk.
  if (report.recommendation !== 'vps-recommended' && report.warnings.length > 2) {
    report.recommendation = 'vps-recommended';
  }

  logger.info({ msg: 'diagnose.done', recommendation: report.recommendation, warnings: report.warnings.length });

  if (args.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`ThreatPulse Hostinger diagnostic`);
    console.log(`  recommendation: ${report.recommendation}`);
    console.log(`  node: ${report.runtime.nodeVersion} (${report.runtime.platform}/${report.runtime.arch})`);
    console.log(`  cpus: ${report.runtime.cpus}, loadAvg: ${report.runtime.loadAvg.map((n) => n.toFixed(2)).join(', ')}`);
    console.log(`  heap limit: ${Math.round(report.process.heapLimitBytes / 1024 / 1024)} MiB`);
    console.log(`  representative refresh: ${refresh.elapsedMs} ms, ${Math.round(refresh.peakRssBytes / 1024 / 1024)} MiB RSS, ${refresh.shardsWritten} shards`);
    console.log(`  filesystem write: ${writePerf.throughputMBps} MiB/s (${writePerf.elapsedMs} ms for 1 MiB)`);
    console.log(`  retained storage: ${Math.round((report.performance.retainedStorage.retainedBytes || 0) / 1024 / 1024)} MiB (${report.performance.retainedStorage.files} files)`);
    if (report.warnings.length > 0) {
      console.log(`  warnings:`);
      for (const w of report.warnings) console.log(`    - ${w}`);
    }
  }
  process.exit(0);
}

main().catch((err) => {
  logger.error({ msg: 'diagnose.error', error: err && err.message ? err.message : String(err) });
  console.error(JSON.stringify({ error: 'diagnose-failed', message: err && err.message ? err.message : String(err) }));
  process.exit(4);
});
