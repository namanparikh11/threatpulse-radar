#!/usr/bin/env node
// V6.0 — Gateway deployment staging script.
//
// Why this exists:
//   The V6.0 architecture splits deployment into TWO Netlify
//   sites — the public ThreatPulse Radar site (which owns the
//   `tpr-baseline` and `tpr-private-credentials` Blob stores
//   and runs the V5.x and V6.0-publisher functions) and a
//   separate private gateway site (which exposes only the
//   authenticated `/private/v1/*` routes).
//
//   The single source of truth for the gateway function and
//   its required shared modules lives at:
//     netlify/gateway/src/private-sync-gateway.mjs
//     netlify/gateway/src/_shared/credentials.mjs
//     netlify/gateway/src/_shared/baselineStore.mjs
//
//   These files are GATEWAY-OWNED. The public site's
//   `netlify/functions/` directory no longer contains the
//   gateway function or the credentials helper, so the public
//   site does not deploy them. The public site's
//   `netlify/functions/_shared/baselineStore.mjs` is a
//   separate file with only the local-context helpers used
//   by the V6.0 publisher functions.
//
//   This script copies ONLY the gateway-owned files into a
//   deployment-only staging directory inside the gateway
//   subtree. The gateway Netlify site is configured to use
//   that staging directory as its `functions` source, so the
//   site ships a minimal functions bundle with no V5.x or
//   V6.0-publisher code.
//
//   Single source of truth, separate deployment. The
//   acceptance suite (scripts/acceptance-deployment-hardening.mjs)
//   enforces the staging directory's contents and verifies
//   that the public site's `netlify/functions/` no longer
//   contains the gateway function or the credentials helper.
//
//   Usage (Netlify build step on the gateway site):
//     node ../../scripts/copy-gateway-files.mjs
//
//   Usage (operator verification, local):
//     node scripts/copy-gateway-files.mjs
//
// Exit code: 0 on success, 1 on any error (missing source
// file, copy failure, etc.).

import { copyFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');
const gatewayDir = join(repoRoot, 'netlify', 'gateway');
const stagedFnDir = join(gatewayDir, 'functions-staging', 'functions');
const stagedSharedDir = join(stagedFnDir, '_shared');

/**
 * Source-of-truth files copied verbatim into the staging
 * directory. Each entry is [repo-relative-source, staged-relative-destination].
 *
 * Keep this list narrow: the gateway site should ship the
 * smallest possible function surface. Adding to this list
 * should require an explicit reason (a real runtime dep) and
 * a corresponding update to docs/deployment.md.
 *
 * All sources are in `netlify/gateway/src/` (gateway-owned),
 * NOT in the public site's `netlify/functions/`. This is the
 * V6.0 deployment-hardening topology: the public site does
 * not deploy the gateway function.
 */
const FILES_TO_COPY = [
  ['netlify/gateway/src/private-sync-gateway.mjs', 'private-sync-gateway.mjs'],
  ['netlify/gateway/src/_shared/credentials.mjs', '_shared/credentials.mjs'],
  ['netlify/gateway/src/_shared/baselineStore.mjs', '_shared/baselineStore.mjs'],
];

/**
 * Verify the staging directory is fully owned by this script
 * — no stale files left over from a previous run with a
 * different (larger) file set. We wipe `_shared/` and the
 * function root before copying so a removed file does not
 * linger in the deployed bundle.
 */
function cleanStaging() {
  const stagingRoot = join(gatewayDir, 'functions-staging');
  if (existsSync(stagingRoot)) {
    rmSync(stagingRoot, { recursive: true, force: true });
  }
  mkdirSync(stagedFnDir, { recursive: true });
  mkdirSync(stagedSharedDir, { recursive: true });
}

let failures = 0;

function fail(msg) {
  console.error(`ERROR: ${msg}`);
  failures++;
}

cleanStaging();

for (const [srcRel, dstRel] of FILES_TO_COPY) {
  const srcAbs = join(repoRoot, srcRel);
  const dstAbs = join(stagedFnDir, dstRel);
  if (!existsSync(srcAbs)) {
    fail(`source file missing: ${srcRel} (expected at ${srcAbs})`);
    continue;
  }
  try {
    copyFileSync(srcAbs, dstAbs);
    console.log(`  copied ${relative(repoRoot, srcAbs)} -> ${relative(gatewayDir, dstAbs)}`);
  } catch (err) {
    fail(`copy failed for ${srcRel}: ${err && err.message ? err.message : err}`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} failure(s); staging aborted.`);
  process.exit(1);
}

console.log(`\nstaged ${FILES_TO_COPY.length} file(s) into ${relative(repoRoot, stagedFnDir)}`);
console.log('Run scripts/acceptance-deployment-hardening.mjs to verify the staged surface.');
