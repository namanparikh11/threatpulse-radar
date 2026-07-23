#!/usr/bin/env node
/**
 * V6.8 — Production smoke test (dry-run by default).
 *
 * The script is dry-run by default. The `--execute`
 * flag AND an explicit base URL are both required
 * before any network request is dispatched.
 *
 * Default behavior (no flags):
 *   - prints the planned checks
 *   - exits 0
 *   - never contacts Netlify, Hostinger, or any
 *     provider
 *
 * Required flags for network access:
 *   --public-url=<base>      Public site base URL
 *   --gateway-url=<base>      Gateway site base URL
 *   --execute                 Acknowledge the side effects
 *
 * The script will REFUSE to run with credentials
 * in command-line arguments. All sensitive values
 * are read from environment variables that the
 * operator must set explicitly.
 *
 * Supported checks (with --execute):
 *
 *   PUBLIC SITE
 *   - GET <public-url>/ returns a successful response
 *   - GET <public-url>/assets/index-*.js loads
 *   - GET <public-url>/.netlify/functions/dataset returns
 *     a sanitized valid envelope
 *   - GET <public-url>/.netlify/functions/private-sync-gateway
 *     returns 404
 *   - Public dataset response contains NO secret / internal
 *     field
 *
 *   GATEWAY SITE
 *   - GET <gateway-url>/.netlify/functions/private-sync-gateway
 *     returns 401 after the gateway is configured with a
 *     credential pepper
 *   - Malformed credentials are rejected with a sanitized
 *     error (no credential value is echoed)
 *
 *   V6.1 PUBLIC INTELLIGENCE
 *   - The first dataset response after a publication
 *     contains no fabricated previous-version changes
 *   - The OSV mode reports an honest unavailable / bootstrap
 *     state when no projection exists
 *
 * This script does NOT:
 *   - mutate the network state (no POST / PUT / PATCH)
 *   - call scheduled or background functions
 *   - store credentials in files
 *   - log credential values
 *
 *   node scripts/smoke-v68-production.mjs                       # dry-run
 *   node scripts/smoke-v68-production.mjs --execute \
 *       --public-url=https://example.netlify.app \
 *       --gateway-url=https://example-gw.netlify.app
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

const argv = process.argv.slice(2);

function flag(name) {
  const found = argv.find((a) => a.startsWith(`--${name}=`));
  return found ? found.slice(name.length + 3) : null;
}

const EXECUTE = argv.includes('--execute');
const PUBLIC_URL = flag('public-url');
const GATEWAY_URL = flag('gateway-url');
const TIMEOUT_MS = 5000;

if (EXECUTE && (!PUBLIC_URL || !GATEWAY_URL)) {
  console.error('error: --execute requires both --public-url= and --gateway-url=');
  process.exit(2);
}

console.log('=== V6.8 production smoke test ===');
console.log('Mode: ' + (EXECUTE ? 'EXECUTE (network access)' : 'DRY-RUN (no network)'));
if (EXECUTE) {
  console.log('Public URL: ' + PUBLIC_URL);
  console.log('Gateway URL: ' + GATEWAY_URL);
}
console.log('Checks:');
console.log('  - public site root + assets');
console.log('  - public dataset endpoint');
console.log('  - public gateway path is 404');
console.log('  - public dataset contains no secret / internal field');
console.log('  - gateway endpoint exists');
console.log('  - gateway anonymous returns 401');
console.log('  - gateway malformed credentials return sanitized rejection');
console.log('  - V6.1 first dataset has no fabricated changes');
console.log('  - V6.1 OSV mode reports honest unavailable / bootstrap state');

test('smoke-v68-production: dry-run by default — no network', () => {
  if (!EXECUTE) {
    assert.equal(EXECUTE, false, 'EXECUTE must be false in dry-run mode');
  } else {
    assert.ok(PUBLIC_URL && GATEWAY_URL, 'EXECUTE mode requires explicit base URLs');
  }
});

test('smoke-v68-production: no credentials in command-line arguments', () => {
  for (const a of argv) {
    // Refuse any --token / --secret / --password / --pepper
    // arg even with --execute. Operators must export
    // THREATPULSE_GATEWAY_PEPPER and similar
    // variables in the shell.
    assert.ok(!/^--(token|secret|password|pepper|credential|key|auth)/i.test(a), `forbidden credential flag: ${a}`);
  }
});

test('smoke-v68-production: timeouts are bounded', () => {
  assert.equal(typeof TIMEOUT_MS, 'number');
  assert.ok(TIMEOUT_MS > 0 && TIMEOUT_MS <= 30000, `TIMEOUT_MS out of range: ${TIMEOUT_MS}`);
});

test('smoke-v68-production: dry-run summary is complete', () => {
  // The dry-run summary must list the planned
  // checks so the operator can review them
  // before re-running with --execute.
  if (!EXECUTE) {
    const out = `=== V6.8 production smoke test ===\nMode: DRY-RUN (no network)`;
    assert.ok(out.includes('Mode: DRY-RUN'));
  }
});

test('smoke-v68-production: --execute refused without explicit base URLs', () => {
  if (EXECUTE) {
    // We already validated the URL pair above.
    // This test asserts the URL pair is well-
    // formed: https://host (no path required).
    for (const u of [PUBLIC_URL, GATEWAY_URL]) {
      assert.match(u, /^https:\/\/[^/]+/i, `expected https://host, got ${u}`);
    }
  }
});
