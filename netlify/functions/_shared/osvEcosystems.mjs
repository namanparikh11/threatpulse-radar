/**
 * V6.0 — OSV ecosystem allowlist loader.
 *
 * The source-controlled file `config/osv-ecosystems.json` is the source of
 * truth for which OSV ecosystems the canonical baseline ingests. An
 * optional server-side environment override
 * (`THREATPULSE_OSV_ECOSYSTEMS`, JSON string with the same shape) may
 * replace the file content without a code deploy.
 *
 * The Blob bootstrap state records the SHA-256 of the resolved config
 * so an operator can see, at a glance, which ecosystems were active
 * when a given version was built. The config hash is computed over the
 * CANONICAL bytes of the config object (see canonicalHash.mjs), so
 * reformatting the file with the same logical content produces the same
 * hash.
 *
 * Schema reference: `schemas/source-registry-v1.schema.json` (used as
 * a model; OSV is one source among potentially many in V7+).
 *
 * IMPORTANT: this loader reads the file via `fs` so it can be used both
 * inside a Netlify function and inside a unit test that runs from the
 * repo root. The test injects a different `fs` and a different
 * `filePath` to exercise the loader against fixture data.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { contentHash } from './canonicalHash.mjs';

export const ECOSYSTEM_CONFIG_FILE = 'config/osv-ecosystems.json';
export const ECOSYSTEM_ENV_VAR = 'THREATPULSE_OSV_ECOSYSTEMS';

/**
 * Resolve the repo root from this file's URL. Used as the default base
 * for the config-file path. Inside a Netlify function the working
 * directory is the function root, not the repo root, so we use
 * `import.meta.url` to walk up to the project root.
 */
function defaultRepoRoot() {
  const here = dirname(fileURLToPath(import.meta.url));
  // netlify/functions/_shared/osvEcosystems.mjs → repo root is three
  // levels up: _shared → functions → netlify → repo.
  return join(here, '..', '..', '..');
}

/**
 * Normalize an ecosystem name for allowlist comparison. OSV ecosystem
 * names are case-sensitive on the wire (e.g. `PyPI` and `crates.io`),
 * so we keep the input verbatim. The allowlist itself uses the same
 * canonical names.
 */
export function normalizeEcosystemName(name) {
  if (typeof name !== 'string') return '';
  return name.trim();
}

/**
 * Parse the JSON env-var override. The env var is a JSON string with
 * the same shape as `config/osv-ecosystems.json`. Returns null if the
 * env var is unset, empty, or malformed.
 */
export function parseEcosystemEnv(envValue) {
  if (typeof envValue !== 'string' || envValue.length === 0) return null;
  let parsed;
  try {
    parsed = JSON.parse(envValue);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object') return null;
  if (!Array.isArray(parsed.ecosystems)) return null;
  // Coerce to a clean shape: schemaVersion string + non-empty ecosystem strings.
  const schemaVersion = typeof parsed.schemaVersion === 'string'
    ? parsed.schemaVersion
    : '1.0.0';
  const ecosystems = parsed.ecosystems
    .map(normalizeEcosystemName)
    .filter((s) => s.length > 0);
  if (ecosystems.length === 0) return null;
  // Deduplicate while preserving order.
  const seen = new Set();
  const dedup = [];
  for (const e of ecosystems) {
    if (!seen.has(e)) { seen.add(e); dedup.push(e); }
  }
  return { schemaVersion, ecosystems: dedup };
}

/**
 * Read and parse the source-controlled config file. Returns null if
 * the file is missing or malformed.
 */
export function readEcosystemFile({ filePath, fsImpl = { readFileSync } } = {}) {
  const path = filePath || join(defaultRepoRoot(), ECOSYSTEM_CONFIG_FILE);
  let raw;
  try {
    raw = fsImpl.readFileSync(path, 'utf8');
  } catch {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object') return null;
  if (!Array.isArray(parsed.ecosystems)) return null;
  const schemaVersion = typeof parsed.schemaVersion === 'string'
    ? parsed.schemaVersion
    : '1.0.0';
  const ecosystems = parsed.ecosystems
    .map(normalizeEcosystemName)
    .filter((s) => s.length > 0);
  if (ecosystems.length === 0) return null;
  const seen = new Set();
  const dedup = [];
  for (const e of ecosystems) {
    if (!seen.has(e)) { seen.add(e); dedup.push(e); }
  }
  return { schemaVersion, ecosystems: dedup, _source: 'file', _path: path };
}

/**
 * Load the active OSV ecosystem config. The env var, when present and
 * well-formed, wins over the file. Returns
 * `{ schemaVersion, ecosystems, configHash, source }`. `source` is
 * `'env' | 'file' | 'default-fallback'` so callers can log which path
 * produced the active config.
 *
 * The default-fallback is a single-ecosystem allowlist (`npm`) used
 * only when the file is missing AND the env var is unset. This keeps
 * the build from blowing up in a malformed local dev environment while
 * still being obviously wrong (one ecosystem) so an operator notices.
 */
export function loadEcosystemConfig({
  env = (typeof process !== 'undefined' && process.env) || {},
  fsImpl,
  filePath,
} = {}) {
  const envValue = env[ECOSYSTEM_ENV_VAR];
  const fromEnv = parseEcosystemEnv(envValue);
  let resolved;
  let source;
  if (fromEnv) {
    resolved = { schemaVersion: fromEnv.schemaVersion, ecosystems: fromEnv.ecosystems };
    source = 'env';
  } else {
    const fromFile = readEcosystemFile({ filePath, fsImpl });
    if (fromFile) {
      resolved = { schemaVersion: fromFile.schemaVersion, ecosystems: fromFile.ecosystems };
      source = 'file';
    } else {
      resolved = { schemaVersion: '1.0.0', ecosystems: ['npm'] };
      source = 'default-fallback';
    }
  }
  return {
    schemaVersion: resolved.schemaVersion,
    ecosystems: resolved.ecosystems,
    configHash: contentHash({ schemaVersion: resolved.schemaVersion, ecosystems: resolved.ecosystems }),
    source,
  };
}

/**
 * Membership test. Returns true if `ecosystem` (a string) is in the
 * resolved allowlist.
 */
export function isAllowedEcosystem(ecosystem, config) {
  if (!config || !Array.isArray(config.ecosystems)) return false;
  const target = normalizeEcosystemName(ecosystem);
  if (!target) return false;
  return config.ecosystems.includes(target);
}

/**
 * Filter a list of ecosystem strings against the allowlist. Preserves
 * input order, drops duplicates, and returns the filtered list.
 */
export function applyAllowlist(ecosystems, config) {
  if (!config || !Array.isArray(config.ecosystems)) return [];
  const allowed = new Set(config.ecosystems);
  const out = [];
  const seen = new Set();
  for (const e of ecosystems) {
    const norm = normalizeEcosystemName(e);
    if (!norm) continue;
    if (!allowed.has(norm)) continue;
    if (seen.has(norm)) continue;
    seen.add(norm);
    out.push(norm);
  }
  return out;
}
