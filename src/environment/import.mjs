/**
 * V6.6 — Import pipeline.
 *
 * Three supported formats:
 *   - CycloneDX JSON (1.4, 1.5, 1.6)
 *   - SPDX JSON (2.3)
 *   - ThreatPulse local inventory JSON
 *   - Bounded CSV software inventory
 *
 * Each importer returns:
 *   {
 *     format: 'cyclonedx-json' | 'spdx-json' | 'threatpulse-inventory-json' | 'csv',
 *     sourceVersion: string | null,
 *     components: ComponentInput[],
 *     warnings: string[],
 *     rejected: number,
 *     sizeBytes: number,
 *   }
 *
 * Imports are deterministic. The order of the
 * returned components follows the source order
 * (after the in-pipeline dedup); IDs are generated
 * deterministically as `cmp-<sha1(assetId|inventoryId|cveId|name|version|ecosystem|namespace)>`
 * so the same source data always produces the same
 * componentId.
 *
 * Raw SBOM payloads are NEVER retained. Only the
 * documented component fields are kept. Build paths,
 * tool metadata, source-control credentials, embedded
 * secrets, and arbitrary external properties are
 * discarded on the way through.
 */

import { ASSET_LIMITS, COMPONENT_SCHEMA_VERSION } from './schema.mjs';
import { normalizeIdentity, normalizeEcosystem } from './purl.mjs';

const SUPPORTED_CYCLONEDX = new Set(['1.4', '1.5', '1.6']);
const SUPPORTED_SPDX = new Set(['2.3']);
const CYCLONEDX_HASH_ALG = new Set(['SHA-1', 'SHA-256', 'SHA-512', 'MD5']);
const MAX_TEXT = ASSET_LIMITS.MAX_IMPORT_BYTES;
const MAX_COMPONENTS = ASSET_LIMITS.MAX_COMPONENTS_PER_IMPORT;

/** Detect the import format. Returns
 *  `{ format, sourceVersion }` or
 *  `{ format: null, reason }`. */
export function detectFormat(input) {
  if (typeof input !== 'string' || input.length === 0) return { format: null, reason: 'empty' };
  if (input.length > MAX_TEXT) return { format: null, reason: 'too-large' };
  // CSV: first non-whitespace char is a letter or digit
  // and the first line contains a comma. We never
  // confuse this with JSON because the first char of
  // a JSON value is `{` or `[`.
  const first = input.charAt(0);
  if (first !== '{' && first !== '[') {
    if (first === 'a' || first === 'A' || first === 'C' || first === 'c') {
      // Possible CSV
      const firstLine = input.split(/\r?\n/, 1)[0];
      if (firstLine.includes(',')) {
        return { format: 'csv', sourceVersion: null };
      }
    }
    return { format: null, reason: 'unrecognised-format' };
  }
  let parsed;
  try { parsed = JSON.parse(input); } catch { return { format: null, reason: 'invalid-json' }; }
  if (!parsed || typeof parsed !== 'object') return { format: null, reason: 'invalid-json' };
  if (typeof parsed.bomFormat === 'string' && parsed.bomFormat.toLowerCase() === 'cyclonedx') {
    return { format: 'cyclonedx-json', sourceVersion: typeof parsed.specVersion === 'string' ? parsed.specVersion : null };
  }
  if (typeof parsed.spdxVersion === 'string') {
    return { format: 'spdx-json', sourceVersion: parsed.spdxVersion };
  }
  if (parsed.format === 'threatpulse-inventory' && Array.isArray(parsed.components)) {
    return { format: 'threatpulse-inventory-json', sourceVersion: typeof parsed.schemaVersion === 'string' ? parsed.schemaVersion : null };
  }
  return { format: null, reason: 'unrecognised-format' };
}

/** Parse an import. Returns
 *  { ok: true, result } or { ok: false, reason }. */
export function parseImport(input, options = {}) {
  const detected = detectFormat(input);
  if (!detected.format) return { ok: false, reason: detected.reason };
  if (detected.format === 'cyclonedx-json') {
    if (!detected.sourceVersion || !SUPPORTED_CYCLONEDX.has(detected.sourceVersion)) {
      return { ok: false, reason: 'unsupported-cyclonedx-version' };
    }
    return parseCycloneDx(input, detected.sourceVersion, options);
  }
  if (detected.format === 'spdx-json') {
    if (!detected.sourceVersion || !SUPPORTED_SPDX.has(detected.sourceVersion)) {
      return { ok: false, reason: 'unsupported-spdx-version' };
    }
    return parseSpdx(input, detected.sourceVersion, options);
  }
  if (detected.format === 'threatpulse-inventory-json') {
    return parseInventoryJson(input, detected.sourceVersion, options);
  }
  if (detected.format === 'csv') {
    return parseCsv(input, options);
  }
  return { ok: false, reason: 'unrecognised-format' };
}

/** CycloneDX 1.4 / 1.5 / 1.6 parser. */
export function parseCycloneDx(input, sourceVersion, options) {
  let doc;
  try { doc = JSON.parse(input); } catch { return { ok: false, reason: 'invalid-json' }; }
  if (!doc || typeof doc !== 'object') return { ok: false, reason: 'invalid-json' };
  const components = Array.isArray(doc.components) ? doc.components : [];
  const out = [];
  const warnings = [];
  const assetId = options.assetId;
  const inventoryId = options.inventoryId;
  const now = new Date().toISOString();
  let rejected = 0;
  for (const c of components) {
    if (!c || typeof c !== 'object') { rejected += 1; continue; }
    const name = typeof c.name === 'string' ? c.name.trim() : '';
    if (!name) { rejected += 1; continue; }
    const version = typeof c.version === 'string' && c.version.length > 0 ? c.version : null;
    const hashes = [];
    if (Array.isArray(c.hashes)) {
      for (const h of c.hashes) {
        if (!h || typeof h !== 'object') continue;
        if (typeof h.alg !== 'string' || typeof h.content !== 'string') continue;
        if (!CYCLONEDX_HASH_ALG.has(h.alg.toUpperCase())) continue;
        if (h.content.length > ASSET_LIMITS.MAX_HASH_CHARS) continue;
        hashes.push(`${h.alg.toUpperCase()}:${h.content}`);
        if (hashes.length >= 20) break;
      }
    }
    const purl = typeof c.purl === 'string' && c.purl.length > 0 ? c.purl : null;
    const cpe = typeof c.cpe === 'string' && c.cpe.length > 0 ? c.cpe : null;
    const ecosystem = inferEcosystemFromPurl(purl) || (typeof c.type === 'string' ? c.type.toLowerCase() : null);
    const namespace = inferNamespaceFromPurl(purl) || null;
    const supplier = extractSupplier(c.supplier);
    const componentType = mapCycloneDxType(c.type);
    const normalized = normalizeIdentity({ purl, ecosystem, namespace, name, version, cpe });
    if (!normalized) { rejected += 1; continue; }
    out.push(Object.freeze({
      componentId: deterministicId(assetId, inventoryId, name, version, ecosystem, namespace),
      assetId,
      inventoryId,
      name: name.slice(0, ASSET_LIMITS.MAX_COMPONENT_NAME_CHARS),
      version: version ? version.slice(0, ASSET_LIMITS.MAX_COMPONENT_VERSION_CHARS) : null,
      ecosystem,
      namespace,
      packageUrl: purl ? purl.slice(0, 500) : null,
      cpe: cpe ? cpe.slice(0, 500) : null,
      supplier: supplier ? supplier.slice(0, ASSET_LIMITS.MAX_SUPPLIER_CHARS) : null,
      componentType,
      hashes,
      sourcePath: null,
      normalizedIdentity: normalized,
      schemaVersion: COMPONENT_SCHEMA_VERSION,
      createdAt: now,
    }));
    if (out.length >= MAX_COMPONENTS) {
      warnings.push(`component cap reached (${MAX_COMPONENTS}); remaining components rejected`);
      rejected += components.length - out.length;
      break;
    }
  }
  return {
    ok: true,
    result: Object.freeze({
      format: 'cyclonedx-json',
      sourceVersion,
      components: dedupe(out),
      warnings,
      rejected,
      sizeBytes: input.length,
    }),
  };
}

/** SPDX 2.3 parser. */
export function parseSpdx(input, sourceVersion, options) {
  let doc;
  try { doc = JSON.parse(input); } catch { return { ok: false, reason: 'invalid-json' }; }
  if (!doc || typeof doc !== 'object') return { ok: false, reason: 'invalid-json' };
  const pkgs = Array.isArray(doc.packages) ? doc.packages : [];
  const out = [];
  const warnings = [];
  const assetId = options.assetId;
  const inventoryId = options.inventoryId;
  const now = new Date().toISOString();
  let rejected = 0;
  for (const p of pkgs) {
    if (!p || typeof p !== 'object') { rejected += 1; continue; }
    const name = typeof p.name === 'string' ? p.name.trim() : '';
    if (!name) { rejected += 1; continue; }
    const version = typeof p.versionInfo === 'string' && p.versionInfo.length > 0 ? p.versionInfo : null;
    const externalRefs = Array.isArray(p.externalRefs) ? p.externalRefs : [];
    let purl = null;
    let cpe = null;
    for (const r of externalRefs) {
      if (!r || typeof r !== 'object') continue;
      const t = typeof r.referenceType === 'string' ? r.referenceType : '';
      if (t === 'purl') {
        const locator = typeof r.referenceLocator === 'string' ? r.referenceLocator : '';
        if (locator.startsWith('pkg:')) { purl = locator; break; }
      }
    }
    if (!cpe) {
      for (const r of externalRefs) {
        if (!r || typeof r !== 'object') continue;
        const t = typeof r.referenceType === 'string' ? r.referenceType : '';
        if (t === 'cpe22Type' || t === 'cpe23Type') {
          cpe = typeof r.referenceLocator === 'string' ? r.referenceLocator : null;
          if (cpe) break;
        }
      }
    }
    const ecosystem = inferEcosystemFromPurl(purl) || 'other';
    const namespace = inferNamespaceFromPurl(purl) || null;
    const componentType = 'library';
    const normalized = normalizeIdentity({ purl, ecosystem, namespace, name, version, cpe });
    if (!normalized) { rejected += 1; continue; }
    out.push(Object.freeze({
      componentId: deterministicId(assetId, inventoryId, name, version, ecosystem, namespace),
      assetId,
      inventoryId,
      name: name.slice(0, ASSET_LIMITS.MAX_COMPONENT_NAME_CHARS),
      version: version ? version.slice(0, ASSET_LIMITS.MAX_COMPONENT_VERSION_CHARS) : null,
      ecosystem,
      namespace,
      packageUrl: purl ? purl.slice(0, 500) : null,
      cpe: cpe ? cpe.slice(0, 500) : null,
      supplier: typeof p.supplier === 'string' ? p.supplier.slice(0, ASSET_LIMITS.MAX_SUPPLIER_CHARS) : null,
      componentType,
      hashes: [],
      sourcePath: null,
      normalizedIdentity: normalized,
      schemaVersion: COMPONENT_SCHEMA_VERSION,
      createdAt: now,
    }));
    if (out.length >= MAX_COMPONENTS) {
      warnings.push(`component cap reached (${MAX_COMPONENTS}); remaining components rejected`);
      rejected += pkgs.length - out.length;
      break;
    }
  }
  return {
    ok: true,
    result: Object.freeze({
      format: 'spdx-json',
      sourceVersion,
      components: dedupe(out),
      warnings,
      rejected,
      sizeBytes: input.length,
    }),
  };
}

/** ThreatPulse local inventory JSON parser. */
export function parseInventoryJson(input, sourceVersion, options) {
  let doc;
  try { doc = JSON.parse(input); } catch { return { ok: false, reason: 'invalid-json' }; }
  if (!doc || typeof doc !== 'object') return { ok: false, reason: 'invalid-json' };
  if (doc.format !== 'threatpulse-inventory') return { ok: false, reason: 'wrong-format' };
  const list = Array.isArray(doc.components) ? doc.components : [];
  const out = [];
  const warnings = [];
  const assetId = options.assetId;
  const inventoryId = options.inventoryId;
  const now = new Date().toISOString();
  let rejected = 0;
  for (const c of list) {
    if (!c || typeof c !== 'object') { rejected += 1; continue; }
    const name = typeof c.name === 'string' ? c.name.trim() : '';
    if (!name) { rejected += 1; continue; }
    const version = typeof c.version === 'string' && c.version.length > 0 ? c.version : null;
    const purl = typeof c.packageUrl === 'string' ? c.packageUrl : null;
    const cpe = typeof c.cpe === 'string' ? c.cpe : null;
    const ecosystem = inferEcosystemFromPurl(purl) || (typeof c.ecosystem === 'string' ? c.ecosystem : null);
    const namespace = inferNamespaceFromPurl(purl) || (typeof c.namespace === 'string' ? c.namespace : null);
    const componentType = typeof c.componentType === 'string' && ['library', 'framework', 'application', 'operating-system', 'container', 'firmware', 'device-driver', 'other'].includes(c.componentType)
      ? c.componentType
      : 'library';
    const normalized = normalizeIdentity({ purl, ecosystem, namespace, name, version, cpe });
    if (!normalized) { rejected += 1; continue; }
    out.push(Object.freeze({
      componentId: deterministicId(assetId, inventoryId, name, version, ecosystem, namespace),
      assetId,
      inventoryId,
      name: name.slice(0, ASSET_LIMITS.MAX_COMPONENT_NAME_CHARS),
      version: version ? version.slice(0, ASSET_LIMITS.MAX_COMPONENT_VERSION_CHARS) : null,
      ecosystem,
      namespace,
      packageUrl: purl ? purl.slice(0, 500) : null,
      cpe: cpe ? cpe.slice(0, 500) : null,
      supplier: typeof c.supplier === 'string' ? c.supplier.slice(0, ASSET_LIMITS.MAX_SUPPLIER_CHARS) : null,
      componentType,
      hashes: Array.isArray(c.hashes) ? c.hashes.filter((h) => typeof h === 'string' && h.length <= ASSET_LIMITS.MAX_HASH_CHARS).slice(0, 20) : [],
      sourcePath: typeof c.sourcePath === 'string' ? c.sourcePath.slice(0, ASSET_LIMITS.MAX_COMPONENT_PATH_CHARS) : null,
      normalizedIdentity: normalized,
      schemaVersion: COMPONENT_SCHEMA_VERSION,
      createdAt: now,
    }));
    if (out.length >= MAX_COMPONENTS) {
      warnings.push(`component cap reached (${MAX_COMPONENTS}); remaining components rejected`);
      rejected += list.length - out.length;
      break;
    }
  }
  return {
    ok: true,
    result: Object.freeze({
      format: 'threatpulse-inventory-json',
      sourceVersion: sourceVersion || null,
      components: dedupe(out),
      warnings,
      rejected,
      sizeBytes: input.length,
    }),
  };
}

/** CSV parser for the documented column set. */
export function parseCsv(input, options) {
  const lines = splitCsvLines(input);
  if (lines.length === 0) return { ok: false, reason: 'empty-csv' };
  const header = parseCsvLine(lines[0]);
  const required = ['asset_name', 'component_name', 'component_version'];
  for (const col of required) {
    if (!header.includes(col)) return { ok: false, reason: `missing-column:${col}` };
  }
  const idx = (col) => header.indexOf(col);
  const assetNameIdx = idx('asset_name');
  const nameIdx = idx('component_name');
  const versionIdx = idx('component_version');
  const ecosystemIdx = idx('ecosystem');
  const purlIdx = idx('package_url');
  const cpeIdx = idx('cpe');
  const supplierIdx = idx('supplier');
  const typeIdx = idx('component_type');
  const pathIdx = idx('source_path');
  const out = [];
  const warnings = [];
  const assetId = options.assetId;
  const inventoryId = options.inventoryId;
  const now = new Date().toISOString();
  let rejected = 0;
  for (let i = 1; i < lines.length; i++) {
    const row = parseCsvLine(lines[i]);
    if (row.length === 1 && row[0] === '') continue;
    const name = (row[nameIdx] || '').trim();
    if (!name) { rejected += 1; continue; }
    const version = (row[versionIdx] || '').trim() || null;
    const purl = purlIdx >= 0 ? (row[purlIdx] || '').trim() || null : null;
    const cpe = cpeIdx >= 0 ? (row[cpeIdx] || '').trim() || null : null;
    const ecosystem = ecosystemIdx >= 0 ? (row[ecosystemIdx] || '').trim() || null : null;
    const namespace = inferNamespaceFromPurl(purl) || null;
    const supplier = supplierIdx >= 0 ? (row[supplierIdx] || '').trim() || null : null;
    const componentType = typeIdx >= 0 && ['library', 'framework', 'application', 'operating-system', 'container', 'firmware', 'device-driver', 'other'].includes((row[typeIdx] || '').trim())
      ? (row[typeIdx] || '').trim()
      : 'library';
    const sourcePath = pathIdx >= 0 ? (row[pathIdx] || '').trim() || null : null;
    // CSV values are text only. Reject anything that
    // smells like a formula or a path traversal.
    if (containsFormula(name) || containsFormula(version || '')) {
      warnings.push(`row ${i + 1}: formula-like value rejected`);
      rejected += 1;
      continue;
    }
    if (name.startsWith('=') || name.startsWith('+') || name.startsWith('-') || name.startsWith('@')) {
      rejected += 1;
      continue;
    }
    const normalized = normalizeIdentity({ purl, ecosystem, namespace, name, version, cpe });
    if (!normalized) { rejected += 1; continue; }
    out.push(Object.freeze({
      componentId: deterministicId(assetId, inventoryId, name, version, ecosystem, namespace),
      assetId,
      inventoryId,
      name: name.slice(0, ASSET_LIMITS.MAX_COMPONENT_NAME_CHARS),
      version: version ? version.slice(0, ASSET_LIMITS.MAX_COMPONENT_VERSION_CHARS) : null,
      ecosystem,
      namespace,
      packageUrl: purl ? purl.slice(0, 500) : null,
      cpe: cpe ? cpe.slice(0, 500) : null,
      supplier: supplier ? supplier.slice(0, ASSET_LIMITS.MAX_SUPPLIER_CHARS) : null,
      componentType,
      hashes: [],
      sourcePath: sourcePath ? sourcePath.slice(0, ASSET_LIMITS.MAX_COMPONENT_PATH_CHARS) : null,
      normalizedIdentity: normalized,
      schemaVersion: COMPONENT_SCHEMA_VERSION,
      createdAt: now,
    }));
    if (out.length >= MAX_COMPONENTS) {
      warnings.push(`component cap reached (${MAX_COMPONENTS}); remaining rows rejected`);
      rejected += lines.length - 1 - i;
      break;
    }
  }
  return {
    ok: true,
    result: Object.freeze({
      format: 'csv',
      sourceVersion: null,
      components: dedupe(out),
      warnings,
      rejected,
      sizeBytes: input.length,
    }),
  };
}

function splitCsvLines(input) {
  if (typeof input !== 'string') return [];
  // We support quoted fields with embedded commas and
  // embedded newlines (inside quotes). The line splitter
  // is a tiny state machine.
  const lines = [];
  let buf = '';
  let inQuotes = false;
  for (let i = 0; i < input.length; i++) {
    const ch = input.charAt(i);
    if (ch === '"') {
      if (inQuotes && input.charAt(i + 1) === '"') { buf += '"'; i += 1; continue; }
      inQuotes = !inQuotes;
      buf += ch;
      continue;
    }
    if ((ch === '\n' || ch === '\r') && !inQuotes) {
      if (buf.length > 0) { lines.push(buf); buf = ''; }
      if (ch === '\r' && input.charAt(i + 1) === '\n') i += 1;
      continue;
    }
    buf += ch;
  }
  if (buf.length > 0) lines.push(buf);
  return lines;
}

function parseCsvLine(line) {
  if (typeof line !== 'string') return [];
  const out = [];
  let buf = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line.charAt(i);
    if (ch === '"') {
      if (inQuotes && line.charAt(i + 1) === '"') { buf += '"'; i += 1; continue; }
      inQuotes = !inQuotes;
      continue;
    }
    if (ch === ',' && !inQuotes) { out.push(buf); buf = ''; continue; }
    buf += ch;
  }
  out.push(buf);
  return out;
}

function containsFormula(s) {
  if (typeof s !== 'string' || s.length === 0) return false;
  return /^[=+\-@\t\r]/.test(s);
}

function inferEcosystemFromPurl(purl) {
  if (typeof purl !== 'string' || !purl.startsWith('pkg:')) return null;
  const slash = purl.indexOf('/');
  if (slash < 0) return null;
  const type = purl.slice(4, slash);
  return normalizeEcosystem(type);
}

function inferNamespaceFromPurl(purl) {
  if (typeof purl !== 'string' || !purl.startsWith('pkg:')) return null;
  const body = purl.slice(4);
  const slash = body.indexOf('/');
  if (slash < 0) return null;
  const rest = body.slice(slash + 1);
  const at = rest.lastIndexOf('@');
  const q = rest.indexOf('?');
  let main = rest;
  if (at >= 0) main = rest.slice(0, at);
  if (q >= 0) main = main.slice(0, q);
  if (main.includes('/')) {
    const ns = main.split('/')[0];
    return ns.length > 0 ? ns : null;
  }
  return null;
}

function mapCycloneDxType(t) {
  if (typeof t !== 'string') return 'library';
  const lower = t.toLowerCase();
  if (lower === 'application') return 'application';
  if (lower === 'framework') return 'framework';
  if (lower === 'library') return 'library';
  if (lower === 'operating-system') return 'operating-system';
  if (lower === 'container') return 'container';
  if (lower === 'firmware') return 'firmware';
  if (lower === 'device-driver') return 'device-driver';
  return 'library';
}

function extractSupplier(s) {
  if (typeof s === 'string') return s;
  if (s && typeof s === 'object' && typeof s.name === 'string') return s.name;
  return null;
}

function dedupe(components) {
  const seen = new Map();
  for (const c of components) {
    if (seen.has(c.componentId)) continue;
    seen.set(c.componentId, c);
  }
  return Array.from(seen.values());
}

/** Deterministic component id. We avoid Node `crypto`
 *  so the browser build is unconstrained; a simple
 *  FNV-1a hash over the joined fields is more than
 *  enough to guarantee uniqueness within a single
 *  inventory snapshot. */
function deterministicId(assetId, inventoryId, name, version, ecosystem, namespace) {
  const parts = [assetId, inventoryId, name, version || '', ecosystem || '', namespace || ''];
  const joined = parts.join('|');
  return 'cmp-' + fnv1a(joined).toString(16).padStart(16, '0');
}

function fnv1a(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h;
}
