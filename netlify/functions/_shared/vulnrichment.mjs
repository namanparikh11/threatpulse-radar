/**
 * v5.5 — CISA Vulnrichment / SSVC enrichment.
 *
 * This module is the *server-side* surface for pulling CISA's
 * SSVC decision context out of the public
 * `cisagov/vulnrichment` GitHub repository. It is the
 * companion to the v3 NVD enrichment and the v2.5 FIRST
 * EPSS enrichment: like them, it runs only in the Netlify
 * function runtime, never in a visitor's browser.
 *
 * Public surface:
 *
 *   - `cveToRepoPath(cveId)`          — pure path builder
 *   - `extractSsvcFromAdp(record)`    — pure ADP SSVC parser
 *   - `fetchOneVulnrichment(cveId)`   — single-CVE fetcher
 *                                       (404-tolerant,
 *                                        timeout/5xx/429
 *                                        distinguishable)
 *   - `prioritizeCvesForRefresh`      — pure sort + cap
 *   - `mergeSsvcIntoRecords`          — pure read-time merge
 *   - `vulnrichmentStatusForCoverage` — pure status decision
 *   - `VULNRICHMENT_*` constants      — tunables
 *
 * Storage:
 *   The Vulnrichment cache lives in its own Netlify Blobs
 *   store (`tpr-vulnrichment`, key `cache`). It is NEVER
 *   written by the visitor's request path; only the refresh
 *   orchestrator writes to it. The visitor path reads it
 *   from `dataset.mjs` at serve time and merges the SSVC
 *   fields into the records inline.
 *
 * Why a separate blob store (instead of stuffing SSVC into
 * the `latest-dataset` envelope):
 *
 *   1. The main `latest-dataset` blob's `fetchedAt` is the
 *      single source of truth for the dashboard's "New
 *      dataset available" banner (v5.1). Rewriting the main
 *      blob on every Vulnrichment update would trigger
 *      spurious "newer dataset" banners every few minutes.
 *   2. A Vulnrichment refresh failure must not be able to
 *      downgrade the public envelope. Keeping the cache
 *      separate means a Vulnrichment outage leaves the
 *      `nvdStatus` / `epssStatus` / `cvssScore` fields
 *      completely untouched.
 *   3. The cache is a simple key→value map and grows
 *      independently of the main dataset's prebuilt envelope
 *      schema. Future fields (e.g. SSVC v3) can be added
 *      without touching the main blob.
 *
 * Honesty contract (carried forward from v5.0 / v5.4.2):
 *
 *   - 404 for a CVE is "no CISA Vulnrichment assessment
 *     available" — NOT a failure. The refresh continues with
 *     the remaining CVEs AND writes a lightweight negative-
 *     cache marker (`{ ssvc: null, status: 'missing',
 *     cachedAt, checkedAt }`) so the same CVE isn't
 *     re-selected within the staleness window. The marker is
 *     naturally ignored by `countEnriched` / `mergeSsvcIntoRecord`
 *     (both gate on `cached.ssvc.ssvcExploitation`), so
 *     `vulnrichmentCoverage.enriched` only counts actual
 *     positive SSVC records.
 *   - Timeout, network error, HTTP 429, HTTP 5xx → preserve
 *     the previously cached SSVC record for that CVE. The
 *     internal `lastRefreshFailure` metadata records the
 *     precise reason for operator visibility; the public
 *     envelope is unaffected.
 *   - Raw provider errors NEVER reach the visitor. The
 *     `vulnrichmentStatus` envelope field is the only signal
 *     visitors see, and it is a coarse `available` /
 *     `partial` / `unavailable`.
 */

// ---------------------------------------------------------------------------
// Public upstream URL — the cisagov/vulnrichment repository on GitHub.
// The repository is a public, no-auth static file collection. We use the
// raw.githubusercontent.com endpoint to skip GitHub's HTML wrapping and
// the API rate limits (raw downloads are not rate-limited per IP for
// reasonable use).
// ---------------------------------------------------------------------------

export const VULNRICHMENT_BASE_URL =
  'https://raw.githubusercontent.com/cisagov/vulnrichment/develop';

/** Hard timeout for a single Vulnrichment GET. */
export const VULNRICHMENT_PER_REQUEST_TIMEOUT_MS = 6_000;

// ---------------------------------------------------------------------------
// Refresh tunables (mirrored on the client-side test surface).
// ---------------------------------------------------------------------------

/** Maximum number of CVEs enriched in a single scheduled refresh cycle. */
export const VULNRICHMENT_MAX_PER_RUN = 50;

/** Maximum concurrent Vulnrichment GETs within a single cycle. */
export const VULNRICHMENT_CONCURRENCY = 5;

/**
 * A cached SSVC entry is considered "stale" after this many
 * days. CISA Vulnrichment can update its SSVC decisions
 * (e.g. `poc` → `active`) without changing the CVE ID, so
 * periodic re-fetch keeps the data fresh. 7 days is
 * conservative: a record whose exploitation status changes
 * will be reflected within a week on the dashboard.
 */
export const VULNRICHMENT_STALE_DAYS = 7;

// ---------------------------------------------------------------------------
// CVE → repository path construction.
//
// The cisagov/vulnrichment repository is laid out as:
//   {year}/{bucket}/CVE-{year}-{id}.json
// where the bucket is the leading digits of the numeric CVE
// ID followed by `xxx` (e.g. CVE-2024-0043 → 2024/0xxx/,
// CVE-2024-6714 → 2024/6xxx/, CVE-2024-12345 → 2024/12xxx/).
//
// The bucket prefix is `digits.length - 3` characters wide.
// 4-digit numbers → 1-char prefix, 5-digit numbers → 2-char
// prefix, etc. This matches the repository's actual layout on
// GitHub (verified by inspection of the 2024 and 2025
// directories in July 2026).
//
// Pure function — easy to test.
// ---------------------------------------------------------------------------

/**
 * Construct the relative repository path for a CVE in the
 * cisagov/vulnrichment repository. The caller is responsible
 * for joining it to the base URL.
 *
 * Returns `null` for malformed CVE IDs (not matching
 * `CVE-YYYY-N+`). The contract is "null on bad input,
 * string on good input" so callers can short-circuit cleanly.
 *
 * Examples:
 *   cveToRepoPath('CVE-2024-6714') → '2024/6xxx/CVE-2024-6714.json'
 *   cveToRepoPath('CVE-2024-0043') → '2024/0xxx/CVE-2024-0043.json'
 *   cveToRepoPath('CVE-2024-12345') → '2024/12xxx/CVE-2024-12345.json'
 *   cveToRepoPath('not-a-cve')     → null
 *   cveToRepoPath('CVE-2024')      → null
 *   cveToRepoPath('')              → null
 *   cveToRepoPath(null)            → null
 */
export function cveToRepoPath(cveId) {
  if (typeof cveId !== 'string') return null;
  const trimmed = cveId.trim();
  if (!trimmed) return null;
  // Match CVE-YYYY-NNNN(N+). Case-insensitive (CISA uses
  // uppercase, but be defensive against the lowercase form
  // that some upstream providers occasionally emit).
  const m = /^CVE-(\d{4})-(\d+)$/i.exec(trimmed);
  if (!m) return null;
  const year = m[1];
  const digits = m[2];
  if (digits.length <= 3) {
    // The repository layout requires at least a 1-char
    // bucket prefix (0xxx, 1xxx, ...). A 1-3 digit number
    // is not a valid CVE ID in any year the repository
    // covers; refuse rather than emit a malformed path.
    return null;
  }
  const bucketPrefix = digits.slice(0, digits.length - 3);
  return `${year}/${bucketPrefix}xxx/${trimmed.toUpperCase()}.json`;
}

// ---------------------------------------------------------------------------
// ADP SSVC parser.
//
// CISA Vulnrichment records follow the CVE JSON 5.x schema.
// The SSVC decision is published by CISA-ADP inside the
// `containers.adp[]` array. The relevant fields:
//
//   {
//     "containers": {
//       "adp": [
//         {
//           "providerMetadata": {
//             "shortName": "CISA-ADP",
//             "dateUpdated": "2024-07-23T00:00:00.000Z"
//           },
//           "metrics": [
//             {
//               "other": {
//                 "type": "ssvc",
//                 "content": {
//                   "options": [
//                     { "Exploitation": "active" },
//                     { "Automatable": "yes" },
//                     { "Technical Impact": "total" }
//                   ],
//                   "version": "2.0.3",
//                   "timestamp": "2024-07-23T00:00:00.000Z"
//                 }
//               }
//             }
//           ]
//         }
//       ]
//     }
//   }
//
// We extract only the three documented decision options
// (Exploitation / Automatable / Technical Impact) plus the
// SSVC version and assessment timestamp. Other CISA-ADP
// metrics (e.g. CVSS) are ignored — those are handled by
// the existing NVD enrichment path.
// ---------------------------------------------------------------------------

const EXPLOITATION_VALUES = new Set(['none', 'poc', 'active']);
const AUTOMATABLE_VALUES = new Set(['yes', 'no']);
const TECHNICAL_IMPACT_VALUES = new Set(['partial', 'total']);

/**
 * Extract the CISA-ADP SSVC decision from a Vulnrichment
 * record. Returns `null` if the record has no CISA-ADP
 * container, no SSVC metric, or is missing any of the
 * three documented decision options. The "missing required
 * option" path is defensive — in practice CISA-ADP always
 * publishes all three together, but a future schema change
 * shouldn't crash the parser.
 *
 * Pure function. The returned object is plain data
 * (JSON-serializable, no Symbols, no Dates) and is safe to
 * cache in the blob store and ship in the public response.
 */
export function extractSsvcFromAdp(record) {
  if (!record || typeof record !== 'object') return null;
  const adpList = record?.containers?.adp;
  if (!Array.isArray(adpList)) return null;

  for (const adp of adpList) {
    if (!adp || typeof adp !== 'object') continue;
    const shortName = adp?.providerMetadata?.shortName;
    if (shortName !== 'CISA-ADP') continue;

    const metrics = adp.metrics;
    if (!Array.isArray(metrics)) continue;

    for (const metric of metrics) {
      const other = metric?.other;
      if (!other || typeof other !== 'object') continue;
      if (other.type !== 'ssvc') continue;
      const content = other.content;
      if (!content || typeof content !== 'object') continue;

      const options = Array.isArray(content.options) ? content.options : null;
      if (!options) continue;

      const parsed = parseSsvcOptions(options);
      if (!parsed) continue;
      // Stash the version + assessment timestamp alongside
      // the three decisions. Both are stable strings per the
      // schema, so we don't need to validate their format.
      const version = typeof content.version === 'string'
        ? content.version
        : undefined;
      const timestamp = typeof content.timestamp === 'string'
        ? content.timestamp
        : undefined;
      return {
        ssvcExploitation: parsed.exploitation,
        ssvcAutomatable: parsed.automatable,
        ssvcTechnicalImpact: parsed.technicalImpact,
        ssvcVersion: version,
        ssvcAssessedAt: timestamp,
        ssvcSource: 'CISA Vulnrichment',
      };
    }
  }
  return null;
}

/**
 * Walk the SSVC `options` array and pull out the three
 * documented decisions. Returns `null` if any required
 * option is missing or has an unrecognised value.
 *
 * The options array is a list of single-key objects
 * (e.g. `[{Exploitation: "active"}, {Automatable: "yes"}]`)
 * — this is how CISA-ADP publishes them in practice. We
 * also accept the dictionary form
 * (e.g. `{Exploitation: "active", Automatable: "yes"}`) for
 * defensive purposes.
 */
function parseSsvcOptions(options) {
  const map = {};
  for (const opt of options) {
    if (!opt || typeof opt !== 'object') continue;
    const keys = Object.keys(opt);
    if (keys.length !== 1) continue;
    const k = keys[0];
    const v = opt[k];
    if (typeof v === 'string') map[k] = v;
  }
  // Defensive: also accept the already-dictionary form.
  if (options.length === 1 && !map.Exploitation && typeof options[0] === 'object') {
    const o = options[0];
    for (const k of Object.keys(o)) {
      if (typeof o[k] === 'string') map[k] = o[k];
    }
  }

  const exploitation = map.Exploitation;
  const automatable = map.Automatable;
  const technicalImpact = map['Technical Impact'];

  if (!EXPLOITATION_VALUES.has(exploitation)) return null;
  if (!AUTOMATABLE_VALUES.has(automatable)) return null;
  if (!TECHNICAL_IMPACT_VALUES.has(technicalImpact)) return null;

  return { exploitation, automatable, technicalImpact };
}

// ---------------------------------------------------------------------------
// Single-CVE fetcher.
//
// Contract:
//   - 200 + valid JSON  → returns the parsed JSON body.
//   - 200 + shape error → throws a tagged Error so the
//                         orchestrator can record it.
//   - 404               → returns `null` (no record exists).
//   - 429 / 5xx         → throws a tagged Error.
//   - timeout / network → throws a tagged Error.
//
// The orchestrator catches throws and treats them as
// "transient for this CVE" — the existing cache entry (if
// any) is preserved, and the cycle continues with the next
// CVE.
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} VulnrichmentFetchResult
 * @property {'ok'|'missing'|'transient'} outcome
 * @property {object|null} record  Parsed JSON body when outcome==='ok'.
 */

/**
 * Fetch the Vulnrichment record for a single CVE.
 *
 * Returns a structured envelope so the orchestrator can
 * distinguish "no record exists" (404) from "the request
 * failed transiently" (timeout / 429 / 5xx / network) from
 * "the record was retrieved successfully" (200 + valid JSON).
 *
 * Never throws. All failure modes are encoded in the
 * returned `outcome` field.
 */
export async function fetchOneVulnrichment(cveId, opts = {}) {
  const path = cveToRepoPath(cveId);
  if (!path) {
    // Malformed CVE — treat as "missing" (the repository
    // can't possibly have a record for it). This is not a
    // transient error and shouldn't pollute the failure
    // counters.
    return { outcome: 'missing', record: null };
  }
  const url = `${VULNRICHMENT_BASE_URL}/${path}`;
  const timeoutMs = typeof opts.timeoutMs === 'number' && opts.timeoutMs > 0
    ? opts.timeoutMs
    : VULNRICHMENT_PER_REQUEST_TIMEOUT_MS;
  const fetcher = typeof opts.fetcher === 'function' ? opts.fetcher : defaultFetcher;

  let res;
  try {
    res = await fetcher(url, { timeoutMs });
  } catch (err) {
    return {
      outcome: 'transient',
      record: null,
      reason: transientReason(err),
    };
  }

  if (res.status === 404) {
    return { outcome: 'missing', record: null };
  }
  if (res.status === 429 || (res.status >= 500 && res.status < 600)) {
    return {
      outcome: 'transient',
      record: null,
      reason: `HTTP ${res.status}`,
    };
  }
  if (!res.ok) {
    return {
      outcome: 'transient',
      record: null,
      reason: `HTTP ${res.status} ${res.statusText || ''}`.trim(),
    };
  }

  let body;
  try {
    body = await res.json();
  } catch {
    return {
      outcome: 'transient',
      record: null,
      reason: 'JSON parse failed',
    };
  }
  return { outcome: 'ok', record: body };
}

/**
 * Default fetcher — uses globalThis.fetch with an
 * AbortController-driven timeout. Exposed as a separate
 * function so the acceptance suite can swap it out for a
 * mock that simulates 404 / 429 / 5xx / network errors
 * without touching the network.
 */
async function defaultFetcher(url, { timeoutMs }) {
  if (typeof globalThis.fetch !== 'function') {
    throw new Error('fetch is not available in this runtime');
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await globalThis.fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      // GitHub's raw content endpoint sends `Cache-Control`
      // on its own; we let it through. We do NOT add
      // cache: 'no-store' because Netlify's edge should be
      // allowed to cache the (public, no-auth) raw file.
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

function transientReason(err) {
  if (!err) return 'unknown error';
  if (typeof err === 'string') return err;
  if (err instanceof Error) {
    // AbortError is the standard name for a timeout-induced
    // abort in both Node's undici and the browser fetch.
    if (err.name === 'AbortError') return `timed out after timeout`;
    return err.message || err.name || 'unknown error';
  }
  return String(err);
}

// ---------------------------------------------------------------------------
// Refresh prioritization (pure).
// ---------------------------------------------------------------------------

/**
 * Pick the CVEs that should be enriched in this refresh
 * cycle. Pure: given the current dataset's CVE list (with
 * their KEV dateAdded timestamps) and the existing cache
 * (with cachedAt timestamps), returns a sorted + capped
 * array of CVE IDs to fetch.
 *
 *   - Missing from the cache → always included.
 *   - Cached entry older than `staleDays` → included.
 *   - Otherwise → skipped (fresh, no need to re-fetch).
 *
 * "Cached entry" includes BOTH positive SSVC records
 * (`{ ssvc, cachedAt }`) AND negative-cache markers
 * (`{ ssvc: null, status: 'missing', cachedAt, checkedAt }`)
 * written for HTTP 404 responses. A fresh negative-cache
 * marker means "we already confirmed there's no CISA
 * Vulnrichment assessment for this CVE within the
 * staleness window" — re-fetching it would just produce
 * another 404 and waste a slot in the 50-cap. An expired
 * negative-cache marker is re-selected so a newly published
 * CISA assessment can replace it.
 *
 * Within the to-enrich set, CVEs are sorted by KEV
 * `dateAdded` descending (newest first). CISA Vulnrichment
 * prioritises the same records CISA is most actively
 * tracking, so the newest KEV entries are the most likely
 * to have a recent SSVC decision worth surfacing.
 *
 * The result is capped at `maxItems` (default 50) so a
 * single refresh never overwhelms the upstream.
 */
export function prioritizeCvesForRefresh(opts) {
  const {
    cveList,           // [{cveId, dateAdded: ISO string|null}, ...]
    cache,             // {[cveId]: {ssvc, cachedAt: epochMs}}
    maxItems = VULNRICHMENT_MAX_PER_RUN,
    staleDays = VULNRICHMENT_STALE_DAYS,
    now = Date.now(),
  } = opts || {};
  if (!Array.isArray(cveList) || cveList.length === 0) return [];
  const cacheMap = cache && typeof cache === 'object' ? cache : {};
  const staleMs = staleDays * 24 * 60 * 60 * 1000;
  const cutoff = now - staleMs;

  const toEnrich = [];
  for (const entry of cveList) {
    if (!entry || typeof entry.cveId !== 'string' || !entry.cveId) continue;
    const existing = cacheMap[entry.cveId];
    if (existing && typeof existing.cachedAt === 'number' && existing.cachedAt >= cutoff) {
      // Fresh — skip.
      continue;
    }
    toEnrich.push({
      cveId: entry.cveId,
      // KEV dateAdded may be missing on older records or
      // records sourced from non-KEV datasets. Fall back
      // to a stable sentinel so the sort is deterministic
      // but the new-KEV-first preference still wins.
      dateAdded: entry.dateAdded || '1970-01-01T00:00:00.000Z',
    });
  }
  // Sort newest first.
  toEnrich.sort((a, b) => {
    if (a.dateAdded > b.dateAdded) return -1;
    if (a.dateAdded < b.dateAdded) return 1;
    return 0;
  });
  return toEnrich.slice(0, maxItems).map((e) => e.cveId);
}

// ---------------------------------------------------------------------------
// Read-time merge (pure).
// ---------------------------------------------------------------------------

/**
 * Merge a SSVC record into a vulnerability. Returns a NEW
 * object — the input is not mutated. When `ssvc` is null,
 * returns the input reference unchanged (so the call site
 * doesn't allocate new objects for the unenriched majority).
 */
export function mergeSsvcIntoRecord(record, ssvc) {
  if (!record || !ssvc) return record;
  return {
    ...record,
    ssvcExploitation: ssvc.ssvcExploitation,
    ssvcAutomatable: ssvc.ssvcAutomatable,
    ssvcTechnicalImpact: ssvc.ssvcTechnicalImpact,
    ssvcVersion: ssvc.ssvcVersion,
    ssvcAssessedAt: ssvc.ssvcAssessedAt,
    ssvcSource: ssvc.ssvcSource,
  };
}

/**
 * Merge SSVC records into an array of vulnerability records.
 * Pure. The `ssvcByCve` argument is a `{[cveId]: ssvc}`
 * lookup; absent CVEs are returned with no SSVC fields.
 */
export function mergeSsvcIntoRecords(records, ssvcByCve) {
  if (!Array.isArray(records) || records.length === 0) return records;
  if (!ssvcByCve || typeof ssvcByCve !== 'object') return records;
  return records.map((r) => {
    if (!r || typeof r.cveId !== 'string') return r;
    const ssvc = ssvcByCve[r.cveId];
    if (!ssvc) return r;
    return mergeSsvcIntoRecord(r, ssvc);
  });
}

// ---------------------------------------------------------------------------
// Coverage status decision (pure).
// ---------------------------------------------------------------------------

/**
 * Compute the public `vulnrichmentStatus` from the cache and
 * the dataset's CVE list. The contract:
 *
 *   - enriched === 0            → 'unavailable'
 *   - enriched === total        → 'available'
 *   - 0 < enriched < total      → 'partial'
 *
 * Honest: we never claim 'available' while the incremental
 * backfill is incomplete.
 */
export function vulnrichmentStatusForCoverage(enriched, total) {
  const e = Number.isFinite(enriched) && enriched > 0 ? Math.floor(enriched) : 0;
  const t = Number.isFinite(total) && total > 0 ? Math.floor(total) : 0;
  if (t === 0) return 'unavailable';
  if (e === 0) return 'unavailable';
  if (e >= t) return 'available';
  return 'partial';
}

// ---------------------------------------------------------------------------
// Bounded parallel worker.
//
// Mirrors the `settledAll` pattern used by NVD and EPSS so
// the failure semantics match the rest of the pipeline:
// each task runs in isolation, never throws out of the
// worker, and surfaces its outcome via the returned
// `{ status, value | reason }` envelope.
// ---------------------------------------------------------------------------

/**
 * Run an array of zero-arg async tasks with a hard
 * concurrency limit. Each task MUST NOT throw — callers
 * are expected to wrap their work in a try/catch and
 * return a structured result envelope.
 */
export async function settledAll(tasks, concurrency) {
  const results = new Array(tasks.length);
  const limit = Math.max(1, Math.min(concurrency, tasks.length));
  let next = 0;
  async function worker() {
    while (true) {
      const i = next++;
      if (i >= tasks.length) return;
      try {
        results[i] = { status: 'fulfilled', value: await tasks[i]() };
      } catch (reason) {
        results[i] = { status: 'rejected', reason };
      }
    }
  }
  const workers = Array.from({ length: limit }, () => worker());
  await Promise.all(workers);
  return results;
}
