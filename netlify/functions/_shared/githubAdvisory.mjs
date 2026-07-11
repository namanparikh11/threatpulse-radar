/**
 * v5.6 — GitHub Advisory Database enrichment.
 *
 * This module is the *server-side* surface for pulling GitHub's
 * reviewed security advisories out of the public GitHub
 * Advisory Database API. It is the companion to the v3 NVD
 * enrichment, the v2.5 FIRST EPSS enrichment, and the v5.5
 * CISA Vulnrichment enrichment: like them, it runs only in
 * the Netlify Function runtime, never in a visitor's browser.
 *
 * Public surface:
 *
 *   - `cveToAdvisoryQueryUrl(cveId)` — pure URL builder
 *   - `extractReviewedAdvisories(arr)` — pure parser
 *   - `fetchOneCveAdvisories(cveId)` — single-CVE fetcher
 *                                     (404-tolerant,
 *                                      timeout/5xx/403/429
 *                                      distinguishable)
 *   - `prioritizeCvesForRefresh` — pure sort + cap
 *   - `mergeAdvisoryIntoRecord` — pure read-time merge
 *   - `githubAdvisoryStatusForCoverage` — pure status decision
 *   - `GITHUB_ADVISORY_*` constants — tunables
 *
 * Storage:
 *   The GitHub Advisory cache lives in its own Netlify Blobs
 *   store (`tpr-github-advisory`, key `cache`). It is NEVER
 *   written by the visitor's request path; only the refresh
 *   orchestrator writes to it. The visitor path reads it
 *   from `dataset.mjs` at serve time and merges the package
 *   remediation fields into the records inline.
 *
 * Why a separate blob store (in addition to `tpr-vulnrichment`):
 *
 *   1. The prebuilt `latest-dataset` blob's `fetchedAt` is the
 *      single source of truth for the dashboard's "New dataset
 *      available" banner (v5.1). Rewriting the main blob on
 *      every GitHub Advisory update would trigger spurious
 *      "newer dataset" banners every few minutes.
 *   2. A GitHub Advisory refresh failure must not be able to
 *      downgrade the public envelope. Keeping the cache
 *      separate means a GitHub outage leaves the
 *      `nvdStatus` / `epssStatus` / `cvssScore` / SSVC
 *      fields completely untouched.
 *   3. The cache schema is independent of the SSVC cache
 *      schema — future fields (e.g. `cvss` from the advisory
 *      payload) can be added without touching the
 *      Vulnrichment blob.
 *
 * Honesty contract (carried forward from v5.0 / v5.4.2 / v5.5):
 *
 *   - HTTP 404 OR HTTP 200 with an empty array is "no
 *     reviewed GitHub advisory for this CVE" — NOT a failure.
 *     A lightweight negative-cache marker
 *     (`{ advisory: null, status: 'missing', cachedAt,
 *     checkedAt }`) is written so the same CVE isn't
 *     re-selected within the staleness window. The marker is
 *     naturally ignored by `countEnriched` and the dataset
 *     read-time merge (both gate on `cached.advisory`), so
 *     `githubAdvisoryCoverage.enriched` only counts actual
 *     positive advisory records.
 *   - Timeout, network error, HTTP 429, HTTP 403 (rate
 *     limit), HTTP 5xx → preserve the previously cached
 *     advisory record for that CVE. The internal
 *     `lastGithubAdvisoryRefresh` metadata records the
 *     sanitized reason for operator visibility; the public
 *     envelope is unaffected.
 *   - Raw provider errors and rate-limit response headers
 *     NEVER reach the visitor. The `githubAdvisoryStatus`
 *     envelope field is the only signal visitors see, and it
 *     is a coarse `available` / `partial` / `unavailable`.
 *   - The optional `GITHUB_TOKEN` env var is read only inside
 *     the Netlify/server-side path, sent only in the
 *     `Authorization: Bearer <token>` header, never in a URL,
 *     never logged, never serialized, never exposed through
 *     public responses, comments, thrown errors, frontend
 *     code, or source maps. Unauthenticated operation works
 *     identically except for the lower refresh cap (25 vs 50).
 */

// ---------------------------------------------------------------------------
// Public upstream URL — the GitHub Advisory Database REST API.
// `type=reviewed` is the v5.6 contract: only advisories that
// GitHub itself has reviewed end-to-end. Unreviewed community
// advisories are intentionally excluded — they are not the
// authoritative source for package remediation context.
// ---------------------------------------------------------------------------

export const GITHUB_ADVISORY_API_BASE_URL = 'https://api.github.com';

export const GITHUB_ADVISORY_API_VERSION = '2026-03-10';

export const GITHUB_ADVISORY_USER_AGENT = 'ThreatPulse-Radar';

/** Hard timeout for a single advisory GET. */
export const GITHUB_ADVISORY_PER_REQUEST_TIMEOUT_MS = 8_000;

// ---------------------------------------------------------------------------
// Refresh tunables (mirrored on the client-side test surface).
// ---------------------------------------------------------------------------

/** Maximum CVEs enriched per cycle WITH a `GITHUB_TOKEN`. */
export const GITHUB_ADVISORY_MAX_PER_RUN_AUTH = 50;

/** Maximum CVEs enriched per cycle WITHOUT a `GITHUB_TOKEN`. */
export const GITHUB_ADVISORY_MAX_PER_RUN_UNAUTH = 25;

/** Maximum concurrent GitHub Advisory GETs within a single cycle. */
export const GITHUB_ADVISORY_CONCURRENCY = 4;

/**
 * A cached advisory entry is considered "stale" after this
 * many days. GitHub's reviewed advisories can be amended
 * (patched version bumped, severity adjusted) without
 * changing the CVE ID, so periodic re-fetch keeps the data
 * fresh. 7 days is conservative: a record whose patched
 * version changes will be reflected within a week on the
 * dashboard.
 */
export const GITHUB_ADVISORY_STALE_DAYS = 7;

/**
 * Minimum remaining rate-limit allowance to keep issuing
 * requests in the current pass. Below this threshold the
 * orchestrator stops the current provider pass to avoid a
 * 403/429 against GitHub, which would force us to discard
 * the in-flight work and (in the worst case) trigger a
 * token-bucket penalty.
 *
 * The anonymous REST API allows 60 req/hour per IP;
 * authenticated requests allow 5,000 req/hour. We treat any
 * remaining allowance under 10 as "too low" so we never
 * spend the very last tokens on the tail of the cycle.
 */
export const GITHUB_ADVISORY_MIN_REMAINING = 10;

// ---------------------------------------------------------------------------
// CVE → Advisory query URL construction.
//
// GitHub's list endpoint:
//   GET /advisories?cve_id=<URL-ENCODED-CVE-ID>&type=reviewed
// Returns a JSON array of advisory objects (possibly empty).
//
// The `cve_id` parameter is the official documented filter.
// We use encodeURIComponent so any future CVE with a
// non-ASCII character is handled safely (none today, but
// defensive).
//
// Pure function — easy to test.
// ---------------------------------------------------------------------------

/**
 * Construct the GitHub Advisory Database query URL for a
 * single CVE. The caller is responsible for joining the
 * returned query string to the API base URL.
 *
 * Returns `null` for malformed CVE IDs (not matching
 * `CVE-YYYY-N+`). The contract is "null on bad input,
 * string on good input" so callers can short-circuit cleanly.
 *
 * The returned string is the *path + query* portion
 * (e.g. `/advisories?cve_id=CVE-2024-1234&type=reviewed`).
 * It does NOT include the base URL, the `Accept` header,
 * the `X-GitHub-Api-Version` header, or any optional
 * `Authorization` header — those are added by the fetcher.
 *
 * Examples:
 *   cveToAdvisoryQueryUrl('CVE-2024-6714')
 *     → '/advisories?cve_id=CVE-2024-6714&type=reviewed'
 *   cveToAdvisoryQueryUrl('not-a-cve') → null
 *   cveToAdvisoryQueryUrl('CVE-2024')  → null
 *   cveToAdvisoryQueryUrl('')          → null
 *   cveToAdvisoryQueryUrl(null)        → null
 */
export function cveToAdvisoryQueryUrl(cveId) {
  if (typeof cveId !== 'string') return null;
  const trimmed = cveId.trim().toUpperCase();
  if (!trimmed) return null;
  // Match CVE-YYYY-NNNN(N+). Case-insensitive at the input
  // (we normalize to uppercase above).
  if (!/^CVE-\d{4}-\d{4,}$/.test(trimmed)) return null;
  return `/advisories?cve_id=${encodeURIComponent(trimmed)}&type=reviewed`;
}

// ---------------------------------------------------------------------------
// Advisory parser.
//
// GitHub's reviewed advisory payload (relevant fields):
//
//   {
//     "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
//     "cve_id": "CVE-2024-1234",
//     "url": "https://api.github.com/advisories/GHSA-xxxx-yyyy-zzzz",
//     "html_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
//     "summary": "...",
//     "description": "...",
//     "type": "reviewed",
//     "severity": "high" | "medium" | "low" | "critical",
//     "cvss": { ... },
//     "published_at": "2024-07-23T00:00:00.000Z",
//     "updated_at": "2024-07-23T00:00:00.000Z",
//     "withdrawn_at": null,
//     "vulnerabilities": [
//       {
//         "package": { "name": "lodash", "ecosystem": "npm" },
//         "vulnerable_version_range": "< 4.17.21",
//         "first_patched_version": "4.17.21"
//       }
//     ]
//   }
//
// We extract only the documented fields. We do NOT keep
// `description`, `cvss`, or any other verbose payload — the
// spec requires "minimal normalized fields" only.
// ---------------------------------------------------------------------------

const VALID_SEVERITIES = new Set(['low', 'moderate', 'medium', 'high', 'critical']);

/**
 * Normalize a single GitHub vulnerability entry. Returns
 * `null` if the entry is missing required fields.
 *
 * The GitHub payload uses `moderate` and `medium` interchangeably
 * for the "middle" severity (the API has accepted both over
 * time). We normalize both to `'medium'` so the UI never
 * shows two different strings for the same logical value.
 */
function normalizeVulnerability(vuln) {
  if (!vuln || typeof vuln !== 'object') return null;
  const pkg = vuln.package;
  if (!pkg || typeof pkg !== 'object') return null;
  const ecosystem = typeof pkg.ecosystem === 'string' ? pkg.ecosystem.trim() : '';
  const name = typeof pkg.name === 'string' ? pkg.name.trim() : '';
  if (!ecosystem || !name) return null;
  const vulnerableVersionRange = typeof vuln.vulnerable_version_range === 'string'
    ? vuln.vulnerable_version_range.trim()
    : '';
  // first_patched_version may be `null` (no fix yet) or
  // a string ("4.17.21"). Per the spec, null means
  // "First patched version unavailable" — we keep the
  // field as `null` so the drawer can render the
  // explicit neutral copy.
  const firstPatchedVersion = typeof vuln.first_patched_version === 'string'
    ? vuln.first_patched_version.trim()
    : null;
  return {
    ecosystem,
    name,
    vulnerableVersionRange,
    firstPatchedVersion,
  };
}

/**
 * Deduplicate package entries using the
 * `ecosystem + name + vulnerableVersionRange` triple. Keeps
 * the first occurrence of each (deterministic order).
 * Caps the result at 5 entries per CVE.
 */
function dedupeAndCapPackages(packages) {
  const seen = new Set();
  const out = [];
  for (const p of packages) {
    const key = `${p.ecosystem}\u0000${p.name.toLowerCase()}\u0000${p.vulnerableVersionRange}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
    if (out.length >= 5) break;
  }
  return out;
}

/**
 * Build a stable sort key for advisories so multiple
 * advisories for the same CVE produce deterministic output
 * across cycles (the same advisory always wins). We sort by:
 *   1. `ghsa_id` ascending (lexicographic)
 * Tie-breaker: `published_at` ascending.
 */
function advisorySortKey(a) {
  const ghsa = typeof a.ghsa_id === 'string' ? a.ghsa_id : '';
  const pub = typeof a.published_at === 'string' ? a.published_at : '';
  return `${ghsa}\u0000${pub}`;
}

/**
 * Extract the set of reviewed, non-withdrawn GitHub advisories
 * from a raw API response array. Returns a normalized object
 * (or `null` if the array is empty / all entries are filtered
 * out / the input is invalid).
 *
 * Pure function. The returned object is plain data
 * (JSON-serializable, no Symbols, no Dates) and is safe to
 * cache in the blob store and ship in the public response.
 *
 * The minimal record shape (per the v5.6 spec):
 *
 *   {
 *     ghsaId: string,
 *     advisoryUrl: string,         // html_url
 *     advisorySeverity: 'low' | 'medium' | 'high' | 'critical',
 *     githubReviewedAt: string,    // updated_at
 *     source: 'GitHub Advisory Database',
 *     packages: [
 *       { ecosystem, name, vulnerableVersionRange, firstPatchedVersion }
 *     ],  // 0..5 entries
 *   }
 */
export function extractReviewedAdvisories(arr) {
  if (!Array.isArray(arr) || arr.length === 0) return null;

  // 1. Filter to reviewed + non-withdrawn advisories.
  const filtered = arr.filter((a) => {
    if (!a || typeof a !== 'object') return false;
    if (a.type !== 'reviewed') return false;
    if (a.withdrawn_at !== null && a.withdrawn_at !== undefined) return false;
    return true;
  });
  if (filtered.length === 0) return null;

  // 2. Sort deterministically (per spec requirement 8).
  filtered.sort((a, b) => {
    const ka = advisorySortKey(a);
    const kb = advisorySortKey(b);
    if (ka < kb) return -1;
    if (ka > kb) return 1;
    return 0;
  });

  // 3. Merge package entries from all advisories. The first
  //    advisory in the sorted list is the "primary" — its
  //    `ghsaId` / `advisoryUrl` / `advisorySeverity` /
  //    `githubReviewedAt` become the canonical fields. If
  //    multiple advisories match, we union their packages
  //    (deduped + capped) so a defender sees the full
  //    remediation surface, not just the first advisory.
  const primary = filtered[0];

  const ghsaId = typeof primary.ghsa_id === 'string' ? primary.ghsa_id : '';
  const advisoryUrl = typeof primary.html_url === 'string'
    ? primary.html_url
    : (typeof primary.url === 'string' ? primary.url : '');
  let advisorySeverity = typeof primary.severity === 'string'
    ? primary.severity.toLowerCase()
    : null;
  // Normalize `moderate` → `medium` for UI consistency.
  if (advisorySeverity === 'moderate') advisorySeverity = 'medium';
  if (!VALID_SEVERITIES.has(advisorySeverity)) advisorySeverity = null;
  // githubReviewedAt: prefer `updated_at` (most recent review)
  // over `published_at` so the field reflects the most
  // recent GitHub review of the advisory.
  const githubReviewedAt = typeof primary.updated_at === 'string'
    ? primary.updated_at
    : (typeof primary.published_at === 'string' ? primary.published_at : '');

  // 4. Collect and dedupe packages across all advisories.
  const allPackages = [];
  for (const a of filtered) {
    const vulns = Array.isArray(a.vulnerabilities) ? a.vulnerabilities : [];
    for (const v of vulns) {
      const normalized = normalizeVulnerability(v);
      if (normalized) allPackages.push(normalized);
    }
  }
  const packages = dedupeAndCapPackages(allPackages);

  return {
    ghsaId,
    advisoryUrl,
    advisorySeverity,
    githubReviewedAt,
    source: 'GitHub Advisory Database',
    packages,
  };
}

// ---------------------------------------------------------------------------
// Single-CVE fetcher.
//
// Contract:
//   - 200 + valid JSON array → returns `{ outcome: 'ok', records: [...] }`.
//   - 200 + empty array     → returns `{ outcome: 'empty', records: [] }`.
//   - 404 / 403 / 429 / 5xx → returns a 'transient' envelope with a
//                              sanitized reason (NEVER the raw
//                              provider error body, NEVER any
//                              token, NEVER any rate-limit
//                              response header).
//   - timeout / network      → returns a 'transient' envelope.
//
// The orchestrator catches all of these and decides whether
// to write a marker / preserve / etc. The fetcher itself
// never throws.
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} AdvisoryFetchResult
 * @property {'ok'|'empty'|'transient'} outcome
 * @property {Array|null} records  Parsed JSON body when outcome==='ok' or 'empty'.
 * @property {string} [reason]     Sanitized diagnostic string. Internal-only.
 * @property {string} [retryAfter] ISO timestamp at which the upstream
 *                                 rate-limit window resets. Internal-only.
 */

/**
 * Fetch GitHub reviewed advisories for a single CVE.
 *
 * Returns a structured envelope so the orchestrator can
 * distinguish "no advisories exist" (200 + empty array) from
 * "the request failed transiently" (timeout / 403 / 429 / 5xx
 * / network) from "advisories were retrieved" (200 + non-empty).
 *
 * Never throws. All failure modes are encoded in the
 * returned `outcome` field.
 */
export async function fetchOneCveAdvisories(cveId, opts = {}) {
  const path = cveToAdvisoryQueryUrl(cveId);
  if (!path) {
    // Malformed CVE — treat as "empty" (GitHub's list
    // endpoint will return an empty array for a malformed
    // filter anyway, but short-circuit cleanly).
    return { outcome: 'empty', records: [] };
  }
  const url = `${GITHUB_ADVISORY_API_BASE_URL}${path}`;
  const timeoutMs = typeof opts.timeoutMs === 'number' && opts.timeoutMs > 0
    ? opts.timeoutMs
    : GITHUB_ADVISORY_PER_REQUEST_TIMEOUT_MS;
  const fetcher = typeof opts.fetcher === 'function' ? opts.fetcher : defaultFetcher;
  // Per the v5.6 token contract: the fetcher MUST NOT receive
  // the token directly. The orchestrator (refresh.mjs) reads
  // process.env.GITHUB_TOKEN and passes only `auth` (a boolean)
  // so the production fetcher knows to add the header. This
  // keeps the token out of test seams, log lines, error
  // messages, and any future code path that imports
  // `fetchOneCveAdvisories`.
  const auth = opts.auth === true;

  let res;
  try {
    res = await fetcher(url, { timeoutMs, auth });
  } catch (err) {
    return {
      outcome: 'transient',
      records: null,
      reason: transientReason(err),
    };
  }

  // Per spec requirement 5: inspect rate-limit headers BEFORE
  // we commit to parsing the body. GitHub returns these on
  // every response (success or failure). When the remaining
  // allowance is too low, we stop the current pass; the
  // orchestrator records the `retryAfter` and preserves all
  // existing cache entries.
  const rateLimitInfo = readRateLimitHeaders(res && res.headers);

  if (res.status === 404) {
    // Defensive: GitHub's documented list endpoint contract
    // is "200 + array (possibly empty)". 404 should not
    // happen for a well-formed `cve_id` filter, but if it
    // does we treat it as "no advisories" — the cycle
    // continues.
    return { outcome: 'empty', records: [] };
  }
  if (res.status === 429) {
    return {
      outcome: 'transient',
      records: null,
      reason: 'HTTP 429 (rate limit)',
      retryAfter: rateLimitInfo.retryAfter,
      remaining: rateLimitInfo.remaining,
    };
  }
  if (res.status === 403) {
    // 403 from GitHub on the advisories list endpoint is
    // almost always the rate-limit secondary signal. We
    // treat it the same as 429.
    return {
      outcome: 'transient',
      records: null,
      reason: 'HTTP 403 (rate limit)',
      retryAfter: rateLimitInfo.retryAfter,
      remaining: rateLimitInfo.remaining,
    };
  }
  if (res.status >= 500 && res.status < 600) {
    return {
      outcome: 'transient',
      records: null,
      reason: `HTTP ${res.status}`,
    };
  }
  if (!res.ok) {
    return {
      outcome: 'transient',
      records: null,
      reason: `HTTP ${res.status} ${res.statusText || ''}`.trim(),
    };
  }

  let body;
  try {
    body = await res.json();
  } catch {
    return {
      outcome: 'transient',
      records: null,
      reason: 'JSON parse failed',
    };
  }
  if (!Array.isArray(body)) {
    return {
      outcome: 'transient',
      records: null,
      reason: 'Unexpected response shape (expected array)',
    };
  }
  if (body.length === 0) {
    return {
      outcome: 'empty',
      records: [],
      remaining: rateLimitInfo.remaining,
      retryAfter: rateLimitInfo.retryAfter,
    };
  }
  return { outcome: 'ok', records: body, remaining: rateLimitInfo.remaining };
}

/**
 * Read the GitHub rate-limit response headers. Returns
 * `null` for any field that is missing or unparseable.
 *
 *   x-ratelimit-remaining:  integer or null
 *   x-ratelimit-reset:      integer (epoch seconds) or null
 *   retry-after:            integer (seconds) or null
 *
 * This helper is used by the orchestrator to decide when
 * to stop the current provider pass. It is intentionally
 * defensive — GitHub has been known to omit the headers
 * during edge-network incidents, and we want the cycle to
 * continue gracefully (the request itself succeeded, even
 * if we don't know the rate-limit state).
 */
export function readRateLimitHeaders(headers) {
  if (!headers || typeof headers !== 'object') {
    return { remaining: null, retryAfter: null };
  }
  const get = (name) => {
    if (typeof headers.get === 'function') {
      const v = headers.get(name);
      return typeof v === 'string' ? v : null;
    }
    if (typeof headers[name] === 'string') return headers[name];
    if (typeof headers[name.toLowerCase()] === 'string') return headers[name.toLowerCase()];
    return null;
  };
  const remainingRaw = get('x-ratelimit-remaining');
  const resetRaw = get('x-ratelimit-reset');
  const retryAfterRaw = get('retry-after');
  const remaining = parseIntStrict(remainingRaw);
  const resetEpoch = parseIntStrict(resetRaw);
  const retryAfter = parseIntStrict(retryAfterRaw);
  // Convert the reset epoch (seconds) to an ISO timestamp
  // so the orchestrator can log a human-readable time
  // without doing epoch math at every call site.
  let resetIso = null;
  if (resetEpoch !== null) {
    const ms = resetEpoch * 1000;
    if (Number.isFinite(ms) && ms > 0) resetIso = new Date(ms).toISOString();
  }
  return {
    remaining,
    retryAfter: resetIso, // canonicalized to ISO
    retryAfterSeconds: retryAfter,
  };
}

function parseIntStrict(s) {
  if (typeof s !== 'string' || !s) return null;
  const n = Number(s);
  if (!Number.isFinite(n)) return null;
  return Math.trunc(n);
}

/**
 * Default fetcher — uses globalThis.fetch with an
 * AbortController-driven timeout. Adds the GitHub-required
 * `Accept` and `X-GitHub-Api-Version` headers always, and the
 * `Authorization: Bearer <token>` header only when `auth: true`
 * is passed.
 *
 * The token is read from `process.env.GITHUB_TOKEN` ONLY when
 * `auth: true`. The token is never logged, never thrown, and
 * never serialized to the response body. If the env var is
 * missing, the request is sent unauthenticated (a 403 response
 * from GitHub is the operator's signal that the token needs
 * to be set; the cycle continues regardless).
 *
 * Exposed as a separate function so the acceptance suite
 * can swap it out for a mock that simulates 404 / 403 / 429
 * / 5xx / network errors without touching the network.
 */
async function defaultFetcher(url, { timeoutMs, auth }) {
  if (typeof globalThis.fetch !== 'function') {
    throw new Error('fetch is not available in this runtime');
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': GITHUB_ADVISORY_API_VERSION,
      'User-Agent': GITHUB_ADVISORY_USER_AGENT,
    };
    if (auth === true) {
      const token = readGithubToken();
      if (token) headers.Authorization = `Bearer ${token}`;
    }
    return await globalThis.fetch(url, {
      method: 'GET',
      headers,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Read the GitHub token from the server-side environment.
 * Returns `null` (never the empty string, never the token)
 * if the env var is not set.
 *
 * The token is read only inside this module. The
 * `defaultFetcher` is the only call site. The token is never
 * logged, never serialized, never written to the blob
 * store, never returned in a response, never propagated to
 * the visitor's request path.
 */
function readGithubToken() {
  if (typeof process === 'undefined' || !process.env) return null;
  const token = process.env.GITHUB_TOKEN;
  if (typeof token !== 'string' || !token) return null;
  return token;
}

function transientReason(err) {
  if (!err) return 'unknown error';
  if (typeof err === 'string') return err;
  if (err instanceof Error) {
    // AbortError is the standard name for a timeout-induced
    // abort in both Node's undici and the browser fetch.
    if (err.name === 'AbortError') return `timed out after ${err.message || 'timeout'}`;
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
 * "Cached entry" includes BOTH positive advisory records
 * (`{ advisory, cachedAt }`) AND negative-cache markers
 * (`{ advisory: null, status: 'missing', cachedAt, checkedAt }`)
 * written for empty-array responses. A fresh negative-cache
 * marker means "we already confirmed there's no reviewed
 * GitHub advisory for this CVE within the staleness window"
 * — re-fetching it would just produce another empty array
 * and waste a slot in the 25/50-cap. An expired
 * negative-cache marker is re-selected so a newly published
 * GitHub advisory can replace it.
 *
 * Within the to-enrich set, CVEs are sorted by KEV
 * `dateAdded` descending (newest first). The newest KEV
 * entries are the most likely to have a recent GitHub
 * advisory worth surfacing.
 *
 * The result is capped at `maxItems` (default
 * `GITHUB_ADVISORY_MAX_PER_RUN_AUTH` / 50 with a token, or
 * `GITHUB_ADVISORY_MAX_PER_RUN_UNAUTH` / 25 without).
 */
export function prioritizeCvesForRefresh(opts) {
  const {
    cveList,           // [{cveId, dateAdded: ISO string|null}, ...]
    cache,             // {[cveId]: {advisory, cachedAt: epochMs}}
    maxItems,
    staleDays = GITHUB_ADVISORY_STALE_DAYS,
    now = Date.now(),
  } = opts || {};
  if (!Array.isArray(cveList) || cveList.length === 0) return [];
  const cacheMap = cache && typeof cache === 'object' ? cache : {};
  const staleMs = staleDays * 24 * 60 * 60 * 1000;
  const cutoff = now - staleMs;
  const effectiveMaxItems = Number.isFinite(maxItems) && maxItems > 0
    ? Math.floor(maxItems)
    : GITHUB_ADVISORY_MAX_PER_RUN_AUTH;

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
  return toEnrich.slice(0, effectiveMaxItems).map((e) => e.cveId);
}

// ---------------------------------------------------------------------------
// Read-time merge (pure).
// ---------------------------------------------------------------------------

/**
 * Merge a GitHub advisory record into a vulnerability.
 * Returns a NEW object — the input is not mutated. When
 * `advisory` is null, returns the input reference unchanged
 * (so the call site doesn't allocate new objects for the
 * unenriched majority).
 */
export function mergeAdvisoryIntoRecord(record, advisory) {
  if (!record || !advisory) return record;
  return {
    ...record,
    githubAdvisory: {
      ghsaId: advisory.ghsaId,
      advisoryUrl: advisory.advisoryUrl,
      advisorySeverity: advisory.advisorySeverity,
      githubReviewedAt: advisory.githubReviewedAt,
      source: advisory.source,
      packages: Array.isArray(advisory.packages) ? advisory.packages : [],
    },
  };
}

/**
 * Merge GitHub advisory records into an array of vulnerability
 * records. Pure. The `advisoryByCve` argument is a
 * `{[cveId]: advisory}` lookup; absent CVEs are returned
 * with no `githubAdvisory` field.
 */
export function mergeAdvisoryIntoRecords(records, advisoryByCve) {
  if (!Array.isArray(records) || records.length === 0) return records;
  if (!advisoryByCve || typeof advisoryByCve !== 'object') return records;
  return records.map((r) => {
    if (!r || typeof r.cveId !== 'string') return r;
    const advisory = advisoryByCve[r.cveId];
    if (!advisory) return r;
    return mergeAdvisoryIntoRecord(r, advisory);
  });
}

// ---------------------------------------------------------------------------
// Coverage status decision (pure).
// ---------------------------------------------------------------------------

/**
 * Compute the public `githubAdvisoryStatus` from the cache
 * and the dataset's CVE list. The contract:
 *
 *   - enriched === 0            → 'unavailable'
 *   - enriched === total        → 'available'
 *   - 0 < enriched < total      → 'partial'
 *
 * Honest: we never claim 'available' while the incremental
 * backfill is incomplete.
 */
export function githubAdvisoryStatusForCoverage(enriched, total) {
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
// Mirrors the `settledAll` pattern used by Vulnrichment, NVD
// and EPSS so the failure semantics match the rest of the
// pipeline: each task runs in isolation, never throws out
// of the worker, and surfaces its outcome via the returned
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
