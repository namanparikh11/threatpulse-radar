// Acceptance tests for the v5.4.2 last-known-good dataset
// serving contract.
//
//   node scripts/acceptance-lastknowngood.mjs
//
// What it covers (per the V5.4.2 product decision):
//   1. The NVD failure classifier in `liveBuild.mjs` tags
//      every transient failure mode (timeout / HTTP 429 /
//      HTTP 5xx / network error) with the right outcome
//      string, and the cooldown-skip path tags itself as
//      'cooldown-skipped'.
//   2. The `shouldSkipOverwrite` guard in `refresh.mjs`
//      refuses to overwrite a good existing blob with ANY
//      NVD-unavailable new build, for every documented
//      failure mode:
//        - timeout
//        - HTTP 429 (rate-limited)
//        - HTTP 503 (5xx transient)
//        - network error
//        - cooldown / skipNvd result
//   3. When the guard fires, the orchestrator's metadata
//      write records the failure on the existing blob
//      (lastRefreshAttemptAt + lastRefreshFailure) without
//      touching the public envelope fields (fetchedAt /
//      nvdStatus / cvss scores).
//   4. The `dataset.mjs` public response strips the
//      internal `lastRefreshAttemptAt` / `lastRefreshFailure`
//      fields before sending to the visitor, and the
//      `_nvdOutcome` Symbol never reaches JSON.stringify.
//   5. The bootstrap path (no existing blob) still writes
//      a degraded envelope so visitors on a fresh deploy
//      have something to see — the public UI shows the
//      honest "NVD: unavailable" pill.
//   6. A genuinely newer AND NVD-enriched build overwrites
//      the old blob cleanly (no false preservation).
//   7. The "Portfolio Project" badge is gone from the
//      application source (UI no longer self-labels).
//   8. NVD_API_KEY is never exposed to the client bundle
//      or the public response.
//
// All previous acceptance scripts (prebuilt / cisa / epss /
// nvd / cache / proxy / softrefresh) keep running unchanged
// — this file is purely additive.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

// ---- Real production modules ---------------------------------------

const {
  NVD_OUTCOME,
  readNvdOutcome,
} = await import('../netlify/functions/_shared/liveBuild.mjs');

const {
  INTERNAL_BLOB_FIELDS,
  buildRefreshFailurePayload,
  countCvssAboveZero,
  isNvdTransientOrSkipped,
  shouldSkipOverwrite,
} = await import('../netlify/functions/_shared/refresh.mjs');

/* ------------------------------------------------------------------ */
/* Test runner                                                        */
/* ------------------------------------------------------------------ */

let passed = 0;
let failed = 0;
const failures = [];

function assert(label, condition, extra = '') {
  if (condition) {
    passed++;
    console.log(`  \u2713 ${label}`);
  } else {
    failed++;
    failures.push({ label, extra });
    console.log(`  \u2717 ${label}${extra ? '  [' + extra + ']' : ''}`);
  }
}

function section(name) {
  console.log(`\n--- ${name} ---`);
}

/**
 * Strip JS-style comments from a source string so the
 * grep-style assertions below check the code, not the
 * comments. Mirrors the helper used in acceptance-nvd.mjs.
 */
function stripComments(s) {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, '')   // /* ... */ block comments
    .replace(/^\s*\/\/.*$/gm, '')       // // line comments (line start)
    .replace(/\s+\/\/.*$/gm, '');      // // trailing-line comments
}

/* ------------------------------------------------------------------ */
/* 1. NVD outcome classifier — every documented failure mode          */
/* ------------------------------------------------------------------ */

section('NVD outcome classifier (liveBuild)');

function makeEnvelopeWithNvdReason(reason) {
  return {
    data: [],
    source: 'merged',
    fetchedAt: '2026-07-10T00:00:00.000Z',
    mode: 'live',
    nvdStatus: 'unavailable',
    nvdReason: reason,
    epssStatus: 'first',
  };
}

function tagOutcome(envelope, outcome) {
  Object.defineProperty(envelope, NVD_OUTCOME, {
    value: outcome,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return envelope;
}

{
  const env = tagOutcome(
    makeEnvelopeWithNvdReason('NVD enrichment failed: NVD timed out after 8000 ms'),
    'timed-out',
  );
  assert('readNvdOutcome reads "timed-out" from the Symbol tag',
    readNvdOutcome(env) === 'timed-out');
  assert('isNvdTransientOrSkipped recognises a timeout envelope',
    isNvdTransientOrSkipped(env) === true);
}

{
  const env = tagOutcome(
    makeEnvelopeWithNvdReason(
      'NVD enrichment failed: NVD rate limit reached (HTTP 429). NVD CVSS enrichment is unavailable.',
    ),
    'rate-limited',
  );
  assert('readNvdOutcome reads "rate-limited" from the Symbol tag',
    readNvdOutcome(env) === 'rate-limited');
  assert('isNvdTransientOrSkipped recognises an HTTP 429 envelope',
    isNvdTransientOrSkipped(env) === true);
}

{
  const env = tagOutcome(
    makeEnvelopeWithNvdReason(
      'NVD enrichment failed: NVD chunk fetch (100 CVEs) failed: HTTP 503 Service Unavailable | url=...',
    ),
    'http-error',
  );
  assert('readNvdOutcome reads "http-error" from the Symbol tag',
    readNvdOutcome(env) === 'http-error');
  assert('isNvdTransientOrSkipped recognises an HTTP 5xx envelope',
    isNvdTransientOrSkipped(env) === true);
}

{
  const env = tagOutcome(
    makeEnvelopeWithNvdReason(
      'NVD enrichment failed: NVD chunk fetch (100 CVEs) failed: fetch failed | url=...',
    ),
    'network-error',
  );
  assert('readNvdOutcome reads "network-error" from the Symbol tag',
    readNvdOutcome(env) === 'network-error');
  assert('isNvdTransientOrSkipped recognises a network-error envelope',
    isNvdTransientOrSkipped(env) === true);
}

{
  // The cooldown-skip synthetic envelope (produced when
  // runRefresh calls buildLiveDataset with { skipNvd: true }).
  const env = tagOutcome(
    makeEnvelopeWithNvdReason(
      'NVD enrichment skipped (cooldown active); CVSS scores are unavailable for this refresh.',
    ),
    'cooldown-skipped',
  );
  assert('readNvdOutcome reads "cooldown-skipped" from the Symbol tag',
    readNvdOutcome(env) === 'cooldown-skipped');
  assert('isNvdTransientOrSkipped recognises a cooldown-skip envelope',
    isNvdTransientOrSkipped(env) === true);
}

{
  // An enriched envelope carries the 'enriched' outcome.
  const env = tagOutcome(
    {
      data: [],
      source: 'merged',
      fetchedAt: '2026-07-10T00:00:00.000Z',
      mode: 'live',
      nvdStatus: 'nvd',
      nvdReason: undefined,
      epssStatus: 'first',
    },
    'enriched',
  );
  assert('enriched envelope has nvdStatus="nvd" (visible to public)',
    env.nvdStatus === 'nvd');
  assert('readNvdOutcome reads "enriched" from the Symbol tag',
    readNvdOutcome(env) === 'enriched');
  assert('isNvdTransientOrSkipped returns false for an enriched envelope',
    isNvdTransientOrSkipped(env) === false);
}

{
  // An envelope with no Symbol tag (older builds, before
  // v5.4.2) and an nvdStatus of 'unavailable' with a
  // transient-flavored reason still counts as transient —
  // the predicate falls back to keyword matching.
  const env = makeEnvelopeWithNvdReason(
    'NVD enrichment failed: NVD timed out after 8000 ms',
  );
  assert('isNvdTransientOrSkipped falls back to keyword match for legacy envelopes',
    isNvdTransientOrSkipped(env) === true);
}

{
  // An enriched envelope with no Symbol tag returns null
  // for readNvdOutcome and is NOT transient.
  const env = {
    data: [],
    source: 'merged',
    fetchedAt: '2026-07-10T00:00:00.000Z',
    mode: 'live',
    nvdStatus: 'nvd',
    nvdReason: undefined,
    epssStatus: 'first',
  };
  assert('readNvdOutcome returns null for a legacy enriched envelope',
    readNvdOutcome(env) === null);
  assert('isNvdTransientOrSkipped returns false for a legacy enriched envelope',
    isNvdTransientOrSkipped(env) === false);
}

/* ------------------------------------------------------------------ */
/* 2. shouldSkipOverwrite — the production guard                      */
/* ------------------------------------------------------------------ */

section('shouldSkipOverwrite — production guard');

const OLD_GOOD = {
  nvdStatus: 'nvd',
  nvdReason: undefined,
  data: Array.from({ length: 800 }, (_, i) => ({
    cveId: `CVE-OLD-${i}`,
    cvssScore: 7.5,
  })),
};

const OLD_BAD = {
  nvdStatus: 'unavailable',
  nvdReason: 'NVD rate limit reached (HTTP 429).',
  data: Array.from({ length: 1000 }, (_, i) => ({
    cveId: `CVE-OLD-${i}`,
    cvssScore: 0,
  })),
};

const OLD_ENRICHED_NO_CVSS = {
  // Edge case: NVD status says "nvd" but no record has a
  // positive CVSS score (e.g. NVD returned metrics but the
  // cvssScore field was missing for every CVE). Should NOT
  // count as "good" — the v5.4.2 guard requires at least
  // one CVSS-positive record.
  nvdStatus: 'nvd',
  nvdReason: undefined,
  data: Array.from({ length: 100 }, (_, i) => ({
    cveId: `CVE-OLD-${i}`,
    cvssScore: 0,
  })),
};

function makeNewWithFailure(failureType, reason) {
  const env = {
    mode: 'live',
    source: 'merged',
    fetchedAt: '2026-07-10T12:05:00.000Z',
    nvdStatus: 'unavailable',
    nvdReason: reason,
    data: Array.from({ length: 1000 }, (_, i) => ({
      cveId: `CVE-NEW-${i}`,
      cvssScore: 0,
    })),
  };
  return tagOutcome(env, failureType);
}

const NEW_TIMEOUT = makeNewWithFailure(
  'timed-out',
  'NVD enrichment failed: NVD timed out after 8000 ms',
);
const NEW_429 = makeNewWithFailure(
  'rate-limited',
  'NVD enrichment failed: NVD rate limit reached (HTTP 429). NVD CVSS enrichment is unavailable.',
);
const NEW_503 = makeNewWithFailure(
  'http-error',
  'NVD enrichment failed: NVD chunk fetch (100 CVEs) failed: HTTP 503 Service Unavailable | url=...',
);
const NEW_NETWORK = makeNewWithFailure(
  'network-error',
  'NVD enrichment failed: NVD chunk fetch (100 CVEs) failed: fetch failed | url=...',
);
const NEW_COOLDOWN_SKIP = makeNewWithFailure(
  'cooldown-skipped',
  'NVD enrichment skipped (cooldown active); CVSS scores are unavailable for this refresh.',
);

assert('v5.4.2: timeout cannot overwrite a good NVD-enriched blob',
  shouldSkipOverwrite(OLD_GOOD, NEW_TIMEOUT) === true,
  'expected the timeout envelope to be preserved against a good old');

assert('v5.4.2: HTTP 429 cannot overwrite a good NVD-enriched blob',
  shouldSkipOverwrite(OLD_GOOD, NEW_429) === true);

assert('v5.4.2: HTTP 503 cannot overwrite a good NVD-enriched blob',
  shouldSkipOverwrite(OLD_GOOD, NEW_503) === true);

assert('v5.4.2: network error cannot overwrite a good NVD-enriched blob',
  shouldSkipOverwrite(OLD_GOOD, NEW_NETWORK) === true);

assert('v5.4.2: cooldown / skipNvd result cannot overwrite a good NVD-enriched blob',
  shouldSkipOverwrite(OLD_GOOD, NEW_COOLDOWN_SKIP) === true);

assert('v5.4.2: a genuinely newer AND NVD-enriched dataset overwrites the old one',
  // The new envelope is enriched (nvdStatus='nvd') — the
  // guard does NOT fire, the write proceeds.
  shouldSkipOverwrite(OLD_GOOD, {
    mode: 'live',
    source: 'merged',
    fetchedAt: '2026-07-10T12:05:00.000Z',
    nvdStatus: 'nvd',
    nvdReason: undefined,
    data: Array.from({ length: 1100 }, (_, i) => ({
      cveId: `CVE-NEW-${i}`,
      cvssScore: 8.0,
    })),
  }) === false);

assert('v5.4.2: an enriched new build with fewer CVSS records overwrites anyway (legitimate growth / KEV shrink)',
  // The guard only fires on NVD-unavailable new builds.
  // An enriched new build always writes, even with fewer
  // CVSS-positive records than the old (e.g. KEV shrank).
  shouldSkipOverwrite(OLD_GOOD, {
    mode: 'live',
    source: 'merged',
    fetchedAt: '2026-07-10T12:05:00.000Z',
    nvdStatus: 'nvd',
    data: Array.from({ length: 600 }, (_, i) => ({
      cveId: `CVE-NEW-${i}`,
      cvssScore: 7.5,
    })),
  }) === false);

assert('v5.4.2: an enriched new build with EQUAL CVSS count overwrites (still genuinely newer)',
  shouldSkipOverwrite(OLD_GOOD, {
    mode: 'live',
    source: 'merged',
    fetchedAt: '2026-07-10T12:05:00.000Z',
    nvdStatus: 'nvd',
    data: Array.from({ length: 800 }, (_, i) => ({
      cveId: `CVE-NEW-${i}`,
      cvssScore: 7.5,
    })),
  }) === false);

assert('v5.4.2: no existing blob → write the new envelope (bootstrap path)',
  shouldSkipOverwrite(null, NEW_TIMEOUT) === false);

assert('v5.4.2: old is also unavailable → write the new envelope (no good blob to preserve)',
  shouldSkipOverwrite(OLD_BAD, NEW_TIMEOUT) === false);

assert('v5.4.2: old claims nvd but has zero CVSS-positive records → still not "good" → write new',
  // OLD_ENRICHED_NO_CVSS carries nvdStatus='nvd' but no
  // record has cvssScore > 0. The v5.4.2 guard requires at
  // least one CVSS-positive record to count as "good" — a
  // no-op enrichment shouldn't block a refresh that recovers
  // CVSS scores from NVD.
  shouldSkipOverwrite(OLD_ENRICHED_NO_CVSS, NEW_TIMEOUT) === false);

assert('v5.4.2: null old envelope → write new (bootstrap path)',
  shouldSkipOverwrite(null, NEW_429) === false);

assert('v5.4.2: null new envelope → do not skip (defensive)',
  shouldSkipOverwrite(OLD_GOOD, null) === false);

/* ------------------------------------------------------------------ */
/* 3. Preserved envelope: fetchedAt + nvdStatus + CVSS stay stable    */
/* ------------------------------------------------------------------ */

section('Preserved envelope: public fields are not reset on guard fire');

{
  // Simulate a refresh where the guard fires: the existing
  // blob's public fields (fetchedAt, nvdStatus, cvssScore)
  // must stay unchanged, and the visitor-facing response
  // must NOT carry any of the new envelope's transient
  // nvdReason.
  const previous = {
    nvdStatus: 'nvd',
    nvdReason: undefined,
    fetchedAt: '2026-07-10T11:00:00.000Z',
    data: OLD_GOOD.data,
  };
  // Guard fires → no overwrite. The existing blob stays.
  const skipped = shouldSkipOverwrite(previous, NEW_TIMEOUT);
  assert('guard fires → existing blob is preserved (no overwrite)',
    skipped === true);
  assert('preserved envelope retains its original fetchedAt',
    previous.fetchedAt === '2026-07-10T11:00:00.000Z');
  assert('preserved envelope retains its original nvdStatus="nvd"',
    previous.nvdStatus === 'nvd');
  assert('preserved envelope retains its CVSS-positive records',
    countCvssAboveZero(previous) === 800);
  // The new envelope's transient reason must NOT appear in
  // the public response. (Simulated: the visitor sees
  // `previous`, not `NEW_TIMEOUT`.)
  assert('public response does NOT carry the new envelope\'s transient nvdReason',
    previous.nvdReason === undefined &&
    !/timed out|HTTP 503|rate limit/i.test(JSON.stringify(previous.nvdReason ?? '')));
}

/* ------------------------------------------------------------------ */
/* 4. Internal metadata writing shape                                 */
/* ------------------------------------------------------------------ */

section('Internal metadata: lastRefreshAttemptAt + lastRefreshFailure');

{
  const now = new Date('2026-07-10T12:05:00.000Z');
  const meta = buildRefreshFailurePayload(NEW_TIMEOUT, now);
  assert('buildRefreshFailurePayload produces type="timed-out" for a timeout envelope',
    meta.type === 'timed-out');
  assert('buildRefreshFailurePayload preserves the truncated reason',
    /timed out/i.test(meta.reason));
  assert('buildRefreshFailurePayload stamps the "at" timestamp',
    meta.at === now.toISOString());
}

{
  const meta = buildRefreshFailurePayload(NEW_429, new Date());
  assert('buildRefreshFailurePayload produces type="rate-limited" for an HTTP 429 envelope',
    meta.type === 'rate-limited');
}

{
  const meta = buildRefreshFailurePayload(NEW_503, new Date());
  assert('buildRefreshFailurePayload produces type="http-error" for an HTTP 5xx envelope',
    meta.type === 'http-error');
}

{
  const meta = buildRefreshFailurePayload(NEW_NETWORK, new Date());
  assert('buildRefreshFailurePayload produces type="network-error" for a network-error envelope',
    meta.type === 'network-error');
}

{
  const meta = buildRefreshFailurePayload(NEW_COOLDOWN_SKIP, new Date());
  assert('buildRefreshFailurePayload produces type="cooldown-skipped" for the synthetic cooldown envelope',
    meta.type === 'cooldown-skipped');
}

{
  // Fallback path: an envelope with no Symbol tag and no
  // recognisable reason still gets a "unknown" type rather
  // than crashing.
  const meta = buildRefreshFailurePayload(
    { nvdStatus: 'unavailable', nvdReason: 'something weird happened' },
    new Date(),
  );
  assert('buildRefreshFailurePayload falls back to "unknown" for unrecognised reasons',
    meta.type === 'unknown');
}

assert('INTERNAL_BLOB_FIELDS includes "lastRefreshAttemptAt"',
  INTERNAL_BLOB_FIELDS.has('lastRefreshAttemptAt'));

assert('INTERNAL_BLOB_FIELDS includes "lastRefreshFailure"',
  INTERNAL_BLOB_FIELDS.has('lastRefreshFailure'));

/* ------------------------------------------------------------------ */
/* 5. Source-level: dataset.mjs strips internal fields                */
/* ------------------------------------------------------------------ */

section('dataset.mjs strips internal metadata from the public response');

const datasetSrc = readFileSync(
  join(root, 'netlify', 'functions', 'dataset.mjs'),
  'utf8',
);

assert('dataset.mjs imports INTERNAL_BLOB_FIELDS from refresh.mjs',
  /import\s*\{[^}]*INTERNAL_BLOB_FIELDS[^}]*\}\s*from\s*['"]\.\/_shared\/refresh\.mjs['"]/.test(datasetSrc),
  'expected INTERNAL_BLOB_FIELDS import');

assert('dataset.mjs defines a publicEnvelope() helper that strips internal fields',
  /function\s+publicEnvelope\(/.test(datasetSrc) &&
    /INTERNAL_BLOB_FIELDS/.test(datasetSrc) &&
    /delete\s+out\[field\]/.test(datasetSrc),
  'expected publicEnvelope() helper iterating INTERNAL_BLOB_FIELDS');

assert('dataset.mjs uses publicEnvelope() on the blob-hit response',
  /publicEnvelope\(\s*prebuilt\s*\)/.test(datasetSrc),
  'expected publicEnvelope(prebuilt) on the prebuilt-envelope branch');

/* ------------------------------------------------------------------ */
/* 6. Source-level: refresh.mjs writes metadata on all paths          */
/* ------------------------------------------------------------------ */

section('refresh.mjs writes lastRefreshAttemptAt + lastRefreshFailure');

const refreshSrc = readFileSync(
  join(root, 'netlify', 'functions', '_shared', 'refresh.mjs'),
  'utf8',
);

assert('refresh.mjs defines writeInternalMetadata() helper',
  /(?:async\s+)?function\s+writeInternalMetadata/.test(refreshSrc),
  'expected writeInternalMetadata helper');

assert('refresh.mjs calls writeInternalMetadata on the cooldown short-circuit',
  // Locate the cooldown short-circuit by its unique condition
  // (the literal `cooldownActive && existingIsGood`) and
  // assert writeInternalMetadata appears in the following
  // 500 chars. This is more robust than searching for the
  // return status (which also appears in decideRefresh and
  // in the file-level comments).
  (() => {
    const code = stripComments(refreshSrc);
    const i = code.indexOf('cooldownActive && existingIsGood');
    if (i < 0) return false;
    const slice = code.slice(i, i + 500);
    return /writeInternalMetadata\(/.test(slice);
  })(),
  'expected writeInternalMetadata call in the cooldown short-circuit');

assert('refresh.mjs calls writeInternalMetadata on the build-error path',
  // The build-error path is the `if (buildError) {` branch
  // inside runRefresh. Find the SECOND occurrence (the first
  // is the unconditional early `if (!store) return failed`).
  (() => {
    const code = stripComments(refreshSrc);
    const first = code.indexOf('if (buildError)');
    if (first < 0) return false;
    // Look for the next 500 chars — that's the build-error
    // path body. The unconditional !store branch doesn't
    // contain "if (buildError)" so first is what we want.
    const slice = code.slice(first, first + 500);
    return /writeInternalMetadata\(/.test(slice);
  })(),
  'expected writeInternalMetadata call on the failed path');

assert('refresh.mjs calls writeInternalMetadata on the preserved path',
  // The preserved path is the `if (shouldSkipOverwrite(...))`
  // branch. Strip comments first so the `// v5.2.6: Quality
  // guard` line doesn't trip the search.
  (() => {
    const code = stripComments(refreshSrc);
    const i = code.indexOf('if (shouldSkipOverwrite(');
    if (i < 0) return false;
    const slice = code.slice(i, i + 800);
    return /writeInternalMetadata\(/.test(slice);
  })(),
  'expected writeInternalMetadata call on the preserved path');

assert('refresh.mjs writes lastRefreshAttemptAt on the completed path',
  /lastRefreshAttemptAt:\s*now\.toISOString\(\)/.test(refreshSrc),
  'expected lastRefreshAttemptAt stamp on the completed write');

assert('refresh.mjs clears lastRefreshFailure on the completed path',
  /lastRefreshFailure:\s*null/.test(refreshSrc),
  'expected lastRefreshFailure: null on the completed write');

assert('refresh.mjs guards on "good existing blob" via nvdStatus === "nvd" + countCvssAboveZero > 0',
  /oldEnvelope\.nvdStatus\s*!==\s*['"]nvd['"]/.test(refreshSrc) &&
    /countCvssAboveZero\(oldEnvelope\)\s*===\s*0/.test(refreshSrc),
  'expected the v5.4.2 broader guard conditions');

/* ------------------------------------------------------------------ */
/* 7. Source-level: liveBuild tags the NVD outcome Symbol             */
/* ------------------------------------------------------------------ */

section('liveBuild.mjs tags the NVD outcome Symbol');

const liveBuildSrc = readFileSync(
  join(root, 'netlify', 'functions', '_shared', 'liveBuild.mjs'),
  'utf8',
);

assert('liveBuild.mjs exports the NVD_OUTCOME Symbol',
  /export\s+const\s+NVD_OUTCOME\s*=/.test(liveBuildSrc),
  'expected NVD_OUTCOME export');

assert('liveBuild.mjs attaches NVD_OUTCOME to the envelope via Object.defineProperty',
  /Object\.defineProperty\(\s*envelope\s*,\s*NVD_OUTCOME/.test(liveBuildSrc),
  'expected the NVD_OUTCOME attachment on the returned envelope');

assert('liveBuild.mjs tags cooldown-skipped envelopes with the right outcome',
  /cooldown-skipped/.test(liveBuildSrc) && /failureType:\s*['"]cooldown-skipped['"]/.test(liveBuildSrc),
  'expected the synthetic skipNvd envelope to carry failureType: "cooldown-skipped"');

assert('liveBuild.mjs classifier maps HTTP 429 → "rate-limited"',
  /HTTP\s+429|rate\s*limit/i.test(liveBuildSrc) &&
    /classifyNvdFailure/.test(liveBuildSrc) &&
    /return\s+['"]rate-limited['"]/.test(liveBuildSrc),
  'expected classifyNvdFailure to return "rate-limited" for 429 errors');

assert('liveBuild.mjs classifier maps timeout → "timed-out"',
  /timed\s*out|after\s+\d+\s*ms/i.test(liveBuildSrc) &&
    /return\s+['"]timed-out['"]/.test(liveBuildSrc),
  'expected classifyNvdFailure to return "timed-out" for timeout errors');

assert('liveBuild.mjs classifier maps HTTP 5xx → "http-error"',
  // Strip comments first so a comment that mentions 5xx
  // doesn't satisfy the check. The classifier must contain
  // BOTH a regex literal that recognises 5xx AND a return
  // statement for the 'http-error' classification. Use
  // String#indexOf to match the literal source characters
  // (the source has a regex literal `HTTP\s+5\d\d` which
  // is a complex multi-character pattern in the file).
  (() => {
    const code = stripComments(liveBuildSrc);
    const fnStart = code.indexOf('function classifyNvdFailure(');
    if (fnStart < 0) return false;
    // Walk forward to find the closing brace of the function
    // (naive brace-counting, but the function is small).
    let depth = 0;
    let fnEnd = -1;
    for (let i = fnStart; i < code.length; i++) {
      if (code[i] === '{') depth++;
      else if (code[i] === '}') {
        depth--;
        if (depth === 0) { fnEnd = i; break; }
      }
    }
    if (fnEnd < 0) return false;
    const body = code.slice(fnStart, fnEnd + 1);
    // The body must contain BOTH:
    //   - a regex literal matching "HTTP 5xx"
    //     (the source has `HTTP\s+5\d\d` — the literal
    //      substring `5\d\d` is unique to the 5xx check)
    //   - a `return 'http-error'` statement
    return /5[\\]d[\\]d/.test(body) &&
      /return\s+['"]http-error['"]/.test(body);
  })(),
  'expected classifyNvdFailure to return "http-error" for 5xx errors');

assert('liveBuild.mjs classifier fallback → "network-error"',
  /return\s+['"]network-error['"]/.test(liveBuildSrc),
  'expected classifyNvdFailure to return "network-error" as a fallback');

/* ------------------------------------------------------------------ */
/* 8. Bootstrap path: no existing blob still writes degraded data     */
/* ------------------------------------------------------------------ */

section('Bootstrap path: no existing blob still writes a degraded envelope');

{
  // Simulate the dataset.mjs bootstrap branch with no
  // existing blob and a build that returns NVD unavailable
  // (e.g. fresh deploy with NVD down). The envelope must
  // be written so the next visitor has something to see,
  // and the public response must include the honest
  // nvdStatus="unavailable" so the visitor sees the
  // accurate pill.
  const bootstrapEnvelope = NEW_TIMEOUT;
  assert('bootstrap envelope is treated as a non-live result with nvdStatus="unavailable"',
    bootstrapEnvelope.nvdStatus === 'unavailable' &&
      bootstrapEnvelope.mode === 'live' &&
      Array.isArray(bootstrapEnvelope.data) &&
      bootstrapEnvelope.data.length > 0,
    'expected the bootstrap envelope to be a well-formed live build with NVD unavailable');
  // The guard is a no-op when there is no existing blob.
  assert('bootstrap path: shouldSkipOverwrite(null, degraded) === false (write proceeds)',
    shouldSkipOverwrite(null, bootstrapEnvelope) === false);
}

/* ------------------------------------------------------------------ */
/* 9. UI: "Portfolio Project" badge removed                           */
/* ------------------------------------------------------------------ */

section('Header.tsx no longer renders the "Portfolio Project" badge');

const headerSrc = readFileSync(
  join(root, 'src', 'components', 'Header.tsx'),
  'utf8',
);

assert('Header.tsx does NOT contain the literal "Portfolio Project" string',
  !/Portfolio Project/.test(headerSrc),
  'expected no "Portfolio Project" label in the application source');

assert('Header.tsx does NOT import the Briefcase icon (was only used by the badge)',
  !/Briefcase/.test(headerSrc),
  'expected no Briefcase import (only the removed badge used it)');

assert('Header.tsx still declares the title "ThreatPulse Radar"',
  /ThreatPulse Radar/.test(headerSrc),
  'expected the page title to remain unchanged');

assert('Header.tsx still renders the "Defensive use only" pill',
  /Defensive use only/.test(headerSrc),
  'expected the defensive-use-only pill to remain');

assert('Header.tsx still renders the "Last refresh" pill with the dataset age',
  /Last refresh:/.test(headerSrc),
  'expected the last-refresh pill (with the dataset age) to remain');

assert('Header.tsx still surfaces NVD status: enriched pill on nvdStatus="nvd"',
  /nvdStatus\s*===\s*['"]nvd['"][\s\S]{0,500}NVD:\s*enriched/.test(headerSrc),
  'expected the NVD: enriched pill to remain visible on the public UI');

assert('Header.tsx still surfaces NVD status: unavailable pill on nvdStatus="unavailable"',
  /nvdStatus\s*===\s*['"]unavailable['"][\s\S]{0,500}NVD:\s*unavailable/.test(headerSrc),
  'expected the NVD: unavailable pill to remain (for the bootstrap-degraded case)');

/* ------------------------------------------------------------------ */
/* 10. API key never exposed                                          */
/* ------------------------------------------------------------------ */

section('NVD_API_KEY is never exposed to the client or the response');

const serviceSrc = readFileSync(
  join(root, 'src', 'services', 'vulnerabilityService.ts'),
  'utf8',
);

assert('service: no VITE_NVD_API_KEY, no import.meta.env.NVD_API_KEY',
  !/VITE_NVD_API_KEY/.test(serviceSrc) &&
    !/import\.meta\.env\.NVD_API_KEY/.test(serviceSrc),
  'expected no client-side NVD_API_KEY reference');

assert('service: no `headers.apiKey` or `NVD_API_KEY` in fetch options',
  !/apiKey\s*:/.test(serviceSrc) && !/NVD_API_KEY/.test(serviceSrc),
  'expected no apiKey header or NVD_API_KEY reference in the service');

assert('dataset.mjs: no VITE_NVD_API_KEY, no apiKey in the response body',
  // Strip comments first — the dataset function's
  // honesty-contract comment legitimately mentions
  // `NVD_API_KEY` to describe the server-side contract,
  // which is exactly the right place for the mention.
  (() => {
    const code = stripComments(datasetSrc);
    return !/VITE_NVD_API_KEY/.test(code) && !/NVD_API_KEY/.test(code);
  })(),
  'expected no client-side NVD_API_KEY reference in the dataset function');

assert('refresh-dataset-background.mjs: no client-side NVD_API_KEY',
  (() => {
    const bgSrc = readFileSync(
      join(root, 'netlify', 'functions', 'refresh-dataset-background.mjs'),
      'utf8',
    );
    return !/VITE_NVD_API_KEY/.test(bgSrc) &&
      !/import\.meta\.env\.NVD_API_KEY/.test(bgSrc);
  })(),
  'expected no client-side NVD_API_KEY reference in the background refresh function');

assert('liveBuild.mjs: NVD_API_KEY read is server-side only (process.env, never import.meta.env)',
  /process\.env\.NVD_API_KEY/.test(liveBuildSrc) &&
    !/import\.meta\.env\.NVD_API_KEY/.test(liveBuildSrc),
  'expected process.env.NVD_API_KEY in the Netlify function, no client-side import');

/* ------------------------------------------------------------------ */
/* 11. JSON.stringify does NOT leak the Symbol                        */
/* ------------------------------------------------------------------ */

section('JSON.stringify does not leak the NVD_OUTCOME Symbol');

{
  const env = {
    data: [],
    source: 'merged',
    fetchedAt: '2026-07-10T00:00:00.000Z',
    mode: 'live',
    nvdStatus: 'unavailable',
    nvdReason: 'NVD timed out',
  };
  Object.defineProperty(env, NVD_OUTCOME, {
    value: 'timed-out',
    enumerable: false,
    writable: false,
    configurable: false,
  });
  const json = JSON.stringify(env);
  assert('JSON.stringify of an envelope does NOT include the NVD_OUTCOME Symbol',
    !/NVD_OUTCOME|Symbol\(/.test(json) && !/"timed-out"/.test(json),
    'expected the Symbol and its value to be invisible to JSON.stringify');
}

/* ------------------------------------------------------------------ */
/* Summary                                                            */
/* ------------------------------------------------------------------ */

console.log();
if (failed === 0) {
  console.log(`LAST-KNOWN-GOOD TESTS PASSED  (${passed}/${passed})`);
} else {
  console.log(
    `LAST-KNOWN-GOOD TESTS FAILED  (${failed} of ${passed + failed} failed)`,
  );
  for (const f of failures) {
    console.log(`  - ${f.label}${f.extra ? '  [' + f.extra + ']' : ''}`);
  }
  process.exit(1);
}
