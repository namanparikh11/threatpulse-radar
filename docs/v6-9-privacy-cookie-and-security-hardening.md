# V6.9 — Privacy, Cookie Audit and Security Hardening

This document records the V6.9 privacy, cookie and security
posture of ThreatPulse Radar. It is the single source of
truth for the audit results, the consent model decision,
the browser-storage and third-party inventory, the security
header matrix, the public route matrix, the import / export
trust boundary, the responsible-disclosure process, the
production verification checklist and the rollback conditions.

## Status

This branch is **NOT claimed production-ready**. The
documentation in this branch ships with `<!-- OPERATOR: -->`
placeholders for every field that requires real legal /
contact / address / retention input. The branch is
**code-ready** but the **operator legal/contact details
block deployment** until each placeholder is replaced
with a real value. See section 11 for the exact list.

## 1. Cookie and storage audit (PHASE 1)

The audit was performed against the production-reachable
code paths and the built `dist/` output. The
machine-readable inventory is encoded in
`scripts/verify-v69-privacy-and-runtime-hardening.mjs`; the
assertions cover every category listed below.

### Cookies

| Category | Result |
| --- | --- |
| `document.cookie` (read) | **absent** in `src/**`, `hostinger/**`, `server/**`, `jobs/**` |
| `Set-Cookie` (set) | **absent** in `src/**`, `hostinger/**`, `server/**`, `jobs/**` |
| `cookieStore` (Cookie Store API) | **absent** |
| `Set-Cookie` HTTP response header (ThreatPulse code) | **absent** in `hostinger/static.mjs` and the portable `server/` routes |
| `Cookie` HTTP request header | **not set** by the browser; not consumed server-side |
| **Audit claim** | **No application-controlled cookies are set or read by ThreatPulse code.** |

The audit claim is bounded to *application-controlled*
cookies. **The hosting platform (Hostinger) and any
upstream CDN / edge layer are out of scope for the
static source audit.** A deployment is NOT considered
complete until the operator has run the live
verification checklist in section 10 to confirm that
the platform's edge does not add its own cookies.

### Browser storage

| Storage | Used by | Purpose | Necessary for the documented feature? | Lifetime |
| --- | --- | --- | --- | --- |
| `localStorage` | `src/services/datasetCache.ts` | A 1-hour TTL cache of the public vulnerability dataset, so a page reload within the same browser does not re-hit `/api/dataset` | Yes — the dataset cache is a documented V4 cost-control feature | 1 hour TTL, expired on `forceRefresh` |
| `localStorage` | `src/reports/history.mjs` | A single boolean flag (`THREATPULSE_HISTORY_ENABLED`) that controls whether the local report history is written to IndexedDB. This is the user's own preference, not PII. | Yes — it is a user-controlled toggle for the V6.5 reports feature | persistent until the user changes the setting or clears site data |
| `sessionStorage` | — | **absent** | n/a | n/a |
| `IndexedDB` (4 databases, one per V6.4–V6.7 surface) | `src/workspace/IndexedDBWorkspaceAdapter.mjs`; `src/environment/IndexedDBEnvironmentAdapter.mjs`; `src/remediation/IndexedDBRemediationAdapter.mjs`; `src/reports/history.mjs` | Per-CVE triage (workspace); local assets and SBOM correlation (environment); remediation plans, tasks, evidence and ledger (remediation); report history (reports) | Yes — these are the V6.4–V6.7 local-only features. They are the documented public-intelligence complement and the only way to retain triage state across reloads | persistent until the user explicitly clears site data or the operator-issued "Clear" action is invoked |
| `Cache Storage` | — | **absent** | n/a | n/a |
| `Service Worker` | — | **absent** | n/a | n/a |
| `BroadcastChannel` | `src/state/WorkspaceContext.tsx`, `src/state/EnvironmentContext.tsx`, `src/state/RemediationContext.tsx`, the corresponding IndexedDB adapters | Local-only multi-tab synchronization. Pure local broadcast; does not touch the network. | Yes — V6.4–V6.7 explicitly surface "Open in another tab" behaviour | ephemeral (in-memory) |

### Third-party browser dependencies

| Category | Result |
| --- | --- |
| Third-party `<script src="https://...">` in `index.html` | **absent** |
| Third-party `<link rel="stylesheet" href="https://...">` in `index.html` | **absent** |
| Third-party fonts (e.g. `fonts.googleapis.com`, `fonts.gstatic.com`, `use.typekit.net`) | **absent** |
| Third-party images, iframes, embeds, objects | **absent** |
| `navigator.sendBeacon` | **absent** |
| `new Image()`-based pixel tracking | **absent** |
| Fingerprinting APIs (Canvas / AudioContext / WebGL / Battery) | **absent** |
| Analytics SDKs (Google Analytics, GA4, GTM, Mixpanel, Amplitude, Sentry, PostHog, Hotjar, FullStory, Matomo, Plausible, Cloudflare Insights, Segment) | **absent** |
| `gtag(`, `fbq(`, `dataLayer.push(` | **absent** |
| `WebSocket`, `EventSource` | **absent** in the browser; both are only opened from the Node server-side when the `jobs/` refresh runs |
| External `fetch()` targets in `src/**` | **only the four documented live-data fallback origins**: CISA KEV (`www.cisa.gov`), NVD (`services.nvd.nist.gov`), FIRST EPSS (`api.first.org`), OSV (`osv.dev`). All four are reached **only when the primary `/api/dataset` route is unavailable**, and a 25 s per-call timeout guarantees a quick fall-through to the prebuilt dataset on the next cycle. |

### Browser-direct external requests

The only browser-direct third-party `fetch()` calls that
can fire from the production bundle are the **live-data
fallback** in `vulnerabilityService.ts#tryBrowserDirectFetch`.
This is **not** a tracking path — it is the same upstream
source pipeline that the Hostinger managed scheduler runs
server-side every 30 minutes to populate the prebuilt
dataset. The browser-direct path exists so the dashboard
can still load data when the visitor's network cannot
reach the Hostinger production domain (e.g. inside a
firewalled enterprise environment).

The user's IP is exposed to those third parties only
during the fallback, and the request contains no
authentication, no identifying cookies and no fingerprint
beyond the standard `User-Agent` and `Accept` headers.
No data is sent to the third parties that the user
controls.

## 2. Consent model decision (PHASE 2)

**Decision: A. NO NON-ESSENTIAL COOKIES OR STORAGE.**

The audit found no application-controlled cookies and no
non-essential storage. Every browser storage primitive
in use is necessary for a documented product feature
(the dataset TTL cache, the V6.4 workspace, the V6.6
environment, the V6.7 remediation, the V6.5 reports,
the multi-tab BroadcastChannel sync). No consent banner
is implemented and none is required.

The disclosure pages (`/legal/privacy.html`,
`/legal/cookies.html`) explain the storage, the
in-browser data lifecycle, the deletion mechanisms, and
the operator's contact channels, so a visitor can make
an informed choice about which features to enable.

The V6.9 milestone is documentation + hardening, not a
consent-management-platform integration.

## 3. Privacy transparency (PHASE 3)

Three static documentation pages are produced and shipped
to the production deployment:

- `public/legal/privacy.html` — full privacy notice with
  the documented operator, hosting, retention, recipient
  and legal-basis wording.
- `public/legal/cookies.html` — the cookie / storage
  audit result, the consent model decision and the
  evidence basis for it.
- `public/legal/security.html` — the responsible-
  disclosure policy, supported versions, the report
  format and the good-faith expectations.
- `public/legal/index.html` — a small directory page
  linking the three.
- `public/.well-known/security.txt` — RFC 9116
  responsible-disclosure contact.

### 3.1 Legal-basis wording

The privacy notice uses the following non-absolute
wording, which is suitable for later legal review by
the operator. **The wording is not legal advice.**

- **Server-log legal basis.** "ThreatPulse application
  and security logs are processed to maintain the
  security, availability and integrity of the
  service, detect abuse and diagnose technical errors.
  The intended legal basis is Article 6(1)(f) GDPR
  (legitimate interests of the controller), subject to
  final operator legal review."
- **Local-storage wording.** "Workspace, environment,
  remediation and report information is stored locally
  in the user's browser to provide functions requested
  by the user. ThreatPulse does not receive this
  locally stored information unless the user
  independently chooses to transmit an exported file."

### 3.2 Cookie / tracking wording

The cookie notice uses the bounded claim:

- "No application-controlled cookies are set or read
  by ThreatPulse code."

The audit cannot observe hosting- / platform- / CDN-
/ browser-extension-level cookie behaviour. The
operator MUST run the live verification checklist
(section 10) before declaring the deployment
complete. The application does NOT install a consent
banner.

### 3.3 Operator-supplied information and remaining gaps

The following operator-supplied information is now
in the build:

- **Service provider / data controller:** Naman Parikh.
- **General, privacy and security contact:**
  `contact@namanp.de` (single address for all three).
- **Application-log retention:** 30 days, enforced by
  `hostinger/log-retention.mjs` and the
  `scripts/acceptance-v69-log-retention.mjs` suite.
- **security.txt:** `Expires: 2027-01-24T00:00:00Z`,
  `Canonical: https://threatpulse.namanp.de/.well-
  known/security.txt`,
  `Policy: https://threatpulse.namanp.de/legal/
  security.html`,
  `Preferred-Languages: en, de`.

The following operator input is **still pending**:

- **Public postal address of the data controller.**
  The privacy notice retains an `<!-- OPERATOR:
  public postal address -->` placeholder. The branch
  is NOT production-ready until the operator supplies
  the real public postal address; the V6.9
  verification suite (assertion 19) flags the
  unresolved placeholder.

## 4. Content Security Policy (PHASE 4)

The Content-Security-Policy is generated from the actual
build dependency graph and applied to every public
response by `hostinger/static.mjs#applySecurityHeaders`
(Hostinger) and `netlify.toml` (Netlify rollback-only).

```
default-src 'self';
base-uri 'self';
object-src 'none';
frame-ancestors 'none';
form-action 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
style-src-elem 'self';
style-src-attr 'unsafe-inline';
img-src 'self' data:;
font-src 'self' data:;
connect-src 'self' https://www.cisa.gov https://services.nvd.nist.gov https://api.first.org;
worker-src 'self' blob:;
manifest-src 'self';
frame-src 'none'
```

Notes:

- `script-src 'self'` is the production-safe value. No
  `'unsafe-eval'`, no `'unsafe-inline'`, no wildcard
  origins. The Vite build produces a deterministic
  bundle with a single self-hosted entry, and the Web
  Workers (`parseInventory.worker.mjs`,
  `correlate.worker.mjs`, `fingerprint.worker.mjs`) are
  loaded from the same origin via `new Worker(new
  URL(...), { type: 'module' })`.
- `connect-src` enumerates the **exact** browser-direct
  origins reachable from the production build. The
  three non-self origins are the documented live-data
  fallback providers (CISA KEV, NVD, FIRST EPSS),
  reached ONLY when the primary same-origin
  `/.netlify/functions/dataset` route is unavailable
  (see `src/services/vulnerabilityService.ts#tryBrowserDirectFetch`).
  No `https:` wildcard, no `*`, no subdomain wildcards.
  Each origin is documented in section 7 below.
- `worker-src 'self' blob:` is required so Vite's runtime
  worker bootstrap (which uses a temporary `blob:` URL
  internally) is not blocked. Removing `blob:` would
  break the build.
- `style-src` is the narrowest cross-browser-compatible
  inline-style policy. Level 3 (`style-src-elem`,
  `style-src-attr`) are honoured by Chrome ≥ 75, Firefox
  ≥ 78, Safari ≥ 15.4. The Level 1 `style-src` fallback
  carries the same effective permission for older
  browsers. The application code itself never injects
  untrusted content as inline style; the only inline
  style usage is React's `style={{...}}` prop (used in
  two progress-bar components) and the small handful
  of inline measurements that React and Recharts
  generate at runtime. Verified by the static audit in
  `scripts/verify-v69-privacy-and-runtime-hardening.mjs`.
- `img-src 'self' data:` is required because the
  inline `radar.svg` icon and a small set of inline
  data-URI placeholders are rendered. The
  `externalLinks` advisory URL fields are anchor
  `href=` values, NOT `img-src`, so they do not affect
  the policy.
- `frame-ancestors 'none'` and the parallel
  `X-Frame-Options: DENY` deny every embedding
  (clickjacking mitigation).
- `frame-src 'none'` denies iframe creation. The
  dashboard has no iframe / embed surface.
- The CSP is enforced (not `Content-Security-Policy-
  Report-Only`) because every application function
  passes without violations (verified by the smoke
  test in `scripts/smoke-v68-local.mjs`).

## 5. HTTP and Node hardening (PHASE 5)

### Security headers

| Header | Value | Source |
| --- | --- | --- |
| `X-Content-Type-Options` | `nosniff` | every response |
| `X-Frame-Options` | `DENY` (was `SAMEORIGIN`) | every response |
| `Referrer-Policy` | `strict-origin-when-cross-origin` (was `same-origin`) | every response |
| `Content-Security-Policy` | the V6.9 policy above | every response |
| `Permissions-Policy` | `accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), xr-spatial-tracking=()` | every response |
| `Cross-Origin-Resource-Policy` | `same-origin` | every response except the documented public dataset route |
| `Strict-Transport-Security` | `max-age=31536000` (1 year; no `includeSubDomains`, no `preload`) | every response in production |
| `X-Powered-By` | **not set** (Node default suppressed) | every response |
| `Server` | **not set** (Node default suppressed) | every response |
| `Cache-Control` | `no-store` for `/health`, `/ready`, error responses, `index.html`; `public, max-age=31536000, immutable` for fingerprinted `/assets/*`; `public, max-age=300` for other static | per response |

Notes:

- `includeSubDomains` is intentionally absent because the
  operator has not yet verified that every subdomain of
  the production domain is HTTPS-only.
- `preload` is intentionally absent because HSTS preload
  is a one-way commitment and the V6.9 milestone is the
  first version to commit a HSTS value.
- The V6.3 acceptance suite was updated to assert the
  V6.9 header values explicitly (DENY, strict-origin-
  when-cross-origin, no `includeSubDomains`, CSP, PP).

### Node timeouts (Hostinger)

`hostinger/app.mjs` now pins every Node-side timeout
explicitly so a future Node default change cannot silently
relax the public surface.

| Limit | Value | Rationale |
| --- | --- | --- |
| `headersTimeout` | 10 s | bound slow-loris; the largest legitimate request is well under 1 s of headers |
| `requestTimeout` | 60 s | bound the full request lifecycle; the SHA-256 fingerprint worker bootstrap + bulk SBOM import are the slowest legitimate path |
| `keepAliveTimeout` | 5 s | bound keep-alive idle |
| `maxRequestsPerConnection` | 100 | cap per-connection request count |
| `MAX_TOTAL_HEADER_BYTES` | 16 KiB | unchanged from V6.3; defense against the OpenTelemetry W3C Baggage propagation vector |
| `MAX_PATH_LENGTH` | 2048 | unchanged from V6.3; produces a 414 for oversized URLs |

### Sanitized errors

Every error response on Hostinger returns a fixed JSON
shape with no stack trace, no filesystem path, no
internal class name. The Node `uncaughtException` /
`unhandledRejection` handlers sanitize before logging.
The portable `server/http.mjs` 500 response body
includes only `{ error: 'internal' }` after the V6.9
hardening; stack traces are written to the operator's
log directory only.

## 6. API and caching hardening (PHASE 6)

| Route | Methods | Content-Type | Cache-Control | Notes |
| --- | --- | --- | --- | --- |
| `GET /health` | GET, HEAD | `application/json; charset=utf-8` | `no-store` | sanitized `{status:'ok'}` |
| `GET /ready` | GET, HEAD | `application/json; charset=utf-8` | `no-store` | sanitized `{ready:true}` or `{ready:false, reason:'dataset-missing'}` |
| `GET /api/dataset` | GET, HEAD | `application/json; charset=utf-8` | `public, s-maxage=900, stale-while-revalidate=300` on Netlify; `no-store` on Hostinger (since the operator controls the Hostinger cache layer separately) | documented public cross-origin contract; CORS-open |
| `GET /.netlify/functions/dataset` | GET, HEAD | `application/json; charset=utf-8` | same as `/api/dataset` | local compatibility alias on Hostinger; not a request to Netlify |
| `GET /*` (static assets) | GET, HEAD | per-extension MIME map | hashed `/assets/*`: `public, max-age=31536000, immutable`; `radar.svg`: `public, max-age=31536000, immutable`; `index.html`: `no-store`; other static: `public, max-age=300` | bounded by `MAX_FILE_SIZE` (8 MiB) |
| `GET /` (SPA fallback) | GET, HEAD | `text/html; charset=utf-8` | `no-store` | every non-asset, non-API path serves `dist/index.html` with `no-store` |
| Anything else | any | — | `no-store` | `404` (or `405` on disallowed methods, with `Allow: GET, HEAD`) |
| Oversized URL | any | `application/json; charset=utf-8` | `no-store` | `414 URI Too Long` |
| Oversized headers | any | `application/json; charset=utf-8` | `no-store` | `431 Request Header Fields Too Large` |
| Malformed URL | any | `application/json; charset=utf-8` | `no-store` | `400 Bad Request` (sanitized) |
| Method `!= GET/HEAD` | non-allowlist | `application/json; charset=utf-8` | `no-store` | `405 Method Not Allowed` with `Allow: GET, HEAD` |

### 6.0 Hostinger vs Netlify route distinction (provider correctness)

The two deployments have **different public-route
surfaces** and MUST NOT be conflated. The matrix
above is the Hostinger production surface. The
Netlify rollback site is preserved as a historical
deployment surface only.

**Hostinger (canonical production):**

- `GET /api/dataset` is a public read endpoint
  served by `hostinger/app.mjs` → `server/routes/dataset.mjs`.
- `GET /.netlify/functions/dataset` is a **local
  public read compatibility alias** served by the
  same `hostinger/app.mjs`. It is NOT a request to
  Netlify; it is a thin path-aliasing layer that
  lets the frozen V6.8 frontend hit a same-origin
  URL even when the deploy target is Hostinger.
- `GET /.netlify/functions/refresh-dataset-background`
  is **closed** and returns the documented sanitized
  `404` response. There is no public Hostinger route
  that triggers a refresh; refreshes are driven by
  the in-process managed scheduler
  (`hostinger/managed-scheduler.mjs`) only.
- Every other non-dataset `/.netlify/functions/*` path
  is closed with the same sanitized `404`. The closed
  Hostinger endpoint does NOT advertise
  `Access-Control-Allow-Origin: same-origin` (a
  closed route has no body and no CORS headers).
- No refresh, write, admin, credential or filesystem
  HTTP endpoint is exposed on Hostinger.

**Netlify (rollback site, preserved historical
contract only):**

- The Netlify site continues to expose the five
  historical public Netlify function entries
  (`dataset.mjs`, `refresh-dataset-background.mjs`,
  `refresh-dataset-scheduled.mjs`,
  `refresh-baseline-scheduled.mjs`,
  `refresh-baseline-background.mjs`).
- The Netlify function contract (CORS-open for
  `dataset.mjs`, `same-origin` for
  `refresh-dataset-background.mjs` after the V6.9
  CORS tightening) is preserved.
- The Netlify refresh function is part of the
  preserved Netlify function contract; its
  CORS/security behaviour MUST NOT be presented as
  a Hostinger endpoint.
- Operators considering disabling the Netlify
  rollback site should consult the V6.8
  Hostinger-migration-closure document.

A future deployment that disables the Netlify
rollback site entirely does not change the
Hostinger public surface.

### 6.1 Application-log retention (30 days)

ThreatPulse application-generated logs (managed-scheduler
logs, cron job logs, JSONL logs, failed-job logs and
verification logs) are retained for **up to 30 days**.
The retention pass is implemented in
`hostinger/log-retention.mjs` and is invoked by the
existing `state-verify` daily maintenance schedule. The
retention pass:

- operates only inside the resolved
  `THREATPULSE_LOG_DIR`;
- never follows a symlink outside that directory;
- never deletes state, snapshot, backup, source files
  or user uploads (only the documented daily JSONL log
  filename pattern is eligible);
- uses file age from `lstatSync` (no `statSync` follow);
- tolerates a missing log directory (`{ok:true, reason:
  'log-dir-missing'}`);
- tolerates concurrent writers (a failed unlink is
  reported and retried on the next scheduled run);
- reports deletion counts and reasons without logging
  secrets or full filesystem paths;
- fails safely on every error path (returns
  `{ok:false, reason:…}` and never throws);
- is enforced by the acceptance suite in
  `scripts/acceptance-v69-log-retention.mjs`.

Hostinger infrastructure / access logs are out of
scope for the application retention policy. ThreatPulse
cannot delete Hostinger-controlled logs.
| Path-traversal attempts | any | `application/json; charset=utf-8` | `no-store` | `404` (sanitized) |

### CORS

| Endpoint | CORS policy | Rationale |
| --- | --- | --- |
| `GET /api/dataset`, `GET /.netlify/functions/dataset` | `Access-Control-Allow-Origin: *` | The documented public-data contract. The dataset is intentionally CORS-open so that CI pipelines, security dashboards and other tools can fetch the latest CVE set. |
| `POST /.netlify/functions/refresh-dataset-background` | `Access-Control-Allow-Origin: same-origin` (was `*` in V6.x; tightened in V6.9) | This is an internal same-origin trigger. The wildcard CORS in V6.x was a legacy design choice; the V6.9 milestone tightens it to same-origin to remove the documented hardening regression. |
| `GET /health`, `GET /ready` | no `Access-Control-Allow-Origin` header | Same-origin only. Liveness / readiness probes do not need a public CORS contract. |
| All other public routes | no `Access-Control-Allow-Origin` header | Same-origin only. |

### No wildcard CORS

`scripts/verify-v69-privacy-and-runtime-hardening.mjs`
assertion #9 enforces that no code path outside the
documented public dataset endpoint advertises a wildcard
`Access-Control-Allow-Origin`. The assertion is a
build-time gate: a regression that re-introduces a
wildcard CORS anywhere else will fail the V6.9
verification suite.

## 7. Local file import / export trust boundary (PHASE 7)

The V6.4–V6.7 local features ingest user-supplied files
(SBOMs in CycloneDX / SPDX, workspace backups, environment
exports, remediation exports, report exports) entirely
in the visitor's browser. None of these files are
uploaded. The audit asserts:

- **Imported files are never transmitted to the server.**
  Verified by `scripts/acceptance-v64-workspace.mjs` (and
  the V6.5 / V6.6 / V6.7 equivalents) — the import path
  uses only the FileReader API and IndexedDB, never
  `fetch()`, `XMLHttpRequest`, `WebSocket`, `navigator.
  sendBeacon` or any background-synchronization API.
- **No imported URL is fetched.** The V6.9 verification
  suite asserts that every URL string in `src/**` is
  either a same-origin path, a `data:` URI, a `blob:`
  URI, or one of the four documented live-data fallback
  hosts.
- **Strict accepted MIME / extension + schema validation.**
  The four schema modules (`workspace/schema.mjs`,
  `environment/schema.mjs`, `remediation/schema.mjs`,
  `reports/schema.mjs`) reject payloads that are not
  objects, are not the documented schema version, or
  are missing required fields. Rejection reasons are
  bounded and surfaced to the UI as sanitized error
  states.
- **Existing byte and record limits.** The workspace
  import caps at `IMPORT_MAX_BYTES` (5 MiB) and
  `IMPORT_MAX_ENTRIES` (10 000). The report import caps
  at `MAX_BYTES` (20 MiB) and `MAX_CVES` (500). Both
  caps are exercised in the existing acceptance suites.
- **Prototype-pollution protection.** Every schema
  module explicitly rejects payloads with `__proto__`,
  `prototype` or `constructor` keys. The
  `verify-v69-privacy-and-runtime-hardening.mjs` script
  asserts that this protection exists in every schema
  module (sample-based check).
- **No `dangerouslySetInnerHTML` with imported content.**
  The V6.9 verification script checks every `.tsx`
  file in `src/components/` for the
  `dangerouslySetInnerHTML` prop. The only accepted
  pattern is a static literal or a known-safe pure
  function call. A regression that injects imported
  user content as HTML will fail the assertion.
- **Output escaping.** Report markdown / HTML exporters
  escape every user-supplied field (note text, tags,
  custom title) through a documented `xe()` pipe-style
  function. The acceptance suites assert that an
  attempted XSS payload in a note is rendered as text
  in the export, not as HTML.
- **Safe generated filenames.** Workspace exports use
  the documented `threatpulse-workspace.json` filename.
  Report exports use a sanitized title slug
  (`threatpulse-<type>-<YYYYMMDD>.html`). The filename
  generator rejects path separators, traversal
  sequences and reserved device names.
- **Download Content-Type.** The download path uses
  `application/json` for JSON exports and
  `text/html; charset=utf-8` for the printed HTML
  report. The `Content-Disposition: attachment` header
  prevents the browser from rendering the file inline.
- **No active HTML / SVG execution in exports.** The
  report HTML exporter does not include inline `<script>`,
  inline event handlers or `javascript:` URLs. The
  exporter explicitly strips any user input that
  contains an HTML tag. The `remediation/canonicalize.
  mjs` module's `xe()` function escapes `<`, `>`, `&`,
  `"`, `'`, `` ` `` and the Markdown table separator
  `|`.
- **No executable file handling.** The download and
  upload paths only handle JSON, Markdown and HTML;
  no `.exe`, `.msi`, `.sh`, `.bat`, `.command`,
  `.scr`, `.cpl` or `.jar` payload is accepted or
  emitted. The dialog `accept=` attributes are bounded
  to `application/json,.json` and `text/csv,.csv`.
- **Backup integrity validation.** Every JSON export
  includes a deterministic SHA-256 checksum computed
  by the Web Crypto API (`SHA-256` over the
  canonicalized JSON). The import path verifies the
  checksum when one is present; a mismatch is surfaced
  to the UI as a "checksum mismatch" sanitized error
  state.
- **Corrupted or oversized input fails closed.** Every
  import path's first action is a byte-size check
  followed by a parse + schema validation. Any failure
  short-circuits the rest of the import; the existing
  IndexedDB state is preserved unchanged.

## 8. Security documentation (PHASE 8)

This milestone adds:

- `SECURITY.md` (top-level) — the public security
  policy, the responsible-disclosure process, the
  supported versions, the out-of-scope categories and
  the operator's contact channels.
- `public/.well-known/security.txt` — the RFC 9116
  `security.txt` for the production domain.
- `docs/v6-9-privacy-cookie-and-security-hardening.md`
  (this document) — the full audit + decision record.
- `public/legal/index.html`, `public/legal/privacy.html`,
  `public/legal/cookies.html` — the user-facing
  privacy / cookies disclosures.

The disclosures use explicit `<!-- OPERATOR: -->`
placeholders for fields that require operator / legal
input (controller name, address, contact e-mail,
retention duration). The placeholders MUST be completed
by the operator before the site is public-facing. No
personal address, tax number, data-protection officer
or jurisdiction is invented in the repository.

## 9. Verification (PHASE 9)

The bounded verification suite
`scripts/verify-v69-privacy-and-runtime-hardening.mjs`
asserts 29 invariants. It is read-only, static,
source-and-dist only, and does not contact the network.

| # | Assertion | Status |
| --- | --- | --- |
| 1 | no `document.cookie` / `Set-Cookie` / `cookieStore` in `src/**` | ✔ |
| 1a | no `Set-Cookie` / `Cookie` request headers in `hostinger/`, `server/`, `jobs/` | ✔ |
| 2 | no analytics / tracking / telemetry / beacons in `src/**` | ✔ |
| 2a | `index.html` does not load any third-party analytics or tracking script | ✔ |
| 3 | every external origin in `src/**` network calls is on the documented allow-list (CISA KEV, NVD, FIRST EPSS, OSV) | ✔ |
| 4 | `dist/assets/*` contain only the documented third-party origins | ✔ |
| 5 | `index.html` does not load any third-party script, stylesheet, font or iframe | ✔ |
| 6 | no `dangerouslySetInnerHTML` in `src/components/` with non-static HTML | ✔ |
| 7 | `hostinger/static.mjs` applies `X-Frame-Options: DENY` | ✔ |
| 7a | `hostinger/static.mjs` applies `Referrer-Policy: strict-origin-when-cross-origin` | ✔ |
| 7b | `hostinger/static.mjs` applies `nosniff` | ✔ |
| 7c | `hostinger/static.mjs` applies a conservative HSTS (no `includeSubDomains`, no `preload`) | ✔ |
| 7d | `hostinger/static.mjs` applies a `Permissions-Policy` | ✔ |
| 7e | `hostinger/static.mjs` applies a `Content-Security-Policy` | ✔ |
| 8 | `netlify.toml` sets `X-Content-Type-Options` on `/` | ✔ |
| 8a | `netlify.toml` sets `Referrer-Policy` on `/` | ✔ |
| 9 | no wildcard `Access-Control-Allow-Origin` outside the documented public dataset endpoint | ✔ |
| 10 | `hostinger/app.mjs` returns a sanitized 500 with no stack trace | ✔ |
| 11 | `Header.tsx` does not render the legacy `Proxy: Netlify` label | ✔ |
| 12 | `CSV_COLUMNS` remains exactly 21 in `src/utils/csvExport.ts` | ✔ |
| 12a | `CSV_COLUMNS` array length is exactly 21 | ✔ |
| 13 | exactly 5 public Netlify function entry files | ✔ |
| 13a | exactly 1 private gateway function entry file | ✔ |
| 14 | `hostinger/app.mjs` applies `requestTimeout` (or Node default) on the HTTP server | ✔ |
| 14a | `hostinger/app.mjs` caps the request header size | ✔ |
| 14b | `hostinger/app.mjs` caps the URL length | ✔ |
| 15 | `hostinger/app.mjs` returns 414 on oversized URLs | ✔ |
| 15a | `hostinger/app.mjs` returns 431 on oversized headers | ✔ |
| 15b | `hostinger/app.mjs` returns 400 on malformed URLs | ✔ |

## 10. Production verification checklist

Before declaring the V6.9 milestone live on the
production domain, the operator MUST confirm:

- [ ] `node scripts/verify-v69-privacy-and-runtime-hardening.mjs` passes.
- [ ] `node scripts/verify-v68-hostinger-migration-closure.mjs` passes (11/11).
- [ ] `node scripts/verify-v68-release.mjs` passes (25/25).
- [ ] `node scripts/acceptance-v63-hostinger.mjs` passes (429/429 after the V6.9 header updates).
- [ ] `node scripts/acceptance-v68-release-candidate.mjs` passes (25/25).
- [ ] `node scripts/acceptance-proxy.mjs` passes (121/121).
- [ ] `node scripts/smoke-v68-local.mjs` passes (11/11).
- [ ] `npm run build` succeeds and the main bundle size is within ±1 % of the V6.8 baseline.
- [ ] Every operator placeholder listed in section 11 is
      replaced with a real value.
- [ ] The privacy / cookies disclosures are reachable
      at `https://<production-domain>/legal/privacy.html`
      and `https://<production-domain>/legal/cookies.html`.
- [ ] `https://<production-domain>/.well-known/security.txt`
      resolves and contains the operator-completed contact.

### 10.1 Live response-header verification

The static audit asserts the V6.9 header baseline. The
following commands confirm the **deployed** headers match
the baseline. The operator MUST run each of these
against the production domain and visually confirm the
output before declaring the milestone live. **No
production change is made by this milestone; the
commands are pre-deployment checks for the operator's
own use.**

```bash
# Inspect every header on the liveness probe.
curl -sSI https://<production-domain>/health

# Inspect the canonical dataset endpoint.
curl -sSI https://<production-domain>/api/dataset

# Inspect a hashed Vite asset.
curl -sSI https://<production-domain>/assets/index-CooerWiI.js

# Inspect the local compatibility alias.
curl -sSI https://<production-domain>/.netlify/functions/dataset
```

For each command, the operator MUST visually confirm
that:

1. **No `Set-Cookie` header is present in any
   response.** If the platform adds its own cookie
   (e.g. a Hostinger analytics cookie, a CDN layer
   cookie, a Cloudflare `__cf_bm` cookie, etc.), this
   must be documented as a platform behaviour and the
   privacy notice updated to disclose it.
2. The `Content-Security-Policy` value matches the
   baseline in section 4. The three
   `connect-src` origins MUST appear in the response
   (no substitutions, no `https:` fallback).
3. The `Strict-Transport-Security` value is exactly
   `max-age=31536000` (no `includeSubDomains`, no
   `preload`).
4. The `Permissions-Policy` value is the V6.9 baseline
   (20 capabilities denied).
5. The `X-Frame-Options` value is `DENY`.
6. The `Referrer-Policy` value is
   `strict-origin-when-cross-origin`.
7. The hashed `/assets/*` response carries
   `Cache-Control: public, max-age=31536000, immutable`.
8. The `index.html` response carries
   `Cache-Control: no-store`.
9. The dataset endpoint carries
   `Access-Control-Allow-Origin: *` (the documented
   public-data contract).
10. The `refresh-dataset-background` endpoint
    (Netlify) carries
    `Access-Control-Allow-Origin: same-origin` (V6.9
    tightening).

### 10.2 Live cookie inspection in a clean browser profile

The static source audit cannot observe behaviour added
by a browser extension, a CDN, a reverse proxy, or the
hosting platform itself. The operator MUST also inspect
the live behaviour in a real browser:

1. **Open Chrome (or Firefox) in a clean profile.** A
   "clean profile" means a fresh user data directory
   with no extensions installed. To open Chrome in
   guest mode: `chrome --guest` (Chromium-based) or
   `firefox -P` to a fresh profile.
2. **Navigate to the production domain.** Do NOT
   install any extension. Do NOT import a profile.
3. **Open DevTools → Application → Cookies.** Confirm
   the `Cookies` panel lists no cookies for the
   production domain.
4. **Open DevTools → Application → Storage.** Confirm
   the `Storage` panel lists exactly one `localStorage`
   entry (`threatpulse-dataset-cache:v1`, or similar
   — the V4 TTL cache) and exactly four `IndexedDB`
   entries (`tpr-workspace`, `tpr-environment`,
   `tpr-remediation`, `tpr-reports`). These are the
   documented V6.4–V6.7 local-only stores; no other
   entries should be present.
5. **Open DevTools → Network → All requests.** Reload
   the page. The recorded requests should be limited
   to the production origin, the Vite-bundled assets,
   the local `/api/dataset` (or
   `/.netlify/functions/dataset`) and the
   same-origin workers. No third-party request should
   appear in the absence of a manual refresh.
6. **Click the "Refresh live data" button** (if the
   prebuilt dataset is being used). If the proxy is
   reachable, the live fallback does NOT fire and no
   third-party request appears. If the proxy is
   unreachable, the live fallback fires and three
   browser-direct requests appear:
   - `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
   - `https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=...`
   - `https://api.first.org/data/v1/epss?cve=...`
7. **Open DevTools → Console.** Reload the page.
   Confirm no CSP violation is reported. The only
   console messages should be the application's normal
   information logs; no red `Refused to apply inline
   style because it violates the following Content
   Security Policy directive` errors should appear.
8. **Open DevTools → Application → Cookies → Show
   partitioned cookies.** Confirm no third-party
   partitioned cookie is associated with the
   production domain.
9. **Repeat with one extension enabled** (e.g. a
   password manager, a content blocker) to confirm
   the extension does not add cookies the application
   does not set. If the extension adds its own
   cookies, that is an extension behaviour, not an
   application behaviour; document it.
10. **Distinguish ThreatPulse / Hostinger /
    extension activity.** If a cookie appears,
    cross-reference the cookie's `domain` attribute:
    cookies with the production domain as `domain`
    are application-controlled; cookies with a
    sub-domain of `hostinger.com` or
    `hostinger.net` are platform-controlled; cookies
    with any other `domain` are extension- or
    browser-controlled.

## 11. Unresolved operator placeholders (production-readiness gate)

The V6.9 branch ships with the following
`<!-- OPERATOR: -->` placeholders. The branch is
**code-ready** but **NOT production-ready** until each
placeholder is replaced with a real value by the
operator. The V6.9 verification script
(`scripts/verify-v69-privacy-and-runtime-hardening.mjs`)
asserts the existence of the placeholders so the gate
fails if a placeholder is removed without being
replaced with a real value.

| # | Placeholder | File | Required before deployment? |
| --- | --- | --- | --- |
| 1 | Controller name and registered address | `public/legal/privacy.html` § 1 | Yes |
| 2 | Data-protection contact e-mail | `public/legal/privacy.html` § 10 | Yes |
| 3 | Server-log retention duration | `public/legal/privacy.html` § 7 | Yes |
| 4 | Legal-basis placeholder for legal review | `public/legal/privacy.html` § 8 | Yes (for legal compliance) |
| 5 | Security contact e-mail | `SECURITY.md`, `public/.well-known/security.txt` | Yes |
| 6 | `Expires` date in `security.txt` | `public/.well-known/security.txt` | Yes (RFC 9116 requires a non-past `Expires`) |
| 7 | PGP key fingerprint (optional) | `SECURITY.md` | No (PGP is optional) |
| 8 | `Acknowledgement:` URL in `security.txt` | `public/.well-known/security.txt` | Recommended |

The verification script asserts that at least one
`<!-- OPERATOR: -->` placeholder exists in each
shipped legal / security file, so a regression that
publishes a placeholder-less file with fabricated
content fails the gate. The intent is to prevent
publication of fabricated personal data, addresses,
tax numbers, legal-entity names or contact e-mails.

**Final decision for this branch:** the legal / security
pages are kept in the build (operator option B) so the
operator can navigate to them and complete the
placeholders before deployment. The verification suite
explicitly flags the unresolved placeholders, so a CI
run after the operator has completed every placeholder
will pass cleanly and the final decision can be
upgraded from **B. V6.9 CODE READY — OPERATOR
LEGAL/CONTACT DETAILS STILL BLOCK DEPLOYMENT** to
**A. V6.9 READY FOR PR — ALL RUNTIME AND OPERATOR
REQUIREMENTS RESOLVED**.

## 12. Rollback conditions

The V6.9 milestone is a documentation + hardening
release. A rollback to the previous V6.8 commit is
required if ANY of the following occur after a V6.9
deployment:

- The production deployment returns a non-200 status on
  `/health` for any reason that is not a Node-level
  unhandled error.
- The `Content-Security-Policy` blocks a documented
  application function (the production build is the
  source of truth; if a future feature adds a new
  external origin, the CSP must be updated BEFORE the
  feature is shipped).
- The `X-Frame-Options: DENY` directive breaks a
  legitimate embed use case that the operator has
  decided is required. (V6.9 ships with no embed use
  case; this is a forward-looking check.)
- The `Referrer-Policy: strict-origin-when-cross-origin`
  policy breaks a documented external integration.
- The `Strict-Transport-Security: max-age=31536000`
  value is later discovered to be too aggressive
  (e.g. the operator needs to roll back to plain HTTP
  for a sub-resource that they own).
- The `node scripts/verify-v69-privacy-and-runtime-
  hardening.mjs` suite is intentionally deleted or
  made a no-op.

The exact rollback procedure is documented in
`docs/v6-8-rollback-plan.md` and is unchanged by V6.9.
