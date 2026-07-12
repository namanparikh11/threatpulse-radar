# Public release checklist

> Pre-release audit notes for **ThreatPulse Radar**. This file
> captures the v5.4 public-readiness audit findings and the manual
> steps to take before the private repo is made public on GitHub.
> The v5.4.1 follow-up removed the two internal handover files
> from the working tree (section 6 below); the v5.5 / v5.5.1
> audits extended the checklist with CISA Vulnrichment coverage;
> the v5.6 / v5.6.1 audits extend it with reviewed GitHub
> Advisory coverage. The remaining pre-release steps in this
> checklist are still manual. The audit only — no
> public-publishing actions are taken from this branch.

---

## Audit findings (v5.4)

### 1. Secrets & credentials — **clean**

- ✅ No `.env`, `.env.local`, `.env.*.local`, `.netrc`, `*.pem`,
  `*.key`, `credentials*`, or `secrets*` files in the working tree.
- ✅ `.gitignore` excludes `.env`, `.env.local`, `.env.*.local`,
  `npm-debug.log*`, `yarn-debug.log*`, `yarn-error.log*`,
  `pnpm-debug.log*`, `zip-source.ps1`, `node_modules/`, `dist/`.
- ✅ No hardcoded API key shapes found in the repo
  (no `ntn_*`, `ghp_*`, `github_pat_*`, `sk-*`, `AKIA*`,
  or `-----BEGIN ... PRIVATE KEY-----` blocks).
- ✅ No `apiKey = "..."`, `secret = "..."`, `token = "..."`,
  or `password = "..."` literals with non-empty values.

### 2. `NVD_API_KEY` references — **clean**

- ✅ Every reference to `NVD_API_KEY` is either:
  - A read from `process.env.NVD_API_KEY` inside the Netlify
    Function (`netlify/functions/_shared/liveBuild.mjs`,
    server-side only, no hardcoded value).
  - Documentation / test text describing the contract.
- ✅ Zero references in any frontend source file
  (`src/**` does not import `process.env`; the only
  `import.meta.env.*` reads are the public-route overrides
  `VITE_DATASET_PROXY_URL` and `VITE_REFRESH_ENDPOINT_URL`).
- ✅ No `VITE_NVD_API_KEY` or any other `VITE_*` secret env var.
- ✅ The acceptance suite (`scripts/acceptance-proxy.mjs`,
  `scripts/acceptance-prebuilt.mjs`) actively asserts
  server-side-only usage as a regression guard.

### 3. Offensive / exploit wording — **clean**

- ✅ No offensive tooling, exploit code, weaponization content,
  or vulnerability scanning logic in any source file.
- ✅ All matches of the words "exploit", "attack", "weaponize"
  in the repo appear only in defensive disclaimers
  ("no exploit code", "no offensive tooling") — these are
  credibility markers, not feature claims.
- ✅ The word "payload" is used only in its generic technical
  sense (JSON envelope, cooldown payload, lock payload).

### 4. Fake data / fabricated claims — **clean**

- ✅ No fabricated CVSS / EPSS / KEV data. Records whose CVE
  is not in NVD keep `cvssScore: 0` and the CISA-derived
  severity (KEV defaults to `High`, ransomware-known to
  `Critical`); records not scored by FIRST keep
  `epssProbability: 0`. Enforced by
  `scripts/acceptance-nvd.mjs` and `scripts/acceptance-epss.mjs`.
- ✅ No "real-time zero-day detection", "guaranteed NVD
  enrichment", or "always-fresh" claims in the README. The
  README's "Defensive-only scope" section explicitly says
  the dashboard does *not* do these things.
- ✅ Mock data is documented as the offline / browser-side
  last-resort fallback and is never written to the prebuilt
  blob. The prebuilt `latest-dataset` blob is written only
  by a successful live build (enforced by
  `scripts/acceptance-prebuilt.mjs`).

### 5. Public-facing docs — **clean**

- ✅ `README.md` (397 lines, rewritten in v5.3) is
  public-presentation-ready: defensive-only scope, accurate
  live demo URL, accurate data sources, honest reliability
  section, accurate tech stack, no internal-only markers.
- ✅ `DEPLOYMENT.md` (864 lines) is technically thorough and
  uses placeholder URLs (`<your-site>.netlify.app`); it does
  not contain session-by-session narration.
- ✅ `PORTFOLIO_WRITEUP.md` (299 lines) is a clean recruiter-
  facing narrative with no internal-only markers.

### 6. Internal handover docs — **resolved in v5.4.1**

These two files were internal-only and contained markers that
would look unprofessional in a public repo (session numbers,
"uncommitted source changes", AI-agent prompts, push-policy
notes). They are **not** linked from `README.md`, so they
won't appear in casual browsing — but they would have appeared
in the repo's file listing.

- ✅ `NEXT_AGENT_PROMPT.md` — removed from the working tree
  in v5.4.1.
- ✅ `PROJECT_HANDOFF.md` — removed from the working tree
  in v5.4.1.

Note: the git history still contains these files in earlier
commits. If the maintainer wants the file listing *and* the
history to be fully clean, rewrite history with
`git filter-repo` (nuclear option) before the visibility flip.
For most public-release cases the working-tree-only removal
done in v5.4.1 is sufficient.

### 7. CISA Vulnrichment — internal metadata isolation — **clean**

The v5.5 Vulnrichment enrichment introduces a fourth
defensive-intelligence feed and a separate Netlify Blobs
store (`tpr-vulnrichment`). The public-surface contract is
the same as the existing CISA KEV / NVD / EPSS feeds:

- ✅ The visitor's response body never contains any of the
  internal operator-only fields the refresh orchestrator
  writes to the prebuilt blob: no `lastVulnrichmentRefresh`,
  no `lastRefreshFailure`, no `lastRefreshAttemptAt`. These
  are stripped by the `publicEnvelope()` helper in
  `netlify/functions/dataset.mjs` (driven by the
  `INTERNAL_BLOB_FIELDS` set in `refresh.mjs`) before the
  response is sent.
- ✅ The Vulnrichment orchestrator's transient-failure
  `reason` is not part of the public envelope. The
  per-cycle `lastVulnrichmentRefresh` envelope carries
  the precise provider failure message in its internal
  `reason` field, but that envelope is on `INTERNAL_BLOB_FIELDS`
  and is stripped before the response is sent. The
  public envelope carries only the coarse
  `vulnrichmentStatus: "available" | "partial" |
  "unavailable"` and the `vulnrichmentCoverage: { enriched,
  total }` counts.
  Note: this is the Vulnrichment-specific boundary. The
  NVD and EPSS provider-facing sanitized `nvdReason` /
  `epssReason` strings ARE intentionally part of the
  public provider-status contract — they are rendered
  verbatim by the `NvdUnavailableBanner` /
  `EpssUnavailableBanner` so a defender can see *why* a
  provider failed, and the application already uses them.
  The two contracts are different and should not be
  conflated.
- ✅ The frontend bundle never references the Vulnrichment
  upstream directly. There is no `raw.githubusercontent.com`
  or `cisagov/vulnrichment` reference in any `src/**` file;
  the browser has no way to call Vulnrichment itself. The
  dashboard reads only the two public envelope fields
  (`vulnrichmentStatus` / `vulnrichmentCoverage`) plus the
  per-record SSVC fields from the Netlify Function.
- ✅ The Vulnrichment cache is in a separate Netlify Blobs
  store (`tpr-vulnrichment`) and is never mixed into the
  main `latest-dataset` blob. A Vulnrichment refresh cannot
  rewrite the main blob's `fetchedAt` and trigger a spurious
  "newer dataset available" banner (v5.1 contract).
- ✅ The acceptance suite (`scripts/acceptance-vulnrichment.mjs`,
  125 assertions) actively asserts all of the above as a
  regression guard.

### 8. GitHub Advisory — internal metadata isolation — **clean**

The v5.6 GitHub Advisory enrichment introduces a fifth
defensive-intelligence feed and a separate Netlify Blobs
store (`tpr-github-advisory`). The public-surface contract
follows the same pattern as the existing four feeds:

- ✅ The visitor's response body never contains any of the
  GitHub Advisory internal-only fields. The optional
  `GITHUB_TOKEN` is read from `process.env` inside the
  Netlify Function only, passed to the upstream as an
  `Authorization: Bearer <token>` header, and **never**
  appears in the function response body, in any URL, in
  any log, or in the frontend bundle. The token is
  optional — the dashboard works identically without it
  (slower incremental backfill; the cap drops from 50 to
  25 CVEs per run).
- ✅ The GitHub Advisory cache markers, negative-cache
  records, raw rate-limit headers (`x-ratelimit-*`,
  `Retry-After`), raw provider error bodies, cache keys,
  and stack traces all stay internal. The public envelope
  carries only the coarse
  `githubAdvisoryStatus: "available" | "partial" |
  "unavailable"` and the `githubAdvisoryCoverage:
  { enriched, total }` counts — the same shape as the
  Vulnrichment envelope, deliberately so a defender can
  read the two side-by-side without inferring provider
  internals. The provider-facing sanitized `nvdReason` /
  `epssReason` strings ARE intentionally part of the
  public provider-status contract (see section 7 note
  above) — the same carve-out applies here.
- ✅ The frontend bundle never references the GitHub
  Advisory API directly. There is no `api.github.com`
  reference in any `src/**` file; the browser has no way
  to call the GitHub Advisory API itself. The dashboard
  reads only the two public envelope fields
  (`githubAdvisoryStatus` / `githubAdvisoryCoverage`)
  plus the per-record package-remediation fields from
  the Netlify Function.
- ✅ The GitHub Advisory cache is in a separate Netlify
  Blobs store (`tpr-github-advisory`) and is never mixed
  into either the main `latest-dataset` blob or the
  Vulnrichment blob. A GitHub Advisory refresh cannot
  rewrite the main blob's `fetchedAt` and trigger a
  spurious "newer dataset available" banner (v5.1
  contract). The read-time merge into the public record
  is additive only — main-envelope fields are never
  replaced.
- ✅ Package remediation context is drawer-only. There is
  no GitHub Advisory column in the main vulnerability
  table, no GitHub Advisory header pill, and the section
  appears only inside the vulnerability details drawer
  as "**Package remediation context**". Missing coverage
  is rendered neutrally (the section is simply omitted
  for CVEs that do not have a reviewed advisory) — never
  as a fabricated "No fix exists" claim. A null patched
  version on a reviewed advisory is rendered as
  "**First patched version unavailable**".
- ✅ External GitHub advisory links use safe new-tab
  behavior: `target="_blank"` and `rel="noopener
  noreferrer"`. The link target is the public
  `https://github.com/advisories/<GHSA-ID>` URL only;
  raw API endpoints and `api.github.com` URLs are never
  surfaced in the drawer.
- ✅ The acceptance suite (`scripts/acceptance-github-advisory.mjs`,
  173 assertions) actively asserts all of the above as a
  regression guard, including: no token leak, no raw
  rate-limit metadata, no raw provider error bodies, no
  internal cache keys / store names, no table column, no
  header pill, and no fabricated patched-version claims.

---

## Pre-release steps (run before flipping the repo public)

The following steps assume the maintainer is the only one
running them, immediately before the GitHub visibility change.

Step A from earlier versions of this checklist (decide what to
do with the internal handover docs) was resolved in v5.4.1:
both files were deleted from the working tree.

### A. Verify `.gitignore` is honored

```bash
git check-ignore -v .env .env.local node_modules dist
# All four should print "<gitignore-pattern>  <file>"
```

If `.env` is ever accidentally created on a developer
machine, it must not be tracked.

### B. Run the build + acceptance suite one more time

```bash
node node_modules/typescript/bin/tsc -b
node node_modules/vite/bin/vite.js build
node scripts/acceptance-prebuilt.mjs
node scripts/acceptance-proxy.mjs
node scripts/acceptance-softrefresh.mjs
node scripts/acceptance-cisa.mjs
node scripts/acceptance-epss.mjs
node scripts/acceptance-nvd.mjs
node scripts/acceptance-cache.mjs
node scripts/acceptance-lastknowngood.mjs
node scripts/acceptance-vulnrichment.mjs
node scripts/acceptance-github-advisory.mjs
```

All ten scripts must report `PASSED (N/N)` with no failures.

### C. Verify the production deploy is honest

On the live demo at
[`https://threatpulse-radar.netlify.app`](https://threatpulse-radar.netlify.app):

- The "Proxy: Netlify" pill is visible (proxy is the live transport).
- The "Dataset store: latest available" pill is visible (the
  prebuilt blob is being read, not the bootstrap path).
- The "Source: CISA KEV + NVD + FIRST EPSS" header label
  shows all three providers enriched.
- The CVSS column has non-zero values for KEV records that
  exist in NVD; KEV records NVD hasn't published yet keep
  `cvssScore: 0` with the CISA-derived severity.
- For at least one KEV-listed CVE, open the detail drawer
  and verify the "CISA decision context" section either
  shows the three SSVC fields with a `CISA Vulnrichment`
  source label, or the empty-state copy "No CISA Vulnrichment
  assessment available." SSVC is intentionally **not** a
  main-table column.
- The public `vulnrichmentStatus` and `vulnrichmentCoverage`
  values are visible in DevTools → Network → the
  `/.netlify/functions/dataset` response body. The status is
  one of `available` / `partial` / `unavailable` and reflects
  the actual cache state, not an optimistic claim.
- The public `githubAdvisoryStatus` and `githubAdvisoryCoverage`
  values are visible in DevTools → Network → the
  `/.netlify/functions/dataset` response body. The status is
  one of `available` / `partial` / `unavailable` and reflects
  the actual cache state, not an optimistic claim.
- For at least one KEV-listed CVE that has a reviewed GitHub
  Advisory, open the detail drawer and verify the
  "**Package remediation context**" section shows: the GHSA
  identifier, the advisory severity, the GitHub-reviewed date,
  a `source: "GitHub Advisory Database"` label, and — when the
  upstream record provides one — the affected package, the
  vulnerable range, and the first patched version. When the
  upstream record omits the patched version, the field reads
  "**First patched version unavailable**" (never "No fix
  exists"). For a CVE without a reviewed advisory, the section
  is simply omitted. Package remediation context is
  intentionally **not** a main-table column and **not** a
  header pill.
- The external GHSA link in the drawer opens in a new tab
  (`target="_blank"`, `rel="noopener noreferrer"`) and points
  to the public `https://github.com/advisories/<GHSA-ID>` URL
  only — never to `api.github.com` or any raw-API endpoint.
- Open the browser DevTools → Network → trigger a manual
  refresh and verify the response body does **not** contain
  any of the GitHub Advisory internal-only fields: no
  `GITHUB_TOKEN` substring anywhere, no raw `x-ratelimit-*`
  headers, no raw `Retry-After` values, no raw provider error
  bodies or stack traces, no `tpr-github-advisory` blob keys,
  no negative-cache markers (`status: "missing"`), and no
  internal cache keys. The only public GitHub Advisory
  surface in the response body is
  `githubAdvisoryStatus` + `githubAdvisoryCoverage` on the
  envelope and the per-record package-remediation fields on
  the record — exactly the same shape as the existing NVD,
  EPSS, and Vulnrichment public contracts.
- Open the browser DevTools → Network → trigger a manual
  refresh and verify the response body contains
  `proxyStatus: "proxy"`, `dataSource: "prebuilt-store"`,
  `nvdStatus: "nvd"`, `epssStatus: "first"`, and no
  `NVD_API_KEY` substring anywhere, and no `GITHUB_TOKEN`
  substring anywhere. Also confirm the response body does
  **not** contain any of the internal-only fields written
  by the refresh orchestrator to the prebuilt blob: no
  `lastRefreshFailure`, no `lastRefreshAttemptAt`, no
  `lastVulnrichmentRefresh`. The public response must
  also remain free of raw upstream URLs (no
  `raw.githubusercontent.com`, no `api.github.com`),
  stack traces, secrets / API keys, and internal store
  metadata (no `tpr-vulnrichment` blob keys, no
  `tpr-github-advisory` blob keys, no `tpr-dataset` blob
  keys, no `refresh-lock` payloads, no GitHub Advisory
  negative-cache markers). The provider-facing sanitized
  `nvdReason` / `epssReason` strings ARE part of the
  honest public provider-status contract — they are
  rendered verbatim by the `NvdUnavailableBanner` and
  `EpssUnavailableBanner` so a defender can see *why* a
  provider failed, and their presence in the response
  body is expected.

### D. GitHub-side preparation (after pushing the release commit)

On the GitHub repo settings page (before flipping visibility):

1. **Disable issues / wiki / projects** if you don't intend to
   use them publicly. A disabled repo surface is more honest
   than an empty one.
2. **Set the default branch to `main`**. Other branches
   (e.g. `v5-2-6-nvd-backoff-quality-guard`,
   `v5-3-launch-polish`, `v5-4-public-readiness`) become
   visible once the repo is public; they show the
   version-by-version evolution and the audits — that's
   fine, but the default landing branch should be `main`.
3. **Add a repository description and URL** (Settings →
   General): "Defensive vulnerability intelligence dashboard
   (CISA KEV + NVD CVSS + FIRST EPSS + CISA Vulnrichment SSVC
   + reviewed GitHub Advisory package remediation). Production-
   style React + Vite + Netlify Functions + Netlify Blobs.
   Defensive use only."
4. **Add topics** (Settings → General): `cybersecurity`,
   `vulnerability-management`, `defensive-security`,
   `react`, `typescript`, `vite`, `netlify`, `cisa-kev`,
   `nvd`, `epss`, `cisa-vulnrichment`, `ssvc`,
   `github-advisory-database`, `ghsa`. These help
   searchability without over-claiming.
5. **Pin the repository** (optional, profile page) if you
   want it at the top of your GitHub profile.
6. **Flip visibility to public** (Settings → Danger Zone →
   "Change repository visibility"). Confirm the audit checklist
   above is green first.

### E. Post-release sanity (after the flip)

- Visit the public URL on a fresh browser profile (no
  `localStorage` from the private deploy). Verify the
  dashboard renders without errors and the source / provider
  pills show the expected states.
- Confirm the README renders correctly on GitHub (badges,
  tables, code blocks).
- Optionally enable GitHub Pages on a docs branch if you want
  rendered documentation — out of scope for v5.4.

---

## What this checklist does NOT do

The v5.4 + v5.4.1 + v5.5 + v5.5.1 + v5.6 + v5.6.1 audit
branches together do **not**:

- Flip the GitHub repository to public.
- Rewrite git history.
- Change any application code, Netlify Functions, refresh
  behavior, provider cadence, UI components, or tests.
- Push to remote.

(v5.4.1 *did* delete two internal markdown files from the
working tree as the documented pre-release action; v5.5
*did* add the CISA Vulnrichment server-side enrichment;
v5.6 *did* add the reviewed GitHub Advisory server-side
enrichment; the audits themselves still did not flip
visibility, rewrite history, or push.)

The maintainer runs the remaining pre-release steps in the
"Pre-release steps" section when ready, by hand, in their own
time.

---

_Last updated: v5.6.1 github-advisory-docs branch
(documentation refresh; v5.6 GitHub Advisory audit findings
added; GitHub Advisory public-surface check added to the
production verification list; production-readiness checklist
extended with the v5.6 reviewed-advisory contract)._