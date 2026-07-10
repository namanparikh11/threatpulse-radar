# Public release checklist

> Pre-release audit notes for **ThreatPulse Radar**. This file
> captures the v5.4 public-readiness audit findings and the manual
> steps to take before the private repo is made public on GitHub.
> The audit only — no public-publishing actions are taken from
> this branch.

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

### 6. Internal handover docs — **need pre-release action**

These two files are internal-only and contain markers that
would look unprofessional in a public repo (session numbers,
"uncommitted source changes", AI-agent prompts, push-policy
notes). They are **not** linked from `README.md`, so they
won't appear in casual browsing — but they will appear in
the repo's file listing.

- ⚠️ `NEXT_AGENT_PROMPT.md` (423 lines) — "drop this into a
  fresh AI session" prompt. Internal-only.
- ⚠️ `PROJECT_HANDOFF.md` (2226 lines) — session-by-session
  handover log. Internal-only.

The GitHub history will still contain these files unless the
history is rewritten at release time. Two clean options are
listed in the "Pre-release steps" section below.

---

## Pre-release steps (run before flipping the repo public)

The following steps assume the maintainer is the only one
running them, immediately before the GitHub visibility change.

### A. Decide what to do with the internal docs

Pick **one** of:

1. **Move to a clearly-marked internal folder** (keeps git
   history intact):
   ```bash
   mkdir -p docs/internal
   git mv NEXT_AGENT_PROMPT.md docs/internal/
   git mv PROJECT_HANDOFF.md docs/internal/
   # Optional: add a README that says "Internal-only
   # handover notes — not for public consumption."
   ```
2. **Delete from the working tree** (history still has the
   files; the public file listing will be clean):
   ```bash
   git rm NEXT_AGENT_PROMPT.md
   git rm PROJECT_HANDOFF.md
   ```
   To also rewrite git history (nuclear option), use
   `git filter-repo` or `git rebase --interactive` and
   squash before the public release.

### B. Verify `.gitignore` is honored

```bash
git check-ignore -v .env .env.local node_modules dist
# All four should print "<gitignore-pattern>  <file>"
```

If `.env` is ever accidentally created on a developer
machine, it must not be tracked.

### C. Run the build + acceptance suite one more time

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
```

All seven scripts must report `PASSED (N/N)` with no failures.

### D. Verify the production deploy is honest

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
- Open the browser DevTools → Network → trigger a manual
  refresh and verify the response body contains
  `proxyStatus: "proxy"`, `dataSource: "prebuilt-store"`,
  `nvdStatus: "nvd"`, `epssStatus: "first"` and no
  `NVD_API_KEY` substring anywhere.

### E. GitHub-side preparation (after pushing the release commit)

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
   (CISA KEV + NVD CVSS + FIRST EPSS). Production-style React
   + Vite + Netlify Functions + Netlify Blobs. Defensive use
   only."
4. **Add topics** (Settings → General): `cybersecurity`,
   `vulnerability-management`, `defensive-security`,
   `react`, `typescript`, `vite`, `netlify`, `cisa-kev`,
   `nvd`, `epss`. These help searchability without over-
   claiming.
5. **Pin the repository** (optional, profile page) if you
   want it at the top of your GitHub profile.
6. **Flip visibility to public** (Settings → Danger Zone →
   "Change repository visibility"). Confirm the audit checklist
   above is green first.

### F. Post-release sanity (after the flip)

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

This is an **audit-only** branch. It does **not**:

- Flip the GitHub repository to public.
- Rewrite git history.
- Delete or move any files.
- Change any code, tests, or UI.
- Push to remote.

The maintainer runs the pre-release steps in the
"Pre-release steps" section when ready, by hand, in their own
time.

---

_Last audited: v5.4 public-readiness branch._