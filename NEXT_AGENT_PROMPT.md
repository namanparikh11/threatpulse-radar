# NEXT_AGENT_PROMPT

> Drop this into a fresh MiniMax Code session when you're ready to take
> ThreatPulse Radar to the next milestone. It is intentionally compact:
> enough context to act, no fluff.

---

## You are working on ThreatPulse Radar

**What it is.** A polished, dark-themed, frontend-only cybersecurity
vulnerability-intelligence dashboard for **defensive** security
portfolio use. Curated mock data only.

**Stack.** React 18 + Vite 5 + TypeScript 5 (strict) + Tailwind CSS 3 +
Recharts 2 + Lucide React.

**Status.** v1.0 is feature-complete and ships clean.
- `npm.cmd run build` → 0 errors, 0 warnings, ~5.7 s. Re-verified at
  the end of the last session (identical output, no source drift).
- `node scripts/acceptance.mjs` → 13/13 passing.
- 60 unique mock vulnerability records.
- Full filter / search / sort pipeline in `useVulnerabilityFilter`.
- Hero is the final public-portfolio cut (no version numbers, no
  top status strip, no live radar animation).
- `main` is clean and **up to date with `origin/main`**, but
  `origin` is a **private** GitHub repo and no deploy has happened
  yet. Do not push without an explicit ask.

## Read first

Open these two files in this order before touching anything:

1. `PROJECT_HANDOFF.md` — the full project status, what's done, what's
   out of scope, the recommended next milestone.
2. `README.md` — the public-facing project description.

## Hard rules for this session

These are non-negotiable. The next agent (you) must not:

- ❌ Add real APIs (NVD, CISA KEV, FIRST EPSS). The mock data is the
  point. v1 ships with `USE_MOCK = true` in
  `src/services/vulnerabilityService.ts` and stays that way.
- ❌ Add new features (auth, persistence, watchlists, CSV export,
  per-vendor sidebar, deep-linking, etc.). The dashboard is feature-frozen.
- ❌ Redesign the header. The pass-4 hero (`src/components/Header.tsx`)
  is the final cut.
- ❌ Touch the filter / search / sort pipeline. The 13 acceptance tests
  in `scripts/acceptance.mjs` must keep passing — do not weaken them.
- ❌ Touch `src/data/mockVulnerabilities.ts`,
  `src/hooks/useVulnerabilityFilter.ts`, or `src/hooks/useDebouncedValue.ts`
  unless the user explicitly asks.
- ❌ Bump major versions of React, Vite, or Recharts.
- ❌ Add a backend, a database, or any kind of server.

If a request seems to violate these, push back once, then ask before
acting. The user values this scope.

## Your only job: Hostinger static deployment prep

Make the `dist/` build drop-in deployable to Hostinger's static
hosting (or any `public_html`-style host). Specifically:

1. **`vite.config.ts`** — set `base: './'` so built asset paths are
   relative (Hostinger may not host at the domain root).

2. **SPA fallback** — Hostinger static serves `index.html` for `/`
   but 404s on a hard refresh of any deep route. Add a
   `public/.htaccess` with the standard SPA rewrite:
   ```apache
   RewriteEngine On
   RewriteBase /
   RewriteRule ^index\.html$ - [L]
   RewriteCond %{REQUEST_FILENAME} !-f
   RewriteCond %{REQUEST_FILENAME} !-d
   RewriteRule . /index.html [L]
   ```
   Vite copies everything in `public/` to `dist/` at build time, so
   this ships in the bundle.

3. **No env vars to swap.** The app reads none at build time. Confirm
   by grepping for `import.meta.env` and `VITE_` — there should be
   zero hits.

4. **Favicon + meta** — `public/radar.svg` is already referenced
   from `index.html`. Confirm `<title>` and the description meta
   are still there (they were last session).

5. **Verify the deployable artifact**:
   - `npm.cmd run build`
   - confirm `dist/index.html`, `dist/.htaccess`, and `dist/assets/*`
     all exist
   - confirm `dist/index.html` references the assets with **relative**
     paths (no leading `/`)
   - run `node scripts/acceptance.mjs` — must still be 13/13
   - sanity-check the `.htaccess` (open it, read it, confirm the
     rewrite rules look right)

6. **Optional but recommended** — add a short `DEPLOY.md` (or
   equivalent section in `README.md`) explaining how to drop
   `dist/` into Hostinger's `public_html`. Keep it under ~30 lines.

7. **Git remote.** `origin` is **already** configured at
   `https://github.com/namanparikh11/threatpulse-radar.git` (private
   repo, no `dist/` ever pushed, no deploy yet). Do **not** push
   unless the user explicitly asks. If they do, confirm the target
   branch and the deploy flow first.

## Things that are already correct (don't redo them)

- Tailwind palette (`tailwind.config.js`).
- Strict TypeScript (`tsconfig.app.json`).
- Manual chunk splitting for `react` / `charts` / `icons` in
  `vite.config.ts` — bundle is well-split.
- The 6 stats cards, 4 charts, vulnerability table, filter panel,
  detail drawer, empty/loading/error states.
- The hero: logo, title, subtitle, 2 badges, 3 status pills.
- `useVulnerabilityFilter` + `useDebouncedValue` + `SearchStatus`
  custom-hook pipeline.
- The 60 unique mock records with stable `id`s.
- The acceptance suite at `scripts/acceptance.mjs`.

## Acceptance for this session

When you're done, report:

1. `npm.cmd run build` result (must be 0 errors, 0 warnings).
2. `node scripts/acceptance.mjs` result (must be 13/13).
3. List of files added / modified (should be tiny — maybe
   `vite.config.ts`, `public/.htaccess`, `README.md` or
   `DEPLOY.md`, and this `NEXT_AGENT_PROMPT.md` if updated).
4. A short note on whether `dist/` is now drop-in deployable
   to Hostinger.

## Style notes

- Match the existing code style: Tailwind utility classes,
  4-space-indent in TS, no semicolons discipline (existing code
  uses them — keep them), function declarations for components
  (`export default function X()`).
- Keep the tone of the existing `README.md` and `PROJECT_HANDOFF.md`:
  factual, no marketing fluff, explicit about what is and isn't
  included.
- Don't introduce new dependencies unless absolutely required.
  The current `package.json` is intentionally lean.

Good luck. The dashboard is in good shape — your job is to ship it.
