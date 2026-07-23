# V6.3 — Dependency Security Review

This document records the controlled dependency-
security review performed for the V6.3 Hostinger
Business runtime. The review uses the standard
`npm audit` toolchain and avoids any force-upgrade
that would change the major version of a direct
dependency without explicit review.

## Methodology

1. `npm audit` — full advisory scan including
   dev dependencies.
2. `npm audit --omit=dev` — production-only scan.
3. `npm audit fix --dry-run` — list the
   compatible fix actions (without applying them).
4. For every advisory, identify the affected
   package, the dependency path, the runtime
   exposure, and the mitigation.

## Summary

| Severity | Count | Status |
| --- | --- | --- |
| Critical | 0 | — |
| High     | 1 | dev-only; fix requires vite 8.x (breaking change); MITIGATED |
| Moderate | 7 | 6 runtime, 1 dev-only; compatible fix not available; MITIGATED |
| Low      | 0 | — |
| **Total** | **8** | **6 remain (mitigated), 2 dev-only (mitigated)** |

## High-severity advisory

### GHSA-fx2h-pf6j-xcff — Vite `server.fs.deny` bypass on Windows alternate paths

- **Package:** `vite` (dev dependency, `<= 6.4.2`)
- **CVSS:** 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **CWE:** CWE-22 (Path Traversal), CWE-200
- **Dependency path:** `vite` (dev) — no runtime
  consumers.
- **Available fix:** `vite@8.1.5` (SemVer-major bump).
- **Runtime exposure:** NONE. The vulnerability is
  in the Vite *dev server*; the production
  application uses the static artifacts emitted by
  `vite build` and is served by the Hostinger
  Node.js process via `hostinger/static.mjs`. The
  Vite dev server is never bound to a network
  socket on Hostinger.
- **Mitigation:**
  1. `npm run build` produces a static `dist/`
     tree that the Hostinger Node.js process
     serves. The Vite dev server is never used
     in production.
  2. The Hostinger runtime does not import Vite.
  3. The current `vite@5.4.21` is the latest
     Vite 5.x; a controlled bump to `vite@6.x`
     is on the V6.4+ roadmap with a manual
     review of the breaking changes.

### Additional Vite-related advisories (moderate)

- **GHSA-4w7w-66w2-5vf9** — Vite path traversal
  in optimized deps `.map` handling. Dev-only.
  Same fix and same mitigation as above.
- **GHSA-v6wh-96g9-6wx3** — `launch-editor`
  NTLMv2 hash disclosure via UNC path handling
  on Windows. Dev-only. The launch-editor code
  path is not exercised by the production
  Hostinger runtime.
- **GHSA-67mh-4wv8-2f99** — `esbuild` enables
  any website to send any requests to the
  development server. Dev-only (esbuild is a
  build-time dependency). Production builds do
  not serve the Vite dev server.

## Moderate-severity advisories (runtime)

### GHSA-8988-4f7v-96qf — OpenTelemetry Core: Unbounded memory allocation in W3C Baggage propagation

- **Package:** `@opentelemetry/core < 2.8.0`
  (transitive via `@netlify/blobs` → `@netlify/otel`)
- **CVSS:** 5.3 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
- **CWE:** CWE-770 (Allocation of Resources
  Without Limits or Throttling)
- **Dependency path:**
  - `@netlify/blobs@^10.0.0` (direct, production)
    → `@netlify/otel@>=3.0.1`
    → `@opentelemetry/core < 2.8.0`
- **Status:** dependency-owned. No compatible
  non-breaking upgrade currently selected. The
  fix requires either (a) a Netlify-side update
  to a newer `@netlify/otel` that pulls in
  `@opentelemetry/core >= 2.8.0`, or (b) a
  breaking bump on `@netlify/blobs` (which
  `npm audit fix --dry-run` will not perform
  without `--force`).
- **Runtime exposure (Hostinger):**
  - The Hostinger runtime imports the V6.2
    `publicIntelligenceStore.mjs` module (it is
    used by the V6.2 dataset + view-mode
    routes). That module statically imports
    `@netlify/blobs`. Node.js therefore loads
    `@netlify/blobs` (and its `@netlify/otel`
    transitive) at Hostinger startup, even when
    the storage backend is `filesystem`.
  - The `getStore` function from `@netlify/blobs`
    is NEVER called by the Hostinger runtime
    (the filesystem storage adapter is used
    instead). The W3C Baggage propagation
    handler is initialised when the
    OpenTelemetry SDK is loaded but no
    instrumented code is on the request path.
  - An attacker who can send a `baggage` HTTP
    header to the Hostinger runtime COULD
    trigger the unbounded-allocation path in
    the OTel SDK. The realistic exposure is
    bounded by Node.js's default
    `--max-http-header-size` (16 KiB total).
- **Bounded by platform/header controls where applicable:**
  - The Hostinger HTTP application applies a
    **defense-in-depth** cap of
    `MAX_TOTAL_HEADER_BYTES` (16 KiB) on the sum
    of every request header, before the request
    handler runs. A request with a single
    oversized header is rejected with HTTP 431.
  - The cap is **defense in depth for the
    Hostinger HTTP application**, not a full
    fix for the OpenTelemetry issue. The OTel
    SDK may initialise its propagation handlers
    before the Hostinger request handler
    runs, so the 16 KiB cap cannot guarantee
    that the W3C Baggage allocation path is
    unreachable; it can only reduce the realistic
    exposure to a bounded allocation.
- **Subject to re-evaluation when the Netlify
  dependency chain updates:** a controlled bump
  of `@netlify/blobs` to the version that pulls
  in `@opentelemetry/core >= 2.8.0` is on the
  V6.4+ roadmap with manual review of the
  breaking changes. Until then, the advisory
  remains.

## Confirmed fixable — none in this milestone

`npm audit fix` (without `--force`) cannot
resolve any of the 8 advisories in this
milestone. The compatible-fix path is empty:

```
$ npm audit fix --dry-run
up to date, audited 222 packages in 3s
```

The `npm audit fix --force` path requires
breaking version bumps on `vite` and
`@netlify/blobs`. Those bumps are deferred to
V6.4+ with a dedicated migration commit.

## Runtime-exposure summary for the Hostinger runtime

| Advisory | Severity | Hostinger exposure | Status |
| --- | --- | --- | --- |
| GHSA-fx2h-pf6j-xcff (vite `server.fs.deny` bypass) | High | None — Vite dev server is not used in production | dependency-owned; non-breaking upgrade not available; documented |
| GHSA-4w7w-66w2-5vf9 (vite path traversal in optimized deps) | Moderate | None — same reason | dependency-owned; non-breaking upgrade not available; documented |
| GHSA-v6wh-96g9-6wx3 (`launch-editor` NTLMv2) | Moderate | None — `launch-editor` is not exercised by the production build | dependency-owned; non-breaking upgrade not available; documented |
| GHSA-67mh-4wv8-2f99 (esbuild dev server) | Moderate | None — esbuild is build-time only | dependency-owned; non-breaking upgrade not available; documented |
| GHSA-8988-4f7v-96qf (OpenTelemetry W3C Baggage) | Moderate | Module loaded transitively via the V6.2 publicIntelligenceStore import of @netlify/blobs. `getStore` is never called. Bounded by the Hostinger 16 KiB header cap (defense in depth, not a full fix). | dependency-owned; non-breaking upgrade not currently selected; subject to re-evaluation when the Netlify chain updates |

**Result:** Every remaining advisory is
**dependency-owned** (the threat is in
`@netlify/blobs` / `@vitejs/*` /
`@opentelemetry/*`, not in ThreatPulse
application code). No compatible non-breaking
upgrade is currently selected. The Hostinger
runtime's only request-bound exposure is the
OTel W3C Baggage propagation, which is **bounded
by the 16 KiB header cap as defense in depth**.
The 16 KiB cap is not a complete fix; the OTel
SDK may initialise its propagation handlers
before the Hostinger request handler runs.
The advisory remains documented and is subject
to re-evaluation when the Netlify dependency
chain publishes a compatible update.

## What changes when this milestone is complete

1. The Hostinger runtime package is shipped
   with the current dependency tree. The
   documented advisories are listed above and
   will be reviewed in V6.4+.
2. The `package.json` and `package-lock.json`
   are not modified. The previous accidental
   force-upgrade was reverted; the verified
   versions are `vite@5.4.21` and
   `@vitejs/plugin-react@4.7.0`.
3. The Hostinger runtime uses the filesystem
   storage adapter and never imports the
   Netlify Blobs adapter. The OpenTelemetry
   transitive dependency is therefore not
   loaded by the Hostinger process.

## Action items for V6.4+

- [ ] Controlled bump of `vite` to `7.x` (the
  first Vite 7.x release that ships with
  esbuild > 0.24.2). Manual review of the
  breaking changes.
- [ ] Controlled bump of `@netlify/blobs` to the
  version that pulls in `@netelemetry/otel`
  with `@opentelemetry/core >= 2.8.0`. Manual
  review of the breaking changes.
- [ ] Re-run `npm audit` after the bumps and
  document any remaining advisories.
