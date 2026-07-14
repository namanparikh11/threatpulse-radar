# V6.0 — Deployment

The V6.0 architecture has THREE separate Netlify
environments:

1. The **public ThreatPulse Radar site** (unchanged from
   V5.7; hosts the V5.7 dashboard, the V6.0 OSV ingestion
   pipeline, and the V6.0 background function).
2. The **private sync gateway** (a separate Netlify site
   that exposes the authenticated `/private/v1/*` routes).
   Owns its own `tpr-private-credentials` store, accessed
   via the gateway site's local Netlify Blobs runtime
   context (no cross-site).
3. The **consumer's site** (whatever the consumer's product
   is; not part of the ThreatPulse Radar repository).

The split between the public site and the private gateway is
the V6.0 amendment #1: the canonical baseline is private; the
gateway is what authenticated callers talk to.

This document covers the production environment variables,
the Blob store layout, the function configurations, and the
publish-time verification steps.

## 1. Public site

The public site is the V5.7 site plus the V6.0 OSV ingestion
pipeline. It owns the `tpr-baseline` Blob store (canonical
baseline data). It does NOT own the credentials store — that
store lives on the gateway site (see section 2).

### Environment variables (public site)

| Variable | Required | Purpose |
| --- | --- | --- |
| `THREATPULSE_REFRESH_TRIGGER_SECRET` | yes | Shared secret used by the Scheduled Function to invoke the Background Function. Long random string. |
| `THREATPULSE_BASELINE_SITE_ID` | yes (for the private gateway below) | The public site's Netlify site ID. Used by the private gateway to read the `tpr-baseline` store cross-site. |
| `THREATPULSE_BLOBS_ACCESS_TOKEN` | yes (for the private gateway below) | A Netlify Blobs access token scoped to the `tpr-baseline` store on the public site. Created in the Netlify UI under **Site settings → Blobs → Access tokens**. |
| `THREATPULSE_OSV_ECOSYSTEMS` | no | Optional JSON override of `config/osv-ecosystems.json`. Same shape. When set, the env var wins; when unset, the file is used. |

### Environment variables that MUST NOT be set

- `THREATPULSE_CREDENTIAL_PEPPER` — the pepper is for the
  private gateway only. Setting it on the public site has
  no effect (the public site never reads credentials) and
  increases the attack surface.

### Functions (public site)

| File | Netlify kind | Path |
| --- | --- | --- |
| `netlify/functions/dataset.mjs` | HTTP | `/.netlify/functions/dataset` (V5.7 dashboard) |
| `netlify/functions/refresh-dataset-background.mjs` | Background | `/.netlify/functions/refresh-dataset-background` (V5.2) |
| `netlify/functions/refresh-dataset-scheduled.mjs` | Scheduled | cron `*/30 * * * *` (V5.2) |
| `netlify/functions/refresh-baseline-scheduled.mjs` | Scheduled | cron `0 * * * *` (V6.0 thin launcher) |
| `netlify/functions/refresh-baseline-background.mjs` | Background | `/.netlify/functions/refresh-baseline-background` (V6.0) |

The V5.2 and V6.0 pipelines are independent. The V5.2
pipeline feeds the V5.7 dashboard; the V6.0 pipeline feeds the
canonical baseline. A failure in one does not block the
other.

### Blob stores (public site)

| Store name | Contents |
| --- | --- |
| `tpr-dataset` | V5.2 latest dataset + refresh lock (unchanged) |
| `tpr-vulnrichment` | V5.5 SSVC cache (unchanged) |
| `tpr-github-advisory` | V5.6 GitHub Advisory cache (unchanged) |
| `tpr-baseline` | **V6.0** canonical baseline (see layout below) |

### `tpr-baseline` layout

```
tpr-baseline/
  manifests/
    latest.json                 ← THE atomic commit point (mutable)
    versions/{version}.json     ← immutable version manifests
  objects/sha256/<hex}.json.gz   ← immutable content-addressed shards
  deltas/{from}__to__{to}.json   ← immutable deltas
  osv-bootstrap-state           ← orchestrator journal (private to the publisher)
  source-registry               ← static source registry
  source-health                 ← aggregate source health
  publication-lock              ← transient publication lock
```

**Do not write to `tpr-baseline` from anything other than the
V6.0 publisher functions.** The publisher is the only
component that should be writing to it. An operator that
needs to read the store can use the Netlify Blobs UI; an
operator that needs to write (e.g., to add a credential) can
do so via the UI as well.

## 2. Private sync gateway

The private sync gateway is a SEPARATE Netlify site. It is
the only component that holds the credential pepper. It
does NOT talk to OSV; it only reads from the public site's
`tpr-baseline` store (for the canonical baseline) via
cross-site env vars, and from its own LOCAL
`tpr-private-credentials` store (for consumer credential
HMACs) via the local Netlify Blobs runtime context. The
public site never sees the credentials store.

### Gateway topology (V6.0.1 deployment-hardened)

The two-site topology is **encoded in the repository**, not
in operator memory. The split lives at
`netlify/gateway/`:

```
netlify/gateway/
  netlify.toml                       # gateway-site Netlify config
  package.json                       # declares @netlify/blobs only
  site/.gitkeep                      # empty publish directory
  src/                               # SOURCE OF TRUTH
    private-sync-gateway.mjs         # the gateway function
    _shared/
      credentials.mjs                # HMAC credential format + verify
      baselineStore.mjs              # cross-site store helpers
  functions-staging/functions/       # OUTPUT of copy-gateway-files.mjs
                                     # (gitignored; recreated on every
                                     #  deploy)
```

The gateway function source-of-truth lives in
`netlify/gateway/src/`, NOT in the public site's
`netlify/functions/`. The public site does NOT deploy the
gateway function.

The gateway Netlify site is configured to use
`netlify/gateway/` as its base directory (set in the
Netlify UI for the gateway site). The site's
`netlify.toml` is `netlify/gateway/netlify.toml`.

The build command is
`node ../../scripts/copy-gateway-files.mjs`, which copies
ONLY the gateway-owned files (the function and the two
required shared modules) into
`netlify/gateway/functions-staging/functions/`. The
staging directory is gitignored and recreated on every
deploy. The public site does not run this script.

### Environment variables (private gateway)

| Variable | Required | Purpose |
| --- | --- | --- |
| `THREATPULSE_BASELINE_SITE_ID` | yes | The public site's Netlify site ID. Used by the cross-site baseline read. |
| `THREATPULSE_BLOBS_ACCESS_TOKEN` | yes | A Netlify Blobs access token scoped to `tpr-baseline` on the public site. Read-only. Used to read manifests, version manifests, shards, deltas, and source registry. |
| `THREATPULSE_CREDENTIAL_PEPPER` | yes | The HMAC pepper. Long random string. MUST be identical to the value used by the operator script when issuing credentials. |

The gateway does NOT need an env var to authorize reading
the credentials store. The credentials store is gateway-
local: it lives on the gateway's own Netlify Blobs runtime
context, which is provided automatically by the Netlify
runtime. There is no token, no site ID, and no cross-site
round trip. The public site's `THREATPULSE_BLOBS_ACCESS_TOKEN`
is scoped to `tpr-baseline` only and does NOT authorize
reading the gateway-local `tpr-private-credentials` store.

### Environment variables that MUST NOT be set

- `THREATPULSE_REFRESH_TRIGGER_SECRET` — the trigger secret
  is for the public-site Background Function only. The
  private gateway has no scheduled function.
- `THREATPULSE_OSV_ECOSYSTEMS` — the private gateway does
  not ingest; it only reads.
- `NVD_API_KEY` / `GITHUB_TOKEN` — the gateway does not
  call upstream providers.

### Function (private gateway)

| File | Netlify kind | Path |
| --- | --- | --- |
| `netlify/gateway/src/private-sync-gateway.mjs` (staged to `netlify/gateway/functions-staging/functions/private-sync-gateway.mjs` at deploy) | HTTP | `/private/v1/*` (mounted via the function's `config.path` export) |

The function's `config.rateLimit` is the initial rule:
`windowLimit: 200`, `windowSize: 60`. Per-credential
hard quotas are deferred.

### Blobs (private gateway)

The private gateway OWNS the `tpr-private-credentials`
Blob store (gateway-local; the public site never sees or
touches it) and READS from the public site's `tpr-baseline`
store via cross-site env vars. The credentials store is
the source of truth for consumer credentials; the baseline
store is the source of truth for the canonical baseline.
Back up the credentials store as part of the gateway site's
Netlify Blobs backup process.

## 3. Consumer's site

The consumer is a third-party product. It uses the
[`client/consumer-client.mjs`](../../client/consumer-client.mjs)
reference client (or its own implementation) to authenticate
to the private gateway and pull the baseline.

### Environment variables (consumer's site)

| Variable | Required | Purpose |
| --- | --- | --- |
| `THREATPULSE_GATEWAY_URL` | yes | The private gateway's base URL (no trailing slash). |
| `THREATPULSE_CONSUMER_CREDENTIAL` | yes | The consumer's HMAC credential (`tpr_…`). Loaded from the consumer's secret manager; never committed. |

The consumer's local store is whatever satisfies the
contract documented in
[`client/contracts.md`](../../client/contracts.md). The
default is a filesystem path.

## 4. netlify.toml — public site

The V6.0 schedule and function declarations live in the
public site's `netlify.toml`:

```toml
[build]
  command = "npm run build"
  publish = "dist"
  functions = "netlify/functions"

[functions]
  node_bundler = "esbuild"

[functions.refresh-baseline-scheduled]
  schedule = "0 * * * *"

[functions.dataset]

[functions.refresh-dataset-background]

[functions.refresh-dataset-scheduled]
  schedule = "*/30 * * * *"
```

The function bundler is `esbuild` so that the `_shared/*.mjs`
modules ship inside each function's bundle (the v5.2.1 fix).
The schedule is hourly (decision #1). The V5.2 30-minute
schedule is unchanged.

## 5. Function configuration — private gateway

The private gateway function's `config` export is:

```js
export const config = {
  path: '/private/v1/*',
  rateLimit: {
    windowLimit: 200,
    windowSize: 60,
    aggregateBy: ['ip', 'domain'],
  },
};
```

Per amendment #5, rate limits and path are exported on the
function, NOT in `netlify.toml`. The Netlify CLI reads the
export and applies it at deploy time.

## 6. Cross-site access tokens

The gateway reads TWO stores on the public site via TWO
Netlify Blobs access tokens. Each token is scoped to one
store, so the blast radius of either token being
compromised is limited to that store.

### Token for `tpr-baseline` (THREATPULSE_BLOBS_ACCESS_TOKEN)

The token for reading the canonical baseline.

To create one:

1. In the Netlify UI for the **public** site, go to
   **Site settings → Blobs**.
2. Click **Create access token**.
3. Scope: **Store: tpr-baseline**, **Permissions: read**.
   (The private gateway only reads.)
4. Copy the token into the private gateway's env vars.
   The token is shown ONCE; lose it and you must rotate.

**Never** put this token in the public site's env vars.
The public site has direct local-context access via its
own runtime context. The token only lives on the private
gateway.

**Never** put this token in the consumer's environment.
The consumer authenticates to the gateway with the HMAC
credential, not with cross-site access.

### Creating the gateway-local `tpr-private-credentials` store

The credentials store lives on the GATEWAY site, not the
public site. The gateway reads it via the local Netlify
Blobs runtime context — no env var, no token, no
cross-site access. To create the store:

1. In the Netlify UI for the **private gateway** site, go
   to **Site settings → Blobs**.
2. The `tpr-private-credentials` store should be created
   automatically when the first function call hits it
   (or you can create it via the UI). Confirm it appears
   in the site's Blobs list.
3. The store has NO access tokens. It is read by the
   gateway's own Netlify runtime, which is the only
   access path.
4. Write `credentials/<keyId>` records to the store via
   the Netlify Blobs UI (or the CLI) on the GATEWAY site.
   Each record is `{ hmac, createdAt, label? }` per
   `docs/credentials.md`.

The public site never sees this store. A token scoped to
the public site's `tpr-baseline` does NOT authorize
reading the gateway-local `tpr-private-credentials` store.

## 7. Cron timing

The V6.0 cron is `0 * * * *` (top of every hour, UTC). The
first run on a fresh site is a bootstrap: it processes the
entire OSV corpus across many Background Function
invocations (each bounded to a slice by `maxRecords` and
`timeBudgetMs`). After bootstrap, each run is incremental.

If the cron tick fires while a previous Background Function
is still running, Netlify queues the new tick. There is no
overlap; the orchestrator's resume cursor ensures correctness
either way.

## 8. Deploy-time verification

After deploying, verify in order:

1. **The scheduled function exists and is wired.**
   In the Netlify UI for the public site, go to
   **Functions → refresh-baseline-scheduled** and confirm
   the schedule is `0 * * * *`. There is no log yet (cron
   hasn't fired since the deploy).

2. **The trigger secret is configured.**
   In the Netlify UI for the public site, go to
   **Site settings → Environment variables** and confirm
   `THREATPULSE_REFRESH_TRIGGER_SECRET` is set. Its value is
   not visible; only its presence.

3. **The cross-site access token is configured on the
   gateway.** In the Netlify UI for the private gateway,
   confirm `THREATPULSE_BASELINE_SITE_ID` and
   `THREATPULSE_BLOBS_ACCESS_TOKEN` are set.

4. **The pepper is configured on the gateway.** Confirm
   `THREATPULSE_CREDENTIAL_PEPPER` is set.

5. **Wait for the first cron tick.** Within an hour of
   deploying, the scheduled function will fire. It will POST
   to the background function with the trigger secret. The
   background function logs the result. After an hour, look
   in **Functions → refresh-baseline-background → Logs** for
   a line like:
   ```
   [v6.0 background refresh] iterations=N totalProcessed=M publishedCount=K elapsedMs=…
   ```

6. **Confirm a manifest exists.** Call the gateway with a
   valid credential:
   ```bash
   curl -i -H "Authorization: Bearer tpr_…" \
     https://your-private-gateway.example.com/private/v1/manifest
   ```
   The response should be 200 OK with a JSON body that has
   `baselineVersion`, `canonicalContentHash`, `shards`, and
   `stats`.

7. **Confirm a shard is fetchable.**
   ```bash
   curl -i -H "Authorization: Bearer tpr_…" \
     "https://your-private-gateway.example.com/private/v1/shard?key=objects/sha256/<hex>.json.gz"
   ```
   The response should be 200 OK with `Content-Type:
   application/octet-stream` and `Content-Encoding: gzip`.

8. **Confirm an anonymous request is rejected.**
   ```bash
   curl -i https://your-private-gateway.example.com/private/v1/manifest
   ```
   The response should be 401 Unauthorized.

9. **Confirm the public dashboard is unchanged.** Visit the
   public site's URL. The V5.7 dashboard should render with
   no new errors. The V6.0 changes are isolated to the
   publisher and the gateway; the dashboard does not touch
   the canonical baseline.

## 9. Rollback

The V6.0 changes are additive. To roll back:

1. Revert the V6.0 commits in reverse order (last-in,
   first-out).
2. Redeploy.

The V5.2 / V5.5 / V5.6 / V5.7 functions and Blob stores are
untouched. The V5.7 dashboard is unaffected by the V6.0
publisher running or not running.

The V6.0 changes do NOT delete the V5.2 `latest-dataset`
Blob. If a V6.0 deploy runs into a problem, the V5.2
pipeline can continue independently.

## 10. Failure modes and recovery

| Symptom | Likely cause | Recovery |
| --- | --- | --- |
| No V6.0 baseline after an hour | Trigger secret mismatch | Check the public-site logs for the background function's 401. Fix the env var. |
| Gateway returns 500 with "store unavailable" | Cross-site env vars missing or wrong site ID | Confirm `THREATPULSE_BASELINE_SITE_ID` and `THREATPULSE_BLOBS_ACCESS_TOKEN` on the gateway. |
| Gateway returns 401 for all requests | Pepper mismatch or credentials not yet written | Confirm `THREATPULSE_CREDENTIAL_PEPPER` is the same value used to generate the credentials. Confirm at least one `credentials/<keyId>` Blob exists. |
| Manifest hash mismatch on consumer | Manifest was tampered with, or the consumer is verifying against a cached version | Re-pull the manifest. Consumers should not cache the manifest hash; the publisher's hash is authoritative. |
| Background function runs but publishes nothing | The orchestrator's bootstrap state shows `status: 'idle'` and no records to process. This is normal for an incremental run. | No action. The next cron tick will process any new OSV records. |
| Bootstrap state stuck in `running` | The previous Background Function was killed mid-run. The orchestrator's resume cursor handles this on the next tick. | No action. The next tick resumes from the cursor. |

## 11. Upgrades

To upgrade from V5.7 to V6.0:

1. Deploy the V6.0 code to the public site. The V5.7 dashboard
   is unaffected (the V6.0 code is additive).
2. Wait for at least one successful background run (logs).
3. Deploy the V6.0 private gateway. Configure the cross-site
   env vars and the pepper.
4. Issue a credential to your first consumer.
5. The consumer pulls the baseline via the reference client
   or its own implementation.
6. The public dashboard continues to work as before.

To upgrade from V6.0.x to V6.0.y (a future V6.0 minor):

- The schemas are versioned. A new schema is additive;
  consumers that don't read the new fields continue to work.
- A breaking change to the schema requires a major version
  bump and a separate migration guide.
- The Blob layout is stable; no migrations needed.
- The credentials are unchanged; a new consumer is not needed
  to upgrade the publisher.

## 12. Deploy-preview secret scoping

Netlify deploy previews (branch deploys, pull-request
previews) inherit the production environment variables
by default. For the V6.0 sites, this is a real risk —
a branch deploy with the production trigger secret
could be triggered by any visitor with the preview URL,
and a branch deploy with the production cross-site
token could read the production baseline.

The required scoping (set in the Netlify UI for each site,
Site settings → Environment variables → "Production"
scope):

**Public site:**
- `THREATPULSE_REFRESH_TRIGGER_SECRET` — scope **Production** only.
  Without this, a branch deploy URL gives anyone with the
  URL the ability to trigger a full V6.0 baseline refresh
  (consumes OSV quota, burns the 15-min background budget).
- `NVD_API_KEY` — scope **Production** only.
- `GITHUB_TOKEN` — scope **Production** only.
- Do NOT set `THREATPULSE_CREDENTIAL_PEPPER` (gateway-only).
- Do NOT set `THREATPULSE_BASELINE_SITE_ID` (gateway-only).
- Do NOT set `THREATPULSE_BLOBS_ACCESS_TOKEN` (gateway-only).
- Do NOT set `THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN`
  (no such env var exists; credentials are gateway-local).
- Do NOT set `THREATPULSE_CREDENTIALS_SITE_ID` (no such env
  var exists; credentials are gateway-local).

**Private gateway site:**
- `THREATPULSE_BASELINE_SITE_ID` — scope **Production** only.
  Without this, a branch deploy of the gateway could read
  the production baseline (low risk — read-only, but still
  unwanted).
- `THREATPULSE_BLOBS_ACCESS_TOKEN` — scope **Production** only.
  Without this, a branch deploy of the gateway could read
  the production baseline.
- `THREATPULSE_CREDENTIAL_PEPPER` — scope **Production** only.
  Without this, a branch deploy of the gateway could forge
  credentials against the production
  `tpr-private-credentials` store (the pepper + a guessed
  keyId lets an attacker compute a valid HMAC). This is
  the highest-impact scoping — never let a preview URL
  be able to read the production pepper.

The `tpr-private-credentials` store is gateway-LOCAL —
the gateway's Netlify runtime has direct access to it
without any env var or token. A branch deploy of the
gateway therefore has the SAME access to the credentials
store as the production deploy (because the access path
is the gateway's own runtime context, not an env-var
scoped to a specific deploy context). The operator must
NOT enable `Auto Publishing` for branch deploys that
would expose the gateway to a public URL. Use Netlify's
"Branch deploys" feature in a way that requires manual
promotion, or disable branch deploys for the gateway
site entirely.
- Do NOT set `THREATPULSE_REFRESH_TRIGGER_SECRET` (gateway
  has no scheduled function).
- Do NOT set `THREATPULSE_OSV_ECOSYSTEMS` (gateway does not
  ingest).
- Do NOT set `NVD_API_KEY` or `GITHUB_TOKEN` (gateway does
  not call upstream providers).
- Do NOT set `THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN`
  (no such env var exists; credentials are gateway-local).
- Do NOT set `THREATPULSE_CREDENTIALS_SITE_ID` (no such env
  var exists; credentials are gateway-local).

For each site, set the env-var scope to "Production" by
default; the Netlify UI exposes a "scopes" selector on each
env var. The deploy-time verification (section 8) should
include a "no preview deploy can read the production store"
spot check via a deploy-preview URL.

## 13. What to NOT do

- Do NOT add a public endpoint that reads the canonical
  baseline. The whole point of V6.0 is that the baseline is
  private.
- Do NOT add a public read API for the baseline. The
  consumer client is the supported way to read it.
- Do NOT change the credential format without a major
  version bump and a clear migration path.
- Do NOT use the consumer's HMAC credential for the
  publisher's trigger secret, or vice versa. They are
  different secrets with different scopes.
- Do NOT log the pepper, the trigger secret, the
  cross-site access token, or any consumer's HMAC
  credential. The function logs and the consumer client
  both keep these out of the logs.
- Do NOT set the public site's
  `THREATPULSE_CREDENTIAL_PEPPER` or any of the cross-site
  Blobs tokens. The public site has no use for them; setting
  them enlarges the attack surface.
